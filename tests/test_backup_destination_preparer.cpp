#include "services/backup_destination_preparer.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>

#include <QDate>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QTemporaryDir>
#include <QTime>
#include <QTimeZone>

#ifdef Q_OS_UNIX
#include <sys/stat.h>
#include <unistd.h>
#endif

using passwall::services::BackupDestinationPreparer;
using passwall::services::GlobalBackupPreferencesResult;
using passwall::services::GlobalBackupPreferencesStatus;
using passwall::services::PreparedBackupDestination;
using passwall::services::VaultFileIdentity;
using passwall::services::VaultKeyMetadata;
using passwall::services::VaultPreferencesStore;

namespace {

void writeFile(const QString& path, const QByteArray& contents)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::NewOnly));
    ASSERT_EQ(file.write(contents), contents.size());
    file.close();
}

class BackupDestinationPreparerTest : public ::testing::Test {
protected:
    QTemporaryDir temporary{QStringLiteral("/tmp/passwall-destination-case-XXXXXX")};
    QString root;
    QString error;
    GlobalBackupPreferencesResult configuration;
  QDateTime timestamp{QDate(2026, 11, 8), QTime(14, 35, 22), QTimeZone::utc()};
    void SetUp() override
    {
        ASSERT_TRUE(temporary.isValid());
        for (const auto format : {QSettings::IniFormat, QSettings::NativeFormat}) {
            QSettings::setPath(format, QSettings::UserScope,
                temporary.filePath(QStringLiteral("settings")));
            QSettings::setPath(format, QSettings::SystemScope,
                temporary.filePath(QStringLiteral("settings")));
        }
        root = temporary.filePath(QStringLiteral("backups"));
        ASSERT_TRUE(QDir().mkpath(root));
        ASSERT_TRUE(QFile::setPermissions(root,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
        configuration.status = GlobalBackupPreferencesStatus::Valid;
        configuration.preferences = {root, 7};
    }

    QString createVault(const QString& name, unsigned char vaultByte)
    {
        const QString path = temporary.filePath(name);
        std::string failure;
        EXPECT_TRUE(passwall::storage::VaultStorage::createSchema(
            path.toStdString(), failure)) << failure;
        VaultKeyMetadata metadata;
        metadata.vaultId.fill(vaultByte);
        EXPECT_TRUE(passwall::storage::VaultStorage::writeMetadata(
            path.toStdString(), metadata, failure)) << failure;
        return path;
    }

    VaultFileIdentity inspect(const QString& path)
    {
        VaultFileIdentity identity;
        EXPECT_TRUE(VaultPreferencesStore::inspectVault(path, identity, error))
            << error.toStdString();
        return identity;
    }

    bool prepare(const VaultFileIdentity& identity, quint64 generation,
        PreparedBackupDestination& output, const QDateTime& date = {})
    {
        return BackupDestinationPreparer::prepare(configuration, identity, generation,
            date.isValid() ? date : timestamp, output, error);
    }
};

TEST_F(BackupDestinationPreparerTest, CopiesWithSameVaultIdShareFamilyAndResolveCollision)
{
    const auto firstIdentity = inspect(createVault(QStringLiteral("first.pwdb"), 0x42));
    const auto secondIdentity = inspect(createVault(QStringLiteral("second.pwdb"), 0x42));
    ASSERT_NE(firstIdentity.inode, secondIdentity.inode);

    PreparedBackupDestination first;
    ASSERT_TRUE(prepare(firstIdentity, 1, first)) << error.toStdString();
    EXPECT_EQ(QFileInfo(first.familyDirectory()).fileName(),
        QString::fromLatin1(firstIdentity.vaultId.toHex()));
    EXPECT_EQ(first.vaultPath(), firstIdentity.path);
    EXPECT_EQ(first.vaultId(), firstIdentity.vaultId);
    EXPECT_EQ(first.bindingGeneration(), 1U);
    EXPECT_EQ(QFileInfo(first.destinationPath()).fileName(),
        QStringLiteral("2026-11-08_14-35-22.pwdb"));
    writeFile(first.destinationPath(), QByteArrayLiteral("published-placeholder"));

    PreparedBackupDestination second;
    ASSERT_TRUE(prepare(secondIdentity, 2, second)) << error.toStdString();
    EXPECT_EQ(second.familyDirectory(), first.familyDirectory());
    EXPECT_EQ(QFileInfo(second.destinationPath()).fileName(),
        QStringLiteral("2026-11-08_14-35-22_2.pwdb"));
}

TEST_F(BackupDestinationPreparerTest, InvalidGlobalConfigurationCannotPrepareADestination)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x40));
    configuration.status = GlobalBackupPreferencesStatus::Invalid;
    PreparedBackupDestination prepared;
    EXPECT_FALSE(prepare(identity, 1, prepared));
    EXPECT_TRUE(QDir(root).entryList(QDir::Dirs | QDir::NoDotAndDotDot).isEmpty());
}

TEST_F(BackupDestinationPreparerTest, DifferentVaultIdsUseDifferentFamilies)
{
    const auto firstIdentity = inspect(createVault(QStringLiteral("first.pwdb"), 0xab));
    const auto secondIdentity = inspect(createVault(QStringLiteral("second.pwdb"), 0xcd));
    PreparedBackupDestination first, second;
    ASSERT_TRUE(prepare(firstIdentity, 1, first)) << error.toStdString();
    ASSERT_TRUE(prepare(secondIdentity, 1, second)) << error.toStdString();
    EXPECT_NE(first.familyDirectory(), second.familyDirectory());
    EXPECT_EQ(QFileInfo(first.familyDirectory()).fileName(),
        QStringLiteral("ab").repeated(16));
    EXPECT_EQ(QFileInfo(second.familyDirectory()).fileName(),
        QStringLiteral("cd").repeated(16));
}

TEST_F(BackupDestinationPreparerTest, TimestampIsConvertedToUtc)
{
  const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x31));
  QDateTime local(QDate(2026, 11, 8), QTime(14, 35, 22), QTimeZone::fromSecondsAheadOfUtc(7200));
  PreparedBackupDestination prepared;
  ASSERT_TRUE(prepare(identity, 7, prepared, local)) << error.toStdString();
  EXPECT_EQ(QFileInfo(prepared.destinationPath()).fileName(),
	    QStringLiteral("2026-11-08_12-35-22.pwdb"));
}

TEST_F(BackupDestinationPreparerTest, InvalidRootAndSymbolicLinksAreRejected)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x32));
    PreparedBackupDestination prepared;
    configuration.preferences.rootDirectory = QStringLiteral("relative/backups");
    EXPECT_FALSE(prepare(identity, 1, prepared));

#ifdef Q_OS_UNIX
    const QString realRoot = temporary.filePath(QStringLiteral("real-root"));
    const QString linkedRoot = temporary.filePath(QStringLiteral("linked-root"));
    ASSERT_TRUE(QDir().mkpath(realRoot));
    ASSERT_TRUE(QFile::setPermissions(realRoot,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    ASSERT_EQ(::symlink(QFile::encodeName(realRoot).constData(),
        QFile::encodeName(linkedRoot).constData()), 0);
    configuration.preferences.rootDirectory = linkedRoot;
    EXPECT_FALSE(prepare(identity, 2, prepared));

    configuration.preferences.rootDirectory = root;
    const QString family = QDir(root).filePath(QString::fromLatin1(identity.vaultId.toHex()));
    const QString redirect = temporary.filePath(QStringLiteral("redirect"));
    ASSERT_TRUE(QDir().mkpath(redirect));
    ASSERT_EQ(::symlink(QFile::encodeName(redirect).constData(),
        QFile::encodeName(family).constData()), 0);
    EXPECT_FALSE(prepare(identity, 3, prepared));
#endif
}

TEST_F(BackupDestinationPreparerTest, FamilyIsPrivateAndRootPermissionsAreUntouched)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x33));
#ifdef Q_OS_UNIX
    ASSERT_EQ(::chmod(QFile::encodeName(root).constData(), 0755), 0);
    struct stat rootBefore {}, rootAfter {}, family {};
    ASSERT_EQ(::stat(QFile::encodeName(root).constData(), &rootBefore), 0);
#endif
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();
#ifdef Q_OS_UNIX
    ASSERT_EQ(::stat(QFile::encodeName(root).constData(), &rootAfter), 0);
    ASSERT_EQ(::stat(QFile::encodeName(prepared.familyDirectory()).constData(), &family), 0);
    EXPECT_EQ(rootBefore.st_mode & 0777, rootAfter.st_mode & 0777);
    EXPECT_EQ(family.st_mode & 0777, 0700);
    EXPECT_EQ(family.st_uid, ::geteuid());
#endif
}

TEST_F(BackupDestinationPreparerTest, FamilySubstitutionInvalidatesPreparation)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x34));
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();
    const QString displaced = prepared.familyDirectory() + QStringLiteral(".old");
    ASSERT_TRUE(QDir().rename(prepared.familyDirectory(), displaced));
    ASSERT_TRUE(QDir().mkpath(prepared.familyDirectory()));
    ASSERT_TRUE(QFile::setPermissions(prepared.familyDirectory(),
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    EXPECT_FALSE(BackupDestinationPreparer::revalidate(
        prepared, identity, 1, error));
}

TEST_F(BackupDestinationPreparerTest, SourceSubstitutionInvalidatesPreparation)
{
    const QString path = createVault(QStringLiteral("vault.pwdb"), 0x35);
    const auto identity = inspect(path);
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();
    ASSERT_TRUE(QFile::rename(path, path + QStringLiteral(".old")));
    ASSERT_EQ(createVault(QStringLiteral("vault.pwdb"), 0x35), path);
    EXPECT_FALSE(BackupDestinationPreparer::revalidate(
        prepared, identity, 1, error));
}

TEST_F(BackupDestinationPreparerTest, IncoherentVaultIdentityIsRejected)
{
    auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x36));
    identity.vaultId.fill('\x7f');
    PreparedBackupDestination prepared;
    EXPECT_FALSE(prepare(identity, 1, prepared));
    EXPECT_TRUE(QDir(root).entryList(QDir::Dirs | QDir::NoDotAndDotDot).isEmpty());
}

TEST_F(BackupDestinationPreparerTest, ExistingNamesAreNeverOverwritten)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x37));
    const QString family = QDir(root).filePath(QString::fromLatin1(identity.vaultId.toHex()));
    ASSERT_TRUE(QDir().mkpath(family));
    ASSERT_TRUE(QFile::setPermissions(family,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    const QString first = QDir(family).filePath(QStringLiteral("2026-11-08_14-35-22.pwdb"));
    const QString second = QDir(family).filePath(QStringLiteral("2026-11-08_14-35-22_2.pwdb"));
    writeFile(first, QByteArrayLiteral("first"));
    writeFile(second, QByteArrayLiteral("second"));

    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 9, prepared)) << error.toStdString();
    EXPECT_EQ(QFileInfo(prepared.destinationPath()).fileName(),
        QStringLiteral("2026-11-08_14-35-22_3.pwdb"));
    writeFile(prepared.destinationPath(), QByteArrayLiteral("concurrent"));
    EXPECT_FALSE(BackupDestinationPreparer::revalidate(
        prepared, identity, 9, error));
    QFile firstFile(first), secondFile(second);
    ASSERT_TRUE(firstFile.open(QIODevice::ReadOnly));
    ASSERT_TRUE(secondFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(firstFile.readAll(), QByteArrayLiteral("first"));
    EXPECT_EQ(secondFile.readAll(), QByteArrayLiteral("second"));
}

TEST_F(BackupDestinationPreparerTest, PreparationKeepsSnapshotReservationAlive)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x38));
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();
    passwall::storage::VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_FALSE(exclusive.tryReserve(identity.path.toStdString(), reservationError));
    EXPECT_TRUE(exclusive.contended());
    EXPECT_FALSE(BackupDestinationPreparer::revalidate(
        prepared, identity, 2, error));
    EXPECT_TRUE(BackupDestinationPreparer::revalidate(
        prepared, identity, 1, error))
        << error.toStdString();
}

} // namespace
