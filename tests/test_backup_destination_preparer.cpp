#include "services/backup_destination_preparer.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>

#include <QCoreApplication>
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
using passwall::services::BackupInstallationIdentity;
using passwall::services::BackupInstallationIdentityDomain;
using passwall::services::BackupSeriesIdentityService;
using passwall::services::GlobalBackupPreferencesResult;
using passwall::services::GlobalBackupPreferencesStore;
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
    BackupInstallationIdentity installationIdentity{
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
        QByteArray(BackupSeriesIdentityService::InstallationIdentitySize, '\x5a')};
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
            date.isValid() ? date : timestamp, output, error,
            nullptr, nullptr, nullptr, nullptr, &installationIdentity);
    }

    QString seriesFor(const VaultFileIdentity& identity,
        const BackupInstallationIdentity* selectedInstallation = nullptr)
    {
        QString seriesId;
        EXPECT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
            selectedInstallation ? *selectedInstallation : installationIdentity,
            identity.vaultId, seriesId, error)) << error.toStdString();
        return QDir(QDir(root).filePath(QString::fromLatin1(identity.vaultId.toHex())))
            .filePath(seriesId);
    }
};

TEST_F(BackupDestinationPreparerTest, CopiesWithSameVaultIdShareSeriesAndResolveCollision)
{
    const auto firstIdentity = inspect(createVault(QStringLiteral("first.pwdb"), 0x42));
    const auto secondIdentity = inspect(createVault(QStringLiteral("second.pwdb"), 0x42));
    ASSERT_NE(firstIdentity.inode, secondIdentity.inode);

    PreparedBackupDestination first;
    ASSERT_TRUE(prepare(firstIdentity, 1, first)) << error.toStdString();
    EXPECT_EQ(QFileInfo(first.familyDirectory()).fileName(),
        QString::fromLatin1(firstIdentity.vaultId.toHex()));
    EXPECT_EQ(QFileInfo(first.seriesDirectory()).absolutePath(),
        first.familyDirectory());
    EXPECT_EQ(QFileInfo(first.seriesDirectory()).fileName(), first.seriesId());
    EXPECT_EQ(first.seriesId().size(),
        BackupSeriesIdentityService::EncodedSeriesIdSize);
    EXPECT_FALSE(first.seriesDirectory().contains(
        QString::fromLatin1(installationIdentity.value.toHex())));
    EXPECT_EQ(first.vaultPath(), firstIdentity.path);
    EXPECT_EQ(first.vaultId(), firstIdentity.vaultId);
    EXPECT_EQ(first.bindingGeneration(), 1U);
    EXPECT_EQ(QFileInfo(first.destinationPath()).fileName(),
        QStringLiteral("generation_1_2026-11-08_14-35-22.pwdb"));
    writeFile(first.destinationPath(), QByteArrayLiteral("published-placeholder"));

    PreparedBackupDestination second;
    ASSERT_TRUE(prepare(secondIdentity, 2, second)) << error.toStdString();
    EXPECT_EQ(second.familyDirectory(), first.familyDirectory());
    EXPECT_EQ(second.seriesDirectory(), first.seriesDirectory());
    EXPECT_EQ(QFileInfo(second.destinationPath()).fileName(),
        QStringLiteral("generation_2_2026-11-08_14-35-22.pwdb"));
}

TEST_F(BackupDestinationPreparerTest, NextGenerationUsesHighestPresentNameDespiteClockRollback)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x42));
    PreparedBackupDestination first;
    ASSERT_TRUE(prepare(identity, 1, first)) << error.toStdString();
    const QDir series(first.seriesDirectory());
    first = {};
    // Placeholders deliberately are not databases: numbering reads only names.
    writeFile(series.filePath(QStringLiteral("generation_12_2028-01-01_00-00-00.pwdb")), "old");
    writeFile(series.filePath(QStringLiteral("generation_2_2027-01-01_00-00-00.pwdb")), "old");
    writeFile(series.filePath(QStringLiteral("2029-01-01_00-00-00.pwdb")), "legacy");
    PreparedBackupDestination next;
    ASSERT_TRUE(prepare(identity, 2, next, timestamp.addDays(-1))) << error.toStdString();
    EXPECT_EQ(QFileInfo(next.destinationPath()).fileName(),
        QStringLiteral("generation_13_2026-11-07_14-35-22.pwdb"));
}

TEST_F(BackupDestinationPreparerTest, MaximumGenerationDoesNotWrap)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x42));
    PreparedBackupDestination first;
    ASSERT_TRUE(prepare(identity, 1, first)) << error.toStdString();
    writeFile(QDir(first.seriesDirectory()).filePath(
        QStringLiteral("generation_18446744073709551615_2026-01-01_00-00-00.pwdb")), "old");
    first = {};
    PreparedBackupDestination next;
    EXPECT_FALSE(prepare(identity, 2, next));
}

TEST_F(BackupDestinationPreparerTest, InvalidGlobalConfigurationCannotPrepareADestination)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x40));
    configuration.status = GlobalBackupPreferencesStatus::Invalid;
    PreparedBackupDestination prepared;
    EXPECT_FALSE(prepare(identity, 1, prepared));
    EXPECT_TRUE(QDir(root).entryList(QDir::Dirs | QDir::NoDotAndDotDot).isEmpty());
}

TEST_F(BackupDestinationPreparerTest,
    PhysicalPreferencesReplacementInvalidatesPreparedDestination)
{
    GlobalBackupPreferencesStore store;
    ASSERT_TRUE(store.save({root, 7}).valid());
    configuration = store.load();
    ASSERT_TRUE(configuration.valid());
    ASSERT_TRUE(configuration.sourceIdentity.has_value());
    const auto identity = inspect(createVault(
        QStringLiteral("physical-preferences.pwdb"), 0x41));
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();

    QFile original(configuration.sourceFile);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    const QByteArray bytes = original.readAll();
    original.close();
    const QString replaced = configuration.sourceFile
        + QStringLiteral(".replaced");
    ASSERT_TRUE(QFile::rename(configuration.sourceFile, replaced));
    writeFile(configuration.sourceFile, bytes);
    ASSERT_TRUE(QFile::setPermissions(configuration.sourceFile,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    const auto current = store.load();
    ASSERT_TRUE(current.valid());
    ASSERT_TRUE(current.sourceIdentity.has_value());
    ASSERT_NE(current.sourceIdentity, configuration.sourceIdentity);
    EXPECT_FALSE(BackupDestinationPreparer::revalidateConfiguration(
        prepared, &current, error));
    EXPECT_FALSE(error.isEmpty());
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
    EXPECT_NE(first.seriesId(), second.seriesId());
}

TEST_F(BackupDestinationPreparerTest, DifferentInstallationsUseDistinctSeries)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0xce));
    PreparedBackupDestination first;
    ASSERT_TRUE(prepare(identity, 1, first)) << error.toStdString();
    const QString firstSeries = first.seriesDirectory();
    first = {};

    installationIdentity.value.fill('\x6b');
    PreparedBackupDestination second;
    ASSERT_TRUE(prepare(identity, 2, second)) << error.toStdString();
    EXPECT_EQ(second.familyDirectory(), QFileInfo(firstSeries).absolutePath());
    EXPECT_NE(second.seriesDirectory(), firstSeries);
}

TEST_F(BackupDestinationPreparerTest, TimestampIsConvertedToUtc)
{
  const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x31));
  QDateTime local(QDate(2026, 11, 8), QTime(14, 35, 22), QTimeZone::fromSecondsAheadOfUtc(7200));
  PreparedBackupDestination prepared;
  ASSERT_TRUE(prepare(identity, 7, prepared, local)) << error.toStdString();
  EXPECT_EQ(QFileInfo(prepared.destinationPath()).fileName(),
	    QStringLiteral("generation_1_2026-11-08_12-35-22.pwdb"));
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
    struct stat rootBefore {}, rootAfter {}, family {}, series {};
    ASSERT_EQ(::stat(QFile::encodeName(root).constData(), &rootBefore), 0);
#endif
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();
#ifdef Q_OS_UNIX
    ASSERT_EQ(::stat(QFile::encodeName(root).constData(), &rootAfter), 0);
    ASSERT_EQ(::stat(QFile::encodeName(prepared.familyDirectory()).constData(), &family), 0);
    ASSERT_EQ(::stat(QFile::encodeName(prepared.seriesDirectory()).constData(), &series), 0);
    EXPECT_EQ(rootBefore.st_mode & 0777, rootAfter.st_mode & 0777);
    EXPECT_EQ(family.st_mode & 0777, 0700);
    EXPECT_EQ(family.st_uid, ::geteuid());
    EXPECT_EQ(series.st_mode & 0777, 0700);
    EXPECT_EQ(series.st_uid, ::geteuid());
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

TEST_F(BackupDestinationPreparerTest, SymbolicSeriesObjectIsRejectedWithoutReplacement)
{
#ifdef Q_OS_UNIX
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x3b));
    const QString series = seriesFor(identity);
    const QString family = QFileInfo(series).absolutePath();
    const QString redirect = temporary.filePath(QStringLiteral("series-redirect"));
    ASSERT_TRUE(QDir().mkpath(family));
    ASSERT_TRUE(QFile::setPermissions(family,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    ASSERT_TRUE(QDir().mkpath(redirect));
    ASSERT_EQ(::symlink(QFile::encodeName(redirect).constData(),
        QFile::encodeName(series).constData()), 0);

    PreparedBackupDestination prepared;
    EXPECT_FALSE(prepare(identity, 1, prepared));
    EXPECT_TRUE(QFileInfo(series).isSymLink());
    EXPECT_TRUE(QDir(redirect).isEmpty());
#endif
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

TEST_F(BackupDestinationPreparerTest, SeriesSubstitutionInvalidatesPreparation)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x39));
    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 1, prepared)) << error.toStdString();
    const QString displaced = prepared.seriesDirectory() + QStringLiteral(".old");
    ASSERT_TRUE(QDir().rename(prepared.seriesDirectory(), displaced));
    ASSERT_TRUE(QDir().mkpath(prepared.seriesDirectory()));
    ASSERT_TRUE(QFile::setPermissions(prepared.seriesDirectory(),
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
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
    const QString series = seriesFor(identity);
    ASSERT_TRUE(QDir().mkpath(series));
    ASSERT_TRUE(QFile::setPermissions(family,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    ASSERT_TRUE(QFile::setPermissions(series,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    const QString first = QDir(series).filePath(QStringLiteral("generation_1_2026-11-08_14-35-22.pwdb"));
    const QString second = QDir(series).filePath(QStringLiteral("generation_2_2026-11-08_14-35-22.pwdb"));
    writeFile(first, QByteArrayLiteral("first"));
    writeFile(second, QByteArrayLiteral("second"));

    PreparedBackupDestination prepared;
    ASSERT_TRUE(prepare(identity, 9, prepared)) << error.toStdString();
    EXPECT_EQ(QFileInfo(prepared.destinationPath()).fileName(),
        QStringLiteral("generation_3_2026-11-08_14-35-22.pwdb"));
    writeFile(prepared.destinationPath(), QByteArrayLiteral("concurrent"));
    EXPECT_FALSE(BackupDestinationPreparer::revalidate(
        prepared, identity, 9, error));
    QFile firstFile(first), secondFile(second);
    ASSERT_TRUE(firstFile.open(QIODevice::ReadOnly));
    ASSERT_TRUE(secondFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(firstFile.readAll(), QByteArrayLiteral("first"));
    EXPECT_EQ(secondFile.readAll(), QByteArrayLiteral("second"));
}

TEST_F(BackupDestinationPreparerTest, InvalidInjectedIdentityFailsBeforeCreatingDirectories)
{
    const auto identity = inspect(createVault(QStringLiteral("vault.pwdb"), 0x3a));
    installationIdentity.value.clear();
    PreparedBackupDestination prepared;
    EXPECT_FALSE(prepare(identity, 1, prepared));
    EXPECT_TRUE(QDir(root).entryList(QDir::AllEntries | QDir::NoDotAndDotDot).isEmpty());
    EXPECT_FALSE(error.isEmpty());
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

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
