#include "services/backup_series_inspector.hpp"

#include "services/backup_series_identity.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>

#include <QDate>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QTime>
#include <QTimeZone>

#include <limits>
#include <string>

#ifdef Q_OS_UNIX
#include <sys/stat.h>
#include <unistd.h>
#endif

using passwall::services::BackupInstallationIdentity;
using passwall::services::BackupInstallationIdentityDomain;
using passwall::services::BackupSeriesIdentityService;
using passwall::services::BackupSeriesInspectionCheckpoint;
using passwall::services::BackupSeriesInspectionOutcome;
using passwall::services::BackupSeriesInspectionRequest;
using passwall::services::BackupSeriesInspector;
using passwall::services::BackupSeriesVersion;
using passwall::services::VaultKeyMetadata;

namespace {

QStringList versionNames(const QVector<BackupSeriesVersion>& versions)
{
    QStringList names;
    for (const auto& version : versions) names.push_back(version.fileName);
    return names;
}

struct ConcurrentMutation {
    QString expectedPath;
    QString movedPath;
    QString replacementPath;
    bool remove = false;
    bool invoked = false;
    bool succeeded = false;
};

void mutateValidatedCandidate(void* raw,
    BackupSeriesInspectionCheckpoint checkpoint, const QString& path) noexcept
{
    auto& mutation = *static_cast<ConcurrentMutation*>(raw);
    if (mutation.invoked
        || checkpoint != BackupSeriesInspectionCheckpoint::CandidateValidated
        || path != mutation.expectedPath)
        return;
    mutation.invoked = true;
    if (mutation.remove) {
        mutation.succeeded = QFile::remove(path);
        return;
    }
    mutation.succeeded = QFile::rename(path, mutation.movedPath)
        && QFile::copy(mutation.replacementPath, path)
        && QFile::setPermissions(path,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner);
}

class BackupSeriesInspectorTest : public ::testing::Test {
protected:
    QTemporaryDir temporary{QStringLiteral("/tmp/passwall-series-inspection-XXXXXX")};
    QString root;
    QString family;
    QString series;
    QString templateVault;
    QByteArray vaultId{16, '\x41'};
    BackupSeriesInspectionRequest request;

    void SetUp() override
    {
        ASSERT_TRUE(temporary.isValid());
        root = temporary.filePath(QStringLiteral("backups"));
        ASSERT_TRUE(QDir().mkpath(root));
        ASSERT_TRUE(makePrivateDirectory(root));

        BackupInstallationIdentity installation{
            BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
            QByteArray(BackupSeriesIdentityService::InstallationIdentitySize, '\x31')};
        QString seriesId;
        QString error;
        ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
            installation, vaultId, seriesId, error)) << error.toStdString();
        family = QDir(root).filePath(QString::fromLatin1(vaultId.toHex()));
        series = QDir(family).filePath(seriesId);
        ASSERT_TRUE(QDir().mkpath(series));
        ASSERT_TRUE(makePrivateDirectory(family));
        ASSERT_TRUE(makePrivateDirectory(series));

        templateVault = createVault(QStringLiteral("template.pwdb"), 0x41);
        request.rootDirectory = root;
        request.vaultId = vaultId;
        request.seriesId = seriesId;
        request.retainedVersions = 7;
    }

    static bool makePrivateDirectory(const QString& path)
    {
        return QFile::setPermissions(path,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner
                | QFileDevice::ExeOwner);
    }

    QString createVault(const QString& name, unsigned char id)
    {
        const QString path = temporary.filePath(name);
        std::string error;
        EXPECT_TRUE(passwall::storage::VaultStorage::createSchema(
            path.toStdString(), error)) << error;
        VaultKeyMetadata metadata;
        metadata.vaultId.fill(id);
        EXPECT_TRUE(passwall::storage::VaultStorage::writeMetadata(
            path.toStdString(), metadata, error)) << error;
        return path;
    }

    QString managedName(int offset) const
    {
        // Deliberately reverse timestamps: generation, not clock, defines order.
        const QDateTime timestamp(QDate(2026, 11, 1), QTime(12, 0, 0),
            QTimeZone::utc());
        return QStringLiteral("generation_%1_%2.pwdb").arg(offset + 1)
            .arg(timestamp.addSecs(-offset).toString(
                QStringLiteral("yyyy-MM-dd_HH-mm-ss")));
    }

    QString copyBackup(const QString& name, const QString& source = {})
    {
        const QString destination = QDir(series).filePath(name);
        EXPECT_TRUE(QFile::copy(source.isEmpty() ? templateVault : source,
            destination));
        EXPECT_TRUE(QFile::setPermissions(destination,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
        return destination;
    }

    void createBackups(int count, int firstOffset = 0)
    {
        for (int index = 0; index < count; ++index)
            copyBackup(managedName(firstOffset + index));
    }

    QStringList treeEntries() const
    {
        QStringList entries;
        QDirIterator iterator(root,
            QDir::AllEntries | QDir::Hidden | QDir::System
                | QDir::NoDotAndDotDot,
            QDirIterator::Subdirectories);
        const QDir base(root);
        while (iterator.hasNext())
            entries.push_back(base.relativeFilePath(iterator.next()));
        entries.sort();
        return entries;
    }
};

TEST_F(BackupSeriesInspectorTest, ZeroThroughSevenVersionsHaveNoExcess)
{
    for (int count = 0; count <= 7; ++count) {
        if (count != 0) copyBackup(managedName(count - 1));
        const auto result = BackupSeriesInspector::inspect(request);
        ASSERT_EQ(result.outcome, BackupSeriesInspectionOutcome::Complete)
            << result.diagnostic.toStdString();
        EXPECT_EQ(result.admissible.size(), count);
        EXPECT_TRUE(result.excess.isEmpty());
        EXPECT_TRUE(result.ambiguities.isEmpty());
    }
}

TEST_F(BackupSeriesInspectorTest, EightVersionsSelectOnlyTheOldest)
{
    createBackups(8);
    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    ASSERT_EQ(result.excess.size(), 1);
    EXPECT_EQ(result.excess.front().fileName, managedName(0));
    EXPECT_EQ(result.admissible.back().fileName, managedName(7));
}

TEST_F(BackupSeriesInspectorTest, SeveralExcessVersionsRemainOldestFirst)
{
    createBackups(11);
    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    ASSERT_EQ(result.excess.size(), 4);
    EXPECT_EQ(versionNames(result.excess),
        (QStringList{managedName(0), managedName(1),
            managedName(2), managedName(3)}));
}

TEST_F(BackupSeriesInspectorTest, RetentionAboveCountAndUint64MaxDoNotOverflow)
{
    createBackups(9);
    request.retainedVersions = 10;
    auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_TRUE(result.excess.isEmpty());

    request.retainedVersions = std::numeric_limits<quint64>::max();
    result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_EQ(result.admissible.size(), 9);
    EXPECT_TRUE(result.excess.isEmpty());
}

TEST_F(BackupSeriesInspectorTest, SeriesOfSameFamilyAreStrictlyIsolated)
{
    createBackups(8);
    BackupInstallationIdentity otherInstallation{
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
        QByteArray(BackupSeriesIdentityService::InstallationIdentitySize, '\x32')};
    QString otherId;
    QString error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        otherInstallation, vaultId, otherId, error));
    const QString otherSeries = QDir(family).filePath(otherId);
    ASSERT_TRUE(QDir().mkpath(otherSeries));
    ASSERT_TRUE(makePrivateDirectory(otherSeries));
    for (int index = 0; index < 12; ++index) {
        const QString destination = QDir(otherSeries).filePath(managedName(100 + index));
        ASSERT_TRUE(QFile::copy(templateVault, destination));
        ASSERT_TRUE(QFile::setPermissions(destination,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    }

    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_EQ(result.admissible.size(), 8);
    ASSERT_EQ(result.excess.size(), 1);
    EXPECT_EQ(result.excess.front().path, QDir(series).filePath(managedName(0)));
    EXPECT_TRUE(QFileInfo::exists(QDir(otherSeries).filePath(managedName(100))));
}

TEST_F(BackupSeriesInspectorTest, LegacyFamilyFilesArePreservedAndExcluded)
{
    createBackups(7);
    const QString legacy = QDir(family).filePath(managedName(100));
    ASSERT_TRUE(QFile::copy(templateVault, legacy));
    ASSERT_TRUE(QFile::setPermissions(legacy,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));

    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_EQ(result.admissible.size(), 7);
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_TRUE(QFileInfo::exists(legacy));
}

TEST_F(BackupSeriesInspectorTest, LegacyNamesStayOutsideConvention)
{
    const QStringList names{
        QStringLiteral("2026-02-30_12-00-00.pwdb"),
        QStringLiteral("2026-11-22_14-30-00_01.pwdb"),
        QStringLiteral("2026-11-22_14-30-00_1.pwdb"),
        QStringLiteral("notes.txt")};
    for (const QString& name : names) copyBackup(name);

    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_TRUE(result.admissible.isEmpty());
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_EQ(result.outsideConvention.size(), names.size());
    EXPECT_TRUE(result.ambiguities.isEmpty());
}

TEST_F(BackupSeriesInspectorTest, AuxiliaryFilesDoNotMakeGenerationOrderingAmbiguous)
{
    createBackups(8);
    const QStringList names{managedName(0) + QStringLiteral(".ready"),
        managedName(0) + QStringLiteral(".release"),
        QStringLiteral("generation_notes.txt")};
    for (const QString& name : names) {
        QFile auxiliary(QDir(series).filePath(name));
        ASSERT_TRUE(auxiliary.open(QIODevice::WriteOnly));
        ASSERT_EQ(auxiliary.write("marker"), 6);
        auxiliary.close();
    }
    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_EQ(result.admissible.size(), 8);
    EXPECT_TRUE(result.ambiguities.isEmpty());
    EXPECT_EQ(result.outsideConvention.size(), names.size());
    ASSERT_EQ(result.excess.size(), 1);
    EXPECT_EQ(result.excess.front().fileName, managedName(0));
    for (const QString& name : names) {
        QFile auxiliary(QDir(series).filePath(name));
        ASSERT_TRUE(auxiliary.open(QIODevice::ReadOnly));
        EXPECT_EQ(auxiliary.readAll(), QByteArrayLiteral("marker"));
    }
}

TEST_F(BackupSeriesInspectorTest, GenerationNumbersUseNumericOrderDespiteReversedClock)
{
    for (int offset : {9, 2, 0, 1}) copyBackup(managedName(offset));
    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    EXPECT_EQ(versionNames(result.admissible),
        (QStringList{managedName(0), managedName(1), managedName(2), managedName(9)}));
}

TEST_F(BackupSeriesInspectorTest, DuplicateGenerationRefusesSelection)
{
    createBackups(8);
    copyBackup(QStringLiteral("generation_1_2027-01-01_00-00-00.pwdb"));
    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_FALSE(result.selectionComplete());
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_FALSE(result.ambiguities.isEmpty());
}

TEST_F(BackupSeriesInspectorTest, MalformedGenerationNamesRefuseSelection)
{
    createBackups(8);
    for (const QString& name : {
            QStringLiteral("generation_01_2026-11-01_00-00-00.pwdb"),
            QStringLiteral("generation_18446744073709551616_2026-11-01_00-00-00.pwdb"),
            QStringLiteral("generation_9_2026-02-30_00-00-00.pwdb")}) {
        const QString path = copyBackup(name);
        const auto result = BackupSeriesInspector::inspect(request);
        EXPECT_FALSE(result.selectionComplete());
        EXPECT_TRUE(result.excess.isEmpty());
        EXPECT_FALSE(result.ambiguities.isEmpty());
        ASSERT_TRUE(QFile::remove(path));
    }
}

#ifdef Q_OS_UNIX
TEST_F(BackupSeriesInspectorTest, CanonicalSymlinkAndNonRegularObjectMakeSelectionUnsafe)
{
    const QString link = QDir(series).filePath(managedName(0));
    ASSERT_EQ(::symlink(QFile::encodeName(templateVault).constData(),
        QFile::encodeName(link).constData()), 0);
    const QString fifo = QDir(series).filePath(managedName(1));
    ASSERT_EQ(::mkfifo(QFile::encodeName(fifo).constData(), 0600), 0);

    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_EQ(result.ambiguities.size(), 2);
    EXPECT_TRUE(QFileInfo::exists(link));
    struct stat status {};
    EXPECT_EQ(::lstat(QFile::encodeName(fifo).constData(), &status), 0);
    EXPECT_TRUE(S_ISFIFO(status.st_mode));
}
#endif

TEST_F(BackupSeriesInspectorTest, IncorrectPermissionsOrHardLinksAreAmbiguous)
{
    const QString permissive = copyBackup(managedName(0));
    ASSERT_TRUE(QFile::setPermissions(permissive,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner
            | QFileDevice::ReadGroup));
    const QString linked = copyBackup(managedName(1));
    const QString secondName = QDir(series).filePath(QStringLiteral("linked-copy"));
#ifdef Q_OS_UNIX
    ASSERT_EQ(::link(QFile::encodeName(linked).constData(),
        QFile::encodeName(secondName).constData()), 0);
#else
    GTEST_SKIP() << "Hard-link identity checks require the POSIX implementation.";
#endif

    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_EQ(result.ambiguities.size(), 2);
}

// B02: names and physical metadata determine membership. Integrity is
// checked only for a new publication or a user-selected restoration.
TEST_F(BackupSeriesInspectorTest, DifferentVaultIdIsNotReadDuringSelection)
{
    const QString otherVault = createVault(QStringLiteral("other.pwdb"), 0x42);
    const QString candidate = copyBackup(managedName(0), otherVault);
    createBackups(7, 1);

    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Complete);
    EXPECT_EQ(result.admissible.size(), 8);
    ASSERT_EQ(result.excess.size(), 1);
    EXPECT_EQ(result.excess.front().path, candidate);
    EXPECT_TRUE(result.ambiguities.isEmpty());
}

TEST_F(BackupSeriesInspectorTest, InvalidSqliteContentsAreNotReadDuringSelection)
{
    createBackups(7, 1);
    const QString invalid = QDir(series).filePath(managedName(0));
    QFile file(invalid);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::NewOnly));
    ASSERT_EQ(file.write("not a PassWall database"), 23);
    file.close();
    ASSERT_TRUE(QFile::setPermissions(invalid,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));

    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Complete);
    EXPECT_EQ(result.admissible.size(), 8);
    ASSERT_EQ(result.excess.size(), 1);
    EXPECT_EQ(result.excess.front().path, invalid);
    EXPECT_TRUE(result.ambiguities.isEmpty());
    EXPECT_TRUE(QFileInfo::exists(invalid));
}

TEST_F(BackupSeriesInspectorTest, SqliteCompanionsRefuseSelectionWithoutReading)
{
    createBackups(8);
    const QString candidate = QDir(series).filePath(managedName(0));
    for (const auto& suffix : {QStringLiteral("-journal"),
             QStringLiteral("-wal"), QStringLiteral("-shm")}) {
        QFile companion(candidate + suffix);
        ASSERT_TRUE(companion.open(QIODevice::WriteOnly | QIODevice::NewOnly));
        companion.close();
        const auto result = BackupSeriesInspector::inspect(request);
        EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
        EXPECT_TRUE(result.excess.isEmpty());
        EXPECT_TRUE(QFileInfo::exists(companion.fileName()));
        ASSERT_TRUE(companion.remove());
    }
}

TEST_F(BackupSeriesInspectorTest, ConcurrentDisappearanceSuppressesTheWholeSelection)
{
    const QString candidate = copyBackup(managedName(0));
    createBackups(7, 1);
    ConcurrentMutation mutation;
    mutation.expectedPath = candidate;
    mutation.remove = true;
    request.observer = {mutateValidatedCandidate, &mutation};

    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_TRUE(mutation.invoked);
    EXPECT_TRUE(mutation.succeeded);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_FALSE(QFileInfo::exists(candidate));
}

TEST_F(BackupSeriesInspectorTest, ConcurrentSubstitutionIsDetectedByFinalRevalidation)
{
    const QString candidate = copyBackup(managedName(0));
    createBackups(7, 1);
    const QString replacement = createVault(QStringLiteral("replacement.pwdb"), 0x41);
    ConcurrentMutation mutation;
    mutation.expectedPath = candidate;
    mutation.movedPath = candidate + QStringLiteral(".old");
    mutation.replacementPath = replacement;
    request.observer = {mutateValidatedCandidate, &mutation};

    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_TRUE(mutation.invoked);
    EXPECT_TRUE(mutation.succeeded);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_TRUE(QFileInfo::exists(candidate));
    EXPECT_TRUE(QFileInfo::exists(mutation.movedPath));
}

TEST_F(BackupSeriesInspectorTest, AccessFailureAndUnexpectedDirectoryIdentityFailClosed)
{
    BackupSeriesInspectionRequest missing = request;
    missing.rootDirectory = temporary.filePath(QStringLiteral("absent"));
    auto result = BackupSeriesInspector::inspect(missing);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_FALSE(QFileInfo::exists(missing.rootDirectory));

    request.expectedSeries = passwall::services::SnapshotDirectoryIdentity{1, 1};
    result = BackupSeriesInspector::inspect(request);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::Unsafe);
    EXPECT_TRUE(result.excess.isEmpty());
}

TEST_F(BackupSeriesInspectorTest, InvalidRetentionIsRejectedWithoutInspection)
{
    createBackups(8);
    request.retainedVersions = 6;
    const auto before = treeEntries();
    const auto result = BackupSeriesInspector::inspect(request);
    EXPECT_EQ(result.outcome, BackupSeriesInspectionOutcome::InvalidRequest);
    EXPECT_TRUE(result.admissible.isEmpty());
    EXPECT_TRUE(result.excess.isEmpty());
    EXPECT_EQ(treeEntries(), before);
}

TEST_F(BackupSeriesInspectorTest, SuccessfulInspectionCreatesDeletesAndRenamesNothing)
{
    createBackups(8);
    const auto before = treeEntries();
    const QFileInfo oldest(QDir(series).filePath(managedName(0)));
    const auto size = oldest.size();
    const auto modified = oldest.lastModified();

    const auto result = BackupSeriesInspector::inspect(request);
    ASSERT_TRUE(result.selectionComplete()) << result.diagnostic.toStdString();
    ASSERT_EQ(result.excess.size(), 1);
    EXPECT_EQ(treeEntries(), before);
    const QFileInfo after(oldest.filePath());
    EXPECT_EQ(after.size(), size);
    EXPECT_EQ(after.lastModified(), modified);
}

} // namespace
