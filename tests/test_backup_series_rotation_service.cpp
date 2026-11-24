#include "services/backup_publication_verifier.hpp"
#include "services/backup_series_identity.hpp"
#include "services/backup_series_rotation_service.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>

#include <QCryptographicHash>
#include <QDate>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QTime>
#include <QTimeZone>

#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace {
thread_local int failManagedUnlinkOnCall = 0;
thread_local bool failNextDirectorySync = false;
}

extern "C" int __real_unlinkat(int, const char*, int);
extern "C" int __wrap_unlinkat(int directory, const char* name, int flags)
{
    if (failManagedUnlinkOnCall > 0 && name != nullptr
        && std::strstr(name, ".pwdb") != nullptr) {
        --failManagedUnlinkOnCall;
        if (failManagedUnlinkOnCall == 0) {
            errno = EIO;
            return -1;
        }
    }
    return __real_unlinkat(directory, name, flags);
}

extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int descriptor)
{
    struct stat status {};
    if (failNextDirectorySync && ::fstat(descriptor, &status) == 0
        && S_ISDIR(status.st_mode)) {
        failNextDirectorySync = false;
        errno = EIO;
        return -1;
    }
    return __real_fsync(descriptor);
}

using passwall::services::BackupFileEvidence;
using passwall::services::BackupInstallationIdentity;
using passwall::services::BackupInstallationIdentityDomain;
using passwall::services::BackupOutcome;
using passwall::services::BackupResult;
using passwall::services::BackupPublicationVerifier;
using passwall::services::SnapshotCancellation;
using passwall::services::SnapshotCheckpoint;
using passwall::services::BackupSeriesIdentityService;
using passwall::services::BackupSeriesRotationCheckpoint;
using passwall::services::BackupSeriesRotationOutcome;
using passwall::services::BackupSeriesRotationRequest;
using passwall::services::BackupSeriesRotationService;
using passwall::services::VaultKeyMetadata;

namespace {

enum class ConcurrentAction {
    None,
    SubstituteCandidate,
    RemoveCandidate,
    ReplaceSeries,
    StopAfterDeletion
};

struct RotationAction {
    ConcurrentAction action = ConcurrentAction::None;
    QString candidate;
    QString movedCandidate;
    QString replacement;
    QString series;
    QString movedSeries;
    bool invoked = false;
    bool succeeded = false;
};

bool rotationAction(void* raw, BackupSeriesRotationCheckpoint checkpoint,
    const QString& path) noexcept
{
    auto& action = *static_cast<RotationAction*>(raw);
    if (action.invoked) return false;
    if (action.action == ConcurrentAction::StopAfterDeletion) {
        if (checkpoint != BackupSeriesRotationCheckpoint::AfterDeletion)
            return false;
        action.invoked = true;
        action.succeeded = true;
        return true;
    }
    if (checkpoint != BackupSeriesRotationCheckpoint::BeforeUnlink
        || path != action.candidate)
        return false;
    action.invoked = true;
    switch (action.action) {
    case ConcurrentAction::SubstituteCandidate:
        action.succeeded = QFile::rename(action.candidate, action.movedCandidate)
            && QFile::copy(action.replacement, action.candidate)
            && QFile::setPermissions(action.candidate,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        break;
    case ConcurrentAction::RemoveCandidate:
        action.succeeded = QFile::remove(action.candidate);
        break;
    case ConcurrentAction::ReplaceSeries:
        action.succeeded = QDir().rename(action.series, action.movedSeries)
            && QDir().mkpath(action.series)
            && QFile::setPermissions(action.series,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner
                    | QFileDevice::ExeOwner);
        break;
    default:
        break;
    }
    return false;
}

class BackupSeriesRotationServiceTest : public ::testing::Test {
protected:
    QTemporaryDir temporary{QStringLiteral("/tmp/passwall-series-rotation-XXXXXX")};
    QString root;
    QString family;
    QString series;
    QString templateVault;
    QString publishedPath;
    QByteArray vaultId{16, '\x51'};
    BackupSeriesRotationRequest request;

    void SetUp() override
    {
        failManagedUnlinkOnCall = 0;
        failNextDirectorySync = false;
        ASSERT_TRUE(temporary.isValid());
        root = temporary.filePath(QStringLiteral("backups"));
        ASSERT_TRUE(QDir().mkpath(root));
        ASSERT_TRUE(makePrivateDirectory(root));

        BackupInstallationIdentity installation{
            BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
            QByteArray(BackupSeriesIdentityService::InstallationIdentitySize, '\x61')};
        QString error;
        ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
            installation, vaultId, request.seriesId, error))
            << error.toStdString();
        family = QDir(root).filePath(QString::fromLatin1(vaultId.toHex()));
        series = QDir(family).filePath(request.seriesId);
        ASSERT_TRUE(QDir().mkpath(series));
        ASSERT_TRUE(makePrivateDirectory(family));
        ASSERT_TRUE(makePrivateDirectory(series));
        templateVault = createVault(QStringLiteral("template.pwdb"), 0x51);

        request.rootDirectory = root;
        request.vaultId = vaultId;
        request.retainedVersions = 7;
    }

    void TearDown() override
    {
        failManagedUnlinkOnCall = 0;
        failNextDirectorySync = false;
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

    QString copyBackup(int offset, const QString& source = {},
        const QString& selectedSeries = {})
    {
        const QString destination = QDir(
            selectedSeries.isEmpty() ? series : selectedSeries).filePath(
                managedName(offset));
        EXPECT_TRUE(QFile::copy(source.isEmpty() ? templateVault : source,
            destination));
        EXPECT_TRUE(QFile::setPermissions(destination,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
        return destination;
    }

    BackupResult publicationFor(const QString& path)
    {
        BackupFileEvidence evidence;
        QString error;
        EXPECT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(
            path, evidence, error)) << error.toStdString();
        EXPECT_TRUE(evidence.permitsDeletion());
        return {BackupOutcome::Published, {}, evidence, path};
    }

    void createSet(int total)
    {
        ASSERT_GE(total, 1);
        for (int offset = 0; offset < total; ++offset)
            copyBackup(offset);
        publishedPath = QDir(series).filePath(managedName(total - 1));
        request.publication = publicationFor(publishedPath);
    }

    QStringList managedFiles(const QString& selectedSeries = {}) const
    {
        return QDir(selectedSeries.isEmpty() ? series : selectedSeries).entryList(
            {QStringLiteral("*.pwdb")}, QDir::Files, QDir::Name);
    }

    QByteArray digest(const QString& path) const
    {
        QFile file(path);
        EXPECT_TRUE(file.open(QIODevice::ReadOnly));
        QCryptographicHash hash(QCryptographicHash::Sha256);
        while (!file.atEnd()) hash.addData(file.read(65536));
        return hash.result();
    }

    QStringList treeEntries(const QString& basePath) const
    {
        QStringList entries;
        QDirIterator iterator(basePath,
            QDir::AllEntries | QDir::Hidden | QDir::System
                | QDir::NoDotAndDotDot,
            QDirIterator::Subdirectories);
        const QDir base(basePath);
        while (iterator.hasNext())
            entries.push_back(base.relativeFilePath(iterator.next()));
        entries.sort();
        return entries;
    }
};

TEST_F(BackupSeriesRotationServiceTest, PublicationVerifierProducesStableByteEvidence)
{
    const QString path = copyBackup(0);
    BackupFileEvidence first, second;
    QString error;
    ASSERT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(path, first, error))
        << error.toStdString();
    EXPECT_TRUE(error.isEmpty());
    EXPECT_TRUE(first.permitsDeletion());
    EXPECT_EQ(first.sha256, digest(path));
    ASSERT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(path, second, error));
    EXPECT_EQ(second, first);

    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Append));
    ASSERT_EQ(file.write("changed"), 7);
    file.close();
    ASSERT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(path, second, error));
    EXPECT_NE(second.sha256, first.sha256);
    EXPECT_EQ(second.sha256, digest(path));
    EXPECT_EQ(second.size, first.size + 7);
}

TEST_F(BackupSeriesRotationServiceTest, PublicationVerifierClearsEvidenceOnCancellationOrLink)
{
    const QString path = copyBackup(0);
    BackupFileEvidence evidence;
    QString error;
    ASSERT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(path, evidence, error));
    bool checked = false;
    const SnapshotCancellation cancellation{
        [](void* context, SnapshotCheckpoint checkpoint) noexcept {
            *static_cast<bool*>(context) = checkpoint == SnapshotCheckpoint::CopyStep;
            return true;
        }, &checked};
    EXPECT_FALSE(BackupPublicationVerifier::inspectEncryptedFile(
        path, evidence, error, cancellation));
    EXPECT_TRUE(checked);
    EXPECT_FALSE(error.isEmpty());
    EXPECT_EQ(evidence, BackupFileEvidence{});

    const QString link = QDir(series).filePath(managedName(1));
    ASSERT_EQ(::symlink(QFile::encodeName(path).constData(),
        QFile::encodeName(link).constData()), 0);
    ASSERT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(path, evidence, error));
    EXPECT_FALSE(BackupPublicationVerifier::inspectEncryptedFile(link, evidence, error));
    EXPECT_FALSE(error.isEmpty());
    EXPECT_EQ(evidence, BackupFileEvidence{});
    EXPECT_TRUE(QFileInfo::exists(path));
    EXPECT_TRUE(QFileInfo(link).isSymLink());
}

TEST_F(BackupSeriesRotationServiceTest, SevenVersionsNeedNoDeletion)
{
    createSet(7);
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome,
        BackupSeriesRotationOutcome::NoRotationNecessary)
        << result.diagnostic.toStdString();
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(result.durableDeletions, 0U);
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, EightVersionsDeleteOnlyTheOldest)
{
    createSet(8);
    const QString oldest = QDir(series).filePath(managedName(0));
    const QByteArray publishedDigest = digest(publishedPath);
    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.deleted.front().path, oldest);
    EXPECT_EQ(result.durableDeletions, 1U);
    EXPECT_FALSE(QFileInfo::exists(oldest));
    EXPECT_EQ(managedFiles().size(), 7);
    EXPECT_EQ(digest(publishedPath), publishedDigest);
}

TEST_F(BackupSeriesRotationServiceTest, TenVersionsReturnToSeven)
{
    createSet(10);
    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    ASSERT_EQ(result.deleted.size(), 3);
    EXPECT_EQ(result.durableDeletions, 3U);
    EXPECT_EQ(result.deleted[0].fileName, managedName(0));
    EXPECT_EQ(result.deleted[1].fileName, managedName(1));
    EXPECT_EQ(result.deleted[2].fileName, managedName(2));
    EXPECT_EQ(managedFiles().size(), 7);
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
}

TEST_F(BackupSeriesRotationServiceTest, RetentionAboveSevenIsAppliedExactly)
{
    createSet(10);
    request.retainedVersions = 8;
    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    EXPECT_EQ(result.deleted.size(), 2);
    EXPECT_EQ(result.durableDeletions, 2U);
    EXPECT_EQ(managedFiles().size(), 8);
}

TEST_F(BackupSeriesRotationServiceTest, RetentionBelowSevenRefusesEverything)
{
    createSet(8);
    request.retainedVersions = 6;
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, Uint64MaxRetentionDoesNotOverflow)
{
    createSet(10);
    request.retainedVersions = std::numeric_limits<quint64>::max();
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome,
        BackupSeriesRotationOutcome::NoRotationNecessary)
        << result.diagnostic.toStdString();
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, OtherSeriesIsStrictlyUntouched)
{
    createSet(8);
    BackupInstallationIdentity otherInstallation{
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
        QByteArray(BackupSeriesIdentityService::InstallationIdentitySize, '\x62')};
    QString otherId;
    QString error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        otherInstallation, vaultId, otherId, error));
    const QString otherSeries = QDir(family).filePath(otherId);
    ASSERT_TRUE(QDir().mkpath(otherSeries));
    ASSERT_TRUE(makePrivateDirectory(otherSeries));
    for (int offset = 100; offset < 110; ++offset)
        copyBackup(offset, {}, otherSeries);
    const auto before = treeEntries(otherSeries);
    const QByteArray retainedDigest = digest(
        QDir(otherSeries).filePath(managedName(100)));

    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    EXPECT_EQ(treeEntries(otherSeries), before);
    EXPECT_EQ(digest(QDir(otherSeries).filePath(managedName(100))),
        retainedDigest);
}

TEST_F(BackupSeriesRotationServiceTest, LegacyFamilyBackupIsUntouched)
{
    createSet(8);
    const QString legacy = QDir(family).filePath(managedName(100));
    ASSERT_TRUE(QFile::copy(templateVault, legacy));
    ASSERT_TRUE(QFile::setPermissions(legacy,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    const QByteArray before = digest(legacy);

    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    EXPECT_TRUE(QFileInfo::exists(legacy));
    EXPECT_EQ(digest(legacy), before);
}

TEST_F(BackupSeriesRotationServiceTest, LegacyNamesInTheSeriesRemainUntouched)
{
    createSet(8);
    const QString legacy = QDir(series).filePath(QStringLiteral("2026-01-01_00-00-00.pwdb"));
    ASSERT_TRUE(QFile::copy(templateVault, legacy));
    ASSERT_TRUE(QFile::setPermissions(legacy, QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    const auto before = digest(legacy);
    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.deleted.front().fileName, managedName(0));
    EXPECT_TRUE(QFileInfo::exists(legacy));
    EXPECT_EQ(digest(legacy), before);
    EXPECT_EQ(managedFiles().size(), 8);
}

TEST_F(BackupSeriesRotationServiceTest, DuplicateGenerationPreventsDeletion)
{
    createSet(8);
    const QString duplicate = QDir(series).filePath(
        QStringLiteral("generation_1_2027-01-01_00-00-00.pwdb"));
    ASSERT_TRUE(QFile::copy(templateVault, duplicate));
    ASSERT_TRUE(QFile::setPermissions(duplicate, QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, NewlyPublishedBackupIsAlwaysPreserved)
{
    createSet(8);
    const BackupFileEvidence evidence = *request.publication.receipt;
    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    BackupFileEvidence after;
    QString error;
    ASSERT_TRUE(BackupPublicationVerifier::inspectEncryptedFile(
        publishedPath, after, error));
    EXPECT_EQ(after, evidence);
}

TEST_F(BackupSeriesRotationServiceTest,
    PublicationNumberAmongOldestRefusesEverything)
{
    publishedPath = copyBackup(0);
    for (int offset = 1; offset < 8; ++offset) copyBackup(offset);
    request.publication = publicationFor(publishedPath);
    const auto before = managedFiles();

    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_TRUE(result.diagnostic.contains(QStringLiteral("numéro de génération")));
    EXPECT_EQ(managedFiles(), before);
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
}

TEST_F(BackupSeriesRotationServiceTest,
    MissingInconsistentOrUncertainPublicationNeverAuthorizesRotation)
{
    createSet(8);
    const auto before = managedFiles();
    const BackupResult valid = request.publication;

    request.publication.receipt.reset();
    EXPECT_EQ(BackupSeriesRotationService::rotate(request).outcome,
        BackupSeriesRotationOutcome::Refused);

    request.publication = valid;
    ++request.publication.receipt->inode;
    EXPECT_EQ(BackupSeriesRotationService::rotate(request).outcome,
        BackupSeriesRotationOutcome::Refused);

    request.publication = valid;
    request.publication.outcome = BackupOutcome::DurabilityUnconfirmed;
    EXPECT_EQ(BackupSeriesRotationService::rotate(request).outcome,
        BackupSeriesRotationOutcome::Refused);

    request.publication = valid;
    request.publication.outcome = BackupOutcome::Unknown;
    EXPECT_EQ(BackupSeriesRotationService::rotate(request).outcome,
        BackupSeriesRotationOutcome::Refused);
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, CanonicalSymlinkBlocksAllDeletion)
{
    createSet(7);
    const QString link = QDir(series).filePath(managedName(100));
    ASSERT_EQ(::symlink(QFile::encodeName(templateVault).constData(),
        QFile::encodeName(link).constData()), 0);
    const auto before = treeEntries(series);
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(treeEntries(series), before);
}

TEST_F(BackupSeriesRotationServiceTest, IncorrectPermissionsBlockAllDeletion)
{
    createSet(7);
    const QString permissive = copyBackup(100);
    ASSERT_TRUE(QFile::setPermissions(permissive,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner
            | QFileDevice::ReadGroup));
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, OldInvalidContentsDoNotBlockRotation)
{
    createSet(8);
    const QString oldest = QDir(series).filePath(managedName(0));
    const QString retained = QDir(series).filePath(managedName(1));
    // Both the deletion candidate and a retained old version contain invalid
    // data. Rotation must not screen either file for SQLite integrity.
    for (const auto& path : {oldest, retained}) {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(file.write("invalid"), 7);
    }
    const auto retainedDigest = digest(retained);
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete);
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.deleted.front().path, oldest);
    EXPECT_EQ(result.durableDeletions, 1U);
    EXPECT_FALSE(QFileInfo::exists(oldest));
    EXPECT_EQ(digest(retained), retainedDigest);
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    EXPECT_EQ(managedFiles().size(), 7);
}

TEST_F(BackupSeriesRotationServiceTest, OldVaultIdIsNotReadDuringRotation)
{
    const QString other = createVault(QStringLiteral("other.pwdb"), 0x52);
    const QString oldest = copyBackup(0, other);
    for (int offset = 1; offset < 8; ++offset) copyBackup(offset);
    publishedPath = QDir(series).filePath(managedName(7));
    request.publication = publicationFor(publishedPath);
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete);
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.deleted.front().path, oldest);
    EXPECT_FALSE(QFileInfo::exists(oldest));
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    EXPECT_EQ(managedFiles().size(), 7);
}

TEST_F(BackupSeriesRotationServiceTest, NewInvalidPublicationBlocksAllDeletion)
{
    createSet(8);
    QFile file(publishedPath);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(file.write("invalid"), 7);
    file.close();
    // A matching byte-level receipt alone cannot prove SQLite compatibility.
    request.publication = publicationFor(publishedPath);
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, NewPublicationWithWrongVaultIdBlocksAllDeletion)
{
    createSet(7);
    const QString other = createVault(QStringLiteral("other.pwdb"), 0x52);
    publishedPath = copyBackup(7, other);
    request.publication = publicationFor(publishedPath);
    const auto before = managedFiles();
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(managedFiles(), before);
}

TEST_F(BackupSeriesRotationServiceTest, OldSqliteJournalPreventsDeletion)
{
    createSet(8);
    const QString oldest = QDir(series).filePath(managedName(0));
    QFile journal(oldest + QStringLiteral("-journal"));
    ASSERT_TRUE(journal.open(QIODevice::WriteOnly | QIODevice::NewOnly));
    ASSERT_EQ(journal.write("journal"), 7);
    journal.close();
    const auto before = treeEntries(series);
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(treeEntries(series), before);
}

TEST_F(BackupSeriesRotationServiceTest, CandidateSubstitutionBeforeUnlinkIsRefused)
{
    createSet(8);
    const QString candidate = QDir(series).filePath(managedName(0));
    const QByteArray candidateDigest = digest(candidate);
    RotationAction action;
    action.action = ConcurrentAction::SubstituteCandidate;
    action.candidate = candidate;
    action.movedCandidate = candidate + QStringLiteral(".old");
    action.replacement = createVault(QStringLiteral("replacement.pwdb"), 0x51);
    request.control = {rotationAction, &action};

    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_TRUE(action.invoked);
    EXPECT_TRUE(action.succeeded);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_TRUE(QFileInfo::exists(candidate));
    EXPECT_TRUE(QFileInfo::exists(action.movedCandidate));
    EXPECT_EQ(digest(action.movedCandidate), candidateDigest);
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
}

TEST_F(BackupSeriesRotationServiceTest, CandidateDisappearanceBeforeUnlinkIsRefused)
{
    createSet(8);
    RotationAction action;
    action.action = ConcurrentAction::RemoveCandidate;
    action.candidate = QDir(series).filePath(managedName(0));
    request.control = {rotationAction, &action};

    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_TRUE(action.invoked);
    EXPECT_TRUE(action.succeeded);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    EXPECT_EQ(managedFiles().size(), 7);
}

TEST_F(BackupSeriesRotationServiceTest, SeriesReplacementBeforeUnlinkIsRefused)
{
    createSet(8);
    RotationAction action;
    action.action = ConcurrentAction::ReplaceSeries;
    action.candidate = QDir(series).filePath(managedName(0));
    action.series = series;
    action.movedSeries = series + QStringLiteral(".old");
    request.control = {rotationAction, &action};

    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_TRUE(action.invoked);
    EXPECT_TRUE(action.succeeded);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_TRUE(QFileInfo::exists(
        QDir(action.movedSeries).filePath(managedName(0))));
    EXPECT_TRUE(QFileInfo::exists(
        QDir(action.movedSeries).filePath(managedName(7))));
}

TEST_F(BackupSeriesRotationServiceTest, UnlinkFailureDeletesNothing)
{
    createSet(8);
    const auto before = managedFiles();
    failManagedUnlinkOnCall = 1;
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Refused);
    EXPECT_TRUE(result.deleted.isEmpty());
    EXPECT_EQ(result.durableDeletions, 0U);
    EXPECT_EQ(managedFiles(), before);
    EXPECT_TRUE(result.diagnostic.contains(QStringLiteral("errno")));
}

TEST_F(BackupSeriesRotationServiceTest,
    SecondUnlinkFailureReportsOnlyTheFirstDurableDeletion)
{
    createSet(10);
    failManagedUnlinkOnCall = 2;
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Partial);
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.deleted.front().fileName, managedName(0));
    EXPECT_EQ(result.durableDeletions, 1U);
    EXPECT_FALSE(QFileInfo::exists(
        QDir(series).filePath(managedName(0))));
    EXPECT_TRUE(QFileInfo::exists(
        QDir(series).filePath(managedName(1))));
    EXPECT_EQ(managedFiles().size(), 9);
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    EXPECT_TRUE(result.diagnostic.contains(QStringLiteral("errno")));
}

TEST_F(BackupSeriesRotationServiceTest,
    DirectorySyncFailureReportsPerformedButUnconfirmedDeletion)
{
    createSet(8);
    const QString oldest = QDir(series).filePath(managedName(0));
    failNextDirectorySync = true;
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_EQ(result.outcome,
        BackupSeriesRotationOutcome::DeletionDurabilityUnconfirmed);
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.deleted.front().path, oldest);
    EXPECT_EQ(result.durableDeletions, 0U);
    EXPECT_FALSE(QFileInfo::exists(oldest));
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    EXPECT_TRUE(result.diagnostic.contains(QStringLiteral("errno")));
}

TEST_F(BackupSeriesRotationServiceTest,
    InterruptionAfterFirstConfirmedDeletionIsPartialWithoutRetry)
{
    createSet(10);
    RotationAction action;
    action.action = ConcurrentAction::StopAfterDeletion;
    request.control = {rotationAction, &action};
    const auto result = BackupSeriesRotationService::rotate(request);
    EXPECT_TRUE(action.invoked);
    EXPECT_EQ(result.outcome, BackupSeriesRotationOutcome::Partial);
    ASSERT_EQ(result.deleted.size(), 1);
    EXPECT_EQ(result.durableDeletions, 1U);
    EXPECT_EQ(managedFiles().size(), 9);
    EXPECT_FALSE(QFileInfo::exists(
        QDir(series).filePath(managedName(0))));
    EXPECT_TRUE(QFileInfo::exists(
        QDir(series).filePath(managedName(1))));
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
}

TEST_F(BackupSeriesRotationServiceTest, PreferencesAndRegistryFilesAreNeverTouched)
{
    createSet(8);
    const QString passwall = temporary.filePath(QStringLiteral("PassWall.conf"));
    const QString global = temporary.filePath(
        QStringLiteral("BackupPreferences.ini"));
    const QString vaultRegistry = temporary.filePath(
        QStringLiteral("vaultRegistry/data"));
    const QString rotationCatalog = temporary.filePath(
        QStringLiteral("rotation-catalog"));
    ASSERT_TRUE(QDir().mkpath(QFileInfo(vaultRegistry).absolutePath()));
    const std::array sentinels{
        std::pair{passwall, QByteArrayLiteral("passwall-sentinel")},
        std::pair{global, QByteArrayLiteral("global-sentinel")},
        std::pair{vaultRegistry, QByteArrayLiteral("registry-sentinel")},
        std::pair{rotationCatalog, QByteArrayLiteral("catalog-sentinel")}};
    for (const auto& item : sentinels) {
        QFile file(item.first);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::NewOnly));
        ASSERT_EQ(file.write(item.second), item.second.size());
    }
    std::array<QByteArray, 4> before;
    for (std::size_t index = 0; index < sentinels.size(); ++index)
        before[index] = digest(sentinels[index].first);

    const auto result = BackupSeriesRotationService::rotate(request);
    ASSERT_EQ(result.outcome, BackupSeriesRotationOutcome::Complete)
        << result.diagnostic.toStdString();
    for (std::size_t index = 0; index < sentinels.size(); ++index)
        EXPECT_EQ(digest(sentinels[index].first), before[index]);
}

} // namespace
