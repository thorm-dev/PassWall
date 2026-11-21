#include "services/initial_backup_preparer.hpp"
#include "services/backup_job.hpp"
#include "services/vault_key_service.hpp"
#include "services/vault_preferences_store.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>
#include <sqlite3.h>

#include <QDate>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QTemporaryDir>
#include <QThread>
#include <QTime>
#include <QTimeZone>

#include <string>

#ifdef Q_OS_UNIX
#include <sys/stat.h>
#endif

using passwall::services::AuthenticatedBackupSession;
using passwall::services::BackupJob;
using passwall::services::BackupOutcome;
using passwall::services::BackupResult;
using passwall::services::BackupTriggerMode;
using passwall::services::GlobalBackupPreferencesResult;
using passwall::services::GlobalBackupPreferencesStatus;
using passwall::services::InitialBackupCancellation;
using passwall::services::InitialBackupAdmission;
using passwall::services::InitialBackupCheckpoint;
using passwall::services::InitialBackupDecision;
using passwall::services::InitialBackupPreparer;
using passwall::services::VaultFileIdentity;
using passwall::services::VaultKeyMetadata;
using passwall::services::VaultPreferencesStore;

namespace {

bool until(const std::function<bool()>& predicate, int limit = 5000)
{
    QElapsedTimer timer;
    timer.start();
    while (!predicate() && timer.elapsed() < limit) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return predicate();
}

void insertFictitiousEntry(const QString& path)
{
    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open_v2(QFile::encodeName(path).constData(), &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW,
        nullptr), SQLITE_OK);
    ASSERT_NE(database, nullptr);
    char* message = nullptr;
    const int code = sqlite3_exec(database,
        "INSERT INTO entries(entry_id,entry_version,nonce,ciphertext) "
        "VALUES(randomblob(16),1,randomblob(24),randomblob(32));",
        nullptr, nullptr, &message);
    const std::string diagnostic = message == nullptr ? std::string{} : message;
    sqlite3_free(message);
    EXPECT_EQ(code, SQLITE_OK) << diagnostic;
    EXPECT_EQ(sqlite3_close(database), SQLITE_OK);
}

void copyAsManagedBackup(const QString& source, const QString& destination)
{
    ASSERT_TRUE(QFile::copy(source, destination));
    ASSERT_TRUE(QFile::setPermissions(destination,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
}

struct CancellationContext {
    InitialBackupCheckpoint checkpoint = InitialBackupCheckpoint::BeforeInspection;
    QString source;
    QString replacement;
    QString family;
    bool substituteSource = false;
    bool substituteFamily = false;
    bool invoked = false;
    bool cancel = false;
};

bool cancellationAction(void* raw, quint64, InitialBackupCheckpoint checkpoint) noexcept
{
    auto& context = *static_cast<CancellationContext*>(raw);
    if (checkpoint != context.checkpoint) return false;
    context.invoked = true;
    if (context.substituteSource) {
        const QString old = context.source + QStringLiteral(".old");
        context.invoked = QFile::rename(context.source, old)
            && QFile::rename(context.replacement, context.source);
    }
    if (context.substituteFamily) {
        const QString old = context.family + QStringLiteral(".old");
        context.invoked = QDir().rename(context.family, old)
            && QDir().mkpath(context.family)
            && QFile::setPermissions(context.family,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner
                    | QFileDevice::ExeOwner);
    }
    return context.cancel;
}

bool sessionRemainsCurrent(void*, quint64, InitialBackupCheckpoint) noexcept
{
    return false;
}

class InitialBackupPreparerTest : public ::testing::Test {
protected:
    QTemporaryDir temporary{QStringLiteral("/tmp/passwall-initial-backup-XXXXXX")};
    QString root;
    QString error;
    GlobalBackupPreferencesResult configuration;
    QDateTime timestamp{QDate(2026, 11, 21), QTime(10, 11, 12), QTimeZone::utc()};

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

    QString createVault(const QString& name, unsigned char vaultByte, bool populated)
    {
        const QString path = temporary.filePath(name);
        std::string failure;
        EXPECT_TRUE(passwall::storage::VaultStorage::createSchema(
            path.toStdString(), failure)) << failure;
        VaultKeyMetadata metadata;
        metadata.vaultId.fill(vaultByte);
        EXPECT_TRUE(passwall::storage::VaultStorage::writeMetadata(
            path.toStdString(), metadata, failure)) << failure;
        if (populated) insertFictitiousEntry(path);
        return path;
    }

    AuthenticatedBackupSession sessionFor(const QString& path,
        quint64 sessionGeneration = 1, quint64 pendingMutation = 0)
    {
        VaultFileIdentity identity;
        EXPECT_TRUE(VaultPreferencesStore::inspectVault(path, identity, error))
            << error.toStdString();
        return {identity, sessionGeneration, pendingMutation, true};
    }

    QString familyFor(const AuthenticatedBackupSession& session,
        const QString& selectedRoot = {}) const
    {
        return QDir(selectedRoot.isEmpty() ? root : selectedRoot).filePath(
            QString::fromLatin1(session.vault.vaultId.toHex()));
    }

    void createFamily(const QString& family)
    {
        ASSERT_TRUE(QDir().mkpath(family));
        ASSERT_TRUE(QFile::setPermissions(family,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    }

    InitialBackupCancellation currentSession() const
    {
        return {sessionRemainsCurrent, nullptr};
    }

    InitialBackupAdmission admissionFor(const AuthenticatedBackupSession& session) const
    {
        return {session.vault, session.sessionGeneration,
            BackupTriggerMode::Generational, true, false, true};
    }

    void setWorkerMode(const QString& source, const QByteArray& mode)
    {
        QFile selection(source + QStringLiteral(".fake-mode"));
        ASSERT_TRUE(selection.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(selection.write(mode), mode.size());
        selection.close();
    }
};

TEST_F(InitialBackupPreparerTest, EmptyVaultDoesNotPrepareARequest)
{
    const auto session = sessionFor(createVault(QStringLiteral("empty.pwdb"), 0x11, false));
    const auto result = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    EXPECT_EQ(result.decision, InitialBackupDecision::EmptyVault);
    EXPECT_FALSE(result.request.has_value());
    EXPECT_FALSE(QFileInfo::exists(familyFor(session)));
}

TEST_F(InitialBackupPreparerTest, PopulatedVaultWithoutBackupPreparesFirstRequestOnly)
{
    const auto session = sessionFor(createVault(QStringLiteral("vault.pwdb"), 0x22, true), 7);
    auto result = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    ASSERT_EQ(result.decision, InitialBackupDecision::Prepared)
        << result.diagnostic.toStdString();
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->sessionGeneration(), 7U);
    EXPECT_EQ(result.request->destination().bindingGeneration(), 7U);
    EXPECT_EQ(result.request->destination().vaultId(), session.vault.vaultId);
    EXPECT_FALSE(QFileInfo::exists(result.request->destination().destinationPath()));
}

TEST_F(InitialBackupPreparerTest, ExistingAdmissibleBackupSuppressesFirstRequest)
{
    const QString source = createVault(QStringLiteral("vault.pwdb"), 0x33, true);
    const auto session = sessionFor(source);
    const QString family = familyFor(session);
    createFamily(family);
    copyAsManagedBackup(source,
        QDir(family).filePath(QStringLiteral("2026-11-20_10-00-00.pwdb")));

    const auto result = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    EXPECT_EQ(result.decision, InitialBackupDecision::ExistingAdmissibleBackup);
    EXPECT_FALSE(result.request.has_value());
}

TEST_F(InitialBackupPreparerTest, ChangedRootRequiresANewFirstCopy)
{
    const QString source = createVault(QStringLiteral("vault.pwdb"), 0x44, true);
    const auto session = sessionFor(source);
    const QString oldFamily = familyFor(session);
    createFamily(oldFamily);
    copyAsManagedBackup(source,
        QDir(oldFamily).filePath(QStringLiteral("2026-11-20_10-00-00.pwdb")));

    const QString newRoot = temporary.filePath(QStringLiteral("new-backups"));
    ASSERT_TRUE(QDir().mkpath(newRoot));
    ASSERT_TRUE(QFile::setPermissions(newRoot,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
    configuration.preferences.rootDirectory = newRoot;
    auto result = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    ASSERT_EQ(result.decision, InitialBackupDecision::Prepared)
        << result.diagnostic.toStdString();
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->destination().rootDirectory(), newRoot);
    EXPECT_TRUE(QFileInfo::exists(
        QDir(oldFamily).filePath(QStringLiteral("2026-11-20_10-00-00.pwdb"))));
}

TEST_F(InitialBackupPreparerTest, CopiesWithSameVaultIdShareExistingFamilyEvidence)
{
    const QString first = createVault(QStringLiteral("first.pwdb"), 0x55, true);
    const QString second = createVault(QStringLiteral("second.pwdb"), 0x55, true);
    const auto firstSession = sessionFor(first);
    const auto secondSession = sessionFor(second, 2);
    ASSERT_NE(firstSession.vault.inode, secondSession.vault.inode);
    const QString family = familyFor(firstSession);
    createFamily(family);
    copyAsManagedBackup(first,
        QDir(family).filePath(QStringLiteral("2026-11-20_10-00-00.pwdb")));

    const auto result = InitialBackupPreparer::prepare(
        configuration, secondSession, timestamp, currentSession());
    EXPECT_EQ(result.decision, InitialBackupDecision::ExistingAdmissibleBackup);
}

TEST_F(InitialBackupPreparerTest, MissingOrInvalidConfigurationDoesNotPrepare)
{
    const auto session = sessionFor(createVault(QStringLiteral("vault.pwdb"), 0x66, true));
    configuration.status = GlobalBackupPreferencesStatus::Absent;
    EXPECT_EQ(InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession()).decision,
        InitialBackupDecision::ConfigurationUnavailable);
    configuration.status = GlobalBackupPreferencesStatus::Invalid;
    EXPECT_EQ(InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession()).decision,
        InitialBackupDecision::ConfigurationUnavailable);
    EXPECT_FALSE(QFileInfo::exists(familyFor(session)));
}

TEST_F(InitialBackupPreparerTest, PendingMutationCoversFirstCopyWithoutDuplicateRequest)
{
    const auto session = sessionFor(
        createVault(QStringLiteral("vault.pwdb"), 0x77, true), 3, 9);
    const auto result = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    EXPECT_EQ(result.decision, InitialBackupDecision::CoveredByPendingMutation);
    EXPECT_FALSE(result.request.has_value());
    EXPECT_FALSE(QFileInfo::exists(familyFor(session)));
}

TEST_F(InitialBackupPreparerTest, SourceSubstitutionDuringInspectionIsRefused)
{
    const QString source = createVault(QStringLiteral("vault.pwdb"), 0x81, true);
    const QString replacement = createVault(QStringLiteral("replacement.pwdb"), 0x81, true);
    const auto session = sessionFor(source);
    CancellationContext context{InitialBackupCheckpoint::BeforeDestinationPreparation,
        source, replacement, {}, true, false, false, false};
    const auto result = InitialBackupPreparer::prepare(configuration, session, timestamp,
        InitialBackupCancellation{cancellationAction, &context});
    EXPECT_TRUE(context.invoked);
    EXPECT_EQ(result.decision, InitialBackupDecision::Refused);
    EXPECT_FALSE(result.request.has_value());
}

TEST_F(InitialBackupPreparerTest, FamilySubstitutionDuringInspectionIsRefused)
{
    const QString source = createVault(QStringLiteral("vault.pwdb"), 0x82, true);
    const auto session = sessionFor(source);
    const QString family = familyFor(session);
    createFamily(family);
    QFile irrelevant(QDir(family).filePath(QStringLiteral("readme.txt")));
    ASSERT_TRUE(irrelevant.open(QIODevice::WriteOnly));
    irrelevant.close();
    CancellationContext context{InitialBackupCheckpoint::BeforeDestinationPreparation,
        {}, {}, family, false, true, false, false};
    const auto result = InitialBackupPreparer::prepare(configuration, session, timestamp,
        InitialBackupCancellation{cancellationAction, &context});
    EXPECT_TRUE(context.invoked);
    EXPECT_EQ(result.decision, InitialBackupDecision::Refused);
}

TEST_F(InitialBackupPreparerTest, ClosedSessionCancelsInspectionWithoutARequest)
{
    const QString source = createVault(QStringLiteral("vault.pwdb"), 0x83, true);
    const auto session = sessionFor(source, 42);
    const QString family = familyFor(session);
    createFamily(family);
    QFile candidate(QDir(family).filePath(QStringLiteral("2026-11-20_10-00-00.pwdb")));
    ASSERT_TRUE(candidate.open(QIODevice::WriteOnly));
    ASSERT_EQ(candidate.write("invalid"), 7);
    candidate.close();
    CancellationContext context{InitialBackupCheckpoint::DuringFamilyInspection,
        {}, {}, {}, false, false, false, true};
    const auto result = InitialBackupPreparer::prepare(configuration, session, timestamp,
        InitialBackupCancellation{cancellationAction, &context});
    EXPECT_TRUE(context.invoked);
    EXPECT_EQ(result.decision, InitialBackupDecision::Cancelled);
    EXPECT_FALSE(result.request.has_value());
}

TEST_F(InitialBackupPreparerTest, FinalAdmissionTransfersTheExistingCapabilityOnlyOnce)
{
    const auto session = sessionFor(
        createVault(QStringLiteral("transfer.pwdb"), 0x91, true), 17);
    auto preparation = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    ASSERT_EQ(preparation.decision, InitialBackupDecision::Prepared);
    ASSERT_TRUE(preparation.request.has_value());
    const QString destination = preparation.request->destination().destinationPath();
    setWorkerMode(session.vault.path, QByteArrayLiteral("slow-snapshot-published-file"));

    BackupJob job(QString::fromLatin1(INITIAL_FAKE_BACKUP_WORKER));
    std::optional<BackupResult> result;
    bool terminated = false;
    QObject::connect(&job, &BackupJob::finished, &job,
        [&](BackupResult value) { result = std::move(value); });
    QObject::connect(&job, &BackupJob::processTerminated, &job,
        [&] { terminated = true; });
    auto admission = admissionFor(session);
    ASSERT_TRUE(preparation.request->admitAndStart(job, admission, error))
        << error.toStdString();
    EXPECT_TRUE(preparation.request->consumed());

    passwall::storage::VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_FALSE(exclusive.tryReserve(session.vault.path.toStdString(), reservationError));
    EXPECT_TRUE(exclusive.contended());

    BackupJob second(QString::fromLatin1(INITIAL_FAKE_BACKUP_WORKER));
    QString secondError;
    EXPECT_FALSE(preparation.request->admitAndStart(second, admission, secondError));
    EXPECT_TRUE(secondError.contains(QStringLiteral("déjà consommée")));

    ASSERT_TRUE(until([&] { return result.has_value() && terminated; }));
    EXPECT_EQ(result->outcome, BackupOutcome::Published)
        << result->diagnostic.toStdString();
    EXPECT_TRUE(QFileInfo::exists(destination));
    reservationError.clear();
    EXPECT_TRUE(exclusive.tryReserve(session.vault.path.toStdString(), reservationError))
        << reservationError;
}

TEST_F(InitialBackupPreparerTest, RefusedAdmissionConsumesAndReleasesThePreparation)
{
    const auto session = sessionFor(
        createVault(QStringLiteral("refused.pwdb"), 0x92, true), 18);
    auto preparation = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    ASSERT_TRUE(preparation.request.has_value());
    auto admission = admissionFor(session);
    admission.triggerMode = BackupTriggerMode::Historical;
    BackupJob job(QStringLiteral("/worker-not-used"));
    EXPECT_FALSE(preparation.request->admitAndStart(job, admission, error));
    EXPECT_TRUE(preparation.request->consumed());

    passwall::storage::VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(session.vault.path.toStdString(), reservationError))
        << reservationError;
    EXPECT_FALSE(preparation.request->admitAndStart(job, admission, error));
    EXPECT_TRUE(error.contains(QStringLiteral("déjà consommée")));
}

TEST_F(InitialBackupPreparerTest, ClosingOrChangedSessionCannotAdmitPreparedRequest)
{
    for (const bool closing : {true, false}) {
        const auto session = sessionFor(createVault(
            closing ? QStringLiteral("closing.pwdb") : QStringLiteral("changed.pwdb"),
            closing ? 0x93 : 0x94, true), closing ? 19 : 20);
        auto preparation = InitialBackupPreparer::prepare(
            configuration, session, timestamp.addSecs(closing ? 0 : 1), currentSession());
        ASSERT_TRUE(preparation.request.has_value());
        auto admission = admissionFor(session);
        admission.closing = closing;
        if (!closing) {
            admission.sessionCurrent = false;
            ++admission.currentSessionGeneration;
        }
        BackupJob job(QStringLiteral("/worker-not-used"));
        EXPECT_FALSE(preparation.request->admitAndStart(job, admission, error));
        passwall::storage::VaultOperationGuard exclusive;
        std::string reservationError;
        EXPECT_TRUE(exclusive.tryReserve(session.vault.path.toStdString(), reservationError))
            << reservationError;
    }
}

TEST_F(InitialBackupPreparerTest, IncompatibleOperationCannotAdmitPreparedRequest)
{
    const auto session = sessionFor(
        createVault(QStringLiteral("incompatible.pwdb"), 0x95, true), 21);
    auto preparation = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    ASSERT_TRUE(preparation.request.has_value());
    auto admission = admissionFor(session);
    admission.operationAdmissible = false;
    BackupJob job(QStringLiteral("/worker-not-used"));
    EXPECT_FALSE(preparation.request->admitAndStart(job, admission, error));
    passwall::storage::VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(session.vault.path.toStdString(), reservationError))
        << reservationError;
}

TEST_F(InitialBackupPreparerTest, FinalAdmissionRefusesSourceRootAndFamilySubstitution)
{
    enum class Substitution { Source, Root, Family };
    int index = 0;
    for (const auto substitution : {Substitution::Source, Substitution::Root, Substitution::Family}) {
        ++index;
        const QString source = createVault(
            QStringLiteral("substitution-%1.pwdb").arg(index),
            static_cast<unsigned char>(0xa0 + index), true);
        const auto session = sessionFor(source, static_cast<quint64>(30 + index));
        auto preparation = InitialBackupPreparer::prepare(
            configuration, session, timestamp.addSecs(index), currentSession());
        ASSERT_TRUE(preparation.request.has_value());
        auto admission = admissionFor(session);
        if (substitution == Substitution::Source) {
            ASSERT_TRUE(QFile::rename(source, source + QStringLiteral(".old")));
            ASSERT_EQ(createVault(QFileInfo(source).fileName(),
                static_cast<unsigned char>(0xa0 + index), true), source);
            admission.currentVault = sessionFor(source).vault;
        } else if (substitution == Substitution::Root) {
            ASSERT_TRUE(QDir().rename(root, root + QStringLiteral(".old")));
            ASSERT_TRUE(QDir().mkpath(root));
            ASSERT_TRUE(QFile::setPermissions(root,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
        } else {
            const QString family = preparation.request->destination().familyDirectory();
            ASSERT_TRUE(QDir().rename(family, family + QStringLiteral(".old")));
            ASSERT_TRUE(QDir().mkpath(family));
            ASSERT_TRUE(QFile::setPermissions(family,
                QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner));
        }
        BackupJob job(QStringLiteral("/worker-not-used"));
        EXPECT_FALSE(preparation.request->admitAndStart(job, admission, error));
        passwall::storage::VaultOperationGuard exclusive;
        std::string reservationError;
        EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
            << reservationError;
    }
}

TEST_F(InitialBackupPreparerTest, FinalAdmissionRefusesVaultIdOrOccupiedDestination)
{
    const auto wrongIdentitySession = sessionFor(
        createVault(QStringLiteral("wrong-vault-id.pwdb"), 0xb0, true), 39);
    auto wrongIdentity = InitialBackupPreparer::prepare(
        configuration, wrongIdentitySession, timestamp, currentSession());
    ASSERT_TRUE(wrongIdentity.request.has_value());
    auto wrongAdmission = admissionFor(wrongIdentitySession);
    wrongAdmission.currentVault.vaultId.fill('\x7f');
    BackupJob firstJob(QStringLiteral("/worker-not-used"));
    EXPECT_FALSE(wrongIdentity.request->admitAndStart(firstJob, wrongAdmission, error));

    const auto occupiedSession = sessionFor(
        createVault(QStringLiteral("occupied.pwdb"), 0xb4, true), 40);
    auto occupied = InitialBackupPreparer::prepare(
        configuration, occupiedSession, timestamp.addSecs(1), currentSession());
    ASSERT_TRUE(occupied.request.has_value());
    QFile destination(occupied.request->destination().destinationPath());
    ASSERT_TRUE(destination.open(QIODevice::WriteOnly | QIODevice::NewOnly));
    ASSERT_EQ(destination.write("occupied"), 8);
    destination.close();
    BackupJob secondJob(QStringLiteral("/worker-not-used"));
    EXPECT_FALSE(occupied.request->admitAndStart(
        secondJob, admissionFor(occupiedSession), error));
    QFile verify(destination.fileName());
    ASSERT_TRUE(verify.open(QIODevice::ReadOnly));
    EXPECT_EQ(verify.readAll(), QByteArrayLiteral("occupied"));
}

TEST_F(InitialBackupPreparerTest, CancellationBeforeAndAfterAdmissionReleasesReservation)
{
    const auto before = sessionFor(
        createVault(QStringLiteral("before-cancel.pwdb"), 0xb1, true), 41);
    {
        auto preparation = InitialBackupPreparer::prepare(
            configuration, before, timestamp, currentSession());
        ASSERT_TRUE(preparation.request.has_value());
    }
    passwall::storage::VaultOperationGuard beforeExclusive;
    std::string reservationError;
    ASSERT_TRUE(beforeExclusive.tryReserve(before.vault.path.toStdString(), reservationError))
        << reservationError;
    beforeExclusive.reset();

    const auto after = sessionFor(
        createVault(QStringLiteral("after-cancel.pwdb"), 0xb2, true), 42);
    auto preparation = InitialBackupPreparer::prepare(
        configuration, after, timestamp.addSecs(1), currentSession());
    ASSERT_TRUE(preparation.request.has_value());
    const QString afterDestination = preparation.request->destination().destinationPath();
    setWorkerMode(after.vault.path, QByteArrayLiteral("cancel"));
    BackupJob job(QString::fromLatin1(INITIAL_FAKE_BACKUP_WORKER));
    std::optional<BackupResult> result;
    bool terminated = false;
    QObject::connect(&job, &BackupJob::finished, &job,
        [&](BackupResult value) { result = std::move(value); });
    QObject::connect(&job, &BackupJob::processTerminated, &job,
        [&] { terminated = true; });
    ASSERT_TRUE(preparation.request->admitAndStart(job, admissionFor(after), error))
        << error.toStdString();
    ASSERT_TRUE(until([&] {
        return QFileInfo::exists(afterDestination + QStringLiteral(".ready"));
    }));
    job.cancel();
    ASSERT_TRUE(until([&] { return result.has_value() && terminated; }));
    EXPECT_EQ(result->outcome, BackupOutcome::CancelledBeforePublication);
    passwall::storage::VaultOperationGuard afterExclusive;
    reservationError.clear();
    EXPECT_TRUE(afterExclusive.tryReserve(after.vault.path.toStdString(), reservationError))
        << reservationError;
}

TEST_F(InitialBackupPreparerTest, SynchronousStartFailureConsumesAndReleasesCapability)
{
    const auto session = sessionFor(
        createVault(QStringLiteral("start-failure.pwdb"), 0xb3, true), 43);
    auto preparation = InitialBackupPreparer::prepare(
        configuration, session, timestamp, currentSession());
    ASSERT_TRUE(preparation.request.has_value());
    BackupJob invalidJob(QString{});
    EXPECT_FALSE(preparation.request->admitAndStart(
        invalidJob, admissionFor(session), error));
    EXPECT_TRUE(preparation.request->consumed());
    passwall::storage::VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(session.vault.path.toStdString(), reservationError))
        << reservationError;
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
