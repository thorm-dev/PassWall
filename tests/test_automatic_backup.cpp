#include "services/automatic_backup_coordinator.hpp"
#include "services/backup_destination_preparer.hpp"
#include "services/backup_job.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_storage.hpp"
#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QDir>
#include <QDateTime>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QCryptographicHash>
#include <QProcess>
#include <QSemaphore>
#include <QSettings>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>
#include <QTimeZone>
#include <QUuid>
#include <sodium.h>
#include <sqlite3.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <functional>
#include <cstdio>
#include <algorithm>
#include <atomic>
#include <memory>
#include <stdexcept>

using namespace passwall::services;
using passwall::storage::VaultOperationGuard;
namespace {
thread_local bool failCatalogue = false, unsupported = false, suppressStop = false, freezeTime = false;
thread_local int frozenYear = 2026;
thread_local QString configuration;
thread_local QPointer<QProcess> stuck;
bool until(const std::function<bool()>& test, int limit = 6000)
{
    QElapsedTimer elapsed; elapsed.start();
    while (!test() && elapsed.elapsed() < limit) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return test();
}
bool workerMarkerWithoutQtEvents(const QString& marker)
{
    // Test-only scheduling barrier: deliberately leave QProcess's cancellation
    // byte queued in Qt while the real child reaches its own marker. A bound
    // detects a failed probe; elapsed time is NOT used as evidence of ordering.
    QElapsedTimer elapsed; elapsed.start();
    while (!QFileInfo::exists(marker) && elapsed.elapsed() < 5000)
        QThread::msleep(1);
    return QFileInfo::exists(marker);
}
bool initialInspectionRemainsCurrent(
    void*, quint64, InitialBackupCheckpoint) noexcept
{
    return false;
}
struct CommitDuringInitialInspection {
    QString path;
    passwall::core::SecureBuffer* key = nullptr;
    bool attempted = false;
    bool committed = false;
};

struct AsyncInitialInspectionBarrier {
    InitialBackupCheckpoint checkpoint = InitialBackupCheckpoint::BeforeInspection;
    QSemaphore entered;
    QSemaphore resume;
    std::atomic_bool blocked{false};
    ~AsyncInitialInspectionBarrier() { resume.release(); }
};
bool waitAtInitialInspectionCheckpoint(
    void* raw, quint64, InitialBackupCheckpoint checkpoint) noexcept
{
    auto& barrier = *static_cast<AsyncInitialInspectionBarrier*>(raw);
    bool expected = false;
    if (checkpoint == barrier.checkpoint
        && barrier.blocked.compare_exchange_strong(expected, true)) {
        barrier.entered.release();
        barrier.resume.acquire();
    }
    return false;
}
bool commitDuringInitialInspection(
    void* raw, quint64, InitialBackupCheckpoint checkpoint) noexcept
{
    auto& context = *static_cast<CommitDuringInitialInspection*>(raw);
    if (checkpoint != InitialBackupCheckpoint::BeforeDestinationPreparation
        || context.attempted)
        return false;
    context.attempted = true;
    try {
        passwall::models::Credential credential;
        credential.title = "Fictitious concurrent mutation";
        credential.username = "fictitious-concurrent-user";
        credential.password = "fictitious-concurrent-password";
        std::string error;
        context.committed = context.key != nullptr
            && CredentialService::add(
                context.path.toStdString(), *context.key, credential, error);
        sodium_memzero(credential.password.data(), credential.password.size());
    } catch (...) {
        context.committed = false;
    }
    return false;
}
void touch(const QString& path, const QByteArray& value = {})
{
    QFile file(path); ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write(value), value.size());
}
QByteArray bytes(const QString& path)
{
    QFile file(path); if (!file.open(QIODevice::ReadOnly)) return {}; return file.readAll();
}
QByteArray encryptedRows(const QString& path)
{
    // SQLite backup may legitimately change header counters. Compare the real
    // encrypted records/metadata, not a byte-for-byte filesystem copy.
    sqlite3* raw = nullptr;
    const int opened = sqlite3_open_v2(QFile::encodeName(path).constData(), &raw, SQLITE_OPEN_READONLY, nullptr);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> db(raw, sqlite3_close_v2);
    EXPECT_EQ(opened, SQLITE_OK);
    if (opened != SQLITE_OK) return {};
    QByteArray rows;
    for (const char* sql : {"SELECT * FROM vault_metadata ORDER BY id", "SELECT * FROM entries ORDER BY entry_id"}) {
        sqlite3_stmt* statement = nullptr;
        const int prepared = sqlite3_prepare_v2(raw, sql, -1, &statement, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(statement, sqlite3_finalize);
        EXPECT_EQ(prepared, SQLITE_OK);
        if (prepared != SQLITE_OK) return {};
        int result;
        while ((result = sqlite3_step(statement)) == SQLITE_ROW)
            for (int column = 0; column < sqlite3_column_count(statement); ++column) {
                const int count = sqlite3_column_bytes(statement, column);
                rows += QByteArray::number(sqlite3_column_type(statement, column)) + ':'
                    + QByteArray::number(count) + ':';
                rows.append(static_cast<const char*>(sqlite3_column_blob(statement, column)), count);
            }
        EXPECT_EQ(result, SQLITE_DONE);
    }
    return rows;
}
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    if (failCatalogue) {
        char link[64], path[4096];
        std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        const auto count = ::readlink(link, path, sizeof(path));
        if (count > 0 && QByteArray(path, count) == QFile::encodeName(configuration)) {
            errno = EIO; return -1;
        }
    }
    return __real_fsync(fd);
}
extern "C" int __real_fstatfs(int, struct statfs*);
extern "C" int __wrap_fstatfs(int fd, struct statfs* output)
{
    const int result = __real_fstatfs(fd, output);
    if (result == 0 && unsupported) output->f_type = NFS_SUPER_MAGIC;
    return result;
}
extern "C" void realAutoKill(QProcess*) asm("__real__ZN8QProcess4killEv");
extern "C" void wrappedAutoKill(QProcess*) asm("__wrap__ZN8QProcess4killEv");
extern "C" void wrappedAutoKill(QProcess* process) { if (suppressStop) stuck = process; else realAutoKill(process); }
extern "C" void realAutoTerminate(QProcess*) asm("__real__ZN8QProcess9terminateEv");
extern "C" void wrappedAutoTerminate(QProcess*) asm("__wrap__ZN8QProcess9terminateEv");
extern "C" void wrappedAutoTerminate(QProcess* process) { if (suppressStop) stuck = process; else realAutoTerminate(process); }
extern "C" QDateTime realAutoTime() asm("__real__ZN9QDateTime15currentDateTimeEv");
extern "C" QDateTime wrappedAutoTime() asm("__wrap__ZN9QDateTime15currentDateTimeEv");
extern "C" QDateTime wrappedAutoTime()
{ return freezeTime ? QDateTime(QDate(frozenYear, 11, 8), QTime(14, 35, 22)) : realAutoTime(); }

namespace {
class AutomaticBackupTest : public ::testing::Test {
protected:
    QTemporaryDir temporary{QStringLiteral("/tmp/passwall-automatic-case-XXXXXX")};
    QString source, destination, error;
    VaultRegistration original;
    passwall::core::SecureBuffer key{0};
    std::unique_ptr<AutomaticBackupCoordinator> coordinator;
    int completions = 0, notices = 0, deferrals = 0;
    int mutationBatchRequests = 0;
    QString mutationBatchPath;
    QVector<quint64> mutationBatchGenerations;
    QVector<quint64> mutationBatchRequestIds;
    QVector<GenerationalBackupRequestKind> generationalRequestKinds;
    QVector<quint64> generationalSessionGenerations;
    QVector<quint64> invalidatedGenerationalRequests;
    QVector<MutationBackupOutcome> mutationBatchOutcomes;
    QVector<MutationBackupResult> mutationBatchResults;
    QVector<MutationBackupPublicationReceipt> mutationPublicationReceipts;
    QVector<QString> mutationBatchDiagnostics;
    QVector<InitialBackupInspectionResult> initialInspectionResults;
    QVector<GenerationalBackupSuspensionState> generationalSuspensions;
    QVector<GenerationalShutdownDrainState> generationalShutdownDrainStates;
    QVector<QString> initialCopyResumeRequests;
    QVector<QString> globalBackupReinspectionRequests;
    bool initialInspectionSettledOnOwnerThread = true;
    BackupResult last;
    QString message;
    QVector<RotationResult> rotations;
    BackupTriggerMode triggerMode = BackupTriggerMode::Historical;
    bool completionWhileReserved = false, terminationReleasedReservation = false;
    void SetUp() override
    {
        ASSERT_TRUE(temporary.isValid()); ASSERT_GE(sodium_init(), 0);
        for (auto format : {QSettings::NativeFormat, QSettings::IniFormat}) {
            QSettings::setPath(format, QSettings::UserScope, temporary.filePath("settings"));
            QSettings::setPath(format, QSettings::SystemScope, temporary.filePath("settings"));
        }
        configuration = VaultPreferencesStore().fileName();
        ASSERT_TRUE(configuration.startsWith(temporary.path()));
        source = temporary.filePath("password.db"); destination = temporary.filePath("backups");
        ASSERT_TRUE(QDir().mkpath(destination));
        ASSERT_TRUE(QFile::setPermissions(destination, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
        std::string failure;
        ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(source.toStdString(), failure));
        VaultKeyMetadata metadata; metadata.vaultId.fill(0x42);
        ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(source.toStdString(), metadata, failure));
        key = passwall::core::SecureBuffer(passwall::core::KeySize);
        std::fill_n(key.data(), key.size(), 0x42);
        ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(source, original, error), VaultRecognition::Registered);
    }
    void TearDown() override
    {
        failCatalogue = false; unsupported = false; suppressStop = false; freezeTime = false;
        frozenYear = 2026;
        if (stuck) realAutoKill(stuck);
        if (coordinator) {
            coordinator->shutdown();
            EXPECT_TRUE(until([&] { return !coordinator->isActive(); }));
            coordinator.reset();
        }
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
    void control(const QString& worker = QString::fromLatin1(AUTO_REAL_WORKER),
                 int mutationGroupingDelayMs = 20000,
                 int mutationContentionWaitMs = 3000)
    {
        coordinator = std::make_unique<AutomaticBackupCoordinator>(
            VaultPreferencesStore(), worker, mutationGroupingDelayMs,
            mutationContentionWaitMs, triggerMode);
        coordinator->trackVault(original);
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::completed,
            coordinator.get(), [this](const QString&, BackupResult result) { ++completions; last = result; });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::notification,
            coordinator.get(), [this](const QString&, const QString& text) { ++notices; message = text; });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::deferred,
            coordinator.get(), [this] { ++deferrals; });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::rotationCompleted,
            coordinator.get(), [this](const QString&, RotationResult result) { rotations.push_back(result); });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::generationalBackupRequested,
            coordinator.get(), [this](GenerationalBackupRequestOffer offer) {
                ++mutationBatchRequests;
                mutationBatchPath = offer.vaultPath;
                mutationBatchGenerations.push_back(offer.mutationGeneration);
                mutationBatchRequestIds.push_back(offer.requestId);
                generationalRequestKinds.push_back(offer.kind);
                generationalSessionGenerations.push_back(offer.sessionGeneration);
            });
        QObject::connect(coordinator.get(),
            &AutomaticBackupCoordinator::generationalBackupRequestInvalidated,
            coordinator.get(), [this](quint64 requestId) {
                invalidatedGenerationalRequests.push_back(requestId);
            });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::mutationBatchSettled,
            coordinator.get(), [this](MutationBackupResult result) {
                mutationBatchOutcomes.push_back(result.outcome);
                if (result.publication)
                    mutationPublicationReceipts.push_back(*result.publication);
                mutationBatchResults.push_back(std::move(result));
            });
        QObject::connect(coordinator.get(),
            &AutomaticBackupCoordinator::initialBackupInspectionSettled,
            coordinator.get(), [this](InitialBackupInspectionResult result) {
                initialInspectionSettledOnOwnerThread =
                    initialInspectionSettledOnOwnerThread
                    && QThread::currentThread() == coordinator->thread();
                initialInspectionResults.push_back(std::move(result));
            });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::mutationBatchDiagnostic,
            coordinator.get(), [this](const QString&, quint64, const QString& diagnostic) {
                mutationBatchDiagnostics.push_back(diagnostic);
            });
        QObject::connect(coordinator.get(),
            &AutomaticBackupCoordinator::generationalBackupSuspensionChanged,
            coordinator.get(), [this](GenerationalBackupSuspensionState state) {
                generationalSuspensions.push_back(std::move(state));
            });
        QObject::connect(coordinator.get(),
            &AutomaticBackupCoordinator::generationalShutdownDrainChanged,
            coordinator.get(), [this](GenerationalShutdownDrainState state) {
                generationalShutdownDrainStates.push_back(std::move(state));
            });
        QObject::connect(coordinator.get(),
            &AutomaticBackupCoordinator::generationalInitialCopyResumeRequested,
            coordinator.get(), [this](const QString& path) {
                initialCopyResumeRequests.push_back(path);
            });
        QObject::connect(coordinator.get(),
            &AutomaticBackupCoordinator::globalBackupReinspectionRequested,
            coordinator.get(), [this](const QString& path) {
                globalBackupReinspectionRequests.push_back(path);
            });
    }
    void fake(const QByteArray& mode, int mutationGroupingDelayMs = 20000,
              int mutationContentionWaitMs = 3000)
    {
        touch(source + ".fake-mode", mode);
        control(QString::fromLatin1(AUTO_FAKE_WORKER), mutationGroupingDelayMs,
            mutationContentionWaitMs);
    }
    static BackupFileEvidence syntheticPublicationEvidence()
    {
        BackupFileEvidence evidence;
        evidence.device = 1; evidence.inode = 2; evidence.size = 3; evidence.mount = 4;
        evidence.directoryDevice = 5; evidence.directoryInode = 6; evidence.directoryMount = 7;
        evidence.birth = QStringLiteral("1:0");
        evidence.modified = QStringLiteral("2:0");
        evidence.changed = QStringLiteral("3:0");
        evidence.directoryBirth = QStringLiteral("4:0");
        evidence.sha256 = QByteArray(32, 'p');
        return evidence;
    }
    MutationBackupPublicationReceipt simulatedReceipt(int index, const QString& target) const
    {
        return {mutationBatchPath, target, mutationBatchGenerations[index],
            mutationBatchRequestIds[index], syntheticPublicationEvidence()};
    }
    void enable(const QString& directory = {})
    {
        ASSERT_TRUE(VaultPreferencesStore().updatePreferences(original.localId,
            {true, directory.isEmpty() ? destination : directory, 7}, error)) << error.toStdString();
    }
    VaultRegistration record()
    {
        QVector<VaultRegistration> records;
        EXPECT_TRUE(VaultPreferencesStore().list(records, error));
        for (const auto& record : records) if (record.localId == original.localId) return record;
        ADD_FAILURE() << "Fictitious record missing";
        throw std::runtime_error("Fictitious test registry unavailable");
    }
    void mutate()
    {
        passwall::models::Credential credential;
        credential.title = "Fictitious title"; credential.username = "fictitious-user";
        credential.password = "fictitious-only-password";
        std::string failure;
        ASSERT_TRUE(CredentialService::add(source.toStdString(), key, credential, failure)) << failure;
        sodium_memzero(credential.password.data(), credential.password.size());
    }
    InitialBackupPreparation prepareInitialCopy(
        quint64 sessionGeneration, bool forceInitialCopy = false)
    {
        GlobalBackupPreferencesResult preferences;
        preferences.status = GlobalBackupPreferencesStatus::Valid;
        preferences.preferences = {destination, 7};
        AuthenticatedBackupSession session{
            original.file, sessionGeneration, 0, true, forceInitialCopy};
        return InitialBackupPreparer::prepare(preferences, session,
            QDateTime(QDate(2026, 11, 21), QTime(10, 11, 12), QTimeZone::utc()),
            InitialBackupCancellation{initialInspectionRemainsCurrent, nullptr});
    }
    GlobalBackupPreferencesResult initialPreferences(
        const QString& root = {}) const
    {
        GlobalBackupPreferencesResult preferences;
        preferences.status = GlobalBackupPreferencesStatus::Valid;
        preferences.preferences = {
            root.isEmpty() ? destination : root, 7};
        return preferences;
    }
    AuthenticatedBackupSession authenticatedSession(
        quint64 sessionGeneration) const
    {
        return {original.file, sessionGeneration, 0, true};
    }
    static QDateTime initialInspectionTime()
    {
        return QDateTime(QDate(2026, 11, 21), QTime(10, 11, 14),
            QTimeZone::utc());
    }
    InitialBackupAdmission initialAdmission(
        quint64 sessionGeneration, quint64 inspectionActivityId = 0) const
    {
        return {original.file, sessionGeneration, BackupTriggerMode::Generational,
            true, false, true, inspectionActivityId};
    }
    QString replaceSourceWithAnotherVault()
    {
        const QString replacement = temporary.filePath(QStringLiteral("replacement.pwdb"));
        const QString previous = temporary.filePath(QStringLiteral("previous-principal.pwdb"));
        std::string failure;
        EXPECT_TRUE(passwall::storage::VaultStorage::createSchema(
            replacement.toStdString(), failure)) << failure;
        VaultKeyMetadata metadata;
        metadata.vaultId.fill(0x61);
        EXPECT_TRUE(passwall::storage::VaultStorage::writeMetadata(
            replacement.toStdString(), metadata, failure)) << failure;
        EXPECT_TRUE(QFile::rename(source, previous));
        EXPECT_TRUE(QFile::rename(replacement, source));
        return previous;
    }
    void wait(int count = 1)
    {
        ASSERT_TRUE(until([&] { return completions >= count; })) << message.toStdString() << " / " << error.toStdString();
    }
    void retention(int count)
    {
        auto preferences = record().backup; preferences.retainedVersions = count;
        ASSERT_TRUE(VaultPreferencesStore().updatePreferences(original.localId, preferences, error)) << error.toStdString();
    }
    void nextBackup()
    {
        const int expected = completions + 1;
        mutate(); coordinator->requestForLockedVault(source); wait(expected);
        ASSERT_EQ(last.outcome, BackupOutcome::Published) << last.diagnostic.toStdString();
    }
    void rotationFault(const QByteArray& fault, const QString& path)
    {
        touch(destination + "/.rotation-fault", fault);
        touch(destination + "/.rotation-target", QFileInfo(path).fileName().toUtf8());
    }
    void observeReservationCompletion()
    {
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::completed,
            coordinator.get(), [this](const QString&, BackupResult result) {
                EXPECT_EQ(result.outcome, BackupOutcome::Published);
                VaultOperationGuard access; std::string failure;
                completionWhileReserved = !access.tryAccess(source.toStdString(), failure);
            });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::activityChanged,
            coordinator.get(), [this](bool active) {
                if (active) return;
                VaultOperationGuard access; std::string failure;
                terminationReleasedReservation = access.tryAccess(source.toStdString(), failure);
            });
    }
    void editCatalogue(const std::function<void(QJsonObject&)>& edit)
    {
        QSettings settings(configuration, QSettings::IniFormat);
        auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
        auto records = root["vaults"].toArray();
        for (qsizetype i = 0; i < records.size(); ++i) {
            auto r = records[i].toObject();
            if (r["localId"] == original.localId) { edit(r); records[i] = r; }
        }
        root["vaults"] = records;
        settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact));
        settings.sync(); ASSERT_EQ(settings.status(), QSettings::NoError);
    }
};

class GenerationalAutomaticBackupTest : public AutomaticBackupTest {
protected:
    void SetUp() override
    {
        AutomaticBackupTest::SetUp();
        triggerMode = BackupTriggerMode::Generational;
    }
};

TEST_F(AutomaticBackupTest, HistoricalModeIsDefaultAndRejectsGenerationalEntries)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 10);
    ASSERT_EQ(coordinator->triggerMode(), BackupTriggerMode::Historical);

    mutate();
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();

    EXPECT_FALSE(coordinator->modificationGroupingPending());
    EXPECT_EQ(coordinator->mutationGeneration(), 0u);
    EXPECT_EQ(mutationBatchRequests, 0);
    coordinator->requestPendingMutationsForLock(source);
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_FALSE(coordinator->markMutationBackupStarted(1, source, 1));
    EXPECT_FALSE(coordinator->generationalBackupSuspension(source).suspended);
    EXPECT_FALSE(coordinator->resumeGenerationalBackup(source, error));
    EXPECT_FALSE(coordinator->beginGenerationalShutdownDrain(error));
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::NotRequested);
}

TEST_F(GenerationalAutomaticBackupTest, GenerationalModeRejectsEveryHistoricalEntryWithoutFallback)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 10);
    ASSERT_EQ(coordinator->triggerMode(), BackupTriggerMode::Generational);

    enable();
    coordinator->requestForLockedVault(source);
    coordinator->resumeAutomaticBackup(original.localId);
    QCoreApplication::processEvents();
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_EQ(completions, 0);
    EXPECT_EQ(notices, 0);

    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    coordinator->requestForLockedVault(source);
    coordinator->resumeAutomaticBackup(original.localId);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_EQ(completions, 0);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest, InitialCopyAloneIsOfferedWithSessionBinding)
{
    mutate(); // Populate before the coordinator starts observing commits.
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto preparation = prepareInitialCopy(71);
    ASSERT_EQ(preparation.decision, InitialBackupDecision::Prepared)
        << preparation.diagnostic.toStdString();
    ASSERT_TRUE(preparation.request.has_value());

    EXPECT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(71), error),
        InitialBackupArbitration::Offered) << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_EQ(generationalRequestKinds.size(), 1);
    EXPECT_EQ(generationalRequestKinds[0], GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(mutationBatchGenerations[0], 0U);
    EXPECT_EQ(generationalSessionGenerations[0], 71U);
    EXPECT_FALSE(coordinator->isActive());

    const quint64 requestId = mutationBatchRequestIds[0];
    QString startError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(requestId, source, 0,
        destination + QStringLiteral("/must-not-start.pwdb"), {}, {}, startError));
    EXPECT_FALSE(startError.isEmpty());
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(mutationBatchResults.empty());
    coordinator->shutdown();
    EXPECT_TRUE(invalidatedGenerationalRequests.contains(requestId));
    ASSERT_EQ(mutationBatchResults.size(), 1);
    EXPECT_EQ(mutationBatchResults[0].kind,
	      GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome,
	      BackupOutcome::CancelledBeforePublication);
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest, PendingCrudGenerationCoversInitialCopyAtAdmission)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();
    auto preparation = prepareInitialCopy(72);
    ASSERT_TRUE(preparation.request.has_value());

    EXPECT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(72), error),
        InitialBackupArbitration::MergedWithExistingRequest) << error.toStdString();
    EXPECT_EQ(mutationBatchRequests, 0);
    VaultOperationGuard releasedInitialCopy;
    std::string reservationError;
    EXPECT_TRUE(releasedInitialCopy.tryReserve(source.toStdString(), reservationError))
        << reservationError;
    releasedInitialCopy.reset();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(generationalRequestKinds[0],
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchGenerations[0], 1U);
    EXPECT_EQ(generationalSessionGenerations[0], 0U);
}

TEST_F(GenerationalAutomaticBackupTest, CommitDuringInitialInspectionIsMergedAtOwnerAdmission)
{
    mutate(); // The inspected vault must already be populated.
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    GlobalBackupPreferencesResult preferences;
    preferences.status = GlobalBackupPreferencesStatus::Valid;
    preferences.preferences = {destination, 7};
    AuthenticatedBackupSession session{original.file, 73, 0, true};
    CommitDuringInitialInspection concurrent{source, &key};

    auto preparation = InitialBackupPreparer::prepare(preferences, session,
        QDateTime(QDate(2026, 11, 21), QTime(10, 11, 13), QTimeZone::utc()),
        InitialBackupCancellation{commitDuringInitialInspection, &concurrent});
    ASSERT_TRUE(concurrent.attempted);
    ASSERT_TRUE(concurrent.committed);
    ASSERT_EQ(preparation.decision, InitialBackupDecision::Prepared)
        << preparation.diagnostic.toStdString();
    ASSERT_TRUE(preparation.request.has_value());

    EXPECT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(73), error),
        InitialBackupArbitration::MergedWithExistingRequest) << error.toStdString();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(generationalRequestKinds[0],
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchGenerations[0], 1U);
}

TEST_F(GenerationalAutomaticBackupTest, CommitBetweenPreparationAndAdmissionWinsArbitration)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto preparation = prepareInitialCopy(74);
    ASSERT_TRUE(preparation.request.has_value());
    mutate();

    EXPECT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(74), error),
        InitialBackupArbitration::MergedWithExistingRequest) << error.toStdString();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(generationalRequestKinds[0],
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchGenerations[0], 1U);
}

TEST_F(GenerationalAutomaticBackupTest, CommitReplacesOfferedInitialCopyWithoutDoubleRequest)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto preparation = prepareInitialCopy(75);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(75), error),
        InitialBackupArbitration::Offered) << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_EQ(generationalRequestKinds[0], GenerationalBackupRequestKind::InitialCopy);
    const quint64 obsoleteInitialToken = mutationBatchRequestIds[0];

    mutate();
    ASSERT_EQ(invalidatedGenerationalRequests.size(), 1);
    EXPECT_EQ(invalidatedGenerationalRequests[0], obsoleteInitialToken);
    EXPECT_TRUE(coordinator->modificationGroupingPending());
    EXPECT_EQ(mutationBatchRequests, 1);
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(generationalRequestKinds[1],
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchGenerations[1], 1U);
    EXPECT_NE(mutationBatchRequestIds[1], obsoleteInitialToken);
    EXPECT_FALSE(coordinator->isActive());

    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest, SeveralCommitsAfterInitialOfferRemainOneMonotoneCrudRequest)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto preparation = prepareInitialCopy(76);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(76), error),
        InitialBackupArbitration::Offered);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    mutate();
    mutate();
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(generationalRequestKinds[1],
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchGenerations[1], 3U);
    EXPECT_EQ(invalidatedGenerationalRequests.size(), 1);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 2);
}

TEST_F(GenerationalAutomaticBackupTest, ChangedOrClosingSessionRefusesInitialAdmissionAndReleasesGuard)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    for (const bool closing : {false, true}) {
        auto preparation = prepareInitialCopy(closing ? 78 : 77);
        ASSERT_TRUE(preparation.request.has_value());
        auto admission = initialAdmission(closing ? 78 : 77);
        admission.closing = closing;
        if (!closing) {
            admission.sessionCurrent = false;
            ++admission.currentSessionGeneration;
        }
        EXPECT_EQ(coordinator->admitInitialBackup(
            std::move(*preparation.request), admission, error),
            InitialBackupArbitration::Refused);
        VaultOperationGuard exclusive;
        std::string reservationError;
        EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
            << reservationError;
    }
    EXPECT_EQ(mutationBatchRequests, 0);
}

TEST_F(AutomaticBackupTest, HistoricalModeRefusesInitialCopyWithoutAnOffer)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto preparation = prepareInitialCopy(79);
    ASSERT_TRUE(preparation.request.has_value());
    auto admission = initialAdmission(79);
    admission.triggerMode = BackupTriggerMode::Historical;

    EXPECT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), admission, error),
        InitialBackupArbitration::Refused);
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest, UserOperationsAreRefusedDuringInitialInspection)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const quint64 activity = coordinator->beginInitialBackupInspection(
        original.file, 81, error);
    ASSERT_NE(activity, 0U) << error.toStdString();

    const auto exportAdmission = coordinator->admitUserOperation(
        BackupUserOperation::ManualExport, source);
    EXPECT_FALSE(exportAdmission.compatible);
    EXPECT_EQ(exportAdmission.blockingState.phase,
        GenerationalOperationPhase::Inspecting);
    const auto restoreAdmission = coordinator->admitUserOperation(
        BackupUserOperation::Restoration, source);
    EXPECT_FALSE(restoreAdmission.compatible);
    EXPECT_FALSE(restoreAdmission.diagnostic.isEmpty());

    EXPECT_TRUE(coordinator->cancelInitialBackupInspection(activity));
    EXPECT_TRUE(coordinator->admitUserOperation(
        BackupUserOperation::ManualExport, source).compatible);
    EXPECT_EQ(coordinator->generationalOperationState(source).phase,
        GenerationalOperationPhase::Cancelled);
}

TEST_F(GenerationalAutomaticBackupTest, PreparedDestinationBlocksExportUntilRaiiRelease)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const quint64 activity = coordinator->beginInitialBackupInspection(
        original.file, 82, error);
    ASSERT_NE(activity, 0U) << error.toStdString();
    auto preparation = prepareInitialCopy(82);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_TRUE(coordinator->markInitialBackupPrepared(
        activity, std::move(*preparation.request), error)) << error.toStdString();

    const auto state = coordinator->generationalOperationState(source);
    EXPECT_EQ(state.phase, GenerationalOperationPhase::PreparedReservation);
    EXPECT_TRUE(state.reservationHeld);
    EXPECT_FALSE(coordinator->admitUserOperation(
        BackupUserOperation::ManualExport, source).compatible);
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), reservationError));

    EXPECT_TRUE(coordinator->cancelInitialBackupInspection(activity));
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest, RestorationPrecheckDoesNotCreateHistoricalIntent)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const quint64 activity = coordinator->beginInitialBackupInspection(
        original.file, 83, error);
    ASSERT_NE(activity, 0U);
    auto preparation = prepareInitialCopy(83);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_TRUE(coordinator->markInitialBackupPrepared(
        activity, std::move(*preparation.request), error)) << error.toStdString();

    ASSERT_FALSE(record().replacement.has_value());
    const auto admission = coordinator->admitUserOperation(
        BackupUserOperation::Restoration, source);
    EXPECT_FALSE(admission.compatible);
    EXPECT_EQ(admission.blockingState.phase,
        GenerationalOperationPhase::PreparedReservation);
    EXPECT_FALSE(record().replacement.has_value());
    auto ownedAdmission = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, source, error);
    EXPECT_FALSE(ownedAdmission.valid());
    EXPECT_FALSE(record().replacement.has_value());
    VaultOperationGuard finalReservation;
    std::string reservationError;
    EXPECT_FALSE(finalReservation.tryReserve(source.toStdString(), reservationError));
    EXPECT_FALSE(record().replacement.has_value());

    EXPECT_TRUE(coordinator->cancelInitialBackupInspection(activity));
}

TEST_F(GenerationalAutomaticBackupTest, OfferedInitialCopyIsNotReportedAsAWorker)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const quint64 activity = coordinator->beginInitialBackupInspection(
        original.file, 84, error);
    ASSERT_NE(activity, 0U);
    auto preparation = prepareInitialCopy(84);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_TRUE(coordinator->markInitialBackupPrepared(
        activity, std::move(*preparation.request), error));
    ASSERT_EQ(coordinator->admitPreparedInitialBackup(
        activity, initialAdmission(84), error), InitialBackupArbitration::Offered)
        << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    const auto state = coordinator->generationalOperationState(source);
    EXPECT_EQ(state.phase, GenerationalOperationPhase::OfferedRequest);
    EXPECT_EQ(state.kind, GenerationalBackupRequestKind::InitialCopy);
    EXPECT_TRUE(state.reservationHeld);
    EXPECT_FALSE(state.workerAlive);
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_FALSE(coordinator->admitUserOperation(
        BackupUserOperation::ManualExport, source).compatible);
}

TEST_F(GenerationalAutomaticBackupTest, PrecheckCannotReplaceFinalExclusiveReservation)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    EXPECT_TRUE(coordinator->admitUserOperation(
        BackupUserOperation::Restoration, source).compatible);

    const quint64 activity = coordinator->beginInitialBackupInspection(
        original.file, 85, error);
    ASSERT_NE(activity, 0U);
    auto preparation = prepareInitialCopy(85);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_TRUE(coordinator->markInitialBackupPrepared(
        activity, std::move(*preparation.request), error));

    auto exactAdmission = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, source, error);
    EXPECT_FALSE(exactAdmission.valid());

    VaultOperationGuard finalReservation;
    std::string reservationError;
    EXPECT_FALSE(finalReservation.tryReserve(source.toStdString(), reservationError));
    EXPECT_TRUE(coordinator->cancelInitialBackupInspection(activity));
    EXPECT_TRUE(finalReservation.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest,
    PendingAutomaticBackupHasPriorityOverOwnedManualAdmission)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();

    auto exportAdmission = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    EXPECT_FALSE(exportAdmission.valid());
    EXPECT_FALSE(error.isEmpty());
    auto restorationAdmission = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, source, error);
    EXPECT_FALSE(restorationAdmission.valid());
    EXPECT_EQ(mutationBatchRequests, 0);
}

TEST_F(GenerationalAutomaticBackupTest,
    OwnedManualAdmissionMakesLaterAutomaticRequestWaitWithoutLoss)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto admission = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    ASSERT_TRUE(admission.valid()) << error.toStdString();

    mutate();
    coordinator->requestPendingMutationsForLock(source);
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 0);

    admission = {};
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(mutationBatchPath, source);
    EXPECT_EQ(mutationBatchGenerations[0], 1U);
}

TEST_F(GenerationalAutomaticBackupTest,
    ManualAdmissionRaiiReleasesAfterCancellationBeforeExclusiveAcquisition)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    {
        auto admission = coordinator->acquireUserOperation(
            BackupUserOperation::Restoration, source, error);
        ASSERT_TRUE(admission.valid()) << error.toStdString();
        EXPECT_FALSE(coordinator->admitUserOperation(
            BackupUserOperation::ManualExport, source).compatible);
        EXPECT_EQ(coordinator->beginInitialBackupInspection(
            original.file, 8501, error), 0U);
    }

    auto next = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    EXPECT_TRUE(next.valid()) << error.toStdString();
}

TEST_F(GenerationalAutomaticBackupTest,
    FailedExclusiveHandoffLeavesNoLogicalOrKernelAdmission)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto admission = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    ASSERT_TRUE(admission.valid()) << error.toStdString();

    BackupJob job(QString::fromLatin1(AUTO_REAL_WORKER));
    EXPECT_FALSE(admission.startExport(job, source, QString{}, error));
    EXPECT_FALSE(error.isEmpty());
    EXPECT_FALSE(admission.startExport(job, source,
        destination + QStringLiteral("/must-not-start.pwdb"), error));

    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
    exclusive.reset();
    auto replacementAdmission = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, source, error);
    EXPECT_TRUE(replacementAdmission.valid()) << error.toStdString();
}

TEST_F(GenerationalAutomaticBackupTest,
    ManualAdmissionRejectsPhysicalSubstitutionBeforeExclusiveHandoff)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto admission = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    ASSERT_TRUE(admission.valid()) << error.toStdString();
    const QString previous = replaceSourceWithAnotherVault();
    ASSERT_TRUE(QFileInfo::exists(previous));

    BackupJob job(QString::fromLatin1(AUTO_REAL_WORKER));
    EXPECT_FALSE(admission.startExport(job, source,
        destination + QStringLiteral("/wrong-principal.pwdb"), error));
    EXPECT_TRUE(error.contains(QStringLiteral("identité"),
        Qt::CaseInsensitive)) << error.toStdString();
    EXPECT_FALSE(QFileInfo::exists(
        destination + QStringLiteral("/wrong-principal.pwdb")));
}

TEST_F(GenerationalAutomaticBackupTest,
    ManualAdmissionTransfersExclusiveReservationToRealBackupJob)
{
    fake("published-file", 1000);
    auto admission = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    ASSERT_TRUE(admission.valid()) << error.toStdString();

    BackupJob job(QString::fromLatin1(AUTO_FAKE_WORKER));
    BackupResult result;
    bool finished = false;
    bool terminated = false;
    QObject::connect(&job, &BackupJob::finished, &job,
        [&](BackupResult value) { result = std::move(value); finished = true; });
    QObject::connect(&job, &BackupJob::processTerminated, &job,
        [&] { terminated = true; });
    const QString output = destination
        + QStringLiteral("/admitted-manual-export.pwdb");
    ASSERT_TRUE(admission.startExport(job, source, output, error))
        << error.toStdString();

    VaultOperationGuard incompatible;
    std::string reservationError;
    EXPECT_FALSE(incompatible.trySnapshotAccess(
        source.toStdString(), reservationError));
    ASSERT_TRUE(until([&] { return finished && terminated; }, 5000));
    EXPECT_EQ(result.outcome, BackupOutcome::Published)
        << result.diagnostic.toStdString();
    EXPECT_TRUE(QFileInfo::exists(output));
}

TEST_F(GenerationalAutomaticBackupTest,
    ManualAdmissionsForIndependentVaultsDoNotBlockEachOther)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const QString other = temporary.filePath(QStringLiteral("independent.pwdb"));
    std::string storageError;
    ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(
        other.toStdString(), storageError)) << storageError;
    VaultKeyMetadata metadata;
    metadata.vaultId.fill(0x24);
    ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(
        other.toStdString(), metadata, storageError)) << storageError;

    auto first = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    ASSERT_TRUE(first.valid()) << error.toStdString();
    auto second = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, other, error);
    EXPECT_TRUE(second.valid()) << error.toStdString();
}

TEST_F(GenerationalAutomaticBackupTest,
    NewAuthenticatedSessionRevokesLateManualAdmission)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    auto stale = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, source, error);
    ASSERT_TRUE(stale.valid()) << error.toStdString();

    coordinator->trackVault(original);
    EXPECT_FALSE(stale.valid());

    auto current = coordinator->acquireUserOperation(
        BackupUserOperation::Restoration, source, error);
    EXPECT_TRUE(current.valid()) << error.toStdString();
}

TEST_F(GenerationalAutomaticBackupTest, SessionChangeInvalidatesLateInitialPreparation)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const quint64 activity = coordinator->beginInitialBackupInspection(
        original.file, 86, error);
    ASSERT_NE(activity, 0U);
    auto preparation = prepareInitialCopy(86);
    ASSERT_TRUE(preparation.request.has_value());

    coordinator->trackVault(original); // New owner session invalidates the old activity.
    EXPECT_FALSE(coordinator->markInitialBackupPrepared(
        activity, std::move(*preparation.request), error));
    EXPECT_EQ(coordinator->generationalOperationState(source).phase,
        GenerationalOperationPhase::Cancelled);
    EXPECT_TRUE(coordinator->admitUserOperation(
        BackupUserOperation::Restoration, source).compatible);
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest, UnknownResultKeepsWorkerAndReservationObservableUntilExit)
{
    fake("ignore", 20);
    suppressStop = true;
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    const QString output = destination + QStringLiteral("/unknown-supervised.pwdb");
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, error)) << error.toStdString();
    ASSERT_TRUE(until([&] { return QFileInfo::exists(output + ".ready"); }, 1000));

    coordinator->cancel();
    ASSERT_TRUE(until([&] {
        const auto state = coordinator->generationalOperationState(source);
        return state.phase == GenerationalOperationPhase::WorkerActive
            && state.resultObserved && state.workerOutcome == BackupOutcome::Unknown;
    }, 5000));
    const auto live = coordinator->generationalOperationState(source);
    EXPECT_TRUE(live.workerAlive);
    EXPECT_TRUE(live.reservationHeld);
    EXPECT_TRUE(coordinator->isActive());
    const auto suspendedWhileAlive =
        coordinator->generationalBackupSuspension(source);
    EXPECT_TRUE(suspendedWhileAlive.suspended);
    EXPECT_EQ(suspendedWhileAlive.reason,
        GenerationalBackupSuspensionReason::Unknown);
    EXPECT_TRUE(suspendedWhileAlive.workerAlive);
    EXPECT_FALSE(coordinator->resumeGenerationalBackup(source, error));
    EXPECT_TRUE(error.contains(QStringLiteral("worker")));
    EXPECT_FALSE(coordinator->admitUserOperation(BackupUserOperation::Restoration, source).compatible);
    {
      VaultOperationGuard exclusive;
      EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), accessError));
    }
    suppressStop = false;
    ASSERT_TRUE(stuck);
    realAutoKill(stuck);
    ASSERT_TRUE(until([&] { return !coordinator->isActive(); }, 2000));
    const auto terminal = coordinator->generationalOperationState(source);
    EXPECT_EQ(terminal.phase, GenerationalOperationPhase::Completed);
    EXPECT_FALSE(terminal.workerAlive);
    EXPECT_FALSE(terminal.reservationHeld);
    auto manualAfterTermination = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    EXPECT_TRUE(manualAfterTermination.valid()) << error.toStdString();
    manualAfterTermination = {};
    {
      VaultOperationGuard exclusive;
      EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), accessError)) << accessError;
    }
    error.clear();
    EXPECT_TRUE(coordinator->resumeGenerationalBackup(source, error))
        << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
}

TEST_F(AutomaticBackupTest, HistoricalModeKeepsUserOperationAdmissionUnchanged)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    EXPECT_EQ(coordinator->beginInitialBackupInspection(
        original.file, 87, error), 0U);
    EXPECT_TRUE(coordinator->admitUserOperation(
        BackupUserOperation::ManualExport, source).compatible);
    EXPECT_TRUE(coordinator->admitUserOperation(
        BackupUserOperation::Restoration, source).compatible);
    auto owned = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    EXPECT_TRUE(owned.valid()) << error.toStdString();
    EXPECT_EQ(coordinator->generationalOperationState(source).phase,
        GenerationalOperationPhase::Idle);
}

TEST_F(GenerationalAutomaticBackupTest,
    AsyncInitialInspectionReturnsOnOwnerThreadWithoutBlockingTheOwner)
{
    mutate(); // Populate before the coordinator observes commits.
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(91), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(launch.outcome, InitialBackupInspectionLaunch::Started)
        << launch.diagnostic.toStdString();
    EXPECT_NE(launch.activityId, 0U);

    // Reaching this assertion proves that the owner call did not wait for the
    // deliberately blocked worker checkpoint.
    EXPECT_TRUE(coordinator->initialBackupInspectionActive());
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));
    EXPECT_TRUE(initialInspectionResults.isEmpty());
    barrier.resume.release();

    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));
    EXPECT_TRUE(initialInspectionSettledOnOwnerThread);
    EXPECT_EQ(initialInspectionResults[0].decision,
        InitialBackupDecision::Prepared);
    EXPECT_EQ(initialInspectionResults[0].arbitration,
        InitialBackupArbitration::Offered);
    ASSERT_EQ(mutationBatchRequests, 1);
    EXPECT_EQ(generationalRequestKinds[0],
        GenerationalBackupRequestKind::InitialCopy);
    EXPECT_FALSE(coordinator->isActive()); // No worker is connected in 2I-4E-1.
}

TEST_F(GenerationalAutomaticBackupTest,
    LockDuringInspectionCancelsWithoutWaitingAndReleasesAfterWorkerExit)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    barrier.checkpoint = InitialBackupCheckpoint::BeforeDestinationPreparation;
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(92), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(launch.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));

    coordinator->stopModificationGrouping(); // Models the synchronous lock cleanup.
    EXPECT_EQ(coordinator->generationalOperationState(source).phase,
        GenerationalOperationPhase::Cancelling);
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), reservationError));
    barrier.resume.release();

    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));
    EXPECT_EQ(initialInspectionResults[0].decision,
        InitialBackupDecision::Cancelled);
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest,
    DestroyedOwnerDoesNotWaitAndLatePreparationOnlyReleasesItsCapability)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    barrier.checkpoint = InitialBackupCheckpoint::BeforeDestinationPreparation;
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(93), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(launch.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));

    coordinator.reset(); // shutdown() requests cancellation but never joins.
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), reservationError));
    barrier.resume.release();
    ASSERT_TRUE(until([&] {
        return exclusive.tryReserve(source.toStdString(), reservationError);
    }));
    EXPECT_EQ(mutationBatchRequests, 0);
}

TEST_F(GenerationalAutomaticBackupTest,
    ConfigurationChangeInvalidatesTheOldInspectionBeforeAReplacementCanStart)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    const auto first = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(94), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(first.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));

    const QString newRoot = temporary.filePath(QStringLiteral("new-backup-root"));
    ASSERT_TRUE(QDir().mkpath(newRoot));
    ASSERT_TRUE(QFile::setPermissions(newRoot,
        QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
    coordinator->applyGlobalBackupPreferences(initialPreferences(newRoot));
    EXPECT_EQ(coordinator->generationalOperationState(source).phase,
        GenerationalOperationPhase::Cancelling);
    barrier.resume.release();
    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));
    EXPECT_EQ(initialInspectionResults[0].decision,
        InitialBackupDecision::Cancelled);

    const auto replacement = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(newRoot), authenticatedSession(94),
        initialInspectionTime());
    ASSERT_EQ(replacement.outcome, InitialBackupInspectionLaunch::Started)
        << replacement.diagnostic.toStdString();
    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 2; }));
    EXPECT_EQ(initialInspectionResults[1].decision,
        InitialBackupDecision::Prepared);
}

TEST_F(GenerationalAutomaticBackupTest,
    InvalidGlobalPreferencesRetainCrudGenerationUntilAValidConfigurationReturns)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    coordinator->applyGlobalBackupPreferences(initialPreferences());
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }));
    const quint64 staleRequest = mutationBatchRequestIds[0];

    GlobalBackupPreferencesResult unavailable;
    unavailable.status = GlobalBackupPreferencesStatus::Absent;
    coordinator->applyGlobalBackupPreferences(unavailable);
    EXPECT_TRUE(invalidatedGenerationalRequests.contains(staleRequest));

    mutate();
    ASSERT_TRUE(until([&] {
        return !coordinator->modificationGroupingPending();
    }));
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_FALSE(coordinator->isActive());

    auto changedRetention = initialPreferences();
    changedRetention.preferences.retainedVersions = 9;
    coordinator->applyGlobalBackupPreferences(changedRetention);
    ASSERT_TRUE(until([&] { return mutationBatchRequests >= 2; }));
    EXPECT_EQ(mutationBatchGenerations.last(), 2U);
    EXPECT_FALSE(coordinator->generationalBackupSuspension(source).suspended);
}

TEST_F(GenerationalAutomaticBackupTest,
    FinalPreparedConsumptionReloadsPreferencesAndRejectsAStaleDestination)
{
    fake("snapshot-published-file", 20);
    const QString secondRoot = temporary.filePath(QStringLiteral("second-root"));
    ASSERT_TRUE(QDir().mkpath(secondRoot));
    ASSERT_TRUE(QFile::setPermissions(secondRoot,
        QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
    GlobalBackupPreferencesStore store;
    const auto first = store.save({destination, 7});
    ASSERT_TRUE(first.valid()) << first.diagnostic.toStdString();

    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }));
    const quint64 staleRequest = mutationBatchRequestIds[0];
    const quint64 generation = mutationBatchGenerations[0];
    PreparedBackupDestination prepared;
    ASSERT_TRUE(BackupDestinationPreparer::prepare(first, original.file,
        generation, initialInspectionTime(), prepared, error))
        << error.toStdString();

    const auto second = store.save({secondRoot, 8});
    ASSERT_TRUE(second.valid()) << second.diagnostic.toStdString();
    EXPECT_FALSE(coordinator->startPreparedMutationBackupSnapshot(
        staleRequest, source, generation, std::move(prepared), error));
    EXPECT_TRUE(error.contains(QStringLiteral("configuration globale"),
        Qt::CaseInsensitive));
    EXPECT_TRUE(invalidatedGenerationalRequests.contains(staleRequest));
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(mutationBatchResults.isEmpty());
    ASSERT_TRUE(until([&] { return mutationBatchRequests >= 2; }));
    EXPECT_EQ(mutationBatchGenerations.last(), generation);
}

TEST_F(GenerationalAutomaticBackupTest,
    PersistedPreferenceNotificationInvalidatesAnUnstartedOffer)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    const QString secondRoot = temporary.filePath(QStringLiteral("notified-root"));
    ASSERT_TRUE(QDir().mkpath(secondRoot));
    ASSERT_TRUE(QFile::setPermissions(secondRoot,
        QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
    GlobalBackupPreferencesStore store;
    ASSERT_TRUE(store.save({destination, 7}).valid());
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();

    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }));
    const quint64 staleRequest = mutationBatchRequestIds[0];
    ASSERT_TRUE(store.save({secondRoot, 10}).valid());
    ASSERT_TRUE(until([&] {
        return invalidatedGenerationalRequests.contains(staleRequest)
            && mutationBatchRequests >= 2;
    }));
    EXPECT_EQ(mutationBatchGenerations.last(), 1U);
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(mutationBatchResults.isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest,
    PreferenceChangeDoesNotInterruptAnAlreadyStartedWorker)
{
    fake("slow-snapshot-published-file", 1000);
    const auto current = initialPreferences();
    coordinator->applyGlobalBackupPreferences(current);
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }));
    const quint64 generation = mutationBatchGenerations[0];
    PreparedBackupDestination prepared;
    ASSERT_TRUE(BackupDestinationPreparer::prepare(current, original.file,
        generation, initialInspectionTime(), prepared, error))
        << error.toStdString();
    ASSERT_TRUE(coordinator->startPreparedMutationBackupSnapshot(
        mutationBatchRequestIds[0], source, generation,
        std::move(prepared), error)) << error.toStdString();
    ASSERT_TRUE(coordinator->isActive());

    auto changed = current;
    changed.preferences.retainedVersions = 12;
    coordinator->applyGlobalBackupPreferences(changed);
    EXPECT_TRUE(coordinator->isActive());
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].outcome,
        MutationBackupOutcome::Published);
}

TEST_F(GenerationalAutomaticBackupTest,
    DuplicateInspectionForOneSessionAndConfigurationIsNeverStartedTwice)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    const auto first = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(95), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(first.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));
    const auto duplicate = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(95), initialInspectionTime());
    EXPECT_EQ(duplicate.outcome, InitialBackupInspectionLaunch::AlreadyRunning);
    EXPECT_EQ(duplicate.activityId, first.activityId);
    barrier.resume.release();
    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));

    const auto settledDuplicate = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(95), initialInspectionTime());
    EXPECT_EQ(settledDuplicate.outcome,
        InitialBackupInspectionLaunch::AlreadySettled);
    EXPECT_EQ(settledDuplicate.activityId, first.activityId);
    EXPECT_EQ(initialInspectionResults.size(), 1);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }));
}

TEST_F(GenerationalAutomaticBackupTest,
    VaultChangeInvalidatesALateInspectionResult)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    barrier.checkpoint = InitialBackupCheckpoint::BeforeReturn;
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(96), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(launch.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));

    const QString secondPath = temporary.filePath(QStringLiteral("second.pwdb"));
    std::string failure;
    ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(
        secondPath.toStdString(), failure)) << failure;
    VaultKeyMetadata metadata;
    metadata.vaultId.fill(0x57);
    ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(
        secondPath.toStdString(), metadata, failure)) << failure;
    VaultRegistration second;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(
        secondPath, second, error), VaultRecognition::Registered)
        << error.toStdString();
    coordinator->trackVault(second);
    barrier.resume.release();

    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));
    EXPECT_EQ(initialInspectionResults[0].decision,
        InitialBackupDecision::Cancelled);
    EXPECT_EQ(mutationBatchRequests, 0);
}

TEST_F(GenerationalAutomaticBackupTest,
    CrudCommitDuringAsyncInspectionWinsOwnerThreadArbitration)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    AsyncInitialInspectionBarrier barrier;
    barrier.checkpoint = InitialBackupCheckpoint::BeforeDestinationPreparation;
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(97), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(launch.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));

    mutate(); // Business access coexists with the held snapshot capability.
    barrier.resume.release();
    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));
    EXPECT_EQ(initialInspectionResults[0].decision,
        InitialBackupDecision::Prepared);
    EXPECT_EQ(initialInspectionResults[0].arbitration,
        InitialBackupArbitration::MergedWithExistingRequest);
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }));
    EXPECT_EQ(generationalRequestKinds[0],
        GenerationalBackupRequestKind::CrudGeneration);
}

TEST_F(AutomaticBackupTest,
    HistoricalModeNeverStartsAnAsyncInitialInspection)
{
    mutate();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(98), initialInspectionTime());
    EXPECT_EQ(launch.outcome, InitialBackupInspectionLaunch::Refused);
    EXPECT_EQ(launch.activityId, 0U);
    EXPECT_FALSE(coordinator->initialBackupInspectionActive());
    QCoreApplication::processEvents();
    EXPECT_TRUE(initialInspectionResults.isEmpty());
    EXPECT_EQ(mutationBatchRequests, 0);
}

TEST_F(GenerationalAutomaticBackupTest,
    PreparedInitialCopyUsesTheCommonWorkerAndPublishesACompleteResult)
{
    mutate(); // Populate before the coordinator observes commits.
    fake("snapshot-published-file", 1000);
    auto preparation = prepareInitialCopy(101);
    ASSERT_EQ(preparation.decision, InitialBackupDecision::Prepared)
        << preparation.diagnostic.toStdString();
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(101), error),
        InitialBackupArbitration::Offered) << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_EQ(generationalRequestKinds[0],
        GenerationalBackupRequestKind::InitialCopy);

    const quint64 requestId = mutationBatchRequestIds[0];
    ASSERT_TRUE(coordinator->startInitialBackupSnapshot(requestId, error))
        << error.toStdString();
    EXPECT_TRUE(coordinator->isActive());
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));

    const auto& result = mutationBatchResults[0];
    EXPECT_EQ(result.kind, GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(result.sessionGeneration, 101U);
    EXPECT_EQ(result.generation, 0U);
    EXPECT_EQ(result.requestId, requestId);
    EXPECT_EQ(result.outcome, MutationBackupOutcome::Published);
    EXPECT_EQ(result.workerOutcome, BackupOutcome::Published);
    ASSERT_TRUE(result.publication.has_value());
    EXPECT_EQ(result.publication->kind,
        GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(result.publication->sessionGeneration, 101U);
    EXPECT_EQ(result.publication->generation, 0U);
    EXPECT_EQ(result.publication->requestId, requestId);
    EXPECT_TRUE(result.publication->evidence.permitsDeletion());
    EXPECT_TRUE(QFileInfo::exists(result.publication->destination));
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(rotations.isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest,
    PreparedCrudGenerationUsesTheSameWorkerSupervisionAndFullBindings)
{
    fake("snapshot-published-file", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const quint64 generation = mutationBatchGenerations[0];
    PreparedBackupDestination prepared;
    ASSERT_TRUE(BackupDestinationPreparer::prepare(
        initialPreferences(), original.file, generation,
        initialInspectionTime(), prepared, error)) << error.toStdString();

    ASSERT_TRUE(coordinator->startPreparedMutationBackupSnapshot(
        mutationBatchRequestIds[0], mutationBatchPath, generation,
        std::move(prepared), error)) << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    const auto& result = mutationBatchResults[0];
    EXPECT_EQ(result.kind, GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(result.generation, generation);
    EXPECT_EQ(result.sessionGeneration, 0U);
    EXPECT_EQ(result.outcome, MutationBackupOutcome::Published);
    ASSERT_TRUE(result.publication.has_value());
    EXPECT_EQ(result.publication->kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_TRUE(QFileInfo::exists(result.publication->destination));
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest,
    InitialCopyTokenIsSingleUseAndAnObsoleteTokenCannotStartAWorker)
{
    mutate();
    fake("failed", 1000);
    auto preparation = prepareInitialCopy(102);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(102), error),
        InitialBackupArbitration::Offered);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const quint64 requestId = mutationBatchRequestIds[0];

    EXPECT_FALSE(coordinator->startInitialBackupSnapshot(requestId + 1, error));
    EXPECT_FALSE(error.isEmpty());
    EXPECT_FALSE(coordinator->isActive());
    ASSERT_TRUE(coordinator->startInitialBackupSnapshot(requestId, error))
        << error.toStdString();
    EXPECT_FALSE(coordinator->startInitialBackupSnapshot(requestId, error));
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].kind,
        GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchRequests, 1);
}

TEST_F(GenerationalAutomaticBackupTest,
    InitialCopyFinalAdmissionRejectsAChangedSession)
{
    mutate();
    fake("snapshot-published-file", 1000);
    auto preparation = prepareInitialCopy(106);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(106), error),
        InitialBackupArbitration::Offered);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    coordinator->trackVault(original); // Same file, but a distinct authenticated session.
    EXPECT_FALSE(coordinator->startInitialBackupSnapshot(
        mutationBatchRequestIds[0], error));
    EXPECT_TRUE(error.contains(QStringLiteral("session courante")));
    ASSERT_EQ(mutationBatchResults.size(), 1);
    EXPECT_EQ(mutationBatchResults[0].kind,
        GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Failed);
    EXPECT_FALSE(coordinator->isActive());

    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest,
    CrudMutationDuringInitialCopyWorkerRemainsASeparateLaterRequest)
{
    mutate();
    fake("slow-snapshot-published-file", 20);
    auto preparation = prepareInitialCopy(103);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(103), error),
        InitialBackupArbitration::Offered);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_TRUE(coordinator->startInitialBackupSnapshot(
        mutationBatchRequestIds[0], error)) << error.toStdString();
    ASSERT_TRUE(until([&] { return coordinator->isActive(); }, 1000));

    mutate();
    EXPECT_TRUE(coordinator->modificationGroupingPending());
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].kind,
        GenerationalBackupRequestKind::InitialCopy);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(generationalRequestKinds[1],
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchGenerations[1], 1U);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest,
    InitialCopyFailedLaunchSettlesOnceAndReleasesTheSnapshotReservation)
{
    mutate();
    const QString missingWorker = temporary.filePath(
        QStringLiteral("missing-backup-worker"));
    control(missingWorker, 1000);
    auto preparation = prepareInitialCopy(104);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(104), error),
        InitialBackupArbitration::Offered);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_TRUE(coordinator->startInitialBackupSnapshot(
        mutationBatchRequestIds[0], error)) << error.toStdString();

    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].kind,
        GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome,
        BackupOutcome::FailedBeforePublication);
    EXPECT_FALSE(mutationBatchResults[0].diagnostic.isEmpty());
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_FALSE(coordinator->isActive());
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_TRUE(exclusive.tryReserve(source.toStdString(), reservationError))
        << reservationError;
}

TEST_F(GenerationalAutomaticBackupTest,
    InitialCopyUnconfirmedPublicationRemainsUnknownWithoutAutomaticRetry)
{
    mutate();
    fake("snapshot-published-without-receipt", 1000);
    auto preparation = prepareInitialCopy(105);
    ASSERT_TRUE(preparation.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*preparation.request), initialAdmission(105), error),
        InitialBackupArbitration::Offered);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_TRUE(coordinator->startInitialBackupSnapshot(
        mutationBatchRequestIds[0], error)) << error.toStdString();

    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].kind,
        GenerationalBackupRequestKind::InitialCopy);
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Unknown);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome, BackupOutcome::Unknown);
    EXPECT_FALSE(mutationBatchResults[0].publication.has_value());
    EXPECT_TRUE(mutationBatchResults[0].diagnostic.contains(
        QStringLiteral("Preuve de publication")));
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    const auto suspended = coordinator->generationalBackupSuspension(source);
    EXPECT_TRUE(suspended.suspended);
    EXPECT_EQ(suspended.reason, GenerationalBackupSuspensionReason::Unknown);
    ASSERT_TRUE(coordinator->resumeGenerationalBackup(source, error))
        << error.toStdString();
    ASSERT_EQ(initialCopyResumeRequests.size(), 1);
    EXPECT_EQ(initialCopyResumeRequests[0], QFileInfo(source).absoluteFilePath());
    EXPECT_FALSE(coordinator->resumeGenerationalBackup(source, error));
    EXPECT_EQ(initialCopyResumeRequests.size(), 1);
    auto retry = prepareInitialCopy(106, true);
    ASSERT_TRUE(retry.request.has_value());
    ASSERT_EQ(coordinator->admitInitialBackup(
        std::move(*retry.request), initialAdmission(106), error),
        InitialBackupArbitration::Offered) << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(generationalRequestKinds[1],
        GenerationalBackupRequestKind::InitialCopy);
}

TEST_F(GenerationalAutomaticBackupTest,
    GenerationalUnknownWorkerOutlivesItsDestroyedCoordinatorWithReservation)
{
    fake("ignore", 20);
    suppressStop = true;
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard access;
    std::string reservationError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), reservationError))
        << reservationError;
    const QString output = destination + QStringLiteral("/unknown-owner.pwdb");
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(
        mutationBatchRequestIds[0], mutationBatchPath,
        mutationBatchGenerations[0], output, std::move(access), {}, error))
        << error.toStdString();
    ASSERT_TRUE(until([&] { return QFileInfo::exists(output + ".ready"); }, 1000));

    coordinator->cancel();
    ASSERT_TRUE(until([&] {
        const auto state = coordinator->generationalOperationState(source);
        return state.phase == GenerationalOperationPhase::WorkerActive
            && state.resultObserved
            && state.workerOutcome == BackupOutcome::Unknown;
    }, 5000));
    VaultOperationGuard exclusive;
    EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), reservationError));
    coordinator.reset();
    EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), reservationError));

    suppressStop = false;
    ASSERT_TRUE(stuck);
    realAutoKill(stuck);
    ASSERT_TRUE(until([&] {
        return exclusive.tryReserve(source.toStdString(), reservationError);
    }, 2000));
}

TEST_F(GenerationalAutomaticBackupTest, ConfirmedMutationsRestartSingleShotAndFormSuccessiveBatches)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 100);

    mutate();
    EXPECT_TRUE(coordinator->modificationGroupingPending());
    EXPECT_EQ(coordinator->mutationGeneration(), 1u);
    QThread::msleep(40); // No event delivery: the next COMMIT deterministically restarts the timer first.
    mutate();
    EXPECT_EQ(coordinator->mutationGeneration(), 2u);
    QThread::msleep(40);
    mutate();
    EXPECT_EQ(coordinator->mutationGeneration(), 3u);

    QElapsedTimer beforeLastDeadline;
    beforeLastDeadline.start();
    while (beforeLastDeadline.elapsed() < 60) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 0);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_EQ(mutationBatchGenerations.size(), 1);
    EXPECT_EQ(mutationBatchGenerations[0], 3u);
    EXPECT_EQ(mutationBatchPath, QFileInfo(source).absoluteFilePath());
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    const QString firstPublication = temporary.filePath(QStringLiteral("simulated-first.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[0], mutationBatchPath, mutationBatchGenerations[0],
        firstPublication));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Published,
        simulatedReceipt(0, firstPublication)));
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Published);

    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    ASSERT_EQ(mutationBatchGenerations.size(), 2);
    EXPECT_EQ(mutationBatchGenerations[1], 4u);
    EXPECT_EQ(completions, 0);
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(QDir(destination).entryList(QDir::Files).isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest, OtherVaultAndObsoleteSessionEventsAreIgnored)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 40);

    const QString other = temporary.filePath(QStringLiteral("other.pwdb"));
    std::string failure;
    ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(other.toStdString(), failure));
    VaultKeyMetadata metadata;
    metadata.vaultId.fill(0x43);
    ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(other.toStdString(), metadata, failure));
    VaultRegistration otherRegistration;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(other, otherRegistration, error),
        VaultRecognition::Registered);

    passwall::models::Credential foreign;
    foreign.title = "Fictitious foreign title";
    foreign.username = "fictitious-foreign-user";
    foreign.password = "fictitious-foreign-password";
    ASSERT_TRUE(CredentialService::add(other.toStdString(), key, foreign, failure)) << failure;
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    EXPECT_EQ(coordinator->mutationGeneration(), 0u);

    const quint64 obsolete = CredentialService::currentCommitGeneration();
    coordinator->trackVault(original); // New session, even for the same physical vault.
    emit CredentialService::events().committed(source, CredentialMutation::Added, obsolete);
    EXPECT_FALSE(coordinator->modificationGroupingPending());

    mutate();
    ASSERT_TRUE(coordinator->modificationGroupingPending());
    coordinator->trackVault(otherRegistration); // Ends the source session and cancels its deadline.
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < 80) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 0);

    foreign.title = "Fictitious foreign title updated";
    ASSERT_TRUE(CredentialService::update(other.toStdString(), key, foreign, failure)) << failure;
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(mutationBatchPath, QFileInfo(other).absoluteFilePath());
}

TEST_F(GenerationalAutomaticBackupTest, StoppingGroupingCancelsPendingDeadlineWithoutStartingBackup)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 40);
    mutate();
    ASSERT_TRUE(coordinator->modificationGroupingPending());

    coordinator->stopModificationGrouping();
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    EXPECT_EQ(coordinator->mutationGeneration(), 0u);
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < 80) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_EQ(completions, 0);
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(QDir(destination).entryList(QDir::Files).isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest, LockCapturesPendingMutationsAndDefersOneRequest)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();
    mutate();
    mutate();
    ASSERT_TRUE(coordinator->modificationGroupingPending());

    coordinator->requestPendingMutationsForLock(source);
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    EXPECT_EQ(coordinator->mutationGeneration(), 0u);
    EXPECT_EQ(mutationBatchRequests, 0); // Never delivered in the lock stack.

    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_EQ(mutationBatchGenerations.size(), 1);
    EXPECT_EQ(mutationBatchGenerations[0], 3u);
    EXPECT_EQ(mutationBatchPath, QFileInfo(source).absoluteFilePath());
    EXPECT_EQ(completions, 0);
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(QDir(destination).entryList(QDir::Files).isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest, LockWithoutPendingMutationEmitsNoRequest)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 10);
    coordinator->requestPendingMutationsForLock(source);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 0);

    coordinator->trackVault(original); // A new authenticated session.
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    coordinator->requestPendingMutationsForLock(source);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1); // The expired generation is not re-emitted.
}

TEST_F(GenerationalAutomaticBackupTest, LockAtPendingDeadlineDoesNotLoseOrDuplicateTheRequest)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    QThread::msleep(30); // Deadline elapsed, but its event has not been delivered.
    coordinator->requestPendingMutationsForLock(source);

    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    QElapsedTimer settle;
    settle.start();
    while (settle.elapsed() < 50) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 1);
    ASSERT_EQ(mutationBatchGenerations.size(), 1);
    EXPECT_EQ(mutationBatchGenerations[0], 1u);
}

TEST_F(GenerationalAutomaticBackupTest, CapturedLockRequestRetainsItsVaultIdentityAcrossANewSession)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    coordinator->trackVault(original);

    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(mutationBatchPath, QFileInfo(source).absoluteFilePath());
    ASSERT_EQ(mutationBatchGenerations.size(), 1);
    EXPECT_EQ(mutationBatchGenerations[0], 1u);
    EXPECT_FALSE(coordinator->modificationGroupingPending());
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainWithoutMutationCompletesIdempotentlyWithoutARequest)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20000);

    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error))
        << error.toStdString();
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Completed);
    EXPECT_FALSE(coordinator->generationalShutdownDrainState().requestPending);
    EXPECT_EQ(mutationBatchRequests, 0);

    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Completed);
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainMakesTheLatestGroupedCrudGenerationImmediatelyEligibleOnce)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20000);
    mutate();
    mutate();
    mutate();
    ASSERT_TRUE(coordinator->modificationGroupingPending());

    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error))
        << error.toStdString();
    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(mutationBatchGenerations[0], 3U);
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Draining);
    EXPECT_TRUE(coordinator->generationalShutdownDrainState().requestPending);
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainWaitsForARealWorkerThenPublishesThePostSnapshotGeneration)
{
    fake("gated-snapshot-published-file", 20000);
    mutate();
    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    const quint64 firstGeneration = mutationBatchGenerations[0];
    PreparedBackupDestination prepared;
    ASSERT_TRUE(BackupDestinationPreparer::prepare(initialPreferences(),
        original.file, firstGeneration, initialInspectionTime(), prepared, error))
        << error.toStdString();
    const QString firstDestination = prepared.destinationPath();
    ASSERT_TRUE(coordinator->startPreparedMutationBackupSnapshot(
        mutationBatchRequestIds[0], source, firstGeneration,
        std::move(prepared), error)) << error.toStdString();
    ASSERT_TRUE(until([&] {
        return QFileInfo::exists(firstDestination + QStringLiteral(".ready"));
    }, 1000));
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::WorkerActive);
    EXPECT_TRUE(coordinator->generationalShutdownDrainState().workerAlive);

    mutate(); // A distinct COMMIT after the first snapshot attempt began.
    EXPECT_EQ(mutationBatchRequests, 1);
    touch(firstDestination + QStringLiteral(".release"), "continue");
    ASSERT_TRUE(until([&] {
        return mutationBatchResults.size() == 1 && mutationBatchRequests == 2;
    }, 5000));
    EXPECT_EQ(mutationBatchResults[0].outcome,
        MutationBackupOutcome::Published);
    EXPECT_EQ(mutationBatchGenerations[1], 2U);

    const QString secondDestination =
        temporary.filePath(QStringLiteral("close-drain-generation-2.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[1], mutationBatchPath,
        mutationBatchGenerations[1], secondDestination));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[1], MutationBackupOutcome::Published,
        simulatedReceipt(1, secondDestination)));
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Completed);
    EXPECT_EQ(mutationBatchRequests, 2);
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainDoesNotCreateARedundantGenerationAfterPublishedAttempt)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const QString published =
        temporary.filePath(QStringLiteral("close-drain-single.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[0], mutationBatchPath,
        mutationBatchGenerations[0], published));

    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Published,
        simulatedReceipt(0, published)));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Completed);
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainReportsFailureOrUnknownWithoutAutomaticRetry)
{
    for (const auto outcome : {MutationBackupOutcome::Failed,
             MutationBackupOutcome::Unknown}) {
        if (coordinator) {
            coordinator->shutdown();
            coordinator.reset();
        }
        control(QString::fromLatin1(AUTO_REAL_WORKER), 20000);
        mutationBatchRequests = 0;
        mutationBatchGenerations.clear();
        mutationBatchRequestIds.clear();
        mutationBatchResults.clear();
        mutate();
        ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
        ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
        const QString output = temporary.filePath(
            outcome == MutationBackupOutcome::Failed
                ? QStringLiteral("close-drain-failed.pwdb")
                : QStringLiteral("close-drain-unknown.pwdb"));
        ASSERT_TRUE(coordinator->markMutationBackupStarted(
            mutationBatchRequestIds[0], mutationBatchPath,
            mutationBatchGenerations[0], output));
        ASSERT_TRUE(coordinator->markMutationBackupFinished(
            mutationBatchRequestIds[0], outcome));
        EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
            GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension);
        ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
        EXPECT_EQ(mutationBatchRequests, 1);
        EXPECT_TRUE(coordinator->generationalBackupSuspension(source).suspended);
    }
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainKeepsAnUnknownLiveWorkerDistinctUntilEffectiveTermination)
{
    fake("ignore", 20000);
    suppressStop = true;
    mutate();
    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    PreparedBackupDestination prepared;
    ASSERT_TRUE(BackupDestinationPreparer::prepare(initialPreferences(),
        original.file, mutationBatchGenerations[0], initialInspectionTime(),
        prepared, error)) << error.toStdString();
    const QString output = prepared.destinationPath();
    ASSERT_TRUE(coordinator->startPreparedMutationBackupSnapshot(
        mutationBatchRequestIds[0], source, mutationBatchGenerations[0],
        std::move(prepared), error)) << error.toStdString();
    ASSERT_TRUE(until([&] {
        return QFileInfo::exists(output + QStringLiteral(".ready"));
    }, 1000));

    coordinator->cancel();
    ASSERT_TRUE(until([&] {
        return coordinator->generationalShutdownDrainState().status
                == GenerationalShutdownDrainStatus::WorkerActive
            && coordinator->generationalBackupSuspension(source).suspended;
    }, 5000));
    EXPECT_TRUE(coordinator->generationalShutdownDrainState().workerAlive);
    VaultOperationGuard exclusive;
    std::string reservationError;
    EXPECT_FALSE(exclusive.tryReserve(source.toStdString(), reservationError));

    suppressStop = false;
    ASSERT_TRUE(stuck);
    realAutoKill(stuck);
    ASSERT_TRUE(until([&] {
        return coordinator->generationalShutdownDrainState().status
            == GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension;
    }, 2000));
    EXPECT_FALSE(coordinator->generationalShutdownDrainState().workerAlive);
    EXPECT_EQ(mutationBatchRequests, 1);
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainWaitsBehindAnAdmittedManualOperationWithoutLosingTheGeneration)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20000);
    auto manual = coordinator->acquireUserOperation(
        BackupUserOperation::ManualExport, source, error);
    ASSERT_TRUE(manual.valid()) << error.toStdString();
    mutate();

    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Draining);
    manual = {};
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    EXPECT_EQ(mutationBatchGenerations[0], 1U);
}

TEST_F(GenerationalAutomaticBackupTest,
    CloseDrainCancelsLateInitialInspectionAndRejectsStaleConfiguration)
{
    mutate(); // Populate before the coordinator observes commits.
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20000);
    AsyncInitialInspectionBarrier barrier;
    barrier.checkpoint = InitialBackupCheckpoint::BeforeDestinationPreparation;
    const auto launch = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(120), initialInspectionTime(),
        {waitAtInitialInspectionCheckpoint, &barrier});
    ASSERT_EQ(launch.outcome, InitialBackupInspectionLaunch::Started);
    ASSERT_TRUE(barrier.entered.tryAcquire(1, 1000));

    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Draining);
    const auto refused = coordinator->startInitialBackupInspectionAsync(
        initialPreferences(), authenticatedSession(120), initialInspectionTime());
    EXPECT_EQ(refused.outcome, InitialBackupInspectionLaunch::Refused);
    barrier.resume.release();
    ASSERT_TRUE(until([&] { return initialInspectionResults.size() == 1; }));
    EXPECT_EQ(initialInspectionResults[0].decision,
        InitialBackupDecision::Cancelled);
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::Completed);

    coordinator->shutdown();
    coordinator.reset();
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20000);
    coordinator->applyGlobalBackupPreferences(initialPreferences());
    mutate();
    ASSERT_TRUE(coordinator->beginGenerationalShutdownDrain(error));
    ASSERT_TRUE(until([&] { return mutationBatchRequests >= 1; }, 1000));
    const quint64 staleRequest = mutationBatchRequestIds.last();
    const quint64 staleGeneration = mutationBatchGenerations.last();
    PreparedBackupDestination staleDestination;
    ASSERT_TRUE(BackupDestinationPreparer::prepare(initialPreferences(),
        original.file, staleGeneration, initialInspectionTime(),
        staleDestination, error)) << error.toStdString();
    GlobalBackupPreferencesResult unavailable;
    unavailable.status = GlobalBackupPreferencesStatus::ReadError;
    unavailable.diagnostic = QStringLiteral("Configuration fictivement illisible.");
    coordinator->applyGlobalBackupPreferences(unavailable);
    EXPECT_TRUE(invalidatedGenerationalRequests.contains(staleRequest));
    EXPECT_FALSE(coordinator->startPreparedMutationBackupSnapshot(
        staleRequest, source, staleGeneration,
        std::move(staleDestination), error));
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownWithoutMutationProducesNoGenerationResult)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    coordinator->shutdown();

    EXPECT_TRUE(coordinator->canClose());
    EXPECT_EQ(mutationBatchRequests, 0);
    EXPECT_TRUE(mutationBatchOutcomes.isEmpty());
    EXPECT_TRUE(mutationBatchDiagnostics.isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownBeforeDeadlineExplicitlyFailsTheCapturedGeneration)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();
    ASSERT_TRUE(coordinator->modificationGroupingPending());

    coordinator->shutdown();

    EXPECT_TRUE(coordinator->canClose());
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    EXPECT_EQ(mutationBatchRequests, 0);
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    ASSERT_EQ(mutationBatchDiagnostics.size(), 1);
    EXPECT_TRUE(mutationBatchDiagnostics[0].contains(QStringLiteral("Fermeture normale")));
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownAfterOfferFailsItOnceWithoutStartingAWorker)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    coordinator->shutdown();
    QCoreApplication::processEvents();

    EXPECT_TRUE(coordinator->canClose());
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownSettlesActiveUnknownAndLaterGenerationFailed)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[0], mutationBatchPath, mutationBatchGenerations[0]));

    coordinator->trackVault(original);
    mutate();
    coordinator->shutdown();

    EXPECT_TRUE(coordinator->canClose());
    ASSERT_EQ(mutationBatchOutcomes.size(), 2);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchOutcomes[1], MutationBackupOutcome::Unknown);
    EXPECT_FALSE(coordinator->mutationBackupActive());
    EXPECT_EQ(mutationBatchRequests, 1);
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownDuringContentionEndsTheWaitWithoutRetry)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    QString startError;
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], destination + "/contended-close.db",
        std::move(contended), {}, startError));
    ASSERT_TRUE(coordinator->mutationContentionPending());

    coordinator->shutdown();
    replacement.reset();
    QCoreApplication::processEvents();

    EXPECT_TRUE(coordinator->canClose());
    EXPECT_FALSE(coordinator->mutationContentionPending());
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchRequests, 1);
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownAfterFailedOrUnknownAddsNoResultOrRetry)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[0], mutationBatchPath,
        mutationBatchGenerations[0]));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Failed));
    ASSERT_TRUE(coordinator->resumeGenerationalBackup(source, error))
        << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[1], mutationBatchPath,
        mutationBatchGenerations[1]));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[1], MutationBackupOutcome::Unknown));
    ASSERT_EQ(mutationBatchOutcomes.size(), 2);

    coordinator->shutdown();
    QCoreApplication::processEvents();

    EXPECT_TRUE(coordinator->canClose());
    EXPECT_EQ(mutationBatchOutcomes.size(), 2);
    EXPECT_EQ(mutationBatchRequests, 2);
}

TEST_F(GenerationalAutomaticBackupTest, ShutdownCancelsRealGenerationAndRetainsReservationUntilTermination)
{
    fake("cancel", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    const QString output = destination + QStringLiteral("/cancel-on-close.db");
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return QFileInfo::exists(output + ".ready"); }, 1000));
    VaultOperationGuard replacement;
    EXPECT_FALSE(replacement.tryReserve(source.toStdString(), accessError));

    coordinator->shutdown();
    ASSERT_TRUE(until([&] { return !coordinator->isActive(); }, 5000));
    ASSERT_TRUE(until([&] { return coordinator->canClose(); }, 1000));

    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    EXPECT_FALSE(QFileInfo::exists(output));
}

TEST_F(GenerationalAutomaticBackupTest, MutationDuringActiveBackupWaitsForItsOwnGeneration)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const quint64 firstRequest = mutationBatchRequestIds[0];
    const QString firstPublication = temporary.filePath(QStringLiteral("simulated-active.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        firstRequest, mutationBatchPath, mutationBatchGenerations[0], firstPublication));
    EXPECT_TRUE(coordinator->mutationBackupActive());

    mutate(); // This commit happened after the simulated start.
    QElapsedTimer expired;
    expired.start();
    while (expired.elapsed() < 60) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 1); // Never a concurrent second attempt.

    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        firstRequest, MutationBackupOutcome::Published,
        simulatedReceipt(0, firstPublication)));
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    ASSERT_EQ(mutationBatchGenerations.size(), 2);
    EXPECT_EQ(mutationBatchGenerations[0], 1u);
    EXPECT_EQ(mutationBatchGenerations[1], 2u);
    EXPECT_FALSE(coordinator->mutationBackupActive());
    EXPECT_EQ(completions, 0);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(GenerationalAutomaticBackupTest,
    LockDuringActiveBackupRetainsLaterGenerationBehindSuspension)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 1000);
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const quint64 firstRequest = mutationBatchRequestIds[0];
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        firstRequest, mutationBatchPath, mutationBatchGenerations[0]));

    coordinator->trackVault(original); // A later authenticated session.
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);

    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        firstRequest, MutationBackupOutcome::Unknown));
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    const auto suspended = coordinator->generationalBackupSuspension(source);
    ASSERT_TRUE(suspended.suspended);
    EXPECT_EQ(suspended.latestMutationGeneration, 1u);
    ASSERT_TRUE(coordinator->resumeGenerationalBackup(source, error))
        << error.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(mutationBatchGenerations[1], 1u); // New session, distinct request token.
    EXPECT_NE(mutationBatchRequestIds[0], mutationBatchRequestIds[1]);
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Unknown);
}

TEST_F(GenerationalAutomaticBackupTest,
    FailedGenerationSuspendsLaterCommitsUntilOneExplicitResume)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const quint64 failedRequest = mutationBatchRequestIds[0];
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        failedRequest, mutationBatchPath, mutationBatchGenerations[0]));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        failedRequest, MutationBackupOutcome::Failed));

    QElapsedTimer settle;
    settle.start();
    while (settle.elapsed() < 60) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 1);
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);

    mutate();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    auto suspended = coordinator->generationalBackupSuspension(source);
    ASSERT_TRUE(suspended.suspended);
    EXPECT_EQ(suspended.reason, GenerationalBackupSuspensionReason::Failed);
    EXPECT_EQ(suspended.latestMutationGeneration, 2u);
    EXPECT_FALSE(record().automaticSuspended); // No historical persistence.

    coordinator->requestPendingMutationsForLock(source);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    ASSERT_TRUE(coordinator->resumeGenerationalBackup(source, error))
        << error.toStdString();
    EXPECT_FALSE(coordinator->resumeGenerationalBackup(source, error));
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(mutationBatchGenerations[1], 2u);
    EXPECT_FALSE(coordinator->markMutationBackupFinished(
        failedRequest, MutationBackupOutcome::Published));
    suspended = coordinator->generationalBackupSuspension(source);
    EXPECT_TRUE(suspended.suspended);
    EXPECT_TRUE(suspended.resumeRequested);

    const quint64 resumedRequest = mutationBatchRequestIds[1];
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        resumedRequest, mutationBatchPath, mutationBatchGenerations[1],
        temporary.filePath(QStringLiteral("explicit-resume.pwdb"))));
    auto receipt = simulatedReceipt(1,
        temporary.filePath(QStringLiteral("explicit-resume.pwdb")));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        resumedRequest, MutationBackupOutcome::Published, receipt));
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 2);
    EXPECT_FALSE(coordinator->generationalBackupSuspension(source).suspended);
}

TEST_F(GenerationalAutomaticBackupTest,
    SuspensionIsIsolatedFromAnotherPhysicalVault)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        mutationBatchRequestIds[0], mutationBatchPath,
        mutationBatchGenerations[0]));
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Failed));

    const QString otherPath = temporary.filePath(QStringLiteral("other.pwdb"));
    std::string failure;
    ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(
        otherPath.toStdString(), failure)) << failure;
    VaultKeyMetadata metadata;
    metadata.vaultId.fill(0x63);
    ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(
        otherPath.toStdString(), metadata, failure)) << failure;
    VaultRegistration other;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(otherPath, other, error),
        VaultRecognition::Registered) << error.toStdString();
    coordinator->trackVault(other);
    passwall::models::Credential credential;
    credential.title = "Other fictitious vault";
    credential.username = "other-user";
    credential.password = "other-fictitious-password";
    ASSERT_TRUE(CredentialService::add(
        otherPath.toStdString(), key, credential, failure)) << failure;
    sodium_memzero(credential.password.data(), credential.password.size());

    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(mutationBatchPath, QFileInfo(otherPath).absoluteFilePath());
    EXPECT_TRUE(coordinator->generationalBackupSuspension(source).suspended);
    EXPECT_FALSE(coordinator->generationalBackupSuspension(otherPath).suspended);
}

TEST_F(GenerationalAutomaticBackupTest, ObsoleteResultCannotSettleANewerSessionRequest)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const quint64 oldRequest = mutationBatchRequestIds[0];
    EXPECT_FALSE(coordinator->markMutationBackupStarted(
        oldRequest + 1, mutationBatchPath, mutationBatchGenerations[0]));
    EXPECT_FALSE(coordinator->markMutationBackupStarted(
        oldRequest, mutationBatchPath + QStringLiteral(".other"), mutationBatchGenerations[0]));
    EXPECT_FALSE(coordinator->markMutationBackupStarted(
        oldRequest, mutationBatchPath, mutationBatchGenerations[0] + 1));
    const QString oldPublication = temporary.filePath(QStringLiteral("simulated-old.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        oldRequest, mutationBatchPath, mutationBatchGenerations[0], oldPublication));

    coordinator->trackVault(original);
    mutate();
    QElapsedTimer expired;
    expired.start();
    while (expired.elapsed() < 60) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_FALSE(coordinator->markMutationBackupFinished(
        oldRequest + 1, MutationBackupOutcome::Published));
    EXPECT_TRUE(coordinator->mutationBackupActive());

    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        oldRequest, MutationBackupOutcome::Published,
        simulatedReceipt(0, oldPublication)));
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    const quint64 currentRequest = mutationBatchRequestIds[1];
    const QString currentPublication = temporary.filePath(QStringLiteral("simulated-current.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(
        currentRequest, mutationBatchPath, mutationBatchGenerations[1], currentPublication));
    EXPECT_FALSE(coordinator->markMutationBackupFinished(
        oldRequest, MutationBackupOutcome::Published));
    EXPECT_TRUE(coordinator->mutationBackupActive());
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        currentRequest, MutationBackupOutcome::Published,
        simulatedReceipt(1, currentPublication)));
    EXPECT_FALSE(coordinator->mutationBackupActive());
}

TEST_F(GenerationalAutomaticBackupTest, RealGenerationJobPublishesWithItsRequestToken)
{
    fake("snapshot-published-file", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const QString published = destination + QStringLiteral("/generation-published.db");
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], published,
        std::move(access), {}, startError)) << startError.toStdString();
    EXPECT_TRUE(coordinator->mutationBackupActive());
    EXPECT_TRUE(coordinator->isActive());

    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Published);
    ASSERT_EQ(mutationBatchResults.size(), 1);
    EXPECT_EQ(mutationBatchResults[0].vaultPath, mutationBatchPath);
    EXPECT_EQ(mutationBatchResults[0].generation, mutationBatchGenerations[0]);
    EXPECT_EQ(mutationBatchResults[0].requestId, mutationBatchRequestIds[0]);
    EXPECT_EQ(mutationBatchResults[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationBatchResults[0].sessionGeneration, 0U);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome, BackupOutcome::Published);
    EXPECT_TRUE(mutationBatchResults[0].diagnostic.isEmpty());
    ASSERT_TRUE(mutationBatchResults[0].publication.has_value());
    ASSERT_EQ(mutationPublicationReceipts.size(), 1);
    EXPECT_EQ(mutationPublicationReceipts[0].requestId, mutationBatchRequestIds[0]);
    EXPECT_EQ(mutationPublicationReceipts[0].generation, mutationBatchGenerations[0]);
    EXPECT_EQ(mutationPublicationReceipts[0].vaultPath, mutationBatchPath);
    EXPECT_EQ(mutationPublicationReceipts[0].destination, published);
    EXPECT_EQ(mutationPublicationReceipts[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(mutationPublicationReceipts[0].sessionGeneration, 0U);
    EXPECT_TRUE(mutationPublicationReceipts[0].evidence.permitsDeletion());
    EXPECT_FALSE(coordinator->mutationBackupActive());
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(QFileInfo::exists(published));
    EXPECT_EQ(completions, 0); // Historical automatic path was not invoked.
    EXPECT_TRUE(rotations.isEmpty()); // Snapshot publication is distinct from rotation.
}

TEST_F(GenerationalAutomaticBackupTest, PublishedGenerationRequiresACompleteReceiptForTheExactDestination)
{
    for (const QByteArray mode : {QByteArray("snapshot-published-without-receipt"),
             QByteArray("snapshot-insufficient-receipt"),
             QByteArray("snapshot-wrong-path-receipt")}) {
        if (coordinator) {
            coordinator->shutdown();
            ASSERT_TRUE(until([&] { return !coordinator->isActive(); }));
            coordinator.reset();
        }
        fake(mode, 20);
        mutationBatchRequests = 0;
        mutationBatchPath.clear();
        mutationBatchGenerations.clear();
        mutationBatchRequestIds.clear();
        mutationBatchOutcomes.clear();
        mutationBatchResults.clear();
        mutationPublicationReceipts.clear();
        mutate();
        ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
        VaultOperationGuard access;
        std::string accessError;
        ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
        const QString output = destination + QStringLiteral("/proof-")
            + QString::fromLatin1(mode) + QStringLiteral(".pwdb");
        QString startError;
        ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
            mutationBatchPath, mutationBatchGenerations[0], output,
            std::move(access), {}, startError)) << startError.toStdString();
        ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
        EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Unknown);
        ASSERT_EQ(mutationBatchResults.size(), 1);
        EXPECT_EQ(mutationBatchResults[0].workerOutcome, BackupOutcome::Unknown);
        EXPECT_TRUE(mutationBatchResults[0].diagnostic.contains(
            QStringLiteral("Preuve de publication")));
        EXPECT_TRUE(mutationPublicationReceipts.isEmpty());
        EXPECT_TRUE(QFileInfo::exists(output)); // Visibility alone never upgrades the result.
    }
}

TEST_F(GenerationalAutomaticBackupTest, SimulatedPublishedOutcomeCannotSettleWithoutMatchingReceipt)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const QString target = temporary.filePath(QStringLiteral("simulated-proof.pwdb"));
    ASSERT_TRUE(coordinator->markMutationBackupStarted(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], target));
    EXPECT_FALSE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Published));
    auto wrong = simulatedReceipt(0, target);
    ++wrong.requestId;
    EXPECT_FALSE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Published, wrong));
    wrong = simulatedReceipt(0, target);
    wrong.destination += QStringLiteral(".other");
    EXPECT_FALSE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Published, wrong));
    EXPECT_TRUE(coordinator->mutationBackupActive());
    EXPECT_TRUE(mutationPublicationReceipts.isEmpty());
    ASSERT_TRUE(coordinator->markMutationBackupFinished(
        mutationBatchRequestIds[0], MutationBackupOutcome::Unknown));
}

TEST_F(GenerationalAutomaticBackupTest, RealGenerationJobMapsConfirmedFailureWithoutRetry)
{
    fake("failed", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const QString failed = destination + QStringLiteral("/generation-failed.db");
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], failed,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_FALSE(QFileInfo::exists(failed));
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    EXPECT_EQ(completions, 0);
}

TEST_F(GenerationalAutomaticBackupTest, GenerationResultPreservesWorkerFailureDiagnostic)
{
    fake("enospc", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    const QString output = destination + QStringLiteral("/generation-enospc.db");
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    const auto& result = mutationBatchResults[0];
    EXPECT_EQ(result.outcome, MutationBackupOutcome::Failed);
    EXPECT_EQ(result.workerOutcome, BackupOutcome::FailedBeforePublication);
    EXPECT_EQ(result.diagnostic, QStringLiteral("Écriture [errno=28]."));
    EXPECT_EQ(result.requestId, mutationBatchRequestIds[0]);
    EXPECT_EQ(result.generation, mutationBatchGenerations[0]);
    EXPECT_FALSE(result.publication.has_value());
    EXPECT_FALSE(QFileInfo::exists(output));
}

TEST_F(GenerationalAutomaticBackupTest, GenerationResultDistinguishesConfirmedCancellation)
{
    fake("cancel", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    const QString output = destination + QStringLiteral("/generation-cancelled.db");
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return QFileInfo::exists(output + ".ready"); }, 1000));
    coordinator->cancel();
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Failed);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome,
        BackupOutcome::CancelledBeforePublication);
    EXPECT_TRUE(mutationBatchResults[0].diagnostic.isEmpty());
    EXPECT_FALSE(mutationBatchResults[0].publication.has_value());
}

TEST_F(GenerationalAutomaticBackupTest, GenerationResultPreservesDurabilityUnconfirmed)
{
    fake("durability-file", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    const QString output = destination + QStringLiteral("/generation-durability.db");
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchResults.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchResults[0].outcome, MutationBackupOutcome::Unknown);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome,
        BackupOutcome::DurabilityUnconfirmed);
    EXPECT_FALSE(mutationBatchResults[0].publication.has_value());
    EXPECT_TRUE(QFileInfo::exists(output));
}

TEST_F(GenerationalAutomaticBackupTest, RealGenerationJobMapsMissingOrCrashedResultToUnknown)
{
    for (const QByteArray mode : {QByteArray("missing"), QByteArray("crash")}) {
        if (coordinator) {
            coordinator->shutdown();
            ASSERT_TRUE(until([&] { return !coordinator->isActive(); }));
            coordinator.reset();
        }
        fake(mode, 20);
        mutationBatchRequests = 0;
        mutationBatchPath.clear();
        mutationBatchGenerations.clear();
        mutationBatchRequestIds.clear();
        mutationBatchOutcomes.clear();
        mutationBatchResults.clear();
        mutate();
        ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
        VaultOperationGuard access;
        std::string accessError;
        ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
        QString startError;
        const QString output = destination + QStringLiteral("/generation-")
            + QString::fromLatin1(mode) + QStringLiteral(".db");
        ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
            mutationBatchPath, mutationBatchGenerations[0], output,
            std::move(access), {}, startError)) << startError.toStdString();
        ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
        EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Unknown);
        ASSERT_EQ(mutationBatchResults.size(), 1);
        EXPECT_EQ(mutationBatchResults[0].workerOutcome, BackupOutcome::Unknown);
        EXPECT_FALSE(mutationBatchResults[0].diagnostic.isEmpty());
        EXPECT_FALSE(mutationBatchResults[0].publication.has_value());
        EXPECT_FALSE(QFileInfo::exists(output));
        EXPECT_EQ(mutationBatchRequests, 1);
    }
}

TEST_F(GenerationalAutomaticBackupTest, RealActiveGenerationPreservesLaterCommitWithoutConcurrentWorker)
{
    fake("slow-snapshot-published-file");
    // Recreate with an injectable grouping delay while preserving the fake mode.
    coordinator->shutdown();
    coordinator.reset();
    control(QString::fromLatin1(AUTO_FAKE_WORKER), 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const QString first = destination + QStringLiteral("/generation-slow.db");
    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    QString startError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], first,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(coordinator->isActive());

    mutate();
    QElapsedTimer expired;
    expired.start();
    while (expired.elapsed() < 60) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    EXPECT_EQ(mutationBatchRequests, 1);
    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Published);
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_EQ(mutationBatchGenerations[1], 2u);
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_EQ(completions, 0);
}

TEST_F(GenerationalAutomaticBackupTest, TemporaryReservationContentionRetriesAfterActualRelease)
{
    fake("snapshot-published-file", 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    ASSERT_TRUE(contended.contended());
    QString startError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0],
        destination + QStringLiteral("/blocked.db"), std::move(contended), {}, startError));
    EXPECT_TRUE(coordinator->mutationContentionPending());
    EXPECT_FALSE(coordinator->mutationBackupActive());

    replacement.reset();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    EXPECT_NE(mutationBatchRequestIds[0], mutationBatchRequestIds[1]);
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0],
        destination + QStringLiteral("/stale-token.db"), {}, {}, startError));
    VaultOperationGuard access;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[1],
        mutationBatchPath, mutationBatchGenerations[1],
        destination + QStringLiteral("/after-replacement.db"),
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Published);
    EXPECT_TRUE(mutationBatchDiagnostics.isEmpty());
}

TEST_F(GenerationalAutomaticBackupTest, PersistentContentionExpiresOnceWithExplicitFailure)
{
    fake("snapshot-published-file", 20, 60);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    ASSERT_TRUE(contended.contended());
    QString startError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0],
        destination + QStringLiteral("/never-started.db"),
        std::move(contended), {}, startError));

    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 1000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    ASSERT_EQ(mutationBatchResults.size(), 1);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome,
        BackupOutcome::FailedBeforePublication);
    EXPECT_TRUE(mutationBatchResults[0].diagnostic.contains(
        QStringLiteral("toujours indisponible")));
    ASSERT_EQ(mutationBatchDiagnostics.size(), 1);
    EXPECT_TRUE(mutationBatchDiagnostics[0].contains(QStringLiteral("toujours indisponible")));
    EXPECT_FALSE(coordinator->mutationContentionPending());
    EXPECT_FALSE(coordinator->isActive());
    replacement.reset();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1); // The expired generation is never retried.
}

TEST_F(GenerationalAutomaticBackupTest, LaterGenerationSurvivesContentionAndRunsAfterTheFirstAttempt)
{
    fake("snapshot-published-file", 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    mutate(); // A later generation exists before the incompatible reservation.
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    QString startError;
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], destination + "/blocked.db",
        std::move(contended), {}, startError));

    ASSERT_TRUE(until([&] { return !coordinator->modificationGroupingPending(); }, 1000));
    replacement.reset();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    VaultOperationGuard access;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[1],
        mutationBatchPath, mutationBatchGenerations[1], destination + "/first-generation.db",
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 3; }, 1000));
    ASSERT_EQ(mutationBatchGenerations.size(), 3);
    EXPECT_EQ(mutationBatchGenerations[0], 1u);
    EXPECT_EQ(mutationBatchGenerations[1], 1u);
    EXPECT_EQ(mutationBatchGenerations[2], 2u);
    EXPECT_NE(mutationBatchRequestIds[1], mutationBatchRequestIds[2]);
}

TEST_F(GenerationalAutomaticBackupTest, CompetingReservationAfterWakeDoesNotBypassTheSingleDeadline)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    std::string accessError;
    VaultOperationGuard first;
    ASSERT_TRUE(first.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    QString startError;
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], destination + "/blocked.db",
        std::move(contended), {}, startError));

    first.reset();
    VaultOperationGuard competitor;
    ASSERT_TRUE(competitor.tryReserve(source.toStdString(), accessError)) << accessError;
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    VaultOperationGuard contendedAgain;
    ASSERT_FALSE(contendedAgain.trySnapshotAccess(source.toStdString(), accessError));
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[1],
        mutationBatchPath, mutationBatchGenerations[1], destination + "/blocked-again.db",
        std::move(contendedAgain), {}, startError));
    competitor.reset();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 3; }, 1000));
    EXPECT_TRUE(coordinator->cancelMutationBackupBeforeLaunch(mutationBatchRequestIds[2],
        mutationBatchPath, mutationBatchGenerations[2]));
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
}

TEST_F(GenerationalAutomaticBackupTest, CancellationWhileWaitingPreventsAReleaseFromRetrying)
{
    control(QString::fromLatin1(AUTO_REAL_WORKER), 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    QString startError;
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], destination + "/cancelled.db",
        std::move(contended), {}, startError));
    ASSERT_TRUE(coordinator->cancelMutationBackupBeforeLaunch(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0]));
    replacement.reset();
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 1);
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    ASSERT_EQ(mutationBatchResults.size(), 1);
    EXPECT_EQ(mutationBatchResults[0].workerOutcome,
        BackupOutcome::CancelledBeforePublication);
    EXPECT_TRUE(mutationBatchResults[0].diagnostic.contains(
        QStringLiteral("annulée avant lancement")));
}

TEST_F(GenerationalAutomaticBackupTest, PhysicalReplacementDuringContentionInvalidatesTheRetriedRequest)
{
    fake("snapshot-published-file", 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    QString startError;
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], destination + "/old-principal.db",
        std::move(contended), {}, startError));
    replaceSourceWithAnotherVault(); // External actor deliberately ignores the cooperative lock.
    replacement.reset();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    VaultOperationGuard current;
    ASSERT_TRUE(current.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[1],
        mutationBatchPath, mutationBatchGenerations[1], destination + "/wrong-vault.db",
        std::move(current), {}, startError));
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_FALSE(QFileInfo::exists(destination + "/wrong-vault.db"));
}

TEST_F(GenerationalAutomaticBackupTest, WorkerFailureAfterContentionIsNeverRetriedAutomatically)
{
    fake("failed", 20, 500);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    VaultOperationGuard replacement;
    std::string accessError;
    ASSERT_TRUE(replacement.tryReserve(source.toStdString(), accessError)) << accessError;
    VaultOperationGuard contended;
    ASSERT_FALSE(contended.trySnapshotAccess(source.toStdString(), accessError));
    QString startError;
    ASSERT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], destination + "/failed.db",
        std::move(contended), {}, startError));
    replacement.reset();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 2; }, 1000));
    VaultOperationGuard access;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[1],
        mutationBatchPath, mutationBatchGenerations[1], destination + "/failed.db",
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    QCoreApplication::processEvents();
    EXPECT_EQ(mutationBatchRequests, 2);
}

TEST_F(GenerationalAutomaticBackupTest, PhysicalReplacementBeforeGenerationLaunchIsRejectedAndSettled)
{
    fake("snapshot-published-file", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));
    const QString previous = replaceSourceWithAnotherVault();
    ASSERT_TRUE(QFileInfo::exists(previous));

    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    const QString output = destination + QStringLiteral("/wrong-physical-source.db");
    QString startError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, startError));
    EXPECT_FALSE(startError.isEmpty());
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_FALSE(coordinator->mutationBackupActive());
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_FALSE(QFileInfo::exists(output));
    EXPECT_EQ(mutationBatchRequests, 1); // Stale generation is never retried.
}

TEST_F(GenerationalAutomaticBackupTest, ConcurrentPathSubstitutionCannotReusePinnedSnapshotCapability)
{
    fake("snapshot-published-file", 20);
    mutate();
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    VaultOperationGuard oldAccess;
    std::string accessError;
    ASSERT_TRUE(oldAccess.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    replaceSourceWithAnotherVault(); // Models a third party ignoring cooperative locks.

    const QString output = destination + QStringLiteral("/substituted.db");
    QString startError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(oldAccess), {}, startError));
    ASSERT_EQ(mutationBatchOutcomes.size(), 1);
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Failed);
    EXPECT_FALSE(QFileInfo::exists(output));

    VaultOperationGuard currentAccess;
    ASSERT_TRUE(currentAccess.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    EXPECT_FALSE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(currentAccess), {}, startError));
    EXPECT_EQ(mutationBatchOutcomes.size(), 1); // Settled request cannot be reused.
    EXPECT_FALSE(QFileInfo::exists(output));
}

TEST_F(GenerationalAutomaticBackupTest, OrdinaryLockAndNewSessionPreserveMatchingPhysicalRequest)
{
    fake("snapshot-published-file", 1000);
    mutate();
    coordinator->requestPendingMutationsForLock(source);
    coordinator->trackVault(original); // Same physical vault, new authenticated session.
    ASSERT_TRUE(until([&] { return mutationBatchRequests == 1; }, 1000));

    VaultOperationGuard access;
    std::string accessError;
    ASSERT_TRUE(access.trySnapshotAccess(source.toStdString(), accessError)) << accessError;
    const QString output = destination + QStringLiteral("/locked-generation.db");
    QString startError;
    ASSERT_TRUE(coordinator->startMutationBackupSnapshot(mutationBatchRequestIds[0],
        mutationBatchPath, mutationBatchGenerations[0], output,
        std::move(access), {}, startError)) << startError.toStdString();
    ASSERT_TRUE(until([&] { return mutationBatchOutcomes.size() == 1; }, 5000));
    EXPECT_EQ(mutationBatchOutcomes[0], MutationBackupOutcome::Published);
    EXPECT_TRUE(QFileInfo::exists(output));
}

TEST_F(AutomaticBackupTest, DisabledBackupsNeverLaunchOrCreateAFile)
{
    control(); coordinator->requestForLockedVault(source); QCoreApplication::processEvents();
    EXPECT_FALSE(coordinator->isActive()); EXPECT_EQ(completions, 0);
    EXPECT_TRUE(QDir(destination).entryList(QDir::Files).isEmpty());
}
TEST_F(AutomaticBackupTest, ActivationMakesFirstRealSnapshotWithoutAnyRecentCrud)
{
    control(); enable(); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::Published) << last.diagnostic.toStdString();
    const auto saved = record(); ASSERT_EQ(saved.automaticVersions.size(), 1);
    EXPECT_FALSE(saved.backupRequired); EXPECT_FALSE(saved.automaticSuspended);
    EXPECT_TRUE(saved.automaticVersions[0].durable);
    EXPECT_TRUE(encryptedRows(saved.automaticVersions[0].path) == encryptedRows(source));
    EXPECT_TRUE(QFileInfo(saved.automaticVersions[0].path).fileName().startsWith("password_"));
}
TEST_F(AutomaticBackupTest, MultipleCrudAreGroupedAndUnchangedLocksNeverDuplicate)
{
    control(); enable(); wait(); mutate(); mutate(); mutate();
    QCoreApplication::processEvents(); EXPECT_EQ(completions, 1);
    coordinator->requestForLockedVault(source); wait(2);
    EXPECT_FALSE(record().backupRequired); EXPECT_EQ(record().automaticVersions.size(), 2);
    coordinator->requestForLockedVault(source); QCoreApplication::processEvents();
    QCoreApplication::processEvents(); EXPECT_EQ(completions, 2);
}
TEST_F(AutomaticBackupTest, MissingDestinationSuspendsDurablyWithoutCreatingFallback)
{
    control(); const auto absent = temporary.filePath("absent/mount/backups"); enable(absent);
    ASSERT_TRUE(until([&] { return notices == 1; }));
    EXPECT_FALSE(QFileInfo::exists(absent)); EXPECT_TRUE(record().automaticSuspended);
    EXPECT_TRUE(record().backupRequired); EXPECT_EQ(completions, 0);
    coordinator->requestForLockedVault(source); QCoreApplication::processEvents(); EXPECT_EQ(notices, 1);
}
TEST_F(AutomaticBackupTest, UnsupportedFilesystemIsRejectedBeforeLaunchingWorker)
{
    control(); unsupported = true; enable();
    ASSERT_TRUE(until([&] { return notices == 1; })); unsupported = false;
    EXPECT_TRUE(message.contains("non prise en charge")); EXPECT_EQ(completions, 0);
    EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, SymlinkDestinationNeverRedirectsTheBackup)
{
    control(); const auto link = temporary.filePath("alias"); ASSERT_TRUE(QFile::link(destination, link)); enable(link);
    ASSERT_TRUE(until([&] { return notices == 1; }));
    EXPECT_TRUE(QDir(destination).entryList(QDir::Files).isEmpty()); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, WriteFailureReportsIdentifiableEnospcAndDoesNotRetry)
{
    fake("enospc"); enable(); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::FailedBeforePublication); EXPECT_TRUE(message.contains("Espace insuffisant"));
    EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
    mutate(); coordinator->requestForLockedVault(source); QCoreApplication::processEvents();
    EXPECT_EQ(completions, 1); EXPECT_EQ(notices, 1);
}
TEST_F(AutomaticBackupTest, MissingResultIsUnknownNotSuccess)
{
    fake("missing"); enable(); wait(); EXPECT_EQ(last.outcome, BackupOutcome::Unknown);
    EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, PublishedResponseWithoutAFileCannotClearIntent)
{
    fake("normal"); enable(); wait(); EXPECT_EQ(last.outcome, BackupOutcome::Unknown);
    EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, UnconfirmedDurabilityIsCataloguedWithoutClearingIntent)
{
    fake("durability-file"); enable(); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::DurabilityUnconfirmed);
    const auto saved = record(); ASSERT_EQ(saved.automaticVersions.size(), 1);
    EXPECT_FALSE(saved.automaticVersions[0].durable); EXPECT_TRUE(saved.backupRequired);
    EXPECT_TRUE(saved.automaticSuspended); EXPECT_TRUE(QFileInfo::exists(saved.automaticVersions[0].path));
}
TEST_F(AutomaticBackupTest, CatalogueFailurePreservesPublishedFileAndPendingSuspension)
{
    fake("published-file");
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::activityChanged, coordinator.get(),
        [](bool active) { if (active) failCatalogue = true; });
    enable(); wait(); failCatalogue = false;
    EXPECT_EQ(last.outcome, BackupOutcome::Unknown); EXPECT_TRUE(record().backupRequired);
    EXPECT_TRUE(record().automaticSuspended);
    EXPECT_EQ(QDir(destination).entryList({"password_*.db"}, QDir::Files).size(), 1);
}
TEST_F(AutomaticBackupTest, ChangedDestinationDoesNotSilentlyResumeButExplicitResumeCreatesCurrentSnapshot)
{
    control(); enable(temporary.filePath("missing")); ASSERT_TRUE(until([&] { return notices == 1; }));
    enable(); QCoreApplication::processEvents(); QCoreApplication::processEvents(); EXPECT_EQ(completions, 0);
    mutate(); coordinator->resumeAutomaticBackup(original.localId); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::Published); EXPECT_FALSE(record().backupRequired);
    EXPECT_TRUE(encryptedRows(record().automaticVersions.last().path) == encryptedRows(source));
}
TEST_F(AutomaticBackupTest, EditorOrOtherAccessDefersWithoutDiscardingAnythingOrSuspending)
{
    control(); enable();
    VaultOperationGuard editing; std::string failure;
    ASSERT_TRUE(editing.tryAccess(source.toStdString(), failure));
    ASSERT_TRUE(until([&] { return deferrals == 1; }));
    EXPECT_EQ(completions, 0); EXPECT_EQ(notices, 0); EXPECT_FALSE(record().automaticSuspended);
    editing.reset(); coordinator->retryPending(); wait(); EXPECT_EQ(last.outcome, BackupOutcome::Published);
}
TEST_F(AutomaticBackupTest, PausedCoordinationDoesNotStartUntilResumption)
{
    control(); coordinator->setPaused(true); enable(); QCoreApplication::processEvents();
    EXPECT_EQ(completions, 0); EXPECT_FALSE(coordinator->isActive());
    coordinator->setPaused(false); wait(); EXPECT_EQ(last.outcome, BackupOutcome::Published);
}
TEST_F(AutomaticBackupTest, ReservationRemainsHeldDuringResultPersistenceAndNotification)
{
    fake("slow-published-file"); enable();
    ASSERT_TRUE(until([&] { return coordinator->isActive(); }));
    VaultOperationGuard access; std::string failure;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    bool observed = false;
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::completed, coordinator.get(),
        [&](const QString&, BackupResult result) {
            observed = true; EXPECT_EQ(result.outcome, BackupOutcome::Published);
            EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
            EXPECT_FALSE(record().backupRequired);
        });
    wait(); EXPECT_TRUE(observed); EXPECT_TRUE(access.tryAccess(source.toStdString(), failure));
}
TEST_F(AutomaticBackupTest, VoluntaryCancellationSuspendsUntilExplicitResume)
{
    fake("cancel"); enable(); ASSERT_TRUE(until([&] { return coordinator->isActive(); }));
    ASSERT_TRUE(until([&] { return QFileInfo::exists(record().backupAttemptDestination + ".ready"); }));
    coordinator->cancel(); wait(); EXPECT_EQ(last.outcome, BackupOutcome::CancelledBeforePublication);
    EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, NormalShutdownCancellationKeepsIntentWithoutPermanentErrorSuspension)
{
    fake("cancel"); enable(); ASSERT_TRUE(until([&] { return coordinator->isActive(); }));
    ASSERT_TRUE(until([&] { return QFileInfo::exists(record().backupAttemptDestination + ".ready"); }));
    coordinator->shutdown(); wait(); ASSERT_TRUE(until([&] { return coordinator->canClose(); }));
    EXPECT_EQ(last.outcome, BackupOutcome::CancelledBeforePublication);
    EXPECT_TRUE(record().backupRequired); EXPECT_FALSE(record().automaticSuspended); EXPECT_EQ(notices, 0);
}
TEST_F(AutomaticBackupTest, ClosingAfterVoluntaryCancellationDoesNotEraseItsSuspension)
{
    fake("cancel"); enable(); ASSERT_TRUE(until([&] { return coordinator->isActive(); }));
    ASSERT_TRUE(until([&] { return QFileInfo::exists(record().backupAttemptDestination + ".ready"); }));
    coordinator->cancel(); coordinator->shutdown(); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::CancelledBeforePublication);
    EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, RestartRecognizesPendingIntentAndWaitsForTheNextAppropriateLock)
{
    enable(); mutate(); // No coordinator existed: simulate an earlier process exit.
    VaultRegistration saved;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(source, saved, error), VaultRecognition::Recognized);
    control(); coordinator->trackVault(saved); QCoreApplication::processEvents(); EXPECT_EQ(completions, 0);
    coordinator->requestForLockedVault(source); wait(); EXPECT_EQ(last.outcome, BackupOutcome::Published);
}
TEST_F(AutomaticBackupTest, CrashLatchSurvivesReconstructionAndDoesNotRetryWithoutResume)
{
    enable(); const auto saved = record();
    VaultOperationGuard reservation; std::string failure; ASSERT_TRUE(reservation.tryReserve(source.toStdString(), failure));
    SnapshotDirectoryIdentity identity;
    ASSERT_TRUE(VaultSnapshotService::inspectDestinationDirectory(destination.toStdString(), identity, failure));
    ASSERT_TRUE(VaultPreferencesStore().beginAutomaticBackup(saved, identity, destination + "/interrupted.db",
        QUuid::createUuid().toString(QUuid::WithoutBraces), reservation, error));
    reservation.reset(); control(); coordinator->trackVault(record()); coordinator->requestForLockedVault(source);
    QCoreApplication::processEvents(); QCoreApplication::processEvents(); EXPECT_EQ(completions, 0);
    EXPECT_TRUE(record().automaticSuspended); coordinator->resumeAutomaticBackup(original.localId); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::Published);
}
TEST_F(AutomaticBackupTest, RemountedOrReplacedDestinationIsNotSilentlyAccepted)
{
    control(); enable(); wait();
    ASSERT_TRUE(QDir().rename(destination, destination + "-old")); ASSERT_TRUE(QDir().mkpath(destination));
    ASSERT_TRUE(QFile::setPermissions(destination, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
    mutate(); coordinator->requestForLockedVault(source); ASSERT_TRUE(until([&] { return notices == 1; }));
    EXPECT_EQ(completions, 1); EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
    EXPECT_TRUE(QDir(destination).entryList(QDir::Files).isEmpty());
}
TEST_F(AutomaticBackupTest, UnexpectedSourceReplacementIsRefused)
{
    control(); enable();
    ASSERT_TRUE(QFile::rename(source, source + ".old")); ASSERT_TRUE(QFile::copy(source + ".old", source));
    const auto before = bytes(source); ASSERT_TRUE(until([&] { return notices == 1; }));
    EXPECT_EQ(completions, 0); EXPECT_EQ(bytes(source), before); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, OldConfirmationCannotClearTheIntentOfANewAttempt)
{
    control(); enable(); wait(); const auto old = record().automaticVersions.last().attemptId;
    mutate(); const auto expected = record();
    VaultOperationGuard reservation; std::string failure; ASSERT_TRUE(reservation.tryReserve(source.toStdString(), failure));
    SnapshotDirectoryIdentity identity;
    ASSERT_TRUE(VaultSnapshotService::inspectDestinationDirectory(destination.toStdString(), identity, failure));
    ASSERT_TRUE(VaultPreferencesStore().beginAutomaticBackup(expected, identity, destination + "/new.db",
        QUuid::createUuid().toString(QUuid::WithoutBraces), reservation, error));
    EXPECT_FALSE(VaultPreferencesStore().finishAutomaticBackup(original.localId, old,
        {BackupOutcome::Published, {}}, false, reservation, error));
    EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, ExistingBackupsAndManualExportsAreNeverDeleted)
{
    touch(destination + "/manual.db", "manual"); touch(destination + "/password_old.db", "old");
    control(); enable(); wait(); mutate(); coordinator->requestForLockedVault(source); wait(2);
    EXPECT_EQ(bytes(destination + "/manual.db"), "manual"); EXPECT_EQ(bytes(destination + "/password_old.db"), "old");
    EXPECT_EQ(record().automaticVersions.size(), 2);
    for (const auto& version : record().automaticVersions) EXPECT_TRUE(QFileInfo::exists(version.path));
}
TEST_F(AutomaticBackupTest, TwoBackupsInTheSameSecondUseDistinctNamesWithoutOverwriting)
{
    freezeTime = true; control(); enable(); wait(); mutate(); coordinator->requestForLockedVault(source); wait(2);
    const auto saved = record(); ASSERT_EQ(saved.automaticVersions.size(), 2);
    EXPECT_TRUE(saved.automaticVersions[0].path.endsWith("password_08-11-2026_14-35-22.db"));
    EXPECT_NE(saved.automaticVersions[0].path, saved.automaticVersions[1].path);
    EXPECT_TRUE(QFileInfo::exists(saved.automaticVersions[0].path));
    EXPECT_TRUE(QFileInfo::exists(saved.automaticVersions[1].path));
}
TEST_F(AutomaticBackupTest, DestinationDisappearingDuringTheRealCopyDoesNotRedirectPublication)
{
    const auto copy = temporary.filePath("during.pwdb"); ASSERT_TRUE(QFile::copy(source, copy)); source = copy;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(source, original, error), VaultRecognition::Registered);
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable();
    ASSERT_TRUE(until([&] { return QFileInfo::exists(source + ".checkpoint"); }));
    ASSERT_TRUE(QDir().rename(destination, destination + "-removed"));
    touch(source + ".resume"); wait();
    EXPECT_EQ(last.outcome, BackupOutcome::FailedBeforePublication);
    EXPECT_FALSE(QFileInfo::exists(destination)); EXPECT_TRUE(record().backupRequired);
    EXPECT_TRUE(record().automaticSuspended);
    EXPECT_TRUE(QDir(destination + "-removed").entryList({"*.db"}, QDir::Files).isEmpty());
}
TEST_F(AutomaticBackupTest, DifferentVaultsKeepTheirOwnVersionsAndIntents)
{
    control(); enable(); wait();
    const auto second = temporary.filePath("second.db"); ASSERT_TRUE(QFile::copy(source, second));
    VaultRegistration other;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(second, other, error), VaultRecognition::Registered);
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(other.localId, {true, destination, 7}, error)); wait(2);
    mutate(); EXPECT_TRUE(record().backupRequired);
    QVector<VaultRegistration> values; ASSERT_TRUE(VaultPreferencesStore().list(values, error));
    for (const auto& value : values) if (value.localId == other.localId) {
        EXPECT_FALSE(value.backupRequired); EXPECT_EQ(value.automaticVersions.size(), 1);
        EXPECT_TRUE(QFileInfo(value.automaticVersions[0].path).fileName().startsWith("second_"));
    }
}
TEST_F(AutomaticBackupTest, OccupiedVaultDoesNotStarveAnotherRegisteredVault)
{
    control(); enable(); VaultOperationGuard editing; std::string failure;
    ASSERT_TRUE(editing.tryAccess(source.toStdString(), failure));
    ASSERT_TRUE(until([&] { return deferrals == 1; }));
    const auto second = temporary.filePath("second.db"); ASSERT_TRUE(QFile::copy(source, second));
    VaultRegistration other;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(second, other, error), VaultRecognition::Registered);
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(other.localId, {true, destination, 7}, error));
    wait(); EXPECT_EQ(last.outcome, BackupOutcome::Published);
    EXPECT_TRUE(record().backupRequired); EXPECT_FALSE(record().automaticSuspended);
    editing.reset(); coordinator->retryPending(); wait(2); EXPECT_FALSE(record().backupRequired);
}
TEST_F(AutomaticBackupTest, WorkerRechecksTheActualDestinationIdentity)
{
    VaultOperationGuard reservation; std::string failure; ASSERT_TRUE(reservation.tryReserve(source.toStdString(), failure));
    SnapshotDirectoryIdentity identity;
    ASSERT_TRUE(VaultSnapshotService::inspectDestinationDirectory(destination.toStdString(), identity, failure));
    ++identity.inode;
    BackupJob job; bool done = false; BackupResult result;
    QObject::connect(&job, &BackupJob::finished, &job, [&](BackupResult value) { result = value; done = true; });
    ASSERT_TRUE(job.startReserved(source, destination + "/wrong.db", std::move(reservation), {}, identity));
    ASSERT_TRUE(until([&] { return done; })); EXPECT_EQ(result.outcome, BackupOutcome::FailedBeforePublication);
    EXPECT_FALSE(QFileInfo::exists(destination + "/wrong.db"));
}
TEST_F(AutomaticBackupTest, UnknownLiveChildKeepsReservationAfterCoordinatorDestruction)
{
    fake("ignore"); suppressStop = true; enable(); ASSERT_TRUE(until([&] { return coordinator->isActive(); }));
    ASSERT_TRUE(until([&] { return QFileInfo::exists(record().backupAttemptDestination + ".ready"); }));
    coordinator->cancel(); wait(); EXPECT_EQ(last.outcome, BackupOutcome::Unknown);
    EXPECT_TRUE(coordinator->isActive()); EXPECT_TRUE(record().automaticSuspended);
    VaultOperationGuard access; std::string failure; EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    coordinator.reset(); EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    suppressStop = false; ASSERT_TRUE(stuck); realAutoKill(stuck);
    ASSERT_TRUE(until([&] { return access.tryAccess(source.toStdString(), failure); }));
}

TEST_F(AutomaticBackupTest, RotationKeepsSevenAndRemovesOnlyTheOldestAfterEighthPublication)
{
    control(); enable(); wait();
    QStringList paths{record().automaticVersions.first().path};
    for (int i = 1; i < 7; ++i) { nextBackup(); paths << record().automaticVersions.last().path; }
    ASSERT_EQ(record().automaticVersions.size(), 7);
    for (const auto& p : paths) EXPECT_TRUE(QFileInfo::exists(p));
    ASSERT_TRUE(record().automaticVersions.first().evidence->permitsDeletion());
    nextBackup();
    EXPECT_FALSE(QFileInfo::exists(paths.first()));
    for (const auto& p : paths.mid(1)) EXPECT_TRUE(QFileInfo::exists(p));
    EXPECT_EQ(record().automaticVersions.size(), 7);
    EXPECT_EQ(record().automaticOrder, 8);
    EXPECT_TRUE(record().rotationState.isEmpty());
    ASSERT_EQ(rotations.size(), 8); EXPECT_EQ(rotations.last().deleted, 1);
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Complete);
}
TEST_F(AutomaticBackupTest, RotationRetentionReductionWaitsForNewConfirmedBackup)
{
    control(); enable(); wait();
    for (int i = 1; i < 7; ++i) nextBackup();
    retention(3); QCoreApplication::processEvents();
    EXPECT_EQ(record().automaticVersions.size(), 7); EXPECT_EQ(completions, 7);
    nextBackup(); EXPECT_EQ(record().automaticVersions.size(), 3); EXPECT_EQ(rotations.last().deleted, 5);
}
TEST_F(AutomaticBackupTest, RotationCustomLimitAndIncreaseNeverCreateArtificialVersions)
{
    control(); enable(); wait(); retention(2); nextBackup(); nextBackup();
    EXPECT_EQ(record().automaticVersions.size(), 2);
    retention(4); QCoreApplication::processEvents(); EXPECT_EQ(completions, 3);
    nextBackup(); EXPECT_EQ(record().automaticVersions.size(), 3); EXPECT_EQ(rotations.last().deleted, 0);
    nextBackup(); EXPECT_EQ(record().automaticVersions.size(), 4);
}
TEST_F(AutomaticBackupTest, RotationNeverTouchesManualUnknownOrPreRestoreCopies)
{
    for (const auto& name : {"manual.db", "password_01-01-2000_00-00-00.db", "pre-restore.db"})
        touch(destination + '/' + name, "fictitious-independent-file");
    control(); enable(); wait(); retention(1); nextBackup();
    for (const auto& name : {"manual.db", "password_01-01-2000_00-00-00.db", "pre-restore.db"})
        EXPECT_EQ(bytes(destination + '/' + name), "fictitious-independent-file");
    EXPECT_EQ(record().automaticVersions.size(), 1);
}
TEST_F(AutomaticBackupTest, RotationLegacyVersionIsNotRetroactivelyAuthorizedOrRetried)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    editCatalogue([](QJsonObject& r) {
        auto a = r["automaticVersions"].toArray(); auto v = a[0].toObject();
        v.remove("evidence"); v.remove("order"); v.remove("destinationEpoch"); a[0] = v; r["automaticVersions"] = a;
    });
    nextBackup(); EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
    EXPECT_FALSE(record().backupRequired); EXPECT_FALSE(record().automaticSuspended);
    const auto uncertain = record().rotationAttempt;
    nextBackup(); EXPECT_EQ(record().rotationAttempt, uncertain); EXPECT_EQ(record().automaticVersions.size(), 3);
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(last.outcome, BackupOutcome::Published);
}
TEST_F(AutomaticBackupTest, RotationRejectsModifiedContentEvenWhenItsSizeIsUnchanged)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    const auto before = bytes(old); ASSERT_GT(before.size(), 200);
    auto changed = before; changed[200] = changed[200] ^ 1; touch(old, changed);
    nextBackup(); EXPECT_EQ(bytes(old), changed); EXPECT_EQ(record().automaticVersions.size(), 2);
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationRejectsReplacedFileAtTheSamePath)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    ASSERT_TRUE(QFile::rename(old, old + ".preserved")); ASSERT_TRUE(QFile::copy(source, old));
    const auto replacement = bytes(old); nextBackup();
    EXPECT_EQ(bytes(old), replacement); EXPECT_TRUE(QFileInfo::exists(old + ".preserved"));
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationRejectsSymlinkAndPreservesItsTarget)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    ASSERT_TRUE(QFile::rename(old, old + ".preserved"));
    ASSERT_EQ(::symlink(QFile::encodeName(source).constData(), QFile::encodeName(old).constData()), 0);
    const auto before = bytes(source); nextBackup();
    EXPECT_TRUE(QFileInfo(old).isSymLink()); EXPECT_TRUE(QFileInfo::exists(old + ".preserved"));
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
    // CRUD legitimately changes the source; it remains a readable SQLite vault.
    EXPECT_FALSE(encryptedRows(source).isEmpty()); EXPECT_FALSE(before.isEmpty());
}
TEST_F(AutomaticBackupTest, RotationRejectsHardLinkedVersionAndPreservesBothNames)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    ASSERT_EQ(::link(QFile::encodeName(old).constData(), QFile::encodeName(old + ".alias").constData()), 0);
    nextBackup(); EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_TRUE(QFileInfo::exists(old + ".alias"));
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationNeverDeletesABackupRegisteredAsAnotherPrincipal)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    VaultRegistration secondary;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(old, secondary, error), VaultRecognition::Registered);
    nextBackup(); EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_TRUE(QFileInfo::exists(source));
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationUsesPublicationOrderDespiteClockRollbackAndSameSecondCollisions)
{
    freezeTime = true; frozenYear = 2030; control(); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first(); frozenYear = 2020; nextBackup();
    EXPECT_FALSE(QFileInfo::exists(old.path)); EXPECT_TRUE(record().automaticVersions.first().path.contains("2020"));
    const auto second = record().automaticVersions.first(); nextBackup();
    EXPECT_FALSE(QFileInfo::exists(second.path)); EXPECT_NE(record().automaticVersions.first().path, second.path);
    EXPECT_GT(record().automaticVersions.first().order, second.order);
}
TEST_F(AutomaticBackupTest, RotationLeavesAllOldDestinationsUntouchedEvenWhenReturningToOne)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    const auto other = temporary.filePath("new-destination"); ASSERT_TRUE(QDir().mkpath(other));
    ASSERT_TRUE(QFile::setPermissions(other, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
    auto p = record().backup; p.directory = other; ASSERT_TRUE(VaultPreferencesStore().updatePreferences(original.localId, p, error));
    nextBackup(); const auto elsewhere = record().automaticVersions.last().path; nextBackup();
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_FALSE(QFileInfo::exists(elsewhere));
    p.directory = destination; ASSERT_TRUE(VaultPreferencesStore().updatePreferences(original.localId, p, error));
    nextBackup(); nextBackup(); EXPECT_TRUE(QFileInfo::exists(old));
}
TEST_F(AutomaticBackupTest, RotationRejectsForgedDigestWithoutTrustingTheCatalogueAlone)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    editCatalogue([](QJsonObject& r) {
        auto a = r["automaticVersions"].toArray(); auto v = a[0].toObject();
        auto e = v["evidence"].toObject(); e["sha256"] = QString(64, '0'); v["evidence"] = e;
        a[0] = v; r["automaticVersions"] = a;
    });
    nextBackup(); EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationRefusesIncompleteEvidenceWithoutNormalizingTheConfiguration)
{
    control(); enable(); wait(); const auto old = record().automaticVersions.first().path;
    editCatalogue([](QJsonObject& r) {
        auto a = r["automaticVersions"].toArray(); auto v = a[0].toObject();
        auto e = v["evidence"].toObject(); e.remove("sha256"); v["evidence"] = e; a[0] = v; r["automaticVersions"] = a;
    });
    const auto before = bytes(configuration);
    QVector<VaultRegistration> out; EXPECT_FALSE(VaultPreferencesStore().list(out, error)); EXPECT_FALSE(error.isEmpty());
    EXPECT_EQ(bytes(configuration), before); EXPECT_TRUE(QFileInfo::exists(old));
}
TEST_F(AutomaticBackupTest, RotationNewReceiptBindsCiphertextDigestAndPublicationIdentity)
{
    control(); enable(); wait(); const auto v = record().automaticVersions.first();
    ASSERT_TRUE(v.evidence); EXPECT_EQ(v.evidence->sha256, QCryptographicHash::hash(bytes(v.path), QCryptographicHash::Sha256));
    EXPECT_EQ(v.evidence->inode, v.inode); EXPECT_EQ(v.evidence->size, quint64(bytes(v.path).size()));
    EXPECT_EQ(v.evidence->directoryInode, record().backupDirectory.inode); EXPECT_EQ(v.order, 1);
}
TEST_F(AutomaticBackupTest, RotationUnlinkErrorDoesNotSuspendBackupsOrCompensateWithOtherVersions)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; rotationFault("unlink", old); nextBackup();
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(record().automaticVersions.size(), 2);
    EXPECT_FALSE(record().backupRequired); EXPECT_FALSE(record().automaticSuspended);
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused); EXPECT_TRUE(message.contains("rotation"));
    const auto latch = record().rotationAttempt; nextBackup();
    EXPECT_EQ(record().rotationAttempt, latch); EXPECT_EQ(record().automaticVersions.size(), 3);
    for (const auto& v : record().automaticVersions) EXPECT_TRUE(QFileInfo::exists(v.path));
}
TEST_F(AutomaticBackupTest, RotationDirectorySyncFailureKeepsUncertainIntentAndNeverRepeatsDeletion)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; rotationFault("sync", old); nextBackup();
    EXPECT_FALSE(QFileInfo::exists(old)); EXPECT_FALSE(record().rotationCandidate.isEmpty());
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Unknown); EXPECT_FALSE(record().backupRequired);
    const auto latch = record().rotationAttempt; nextBackup(); EXPECT_EQ(record().rotationAttempt, latch);
    EXPECT_TRUE(QFileInfo::exists(record().automaticVersions.last().path));
}
TEST_F(AutomaticBackupTest, RotationCrashAfterUnlinkLeavesConservativeCatalogueAndCopySuccess)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; rotationFault("crash", old); nextBackup();
    EXPECT_FALSE(QFileInfo::exists(old)); EXPECT_EQ(record().rotationState, "running");
    EXPECT_FALSE(record().rotationCandidate.isEmpty()); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Unknown);
    EXPECT_FALSE(record().backupRequired); EXPECT_FALSE(record().automaticSuspended);
    nextBackup(); EXPECT_EQ(record().automaticVersions.size(), 3);
}
TEST_F(AutomaticBackupTest, RotationCatalogueSyncErrorAfterDeletionCannotDeleteAdditionalFiles)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); nextBackup(); nextBackup(); retention(1);
    const auto before = record().automaticVersions; rotationFault("catalogue", before.first().path); nextBackup();
    EXPECT_FALSE(QFileInfo::exists(before.first().path));
    for (const auto& v : before.sliced(1)) EXPECT_TRUE(QFileInfo::exists(v.path));
    EXPECT_EQ(last.outcome, BackupOutcome::Published); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Unknown);
}
TEST_F(AutomaticBackupTest, RotationSubstitutionBetweenHashAndFinalBindingNeverDeletesReplacement)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; const auto saved = bytes(old);
    rotationFault("swap", old); nextBackup();
    EXPECT_EQ(bytes(old), "unknown"); EXPECT_EQ(bytes(old + ".preserved"), saved);
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationMissingOrMalformedReplyIsNotACopyFailureAndIsNotRetried)
{
    fake("published-file"); enable(); wait(); retention(1);
    touch(source + ".fake-rotation-mode", "missing"); nextBackup();
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Unknown); EXPECT_FALSE(record().backupRequired);
    const auto pending = record().rotationAttempt; touch(source + ".fake-rotation-mode", "malformed"); nextBackup();
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Unknown); EXPECT_EQ(record().rotationAttempt, pending);
    EXPECT_EQ(record().automaticVersions.size(), 3); EXPECT_FALSE(record().automaticSuspended);
}
TEST_F(AutomaticBackupTest, RotationReservationIsContinuousAndCrudRemainsRefusedUntilRealTermination)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; rotationFault("pause", old);
    bool between = false;
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::copyConfirmed, coordinator.get(),
        [&](const QString&, BackupResult r) {
            between = true; EXPECT_EQ(r.outcome, BackupOutcome::Published);
            VaultOperationGuard access; std::string failure; EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
        });
    const int count = completions; mutate(); coordinator->requestForLockedVault(source);
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-checkpoint"); }));
    EXPECT_TRUE(between); EXPECT_EQ(completions, count); EXPECT_TRUE(coordinator->isActive());
    VaultOperationGuard access; std::string failure; EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    passwall::models::Credential c; c.title = "Fictitious"; c.username = "fictitious"; c.password = "fictitious-only";
    EXPECT_FALSE(CredentialService::add(source.toStdString(), key, c, failure));
    int events = 0; QTimer heartbeat; QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++events; }); heartbeat.start(1);
    ASSERT_TRUE(until([&] { return events > 3; })); // GUI/owner event loop remains live while child is paused.
    touch(destination + "/.rotation-resume", "resume"); wait(count + 1);
    EXPECT_TRUE(access.tryAccess(source.toStdString(), failure)); EXPECT_FALSE(QFileInfo::exists(old));
}
TEST_F(AutomaticBackupTest, RecoveryFenceDefersWithoutStartingOrSuspendingAutomaticBackup)
{
    control(); enable(); wait(); mutate();
    const auto before = record();
    {
        // Simulate only an already durable recovery fence, NOT a replacement
        // authorization or real cleanup acknowledgement.
        QSettings settings(configuration, QSettings::IniFormat);
        auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
        auto records = root["vaults"].toArray(); auto value = records[0].toObject();
        value["replacement"] = QJsonObject{{"version", 1}, {"operation", QUuid::createUuid().toString(QUuid::WithoutBraces)},
            {"previous", value["file"]}, {"previousDigest", QString(64, '0')},
            {"phase", "prepared"}, {"artifacts", QJsonArray{}}};
        records[0] = value; root["vaults"] = records;
        settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    }
    coordinator->requestForLockedVault(source);
    ASSERT_TRUE(until([&] { return deferrals == 1; }));
    EXPECT_FALSE(coordinator->isActive()); EXPECT_EQ(notices, 0); EXPECT_EQ(completions, 1);
    const auto after = record(); EXPECT_TRUE(after.replacement);
    EXPECT_EQ(after.backupRequired, before.backupRequired);
    EXPECT_EQ(after.automaticSuspended, before.automaticSuspended);
    EXPECT_EQ(after.backupAttempt, before.backupAttempt);
    EXPECT_EQ(after.automaticVersions, before.automaticVersions);
    VaultOperationGuard reservation; std::string failure;
    ASSERT_TRUE(reservation.tryReserve(source.toStdString(), failure));
    EXPECT_FALSE(VaultPreferencesStore().beginAutomaticBackup(before, before.backupDirectory,
        destination + "/blocked.db", QUuid::createUuid().toString(QUuid::WithoutBraces),
        reservation, error, true));
    EXPECT_EQ(record().automaticSuspended, before.automaticSuspended);
}
TEST_F(AutomaticBackupTest, RotationCancellationAfterCopyNeverRetractsPublishedBackup)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable();
    ASSERT_TRUE(until([&] { return completions == 1; })) << message.toStdString();
    const auto initial = record(); ASSERT_EQ(initial.automaticVersions.size(), 1);
    retention(1);
    const auto old = initial.automaticVersions.first().path; rotationFault("cancel", old);
    mutate(); coordinator->requestForLockedVault(source);
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-checkpoint"); }));
    const auto published = record().automaticVersions.last().path;
    const auto publishedBytes = bytes(published); ASSERT_FALSE(publishedBytes.isEmpty());
    const auto oldBytes = bytes(old); ASSERT_FALSE(oldBytes.isEmpty());
    observeReservationCompletion();
    coordinator->cancel(); coordinator->cancel(); // Requests, not receipt acknowledgements.
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-cancel-readable"); }));
    EXPECT_FALSE(QFileInfo::exists(destination + "/.rotation-cancel-received"));
    touch(destination + "/.rotation-resume", "resume");
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-cancel-received"); }));
    EXPECT_TRUE(coordinator->isActive()); EXPECT_EQ(completions, 1);
    VaultOperationGuard access; std::string failure;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    EXPECT_EQ(bytes(old), oldBytes); EXPECT_EQ(bytes(published), publishedBytes);
    // The REAL read consumed '!'; only now may ParentChannel accept it and
    // produce a terminal Cancelled record, then the child actually exits.
    touch(destination + "/.rotation-accept-cancel", "resume");
    ASSERT_TRUE(until([&] { return completions == 2 && !coordinator->isActive(); }));
    ASSERT_EQ(rotations.size(), 2);
    EXPECT_EQ(last.outcome, BackupOutcome::Published); EXPECT_FALSE(record().backupRequired);
    EXPECT_FALSE(record().automaticSuspended); EXPECT_EQ(record().automaticVersions.size(), 2);
    EXPECT_EQ(bytes(published), publishedBytes); EXPECT_EQ(bytes(old), oldBytes);
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Cancelled)
        << rotations.last().diagnostic.toStdString();
    EXPECT_EQ(rotations.last().deleted, 0);
    EXPECT_TRUE(completionWhileReserved); EXPECT_TRUE(terminationReleasedReservation);
    EXPECT_TRUE(access.tryAccess(source.toStdString(), failure));
}
TEST_F(AutomaticBackupTest, RotationQueuedCancellationCannotUndoAnAlreadyAppliedDeletion)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable();
    ASSERT_TRUE(until([&] { return completions == 1; })) << message.toStdString();
    const auto initial = record(); ASSERT_EQ(initial.automaticVersions.size(), 1);
    retention(1);
    const auto old = initial.automaticVersions.first().path; rotationFault("queued-cancel", old);
    mutate(); coordinator->requestForLockedVault(source);
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-checkpoint"); }));
    const auto published = record().automaticVersions.last().path;
    const auto publishedBytes = bytes(published); ASSERT_FALSE(publishedBytes.isEmpty());
    observeReservationCompletion();
    coordinator->cancel(); // Same request-before-resume order as the former test.
    touch(destination + "/.rotation-resume", "resume");
    // Do NOT dispatch Qt yet: the byte remains in QProcess's buffer. The real
    // cancellation read returns EAGAIN, and the real unlink succeeds first.
    ASSERT_TRUE(workerMarkerWithoutQtEvents(destination + "/.rotation-deleted"));
    EXPECT_TRUE(QFileInfo::exists(destination + "/.rotation-cancel-not-received"));
    EXPECT_FALSE(QFileInfo::exists(destination + "/.rotation-cancel-received"));
    EXPECT_FALSE(QFileInfo::exists(old)); EXPECT_EQ(bytes(published), publishedBytes);
    EXPECT_TRUE(coordinator->isActive()); EXPECT_EQ(completions, 1);
    VaultOperationGuard access; std::string failure;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    // Resume Qt delivery, then acknowledge the actual read separately from
    // accepting the cancellation and from process termination.
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-cancel-readable"); }));
    touch(destination + "/.rotation-return-unlink", "resume");
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-cancel-received"); }));
    EXPECT_TRUE(coordinator->isActive()); EXPECT_EQ(completions, 1);
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    touch(destination + "/.rotation-accept-cancel", "resume");
    ASSERT_TRUE(until([&] { return completions == 2 && !coordinator->isActive(); }));
    ASSERT_EQ(rotations.size(), 2);
    EXPECT_EQ(last.outcome, BackupOutcome::Published); EXPECT_FALSE(record().backupRequired);
    EXPECT_FALSE(record().automaticSuspended); EXPECT_EQ(record().automaticVersions.size(), 1);
    EXPECT_FALSE(QFileInfo::exists(old)); EXPECT_EQ(bytes(published), publishedBytes);
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Cancelled) << rotations.last().diagnostic.toStdString();
    EXPECT_EQ(rotations.last().deleted, 1); // Cancellation never restores a deleted old version.
    EXPECT_TRUE(completionWhileReserved); EXPECT_TRUE(terminationReleasedReservation);
    EXPECT_TRUE(access.tryAccess(source.toStdString(), failure));
}
TEST_F(AutomaticBackupTest, RotationClosingBetweenPhasesDoesNotLaunchCleanupOrLoseReservationEarly)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::copyConfirmed, coordinator.get(),
        [&](const QString&, BackupResult) {
            coordinator->shutdown(); VaultOperationGuard access; std::string failure;
            EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
        });
    nextBackup(); EXPECT_TRUE(coordinator->canClose()); EXPECT_TRUE(QFileInfo::exists(old));
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Cancelled); EXPECT_FALSE(record().backupRequired);
}
TEST_F(AutomaticBackupTest, RotationUnknownLiveChildKeepsReservationAfterFacadeDestruction)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; rotationFault("ignore", old);
    mutate(); coordinator->requestForLockedVault(source);
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-checkpoint"); }));
    suppressStop = true; coordinator->cancel(); wait(2);
    EXPECT_EQ(last.outcome, BackupOutcome::Published); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Unknown);
    EXPECT_TRUE(coordinator->isActive()); VaultOperationGuard access; std::string failure;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    coordinator->shutdown(); EXPECT_TRUE(coordinator->canClose()); coordinator.reset();
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    suppressStop = false; ASSERT_TRUE(stuck); realAutoKill(stuck);
    ASSERT_TRUE(until([&] { return access.tryAccess(source.toStdString(), failure); }));
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_FALSE(record().backupRequired);
}
TEST_F(AutomaticBackupTest, RotationDifferentVaultsSharingDirectoryRetainOnlyTheirOwnVersions)
{
    control(); enable(); wait(); retention(1);
    const auto other = temporary.filePath("other.db"); ASSERT_TRUE(QFile::copy(source, other));
    VaultRegistration secondary;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(other, secondary, error), VaultRecognition::Registered);
    coordinator->trackVault(secondary);
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(secondary.localId, {true, destination, 1}, error)); wait(2);
    QVector<VaultRegistration> records; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    QString secondPath;
    for (const auto& r : records) if (r.localId == secondary.localId) secondPath = r.automaticVersions.first().path;
    ASSERT_FALSE(secondPath.isEmpty()); nextBackup(); nextBackup();
    EXPECT_TRUE(QFileInfo::exists(secondPath)); EXPECT_EQ(record().automaticVersions.size(), 1);
}
TEST_F(AutomaticBackupTest, RotationDirectorySubstitutionAfterCopyPreservesFilesInTheOldDirectory)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::copyConfirmed, coordinator.get(),
        [&](const QString&, BackupResult) {
            EXPECT_TRUE(QDir().rename(destination, destination + ".preserved"));
            EXPECT_TRUE(QDir().mkpath(destination));
            EXPECT_TRUE(QFile::setPermissions(destination, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
        });
    nextBackup(); EXPECT_TRUE(QFileInfo::exists(destination + ".preserved/" + QFileInfo(old).fileName()));
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
    EXPECT_EQ(QDir(destination + ".preserved").entryList({"*.db"}, QDir::Files).size(), 2);
}
TEST_F(AutomaticBackupTest, RotationCannotClaimTheSamePersistentAuthorityTwice)
{
    control(); enable(); wait(); retention(1);
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::copyConfirmed, coordinator.get(),
        [&](const QString&, BackupResult) {
            EXPECT_EQ(record().rotationState, "prepared");
            coordinator->cancel();
        });
    nextBackup();
    VaultOperationGuard lease; std::string failure; ASSERT_TRUE(lease.tryReserve(source.toStdString(), failure));
    VaultRegistration output;
    ASSERT_TRUE(VaultPreferencesStore().claimRotation(original.localId,
        record().automaticVersions.last().attemptId, lease, output, error));
    EXPECT_EQ(output.rotationState, "running");
    EXPECT_FALSE(VaultPreferencesStore().claimRotation(original.localId,
        record().automaticVersions.last().attemptId, lease, output, error));
    EXPECT_TRUE(output.localId.isEmpty()); EXPECT_EQ(record().automaticVersions.size(), 2);
}
TEST_F(AutomaticBackupTest, RotationIntentPersistenceFailureNeverAuthorizesUnlink)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path; rotationFault("mark", old); nextBackup();
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(record().automaticVersions.size(), 2);
    EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused); EXPECT_FALSE(record().backupRequired);
}
TEST_F(AutomaticBackupTest, RotationPublicationReceiptRejectsSubstitutionBeforeAssociation)
{
    control(QString::fromLatin1(AUTO_PROBE_WORKER)); enable(); wait(); retention(1);
    const auto old = record().automaticVersions.first().path;
    touch(destination + "/.publication-swap", "swap");
    mutate(); coordinator->requestForLockedVault(source); wait(2);
    EXPECT_EQ(last.outcome, BackupOutcome::Unknown); EXPECT_TRUE(QFileInfo::exists(old));
    EXPECT_EQ(record().automaticVersions.size(), 1); EXPECT_TRUE(record().backupRequired);
    EXPECT_TRUE(record().automaticSuspended); EXPECT_EQ(rotations.size(), 1);
}
TEST_F(AutomaticBackupTest, RotationCannotRunAfterUnconfirmedPublicationOrCatalogueFailure)
{
    fake("published-file"); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    touch(source + ".fake-mode", "durability-file"); mutate(); coordinator->requestForLockedVault(source); wait(2);
    EXPECT_EQ(last.outcome, BackupOutcome::DurabilityUnconfirmed); EXPECT_EQ(rotations.size(), 1);
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_TRUE(record().backupRequired);
    touch(source + ".fake-mode", "published-file");
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::activityChanged, coordinator.get(),
        [](bool active) { if (active) failCatalogue = true; });
    coordinator->resumeAutomaticBackup(original.localId); wait(3); failCatalogue = false;
    EXPECT_EQ(last.outcome, BackupOutcome::Unknown); EXPECT_EQ(rotations.size(), 1); EXPECT_TRUE(QFileInfo::exists(old));
}
TEST_F(AutomaticBackupTest, RotationParentChannelClosureCancelsBeforeUnlink)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::copyConfirmed, coordinator.get(),
        [&](const QString&, BackupResult) { coordinator->cancel(); });
    nextBackup(); EXPECT_EQ(record().rotationState, "prepared"); rotationFault("pause", old);
    VaultOperationGuard reservation; std::string failure; ASSERT_TRUE(reservation.tryReserve(source.toStdString(), failure));
    const auto handles = reservation.inheritedHandles();
    QProcess process;
    process.setChildProcessModifier([handles] {
        for (int fd : handles) if (fd >= 0 && ::fcntl(fd, F_SETFD, 0) != 0) ::_exit(127);
    });
    process.start(QString::fromLatin1(AUTO_PROBE_WORKER), {"--rotation-v1", QString::number(handles[0]), QString::number(handles[1])});
    ASSERT_TRUE(until([&] { return process.state() == QProcess::Running; }));
    const auto request = backup_protocol::rotationRequest(source,
        {configuration, original.localId, record().rotationAttempt});
    ASSERT_EQ(process.write(request), request.size());
    ASSERT_TRUE(until([&] { return QFileInfo::exists(destination + "/.rotation-checkpoint"); }));
    process.closeWriteChannel(); touch(destination + "/.rotation-resume", "resume");
    ASSERT_TRUE(until([&] { return process.state() == QProcess::NotRunning; }));
    RotationResult result; ASSERT_TRUE(backup_protocol::parseRotationResult(process.readAllStandardOutput(), result));
    EXPECT_EQ(result.outcome, RotationOutcome::Cancelled) << result.diagnostic.toStdString();
    EXPECT_TRUE(QFileInfo::exists(old));
}
TEST_F(AutomaticBackupTest, RotationUnavailableBirthEvidenceNeverGrantsDeletionPermission)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    editCatalogue([](QJsonObject& r) {
        auto a = r["automaticVersions"].toArray(); auto v = a[0].toObject();
        auto e = v["evidence"].toObject(); e["birth"] = ""; v["birthTime"] = "";
        v["evidence"] = e; a[0] = v; r["automaticVersions"] = a;
    });
    nextBackup(); EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_EQ(rotations.last().outcome, RotationOutcome::Refused);
}
TEST_F(AutomaticBackupTest, RotationRealParentDeathKeepsTheChildReservationUntilCancellationAndExit)
{
    control(); enable(); wait(); retention(1); const auto old = record().automaticVersions.first().path;
    QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::copyConfirmed, coordinator.get(),
        [&](const QString&, BackupResult) { coordinator->cancel(); });
    nextBackup(); rotationFault("pause", old);
    QProcess helper;
    helper.start(QCoreApplication::applicationFilePath(), {"--rotation-parent-probe", source,
        configuration, original.localId, record().rotationAttempt, QString::fromLatin1(AUTO_PROBE_WORKER)});
    const bool reached = until([&] { return QFileInfo::exists(destination + "/.rotation-checkpoint"); });
    if (!reached) {
        touch(destination + "/.rotation-resume", "resume"); helper.kill();
        (void)until([&] { return helper.state() == QProcess::NotRunning; });
    }
    ASSERT_TRUE(reached);
    helper.kill(); ASSERT_TRUE(until([&] { return helper.state() == QProcess::NotRunning; }));
    VaultOperationGuard access; std::string failure;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), failure));
    touch(destination + "/.rotation-resume", "resume");
    ASSERT_TRUE(until([&] { return access.tryAccess(source.toStdString(), failure); }));
    EXPECT_TRUE(QFileInfo::exists(old)); EXPECT_FALSE(record().backupRequired);
    EXPECT_EQ(record().rotationState, "running");
}
}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() == 7 && args[1] == "--rotation-parent-probe") {
        // Isolated real parent process, killed by its test only AFTER the
        // rotation child reaches the explicit barrier. No default preferences.
        VaultOperationGuard reservation; std::string failure;
        if (!reservation.tryReserve(args[2].toStdString(), failure)) return 2;
        const auto handles = reservation.inheritedHandles();
        QProcess process;
        process.setChildProcessModifier([handles] {
            for (int fd : handles) if (fd >= 0 && ::fcntl(fd, F_SETFD, 0) != 0) ::_exit(127);
        });
        QObject::connect(&process, &QProcess::started, &app, [&] {
            const auto request = backup_protocol::rotationRequest(args[2], {args[3], args[4], args[5]});
            if (process.write(request) != request.size()) process.kill();
        });
        QObject::connect(&process, &QProcess::finished, &app, [&] { app.quit(); });
        QObject::connect(&process, &QProcess::errorOccurred, &app, [&](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) app.quit();
        });
        process.start(args[6], {"--rotation-v1", QString::number(handles[0]), QString::number(handles[1])});
        return app.exec();
    }
    QTemporaryDir isolated;
    if (!isolated.isValid()) return 2;
    for (auto format : {QSettings::NativeFormat, QSettings::IniFormat}) {
        QSettings::setPath(format, QSettings::UserScope, isolated.path());
        QSettings::setPath(format, QSettings::SystemScope, isolated.path());
    }
    ::testing::InitGoogleTest(&argc, argv); return RUN_ALL_TESTS();
}
