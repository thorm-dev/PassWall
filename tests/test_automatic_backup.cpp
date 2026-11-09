#include "services/automatic_backup_coordinator.hpp"
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
#include <QSettings>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>
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
    BackupResult last;
    QString message;
    QVector<RotationResult> rotations;
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
    void control(const QString& worker = QString::fromLatin1(AUTO_REAL_WORKER))
    {
        coordinator = std::make_unique<AutomaticBackupCoordinator>(VaultPreferencesStore(), worker);
        coordinator->trackVault(original);
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::completed,
            coordinator.get(), [this](const QString&, BackupResult result) { ++completions; last = result; });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::notification,
            coordinator.get(), [this](const QString&, const QString& text) { ++notices; message = text; });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::deferred,
            coordinator.get(), [this] { ++deferrals; });
        QObject::connect(coordinator.get(), &AutomaticBackupCoordinator::rotationCompleted,
            coordinator.get(), [this](const QString&, RotationResult result) { rotations.push_back(result); });
    }
    void fake(const QByteArray& mode)
    {
        touch(source + ".fake-mode", mode);
        control(QString::fromLatin1(AUTO_FAKE_WORKER));
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
