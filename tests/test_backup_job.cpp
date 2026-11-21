#include "services/backup_job.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_storage.hpp"
#include "storage/vault_operation_guard.hpp"
#include "posix_test_io.hpp"

#include <gtest/gtest.h>
#include <sodium.h>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>
#include <QScopeGuard>
#include <QPointer>
#include <functional>
#include <memory>
#include <optional>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

namespace {
// Test-only suppression models an unconfirmed stop, not a real kernel hang.
thread_local bool suppressProcessStops = false;
thread_local QPointer<QProcess> suppressedProcess;
}
extern "C" void realProcessKill(QProcess*) asm("__real__ZN8QProcess4killEv");
extern "C" void wrappedProcessKill(QProcess*) asm("__wrap__ZN8QProcess4killEv");
extern "C" void wrappedProcessKill(QProcess* process)
{
    if (suppressProcessStops) suppressedProcess = process;
    else realProcessKill(process);
}
extern "C" void realProcessTerminate(QProcess*) asm("__real__ZN8QProcess9terminateEv");
extern "C" void wrappedProcessTerminate(QProcess*) asm("__wrap__ZN8QProcess9terminateEv");
extern "C" void wrappedProcessTerminate(QProcess* process)
{
    if (suppressProcessStops) suppressedProcess = process;
    else realProcessTerminate(process);
}

namespace {
using namespace passwall::services;
bool until(const std::function<bool()>& predicate, int limit = 7000)
{
    QElapsedTimer timer;
    timer.start();
    while (!predicate() && timer.elapsed() < limit) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return predicate();
}
void touch(const QString& path)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
}
class BackupJobTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suite;
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-backup-case-XXXXXX")};
    QString source, destination;
    std::optional<BackupResult> result;
    int reports = 0;
    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        suite = std::make_unique<QTemporaryDir>(QStringLiteral("/tmp/passwall-backup-suite-XXXXXX"));
        ASSERT_TRUE(suite->isValid());
        passwall::core::SecureBuffer key(0);
        std::string error;
        const auto path = suite->filePath("template.pwdb").toStdString();
        ASSERT_TRUE(VaultLifecycleService::createVault(path, "fictitious-backup-master", key, error));
        passwall::models::Credential credential;
        credential.title = "Fictitious backup";
        credential.username = "fictitious-user";
        credential.password = "fictitious-only-password";
        credential.notes.assign(192 * 1024, 'n');
        ASSERT_TRUE(CredentialService::add(path, key, credential, error));
        sodium_memzero(credential.password.data(), credential.password.size());
        sodium_memzero(credential.notes.data(), credential.notes.size());
        key = passwall::core::SecureBuffer(0); // Never sent to driver/worker.
    }
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        source = directory.filePath("source.pwdb");
        destination = directory.filePath("backup.pwdb");
        ASSERT_TRUE(QFile::copy(suite->filePath("template.pwdb"), source));
    }
    void observe(BackupJob& job)
    {
        QObject::connect(&job, &BackupJob::finished, &job, [this](BackupResult value) {
            result = std::move(value); ++reports;
        });
    }
    void noTemporaries()
    {
        EXPECT_TRUE(QDir(directory.path()).entryList({".passwall-snapshot-*"}, QDir::Dirs | QDir::Hidden).isEmpty());
    }
    void useSource(const char* name)
    {
        source = directory.filePath(QString::fromLatin1(name));
        ASSERT_TRUE(QFile::copy(suite->filePath("template.pwdb"), source));
    }
};

TEST_F(BackupJobTest, RealWorkerPublishesKeylessSnapshotAndPreservesSource)
{
    QFile before(source); ASSERT_TRUE(before.open(QIODevice::ReadOnly));
    const auto original = before.readAll(); before.close();
    BackupJob job; observe(job);
    ASSERT_EQ(BackupJob::siblingWorkerPath(), QString::fromLatin1(REAL_BACKUP_WORKER));
    ASSERT_TRUE(job.start(source, destination));
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::Published) << result->diagnostic.toStdString();
    EXPECT_EQ(reports, 1);
    passwall::services::VaultKeyMetadata metadata;
    std::string error;
    EXPECT_TRUE(passwall::storage::VaultStorage::readMetadata(destination.toStdString(), metadata, error));
    ASSERT_TRUE(before.open(QIODevice::ReadOnly)); EXPECT_EQ(before.readAll(), original);
    noTemporaries();
}
TEST_F(BackupJobTest, MissingSourceIsConfirmedFailureAndNoDestinationIsCreated)
{
    BackupJob job; observe(job);
    ASSERT_TRUE(job.start(directory.filePath("missing.pwdb"), destination));
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::FailedBeforePublication);
    EXPECT_FALSE(QFile::exists(destination)); noTemporaries();
}
TEST_F(BackupJobTest, FailedLaunchCannotReportPublication)
{
    BackupJob job(directory.filePath("missing-executable")); observe(job);
    ASSERT_TRUE(job.start(source, destination));
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::FailedBeforePublication);
}
TEST_F(BackupJobTest, RejectsUncontrolledExecutableAndInvalidPaths)
{
    BackupJob job(QStringLiteral("passwall_backup_worker"));
    EXPECT_FALSE(job.start(source, destination));
    BackupJob normal;
    EXPECT_FALSE(normal.start(QStringLiteral("relative.pwdb"), destination));
    EXPECT_FALSE(normal.start(source, QString("/tmp/a") + QChar::Null + "b"));
}
TEST_F(BackupJobTest, SnapshotStartRejectsBusinessAndExclusiveCapabilities)
{
    std::string error;
    passwall::storage::VaultOperationGuard business;
    ASSERT_TRUE(business.tryAccess(source.toStdString(), error));
    BackupJob first;
    EXPECT_FALSE(first.startSnapshotReserved(source, destination, std::move(business), {}));

    passwall::storage::VaultOperationGuard exclusive;
    ASSERT_TRUE(exclusive.tryReserve(source.toStdString(), error));
    BackupJob second;
    EXPECT_FALSE(second.startSnapshotReserved(source, destination, std::move(exclusive), {}));
}
TEST_F(BackupJobTest, SnapshotPublicationReturnsReceiptBoundToDestination)
{
    passwall::storage::VaultOperationGuard snapshot;
    std::string error;
    ASSERT_TRUE(snapshot.trySnapshotAccess(source.toStdString(), error)) << error;
    BackupJob job; observe(job);
    ASSERT_TRUE(job.startSnapshotReserved(source, destination, std::move(snapshot), {}));
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    ASSERT_EQ(result->outcome, BackupOutcome::Published) << result->diagnostic.toStdString();
    ASSERT_TRUE(result->receipt.has_value());
    EXPECT_EQ(result->publishedPath, destination);
    EXPECT_TRUE(result->receipt->permitsDeletion());
}
TEST_F(BackupJobTest, CancellationBeforeDeferredStartNeverLaunches)
{
    BackupJob job; observe(job);
    ASSERT_TRUE(job.start(source, destination)); job.cancel(); job.cancel();
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::CancelledBeforePublication);
    EXPECT_FALSE(QFile::exists(destination)); noTemporaries();
}
TEST_F(BackupJobTest, CancellationDuringRealCopyCleansPrivateTemporaries)
{
    useSource("during.pwdb");
    BackupJob job(QString::fromLatin1(PROBE_BACKUP_WORKER)); observe(job);
    passwall::storage::VaultOperationGuard snapshot;
    std::string guardError;
    ASSERT_TRUE(snapshot.trySnapshotAccess(source.toStdString(), guardError)) << guardError;
    ASSERT_TRUE(job.startSnapshotReserved(source, destination, std::move(snapshot), {}));
    ASSERT_TRUE(until([&] { return QFile::exists(source + ".checkpoint"); }));
    passwall::storage::VaultOperationGuard business, replacement, secondSnapshot;
    EXPECT_TRUE(business.tryAccess(source.toStdString(), guardError));
    EXPECT_FALSE(replacement.tryReserve(source.toStdString(), guardError));
    EXPECT_FALSE(secondSnapshot.trySnapshotAccess(source.toStdString(), guardError));
    business.reset();
    job.cancel(); touch(source + ".resume");
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::CancelledBeforePublication);
    EXPECT_FALSE(QFile::exists(destination)); noTemporaries();
}
TEST_F(BackupJobTest, CancellationAfterLinkNeverErasesOrCallsPublishedFileCancelled)
{
    useSource("after.pwdb");
    BackupJob job(QString::fromLatin1(PROBE_BACKUP_WORKER)); observe(job);
    ASSERT_TRUE(job.start(source, destination));
    ASSERT_TRUE(until([&] { return QFile::exists(source + ".checkpoint"); }));
    ASSERT_TRUE(QFile::exists(destination));
    job.cancel(); touch(source + ".resume");
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::Published);
    EXPECT_TRUE(QFile::exists(destination)); noTemporaries();
}
TEST_F(BackupJobTest, DirectorySyncFailureKeepsPublishedFileAndPreciseUncertainty)
{
    useSource("durability.pwdb");
    BackupJob job(QString::fromLatin1(PROBE_BACKUP_WORKER)); observe(job);
    ASSERT_TRUE(job.start(source, destination));
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::DurabilityUnconfirmed);
    EXPECT_TRUE(QFile::exists(destination)); noTemporaries();
}
TEST_F(BackupJobTest, ExitAfterPublicationIsUnknownAndNeverDeletesFinalFile)
{
    useSource("crash.pwdb");
    BackupJob job(QString::fromLatin1(PROBE_BACKUP_WORKER)); observe(job);
    ASSERT_TRUE(job.start(source, destination));
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::Unknown);
    EXPECT_TRUE(QFile::exists(destination));
    // Abrupt _exit bypasses RAII: orphan staging is retained, not scanned/deleted.
}
TEST_F(BackupJobTest, MalformedMissingCrashedAndOversizedRepliesAreNeverSuccess)
{
    for (const auto* mode : {"crash", "missing", "malformed", "partial", "oversize"}) {
        result.reset();
        BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER)); observe(job);
        ASSERT_TRUE(job.start("/" + QString::fromLatin1(mode), destination));
        ASSERT_TRUE(until([&] { return result.has_value(); }));
        EXPECT_EQ(result->outcome, BackupOutcome::Unknown) << mode;
    }
}
TEST_F(BackupJobTest, ProtocolStatesAndFragmentedRecordsArePreserved)
{
    for (auto pair : {std::pair{"failed", BackupOutcome::FailedBeforePublication},
             {"durability", BackupOutcome::DurabilityUnconfirmed}, {"slow", BackupOutcome::Published}}) {
        result.reset();
        BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER)); observe(job);
        ASSERT_TRUE(job.start("/" + QString::fromLatin1(pair.first), destination));
        ASSERT_TRUE(until([&] { return result.has_value(); }));
        EXPECT_EQ(result->outcome, pair.second);
    }
}
TEST_F(BackupJobTest, LatePublicationRecordWinsOverCancellationRequest)
{
    BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER)); observe(job);
    ASSERT_TRUE(job.start("/late", destination));
    ASSERT_TRUE(until([&] { return QFile::exists(destination + ".ready"); }));
    job.cancel();
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::Published);
    EXPECT_EQ(reports, 1);
}
TEST_F(BackupJobTest, UnresponsiveChildEscalatesWithoutBlockingEventLoop)
{
    BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER)); observe(job);
    ASSERT_TRUE(job.start("/ignore", destination));
    ASSERT_TRUE(until([&] { return QFile::exists(destination + ".ready"); }));
    QElapsedTimer timer; timer.start();
    job.cancel();
    EXPECT_LT(timer.elapsed(), 100);
    int events = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, &heartbeat, [&] { ++events; });
    heartbeat.start(10);
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::Unknown);
    EXPECT_GT(events, 50);
}
TEST_F(BackupJobTest, DriverDestructionDoesNotDestroyActiveQProcessOrWait)
{
    useSource("during.pwdb");
    auto job = std::make_unique<BackupJob>(QString::fromLatin1(PROBE_BACKUP_WORKER));
    ASSERT_TRUE(job->start(source, destination));
    ASSERT_TRUE(until([&] { return QFile::exists(source + ".checkpoint"); }));
    QElapsedTimer timer; timer.start(); job.reset();
    EXPECT_LT(timer.elapsed(), 100);
    touch(source + ".resume");
    ASSERT_TRUE(until([&] {
        return QDir(directory.path()).entryList({".passwall-snapshot-*"}, QDir::Dirs | QDir::Hidden).isEmpty();
    }));
    EXPECT_FALSE(QFile::exists(destination));
}
TEST_F(BackupJobTest, ClosedParentChannelCancelsRealWorkerBeforePublication)
{
    useSource("during.pwdb");
    QProcess process;
    process.start(QString::fromLatin1(PROBE_BACKUP_WORKER), {"--protocol-v1"});
    ASSERT_TRUE(process.waitForStarted(2000));
    process.write(backup_protocol::request(source, destination));
    ASSERT_TRUE(until([&] { return QFile::exists(source + ".checkpoint"); }));
    process.closeWriteChannel(); touch(source + ".resume");
    ASSERT_TRUE(process.waitForFinished(5000));
    BackupResult value;
    ASSERT_TRUE(backup_protocol::parseResult(process.readAllStandardOutput(), value));
    EXPECT_EQ(value.outcome, BackupOutcome::CancelledBeforePublication);
    EXPECT_FALSE(QFile::exists(destination)); noTemporaries();
}

TEST_F(BackupJobTest, UnresponsiveChildIsReapedAfterDriverDestructionWithoutWaiting)
{
    auto job = std::make_unique<BackupJob>(QString::fromLatin1(FAKE_BACKUP_WORKER));
    ASSERT_TRUE(job->start("/ignore", destination));
    ASSERT_TRUE(until([&] { return QFile::exists(destination + ".ready"); }));
    QFile marker(destination + ".ready");
    ASSERT_TRUE(marker.open(QIODevice::ReadOnly));
    bool valid = false;
    const auto pid = marker.readAll().toLongLong(&valid);
    ASSERT_TRUE(valid); ASSERT_GT(pid, 1);
    QElapsedTimer timer; timer.start(); job.reset();
    EXPECT_LT(timer.elapsed(), 100);
    ASSERT_TRUE(until([&] { return ::kill(static_cast<pid_t>(pid), 0) == -1 && errno == ESRCH; }));
    EXPECT_LT(timer.elapsed(), 6000);
    EXPECT_FALSE(QFile::exists(destination));
}
TEST_F(BackupJobTest, WorkerRejectsInvalidOrOversizedRequestsWithoutPublishing)
{
    for (auto request : {QByteArray("{\"v\":2}\n"), QByteArray(32769, 'a') + '\n'}) {
        QProcess process;
        process.start(QString::fromLatin1(REAL_BACKUP_WORKER), {"--protocol-v1"});
        ASSERT_TRUE(process.waitForStarted(2000));
        process.write(request); process.closeWriteChannel();
        ASSERT_TRUE(process.waitForFinished(5000));
        EXPECT_NE(process.exitCode(), 0);
        EXPECT_TRUE(process.readAllStandardOutput().isEmpty());
        EXPECT_FALSE(QFile::exists(destination));
    }
}
TEST_F(BackupJobTest, WorkerRejectsForgedSnapshotDescriptorsWithoutPublishing)
{
    QProcess process;
    process.start(QString::fromLatin1(REAL_BACKUP_WORKER),
        {"--snapshot-v1", "64", "-1", "65"});
    ASSERT_TRUE(process.waitForStarted(2000));
    process.write(backup_protocol::request(source, destination));
    process.closeWriteChannel();
    ASSERT_TRUE(process.waitForFinished(5000));
    EXPECT_NE(process.exitCode(), 0);
    EXPECT_TRUE(process.readAllStandardOutput().isEmpty());
    EXPECT_FALSE(QFile::exists(destination));
}

TEST_F(BackupJobTest, ParentProcessDeathPreventsVoluntaryLatePublication)
{
    // Reap our deliberately orphaned grandchild ourselves, not through PID 1.
    int previous = 0;
    ASSERT_EQ(::prctl(PR_GET_CHILD_SUBREAPER, &previous), 0);
    ASSERT_EQ(::prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
    struct Reset { int value; ~Reset() { ::prctl(PR_SET_CHILD_SUBREAPER, value); } } reset{previous};
    useSource("during.pwdb");
    QProcess parent;
    parent.start(QCoreApplication::applicationFilePath(), {"--orphan-worker", source, destination});
    ASSERT_TRUE(parent.waitForStarted(2000));
    ASSERT_TRUE(parent.waitForFinished(7000));
    ASSERT_EQ(parent.exitCode(), 0);
    bool valid = false;
    const auto pid = parent.readAllStandardOutput().trimmed().toLongLong(&valid);
    ASSERT_TRUE(valid); ASSERT_GT(pid, 1);
    passwall::storage::VaultOperationGuard access;
    std::string error;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), error));
    touch(source + ".resume");
    int status = 0;
    bool reaped = false;
    ASSERT_TRUE(until([&] {
        if (reaped) return true;
        const auto result = ::waitpid(static_cast<pid_t>(pid), &status, WNOHANG);
        reaped = result == pid;
        return reaped;
    }));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_FALSE(QFile::exists(destination)); noTemporaries();
    EXPECT_TRUE(access.tryAccess(source.toStdString(), error));
}

TEST_F(BackupJobTest, UnknownWithLiveWorkerRetainsSnapshotSerializationUntilConfirmedTermination)
{
    QFile mode(source + ".fake-mode");
    ASSERT_TRUE(mode.open(QIODevice::WriteOnly)); mode.write("ignore"); mode.close();
    const auto restore = qScopeGuard([] {
        suppressProcessStops = false;
        if (suppressedProcess) realProcessKill(suppressedProcess);
        suppressedProcess.clear();
    });
    suppressProcessStops = true;
    BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER)); observe(job);
    int terminated = 0;
    QObject::connect(&job, &BackupJob::processTerminated, &job, [&] { ++terminated; });
    passwall::storage::VaultOperationGuard snapshot;
    std::string error;
    ASSERT_TRUE(snapshot.trySnapshotAccess(source.toStdString(), error)) << error;
    ASSERT_TRUE(job.startSnapshotReserved(source, destination, std::move(snapshot), {}));
    ASSERT_TRUE(until([&] { return QFile::exists(destination + ".ready"); }));
    job.cancel();
    ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_EQ(result->outcome, BackupOutcome::Unknown);
    EXPECT_TRUE(job.isActive()); EXPECT_EQ(terminated, 0);
    passwall::storage::VaultOperationGuard access, replacement;
    EXPECT_TRUE(access.tryAccess(source.toStdString(), error));
    EXPECT_FALSE(replacement.tryReserve(source.toStdString(), error));
    BackupJob another;
    EXPECT_FALSE(another.start(source, directory.filePath("another.db")));
    access.reset();
    ASSERT_TRUE(suppressedProcess);
    suppressProcessStops = false; realProcessKill(suppressedProcess);
    ASSERT_TRUE(until([&] { return !job.isActive(); }));
    EXPECT_EQ(terminated, 1); EXPECT_EQ(reports, 1);
    EXPECT_TRUE(replacement.tryReserve(source.toStdString(), error));
}

TEST_F(BackupJobTest, DestroyingFacadeAfterUnknownDoesNotReleaseLiveWorkerReservation)
{
    QFile mode(source + ".fake-mode");
    ASSERT_TRUE(mode.open(QIODevice::WriteOnly)); mode.write("ignore"); mode.close();
    const auto restore = qScopeGuard([] {
        suppressProcessStops = false;
        if (suppressedProcess) realProcessKill(suppressedProcess);
        suppressedProcess.clear();
    });
    suppressProcessStops = true;
    auto job = std::make_unique<BackupJob>(QString::fromLatin1(FAKE_BACKUP_WORKER)); observe(*job);
    passwall::storage::VaultOperationGuard snapshot;
    std::string error;
    ASSERT_TRUE(snapshot.trySnapshotAccess(source.toStdString(), error)) << error;
    ASSERT_TRUE(job->startSnapshotReserved(source, destination, std::move(snapshot), {}));
    ASSERT_TRUE(until([&] { return QFile::exists(destination + ".ready"); }));
    job->cancel(); ASSERT_TRUE(until([&] { return result.has_value(); }));
    EXPECT_TRUE(job->isActive()); job.reset();
    passwall::storage::VaultOperationGuard access, replacement;
    EXPECT_TRUE(access.tryAccess(source.toStdString(), error));
    EXPECT_FALSE(replacement.tryReserve(source.toStdString(), error));
    access.reset();
    ASSERT_TRUE(suppressedProcess);
    suppressProcessStops = false; realProcessKill(suppressedProcess);
    ASSERT_TRUE(until([&] { return replacement.tryReserve(source.toStdString(), error); }));
}

TEST_F(BackupJobTest, ExecChildRetainsReservationAfterUnexpectedParentExit)
{
    int previous = 0;
    ASSERT_EQ(::prctl(PR_GET_CHILD_SUBREAPER, &previous), 0);
    ASSERT_EQ(::prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
    const auto restore = qScopeGuard([&] {
        QFile exit(destination + ".exit");
        EXPECT_TRUE(exit.open(QIODevice::WriteOnly));
        EXPECT_EQ(::prctl(PR_SET_CHILD_SUBREAPER, previous), 0);
    });
    QFile mode(source + ".fake-mode");
    ASSERT_TRUE(mode.open(QIODevice::WriteOnly)); mode.write("orphan"); mode.close();
    QProcess parent;
    parent.start(QCoreApplication::applicationFilePath(), {"--orphan-driver", source, destination});
    ASSERT_TRUE(parent.waitForStarted(2000));
    ASSERT_TRUE(parent.waitForFinished(7000));
    ASSERT_EQ(parent.exitCode(), 0);
    QFile ready(destination + ".ready"); ASSERT_TRUE(ready.open(QIODevice::ReadOnly));
    bool ok = false; const auto pid = ready.readAll().toLongLong(&ok);
    ASSERT_TRUE(ok); ASSERT_GT(pid, 1);
    passwall::storage::VaultOperationGuard access, replacement, secondSnapshot;
    std::string error;
    EXPECT_TRUE(access.tryAccess(source.toStdString(), error));
    EXPECT_FALSE(replacement.tryReserve(source.toStdString(), error));
    EXPECT_FALSE(secondSnapshot.trySnapshotAccess(source.toStdString(), error));
    access.reset();
    touch(destination + ".exit");
    int status = 0;
    bool reaped = false;
    ASSERT_TRUE(until([&] {
        if (!reaped) reaped = ::waitpid(pid, &status, WNOHANG) == pid;
        return reaped;
    }));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_TRUE(replacement.tryReserve(source.toStdString(), error));
}

TEST_F(BackupJobTest, ProtocolRejectsWrongTypesVersionsAndDuplicateTerminalRecords)
{
    BackupResult value;
    EXPECT_FALSE(backup_protocol::parseResult("{\"v\":2,\"outcome\":\"published\",\"diagnostic\":\"\"}", value));
    EXPECT_FALSE(backup_protocol::parseResult("{\"v\":1,\"outcome\":true,\"diagnostic\":\"\"}", value));
    EXPECT_FALSE(backup_protocol::parseResult("{\"v\":1,\"outcome\":\"published\",\"diagnostic\":7}", value));
    const auto record = backup_protocol::result({BackupOutcome::Published, {}});
    EXPECT_FALSE(backup_protocol::parseResult(record + record, value));
    auto evidence = BackupFileEvidence{};
    evidence.device = 1; evidence.inode = 2; evidence.size = 3; evidence.mount = 4;
    evidence.directoryDevice = 5; evidence.directoryInode = 6; evidence.directoryMount = 7;
    evidence.modified = QStringLiteral("1:0"); evidence.changed = QStringLiteral("2:0");
    evidence.sha256 = QByteArray(32, 'p');
    const auto bound = backup_protocol::result(
        {BackupOutcome::Published, {}, evidence, destination});
    ASSERT_TRUE(backup_protocol::parseResult(bound, value));
    EXPECT_EQ(value.publishedPath, destination);
    ASSERT_TRUE(value.receipt.has_value());
    EXPECT_EQ(*value.receipt, evidence);
    auto missingPath = QJsonDocument::fromJson(bound).object();
    missingPath.remove(QStringLiteral("publishedPath"));
    EXPECT_FALSE(backup_protocol::parseResult(
        QJsonDocument(missingPath).toJson(QJsonDocument::Compact), value));
    QString from, to;
    EXPECT_FALSE(backup_protocol::parseRequest("{\"v\":1,\"source\":7,\"destination\":\"/tmp/test\"}", from, to));
}

TEST_F(BackupJobTest, ApplicationQuitStopsUnresponsiveChildWithoutWaitingInDestructors)
{
    int previous = 0;
    ASSERT_EQ(::prctl(PR_GET_CHILD_SUBREAPER, &previous), 0);
    ASSERT_EQ(::prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
    struct Reset { int value; ~Reset() { ::prctl(PR_SET_CHILD_SUBREAPER, value); } } reset{previous};
    QProcess parent;
    QElapsedTimer timer; timer.start();
    parent.start(QCoreApplication::applicationFilePath(), {"--quit-active-driver", destination});
    ASSERT_TRUE(parent.waitForStarted(2000));
    ASSERT_TRUE(parent.waitForFinished(3000));
    EXPECT_EQ(parent.exitCode(), 0);
    EXPECT_LT(timer.elapsed(), 2000);
    QFile marker(destination + ".ready");
    ASSERT_TRUE(marker.open(QIODevice::ReadOnly));
    bool valid = false;
    const auto pid = marker.readAll().toLongLong(&valid);
    ASSERT_TRUE(valid); ASSERT_GT(pid, 1);
    int status = 0;
    bool reaped = false;
    ASSERT_TRUE(until([&] {
        if (!reaped) reaped = ::waitpid(static_cast<pid_t>(pid), &status, WNOHANG) == pid;
        return reaped;
    }));
    EXPECT_TRUE(WIFSIGNALED(status));
    EXPECT_EQ(WTERMSIG(status), SIGKILL);
    EXPECT_FALSE(QFile::exists(destination));
}
} // namespace

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    if (application.arguments().size() == 4 && application.arguments()[1] == "--orphan-driver") {
        const auto source = application.arguments()[2], destination = application.arguments()[3];
        BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER));
        passwall::storage::VaultOperationGuard snapshot;
        std::string error;
        if (!snapshot.trySnapshotAccess(source.toStdString(), error)
            || !job.startSnapshotReserved(source, destination, std::move(snapshot), {})
            || !until([&] { return QFile::exists(destination + ".ready"); })) return 2;
        ::_exit(0); // No facade, QProcess or QApplication destructor/quit signal.
    }
    if (application.arguments().size() == 3 && application.arguments()[1] == "--quit-active-driver") {
        const auto destination = application.arguments()[2];
        BackupJob job(QString::fromLatin1(FAKE_BACKUP_WORKER));
        if (!job.start("/ignore", destination)
            || !until([&] { return QFile::exists(destination + ".ready"); })) return 2;
        QTimer::singleShot(0, &application, &QCoreApplication::quit);
        return application.exec(); // Exercises real aboutToQuit and facade destruction.
    }
    if (application.arguments().size() == 4 && application.arguments()[1] == "--orphan-worker") {
        const auto source = application.arguments()[2], destination = application.arguments()[3];
        QProcess process;
        process.setStandardOutputFile(QProcess::nullDevice());
        process.setStandardErrorFile(QProcess::nullDevice());
        process.start(QString::fromLatin1(PROBE_BACKUP_WORKER), {"--protocol-v1"});
        if (!process.waitForStarted(2000)) return 2;
        const auto pid = QByteArray::number(process.processId()) + '\n';
        process.write(backup_protocol::request(source, destination));
        if (!until([&] { return QFile::exists(source + ".checkpoint"); })) return 2;
        if (!passwall::test_io::writeAll(1, pid.constData(), pid.size())) ::_exit(3);
        ::_exit(0); // Real parent loss, no QProcess destructor/terminate/cancel.
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
