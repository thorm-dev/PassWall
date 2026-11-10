#include "services/restore_protocol.hpp"
#include "services/restore_job.hpp"
#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QProcessEnvironment>
#include <QDir>
#include "storage/vault_operation_guard.hpp"
#include <fcntl.h>
#include <sodium.h>
#include <thread>

using namespace passwall::services;
namespace wire = passwall::services::restore_protocol;
namespace {
bool observeSecure = false, secureWiped = true;
int secureLive = 0;
std::array<std::pair<void*, std::size_t>, 64> secureAllocations{};
}
extern "C" void* __real_sodium_malloc(std::size_t);
extern "C" void* __wrap_sodium_malloc(std::size_t size) {
    void* data = __real_sodium_malloc(size);
    if (data && observeSecure) for (auto& entry : secureAllocations) if (!entry.first) {
        entry = {data, size}; ++secureLive; break;
    }
    return data;
}
extern "C" void __real_sodium_free(void*);
extern "C" void __wrap_sodium_free(void* data) {
    for (auto& entry : secureAllocations) if (entry.first == data && data) {
        for (std::size_t i = 0; i < entry.second; ++i)
            if (static_cast<unsigned char*>(data)[i]) secureWiped = false;
        entry = {}; --secureLive; break;
    }
    __real_sodium_free(data);
}
namespace {
struct Pair {
    int fds[2]{-1, -1};
    Pair() { if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds)) throw std::runtime_error("socketpair"); }
    ~Pair() { for (int fd : fds) if (fd >= 0) ::close(fd); }
};
TEST(RestoreProtocolTest, MetadataRoundTrip) {
    Pair p;
    ASSERT_TRUE(wire::send(p.fds[0], wire::Probe, {{"n", 3}}));
    wire::Type type; quint32 size; QJsonObject object;
    ASSERT_TRUE(wire::readHeader(p.fds[1], type, size)); EXPECT_EQ(type, wire::Probe);
    ASSERT_TRUE(wire::readObject(p.fds[1], size, object)); EXPECT_EQ(object["n"].toInt(), 3);
}
TEST(RestoreProtocolTest, FragmentedHeaderAndPayload) {
    Pair p;
    std::thread sender([&] {
        struct End { int fd; ~End() { ::shutdown(fd, SHUT_WR); } } end{p.fds[0]};
        const QByteArray data("{\"n\":2}"); const auto header = wire::header(wire::Permit, data.size());
        for (char c : header) if (!wire::transfer(p.fds[0], &c, 1, true)) return;
        for (char c : data) if (!wire::transfer(p.fds[0], &c, 1, true)) return;
    });
    wire::Type type; quint32 size; QJsonObject object;
    const bool head = wire::readHeader(p.fds[1], type, size);
    const bool body = head && wire::readObject(p.fds[1], size, object);
    sender.join(); ASSERT_TRUE(body); EXPECT_EQ(type, wire::Permit); EXPECT_EQ(object["n"].toInt(), 2);
}
TEST(RestoreProtocolTest, TruncatedHeaderRejected) {
    Pair p; char byte = 1; ASSERT_TRUE(wire::transfer(p.fds[0], &byte, 1, true));
    ASSERT_EQ(::shutdown(p.fds[0], SHUT_WR), 0);
    wire::Type type; quint32 size; EXPECT_FALSE(wire::readHeader(p.fds[1], type, size));
}
TEST(RestoreProtocolTest, TruncatedPayloadRejected) {
    Pair p; auto prefix = wire::header(wire::Result, 12);
    ASSERT_TRUE(wire::transfer(p.fds[0], prefix.data(), prefix.size(), true));
    ASSERT_EQ(::shutdown(p.fds[0], SHUT_WR), 0);
    wire::Type type; quint32 size; QJsonObject object;
    ASSERT_TRUE(wire::readHeader(p.fds[1], type, size)); EXPECT_FALSE(wire::readObject(p.fds[1], size, object));
}
TEST(RestoreProtocolTest, OversizedMetadataRejectedBeforeAllocation) {
    Pair p; auto prefix = wire::header(wire::Begin, wire::metadataLimit + 1);
    ASSERT_TRUE(wire::transfer(p.fds[0], prefix.data(), prefix.size(), true));
    wire::Type type; quint32 size; EXPECT_FALSE(wire::readHeader(p.fds[1], type, size));
}
TEST(RestoreProtocolTest, PasswordLimitExactAndOneOver) {
    Pair p;
    for (quint32 n : {wire::passwordLimit, wire::passwordLimit + 1}) {
        auto prefix = wire::header(wire::Password, n);
        ASSERT_TRUE(wire::transfer(p.fds[0], prefix.data(), prefix.size(), true));
        wire::Type type; quint32 size;
        EXPECT_EQ(wire::readHeader(p.fds[1], type, size), n == wire::passwordLimit);
    }
}
TEST(RestoreProtocolTest, InvalidTypeRejected) {
    Pair p; auto prefix = wire::header(wire::Type(255), 0);
    ASSERT_TRUE(wire::transfer(p.fds[0], prefix.data(), prefix.size(), true));
    wire::Type type; quint32 size; EXPECT_FALSE(wire::readHeader(p.fds[1], type, size));
}
TEST(RestoreProtocolTest, EmptyAndInvalidJsonRejected) {
    Pair p; QJsonObject object;
    EXPECT_FALSE(wire::readObject(p.fds[1], 0, object));
    char byte = '!'; ASSERT_TRUE(wire::transfer(p.fds[0], &byte, 1, true));
    EXPECT_FALSE(wire::readObject(p.fds[1], 1, object));
}
TEST(RestoreProtocolTest, ResultPreservesDurabilityAndRecoveryStates) {
    for (int i = 0; i <= int(ReplacementOutcome::Replaced); ++i) {
        ReplacementResult source; source.outcome = ReplacementOutcome(i);
        source.operationId = "test-operation"; source.recoveryArtifact = "/fictitious/recovery.db";
        source.finalization.state = ReplacementFinalizationState::SafeResolutionUnconfirmed;
        source.precaution.publication = SnapshotPublication::PublishedDurabilityUnconfirmed;
        ReplacementResult result;
        ASSERT_TRUE(wire::decode(wire::encode(source), result)); EXPECT_EQ(result.outcome, source.outcome);
        EXPECT_EQ(result.finalization.state, source.finalization.state);
        EXPECT_EQ(result.precaution.publication, source.precaution.publication);
        EXPECT_EQ(result.recoveryArtifact, source.recoveryArtifact);
    }
}
TEST(RestoreProtocolTest, InvalidResultEnumRejected) {
    ReplacementResult result; auto record = wire::encode(result); record["outcome"] = 8;
    EXPECT_FALSE(wire::decode(record, result)); record["outcome"] = 0.5;
    EXPECT_FALSE(wire::decode(record, result));
}
TEST(RestoreProtocolTest, ContradictoryResultCannotClaimCancellationOrSuccess) {
    ReplacementResult r; r.outcome = ReplacementOutcome::Replaced;
    EXPECT_FALSE(wire::consistent(r, int(ReplacementCheckpoint::BeforeWork)));
    EXPECT_FALSE(wire::consistent(r, int(ReplacementCheckpoint::AfterDirectorySync)));
    r.finalization.state = ReplacementFinalizationState::Resolved;
    EXPECT_TRUE(wire::consistent(r, int(ReplacementCheckpoint::AfterDirectorySync)));
    r.sourceAuthenticationFailed = true;
    EXPECT_FALSE(wire::consistent(r, int(ReplacementCheckpoint::AfterDirectorySync)));
    r.sourceAuthenticationFailed = false; r.outcome = ReplacementOutcome::CancelledBeforeEngagement;
    EXPECT_FALSE(wire::consistent(r, int(ReplacementCheckpoint::AfterExchange)));
}
TEST(RestoreProtocolTest, SessionAndOperationAreBothRequired) {
    EXPECT_TRUE(wire::bound({{"operation", "a"}, {"session", "b"}}, "a", "b"));
    EXPECT_FALSE(wire::bound({{"operation", "a"}, {"session", "old"}}, "a", "b"));
    EXPECT_FALSE(wire::bound({{"operation", "other"}, {"session", "b"}}, "a", "b"));
}
TEST(RestoreProtocolTest, TruncatedPasswordUsesSecureBufferAndWipesOnScopeExit) {
    ASSERT_GE(sodium_init(), 0); Pair p;
    char fake[3] = {'x', 'y', 'z'}; ASSERT_TRUE(wire::transfer(p.fds[0], fake, sizeof(fake), true));
    ASSERT_EQ(::shutdown(p.fds[0], SHUT_WR), 0);
    observeSecure = true; secureWiped = true;
    {
        passwall::core::SecureBuffer owned(32);
        EXPECT_FALSE(wire::transfer(p.fds[1], owned.data(), owned.size(), false));
        EXPECT_EQ(secureLive, 1);
    }
    observeSecure = false; EXPECT_EQ(secureLive, 0); EXPECT_TRUE(secureWiped);
}
TEST(RestoreJobTest, RejectedStartDestroysOwnedSenderBufferWithoutMutatingAnotherBuffer) {
    ASSERT_GE(sodium_init(), 0);
    passwall::core::SecureBuffer caller(16); caller.data()[0] = 7;
    observeSecure = true; secureWiped = true;
    {
        RestoreJob job("not-an-absolute-worker"); passwall::core::SecureBuffer sender(32);
        sender.data()[0] = 42;
        EXPECT_FALSE(job.start({}, "/fictitious/source.db", std::move(sender), {}));
        EXPECT_TRUE(sender.empty());
    }
    observeSecure = false; EXPECT_EQ(secureLive, 0); EXPECT_TRUE(secureWiped); EXPECT_TRUE(caller.data()[0] == 7);
}
TEST(RestoreWorkerTest, DirectInvocationRefused) {
    QProcess child; child.start(RESTORE_REAL_WORKER, {});
    ASSERT_TRUE(child.waitForFinished(3000)); EXPECT_EQ(child.exitStatus(), QProcess::NormalExit);
    EXPECT_EQ(child.exitCode(), 64); EXPECT_TRUE(child.readAllStandardOutput().isEmpty());
}
TEST(RestoreWorkerTest, RealWorkerRefusesUntrustedExecutableParentBeforeReadingSecret) {
    Pair p; QTemporaryDir dir; ASSERT_TRUE(dir.isValid());
    QFile dummy(dir.filePath("not-an-authority")); ASSERT_TRUE(dummy.open(QIODevice::ReadWrite));
    const int socket = ::fcntl(p.fds[1], F_DUPFD_CLOEXEC, 64);
    const int a = ::fcntl(dummy.handle(), F_DUPFD_CLOEXEC, 64);
    const int b = ::fcntl(dummy.handle(), F_DUPFD_CLOEXEC, 64);
    ASSERT_GE(socket, 64); ASSERT_GE(a, 64); ASSERT_GE(b, 64);
    QProcess child; child.setChildProcessModifier([=] { for (int fd : {socket, a, b}) if (::fcntl(fd, F_SETFD, 0)) ::_exit(127); });
    child.start(RESTORE_REAL_WORKER, {"--restore-v1", QString::number(socket), QString::number(a), QString::number(b)});
    ASSERT_TRUE(child.waitForFinished(3000)); EXPECT_EQ(child.exitStatus(), QProcess::NormalExit);
    EXPECT_EQ(child.exitCode(), 77); EXPECT_TRUE(child.readAllStandardOutput().isEmpty());
    ::close(socket); ::close(a); ::close(b);
}
TEST(RestoreJobTest, MissingAuthorityCannotStartAWorker) {
    ASSERT_GE(sodium_init(), 0);
    RestoreJob job(QString::fromUtf8(RESTORE_TEST_WORKER));
    passwall::core::SecureBuffer password(16);
    EXPECT_FALSE(job.start({}, "/fictitious/source.db", std::move(password), "/fictitious/precaution.db"));
    EXPECT_FALSE(job.isActive()); EXPECT_FALSE(job.startError().isEmpty());
}
TEST(RestoreJobTest, RelativeWorkerPathRejected) {
    ASSERT_GE(sodium_init(), 0); RestoreJob job("relative-worker");
    passwall::core::SecureBuffer password(16);
    EXPECT_FALSE(job.start({}, "/fictitious/source.db", std::move(password), {})); EXPECT_FALSE(job.isActive());
}
TEST(RestoreJobTest, ConstructorRefusalWipesSenderAndDoesNotLeakPrivateDescriptors) {
    ASSERT_GE(sodium_init(), 0);
    { RestoreJob warm(QString::fromUtf8(RESTORE_TEST_WORKER));
      passwall::core::SecureBuffer data(1); EXPECT_FALSE(warm.start({}, "/fictitious/source.db", std::move(data), {})); }
    const auto before = QDir("/proc/self/fd").entryList(QDir::AllEntries | QDir::NoDotAndDotDot).size();
    observeSecure = true; secureWiped = true;
    for (int i = 0; i < 16; ++i) {
        RestoreJob job(QString::fromUtf8(RESTORE_TEST_WORKER)); passwall::core::SecureBuffer sender(32);
        sender.data()[0] = 42;
        EXPECT_FALSE(job.start({}, "/fictitious/source.db", std::move(sender), {})); EXPECT_FALSE(job.isActive());
    }
    observeSecure = false; EXPECT_EQ(secureLive, 0); EXPECT_TRUE(secureWiped);
    EXPECT_EQ(QDir("/proc/self/fd").entryList(QDir::AllEntries | QDir::NoDotAndDotDot).size(), before);
}
TEST(RestoreWorkerTest, ParentExitCannotLeaveAnExecutingGrantOrAutomaticallyRepeatExchange) {
    QTemporaryDir root; ASSERT_TRUE(root.isValid());
    QProcess child;
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert("PW_RESTORE_PARENT_ROOT", root.path());
    child.setProcessEnvironment(environment);
    child.start(RESTORE_GUI_TEST_PROGRAM, {"--gtest_filter=MainWindowEditorLockTest.RestoreParentExitProbe"});
    ASSERT_TRUE(child.waitForFinished(20000)); EXPECT_EQ(child.exitStatus(), QProcess::NormalExit);
    ASSERT_EQ(child.exitCode(), 88);
    QFile metadata(root.filePath("probe.json")); ASSERT_TRUE(metadata.open(QIODevice::ReadOnly));
    const auto object = QJsonDocument::fromJson(metadata.readAll()).object(); ASSERT_EQ(object.size(), 4);
    passwall::storage::VaultOperationGuard access; std::string failure;
    QElapsedTimer elapsed; elapsed.start(); bool acquired = false;
    while (!(acquired = access.tryAccess(object["principal"].toString().toStdString(), failure)) && elapsed.elapsed() < 10000)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    ASSERT_TRUE(acquired); access.reset();
    const VaultPreferencesStore store(object["config"].toString());
    const auto result = VaultReplacementAuthorization::recoverReplacement(store, object["local"].toString(),
        object["operation"].toString(), ReplacementRecoveryAction::Inspect);
    EXPECT_EQ(result.layout, ReplacementLayout::ArmedBeforeExchange);
    QString error;
    EXPECT_EQ(store.recoveryAccess(object["principal"].toString(), error), VaultRecoveryAccess::RecoveryRequired);
}
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv); ::testing::InitGoogleTest(&argc, argv); return RUN_ALL_TESTS();
}
