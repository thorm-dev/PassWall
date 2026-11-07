#include "private_dbus.hpp"

#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QDBusMessage>
#include <QDBusPendingReply>
#include <QDBusVirtualObject>
#include <QDir>
#include <QFile>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcessEnvironment>
#include <QScopeGuard>
#include <QTimer>

#include <memory>
#include <vector>

namespace {
using passwall::tests::waitFor;

void appendEvent(const QString& path, const QByteArray& event)
{
    QFile log(path);
    ASSERT_TRUE(log.open(QIODevice::WriteOnly | QIODevice::Append));
    ASSERT_EQ(log.write(event), event.size());
    ASSERT_TRUE(log.flush());
}

class FakeControl final : public QDBusVirtualObject {
public:
    enum Mode { Acknowledge, Refuse, NeverReply, Malformed };
    QString log;
    Mode mode = Acknowledge;
    int delayMs = 0;
    int requests = 0;
    int replies = 0;
    bool interactiveAuthorization = true;

    QString introspect(const QString&) const override { return {}; }
    bool handleMessage(const QDBusMessage& message, const QDBusConnection& connection) override
    {
        EXPECT_TRUE(message.interface() == QStringLiteral("org.passwall.PassWall.Control1"));
        EXPECT_TRUE(message.member() == QStringLiteral("Lock"));
        EXPECT_TRUE(message.arguments().isEmpty());
        ++requests;
        interactiveAuthorization = message.isInteractiveAuthorizationAllowed();
        message.setDelayedReply(true);
        if (mode == NeverReply)
            return true;
        QTimer::singleShot(delayMs, this, [this, message, connection] {
            ++replies;
            if (mode == Refuse) {
                connection.send(message.createErrorReply(QStringLiteral("org.passwall.Error.CleanupFailed"),
                    QStringLiteral("fictitious-private-error-details")));
            } else {
                appendEvent(log, "reply\n");
                connection.send(mode == Malformed ? message.createReply(QStringLiteral("unexpected")) :
                    message.createReply());
            }
        });
        return true;
    }
};

class SessionLockCoordinatorTest : public ::testing::Test {
protected:
    passwall::tests::PrivateDBus bus;
    QTemporaryDir directory{QStringLiteral("/tmp/pw-session-coordinator-XXXXXX")};
    QString log;
    QString program;
    QString fakeLocker;
    std::unique_ptr<QDBusConnection> serviceBus;
    FakeControl service;
    std::vector<std::unique_ptr<QProcess>> processes;

    void SetUp() override
    {
        ASSERT_TRUE(bus.isValid());
        ASSERT_TRUE(directory.isValid());
        log = directory.filePath(QStringLiteral("events.log"));
        program = directory.filePath(QStringLiteral("passwall-session-lock-test"));
        fakeLocker = directory.filePath(QStringLiteral("passwall-test-screen-locker"));
        // Only the test frontend can use this sibling fake. The installed
        // production command has no CLI or environment override for swaylock.
        ASSERT_TRUE(QFile::copy(QString::fromLocal8Bit(PASSWALL_COORDINATOR_TEST_PROGRAM), program));
        ASSERT_TRUE(QFile::copy(QString::fromLocal8Bit(PASSWALL_FAKE_LOCKER_PROGRAM), fakeLocker));
        const auto executable = QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner;
        ASSERT_TRUE(QFile::setPermissions(program, executable));
        ASSERT_TRUE(QFile::setPermissions(fakeLocker, executable));
        service.log = log;
    }
    void TearDown() override
    {
        for (auto& process : processes) {
            if (process->state() != QProcess::NotRunning &&
                !waitFor([&] { return process->state() == QProcess::NotRunning; }, 5000)) {
                process->kill();
                process->waitForFinished(1000);
            }
        }
        if (serviceBus)
            serviceBus->unregisterObject(QStringLiteral("/org/passwall/PassWall"));
    }
    void offerService(FakeControl::Mode mode = FakeControl::Acknowledge, int delay = 0)
    {
        service.mode = mode;
        service.delayMs = delay;
        serviceBus = std::make_unique<QDBusConnection>(bus.connect());
        ASSERT_TRUE(serviceBus->isConnected());
        ASSERT_TRUE(serviceBus->registerVirtualObject(QStringLiteral("/org/passwall/PassWall"), &service));
        ASSERT_TRUE(serviceBus->registerService(QStringLiteral("org.passwall.PassWall")));
    }
    QProcessEnvironment environment() const
    {
        auto result = QProcessEnvironment::systemEnvironment();
        result.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), bus.address());
        result.insert(QStringLiteral("XDG_RUNTIME_DIR"), directory.path());
        result.insert(QStringLiteral("PASSWALL_TEST_LOCKER_LOG"), log);
        result.insert(QStringLiteral("PASSWALL_TEST_LOCKER_HOLD_MS"), QStringLiteral("0"));
        result.insert(QStringLiteral("PASSWALL_TEST_LOCKER_EXIT_CODE"), QStringLiteral("0"));
        result.remove(QStringLiteral("PASSWALL_TEST_LOCKER_CRASH"));
        return result;
    }
    QProcess& start(const QProcessEnvironment& env, const QString& path = {}, const QStringList& args = {})
    {
        auto process = std::make_unique<QProcess>();
        process->setProcessEnvironment(env);
        process->start(path.isEmpty() ? program : path, args);
        processes.push_back(std::move(process));
        return *processes.back();
    }
    void finished(QProcess& process, int exitCode = 0)
    {
        ASSERT_TRUE(waitFor([&] { return process.state() == QProcess::NotRunning; }, 5000));
        EXPECT_TRUE(process.exitStatus() == QProcess::NormalExit);
        EXPECT_EQ(process.exitCode(), exitCode);
        EXPECT_TRUE(process.readAllStandardOutput().isEmpty());
    }
    QByteArray events() const
    {
        QFile file(log);
        if (!file.open(QIODevice::ReadOnly))
            return {};
        return file.readAll();
    }
    void notAcknowledged(QProcess& process)
    {
        const auto diagnostic = process.readAllStandardError();
        EXPECT_TRUE(diagnostic.contains("cleanup not confirmed"));
        EXPECT_FALSE(diagnostic.contains("cleanup acknowledged"));
        EXPECT_FALSE(diagnostic.contains("fictitious-private-error-details"));
    }
};

TEST_F(SessionLockCoordinatorTest, AcknowledgesCleanupBeforeStartingLocker)
{
    offerService();
    auto& process = start(environment());
    finished(process);
    EXPECT_EQ(events(), QByteArray("reply\nstarted\n"));
    EXPECT_EQ(service.requests, 1);
    EXPECT_TRUE(process.readAllStandardError().contains("cleanup acknowledged"));
    EXPECT_FALSE(service.interactiveAuthorization);
}

TEST_F(SessionLockCoordinatorTest, ActivatablePassWallIsNotAutomaticallyStarted)
{
    // Qt 6.8.2 does not restore autoStartService in fromDBusMessage(). Test
    // actual activation rather than the default value of the received object.
    const auto services = directory.filePath(QStringLiteral("services"));
    const auto marker = directory.filePath(QStringLiteral("activation-probe"));
    ASSERT_TRUE(QDir().mkdir(services));
    QFile activation(services + QStringLiteral("/org.passwall.PassWall.service"));
    ASSERT_TRUE(activation.open(QIODevice::WriteOnly));
    ASSERT_GT(activation.write((QStringLiteral("[D-BUS Service]\nName=org.passwall.PassWall\nExec=") +
        fakeLocker + QStringLiteral(" --activation-probe ") + marker + QStringLiteral("\n")).toUtf8()), 0);
    activation.close();
    const auto socket = directory.filePath(QStringLiteral("activatable-bus"));
    QFile config(directory.filePath(QStringLiteral("private-bus.conf")));
    ASSERT_TRUE(config.open(QIODevice::WriteOnly));
    ASSERT_GT(config.write((QStringLiteral("<busconfig><type>session</type><auth>EXTERNAL</auth><listen>unix:path=") +
        socket.toHtmlEscaped() + QStringLiteral("</listen><servicedir>") + services.toHtmlEscaped() +
        QStringLiteral("</servicedir><policy context=\"default\"><allow send_destination=\"*\"/>") +
        QStringLiteral("<allow receive_sender=\"*\"/><allow own=\"*\"/></policy></busconfig>")).toUtf8()), 0);
    config.close();
    QProcess broker;
    broker.start(QStringLiteral("dbus-daemon"), {QStringLiteral("--nofork"), QStringLiteral("--nopidfile"),
        QStringLiteral("--print-address=1"), QStringLiteral("--config-file=") + config.fileName()});
    const auto stop = qScopeGuard([&] {
        broker.terminate();
        if (!broker.waitForFinished(1000)) {
            broker.kill();
            broker.waitForFinished(1000);
        }
    });
    ASSERT_TRUE(broker.waitForStarted(1000));
    ASSERT_TRUE(broker.waitForReadyRead(1000));
    const auto address = QString::fromUtf8(broker.readLine()).trimmed();
    ASSERT_FALSE(address.isEmpty());
    const auto connectionName = QStringLiteral("activation-client-") + QUuid::createUuid().toString();
    const auto client = QDBusConnection::connectToBus(address, connectionName);
    const auto disconnect = qScopeGuard([&] { QDBusConnection::disconnectFromBus(connectionName); });
    ASSERT_TRUE(client.isConnected());
    auto query = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("ListActivatableNames"));
    QDBusPendingReply<QStringList> available = client.asyncCall(query, 2000);
    ASSERT_TRUE(waitFor([&] { return available.isFinished(); }));
    ASSERT_FALSE(available.isError());
    ASSERT_TRUE(available.value().contains(QStringLiteral("org.passwall.PassWall")));

    auto env = environment();
    env.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), address);
    auto& process = start(env);
    finished(process);
    EXPECT_FALSE(QFile::exists(marker));
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);

    // Positive control: the SAME private broker really can launch this fake
    // service. Its executable exits without registering, intentionally.
    auto activate = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("StartServiceByName"));
    activate.setArguments({QStringLiteral("org.passwall.PassWall"), QVariant::fromValue(uint(0))});
    QDBusPendingReply<uint> activated = client.asyncCall(activate, 2000);
    ASSERT_TRUE(waitFor([&] { return QFile::exists(marker); }));
    ASSERT_TRUE(waitFor([&] { return activated.isFinished(); }));
    EXPECT_TRUE(activated.isError()); // The probe deliberately never claims the name.
    QFile proof(marker);
    ASSERT_TRUE(proof.open(QIODevice::ReadOnly));
    EXPECT_EQ(proof.readAll(), QByteArray("activated\n"));
}

TEST_F(SessionLockCoordinatorTest, AbsentPassWallStillStartsLocker)
{
    auto& process = start(environment());
    finished(process);
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, UnavailableBusStillStartsLocker)
{
    auto env = environment();
    env.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"),
        QStringLiteral("unix:path=") + directory.filePath(QStringLiteral("missing-bus")));
    auto& process = start(env);
    finished(process);
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, MissingBusAddressDoesNotAutolaunchABusOrPassWall)
{
    auto env = environment();
    env.remove(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"));
    auto& process = start(env);
    finished(process);
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, NoReplyExpiresWithinBoundAndStartsLocker)
{
    offerService(FakeControl::NeverReply);
    QElapsedTimer elapsed;
    elapsed.start();
    auto& process = start(environment());
    finished(process);
    EXPECT_GE(elapsed.elapsed(), 1400);
    EXPECT_LT(elapsed.elapsed(), 3000);
    EXPECT_EQ(service.requests, 1);
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, ErrorStillStartsLockerWithoutPrintingRemoteBody)
{
    offerService(FakeControl::Refuse);
    auto& process = start(environment());
    finished(process);
    EXPECT_EQ(service.requests, 1);
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, DelayedAcknowledgementWithinDeadlinePreservesOrder)
{
    offerService(FakeControl::Acknowledge, 200);
    auto& process = start(environment());
    ASSERT_TRUE(waitFor([&] { return service.requests == 1; }));
    EXPECT_TRUE(events().isEmpty());
    finished(process);
    EXPECT_EQ(events(), QByteArray("reply\nstarted\n"));
    EXPECT_EQ(service.requests, 1);
    EXPECT_TRUE(process.readAllStandardError().contains("cleanup acknowledged"));
}

TEST_F(SessionLockCoordinatorTest, LateReplyAfterDeadlineCannotLaunchASecondLocker)
{
    offerService(FakeControl::Acknowledge, 1800);
    auto env = environment();
    env.insert(QStringLiteral("PASSWALL_TEST_LOCKER_HOLD_MS"), QStringLiteral("1000"));
    auto& process = start(env);
    ASSERT_TRUE(waitFor([&] { return events().contains("started\n"); }));
    EXPECT_EQ(service.replies, 0);
    ASSERT_TRUE(waitFor([&] { return service.replies == 1; }));
    EXPECT_TRUE(process.state() != QProcess::NotRunning);
    finished(process);
    EXPECT_EQ(events(), QByteArray("started\nreply\n"));
    EXPECT_EQ(service.requests, 1);
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, ConcurrentRequestsDuringDbusAndLockerAreCoalesced)
{
    offerService(FakeControl::Acknowledge, 200);
    auto env = environment();
    env.insert(QStringLiteral("PASSWALL_TEST_LOCKER_HOLD_MS"), QStringLiteral("1000"));
    auto& first = start(env);
    ASSERT_TRUE(waitFor([&] { return service.requests == 1; }));
    auto& second = start(env);
    finished(second);
    EXPECT_TRUE(second.readAllStandardError().contains("no second locker started"));
    ASSERT_TRUE(waitFor([&] { return events().contains("started\n"); }));
    auto& third = start(env);
    finished(third);
    EXPECT_TRUE(third.readAllStandardError().contains("no second locker started"));
    finished(first);
    EXPECT_EQ(events().count("started\n"), 1);
    EXPECT_EQ(service.requests, 3); // One cleanup per invocation, one screen locker.
}

TEST_F(SessionLockCoordinatorTest, PreviousLockerExitDuringCleanupAllowsANewLaunch)
{
    offerService();
    auto firstEnvironment = environment();
    firstEnvironment.insert(QStringLiteral("PASSWALL_TEST_LOCKER_HOLD_MS"), QStringLiteral("250"));
    auto& first = start(firstEnvironment);
    ASSERT_TRUE(waitFor([&] { return events().contains("started\n"); }));
    service.delayMs = 500;
    auto& second = start(environment());
    ASSERT_TRUE(waitFor([&] { return service.requests == 2; }));
    finished(first);
    EXPECT_EQ(service.replies, 1); // The second request is still awaiting cleanup.
    finished(second);
    EXPECT_EQ(events(), QByteArray("reply\nstarted\nreply\nstarted\n"));
    EXPECT_EQ(service.requests, 2);
    EXPECT_FALSE(second.readAllStandardError().contains("no second locker started"));
}

TEST_F(SessionLockCoordinatorTest, NewInvocationAfterLockerExitCanRunAgain)
{
    offerService();
    auto& first = start(environment());
    finished(first);
    auto& second = start(environment());
    finished(second);
    EXPECT_EQ(events(), QByteArray("reply\nstarted\nreply\nstarted\n"));
    EXPECT_EQ(service.requests, 2);
}

TEST_F(SessionLockCoordinatorTest, MissingLockerReportsFailure)
{
    offerService();
    ASSERT_TRUE(QFile::remove(fakeLocker)); // Isolated copied fake only.
    auto& process = start(environment());
    finished(process, 1);
    EXPECT_EQ(events(), QByteArray("reply\n"));
    EXPECT_TRUE(process.readAllStandardError().contains("screen lock NOT confirmed"));
}

TEST_F(SessionLockCoordinatorTest, NonExecutableLockerReportsFailure)
{
    offerService();
    ASSERT_TRUE(QFile::setPermissions(fakeLocker, QFile::ReadOwner | QFile::WriteOwner));
    auto& process = start(environment());
    finished(process, 1);
    EXPECT_EQ(events(), QByteArray("reply\n"));
    EXPECT_TRUE(process.readAllStandardError().contains("screen lock NOT confirmed"));
}

TEST_F(SessionLockCoordinatorTest, LockerNonzeroExitDoesNotClaimScreenUnlock)
{
    auto env = environment();
    env.insert(QStringLiteral("PASSWALL_TEST_LOCKER_EXIT_CODE"), QStringLiteral("9"));
    auto& process = start(env);
    finished(process, 1);
    EXPECT_EQ(events(), QByteArray("started\n"));
    const auto diagnostic = process.readAllStandardError();
    EXPECT_TRUE(diagnostic.contains("screen locker failed"));
    EXPECT_FALSE(diagnostic.contains("unlocked"));
}

TEST_F(SessionLockCoordinatorTest, LockerCrashDoesNotClaimScreenUnlock)
{
    auto env = environment();
    env.insert(QStringLiteral("PASSWALL_TEST_LOCKER_CRASH"), QStringLiteral("1"));
    auto& process = start(env);
    finished(process, 1);
    EXPECT_EQ(events(), QByteArray("started\n"));
    const auto diagnostic = process.readAllStandardError();
    EXPECT_TRUE(diagnostic.contains("screen locker failed"));
    EXPECT_FALSE(diagnostic.contains("unlocked"));
}

TEST_F(SessionLockCoordinatorTest, SilentDbusHandshakeCannotDelayScreenLocking)
{
    QLocalServer silentBus;
    ASSERT_TRUE(silentBus.listen(directory.filePath(QStringLiteral("silent-bus"))));
    int accepted = 0;
    QObject::connect(&silentBus, &QLocalServer::newConnection, &silentBus, [&] {
        while (auto* socket = silentBus.nextPendingConnection()) {
            socket->setParent(&silentBus);
            ++accepted; // No D-Bus authentication reply: connectToBus stalls.
        }
    });
    auto env = environment();
    env.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"),
        QStringLiteral("unix:path=") + silentBus.fullServerName());
    QElapsedTimer elapsed;
    elapsed.start();
    auto& process = start(env);
    finished(process);
    EXPECT_GE(accepted, 1);
    EXPECT_GE(elapsed.elapsed(), 1400);
    EXPECT_LT(elapsed.elapsed(), 3000);
    EXPECT_EQ(events(), QByteArray("started\n"));
    EXPECT_TRUE(process.readAllStandardError().contains("deadline expired"));
}

TEST_F(SessionLockCoordinatorTest, InvalidReplyIsNeverAnAcknowledgement)
{
    offerService(FakeControl::Malformed);
    auto& process = start(environment());
    finished(process);
    EXPECT_EQ(service.requests, 1);
    EXPECT_EQ(events(), QByteArray("reply\nstarted\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, MissingRuntimeDoesNotPreventAttemptingScreenLock)
{
    auto env = environment();
    env.insert(QStringLiteral("XDG_RUNTIME_DIR"), directory.filePath(QStringLiteral("missing-runtime")));
    auto& process = start(env);
    finished(process);
    EXPECT_EQ(events(), QByteArray("started\n"));
    EXPECT_TRUE(process.readAllStandardError().contains("invocation exclusion unavailable"));
}

TEST_F(SessionLockCoordinatorTest, BusLossDuringRequestStillStartsLocker)
{
    offerService(FakeControl::NeverReply);
    auto& process = start(environment());
    ASSERT_TRUE(waitFor([&] { return service.requests == 1; }));
    bus.stop();
    finished(process);
    EXPECT_EQ(events(), QByteArray("started\n"));
    notAcknowledged(process);
}

TEST_F(SessionLockCoordinatorTest, ProductionRejectsLockerOverrideArguments)
{
    offerService();
    auto& process = start(environment(), QString::fromLocal8Bit(PASSWALL_COORDINATOR_PROGRAM),
        {QStringLiteral("--locker"), fakeLocker});
    finished(process, 64); // Never run the production command without arguments in tests.
    EXPECT_TRUE(events().isEmpty());
    EXPECT_EQ(service.requests, 0);
    EXPECT_TRUE(process.readAllStandardError().contains("no arguments"));
}
} // namespace

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
