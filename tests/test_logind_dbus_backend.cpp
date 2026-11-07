#include "platform/linux_session_monitor.hpp"
#include "fake_login1_backend.hpp"

#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusUnixFileDescriptor>
#include <QDBusVirtualObject>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QPointer>
#include <QProcess>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QThread>
#include <QUuid>
#include <QVariantMap>

#include <functional>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace {
// Interpose only our executable's calls, not Qt internals. The real Qt call
// still executes against the real PRIVATE bus, including its implicit lookup.
thread_local std::function<void(QDBusConnection&, const QString&, const QString&,
                                QObject*, const char*)> subscriptionProbe;
thread_local std::function<void(const QDBusMessage&)> asyncCallProbe;
}
extern "C" bool realDBusConnect(QDBusConnection*, const QString&, const QString&,
    const QString&, const QString&, QObject*, const char*)
    asm("__real__ZN15QDBusConnection7connectERK7QStringS2_S2_S2_P7QObjectPKc");
extern "C" bool wrappedDBusConnect(QDBusConnection*, const QString&, const QString&,
    const QString&, const QString&, QObject*, const char*)
    asm("__wrap__ZN15QDBusConnection7connectERK7QStringS2_S2_S2_P7QObjectPKc");
extern "C" bool wrappedDBusConnect(QDBusConnection* connection, const QString& sender,
    const QString& path, const QString& interface, const QString& member,
    QObject* receiver, const char* slot)
{
    if (subscriptionProbe)
        subscriptionProbe(*connection, sender, member, receiver, slot);
    return realDBusConnect(connection, sender, path, interface, member, receiver, slot);
}
extern "C" QDBusPendingCall realDBusAsyncCall(
    const QDBusConnection*, const QDBusMessage&, int)
    asm("__real__ZNK15QDBusConnection9asyncCallERK12QDBusMessagei");
extern "C" QDBusPendingCall wrappedDBusAsyncCall(
    const QDBusConnection*, const QDBusMessage&, int)
    asm("__wrap__ZNK15QDBusConnection9asyncCallERK12QDBusMessagei");
extern "C" QDBusPendingCall wrappedDBusAsyncCall(
    const QDBusConnection* connection, const QDBusMessage& message, int timeout)
{
    if (asyncCallProbe)
        asyncCallProbe(message);
    return realDBusAsyncCall(connection, message, timeout);
}

namespace {
using passwall::platform::LinuxSessionMonitor;
constexpr auto service = "org.freedesktop.login1";
constexpr auto path = "/org/freedesktop/login1";
constexpr auto manager = "org.freedesktop.login1.Manager";

bool eventually(const std::function<bool()>& condition, int timeout = 2500)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!condition() && elapsed.elapsed() < timeout) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return condition();
}

class SignalCapture final : public QObject {
    Q_OBJECT
public:
    std::vector<QDBusMessage> messages;
public slots:
    void receive(const QDBusMessage& message) { messages.push_back(message); }
};

class RetainDeferredDelete final : public QObject {
protected:
    bool eventFilter(QObject*, QEvent* event) override
    {
        // Model a queued signal whose old receiver outlives the reconnection.
        return event->type() == QEvent::DeferredDelete;
    }
};

class SimulatedLogind final : public QDBusVirtualObject {
public:
    ~SimulatedLogind() override
    {
        for (int peer : peers)
            ::close(peer);
    }
    QString introspect(const QString&) const override { return {}; }
    bool handleMessage(const QDBusMessage& message,
                       const QDBusConnection& connection) override
    {
        if (message.interface() == manager && message.member() == "Inhibit") {
            ++requests;
            EXPECT_TRUE(message.arguments() == QVariantList({
                QStringLiteral("sleep:shutdown"), QStringLiteral("PassWall"),
                QStringLiteral("Lock vault and clear secrets"), QStringLiteral("delay")}));
            if (deny) {
                return connection.send(message.createErrorReply(
                    QStringLiteral("org.freedesktop.DBus.Error.AccessDenied"),
                    QStringLiteral("Simulated refusal")));
            }
            auto writer = passwall::tests::createFifoInhibitor(fifoDirectory, peers);
            if (!writer.valid())
                return false;
            QDBusUnixFileDescriptor fd;
            fd.giveFileDescriptor(::fcntl(writer.descriptor(), F_DUPFD_CLOEXEC, 0));
            return connection.send(message.createReply(QVariant::fromValue(fd)));
        }
        if (message.interface() == "org.freedesktop.DBus.Properties" &&
            message.member() == "GetAll") {
            ++snapshots;
            if (breakBeforeSnapshot && !peers.empty())
                ::close(std::exchange(peers.back(), -1));
            if (delaySnapshot) {
                message.setDelayedReply(true);
                pendingSnapshots.push_back(message);
                return true;
            }
            return connection.send(snapshotReply(message));
        }
        return false;
    }
    QDBusMessage snapshotReply(const QDBusMessage& message) const
    {
        const QVariantMap properties{
            {QStringLiteral("PreparingForSleep"), malformed
                ? QVariant(QStringLiteral("false")) : QVariant(sleeping)},
            {QStringLiteral("PreparingForShutdown"), shuttingDown}
        };
        return message.createReply(QVariant::fromValue(properties));
    }
    bool replyToSnapshot(const QDBusConnection& connection)
    {
        if (pendingSnapshots.empty())
            return false;
        auto message = pendingSnapshots.front();
        pendingSnapshots.erase(pendingSnapshots.begin());
        return connection.send(snapshotReply(message));
    }
    bool prepare(const QDBusConnection& connection, bool sleep, bool active)
    {
        (sleep ? sleeping : shuttingDown) = active;
        auto message = QDBusMessage::createSignal(path, manager,
            sleep ? QStringLiteral("PrepareForSleep") : QStringLiteral("PrepareForShutdown"));
        message.setArguments({active});
        return connection.send(message);
    }
    bool held(std::size_t index) const
    {
        if (index >= peers.size() || peers[index] < 0)
            return false;
        pollfd descriptor{peers[index], 0, 0};
        return ::poll(&descriptor, 1, 0) == 0;
    }
    bool deny = false;
    bool malformed = false;
    bool sleeping = false;
    bool shuttingDown = false;
    bool breakBeforeSnapshot = false;
    bool delaySnapshot = false;
    std::vector<QDBusMessage> pendingSnapshots;
    int requests = 0;
    int snapshots = 0;
    std::vector<int> peers;
    QTemporaryDir fifoDirectory{QStringLiteral("/tmp/passwall-dbus-inhibitor-XXXXXX")};
};

class LogindDBusBackendTest : public ::testing::Test {
protected:
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-logind-test-XXXXXX")};
    QProcess daemon;
    std::unique_ptr<QDBusConnection> connection;
    QString busAddress;
    SimulatedLogind simulated;
    std::unique_ptr<LinuxSessionMonitor> monitor;
    passwall::platform::Login1Backend* backend = nullptr;
    bool unlocked = false;
    bool checkedBeforeClose = false;
    bool checkHeldDuringCleanup = false;
    int cleanups = 0;

    void startPrivateBus(const QString& config = {})
    {
        // This is a PRIVATE test bus, not the system/session bus. No actual
        // logind method, power event, system service or user setting is touched.
        daemon.start(QStringLiteral("dbus-daemon"), {
            config.isEmpty() ? QStringLiteral("--session")
                             : QStringLiteral("--config-file=") + config,
            QStringLiteral("--nofork"),
            QStringLiteral("--print-address=1"),
            QStringLiteral("--address=unix:path=") + directory.filePath("bus")});
        ASSERT_TRUE(daemon.waitForStarted(2000));
        ASSERT_TRUE(daemon.waitForReadyRead(2000)) << daemon.readAllStandardError().constData();
        const QString address = QString::fromUtf8(daemon.readLine()).trimmed();
        ASSERT_TRUE(address.startsWith(QStringLiteral("unix:")))
            << daemon.readAllStandardError().constData();
        // No fixed bus GUID: a restarted private broker must be reconnectable.
        busAddress = address.section(QLatin1Char(','), 0, 0);
    }
    void connectFixture()
    {
        connection = std::make_unique<QDBusConnection>(QDBusConnection::connectToBus(
            busAddress, QStringLiteral("passwall-logind-fixture-") + QUuid::createUuid().toString()));
        ASSERT_TRUE(connection->isConnected());
        ASSERT_TRUE(connection->registerService(service));
        ASSERT_TRUE(connection->registerVirtualObject(path, &simulated));
    }
    void disconnectFixture()
    {
        if (connection) {
            const QString name = connection->name();
            connection.reset();
            QDBusConnection::disconnectFromBus(name);
        }
    }
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        ASSERT_NO_FATAL_FAILURE(startPrivateBus());
        ASSERT_NO_FATAL_FAILURE(connectFixture());
        auto ownedBackend = passwall::platform::makeLogindDBusBackend(busAddress);
        backend = ownedBackend.get();
        monitor = std::make_unique<LinuxSessionMonitor>(std::move(ownedBackend));
        LinuxSessionMonitor* const owner = monitor.get();
        QObject::connect(owner, &LinuxSessionMonitor::protectionChanged, owner,
                         [this, owner](bool available) {
            if (available)
                return;
            ++cleanups;
            if (checkHeldDuringCleanup) {
                checkedBeforeClose = true;
                EXPECT_TRUE(simulated.held(simulated.peers.size() - 1));
            }
            unlocked = false;
            owner->acknowledgeLocked();
        }, Qt::DirectConnection);
    }
    void TearDown() override
    {
        subscriptionProbe = {};
        asyncCallProbe = {};
        checkHeldDuringCleanup = false;
        monitor.reset();
        disconnectFixture();
        if (daemon.state() != QProcess::NotRunning) {
            daemon.terminate();
            if (!daemon.waitForFinished(2000)) {
                daemon.kill();
                daemon.waitForFinished(2000);
            }
        }
    }
    void ready()
    {
        monitor->start();
        ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
        ASSERT_EQ(simulated.requests, 1);
        ASSERT_TRUE(simulated.held(0));
        unlocked = true;
    }
    void checkResponsiveWhenPaused(bool duringLookup, int pauseMs = 400)
    {
        bool intercepted = false;
        bool pauseSucceeded = false;
        std::atomic<bool> resumed = false;
        int ticksWhilePaused = 0;
        int cleanupsBeforePause = 0;
        bool sawTimeoutWhilePaused = false;
        std::thread rescue;
        const auto pause = [&] {
            if (intercepted)
                return;
            intercepted = true;
            cleanupsBeforePause = cleanups;
            const auto pid = static_cast<pid_t>(daemon.processId());
            pauseSucceeded = pid > 1 && ::kill(pid, SIGSTOP) == 0;
            rescue = std::thread([&, pid] {
                std::this_thread::sleep_for(std::chrono::milliseconds(pauseMs));
                if (pauseSucceeded)
                    ::kill(pid, SIGCONT); // ONLY this fixture's child
                resumed = true;
            });
        };
        if (duringLookup) {
            asyncCallProbe = [&](const QDBusMessage& message) {
                if (message.member() == QStringLiteral("GetNameOwner"))
                    pause();
            };
        } else {
            subscriptionProbe = [&](QDBusConnection&, const QString&, const QString&,
                                     QObject*, const char*) { pause(); };
        }
        QTimer heartbeat;
        heartbeat.setInterval(5);
        QObject::connect(&heartbeat, &QTimer::timeout, monitor.get(), [&] {
            if (intercepted && !resumed) {
                ++ticksWhilePaused;
                EXPECT_FALSE(monitor->protectionAvailable());
                sawTimeoutWhilePaused |= cleanups > cleanupsBeforePause;
            }
        });
        heartbeat.start();
        monitor->start();
        const bool ready = eventually([&] { return monitor->protectionAvailable(); }, 5000);
        subscriptionProbe = {};
        asyncCallProbe = {};
        if (rescue.joinable())
            rescue.join();
        heartbeat.stop();
        EXPECT_TRUE(intercepted);
        EXPECT_TRUE(pauseSucceeded);
        EXPECT_TRUE(ready);
        EXPECT_GE(ticksWhilePaused, 5);
        if (pauseMs > 1500)
            EXPECT_TRUE(sawTimeoutWhilePaused);
        EXPECT_FALSE(unlocked);
    }
};

TEST_F(LogindDBusBackendTest, RealFdTransferReleasesAllCopiesAfterCleanup)
{
    ready();
    checkHeldDuringCleanup = true;
    ASSERT_TRUE(simulated.prepare(*connection, true, true));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_TRUE(checkedBeforeClose);
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(0));
}

TEST_F(LogindDBusBackendTest, GuiKeepsDispatchingWhileBusIsPausedDuringSubscription)
{
    // Resume independently of the GUI: the OLD synchronous subscription must
    // fail its heartbeat assertion, not hang the test runner indefinitely.
    checkResponsiveWhenPaused(false);
}

TEST_F(LogindDBusBackendTest, GuiKeepsDispatchingWhileOwnerResolutionIsDelayed)
{
    checkResponsiveWhenPaused(true);
}

TEST_F(LogindDBusBackendTest, OwnerResolutionTimeoutFailsClosedThenRecovers)
{
    checkResponsiveWhenPaused(true, 2100);
}

TEST_F(LogindDBusBackendTest, SubscriptionsAvoidImplicitResolutionAndKeepOwnerThread)
{
    int subscriptions = 0;
    subscriptionProbe = [&](QDBusConnection&, const QString& sender, const QString&,
                             QObject* receiver, const char*) {
        ++subscriptions;
        EXPECT_TRUE(sender.isEmpty() || sender == QStringLiteral("org.freedesktop.DBus"));
        EXPECT_TRUE(QThread::currentThread() == monitor->thread());
        EXPECT_TRUE(receiver->thread() == monitor->thread());
    };
    QObject observer;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     &observer, [&](bool) {
        EXPECT_TRUE(QThread::currentThread() == monitor->thread());
    });
    ready();
    subscriptionProbe = {};
    EXPECT_EQ(subscriptions, 4);
    ASSERT_TRUE(simulated.prepare(*connection, true, true));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, ServiceAbsentAtStartupRemainsClosedUntilFreshAcquisition)
{
    ASSERT_TRUE(connection->unregisterService(service));
    monitor->start();
    ASSERT_TRUE(eventually([&] { return cleanups >= 2; }));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(monitor->protectionIsOperational());
    EXPECT_EQ(simulated.requests, 0);
    ASSERT_TRUE(connection->registerService(service));
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
    EXPECT_EQ(simulated.requests, 1);
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, OwnerDisappearingDuringSubscriptionCannotAuthorizeAccess)
{
    bool disappeared = false;
    subscriptionProbe = [&](QDBusConnection&, const QString&, const QString&,
                             QObject*, const char*) {
        if (!disappeared) {
            disappeared = true;
            EXPECT_TRUE(connection->unregisterService(service));
        }
    };
    monitor->start();
    ASSERT_TRUE(eventually([&] { return disappeared && cleanups >= 2; }));
    subscriptionProbe = {};
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
    EXPECT_EQ(simulated.requests, 0);
    ASSERT_TRUE(connection->registerService(service));
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, ReplacementRequiresFreshProtectionAndRejectsFormerOwnerSignals)
{
    ready();
    const auto allowReplacement = connection->interface()->registerService(service,
        QDBusConnectionInterface::DontQueueService, QDBusConnectionInterface::AllowReplacement);
    ASSERT_TRUE(allowReplacement.isValid());
    SignalCapture capture;
    ASSERT_TRUE(connection->connect(QString(), path, manager, QStringLiteral("PrepareForSleep"),
                                    &capture, SLOT(receive(QDBusMessage))));
    SignalCapture owners;
    ASSERT_TRUE(connection->connect(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("NameOwnerChanged"), &owners, SLOT(receive(QDBusMessage))));
    SimulatedLogind replacement;
    auto next = QDBusConnection::connectToBus(busAddress,
        QStringLiteral("passwall-replacement-") + QUuid::createUuid().toString());
    const auto closeNext = qScopeGuard([&] { QDBusConnection::disconnectFromBus(next.name()); });
    ASSERT_TRUE(next.isConnected());
    ASSERT_TRUE(next.registerVirtualObject(path, &replacement));
    const auto replaced = next.interface()->registerService(service,
        QDBusConnectionInterface::ReplaceExistingService, QDBusConnectionInterface::DontAllowReplacement);
    ASSERT_TRUE(replaced.isValid());
    ASSERT_EQ(replaced.value(), QDBusConnectionInterface::ServiceRegistered);
    ASSERT_TRUE(eventually([&] {
        return replacement.requests == 1 && monitor->protectionAvailable();
    }));
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(0));
    EXPECT_TRUE(replacement.held(0));
    bool directSwapObserved = false;
    for (const auto& message : owners.messages) {
        const auto arguments = message.arguments();
        if (arguments.size() == 3 && arguments[0].toString() == QLatin1String(service) &&
            arguments[1].toString() == connection->baseService() &&
            arguments[2].toString() == next.baseService())
            directSwapObserved = true;
    }
    EXPECT_TRUE(directSwapObserved); // no empty-owner interval in this case
    unlocked = true; // explicit manual unlock of the new session only
    ASSERT_TRUE(simulated.prepare(*connection, true, true));
    ASSERT_TRUE(eventually([&] { return capture.messages.size() == 1; }));
    EXPECT_TRUE(monitor->protectionIsOperational());
    EXPECT_TRUE(unlocked); // the former owner's signal was actually received
    ASSERT_TRUE(replacement.prepare(next, true, true));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(replacement.held(0));
}

TEST_F(LogindDBusBackendTest, LateSnapshotFromReplacedOwnerCannotAuthorizeProtection)
{
    simulated.delaySnapshot = true;
    monitor->start();
    ASSERT_TRUE(eventually([&] { return simulated.pendingSnapshots.size() == 1; }));
    const auto pending = backend->findChildren<QDBusPendingCallWatcher*>();
    ASSERT_EQ(pending.size(), 1);
    const QPointer<QDBusPendingCallWatcher> oldReply(pending.front());
    int readySignals = 0;
    QObject observer;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     &observer, [&](bool ready) { readySignals += ready ? 1 : 0; });
    SimulatedLogind replacement;
    replacement.sleeping = true;
    auto next = QDBusConnection::connectToBus(busAddress,
        QStringLiteral("passwall-replacement-") + QUuid::createUuid().toString());
    const auto closeNext = qScopeGuard([&] { QDBusConnection::disconnectFromBus(next.name()); });
    ASSERT_TRUE(next.isConnected());
    ASSERT_TRUE(next.registerVirtualObject(path, &replacement));
    ASSERT_TRUE(connection->unregisterService(service));
    ASSERT_TRUE(next.registerService(service));
    ASSERT_TRUE(eventually([&] { return replacement.snapshots == 1; }));
    ASSERT_TRUE(eventually([&] { return !replacement.held(0); }));
    ASSERT_FALSE(monitor->protectionAvailable());
    ASSERT_TRUE(simulated.replyToSnapshot(*connection)); // old false/false state
    ASSERT_TRUE(eventually([&] { return oldReply.isNull(); }));
    EXPECT_EQ(readySignals, 0);
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(0));
}

TEST_F(LogindDBusBackendTest, PrivateBusRecoveryReacquiresWithoutUnlocking)
{
    ready();
    daemon.terminate();
    ASSERT_TRUE(daemon.waitForFinished(2000));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_FALSE(simulated.held(0));
    disconnectFixture();
    ASSERT_NO_FATAL_FAILURE(startPrivateBus());
    ASSERT_NO_FATAL_FAILURE(connectFixture());
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }, 4000));
    EXPECT_EQ(simulated.requests, 2);
    EXPECT_TRUE(simulated.held(1));
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, OldConnectionSignalCannotAffectRestartedBusWithReusedOwnerName)
{
    SignalCapture capture;
    ASSERT_TRUE(connection->connect(QString(), path, manager, QStringLiteral("PrepareForSleep"),
                                    &capture, SLOT(receive(QDBusMessage))));
    ASSERT_TRUE(simulated.prepare(*connection, true, true));
    ASSERT_TRUE(eventually([&] { return capture.messages.size() == 1; }));
    const QDBusMessage oldMessage = capture.messages.front();
    simulated.sleeping = false;
    QPointer<QObject> oldReceiver;
    QByteArray oldSlot;
    subscriptionProbe = [&](QDBusConnection&, const QString&, const QString& member,
                             QObject* receiver, const char* slot) {
        if (member == QStringLiteral("PrepareForSleep") && !oldReceiver) {
            oldReceiver = receiver;
            oldSlot = slot;
        }
    };
    ready();
    subscriptionProbe = {};
    ASSERT_FALSE(oldReceiver.isNull());
    RetainDeferredDelete retain;
    oldReceiver->installEventFilter(&retain);
    daemon.terminate();
    ASSERT_TRUE(daemon.waitForFinished(2000));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    monitor->stop(); // keep reconnection ordering deterministic in this test
    disconnectFixture();
    ASSERT_NO_FATAL_FAILURE(startPrivateBus());
    ASSERT_NO_FATAL_FAILURE(connectFixture());
    ASSERT_TRUE(oldMessage.service() == connection->baseService());
    monitor->start();
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
    unlocked = true;
    ASSERT_FALSE(oldReceiver.isNull());
    const QByteArray method = oldSlot.mid(1, oldSlot.indexOf('(') - 1);
    ASSERT_TRUE(QMetaObject::invokeMethod(oldReceiver, method.constData(),
        Qt::DirectConnection, Q_ARG(QDBusMessage, oldMessage)));
    EXPECT_TRUE(monitor->protectionIsOperational());
    EXPECT_TRUE(unlocked);
    oldReceiver->removeEventFilter(&retain);
    oldReceiver->deleteLater();
}

TEST_F(LogindDBusBackendTest, StopRestartDropsOldPendingSnapshotAndNeverUnlocks)
{
    simulated.delaySnapshot = true;
    monitor->start();
    ASSERT_TRUE(eventually([&] { return simulated.pendingSnapshots.size() == 1; }));
    const auto pending = backend->findChildren<QDBusPendingCallWatcher*>();
    ASSERT_EQ(pending.size(), 1);
    const QPointer<QDBusPendingCallWatcher> oldReply(pending.front());
    monitor->stop();
    EXPECT_TRUE(oldReply.isNull());
    EXPECT_FALSE(simulated.held(0));
    simulated.delaySnapshot = false;
    monitor->start();
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
    ASSERT_TRUE(simulated.replyToSnapshot(*connection));
    EXPECT_TRUE(oldReply.isNull()); // no receiver survives for this late reply
    EXPECT_TRUE(monitor->protectionIsOperational());
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, BrokerRefusalOfSignalRulesFailsClosed)
{
    daemon.terminate();
    ASSERT_TRUE(daemon.waitForFinished(2000));
    disconnectFixture();
    const QString config = directory.filePath(QStringLiteral("private-bus.conf"));
    QFile file(config);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::NewOnly));
    const QByteArray configData = QByteArray(
        "<busconfig><type>session</type><auth>EXTERNAL</auth><listen>unix:path=") +
        directory.filePath(QStringLiteral("bus")).toUtf8() + QByteArray(
        "</listen>"
        "<policy context='default'><allow own='*'/>"
        "<allow send_destination='*'/><allow receive_sender='*'/>"
        "<deny send_destination='org.freedesktop.DBus' "
        "send_interface='org.freedesktop.DBus' send_member='AddMatch'/>"
        "</policy></busconfig>");
    ASSERT_EQ(file.write(configData), configData.size());
    file.close();
    ASSERT_NO_FATAL_FAILURE(startPrivateBus(config));
    ASSERT_NO_FATAL_FAILURE(connectFixture());
    bool sawAddMatch = false;
    asyncCallProbe = [&](const QDBusMessage& message) {
        sawAddMatch |= message.member() == QStringLiteral("AddMatch");
    };
    monitor->start();
    ASSERT_TRUE(eventually([&] { return cleanups >= 2; }));
    asyncCallProbe = {};
    EXPECT_TRUE(sawAddMatch);
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(monitor->protectionIsOperational());
    EXPECT_FALSE(unlocked);
    EXPECT_EQ(simulated.requests, 0);
}

TEST_F(LogindDBusBackendTest, PreparationDuringPendingSnapshotInvalidatesItsLateReply)
{
    simulated.delaySnapshot = true;
    int readySignals = 0;
    QObject observer;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     &observer, [&](bool ready) { readySignals += ready ? 1 : 0; });
    monitor->start();
    ASSERT_TRUE(eventually([&] { return simulated.pendingSnapshots.size() == 1; }));
    const auto pending = backend->findChildren<QDBusPendingCallWatcher*>();
    ASSERT_EQ(pending.size(), 1);
    const QPointer<QDBusPendingCallWatcher> oldReply(pending.front());
    ASSERT_TRUE(simulated.prepare(*connection, true, true));
    ASSERT_TRUE(eventually([&] { return !simulated.held(0); }));
    simulated.sleeping = false;
    ASSERT_TRUE(simulated.replyToSnapshot(*connection));
    ASSERT_TRUE(eventually([&] { return oldReply.isNull(); }));
    EXPECT_EQ(readySignals, 0);
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
}

class LogindDBusRestartTest : public LogindDBusBackendTest,
                              public ::testing::WithParamInterface<const char*> {};

TEST_P(LogindDBusRestartTest, OldAsyncStageCannotReviveAReplacedConnection)
{
    bool restarted = false;
    int readySignals = 0;
    QObject observer;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     &observer, [&](bool ready) { readySignals += ready ? 1 : 0; });
    asyncCallProbe = [&](const QDBusMessage& message) {
        if (!restarted && message.member() == QLatin1String(GetParam())) {
            restarted = true;
            // Queued BEFORE the old asyncCall can post its completion.
            QMetaObject::invokeMethod(monitor.get(), [&] {
                monitor->stop();
                EXPECT_FALSE(monitor->protectionAvailable());
                monitor->start();
            }, Qt::QueuedConnection);
        }
    };
    monitor->start();
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
    asyncCallProbe = {};
    EXPECT_TRUE(restarted);
    EXPECT_EQ(readySignals, 1);
    EXPECT_EQ(simulated.requests, 1);
    EXPECT_TRUE(simulated.held(0));
    EXPECT_FALSE(unlocked);
}

INSTANTIATE_TEST_SUITE_P(PendingStages, LogindDBusRestartTest,
                        ::testing::Values("AddMatch", "GetNameOwner"));

TEST_F(LogindDBusBackendTest, BrokenWriteFifoDuringGetAllNeverPublishesProtection)
{
    simulated.breakBeforeSnapshot = true;
    int readySignals = 0;
    QObject observer;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     &observer, [&](bool ready) { readySignals += ready ? 1 : 0; });
    monitor->start();
    ASSERT_TRUE(eventually([&] {
        return simulated.snapshots == 1 && cleanups >= 3;
    }));
    EXPECT_EQ(readySignals, 0);
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(monitor->protectionIsOperational());
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, ResumeReacquiresAndShutdownLocksViaRealDBusSignals)
{
    ready();
    ASSERT_TRUE(simulated.prepare(*connection, true, true));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    ASSERT_TRUE(simulated.prepare(*connection, true, false));
    ASSERT_TRUE(eventually([&] { return monitor->protectionAvailable(); }));
    EXPECT_EQ(simulated.requests, 2);
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(0));
    ASSERT_TRUE(simulated.held(1));
    unlocked = true; // another explicit manual unlock
    ASSERT_TRUE(simulated.prepare(*connection, false, true));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(1));
}

TEST_F(LogindDBusBackendTest, ServiceOwnerLossLocksAndReleasesDescriptor)
{
    ready();
    ASSERT_TRUE(connection->unregisterService(service));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(0));
}

TEST_F(LogindDBusBackendTest, InhibitorAccessDeniedFailsClosed)
{
    simulated.deny = true;
    monitor->start();
    ASSERT_TRUE(eventually([&] { return simulated.requests == 1 && cleanups >= 3; }));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
    EXPECT_TRUE(simulated.peers.empty());
}

TEST_F(LogindDBusBackendTest, MalformedStateFailsClosedAndReleasesDescriptor)
{
    simulated.malformed = true;
    monitor->start();
    ASSERT_TRUE(eventually([&] {
        return !simulated.peers.empty() && !simulated.held(0);
    }));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
}

TEST_F(LogindDBusBackendTest, PrivateBusDisconnectionRevokesProtection)
{
    ready();
    daemon.terminate(); // ONLY our own isolated dbus-daemon, never system DBus
    ASSERT_TRUE(daemon.waitForFinished(2000));
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }));
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(simulated.held(0));
}

TEST_F(LogindDBusBackendTest, ReentrantStopDuringReadinessCleansPendingReplies)
{
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     monitor.get(), [this](bool ready) {
        if (ready)
            monitor->stop();
    });
    monitor->start();
    ASSERT_TRUE(eventually([&] {
        return !simulated.peers.empty() && !simulated.held(0);
    }));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
}
} // namespace

#include "test_logind_dbus_backend.moc"
