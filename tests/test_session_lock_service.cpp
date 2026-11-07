#include "platform/linux_instance_lock.hpp"
#include "platform/session_lock_service.hpp"
#include "private_dbus.hpp"

#include <gtest/gtest.h>
#include <QDBusConnectionInterface>
#include <QDBusError>
#include <QDBusPendingReply>
#include <QTemporaryDir>
#include <stdexcept>

namespace {
using passwall::platform::LinuxInstanceLock;
using passwall::platform::SessionLockService;
using passwall::tests::waitFor;

class SessionLockServiceTest : public ::testing::Test {
protected:
    passwall::tests::PrivateDBus bus;
    QTemporaryDir runtime{QStringLiteral("/tmp/pw-lock-service-XXXXXX")};
    std::unique_ptr<LinuxInstanceLock> instance;
    std::unique_ptr<SessionLockService> service;
    std::unique_ptr<QDBusConnection> client;
    std::vector<SessionLockService::Completion> cleanups;
    int unavailable = 0;

    void SetUp() override
    {
        ASSERT_TRUE(bus.isValid());
        QString error;
        instance = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
        ASSERT_NE(instance, nullptr);
        client = std::make_unique<QDBusConnection>(bus.connect());
        ASSERT_TRUE(client->isConnected());
        service = std::make_unique<SessionLockService>(*instance,
            [this](auto completion) { cleanups.push_back(std::move(completion)); });
        QObject::connect(service.get(), &SessionLockService::availabilityChanged,
            service.get(), [this](bool ready) { if (!ready) ++unavailable; });
    }
    void start()
    {
        service->start(bus.address());
        ASSERT_TRUE(waitFor([&] { return service->isAvailable(); }));
    }
    void TearDown() override
    {
        service.reset();
        client.reset();
    }
    QDBusPendingReply<> request(QString member = QStringLiteral("Lock"), QVariantList args = {})
    {
        auto message = QDBusMessage::createMethodCall(QString::fromLatin1(SessionLockService::Service),
            QString::fromLatin1(SessionLockService::Path), QString::fromLatin1(SessionLockService::Interface), member);
        message.setArguments(args);
        message.setAutoStartService(false);
        return client->asyncCall(message, 2000);
    }
};

TEST_F(SessionLockServiceTest, RepliesOnlyAfterExplicitCleanupCompletion)
{
    start();
    auto reply = request();
    ASSERT_TRUE(waitFor([&] { return cleanups.size() == 1; }));
    EXPECT_FALSE(reply.isFinished());
    cleanups.front()(true);
    ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
    EXPECT_FALSE(reply.isError());
    EXPECT_TRUE(reply.reply().arguments().isEmpty());
}

TEST_F(SessionLockServiceTest, ConcurrentRequestsKeepTheirOwnPendingAcknowledgements)
{
    start();
    auto first = request();
    auto second = request();
    auto third = request();
    ASSERT_TRUE(waitFor([&] { return cleanups.size() == 3; }));
    EXPECT_FALSE(first.isFinished());
    EXPECT_FALSE(second.isFinished());
    EXPECT_FALSE(third.isFinished());
    cleanups[1](true);
    ASSERT_TRUE(waitFor([&] { return second.isFinished(); }));
    EXPECT_FALSE(second.isError());
    EXPECT_FALSE(first.isFinished());
    EXPECT_FALSE(third.isFinished());
    cleanups[0](true);
    cleanups[2](true);
    ASSERT_TRUE(waitFor([&] { return first.isFinished() && third.isFinished(); }));
    EXPECT_FALSE(first.isError());
    EXPECT_FALSE(third.isError());
}

TEST_F(SessionLockServiceTest, ExposesOnlyLockAndRejectsParameters)
{
    start();
    for (const auto& member : {QStringLiteral("Unlock"), QStringLiteral("GetCredential")}) {
        auto reply = request(member);
        ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
        EXPECT_TRUE(reply.isError());
    }
    auto malformed = request(QStringLiteral("Lock"), {QStringLiteral("unexpected")});
    ASSERT_TRUE(waitFor([&] { return malformed.isFinished(); }));
    EXPECT_TRUE(malformed.isError());
    EXPECT_TRUE(cleanups.empty());
    auto message = QDBusMessage::createMethodCall(QString::fromLatin1(SessionLockService::Service),
        QString::fromLatin1(SessionLockService::Path), QStringLiteral("org.freedesktop.DBus.Introspectable"),
        QStringLiteral("Introspect"));
    QDBusPendingReply<QString> xml = client->asyncCall(message);
    ASSERT_TRUE(waitFor([&] { return xml.isFinished(); }));
    ASSERT_FALSE(xml.isError());
    EXPECT_TRUE(xml.value().contains(QStringLiteral("name=\"Lock\"")));
    EXPECT_FALSE(xml.value().contains(QStringLiteral("name=\"Unlock\"")));
    EXPECT_FALSE(xml.value().contains(QStringLiteral("password")));
    EXPECT_FALSE(xml.value().contains(QStringLiteral("org.passwall.PassWall.SessionGuard1")));
    EXPECT_FALSE(xml.value().contains(QStringLiteral("name=\"Acquire\"")));
    EXPECT_FALSE(xml.value().contains(QStringLiteral("name=\"Release\"")));
}

TEST_F(SessionLockServiceTest, RemovedGuardInterfaceAndMethodsAreRejected)
{
    start();
    for (const auto& interface : {QStringLiteral("org.passwall.PassWall.SessionGuard1"),
                                  QString::fromLatin1(SessionLockService::Interface)}) {
        for (const auto& member : {QStringLiteral("Acquire"), QStringLiteral("Release")}) {
            auto message = QDBusMessage::createMethodCall(QString::fromLatin1(SessionLockService::Service),
                QString::fromLatin1(SessionLockService::Path), interface, member);
            if (member == QStringLiteral("Release"))
                message.setArguments({QStringLiteral("obsolete-test-token")});
            message.setAutoStartService(false);
            QDBusPendingReply<> reply = client->asyncCall(message, 2000);
            ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
            EXPECT_TRUE(reply.isError());
            EXPECT_EQ(reply.error().type(), QDBusError::UnknownMethod);
        }
    }
    EXPECT_TRUE(cleanups.empty());
    EXPECT_TRUE(service->isAvailable());
}

TEST_F(SessionLockServiceTest, FailedCleanupReturnsErrorAndRevokesAvailability)
{
    start();
    auto reply = request();
    ASSERT_TRUE(waitFor([&] { return cleanups.size() == 1; }));
    cleanups.front()(false);
    ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
    EXPECT_TRUE(reply.isError());
    EXPECT_FALSE(service->isAvailable());
    EXPECT_EQ(unavailable, 1);
}

TEST_F(SessionLockServiceTest, ExceptionsNeverBecomeSuccessfulAcknowledgements)
{
    service = std::make_unique<SessionLockService>(*instance, [](auto) {
        throw std::runtime_error("synthetic-cleanup-failure");
    });
    start();
    auto reply = request();
    ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
    EXPECT_TRUE(reply.isError());
    EXPECT_FALSE(reply.error().message().contains(QStringLiteral("synthetic")));
    EXPECT_FALSE(service->isAvailable());
}

TEST_F(SessionLockServiceTest, ExistingServiceOwnerIsNeverReplacedOrQueuedFor)
{
    auto foreign = bus.connect();
    ASSERT_TRUE(foreign.registerService(QString::fromLatin1(SessionLockService::Service)));
    service->start(bus.address());
    ASSERT_TRUE(waitFor([&] { return unavailable == 1; }));
    EXPECT_FALSE(service->isAvailable());
    // Query the actual owner, not a cached boolean.
    auto query = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetNameOwner"));
    query.setArguments({QString::fromLatin1(SessionLockService::Service)});
    QDBusPendingReply<QString> owner = client->asyncCall(query);
    ASSERT_TRUE(waitFor([&] { return owner.isFinished(); }));
    ASSERT_FALSE(owner.isError());
    EXPECT_EQ(owner.value(), foreign.baseService());
    ASSERT_TRUE(foreign.unregisterService(QString::fromLatin1(SessionLockService::Service)));
    QCoreApplication::processEvents();
    EXPECT_FALSE(service->isAvailable());
}

TEST_F(SessionLockServiceTest, MissingBusDoesNotAuthorizeProtection)
{
    service->start(QString());
    EXPECT_EQ(unavailable, 1);
    EXPECT_FALSE(service->isAvailable());
    service->start(QStringLiteral("unix:path=") + runtime.filePath(QStringLiteral("missing-bus")));
    EXPECT_EQ(unavailable, 2);
    EXPECT_FALSE(service->isAvailable());
}

TEST_F(SessionLockServiceTest, StopCancelsPendingReplyAndLateCompletionCannotReviveIt)
{
    start();
    auto oldReply = request();
    ASSERT_TRUE(waitFor([&] { return cleanups.size() == 1; }));
    const auto stale = cleanups.front();
    service->stop();
    ASSERT_TRUE(waitFor([&] { return oldReply.isFinished(); }));
    EXPECT_TRUE(oldReply.isError());
    start();
    auto newReply = request();
    ASSERT_TRUE(waitFor([&] { return cleanups.size() == 2; }));
    stale(true);
    QCoreApplication::processEvents();
    EXPECT_FALSE(newReply.isFinished());
    cleanups.back()(true);
    ASSERT_TRUE(waitFor([&] { return newReply.isFinished(); }));
    EXPECT_FALSE(newReply.isError());
    EXPECT_TRUE(oldReply.isError());
}

TEST_F(SessionLockServiceTest, BusLossFailsClosedWithoutASuccessfulPendingReply)
{
    start();
    auto reply = request();
    ASSERT_TRUE(waitFor([&] { return cleanups.size() == 1; }));
    bus.stop();
    ASSERT_TRUE(waitFor([&] { return !service->isAvailable(); }));
    cleanups.front()(true);
    ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
    EXPECT_TRUE(reply.isError());
    EXPECT_GE(unavailable, 1);
}
} // namespace
