#include "platform/linux_instance_lock.hpp"
#include "platform/session_lock_service.hpp"
#include "private_dbus.hpp"

#include <gtest/gtest.h>
#include <QDBusConnectionInterface>
#include <QDBusPendingReply>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QLocalServer>
#include <QSysInfo>
#include <QTemporaryDir>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using passwall::platform::LinuxInstanceLock;
using passwall::platform::SessionLockService;
using passwall::tests::waitFor;

class LinuxInstanceLockTest : public ::testing::Test {
protected:
    QTemporaryDir runtime{QStringLiteral("/tmp/pw-instance-XXXXXX")};
    QString error;
    QString helper() const { return QCoreApplication::applicationDirPath() + QStringLiteral("/passwall_instance_probe"); }
    void start(QProcess& process, const QStringList& extra = {})
    {
        process.setProgram(helper());
        process.setArguments(QStringList{runtime.path()} + extra);
        process.start();
        ASSERT_TRUE(process.waitForStarted(1000));
    }
    void ready(QProcess& process)
    {
        if (!process.canReadLine())
            ASSERT_TRUE(process.waitForReadyRead(2000));
        ASSERT_EQ(process.readLine().trimmed(), QByteArrayLiteral("READY"));
    }
    void finish(QProcess& process)
    {
        process.write("quit\n");
        ASSERT_TRUE(process.waitForFinished(2000));
        EXPECT_EQ(process.exitCode(), 0);
    }
};

TEST_F(LinuxInstanceLockTest, FirstAcquisitionAndNormalCloseAllowRestart)
{
    auto first = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    ASSERT_NE(first, nullptr);
    EXPECT_TRUE(first->isHeld());
    auto second = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    EXPECT_EQ(second, nullptr);
    EXPECT_FALSE(error.isEmpty());
    first.reset();
    EXPECT_NE(LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error), nullptr);
}

TEST_F(LinuxInstanceLockTest, SecondProcessDoesNotTouchExistingSocketOrLock)
{
    QProcess first;
    start(first);
    ready(first);
    const QString socket = runtime.filePath(QStringLiteral("passwall-native-bridge.sock"));
    struct stat before{}, after{};
    ASSERT_EQ(::lstat(QFile::encodeName(socket).constData(), &before), 0);
    QFile file(runtime.filePath(QStringLiteral("passwall-app.lock")));
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    const auto contents = file.readAll();
    file.close();
    // Even a very old active lock is not a reason to remove it.
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    ASSERT_TRUE(file.setFileTime(QDateTime::currentDateTimeUtc().addYears(-1), QFileDevice::FileModificationTime));
    file.close();
    QProcess second;
    start(second);
    ASSERT_TRUE(second.waitForFinished(2000));
    EXPECT_EQ(second.exitCode(), 3);
    EXPECT_EQ(first.state(), QProcess::Running);
    ASSERT_EQ(::lstat(QFile::encodeName(socket).constData(), &after), 0);
    EXPECT_EQ(before.st_ino, after.st_ino);
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    EXPECT_EQ(file.readAll(), contents);
    finish(first);
}

TEST_F(LinuxInstanceLockTest, ConcurrentLaunchesAdmitExactlyOneProcess)
{
    QProcess first, second;
    start(first);
    start(second);
    ASSERT_TRUE(waitFor([&] { return first.state() == QProcess::NotRunning || second.state() == QProcess::NotRunning; }));
    QProcess& winner = first.state() == QProcess::Running ? first : second;
    QProcess& loser = first.state() == QProcess::Running ? second : first;
    EXPECT_EQ(loser.exitCode(), 3);
    ready(winner);
    finish(winner);
}

TEST_F(LinuxInstanceLockTest, CrashRecoveryAlsoRecoversOnlyTheStaleOwnedSocket)
{
    QProcess first;
    start(first);
    ready(first);
    first.kill(); // Only this isolated probe, never a real PassWall process.
    ASSERT_TRUE(first.waitForFinished(2000));
    ASSERT_TRUE(QFileInfo::exists(runtime.filePath(QStringLiteral("passwall-app.lock"))));
    auto recovered = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    ASSERT_NE(recovered, nullptr);
    EXPECT_TRUE(recovered->prepareNativeBridgeSocket(error));
    EXPECT_FALSE(QFileInfo::exists(runtime.filePath(QStringLiteral("passwall-native-bridge.sock"))));
}

TEST_F(LinuxInstanceLockTest, UnsafeDirectoriesAndUnexpectedRuntimeAreRejected)
{
    const auto original = qgetenv("XDG_RUNTIME_DIR");
    qputenv("XDG_RUNTIME_DIR", runtime.path().toUtf8());
    EXPECT_EQ(LinuxInstanceLock::acquire(error), nullptr);
    qputenv("XDG_RUNTIME_DIR", original);
    ASSERT_EQ(::chmod(QFile::encodeName(runtime.path()).constData(), 0770), 0);
    EXPECT_EQ(LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error), nullptr);
    ASSERT_EQ(::chmod(QFile::encodeName(runtime.path()).constData(), 0700), 0);
    const QString link = runtime.path() + QStringLiteral("-alias");
    ASSERT_TRUE(QFile::link(runtime.path(), link));
    EXPECT_EQ(LinuxInstanceLock::acquireInDirectoryForTesting(link, error), nullptr);
    ASSERT_TRUE(QFile::remove(link));
    EXPECT_EQ(LinuxInstanceLock::acquireInDirectoryForTesting(runtime.filePath(QStringLiteral("absent")), error), nullptr);
}

TEST_F(LinuxInstanceLockTest, MalformedSymlinkAndCreationFailuresFailClosed)
{
    const QString name = runtime.filePath(QStringLiteral("passwall-app.lock"));
    QFile file(name);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    file.write("unparseable\n");
    file.close();
    EXPECT_EQ(LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error), nullptr);
    ASSERT_TRUE(QFile::remove(name));
    ASSERT_TRUE(QFile::link(runtime.filePath(QStringLiteral("absent")), name));
    EXPECT_EQ(LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error), nullptr);
    ASSERT_TRUE(QFile::remove(name));
    ASSERT_TRUE(QDir().mkdir(name));
    EXPECT_EQ(LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error), nullptr);
}

TEST_F(LinuxInstanceLockTest, SocketRecoveryNeverRemovesRegularFilesOrLiveListeners)
{
    QProcess listener;
    start(listener);
    ready(listener);
    auto denied = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    EXPECT_EQ(denied, nullptr);
    finish(listener);
    auto instance = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    ASSERT_NE(instance, nullptr);
    const QString path = runtime.filePath(QStringLiteral("passwall-native-bridge.sock"));
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    file.write("not-a-socket");
    file.close();
    EXPECT_FALSE(instance->prepareNativeBridgeSocket(error));
    EXPECT_TRUE(QFileInfo::exists(path));
    ASSERT_TRUE(QFile::remove(path));
    QLocalServer live;
    ASSERT_TRUE(live.listen(path));
    EXPECT_FALSE(instance->prepareNativeBridgeSocket(error));
    EXPECT_TRUE(live.isListening());
    EXPECT_TRUE(QFileInfo::exists(path));
}

TEST_F(LinuxInstanceLockTest, MultipleRealNativeHostsCanWaitWhileApplicationLockIsHeld)
{
    auto instance = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    ASSERT_NE(instance, nullptr);
    QProcess first, second;
    for (auto* process : {&first, &second}) {
        process->setProgram(QCoreApplication::applicationDirPath() + QStringLiteral("/passwall_native_host"));
        process->start();
        ASSERT_TRUE(process->waitForStarted(1000));
    }
    EXPECT_TRUE(waitFor([&] { return first.state() == QProcess::Running && second.state() == QProcess::Running; }));
    for (auto* process : {&first, &second}) {
        process->closeWriteChannel(); // EOF, no request and no app launch.
        ASSERT_TRUE(process->waitForFinished(2000));
        EXPECT_EQ(process->exitCode(), 0);
        EXPECT_TRUE(process->readAllStandardOutput().isEmpty());
    }
    EXPECT_TRUE(instance->isHeld());
}

TEST_F(LinuxInstanceLockTest, OnlyAdmittedProcessOwnsTheControlService)
{
    passwall::tests::PrivateDBus bus;
    ASSERT_TRUE(bus.isValid());
    QProcess first, second;
    start(first, {bus.address()});
    ready(first);
    auto client = bus.connect();
    auto query = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetNameOwner"));
    query.setArguments({QString::fromLatin1(SessionLockService::Service)});
    QDBusPendingReply<QString> owner = client.asyncCall(query);
    ASSERT_TRUE(waitFor([&] { return owner.isFinished(); }));
    ASSERT_FALSE(owner.isError());
    const QString original = owner.value();
    start(second, {bus.address()});
    ASSERT_TRUE(second.waitForFinished(2000));
    EXPECT_EQ(second.exitCode(), 3);
    QDBusPendingReply<QString> unchanged = client.asyncCall(query);
    ASSERT_TRUE(waitFor([&] { return unchanged.isFinished(); }));
    ASSERT_FALSE(unchanged.isError());
    EXPECT_EQ(unchanged.value(), original);
    auto request = QDBusMessage::createMethodCall(QString::fromLatin1(SessionLockService::Service),
        QString::fromLatin1(SessionLockService::Path), QString::fromLatin1(SessionLockService::Interface), QStringLiteral("Lock"));
    request.setAutoStartService(false);
    QDBusPendingReply<> reply = client.asyncCall(request);
    ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
    EXPECT_FALSE(reply.isError());
    finish(first);
    QProcess restarted;
    start(restarted, {bus.address()});
    ready(restarted);
    finish(restarted);
}

TEST_F(LinuxInstanceLockTest, CrashReleasesControlNameAndNewProcessOwnsBothProtections)
{
    passwall::tests::PrivateDBus bus;
    ASSERT_TRUE(bus.isValid());
    QProcess first;
    start(first, {bus.address()});
    ready(first);
    first.kill(); // Isolated helper, with no vault or user configuration.
    ASSERT_TRUE(first.waitForFinished(2000));
    QProcess replacement;
    start(replacement, {bus.address()});
    ready(replacement);
    auto refused = LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
    EXPECT_EQ(refused, nullptr);
    auto client = bus.connect();
    auto request = QDBusMessage::createMethodCall(QString::fromLatin1(SessionLockService::Service),
        QString::fromLatin1(SessionLockService::Path), QString::fromLatin1(SessionLockService::Interface), QStringLiteral("Lock"));
    request.setAutoStartService(false);
    QDBusPendingReply<> reply = client.asyncCall(request);
    ASSERT_TRUE(waitFor([&] { return reply.isFinished(); }));
    EXPECT_FALSE(reply.isError());
    finish(replacement);
}
} // namespace
