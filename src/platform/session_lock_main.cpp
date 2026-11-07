#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QTimer>

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr int cleanupDeadlineMs = 1500;
constexpr auto workerArgument = "--dbus-lock-worker";
enum CleanupResult { Acknowledged = 0, Unavailable = 2, Refused = 3, Expired = 4, InvalidReply = 5 };

// Only this child touches Qt DBus. Even connectToBus()'s internal synchronous
// handshake cannot prevent the parent from launching the screen locker on time.
int requestCleanup(QCoreApplication& application)
{
    const auto address = qEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS");
    if (address.isEmpty())
        return Unavailable;
    QTimer deadline;
    deadline.setSingleShot(true);
    deadline.setTimerType(Qt::PreciseTimer);
    QObject::connect(&deadline, &QTimer::timeout, &application,
        [&] { application.exit(Expired); });
    deadline.start(cleanupDeadlineMs);
    const auto bus = QDBusConnection::connectToBus(address, QStringLiteral("passwall-lock-request"));
    if (!bus.isConnected())
        return Unavailable;
    auto message = QDBusMessage::createMethodCall(QStringLiteral("org.passwall.PassWall"),
        QStringLiteral("/org/passwall/PassWall"), QStringLiteral("org.passwall.PassWall.Control1"),
        QStringLiteral("Lock"));
    message.setAutoStartService(false);
    message.setInteractiveAuthorizationAllowed(false);
    // Exactly one Lock call; no interface introspection and no service activation.
    QDBusPendingCallWatcher reply(bus.asyncCall(message, cleanupDeadlineMs));
    QObject::connect(&reply, &QDBusPendingCallWatcher::finished, &application, [&] {
        const auto response = reply.reply();
        if (response.type() == QDBusMessage::ReplyMessage)
            application.exit(response.arguments().isEmpty() && response.signature().isEmpty()
                ? Acknowledged : InvalidReply);
        else if (response.errorName() == QStringLiteral("org.freedesktop.DBus.Error.ServiceUnknown") ||
                 response.errorName() == QStringLiteral("org.freedesktop.DBus.Error.NameHasNoOwner"))
            application.exit(Unavailable);
        else
            application.exit(Refused);
        // Never print the remote error body or any returned argument.
    });
    return application.exec();
}

// Invocation exclusion only, NOT a vault access guard. Keep the inode: unlinking
// a flock file could admit a second owner. No PID/stale-file recovery is needed.
class InvocationLock final {
public:
    enum Result { Acquired, Busy, Unsafe };
    ~InvocationLock() { if (fd_ >= 0) ::close(fd_); }
    InvocationLock() = default;
    InvocationLock(const InvocationLock&) = delete;
    InvocationLock& operator=(const InvocationLock&) = delete;
    Result acquire()
    {
        const auto path = qEnvironmentVariable("XDG_RUNTIME_DIR");
#ifndef PASSWALL_SESSION_LOCK_TESTING
        if (path != QStringLiteral("/run/user/%1").arg(::getuid()))
            return Unsafe;
#endif
        if (::getuid() != ::geteuid() || !QDir::isAbsolutePath(path) ||
            QDir::cleanPath(path) != path || QFileInfo(path).canonicalFilePath() != path)
            return Unsafe;
        const auto encoded = QFile::encodeName(path);
        const int directory = ::open(encoded.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory < 0)
            return Unsafe;
        struct stat info{};
        const bool safe = ::fstat(directory, &info) == 0 && S_ISDIR(info.st_mode) &&
            info.st_uid == ::getuid() && (info.st_mode & 0777) == 0700;
        if (safe)
            fd_ = ::openat(directory, "passwall-session-lock.lock",
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
        ::close(directory);
        if (fd_ < 0 || ::fstat(fd_, &info) != 0 || !S_ISREG(info.st_mode) ||
            info.st_uid != ::getuid() || info.st_nlink != 1 || (info.st_mode & 0777) != 0600)
            return Unsafe;
        return tryAcquire();
    }
    Result tryAcquire()
    {
        if (fd_ < 0)
            return Unsafe;
        if (::flock(fd_, LOCK_EX | LOCK_NB) == 0)
            return Acquired;
        return errno == EWOULDBLOCK || errno == EAGAIN ? Busy : Unsafe;
    }
private:
    int fd_ = -1;
};

class Coordinator final : public QObject {
public:
    explicit Coordinator(QCoreApplication& application) : application_(application)
    {
        deadline_.setSingleShot(true);
        deadline_.setTimerType(Qt::PreciseTimer);
        worker_.setStandardOutputFile(QProcess::nullDevice());
        worker_.setStandardErrorFile(QProcess::nullDevice());
        locker_.setStandardOutputFile(QProcess::nullDevice());
        locker_.setStandardErrorFile(QProcess::nullDevice());
        connect(&deadline_, &QTimer::timeout, this, [this] { launchLocker(Expired); });
        connect(&worker_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
            launchLocker(Unavailable);
        });
        connect(&worker_, &QProcess::finished, this, [this](int result, QProcess::ExitStatus status) {
            launchLocker(elapsed_.elapsed() >= cleanupDeadlineMs ? Expired :
                status == QProcess::NormalExit ? result : Unavailable);
        });
        connect(&locker_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) {
                std::fputs("PassWall: screen locker could not be started; screen lock NOT confirmed.\n", stderr);
                application_.exit(1);
            }
        });
        connect(&locker_, &QProcess::finished, this, [this](int code, QProcess::ExitStatus status) {
            if (status != QProcess::NormalExit || code != 0)
                std::fputs("PassWall: screen locker failed; screen lock state is unknown.\n", stderr);
            // No inference of screen unlock, no D-Bus release or vault operation.
            application_.exit(status == QProcess::NormalExit && code == 0 ? 0 : 1);
        });
    }
    void start()
    {
        exclusion_ = instance_.acquire();
        // Even a repeated request must clean a possible fresh vault session.
        // Exclusion deduplicates the screen locker, not Control1.Lock().
        elapsed_.start();
        deadline_.start(cleanupDeadlineMs);
        worker_.start(QCoreApplication::applicationFilePath(), {QString::fromLatin1(workerArgument)});
    }
private:
    void launchLocker(int result)
    {
        if (lockerAttempted_)
            return; // Includes late worker replies, errors and timeout callbacks.
        lockerAttempted_ = true;
        deadline_.stop();
        if (worker_.state() != QProcess::NotRunning)
            worker_.kill(); // Asynchronous: never wait for D-Bus before screen locking.
        const char* diagnostic;
        switch (result) {
        case Acknowledged:
            diagnostic = "PassWall: cleanup acknowledged.\n";
            break;
        case Expired:
            diagnostic = "PassWall: cleanup not confirmed (1500 ms deadline expired); attempting screen locking.\n";
            break;
        case Unavailable:
            diagnostic = "PassWall: cleanup not confirmed (service or bus unavailable); attempting screen locking.\n";
            break;
        default:
            diagnostic = "PassWall: cleanup not confirmed (request refused or invalid reply); attempting screen locking.\n";
        }
        if (exclusion_ == InvocationLock::Busy) {
            // The preceding locker may have exited while this call awaited
            // cleanup. In that case take ownership and honor the new request.
            exclusion_ = instance_.tryAcquire();
            if (exclusion_ == InvocationLock::Busy) {
                std::fputs(diagnostic, stderr);
                std::fputs("PassWall: another screen-lock request is in progress; no second locker started.\n", stderr);
                application_.exit(0);
                return;
            }
        }
#ifdef PASSWALL_SESSION_LOCK_TESTING
        // Compile-time test frontend only. Production accepts NO locker override.
        locker_.start(QCoreApplication::applicationDirPath() + QStringLiteral("/passwall-test-screen-locker"),
            {QStringLiteral("-p")});
#else
        locker_.start(QStringLiteral("/usr/bin/swaylock"), {QStringLiteral("-p")});
#endif
        // Launch first: diagnostics must not precede the screen-lock attempt.
        std::fputs(diagnostic, stderr);
        if (exclusion_ == InvocationLock::Unsafe)
            std::fputs("PassWall: invocation exclusion unavailable; attempting screen locking anyway.\n", stderr);
    }
    QCoreApplication& application_;
    InvocationLock instance_; // Held until the locker exits, solely for deduplication.
    InvocationLock::Result exclusion_ = InvocationLock::Unsafe;
    QProcess worker_;
    QProcess locker_;
    QTimer deadline_;
    QElapsedTimer elapsed_;
    bool lockerAttempted_ = false;
};
} // namespace

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    const auto arguments = application.arguments();
    if (arguments.size() == 2 && arguments[1] == QString::fromLatin1(workerArgument))
        return requestCleanup(application);
    if (arguments.size() != 1) {
        std::fputs("Usage: passwall-session-lock (no arguments)\n", stderr);
        return 64;
    }
    Coordinator coordinator(application);
    QTimer::singleShot(0, &coordinator, [&] { coordinator.start(); });
    return application.exec();
}
