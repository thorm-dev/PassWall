#include "linux_instance_lock.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace passwall::platform {
namespace {
bool safeFile(const QByteArray& name, bool mayBeAbsent)
{
    struct stat info{};
    if (::lstat(name.constData(), &info) < 0)
        return mayBeAbsent && errno == ENOENT;
    return S_ISREG(info.st_mode) && info.st_uid == ::getuid() &&
        info.st_nlink == 1 && !(info.st_mode & 0022) && info.st_size <= 4096;
}
}

LinuxInstanceLock::LinuxInstanceLock(QString runtimeDirectory)
    : directory_(std::move(runtimeDirectory)),
      lock_(directory_ + QStringLiteral("/passwall-app.lock"))
{
    lock_.setStaleLockTime(0);
}
LinuxInstanceLock::~LinuxInstanceLock() = default;
bool LinuxInstanceLock::isHeld() const noexcept { return lock_.isLocked(); }
QString LinuxInstanceLock::fileName() const { return lock_.fileName(); }

std::unique_ptr<LinuxInstanceLock> LinuxInstanceLock::acquire(QString& error)
{
    // Pin the systemd per-user directory: another XDG_RUNTIME_DIR must not
    // create an independent lock namespace for the same UID on this machine.
    const QString expected = QStringLiteral("/run/user/%1").arg(::getuid());
    if (qEnvironmentVariable("XDG_RUNTIME_DIR") != expected) {
        error = QStringLiteral("XDG_RUNTIME_DIR doit désigner le répertoire /run/user de cet utilisateur.");
        return {};
    }
    return acquireDirectory(expected, error);
}
std::unique_ptr<LinuxInstanceLock> LinuxInstanceLock::acquireInDirectoryForTesting(
    const QString& directory, QString& error)
{
    return acquireDirectory(directory, error);
}
std::unique_ptr<LinuxInstanceLock> LinuxInstanceLock::acquireDirectory(
    const QString& directory, QString& error)
{
    error.clear();
    const QByteArray encoded = QFile::encodeName(directory);
    struct stat info{};
    if (::getuid() != ::geteuid() || !QDir::isAbsolutePath(directory) ||
        QDir::cleanPath(directory) != directory ||
        QFileInfo(directory).canonicalFilePath() != directory ||
        ::lstat(encoded.constData(), &info) < 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != ::getuid() || (info.st_mode & 0777) != 0700) {
        error = QStringLiteral("Répertoire d'exécution non sûr (propriétaire, chemin ou permissions).");
        return {};
    }
    auto result = std::unique_ptr<LinuxInstanceLock>(new LinuxInstanceLock(directory));
    const QByteArray name = QFile::encodeName(result->fileName());
    if (!safeFile(name, true) || !safeFile(name + ".rmlock", true)) {
        error = QStringLiteral("État du verrou d'instance non sûr ou indéterminé.");
        return {};
    }
    if (!result->lock_.tryLock(0)) {
        error = QStringLiteral("PassWall est déjà actif, ou son verrou ne peut pas être établi sûrement.");
        return {};
    }
    if (!QFile::setPermissions(result->fileName(), QFile::ReadOwner | QFile::WriteOwner) ||
        !safeFile(name, false)) {
        error = QStringLiteral("Impossible de protéger le verrou d'instance.");
        return {};
    }
    // Qt warns but can continue if native flock fails. Verify that its actual
    // inode is locked; otherwise fail closed instead of trusting only a PID.
    const int probe = ::open(name.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (probe < 0) {
        error = QStringLiteral("Impossible de vérifier le verrou natif.");
        return {};
    }
    const int locked = ::flock(probe, LOCK_EX | LOCK_NB);
    const int probeError = errno;
    ::close(probe);
    if (locked == 0 || (probeError != EWOULDBLOCK && probeError != EAGAIN)) {
        error = QStringLiteral("Exclusion native du verrou non confirmée.");
        return {};
    }
    return result;
}

bool LinuxInstanceLock::prepareNativeBridgeSocket(QString& error) const
{
    error.clear();
    if (!isHeld()) {
        error = QStringLiteral("Verrou d'instance requis avant le socket natif.");
        return false;
    }
    const QByteArray path = QFile::encodeName(directory_ + QStringLiteral("/passwall-native-bridge.sock"));
    struct stat before{}, after{};
    if (::lstat(path.constData(), &before) < 0) {
        if (errno == ENOENT)
            return true;
    } else if (S_ISSOCK(before.st_mode) && before.st_uid == ::getuid() && before.st_nlink == 1) {
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        if (static_cast<std::size_t>(path.size()) < sizeof(address.sun_path)) {
            std::memcpy(address.sun_path, path.constData(), path.size() + 1);
            const int socket = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (socket >= 0) {
                const int connected = ::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address));
                const int failure = errno;
                ::close(socket);
                if (connected < 0 && failure == ECONNREFUSED &&
                    ::lstat(path.constData(), &after) == 0 &&
                    before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
                    ::unlink(path.constData()) == 0)
                    return true;
            }
        }
    }
    error = QStringLiteral("Socket natif existant : absence d'écouteur non confirmée, démarrage refusé.");
    return false;
}
} // namespace passwall::platform
