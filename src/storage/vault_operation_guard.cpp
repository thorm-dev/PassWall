#include "storage/vault_operation_guard.hpp"

#include <QCryptographicHash>
#include <QByteArray>
#include <cerrno>
#include <filesystem>
#include <utility>
#ifdef __linux__
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace passwall::storage {
namespace {
bool fail(std::string& error, const char* message)
{
    error = message;
    return false;
}
#ifdef __linux__
struct Descriptor {
    int value = -1;
    ~Descriptor() noexcept { if (value >= 0) ::close(value); }
};
std::string digest(const std::string& value)
{
    return QCryptographicHash::hash(QByteArray::fromRawData(value.data(), value.size()),
                                   QCryptographicHash::Sha256).toHex().toStdString() + ".lock";
}

bool identity(const std::string& path, std::string& pathKey, std::string& fileKey,
              std::string& error)
{
    if (path.empty() || path.find('\0') != std::string::npos)
        return fail(error, "Chemin de coffre invalide pour la réservation.");
    for (const auto& part : std::filesystem::path(path))
        if (part == "..")
            return fail(error, "Composante de chemin ambiguë refusée.");
    std::error_code ec;
    const auto absolute = std::filesystem::absolute(path, ec).lexically_normal();
    if (ec || absolute.filename().empty())
        return fail(error, "Chemin du coffre impossible à identifier.");
    Descriptor directory{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    for (const auto& part : absolute.parent_path().relative_path()) {
        if (directory.value < 0) break;
        const int next = ::openat(directory.value, part.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ::close(directory.value);
        directory.value = next;
    }
    if (directory.value < 0)
        return fail(error, "Chemin du coffre inaccessible ou lien symbolique refusé.");
    struct stat file {};
    fileKey.clear();
    if (::fstatat(directory.value, absolute.filename().c_str(), &file, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(file.st_mode) || file.st_nlink < 1 || file.st_uid != ::geteuid())
            return fail(error, "Identité du coffre non sûre ou ambiguë.");
        fileKey = digest("inode:" + std::to_string(file.st_dev) + ':' + std::to_string(file.st_ino));
    } else if (errno != ENOENT) {
        return fail(error, "Identité du coffre impossible à vérifier.");
    }
    struct stat parent {};
    if (::fstat(directory.value, &parent) != 0)
        return fail(error, "Identité du dossier du coffre indisponible.");
    // Parent-directory identity + basename survives replacement of the SQLite
    // inode AND recognizes alternate mount paths of that same directory. The
    // second key catches renaming the source file. Never just path/vault_id.
    pathKey = digest("name:" + std::to_string(parent.st_dev) + ':'
        + std::to_string(parent.st_ino) + ':' + absolute.filename().string());
    return true;
}

int openNamespace()
{
    // Fixed per-UID namespace, never TMPDIR/an environment-selected alternative.
    // Synchronization resources only, not another preferences file. Lock files
    // are intentionally NOT unlinked: that would allow split flock namespaces.
    Descriptor temporary{::open("/tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (temporary.value < 0) return -1;
    const auto name = ".passwall-vault-operations-" + std::to_string(::geteuid());
    if (::mkdirat(temporary.value, name.c_str(), 0700) != 0 && errno != EEXIST) return -1;
    const int fd = ::openat(temporary.value, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info {};
    if (fd < 0) return -1;
    if (::fstat(fd, &info) != 0 || info.st_uid != ::geteuid() || (info.st_mode & 0777) != 0700) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool safeLock(int fd)
{
    struct stat info {};
    return fd >= 0 && ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode)
        && info.st_uid == ::geteuid() && info.st_nlink == 1
        && (info.st_mode & 0777) == 0600 && info.st_size == 0;
}

int lockFile(int directory, const std::string& key, bool exclusive, bool& contended)
{
    Descriptor fd{::openat(directory, key.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600)};
    if (!safeLock(fd.value)) return -1;
    if (::flock(fd.value, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0) {
        contended = errno == EWOULDBLOCK || errno == EAGAIN;
        return -1;
    }
    // High descriptors avoid collisions with QProcess's standard/exec pipes.
    // All are CLOEXEC until the precise child modifier explicitly transfers them.
    return ::fcntl(fd.value, F_DUPFD_CLOEXEC, 64);
}
#endif
} // namespace

VaultOperationGuard::~VaultOperationGuard() noexcept { reset(); }
VaultOperationGuard::VaultOperationGuard(VaultOperationGuard&& other) noexcept
    : handles_(std::exchange(other.handles_, {-1, -1})),
      pathKey_(std::move(other.pathKey_)), fileKey_(std::move(other.fileKey_)),
      exclusive_(std::exchange(other.exclusive_, false)),
      contended_(std::exchange(other.contended_, false)) {}
VaultOperationGuard& VaultOperationGuard::operator=(VaultOperationGuard&& other) noexcept
{
    if (this != &other) {
        reset();
        handles_ = std::exchange(other.handles_, {-1, -1});
        pathKey_ = std::move(other.pathKey_);
        fileKey_ = std::move(other.fileKey_);
        exclusive_ = std::exchange(other.exclusive_, false);
        contended_ = std::exchange(other.contended_, false);
    }
    return *this;
}
void VaultOperationGuard::reset() noexcept
{
#ifdef __linux__
    // Never LOCK_UN: an exec'd child may share this open file description.
    for (int fd : handles_) if (fd >= 0) ::close(fd);
#endif
    handles_ = {-1, -1};
    pathKey_.clear(); fileKey_.clear(); exclusive_ = false; contended_ = false;
}
bool VaultOperationGuard::acquire(const std::string& path, bool exclusive, std::string& error)
{
    reset();
#ifdef __linux__
    std::string pathKey, fileKey;
    if (!identity(path, pathKey, fileKey, error)) return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0) return fail(error, "Synchronisation du coffre indisponible ; accès refusé.");
    VaultOperationGuard candidate;
    candidate.pathKey_ = pathKey; candidate.fileKey_ = fileKey;
    candidate.handles_[0] = lockFile(directory.value, pathKey, exclusive, contended_);
    if (candidate.handles_[0] < 0)
        return fail(error, "Coffre réservé par une opération incompatible, ou verrou indisponible.");
    if (!fileKey.empty()) {
        candidate.handles_[1] = lockFile(directory.value, fileKey, exclusive, contended_);
        if (candidate.handles_[1] < 0)
            return fail(error, "Fichier du coffre réservé par une opération incompatible.");
    }
    std::string currentPath, currentFile;
    if (!identity(path, currentPath, currentFile, error) || currentPath != pathKey || currentFile != fileKey)
        return fail(error, "Le coffre a changé pendant sa réservation.");
    candidate.exclusive_ = exclusive;
    *this = std::move(candidate);
    return true;
#else
    return fail(error, "Exclusion des opérations indisponible sur cette plateforme.");
#endif
}
bool VaultOperationGuard::tryAccess(const std::string& path, std::string& error)
{ return acquire(path, false, error); }
bool VaultOperationGuard::tryReserve(const std::string& path, std::string& error)
{ return acquire(path, true, error); }
std::array<int, 2> VaultOperationGuard::inheritedHandles() const noexcept
{ return exclusive_ ? handles_ : std::array<int, 2>{-1, -1}; }
bool VaultOperationGuard::matchesReservation(const std::string& path, std::string& error) const
{
#ifdef __linux__
    std::string key, file;
    if (!exclusive_ || handles_[0] < 0 || !identity(path, key, file, error)
        || key != pathKey_ || file != fileKey_) return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0) return false;
    for (unsigned i = 0; i < 2; ++i) {
        if (handles_[i] == -1) continue;
        struct stat expected {}, actual {};
        const auto& name = i == 0 ? pathKey_ : fileKey_;
        if (!safeLock(handles_[i]) || ::fstat(handles_[i], &actual) != 0
            || ::fstatat(directory.value, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
            || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
            || ::flock(handles_[i], LOCK_EX | LOCK_NB) != 0) return false;
    }
    return true;
#else
    return false;
#endif
}
bool VaultOperationGuard::adoptReservation(const std::string& path,
    std::array<int, 2> handles, std::string& error)
{
    reset();
#ifdef __linux__
    if (handles[0] < 64 || (handles[1] != -1 && (handles[1] < 64 || handles[0] == handles[1])))
        return fail(error, "Descripteurs de réservation invalides.");
    handles_ = handles; // Own after structural validation; no stdio/duplicate FD.
    if (!identity(path, pathKey_, fileKey_, error)) return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0 || (fileKey_.empty() != (handles[1] == -1)))
        return fail(error, "Identité de la réservation non confirmée.");
    for (unsigned i = 0; i < 2; ++i) {
        if (handles[i] == -1) continue;
        const auto& name = i == 0 ? pathKey_ : fileKey_;
        struct stat expected {}, actual {};
        if (!safeLock(handles[i]) || ::fstat(handles[i], &actual) != 0
            || ::fstatat(directory.value, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
            || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
            || ::flock(handles[i], LOCK_EX | LOCK_NB) != 0
            || ::fcntl(handles[i], F_SETFD, FD_CLOEXEC) != 0)
            return fail(error, "Réservation héritée non valide.");
    }
    exclusive_ = true;
    return true;
#else
    return false;
#endif
}
bool VaultOperationGuard::ownsExclusiveLocks() const
{
#ifdef __linux__
    if (!exclusive_ || handles_[0] < 0) return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0) return false;
    for (unsigned i = 0; i < 2; ++i) {
        if (handles_[i] < 0) continue;
        const auto& name = i == 0 ? pathKey_ : fileKey_;
        struct stat expected {}, actual {};
        if (!safeLock(handles_[i]) || ::fstat(handles_[i], &actual) != 0
            || ::fstatat(directory.value, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
            || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
            || ::flock(handles_[i], LOCK_EX | LOCK_NB) != 0) return false;
    }
    return true;
#else
    return false;
#endif
}
bool VaultOperationGuard::matchesReplacement(const std::string& path,
    const VaultOperationGuard& candidate, std::string& error) const
{
#ifdef __linux__
    std::string name, file;
    return ownsExclusiveLocks() && candidate.ownsExclusiveLocks()
        && identity(path, name, file, error) && name == pathKey_
        && !file.empty() && file == candidate.fileKey_;
#else
    return false;
#endif
}
} // namespace passwall::storage
