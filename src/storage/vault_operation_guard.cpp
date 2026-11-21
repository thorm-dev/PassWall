#include "storage/vault_operation_guard.hpp"

#include <QCryptographicHash>
#include <QByteArray>
#include <atomic>
#include <cerrno>
#include <filesystem>
#include <mutex>
#include <utility>
#ifdef __linux__
#include <fcntl.h>
#include <sys/eventfd.h>
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
std::once_flag releaseEventOnce;
std::atomic<int> releaseEvent{-1};

int initializeReleaseEvent() noexcept
{
    try {
        std::call_once(releaseEventOnce, [] {
            releaseEvent.store(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK),
                std::memory_order_release);
        });
    } catch (...) {
        return -1;
    }
    return releaseEvent.load(std::memory_order_acquire);
}

void notifyRelease() noexcept
{
    const int fd = releaseEvent.load(std::memory_order_acquire);
    if (fd < 0) return; // No coordinator subscribed in this process.
    const std::uint64_t value = 1;
    ssize_t written;
    do written = ::write(fd, &value, sizeof(value));
    while (written < 0 && errno == EINTR);
    static_cast<void>(written);
    // EAGAIN only means an earlier unread hint already guarantees a wake-up.
}
std::string digest(const std::string& value)
{
    return QCryptographicHash::hash(QByteArray::fromRawData(value.data(), value.size()),
                                   QCryptographicHash::Sha256).toHex().toStdString() + ".lock";
}

bool identity(const std::string& path, std::string& pathKey, std::string& fileKey,
              std::string& error, std::uint64_t* device = nullptr,
              std::uint64_t* inode = nullptr)
{
    if (device) *device = 0;
    if (inode) *inode = 0;
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
        if (device) *device = static_cast<std::uint64_t>(file.st_dev);
        if (inode) *inode = static_cast<std::uint64_t>(file.st_ino);
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
      snapshotHandle_(std::exchange(other.snapshotHandle_, -1)),
      pathKey_(std::move(other.pathKey_)), fileKey_(std::move(other.fileKey_)),
      snapshotKey_(std::move(other.snapshotKey_)),
      device_(std::exchange(other.device_, 0)), inode_(std::exchange(other.inode_, 0)),
      mode_(std::exchange(other.mode_, Mode::None)),
      attempted_(std::exchange(other.attempted_, false)),
      contended_(std::exchange(other.contended_, false)) {}
VaultOperationGuard& VaultOperationGuard::operator=(VaultOperationGuard&& other) noexcept
{
    if (this != &other) {
        reset();
        handles_ = std::exchange(other.handles_, {-1, -1});
        snapshotHandle_ = std::exchange(other.snapshotHandle_, -1);
        pathKey_ = std::move(other.pathKey_);
        fileKey_ = std::move(other.fileKey_);
        snapshotKey_ = std::move(other.snapshotKey_);
        device_ = std::exchange(other.device_, 0);
        inode_ = std::exchange(other.inode_, 0);
        mode_ = std::exchange(other.mode_, Mode::None);
        attempted_ = std::exchange(other.attempted_, false);
        contended_ = std::exchange(other.contended_, false);
    }
    return *this;
}
void VaultOperationGuard::reset() noexcept
{
    const bool released = mode_ != Mode::None;
#ifdef __linux__
    // Never LOCK_UN: an exec'd child may share this open file description.
    for (int fd : handles_) if (fd >= 0) ::close(fd);
    if (snapshotHandle_ >= 0) ::close(snapshotHandle_);
#endif
    handles_ = {-1, -1};
    snapshotHandle_ = -1;
    pathKey_.clear(); fileKey_.clear(); snapshotKey_.clear();
    device_ = 0; inode_ = 0;
    mode_ = Mode::None; attempted_ = false; contended_ = false;
#ifdef __linux__
    if (released) notifyRelease();
#else
    static_cast<void>(released);
#endif
}
int VaultOperationGuard::releaseNotificationDescriptor() noexcept
{
#ifdef __linux__
    return initializeReleaseEvent();
#else
    return -1;
#endif
}
void VaultOperationGuard::consumeReleaseNotifications() noexcept
{
#ifdef __linux__
    const int fd = releaseEvent.load(std::memory_order_acquire);
    if (fd < 0) return;
    std::uint64_t value = 0;
    ssize_t count;
    do count = ::read(fd, &value, sizeof(value));
    while (count < 0 && errno == EINTR);
    static_cast<void>(count);
#endif
}
bool VaultOperationGuard::acquire(const std::string& path, Mode mode, std::string& error)
{
    reset();
    attempted_ = true;
#ifdef __linux__
    const bool exclusive = mode == Mode::Exclusive;
    std::string pathKey, fileKey;
    std::uint64_t device = 0, inode = 0;
    if (!identity(path, pathKey, fileKey, error, &device, &inode)) return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0) return fail(error, "Synchronisation du coffre indisponible ; accès refusé.");
    VaultOperationGuard candidate;
    candidate.attempted_ = true;
    candidate.pathKey_ = pathKey; candidate.fileKey_ = fileKey;
    candidate.device_ = device; candidate.inode_ = inode;
    candidate.handles_[0] = lockFile(directory.value, pathKey, exclusive, contended_);
    if (candidate.handles_[0] < 0)
        return fail(error, "Coffre réservé par une opération incompatible, ou verrou indisponible.");
    if (!fileKey.empty()) {
        candidate.handles_[1] = lockFile(directory.value, fileKey, exclusive, contended_);
        if (candidate.handles_[1] < 0)
            return fail(error, "Fichier du coffre réservé par une opération incompatible.");
    }
    if (mode == Mode::Snapshot) {
        // The inode key serializes aliases of an existing source. A missing
        // source uses the stable pathname key and will later be refused by the
        // snapshot engine without creating a destination.
        candidate.snapshotKey_ = digest("snapshot:"
            + (fileKey.empty() ? pathKey : fileKey));
        candidate.snapshotHandle_ = lockFile(directory.value,
            candidate.snapshotKey_, true, contended_);
        if (candidate.snapshotHandle_ < 0)
            return fail(error, "Un instantané de ce coffre est déjà en cours.");
    }
    std::string currentPath, currentFile;
    if (!identity(path, currentPath, currentFile, error) || currentPath != pathKey || currentFile != fileKey)
        return fail(error, "Le coffre a changé pendant sa réservation.");
    candidate.mode_ = mode;
    *this = std::move(candidate);
    return true;
#else
    return fail(error, "Exclusion des opérations indisponible sur cette plateforme.");
#endif
}
bool VaultOperationGuard::tryAccess(const std::string& path, std::string& error)
{ return acquire(path, Mode::Access, error); }
bool VaultOperationGuard::trySnapshotAccess(const std::string& path, std::string& error)
{ return acquire(path, Mode::Snapshot, error); }
bool VaultOperationGuard::tryReserve(const std::string& path, std::string& error)
{ return acquire(path, Mode::Exclusive, error); }
std::array<int, 3> VaultOperationGuard::inheritedSnapshotHandles() const noexcept
{ return mode_ == Mode::Snapshot
    ? std::array<int, 3>{handles_[0], handles_[1], snapshotHandle_}
    : std::array<int, 3>{-1, -1, -1}; }
std::array<int, 2> VaultOperationGuard::inheritedHandles() const noexcept
{ return mode_ == Mode::Exclusive ? handles_ : std::array<int, 2>{-1, -1}; }
bool VaultOperationGuard::matchesAccess(const std::string& path, std::string& error) const
{
#ifdef __linux__
    std::string key, file;
    if (mode_ != Mode::Access || handles_[0] < 0
        || !identity(path, key, file, error) || key != pathKey_ || file != fileKey_)
        return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0) return false;
    for (unsigned i = 0; i < 2; ++i) {
        if (handles_[i] == -1) continue;
        struct stat expected {}, actual {};
        const auto& name = i == 0 ? pathKey_ : fileKey_;
        if (!safeLock(handles_[i]) || ::fstat(handles_[i], &actual) != 0
            || ::fstatat(directory.value, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
            || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
            || ::flock(handles_[i], LOCK_SH | LOCK_NB) != 0) return false;
    }
    return true;
#else
    Q_UNUSED(path); Q_UNUSED(error);
    return false;
#endif
}
bool VaultOperationGuard::matchesSnapshotAccess(const std::string& path, std::string& error) const
{
#ifdef __linux__
    std::string key, file;
    if (mode_ != Mode::Snapshot || handles_[0] < 0 || snapshotHandle_ < 0
        || !identity(path, key, file, error) || key != pathKey_ || file != fileKey_)
        return false;
    const auto expectedSnapshot = digest("snapshot:" + (file.empty() ? key : file));
    if (expectedSnapshot != snapshotKey_) return false;
    Descriptor directory{openNamespace()};
    if (directory.value < 0) return false;
    for (unsigned i = 0; i < 2; ++i) {
        if (handles_[i] == -1) continue;
        struct stat expected {}, actual {};
        const auto& name = i == 0 ? pathKey_ : fileKey_;
        if (!safeLock(handles_[i]) || ::fstat(handles_[i], &actual) != 0
            || ::fstatat(directory.value, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
            || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
            || ::flock(handles_[i], LOCK_SH | LOCK_NB) != 0) return false;
    }
    struct stat expected {}, actual {};
    return safeLock(snapshotHandle_) && ::fstat(snapshotHandle_, &actual) == 0
        && ::fstatat(directory.value, snapshotKey_.c_str(), &expected, AT_SYMLINK_NOFOLLOW) == 0
        && expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino
        && ::flock(snapshotHandle_, LOCK_EX | LOCK_NB) == 0;
#else
    return false;
#endif
}
bool VaultOperationGuard::matchesSnapshotIdentity(const std::string& path,
    std::uint64_t device, std::uint64_t inode, std::string& error) const
{
    if (!matchesSnapshotAccess(path, error)) return false;
    if (device == 0 || inode == 0 || device_ != device || inode_ != inode)
        return fail(error, "L’identité physique du coffre a changé ; demande de sauvegarde obsolète.");
    return true;
}
bool VaultOperationGuard::matchesReservation(const std::string& path, std::string& error) const
{
#ifdef __linux__
    std::string key, file;
    if (mode_ != Mode::Exclusive || handles_[0] < 0 || !identity(path, key, file, error)
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
bool VaultOperationGuard::adoptSnapshotAccess(const std::string& path,
    std::array<int, 3> handles, std::string& error)
{
    reset();
    attempted_ = true;
#ifdef __linux__
    if (handles[0] < 64 || handles[2] < 64
        || (handles[1] != -1 && handles[1] < 64)
        || handles[0] == handles[2] || handles[1] == handles[0]
        || handles[1] == handles[2])
        return fail(error, "Descripteurs d'instantané invalides.");
    handles_ = {handles[0], handles[1]};
    snapshotHandle_ = handles[2];
    if (!identity(path, pathKey_, fileKey_, error, &device_, &inode_)) return false;
    snapshotKey_ = digest("snapshot:" + (fileKey_.empty() ? pathKey_ : fileKey_));
    Descriptor directory{openNamespace()};
    if (directory.value < 0 || (fileKey_.empty() != (handles[1] == -1)))
        return fail(error, "Identité de l'instantané non confirmée.");
    for (unsigned i = 0; i < 2; ++i) {
        if (handles_[i] == -1) continue;
        const auto& name = i == 0 ? pathKey_ : fileKey_;
        struct stat expected {}, actual {};
        if (!safeLock(handles_[i]) || ::fstat(handles_[i], &actual) != 0
            || ::fstatat(directory.value, name.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
            || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
            || ::flock(handles_[i], LOCK_SH | LOCK_NB) != 0
            || ::fcntl(handles_[i], F_SETFD, FD_CLOEXEC) != 0)
            return fail(error, "Accès d'instantané hérité non valide.");
    }
    struct stat expected {}, actual {};
    if (!safeLock(snapshotHandle_) || ::fstat(snapshotHandle_, &actual) != 0
        || ::fstatat(directory.value, snapshotKey_.c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0
        || expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino
        || ::flock(snapshotHandle_, LOCK_EX | LOCK_NB) != 0
        || ::fcntl(snapshotHandle_, F_SETFD, FD_CLOEXEC) != 0)
        return fail(error, "Sérialisation d'instantané héritée non valide.");
    mode_ = Mode::Snapshot;
    return true;
#else
    return false;
#endif
}
bool VaultOperationGuard::adoptReservation(const std::string& path,
    std::array<int, 2> handles, std::string& error)
{
    reset();
    attempted_ = true;
#ifdef __linux__
    if (handles[0] < 64 || (handles[1] != -1 && (handles[1] < 64 || handles[0] == handles[1])))
        return fail(error, "Descripteurs de réservation invalides.");
    handles_ = handles; // Own after structural validation; no stdio/duplicate FD.
    if (!identity(path, pathKey_, fileKey_, error, &device_, &inode_)) return false;
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
    mode_ = Mode::Exclusive;
    return true;
#else
    return false;
#endif
}
bool VaultOperationGuard::ownsExclusiveLocks() const
{
#ifdef __linux__
    if (mode_ != Mode::Exclusive || handles_[0] < 0) return false;
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
