// Isolated child-side linker injections: exercise the REAL worker/engine IPC.
// Test barriers are bounded and use only files in a private fictitious directory.
#include <sqlite3.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <map>
#include <csignal>
#include <cstdio>
#include <poll.h>

namespace {
std::string source;
bool paused = false, linked = false;
std::string rotationMode, rotationDirectory;
bool rotationUnlinked = false;
bool rotationCheckpointPassed = false;
std::map<std::string, int> bindings;
std::string readSmall(const std::string& path)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return {};
    char bytes[256]; const auto n = ::read(fd, bytes, sizeof(bytes)); ::close(fd);
    return n > 0 ? std::string(bytes, n) : std::string();
}
bool rotationTarget(int fd, const char* name)
{
    char descriptor[64], path[4096];
    std::snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    const auto n = ::readlink(descriptor, path, sizeof(path));
    if (n <= 0) return false;
    const std::string directory(path, n);
    if (readSmall(directory + "/.rotation-target") != name) return false;
    rotationDirectory = directory; rotationMode = readSmall(directory + "/.rotation-fault");
    return !rotationMode.empty();
}
void rotationMarker(const char* suffix)
{
    const auto marker = rotationDirectory + suffix;
    const int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || ::close(fd) != 0) ::_exit(90);
}
void waitForRotationMarker(const char* suffix)
{
    const auto path = rotationDirectory + suffix;
    for (int attempt = 0; attempt < 5000; ++attempt) {
        if (::access(path.c_str(), F_OK) == 0) return;
        ::usleep(1000); // Poll a condition, not a delay used to order cancellation.
    }
    ::_exit(91); // A missing handshake is a failed probe, never success.
}
void cancellationReadable()
{
    struct pollfd input{STDIN_FILENO, POLLIN, 0};
    int ready;
    do { ready = ::poll(&input, 1, 5000); } while (ready < 0 && errno == EINTR);
    if (ready != 1 || !(input.revents & POLLIN)) ::_exit(92);
    // Readability proves delivery to the pipe, NOT reception/acceptance.
    rotationMarker("/.rotation-cancel-readable");
}
void rotationBarrier()
{
    rotationMarker("/.rotation-checkpoint");
    if (rotationMode == "cancel") cancellationReadable();
    if (rotationMode == "cancel" || rotationMode == "queued-cancel") {
        waitForRotationMarker("/.rotation-resume");
        rotationCheckpointPassed = true;
        return;
    }
    if (rotationMode == "ignore") ::signal(SIGTERM, SIG_IGN);
    while (::access((rotationDirectory + "/.rotation-resume").c_str(), F_OK) != 0) ::usleep(1000);
}
bool mode(const char* suffix) { return source.ends_with(suffix); }
void barrier()
{
    const auto marker = source + ".checkpoint";
    const int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) ::close(fd);
    const auto resume = source + ".resume";
    for (int attempt = 0; attempt < 5000 && ::access(resume.c_str(), F_OK) != 0; ++attempt)
        ::usleep(1000);
}
}
extern "C" ssize_t __real_read(int, void*, size_t);
extern "C" ssize_t __wrap_read(int fd, void* buffer, size_t size)
{
    const auto count = __real_read(fd, buffer, size);
    const int saved = errno;
    if (fd == STDIN_FILENO && rotationCheckpointPassed) {
        if (rotationMode == "queued-cancel" && !rotationUnlinked
            && count == -1 && (saved == EAGAIN || saved == EWOULDBLOCK)) {
            // Observe the real production cancellation check, without changing
            // its return value or consuming a byte on the worker's behalf.
            rotationMarker("/.rotation-cancel-not-received");
        }
        if (count == 1 && *static_cast<const char*>(buffer) == '!'
            && (rotationMode == "cancel" || rotationMode == "queued-cancel")) {
            rotationMarker("/.rotation-cancel-received");
            // The byte was actually read. ParentChannel has not yet received
            // this return value; only the terminal result proves acceptance.
            waitForRotationMarker("/.rotation-accept-cancel");
            rotationCheckpointPassed = false;
        }
    }
    errno = saved;
    return count;
}
extern "C" int __real_sqlite3_open_v2(const char*, sqlite3**, int, const char*);
extern "C" int __wrap_sqlite3_open_v2(const char* path, sqlite3** db, int flags, const char* vfs)
{
    if (source.empty()) source = path;
    return __real_sqlite3_open_v2(path, db, flags, vfs);
}
extern "C" int __real_sqlite3_backup_step(sqlite3_backup*, int);
extern "C" int __wrap_sqlite3_backup_step(sqlite3_backup* backup, int pages)
{
    const int code = __real_sqlite3_backup_step(backup, pages);
    if (!paused && mode("during.pwdb")) { paused = true; barrier(); }
    return code;
}
extern "C" int __real_linkat(int, const char*, int, const char*, int);
extern "C" int __wrap_linkat(int from, const char* oldName, int to, const char* name, int flags)
{
    const int code = __real_linkat(from, oldName, to, name, flags);
    if (code == 0) {
        linked = true;
        char descriptor[64], path[4096];
        std::snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", to);
        const auto n = ::readlink(descriptor, path, sizeof(path));
        if (n > 0 && readSmall(std::string(path, n) + "/.publication-swap") == "swap") {
            (void)::unlinkat(to, name, 0);
            const int replacement = ::openat(to, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (replacement >= 0) { (void)::write(replacement, "unknown", 7); ::close(replacement); }
        }
        if (mode("after.pwdb")) barrier();
        if (mode("crash.pwdb")) ::_exit(7);
    }
    return code;
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    struct stat status{};
    if (rotationMode == "mark" && ::fstat(fd, &status) == 0 && S_ISREG(status.st_mode)) {
        errno = EIO; return -1;
    }
    if (rotationUnlinked && ((rotationMode == "sync" && ::fstat(fd, &status) == 0 && S_ISDIR(status.st_mode))
        || (rotationMode == "catalogue" && ::fstat(fd, &status) == 0 && S_ISREG(status.st_mode)))) {
        errno = EIO; return -1;
    }
    if (linked && mode("durability.pwdb") && ::fstat(fd, &status) == 0 && S_ISDIR(status.st_mode)) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
extern "C" int __real_fstatat(int, const char*, struct stat*, int);
extern "C" int __wrap_fstatat(int fd, const char* name, struct stat* output, int flags)
{
    // Two identity checks in tryReserve(), one after hashing, then the FINAL
    // name binding just before unlink. Inject only at that fourth check.
    if (rotationTarget(fd, name) && ++bindings[name] == 4) {
        if (rotationMode == "pause" || rotationMode == "ignore"
            || rotationMode == "cancel" || rotationMode == "queued-cancel") rotationBarrier();
        if (rotationMode == "swap") {
            (void)::renameat(fd, name, fd, (std::string(name) + ".preserved").c_str());
            const int replacement = ::openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (replacement >= 0) { (void)::write(replacement, "unknown", 7); ::close(replacement); }
        }
    }
    return __real_fstatat(fd, name, output, flags);
}
extern "C" int __real_unlinkat(int, const char*, int);
extern "C" int __wrap_unlinkat(int fd, const char* name, int flags)
{
    const bool target = rotationTarget(fd, name);
    if (target && rotationMode == "unlink") { errno = EACCES; return -1; }
    const int code = __real_unlinkat(fd, name, flags);
    if (target && code == 0) {
        rotationUnlinked = true;
        if (rotationMode == "queued-cancel") {
            rotationMarker("/.rotation-deleted");
            cancellationReadable();
            waitForRotationMarker("/.rotation-return-unlink");
        }
        if (rotationMode == "crash") ::_exit(8);
    }
    return code;
}
