// Tester le demarrage reel sans rendre publiques les fonctions internes du
// Native Host. Les wrappers POSIX ne sont lies que dans cette cible de tests.
#define main passwallNativeHostMainForTesting
#include "../src/native/native_host.cpp"
#undef main

#include <gtest/gtest.h>

#include <cstdarg>
#include <sys/stat.h>

namespace {

enum class RedirectFailure {
    None,
    Open,
    Stdin,
    Stdout
};

class ProbePipe final {
public:
    ProbePipe() { valid_ = ::pipe(fds_) == 0; }
    ~ProbePipe()
    {
        if (valid_) {
            ::close(fds_[0]);
            closeWriter();
        }
    }

    ProbePipe(const ProbePipe&) = delete;
    ProbePipe& operator=(const ProbePipe&) = delete;

    bool valid() const { return valid_; }
    int reader() const { return fds_[0]; }
    int writer() const { return fds_[1]; }

    void closeWriter()
    {
        if (fds_[1] >= 0) {
            ::close(fds_[1]);
            fds_[1] = -1;
        }
    }

    std::string readAll() const
    {
        std::string result;
        char buffer[64];
        ssize_t count;
        while ((count = ::read(reader(), buffer, sizeof(buffer))) != 0) {
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                ADD_FAILURE() << "read failed: " << std::strerror(errno);
                break;
            }
            result.append(buffer, static_cast<std::size_t>(count));
        }
        return result;
    }

private:
    int fds_[2]{-1, -1};
    bool valid_ = false;
};

struct StartupProbe {
    RedirectFailure failure;
    const ProbePipe& events;
    const ProbePipe& output;
    int initiallyClosedFd;
    dev_t nullDevice;
    pid_t childPid = -1;
    bool inChild = false;
    int nullFd = -1;
};

StartupProbe* activeProbe = nullptr;

class ScopedStartupProbe final {
public:
    explicit ScopedStartupProbe(StartupProbe& probe) { activeProbe = &probe; }
    ~ScopedStartupProbe() { activeProbe = nullptr; }
};

void recordEvent(char event)
{
    ssize_t count;
    do {
        count = ::write(activeProbe->events.writer(), &event, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 1) {
        _exit(90);
    }
}

void checkLaunch(
    RedirectFailure failure,
    int expectedExitCode,
    const char* expectedEvents,
    int initiallyClosedFd = -1)
{
    ProbePipe events;
    ProbePipe output;
    ASSERT_TRUE(events.valid());
    ASSERT_TRUE(output.valid());

    struct stat nullStatus {};
    struct stat inputBefore {};
    struct stat outputBefore {};
    ASSERT_EQ(::stat("/dev/null", &nullStatus), 0);
    ASSERT_EQ(::fstat(STDIN_FILENO, &inputBefore), 0);
    ASSERT_EQ(::fstat(STDOUT_FILENO, &outputBefore), 0);
    const int inputFlags = ::fcntl(STDIN_FILENO, F_GETFD);
    const int outputFlags = ::fcntl(STDOUT_FILENO, F_GETFD);

    StartupProbe probe{
        failure, events, output, initiallyClosedFd, nullStatus.st_rdev};
    ScopedStartupProbe scopedProbe(probe);
    std::string error;
    ASSERT_TRUE(launchPassWall(error)) << error;
    ASSERT_GT(probe.childPid, 0);
    events.closeWriter();
    output.closeWriter();

    int status = 0;
    pid_t waited;
    do {
        waited = ::waitpid(probe.childPid, &status, 0);
    } while (waited < 0 && errno == EINTR);
    ASSERT_EQ(waited, probe.childPid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), expectedExitCode);
    EXPECT_EQ(events.readAll(), expectedEvents);
    EXPECT_TRUE(output.readAll().empty());

    // Le parent conserve les descripteurs du protocole et leurs attributs.
    struct stat inputAfter {};
    struct stat outputAfter {};
    ASSERT_EQ(::fstat(STDIN_FILENO, &inputAfter), 0);
    ASSERT_EQ(::fstat(STDOUT_FILENO, &outputAfter), 0);
    EXPECT_EQ(inputAfter.st_dev, inputBefore.st_dev);
    EXPECT_EQ(inputAfter.st_ino, inputBefore.st_ino);
    EXPECT_EQ(inputAfter.st_mode, inputBefore.st_mode);
    EXPECT_EQ(outputAfter.st_dev, outputBefore.st_dev);
    EXPECT_EQ(outputAfter.st_ino, outputBefore.st_ino);
    EXPECT_EQ(outputAfter.st_mode, outputBefore.st_mode);
    EXPECT_EQ(::fcntl(STDIN_FILENO, F_GETFD), inputFlags);
    EXPECT_EQ(::fcntl(STDOUT_FILENO, F_GETFD), outputFlags);
}

} // namespace

extern "C" {

int __real_open(const char* path, int flags, ...);
int __real_dup2(int oldFd, int newFd);
int __real_access(const char* path, int mode);
pid_t __real_fork();

int __wrap_open(const char* path, int flags, ...)
{
    if (activeProbe != nullptr && activeProbe->inChild &&
        std::strcmp(path, "/dev/null") == 0) {
        recordEvent('O');
        if (activeProbe->failure == RedirectFailure::Open) {
            errno = EACCES;
            return -1;
        }
        activeProbe->nullFd = __real_open(path, flags);
        return activeProbe->nullFd;
    }

    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        const mode_t mode = va_arg(arguments, mode_t);
        va_end(arguments);
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

int __wrap_dup2(int oldFd, int newFd)
{
    if (activeProbe != nullptr && activeProbe->inChild) {
        recordEvent(newFd == STDIN_FILENO ? 'I' : 'U');
        if ((newFd == STDIN_FILENO &&
             activeProbe->failure == RedirectFailure::Stdin) ||
            (newFd == STDOUT_FILENO &&
             activeProbe->failure == RedirectFailure::Stdout)) {
            errno = EBADF;
            return -1;
        }
    }
    return __real_dup2(oldFd, newFd);
}

int __wrap_access(const char* path, int mode)
{
    // Le faux execl ci-dessous n'a besoin d'aucun passwall_app installe.
    if (activeProbe != nullptr && mode == X_OK) {
        return 0;
    }
    return __real_access(path, mode);
}

pid_t __wrap_fork()
{
    const pid_t pid = __real_fork();
    if (activeProbe != nullptr) {
        if (pid == 0) {
            activeProbe->inChild = true;
            ::close(activeProbe->events.reader());
            ::close(activeProbe->output.reader());
            if (__real_dup2(activeProbe->output.writer(), STDOUT_FILENO) < 0) {
                _exit(91);
            }
            ::close(activeProbe->output.writer());
            if (activeProbe->initiallyClosedFd >= 0) {
                ::close(activeProbe->initiallyClosedFd);
            }
        } else {
            activeProbe->childPid = pid;
        }
    }
    return pid;
}

int __wrap_execl(const char*, const char*, ...)
{
    // Ne jamais demarrer Qt : verifier les descripteurs au point de lancement.
    if (activeProbe == nullptr || !activeProbe->inChild) {
        _exit(92);
    }
    recordEvent('E');
    struct stat input {};
    struct stat output {};
    const bool redirected =
        ::fstat(STDIN_FILENO, &input) == 0 &&
        ::fstat(STDOUT_FILENO, &output) == 0 &&
        S_ISCHR(input.st_mode) && S_ISCHR(output.st_mode) &&
        input.st_rdev == activeProbe->nullDevice &&
        output.st_rdev == activeProbe->nullDevice;
    const bool extraFdClosed = activeProbe->nullFd <= STDERR_FILENO ||
        (::fcntl(activeProbe->nullFd, F_GETFD) == -1 && errno == EBADF);
    constexpr char marker[] = "unexpected-application-stdout";
    const bool wrote = ::write(STDOUT_FILENO, marker, sizeof(marker)) ==
        static_cast<ssize_t>(sizeof(marker));
    _exit(redirected && extraFdClosed && wrote ? 0 : 93);
}

} // extern "C"

TEST(NativeHostStartupTest, OpenFailureStopsBeforeDuplicationAndExec)
{
    checkLaunch(RedirectFailure::Open, 126, "O");
}

TEST(NativeHostStartupTest, StdinDuplicationFailureStopsBeforeExec)
{
    checkLaunch(RedirectFailure::Stdin, 126, "OI");
}

TEST(NativeHostStartupTest, StdoutDuplicationFailureStopsBeforeExec)
{
    checkLaunch(RedirectFailure::Stdout, 126, "OIU");
}

TEST(NativeHostStartupTest, RedirectsBothStreamsAndClosesExtraFdBeforeExec)
{
    checkLaunch(RedirectFailure::None, 0, "OIUE");
}

TEST(NativeHostStartupTest, KeepsDevNullOpenWhenItReusesStdin)
{
    checkLaunch(RedirectFailure::None, 0, "OIUE", STDIN_FILENO);
}

TEST(NativeHostStartupTest, KeepsDevNullOpenWhenItReusesStdout)
{
    checkLaunch(RedirectFailure::None, 0, "OIUE", STDOUT_FILENO);
}
