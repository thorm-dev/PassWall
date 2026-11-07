#include "fake_login1_backend.hpp"

#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QThread>

#include <functional>
#include <cerrno>
#include <limits>
#include <memory>
#include <type_traits>

namespace {
thread_local int failingPollFd = -1;
thread_local int failingPollError = 0;
}
extern "C" int __real_poll(pollfd*, nfds_t, int);
extern "C" int __wrap_poll(pollfd* fds, nfds_t count, int timeout)
{
    if (count == 1 && timeout == 0 && fds[0].fd == failingPollFd &&
        failingPollError != 0) {
        errno = std::exchange(failingPollError, 0);
        failingPollFd = -1;
        return -1;
    }
    return __real_poll(fds, count, timeout);
}

namespace {
using passwall::platform::InhibitorFd;
using passwall::platform::LinuxSessionMonitor;
using passwall::platform::Login1State;
using passwall::tests::FakeLogin1Backend;

static_assert(!std::is_copy_constructible_v<InhibitorFd>);
static_assert(std::is_nothrow_move_constructible_v<InhibitorFd>);

bool eventually(const std::function<bool()>& condition, int timeout = 250)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < timeout) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return condition();
}

class LinuxSessionMonitorTest : public ::testing::Test {
protected:
    FakeLogin1Backend* backend = nullptr;
    std::unique_ptr<LinuxSessionMonitor> monitor;
    bool unlocked = false;
    bool acknowledge = true;
    int cleanups = 0;
    std::function<void()> duringCleanup;

    void SetUp() override
    {
        auto fake = std::make_unique<FakeLogin1Backend>();
        backend = fake.get();
        monitor = std::make_unique<LinuxSessionMonitor>(std::move(fake));
        LinuxSessionMonitor* const owner = monitor.get();
        QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                         monitor.get(), [this, owner](bool available) {
            if (available)
                return; // NEVER set unlocked=true from readiness/resume.
            ++cleanups;
            if (duringCleanup)
                duringCleanup();
            unlocked = false;
            if (acknowledge)
                owner->acknowledgeLocked();
        }, Qt::DirectConnection);
    }
    void TearDown() override
    {
        duringCleanup = {};
        monitor.reset();
    }
    void ready()
    {
        monitor->start();
        ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
        ASSERT_FALSE(monitor->protectionAvailable());
        ASSERT_TRUE(backend->completeInhibit());
        ASSERT_FALSE(monitor->protectionAvailable());
        ASSERT_TRUE(backend->completeState());
        ASSERT_TRUE(monitor->protectionAvailable());
        ASSERT_TRUE(backend->inhibitorHeld(0));
        unlocked = true; // Model an explicit manual unlock, not a monitor action.
    }
    void reacquire()
    {
        ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
        ASSERT_TRUE(backend->completeInhibit());
        ASSERT_TRUE(backend->completeState());
        ASSERT_TRUE(monitor->protectionAvailable());
        EXPECT_FALSE(unlocked);
    }
};

TEST_F(LinuxSessionMonitorTest, SleepLocksBeforeReleasingTheDescriptor)
{
    ready();
    bool checked = false;
    duringCleanup = [&] {
        checked = true;
        EXPECT_TRUE(backend->inhibitorHeld(0));
        EXPECT_FALSE(monitor->protectionAvailable());
    };
    emit backend->prepareForSleep(true);
    EXPECT_TRUE(checked);
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_TRUE(backend->inhibitors.empty());
}

TEST_F(LinuxSessionMonitorTest, BrokenWriteFifoBeforeSnapshotNeverPublishesReady)
{
    int readySignals = 0;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     monitor.get(), [&](bool ready) {
        if (ready)
            ++readySignals;
    });
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_EQ(backend->snapshots.size(), 1);
    ASSERT_EQ(backend->writers.size(), 1);
    const int writer = backend->writers[0];
    ASSERT_EQ(::fcntl(writer, F_GETFL) & O_ACCMODE, O_WRONLY);
    struct stat status{};
    ASSERT_EQ(::fstat(writer, &status), 0);
    ASSERT_TRUE(S_ISFIFO(status.st_mode));
    pollfd descriptor{writer, 0, 0};
    ASSERT_EQ(::poll(&descriptor, 1, 0), 0);

    backend->breakPeer(0);
    ASSERT_EQ(::poll(&descriptor, 1, 0), 1);
    ASSERT_NE(descriptor.revents & POLLERR, 0);
    // No processEvents(): the periodic timer cannot rescue this publication.
    ASSERT_TRUE(backend->completeState(Login1State{false, false}));
    EXPECT_EQ(readySignals, 0);
    EXPECT_FALSE(monitor->protectionAvailable());
}

TEST_F(LinuxSessionMonitorTest, HealthyWriteFifoRemainsOperational)
{
    ready();
    EXPECT_TRUE(monitor->protectionIsOperational());
    for (int i = 0; i < 20; ++i)
        EXPECT_TRUE(monitor->protectionIsOperational());
    EXPECT_TRUE(unlocked);
    EXPECT_TRUE(backend->inhibitorHeld(0));
}

TEST_F(LinuxSessionMonitorTest, BrokenAtAcquisitionNeverRequestsSnapshot)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    backend->breakOnInhibit = true;
    ASSERT_TRUE(backend->completeInhibit());
    EXPECT_TRUE(backend->snapshots.empty());
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(monitor->protectionIsOperational());
}

TEST_F(LinuxSessionMonitorTest, FreshCheckDetectsLossWithoutWaitingForHealthTimer)
{
    ready();
    backend->breakPeer(0);
    // No event-loop turn and no timer timeout has run.
    EXPECT_FALSE(monitor->protectionIsOperational());
    monitor->invalidateProtection();
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(monitor->protectionIsOperational());
}

TEST_F(LinuxSessionMonitorTest, BrokenPendingSnapshotCannotReviveAfterInvalidationAndRecovery)
{
    int readySignals = 0;
    QObject observer;
    QObject::connect(monitor.get(), &LinuxSessionMonitor::protectionChanged,
                     &observer, [&](bool ready) { readySignals += ready ? 1 : 0; });
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit());
    backend->breakPeer(0);
    monitor->invalidateProtection();
    emit backend->availabilityChanged(false);
    emit backend->availabilityChanged(true);
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_EQ(backend->snapshots.size(), 2U);
    ASSERT_TRUE(backend->completeState()); // stale GetAll from broken FD
    EXPECT_EQ(readySignals, 0);
    EXPECT_FALSE(monitor->protectionAvailable());
    ASSERT_TRUE(backend->completeState()); // current GetAll, healthy new FD
    EXPECT_EQ(readySignals, 1);
    EXPECT_TRUE(monitor->protectionIsOperational());
    EXPECT_FALSE(unlocked);
    EXPECT_TRUE(backend->inhibitorHeld(1));
}

TEST(InhibitorFdTest, EmptyAndInvalidDescriptorsFailClosed)
{
    EXPECT_FALSE(InhibitorFd{}.operational());
    // Impossible FD number: POLLNVAL, without closing/reusing a borrowed FD.
    InhibitorFd invalid(std::numeric_limits<int>::max());
    EXPECT_TRUE(invalid.valid());
    EXPECT_FALSE(invalid.operational());
}

TEST(InhibitorFdTest, ReadSideHangupAlsoFailsClosed)
{
    int fds[2];
    ASSERT_EQ(::pipe2(fds, O_NONBLOCK | O_CLOEXEC), 0);
    InhibitorFd reader(fds[0]);
    InhibitorFd writer(fds[1]);
    ASSERT_TRUE(reader.operational());
    writer.reset();
    pollfd descriptor{reader.descriptor(), 0, 0};
    ASSERT_EQ(::poll(&descriptor, 1, 0), 1);
    ASSERT_NE(descriptor.revents & POLLHUP, 0);
    EXPECT_FALSE(reader.operational());
}

TEST(InhibitorFdTest, MovesPreserveLatchedFailureAndExclusiveOwnership)
{
    FakeLogin1Backend backend;
    InhibitorFd fd;
    backend.inhibit([&](InhibitorFd acquired) { fd = std::move(acquired); });
    ASSERT_TRUE(backend.completeInhibit());
    ASSERT_TRUE(fd.operational());
    failingPollFd = fd.descriptor();
    failingPollError = EIO;
    const bool operational = fd.operational();
    const bool consumed = failingPollError == 0;
    failingPollFd = -1;
    failingPollError = 0;
    ASSERT_TRUE(consumed);
    ASSERT_FALSE(operational);
    InhibitorFd moved(std::move(fd));
    EXPECT_FALSE(fd.valid());
    EXPECT_TRUE(moved.valid());
    EXPECT_FALSE(moved.operational());
    InhibitorFd assigned;
    assigned = std::move(moved);
    EXPECT_FALSE(moved.valid());
    EXPECT_TRUE(assigned.valid());
    EXPECT_FALSE(assigned.operational());
    EXPECT_TRUE(backend.inhibitorHeld(0));
    assigned.reset();
    EXPECT_FALSE(backend.inhibitorHeld(0));
}

class LinuxSessionMonitorPollErrorTest : public LinuxSessionMonitorTest,
                                        public ::testing::WithParamInterface<int> {};

TEST_P(LinuxSessionMonitorPollErrorTest, PollFailureLatchesUntilReacquisition)
{
    ready();
    failingPollFd = backend->writers[0];
    failingPollError = GetParam();
    const bool operational = monitor->protectionIsOperational();
    // Always clear injection before assertions or any possible early return.
    const bool consumed = failingPollError == 0;
    failingPollFd = -1;
    failingPollError = 0;
    EXPECT_TRUE(consumed);
    EXPECT_FALSE(operational);
    EXPECT_FALSE(monitor->protectionIsOperational()); // no transient regrant
    duringCleanup = [&] { EXPECT_TRUE(backend->inhibitorHeld(0)); };
    monitor->invalidateProtection();
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    duringCleanup = {};
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }, 1800));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_TRUE(backend->completeState());
    EXPECT_TRUE(monitor->protectionIsOperational());
    EXPECT_FALSE(unlocked);
}

INSTANTIATE_TEST_SUITE_P(SystemErrors, LinuxSessionMonitorPollErrorTest,
                        ::testing::Values(EINTR, EIO, ENOMEM));

TEST_F(LinuxSessionMonitorTest, ShutdownLocksBeforeReleasingTheDescriptor)
{
    ready();
    duringCleanup = [&] { EXPECT_TRUE(backend->inhibitorHeld(0)); };
    emit backend->prepareForShutdown(true);
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_FALSE(monitor->protectionAvailable());
}

TEST_F(LinuxSessionMonitorTest, RepeatedSignalsRemainLockedAndDoNotReacquire)
{
    ready();
    emit backend->prepareForSleep(true);
    emit backend->prepareForSleep(true);
    emit backend->prepareForShutdown(true);
    QCoreApplication::processEvents();
    EXPECT_FALSE(unlocked);
    EXPECT_TRUE(backend->inhibitors.empty());
    EXPECT_FALSE(backend->inhibitorHeld(0));
}

TEST_F(LinuxSessionMonitorTest, ResumeReacquiresButNeverUnlocks)
{
    ready();
    emit backend->prepareForSleep(true);
    emit backend->prepareForSleep(false);
    reacquire();
    EXPECT_TRUE(backend->inhibitorHeld(1));
}

TEST_F(LinuxSessionMonitorTest, ShutdownCancellationAlsoRequiresANewInhibitor)
{
    ready();
    emit backend->prepareForShutdown(true);
    emit backend->prepareForShutdown(false);
    reacquire();
}

TEST_F(LinuxSessionMonitorTest, ResumeWithoutObservedPreparationStillLocks)
{
    ready();
    emit backend->prepareForSleep(false);
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    reacquire();
}

TEST_F(LinuxSessionMonitorTest, BothTransitionsMustHaveFinished)
{
    ready();
    emit backend->prepareForSleep(true);
    emit backend->prepareForShutdown(true);
    emit backend->prepareForSleep(false);
    QCoreApplication::processEvents();
    EXPECT_TRUE(backend->inhibitors.empty());
    emit backend->prepareForShutdown(false);
    reacquire();
}

TEST_F(LinuxSessionMonitorTest, ServiceLossLocksAndRecoveryNeverUnlocks)
{
    ready();
    emit backend->availabilityChanged(false);
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    emit backend->availabilityChanged(true);
    reacquire();
}

TEST_F(LinuxSessionMonitorTest, InhibitorRefusalFailsClosedAndCanBeRetried)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit(false));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }, 1800));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_TRUE(backend->completeState());
    EXPECT_TRUE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
}

TEST_F(LinuxSessionMonitorTest, SnapshotFailureReleasesInhibitorAndFailsClosed)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_TRUE(backend->completeState(std::nullopt));
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_FALSE(monitor->protectionAvailable());
}

TEST_F(LinuxSessionMonitorTest, AlreadyPreparingSnapshotCannotAuthorizeUnlock)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_TRUE(backend->completeState(Login1State{true, false}));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(backend->inhibitorHeld(0));
    emit backend->prepareForSleep(false);
    reacquire();
}

TEST_F(LinuxSessionMonitorTest, LateInhibitorAfterPreparationIsClosed)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    emit backend->prepareForSleep(true);
    ASSERT_TRUE(backend->completeInhibit());
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_TRUE(backend->snapshots.empty());
    EXPECT_FALSE(monitor->protectionAvailable());
}

TEST_F(LinuxSessionMonitorTest, LateSnapshotCannotReviveAnInvalidatedAttempt)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    ASSERT_TRUE(backend->completeInhibit());
    emit backend->prepareForShutdown(true);
    ASSERT_TRUE(backend->completeState());
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_FALSE(monitor->protectionAvailable());
}

TEST_F(LinuxSessionMonitorTest, OldOwnerReplyCannotAuthorizeANewOwner)
{
    monitor->start();
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }));
    emit backend->availabilityChanged(false);
    emit backend->availabilityChanged(true);
    ASSERT_TRUE(backend->completeInhibit());
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_FALSE(monitor->protectionAvailable());
    reacquire();
}

TEST_F(LinuxSessionMonitorTest, DescriptorIsRetainedUntilExplicitCleanupAcknowledgement)
{
    ready();
    acknowledge = false;
    emit backend->prepareForSleep(true);
    EXPECT_FALSE(unlocked);
    EXPECT_TRUE(backend->inhibitorHeld(0));
    monitor->acknowledgeLocked();
    EXPECT_FALSE(backend->inhibitorHeld(0));
}

TEST_F(LinuxSessionMonitorTest, ReentrantPreparationCannotReleaseBeforeOuterCleanup)
{
    ready();
    bool checked = false;
    duringCleanup = [&] {
        if (checked)
            return;
        checked = true;
        emit backend->prepareForShutdown(true);
        EXPECT_TRUE(backend->inhibitorHeld(0));
    };
    emit backend->prepareForSleep(true);
    EXPECT_TRUE(checked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    EXPECT_FALSE(unlocked);
}

TEST_F(LinuxSessionMonitorTest, StopLocksBeforeReleaseAndDoesNotReacquire)
{
    ready();
    duringCleanup = [&] { EXPECT_TRUE(backend->inhibitorHeld(0)); };
    monitor->stop();
    EXPECT_FALSE(unlocked);
    EXPECT_FALSE(backend->inhibitorHeld(0));
    QCoreApplication::processEvents();
    EXPECT_TRUE(backend->inhibitors.empty());
    EXPECT_FALSE(monitor->protectionAvailable());
}

TEST_F(LinuxSessionMonitorTest, InhibitorPeerLossRevokesProtection)
{
    ready();
    ::close(backend->peers[0]);
    backend->peers[0] = -1;
    ASSERT_TRUE(eventually([&] { return !monitor->protectionAvailable(); }, 1800));
    EXPECT_FALSE(unlocked);
}

TEST_F(LinuxSessionMonitorTest, CannotReacquireWhileOuterCleanupIsStillPending)
{
    ready();
    acknowledge = false;
    emit backend->prepareForSleep(true);
    emit backend->prepareForSleep(false);
    QCoreApplication::processEvents();
    EXPECT_TRUE(backend->inhibitors.empty());
    EXPECT_TRUE(backend->inhibitorHeld(0));
    EXPECT_FALSE(monitor->protectionAvailable());
    acknowledge = true;
    monitor->acknowledgeLocked();
    EXPECT_FALSE(backend->inhibitorHeld(0));
    ASSERT_TRUE(eventually([&] { return !backend->inhibitors.empty(); }, 1800));
    ASSERT_TRUE(backend->completeInhibit());
    ASSERT_TRUE(backend->completeState());
    EXPECT_TRUE(monitor->protectionAvailable());
    EXPECT_FALSE(unlocked);
}
} // namespace
