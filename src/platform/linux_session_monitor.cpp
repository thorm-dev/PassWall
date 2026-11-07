#include "linux_session_monitor.hpp"

#include <QThread>

#include <exception>
#include <limits>
#include <utility>
#include <poll.h>
#include <unistd.h>

namespace passwall::platform {

InhibitorFd::~InhibitorFd() { reset(); }
InhibitorFd::InhibitorFd(InhibitorFd&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), failed_(std::exchange(other.failed_, false)) {}
InhibitorFd& InhibitorFd::operator=(InhibitorFd&& other) noexcept
{
    if (this != &other) {
        reset();
        fd_ = std::exchange(other.fd_, -1);
        failed_ = std::exchange(other.failed_, false);
    }
    return *this;
}
bool InhibitorFd::operational() const noexcept
{
    if (!valid() || failed_)
        return false;
    // logind returns the WRITE side of a FIFO. Loss of its reader sets
    // POLLERR (not just POLLHUP). events=0 ignores ordinary writability.
    pollfd descriptor{fd_, 0, 0};
    const int result = ::poll(&descriptor, 1, 0);
    failed_ = result < 0 ||
        (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL));
    return !failed_;
}
void InhibitorFd::reset() noexcept
{
    const int fd = std::exchange(fd_, -1);
    failed_ = false;
    if (fd >= 0)
        ::close(fd);
}

LinuxSessionMonitor::LinuxSessionMonitor(
    std::unique_ptr<Login1Backend> backend, QObject* parent)
    : QObject(parent), backend_(std::move(backend)), retry_(this), health_(this)
{
    Q_ASSERT(backend_ && backend_->thread() == thread());
    backend_->setParent(this);
    retry_.setSingleShot(true);
    health_.setInterval(1000);
    connect(&health_, &QTimer::timeout, this, [this]() {
        if (!inhibitor_.valid())
            return;
        if (!inhibitor_.operational())
            acquisitionFailed();
    });
    connect(&retry_, &QTimer::timeout, this, &LinuxSessionMonitor::requestProtection);
    connect(backend_.get(), &Login1Backend::availabilityChanged, this,
            [this](bool available) {
        if (!running_)
            return;
        invalidateAttempt();
        available_ = available;
        // A new service owner must be queried; never trust the previous state.
        sleeping_ = shuttingDown_ = false;
        revokeProtection();
        if (available_)
            retry_.start(0);
    });
    connect(backend_.get(), &Login1Backend::prepareForSleep, this,
            [this](bool active) { preparing(true, active); });
    connect(backend_.get(), &Login1Backend::prepareForShutdown, this,
            [this](bool active) { preparing(false, active); });
}

LinuxSessionMonitor::~LinuxSessionMonitor() { stop(); }

bool LinuxSessionMonitor::protectionIsOperational() const noexcept
{
    return QThread::currentThread() == thread() && running_ && available_ &&
        ready_ && !pending_ && !revoking_ && !awaitingCleanup_ &&
        !sleeping_ && !shuttingDown_ && inhibitor_.operational();
}

void LinuxSessionMonitor::invalidateProtection()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (running_)
        acquisitionFailed();
}

void LinuxSessionMonitor::invalidateAttempt()
{
    // Never let an old completion become current again, even after overflow.
    if (attempt_ == std::numeric_limits<quint64>::max())
        std::terminate();
    ++attempt_;
    pending_ = false;
    retry_.stop();
}

void LinuxSessionMonitor::revokeProtection()
{
    ready_ = false;
    // A nested event loop in a downstream callback must not release the FD
    // while the OUTER cleanup is still in progress.
    if (revoking_)
        return;
    awaitingCleanup_ = true;
    cleanupAcknowledged_ = false;
    revoking_ = true;
    try {
        emit protectionChanged(false);
    } catch (...) {
        // Continuing after incomplete cleanup would violate the FD contract.
        std::terminate();
    }
    revoking_ = false;
    if (cleanupAcknowledged_) {
        inhibitor_.reset();
        awaitingCleanup_ = false;
    }
}

void LinuxSessionMonitor::acknowledgeLocked()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (!awaitingCleanup_ || ready_)
        return;
    cleanupAcknowledged_ = true;
    if (!revoking_) {
        inhibitor_.reset();
        awaitingCleanup_ = false;
    }
}

void LinuxSessionMonitor::start()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (running_)
        return;
    running_ = true;
    health_.start();
    revokeProtection();
    backend_->start();
}

void LinuxSessionMonitor::stop()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (!running_)
        return;
    running_ = false;
    available_ = false;
    health_.stop();
    invalidateAttempt();
    revokeProtection();
    backend_->stop();
}

void LinuxSessionMonitor::preparing(bool sleep, bool active)
{
    if (!running_)
        return;
    invalidateAttempt();
    (sleep ? sleeping_ : shuttingDown_) = active;
    // Also lock on resume/cancellation: a missed true must not leave a usable
    // session. No notification, nested wait or DBus method call in this path.
    revokeProtection();
    if (!sleeping_ && !shuttingDown_ && available_)
        retry_.start(0);
}

void LinuxSessionMonitor::acquisitionFailed()
{
    invalidateAttempt();
    revokeProtection();
    if (running_ && available_ && !sleeping_ && !shuttingDown_)
        retry_.start(1000);
}

void LinuxSessionMonitor::requestProtection()
{
    if (!running_ || !available_ || ready_ || pending_ || sleeping_ || shuttingDown_)
        return;
    if (revoking_ || awaitingCleanup_) {
        retry_.start(1000);
        return;
    }
    invalidateAttempt();
    pending_ = true;
    const quint64 attempt = attempt_;
    backend_->inhibit([this, attempt](InhibitorFd fd) {
        if (!running_ || attempt != attempt_)
            return; // Exclusive FD is closed, including late successful replies.
        if (!fd.operational()) {
            acquisitionFailed();
            return;
        }
        inhibitor_ = std::move(fd);
        // Subscriptions precede Inhibit; the snapshot follows it. A true signal
        // at ANY point invalidates this attempt before it can authorize unlock.
        backend_->readState([this, attempt](std::optional<Login1State> state) {
            if (!running_ || attempt != attempt_)
                return;
            if (!state) {
                acquisitionFailed();
                return;
            }
            pending_ = false;
            sleeping_ = state->preparingForSleep;
            shuttingDown_ = state->preparingForShutdown;
            if (sleeping_ || shuttingDown_) {
                invalidateAttempt();
                revokeProtection();
                return;
            }
            // The peer may have disappeared while GetAll was pending.
            // Check immediately before publication, not at the next timer.
            if (!inhibitor_.operational()) {
                acquisitionFailed();
                return;
            }
            ready_ = true;
            emit protectionChanged(true);
        });
    });
}

} // namespace passwall::platform
