#pragma once

// Linux-only: this header and its implementation are excluded on other systems.
#include <QObject>
#include <QTimer>

#include <functional>
#include <memory>
#include <optional>

namespace passwall::platform {

// Exclusive ownership, including for stale asynchronous replies. Never retry
// close() after EINTR on Linux: the descriptor may already have been reused.
class InhibitorFd final {
public:
    explicit InhibitorFd(int fd = -1) noexcept : fd_(fd) {}
    ~InhibitorFd();
    InhibitorFd(const InhibitorFd&) = delete;
    InhibitorFd& operator=(const InhibitorFd&) = delete;
    InhibitorFd(InhibitorFd&& other) noexcept;
    InhibitorFd& operator=(InhibitorFd&& other) noexcept;
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    // A number alone is not proof that logind still holds the FIFO's peer.
    // Owner thread only. Nonblocking, no I/O or DBus call; any poll error
    // latches failure until reset/reacquisition, including transient EINTR.
    [[nodiscard]] bool operational() const noexcept;
    [[nodiscard]] int descriptor() const noexcept { return fd_; } // borrowed
    void reset() noexcept;
private:
    int fd_;
    mutable bool failed_ = false;
};

struct Login1State {
    bool preparingForSleep = false;
    bool preparingForShutdown = false;
};

// Injectable asynchronous transport. All methods, signals and completions run
// on the owner's Qt thread. stop()/destruction cancel outstanding completions.
// An empty result means failure (including access denied, timeout or bad data).
class Login1Backend : public QObject {
    Q_OBJECT
public:
    using InhibitResult = std::function<void(InhibitorFd)>;
    using StateResult = std::function<void(std::optional<Login1State>)>;
    using QObject::QObject;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void inhibit(InhibitResult completion) = 0;
    virtual void readState(StateResult completion) = 0;
signals:
    void availabilityChanged(bool available);
    void prepareForSleep(bool active);
    void prepareForShutdown(bool active);
};

class LinuxSessionMonitor final : public QObject {
    Q_OBJECT
public:
    explicit LinuxSessionMonitor(std::unique_ptr<Login1Backend> backend,
                                 QObject* parent = nullptr);
    ~LinuxSessionMonitor() override;
    void start();
    void stop();
    // Called synchronously by the vault owner AFTER all lock cleanup. Needed
    // when a system event reenters a manual lock already in progress.
    void acknowledgeLocked();
    [[nodiscard]] bool protectionAvailable() const noexcept { return ready_; }
    // Fresh check on the owner thread, without signals or cleanup (failures
    // latch in the FD). Cached readiness alone must never authorize access.
    [[nodiscard]] bool protectionIsOperational() const noexcept;
    // Report a failed check AFTER local secrets have been wiped. This revokes
    // the attempt and waits for synchronous vault cleanup before closing FD.
    void invalidateProtection();
signals:
    // MUST be connected directly to synchronous lock/cleanup on the SAME
    // thread before start(). false requires acknowledgeLocked() after cleanup,
    // even when already unavailable. true only allows a NEW manual unlock.
    void protectionChanged(bool available);
private:
    void revokeProtection();
    void invalidateAttempt();
    void requestProtection();
    void acquisitionFailed();
    void preparing(bool sleep, bool active);

    std::unique_ptr<Login1Backend> backend_;
    QTimer retry_;
    QTimer health_;
    InhibitorFd inhibitor_;
    quint64 attempt_ = 0;
    bool running_ = false;
    bool available_ = false;
    bool ready_ = false;
    bool pending_ = false;
    bool revoking_ = false;
    bool awaitingCleanup_ = false;
    bool cleanupAcknowledged_ = false;
    bool sleeping_ = false;
    bool shuttingDown_ = false;
};

// System bus / org.freedesktop.login1, no widgets or vault dependencies.
// Empty address selects the SYSTEM bus. An explicit address supports an
// isolated simulated service in tests, never a different production service.
[[nodiscard]] std::unique_ptr<Login1Backend> makeLogindDBusBackend(
    const QString& busAddress = {});

} // namespace passwall::platform
