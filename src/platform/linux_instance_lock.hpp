#pragma once

#include <QLockFile>
#include <QString>
#include <memory>

namespace passwall::platform {

// Linux only. Construct BEFORE QApplication/services, destroy AFTER them.
// Cooperative per-UID exclusion, independent of the display and session bus.
// Never use age to evict a long-lived lock; QLockFile recovers a dead PID with
// its native flock-protected stale-file removal. Uncertain files fail closed.
class LinuxInstanceLock final {
public:
    static std::unique_ptr<LinuxInstanceLock> acquire(QString& error);
    // Isolated process tests only: never point a test at the user's runtime dir.
    static std::unique_ptr<LinuxInstanceLock> acquireInDirectoryForTesting(
        const QString& runtimeDirectory, QString& error);
    ~LinuxInstanceLock();
    LinuxInstanceLock(const LinuxInstanceLock&) = delete;
    LinuxInstanceLock& operator=(const LinuxInstanceLock&) = delete;
    [[nodiscard]] bool isHeld() const noexcept;
    [[nodiscard]] QString fileName() const;
    // Called ONLY by the admitted application, before creating its bridge.
    // Recover a crash-left socket only when owned, unchanged and ECONNREFUSED.
    bool prepareNativeBridgeSocket(QString& error) const;
private:
    explicit LinuxInstanceLock(QString runtimeDirectory);
    static std::unique_ptr<LinuxInstanceLock> acquireDirectory(
        const QString& runtimeDirectory, QString& error);
    QString directory_;
    QLockFile lock_;
};

} // namespace passwall::platform
