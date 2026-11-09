#pragma once

#include "services/backup_protocol.hpp"
#include <QObject>
#include <QPointer>
#include "storage/vault_operation_guard.hpp"
#include <functional>

namespace passwall::services {
class BackupProcessSession;

// Single-use asynchronous Qt Core driver. All methods/destruction on its owner
// thread, with a running Qt event loop. No GUI, keys, or auto-retry. The caller
// authorizes both paths. No PATH search: default executable is an app sibling;
// the explicit constructor accepts an absolute trusted deployment/test path.
// Destroying the driver requests cancellation without waiting. While the event
// loop lives, its independent supervisor escalates/reaps. On aboutToQuit it sends
// SIGKILL without waiting; parent exit also closes IPC and triggers worker stop.
// Forced termination may leave private staging. No final file is ever removed.
class BackupJob final : public QObject {
    Q_OBJECT
public:
    explicit BackupJob(QObject* parent = nullptr);
    explicit BackupJob(QString workerPath, QObject* parent = nullptr);
    ~BackupJob() override;
    bool start(const QString& source, const QString& destination);
    // Finalization runs on the owner thread, BEFORE releasing the reservation,
    // including after a facade was destroyed. It must not capture that facade.
    using Finalizer = std::function<void(BackupResult&, const storage::VaultOperationGuard&)>;
    bool startReserved(const QString& source, const QString& destination,
        storage::VaultOperationGuard reservation, Finalizer finalize,
        std::optional<SnapshotDirectoryIdentity> directory = {},
        std::optional<AutomaticBackupContext> automatic = {});
    void cancel();
    [[nodiscard]] bool isActive() const noexcept { return active_; }
    [[nodiscard]] QString startError() const { return startError_; }
    static QString siblingWorkerPath();
signals:
    // Copy AND catalogue confirmed. The reservation is still held; an optional
    // rotation follows. This is not processTerminated / permission to write.
    void copyConfirmed(passwall::services::BackupResult result);
    void rotationStarted();
    void rotationFinished(passwall::services::RotationResult result);
    // After launch, definitive states require a valid terminal record AND normal
    // child exit. Failed launch/pre-launch cancellation need no child record.
    // Unknown may be reported while a killed child is still stuck in the kernel.
    void finished(passwall::services::BackupResult result); // Copy result, never changed by rotation errors.
    // Separate from finished(Unknown). No child can still access the source.
    void processTerminated();
private:
    QString workerPath_;
    QPointer<BackupProcessSession> session_;
    bool started_ = false;
    bool active_ = false;
    QString startError_;
    friend class BackupProcessSession;
};
} // namespace passwall::services
