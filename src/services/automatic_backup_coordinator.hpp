#pragma once

#include "services/vault_preferences_store.hpp"
#include <QMap>
#include <QPointer>
#include <QSet>
#include <memory>

namespace passwall::services {
class BackupJob;

// Owner-thread Qt coordinator. No key, credential, timer, retry loop or copy
// engine. Registry/preflight work runs only from deferred dispatch, never from
// lockVault's cleanup/acknowledgement stack. Copy I/O belongs to the worker.
class AutomaticBackupCoordinator final : public QObject {
    Q_OBJECT
public:
    explicit AutomaticBackupCoordinator(QObject* parent = nullptr);
    AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker, QObject* parent = nullptr);
    ~AutomaticBackupCoordinator() override;
    void trackVault(const VaultRegistration& registration);
    void requestForLockedVault(const QString& path);
    void resumeAutomaticBackup(const QString& localId);
    void setPaused(bool paused);
    void retryPending(); // Event-driven only: editor closed, operation ended, resumed.
    void cancel(); // Explicit voluntary cancellation suspends subsequent attempts.
    void shutdown();
    [[nodiscard]] bool isActive() const noexcept;
    [[nodiscard]] bool canClose() const noexcept { return closeReady_; }
signals:
    void notification(QString localId, QString message);
    void completed(QString localId, passwall::services::BackupResult result);
    void copyConfirmed(QString localId, passwall::services::BackupResult result);
    void rotationCompleted(QString localId, passwall::services::RotationResult result);
    void activityChanged(bool active);
    void closeReady();
    void deferred(QString localId);
private:
    void dispatch();
    void schedulePending();
    void fail(const QString& id, const QString& message);
    VaultPreferencesStore store_;
    QString worker_;
    QMap<QString, QString> known_; // path -> local id, automatic only
    QMap<QString, QString> pending_; // local id -> source
    QSet<QString> resumes_, notified_, deferredIds_;
    QPointer<BackupJob> job_;
    std::shared_ptr<bool> normalInterruption_;
    bool paused_ = false, queued_ = false, closing_ = false, closeReady_ = false;
    bool voluntaryCancellation_ = false;
    bool unconfirmedRotationStop_ = false;
};
}
