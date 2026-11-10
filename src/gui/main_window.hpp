
#pragma once

#include "core/crypto_engine.hpp"
#include "models/credential.hpp"
#include "native/native_request_processor.hpp"
#include "services/vault_replacement_authorization.hpp"

#include <QMainWindow>
#include <QString>
#include <QTimer>
#include <QJsonObject>
#include <QPointer>
#ifdef Q_OS_LINUX
#include "services/restore_job.hpp"
#endif

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

QT_BEGIN_NAMESPACE
class QVariant;
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

#ifdef Q_OS_LINUX
namespace passwall::services { class BackupJob; class AutomaticBackupCoordinator; }
class QCloseEvent;
#endif

namespace passwall::gui {

#ifdef Q_OS_LINUX
class VaultExportDialog;
#endif

class MainWindow : public QMainWindow, public native::NativeVaultAccess {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void activateFromNativeRequest();
    // Same-thread lifecycle gate. false locks synchronously (or joins a lock
    // already in progress); true NEVER unlocks. Linux starts fail-closed.
    void setLifecycleProtectionAvailable(bool available);
    // The check is local, nonblocking, with no Qt signals/cleanup on the GUI thread.
    // invalidate is called at a safe boundary AFTER temporary secrets cleanup.
    // Installing/replacing a validator locks; it never authorizes a session.
    void setLifecycleProtectionValidator(std::function<bool()> check,
                                         std::function<void()> invalidate);
    // Owner-thread only. Completion is queued AFTER the outer lock returns,
    // never on vaultSessionInvalidated. true also waits for delegated secret
    // cleanup/actual termination, not just local cleanup or a cancel request;
    // it confirms accessible cleanup,
    // not erasure of historical Qt/kernel copies. No unlock operation.
    void requestExternalLock(std::function<void(bool)> completion);
    // Internal 6A entry point, no restore GUI or replacement. Owner-thread only.
    // The only production issuer is this real cleanup/acknowledgement path.
    void requestReplacementAuthorization(const QString& localId,
        std::function<void(services::VaultReplacementAuthorization, QString)> completion);
#ifdef Q_OS_LINUX
    // Internal pilot API, no restore GUI. Only an authority issued by THIS
    // MainWindow can be consumed. Returned facade remains owned by the window.
    services::RestoreJob* startReplacementOperation(services::VaultReplacementAuthorization,
        const QString& source, core::SecureBuffer password, const QString& precaution);
#endif
    [[nodiscard]] native::NativeRequestResponse handleNativeRequest(
        const QJsonObject& request);

    [[nodiscard]] native::VaultLease acquireLease() const noexcept override;
    [[nodiscard]] bool isLeaseCurrent(
        const native::VaultLease& lease) const noexcept override;
    [[nodiscard]] native::VaultAccessResult copySummaries(
        const native::VaultLease& lease,
        std::vector<models::CredentialSummary>& output) override;
    [[nodiscard]] native::VaultAccessResult loadCredential(
        const native::VaultLease& lease,
        const models::EntryId& entryId,
        models::Credential& output) override;

signals:
    // Émis synchroniquement après invalidation Native et effacement de la clé.
    // Tous les contextes sont nettoyés avant la phase de fermeture réentrante.
    void vaultSessionInvalidated();
    void vaultEditorsMustClose();
    void lifecycleSecretsCleared();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
#ifdef Q_OS_LINUX
    void closeEvent(QCloseEvent* event) override;
#endif

private:
    void chooseCreatePath();
    void chooseUnlockPath();
    void createVault();
    void unlockVault();
    void registerAuthenticatedVault(const QString& path);
    void persistUiPreference(const QString& key, const QVariant& value);

    void showUnlockedVault();
    enum class LockReason { Security, ReplacementPreparation };
    void lockVault(LockReason reason = LockReason::Security);
    void requestLock(std::function<void(bool)> completion, LockReason reason);

    bool refreshCredentials();
    void filterCredentials(const QString& text);
    void addCredential();
    void editCredential();
    void deleteCredential();

    void showError(const QString& message);
    void clearPasswordFields();
    void clearCredentials();

    [[nodiscard]] bool isSessionThread() const noexcept;
    [[nodiscard]] bool hasLifecycleProtection() const noexcept;
    [[nodiscard]] bool ensureLifecycleProtection();
    [[nodiscard]] bool advanceSessionGeneration() noexcept;
    void scheduleExternalLockCompletion();
    void completeExternalLockRequests();
    [[nodiscard]] bool externalLockBlocksAccess() const noexcept;
    void updateSessionAccessUi();
    [[nodiscard]] bool isFullyLocked() const;
    [[nodiscard]] bool recoveryAllowsCurrentSession() const noexcept;
    void revokeReplacement() noexcept;
    void updateInactivityTimer();
    [[nodiscard]] bool beginUnlockedSession() noexcept;
    [[nodiscard]] native::VaultAccessResult leaseFailureResult(
        const native::VaultLease& lease) const noexcept;
    static void clearSummaryOutput(
        std::vector<models::CredentialSummary>& output) noexcept;

#ifdef Q_OS_LINUX
    void exportVault();
    void updateExportAction();
    [[nodiscard]] bool exportAuthorizationCurrent(native::VaultLease lease, const QString& source);
    [[nodiscard]] bool hasOpenCredentialEditor() const;
    void startVaultExport(const QString& source, const QString& destination);
    void cancelVaultExport();
    void queueExportClose();
    bool exportInProgress_ = false;
    bool exportLockPending_ = false;
    bool exportCloseRequested_ = false;
    bool exportUncertain_ = false;
    QPointer<services::BackupJob> backupJob_;
    services::AutomaticBackupCoordinator* automaticBackup_ = nullptr;
    // Independent modeless window: lockVault must not reject/cancel a keyless
    // backup window when another session is locked. Explicitly owned below.
    QPointer<VaultExportDialog> exportDialog_;
#endif

    QTimer inactivityTimer_;
    int autoLockMinutes_ = 5;

    Ui::MainWindow* ui_;
    core::SecureBuffer dataKey_{0};

    QString vaultPath_;
    std::vector<models::CredentialSummary> credentialSummaries_;
    // La valeur 0 est invalide et force un échec fermé après un éventuel
    // débordement. Toute transition de session valide porte une génération
    // non nulle et différente de la précédente.
    std::uint64_t sessionGeneration_ = 0;
    bool sessionGenerationExhausted_ = false;
    bool vaultLockInProgress_ = false;
    bool lifecycleLockPending_ = false;
    std::vector<std::function<void(bool)>> externalLockRequests_;
    bool externalLockCompletionQueued_ = false;
    bool externalLockReplyInProgress_ = false;
    bool externalLockFailed_ = false;
    bool externalLockClosing_ = false;
    bool replacementTransition_ = false;
    std::weak_ptr<services::VaultReplacementAuthorization::State> replacement_;
    std::uint64_t replacementGeneration_ = 1; // Also changes on repeated locks.
#ifdef Q_OS_LINUX
    QPointer<services::RestoreJob> restoreJob_;
    bool restoreSecretsPending_ = false;
    void completeRestoreCleanup();
#endif
    struct LifecycleProtectionValidator {
        std::function<bool()> check;
        std::function<void()> invalidate;
    };
    // Snapshot ownership keeps callbacks alive if a Qt callback reenters setup.
    std::shared_ptr<const LifecycleProtectionValidator> lifecycleValidator_;
#ifdef Q_OS_LINUX
    bool lifecycleProtectionAvailable_ = false;
#else
    bool lifecycleProtectionAvailable_ = true;
#endif
};

} // namespace passwall::gui
