
#pragma once

#include "core/crypto_engine.hpp"
#include "models/credential.hpp"
#include "native/native_request_processor.hpp"
#include "services/backup_trigger_mode.hpp"
#include "services/backup_series_identity.hpp"
#include "services/vault_replacement_authorization.hpp"

#include <QMainWindow>
#include <QString>
#include <QTimer>
#include <QJsonObject>
#include <QPointer>
#include <QSet>
#ifdef Q_OS_LINUX
#include "services/restore_job.hpp"
#endif

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <atomic>
#include <vector>

QT_BEGIN_NAMESPACE
class QVariant;
class QMessageBox;
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

#ifdef Q_OS_LINUX
namespace passwall::services {
class BackupJob;
class AutomaticBackupCoordinator;
class ManualBackupOperationAdmission;
class GenerationalBackupRotationController;
struct GenerationalBackupRequestOffer;
struct VaultFileIdentity;
}
class QCloseEvent;
#endif

namespace passwall::gui {

#ifdef Q_OS_LINUX
class VaultExportDialog;
class VaultRestoreController;
class VaultRecoveryController;
struct GenerationalCrudPreparation;
class GlobalBackupPreferencesController;
class GenerationalBackupStatusController;
#endif

class MainWindow : public QMainWindow, public native::NativeVaultAccess {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
#ifdef PASSWALL_GUI_TESTING
    // Production selects Generational exclusively. Historical remains
    // constructible only by GUI fixtures that still verify the legacy
    // recovery and export guarantees during their transition.
    [[nodiscard]] static std::unique_ptr<MainWindow>
        createForHistoricalTests(QWidget* parent = nullptr);
    // GUI integration fixtures may use the reduced grouping delay and their
    // explicit fictitious installation identity.
    [[nodiscard]] static std::unique_ptr<MainWindow>
        createForGenerationalTests(QWidget* parent = nullptr);
    // This remains a test-only entry point, but deliberately uses the values
    // that a future production activation will use: system identity, 20 s
    // grouping and the normal sibling worker lookup.  It must not acquire the
    // fixture identity, reduced delay or any worker test hook.
    [[nodiscard]] static std::unique_ptr<MainWindow>
        createForGenerationalProductionCompositionTests(
            QWidget* parent = nullptr);
#endif
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
    // Internal 6A preparation entry point, also used by the restoration GUI.
    // Does not replace a file. Owner-thread only.
    // The only production issuer is this real cleanup/acknowledgement path.
    void requestReplacementAuthorization(const QString& localId,
        std::function<void(services::VaultReplacementAuthorization, QString)> completion,
        std::shared_ptr<services::ManualBackupOperationAdmission> admission = {},
        QString admittedVaultPath = {});
#ifdef Q_OS_LINUX
    // Internal execution API used by the restoration GUI/tests. Only an authority issued by THIS
    // MainWindow can be consumed. Returned facade remains owned by the window.
    services::RestoreJob* startReplacementOperation(services::VaultReplacementAuthorization,
        const QString& source, core::SecureBuffer password, const QString& precaution,
        QString* startError = nullptr);
    // Recovery admission is distinct from replacement issuance. Always locks,
    // waits for actual cleanup, then performs secretless proof I/O off-thread.
    void requestReplacementRecovery(const QString& localId, const QString& operationId,
        services::ReplacementRecoveryAction,
        std::function<void(services::ReplacementRecoveryResult)>);
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
#ifdef Q_OS_LINUX
#ifdef PASSWALL_GUI_TESTING
    explicit MainWindow(services::BackupTriggerMode backupTriggerMode,
                        QWidget* parent,
                        bool useGenerationalTestInjections = false);
#else
    explicit MainWindow(services::BackupTriggerMode backupTriggerMode,
                        QWidget* parent);
#endif
#endif
#ifdef Q_OS_LINUX
    friend class VaultRestoreController; // Coordinates the real issuer; never a friend of Authorization.
    friend class VaultRecoveryController;
    VaultRecoveryController* recoveryController_ = nullptr;
    std::shared_ptr<std::atomic<bool>> recoveryAdmission_;
    QSet<QString> recoveryUnconfirmed_; // Visible receipts never upgrade failed GUI results.
    void restoreVault();
    bool replacementMatchesSelection(const services::VaultReplacementAuthorization&,
        const services::VaultRegistration&) const noexcept;
    VaultRestoreController* restoreController_ = nullptr;
#endif
    void chooseCreatePath();
    void chooseUnlockPath();
    void createVault();
    void unlockVault();
    void registerAuthenticatedVault(const QString& path);
    bool persistUiPreference(const QString& key, const QVariant& value);

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
    void startVaultExport(const QString& source, const QString& destination,
        std::shared_ptr<services::ManualBackupOperationAdmission> admission);
    void cancelVaultExport();
    void queueExportClose();
    void queueGenerationalDrainClose();
    void handleGenerationalDrainTerminal();
    void showGenerationalCloseFailureNotice();
    void continueAfterGenerationalCloseFailure();
    void consumeGenerationalBackupRequest(
        services::GenerationalBackupRequestOffer offer);
    void completeGenerationalCrudPreparation(
        const std::shared_ptr<GenerationalCrudPreparation>& preparation);
    void invalidateGenerationalCrudPreparation(quint64 requestId);
    bool exportInProgress_ = false;
    bool exportLockPending_ = false;
    bool exportCloseRequested_ = false;
    bool exportUncertain_ = false;
    bool generationalCloseDrainRequested_ = false;
    bool generationalDrainCloseQueued_ = false;
    bool generationalCloseFailureAccepted_ = false;
    QPointer<QMessageBox> generationalCloseFailureNotice_;
    std::shared_ptr<GenerationalCrudPreparation> generationalCrudPreparation_;
    // Constructed only when the immutable coordinator mode is Generational.
    services::GenerationalBackupRotationController*
        generationalRotationController_ = nullptr;
    GlobalBackupPreferencesController*
        globalBackupPreferencesController_ = nullptr;
    GenerationalBackupStatusController*
        generationalBackupStatusController_ = nullptr;
    std::shared_ptr<const services::VaultFileIdentity>
        authenticatedBackupVault_;
    // Empty in production: the destination preparer then resolves the real
    // libsystemd application-specific identity. Fixtures alone inject a fake
    // identity through createForGenerationalTests().
    std::optional<services::BackupInstallationIdentity>
        backupInstallationIdentity_;
    QPointer<services::BackupJob> backupJob_;
    services::AutomaticBackupCoordinator* automaticBackup_ = nullptr;
    // Independent modeless window: lockVault must not reject/cancel a keyless
    // backup window when another session is locked. Explicitly owned below.
    QPointer<VaultExportDialog> exportDialog_;
#endif

    QTimer inactivityTimer_;
    int autoLockMinutes_ = 1;

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
