#include "gui/main_window.hpp"
#include "services/vault_preferences_store.hpp"
#include "services/automatic_backup_coordinator.hpp"
#ifdef Q_OS_LINUX
#include "gui/vault_restore_controller.hpp"
#include "services/vault_replacement_service.hpp"
#endif
#include <QScopeGuard>
#include <QThread>

namespace {
// No secrets or GUI calls in work. Not parented to MainWindow: closing a window
// must not destroy/wait on a running QThread. Completion always runs on GUI.
void prepareOffThread(std::function<void()> work, std::function<void()> complete)
{
    auto* delivery = new QObject;
    auto* task = QThread::create([work = std::move(work)] { work(); });
    QObject::connect(task, &QThread::finished, delivery,
        [task, delivery, complete = std::move(complete)] {
            try { complete(); } catch (...) { /* No callback escapes Qt. */ }
            task->deleteLater(); delivery->deleteLater();
        }, Qt::QueuedConnection);
    task->start();
}
}

namespace passwall::gui {
void MainWindow::revokeReplacement() noexcept
{
#ifdef Q_OS_LINUX
    if (recoveryAdmission_) *recoveryAdmission_ = false;
#endif
    if (replacementGeneration_ != 0) ++replacementGeneration_; // zero stays fail-closed
    services::VaultReplacementAuthorization::revoke(replacement_.lock());
#ifdef Q_OS_LINUX
    if (restoreJob_) restoreJob_->cancel();
#endif
}
bool MainWindow::recoveryAllowsCurrentSession() const noexcept
{
    try {
        QString error;
        return services::VaultPreferencesStore().recoveryAccess(vaultPath_, error)
            == services::VaultRecoveryAccess::Allowed;
    } catch (...) { return false; }
}
void MainWindow::requestReplacementAuthorization(const QString& localId,
    std::function<void(services::VaultReplacementAuthorization, QString)> completion,
    std::shared_ptr<services::ManualBackupOperationAdmission> admission,
    QString admittedVaultPath)
{
    using Authorization = services::VaultReplacementAuthorization;
    if (!isSessionThread()) qFatal("Replacement preparation must run on the vault owner's thread");
    if (!completion) return;
    const QPointer<MainWindow> guarded(this);
    const auto reject = [&](services::VaultReplacementAuthorization authority, QString error) noexcept {
        try { completion(std::move(authority), std::move(error)); } catch (...) {}
    };
    auto precautionPolicy =
        services::ReplacementPrecautionPolicy::HistoricalRegistration;
#ifdef Q_OS_LINUX
    if (admittedVaultPath.isEmpty()) admittedVaultPath = vaultPath_;
    const bool generational = automaticBackup_
        && automaticBackup_->triggerMode()
            == services::BackupTriggerMode::Generational;
    if (generational)
        precautionPolicy = services::ReplacementPrecautionPolicy::Required;
    if (generational && !admission) {
        QString admissionError;
        auto acquired = automaticBackup_->acquireUserOperation(
            services::BackupUserOperation::Restoration, admittedVaultPath,
            admissionError);
        if (!acquired.valid()) {
            reject({}, admissionError);
            return; // No reservation and therefore no persistent replacement intent.
        }
        try {
            admission = std::make_shared<
                services::ManualBackupOperationAdmission>(std::move(acquired));
        } catch (...) {
            reject({}, QStringLiteral(
                "Impossible de conserver l'admission de la restauration."));
            return;
        }
    }
    if (generational && (!admission || !admission->valid())) {
        reject({}, QStringLiteral(
            "Admission de restauration absente, révoquée ou obsolète."));
        return;
    }
#endif
    if (replacementGeneration_ == 0 || externalLockBlocksAccess() || vaultLockInProgress_ || !ensureLifecycleProtection() || !guarded
#ifdef Q_OS_LINUX
        || hasOpenCredentialEditor() || exportInProgress_
        || (automaticBackup_
            && automaticBackup_->triggerMode()
                == services::BackupTriggerMode::Historical
            && automaticBackup_->isActive())
#endif
    ) {
        reject({}, QStringLiteral("Une opération incompatible ou un éditeur est encore actif."));
        return;
    }
    const auto initialGeneration = sessionGeneration_;
    const auto preparationGeneration = replacementGeneration_;
    struct Pending {
        std::shared_ptr<Authorization::State> state;
        std::shared_ptr<services::ManualBackupOperationAdmission> admission;
        QString admittedVaultPath;
        QString error;
    };
    auto pending = std::make_shared<Pending>();
#ifdef Q_OS_LINUX
    if (admission && admission->generational()) {
        if (!admission->consumeForExclusive(
                services::BackupUserOperation::Restoration,
                admittedVaultPath, pending->error)) {
            reject({}, pending->error);
            return;
        }
        pending->admission = std::move(admission);
        pending->admittedVaultPath = std::move(admittedVaultPath);
    }
#endif
    // Set only after the single-use admission was consumed successfully and
    // before any registry/reservation work can start.
    replacementTransition_ = true;
    auto deliver = [guarded, completion = std::move(completion)](Authorization authority, QString error) mutable {
        if (guarded) guarded->replacementTransition_ = false;
        try { completion(std::move(authority), std::move(error)); } catch (...) {}
    };
    try {
        // Construct the configuration pathname on its owner thread. The store
        // itself contains only a QString and creates fresh QSettings per call.
        const services::VaultPreferencesStore store;
        auto validation = [guarded, preparationGeneration] { return guarded && guarded->isSessionThread()
            && guarded->replacementGeneration_ == preparationGeneration
            && guarded->hasLifecycleProtection() && guarded->isFullyLocked(); };
        prepareOffThread([pending, store, localId, validation, precautionPolicy] {
            try {
                storage::VaultOperationGuard reservation;
                std::string reservationError;
                if (pending->admission) {
                    if (!reservation.tryReserve(
                            pending->admittedVaultPath.toStdString(),
                            reservationError)) {
                        pending->error = QString::fromStdString(reservationError);
                        return;
                    }
                    pending->state = Authorization::reserve(store, localId,
                        precautionPolicy, validation, std::move(reservation),
                        pending->error);
                } else {
                    pending->state = Authorization::reserve(store, localId,
                        precautionPolicy, validation, pending->error);
                }
            } catch (...) { pending->error = QStringLiteral("Impossible de réserver le coffre."); }
        }, [guarded, pending, initialGeneration, preparationGeneration, deliver]() mutable {
            // The real reservation is now held by state or definitively
            // refused. Release the logical slot only on the owner thread.
            pending->admission.reset();
            const auto state = pending->state;
            if (!state || !guarded || guarded->sessionGeneration_ != initialGeneration
                || guarded->replacementGeneration_ != preparationGeneration
                || !guarded->hasLifecycleProtection()
                || !Authorization::targetsSession(state, guarded->vaultPath_)) {
                Authorization::revoke(state);
                deliver({}, pending->error.isEmpty() ? QStringLiteral("Préparation devenue obsolète ou coffre incompatible.") : pending->error);
                return;
            }
            guarded->replacement_ = state;
            guarded->requestLock([guarded, pending, state, deliver](bool cleaned) mutable {
                if (!guarded || !cleaned || !Authorization::beginPreparation(state, pending->error)) {
                    Authorization::revoke(state); deliver({}, pending->error); return;
                }
                const auto lockedGeneration = guarded->sessionGeneration_;
                prepareOffThread([pending, state] {
                    try { Authorization::prepare(state, pending->error); }
                    catch (...) { pending->error = QStringLiteral("Erreur de préparation persistante ; récupération à vérifier."); }
                }, [guarded, pending, state, lockedGeneration, deliver]() mutable {
                    if (!guarded || guarded->sessionGeneration_ != lockedGeneration)
                        Authorization::revoke(state);
                    auto authority = Authorization::finishPreparation(state, pending->error);
                    deliver(std::move(authority), pending->error);
                });
            }, LockReason::ReplacementPreparation);
        });
    } catch (...) {
        Authorization::revoke(pending->state);
        deliver({}, QStringLiteral("Impossible de préparer le remplacement du coffre."));
    }
}
#ifdef Q_OS_LINUX
void MainWindow::requestReplacementRecovery(const QString& localId, const QString& operationId,
    services::ReplacementRecoveryAction action,
    std::function<void(services::ReplacementRecoveryResult)> completion)
{
    using namespace services;
    if (!isSessionThread()) qFatal("Recovery must be admitted on the vault owner's thread");
    if (!completion) return;
    // Do not revoke a live authority/worker just to get a successful reservation.
    // A prior uncertain recovery may be retried, but may not open a session.
    if (replacementGeneration_ == 0 || replacementTransition_ || VaultReplacementAuthorization::active(replacement_.lock())
        || externalLockClosing_ || externalLockFailed_ || vaultLockInProgress_
        || externalLockReplyInProgress_ || !externalLockRequests_.empty()
        || exportCloseRequested_ || exportInProgress_ || restoreSecretsPending_
        || (restoreJob_ && restoreJob_->isActive()) || hasOpenCredentialEditor()
        || (automaticBackup_ && automaticBackup_->isActive()) || !ensureLifecycleProtection()) {
        ReplacementRecoveryResult result;
        result.diagnostic = tr("Opération encore active ou protection indisponible ; récupération refusée.");
        completion(std::move(result)); return;
    }
    replacementTransition_ = true;
    auto admitted = std::make_shared<std::atomic<bool>>(true);
    recoveryAdmission_ = admitted;
    const auto generation = replacementGeneration_;
    const QPointer<MainWindow> window(this);
    const VaultPreferencesStore store;
    requestLock([window, admitted, generation, store, localId, operationId, action,
                 completion = std::move(completion)](bool cleaned) mutable {
        if (!window) return;
        if (!cleaned || !*admitted || window->replacementGeneration_ != generation
            || !window->hasLifecycleProtection()) {
            window->replacementTransition_ = false;
            completion({}); return;
        }
        const auto lockedGeneration = window->sessionGeneration_;
        auto result = std::make_shared<ReplacementRecoveryResult>();
        prepareOffThread([store, localId, operationId, action, admitted, result] {
            try {
                *result = VaultReplacementAuthorization::recoverLocked(store, localId, operationId,
                    action, [admitted] { return admitted->load(); });
            } catch (...) { result->diagnostic = QStringLiteral("Récupération interrompue ; résultat non confirmé."); }
        }, [window, admitted, generation, lockedGeneration, result, action, localId,
            completion = std::move(completion)]() mutable {
            if (!window) return;
            const bool current = *admitted && window->replacementGeneration_ == generation
                && window->sessionGeneration_ == lockedGeneration
                && window->hasLifecycleProtection() && window->isFullyLocked();
            window->replacementTransition_ = false;
            if (!current) {
                // An inspected layout is not an offer of action once its
                // owner/session admission has been revoked.
                result->layout = ReplacementLayout::Unrecognized;
                result->finalization.state = ReplacementFinalizationState::RecoveryRequired;
                result->diagnostic = tr("Retour de récupération obsolète ; aucune réussite confirmée.");
            }
            if (action != ReplacementRecoveryAction::Inspect) {
                const bool resolved = current && result->finalization.state == ReplacementFinalizationState::Resolved;
                if (resolved) window->recoveryUnconfirmed_.remove(localId);
                else window->recoveryUnconfirmed_.insert(localId);
                if (resolved && window->restoreController_) window->restoreController_->recoveryConfirmed(localId);
            }
            window->updateSessionAccessUi(); window->updateExportAction();
            completion(std::move(*result));
        });
    }, LockReason::ReplacementPreparation);
}
void MainWindow::restoreVault()
{
    if (externalLockClosing_ || exportCloseRequested_) return;
    if (!restoreController_) restoreController_ = new VaultRestoreController(*this);
    restoreController_->open();
}
bool MainWindow::replacementMatchesSelection(const services::VaultReplacementAuthorization& authority,
    const services::VaultRegistration& selected) const noexcept
{
    return authority.state_ && authority.state_ == replacement_.lock() && authority.matchesSelection(selected);
}
services::RestoreJob* MainWindow::startReplacementOperation(services::VaultReplacementAuthorization authority,
    const QString& source, core::SecureBuffer password, const QString& precaution, QString* startError)
{
    if (!isSessionThread()) qFatal("Restoration must run on the owner's thread");
    if (!authority.state_ || authority.state_ != replacement_.lock() || !authority.delegationCurrent()
        || (restoreJob_ && restoreJob_->isActive()) || restoreSecretsPending_) {
        if (startError) *startError = tr("Autorisation devenue obsolète ou opération incompatible encore active.");
        return nullptr;
    }
    auto* job = new services::RestoreJob(services::RestoreJob::siblingWorkerPath(), this);
    restoreJob_ = job;
    restoreSecretsPending_ = true; // Before any launch/reentrant observer.
    const QPointer<MainWindow> window(this);
    const QPointer<services::RestoreJob> facade(job);
    // Observers are retained by the independent session, not by the facade.
    job->cleanupObserver_ = [window](services::RestoreCleanup) {
        if (!window) return;
        window->restoreSecretsPending_ = false; window->completeRestoreCleanup();
    };
    job->terminationObserver_ = [window, facade] {
        if (!window) return;
        if (window->restoreJob_ == facade) window->restoreJob_.clear();
        if (facade) facade->deleteLater();
        window->updateSessionAccessUi(); window->updateExportAction();
    };
    if (!job->start(std::move(authority), source, std::move(password), precaution)) {
        if (startError) *startError = job->startError();
        restoreSecretsPending_ = false; restoreJob_.clear(); job->deleteLater();
        completeRestoreCleanup(); return nullptr;
    }
    return job;
}
void MainWindow::completeRestoreCleanup()
{
    if (restoreSecretsPending_ || vaultLockInProgress_) return;
    // No nested event loop; queued owner-thread processing revalidates the
    // ordinary local cleanup before any global positive acknowledgement.
    QMetaObject::invokeMethod(this, [this] {
        if (restoreSecretsPending_ || vaultLockInProgress_ || !isFullyLocked()) return;
        if (lifecycleLockPending_) {
            lifecycleLockPending_ = false; emit lifecycleSecretsCleared();
        }
        scheduleExternalLockCompletion();
    }, Qt::QueuedConnection);
}
#endif
} // namespace passwall::gui
