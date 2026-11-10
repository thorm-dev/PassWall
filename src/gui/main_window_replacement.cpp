#include "gui/main_window.hpp"
#include "services/vault_preferences_store.hpp"
#include "services/automatic_backup_coordinator.hpp"
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
    std::function<void(services::VaultReplacementAuthorization, QString)> completion)
{
    using Authorization = services::VaultReplacementAuthorization;
    if (!isSessionThread()) qFatal("Replacement preparation must run on the vault owner's thread");
    if (!completion) return;
    const QPointer<MainWindow> guarded(this);
    const auto reject = [&](services::VaultReplacementAuthorization authority, QString error) noexcept {
        try { completion(std::move(authority), std::move(error)); } catch (...) {}
    };
    if (replacementGeneration_ == 0 || externalLockBlocksAccess() || vaultLockInProgress_ || !ensureLifecycleProtection() || !guarded
#ifdef Q_OS_LINUX
        || hasOpenCredentialEditor() || exportInProgress_
        || (automaticBackup_ && automaticBackup_->isActive())
#endif
    ) {
        reject({}, QStringLiteral("Une opération incompatible ou un éditeur est encore actif."));
        return;
    }
    // Set before registry/reservation work. No nested UI loop, no blocking flock.
    replacementTransition_ = true;
    const auto initialGeneration = sessionGeneration_;
    const auto preparationGeneration = replacementGeneration_;
    struct Pending {
        std::shared_ptr<Authorization::State> state;
        QString error;
    };
    auto pending = std::make_shared<Pending>();
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
        prepareOffThread([pending, store, localId, validation] {
            try {
                pending->state = Authorization::reserve(store, localId, validation, pending->error);
            } catch (...) { pending->error = QStringLiteral("Impossible de réserver le coffre."); }
        }, [guarded, pending, initialGeneration, preparationGeneration, deliver]() mutable {
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
services::RestoreJob* MainWindow::startReplacementOperation(services::VaultReplacementAuthorization authority,
    const QString& source, core::SecureBuffer password, const QString& precaution)
{
    if (!isSessionThread()) qFatal("Restoration must run on the owner's thread");
    if (!authority.state_ || authority.state_ != replacement_.lock() || !authority.delegationCurrent()
        || (restoreJob_ && restoreJob_->isActive()) || restoreSecretsPending_) return nullptr;
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
