#include "gui/vault_restore_controller.hpp"
#include "gui/vault_restore_dialog.hpp"
#include "gui/main_window.hpp"
#include "services/automatic_backup_coordinator.hpp"
#include "services/vault_snapshot_service.hpp"
#include <QFileInfo>
#include <QStatusBar>
#include <QThread>
#include <algorithm>

namespace passwall::gui {
VaultRestoreController::VaultRestoreController(MainWindow& owner) : QObject(&owner), owner_(owner) {}
VaultRestoreController::~VaultRestoreController() {
    if (job_) job_->cancel();
    delete dialog_.data(); // Wipes the GUI field, never waits for a child.
}
bool VaultRestoreController::hasSensitiveInput() const { return dialog_ && dialog_->hasPassword(); }
void VaultRestoreController::recoveryConfirmed(const QString& localId) {
    uncertain_.remove(localId);
    if (dialog_ && stage_ != Stage::Running && stage_ != Stage::Preparing
        && stage_ != Stage::Password && stage_ != Stage::Resolving) load();
}
void VaultRestoreController::open() {
    if (dialog_) { dialog_->show(); dialog_->raise(); dialog_->activateWindow(); return; }
    dialog_ = new VaultRestoreDialog;
    connect(dialog_, &VaultRestoreDialog::preparationRequested, this, [this] { prepare(); });
    connect(dialog_, &VaultRestoreDialog::executionRequested, this, [this] { execute(); });
    connect(dialog_, &VaultRestoreDialog::cancellationRequested, this, [this] { cancel(); });
    connect(dialog_, &VaultRestoreDialog::closingRequested, this, [this] { cancel(); });
    connect(dialog_, &QDialog::finished, this, [this] { dialog_.clear(); });
    dialog_->show();
    if (job_ && job_->isActive()) {
        if (result_) displayResult(false);
        else dialog_->running(tr("Restauration toujours en cours ; attente de terminaison."));
        return;
    }
    if (stage_ == Stage::Preparing) { dialog_->preparing(); return; }
    if (stage_ == Stage::Resolving) {
        dialog_->running(tr("Vérification durable de l'abandon de la restauration…"), false);
        return;
    }
    result_.reset(); cancelled_ = engaged_ = cleanup_ = finalReported_ = false; load();
}
void VaultRestoreController::load() {
    stage_ = Stage::Loading; operationId_.clear(); automaticAbandonPending_.reset();
    automaticAbandonDiagnostic_.clear();
    const auto serial = ++generation_;
    struct Listing { QVector<services::VaultRegistration> records; QString error; bool ok = false; };
    auto listing = std::make_shared<Listing>();
    const services::VaultPreferencesStore store;
    auto* delivery = new QObject;
    auto* task = QThread::create([listing, store] {
        try { listing->ok = store.list(listing->records, listing->error); }
        catch (...) { listing->error = QStringLiteral("Lecture du registre impossible ; récupération non exclue."); }
    });
    const QPointer<VaultRestoreController> guarded(this);
    connect(task, &QThread::finished, delivery, [guarded, listing, serial, delivery, task] {
        task->deleteLater(); delivery->deleteLater();
        if (!guarded || guarded->generation_ != serial || !guarded->dialog_) return;
        if (!listing->ok) { guarded->fail(listing->error); return; }
        guarded->records_ = listing->records; guarded->stage_ = Stage::Choosing;
        guarded->dialog_->setRegistrations(listing->records, guarded->uncertain_);
    }, Qt::QueuedConnection);
    task->start();
}
void VaultRestoreController::fail(const QString& message) {
    stage_ = Stage::Result; authority_.reset();
    if (dialog_) dialog_->showError(message);
    else owner_.statusBar()->showMessage(message);
    owner_.updateSessionAccessUi(); owner_.updateExportAction();
}
void VaultRestoreController::prepare() {
    if (stage_ != Stage::Choosing || !dialog_) return;
    const auto selected = dialog_->selectedId();
    const auto found = std::find_if(records_.cbegin(), records_.cend(), [&](const auto& r) { return r.localId == selected; });
    if (found == records_.cend() || found->replacement || uncertain_.contains(selected)) {
        fail(tr("Coffre inconnu ou récupération nécessaire ; aucune restauration autorisée.")); return;
    }
    if (!dialog_->confirmed() || dialog_->source().isEmpty()
        || (!found->backup.automatic && dialog_->precaution().isEmpty())) {
        // Keep the form usable after a missing confirmation/required path.
        dialog_->validationError(tr("Confirmez le remplacement, choisissez la sauvegarde et la copie obligatoire éventuelle.")); return;
    }
    QString executableError;
    if (!services::RestoreJob::validateInstallation(services::RestoreJob::siblingWorkerPath(),
        services::RestoreJob::siblingApplicationPath(), executableError)) {
        fail(tr("Restauration indisponible avant préparation : %1").arg(executableError)); return;
    }
    if (owner_.externalLockBlocksAccess() || owner_.vaultLockInProgress_ || owner_.exportInProgress_
        || owner_.exportCloseRequested_ || owner_.hasOpenCredentialEditor()
        || (owner_.automaticBackup_ && owner_.automaticBackup_->isActive()) || !owner_.ensureLifecycleProtection()) {
        fail(tr("Une édition, une opération incompatible ou une protection indisponible empêche la restauration.")); return;
    }
    selected_ = *found; principalId_ = selected; source_ = dialog_->source();
    precaution_ = found->backup.automatic ? QString{} : dialog_->precaution();
    cancelled_ = false; stage_ = Stage::Prevalidating; dialog_->prevalidating();
    const auto serial = ++generation_;
    const auto securityGeneration = owner_.replacementGeneration_;
    struct Prevalidation {
        bool ok = false;
        services::SnapshotSourceIdentity identity;
        QString error;
    };
    auto result = std::make_shared<Prevalidation>();
    const auto source = source_;
    auto* delivery = new QObject;
    auto* task = QThread::create([result, source] {
        try {
            std::string error;
            result->ok = services::VaultSnapshotService::prevalidateVaultSource(
                source.toStdString(), error, &result->identity);
            result->error = QString::fromStdString(error);
        } catch (...) { result->error = QStringLiteral("Prévalidation de la sauvegarde interrompue."); }
    });
    const QPointer<VaultRestoreController> guarded(this);
    connect(task, &QThread::finished, delivery,
        [guarded, result, serial, securityGeneration, delivery, task] {
            task->deleteLater(); delivery->deleteLater();
            if (!guarded || guarded->generation_ != serial || guarded->cancelled_) {
                if (guarded) emit guarded->preparationSettled(false);
                return;
            }
            if (!guarded->dialog_) { emit guarded->preparationSettled(false); return; }
            if (!result->ok) {
                guarded->stage_ = Stage::Choosing;
                guarded->dialog_->choosing();
                guarded->dialog_->validationError(tr("Sauvegarde refusée avant verrouillage : %1")
                    .arg(result->error.isEmpty() ? tr("format ou accès incompatible.") : result->error));
                emit guarded->preparationSettled(true);
                return;
            }
            if (result->identity.device == guarded->selected_.file.device
                && result->identity.inode == guarded->selected_.file.inode) {
                guarded->stage_ = Stage::Choosing;
                guarded->dialog_->choosing();
                guarded->dialog_->validationError(tr("Sauvegarde refusée avant verrouillage : la source est le coffre principal."));
                emit guarded->preparationSettled(true);
                return;
            }
            guarded->authorizeAfterPrevalidation(serial, securityGeneration);
        }, Qt::QueuedConnection);
    task->start();
}

void VaultRestoreController::authorizeAfterPrevalidation(quint64 serial, quint64 securityGeneration) {
    if (generation_ != serial || cancelled_ || !dialog_) {
        emit preparationSettled(false); return;
    }
    if (securityGeneration != owner_.replacementGeneration_
        || owner_.externalLockBlocksAccess() || owner_.vaultLockInProgress_ || owner_.exportInProgress_
        || owner_.exportCloseRequested_ || owner_.hasOpenCredentialEditor()
        || (owner_.automaticBackup_ && owner_.automaticBackup_->isActive()) || !owner_.ensureLifecycleProtection()) {
        fail(tr("Une édition, une opération incompatible ou une protection indisponible empêche la restauration."));
        emit preparationSettled(true); return;
    }
    stage_ = Stage::Preparing; dialog_->preparing();
    // No secret entered yet. Explicit confirmation permits locking even another
    // active vault; the ordinary 6A emitter then reserves the selected record.
    // This deliberate lock must NOT trigger an automatic backup or cancellation.
    owner_.lockVault(MainWindow::LockReason::ReplacementPreparation);
    if (serial != generation_ || securityGeneration != owner_.replacementGeneration_ || !owner_.isFullyLocked()) {
        fail(tr("Le verrouillage a été interrompu ; restauration non démarrée.")); return;
    }
    const QPointer<VaultRestoreController> guarded(this);
    owner_.requestReplacementAuthorization(principalId_, [guarded, serial](auto authority, QString error) {
        if (!guarded) return;
        if (guarded->generation_ != serial) { emit guarded->preparationSettled(false); return; }
        if (guarded->cancelled_ || authority.operationId().isEmpty() || !guarded->dialog_) {
            guarded->fail(error.isEmpty() ? tr("Préparation interrompue ; le coffre peut nécessiter une récupération.") : error);
            emit guarded->preparationSettled(true); return;
        }
        if (!guarded->owner_.replacementMatchesSelection(authority, guarded->selected_)) {
            guarded->fail(tr("L'identité ou les préférences du coffre ont changé depuis la confirmation. "
                "Aucune restauration démarrée ; récupération de la préparation à vérifier."));
            emit guarded->preparationSettled(true); return;
        }
        guarded->operationId_ = authority.operationId();
        guarded->authority_ = std::move(authority); guarded->stage_ = Stage::Password;
        guarded->dialog_->awaitingPassword();
        emit guarded->preparationSettled(true);
    });
}
void VaultRestoreController::execute() {
    if (stage_ != Stage::Password || !dialog_ || authority_.operationId().isEmpty()) return;
    if (!dialog_->hasPassword()) { dialog_->validationError(tr("Le mot de passe maître est obligatoire.")); return; }
    try {
        auto password = dialog_->takePassword(); // Qt temporaries already wiped on return.
        stage_ = Stage::Running; dialog_->running(tr("Vérification de la sauvegarde et préparation de la restauration…"));
        QString startError;
        job_ = owner_.startReplacementOperation(std::move(authority_), source_, std::move(password), precaution_, &startError);
        if (!job_) {
            automaticAbandonDiagnostic_ = startError.left(1024);
            if (dialog_ && !startError.isEmpty())
                dialog_->running(tr("Démarrage refusé : %1 Vérification de l'abandon…").arg(startError), false);
            abandonPrepared(AutomaticAbandonReason::StartupRefused);
            return;
        }
        using Job = services::RestoreJob;
        connect(job_, &Job::phaseChanged, this, [this](auto value) { phase(value); });
        connect(job_, &Job::secretsCleared, this, [this](auto) { cleanup_ = true; });
        connect(job_, &Job::resultReceived, this, [this](auto value) {
            if (!finalReported_) { result_ = value; displayResult(false); }
        });
        connect(job_, &Job::finished, this, [this](auto value) {
            if (value.outcome == services::RestoreOutcome::Unknown) uncertain_.insert(principalId_);
            automaticAbandonPending_.reset();
            automaticAbandonDiagnostic_.clear();
            const bool exactNonEngagement = value.outcome != services::RestoreOutcome::Unknown
                && value.replacementStatusKnown && !operationId_.isEmpty()
                && value.replacement.operationId == operationId_
                && (value.replacement.outcome == services::ReplacementOutcome::NotReplaced
                    || value.replacement.outcome == services::ReplacementOutcome::CancelledBeforeEngagement);
            if (exactNonEngagement) {
                if (value.outcome == services::RestoreOutcome::SourceAuthenticationFailed
                    && value.replacement.sourceAuthenticationFailed)
                    automaticAbandonPending_ = AutomaticAbandonReason::AuthenticationRejected;
                else if (cancelled_ || value.replacement.outcome == services::ReplacementOutcome::CancelledBeforeEngagement)
                    automaticAbandonPending_ = AutomaticAbandonReason::Cancellation;
                else {
                    automaticAbandonPending_ = AutomaticAbandonReason::NonEngagedFailure;
                    automaticAbandonDiagnostic_ = value.replacement.diagnostic.left(1024);
                }
            }
            finalReported_ = true; result_ = value; displayResult(false);
        });
        connect(job_, &Job::processTerminated, this, [this] {
            if (!finalReported_) {
                if (!result_) result_.emplace();
                result_->outcome = services::RestoreOutcome::Unknown;
                uncertain_.insert(principalId_);
            }
            cleanup_ = true; job_.clear(); stage_ = Stage::Result; displayResult(true);
            if (automaticAbandonPending_ && finalReported_ && result_
                && result_->replacementStatusKnown) {
                abandonPrepared(*automaticAbandonPending_);
            }
        });
    } catch (...) {
        if (dialog_) dialog_->clearPassword();
        if (job_ && job_->isActive()) { cancel(); return; }
        fail(tr("Saisie ou transfert interrompu ; aucun succès confirmé, récupération à vérifier."));
    }
}
void VaultRestoreController::abandonPrepared(AutomaticAbandonReason reason) {
    if (stage_ == Stage::Resolving) return;
    if (principalId_.isEmpty() || operationId_.isEmpty()) {
        authority_.reset(); owner_.revokeReplacement();
        const auto prefix = reason == AutomaticAbandonReason::Cancellation ? tr("Restauration annulée")
            : reason == AutomaticAbandonReason::AuthenticationRejected ? tr("Mot de passe maître incorrect")
            : reason == AutomaticAbandonReason::StartupRefused ? tr("Démarrage de la restauration refusé")
            : tr("Restauration refusée avant engagement");
        fail(prefix + tr(", mais l'abandon durable n'a pas pu être vérifié ; récupération manuelle nécessaire."));
        return;
    }
    automaticAbandonPending_.reset();
    stage_ = Stage::Resolving;
    authority_.reset();
    owner_.revokeReplacement();
    const auto serial = ++generation_;
    const auto localId = principalId_, operationId = operationId_;
    if (dialog_) {
        dialog_->clearPassword();
        dialog_->running(tr("Vérification durable de l'abandon de la restauration…"), false);
    }
    const QPointer<VaultRestoreController> guarded(this);
    owner_.requestReplacementRecovery(localId, operationId,
        services::ReplacementRecoveryAction::AbandonPrepared,
        [guarded, serial, localId, operationId, reason](auto recovered) {
            if (!guarded || guarded->generation_ != serial
                || guarded->principalId_ != localId || guarded->operationId_ != operationId) return;
            const bool safe = recovered.layout == services::ReplacementLayout::Abandoned
                && recovered.finalization.state == services::ReplacementFinalizationState::Resolved;
            guarded->stage_ = Stage::Result;
            if (safe) {
                guarded->uncertain_.remove(localId);
                guarded->operationId_.clear();
                QString message = reason == AutomaticAbandonReason::Cancellation ? tr("Restauration annulée")
                    : reason == AutomaticAbandonReason::AuthenticationRejected ? tr("Mot de passe maître incorrect")
                    : reason == AutomaticAbandonReason::StartupRefused ? tr("Démarrage refusé ; préparation abandonnée en sécurité")
                    : tr("Restauration refusée avant engagement ; préparation abandonnée en sécurité");
                if ((reason == AutomaticAbandonReason::NonEngagedFailure
                        || reason == AutomaticAbandonReason::StartupRefused)
                    && !guarded->automaticAbandonDiagnostic_.isEmpty())
                    message += '\n' + guarded->automaticAbandonDiagnostic_;
                if (guarded->dialog_) guarded->dialog_->showError(message);
                else guarded->owner_.statusBar()->showMessage(message);
            } else {
                guarded->uncertain_.insert(localId);
                const auto prefix = reason == AutomaticAbandonReason::Cancellation ? tr("Restauration annulée")
                    : reason == AutomaticAbandonReason::AuthenticationRejected ? tr("Mot de passe maître incorrect")
                    : reason == AutomaticAbandonReason::StartupRefused ? tr("Démarrage de la restauration refusé")
                    : tr("Restauration refusée avant engagement");
                QString message = prefix + tr(", mais l'abandon durable n'est pas confirmé ; récupération manuelle nécessaire.");
                if (!recovered.diagnostic.isEmpty()) message += '\n' + recovered.diagnostic.left(1024);
                if (guarded->dialog_) guarded->dialog_->showError(message);
                else guarded->owner_.statusBar()->showMessage(message);
            }
            guarded->owner_.updateSessionAccessUi();
            guarded->owner_.updateExportAction();
        });
}
void VaultRestoreController::displayResult(bool terminated) {
    const services::RestoreResult value = result_.value_or(services::RestoreResult{});
    if (dialog_) dialog_->showResult(value, terminated, cleanup_);
    else owner_.statusBar()->showMessage(VaultRestoreDialog::resultMessage(value, terminated, cleanup_));
}
void VaultRestoreController::phase(services::ReplacementCheckpoint point) {
    using Phase = services::ReplacementCheckpoint;
    if (point >= Phase::Armed) engaged_ = true;
    if (!dialog_ || cancelled_) return;
    QString text;
    switch (point) {
    case Phase::BeforeWork: text = tr("Vérification de la sauvegarde…"); break;
    case Phase::SourceAuthenticated: text = tr("Sauvegarde authentifiée ; secrets temporaires nettoyés. Copie de précaution éventuelle…"); break;
    case Phase::PrecautionCreated:
        text = selected_.backup.automatic
            ? tr("Aucune copie de précaution supplémentaire requise ; préparation du remplacement…")
            : tr("Copie de précaution confirmée ; préparation du remplacement…");
        break;
    case Phase::CandidateStaged: case Phase::BeforeArm: text = tr("Candidat préparé ; préparation de l'engagement…"); break;
    case Phase::Armed: case Phase::BeforeExchange: text = tr("Remplacement engagé : l'annulation ne garantit plus l'absence de substitution."); break;
    case Phase::AfterExchange: case Phase::AfterDirectorySync: text = tr("Coffre remplacé ; vérification de durabilité et finalisation…"); break;
    }
    dialog_->running(text);
}
void VaultRestoreController::cancel() {
    if (job_ && job_->isActive()) {
        cancelled_ = true; job_->cancel();
        if (dialog_) dialog_->running(engaged_ ? tr("Arrêt demandé après engagement ; récupération éventuellement nécessaire.")
            : tr("Annulation demandée ; attente de sa confirmation et de la terminaison."), false);
    } else if (stage_ == Stage::Password) {
        cancelled_ = true;
        abandonPrepared(AutomaticAbandonReason::Cancellation);
    } else if (stage_ == Stage::Prevalidating) {
        cancelled_ = true; ++generation_; stage_ = Stage::Choosing;
        if (dialog_) { dialog_->choosing(); dialog_->validationError(tr("Restauration annulée ; aucune préparation persistante créée.")); }
    } else if (stage_ == Stage::Preparing) {
        cancelled_ = true; ++generation_; owner_.revokeReplacement();
        fail(tr("Restauration non démarrée. La préparation interrompue peut nécessiter une récupération."));
    } else if (stage_ == Stage::Loading) {
        ++generation_; stage_ = Stage::Idle;
        if (dialog_) dialog_->showError(tr("Chargement annulé. Aucune restauration démarrée."));
    }
}
void VaultRestoreController::onLock(bool security) {
    if (dialog_) dialog_->clearPassword(); // Synchronous BEFORE global cleanup acknowledgement.
    if (security && (stage_ == Stage::Prevalidating || stage_ == Stage::Preparing
        || stage_ == Stage::Password || stage_ == Stage::Running)) cancel();
}
} // namespace passwall::gui
