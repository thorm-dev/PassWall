#include "gui/generational_backup_status_controller.hpp"

#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

namespace passwall::gui {
namespace {

class GenerationalBackupStatusDialog final : public QDialog {
public:
    explicit GenerationalBackupStatusDialog(QWidget* parent)
        : QDialog(parent)
    {
        setObjectName(QStringLiteral("generationalBackupStatusDialog"));
        setWindowTitle(tr("État des sauvegardes"));
        setModal(false);
        resize(560, 300);

        auto* layout = new QVBoxLayout(this);
        const auto addSection = [layout](const QString& title,
                                    const QString& statusName,
                                    const QString& detailName) {
            auto* heading = new QLabel(title);
            QFont font = heading->font();
            font.setBold(true);
            heading->setFont(font);
            layout->addWidget(heading);
            auto* status = new QLabel;
            status->setObjectName(statusName);
            status->setWordWrap(true);
            layout->addWidget(status);
            auto* detail = new QLabel;
            detail->setObjectName(detailName);
            detail->setWordWrap(true);
            detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(detail);
        };
        addSection(tr("Sauvegarde"),
            QStringLiteral("generationalBackupStateLabel"),
            QStringLiteral("generationalBackupDetailLabel"));
        addSection(tr("Rotation des anciennes versions"),
            QStringLiteral("generationalRotationStateLabel"),
            QStringLiteral("generationalRotationDetailLabel"));
        addSection(tr("Configuration globale"),
            QStringLiteral("generationalConfigurationStateLabel"),
            QStringLiteral("generationalConfigurationDetailLabel"));

        manualButton = new QPushButton(tr("Sauvegarder maintenant"));
        manualButton->setObjectName(QStringLiteral("generationalBackupManualButton"));
        layout->addWidget(manualButton);
        retryButton = new QPushButton(tr("Réessayer la sauvegarde"));
        retryButton->setObjectName(QStringLiteral("generationalBackupRetryButton"));
        layout->addWidget(retryButton);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
        buttons->button(QDialogButtonBox::Close)->setObjectName(
            QStringLiteral("generationalBackupStatusCloseButton"));
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        layout->addWidget(buttons);
    }

    QPushButton* manualButton = nullptr;
    QPushButton* retryButton = nullptr;
};

QString diagnosticOr(QString diagnostic, const QString& fallback)
{
    diagnostic = diagnostic.trimmed();
    return diagnostic.isEmpty() ? fallback : diagnostic.left(2048);
}

bool samePhysicalVault(const services::VaultFileIdentity& first,
    const services::VaultFileIdentity& second)
{
    // birthTime is optional evidence. The coordinator's established identity
    // contract uses the stable path/vault_id/device/inode tuple and requires
    // non-zero filesystem identities.
    return !first.path.isEmpty() && first.path == second.path
        && first.vaultId.size() == 16
        && first.vaultId == second.vaultId
        && first.device != 0 && first.inode != 0
        && first.device == second.device && first.inode == second.inode;
}

} // namespace

GenerationalBackupStatusController::GenerationalBackupStatusController(
    services::AutomaticBackupCoordinator& coordinator,
    services::GenerationalBackupRotationController& rotation,
    QWidget* parent)
    : QObject(parent), coordinator_(&coordinator), rotation_(&rotation),
      backupStatus_(tr("Aucune opération de sauvegarde observée.")),
      rotationStatus_(tr("Aucune rotation observée.")),
      configurationStatus_(tr("Configuration globale non encore vérifiée."))
{
    setObjectName(QStringLiteral("generationalBackupStatusController"));
    connect(&coordinator,
        &services::AutomaticBackupCoordinator::generationalBackupRequested,
        this, &GenerationalBackupStatusController::consumeOffer);
    connect(&coordinator,
        &services::AutomaticBackupCoordinator::generationalOperationStateChanged,
        this, &GenerationalBackupStatusController::consumeOperationState);
    connect(&coordinator,
        &services::AutomaticBackupCoordinator::mutationBatchSettled,
        this, &GenerationalBackupStatusController::consumeBackupResult);
    connect(&coordinator,
        &services::AutomaticBackupCoordinator::generationalBackupSuspensionChanged,
        this, &GenerationalBackupStatusController::consumeSuspension);
    connect(&rotation,
        &services::GenerationalBackupRotationController::rotationSettled,
        this, &GenerationalBackupStatusController::consumeRotation);
}

GenerationalBackupStatusController::~GenerationalBackupStatusController()
{
    delete dialog_.data();
}

void GenerationalBackupStatusController::setAuthenticatedVault(
    const services::VaultFileIdentity& vault)
{
    if (!trackedVault_ || *trackedVault_ != vault)
        resetForDifferentVault();
    trackedVault_ = vault;
    authenticatedSessionCurrent_ = true;
    if (coordinator_) {
        const auto state = coordinator_->generationalBackupSuspension(vault.path);
        if (state.suspended)
            consumeSuspension(state);
        else
            suspension_.reset();
    }
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::invalidateAuthenticatedSession() noexcept
{
    authenticatedSessionCurrent_ = false;
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::preferencesReadSettled(
    services::GlobalBackupPreferencesStatus status)
{
    using services::GlobalBackupPreferencesStatus;
    switch (status) {
    case GlobalBackupPreferencesStatus::Absent:
        configurationStatus_ = tr("Préférences globales absentes.");
        configurationAttentionRequired_ = true;
        break;
    case GlobalBackupPreferencesStatus::Valid:
        configurationStatus_ = tr(
            "Configuration enregistrée ; la destination doit encore être contrôlée lors de la sauvegarde.");
        configurationAttentionRequired_ = false;
        break;
    case GlobalBackupPreferencesStatus::Invalid:
        configurationStatus_ = tr("Préférences globales invalides ou incomplètes.");
        configurationAttentionRequired_ = true;
        break;
    case GlobalBackupPreferencesStatus::ReadError:
        configurationStatus_ = tr("Lecture sûre des préférences globales impossible.");
        configurationAttentionRequired_ = true;
        break;
    case GlobalBackupPreferencesStatus::WriteError:
        configurationStatus_ = tr("État de persistance des préférences non confirmé.");
        configurationAttentionRequired_ = true;
        break;
    }
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::preferencesWriteSettled(
    services::GlobalBackupPreferencesStatus status)
{
    preferencesReadSettled(status);
}

void GenerationalBackupStatusController::open()
{
    if (!dialog_) {
        auto* dialog = new GenerationalBackupStatusDialog(
            qobject_cast<QWidget*>(parent()));
        dialog_ = dialog;
        connect(dialog, &QDialog::finished, this, [this, dialog] {
            if (dialog_ == dialog) dialog_.clear();
            dialog->deleteLater();
        });
        connect(dialog->manualButton, &QPushButton::clicked,
            this, &GenerationalBackupStatusController::requestManualBackup);
        connect(dialog->retryButton, &QPushButton::clicked,
            this, &GenerationalBackupStatusController::requestRetry);
    }
    updateDialog();
    dialog_->show();
    dialog_->raise();
    dialog_->activateWindow();
}

bool GenerationalBackupStatusController::retryAvailable() const noexcept
{
    return authenticatedSessionCurrent_ && coordinator_
        && suspensionMatchesCurrentVault() && suspension_->suspended
        && !suspension_->resumeRequested && !suspension_->workerAlive
        && (suspension_->reason
                == services::GenerationalBackupSuspensionReason::Failed
            || suspension_->reason
                == services::GenerationalBackupSuspensionReason::Unknown);
}

bool GenerationalBackupStatusController::tracksPath(const QString& path) const
{
    return trackedVault_ && trackedVault_->path == path;
}

bool GenerationalBackupStatusController::suspensionMatchesCurrentVault() const noexcept
{
    return trackedVault_ && suspension_
        && suspension_->vaultPath == trackedVault_->path
        && suspension_->vaultId == trackedVault_->vaultId
        && suspension_->device == trackedVault_->device
        && suspension_->inode == trackedVault_->inode;
}

void GenerationalBackupStatusController::consumeOffer(
    services::GenerationalBackupRequestOffer offer)
{
    const bool validKindAndGeneration =
        offer.kind == services::GenerationalBackupRequestKind::CrudGeneration
        && offer.mutationGeneration != 0 && offer.sessionGeneration == 0;
    if (!trackedVault_ || offer.requestId == 0
        || offer.vaultPath != offer.vault.path
        || !samePhysicalVault(offer.vault, *trackedVault_)
        || !validKindAndGeneration
        || acceptedRequests_.contains(offer.requestId)
        || publishedRequests_.contains(offer.requestId))
        return;
    // Locking revokes retry and all authenticated actions, but it deliberately
    // retains this non-secret physical identity so an exact offer captured by
    // the shutdown drain can still be followed to its terminal result.
    ObservedRequest observed;
    observed.vault = offer.vault;
    observed.kind = offer.kind;
    observed.mutationGeneration = offer.mutationGeneration;
    observed.sessionGeneration = offer.sessionGeneration;
    acceptedRequests_.insert(offer.requestId, std::move(observed));
    terminalBackupResultObserved_ = false;
    backupStatus_ = tr("Sauvegarde en attente de démarrage.");
    backupDetail_.clear();
    backupAttentionRequired_ = false;
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::consumeOperationState(
    services::GenerationalOperationState state)
{
    using services::GenerationalOperationPhase;
    if (!tracksPath(state.vaultPath)) return;
    if (state.requestId != 0
        && !acceptedRequests_.contains(state.requestId))
        return;
    if (state.requestId == 0 && terminalBackupResultObserved_)
        return;

    switch (state.phase) {
    case GenerationalOperationPhase::PendingRequest:
    case GenerationalOperationPhase::OfferedRequest:
    case GenerationalOperationPhase::WaitingForReservation:
    case GenerationalOperationPhase::AttemptActive:
        backupStatus_ = tr("Sauvegarde en attente.");
        backupAttentionRequired_ = false;
        break;
    case GenerationalOperationPhase::WorkerActive:
        backupStatus_ = tr("Sauvegarde en cours.");
        backupAttentionRequired_ = false;
        break;
    case GenerationalOperationPhase::Idle:
    case GenerationalOperationPhase::Completed:
    case GenerationalOperationPhase::Cancelled:
        return; // Only the matching terminal result may qualify the outcome.
    }
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::consumeBackupResult(
    services::MutationBackupResult result)
{
    using services::BackupOutcome;
    using services::MutationBackupOutcome;
    const auto accepted = acceptedRequests_.constFind(result.requestId);
    if (!tracksPath(result.vaultPath) || result.requestId == 0
        || accepted == acceptedRequests_.cend()
        || accepted->vault.path != result.vaultPath
        || accepted->kind != result.kind
        || accepted->mutationGeneration != result.generation
        || accepted->sessionGeneration != result.sessionGeneration)
        return;

    const bool confirmedPublication =
        result.outcome == MutationBackupOutcome::Published
        && result.workerTerminated
        && result.workerOutcome == BackupOutcome::Published
        && result.confirmedPublicationResult
        && result.confirmedPublicationResult->outcome == BackupOutcome::Published
        && result.publication
        && result.publication->requestId == result.requestId
        && result.publication->generation == result.generation
        && result.publication->kind == result.kind
        && result.publication->sessionGeneration == result.sessionGeneration
        && result.publication->vaultPath == result.vaultPath
        && !result.publication->destination.isEmpty()
        && result.publication->evidence.permitsDeletion()
        && result.confirmedPublicationResult->receipt
        && result.confirmedPublicationResult->receipt->permitsDeletion()
        && *result.confirmedPublicationResult->receipt
            == result.publication->evidence
        && result.confirmedPublicationResult->publishedPath
            == result.publication->destination;
    ObservedRequest observed = *accepted;
    acceptedRequests_.erase(accepted);
    terminalBackupResultObserved_ = true;
    if (confirmedPublication) {
        observed.publishedPath = result.publication->destination;
        publishedRequests_.insert(result.requestId, std::move(observed));
        backupStatus_ = tr("Sauvegarde publiée et confirmée.");
        backupDetail_ = diagnosticOr(std::move(result.diagnostic),
            tr("Le worker est terminé et la publication a été validée."));
        backupAttentionRequired_ = false;
    } else if (result.workerOutcome
            == BackupOutcome::CancelledBeforePublication) {
        backupStatus_ = tr("Sauvegarde annulée avant publication.");
        backupDetail_ = diagnosticOr(std::move(result.diagnostic),
            tr("Aucune publication n'est confirmée."));
        backupAttentionRequired_ = false;
    } else if (result.outcome == MutationBackupOutcome::Failed) {
        backupStatus_ = tr("Sauvegarde échouée.");
        backupDetail_ = diagnosticOr(std::move(result.diagnostic),
            tr("Aucune publication n'est confirmée."));
        backupAttentionRequired_ = true;
    } else {
        backupStatus_ = tr(
            "Résultat de sauvegarde incertain ; la réussite ne peut pas être garantie.");
        backupDetail_ = diagnosticOr(std::move(result.diagnostic),
            result.workerOutcome == BackupOutcome::DurabilityUnconfirmed
                ? tr("La durabilité de la publication n'est pas confirmée.")
                : tr("Aucune publication confirmée ne peut être déduite du résultat."));
        backupAttentionRequired_ = true;
    }
    lastBackupResultStatus_ = backupStatus_;
    lastBackupResultDetail_ = backupDetail_;
    if (!confirmedPublication)
        deferredRotationResults_.remove(result.requestId);
    if (suspensionMatchesCurrentVault() && suspension_->suspended) {
        if (result.workerOutcome == BackupOutcome::CancelledBeforePublication)
            backupStatus_ = tr(
                "Sauvegarde annulée avant publication ; sauvegardes automatiques suspendues.");
        else if (result.outcome == MutationBackupOutcome::Failed)
            backupStatus_ = tr(
                "Sauvegarde échouée ; sauvegardes automatiques suspendues.");
        else if (result.outcome == MutationBackupOutcome::Unknown)
            backupStatus_ = tr(
                "Résultat incertain ; sauvegardes automatiques suspendues.");
        backupAttentionRequired_ = true;
    }
    updateDialog();
    publishPresentation();
    if (publishedRequests_.contains(result.requestId)
        && deferredRotationResults_.contains(result.requestId))
        consumeRotation(deferredRotationResults_.take(result.requestId));
}

void GenerationalBackupStatusController::consumeSuspension(
    services::GenerationalBackupSuspensionState state)
{
    if (!trackedVault_ || state.vaultPath != trackedVault_->path
        || state.vaultId != trackedVault_->vaultId
        || state.device != trackedVault_->device
        || state.inode != trackedVault_->inode)
        return;
    if (!state.suspended) {
        suspension_.reset();
    } else {
        suspension_ = std::move(state);
        if (suspension_->reason
            == services::GenerationalBackupSuspensionReason::Unknown)
            backupStatus_ = tr("Sauvegardes automatiques suspendues après un résultat incertain.");
        else
            backupStatus_ = tr("Sauvegardes automatiques suspendues après un échec.");
        backupDetail_ = diagnosticOr(suspension_->diagnostic,
            tr("Une reprise explicite est nécessaire."));
        backupAttentionRequired_ = true;
    }
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::consumeRotation(
    services::GenerationalBackupRotationResult result)
{
    using services::BackupSeriesRotationOutcome;
    if (result.requestId == 0)
        return;
    const auto published = publishedRequests_.constFind(result.requestId);
    if (published == publishedRequests_.cend()) {
        const auto accepted = acceptedRequests_.constFind(result.requestId);
        if (accepted != acceptedRequests_.cend()
            && accepted->kind == result.kind
            && accepted->mutationGeneration == result.generation
            && accepted->sessionGeneration == result.sessionGeneration)
            deferredRotationResults_.insert(result.requestId,
                std::move(result));
        return;
    }
    if (published->kind != result.kind
        || published->mutationGeneration != result.generation
        || published->sessionGeneration != result.sessionGeneration
        || published->publishedPath != result.publishedPath)
        return;
    publishedRequests_.erase(published);
    rotationAttentionRequired_ = false;
    switch (result.rotation.outcome) {
    case BackupSeriesRotationOutcome::NoRotationNecessary:
        rotationStatus_ = tr("Aucune rotation nécessaire.");
        break;
    case BackupSeriesRotationOutcome::Complete:
        rotationStatus_ = tr("Rotation terminée.");
        break;
    case BackupSeriesRotationOutcome::Refused:
        rotationStatus_ = tr("Rotation refusée avant suppression confirmée.");
        break;
    case BackupSeriesRotationOutcome::Partial:
        rotationStatus_ = tr("Rotation partielle ; certaines anciennes versions restent présentes.");
        break;
    case BackupSeriesRotationOutcome::DeletionDurabilityUnconfirmed:
        rotationStatus_ = tr("Suppression effectuée, mais durabilité non confirmée.");
        break;
    case BackupSeriesRotationOutcome::Unknown:
        rotationStatus_ = tr("Résultat de rotation inconnu.");
        break;
    }
    rotationDetail_ = result.rotation.diagnostic.left(2048);
    if (result.rotation.outcome == BackupSeriesRotationOutcome::Refused
        || result.rotation.outcome == BackupSeriesRotationOutcome::Partial
        || result.rotation.outcome
            == BackupSeriesRotationOutcome::DeletionDurabilityUnconfirmed
        || result.rotation.outcome == BackupSeriesRotationOutcome::Unknown)
        rotationAttentionRequired_ = true;
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::requestManualBackup()
{
    if (!authenticatedSessionCurrent_ || !coordinator_ || !trackedVault_)
        return;
    QString diagnostic;
    if (!coordinator_->requestGenerationalBackup(trackedVault_->path,
            diagnostic)) {
        // Do not overwrite an in-flight or confirmed result on a duplicate
        // click. The request was refused, not a failed publication.
        backupDetail_ = tr("Demande manuelle refusée : %1").arg(diagnosticOr(
            std::move(diagnostic), tr("Sauvegarde indisponible.")));
        backupAttentionRequired_ = true;
    } else {
        backupStatus_ = tr("Sauvegarde manuelle demandée ; admission en attente.");
        backupDetail_.clear();
        backupAttentionRequired_ = false;
    }
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::requestRetry()
{
    if (!retryAvailable() || !coordinator_ || !trackedVault_) return;
    // Re-sample immediately before the authoritative call. The coordinator
    // then reopens the path, checks vault_id/device/inode and refuses a live
    // predecessor or duplicate request itself.
    const auto current = coordinator_->generationalBackupSuspension(
        trackedVault_->path);
    suspension_ = current.suspended
        ? std::optional<services::GenerationalBackupSuspensionState>(current)
        : std::nullopt;
    if (!retryAvailable()) {
        updateDialog();
        publishPresentation();
        return;
    }
    QString diagnostic;
    if (!coordinator_->resumeGenerationalBackup(trackedVault_->path,
            diagnostic)) {
        backupStatus_ = tr("Reprise de sauvegarde refusée.");
        backupDetail_ = diagnosticOr(std::move(diagnostic),
            tr("La suspension n'est plus admissible à une reprise."));
        backupAttentionRequired_ = true;
    } else {
        backupStatus_ = tr("Reprise explicitement demandée ; nouvelle admission en attente.");
        backupDetail_.clear();
        backupAttentionRequired_ = false;
    }
    updateDialog();
    publishPresentation();
}

void GenerationalBackupStatusController::resetForDifferentVault()
{
    suspension_.reset();
    acceptedRequests_.clear();
    publishedRequests_.clear();
    deferredRotationResults_.clear();
    terminalBackupResultObserved_ = false;
    backupStatus_ = tr("Aucune opération de sauvegarde observée pour ce coffre.");
    backupDetail_.clear();
    lastBackupResultStatus_.clear();
    lastBackupResultDetail_.clear();
    rotationStatus_ = tr("Aucune rotation observée pour ce coffre.");
    rotationDetail_.clear();
    backupAttentionRequired_ = false;
    rotationAttentionRequired_ = false;
}

void GenerationalBackupStatusController::updateDialog()
{
    if (!dialog_) return;
    dialog_->findChild<QLabel*>(
        QStringLiteral("generationalBackupStateLabel"))->setText(backupStatus_);
    QString presentedBackupDetail = backupDetail_;
    if (!lastBackupResultStatus_.isEmpty()
        && backupStatus_ != lastBackupResultStatus_) {
        if (!presentedBackupDetail.isEmpty())
            presentedBackupDetail += QStringLiteral("\n\n");
        presentedBackupDetail += tr("Dernier résultat terminal : %1")
            .arg(lastBackupResultStatus_);
        if (!lastBackupResultDetail_.isEmpty())
            presentedBackupDetail += QStringLiteral("\n")
                + lastBackupResultDetail_;
    }
    dialog_->findChild<QLabel*>(
        QStringLiteral("generationalBackupDetailLabel"))->setText(
            presentedBackupDetail);
    dialog_->findChild<QLabel*>(
        QStringLiteral("generationalRotationStateLabel"))->setText(rotationStatus_);
    dialog_->findChild<QLabel*>(
        QStringLiteral("generationalRotationDetailLabel"))->setText(rotationDetail_);
    dialog_->findChild<QLabel*>(
        QStringLiteral("generationalConfigurationStateLabel"))->setText(configurationStatus_);
    dialog_->findChild<QLabel*>(
        QStringLiteral("generationalConfigurationDetailLabel"))->setText(
            tr("Une configuration enregistrée ne prouve ni l'accessibilité de la destination, ni une publication."));
    dialog_->findChild<QPushButton*>(
        QStringLiteral("generationalBackupManualButton"))->setEnabled(
            authenticatedSessionCurrent_ && coordinator_ && trackedVault_
            && !suspensionMatchesCurrentVault());
    dialog_->findChild<QPushButton*>(
        QStringLiteral("generationalBackupRetryButton"))->setEnabled(
            retryAvailable());
}

void GenerationalBackupStatusController::publishPresentation()
{
    QString summary = backupStatus_;
    if (summary.isEmpty()) summary = tr("État des sauvegardes disponible.");
    emit presentationChanged(std::move(summary),
        backupAttentionRequired_ || rotationAttentionRequired_
            || configurationAttentionRequired_);
}

} // namespace passwall::gui
