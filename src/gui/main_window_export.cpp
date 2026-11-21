#include "gui/main_window.hpp"
#include "gui/vault_export_dialog.hpp"
#include "services/backup_job.hpp"
#include "services/automatic_backup_coordinator.hpp"
#include "ui_main_window.h"

#include <QCloseEvent>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QPushButton>
#include <QScopeGuard>
#include <QStatusBar>

namespace passwall::gui {
namespace {
QString absoluteSourcePath(const QString& path)
{
    // Preserve symlinks and dot components for the engine's strict checks.
    // QFileInfo::canonicalFilePath/cleanPath would silently reinterpret them.
    if (path.isEmpty() || QDir::isAbsolutePath(path)) return path;
    return QDir::currentPath() + QLatin1Char('/') + path;
}
}
bool MainWindow::hasOpenCredentialEditor() const
{
    // CRUD commits synchronously; only modal editors hold unsaved credentials.
    // Refuse even an unchanged editor rather than silently discard its fields.
    return !findChildren<QDialog*>(QStringLiteral("credentialEditorDialog")).isEmpty();
}
void MainWindow::updateExportAction()
{
    if (automaticBackup_) automaticBackup_->setPaused(exportInProgress_ || exportCloseRequested_
        || externalLockBlocksAccess()
        || vaultLockInProgress_ || externalLockReplyInProgress_ || !externalLockRequests_.empty()
        || !lifecycleProtectionAvailable_ || hasOpenCredentialEditor());
    // Presentation only: do not poll/invalidate lifecycle protection while
    // updating a widget. Every real export boundary validates it explicitly.
    const bool automaticOperationCompatible = !automaticBackup_
        || automaticBackup_->admitUserOperation(
            services::BackupUserOperation::ManualExport, vaultPath_).compatible;
    const bool historicalAutomaticWorker = automaticBackup_
        && automaticBackup_->triggerMode()
            == services::BackupTriggerMode::Historical
        && automaticBackup_->isActive();
    ui_->exportVaultButton->setEnabled(!exportInProgress_ && !exportCloseRequested_
        && !historicalAutomaticWorker
        && automaticOperationCompatible
        && !hasOpenCredentialEditor() && lifecycleProtectionAvailable_
        && !externalLockBlocksAccess() && !vaultLockInProgress_
        && !vaultPath_.isEmpty() && !dataKey_.empty() && sessionGeneration_ != 0);
}
bool MainWindow::exportAuthorizationCurrent(native::VaultLease lease, const QString& source)
{
    return !exportCloseRequested_ && !vaultLockInProgress_ && ensureLifecycleProtection()
        && isLeaseCurrent(lease) && absoluteSourcePath(vaultPath_) == source && !hasOpenCredentialEditor();
}
void MainWindow::exportVault()
{
    if (automaticBackup_
        && automaticBackup_->triggerMode()
            == services::BackupTriggerMode::Historical
        && automaticBackup_->isActive()) {
        statusBar()->showMessage(tr("Une sauvegarde automatique est déjà en cours."));
        return;
    }
    if (exportInProgress_ || exportCloseRequested_ || !ensureLifecycleProtection()) return;
    if (hasOpenCredentialEditor()) {
        statusBar()->showMessage(tr("Terminez ou annulez l'édition en cours avant d'exporter le coffre."));
        return;
    }
    const auto lease = acquireLease();
    const QString source = absoluteSourcePath(vaultPath_); // Non-secret authorization context only.
    if (!lease.unlocked || source.isEmpty()) return;
    if (automaticBackup_) {
        const auto admission = automaticBackup_->admitUserOperation(
            services::BackupUserOperation::ManualExport, source);
        if (!admission.compatible) {
            statusBar()->showMessage(admission.diagnostic);
            return;
        }
    }
    const QPointer<MainWindow> guarded(this);
    exportInProgress_ = true;
    bool handedOff = false;
    const auto reset = qScopeGuard([guarded, &handedOff] {
        if (guarded && !handedOff) {
            guarded->exportInProgress_ = false;
            guarded->exportLockPending_ = false;
            guarded->updateExportAction();
        }
    });
    updateExportAction();
    QString destination;
    {
        QFileDialog selection(this, tr("Exporter le coffre"), QFileInfo(source).absolutePath(),
            tr("Coffres PassWall (*.pwdb);;Tous les fichiers (*)"));
        selection.setObjectName(QStringLiteral("vaultExportDestinationDialog"));
        selection.setAcceptMode(QFileDialog::AcceptSave);
        selection.setFileMode(QFileDialog::AnyFile);
        selection.setDefaultSuffix(QStringLiteral("pwdb"));
        selection.setOption(QFileDialog::DontConfirmOverwrite);
        selection.setOption(QFileDialog::DontResolveSymlinks);
        // No probe/open/write/canonicalization by PassWall here. All definitive
        // destination checks and publication remain in VaultSnapshotService.
        if (selection.exec() != QDialog::Accepted || !guarded) return;
        const auto files = selection.selectedFiles();
        if (files.size() != 1) return;
        destination = files.front();
    }
    if (!guarded || destination.isEmpty() || !exportAuthorizationCurrent(lease, source)) return;
    {
        QMessageBox confirmation(QMessageBox::Question, tr("Exporter le coffre"),
            tr("Pour protéger vos données, PassWall va verrouiller votre coffre avant de créer la sauvegarde. "
               "Vous devrez le déverrouiller à nouveau pour accéder à vos identifiants."),
            QMessageBox::NoButton, this);
        confirmation.setObjectName(QStringLiteral("vaultExportConfirmationDialog"));
        confirmation.setTextFormat(Qt::PlainText);
        auto* cancel = confirmation.addButton(tr("Annuler"), QMessageBox::RejectRole);
        auto* save = confirmation.addButton(tr("Verrouiller et sauvegarder"), QMessageBox::AcceptRole);
        save->setObjectName(QStringLiteral("vaultExportConfirmButton"));
        confirmation.setDefaultButton(cancel);
        confirmation.setEscapeButton(cancel);
        confirmation.exec();
        if (!guarded || confirmation.clickedButton() != save) return;
    }
    // The dialogs may run nested Qt loops. Same path is insufficient: require
    // the original generation, current lifecycle protection and no editor.
    if (!exportAuthorizationCurrent(lease, source)) return;
    QString admissionError;
    std::shared_ptr<services::ManualBackupOperationAdmission> manualAdmission;
    if (automaticBackup_
        && automaticBackup_->triggerMode()
            == services::BackupTriggerMode::Generational) {
        auto admission = automaticBackup_->acquireUserOperation(
            services::BackupUserOperation::ManualExport, source,
            admissionError);
        if (!admission.valid()) {
            statusBar()->showMessage(admissionError.isEmpty()
                ? tr("Export différé : une sauvegarde automatique a pris la priorité.")
                : admissionError);
            return;
        }
        try {
            manualAdmission = std::make_shared<
                services::ManualBackupOperationAdmission>(std::move(admission));
        } catch (...) {
            statusBar()->showMessage(
                tr("Impossible de conserver l'admission de l'export."));
            return;
        }
    }
    exportLockPending_ = true;
    requestExternalLock([guarded, source, destination,
                         manualAdmission = std::move(manualAdmission)](bool cleaned) mutable {
        if (!guarded) return;
        guarded->exportLockPending_ = false;
        if (!cleaned || guarded->exportCloseRequested_) {
            guarded->exportInProgress_ = false;
            guarded->updateExportAction();
            if (guarded->exportCloseRequested_) guarded->queueExportClose();
            else guarded->statusBar()->showMessage(guarded->tr("Verrouillage non confirmé : sauvegarde non démarrée."));
            return;
        }
        // The existing acknowledgement runs only after the OUTER lock returned,
        // and blocks fresh sessions through the end of this callback.
        guarded->startVaultExport(source, destination,
            std::move(manualAdmission));
    });
    handedOff = true;
}
void MainWindow::startVaultExport(const QString& source, const QString& destination,
    std::shared_ptr<services::ManualBackupOperationAdmission> admission)
{
    if (!isFullyLocked() || exportCloseRequested_ || backupJob_) {
        exportInProgress_ = false;
        updateExportAction();
        statusBar()->showMessage(tr("Verrouillage non confirmé : sauvegarde non démarrée."));
        return;
    }
    auto* dialog = new VaultExportDialog;
    exportUncertain_ = false;
    exportDialog_ = dialog;
    connect(dialog, &VaultExportDialog::cancellationRequested, this, &MainWindow::cancelVaultExport);
    connect(dialog, &QDialog::finished, this, [this, dialog] {
        if (exportDialog_ != dialog) return;
        exportDialog_.clear();
        if (exportCloseRequested_ && exportUncertain_ && backupJob_) {
            // Explicit acknowledgement permits closing the facade, NOT freeing
            // the supervisor/child's reservation or claiming that it stopped.
            backupJob_->cancel();
            backupJob_->deleteLater();
            backupJob_.clear();
        }
        exportInProgress_ = backupJob_ && backupJob_->isActive();
        updateExportAction();
        if (exportCloseRequested_) queueExportClose();
    });
    // No override in production: an explicit controlled sibling, never PATH.
    auto* job = new services::BackupJob(services::BackupJob::siblingWorkerPath(), this);
    backupJob_ = job;
    connect(job, &services::BackupJob::processTerminated, this, [this, job] {
        if (backupJob_ != job) return;
        backupJob_.clear();
        job->deleteLater();
        if (!exportDialog_) exportInProgress_ = false;
        updateExportAction();
        if (exportCloseRequested_ && !exportDialog_) queueExportClose();
    });
    connect(job, &services::BackupJob::finished, this, [this, job, dialog = QPointer(dialog)](services::BackupResult result) {
        if (backupJob_ != job) return;
        exportUncertain_ = result.outcome == services::BackupOutcome::Unknown;
        if (!job->isActive()) {
            backupJob_.clear();
            job->deleteLater();
        }
        if (dialog) dialog->showResult(result, exportCloseRequested_);
        if (exportCloseRequested_) {
            if (result.outcome == services::BackupOutcome::Unknown ||
                result.outcome == services::BackupOutcome::DurabilityUnconfirmed) {
                // Keep a nonmodal notice for explicit acknowledgement. Never
                // disguise an uncertain close as a confirmed cancellation.
                if (dialog) dialog->show();
                else queueExportClose();
            } else {
                if (dialog) dialog->accept();
                queueExportClose();
            }
        }
    });
    // No GUI event processing between confirmation of cleanup and start().
    // Its deferred child launch happens only after this callback returns.
    QString admittedStartError;
    const bool started = admission && admission->generational()
        ? admission->startExport(*job, source, destination,
            admittedStartError)
        : job->start(source, destination);
    if (!started) {
        backupJob_.clear();
        job->deleteLater();
        dialog->showResult({services::BackupOutcome::FailedBeforePublication,
            admittedStartError.isEmpty() ? job->startError()
                                         : admittedStartError}, false);
    }
    dialog->show(); // Modeless, no nested loop during backup.
}
void MainWindow::cancelVaultExport()
{
    if (backupJob_) {
        if (exportDialog_) exportDialog_->cancellationPending();
        backupJob_->cancel();
    }
}
void MainWindow::queueExportClose()
{
    QTimer::singleShot(0, this, [this] { close(); });
}
void MainWindow::queueGenerationalDrainClose()
{
    if (generationalDrainCloseQueued_)
        return;
    generationalDrainCloseQueued_ = true;
    QTimer::singleShot(0, this, [this] {
        generationalDrainCloseQueued_ = false;
        close();
    });
}
void MainWindow::closeEvent(QCloseEvent* event)
{
    exportCloseRequested_ = true; // Fail-closed while asynchronous close runs.
    // The independent restore supervisor outlives this facade/window. Closing
    // requests cancellation, never waits in a QProcess destructor or reports a
    // positive cleanup acknowledgement while an unconfirmed child holds secrets.
    if (restoreJob_) restoreJob_->cancel();
    const bool generational = automaticBackup_
        && automaticBackup_->triggerMode()
            == services::BackupTriggerMode::Generational;
    if (generational) {
      const bool firstDrainClose = !generationalCloseDrainRequested_;
      const auto drainState = automaticBackup_->generationalShutdownDrainState();
      const bool terminal = drainState.status
	== services::GenerationalShutdownDrainStatus::Completed
	|| drainState.status
	== services::GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension;
      if (!generationalCloseDrainRequested_ || !terminal) {
	event->ignore();
	ui_->centralwidget->setEnabled(false);
	if (!generationalCloseDrainRequested_) {
	  generationalCloseDrainRequested_ = true;
	  QString drainError;
	  if (!automaticBackup_->beginGenerationalShutdownDrain(drainError)) {
	    // No progressive state can be supervised.  Fall back to
	    // the pre-existing fail-closed shutdown path; do not
	    // claim that an unstarted generation was saved.
	    automaticBackup_->shutdown();
                    if (!automaticBackup_->canClose())
                        return;
                    queueGenerationalDrainClose();
                    return;
                }
            }
            // lockVault() captures a committed generation before clearing the
            // session, synchronously wipes keys and prevents new GUI work.
            // The drain has already captured the current generation, but its
            // queued dispatch still cannot run before this cleanup returns.
            if (firstDrainClose) lockVault();
            const auto current = automaticBackup_->generationalShutdownDrainState();
            if (current.status == services::GenerationalShutdownDrainStatus::Completed
                || current.status == services::GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension)
                queueGenerationalDrainClose();
            return;
        }
        // A terminal drain has no active worker.  Do not call shutdown(): its
        // immediate semantics are intentionally distinct from the drain.
        externalLockClosing_ = true;
        lockVault();
        if (exportDialog_) exportDialog_->accept();
        QMainWindow::closeEvent(event);
        return;
    }
    // Capture the last committed generation synchronously before entering the
    // fail-closed window state. Delivery remains deferred and cannot delay the
    // cleanup below.
    if (automaticBackup_ && !vaultPath_.isEmpty())
        automaticBackup_->requestPendingMutationsForLock(vaultPath_);
    if (automaticBackup_ && !automaticBackup_->canClose()) {
        automaticBackup_->shutdown();
        if (!automaticBackup_->canClose()) {
            event->ignore();
            // Secret cleanup and Native Messaging invalidation never wait for
            // actual child termination.
            lockVault();
            return;
        }
    }
    if (backupJob_ && exportUncertain_ && !exportDialog_) {
        // Unknown was already presented and acknowledged. The independent
        // supervisor and inherited kernel locks outlive this facade/window.
        backupJob_->cancel();
        backupJob_->deleteLater();
        backupJob_.clear();
    }
    if (backupJob_ || exportLockPending_ || vaultLockInProgress_) {
        event->ignore();
        ui_->centralwidget->setEnabled(false);
        cancelVaultExport(); // BEFORE Qt can leave its event loop.
        if (vaultLockInProgress_) {
            const QPointer<MainWindow> guarded(this);
            requestExternalLock([guarded](bool) { if (guarded) guarded->queueExportClose(); });
        } else {
            lockVault();
        }
        return; // completion/cancellation escalation drives the next close.
    }
    externalLockClosing_ = true;
    lockVault();
    if (exportDialog_) exportDialog_->accept();
    QMainWindow::closeEvent(event);
}
} // namespace passwall::gui
