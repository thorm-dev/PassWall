#include "gui/vault_backup_settings_controller.hpp"
#include "gui/vault_backup_settings_dialog.hpp"
#include "gui/main_window.hpp"
#include <QThread>
#include <QTimer>
#include <QWindow>
#include <algorithm>

namespace passwall::gui {
namespace {
// No secret, widget or borrowed GUI pointer in work; queued delivery is on GUI.
// Independent lifetimes: destroying a window never waits for filesystem I/O.
void run(std::function<void()> work, std::function<void()> complete)
{
    auto* delivery = new QObject;
    auto* task = QThread::create([work = std::move(work)] { work(); });
    QObject::connect(task, &QThread::finished, delivery, [task, delivery, complete = std::move(complete)] {
        try { complete(); } catch (...) { /* No exception escapes a Qt callback. */ }
        task->deleteLater(); delivery->deleteLater();
    }, Qt::QueuedConnection);
    task->start();
}
bool sameSelection(const services::VaultRegistration& a, const services::VaultRegistration& b)
{ return a.localId == b.localId && a.file == b.file && a.backup == b.backup; }
}
VaultBackupSettingsController::VaultBackupSettingsController(MainWindow& owner) : QObject(&owner), owner_(owner)
{
    auto* coordinator = owner_.automaticBackup_;
    connect(&services::VaultPreferencesStore::events(), &services::VaultPreferencesEvents::changed, this,
        [this](const QString& path, const QString&, const QString&, bool) { if (path == store_.fileName()) refresh(); }, Qt::QueuedConnection);
    connect(coordinator, &services::AutomaticBackupCoordinator::notification, this, [this](const QString& id, const QString& text) {
        diagnostics_[id] = text.left(2048); refresh();
    });
    connect(coordinator, &services::AutomaticBackupCoordinator::completed, this, [this](const QString& id, auto result) {
        results_[id] = result; refresh();
    });
    connect(coordinator, &services::AutomaticBackupCoordinator::copyConfirmed, this, [this] { refresh(); });
    connect(coordinator, &services::AutomaticBackupCoordinator::rotationCompleted, this, [this] { refresh(); });
    connect(coordinator, &services::AutomaticBackupCoordinator::activityChanged, this, [this](bool active) {
        if (active) {
            const auto id = owner_.automaticBackup_->activeVaultId();
            results_.remove(id); diagnostics_.remove(id); // New attempt, not a new persistent authorization.
        }
        refresh();
    });
    connect(coordinator, &services::AutomaticBackupCoordinator::deferred, this, [this] { refresh(); });
}
VaultBackupSettingsController::~VaultBackupSettingsController() { delete dialog_.data(); }
void VaultBackupSettingsController::open()
{
    if (dialog_) { dialog_->show(); dialog_->raise(); dialog_->activateWindow(); return; }
    dialog_ = new VaultBackupSettingsDialog; displayed_.reset(); current_.reset(); ++selection_;
    connect(dialog_, &QDialog::finished, this, [this, closed = dialog_.data()] {
        ++selection_; ++read_; QObject::disconnect(closed, nullptr, this, nullptr); dialog_.clear();
    });
    connect(dialog_, &VaultBackupSettingsDialog::selectionChanged, this, [this] {
        ++selection_; displayed_.reset(); current_.reset(); dialog_->setPreferences({}); dialog_->feedback({}); load(true);
    });
    connect(dialog_, &VaultBackupSettingsDialog::reloadRequested, this, [this] {
        ++selection_; displayed_.reset(); dialog_->feedback({}); load(true);
    });
    connect(dialog_, &VaultBackupSettingsDialog::saveRequested, this, &VaultBackupSettingsController::save);
    connect(dialog_, &VaultBackupSettingsDialog::resumeRequested, this, &VaultBackupSettingsController::resume);
    connect(dialog_, &VaultBackupSettingsDialog::draftChanged, this, &VaultBackupSettingsController::updateActions);
    dialog_->show();
    if (dialog_->windowHandle() && owner_.windowHandle())
        dialog_->windowHandle()->setTransientParent(owner_.windowHandle());
    load(true);
}
void VaultBackupSettingsController::refresh()
{
    if (!dialog_ || writing_ || refreshQueued_) return;
    refreshQueued_ = true;
    QTimer::singleShot(0, this, [this] { refreshQueued_ = false; if (dialog_ && !writing_) load(false); });
}
void VaultBackupSettingsController::load(bool resetForm)
{
    if (!dialog_) return;
    struct Listing { QVector<services::VaultRegistration> records; QString error; bool ok = false; };
    auto listing = std::make_shared<Listing>(); const auto store = store_;
    const auto serial = ++read_; const auto selection = selection_; const auto id = dialog_->selectedId();
    reading_ = true; dialog_->setActions(false, false);
    const QPointer<VaultBackupSettingsController> guarded(this);
    run([store, listing] {
        try { listing->ok = store.listForDisplay(listing->records, listing->error); }
        catch (...) { listing->error = QStringLiteral("Lecture du registre impossible ; aucune réinitialisation."); }
    }, [guarded, serial, selection, id, listing, resetForm] {
        if (!guarded) return;
        if (!guarded->dialog_ || guarded->read_ != serial || guarded->selection_ != selection) {
            emit guarded->readSettled(false); return;
        }
        guarded->reading_ = false;
        if (!listing->ok) {
            guarded->current_.reset(); guarded->dialog_->state(listing->error, {});
            guarded->updateActions(); emit guarded->readSettled(true); return;
        }
        guarded->dialog_->setRecords(listing->records, id);
        const auto found = std::find_if(listing->records.cbegin(), listing->records.cend(), [&](const auto& r) { return r.localId == id; });
        guarded->current_.reset();
        if (found != listing->records.cend()) {
            guarded->current_ = *found;
            if (resetForm || !guarded->displayed_) {
                guarded->displayed_ = *found; guarded->dialog_->setPreferences(found->backup);
            }
        } else guarded->dialog_->state(listing->records.isEmpty()
            ? tr("Aucun coffre principal enregistré.") : tr("Sélectionnez explicitement le coffre principal concerné."), {});
        guarded->updateActions(); emit guarded->readSettled(true);
    });
}
void VaultBackupSettingsController::updateActions()
{
    if (!dialog_) return;
    if (!current_) { dialog_->setActions(false, false); return; }
    const auto& record = *current_; const auto* coordinator = owner_.automaticBackup_;
    const bool active = coordinator->activeVaultId() == record.localId;
    const bool pending = coordinator->resumePending(record.localId);
    const bool stale = !displayed_ || !sameSelection(record, *displayed_);
    services::VaultBackupPreferences draft;
    const bool edited = !dialog_->preferences(draft) || draft != record.backup;
    const bool usable = !reading_ && !writing_ && !stale && !record.replacement
        && !active && !pending && !coordinator->isClosing() && !owner_.exportCloseRequested_;
    dialog_->setActions(usable, usable && !edited && record.backup.automatic && record.automaticSuspended);
    QString state;
    if (record.replacement) state = tr("Récupération de restauration nécessaire : préférences et reprise bloquées.");
    else if (active) state = results_.contains(record.localId) && results_[record.localId].outcome == services::BackupOutcome::Unknown
        ? tr("Résultat incertain ; processus encore actif. Réservation conservée, reprise interdite pour l'instant.")
        : tr("Sauvegarde ou rotation en cours ; attente de la terminaison effective du processus.");
    else if (pending) state = tr("Reprise demandée, en attente des protections ou d'une opération incompatible ; aucune réussite confirmée.");
    else if (!record.backup.automatic) state = tr("Sauvegardes automatiques désactivées.");
    else if (record.automaticSuspended) {
        if (results_.contains(record.localId)) {
            const auto result = results_[record.localId];
            if (result.outcome == services::BackupOutcome::Unknown || result.outcome == services::BackupOutcome::DurabilityUnconfirmed)
                state = tr("Sauvegardes suspendues après résultat incertain ; reprise explicite nécessaire.");
            else if (result.outcome == services::BackupOutcome::FailedBeforePublication || result.outcome == services::BackupOutcome::CancelledBeforePublication)
                state = tr("Sauvegardes suspendues après échec ou annulation ; reprise explicite nécessaire.");
            else state = tr("Suspension persistante après incident ou résultat non confirmé ; reprise explicite nécessaire.");
        } else state = tr("Suspension persistante après incident ou résultat non confirmé ; reprise explicite nécessaire.");
        if (diagnostics_.contains(record.localId)) state += '\n' + diagnostics_[record.localId];
    } else if (record.backupRequired) state = tr("Activées ; sauvegarde nécessaire ou en attente. La destination sera recontrôlée avant la copie.");
    else if (results_.contains(record.localId) && (results_[record.localId].outcome == services::BackupOutcome::Unknown
        || results_[record.localId].outcome == services::BackupOutcome::DurabilityUnconfirmed))
        state = tr("Dernière tentative observée au résultat incertain ; vérifiez le registre avant toute conclusion de réussite.");
    else state = tr("Activées ; aucune modification en attente. La destination sera recontrôlée à chaque tentative.");
    if (stale) state += tr("\nL'identité ou les préférences ont changé : actualisez pour revalider les valeurs affichées.");
    else if (edited) state += tr("\nModifications non enregistrées : enregistrez-les avant de demander une reprise.");
    if (coordinator->isPaused() && record.backup.automatic) state += tr("\nCoordination différée par l'état actuel de l'application.");
    const auto rotation = record.rotationAttempt.isEmpty() ? tr("Rotation : aucun blocage enregistré.")
        : active ? tr("Rotation : opération en cours ou à confirmer ; aucune suppression n'est autorisée par ce dialogue.")
        : tr("Suppressions de rotation bloquées ou non confirmées. Cela n'interdit pas à lui seul les nouvelles copies ; aucune remise à zéro ici.");
    dialog_->state(state, rotation);
}
void VaultBackupSettingsController::save()
{
    if (!dialog_ || !displayed_ || !current_ || reading_ || writing_ || current_->replacement
        || !sameSelection(*displayed_, *current_) || owner_.automaticBackup_->isClosing()
        || owner_.exportCloseRequested_ || owner_.automaticBackup_->activeVaultId() == current_->localId
        || owner_.automaticBackup_->resumePending(current_->localId)) return;
    services::VaultBackupPreferences preferences;
    if (!dialog_->preferences(preferences)) { dialog_->feedback(tr("Le nombre de versions doit être un entier de 1 à 2 147 483 647.")); return; }
    const auto expected = *displayed_; const auto store = store_; const auto selected = selection_;
    struct Written { bool saved = false; QString error; }; auto result = std::make_shared<Written>();
    writing_ = true; dialog_->setActions(false, false); dialog_->feedback(tr("Validation et enregistrement en cours…"));
    const QPointer<VaultBackupSettingsController> guarded(this);
    run([store, expected, preferences, result] {
        try {
            if (preferences.automatic) {
                services::SnapshotDirectoryIdentity identity; std::string error;
                if (!services::VaultSnapshotService::inspectDestinationDirectory(preferences.directory.toStdString(), identity, error)) {
                    result->error = QString::fromStdString(error); return;
                }
            }
            result->saved = store.updatePreferencesIfCurrent(expected, preferences, result->error);
        } catch (...) { result->error = QStringLiteral("Enregistrement interrompu ; persistance non confirmée."); }
    }, [guarded, selected, expected, result] {
        if (!guarded) return;
        guarded->writing_ = false;
        const bool same = guarded->dialog_ && guarded->selection_ == selected
            && guarded->dialog_->selectedId() == expected.localId;
        if (same) guarded->dialog_->feedback(result->saved
            ? tr("Préférences enregistrées durablement. L'état de la sauvegarde est indiqué séparément ; une suspension n'est pas levée.")
            : tr("Enregistrement refusé ou non confirmé. Des changements peuvent être visibles après une erreur de persistance.\n") + result->error);
        if (guarded->dialog_) guarded->load(same && result->saved);
        emit guarded->writeSettled(expected.localId, result->saved);
    });
}
void VaultBackupSettingsController::resume()
{
    if (!dialog_ || !current_ || !displayed_ || reading_ || writing_ || !sameSelection(*current_, *displayed_)) return;
    auto* coordinator = owner_.automaticBackup_; const auto& r = *current_;
    services::VaultBackupPreferences draft;
    if (!dialog_->preferences(draft) || draft != r.backup) return;
    if (!r.backup.automatic || !r.automaticSuspended || r.replacement || coordinator->isClosing()
        || coordinator->activeVaultId() == r.localId || coordinator->resumePending(r.localId)) return;
    coordinator->resumeAutomaticBackup(r.localId); // Does not clear the persistent latch here.
    dialog_->feedback(tr("Demande explicite de reprise transmise. La destination sera revalidée ; aucune publication encore confirmée."));
    updateActions();
    refresh(); // Observe also a dispatch that becomes unnecessary/refused without launching a child.
}
}
