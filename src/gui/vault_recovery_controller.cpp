#include "gui/vault_recovery_controller.hpp"
#include "gui/main_window.hpp"
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QThread>
#include <QVBoxLayout>
#include <QWindow>

namespace passwall::gui {
using namespace services;
VaultRecoveryController::VaultRecoveryController(MainWindow& owner) : QObject(&owner), owner_(owner) {}
VaultRecoveryController::~VaultRecoveryController() { delete dialog_.data(); }
void VaultRecoveryController::open() {
    if (dialog_) { dialog_->show(); dialog_->raise(); return; }
    // Explicit lifetime, outside lockVault's secret-dialog rejection tree.
    auto* dialog = new QDialog;
    dialog_ = dialog;
    dialog->setObjectName("vaultRecoveryDialog");
    dialog->setWindowTitle(tr("Récupérer une restauration interrompue"));
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setAttribute(Qt::WA_QuitOnClose, false);
    auto* layout = new QVBoxLayout(dialog);
    layout->addWidget(new QLabel(tr("Choisissez le coffre. Son examen verrouille PassWall ; aucune ouverture automatique."), dialog));
    selection_ = new QComboBox(dialog); selection_->setObjectName("recoveryVaultCombo"); layout->addWidget(selection_);
    status_ = new QLabel(dialog); status_->setObjectName("recoveryStatusLabel"); status_->setWordWrap(true); layout->addWidget(status_);
    activity_ = new QProgressBar(dialog); activity_->setObjectName("recoveryActivity"); activity_->setRange(0, 0); layout->addWidget(activity_);
    inspect_ = new QPushButton(tr("Verrouiller et examiner"), dialog); inspect_->setObjectName("recoveryInspectButton"); layout->addWidget(inspect_);
    confirmation_ = new QCheckBox(tr("Je confirme l'action proposée sur ce coffre."), dialog);
    confirmation_->setObjectName("recoveryConfirmationCheck"); layout->addWidget(confirmation_);
    resolve_ = new QPushButton(tr("Aucune action autorisée"), dialog); resolve_->setObjectName("recoveryResolveButton"); layout->addWidget(resolve_);
    reload_ = new QPushButton(tr("Actualiser la liste"), dialog); reload_->setObjectName("recoveryReloadButton"); layout->addWidget(reload_);
    auto* close = new QPushButton(tr("Fermer"), dialog); layout->addWidget(close);
    connect(close, &QPushButton::clicked, dialog, &QDialog::reject);
    connect(inspect_, &QPushButton::clicked, this, &VaultRecoveryController::inspect);
    connect(resolve_, &QPushButton::clicked, this, &VaultRecoveryController::resolve);
    connect(reload_, &QPushButton::clicked, this, &VaultRecoveryController::load);
    connect(selection_, &QComboBox::currentIndexChanged, this, [this] {
        ++generation_; local_.clear(); operation_.clear(); offered_ = ReplacementRecoveryAction::Inspect;
        confirmation_->setChecked(false); resolve_->setEnabled(false);
        inspect_->setEnabled(!active_ && selection_->currentIndex() >= 0);
        status_->setText(tr("Examinez le coffre pour vérifier les preuves ; la liste n'est pas une autorisation."));
    });
    connect(confirmation_, &QCheckBox::toggled, this, [this](bool checked) {
        resolve_->setEnabled(!active_ && checked && offered_ != ReplacementRecoveryAction::Inspect);
    });
    connect(dialog, &QDialog::finished, this, [this, dialog] {
        if (dialog_ != dialog) return;
        ++generation_; dialog_.clear(); // The owner/task, not this dialog, retains the exclusion.
    });
    dialog->show();
    if (dialog->windowHandle() && owner_.windowHandle()) dialog->windowHandle()->setTransientParent(owner_.windowHandle());
    if (active_) { busy(true); status_->setText(tr("Récupération encore active ; attendez sa fin puis actualisez.")); }
    else load();
}
void VaultRecoveryController::busy(bool value) {
    if (!dialog_) return;
    activity_->setVisible(value);
    selection_->setEnabled(!value); reload_->setEnabled(!value);
    inspect_->setEnabled(!value && selection_->currentIndex() >= 0);
    confirmation_->setEnabled(!value);
    resolve_->setEnabled(!value && confirmation_->isChecked() && offered_ != ReplacementRecoveryAction::Inspect);
}
void VaultRecoveryController::load() {
    if (!dialog_ || active_) return;
    records_.clear(); local_.clear(); operation_.clear();
    offered_ = ReplacementRecoveryAction::Inspect;
    confirmation_->setChecked(false); selection_->clear();
    active_ = true; busy(true); status_->setText(tr("Lecture du registre…"));
    const auto serial = ++generation_;
    struct Listing { QVector<VaultRegistration> records; QString error; bool ok = false; };
    auto listing = std::make_shared<Listing>(); const VaultPreferencesStore store;
    const QPointer<VaultRecoveryController> self(this);
    auto* delivery = new QObject;
    auto* task = QThread::create([listing, store] {
        try { listing->ok = store.listForDisplay(listing->records, listing->error); }
        catch (...) { listing->ok = false; }
    });
    connect(task, &QThread::finished, delivery, [self, task, delivery, listing, serial] {
        task->deleteLater(); delivery->deleteLater();
        if (!self) return;
        self->active_ = false;
        if (!self->dialog_ || self->generation_ != serial) {
            if (self->dialog_) self->busy(false);
            emit self->settled(false); return;
        }
        if (!listing->ok) listing->records.clear();
        self->records_ = listing->records;
        self->selection_->clear();
        for (const auto& record : listing->records) {
            if (record.replacement || record.resolvedReplacement)
                self->selection_->addItem(record.file.path, record.localId);
        }
        self->selection_->setCurrentIndex(-1);
        self->busy(false);
        self->status_->setText(listing->ok ? tr("Sélectionnez explicitement le coffre à examiner.")
            : tr("Registre indisponible ou invalide ; aucune récupération autorisée."));
        emit self->settled(true);
    }, Qt::QueuedConnection);
    task->start();
}
void VaultRecoveryController::inspect() {
    if (!dialog_ || active_ || selection_->currentIndex() < 0) return;
    const auto id = selection_->currentData().toString();
    for (const auto& r : records_) if (r.localId == id) {
        const auto intent = r.replacement ? r.replacement : r.resolvedReplacement;
        if (!intent) return;
        local_ = id; operation_ = intent->operationId;
        perform(ReplacementRecoveryAction::Inspect); return;
    }
}
void VaultRecoveryController::resolve() {
    if (!dialog_ || active_ || !confirmation_->isChecked() || offered_ == ReplacementRecoveryAction::Inspect) return;
    perform(offered_);
}
void VaultRecoveryController::perform(ReplacementRecoveryAction action) {
    active_ = true; const auto serial = ++generation_;
    const auto id = local_, operation = operation_;
    offered_ = ReplacementRecoveryAction::Inspect;
    confirmation_->setChecked(false); busy(true);
    status_->setText(tr("Nettoyage puis vérification des preuves et de la persistance…"));
    const QPointer<VaultRecoveryController> self(this);
    owner_.requestReplacementRecovery(id, operation, action, [self, serial, id, operation, action](auto result) {
        if (!self) return;
        self->active_ = false;
        const bool current = self->dialog_ && self->generation_ == serial
            && self->local_ == id && self->operation_ == operation;
        if (current) { self->display(result, action != ReplacementRecoveryAction::Inspect); self->busy(false); }
        else if (self->dialog_) { self->busy(false); self->status_->setText(tr("Ancienne opération terminée ; actualisez avant toute action.")); }
        emit self->settled(current);
    });
}
void VaultRecoveryController::display(const ReplacementRecoveryResult& result, bool executed) {
    offered_ = ReplacementRecoveryAction::Inspect;
    if (executed && result.finalization.state == ReplacementFinalizationState::Resolved) {
        status_->setText(tr("Récupération durablement confirmée. Le coffre reste verrouillé ; authentifiez-vous normalement."));
    } else if (executed) {
        status_->setText(tr("Récupération non confirmée : restrictions maintenues. Réexaminez le coffre ; aucun échange ni effacement effectué par cette récupération."));
    } else switch (result.layout) {
    case ReplacementLayout::PreparedIntact: case ReplacementLayout::AbandonmentPending:
        status_->setText(tr("Restauration non engagée, principal intact : abandon contrôlé possible."));
        offered_ = ReplacementRecoveryAction::AbandonPrepared; break;
    case ReplacementLayout::ArmedAfterExchange: case ReplacementLayout::IdentityConfirmed:
        status_->setText(tr("Remplacement déjà effectué : finalisation possible, sans nouvel échange."));
        offered_ = ReplacementRecoveryAction::FinalizeExchanged; break;
    case ReplacementLayout::Resolved:
        status_->setText(tr("Remplacement déjà résolu. Vous pouvez confirmer à nouveau sa persistance, sans le réexécuter."));
        offered_ = ReplacementRecoveryAction::FinalizeExchanged; break;
    case ReplacementLayout::Abandoned:
        status_->setText(tr("Abandon déjà enregistré. Confirmation de persistance possible, sans nouvelle restauration."));
        offered_ = ReplacementRecoveryAction::AbandonPrepared; break;
    case ReplacementLayout::ArmedBeforeExchange:
        status_->setText(tr("Remplacement armé avant échange : blocage conservé. Aucun abandon ni second échange autorisé.")); break;
    default:
        status_->setText(tr("Opération encore active, preuves insuffisantes ou état incertain : blocage conservé. Un diagnostic supplémentaire est nécessaire.")); break;
    }
    resolve_->setText(offered_ == ReplacementRecoveryAction::AbandonPrepared ? tr("Confirmer l'abandon contrôlé")
        : offered_ == ReplacementRecoveryAction::FinalizeExchanged ? tr("Confirmer la finalisation") : tr("Aucune action autorisée"));
}
}
