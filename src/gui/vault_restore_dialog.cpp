#include "gui/vault_restore_dialog.hpp"
#include "services/restore_protocol.hpp"
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScopeGuard>
#include <QSignalBlocker>
#include <QVBoxLayout>
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace passwall::gui {
namespace {
QString absolute(const QString& path) {
    return path.isEmpty() || QDir::isAbsolutePath(path) ? path : QDir::currentPath() + '/' + path;
}
QLabel* label(const QString& text, QWidget* parent) {
    auto* result = new QLabel(text, parent);
    result->setTextFormat(Qt::PlainText); result->setWordWrap(true);
    return result;
}
}
VaultRestoreDialog::VaultRestoreDialog() : QDialog(nullptr)
{
    setObjectName("vaultRestoreDialog"); setWindowTitle(tr("Restaurer depuis une sauvegarde"));
    setAttribute(Qt::WA_DeleteOnClose); setMinimumWidth(600);
    auto* layout = new QVBoxLayout(this);
    layout->addWidget(label(tr("Le contenu intégral du coffre principal sera remplacé, sans fusion. "
        "La sauvegarde doit appartenir à la même lignée cryptographique ; elle sera authentifiée intégralement. "
        "Le coffre ouvert sera verrouillé. Après engagement, l'annulation peut devenir impossible. "
        "L'ancien principal sera conservé dans un emplacement privé de récupération : "
        "cela ne garantit pas un retour arrière automatique."), this));
    choices_ = new QWidget(this); auto* form = new QFormLayout(choices_);
    principal_ = new QComboBox(choices_); principal_->setObjectName("restorePrincipalCombo");
    principal_->setPlaceholderText(tr("Choisir explicitement le coffre principal…"));
    form->addRow(tr("Coffre principal enregistré"), principal_);
    auto pathRow = [&](const char* name, QLineEdit*& field, bool save) {
        auto* row = new QWidget(choices_); auto* line = new QHBoxLayout(row); line->setContentsMargins(0, 0, 0, 0);
        field = new QLineEdit(row); field->setObjectName(QString::fromLatin1(name));
        auto* browse = new QPushButton(tr("Parcourir…"), row); line->addWidget(field); line->addWidget(browse);
        connect(browse, &QPushButton::clicked, this, [this, field, save] { chooseFile(field, save); });
        return row;
    };
    form->addRow(tr("Sauvegarde choisie librement"), pathRow("restoreSourceEdit", source_, false));
    precautionRow_ = pathRow("restorePrecautionEdit", precaution_, true);
    form->addRow(tr("Copie de précaution exceptionnelle"), precautionRow_);
    policy_ = label({}, choices_); policy_->setObjectName("restorePolicyLabel"); form->addRow(policy_);
    confirmation_ = new QCheckBox(tr("Je confirme le remplacement intégral de ce coffre."), choices_);
    confirmation_->setObjectName("restoreConfirmationCheck"); form->addRow(confirmation_);
    layout->addWidget(choices_);
    layout->addWidget(label(tr("Le mot de passe maître de la sauvegarde sera demandé seulement après "
        "la préparation sécurisée. Une préparation interrompue peut nécessiter une récupération."), this));
    password_ = new QLineEdit(this); password_->setObjectName("restoreMasterPasswordEdit");
    password_->setEchoMode(QLineEdit::Password); password_->setMaxLength(services::restore_protocol::passwordLimit);
    password_->setPlaceholderText(tr("Mot de passe maître de la sauvegarde")); password_->setEnabled(false);
    layout->addWidget(password_);
    status_ = label(tr("Chargement des coffres enregistrés…"), this); status_->setObjectName("restoreStatusLabel");
    activity_ = new QProgressBar(this); activity_->setObjectName("restoreActivity"); activity_->setRange(0, 0);
    layout->addWidget(status_); layout->addWidget(activity_);
    auto* buttons = new QHBoxLayout;
    primary_ = new QPushButton(tr("Verrouiller et préparer"), this); primary_->setObjectName("restorePrepareButton");
    primary_->setEnabled(false); primary_->setDefault(false); primary_->setAutoDefault(false);
    cancel_ = new QPushButton(tr("Fermer"), this); cancel_->setObjectName("restoreCancelButton");
    buttons->addWidget(primary_); buttons->addWidget(cancel_); layout->addLayout(buttons);
    connect(primary_, &QPushButton::clicked, this, [this] {
        if (stage_ == Stage::Choosing) emit preparationRequested();
        else if (stage_ == Stage::Password) emit executionRequested();
    });
    connect(cancel_, &QPushButton::clicked, this, [this] {
        if (stage_ == Stage::Running || stage_ == Stage::Preparing || stage_ == Stage::Password)
            emit cancellationRequested();
        else reject();
    });
    connect(principal_, &QComboBox::currentIndexChanged, this, [this] {
        confirmation_->setChecked(false); updateSelection();
    });
    for (auto* path : {source_, precaution_})
        connect(path, &QLineEdit::textChanged, this, [this] { confirmation_->setChecked(false); });
}
VaultRestoreDialog::~VaultRestoreDialog() { clearPassword(); }
QString VaultRestoreDialog::selectedId() const { return principal_->currentData().toString(); }
QString VaultRestoreDialog::source() const { return absolute(source_->text()); }
QString VaultRestoreDialog::precaution() const { return absolute(precaution_->text()); }
bool VaultRestoreDialog::confirmed() const { return confirmation_->isChecked(); }
bool VaultRestoreDialog::hasPassword() const { return !password_->text().isEmpty(); }
void VaultRestoreDialog::clearPassword() noexcept {
    try { const QSignalBlocker blocked(password_); password_->clear(); } catch (...) {}
}
core::SecureBuffer VaultRestoreDialog::takePassword() {
    QString text; QByteArray utf8;
    const auto textCleanup = qScopeGuard([&]() noexcept {
        if (text.isDetached() && !text.isEmpty()) sodium_memzero(text.data(), std::size_t(text.size()) * sizeof(QChar));
        text.clear();
    });
    const auto bytesCleanup = qScopeGuard([&]() noexcept {
        if (utf8.isDetached() && !utf8.isEmpty()) sodium_memzero(utf8.data(), std::size_t(utf8.size()));
        utf8.clear();
    });
    text = password_->text(); clearPassword(); text.detach(); utf8 = text.toUtf8();
    if (utf8.isEmpty() || utf8.size() > services::restore_protocol::passwordLimit)
        throw std::length_error("Invalid restoration password length");
    core::SecureBuffer result(utf8.size()); std::memcpy(result.data(), utf8.constData(), result.size());
    return result;
}
void VaultRestoreDialog::setRegistrations(const QVector<services::VaultRegistration>& records, const QSet<QString>& uncertain) {
    records_ = records; uncertain_ = uncertain; principal_->clear();
    for (const auto& record : records) principal_->addItem(record.file.path, record.localId);
    principal_->setCurrentIndex(-1);
    choosing();
}
void VaultRestoreDialog::updateSelection() {
    if (stage_ != Stage::Choosing) return;
    const auto index = principal_->currentIndex();
    const bool exists = index >= 0 && index < records_.size();
    const bool recovery = exists && (records_[index].replacement.has_value() || uncertain_.contains(records_[index].localId));
    const bool required = exists && !records_[index].backup.automatic;
    precautionRow_->setVisible(required);
    if (auto* caption = qobject_cast<QFormLayout*>(choices_->layout())->labelForField(precautionRow_))
        caption->setVisible(required);
    policy_->setText(!exists ? tr("Sélectionnez explicitement un coffre principal enregistré.") : recovery ? tr("Récupération nécessaire : ce coffre est bloqué par une restauration interrompue. "
        "Aucune nouvelle restauration n'est autorisée. Le parcours de récupération sera fourni séparément.") :
        required ? tr("Sauvegardes automatiques désactivées : une copie exceptionnelle, hors rotation, est obligatoire.") :
        tr("Sauvegardes automatiques activées : aucune copie supplémentaire ni disponibilité du dossier habituel exigée."));
    primary_->setEnabled(exists && !recovery);
}
void VaultRestoreDialog::choosing() {
    stage_ = Stage::Choosing; choices_->setEnabled(true); password_->setEnabled(false);
    activity_->hide(); primary_->setText(tr("Verrouiller et préparer")); cancel_->setText(tr("Fermer"));
    status_->setText(records_.isEmpty() ? tr("Aucun coffre principal enregistré n'est disponible.") :
        tr("Choisissez explicitement le principal et une sauvegarde. La sauvegarde n'est pas encore validée."));
    updateSelection();
}
void VaultRestoreDialog::preparing() {
    stage_ = Stage::Preparing; choices_->setEnabled(false); password_->setEnabled(false);
    primary_->setEnabled(false); cancel_->setEnabled(true); cancel_->setText(tr("Annuler"));
    activity_->show(); status_->setText(tr("Préparation et verrouillage réel du coffre…"));
}
void VaultRestoreDialog::awaitingPassword() {
    stage_ = Stage::Password; choices_->setEnabled(false); activity_->hide(); password_->setEnabled(true);
    password_->setFocus(); primary_->setEnabled(true); primary_->setText(tr("Authentifier et restaurer"));
    status_->setText(tr("Préparation acquise, coffre verrouillé. Saisissez le maître de la sauvegarde, "
        "puis confirmez son authentification et le remplacement."));
}
void VaultRestoreDialog::running(const QString& message, bool cancellationPossible) {
    stage_ = Stage::Running; choices_->setEnabled(false); password_->setEnabled(false); primary_->setEnabled(false);
    activity_->show(); status_->setText(message); cancel_->setText(tr("Demander l'arrêt"));
    cancel_->setEnabled(cancellationPossible);
}
void VaultRestoreDialog::validationError(const QString& message) { status_->setText(message); }
void VaultRestoreDialog::showError(const QString& message) {
    clearPassword(); stage_ = Stage::Result; choices_->setEnabled(false); password_->setEnabled(false);
    primary_->setEnabled(false); activity_->hide(); status_->setText(message);
    cancel_->setEnabled(true); cancel_->setText(tr("Fermer"));
}
QString VaultRestoreDialog::resultMessage(const services::RestoreResult& r, bool terminated, bool cleaned) {
    using namespace services;
    QString text;
    if (!terminated) text = r.outcome == RestoreOutcome::Unknown
        ? tr("Résultat incertain et arrêt du processus non confirmé. Le coffre reste indisponible ; récupération à vérifier.")
        : tr("Résultat métier reçu. Attente de la terminaison effective du processus ; restauration non encore confirmée.");
    else if (!cleaned || r.outcome == RestoreOutcome::Unknown || !r.replacementStatusKnown)
        text = tr("Résultat incertain : le coffre peut avoir été remplacé. Conservez les fichiers ; une vérification de récupération est nécessaire.");
    else switch (r.replacement.outcome) {
    case ReplacementOutcome::NotReplaced:
        text = r.replacement.sourceAuthenticationFailed
            ? tr("Authentification de la sauvegarde refusée. Aucun remplacement confirmé.")
            : tr("Échec avant remplacement : aucune substitution n'a eu lieu.");
        text += tr(" Le coffre reste verrouillé ; une préparation persistante peut nécessiter une récupération."); break;
    case ReplacementOutcome::CancelledBeforeEngagement:
        text = tr("Annulation confirmée avant engagement. Le coffre reste verrouillé ; l'état de préparation peut nécessiter une récupération."); break;
    case ReplacementOutcome::EngagedRecoveryRequired:
        text = tr("Remplacement engagé, résultat non confirmé : récupération nécessaire. Ne relancez pas une substitution."); break;
    case ReplacementOutcome::ReplacedDurabilityUnconfirmed:
        text = tr("Le coffre a été remplacé, mais la durabilité n'est pas confirmée. Conservez les fichiers ; récupération nécessaire."); break;
    case ReplacementOutcome::ReplacedFinalizationPending:
        text = tr("Le coffre a été remplacé ; finalisation en attente. L'accès reste bloqué jusqu'à vérification de récupération."); break;
    case ReplacementOutcome::Replaced:
        text = r.outcome == RestoreOutcome::EngineResult && r.replacement.finalization.state == ReplacementFinalizationState::Resolved
            ? tr("Restauration confirmée. Le coffre reste verrouillé : une nouvelle authentification est nécessaire. L'ancien principal est conservé.")
            : tr("Finalisation non confirmée : récupération à vérifier avant toute ouverture."); break;
    }
    if (!r.diagnostic.isEmpty()) text += '\n' + r.diagnostic.left(1024);
    if (!r.replacement.diagnostic.isEmpty()) text += '\n' + r.replacement.diagnostic.left(1024);
    return text;
}
void VaultRestoreDialog::showResult(const services::RestoreResult& r, bool terminated, bool cleaned) {
    if (terminated) showError(resultMessage(r, true, cleaned));
    else running(resultMessage(r, false, cleaned));
}
void VaultRestoreDialog::chooseFile(QLineEdit* field, bool save) {
    auto* selection = new QFileDialog(this, save ? tr("Copie de précaution exceptionnelle") : tr("Choisir une sauvegarde"));
    selection->setAttribute(Qt::WA_DeleteOnClose); selection->setOption(QFileDialog::DontResolveSymlinks);
    selection->setAcceptMode(save ? QFileDialog::AcceptSave : QFileDialog::AcceptOpen);
    selection->setFileMode(save ? QFileDialog::AnyFile : QFileDialog::ExistingFile);
    selection->setOption(QFileDialog::DontConfirmOverwrite); // Engine never overwrites this destination.
    connect(selection, &QFileDialog::fileSelected, this, [this, field](const QString& path) {
        if (stage_ == Stage::Choosing) field->setText(path);
    });
    selection->open(); // No nested event loop, including during file selection.
}
void VaultRestoreDialog::reject() {
    clearPassword(); emit closingRequested(); QDialog::reject();
}
} // namespace passwall::gui
