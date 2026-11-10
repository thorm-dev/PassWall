#include "gui/vault_backup_settings_dialog.hpp"
#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVBoxLayout>
#include <limits>

namespace passwall::gui {
VaultBackupSettingsDialog::VaultBackupSettingsDialog() : QDialog(nullptr)
{
    setObjectName("vaultBackupSettingsDialog"); setWindowTitle(tr("Sauvegardes automatiques"));
    setModal(false);
    // Must not keep the application alive as another primary window. Ownership
    // stays in the controller, outside MainWindow's secret-dialog rejection tree.
    setAttribute(Qt::WA_QuitOnClose, false);
    setAttribute(Qt::WA_DeleteOnClose); setMinimumWidth(620);
    auto* layout = new QVBoxLayout(this);
    auto label = [&](const QString& text, const char* name) {
        auto* item = new QLabel(text, this); item->setObjectName(QString::fromLatin1(name));
        item->setTextFormat(Qt::PlainText); item->setWordWrap(true); layout->addWidget(item); return item;
    };
    label(tr("Ces trois préférences sont locales à cette installation, pas inscrites dans le coffre. "
        "Une copie portable ne les hérite pas. Les anciennes sauvegardes ne sont pas déplacées."), "backupLocalPolicyLabel");
    auto* form = new QFormLayout;
    vault_ = new QComboBox(this); vault_->setObjectName("backupVaultCombo");
    vault_->setPlaceholderText(tr("Choisir explicitement le coffre principal…"));
    form->addRow(tr("Coffre principal enregistré"), vault_);
    automatic_ = new QCheckBox(tr("Activer les sauvegardes automatiques"), this);
    automatic_->setObjectName("backupAutomaticCheck"); form->addRow(automatic_);
    auto* row = new QHBoxLayout;
    directory_ = new QLineEdit(this); directory_->setObjectName("backupDirectoryEdit");
    browse_ = new QPushButton(tr("Parcourir…"), this); browse_->setObjectName("backupDirectoryButton");
    row->addWidget(directory_); row->addWidget(browse_); form->addRow(tr("Répertoire local existant"), row);
    retained_ = new QSpinBox(this); retained_->setObjectName("backupRetentionSpin");
    retained_->setRange(1, std::numeric_limits<int>::max()); retained_->setValue(7);
    form->addRow(tr("Versions automatiques conservées"), retained_); layout->addLayout(form);
    label(tr("Activation : première copie selon le coordinateur existant. Ensuite, les modifications sont "
        "regroupées au verrouillage. Une erreur suspend les tentatives jusqu'à une reprise explicite. "
        "La rétention s'applique après une nouvelle copie confirmée, jamais par suppression immédiate ici."), "backupTriggerPolicyLabel");
    state_ = label(tr("Chargement du registre…"), "backupStateLabel");
    rotation_ = label({}, "backupRotationLabel"); feedback_ = label({}, "backupFeedbackLabel");
    auto* buttons = new QHBoxLayout;
    save_ = new QPushButton(tr("Enregistrer"), this); save_->setObjectName("backupSaveButton");
    resume_ = new QPushButton(tr("Reprendre la sauvegarde"), this); resume_->setObjectName("backupResumeButton");
    auto* reload = new QPushButton(tr("Actualiser"), this); reload->setObjectName("backupReloadButton");
    auto* close = new QPushButton(tr("Fermer"), this); close->setObjectName("backupSettingsCloseButton");
    for (auto* button : {save_, resume_, reload, close}) { button->setAutoDefault(false); buttons->addWidget(button); }
    layout->addLayout(buttons); setActions(false, false);
    connect(vault_, &QComboBox::currentIndexChanged, this, [this] { emit selectionChanged(selectedId()); });
    connect(save_, &QPushButton::clicked, this, &VaultBackupSettingsDialog::saveRequested);
    connect(resume_, &QPushButton::clicked, this, &VaultBackupSettingsDialog::resumeRequested);
    connect(reload, &QPushButton::clicked, this, &VaultBackupSettingsDialog::reloadRequested);
    connect(automatic_, &QCheckBox::toggled, this, &VaultBackupSettingsDialog::draftChanged);
    connect(directory_, &QLineEdit::textChanged, this, &VaultBackupSettingsDialog::draftChanged);
    connect(retained_, &QSpinBox::valueChanged, this, &VaultBackupSettingsDialog::draftChanged);
    connect(close, &QPushButton::clicked, this, &QDialog::reject);
    connect(browse_, &QPushButton::clicked, this, [this] {
        const auto id = selectedId();
        auto* picker = new QFileDialog(this, tr("Destination des sauvegardes"));
        picker->setAttribute(Qt::WA_DeleteOnClose); picker->setFileMode(QFileDialog::Directory);
        picker->setOption(QFileDialog::ShowDirsOnly); picker->setOption(QFileDialog::DontResolveSymlinks);
        connect(picker, &QFileDialog::fileSelected, this, [this, id](const QString& path) {
            if (selectedId() == id && directory_->isEnabled()) directory_->setText(path);
        });
        picker->open();
    });
}
QString VaultBackupSettingsDialog::selectedId() const { return vault_->currentData().toString(); }
void VaultBackupSettingsDialog::setRecords(const QVector<services::VaultRegistration>& records, const QString& selected)
{
    const QSignalBlocker blocked(vault_); vault_->clear();
    for (const auto& record : records) vault_->addItem(record.file.path, record.localId);
    vault_->setCurrentIndex(vault_->findData(selected));
}
void VaultBackupSettingsDialog::setPreferences(const services::VaultBackupPreferences& value)
{ automatic_->setChecked(value.automatic); directory_->setText(value.directory); retained_->setValue(value.retainedVersions); }
bool VaultBackupSettingsDialog::preferences(services::VaultBackupPreferences& output) const
{
    if (!retained_->hasAcceptableInput()) return false;
    output = {automatic_->isChecked(), directory_->text(), retained_->value()};
    return output.retainedVersions > 0;
}
void VaultBackupSettingsDialog::setActions(bool editable, bool resumable)
{
    QWidget* const fields[] = {automatic_, directory_, retained_, browse_, save_};
    for (auto* widget : fields) widget->setEnabled(editable);
    resume_->setEnabled(resumable);
}
void VaultBackupSettingsDialog::state(const QString& text, const QString& rotation)
{ state_->setText(text); rotation_->setText(rotation); }
void VaultBackupSettingsDialog::feedback(const QString& text) { feedback_->setText(text); }
}
