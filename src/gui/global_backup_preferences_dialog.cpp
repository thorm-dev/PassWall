#include "gui/global_backup_preferences_dialog.hpp"

#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSignalBlocker>
#include <QVBoxLayout>

namespace passwall::gui {

GlobalBackupPreferencesDialog::GlobalBackupPreferencesDialog(QWidget* parent)
    : QDialog(parent)
{
    setObjectName(QStringLiteral("globalBackupPreferencesDialog"));
    setWindowTitle(tr("Préférences globales de sauvegarde"));
    setModal(false);
    setAttribute(Qt::WA_QuitOnClose, false);
    setAttribute(Qt::WA_DeleteOnClose);
    setMinimumWidth(620);

    auto* layout = new QVBoxLayout(this);
    auto* introduction = new QLabel(tr(
        "Ces réglages s'appliquent à tous les coffres. Leur enregistrement ne "
        "prouve pas que la destination est actuellement accessible ou utilisable."), this);
    introduction->setObjectName(QStringLiteral("globalBackupIntroductionLabel"));
    introduction->setTextFormat(Qt::PlainText);
    introduction->setWordWrap(true);
    layout->addWidget(introduction);

    auto* form = new QFormLayout;
    auto* rootRow = new QHBoxLayout;
    rootDirectory_ = new QLineEdit(this);
    rootDirectory_->setObjectName(QStringLiteral("globalBackupRootEdit"));
    browse_ = new QPushButton(tr("Parcourir…"), this);
    browse_->setObjectName(QStringLiteral("globalBackupRootButton"));
    browse_->setAutoDefault(false);
    rootRow->addWidget(rootDirectory_);
    rootRow->addWidget(browse_);
    form->addRow(tr("Dossier racine des sauvegardes"), rootRow);

    retainedVersions_ = new QLineEdit(this);
    retainedVersions_->setObjectName(QStringLiteral("globalBackupRetentionEdit"));
    retainedVersions_->setMaxLength(20); // Decimal width of quint64, not a product limit.
    retainedVersions_->setValidator(new QRegularExpressionValidator(
        QRegularExpression(QStringLiteral("[0-9]{1,20}")), retainedVersions_));
    retainedVersions_->setText(QStringLiteral("7"));
    form->addRow(tr("Versions conservées par famille"), retainedVersions_);
    layout->addLayout(form);

    status_ = new QLabel(tr("Chargement des préférences globales…"), this);
    status_->setObjectName(QStringLiteral("globalBackupStatusLabel"));
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    layout->addWidget(status_);
    feedback_ = new QLabel(this);
    feedback_->setObjectName(QStringLiteral("globalBackupFeedbackLabel"));
    feedback_->setTextFormat(Qt::PlainText);
    feedback_->setWordWrap(true);
    layout->addWidget(feedback_);

    auto* buttons = new QHBoxLayout;
    save_ = new QPushButton(tr("Enregistrer"), this);
    save_->setObjectName(QStringLiteral("globalBackupSaveButton"));
    reload_ = new QPushButton(tr("Actualiser"), this);
    reload_->setObjectName(QStringLiteral("globalBackupReloadButton"));
    auto* close = new QPushButton(tr("Fermer"), this);
    close->setObjectName(QStringLiteral("globalBackupCloseButton"));
    for (auto* button : {save_, reload_, close}) {
        button->setAutoDefault(false);
        buttons->addWidget(button);
    }
    layout->addLayout(buttons);

    connect(save_, &QPushButton::clicked,
        this, &GlobalBackupPreferencesDialog::saveRequested);
    connect(reload_, &QPushButton::clicked,
        this, &GlobalBackupPreferencesDialog::reloadRequested);
    connect(rootDirectory_, &QLineEdit::textChanged,
        this, &GlobalBackupPreferencesDialog::draftChanged);
    connect(retainedVersions_, &QLineEdit::textChanged,
        this, &GlobalBackupPreferencesDialog::draftChanged);
    connect(close, &QPushButton::clicked, this, &QDialog::reject);
    connect(browse_, &QPushButton::clicked, this, [this] {
        auto* picker = new QFileDialog(
            this, tr("Dossier racine des sauvegardes"));
        picker->setAttribute(Qt::WA_DeleteOnClose);
        picker->setFileMode(QFileDialog::Directory);
        picker->setOption(QFileDialog::ShowDirsOnly);
        picker->setOption(QFileDialog::DontResolveSymlinks);
        connect(picker, &QFileDialog::fileSelected,
            this, [this](const QString& path) {
                if (rootDirectory_->isEnabled()) rootDirectory_->setText(path);
            });
        picker->open();
    });
}

void GlobalBackupPreferencesDialog::setPreferences(
    const services::GlobalBackupPreferences& preferences)
{
    const QSignalBlocker rootBlocked(rootDirectory_);
    const QSignalBlocker retentionBlocked(retainedVersions_);
    rootDirectory_->setText(preferences.rootDirectory);
    retainedVersions_->setText(QString::number(preferences.retainedVersions));
}

bool GlobalBackupPreferencesDialog::preferences(
    services::GlobalBackupPreferences& output, QString& diagnostic) const
{
    diagnostic.clear();
    bool converted = false;
    const quint64 retained = retainedVersions_->text().toULongLong(&converted);
    if (!retainedVersions_->hasAcceptableInput() || !converted) {
        diagnostic = tr("Le nombre de versions doit être un entier non signé valide.");
        return false;
    }
    if (retained < services::GlobalBackupPreferencesStore::MinimumRetainedVersions) {
        diagnostic = tr("Le nombre de versions conservées doit être au moins égal à sept.");
        return false;
    }
    output.rootDirectory = rootDirectory_->text();
    output.retainedVersions = retained;
    return true;
}

void GlobalBackupPreferencesDialog::setBusy(bool busy)
{
    rootDirectory_->setEnabled(!busy);
    retainedVersions_->setEnabled(!busy);
    browse_->setEnabled(!busy);
    save_->setEnabled(!busy);
    reload_->setEnabled(!busy);
}

void GlobalBackupPreferencesDialog::setStatus(const QString& text)
{
    status_->setText(text);
}

void GlobalBackupPreferencesDialog::setFeedback(const QString& text)
{
    feedback_->setText(text);
}

} // namespace passwall::gui
