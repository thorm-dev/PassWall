#include "gui/vault_export_dialog.hpp"

#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>

namespace passwall::gui {
VaultExportDialog::VaultExportDialog()
    : status_(new QLabel(tr("Sauvegarde du coffre en cours…"), this)),
      activity_(new QProgressBar(this)),
      button_(new QPushButton(tr("Annuler la sauvegarde"), this))
{
    setObjectName(QStringLiteral("vaultExportProgressDialog"));
    setWindowTitle(tr("Export du coffre"));
    setAttribute(Qt::WA_DeleteOnClose);
    setMinimumWidth(480);
    status_->setObjectName(QStringLiteral("vaultExportStatusLabel"));
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    activity_->setRange(0, 0); // No fabricated percentage.
    activity_->setObjectName(QStringLiteral("vaultExportActivity"));
    button_->setObjectName(QStringLiteral("vaultExportCancelButton"));
    auto* layout = new QVBoxLayout(this);
    layout->addWidget(status_);
    layout->addWidget(activity_);
    layout->addWidget(button_);
    connect(button_, &QPushButton::clicked, this, [this] {
        if (running_) reject();
        else accept();
    });
}
void VaultExportDialog::cancellationPending()
{
    if (!running_ || cancellationPending_) return;
    cancellationPending_ = true;
    status_->setText(tr("Annulation demandée… La publication peut encore avoir eu lieu ; attente du résultat."));
    button_->setEnabled(false);
}
void VaultExportDialog::reject()
{
    if (running_) {
        if (!cancellationPending_) {
            cancellationPending();
            emit cancellationRequested();
        }
        return; // The window close button requests cancellation, not success.
    }
    QDialog::reject();
}
void VaultExportDialog::showResult(const services::BackupResult& result, bool closing)
{
    running_ = false;
    activity_->hide();
    QString message;
    using services::BackupOutcome;
    switch (result.outcome) {
    case BackupOutcome::Published:
        message = tr("Sauvegarde du coffre réussie. Le coffre n'a pas été déverrouillé automatiquement.");
        break;
    case BackupOutcome::FailedBeforePublication:
        message = tr("Sauvegarde échouée avant publication. Aucun nouveau fichier final n'a été publié par cette opération.");
        break;
    case BackupOutcome::DurabilityUnconfirmed:
        message = tr("Le fichier a été publié, mais sa durabilité n'est pas confirmée. Conservez-le et vérifiez-le avant de vous y fier.");
        break;
    case BackupOutcome::CancelledBeforePublication:
        message = tr("Sauvegarde annulée avant publication.");
        break;
    case BackupOutcome::Unknown:
        message = tr("Résultat incertain : un fichier peut avoir été créé. Conservez les fichiers présents et vérifiez la destination avant toute nouvelle tentative.");
        break;
    }
    // The trusted worker contract allows constant operation names/error codes,
    // never exception bodies, SQL values, keys or decrypted credentials. Display
    // bounded plain text so destination refusals have an actionable diagnostic.
    if (!result.diagnostic.isEmpty())
        message += QStringLiteral("\n\n") + result.diagnostic.left(1024);
    status_->setText(message);
    button_->setEnabled(true);
    button_->setText(closing ? tr("Fermer PassWall") : tr("Fermer"));
}
} // namespace passwall::gui
