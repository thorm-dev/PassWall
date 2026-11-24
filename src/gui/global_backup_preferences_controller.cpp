#include "gui/global_backup_preferences_controller.hpp"

#include "gui/global_backup_preferences_dialog.hpp"

#include <QThread>
#include <QWidget>

#include <functional>
#include <memory>
#include <utility>

namespace passwall::gui {
namespace {

bool runAsync(std::function<void()> work, std::function<void()> complete)
{
    auto* delivery = new QObject;
    QThread* task = nullptr;
    try {
        task = QThread::create([work = std::move(work)]() mutable { work(); });
    } catch (...) {
        delete delivery;
        return false;
    }
    QObject::connect(task, &QThread::finished, delivery,
        [task, delivery, complete = std::move(complete)]() mutable {
            try {
                complete();
            } catch (...) {
                // No exception may cross a Qt event delivery boundary.
            }
            task->deleteLater();
            delivery->deleteLater();
        }, Qt::QueuedConnection);
    task->start();
    return true;
}

QString statusText(const services::GlobalBackupPreferencesResult& result)
{
    using services::GlobalBackupPreferencesStatus;
    switch (result.status) {
    case GlobalBackupPreferencesStatus::Absent:
        return QObject::tr(
            "Aucune configuration globale n'est enregistrée. Choisissez un dossier "
            "et une rétention avant que les sauvegardes générationnelles puissent fonctionner.");
    case GlobalBackupPreferencesStatus::Valid:
        return QObject::tr(
            "Configuration globale enregistrée. La destination sera encore contrôlée "
            "au moment de chaque sauvegarde.");
    case GlobalBackupPreferencesStatus::Invalid:
        return QObject::tr("La configuration globale présente est invalide ou incomplète.");
    case GlobalBackupPreferencesStatus::ReadError:
        return QObject::tr("Les préférences globales ne peuvent pas être lues en sécurité.");
    case GlobalBackupPreferencesStatus::WriteError:
        return QObject::tr("La persistance des préférences globales n'est pas confirmée.");
    }
    return QObject::tr("État des préférences globales inconnu.");
}

QString diagnosticText(const services::GlobalBackupPreferencesResult& result)
{
    const QString status = statusText(result);
    return result.diagnostic.isEmpty()
        ? status : status + QLatin1Char('\n') + result.diagnostic.left(2048);
}

} // namespace

GlobalBackupPreferencesController::GlobalBackupPreferencesController(
    services::GlobalBackupPreferencesStore store, QObject* parent)
    : QObject(parent), store_(std::move(store))
{
}

GlobalBackupPreferencesController::~GlobalBackupPreferencesController()
{
    ++operationSerial_;
    delete dialog_.data();
}

void GlobalBackupPreferencesController::open()
{
    if (dialog_) {
        dialog_->show();
        dialog_->raise();
        dialog_->activateWindow();
        return;
    }

    ensureDialog();
    dialog_->show();
    if (reading_) {
        dialog_->setBusy(true);
        dialog_->setStatus(tr("Lecture sécurisée des préférences globales…"));
        dialog_->setFeedback({});
        return;
    }
    load();
}

void GlobalBackupPreferencesController::offerInitialConfiguration()
{
    if (initialOfferMade_) return;
    initialOfferMade_ = true;
    if (dialog_ || reading_ || writing_) return;
    startLoad(true);
}

void GlobalBackupPreferencesController::ensureDialog()
{
    if (dialog_) return;
    dialog_ = new GlobalBackupPreferencesDialog(
        qobject_cast<QWidget*>(parent()));
    connect(dialog_, &QDialog::finished, this,
        [this, closed = dialog_.data()] {
            ++operationSerial_;
            QObject::disconnect(closed, nullptr, this, nullptr);
            dialog_.clear();
            reading_ = false;
            writing_ = false;
        });
    connect(dialog_, &GlobalBackupPreferencesDialog::reloadRequested,
        this, &GlobalBackupPreferencesController::load);
    connect(dialog_, &GlobalBackupPreferencesDialog::saveRequested,
        this, &GlobalBackupPreferencesController::save);
    connect(dialog_, &GlobalBackupPreferencesDialog::draftChanged,
        this, [this] {
            if (dialog_ && !reading_ && !writing_) dialog_->setFeedback({});
        });
}

void GlobalBackupPreferencesController::load()
{
    startLoad(false);
}

void GlobalBackupPreferencesController::startLoad(
    bool onlyIfConfigurationNeeded)
{
    if ((!dialog_ && !onlyIfConfigurationNeeded) || reading_ || writing_)
        return;
    const quint64 serial = ++operationSerial_;
    const auto store = store_;
    auto result = std::make_shared<services::GlobalBackupPreferencesResult>();
    reading_ = true;
    if (dialog_) {
        dialog_->setBusy(true);
        dialog_->setStatus(tr("Lecture sécurisée des préférences globales…"));
        dialog_->setFeedback({});
    }
    const QPointer<GlobalBackupPreferencesController> guarded(this);
    if (runAsync([store, result] {
            try {
                *result = store.load();
            } catch (...) {
                result->status = services::GlobalBackupPreferencesStatus::ReadError;
                result->sourceFile = store.fileName();
                result->diagnostic = QStringLiteral(
                    "Lecture des préférences globales interrompue.");
            }
        }, [guarded, serial, result, onlyIfConfigurationNeeded] {
            if (!guarded || guarded->operationSerial_ != serial)
                return;
            guarded->reading_ = false;
            emit guarded->configurationRead(*result);
            if (!guarded || guarded->operationSerial_ != serial)
                return;
            if (!guarded->dialog_ && onlyIfConfigurationNeeded
                && result->status
                    == services::GlobalBackupPreferencesStatus::Valid) {
                emit guarded->readSettled(result->status);
                return;
            }
            if (!guarded->dialog_) {
                guarded->ensureDialog();
                guarded->dialog_->show();
            }
            if (result->status == services::GlobalBackupPreferencesStatus::Valid)
                guarded->dialog_->setPreferences(result->preferences);
            else
                guarded->dialog_->setPreferences({});
            guarded->dialog_->setStatus(diagnosticText(*result));
            guarded->dialog_->setBusy(false);
            emit guarded->readSettled(result->status);
        }))
        return;

    reading_ = false;
    if (!dialog_ && onlyIfConfigurationNeeded) {
        ensureDialog();
        dialog_->show();
    }
    if (dialog_) {
        dialog_->setBusy(false);
        dialog_->setStatus(tr(
            "Impossible de démarrer la lecture des préférences globales."));
    }
    services::GlobalBackupPreferencesResult failed;
    failed.status = services::GlobalBackupPreferencesStatus::ReadError;
    failed.sourceFile = store_.fileName();
    failed.diagnostic = QStringLiteral(
        "Impossible de démarrer la lecture asynchrone des préférences globales.");
    const QPointer<GlobalBackupPreferencesController> stillAlive(this);
    emit configurationRead(failed);
    if (stillAlive)
        emit readSettled(services::GlobalBackupPreferencesStatus::ReadError);
}

void GlobalBackupPreferencesController::save()
{
    if (!dialog_ || reading_ || writing_) return;
    services::GlobalBackupPreferences preferences;
    QString diagnostic;
    if (!dialog_->preferences(preferences, diagnostic)) {
        dialog_->setFeedback(diagnostic);
        emit writeSettled(services::GlobalBackupPreferencesStatus::Invalid);
        return;
    }
    const auto validation =
        services::GlobalBackupPreferencesStore::validate(preferences);
    if (!validation.valid()) {
        dialog_->setFeedback(validation.diagnostic);
        emit writeSettled(validation.status);
        return;
    }

    const quint64 serial = ++operationSerial_;
    const auto store = store_;
    auto result = std::make_shared<services::GlobalBackupPreferencesResult>();
    writing_ = true;
    dialog_->setBusy(true);
    dialog_->setFeedback(tr("Validation et enregistrement sécurisé en cours…"));
    const QPointer<GlobalBackupPreferencesController> guarded(this);
    if (runAsync([store, preferences, result] {
            try {
                *result = store.save(preferences);
            } catch (...) {
                result->status = services::GlobalBackupPreferencesStatus::WriteError;
                result->preferences = preferences;
                result->diagnostic = QStringLiteral(
                    "Enregistrement interrompu ; persistance non confirmée.");
            }
        }, [guarded, serial, result] {
            if (!guarded || !guarded->dialog_
                || guarded->operationSerial_ != serial)
                return;
            guarded->writing_ = false;
            guarded->dialog_->setBusy(false);
            guarded->dialog_->setStatus(diagnosticText(*result));
            if (result->valid()) {
                guarded->dialog_->setPreferences(result->preferences);
                guarded->dialog_->setFeedback(QObject::tr(
                    "Préférences globales enregistrées durablement. La destination "
                    "n'est pas déclarée opérationnelle avant ses contrôles de sauvegarde."));
            } else {
                guarded->dialog_->setFeedback(QObject::tr(
                    "Enregistrement refusé ou non confirmé. Aucune réussite n'est déduite.\n")
                    + result->diagnostic.left(2048));
            }
            emit guarded->writeSettled(result->status);
        }))
        return;

    writing_ = false;
    dialog_->setBusy(false);
    dialog_->setStatus(tr("Impossible de démarrer l'enregistrement des préférences globales."));
    emit writeSettled(services::GlobalBackupPreferencesStatus::WriteError);
}

} // namespace passwall::gui
