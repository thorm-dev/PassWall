#include "services/automatic_backup_coordinator.hpp"
#include "services/backup_job.hpp"
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QTimer>
#include <QUuid>
#include <algorithm>

namespace passwall::services {
AutomaticBackupCoordinator::AutomaticBackupCoordinator(QObject* parent)
    : AutomaticBackupCoordinator(VaultPreferencesStore(), BackupJob::siblingWorkerPath(), parent) {}
AutomaticBackupCoordinator::AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker, QObject* parent)
    : QObject(parent), store_(std::move(store)), worker_(std::move(worker))
{
    setObjectName(QStringLiteral("automaticBackupCoordinator"));
    connect(&VaultPreferencesStore::events(), &VaultPreferencesEvents::changed, this,
        [this](const QString& settings, const QString& id, const QString& path, bool enabled) {
            if (settings != store_.fileName()) return;
            if (!enabled) { known_.remove(path); pending_.remove(id); resumes_.remove(id); return; }
            known_.insert(path, id);
            pending_.insert(id, path);
            retryPending();
        }, Qt::QueuedConnection);
}
AutomaticBackupCoordinator::~AutomaticBackupCoordinator() { shutdown(); }
void AutomaticBackupCoordinator::trackVault(const VaultRegistration& record)
{
    if (record.backup.automatic) known_.insert(record.file.path, record.localId);
    else known_.remove(record.file.path);
}
void AutomaticBackupCoordinator::requestForLockedVault(const QString& path)
{
    const auto source = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    if (closing_ || path.isEmpty() || !known_.contains(source)) return;
    pending_.insert(known_.value(source), source);
    retryPending();
}
void AutomaticBackupCoordinator::resumeAutomaticBackup(const QString& id)
{
    if (closing_) return;
    resumes_.insert(id); notified_.remove(id);
    // Lookup and verification are deferred, not a synchronous GUI callback.
    pending_.insert(id, {});
    retryPending();
}
void AutomaticBackupCoordinator::setPaused(bool paused)
{
    paused_ = paused;
    if (!paused) retryPending();
}
void AutomaticBackupCoordinator::retryPending()
{
    deferredIds_.clear();
    schedulePending();
}
void AutomaticBackupCoordinator::schedulePending()
{
    if (queued_ || paused_ || closing_ || job_ || pending_.isEmpty()) return;
    bool runnable = false;
    for (auto it = pending_.cbegin(); it != pending_.cend(); ++it)
        if (!deferredIds_.contains(it.key())) { runnable = true; break; }
    if (!runnable) return;
    queued_ = true;
    QTimer::singleShot(0, this, [this] { queued_ = false; dispatch(); });
}
bool AutomaticBackupCoordinator::isActive() const noexcept { return job_ && job_->isActive(); }
void AutomaticBackupCoordinator::cancel()
{
    if (job_) { voluntaryCancellation_ = true; job_->cancel(); }
}
void AutomaticBackupCoordinator::shutdown()
{
    if (closing_) return;
    closing_ = true; pending_.clear();
    if (normalInterruption_) *normalInterruption_ = !voluntaryCancellation_;
    if (job_) {
        job_->cancel();
        if (unconfirmedRotationStop_) { closeReady_ = true; emit closeReady(); }
    }
    else { closeReady_ = true; emit closeReady(); }
}
void AutomaticBackupCoordinator::fail(const QString& id, const QString& message)
{
    const QPointer<AutomaticBackupCoordinator> guarded(this);
    QString error;
    const bool saved = store_.suspendAutomaticBackup(id, error);
    if (!notified_.contains(id)) {
        notified_.insert(id);
        emit notification(id, message + (saved ? QString() :
            QStringLiteral(" Suspension persistante non confirmée ; vérifier la configuration.")));
    }
    if (guarded) guarded->schedulePending();
}
void AutomaticBackupCoordinator::dispatch()
{
    if (paused_ || closing_ || job_ || pending_.isEmpty()) return;
    auto next = pending_.cbegin();
    while (next != pending_.cend() && deferredIds_.contains(next.key())) ++next;
    if (next == pending_.cend()) return;
    const auto id = next.key();
    pending_.remove(id);
    try {
        QVector<VaultRegistration> records;
        QString error;
        if (!store_.list(records, error)) { fail(id, error); return; }
        const auto found = std::find_if(records.cbegin(), records.cend(),
            [&](const auto& value) { return value.localId == id; });
        if (found == records.cend()) { fail(id, QStringLiteral("Coffre enregistré introuvable.")); return; }
        auto record = *found;
        if (record.replacement) {
            // Recovery is not a backup failure. Do not arm an attempt, suspend
            // backups or retain a request that would rotate immediately after
            // restoration. A future normal lock/explicit resume can enqueue it.
            resumes_.remove(id);
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            emit deferred(id);
            if (guarded) guarded->schedulePending();
            return;
        }
        const bool resume = resumes_.remove(id);
        if (resume && record.backup.automatic) {
            if (!store_.suspendAutomaticBackup(id, error)) { fail(id, error); return; }
            record.backupRequired = true;
        }
        if (!record.backup.automatic || !record.backupRequired
            || ((record.automaticSuspended || notified_.contains(id)) && !resume)) {
            schedulePending(); return;
        }
        storage::VaultOperationGuard reservation;
        std::string failure;
        if (!reservation.tryReserve(record.file.path.toStdString(), failure)) {
            if (reservation.contended()) {
                pending_.insert(id, record.file.path);
                if (resume) resumes_.insert(id);
                deferredIds_.insert(id);
                const QPointer<AutomaticBackupCoordinator> guarded(this);
                emit deferred(id); // No spin, timer or false storage error.
                if (guarded) guarded->schedulePending();
            } else fail(id, QString::fromStdString(failure));
            return;
        }
        SnapshotDirectoryIdentity directory;
        if (!VaultSnapshotService::inspectDestinationDirectory(record.backup.directory.toStdString(), directory, failure)) {
            fail(id, QString::fromStdString(failure)); return;
        }
        const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
        const auto stem = QFileInfo(record.file.path).completeBaseName() + '_'
            + QDateTime::currentDateTime().toString(QStringLiteral("dd-MM-yyyy_HH-mm-ss"));
        QString destination = QDir(record.backup.directory).filePath(stem + ".db");
        // Never overwrite: even a later collision is rejected by linkat().
        const bool catalogued = std::any_of(record.automaticVersions.cbegin(), record.automaticVersions.cend(),
            [&](const auto& version) { return version.path == destination; });
        // A missing pathname may still belong to an uncertain deletion. Never
        // reuse it and accidentally associate a new inode with that old record.
        if (catalogued || QFileInfo::exists(destination) || QFileInfo(destination).isSymLink())
            destination = QDir(record.backup.directory).filePath(stem + '_' + token + ".db");
        if (!store_.beginAutomaticBackup(record, directory, destination, token, reservation, error, resume)) {
            fail(id, error); return;
        }
        const auto interrupted = std::make_shared<bool>(false);
        auto* job = new BackupJob(worker_, this);
        job_ = job;
        activeId_ = id;
        voluntaryCancellation_ = false;
        unconfirmedRotationStop_ = false;
        normalInterruption_ = interrupted;
        const auto store = store_;
        connect(job, &BackupJob::copyConfirmed, this, [this, id](BackupResult result) {
            emit copyConfirmed(id, result);
        });
        connect(job, &BackupJob::rotationFinished, this, [this, id](RotationResult result) {
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            unconfirmedRotationStop_ = result.outcome == RotationOutcome::Unknown;
            emit rotationCompleted(id, result);
            if (guarded && result.outcome != RotationOutcome::Complete)
                emit notification(id, QStringLiteral("Sauvegarde créée ; rotation non terminée : ") + result.diagnostic);
            if (guarded && closing_ && unconfirmedRotationStop_) { closeReady_ = true; emit closeReady(); }
            // No backupRequired rearm, no automatic-backup suspension. The
            // durable rotation latch independently prevents uncertain retries.
        });
        connect(job, &BackupJob::finished, this, [this, id, job](BackupResult result) {
            if (job_ != job) return;
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            if (result.outcome != BackupOutcome::Published
                && !(closing_ && result.outcome == BackupOutcome::CancelledBeforePublication)
                && !notified_.contains(id)) {
                notified_.insert(id);
                QString diagnostic = result.diagnostic;
                if (diagnostic.contains("errno=28]") || diagnostic.contains("primaire=13,"))
                    diagnostic = QStringLiteral("Espace insuffisant. ") + diagnostic;
                else if (diagnostic.contains("errno=13]"))
                    diagnostic = QStringLiteral("Permission refusée. ") + diagnostic;
                emit notification(id, diagnostic.isEmpty()
                    ? QStringLiteral("Sauvegarde automatique non confirmée ; reprise manuelle nécessaire.") : diagnostic);
            }
            if (!guarded) return;
            emit completed(id, result);
            if (!guarded) return;
            if (closing_ && result.outcome == BackupOutcome::Unknown) {
                closeReady_ = true; emit closeReady(); // Supervisor/child keep the locks.
            }
        });
        connect(job, &BackupJob::processTerminated, this, [this, job] {
            if (job_ != job) return;
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            job_.clear(); activeId_.clear(); job->deleteLater();
            emit activityChanged(false);
            if (!guarded) return;
            if (closing_) { closeReady_ = true; emit closeReady(); }
            else retryPending();
        });
        const bool started = job->startReserved(record.file.path, destination, std::move(reservation),
            [store, id, token, interrupted](BackupResult& result, const storage::VaultOperationGuard& lease) {
                QString error;
                if (!store.finishAutomaticBackup(id, token, result, *interrupted, lease, error))
                    result = {BackupOutcome::Unknown, error};
            }, directory, AutomaticBackupContext{store_.fileName(), id, token});
        if (!started) {
            job_.clear(); activeId_.clear(); job->deleteLater(); fail(id, job->startError());
        } else emit activityChanged(true);
    } catch (...) {
        if (job_ && !job_->isActive()) { job_->deleteLater(); job_.clear(); }
        if (job_) job_->cancel();
        fail(id, QStringLiteral("Erreur inattendue ; sauvegarde automatique suspendue."));
    }
}
}
