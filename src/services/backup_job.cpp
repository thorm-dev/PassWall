#include "services/backup_job.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QCoreApplication>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <QUuid>
#include <fcntl.h>
#include <unistd.h>
#include <memory>

namespace passwall::services {

// Intentionally NOT owned by the facade/application. An active QProcess must
// never be destroyed on GUI shutdown: Qt's destructor kills and then waits.
// This short-lived supervisor deletes itself only after NotRunning. If the
// kernel cannot reap a SIGKILLed child, retain ownership rather than block.
class BackupProcessSession final : public QObject {
public:
    BackupProcessSession(BackupJob* job, QString program, QByteArray request,
                         storage::VaultOperationGuard reservation, BackupJob::Finalizer finalize,
                         QString source, std::optional<AutomaticBackupContext> automatic)
        : job_(job), owner_(job), program_(std::move(program)), request_(std::move(request)),
          reservation_(std::move(reservation)), finalize_(std::move(finalize)),
          source_(std::move(source)), automatic_(std::move(automatic))
    {
        const auto handles = reservation_.inheritedHandles();
        process_.setChildProcessModifier([handles] {
            for (int fd : handles)
                if (fd >= 0 && ::fcntl(fd, F_SETFD, 0) != 0) ::_exit(127);
        });
        process_.setStandardErrorFile(QProcess::nullDevice());
        process_.setReadChannel(QProcess::StandardOutput);
        connect(&process_, &QProcess::started, this, [this] {
            launched_ = true;
            if (process_.write(request_) != request_.size()) protocolFailure();
            request_.clear();
            if (cancelled_) sendCancel();
        });
        connect(&process_, &QProcess::readyReadStandardOutput, this, [this] { read(); });
        connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) {
                stopped();
                if (rotation_) reportRotation({RotationOutcome::Refused, QStringLiteral("Auxiliaire de rotation impossible à démarrer.")});
                report(rotation_ ? copyResult_ : BackupResult{BackupOutcome::FailedBeforePublication,
                    QStringLiteral("Auxiliaire impossible à démarrer.")});
                notifyStopped();
                deleteLater(); // NotRunning, hence nonblocking destruction.
            } else if (error == QProcess::ReadError || error == QProcess::WriteError) {
                protocolFailure();
            }
        });
        connect(&process_, &QProcess::finished, this, [this](int code, QProcess::ExitStatus status) {
            read();
            escalation_.stop();
            if (rotation_) {
                RotationResult result;
                if (invalid_ || status != QProcess::NormalExit || code != 0
                    || !backup_protocol::parseRotationResult(output_, result))
                    result = {RotationOutcome::Unknown, QStringLiteral("Résultat de rotation non confirmé ; aucune reprise automatique.")};
                reportRotation(result);
                stopped(); report(copyResult_); notifyStopped(); deleteLater();
                return;
            }
            if (reported_) { stopped(); notifyStopped(); deleteLater(); return; }
            BackupResult result;
            if (invalid_ || status != QProcess::NormalExit || code != 0
                || !backup_protocol::parseResult(output_, result))
                result = {BackupOutcome::Unknown, QStringLiteral("Résultat de publication non confirmé ; ne pas relancer automatiquement.")};
            if (automatic_ && result.outcome == BackupOutcome::Published && !result.receipt)
                result = {BackupOutcome::Unknown, QStringLiteral("Reçu de publication automatique absent ; aucune suppression autorisée.")};
            finalizeCopy(result);
            if (automatic_ && copyResult_.outcome == BackupOutcome::Published && copyResult_.receipt) {
                // Same supervisor and same open lock descriptions throughout.
                // No active QProcess is destroyed; the first child is reaped.
                rotation_ = true;
                try {
                    request_ = backup_protocol::rotationRequest(source_, *automatic_);
                    output_.clear(); invalid_ = false; launched_ = false; stage_ = 0;
                    if (request_.size() > backup_protocol::requestLimit) throw std::bad_alloc();
                    if (owner_) emit owner_->copyConfirmed(copyResult_);
                    QTimer::singleShot(0, this, [this] { begin(); });
                    return;
                } catch (...) {
                    reportRotation({RotationOutcome::Unknown, QStringLiteral("Préparation de rotation non confirmée.")});
                }
            }
            stopped();
            report(copyResult_);
            notifyStopped();
            deleteLater();
        });
        escalation_.setSingleShot(true);
        connect(&escalation_, &QTimer::timeout, this, [this] {
            if (process_.state() == QProcess::NotRunning) return;
            if (stage_++ == 0) {
                process_.terminate();
                escalation_.start(backup_protocol::terminateMs);
            } else if (stage_ == 2) {
                process_.kill();
                escalation_.start(backup_protocol::killReportMs);
            } else {
                if (rotation_) reportRotation({RotationOutcome::Unknown, QStringLiteral("Arrêt de rotation non confirmé ; aucune reprise automatique.")});
                report(rotation_ ? copyResult_ : BackupResult{BackupOutcome::Unknown,
                    QStringLiteral("Arrêt non confirmé ; publication et nettoyage incertains.")});
                // Still own process_. Never destroy/wait on a live process.
            }
        });
        connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, [this] {
            cancel();
            // No more event-loop timers can be assumed after aboutToQuit.
            // Kill asynchronously; the worker also checks EOF/parent death.
            if (process_.state() != QProcess::NotRunning) process_.kill();
        });
    }
    void begin()
    {
        if (cancelled_) {
            stopped();
            if (rotation_) reportRotation({RotationOutcome::Cancelled, QStringLiteral("Rotation annulée avant lancement.")});
            report(rotation_ ? copyResult_ : BackupResult{BackupOutcome::CancelledBeforePublication, {}});
            notifyStopped();
            deleteLater();
            return;
        }
        const auto handles = reservation_.inheritedHandles();
        if (rotation_ && owner_) emit owner_->rotationStarted();
        // A direct receiver may close/cancel us while observing the phase.
        if (cancelled_) { begin(); return; }
        process_.start(program_, {rotation_ ? QStringLiteral("--rotation-v1") : QStringLiteral("--protocol-v1"),
            QString::number(handles[0]), QString::number(handles[1])});
    }
    void cancel()
    {
        if (cancelled_) return;
        cancelled_ = true;
        if (launched_) sendCancel();
        if (process_.state() != QProcess::NotRunning)
            escalation_.start(backup_protocol::cooperativeCancelMs);
    }
private:
    void stopped()
    {
        const auto owner = owner_;
        if (owner && owner->active_) {
            owner->active_ = false;
        }
    }
    void notifyStopped()
    {
        reservation_.reset(); // AFTER result finalization, never LOCK_UN.
        const auto owner = owner_;
        owner_.clear();
        if (owner) emit owner->processTerminated();
    }
    void sendCancel() { process_.write("!", 1); process_.closeWriteChannel(); }
    void protocolFailure()
    {
        invalid_ = true;
        cancel();
        // A flooding/broken peer must not keep filling QProcess's Qt buffers
        // during the cooperative cancellation grace period.
        if (process_.state() != QProcess::NotRunning) process_.kill();
    }
    void read()
    {
        // Bound retained data; never readAll() on an untrusted/erroring worker.
        const auto room = backup_protocol::resultLimit + 1 - output_.size();
        if (room > 0) output_ += process_.read(room);
        if (output_.size() > backup_protocol::resultLimit || process_.bytesAvailable() > 0)
            protocolFailure();
    }
    void report(BackupResult result)
    {
        if (reported_) return;
        reported_ = true;
        finalizeCopy(result);
        const auto recipient = job_;
        job_.clear();
        if (recipient) emit recipient->finished(copyResult_);
    }
    void finalizeCopy(BackupResult result)
    {
        if (finalized_) return;
        finalized_ = true;
        if (finalize_) {
            try { finalize_(result, reservation_); }
            catch (...) { result = {BackupOutcome::Unknown, QStringLiteral("Suivi de sauvegarde non confirmé.")}; }
            finalize_ = {};
        }
        copyResult_ = std::move(result);
    }
    void reportRotation(RotationResult result)
    {
        if (rotationReported_) return;
        rotationReported_ = true;
        if (owner_) emit owner_->rotationFinished(result);
    }
    QPointer<BackupJob> job_;
    QPointer<BackupJob> owner_;
    QString program_;
    QByteArray request_, output_;
    QProcess process_;
    storage::VaultOperationGuard reservation_;
    BackupJob::Finalizer finalize_;
    QString source_;
    std::optional<AutomaticBackupContext> automatic_;
    BackupResult copyResult_;
    QTimer escalation_;
    int stage_ = 0;
    bool cancelled_ = false, launched_ = false, invalid_ = false, reported_ = false;
    bool rotation_ = false, rotationReported_ = false, finalized_ = false;
};

QString BackupJob::siblingWorkerPath()
{
    return QCoreApplication::applicationDirPath() + QStringLiteral("/passwall_backup_worker");
}
BackupJob::BackupJob(QObject* parent) : BackupJob(siblingWorkerPath(), parent) {}
BackupJob::BackupJob(QString workerPath, QObject* parent)
    : QObject(parent), workerPath_(std::move(workerPath)) {}
BackupJob::~BackupJob()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (session_) session_->cancel(); // No wait, no destruction of active QProcess.
}
bool BackupJob::start(const QString& source, const QString& destination)
{
    Q_ASSERT(QThread::currentThread() == thread());
    startError_ = QStringLiteral("Paramètres de sauvegarde invalides ou opération déjà démarrée.");
    if (started_ || !backup_protocol::validPath(workerPath_)
        || QDir::cleanPath(workerPath_) != workerPath_
        || !backup_protocol::validPath(source) || !backup_protocol::validPath(destination)) return false;
    storage::VaultOperationGuard reservation;
    std::string error;
    if (!reservation.tryReserve(source.toStdString(), error)) {
        startError_ = QString::fromStdString(error);
        return false;
    }
    return startReserved(source, destination, std::move(reservation), {});
}
bool BackupJob::startReserved(const QString& source, const QString& destination,
    storage::VaultOperationGuard reservation, Finalizer finalize,
    std::optional<SnapshotDirectoryIdentity> directory, std::optional<AutomaticBackupContext> automatic)
{
    Q_ASSERT(QThread::currentThread() == thread());
    std::string error;
    if (started_ || !backup_protocol::validPath(workerPath_) || QDir::cleanPath(workerPath_) != workerPath_
        || !backup_protocol::validPath(source) || !backup_protocol::validPath(destination)
        || !reservation.matchesReservation(source.toStdString(), error)) {
        startError_ = QStringLiteral("Réservation ou paramètres de sauvegarde invalides.");
        return false;
    }
    if (automatic && (!backup_protocol::validPath(automatic->settingsFile)
        || QDir::cleanPath(automatic->settingsFile) != automatic->settingsFile
        || QUuid(automatic->localId).isNull() || QUuid(automatic->attempt).isNull())) return false;
    const auto request = backup_protocol::request(source, destination, directory, automatic.has_value());
    if (request.size() > backup_protocol::requestLimit) return false;
    try {
        // No process starts until the queued callback. Constructor/queueing
        // exceptions can therefore destroy this candidate without waiting.
        auto candidate = std::make_unique<BackupProcessSession>(
            this, workerPath_, request, std::move(reservation), std::move(finalize), source, std::move(automatic));
        const QPointer<BackupProcessSession> session(candidate.get());
        QTimer::singleShot(0, candidate.get(), [session] { if (session) session->begin(); });
        session_ = candidate.release();
        started_ = true;
        active_ = true;
        startError_.clear();
    } catch (...) {
        startError_ = QStringLiteral("Impossible de préparer le processus de sauvegarde.");
        return false;
    }
    return true;
}
void BackupJob::cancel()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (session_) session_->cancel();
}
} // namespace passwall::services
