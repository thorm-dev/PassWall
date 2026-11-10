#include "services/restore_job.hpp"
#include "services/restore_protocol.hpp"
#include "services/restore_delegation.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QProcess>
#include <QSocketNotifier>
#include <QThread>
#include <QTimer>
#include <QUuid>
#include <fcntl.h>
#include <sys/stat.h>
#include <deque>
#include <stdexcept>
#include <climits>

namespace passwall::services {
namespace wire = restore_protocol;

class RestoreProcessSession final : public QObject {
public:
    RestoreProcessSession(RestoreJob* job, VaultReplacementAuthorization authority,
        core::SecureBuffer password, QString source, QString precaution, int parent, int child)
        : job_(job), authority_(std::move(authority)), password_(std::move(password)),
          cleanupObserver_(job->cleanupObserver_), terminationObserver_(job->terminationObserver_),
          fd_(parent), child_(child), read_(parent, QSocketNotifier::Read, this),
          write_(parent, QSocketNotifier::Write, this)
    {
        QString failure;
        auto grant = RestoreDelegation::issue(authority_, failure);
        if (grant.isEmpty()) throw std::runtime_error("Invalid restoration delegation");
        operation_ = grant["operation"].toString();
        session_ = QUuid::createUuid().toString(QUuid::WithoutBraces);
        begin_ = {{"v", 1}, {"grant", grant}, {"source", source}, {"precaution", precaution},
            {"size", int(password_.size())}, {"operation", operation_}, {"session", session_}};
        const auto handles = RestoreDelegation::handles(authority_);
        process_.setChildProcessModifier([handles, child] {
            for (int fd : {child, handles[0], handles[1]})
                if (fd < 64 || ::fcntl(fd, F_SETFD, 0) != 0) ::_exit(127);
        });
        process_.setStandardInputFile(QProcess::nullDevice());
        process_.setStandardOutputFile(QProcess::nullDevice());
        process_.setStandardErrorFile(QProcess::nullDevice());
        write_.setEnabled(false);
        connect(&read_, &QSocketNotifier::activated, this, [this] { receive(); });
        connect(&write_, &QSocketNotifier::activated, this, [this] { pump(); });
        connect(&process_, &QProcess::started, this, [this] {
            ::close(std::exchange(child_, -1));
            if (cancelled_) return;
            try { queue(wire::Begin, begin_); begin_ = {}; }
            catch (...) { broken(); }
        });
        connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart) {
                markClean(RestoreCleanup::ConfirmedProcessTermination);
                report({RestoreOutcome::Refused, {}, QStringLiteral("Auxiliaire de restauration impossible à démarrer."), true});
                stopped();
            }
        });
        connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus status) {
                // Bounded drain after actual exit: terminal metadata may still
                // follow the cleanup record in the socket's kernel buffer.
                for (int i = 0; i < 16 && read_.isEnabled(); ++i) receive();
                // Actual OS termination, not kill() or a semantic result.
                markClean(RestoreCleanup::ConfirmedProcessTermination);
                if (!reported_) {
                    if (!invalid_ && terminal_ && code == 0 && status == QProcess::NormalExit)
                        report(result_);
                    else report(unknown(QStringLiteral("Supervision de restauration incertaine [exit=%1, crash=%2] ; inspecter la récupération.")
                        .arg(code).arg(status == QProcess::CrashExit)));
                }
                stopped();
            });
        escalation_.setSingleShot(true);
        connect(&escalation_, &QTimer::timeout, this, [this] {
            if (process_.state() == QProcess::NotRunning) return;
            if (stage_++ == 0) { process_.terminate(); escalation_.start(wire::terminateMs); }
            else if (stage_ == 2) { process_.kill(); escalation_.start(wire::unknownMs); }
            else report(unknown(QStringLiteral("Arrêt non confirmé ; secrets et remplacement potentiellement en cours.")));
        });
        connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, [this] {
            cancel(); if (process_.state() != QProcess::NotRunning) process_.kill();
        });
    }
    ~RestoreProcessSession() override {
        if (fd_ >= 0) ::close(fd_);
        if (child_ >= 0) ::close(child_);
    }
    void launch(const QString& program) {
        if (cancelled_) {
            result_.outcome = RestoreOutcome::EngineResult;
            result_.replacement.outcome = ReplacementOutcome::CancelledBeforeEngagement;
            result_.replacement.operationId = operation_;
            result_.replacementStatusKnown = true; // Parent proves no child was launched.
            markClean(RestoreCleanup::ConfirmedProcessTermination);
            report(result_); stopped(); return;
        }
        const auto handles = RestoreDelegation::handles(authority_);
        process_.start(program, {"--restore-v1", QString::number(child_),
            QString::number(handles[0]), QString::number(handles[1])});
    }
    void cancel() {
        if (cancelled_) return;
        cancelled_ = true;
        // A half-close also interrupts a truncated password safely: never append
        // a cancel frame into the remaining raw password bytes.
        password_ = core::SecureBuffer(0); outgoing_.clear(); queued_.clear();
        sendingPassword_ = false; write_.setEnabled(false);
        ::shutdown(fd_, SHUT_WR);
        if (process_.state() != QProcess::NotRunning) escalation_.start(wire::cooperativeMs);
    }
private:
    RestoreResult unknown(QString diagnostic) const {
        auto r = result_; // Preserve an already received business result/artifact.
        if (invalid_) diagnostic += QStringLiteral(" [protocole invalide]");
        r.outcome = RestoreOutcome::Unknown; r.diagnostic = std::move(diagnostic);
        if (r.replacement.operationId.isEmpty()) r.replacement.operationId = operation_;
        return r;
    }
    void markClean(RestoreCleanup proof) {
        password_ = core::SecureBuffer(0);
        if (cleaned_) return;
        cleaned_ = true;
        if (cleanupObserver_) { try { cleanupObserver_(proof); } catch (...) {} }
        if (job_) { job_->cleanup_ = proof; emit job_->secretsCleared(proof); }
    }
    void report(RestoreResult result) {
        if (reported_) return;
        reported_ = true;
        if (job_) emit job_->finished(std::move(result));
    }
    void stopped() {
        read_.setEnabled(false); write_.setEnabled(false); escalation_.stop();
        authority_.reset(); // Process is NotRunning; final owner can release locks.
        if (terminationObserver_) { try { terminationObserver_(); } catch (...) {} }
        if (job_) { job_->active_ = false; emit job_->processTerminated(); }
        deleteLater();
    }
    void broken() {
        invalid_ = true; read_.setEnabled(false); cancel();
        if (process_.state() != QProcess::NotRunning) process_.kill();
    }
    QJsonObject bound() const { return {{"operation", operation_}, {"session", session_}}; }
    void queue(wire::Type type, QJsonObject object) {
        queued_.emplace_back(type, std::move(object)); write_.setEnabled(true); pump();
    }
    void pump() noexcept {
        try {
            if (cancelled_) return;
            if (outgoing_.isEmpty() && !sendingPassword_ && !queued_.empty()) {
                auto [type, object] = std::move(queued_.front()); queued_.pop_front();
                auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
                if (bytes.size() > wire::metadataLimit) { broken(); return; }
                const auto prefix = wire::header(type, bytes.size());
                outgoing_ = QByteArray(prefix.data(), prefix.size()) + bytes; written_ = 0;
            }
            // One bounded write per event; no GUI waiting and no secret Qt buffer.
            const char* data = nullptr; qsizetype size = 0;
            if (!outgoing_.isEmpty()) { data = outgoing_.constData() + written_; size = outgoing_.size() - written_; }
            else if (sendingPassword_) {
                data = reinterpret_cast<const char*>(password_.data()) + passwordWritten_;
                size = password_.size() - passwordWritten_;
            }
            if (!size) { write_.setEnabled(false); return; }
            const auto n = ::send(fd_, data, std::min<qsizetype>(size, 65536), MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (n <= 0) { broken(); return; }
            if (!outgoing_.isEmpty()) {
                written_ += n;
                if (written_ == outgoing_.size()) outgoing_.clear();
            } else {
                passwordWritten_ += n;
                if (passwordWritten_ == password_.size()) sendingPassword_ = false;
            }
            write_.setEnabled(!outgoing_.isEmpty() || sendingPassword_ || !queued_.empty());
        } catch (...) { broken(); }
    }
    void receive() noexcept {
        try {
            // Fixed retained bound, check header/type BEFORE reading payload.
            for (;;) {
                const qsizetype need = incoming_.size() < 5 ? 5 - incoming_.size()
                    : qsizetype(qFromLittleEndian<quint32>(incoming_.constData())) + 5 - incoming_.size();
                if (need > 0) {
                    char bytes[4096];
                    const auto n = ::recv(fd_, bytes, std::min<qsizetype>(need, sizeof(bytes)), MSG_DONTWAIT);
                    if (n < 0 && errno == EINTR) continue;
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
                    if (n <= 0) {
                        read_.setEnabled(false);
                        if (!incoming_.isEmpty() || (!terminal_ && process_.state() != QProcess::NotRunning)) broken();
                        return;
                    }
                    if (terminal_) { broken(); return; } // Even a one-byte tail is invalid.
                    incoming_.append(bytes, n);
                }
                if (incoming_.size() < 5) continue;
                const auto size = qFromLittleEndian<quint32>(incoming_.constData());
                const auto type = wire::Type(static_cast<unsigned char>(incoming_[4]));
                if (size > wire::metadataLimit || type == wire::Password || type < wire::Probe || type > wire::CancelReceived) {
                    broken(); return;
                }
                if (incoming_.size() != qsizetype(size) + 5) continue;
                QJsonParseError error;
                const auto doc = QJsonDocument::fromJson(incoming_.mid(5), &error);
                incoming_.clear();
                if (error.error != QJsonParseError::NoError || !doc.isObject()
                    || !wire::bound(doc.object(), operation_, session_)) { broken(); return; }
                handle(type, doc.object());
                return; // One frame per activation: let lock/timer events run.
            }
        } catch (...) { broken(); }
    }
    void handle(wire::Type type, const QJsonObject& object) {
        if (terminal_) { broken(); return; }
        if (type == wire::Probe) {
            const int number = object["n"].toInt(-1);
            if (sequence_ == INT_MAX || number != sequence_ + 1 || object.size() != 3) { broken(); return; }
            sequence_ = number;
            if (!cancelled_ && !RestoreDelegation::current(authority_)) cancel();
            if (cancelled_) return;
            auto permit = bound(); permit["n"] = number;
            queue(wire::Permit, permit);
        } else if (type == wire::Ready) {
            if (ready_ || received_ || cleaned_ || cancelled_ || sequence_ == 0 || object.size() != 2) { broken(); return; }
            if (!RestoreDelegation::current(authority_)) { cancel(); return; }
            ready_ = true;
            const auto prefix = wire::header(wire::Password, password_.size());
            outgoing_ = QByteArray(prefix.data(), prefix.size()); written_ = 0;
            sendingPassword_ = true; write_.setEnabled(true); pump();
        } else if (type == wire::Received) {
            if (!ready_ || received_ || sendingPassword_ || !outgoing_.isEmpty() || object.size() != 2) { broken(); return; }
            received_ = true; password_ = core::SecureBuffer(0);
        } else if (type == wire::Cleaned) {
            if (cleaned_ || object.size() != 2 || (ready_ && !received_ && !cancelled_)) { broken(); return; }
            markClean(RestoreCleanup::ConfirmedByWorker);
        } else if (type == wire::Phase) {
            const int phase = object["phase"].toInt(-1);
            if (!received_ || phase < 0 || phase > int(ReplacementCheckpoint::AfterDirectorySync)
                || phase <= lastPhase_ || object.size() != 3
                || (phase >= int(ReplacementCheckpoint::SourceAuthenticated) && !cleaned_)) { broken(); return; }
            lastPhase_ = phase;
            if (job_) emit job_->phaseChanged(ReplacementCheckpoint(phase));
        } else if (type == wire::CancelReceived) {
            if (!cancelled_ || cancelReceived_ || object.size() != 2) { broken(); return; }
            cancelReceived_ = true; if (job_) emit job_->cancellationReceived();
        } else if (type == wire::Result) {
            if (!cleaned_ || object.size() != 4 || !object["kind"].isDouble()
                || object["kind"].toInt(-1) < 0 || object["kind"].toInt(-1) > int(RestoreOutcome::Unknown)
                || object["kind"].toDouble() != object["kind"].toInt(-1)
                || !wire::decode(object["result"].toObject(), result_.replacement)
                || result_.replacement.operationId != operation_) { broken(); return; }
            result_.outcome = RestoreOutcome(object["kind"].toInt()); terminal_ = true;
            if (!wire::consistent(result_.replacement, lastPhase_)
                || ((result_.outcome == RestoreOutcome::EngineResult || result_.outcome == RestoreOutcome::SourceAuthenticationFailed) && !received_)
                || (result_.outcome == RestoreOutcome::SourceAuthenticationFailed && !result_.replacement.sourceAuthenticationFailed)
                || ((result_.outcome == RestoreOutcome::Refused || result_.outcome == RestoreOutcome::TransportFailed)
                    && (lastPhase_ >= 0 || result_.replacement.outcome != ReplacementOutcome::NotReplaced))) {
                terminal_ = false; broken(); return;
            }
            result_.replacementStatusKnown = result_.outcome != RestoreOutcome::Unknown;
            if (job_) emit job_->resultReceived(result_);
        } else broken();
    }
    QPointer<RestoreJob> job_;
    VaultReplacementAuthorization authority_;
    core::SecureBuffer password_;
    std::function<void(RestoreCleanup)> cleanupObserver_;
    std::function<void()> terminationObserver_;
    int fd_, child_, written_ = 0, sequence_ = 0, lastPhase_ = -1, stage_ = 0;
    std::size_t passwordWritten_ = 0;
    QSocketNotifier read_, write_;
    QProcess process_;
    QTimer escalation_;
    QString operation_, session_;
    QJsonObject begin_;
    QByteArray incoming_, outgoing_;
    std::deque<std::pair<wire::Type, QJsonObject>> queued_;
    RestoreResult result_;
    bool ready_ = false, received_ = false, cleaned_ = false, terminal_ = false;
    bool sendingPassword_ = false, cancelled_ = false, cancelReceived_ = false, invalid_ = false, reported_ = false;
};

QString RestoreJob::siblingWorkerPath() { return QCoreApplication::applicationDirPath() + "/passwall_restore_worker"; }
RestoreJob::RestoreJob(QObject* parent) : RestoreJob(siblingWorkerPath(), parent) {}
RestoreJob::RestoreJob(QString worker, QObject* parent) : QObject(parent), worker_(std::move(worker)) {}
RestoreJob::~RestoreJob() { cancel(); }
void RestoreJob::cancel() {
    if (QThread::currentThread() != thread()) qFatal("Restoration cancellation must run on its owner thread");
    if (session_) session_->cancel();
}
bool RestoreJob::start(VaultReplacementAuthorization authority, const QString& source,
    core::SecureBuffer password, const QString& precaution)
try {
    if (QThread::currentThread() != thread()) qFatal("Restoration must start on its owner thread");
    if (started_) return false;
    started_ = true;
    const auto path = [](const QString& p) { return QDir::isAbsolutePath(p) && !p.contains(QChar::Null) && p.toUtf8().size() <= 4096; };
    struct stat program{};
    if (!path(worker_) || !path(source) || (!precaution.isEmpty() && !path(precaution))
        || password.empty() || password.size() > wire::passwordLimit
        || ::lstat(QFile::encodeName(worker_).constData(), &program) != 0 || !S_ISREG(program.st_mode)
        || program.st_uid != ::geteuid() || (program.st_mode & 0022) || !(program.st_mode & 0100)) {
        startError_ = QStringLiteral("Auxiliaire, chemins ou taille de mot de passe invalides."); return false;
    }
    int pair[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) != 0) {
        startError_ = QStringLiteral("Canal privé de restauration indisponible."); return false;
    }
    const int parentFd = ::fcntl(pair[0], F_DUPFD_CLOEXEC, 64);
    const int childFd = ::fcntl(pair[1], F_DUPFD_CLOEXEC, 64);
    ::close(pair[0]); ::close(pair[1]);
    if (parentFd < 0 || childFd < 0) {
        if (parentFd >= 0) ::close(parentFd); if (childFd >= 0) ::close(childFd);
        startError_ = QStringLiteral("Descripteurs privés indisponibles."); return false;
    }
    try {
        struct StartupFds {
            int parent, child;
            ~StartupFds() noexcept { if (parent >= 0) ::close(parent); if (child >= 0) ::close(child); }
        } startup{parentFd, childFd};
        auto session = std::make_unique<RestoreProcessSession>(this, std::move(authority), std::move(password), source, precaution, parentFd, childFd);
        startup.parent = startup.child = -1; // Exactly one fd owner from here.
        QTimer::singleShot(0, session.get(), [s = session.get(), program = worker_] { s->launch(program); });
        session_ = session.get(); active_ = true;
        session.release();
        return true;
    } catch (...) {
        startError_ = QStringLiteral("Délégation de restauration refusée."); return false;
    }
} catch (...) {
    startError_ = QStringLiteral("Préparation de l'auxiliaire interrompue.");
    return false; // By-value password/authority unwind before returning to GUI.
}
} // namespace passwall::services
