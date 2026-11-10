#include "services/restore_protocol.hpp"
#include "services/restore_job.hpp"
#include "services/restore_delegation.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QUuid>
#include <QFileInfo>
#include <QSettings>
#include <csignal>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sodium.h>
#include <climits>
#include <stdexcept>

namespace {
volatile std::sig_atomic_t interrupted = 0;
pid_t parentPid = 0;
void interrupt(int) { interrupted = 1; }
bool stopped() noexcept { return interrupted || ::getppid() != parentPid; }
bool parentExecutable(const QString& expected) {
    struct stat actual {}, trusted {};
    const auto proc = QByteArray("/proc/") + QByteArray::number(parentPid) + "/exe";
    const auto encoded = QFile::encodeName(expected);
    return ::stat(proc.constData(), &actual) == 0 && ::lstat(encoded.constData(), &trusted) == 0
        && S_ISREG(trusted.st_mode) && trusted.st_uid == ::geteuid() && !(trusted.st_mode & 0022)
        && actual.st_dev == trusted.st_dev && actual.st_ino == trusted.st_ino;
}
bool canonicalUuid(const QString& value) {
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces) == value;
}
}

namespace passwall::services {
namespace wire = restore_protocol;
// Friend of the narrow bridge only, never of the authority/6A issuer.
class RestoreWorker final {
public:
    int run(int fd, std::array<int, 2> locks) {
        fd_ = fd;
        try {
            wire::Type type; quint32 size; QJsonObject begin;
            if (!wire::readHeader(fd_, type, size, stopped) || type != wire::Begin
                || !wire::readObject(fd_, size, begin, stopped) || begin.size() != 7 || begin["v"] != QJsonValue(1)
                || !begin["source"].isString() || !begin["precaution"].isString()
                || !begin["size"].isDouble()) return 65;
            operation_ = begin["operation"].toString(); session_ = begin["session"].toString();
            const auto grant = begin["grant"].toObject();
            const int passwordSize = begin["size"].toInt(-1);
            if (!canonicalUuid(operation_) || !canonicalUuid(session_) || grant.size() != 8
                || grant["operation"] != QJsonValue(operation_) || passwordSize <= 0
                || quint32(passwordSize) > wire::passwordLimit || begin["size"].toDouble() != passwordSize) return 65;
            for (auto it = grant.begin(); it != grant.end(); ++it)
                if (!it.value().isString()) return 65;
            // Ordinary storage/authentication gates must consult THIS parent's
            // registry too, never another default configuration (notably tests).
            QDir configRoot(QFileInfo(grant["config"].toString()).absolutePath());
            if (!configRoot.cdUp()) return 65;
            for (auto format : {QSettings::NativeFormat, QSettings::IniFormat})
                for (auto scope : {QSettings::UserScope, QSettings::SystemScope})
                    QSettings::setPath(format, scope, configRoot.absolutePath());
            if (QSettings("PassWall", "PassWall").fileName() != grant["config"].toString()) return 65;
            // Parent executable/socket origin was established BEFORE this API.
            auto authority = RestoreWorkerAdmission::receive(grant, locks,
                [this] { return live(); }, result_.diagnostic);
            retained_ = RestoreWorkerAdmission::retain(authority); // Holds all inode locks until _exit.
            result_.operationId = operation_;
            RestoreOutcome kind = RestoreOutcome::Refused;
            if (retained_) kind = execute(authority, begin, passwordSize);
            // execute has returned: every password/DEK/credential RAII scope
            // has ended, including malformed input, exceptions and cancellation.
            clean();
            auto output = bound(); output["kind"] = int(kind); output["result"] = wire::encode(result_);
            const bool sent = wire::send(fd_, wire::Result, output);
            // Do not destruct retained_ before process termination. This is an
            // intentional descriptor lifetime, NOT a shortcut for secret RAII.
            ::_exit(sent ? 0 : 74);
        } catch (...) {
            try { clean(); } catch (...) {}
            ::_exit(70); // Keep retained inode guards until actual OS exit too.
        }
    }
private:
    QJsonObject bound() const { return {{"operation", operation_}, {"session", session_}}; }
    bool live() noexcept {
        try {
            if (cancelled_ || stopped() || sequence_ == INT_MAX) return cancelReceived();
            auto request = bound(); request["n"] = ++sequence_;
            if (!wire::send(fd_, wire::Probe, request)) return cancelReceived();
            wire::Type type; quint32 size; QJsonObject permit;
            if (!wire::readHeader(fd_, type, size, stopped) || type != wire::Permit
                || !wire::readObject(fd_, size, permit, stopped) || permit.size() != 3
                || !wire::bound(permit, operation_, session_) || permit["n"] != QJsonValue(sequence_)
                || stopped()) return cancelReceived();
            return true;
        } catch (...) { return cancelReceived(); }
    }
    bool cancelReceived() noexcept {
        if (!cancelled_) {
            cancelled_ = true;
            try { wire::send(fd_, wire::CancelReceived, bound()); } catch (...) {}
        }
        return false;
    }
    void clean() {
        if (cleaned_) return;
        if (!wire::send(fd_, wire::Cleaned, bound())) throw std::runtime_error("Cleanup transport failed");
        cleaned_ = true;
    }
    static bool checkpoint(void* pointer, ReplacementCheckpoint point) noexcept {
        auto& worker = *static_cast<RestoreWorker*>(pointer);
        try {
            if (point == ReplacementCheckpoint::SourceAuthenticated) worker.clean();
            auto message = worker.bound(); message["phase"] = int(point);
            if (!wire::send(worker.fd_, wire::Phase, message)) return true;
            // Admission boundary: after this permit a syscall already admitted
            // cannot be recalled by an in-flight parent cancellation.
            return !worker.live();
        } catch (...) { return true; }
    }
    RestoreOutcome execute(VaultReplacementAuthorization& authority, const QJsonObject& begin, int size) {
        core::SecureBuffer password(0);
        try {
            if (!wire::send(fd_, wire::Ready, bound())) return RestoreOutcome::TransportFailed;
            wire::Type type; quint32 length;
            if (!wire::readHeader(fd_, type, length, stopped) || type != wire::Password || length != quint32(size)) {
                cancelReceived(); return RestoreOutcome::TransportFailed;
            }
            password = core::SecureBuffer(size);
            if (!wire::transfer(fd_, password.data(), password.size(), false, stopped)) {
                cancelReceived(); return RestoreOutcome::TransportFailed;
            }
            if (!wire::send(fd_, wire::Received, bound())) return RestoreOutcome::TransportFailed;
            const bool replaced = authority.replacePrincipal(begin["grant"].toObject()["principal"].toString(), begin["source"].toString(),
                std::move(password), begin["precaution"].toString(), result_, {checkpoint, this});
            Q_UNUSED(replaced); // Structured outcome, not this bool, crosses IPC.
            if (cancelled_ && result_.outcome == ReplacementOutcome::NotReplaced) {
                result_.outcome = ReplacementOutcome::CancelledBeforeEngagement;
                result_.sourceAuthenticationFailed = false;
            }
            if (result_.sourceAuthenticationFailed) return RestoreOutcome::SourceAuthenticationFailed;
            return RestoreOutcome::EngineResult;
        } catch (...) {
            result_.diagnostic = QStringLiteral("Phase sensible interrompue ; aucun résultat complet confirmé.");
            return RestoreOutcome::Unknown;
        }
    }
    int fd_ = -1, sequence_ = 0;
    QString operation_, session_;
    bool cancelled_ = false, cleaned_ = false;
    ReplacementResult result_;
    std::shared_ptr<void> retained_; // No access to private State or issuer methods.
};
} // namespace passwall::services

int main(int argc, char** argv) {
    parentPid = ::getppid();
    ::signal(SIGPIPE, SIG_IGN);
    struct sigaction action{}; action.sa_handler = interrupt; sigemptyset(&action.sa_mask);
    if (::sigaction(SIGTERM, &action, nullptr) != 0
        || ::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || stopped()) return 70;
    QCoreApplication app(argc, argv);
    if (argc != 5 || QByteArray(argv[1]) != "--restore-v1") return 64;
    std::array<int, 3> descriptors{};
    for (int i = 0; i < 3; ++i) {
        bool ok = false; const QByteArray value(argv[i + 2]);
        descriptors[i] = value.toInt(&ok);
        if (!ok || descriptors[i] < 64 || QByteArray::number(descriptors[i]) != value
            || ::fcntl(descriptors[i], F_GETFD) < 0) return 64;
        for (int j = 0; j < i; ++j) if (descriptors[j] == descriptors[i]) return 64;
        if (::fcntl(descriptors[i], F_SETFD, FD_CLOEXEC) != 0) return 64;
    }
    ucred peer{}; socklen_t length = sizeof(peer);
    int type = 0; socklen_t typeLength = sizeof(type);
    if (::getsockopt(descriptors[0], SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0
        || length != sizeof(peer) || peer.pid != parentPid || peer.uid != ::geteuid()
        || ::getsockopt(descriptors[0], SOL_SOCKET, SO_TYPE, &type, &typeLength) != 0
        || type != SOCK_STREAM) return 77;
    bool trusted = parentExecutable(QCoreApplication::applicationDirPath() + "/passwall_app");
#ifdef PASSWALL_RESTORE_WORKER_TESTING
    // Separate executable only. No alternate parents in the production worker.
    trusted = parentExecutable(QString::fromUtf8(RESTORE_TEST_PARENT))
        || parentExecutable(QString::fromUtf8(RESTORE_GUI_PARENT));
#endif
    if (!trusted || stopped() || sodium_init() < 0) return 77;
    passwall::services::RestoreWorker worker;
    return worker.run(descriptors[0], {descriptors[1], descriptors[2]});
}
