#include "services/backup_protocol.hpp"
#include "services/vault_snapshot_service.hpp"
#include "services/backup_rotation_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QCoreApplication>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/prctl.h>
#include <unistd.h>

namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }

struct ParentChannel {
    pid_t parent = ::getppid();
    bool cancelled = false;
    static bool check(void* context, passwall::services::SnapshotCheckpoint) noexcept
    {
        auto& self = *static_cast<ParentChannel*>(context);
        if (stopping || ::getppid() != self.parent || self.parent <= 1) self.cancelled = true;
        char byte;
        for (;;) {
            const auto count = ::read(STDIN_FILENO, &byte, 1);
            if (count > 0 || count == 0) { self.cancelled = true; break; }
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) self.cancelled = true;
            break;
        }
        return self.cancelled;
    }
};

bool writeResult(const QByteArray& result)
{
    if (result.size() > passwall::services::backup_protocol::resultLimit) return false;
    qsizetype offset = 0;
    while (offset < result.size()) {
        const auto count = ::write(STDOUT_FILENO, result.constData() + offset, result.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += count;
    }
    return true;
}
} // namespace

int main(int argc, char** argv)
{
    using namespace passwall::services;
    ParentChannel channel; // Capture parent before any initialization/work.
    // Outlive Qt teardown too: no application callback can outlive the source
    // reservation. Parent supervision additionally retains it until child exit.
    passwall::storage::VaultOperationGuard reservation;
    struct sigaction action{};
    action.sa_handler = stop;
    ::sigemptyset(&action.sa_mask);
    if (::sigaction(SIGTERM, &action, nullptr) != 0
        || ::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) return 2;
    ::signal(SIGPIPE, SIG_IGN); // A vanished reader is an IPC failure, not a dump.
    QCoreApplication application(argc, argv);
    const auto arguments = application.arguments();
    const bool rotation = arguments.size() >= 2 && arguments[1] == QStringLiteral("--rotation-v1");
    if ((arguments.size() != 2 && arguments.size() != 4)
        || (!rotation && arguments[1] != QStringLiteral("--protocol-v1"))
        || (rotation && arguments.size() != 4))
        return 2;
    SnapshotResult snapshot;
    std::optional<BackupFileEvidence> receipt;
    try {
        // Exactly one bounded request line. Any later byte is cancellation.
        QByteArray request;
        while (!stopping && request.size() <= backup_protocol::requestLimit) {
            char byte;
            const auto count = ::read(STDIN_FILENO, &byte, 1);
            if (count < 0 && errno == EINTR) continue;
            if (count != 1) return 2;
            request += byte;
            if (byte == '\n') break;
        }
        QString source, destination;
        std::optional<SnapshotDirectoryIdentity> expectedDirectory;
        AutomaticBackupContext context;
        bool wantReceipt = false;
        if (stopping || !request.endsWith('\n') || (rotation
            ? !backup_protocol::parseRotationRequest(request, source, context)
            : !backup_protocol::parseRequest(request, source, destination, &expectedDirectory, &wantReceipt)))
            return 2;
        std::string reservationError;
        if (arguments.size() == 4) {
            bool first = false, second = false;
            const int a = arguments[2].toInt(&first), b = arguments[3].toInt(&second);
            if (!first || !second || a < 64 || (b != -1 && (b < 64 || b == a))
                || !reservation.adoptReservation(source.toStdString(), {a, b}, reservationError)) return 2;
        } else if (!reservation.tryReserve(source.toStdString(), reservationError)) {
            snapshot.diagnostic = reservationError;
            return writeResult(backup_protocol::result({BackupOutcome::FailedBeforePublication,
                QString::fromStdString(reservationError)})) ? 0 : 2;
        }
        const int flags = ::fcntl(STDIN_FILENO, F_GETFL);
        if (flags < 0 || ::fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) != 0) return 2;
        if (rotation) {
            const auto result = BackupRotationService::rotate(context.settingsFile, context.localId,
                context.attempt, source, reservation, {&ParentChannel::check, &channel});
            return writeResult(backup_protocol::rotationResult(result)) ? 0 : 2;
        }
        struct EvidenceContext {
            BackupFileEvidence evidence;
            ParentChannel* channel;
            static bool verify(void* pointer, const std::string& path, std::string& error) {
                auto& self = *static_cast<EvidenceContext*>(pointer);
                QString diagnostic;
                const bool ok = BackupRotationService::inspectEncryptedFile(QString::fromStdString(path),
                    self.evidence, diagnostic, {&ParentChannel::check, self.channel});
                error = diagnostic.toStdString(); return ok;
            }
        } evidence{{}, &channel};
        const bool success = VaultSnapshotService::createSnapshot(source.toStdString(), destination.toStdString(),
            snapshot, {&ParentChannel::check, &channel},
            wantReceipt ? SnapshotVerification{&EvidenceContext::verify, &evidence} : SnapshotVerification{}, &reservation,
            expectedDirectory ? &*expectedDirectory : nullptr);
        (void)success; // Publication state, not bool/exit code, is authoritative.
        if (wantReceipt && (snapshot.publication == SnapshotPublication::Published
            || snapshot.publication == SnapshotPublication::PublishedDurabilityUnconfirmed)) {
            BackupFileEvidence published;
            QString error;
            if (!BackupRotationService::inspectEncryptedFile(destination, published, error,
                    {&ParentChannel::check, &channel})
                || published.device != evidence.evidence.device || published.inode != evidence.evidence.inode
                || published.birth != evidence.evidence.birth || published.size != evidence.evidence.size
                || published.modified != evidence.evidence.modified || published.sha256 != evidence.evidence.sha256
                || published.mount != evidence.evidence.mount
                || (expectedDirectory && (published.directoryDevice != expectedDirectory->device
                    || published.directoryInode != expectedDirectory->inode))) return 2;
            receipt = std::move(published);
        }
    } catch (...) {
        if (rotation) return 2; // Missing rotation result is uncertainty, never copy failure.
        // Never print exception text, paths or database contents.
        snapshot.diagnostic.clear();
    }
    BackupOutcome outcome = BackupOutcome::FailedBeforePublication;
    switch (snapshot.publication) {
    case SnapshotPublication::NotPublished: break;
    case SnapshotPublication::CancelledBeforePublication: outcome = BackupOutcome::CancelledBeforePublication; break;
    case SnapshotPublication::Published: outcome = BackupOutcome::Published; break;
    case SnapshotPublication::PublishedDurabilityUnconfirmed: outcome = BackupOutcome::DurabilityUnconfirmed; break;
    }
    try {
        return writeResult(backup_protocol::result({outcome, QString::fromStdString(snapshot.diagnostic), receipt})) ? 0 : 2;
    } catch (...) { return 2; } // Missing record is UNKNOWN to the parent.
}
