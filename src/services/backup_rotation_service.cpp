#include "services/backup_rotation_service.hpp"
#include "services/backup_publication_verifier_internal.hpp"
#include "services/vault_preferences_store.hpp"

#include <QFileInfo>
#include <QUuid>
#include <algorithm>
#include <fcntl.h>

namespace passwall::services {
namespace {
using namespace backup_publication_detail;
bool binding(const QString& path, const Opened& o, QString& error)
{
    Fd namedDirectory;
    if (!openDirectory(QFileInfo(path).absolutePath(), namedDirectory, error)) return false;
    struct stat d {}, f {}, named {};
    quint64 mount = 0; QString birth;
    extendedIdentity(namedDirectory.value, mount, birth);
    if (::fstat(namedDirectory.value, &d) != 0 || quint64(d.st_dev) != o.evidence.directoryDevice
        || quint64(d.st_ino) != o.evidence.directoryInode || mount != o.evidence.directoryMount
        || birth != o.evidence.directoryBirth
        || ::fstatat(o.directory.value, o.name.constData(), &named, AT_SYMLINK_NOFOLLOW) != 0
        || ::fstat(o.file.value, &f) != 0 || !sameStat(f, o.stable) || !sameStat(named, o.stable))
        return fail(error, "Destination ou version substituée avant suppression.");
    return true;
}
} // namespace

using namespace backup_publication_detail;

RotationResult BackupRotationService::rotate(const QString& settings, const QString& localId,
    const QString& attempt, const QString& source, const storage::VaultOperationGuard& reservation,
    SnapshotCancellation cancellation)
{
    RotationResult result{RotationOutcome::Refused, {}, 0};
    QString& error = result.diagnostic;
    std::string failure;
    if (QUuid(localId).isNull() || QUuid(attempt).isNull()
        || !reservation.matchesReservation(source.toStdString(), failure)) {
        error = QStringLiteral("Identité ou réservation de rotation invalide."); return result;
    }
    VaultPreferencesStore store(settings);
    VaultRegistration record;
    if (!store.claimRotation(localId, attempt, reservation, record, error)) return result;
    // Source is also checked against the inherited capability, never trusted
    // solely because the request or the JSON contains its path.
    if (record.file.path != source) { error = QStringLiteral("Coffre de rotation incohérent."); return result; }
    QVector<AutomaticBackupVersion> current;
    for (const auto& version : record.automaticVersions)
        if (QFileInfo(version.path).absolutePath() == record.backup.directory
            && (version.destinationEpoch.isEmpty() || version.destinationEpoch == record.backupEpoch))
            current.push_back(version);
    std::stable_sort(current.begin(), current.end(), [](const auto& a, const auto& b) { return a.order < b.order; });
    const auto excess = current.size() - record.backup.retainedVersions;
    if (excess > 0) {
        const auto& latest = record.automaticVersions.last();
        storage::VaultOperationGuard latestAccess;
        if (!latestAccess.tryReserve(latest.path.toStdString(), failure)) {
            error = QStringLiteral("Nouvelle sauvegarde occupée ; rotation refusée."); return result;
        }
        Opened newest;
        if (!latest.evidence || !latest.evidence->permitsDeletion()
            || !inspect(latest.path, newest, error, cancellation) || newest.evidence != *latest.evidence) {
            if (error.isEmpty()) error = QStringLiteral("Nouvelle publication non vérifiable ; rotation refusée.");
            if (cancelled(cancellation)) result.outcome = RotationOutcome::Cancelled;
            return result;
        }
        for (qsizetype index = 0; index < excess; ++index) {
            const auto& candidate = current[index];
            if (cancelled(cancellation)) { result.outcome = RotationOutcome::Cancelled; error = QStringLiteral("Rotation annulée."); return result; }
            if (!candidate.durable || !candidate.order || !candidate.evidence || !candidate.evidence->permitsDeletion()
                || candidate.attemptId == attempt || candidate.path == source || candidate.path == latest.path
                || (candidate.device == record.file.device && candidate.inode == record.file.inode)
                || candidate.destinationEpoch != record.backupEpoch
                || candidate.evidence->directoryDevice != record.backupDirectory.device
                || candidate.evidence->directoryInode != record.backupDirectory.inode) {
                error = QStringLiteral("Ancienne version insuffisamment identifiable ; conservation prioritaire."); return result;
            }
            storage::VaultOperationGuard candidateAccess;
            if (!candidateAccess.tryReserve(candidate.path.toStdString(), failure)) {
                error = QStringLiteral("Ancienne version occupée ou ambiguë ; conservation prioritaire."); return result;
            }
            Opened old;
            if (!inspect(candidate.path, old, error, cancellation) || old.evidence != *candidate.evidence) {
                if (error.isEmpty()) error = QStringLiteral("Identité ou empreinte de version modifiée ; conservation prioritaire.");
                if (cancelled(cancellation)) result.outcome = RotationOutcome::Cancelled;
                return result;
            }
            if (!store.markRotationDeletion(localId, attempt, candidate, reservation, error)) return result;
            if (cancelled(cancellation)) { result.outcome = RotationOutcome::Cancelled; error = QStringLiteral("Rotation annulée avant suppression."); return result; }
            if (!binding(latest.path, newest, error) || !binding(candidate.path, old, error)) return result;
            if (cancelled(cancellation)) { result.outcome = RotationOutcome::Cancelled; error = QStringLiteral("Rotation annulée avant suppression."); return result; }
            // Directory-relative unlink after final binding checks. The private
            // write permissions and cooperative reservations exclude ordinary
            // concurrent PassWall writers. Linux has no unlink-by-open-inode;
            // this is NOT an absolute defence against an actively racing UID.
            if (::unlinkat(old.directory.value, old.name.constData(), 0) != 0) {
                systemFailure(error, "Suppression de version impossible"); return result;
            }
            if (::fsync(old.directory.value) != 0) {
                result.outcome = RotationOutcome::Unknown;
                systemFailure(error, "Suppression effectuée ; durabilité non confirmée"); return result;
            }
            if (!store.confirmRotationDeletion(localId, attempt, candidate.attemptId, reservation, error)) {
                result.outcome = RotationOutcome::Unknown; return result;
            }
            ++result.deleted;
        }
    }
    if (cancelled(cancellation)) { result.outcome = RotationOutcome::Cancelled; error = QStringLiteral("Rotation interrompue."); return result; }
    result.outcome = store.completeRotation(localId, attempt, reservation, error)
        ? RotationOutcome::Complete : RotationOutcome::Unknown;
    return result;
}
} // namespace passwall::services
