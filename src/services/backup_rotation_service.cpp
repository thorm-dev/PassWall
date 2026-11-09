#include "services/backup_rotation_service.hpp"
#include "services/vault_preferences_store.hpp"

#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QUuid>
#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace passwall::services {
namespace {
struct Fd {
    int value = -1;
    Fd() = default;
    explicit Fd(int v) : value(v) {}
    ~Fd() noexcept { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
bool fail(QString& error, const char* operation)
{
    error = QString::fromUtf8(operation); return false;
}
bool systemFailure(QString& error, const char* operation)
{
    const int saved = errno;
    error = QString::fromUtf8(operation) + QStringLiteral(" [errno=%1].").arg(saved); return false;
}
bool cancelled(SnapshotCancellation c)
{ return c.requested && c.requested(c.context, SnapshotCheckpoint::CopyStep); }
QString stamp(qint64 seconds, quint32 nanos)
{ return QString::number(seconds) + ':' + QString::number(nanos); }
bool trusted(int fd)
{
    struct stat s {};
    return ::fstat(fd, &s) == 0 && (s.st_uid == 0 || s.st_uid == ::geteuid())
        && (!(s.st_mode & 0022) || (s.st_uid == 0 && (s.st_mode & S_ISVTX)));
}
bool openDirectory(const QString& path, Fd& dir, QString& error)
{
    if (!backup_protocol::validPath(path) || QDir::cleanPath(path) != path)
        return fail(error, "Chemin de rotation non canonique.");
    dir.value = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir.value < 0) return systemFailure(error, "Ouverture de la racine impossible");
    for (const auto& part : path.split('/', Qt::SkipEmptyParts)) {
        const auto name = QFile::encodeName(part);
        const int next = ::openat(dir.value, name.constData(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) return systemFailure(error, "Répertoire inaccessible ou lien refusé");
        ::close(dir.value); dir.value = next;
        if (!trusted(next)) return fail(error, "Ancêtre de destination non sûr.");
    }
    struct stat s {};
    struct statfs fs {};
    if (::fstat(dir.value, &s) != 0 || s.st_uid != ::geteuid() || (s.st_mode & 0022))
        return fail(error, "Destination de rotation non privée en écriture.");
    if (::fstatfs(dir.value, &fs) != 0) return systemFailure(error, "Système de fichiers non identifiable");
    switch (fs.f_type) {
    case EXT4_SUPER_MAGIC: case TMPFS_MAGIC: case XFS_SUPER_MAGIC:
    case BTRFS_SUPER_MAGIC: case F2FS_SUPER_MAGIC: case OVERLAYFS_SUPER_MAGIC: return true;
    default: return fail(error, "Rotation non prise en charge sur ce système de fichiers.");
    }
}
void extendedIdentity(int fd, quint64& mount, QString& birth)
{
    struct statx s {};
    mount = 0; birth.clear();
    if (::statx(fd, "", AT_EMPTY_PATH, STATX_BTIME | STATX_MNT_ID, &s) == 0) {
        if (s.stx_mask & STATX_BTIME) birth = stamp(s.stx_btime.tv_sec, s.stx_btime.tv_nsec);
        if (s.stx_mask & STATX_MNT_ID) mount = s.stx_mnt_id;
    }
}
bool sameStat(const struct stat& a, const struct stat& b)
{
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size
        && a.st_mode == b.st_mode && a.st_uid == b.st_uid && a.st_nlink == b.st_nlink
        && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
        && a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
struct Opened {
    Fd directory, file;
    QByteArray name;
    struct stat stable {};
    BackupFileEvidence evidence;
};
bool inspect(const QString& path, Opened& o, QString& error, SnapshotCancellation cancellation)
{
    if (!backup_protocol::validPath(path) || QDir::cleanPath(path) != path)
        return fail(error, "Chemin de fichier non canonique.");
    const QFileInfo info(path);
    if (!openDirectory(info.absolutePath(), o.directory, error)) return false;
    o.name = QFile::encodeName(info.fileName());
    o.file.value = ::openat(o.directory.value, o.name.constData(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (o.file.value < 0) return systemFailure(error, "Ouverture de version impossible");
    struct stat parent {};
    if (::fstat(o.directory.value, &parent) != 0 || ::fstat(o.file.value, &o.stable) != 0)
        return systemFailure(error, "Identité de version inaccessible");
    if (!S_ISREG(o.stable.st_mode) || o.stable.st_uid != ::geteuid() || o.stable.st_nlink != 1
        || (o.stable.st_mode & 0777) != 0600 || o.stable.st_size <= 0)
        return fail(error, "Version non régulière, liée ou permissions ambiguës.");
    auto& e = o.evidence;
    e.device = o.stable.st_dev; e.inode = o.stable.st_ino; e.size = o.stable.st_size;
    e.directoryDevice = parent.st_dev; e.directoryInode = parent.st_ino;
    e.modified = stamp(o.stable.st_mtim.tv_sec, o.stable.st_mtim.tv_nsec);
    e.changed = stamp(o.stable.st_ctim.tv_sec, o.stable.st_ctim.tv_nsec);
    extendedIdentity(o.file.value, e.mount, e.birth);
    extendedIdentity(o.directory.value, e.directoryMount, e.directoryBirth);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    std::array<char, 65536> bytes;
    quint64 total = 0;
    for (;;) {
        if (cancelled(cancellation)) return fail(error, "Rotation ou vérification annulée.");
        const auto count = ::read(o.file.value, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return systemFailure(error, "Lecture de version impossible");
        if (!count) break;
        // A concurrently growing file must not cause an unbounded verification.
        if (quint64(count) > e.size - total) return fail(error, "Taille modifiée pendant la vérification.");
        total += count;
        hash.addData(QByteArrayView(bytes.data(), count));
    }
    struct stat after {}, named {};
    if (total != e.size || ::fstat(o.file.value, &after) != 0
        || ::fstatat(o.directory.value, o.name.constData(), &named, AT_SYMLINK_NOFOLLOW) != 0
        || !sameStat(o.stable, after) || !sameStat(o.stable, named))
        return fail(error, "Version substituée ou modifiée pendant la vérification.");
    e.sha256 = hash.result();
    return true;
}
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

bool BackupRotationService::inspectEncryptedFile(const QString& path, BackupFileEvidence& output,
    QString& error, SnapshotCancellation cancellation)
{
    output = {}; error.clear();
    Opened file;
    if (!inspect(path, file, error, cancellation)) return false;
    output = std::move(file.evidence); return true;
}

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
