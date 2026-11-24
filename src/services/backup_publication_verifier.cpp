#include "services/backup_publication_verifier_internal.hpp"
#include "services/backup_protocol.hpp"

#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <utility>

namespace passwall::services {
namespace backup_publication_detail {
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
} // namespace backup_publication_detail

bool BackupPublicationVerifier::inspectEncryptedFile(const QString& path, BackupFileEvidence& output,
    QString& error, SnapshotCancellation cancellation)
{
    output = {}; error.clear();
    backup_publication_detail::Opened file;
    if (!backup_publication_detail::inspect(path, file, error, cancellation)) return false;
    output = std::move(file.evidence); return true;
}

} // namespace passwall::services
