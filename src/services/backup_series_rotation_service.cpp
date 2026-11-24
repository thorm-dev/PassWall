#include "services/backup_series_rotation_service.hpp"

#include "services/backup_publication_verifier.hpp"
#include "services/backup_series_identity.hpp"
#include "services/vault_snapshot_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace passwall::services {
namespace {

struct Descriptor {
    int value = -1;
    Descriptor() = default;
    explicit Descriptor(int descriptor) noexcept : value(descriptor) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    Descriptor(Descriptor&& other) noexcept : value(other.value) { other.value = -1; }
    Descriptor& operator=(Descriptor&& other) noexcept
    {
        if (this != &other) {
            if (value >= 0) ::close(value);
            value = other.value;
            other.value = -1;
        }
        return *this;
    }
    ~Descriptor() noexcept { if (value >= 0) ::close(value); }
};

struct OpenedSeries {
    Descriptor descriptor;
    struct stat status {};
};

struct OpenedCandidate {
    Descriptor descriptor;
    QByteArray name;
    struct stat status {};
};

QString posixDiagnostic(const QString& operation)
{
    const int saved = errno;
    return operation + QStringLiteral(" [errno=%1].").arg(saved);
}

bool stopRequested(const BackupSeriesRotationControl& control,
    BackupSeriesRotationCheckpoint checkpoint, const QString& path) noexcept
{
    return control.stopRequested != nullptr
        && control.stopRequested(control.context, checkpoint, path);
}

void stopBeforeDeletion(BackupSeriesRotationResult& result, QString diagnostic)
{
    result.outcome = result.deleted.isEmpty()
        ? BackupSeriesRotationOutcome::Refused
        : BackupSeriesRotationOutcome::Partial;
    result.diagnostic = std::move(diagnostic);
}

bool trustedAncestor(int descriptor)
{
    struct stat status {};
    return ::fstat(descriptor, &status) == 0 && S_ISDIR(status.st_mode)
        && (status.st_uid == 0 || status.st_uid == ::geteuid())
        && ((status.st_mode & 0022) == 0
            || (status.st_uid == 0 && (status.st_mode & S_ISVTX) != 0));
}

SnapshotDirectoryIdentity directoryIdentity(const struct stat& status)
{
    return {static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino)};
}

bool sameDirectoryState(const struct stat& left, const struct stat& right)
{
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode && left.st_uid == right.st_uid
        && left.st_nlink == right.st_nlink
        && left.st_mtim.tv_sec == right.st_mtim.tv_sec
        && left.st_mtim.tv_nsec == right.st_mtim.tv_nsec
        && left.st_ctim.tv_sec == right.st_ctim.tv_sec
        && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

bool sameFileState(const struct stat& left, const struct stat& right)
{
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino
        && left.st_size == right.st_size && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid && left.st_nlink == right.st_nlink
        && left.st_mtim.tv_sec == right.st_mtim.tv_sec
        && left.st_mtim.tv_nsec == right.st_mtim.tv_nsec
        && left.st_ctim.tv_sec == right.st_ctim.tv_sec
        && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

BackupSeriesFileIdentity fileIdentity(const struct stat& status)
{
    return {static_cast<quint64>(status.st_dev),
        static_cast<quint64>(status.st_ino),
        static_cast<quint64>(status.st_size),
        static_cast<quint64>(status.st_uid),
        static_cast<quint64>(status.st_nlink),
        static_cast<quint32>(status.st_mode & 07777),
        static_cast<qint64>(status.st_mtim.tv_sec),
        static_cast<quint32>(status.st_mtim.tv_nsec),
        static_cast<qint64>(status.st_ctim.tv_sec),
        static_cast<quint32>(status.st_ctim.tv_nsec)};
}

bool openPrivateChild(int parent, const QByteArray& name,
    const SnapshotDirectoryIdentity& expected, Descriptor& output,
    struct stat& status, QString& diagnostic)
{
    struct stat named {};
    Descriptor child(::openat(parent, name.constData(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (child.value < 0
        || ::fstat(child.value, &status) != 0
        || ::fstatat(parent, name.constData(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
        diagnostic = posixDiagnostic(
            QStringLiteral("Dossier de rotation inaccessible ou remplacé"));
        return false;
    }
    if (!S_ISDIR(status.st_mode) || !S_ISDIR(named.st_mode)
        || status.st_uid != ::geteuid() || named.st_uid != ::geteuid()
        || (status.st_mode & 07777) != 0700
        || (named.st_mode & 07777) != 0700
        || status.st_dev != named.st_dev || status.st_ino != named.st_ino
        || directoryIdentity(status) != expected) {
        diagnostic = QStringLiteral(
            "Dossier de rotation non privé, ambigu ou substitué.");
        return false;
    }
    output = std::move(child);
    return true;
}

bool openVerifiedSeries(const BackupSeriesRotationRequest& request,
    const BackupSeriesInspectionResult& inspection, OpenedSeries& output,
    QString& diagnostic)
{
    output = {};
    if (!QDir::isAbsolutePath(request.rootDirectory)
        || request.rootDirectory.contains(QChar::Null)
        || QDir::cleanPath(request.rootDirectory) != request.rootDirectory) {
        diagnostic = QStringLiteral("Racine de rotation non canonique.");
        return false;
    }
    Descriptor root(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (root.value < 0) {
        diagnostic = posixDiagnostic(QStringLiteral("Ouverture de la racine impossible"));
        return false;
    }
    for (const QString& component : request.rootDirectory.split(
             QLatin1Char('/'), Qt::SkipEmptyParts)) {
        const QByteArray encoded = QFile::encodeName(component);
        Descriptor next(::openat(root.value, encoded.constData(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (next.value < 0) {
            diagnostic = posixDiagnostic(
                QStringLiteral("Ancêtre de rotation inaccessible ou lien refusé"));
            return false;
        }
        if (!trustedAncestor(next.value)) {
            diagnostic = QStringLiteral("Ancêtre de rotation non protégé.");
            return false;
        }
        root = std::move(next);
    }
    struct stat rootStatus {};
    if (::fstat(root.value, &rootStatus) != 0) {
        diagnostic = posixDiagnostic(QStringLiteral("Identité de racine inaccessible"));
        return false;
    }
    if (rootStatus.st_uid != ::geteuid() || (rootStatus.st_mode & 0022) != 0
        || directoryIdentity(rootStatus) != inspection.rootIdentity) {
        diagnostic = QStringLiteral("Racine de rotation substituée ou non protégée.");
        return false;
    }

    Descriptor family;
    struct stat familyStatus {};
    if (!openPrivateChild(root.value, request.vaultId.toHex(),
            inspection.familyIdentity, family, familyStatus, diagnostic))
        return false;
    Descriptor series;
    struct stat seriesStatus {};
    if (!openPrivateChild(family.value, request.seriesId.toLatin1(),
            inspection.seriesIdentity, series, seriesStatus, diagnostic))
        return false;
    output.descriptor = std::move(series);
    output.status = seriesStatus;
    return true;
}

bool openCandidate(const BackupSeriesVersion& candidate,
    const QString& seriesPath, int seriesDescriptor,
    OpenedCandidate& output, QString& diagnostic)
{
    output = {};
    if (candidate.fileName.isEmpty()
        || candidate.path != QDir(seriesPath).filePath(candidate.fileName)
        || QFileInfo(candidate.path).absolutePath() != seriesPath) {
        diagnostic = QStringLiteral("Chemin du candidat incohérent.");
        return false;
    }
    const QByteArray name = QFile::encodeName(candidate.fileName);
    if (name.isEmpty() || name.contains('/')
        || QString::fromLocal8Bit(name) != candidate.fileName) {
        diagnostic = QStringLiteral("Nom du candidat non réversible.");
        return false;
    }
    struct stat named {}, opened {};
    if (::fstatat(seriesDescriptor, name.constData(),
            &named, AT_SYMLINK_NOFOLLOW) != 0) {
        diagnostic = posixDiagnostic(QStringLiteral("Candidat disparu ou inaccessible"));
        return false;
    }
    // Pin the inode without opening the encrypted contents for reading.
    Descriptor file(::openat(seriesDescriptor, name.constData(),
        O_PATH | O_NOFOLLOW | O_CLOEXEC));
    if (file.value < 0 || ::fstat(file.value, &opened) != 0) {
        diagnostic = posixDiagnostic(QStringLiteral("Identification du candidat impossible"));
        return false;
    }
    if (!sameFileState(named, opened) || !S_ISREG(opened.st_mode)
        || opened.st_uid != ::geteuid() || opened.st_nlink != 1
        || (opened.st_mode & 07777) != 0600 || opened.st_size <= 0
        || fileIdentity(opened) != candidate.identity) {
        diagnostic = QStringLiteral("Candidat substitué, lié ou non protégé.");
        return false;
    }
    output.descriptor = std::move(file);
    output.name = name;
    output.status = opened;
    return true;
}

QByteArray vaultIdBytes(const SnapshotVaultContents& contents)
{
    return QByteArray(reinterpret_cast<const char*>(contents.vaultId.data()),
        static_cast<qsizetype>(contents.vaultId.size()));
}

bool versionMatchesReceipt(const BackupSeriesVersion& version,
    const BackupFileEvidence& receipt)
{
    return version.identity.device == receipt.device
        && version.identity.inode == receipt.inode
        && version.identity.size == receipt.size;
}

const BackupSeriesVersion* findVersion(
    const QVector<BackupSeriesVersion>& versions, const QString& path)
{
    for (const BackupSeriesVersion& version : versions)
        if (version.path == path) return &version;
    return nullptr;
}

bool isExcess(const BackupSeriesInspectionResult& inspection,
    const QString& path)
{
    return findVersion(inspection.excess, path) != nullptr;
}

BackupSeriesInspectionRequest inspectionRequest(
    const BackupSeriesRotationRequest& request)
{
    BackupSeriesInspectionRequest inspection;
    inspection.rootDirectory = request.rootDirectory;
    inspection.vaultId = request.vaultId;
    inspection.seriesId = request.seriesId;
    inspection.retainedVersions = request.retainedVersions;
    inspection.expectedRoot = request.expectedRoot;
    inspection.expectedFamily = request.expectedFamily;
    inspection.expectedSeries = request.expectedSeries;
    return inspection;
}

bool verifyPublication(const BackupSeriesRotationRequest& request,
    const BackupSeriesInspectionResult& inspection,
    const storage::VaultOperationGuard& publicationGuard,
    QString& diagnostic)
{
    std::string reservationError;
    if (!publicationGuard.matchesReservation(
            request.publication.publishedPath.toStdString(), reservationError)) {
        diagnostic = reservationError.empty()
            ? QStringLiteral("Réservation de la nouvelle publication perdue.")
            : QString::fromStdString(reservationError);
        return false;
    }
    if (!request.publication.receipt
        || !request.publication.receipt->permitsDeletion()) {
        diagnostic = QStringLiteral("Preuve de publication insuffisante.");
        return false;
    }
    const BackupSeriesVersion* published = findVersion(
        inspection.admissible, request.publication.publishedPath);
    if (published == nullptr
        || !versionMatchesReceipt(*published, *request.publication.receipt)
        || request.publication.receipt->directoryDevice
            != inspection.seriesIdentity.device
        || request.publication.receipt->directoryInode
            != inspection.seriesIdentity.inode) {
        diagnostic = QStringLiteral(
            "La nouvelle publication n'est pas une version admissible de cette série.");
        return false;
    }
    BackupFileEvidence observed;
    QString evidenceError;
    if (!BackupPublicationVerifier::inspectEncryptedFile(
            request.publication.publishedPath, observed, evidenceError)
        || observed != *request.publication.receipt) {
        diagnostic = evidenceError.isEmpty()
            ? QStringLiteral("Preuve de publication devenue incohérente.")
            : evidenceError;
        return false;
    }
    return true;
}

// The only SQLite screening in generational rotation concerns the fresh
// publication. Its receipt is independently rechecked at every deletion gate.
bool validatePublicationContents(const BackupSeriesRotationRequest& request,
    const BackupSeriesInspectionResult& inspection, QString& diagnostic)
{
    const auto* published = findVersion(inspection.admissible,
        request.publication.publishedPath);
    SnapshotSourceIdentity identity;
    SnapshotVaultContents contents;
    std::string structuralError;
    if (published == nullptr
        || !VaultSnapshotService::prevalidateVaultSourceLightweight(
            request.publication.publishedPath.toStdString(), structuralError,
            &identity, &contents)
        || identity.device != published->identity.device
        || identity.inode != published->identity.inode
        || vaultIdBytes(contents) != request.vaultId) {
        diagnostic = structuralError.empty()
            ? QStringLiteral("Structure, identité ou vault_id de la nouvelle publication divergent.")
            : QString::fromStdString(structuralError);
        return false;
    }
    return true;
}

bool finalCandidateBinding(const BackupSeriesVersion& candidate,
    const QString& seriesPath, const OpenedSeries& before,
    const OpenedSeries& current, const OpenedCandidate& reserved,
    OpenedCandidate& opened, QString& diagnostic)
{
    struct stat held {};
    if (::fstat(reserved.descriptor.value, &held) != 0
        || fileIdentity(held) != candidate.identity) {
        diagnostic = QStringLiteral("Identité physique du candidat modifiée avant suppression.");
        return false;
    }
    if (!sameDirectoryState(before.status, current.status)) {
        diagnostic = QStringLiteral(
            "Le dossier de série a changé avant la suppression.");
        return false;
    }
    return openCandidate(candidate, seriesPath,
        current.descriptor.value, opened, diagnostic);
}

} // namespace

BackupSeriesRotationResult BackupSeriesRotationService::rotate(
    const BackupSeriesRotationRequest& supplied)
{
    BackupSeriesRotationResult result;
    try {
        const BackupSeriesRotationRequest request = supplied;
        if (request.publication.outcome != BackupOutcome::Published
            || !request.publication.receipt
            || !request.publication.receipt->permitsDeletion()
            || request.publication.publishedPath.isEmpty()
            || QDir::cleanPath(request.publication.publishedPath)
                != request.publication.publishedPath) {
            stopBeforeDeletion(result,
                QStringLiteral("Seule une publication terminale confirmée autorise la rotation."));
            return result;
        }
        const QString expectedSeries = QDir(QDir(request.rootDirectory).filePath(
            QString::fromLatin1(request.vaultId.toHex()))).filePath(request.seriesId);
        if (QFileInfo(request.publication.publishedPath).absolutePath()
            != expectedSeries) {
            stopBeforeDeletion(result,
                QStringLiteral("La publication ne se trouve pas dans la série attendue."));
            return result;
        }
        if (stopRequested(request.control,
                BackupSeriesRotationCheckpoint::BeforeInspection, expectedSeries)) {
            stopBeforeDeletion(result, QStringLiteral("Rotation annulée avant inspection."));
            return result;
        }

#ifndef Q_OS_UNIX
        stopBeforeDeletion(result,
            QStringLiteral("Rotation sécurisée indisponible sur cette plateforme."));
        return result;
#else
        storage::VaultOperationGuard publicationGuard;
        std::string reservationError;
        if (!publicationGuard.tryReserve(
                request.publication.publishedPath.toStdString(), reservationError)) {
            stopBeforeDeletion(result, reservationError.empty()
                ? QStringLiteral("Nouvelle publication occupée ou non réservable.")
                : QString::fromStdString(reservationError));
            return result;
        }

        BackupSeriesInspectionRequest inspect = inspectionRequest(request);
        BackupSeriesInspectionResult inspection = BackupSeriesInspector::inspect(inspect);
        if (!inspection.selectionComplete()) {
            stopBeforeDeletion(result, inspection.diagnostic.isEmpty()
                ? QStringLiteral("Inspection de série ambiguë ou incomplète.")
                : inspection.diagnostic);
            return result;
        }
        inspect.expectedRoot = inspection.rootIdentity;
        inspect.expectedFamily = inspection.familyIdentity;
        inspect.expectedSeries = inspection.seriesIdentity;

        QString diagnostic;
        if (!verifyPublication(request, inspection, publicationGuard, diagnostic)
            || !validatePublicationContents(request, inspection, diagnostic)) {
            stopBeforeDeletion(result, std::move(diagnostic));
            return result;
        }
        if (isExcess(inspection, request.publication.publishedPath)) {
            stopBeforeDeletion(result, QStringLiteral(
                "Le numéro de génération placerait la nouvelle publication parmi les excédents."));
            return result;
        }
        if (inspection.excess.isEmpty()) {
            result.outcome = BackupSeriesRotationOutcome::NoRotationNecessary;
            return result;
        }
        result.deleted.reserve(inspection.excess.size());

        for (;;) {
            diagnostic.clear();
            if (stopRequested(request.control,
                    BackupSeriesRotationCheckpoint::BeforeCandidateReservation,
                    inspection.seriesDirectory)) {
                stopBeforeDeletion(result, QStringLiteral("Rotation interrompue."));
                return result;
            }
            inspection = BackupSeriesInspector::inspect(inspect);
            if (!inspection.selectionComplete()
                || !verifyPublication(request, inspection,
                    publicationGuard, diagnostic)
                || isExcess(inspection, request.publication.publishedPath)) {
                if (diagnostic.isEmpty())
                    diagnostic = inspection.diagnostic.isEmpty()
                        ? QStringLiteral("Plan de rotation devenu ambigu ou incohérent.")
                        : inspection.diagnostic;
                stopBeforeDeletion(result, std::move(diagnostic));
                return result;
            }
            if (inspection.excess.isEmpty()) {
                result.outcome = result.deleted.isEmpty()
                    ? BackupSeriesRotationOutcome::NoRotationNecessary
                    : BackupSeriesRotationOutcome::Complete;
                return result;
            }
            const BackupSeriesVersion candidate = inspection.excess.front();
            if (candidate.path == request.publication.publishedPath) {
                stopBeforeDeletion(result, QStringLiteral(
                    "La nouvelle publication ne peut jamais être supprimée."));
                return result;
            }

            storage::VaultOperationGuard candidateGuard;
            reservationError.clear();
            if (!candidateGuard.tryReserve(candidate.path.toStdString(), reservationError)) {
                stopBeforeDeletion(result, reservationError.empty()
                    ? QStringLiteral("Candidat occupé ou non réservable.")
                    : QString::fromStdString(reservationError));
                return result;
            }
            if (stopRequested(request.control,
                    BackupSeriesRotationCheckpoint::BeforeCandidateRevalidation,
                    candidate.path)) {
                stopBeforeDeletion(result, QStringLiteral("Rotation interrompue."));
                return result;
            }

            BackupSeriesInspectionResult current = BackupSeriesInspector::inspect(inspect);
            const BackupSeriesVersion* currentCandidate = current.selectionComplete()
                ? findVersion(current.excess, candidate.path) : nullptr;
            if (!current.selectionComplete() || currentCandidate == nullptr
                || currentCandidate->identity != candidate.identity
                || !verifyPublication(request, current, publicationGuard, diagnostic)
                || isExcess(current, request.publication.publishedPath)) {
                if (diagnostic.isEmpty()) diagnostic = current.diagnostic.isEmpty()
                    ? QStringLiteral("Le candidat n'est plus le même excédent admissible.")
                    : current.diagnostic;
                stopBeforeDeletion(result, std::move(diagnostic));
                return result;
            }

            OpenedSeries openedSeries;
            if (!openVerifiedSeries(request, current, openedSeries, diagnostic)) {
                stopBeforeDeletion(result, std::move(diagnostic));
                return result;
            }
            OpenedCandidate openedCandidate;
            if (!openCandidate(candidate, current.seriesDirectory,
                    openedSeries.descriptor.value, openedCandidate, diagnostic)) {
                stopBeforeDeletion(result, std::move(diagnostic));
                return result;
            }

            if (stopRequested(request.control,
                    BackupSeriesRotationCheckpoint::BeforeUnlink,
                    candidate.path)) {
                stopBeforeDeletion(result, QStringLiteral(
                    "Rotation interrompue avant suppression."));
                return result;
            }
            BackupSeriesInspectionResult finalInspection =
                BackupSeriesInspector::inspect(inspect);
            const BackupSeriesVersion* finalSelected =
                finalInspection.selectionComplete()
                ? findVersion(finalInspection.excess, candidate.path) : nullptr;
            if (!finalInspection.selectionComplete()
                || finalSelected == nullptr
                || finalSelected->identity != candidate.identity
                || isExcess(finalInspection, request.publication.publishedPath)
                || !verifyPublication(request, finalInspection,
                    publicationGuard, diagnostic)) {
                if (diagnostic.isEmpty()) diagnostic =
                    finalInspection.diagnostic.isEmpty()
                    ? QStringLiteral(
                        "La sélection a changé avant la suppression.")
                    : finalInspection.diagnostic;
                stopBeforeDeletion(result, std::move(diagnostic));
                return result;
            }
            OpenedSeries finalSeries;
            OpenedCandidate finalCandidate;
            if (!openVerifiedSeries(request, finalInspection,
                    finalSeries, diagnostic)
                || !finalCandidateBinding(candidate,
                    finalInspection.seriesDirectory,
                    openedSeries, finalSeries, openedCandidate, finalCandidate, diagnostic)
                || !candidateGuard.matchesReservation(
                    candidate.path.toStdString(), reservationError)) {
                if (diagnostic.isEmpty()) diagnostic = reservationError.empty()
                    ? QStringLiteral("Liaison finale du candidat perdue.")
                    : QString::fromStdString(reservationError);
                stopBeforeDeletion(result, std::move(diagnostic));
                return result;
            }

            // Pre-register the exact observed version without allocating after
            // unlinkat. Remove it again if the syscall reports no deletion.
            result.deleted.push_back(candidate);
            // The private directory and cooperative reservations reduce races,
            // but POSIX has no unlink-by-open-inode: a hostile same-UID process
            // can still race the final named check and this unlinkat call.
            if (::unlinkat(finalSeries.descriptor.value,
                    finalCandidate.name.constData(), 0) != 0) {
                result.deleted.removeLast();
                stopBeforeDeletion(result,
                    posixDiagnostic(QStringLiteral("Suppression de version impossible")));
                return result;
            }
            if (::fsync(finalSeries.descriptor.value) != 0) {
                result.outcome =
                    BackupSeriesRotationOutcome::DeletionDurabilityUnconfirmed;
                result.diagnostic = posixDiagnostic(QStringLiteral(
                    "Suppression effectuée ; durabilité du dossier non confirmée"));
                return result;
            }
            ++result.durableDeletions;
            if (stopRequested(request.control,
                    BackupSeriesRotationCheckpoint::AfterDeletion,
                    candidate.path)) {
                stopBeforeDeletion(result, QStringLiteral(
                    "Rotation interrompue après une suppression confirmée."));
                return result;
            }
            diagnostic.clear();
        }
#endif
    } catch (...) {
        result.outcome = BackupSeriesRotationOutcome::Unknown;
        try { result.diagnostic = QStringLiteral(
            "Résultat de rotation incertain ; aucune reprise automatique."); }
        catch (...) { result.diagnostic.clear(); }
        return result;
    }
}

} // namespace passwall::services
