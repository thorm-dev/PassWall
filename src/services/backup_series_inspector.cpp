#include "services/backup_series_inspector.hpp"

#include "services/backup_series_identity.hpp"
#include "services/backup_generation_name.hpp"
#include "services/global_backup_preferences_store.hpp"

#include <QDir>
#include <QFile>

#include <algorithm>
#include <cerrno>
#include <dirent.h>
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

struct DirectoryStream {
    DIR* value = nullptr;
    DirectoryStream() = default;
    DirectoryStream(const DirectoryStream&) = delete;
    DirectoryStream& operator=(const DirectoryStream&) = delete;
    ~DirectoryStream() noexcept { if (value != nullptr) ::closedir(value); }
};

struct Layout {
    Descriptor root;
    Descriptor family;
    Descriptor series;
    struct stat rootStatus {};
    struct stat familyStatus {};
    struct stat seriesStatus {};
    SnapshotDirectoryIdentity rootIdentity;
    SnapshotDirectoryIdentity familyIdentity;
    SnapshotDirectoryIdentity seriesIdentity;
};

void setFailure(BackupSeriesInspectionResult& result,
    BackupSeriesInspectionOutcome outcome, QString diagnostic)
{
    result.outcome = outcome;
    result.excess.clear();
    if (result.diagnostic.isEmpty()) result.diagnostic = std::move(diagnostic);
}

QString systemDiagnostic(const QString& operation)
{
    const int saved = errno;
    return operation + QStringLiteral(" [errno=%1].").arg(saved);
}

SnapshotDirectoryIdentity directoryIdentity(const struct stat& status)
{
    return {static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino)};
}

bool sameDirectoryStatus(const struct stat& left, const struct stat& right)
{
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode && left.st_uid == right.st_uid
        && left.st_nlink == right.st_nlink
        && left.st_mtim.tv_sec == right.st_mtim.tv_sec
        && left.st_mtim.tv_nsec == right.st_mtim.tv_nsec
        && left.st_ctim.tv_sec == right.st_ctim.tv_sec
        && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

bool trustedAncestor(int descriptor)
{
    struct stat status {};
    return ::fstat(descriptor, &status) == 0 && S_ISDIR(status.st_mode)
        && (status.st_uid == 0 || status.st_uid == ::geteuid())
        && ((status.st_mode & 0022) == 0
            || (status.st_uid == 0 && (status.st_mode & S_ISVTX) != 0));
}

bool openCanonicalDirectory(const QString& path, Descriptor& output,
    struct stat& status, QString& diagnostic)
{
    if (!QDir::isAbsolutePath(path) || path.contains(QChar::Null)
        || QDir::cleanPath(path) != path) {
        diagnostic = QStringLiteral("Chemin de racine non canonique.");
        return false;
    }
    Descriptor current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (current.value < 0) {
        diagnostic = systemDiagnostic(QStringLiteral("Ouverture de la racine impossible"));
        return false;
    }
    for (const QString& component : path.split(QLatin1Char('/'), Qt::SkipEmptyParts)) {
        const QByteArray encoded = QFile::encodeName(component);
        Descriptor next(::openat(current.value, encoded.constData(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (next.value < 0) {
            diagnostic = systemDiagnostic(
                QStringLiteral("Dossier de sauvegarde inaccessible ou lien refusé"));
            return false;
        }
        if (!trustedAncestor(next.value)) {
            diagnostic = QStringLiteral(
                "Un dossier du chemin de sauvegarde n'est pas protégé.");
            return false;
        }
        current = std::move(next);
    }
    if (::fstat(current.value, &status) != 0) {
        diagnostic = systemDiagnostic(QStringLiteral("Identité de la racine inaccessible"));
        return false;
    }
    output = std::move(current);
    return true;
}

bool openPrivateChild(int parent, const QByteArray& name,
    Descriptor& output, struct stat& status, QString& diagnostic)
{
    struct stat named {};
    Descriptor child(::openat(parent, name.constData(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (child.value < 0
        || ::fstat(child.value, &status) != 0
        || ::fstatat(parent, name.constData(), &named, AT_SYMLINK_NOFOLLOW) != 0) {
        diagnostic = systemDiagnostic(
            QStringLiteral("Dossier géré absent, inaccessible ou remplacé"));
        return false;
    }
    if (!S_ISDIR(status.st_mode) || !S_ISDIR(named.st_mode)
        || status.st_uid != ::geteuid() || named.st_uid != ::geteuid()
        || (status.st_mode & 07777) != 0700
        || (named.st_mode & 07777) != 0700
        || status.st_dev != named.st_dev || status.st_ino != named.st_ino) {
        diagnostic = QStringLiteral(
            "Dossier géré non privé, ambigu ou substitué.");
        return false;
    }
    output = std::move(child);
    return true;
}

bool validSeriesId(const QString& value)
{
    if (value.size() != BackupSeriesIdentityService::EncodedSeriesIdSize)
        return false;
    for (const QChar character : value) {
        const ushort code = character.unicode();
        if (!((code >= '0' && code <= '9') || (code >= 'a' && code <= 'f')))
            return false;
    }
    return true;
}

bool inspectDirectoryPath(const QString& path,
    const SnapshotDirectoryIdentity& descriptorIdentity,
    SnapshotDirectoryIdentity& observed, QString& diagnostic)
{
    std::string error;
    if (!VaultSnapshotService::inspectDestinationDirectory(
            path.toStdString(), observed, error)) {
        diagnostic = error.empty()
            ? QStringLiteral("Dossier de sauvegarde refusé.")
            : QString::fromStdString(error);
        return false;
    }
    if (observed != descriptorIdentity) {
        diagnostic = QStringLiteral(
            "Le chemin du dossier ne désigne plus son identité ouverte.");
        return false;
    }
    return true;
}

bool openLayout(const BackupSeriesInspectionRequest& request,
    BackupSeriesInspectionResult& result, Layout& layout, QString& diagnostic)
{
    if (!openCanonicalDirectory(request.rootDirectory, layout.root,
            layout.rootStatus, diagnostic))
        return false;
    if (layout.rootStatus.st_uid != ::geteuid()
        || (layout.rootStatus.st_mode & 0022) != 0) {
        diagnostic = QStringLiteral(
            "La racine doit appartenir à l'utilisateur et être protégée en écriture.");
        return false;
    }
    layout.rootIdentity = directoryIdentity(layout.rootStatus);
    if (layout.rootIdentity.inode == 0
        || (request.expectedRoot && *request.expectedRoot != layout.rootIdentity)) {
        diagnostic = QStringLiteral("Identité de racine inattendue ou indisponible.");
        return false;
    }

    const QByteArray familyName = request.vaultId.toHex();
    if (!openPrivateChild(layout.root.value, familyName, layout.family,
            layout.familyStatus, diagnostic))
        return false;
    layout.familyIdentity = directoryIdentity(layout.familyStatus);
    if (layout.familyIdentity.inode == 0
        || (request.expectedFamily && *request.expectedFamily != layout.familyIdentity)) {
        diagnostic = QStringLiteral("Identité du dossier familial inattendue.");
        return false;
    }

    const QByteArray seriesName = request.seriesId.toLatin1();
    if (!openPrivateChild(layout.family.value, seriesName, layout.series,
            layout.seriesStatus, diagnostic))
        return false;
    layout.seriesIdentity = directoryIdentity(layout.seriesStatus);
    if (layout.seriesIdentity.inode == 0
        || (request.expectedSeries && *request.expectedSeries != layout.seriesIdentity)) {
        diagnostic = QStringLiteral("Identité du dossier de série inattendue.");
        return false;
    }

    SnapshotDirectoryIdentity observed;
    if (!inspectDirectoryPath(result.rootDirectory,
            layout.rootIdentity, observed, diagnostic)
        || !inspectDirectoryPath(result.familyDirectory,
            layout.familyIdentity, observed, diagnostic)
        || !inspectDirectoryPath(result.seriesDirectory,
            layout.seriesIdentity, observed, diagnostic))
        return false;
    return true;
}

bool listNames(int directory, QVector<QByteArray>& output, QString& diagnostic)
{
    output.clear();
    Descriptor independent(::openat(directory, ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (independent.value < 0) {
        diagnostic = systemDiagnostic(QStringLiteral("Ouverture du contenu impossible"));
        return false;
    }
    DirectoryStream stream;
    stream.value = ::fdopendir(independent.value);
    if (stream.value == nullptr) {
        diagnostic = systemDiagnostic(QStringLiteral("Parcours du contenu impossible"));
        return false;
    }
    independent.value = -1;
    for (;;) {
        errno = 0;
        dirent* entry = ::readdir(stream.value);
        if (entry == nullptr) {
            if (errno != 0) {
                diagnostic = systemDiagnostic(QStringLiteral("Lecture du contenu interrompue"));
                return false;
            }
            break;
        }
        const QByteArray name(entry->d_name);
        if (name == QByteArrayLiteral(".") || name == QByteArrayLiteral(".."))
            continue;
        output.push_back(name);
    }
    std::sort(output.begin(), output.end());
    return true;
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

bool statusMatchesIdentity(const struct stat& status,
    const BackupSeriesFileIdentity& identity)
{
    return fileIdentity(status) == identity;
}

void addAmbiguity(BackupSeriesInspectionResult& result,
    const QString& name, QString diagnostic)
{
    result.ambiguities.push_back({name, std::move(diagnostic)});
    result.outcome = BackupSeriesInspectionOutcome::Unsafe;
    result.excess.clear();
}

bool inspectCandidate(const BackupSeriesInspectionRequest& request,
    BackupSeriesInspectionResult& result, const Layout& layout,
    const QByteArray& encodedName, const QString& name,
    const QDateTime& timestamp, quint64 generation)
{
    struct stat before {};
    if (::fstatat(layout.series.value, encodedName.constData(),
            &before, AT_SYMLINK_NOFOLLOW) != 0) {
        addAmbiguity(result, name,
            systemDiagnostic(QStringLiteral("Identité du candidat inaccessible")));
        return false;
    }
    if (!S_ISREG(before.st_mode) || before.st_uid != ::geteuid()
        || before.st_nlink != 1 || (before.st_mode & 07777) != 0600
        || before.st_size <= 0) {
        addAmbiguity(result, name, QStringLiteral(
            "Objet canonique non régulier, lié ou doté de permissions incompatibles."));
        return false;
    }
    // Names and physical metadata only. Never open or read an older vault.
    const QString path = QDir(result.seriesDirectory).filePath(name);
    result.admissible.push_back({name, path, timestamp, generation,
        fileIdentity(before)});
    if (request.observer.reached != nullptr)
        request.observer.reached(request.observer.context,
            BackupSeriesInspectionCheckpoint::CandidateValidated, path);
    return true;
}

bool versionLess(const BackupSeriesVersion& left,
    const BackupSeriesVersion& right)
{
    if (left.generation != right.generation)
        return left.generation < right.generation;
    // Duplicate generation numbers are rejected before any selection.
    if (left.fileName != right.fileName) return left.fileName < right.fileName;
    if (left.identity.device != right.identity.device)
        return left.identity.device < right.identity.device;
    return left.identity.inode < right.identity.inode;
}

bool finalRevalidation(const BackupSeriesInspectionRequest& request,
    BackupSeriesInspectionResult& result, const Layout& original,
    const QVector<QByteArray>& originalNames)
{
    if (request.observer.reached != nullptr)
        request.observer.reached(request.observer.context,
            BackupSeriesInspectionCheckpoint::BeforeFinalRevalidation,
            result.seriesDirectory);

    Layout current;
    QString diagnostic;
    if (!openLayout(request, result, current, diagnostic)
        || current.rootIdentity != original.rootIdentity
        || current.familyIdentity != original.familyIdentity
        || current.seriesIdentity != original.seriesIdentity
        || !sameDirectoryStatus(current.rootStatus, original.rootStatus)
        || !sameDirectoryStatus(current.familyStatus, original.familyStatus)
        || !sameDirectoryStatus(current.seriesStatus, original.seriesStatus)) {
        addAmbiguity(result, QString{}, diagnostic.isEmpty()
            ? QStringLiteral("Disposition des dossiers modifiée pendant l'inspection.")
            : diagnostic);
        return false;
    }
    QVector<QByteArray> currentNames;
    if (!listNames(current.series.value, currentNames, diagnostic)) {
        addAmbiguity(result, QString{}, diagnostic);
        return false;
    }
    if (currentNames != originalNames) {
        addAmbiguity(result, QString{}, QStringLiteral(
            "Contenu de la série modifié pendant l'inspection."));
        return false;
    }
    for (const BackupSeriesVersion& version : result.admissible) {
        const QByteArray encoded = QFile::encodeName(version.fileName);
        struct stat named {};
        if (::fstatat(current.series.value, encoded.constData(),
                &named, AT_SYMLINK_NOFOLLOW) != 0) {
            addAmbiguity(result, version.fileName,
                systemDiagnostic(QStringLiteral("Revalidation de la version impossible")));
            return false;
        }
        if (!statusMatchesIdentity(named, version.identity)) {
            addAmbiguity(result, version.fileName, QStringLiteral(
                "Version substituée ou modifiée après son identification physique."));
            return false;
        }
    }
    return true;
}

} // namespace

BackupSeriesInspectionResult BackupSeriesInspector::inspect(
    const BackupSeriesInspectionRequest& request)
{
    BackupSeriesInspectionResult result;
    try {
        result.rootDirectory = request.rootDirectory;
        result.familyDirectory = QDir(request.rootDirectory).filePath(
            QString::fromLatin1(request.vaultId.toHex()));
        result.seriesDirectory = QDir(result.familyDirectory).filePath(request.seriesId);
        if (request.vaultId.size() != BackupSeriesIdentityService::VaultIdSize
            || !validSeriesId(request.seriesId)
            || request.retainedVersions
                < GlobalBackupPreferencesStore::MinimumRetainedVersions) {
            setFailure(result, BackupSeriesInspectionOutcome::InvalidRequest,
                QStringLiteral("Identité de série ou rétention invalide."));
            return result;
        }

#ifndef Q_OS_UNIX
        setFailure(result, BackupSeriesInspectionOutcome::Unsafe,
            QStringLiteral("Inspection sécurisée des séries indisponible sur cette plateforme."));
        return result;
#else
        Layout layout;
        QString diagnostic;
        if (!openLayout(request, result, layout, diagnostic)) {
            setFailure(result, BackupSeriesInspectionOutcome::Unsafe,
                std::move(diagnostic));
            return result;
        }
        result.rootIdentity = layout.rootIdentity;
        result.familyIdentity = layout.familyIdentity;
        result.seriesIdentity = layout.seriesIdentity;

        QVector<QByteArray> names;
        if (!listNames(layout.series.value, names, diagnostic)) {
            setFailure(result, BackupSeriesInspectionOutcome::Unsafe,
                std::move(diagnostic));
            return result;
        }
        result.outcome = BackupSeriesInspectionOutcome::Complete;
        for (const QByteArray& encodedName : names) {
            QDateTime timestamp;
            quint64 generation = 0;
            const QString name = QString::fromLatin1(encodedName);
            if (!parseBackupGenerationName(name, generation, timestamp)) {
                if (isBackupGenerationCandidate(name)) {
                    addAmbiguity(result, name, QStringLiteral("Nom de génération invalide."));
                    continue;
                }
                result.outsideConvention.push_back({
                    QString::fromLocal8Bit(encodedName),
                    QStringLiteral("Nom hors convention générationnelle ; objet préservé.")});
                continue;
            }
            // A managed copy with SQLite companions may be in use or require
            // recovery. Preserve it and refuse deletion without opening it.
            bool hasCompanion = false;
            for (const char* suffix : {"-journal", "-wal", "-shm"}) {
                if (std::binary_search(names.cbegin(), names.cend(),
                        encodedName + suffix)) {
                    hasCompanion = true;
                    break;
                }
            }
            if (hasCompanion) {
                addAmbiguity(result, name,
                    QStringLiteral("Fichier auxiliaire SQLite présent ; rotation refusée."));
                continue;
            }
            (void)inspectCandidate(request, result, layout, encodedName,
                name, timestamp, generation);
        }
        std::sort(result.admissible.begin(), result.admissible.end(), versionLess);
        for (qsizetype i = 1; i < result.admissible.size(); ++i) {
            if (result.admissible[i - 1].generation == result.admissible[i].generation)
                addAmbiguity(result, result.admissible[i].fileName,
                    QStringLiteral("Numéro de génération dupliqué."));
        }
        if (!finalRevalidation(request, result, layout, names)) {
            if (result.diagnostic.isEmpty())
                result.diagnostic = QStringLiteral(
                    "Inspection ambiguë ; aucune sélection d'excédent n'est sûre.");
            return result;
        }
        if (!result.ambiguities.isEmpty()) {
            setFailure(result, BackupSeriesInspectionOutcome::Unsafe,
                QStringLiteral("Inspection partielle ou ambiguë ; aucun excédent sélectionné."));
            return result;
        }

        const quint64 count = static_cast<quint64>(result.admissible.size());
        if (request.retainedVersions < count) {
            const qsizetype excessCount = result.admissible.size()
                - static_cast<qsizetype>(request.retainedVersions);
            result.excess = result.admissible.mid(0, excessCount);
        }
        result.outcome = BackupSeriesInspectionOutcome::Complete;
        result.diagnostic.clear();
        return result;
#endif
    } catch (...) {
        setFailure(result, BackupSeriesInspectionOutcome::Unsafe,
            QStringLiteral("Inspection de la série interrompue."));
        return result;
    }
}

} // namespace passwall::services
