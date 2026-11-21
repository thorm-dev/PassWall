#include "services/backup_destination_preparer.hpp"
#include "services/backup_job.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <cerrno>
#include <filesystem>
#include <limits>
#include <utility>

#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace passwall::services {
namespace {

bool fail(QString& error, const QString& message)
{
    error = message;
    return false;
}

QString canonicalPath(const QString& path)
{
    if (path.isEmpty() || path.contains(QChar{}) || !QDir::isAbsolutePath(path))
        return {};
    const QString clean = QDir::cleanPath(path);
    return clean == path ? clean : QString{};
}

bool sameVault(const VaultFileIdentity& expected, const VaultFileIdentity& observed)
{
    return expected.path == observed.path && expected.vaultId == observed.vaultId
        && expected.device != 0 && expected.inode != 0
        && expected.device == observed.device && expected.inode == observed.inode;
}

#ifdef Q_OS_UNIX
struct Descriptor {
    int value = -1;
    Descriptor() = default;
    explicit Descriptor(int descriptor) noexcept : value(descriptor) {}
    ~Descriptor() noexcept { if (value >= 0) (void)::close(value); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
};

bool trustedDirectory(int descriptor)
{
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)
        || (status.st_uid != ::geteuid() && status.st_uid != 0))
        return false;
    return (status.st_mode & 0022) == 0
        || (status.st_uid == 0 && (status.st_mode & S_ISVTX) != 0);
}

bool openDirectory(const QString& path, Descriptor& output, QString& error)
{
    const QString clean = canonicalPath(path);
    if (clean.isEmpty() || clean == QStringLiteral("/"))
        return fail(error, QStringLiteral("Racine de sauvegarde invalide."));
    const std::filesystem::path parsed(QFile::encodeName(clean).constData());
    Descriptor current(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (current.value < 0)
        return fail(error, QStringLiteral("Ouverture de la racine système impossible."));
    for (const auto& component : parsed.relative_path()) {
        const int next = ::openat(current.value, component.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0)
            return fail(error, QStringLiteral(
                "Dossier de sauvegarde inaccessible ou lien symbolique refusé."));
        (void)::close(current.value);
        current.value = next;
        if (!trustedDirectory(current.value))
            return fail(error, QStringLiteral(
                "Un dossier du chemin est modifiable par un autre utilisateur."));
    }
    output.value = std::exchange(current.value, -1);
    return true;
}

SnapshotDirectoryIdentity directoryIdentity(int descriptor)
{
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)) return {};
    return {static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino)};
}

bool openFamily(const QString& root, const QByteArray& familyName,
    SnapshotDirectoryIdentity& rootIdentity,
    SnapshotDirectoryIdentity& familyIdentity, QString& error)
{
    Descriptor rootDirectory;
    if (!openDirectory(root, rootDirectory, error)) return false;
    struct stat rootStatus {};
    if (::fstat(rootDirectory.value, &rootStatus) != 0
        || rootStatus.st_uid != ::geteuid() || (rootStatus.st_mode & 0022) != 0)
        return fail(error, QStringLiteral(
            "La racine de sauvegarde doit appartenir à l'utilisateur et être protégée en écriture."));
    rootIdentity = directoryIdentity(rootDirectory.value);
    if (rootIdentity.device == 0 || rootIdentity.inode == 0)
        return fail(error, QStringLiteral("Identité de la racine indisponible."));

    bool created = false;
    if (::mkdirat(rootDirectory.value, familyName.constData(), 0700) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        return fail(error, QStringLiteral("Création du dossier familial impossible."));
    }
    Descriptor family(::openat(rootDirectory.value, familyName.constData(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    struct stat familyStatus {}, namedStatus {};
    if (family.value < 0 || ::fstat(family.value, &familyStatus) != 0
        || ::fstatat(rootDirectory.value, familyName.constData(), &namedStatus,
            AT_SYMLINK_NOFOLLOW) != 0
        || !S_ISDIR(familyStatus.st_mode) || !S_ISDIR(namedStatus.st_mode)
        || familyStatus.st_uid != ::geteuid() || namedStatus.st_uid != ::geteuid()
        || (familyStatus.st_mode & 0777) != 0700
        || familyStatus.st_dev != namedStatus.st_dev
        || familyStatus.st_ino != namedStatus.st_ino)
        return fail(error, QStringLiteral(
            "Dossier familial non privé, ambigu ou remplacé concurremment."));
    if (created && (::fsync(family.value) != 0 || ::fsync(rootDirectory.value) != 0))
        return fail(error, QStringLiteral(
            "Dossier familial visible, mais persistance non confirmée."));
    familyIdentity = directoryIdentity(family.value);
    if (familyIdentity.device == 0 || familyIdentity.inode == 0)
        return fail(error, QStringLiteral("Identité du dossier familial indisponible."));
    return true;
}

bool chooseDestination(const QString& familyPath,
    const SnapshotDirectoryIdentity& expectedFamily, const QDateTime& timestamp,
    QString& destination, QString& error)
{
    Descriptor family;
    if (!openDirectory(familyPath, family, error)) return false;
    if (directoryIdentity(family.value) != expectedFamily)
        return fail(error, QStringLiteral("Le dossier familial a changé."));

    const QString stem = timestamp.toUTC().toString(QStringLiteral("yyyy-MM-dd_HH-mm-ss"));
    if (!timestamp.isValid() || stem.size() != 19)
        return fail(error, QStringLiteral("Horodatage UTC invalide."));
    for (quint64 suffix = 1; suffix != std::numeric_limits<quint64>::max(); ++suffix) {
        const QString name = stem
            + (suffix == 1 ? QString{} : QStringLiteral("_") + QString::number(suffix))
            + QStringLiteral(".pwdb");
        const QByteArray encoded = QFile::encodeName(name);
        struct stat existing {};
        if (::fstatat(family.value, encoded.constData(), &existing,
                AT_SYMLINK_NOFOLLOW) == 0)
            continue;
        if (errno != ENOENT)
            return fail(error, QStringLiteral(
                "Vérification du nom de sauvegarde impossible."));
        destination = QDir(familyPath).filePath(name);
        return true;
    }
    return fail(error, QStringLiteral("Aucun nom de sauvegarde disponible."));
}

bool destinationStillAbsent(const PreparedBackupDestination& prepared,
    QString& error)
{
    Descriptor family;
    if (!openDirectory(prepared.familyDirectory(), family, error)) return false;
    if (directoryIdentity(family.value) != prepared.familyIdentity())
        return fail(error, QStringLiteral("Le dossier familial a changé."));
    const QFileInfo destination(prepared.destinationPath());
    if (destination.absolutePath() != prepared.familyDirectory()
        || destination.fileName().isEmpty())
        return fail(error, QStringLiteral("Destination préparée incohérente."));
    const QByteArray name = QFile::encodeName(destination.fileName());
    struct stat status {};
    if (::fstatat(family.value, name.constData(), &status, AT_SYMLINK_NOFOLLOW) == 0)
        return fail(error, QStringLiteral(
            "Le nom préparé est désormais occupé ; aucun écrasement autorisé."));
    if (errno != ENOENT)
        return fail(error, QStringLiteral(
            "La destination préparée ne peut plus être vérifiée."));
    return true;
}
#endif

} // namespace

bool BackupDestinationPreparer::prepare(
    const GlobalBackupPreferencesResult& configuration,
    const VaultFileIdentity& expectedVault, quint64 bindingGeneration,
    const QDateTime& timestamp, PreparedBackupDestination& output, QString& error,
    const SnapshotDirectoryIdentity* expectedRoot,
    const SnapshotDirectoryIdentity* expectedFamily, storage::VaultOperationGuard* existingSnapshotAccess)
{
    output = {};
    error.clear();
    if (!configuration.valid())
        return fail(error, QStringLiteral(
            "Configuration globale absente, invalide ou inaccessible."));
    const auto& preferences = configuration.preferences;
    const QString root = canonicalPath(preferences.rootDirectory);
    const QString vaultPath = canonicalPath(expectedVault.path);
    if (root.isEmpty() || vaultPath.isEmpty()
        || preferences.retainedVersions < GlobalBackupPreferencesStore::MinimumRetainedVersions)
        return fail(error, QStringLiteral("Préférences globales invalides."));
    if (bindingGeneration == 0 || expectedVault.vaultId.size() != 16
        || expectedVault.device == 0 || expectedVault.inode == 0)
        return fail(error, QStringLiteral("Identité ou génération du coffre invalide."));
    if (!timestamp.isValid())
        return fail(error, QStringLiteral("Horodatage UTC invalide."));
#ifndef Q_OS_UNIX
    Q_UNUSED(timestamp);
    return fail(error, QStringLiteral(
        "Préparation sécurisée des destinations indisponible sur cette plateforme."));
#else
    storage::VaultOperationGuard ownedSnapshotAccess;
    auto* snapshotAccess = existingSnapshotAccess ? existingSnapshotAccess : &ownedSnapshotAccess;
    std::string reservationError;
    if (!existingSnapshotAccess
    && !snapshotAccess->trySnapshotAccess(vaultPath.toStdString(), reservationError))
      return fail(error, reservationError.empty()
            ? QStringLiteral("Réservation d'instantané impossible.")
            : QString::fromStdString(reservationError));
    if (!snapshotAccess->matchesSnapshotIdentity(vaultPath.toStdString(),
            expectedVault.device, expectedVault.inode, reservationError))
        return fail(error, reservationError.empty()
            ? QStringLiteral("Identité physique du coffre divergente.")
            : QString::fromStdString(reservationError));

    VaultFileIdentity observed;
    QString inspectionError;
    if (!VaultPreferencesStore::inspectVault(vaultPath, observed, inspectionError))
        return fail(error, inspectionError.isEmpty()
            ? QStringLiteral("Identité du coffre impossible à vérifier.")
            : inspectionError);
    if (!sameVault(expectedVault, observed))
        return fail(error, QStringLiteral(
            "Le coffre ne correspond pas à l'identité et au vault_id attendus."));

    SnapshotDirectoryIdentity inspectedRoot;
    std::string destinationError;
    if (!VaultSnapshotService::inspectDestinationDirectory(
            root.toStdString(), inspectedRoot, destinationError))
        return fail(error, destinationError.empty()
            ? QStringLiteral("Racine de sauvegarde refusée.")
            : QString::fromStdString(destinationError));
    if (expectedRoot != nullptr && inspectedRoot != *expectedRoot)
        return fail(error, QStringLiteral(
            "La racine de sauvegarde ne correspond plus à l'inspection initiale."));

    const QByteArray familyName = expectedVault.vaultId.toHex();
    SnapshotDirectoryIdentity rootIdentity, familyIdentity;
    if (!openFamily(root, familyName, rootIdentity, familyIdentity, error)) return false;
    if (rootIdentity != inspectedRoot)
        return fail(error, QStringLiteral(
            "La racine de sauvegarde a changé pendant sa préparation."));
    if (expectedFamily != nullptr && familyIdentity != *expectedFamily)
        return fail(error, QStringLiteral(
            "Le dossier familial ne correspond plus à l'inspection initiale."));
    const QString familyPath = QDir(root).filePath(QString::fromLatin1(familyName));
    SnapshotDirectoryIdentity inspectedFamily;
    if (!VaultSnapshotService::inspectDestinationDirectory(
            familyPath.toStdString(), inspectedFamily, destinationError)
        || inspectedFamily != familyIdentity)
        return fail(error, destinationError.empty()
            ? QStringLiteral("Le dossier familial a changé pendant sa préparation.")
            : QString::fromStdString(destinationError));
    QString destination;
    if (!chooseDestination(familyPath, familyIdentity, timestamp, destination, error))
        return false;
    if (!snapshotAccess->matchesSnapshotIdentity(vaultPath.toStdString(),
            expectedVault.device, expectedVault.inode, reservationError))
        return fail(error, QStringLiteral(
            "Le coffre a changé pendant la préparation de sa destination."));

    output.sourceIdentity_ = observed;
    output.vaultPath_ = vaultPath;
    output.vaultId_ = observed.vaultId;
    output.bindingGeneration_ = bindingGeneration;
    output.rootDirectory_ = root;
    output.familyDirectory_ = familyPath;
    output.destinationPath_ = destination;
    output.rootIdentity_ = rootIdentity;
    output.familyIdentity_ = familyIdentity;
    output.preparedPreferences_ = configuration.preferences;
    output.preferencesSourceFile_ = configuration.sourceFile;
    output.snapshotAccess_ = std::move(*snapshotAccess);
    return true;
#endif
}

bool BackupDestinationPreparer::revalidateConfiguration(
    const PreparedBackupDestination& prepared,
    const GlobalBackupPreferencesResult* current, QString& error)
{
    error.clear();
    const auto matches = [&](const GlobalBackupPreferencesResult& observed) {
        return observed.status == GlobalBackupPreferencesStatus::Valid
            && observed.preferences == prepared.preparedPreferences_
            && (prepared.preferencesSourceFile_.isEmpty()
                || observed.sourceFile == prepared.preferencesSourceFile_);
    };
    if (current != nullptr && !matches(*current))
        return fail(error, QStringLiteral(
            "La configuration globale a changé depuis la préparation."));
    if (prepared.preferencesSourceFile_.isEmpty())
        return current == nullptr || matches(*current);

    const auto observed = GlobalBackupPreferencesStore(
        prepared.preferencesSourceFile_).load();
    if (!matches(observed))
        return fail(error, QStringLiteral(
            "La configuration globale n'est plus celle de la préparation."));
    return true;
}

bool BackupDestinationPreparer::revalidate(
    const PreparedBackupDestination& prepared,
    const VaultFileIdentity& expectedVault, quint64 expectedBindingGeneration,
    QString& error)
{
    error.clear();
#ifndef Q_OS_UNIX
    Q_UNUSED(prepared);
    Q_UNUSED(expectedVault);
    Q_UNUSED(expectedBindingGeneration);
    return fail(error, QStringLiteral(
        "Revalidation sécurisée indisponible sur cette plateforme."));
#else
    if (!revalidateConfiguration(prepared, nullptr, error)) return false;
    if (expectedBindingGeneration == 0
        || prepared.bindingGeneration_ != expectedBindingGeneration
        || !sameVault(prepared.sourceIdentity_, expectedVault)
        || prepared.vaultId_ != expectedVault.vaultId
        || prepared.vaultId_.size() != 16
        || prepared.vaultPath_.isEmpty() || prepared.destinationPath_.isEmpty())
        return fail(error, QStringLiteral(
            "Destination préparée incomplète ou liée à une autre demande."));
    std::string reservationError;
    if (!prepared.snapshotAccess_.matchesSnapshotIdentity(
            prepared.vaultPath_.toStdString(), prepared.sourceIdentity_.device,
            prepared.sourceIdentity_.inode, reservationError))
        return fail(error, reservationError.empty()
            ? QStringLiteral("Réservation ou identité du coffre devenue invalide.")
            : QString::fromStdString(reservationError));
    VaultFileIdentity observed;
    QString inspectionError;
    if (!VaultPreferencesStore::inspectVault(
            prepared.vaultPath_, observed, inspectionError)
        || !sameVault(prepared.sourceIdentity_, observed))
        return fail(error, inspectionError.isEmpty()
            ? QStringLiteral("Identité du coffre devenue incohérente.")
            : inspectionError);
    SnapshotDirectoryIdentity root, family;
    std::string directoryError;
    if (!VaultSnapshotService::inspectDestinationDirectory(
            prepared.rootDirectory_.toStdString(), root, directoryError)
        || root != prepared.rootIdentity_)
        return fail(error, directoryError.empty()
            ? QStringLiteral("La racine de sauvegarde a changé.")
            : QString::fromStdString(directoryError));
    if (!VaultSnapshotService::inspectDestinationDirectory(
            prepared.familyDirectory_.toStdString(), family, directoryError)
        || family != prepared.familyIdentity_)
        return fail(error, directoryError.empty()
            ? QStringLiteral("Le dossier familial a changé.")
            : QString::fromStdString(directoryError));
    if (!destinationStillAbsent(prepared, error)) return false;
    if (!prepared.snapshotAccess_.matchesSnapshotIdentity(
            prepared.vaultPath_.toStdString(), prepared.sourceIdentity_.device,
            prepared.sourceIdentity_.inode, reservationError))
        return fail(error, reservationError.empty()
            ? QStringLiteral("Le coffre a changé pendant la revalidation.")
            : QString::fromStdString(reservationError));
    return true;
#endif
}

bool BackupDestinationPreparer::startPreparedSnapshot(
    PreparedBackupDestination& prepared, const VaultFileIdentity& expectedVault,
    quint64 expectedBindingGeneration, BackupJob& job, QString& error)
{
    if (!revalidate(prepared, expectedVault, expectedBindingGeneration, error)) {
        prepared = {};
        return false;
    }

    const QString source = prepared.vaultPath_;
    const QString destination = prepared.destinationPath_;
    const SnapshotDirectoryIdentity family = prepared.familyIdentity_;
    auto access = std::move(prepared.snapshotAccess_);
    prepared = {};
    if (!job.startSnapshotReserved(source, destination, std::move(access), {}, family)) {
        error = job.startError().isEmpty()
            ? QStringLiteral("Démarrage de la sauvegarde préparée refusé.")
            : job.startError();
        return false;
    }
    error.clear();
    return true;
}

} // namespace passwall::services
