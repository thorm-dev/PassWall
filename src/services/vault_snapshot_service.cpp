#include "services/vault_snapshot_service.hpp"
#include "services/vault_preferences_store.hpp"
#include "storage/vault_operation_guard.hpp"

#include "storage/sqlite_connection_config.hpp"
#include "storage/vault_storage.hpp"

#include <sqlite3.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <string_view>
#include <thread>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace passwall::services {
namespace {

struct Descriptor {
    int value = -1;
    Descriptor() = default;
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() noexcept { close(); }
    int close() noexcept
    {
        const int fd = value;
        value = -1;
        return fd >= 0 ? ::close(fd) : 0; // Do not retry close(EINTR) on Linux.
    }
};

struct Database {
    sqlite3* value = nullptr;
    Database() = default;
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    ~Database() noexcept { if (value != nullptr) sqlite3_close_v2(value); }
    int close() noexcept
    {
        const int code = value != nullptr ? sqlite3_close(value) : SQLITE_OK;
        if (code == SQLITE_OK) value = nullptr;
        return code;
    }
};

struct Statement {
    sqlite3_stmt* value = nullptr;
    Statement() = default;
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    ~Statement() noexcept { if (value != nullptr) sqlite3_finalize(value); }
};

struct Backup {
    sqlite3_backup* value = nullptr;
    Backup() = default;
    Backup(const Backup&) = delete;
    Backup& operator=(const Backup&) = delete;
    ~Backup() noexcept { finish(); }
    int finish() noexcept
    {
        auto* handle = value;
        value = nullptr;
        return handle != nullptr ? sqlite3_backup_finish(handle) : SQLITE_OK;
    }
};

bool fail(std::string& error, const char* operation)
{
    error = operation;
    return false;
}

bool posixFailure(std::string& error, const char* operation)
{
    const int code = errno;
    error = std::string(operation) + " [errno=" + std::to_string(code) + "].";
    return false;
}

bool sqlFailure(sqlite3* database, int code, const char* operation, std::string& error)
{
    const int extended = sqlite3_extended_errcode(database);
    const int primary = code & 0xff;
    error = std::string(operation) + " [SQLite primaire=" + std::to_string(primary)
        + ", étendu=" + std::to_string((extended & 0xff) == primary ? extended : code) + "].";
    return false;
}

bool validPath(const std::string& path)
{
    if (path.empty() || path.find('\0') != std::string::npos)
        return false;
    const std::filesystem::path parsed(path);
    if (!parsed.is_absolute() || parsed.filename().empty())
        return false;
    for (const auto& part : parsed)
        if (part == "." || part == "..") return false;
    return true;
}

bool trustedDirectory(int fd)
{
    struct stat status{};
    if (::fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode)
        || (status.st_uid != ::geteuid() && status.st_uid != 0))
        return false;
    // A root-owned sticky directory such as /tmp protects our own child names.
    return (status.st_mode & 0022) == 0
        || (status.st_uid == 0 && (status.st_mode & S_ISVTX) != 0);
}

bool openParent(const std::filesystem::path& path, Descriptor& output, std::string& error)
{
    output.value = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (output.value < 0) return posixFailure(error, "Ouverture du dossier racine impossible");
    for (const auto& component : path.parent_path().relative_path()) {
        const int next = ::openat(output.value, component.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) return posixFailure(error, "Dossier inaccessible ou lien symbolique refusé");
        output.close();
        output.value = next;
        if (!trustedDirectory(next))
            return fail(error, "Un dossier du chemin est modifiable par un autre utilisateur.");
    }
    return true;
}

struct StagingDirectory {
    const int parent;
    std::string name;
    Descriptor directory;
    bool owned = false;

    explicit StagingDirectory(int parent) noexcept : parent(parent) {}
    StagingDirectory(const StagingDirectory&) = delete;
    StagingDirectory& operator=(const StagingDirectory&) = delete;
    ~StagingDirectory() noexcept { cleanup(); }

    bool cleanup() noexcept
    {
        if (!owned) return true;
        bool clean = true;
        if (directory.value >= 0) {
            for (const char* file : {"snapshot.pwdb", "snapshot.pwdb-journal",
                                     "snapshot.pwdb-wal", "snapshot.pwdb-shm"})
                if (::unlinkat(directory.value, file, 0) != 0 && errno != ENOENT) clean = false;
        }
        if (::unlinkat(parent, name.c_str(), AT_REMOVEDIR) == 0) owned = false;
        else clean = false;
        return clean;
    }

    bool create(std::string& error)
    {
        std::array<unsigned char, 16> random{};
        std::size_t offset = 0;
        while (offset < random.size()) {
            const auto count = ::getrandom(random.data() + offset, random.size() - offset, 0);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return posixFailure(error, "Génération du nom temporaire impossible");
            offset += static_cast<std::size_t>(count);
        }
        constexpr char alphabet[] = "0123456789abcdef";
        name = ".passwall-snapshot-";
        for (const auto byte : random) {
            name += alphabet[byte >> 4];
            name += alphabet[byte & 15];
        }
        if (::mkdirat(parent, name.c_str(), 0700) != 0)
            return posixFailure(error, "Création du dossier temporaire impossible");
        owned = true; // Arm cleanup before any subsequent allocation/API call.
        directory.value = ::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory.value < 0) return posixFailure(error, "Ouverture du dossier temporaire impossible");
        struct stat status{};
        if (::fstat(directory.value, &status) != 0 || status.st_uid != ::geteuid()
            || (status.st_mode & 0777) != 0700)
            return fail(error, "Les permissions du dossier temporaire ne sont pas privées.");
        return true;
    }
};

bool openDatabase(const std::string& path, bool source, Database& database, std::string& error)
{
    const int flags = (source ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE)
        | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW;
    const int code = sqlite3_open_v2(path.c_str(), &database.value, flags, nullptr);
    if (code != SQLITE_OK)
        return sqlFailure(database.value, code, "Ouverture SQLite impossible", error);
    return storage::configureSqliteConnection(database.value, error, !source);
}

bool prepare(sqlite3* database, const char* sql, Statement& query, std::string& error)
{
    const int code = sqlite3_prepare_v2(database, sql, -1, &query.value, nullptr);
    return code == SQLITE_OK || sqlFailure(database, code, "Préparation du contrôle impossible", error);
}

bool singleInteger(sqlite3* database, const char* sql, sqlite3_int64 expected, std::string& error)
{
    Statement query;
    if (!prepare(database, sql, query, error)) return false;
    const int code = sqlite3_step(query.value);
    if (code != SQLITE_ROW)
        return sqlFailure(database, code, "Lecture du contrôle impossible", error);
    if (sqlite3_column_type(query.value, 0) != SQLITE_INTEGER
        || sqlite3_column_int64(query.value, 0) != expected)
        return fail(error, "Structure ou enregistrements du coffre incompatibles.");
    const int end = sqlite3_step(query.value);
    return end == SQLITE_DONE || sqlFailure(database, end, "Fin du contrôle impossible", error);
}

bool textEquals(sqlite3_stmt* statement, int column, std::string_view expected)
{
    const auto* text = sqlite3_column_text(statement, column);
    return sqlite3_column_type(statement, column) == SQLITE_TEXT && text != nullptr
        && sqlite3_column_bytes(statement, column) == static_cast<int>(expected.size())
        && std::memcmp(text, expected.data(), expected.size()) == 0;
}

bool checkColumns(sqlite3* database, const char* pragma,
                  const std::string_view* names, const std::string_view* types,
                  std::size_t count, std::string& error)
{
    Statement query;
    if (!prepare(database, pragma, query, error)) return false;
    for (std::size_t index = 0; index < count; ++index) {
        const int code = sqlite3_step(query.value);
        if (code != SQLITE_ROW)
            return fail(error, "Colonnes du coffre absentes ou illisibles.");
        if (!textEquals(query.value, 1, names[index]) || !textEquals(query.value, 2, types[index])
            || sqlite3_column_int(query.value, 0) != static_cast<int>(index)
            || sqlite3_column_int(query.value, 5) != (index == 0 ? 1 : 0)
            || sqlite3_column_int(query.value, 3) != (index == 0 ? 0 : 1)
            || sqlite3_column_type(query.value, 4) != SQLITE_NULL
            || sqlite3_column_int(query.value, 6) != 0)
            return fail(error, "Colonnes du coffre incompatibles.");
    }
    if (sqlite3_step(query.value) != SQLITE_DONE)
        return fail(error, "Colonnes supplémentaires ou contrôle incomplet.");
    return true;
}

bool validateSnapshot(sqlite3* database, std::string& error)
{
    // Explicit object allow-list, including the two implicit UNIQUE/PK indexes.
    // No view, trigger, virtual table, or extra application table is accepted.
    if (!singleInteger(database,
            "SELECT count(*) FROM main.sqlite_schema WHERE "
            "(type='table' AND name=tbl_name AND name IN ('vault_metadata','entries')) OR "
            "(type='index' AND sql IS NULL AND "
            "((name='sqlite_autoindex_vault_metadata_1' AND tbl_name='vault_metadata') OR "
            "(name='sqlite_autoindex_entries_1' AND tbl_name='entries')));", 4, error)
        || !singleInteger(database, "SELECT count(*) FROM main.sqlite_schema;", 4, error))
        return false;
    constexpr std::string_view metadataNames[] = {"id", "vault_id", "format_version", "salt",
        "argon2_operations", "argon2_memory", "wrap_nonce", "wrapped_dek"};
    constexpr std::string_view metadataTypes[] = {"INTEGER", "BLOB", "INTEGER", "BLOB",
        "INTEGER", "INTEGER", "BLOB", "BLOB"};
    constexpr std::string_view entryNames[] = {"entry_id", "entry_version", "nonce", "ciphertext"};
    constexpr std::string_view entryTypes[] = {"BLOB", "INTEGER", "BLOB", "BLOB"};
    if (!checkColumns(database, "PRAGMA main.table_xinfo(vault_metadata);", metadataNames,
                      metadataTypes, 8, error)
        || !checkColumns(database, "PRAGMA main.table_xinfo(entries);", entryNames, entryTypes, 4, error)
        || !singleInteger(database, "SELECT count(*) FROM vault_metadata;", 1, error)
        || !singleInteger(database,
            "SELECT count(*) FROM entries WHERE typeof(entry_id)!='blob' OR length(entry_id)!=16 "
            "OR typeof(entry_version)!='integer' OR entry_version!=1 "
            "OR typeof(nonce)!='blob' OR length(nonce)!=24 "
            "OR typeof(ciphertext)!='blob' OR length(ciphertext)<16 OR length(ciphertext)>5242896;",
            0, error))
        return false;
    Statement query;
    if (!prepare(database, "PRAGMA main.integrity_check;", query, error)) return false;
    const int code = sqlite3_step(query.value);
    if (code != SQLITE_ROW)
        return sqlFailure(database, code, "Contrôle d'intégrité impossible", error);
    if (!textEquals(query.value, 0, "ok") || sqlite3_step(query.value) != SQLITE_DONE)
        return fail(error, "Le contrôle d'intégrité SQLite a échoué.");
    return true;
}

} // namespace

bool VaultSnapshotService::inspectDestinationDirectory(const std::string& path,
    SnapshotDirectoryIdentity& identity, std::string& error)
{
    identity = {};
    if (!validPath(path)) return fail(error, "Chemin de destination invalide.");
    Descriptor parent;
    if (!openParent(std::filesystem::path(path) / ".passwall-probe", parent, error)) return false;
    struct stat status {};
    if (::fstat(parent.value, &status) != 0 || status.st_uid != ::geteuid()
        || (status.st_mode & 0022) != 0)
        return fail(error, "Le dossier de destination doit appartenir à l'utilisateur et être protégé en écriture.");
    struct statfs filesystem {};
    if (::fstatfs(parent.value, &filesystem) != 0)
        return posixFailure(error, "Identification du système de fichiers impossible");
    switch (filesystem.f_type) {
    case EXT4_SUPER_MAGIC: case TMPFS_MAGIC: case XFS_SUPER_MAGIC:
    case BTRFS_SUPER_MAGIC: case F2FS_SUPER_MAGIC: case OVERLAYFS_SUPER_MAGIC: break;
    default: return fail(error, "Destination non prise en charge : publication locale requise pour cette version.");
    }
    if (::faccessat(parent.value, ".", W_OK | X_OK, AT_EACCESS) != 0)
        return posixFailure(error, "Destination inaccessible en écriture");
    identity = {std::uint64_t(status.st_dev), std::uint64_t(status.st_ino)};
    return true;
}

namespace {
// Internal only. The sole non-null producer below is a private method callable
// by the opaque 6A authority. Public createSnapshot never obtains this exception.
struct PrincipalReadPermission {
    bool (*check)(void*, SnapshotCheckpoint, std::string&) = nullptr;
    void* context = nullptr;
};
bool createSnapshotImpl(const std::string& sourcePath,
    const std::string& destinationPath, SnapshotResult& result, SnapshotCancellation cancellation,
    SnapshotVerification verification, const storage::VaultOperationGuard* reservation,
    const SnapshotDirectoryIdentity* expectedDirectory, PrincipalReadPermission permission = {})
{
    result.publication = SnapshotPublication::NotPublished;
    result.diagnostic.clear();
    auto& error = result.diagnostic;
    const auto cancelled = [&](SnapshotCheckpoint checkpoint) {
        if (!cancellation.requested || !cancellation.requested(cancellation.context, checkpoint))
            return false;
        result.publication = SnapshotPublication::CancelledBeforePublication;
        return true;
    };
    if (cancelled(SnapshotCheckpoint::BeforeWork)) return false;
    const auto permitted = [&](SnapshotCheckpoint checkpoint) {
        return !permission.check || permission.check(permission.context, checkpoint, error);
    };
    if (!permitted(SnapshotCheckpoint::BeforeWork)) return false;
    if (!validPath(sourcePath) || !validPath(destinationPath))
        return fail(error, "Des chemins absolus sans composante ambiguë sont requis.");
    storage::VaultOperationGuard ownedReservation;
    if (reservation) {
        if (!reservation->matchesReservation(sourcePath, error))
            return fail(error, "Réservation de la source non confirmée.");
    } else if (!ownedReservation.tryReserve(sourcePath, error)) {
        return false;
    }
    if (!permission.check && !VaultPreferencesStore::checkRecoveryAccess(sourcePath, error)) return false;
    const std::filesystem::path source(sourcePath), destination(destinationPath);
    Descriptor sourceParent, parent;
    if (!openParent(source, sourceParent, error) || !openParent(destination, parent, error)) return false;
    struct stat parentStatus{};
    if (::fstat(parent.value, &parentStatus) != 0 || parentStatus.st_uid != ::geteuid()
        || (parentStatus.st_mode & 0022) != 0)
        return fail(error, "Le dossier de destination doit appartenir à l'utilisateur et être protégé en écriture.");
    if (expectedDirectory && *expectedDirectory != SnapshotDirectoryIdentity{
            std::uint64_t(parentStatus.st_dev), std::uint64_t(parentStatus.st_ino)})
        return fail(error, "Le support ou le dossier de destination a changé.");
    struct statfs filesystem{};
    if (::fstatfs(parent.value, &filesystem) != 0)
        return posixFailure(error, "Identification du système de fichiers impossible");
    switch (filesystem.f_type) {
    case EXT4_SUPER_MAGIC: case TMPFS_MAGIC: case XFS_SUPER_MAGIC:
    case BTRFS_SUPER_MAGIC: case F2FS_SUPER_MAGIC: case OVERLAYFS_SUPER_MAGIC:
        break;
    default:
        return fail(error, "Destination non prise en charge : publication locale requise pour cette version.");
    }
    struct stat existing{};
    if (::fstatat(parent.value, destination.filename().c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0)
        return fail(error, "La destination existe déjà ; aucun écrasement autorisé.");
    if (errno != ENOENT) return posixFailure(error, "Vérification de la destination impossible");
    // Reject unsupported directory synchronization BEFORE building a snapshot.
    if (::fsync(parent.value) != 0) return posixFailure(error, "Synchronisation du dossier indisponible");

    Descriptor sourceFile;
    sourceFile.value = ::openat(sourceParent.value, source.filename().c_str(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat sourceStatus{};
    if (sourceFile.value < 0) return posixFailure(error, "Source absente ou lien symbolique refusé");
    if (::fstat(sourceFile.value, &sourceStatus) != 0 || !S_ISREG(sourceStatus.st_mode))
        return fail(error, "La source doit être un fichier régulier.");

    StagingDirectory staging(parent.value);
    if (!staging.create(error)) return false;
    const std::string temporaryPath = (destination.parent_path() / staging.name / "snapshot.pwdb").string();
    Descriptor temporaryFile;
    temporaryFile.value = ::openat(staging.directory.value, "snapshot.pwdb",
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (temporaryFile.value < 0) return posixFailure(error, "Création du fichier temporaire impossible");
    struct stat temporaryStatus{};
    if (::fstat(temporaryFile.value, &temporaryStatus) != 0 || !S_ISREG(temporaryStatus.st_mode)
        || temporaryStatus.st_uid != ::geteuid() || (temporaryStatus.st_mode & 0777) != 0600)
        return fail(error, "Le fichier temporaire ne possède pas les permissions privées requises.");

    Database from, to;
    if (!openDatabase(sourcePath, true, from, error) || !openDatabase(temporaryPath, false, to, error)) return false;
    struct stat current{};
    if (::fstatat(sourceParent.value, source.filename().c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0
        || current.st_dev != sourceStatus.st_dev || current.st_ino != sourceStatus.st_ino)
        return fail(error, "La source a changé pendant son ouverture.");

    Backup backup;
    backup.value = sqlite3_backup_init(to.value, "main", from.value, "main");
    if (backup.value == nullptr)
        return sqlFailure(to.value, sqlite3_errcode(to.value), "Initialisation de l'instantané impossible", error);
    unsigned consecutiveContention = 0;
    int code;
    while (true) {
        if (cancelled(SnapshotCheckpoint::CopyStep)) return false;
        if (!permitted(SnapshotCheckpoint::CopyStep)) return false;
        code = sqlite3_backup_step(backup.value, 16);
        if (code == SQLITE_DONE) break;
        if (code == SQLITE_OK) {
            // Progress (including SQLite's legitimate source restarts) is not
            // subject to a global time or iteration limit.
            consecutiveContention = 0;
        } else if ((code & 0xff) == SQLITE_BUSY || (code & 0xff) == SQLITE_LOCKED) {
            // Each BUSY call already uses the unchanged V1 busy_timeout. Bound
            // only consecutive failed attempts, never the healthy copy itself.
            if (++consecutiveContention >= 3) {
                backup.finish();
                return sqlFailure(to.value, code,
                    "Contention SQLite persistante après 3 tentatives consécutives", error);
            }
        } else {
            // Do not query the destination connection while backup is active.
            // finish() releases/rolls back the copy before diagnostic APIs.
            backup.finish();
            return sqlFailure(to.value, code, "Copie SQLite interrompue", error);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    code = backup.finish();
    if (code != SQLITE_OK) return sqlFailure(to.value, code, "Finalisation de l'instantané impossible", error);
    // No destination API calls were made while the backup handle was active.
    if (cancelled(SnapshotCheckpoint::BeforeValidation)) return false;
    if (!permitted(SnapshotCheckpoint::BeforeValidation)) return false;
    if (!storage::configureSqliteConnection(to.value, error) || !validateSnapshot(to.value, error)) return false;
    code = to.close();
    if (code != SQLITE_OK) return sqlFailure(to.value, code, "Fermeture de la copie impossible", error);
    code = from.close();
    if (code != SQLITE_OK) return sqlFailure(from.value, code, "Fermeture de la source impossible", error);

    VaultKeyMetadata metadata;
    if (!storage::VaultStorage::readMetadata(temporaryPath, metadata, error)) return false;
    if (metadata.formatVersion != VaultFormatVersion || metadata.operationsLimit < 3
        || metadata.operationsLimit > 4 || metadata.memoryLimit < VaultArgon2Memory
        || metadata.memoryLimit > 2 * VaultArgon2Memory)
        return fail(error, "Métadonnées ou format du coffre incompatibles avec PassWall V1.");
    if (verification.verify && !verification.verify(verification.context, temporaryPath, error))
        return false;
    if (::fsync(temporaryFile.value) != 0) return posixFailure(error, "Synchronisation de la copie impossible");
    if (temporaryFile.close() != 0) return posixFailure(error, "Fermeture du fichier temporaire impossible");
    if (::fstatat(sourceParent.value, source.filename().c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0
        || current.st_dev != sourceStatus.st_dev || current.st_ino != sourceStatus.st_ino)
        return fail(error, "La source a été remplacée pendant la copie.");

    if (cancelled(SnapshotCheckpoint::BeforePublication)) return false;
    if (!permitted(SnapshotCheckpoint::BeforePublication)) return false;
    if (expectedDirectory) {
        Descriptor namedParent;
        struct stat named {};
        if (!openParent(destination, namedParent, error) || ::fstat(namedParent.value, &named) != 0
            || std::uint64_t(named.st_dev) != expectedDirectory->device
            || std::uint64_t(named.st_ino) != expectedDirectory->inode)
            return fail(error, "La destination a disparu ou changé avant publication.");
    }
    if (::linkat(staging.directory.value, "snapshot.pwdb", parent.value,
                 destination.filename().c_str(), 0) != 0)
        return posixFailure(error, "Publication sans écrasement impossible");
    // No allocation, callback or throwing operation before recording this fact.
    result.publication = SnapshotPublication::PublishedDurabilityUnconfirmed;
    const bool cleaned = staging.cleanup();
    if (::fsync(parent.value) != 0)
        return posixFailure(error, "Copie publiée ; durabilité du répertoire non confirmée");
    result.publication = SnapshotPublication::Published;
    if (!cleaned) error = "Copie publiée ; un temporaire privé n'a pas pu être supprimé.";
    return true;
}
} // namespace

bool VaultSnapshotService::createSnapshot(const std::string& source,
    const std::string& destination, SnapshotResult& result, SnapshotCancellation cancellation,
    SnapshotVerification verification, const storage::VaultOperationGuard* reservation,
    const SnapshotDirectoryIdentity* expectedDirectory)
{
    return createSnapshotImpl(source, destination, result, cancellation, verification,
        reservation, expectedDirectory);
}

bool VaultSnapshotService::createReplacementSnapshot(const std::string& source,
    const std::string& destination, SnapshotResult& result, SnapshotCancellation cancellation,
    const storage::VaultOperationGuard& reservation, ReplacementReadCheck permission)
{
    return createSnapshotImpl(source, destination, result, cancellation, {}, &reservation,
        nullptr, {permission.check, permission.context});
}

} // namespace passwall::services
