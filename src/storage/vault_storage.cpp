
#include "vault_storage.hpp"
#include "storage/sqlite_connection_config.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <fcntl.h>
#include <unistd.h>

namespace passwall::storage {
namespace {

struct Database {
    sqlite3* handle = nullptr;

    Database() = default;
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    ~Database() noexcept { close(); }

    int close() noexcept
    {
        const int result = handle != nullptr ? sqlite3_close_v2(handle) : SQLITE_OK;
        if (result == SQLITE_OK)
            handle = nullptr;
        return result;
    }
};

struct Statement {
    sqlite3_stmt* handle = nullptr;

    Statement() = default;
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    ~Statement() noexcept { finalize(); }

    void finalize() noexcept
    {
        if (handle != nullptr) {
            sqlite3_finalize(handle);
            handle = nullptr;
        }
    }
};

struct ErrorMessage {
    char* handle = nullptr;

    ErrorMessage() = default;
    ErrorMessage(const ErrorMessage&) = delete;
    ErrorMessage& operator=(const ErrorMessage&) = delete;
    ~ErrorMessage() noexcept { sqlite3_free(handle); }
};

struct CreatedFile {
    // The caller's path outlives this guard. SQLite closes/rolls back first,
    // including its journal; only our exclusively created file is unlinked.
    const std::string& path;
    bool active = false;

    explicit CreatedFile(const std::string& path) noexcept : path(path) {}
    CreatedFile(const CreatedFile&) = delete;
    CreatedFile& operator=(const CreatedFile&) = delete;
    ~CreatedFile() noexcept
    {
        if (active)
            ::unlink(path.c_str());
    }
};

bool execute(sqlite3* database, const char* sql, std::string& error)
{
    ErrorMessage message;
    const int result = sqlite3_exec(database, sql, nullptr, nullptr, &message.handle);

    if (result == SQLITE_OK) {
        return true;
    }

    error = message.handle != nullptr ? message.handle : sqlite3_errmsg(database);
    return false;
}

bool openDatabase(
    const std::string& databasePath,
    Database& database,
    std::string& error,
    bool newlyCreated = false)
{
    const int result = sqlite3_open_v2(
        databasePath.c_str(),
        &database.handle,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
        nullptr);

    if (result == SQLITE_OK) {
        return configureSqliteConnection(database.handle, error, newlyCreated);
    }

    error = database.handle != nullptr
        ? sqlite3_errmsg(database.handle)
        : "Impossible d'ouvrir le fichier SQLite.";

    return false;
}

bool isBlobOfSize(
    sqlite3_stmt* statement,
    int column,
    int expectedSize)
{
    return sqlite3_column_type(statement, column) == SQLITE_BLOB
        && sqlite3_column_bytes(statement, column) == expectedSize
        && sqlite3_column_blob(statement, column) != nullptr;
}

} // namespace

bool VaultStorage::createSchema(
    const std::string& databasePath,
    std::string& error)
{
    error.clear();

    if (databasePath.empty()) {
        error = "Le chemin du coffre est vide.";
        return false;
    }

    CreatedFile createdFile(databasePath);
    const int fileDescriptor = ::open(
        databasePath.c_str(),
        O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
        0600);

    if (fileDescriptor == -1) {
        error = "Impossible de créer le fichier : il existe déjà ou le chemin est inaccessible.";
        return false;
    }

    createdFile.active = true;
    if (::close(fileDescriptor) != 0) {
        error = "Impossible de fermer le fichier nouvellement créé.";
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error, true)) {
        return false;
    }

    bool success = execute(database.handle, "BEGIN IMMEDIATE;", error);

    if (success) {
        success = execute(database.handle, R"sql(
            CREATE TABLE vault_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                vault_id BLOB NOT NULL UNIQUE CHECK (length(vault_id) = 16),
                format_version INTEGER NOT NULL CHECK (format_version > 0),
                salt BLOB NOT NULL CHECK (length(salt) = 16),
                argon2_operations INTEGER NOT NULL CHECK (argon2_operations > 0),
                argon2_memory INTEGER NOT NULL CHECK (argon2_memory > 0),
                wrap_nonce BLOB NOT NULL CHECK (length(wrap_nonce) = 24),
                wrapped_dek BLOB NOT NULL CHECK (length(wrapped_dek) = 48)
            );

            CREATE TABLE entries (
                entry_id BLOB PRIMARY KEY CHECK (length(entry_id) = 16),
                entry_version INTEGER NOT NULL CHECK (entry_version > 0),
                nonce BLOB NOT NULL CHECK (length(nonce) = 24),
                ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16)
            );
        )sql", error);
    }

    if (success) {
        success = execute(database.handle, "COMMIT;", error);
    } else {
        std::string rollbackError;
        execute(database.handle, "ROLLBACK;", rollbackError);
    }

    const int closeResult = database.close();

    if (success && closeResult != SQLITE_OK) {
        error = "Impossible de fermer proprement le fichier SQLite.";
        success = false;
    }

    if (!success) {
        return false;
    }

    createdFile.active = false;
    return true;
}

bool VaultStorage::writeMetadata(
    const std::string& databasePath,
    const services::VaultKeyMetadata& metadata,
    std::string& error)
{
    error.clear();

    if (databasePath.empty()) {
        error = "Le chemin du coffre est vide.";
        return false;
    }

    if (metadata.formatVersion <= 0 ||
        metadata.operationsLimit == 0 ||
        metadata.memoryLimit == 0 ||
        metadata.operationsLimit >
            static_cast<std::uint64_t>(
                std::numeric_limits<sqlite3_int64>::max()) ||
        metadata.memoryLimit >
            static_cast<std::size_t>(
                std::numeric_limits<sqlite3_int64>::max())) {
        error = "Les métadonnées du coffre contiennent des valeurs invalides.";
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    bool success = execute(database.handle, "BEGIN IMMEDIATE;", error);
    Statement statement;

    if (success) {
        const char* sql = R"sql(
            INSERT INTO vault_metadata (
                id,
                vault_id,
                format_version,
                salt,
                argon2_operations,
                argon2_memory,
                wrap_nonce,
                wrapped_dek
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?);
        )sql";

        const int prepareResult = sqlite3_prepare_v2(
            database.handle, sql, -1, &statement.handle, nullptr);

        if (prepareResult != SQLITE_OK) {
            error = sqlite3_errmsg(database.handle);
            success = false;
        }
    }

    if (success) {
        const int bindResults[] = {
            sqlite3_bind_blob(
                statement.handle, 1,
                metadata.vaultId.data(),
                static_cast<int>(metadata.vaultId.size()),
                SQLITE_TRANSIENT),
            sqlite3_bind_int(statement.handle, 2, metadata.formatVersion),
            sqlite3_bind_blob(
                statement.handle, 3,
                metadata.salt.data(),
                static_cast<int>(metadata.salt.size()),
                SQLITE_TRANSIENT),
            sqlite3_bind_int64(
                statement.handle, 4,
                static_cast<sqlite3_int64>(metadata.operationsLimit)),
            sqlite3_bind_int64(
                statement.handle, 5,
                static_cast<sqlite3_int64>(metadata.memoryLimit)),
            sqlite3_bind_blob(
                statement.handle, 6,
                metadata.wrapNonce.data(),
                static_cast<int>(metadata.wrapNonce.size()),
                SQLITE_TRANSIENT),
            sqlite3_bind_blob(
                statement.handle, 7,
                metadata.wrappedDek.data(),
                static_cast<int>(metadata.wrappedDek.size()),
                SQLITE_TRANSIENT)
        };

        for (const int bindResult : bindResults) {
            if (bindResult != SQLITE_OK) {
                error = sqlite3_errmsg(database.handle);
                success = false;
                break;
            }
        }
    }

    if (success) {
        const int stepResult = sqlite3_step(statement.handle);

        if (stepResult != SQLITE_DONE) {
            error = sqlite3_errmsg(database.handle);
            success = false;
        }
    }

    statement.finalize();

    if (success) {
        success = execute(database.handle, "COMMIT;", error);
    }

    if (!success) {
        std::string rollbackError;
        execute(database.handle, "ROLLBACK;", rollbackError);
    }

    const int closeResult = database.close();

    if (success && closeResult != SQLITE_OK) {
        error = "Impossible de fermer proprement le fichier SQLite.";
        return false;
    }

    return success;
}

bool VaultStorage::readMetadata(
    const std::string& databasePath,
    services::VaultKeyMetadata& metadata,
    std::string& error)
{
    error.clear();
    metadata = services::VaultKeyMetadata{};

    if (databasePath.empty()) {
        error = "Le chemin du coffre est vide.";
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    Statement statement;

    const char* sql = R"sql(
        SELECT
            vault_id,
            format_version,
            salt,
            argon2_operations,
            argon2_memory,
            wrap_nonce,
            wrapped_dek
        FROM vault_metadata
        WHERE id = 1;
    )sql";

    bool success = true;

    if (sqlite3_prepare_v2(
            database.handle, sql, -1, &statement.handle, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(database.handle);
        success = false;
    }

    services::VaultKeyMetadata candidate{};

    if (success) {
        const int stepResult = sqlite3_step(statement.handle);

        if (stepResult != SQLITE_ROW) {
            error = stepResult == SQLITE_DONE
                ? "Les métadonnées du coffre sont absentes."
                : sqlite3_errmsg(database.handle);
            success = false;
        }
    }

    if (success) {
        const sqlite3_int64 version = sqlite3_column_int64(statement.handle, 1);
        const sqlite3_int64 operations = sqlite3_column_int64(statement.handle, 3);
        const sqlite3_int64 memory = sqlite3_column_int64(statement.handle, 4);

        const bool validTypes =
            sqlite3_column_type(statement.handle, 1) == SQLITE_INTEGER &&
            sqlite3_column_type(statement.handle, 3) == SQLITE_INTEGER &&
            sqlite3_column_type(statement.handle, 4) == SQLITE_INTEGER;

        const bool validBlobs =
            isBlobOfSize(statement.handle, 0, 16) &&
            isBlobOfSize(statement.handle, 2, 16) &&
            isBlobOfSize(statement.handle, 5, 24) &&
            isBlobOfSize(statement.handle, 6, 48);

        if (!validTypes || !validBlobs ||
            version <= 0 ||
            version > std::numeric_limits<int>::max() ||
            operations <= 0 ||
            memory <= 0 ||
            static_cast<std::uint64_t>(memory) >
                std::numeric_limits<std::size_t>::max()) {
            error = "Les métadonnées du coffre sont invalides ou corrompues.";
            success = false;
        } else {
            std::copy_n(
                static_cast<const unsigned char*>(
                    sqlite3_column_blob(statement.handle, 0)),
                candidate.vaultId.size(),
                candidate.vaultId.begin());

            candidate.formatVersion = static_cast<int>(version);

            std::copy_n(
                static_cast<const unsigned char*>(
                    sqlite3_column_blob(statement.handle, 2)),
                candidate.salt.size(),
                candidate.salt.begin());

            candidate.operationsLimit =
                static_cast<std::uint64_t>(operations);

            candidate.memoryLimit = static_cast<std::size_t>(memory);

            std::copy_n(
                static_cast<const unsigned char*>(
                    sqlite3_column_blob(statement.handle, 5)),
                candidate.wrapNonce.size(),
                candidate.wrapNonce.begin());

            std::copy_n(
                static_cast<const unsigned char*>(
                    sqlite3_column_blob(statement.handle, 6)),
                candidate.wrappedDek.size(),
                candidate.wrappedDek.begin());
        }
    }

    statement.finalize();

    const int closeResult = database.close();

    if (success && closeResult != SQLITE_OK) {
        error = "Impossible de fermer proprement le fichier SQLite.";
        return false;
    }

    if (!success) {
        return false;
    }

    metadata = candidate;
    return true;
}

} // namespace passwall::storage
