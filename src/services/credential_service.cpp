
#include "services/credential_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include "services/vault_key_service.hpp"
#include "services/vault_preferences_store.hpp"
#include "storage/vault_storage.hpp"
#include "storage/sqlite_connection_config.hpp"

#include <sqlite3.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace passwall::services {
namespace {

using models::Credential;
using models::CredentialSummary;
using models::EntryId;
using core::CryptoEngine;
using core::CryptoError;
using core::EncryptedData;
using core::SecureBuffer;

void wipeString(std::string& value) noexcept
{
    if (!value.empty()) {
        sodium_memzero(value.data(), value.size());
    }
    value.clear();
}

void wipeCredential(Credential& credential) noexcept
{
    wipeString(credential.title);
    wipeString(credential.url);
    wipeString(credential.username);
    wipeString(credential.password);
    wipeString(credential.notes);
    sodium_memzero(credential.id.data(), credential.id.size());
    credential.version = 0;
}

class CredentialWiper final {
public:
    explicit CredentialWiper(Credential& credential) noexcept
        : credential_(credential)
    {
    }

    ~CredentialWiper() { wipeCredential(credential_); }

    CredentialWiper(const CredentialWiper&) = delete;
    CredentialWiper& operator=(const CredentialWiper&) = delete;

private:
    Credential& credential_;
};

class CredentialVectorWiper final {
public:
    explicit CredentialVectorWiper(std::vector<Credential>& credentials) noexcept
        : credentials_(credentials)
    {
    }

    ~CredentialVectorWiper()
    {
        for (auto& credential : credentials_) {
            wipeCredential(credential);
        }
    }

    CredentialVectorWiper(const CredentialVectorWiper&) = delete;
    CredentialVectorWiper& operator=(const CredentialVectorWiper&) = delete;

private:
    std::vector<Credential>& credentials_;
};

constexpr std::uint32_t EntryFormatVersion = 1;
constexpr std::size_t FieldCount = 5;
constexpr std::size_t HeaderSize = 4 + FieldCount * 4;
constexpr std::size_t MaxFieldSize = 1024 * 1024;
constexpr std::size_t MaxPlaintextSize = 5 * 1024 * 1024;
constexpr std::size_t AadSize = 52;

constexpr std::array<unsigned char, 4> Magic = {
    'P', 'W', 'C', '1'
};

constexpr std::array<unsigned char, 16> EntryPurpose = {
    'P', 'W', '-', 'E', 'N', 'T', 'R', 'Y',
    '-', 'E', 'N', 'C', '-', 'v', '1', 0
};

struct Database {
    storage::VaultOperationGuard access;
    sqlite3* handle = nullptr;

    ~Database()
    {
        if (handle != nullptr) {
            sqlite3_close_v2(handle);
        }
    }

    Database() = default;
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
};

struct Statement {
    sqlite3_stmt* handle = nullptr;

    ~Statement()
    {
        if (handle != nullptr) {
            sqlite3_finalize(handle);
        }
    }

    Statement() = default;
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
};

struct SqlFailure {
    int primary;
    int extended;
    bool extendedConfirmed;
};

SqlFailure captureSqlFailure(sqlite3* database, int result) noexcept
{
    // Save immediately: finalize(), ROLLBACK and even subsequent API calls
    // may replace the connection's last error. A returned extended code also
    // remains usable if the connection has no matching diagnostic (e.g. MISUSE).
    const int extended = sqlite3_extended_errcode(database);
    const int primary = result & 0xff;
    const bool matching = (extended & 0xff) == primary;
    return {primary, matching ? extended : result, matching || result > 0xff};
}

std::string describeSqlFailure(const SqlFailure& failure)
{
    // errstr(), unlike errmsg(), cannot include trigger text, bound values,
    // SQL fragments or other database-controlled content.
    const char* reason = sqlite3_errstr(failure.primary);
    return std::string(reason != nullptr ? reason : "erreur SQLite")
        + " [SQLite primaire=" + std::to_string(failure.primary)
        + ", étendu=" + std::to_string(failure.extended)
        + (failure.extendedConfirmed ? "]." : ", détail étendu non confirmé].");
}

bool sqlError(sqlite3* database, int result, const char* operation, std::string& error)
{
    const auto failure = captureSqlFailure(database, result);
    error = std::string(operation) + " : " + describeSqlFailure(failure);
    return false;
}

bool openDatabase(
    const std::string& path,
    Database& database,
    std::string& error)
{
    if (path.empty()) {
        error = "Le chemin du coffre est vide.";
        return false;
    }

    if (!database.access.tryAccess(path, error)) return false;
    if (!VaultPreferencesStore::checkRecoveryAccess(path, error)) return false;
    const int result = sqlite3_open_v2(
        path.c_str(),
        &database.handle,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
        nullptr);

    if (result != SQLITE_OK) {
        error = database.handle != nullptr
            ? sqlite3_errmsg(database.handle)
            : "Impossible d'ouvrir le coffre SQLite.";
        return false;
    }

    return storage::configureSqliteConnection(database.handle, error);
}

bool prepare(
    sqlite3* database,
    const char* sql,
    Statement& statement,
    std::string& error)
{
    const int result = sqlite3_prepare_v2(database, sql, -1, &statement.handle, nullptr);
    if (result != SQLITE_OK)
        return sqlError(database, result, "Préparation SQL", error);

    return true;
}

bool validKey(const SecureBuffer& key)
{
    return key.data() != nullptr && key.size() == core::KeySize;
}

bool validField(const std::string& field)
{
    return field.size() <= MaxFieldSize;
}

bool validCredentialFieldSizes(const Credential& credential)
{
    return validField(credential.title)
        && validField(credential.url)
        && validField(credential.username)
        && validField(credential.password)
        && validField(credential.notes);
}

bool containsNonWhitespace(std::string_view value) noexcept
{
    // Propriété Unicode White_Space, encodée en UTF-8. Comparaison par vues :
    // pas de copie des champs, d'allocation, de locale ou de normalisation.
    constexpr std::string_view whitespace[] = {
        " ", "\t", "\n", "\v", "\f", "\r", "\xC2\x85", "\xC2\xA0",
        "\xE1\x9A\x80", "\xE2\x80\x80", "\xE2\x80\x81", "\xE2\x80\x82",
        "\xE2\x80\x83", "\xE2\x80\x84", "\xE2\x80\x85", "\xE2\x80\x86",
        "\xE2\x80\x87", "\xE2\x80\x88", "\xE2\x80\x89", "\xE2\x80\x8A",
        "\xE2\x80\xA8", "\xE2\x80\xA9", "\xE2\x80\xAF", "\xE2\x81\x9F",
        "\xE3\x80\x80"
    };
    while (!value.empty()) {
        const auto match = std::find_if(std::begin(whitespace), std::end(whitespace),
            [value](std::string_view space) { return value.starts_with(space); });
        if (match == std::end(whitespace))
            return true;
        value.remove_prefix(match->size());
    }
    return false;
}

void writeU32(unsigned char* destination, std::uint32_t value)
{
    destination[0] = static_cast<unsigned char>(value & 0xFF);
    destination[1] = static_cast<unsigned char>((value >> 8) & 0xFF);
    destination[2] = static_cast<unsigned char>((value >> 16) & 0xFF);
    destination[3] = static_cast<unsigned char>((value >> 24) & 0xFF);
}

std::uint32_t readU32(const unsigned char* source)
{
    return static_cast<std::uint32_t>(source[0])
        | (static_cast<std::uint32_t>(source[1]) << 8)
        | (static_cast<std::uint32_t>(source[2]) << 16)
        | (static_cast<std::uint32_t>(source[3]) << 24);
}

std::array<unsigned char, AadSize> makeAssociatedData(
    const services::VaultKeyMetadata& metadata,
    const EntryId& entryId)
{
    std::array<unsigned char, AadSize> aad{};

    std::copy(
        metadata.vaultId.begin(),
        metadata.vaultId.end(),
        aad.begin());

    std::copy(
        entryId.begin(),
        entryId.end(),
        aad.begin() + 16);

    writeU32(aad.data() + 32, EntryFormatVersion);

    std::copy(
        EntryPurpose.begin(),
        EntryPurpose.end(),
        aad.begin() + 36);

    return aad;
}

bool serialize(
    const Credential& credential,
    SecureBuffer& plaintext,
    std::string& error)
{
    if (!CredentialService::validate(credential, error)) {
        return false;
    }

    const std::array<const std::string*, FieldCount> fields = {
        &credential.title,
        &credential.url,
        &credential.username,
        &credential.password,
        &credential.notes
    };

    std::size_t totalSize = HeaderSize;

    for (const auto* field : fields) {
        if (field->size() >
            std::numeric_limits<std::uint32_t>::max()) {
            error = "Un champ est trop volumineux.";
            return false;
        }

        if (totalSize > MaxPlaintextSize - field->size()) {
            error = "L'identifiant est trop volumineux.";
            return false;
        }

        totalSize += field->size();
    }

    if (totalSize > MaxPlaintextSize) {
        error = "L'identifiant est trop volumineux.";
        return false;
    }

    try {
        plaintext = SecureBuffer(totalSize);
    } catch (...) {
        error = "Impossible d'allouer la mémoire sécurisée.";
        return false;
    }

    unsigned char* output = plaintext.data();

    std::copy(Magic.begin(), Magic.end(), output);
    std::size_t offset = 4;

    for (const auto* field : fields) {
        writeU32(
            output + offset,
            static_cast<std::uint32_t>(field->size()));
        offset += 4;
    }

    for (const auto* field : fields) {
        if (!field->empty()) {
            std::memcpy(
                output + offset,
                field->data(),
                field->size());
        }

        offset += field->size();
    }

    return true;
}

bool deserialize(
    std::span<const unsigned char> plaintext,
    const EntryId& entryId,
    Credential& credential,
    std::string& error)
{
    if (plaintext.size() < HeaderSize ||
        plaintext.size() > MaxPlaintextSize ||
        !std::equal(
            Magic.begin(),
            Magic.end(),
            plaintext.begin())) {
        error = "Le contenu déchiffré est invalide.";
        return false;
    }

    std::array<std::uint32_t, FieldCount> lengths{};
    std::size_t offset = 4;
    std::size_t payloadSize = 0;

    for (std::size_t i = 0; i < FieldCount; ++i) {
        lengths[i] = readU32(plaintext.data() + offset);
        offset += 4;

        if (lengths[i] > MaxFieldSize ||
            payloadSize > MaxPlaintextSize - lengths[i]) {
            error = "Les longueurs des champs sont invalides.";
            return false;
        }

        payloadSize += lengths[i];
    }

    if (HeaderSize + payloadSize != plaintext.size()) {
        error = "La structure de l'identifiant est invalide.";
        return false;
    }

    Credential candidate;
    CredentialWiper candidateWiper(candidate);
    candidate.id = entryId;
    candidate.version = EntryFormatVersion;

    std::array<std::string*, FieldCount> fields = {
        &candidate.title,
        &candidate.url,
        &candidate.username,
        &candidate.password,
        &candidate.notes
    };

    offset = HeaderSize;

    try {
        for (std::size_t i = 0; i < FieldCount; ++i) {
            fields[i]->assign(
                reinterpret_cast<const char*>(plaintext.data() + offset),
                lengths[i]);

            offset += lengths[i];
        }
    } catch (...) {
        error = "Impossible de reconstruire l'identifiant en mémoire.";
        return false;
    }

    wipeCredential(credential);
    credential = std::move(candidate);
    return true;
}

bool bindEntryId(
    sqlite3_stmt* statement,
    int index,
    const EntryId& entryId,
    sqlite3* database,
    std::string& error)
{
    const int result = sqlite3_bind_blob(
            statement,
            index,
            entryId.data(),
            static_cast<int>(entryId.size()),
            SQLITE_TRANSIENT);
    if (result != SQLITE_OK)
        return sqlError(database, result, "Liaison de l'identifiant", error);

    return true;
}

bool encryptCredential(
    const services::VaultKeyMetadata& metadata,
    const SecureBuffer& dataKey,
    const Credential& credential,
    EncryptedData& encrypted,
    std::string& error)
{
    SecureBuffer plaintext(0);

    if (!serialize(credential, plaintext, error)) {
        return false;
    }

    const auto aad = makeAssociatedData(metadata, credential.id);

    const auto keySpan = std::span<const unsigned char>(
        dataKey.data(), dataKey.size());

    const CryptoError result = CryptoEngine::encrypt(
        std::span<const unsigned char>(
            plaintext.data(), plaintext.size()),
        std::span<const unsigned char>(aad.data(), aad.size()),
        keySpan,
        encrypted);

    if (result != CryptoError::None) {
        error = "Le chiffrement de l'identifiant a échoué.";
        return false;
    }

    return true;
}

bool decryptCredential(
    const services::VaultKeyMetadata& metadata,
    const SecureBuffer& dataKey,
    const EntryId& entryId,
    std::uint32_t version,
    const EncryptedData& encrypted,
    Credential& credential,
    std::string& error)
{
    if (version != EntryFormatVersion) {
        error = "La version de cet identifiant n'est pas prise en charge.";
        return false;
    }

    const auto aad = makeAssociatedData(metadata, entryId);

    SecureBuffer plaintext(0);

    const auto keySpan = std::span<const unsigned char>(
        dataKey.data(), dataKey.size());

    const CryptoError result = CryptoEngine::decrypt(
        encrypted,
        std::span<const unsigned char>(aad.data(), aad.size()),
        keySpan,
        plaintext);

    if (result != CryptoError::None) {
        error = "Impossible d'authentifier l'identifiant. "
                "La clé est incorrecte ou les données ont été modifiées.";
        return false;
    }

    return deserialize(
        std::span<const unsigned char>(
            plaintext.data(), plaintext.size()),
        entryId,
        credential,
        error);
}

bool readEntry(
    sqlite3* database,
    const services::VaultKeyMetadata& metadata,
    const SecureBuffer& dataKey,
    const EntryId& entryId,
    Credential& credential,
    std::string& error)
{
    Statement statement;

    if (!prepare(
            database,
            "SELECT entry_version, nonce, ciphertext "
            "FROM entries WHERE entry_id = ?;",
            statement,
            error)) {
        return false;
    }

    if (!bindEntryId(statement.handle, 1, entryId, database, error)) {
        return false;
    }

    const int result = sqlite3_step(statement.handle);

    if (result != SQLITE_ROW) {
        if (result != SQLITE_DONE)
            return sqlError(database, result, "Lecture de l'identifiant", error);
        error = "Cet identifiant n'existe pas.";
        return false;
    }

    if (sqlite3_column_type(statement.handle, 0) != SQLITE_INTEGER ||
        sqlite3_column_type(statement.handle, 1) != SQLITE_BLOB ||
        sqlite3_column_type(statement.handle, 2) != SQLITE_BLOB) {
        error = "L'enregistrement SQLite est invalide.";
        return false;
    }

    const sqlite3_int64 storedVersion =
        sqlite3_column_int64(statement.handle, 0);

    const int nonceSize = sqlite3_column_bytes(statement.handle, 1);
    const int ciphertextSize = sqlite3_column_bytes(statement.handle, 2);

    if (storedVersion <= 0 ||
        storedVersion > std::numeric_limits<std::uint32_t>::max() ||
        nonceSize != static_cast<int>(core::NonceSize) ||
        ciphertextSize < static_cast<int>(core::AuthenticationTagSize) ||
        ciphertextSize > static_cast<int>(
            MaxPlaintextSize + core::AuthenticationTagSize)) {
        error = "L'enregistrement SQLite est corrompu.";
        return false;
    }

    EncryptedData encrypted;

    std::copy_n(
        static_cast<const unsigned char*>(
            sqlite3_column_blob(statement.handle, 1)),
        encrypted.nonce.size(),
        encrypted.nonce.begin());

    const auto* ciphertext =
        static_cast<const unsigned char*>(
            sqlite3_column_blob(statement.handle, 2));

    try {
        encrypted.ciphertext.assign(
            ciphertext,
            ciphertext + ciphertextSize);
    } catch (...) {
        error = "Mémoire insuffisante pour lire l'identifiant.";
        return false;
    }

    return decryptCredential(
        metadata,
        dataKey,
        entryId,
        static_cast<std::uint32_t>(storedVersion),
        encrypted,
        credential,
        error);
}

bool insertEncrypted(
    sqlite3* database,
    const Credential& credential,
    const EncryptedData& encrypted,
    std::string& error)
{
    Statement statement;

    if (!prepare(
            database,
            "INSERT INTO entries "
            "(entry_id, entry_version, nonce, ciphertext) "
            "VALUES (?, ?, ?, ?);",
            statement,
            error)) {
        return false;
    }

    if (!bindEntryId(
            statement.handle, 1, credential.id, database, error)) {
        return false;
    }

    int result;
    if ((result = sqlite3_bind_int64(
            statement.handle, 2, EntryFormatVersion)) != SQLITE_OK ||
        (result = sqlite3_bind_blob(
            statement.handle,
            3,
            encrypted.nonce.data(),
            static_cast<int>(encrypted.nonce.size()),
            SQLITE_TRANSIENT)) != SQLITE_OK ||
        (result = sqlite3_bind_blob(
            statement.handle,
            4,
            encrypted.ciphertext.data(),
            static_cast<int>(encrypted.ciphertext.size()),
            SQLITE_TRANSIENT)) != SQLITE_OK)
        return sqlError(database, result, "Liaison pour INSERT", error);

    result = sqlite3_step(statement.handle);
    if (result != SQLITE_DONE)
        return sqlError(database, result, "INSERT", error);

    return true;
}

struct TransactionState {
    bool autocommit;
    int main;

    bool ended() const noexcept { return autocommit && main == SQLITE_TXN_NONE; }
    bool active() const noexcept
    {
        return !autocommit && main >= SQLITE_TXN_NONE && main <= SQLITE_TXN_WRITE;
    }
};

TransactionState transactionState(sqlite3* database) noexcept
{
    const bool autocommit = sqlite3_get_autocommit(database) != 0;
    return {autocommit, sqlite3_txn_state(database, "main")};
}

std::string describeState(const TransactionState& state)
{
    const char* name = state.main == SQLITE_TXN_NONE ? "NONE"
        : state.main == SQLITE_TXN_READ ? "READ"
        : state.main == SQLITE_TXN_WRITE ? "WRITE" : "inconnu";
    return std::string("autocommit=") + (state.autocommit ? "1" : "0") + ", main=" + name;
}

void rollback(sqlite3* database, const char* operation, std::string& error,
              bool commitAttempted = false)
{
    // The initial cause/code is already saved in error, before any cleanup.
    error.insert(0, std::string(operation) + " : ");
    const auto before = transactionState(database);
    if (before.ended()) {
        error += commitAttempted
            ? " Après échec de COMMIT : aucune transaction active ; résultat persistant non confirmé."
            : " Annulation automatique observée avant COMMIT ; aucune transaction active.";
        return;
    }
    if (!before.active()) {
        error += " État transactionnel non confirmé (" + describeState(before)
            + ") ; aucun rollback annoncé. Fermeture par RAII.";
        return;
    }

    const int result = sqlite3_exec(database, "ROLLBACK;", nullptr, nullptr, nullptr);
    // Capture cleanup's own error BEFORE inspecting the post-rollback state.
    const auto cleanupFailure = result == SQLITE_OK ? SqlFailure{0, 0, true}
                                                  : captureSqlFailure(database, result);
    const auto after = transactionState(database);
    error += " Transaction encore active avant nettoyage (" + describeState(before) + ").";
    if (result == SQLITE_OK && after.ended()) {
        error += " ROLLBACK explicite confirmé par SQLite.";
    } else {
        error += result == SQLITE_OK ? " ROLLBACK a retourné SQLITE_OK, mais"
            : " Échec secondaire de ROLLBACK : " + describeSqlFailure(cleanupFailure);
        error += " annulation non confirmée (" + describeState(after) + "). Fermeture par RAII.";
    }
}

bool beginTransaction(sqlite3* database, const char* operation, std::string& error)
{
    const int result = sqlite3_exec(database, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr);
    if (result != SQLITE_OK) {
        sqlError(database, result, "BEGIN IMMEDIATE", error);
        const auto state = transactionState(database);
        if (state.ended()) {
            error.insert(0, std::string(operation) + " : ");
            error += " BEGIN refusé ; aucune transaction active observée.";
        } else {
            rollback(database, operation, error);
        }
        return false;
    }
    const auto state = transactionState(database);
    if (state.autocommit || state.main != SQLITE_TXN_WRITE) {
        error = std::string(operation) + " : BEGIN IMMEDIATE a retourné SQLITE_OK, mais la transaction "
            "d'écriture n'est pas confirmée (" + describeState(state) + "). Fermeture par RAII.";
        return false;
    }
    return true;
}

bool commit(sqlite3* database, const char* operation, std::string& error)
{
    const int result = sqlite3_exec(database, "COMMIT;", nullptr, nullptr, nullptr);
    if (result != SQLITE_OK) {
        sqlError(database, result, "COMMIT", error);
        rollback(database, operation, error, true);
        return false;
    }
    const auto state = transactionState(database);
    if (!state.ended()) {
        error = std::string(operation) + " : COMMIT a retourné SQLITE_OK, mais la fin de transaction "
            "n'est pas confirmée (" + describeState(state)
            + "). Résultat persistant non confirmé. Fermeture par RAII.";
        return false;
    }
    return true;
}

bool loadMetadata(
    const std::string& databasePath,
    services::VaultKeyMetadata& metadata,
    std::string& error)
{
    return storage::VaultStorage::readMetadata(
        databasePath, metadata, error);
}

bool prepareMutation(const std::string& path, storage::VaultOperationGuard& access,
                     std::string& error)
{
    QString failure;
    if (VaultPreferencesStore().prepareMutation(QString::fromStdString(path), access, failure))
        return true;
    error = "Modification refusée (suivi des sauvegardes) : " + failure.toStdString();
    return false;
}

} // namespace

bool CredentialService::validate(const Credential& credential, std::string& error)
{
    error.clear();
    if (!validCredentialFieldSizes(credential)) {
        error = "Un champ dépasse la taille maximale autorisée.";
        return false;
    }
    if (!containsNonWhitespace(credential.title)) {
        error = "Le titre est obligatoire et ne doit pas contenir uniquement des espaces.";
        return false;
    }
    if (!containsNonWhitespace(credential.username)) {
        error = "Le nom d'utilisateur est obligatoire et ne doit pas contenir uniquement des espaces.";
        return false;
    }
    if (credential.password.empty()) {
        error = "Le mot de passe est obligatoire.";
        return false;
    }
    return true;
}

bool CredentialService::add(
    const std::string& databasePath,
    const SecureBuffer& dataKey,
    Credential& credential,
    std::string& error)
{
    error.clear();

    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }

    if (!validate(credential, error)) {
        return false;
    }

    storage::VaultOperationGuard mutation;
    if (!prepareMutation(databasePath, mutation, error)) return false;

    services::VaultKeyMetadata metadata{};

    if (!loadMetadata(databasePath, metadata, error)) {
        return false;
    }

    Credential candidate;
    CredentialWiper candidateWiper(candidate);
    // Armer l'effacement AVANT les copies de chaînes : l'affectation peut
    // échouer après avoir déjà copié le mot de passe ou d'autres champs.
    candidate = credential;

    if (!CryptoEngine::initialize()) {
        error = "L'initialisation du moteur cryptographique a échoué.";
        return false;
    }

    randombytes_buf(candidate.id.data(), candidate.id.size());
    candidate.version = EntryFormatVersion;

    EncryptedData encrypted;

    if (!encryptCredential(
            metadata, dataKey, candidate, encrypted, error)) {
        sodium_memzero(candidate.id.data(), candidate.id.size());
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        sodium_memzero(candidate.id.data(), candidate.id.size());
        return false;
    }

    if (!beginTransaction(database.handle, "Ajout", error)) {
        sodium_memzero(candidate.id.data(), candidate.id.size());
        return false;
    }

    if (!insertEncrypted(database.handle, candidate, encrypted, error)) {
        rollback(database.handle, "Ajout", error);
        sodium_memzero(candidate.id.data(), candidate.id.size());
        return false;
    }

    if (!commit(database.handle, "Ajout", error)) {
        sodium_memzero(candidate.id.data(), candidate.id.size());
        return false;
    }

    credential.id = candidate.id;
    credential.version = candidate.version;
    sodium_memzero(candidate.id.data(), candidate.id.size());

    return true;
}

bool CredentialService::get(
    const std::string& databasePath,
    const SecureBuffer& dataKey,
    const EntryId& entryId,
    Credential& credential,
    std::string& error)
{
    error.clear();
    wipeCredential(credential);
    credential.version = EntryFormatVersion;

    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }

    services::VaultKeyMetadata metadata{};

    if (!loadMetadata(databasePath, metadata, error)) {
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    Credential candidate;
    CredentialWiper candidateWiper(candidate);

    if (!readEntry(
            database.handle,
            metadata,
            dataKey,
            entryId,
            candidate,
            error)) {
        return false;
    }

    credential = std::move(candidate);
    return true;
}

bool CredentialService::list(
    const std::string& databasePath,
    const SecureBuffer& dataKey,
    std::vector<Credential>& credentials,
    std::string& error)
{
    error.clear();
    for (auto& credential : credentials) {
        wipeCredential(credential);
    }
    credentials.clear();

    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }

    services::VaultKeyMetadata metadata{};

    if (!loadMetadata(databasePath, metadata, error)) {
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    Statement statement;

    if (!prepare(
            database.handle,
            "SELECT entry_id FROM entries ORDER BY entry_id;",
            statement,
            error)) {
        return false;
    }

    std::vector<Credential> result;
    CredentialVectorWiper resultWiper(result);

    try {
        while (true) {
            const int stepResult = sqlite3_step(statement.handle);

            if (stepResult == SQLITE_DONE) {
                break;
            }

            if (stepResult != SQLITE_ROW) {
                error = sqlite3_errmsg(database.handle);
                return false;
            }

            if (sqlite3_column_type(statement.handle, 0) != SQLITE_BLOB ||
                sqlite3_column_bytes(statement.handle, 0) !=
                    static_cast<int>(models::EntryIdSize)) {
                error = "Un identifiant d'entrée SQLite est invalide.";
                return false;
            }

            EntryId entryId{};

            std::copy_n(
                static_cast<const unsigned char*>(
                    sqlite3_column_blob(statement.handle, 0)),
                entryId.size(),
                entryId.begin());

            Credential credential;
            CredentialWiper credentialWiper(credential);

            if (!readEntry(
                    database.handle,
                    metadata,
                    dataKey,
                    entryId,
                    credential,
                    error)) {
                sodium_memzero(entryId.data(), entryId.size());
                return false;
            }

            sodium_memzero(entryId.data(), entryId.size());
            result.push_back(std::move(credential));
        }
    } catch (...) {
        error = "Mémoire insuffisante pour charger les identifiants.";
        return false;
    }

    credentials = std::move(result);
    return true;
}

bool CredentialService::listSummaries(
    const std::string& databasePath,
    const SecureBuffer& dataKey,
    std::vector<CredentialSummary>& summaries,
    std::string& error)
{
    error.clear();
    summaries.clear();

    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }

    services::VaultKeyMetadata metadata{};

    if (!loadMetadata(databasePath, metadata, error)) {
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    Statement statement;

    if (!prepare(
            database.handle,
            "SELECT entry_id FROM entries ORDER BY entry_id;",
            statement,
            error)) {
        return false;
    }

    std::vector<CredentialSummary> result;

    try {
        while (true) {
            const int stepResult = sqlite3_step(statement.handle);

            if (stepResult == SQLITE_DONE) {
                break;
            }

            if (stepResult != SQLITE_ROW) {
                error = sqlite3_errmsg(database.handle);
                return false;
            }

            if (sqlite3_column_type(statement.handle, 0) != SQLITE_BLOB ||
                sqlite3_column_bytes(statement.handle, 0) !=
                    static_cast<int>(models::EntryIdSize)) {
                error = "Un identifiant d'entrée SQLite est invalide.";
                return false;
            }

            EntryId entryId{};

            std::copy_n(
                static_cast<const unsigned char*>(
                    sqlite3_column_blob(statement.handle, 0)),
                entryId.size(),
                entryId.begin());

            Credential credential;
            CredentialWiper credentialWiper(credential);

            if (!readEntry(
                    database.handle,
                    metadata,
                    dataKey,
                    entryId,
                    credential,
                    error)) {
                sodium_memzero(entryId.data(), entryId.size());
                return false;
            }

            CredentialSummary summary;
            summary.id = credential.id;
            summary.version = credential.version;
            summary.title = std::move(credential.title);
            summary.url = std::move(credential.url);
            summary.username = std::move(credential.username);

            sodium_memzero(entryId.data(), entryId.size());
            result.push_back(std::move(summary));
        }
    } catch (...) {
        error = "Mémoire insuffisante pour charger les résumés d'identifiants.";
        return false;
    }

    summaries = std::move(result);
    return true;
}

bool CredentialService::authenticateAll(
    const std::string& databasePath, const SecureBuffer& dataKey, std::string& error)
{
    return authenticateAll(databasePath, dataKey, error, nullptr, nullptr);
}
bool CredentialService::authenticateAll(
    const std::string& databasePath, const SecureBuffer& dataKey, std::string& error,
    bool (*cancelled)(void*) noexcept, void* context)
{
    error.clear();
    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }
    VaultKeyMetadata metadata{};
    if (!loadMetadata(databasePath, metadata, error)) return false;
    Database database;
    if (!openDatabase(databasePath, database, error)) return false;
    Statement statement;
    if (!prepare(database.handle, "SELECT entry_id FROM entries ORDER BY entry_id;", statement, error))
        return false;
    for (;;) {
        if (cancelled && cancelled(context)) {
            error = "Authentification interrompue.";
            return false;
        }
        const int code = sqlite3_step(statement.handle);
        if (code == SQLITE_DONE) return true;
        if (code != SQLITE_ROW)
            return sqlError(database.handle, code, "Parcours d'authentification", error);
        if (sqlite3_column_type(statement.handle, 0) != SQLITE_BLOB
            || sqlite3_column_bytes(statement.handle, 0) != static_cast<int>(models::EntryIdSize)
            || sqlite3_column_blob(statement.handle, 0) == nullptr) {
            error = "Un identifiant d'entrée SQLite est invalide.";
            return false;
        }
        Credential credential;
        CredentialWiper wiper(credential); // Armed before read/assign can throw.
        EntryId id{};
        std::copy_n(static_cast<const unsigned char*>(sqlite3_column_blob(statement.handle, 0)), id.size(), id.begin());
        if (!readEntry(database.handle, metadata, dataKey, id, credential, error)
            || !validate(credential, error)) return false;
        // The scope ends (and wipes all five strings) before the next SQL step.
    }
}

bool CredentialService::update(
    const std::string& databasePath,
    const SecureBuffer& dataKey,
    const Credential& credential,
    std::string& error)
{
    error.clear();

    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }

    if (!validate(credential, error)) {
        return false;
    }

    storage::VaultOperationGuard mutation;
    if (!prepareMutation(databasePath, mutation, error)) return false;

    services::VaultKeyMetadata metadata{};

    if (!loadMetadata(databasePath, metadata, error)) {
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    if (!beginTransaction(database.handle, "Modification", error)) {
        return false;
    }

    Credential existing;
    CredentialWiper existingWiper(existing);

    if (!readEntry(
            database.handle,
            metadata,
            dataKey,
            credential.id,
            existing,
            error)) {
        rollback(database.handle, "Modification", error);
        return false;
    }

    // L'ancienne entrée n'est nécessaire que pour vérifier son authenticité.
    // Son nettoyeur RAII reste actif, mais ses secrets ne doivent pas attendre
    // la fin du chiffrement ou de la transaction pour être effacés.
    wipeCredential(existing);

    EncryptedData encrypted;

    // Le sérialiseur et l'écriture SQL imposent déjà EntryFormatVersion ;
    // aucune copie modifiable des champs de l'appelant n'est nécessaire.
    if (!encryptCredential(
            metadata, dataKey, credential, encrypted, error)) {
        rollback(database.handle, "Modification", error);
        return false;
    }

    Statement statement;

    if (!prepare(
            database.handle,
            "UPDATE entries SET entry_version = ?, nonce = ?, "
            "ciphertext = ? WHERE entry_id = ?;",
            statement,
            error)) {
        rollback(database.handle, "Modification", error);
        return false;
    }

    int bindResult;
    const bool bound =
        (bindResult = sqlite3_bind_int64(
            statement.handle, 1, EntryFormatVersion)) == SQLITE_OK &&
        (bindResult = sqlite3_bind_blob(
            statement.handle,
            2,
            encrypted.nonce.data(),
            static_cast<int>(encrypted.nonce.size()),
            SQLITE_TRANSIENT)) == SQLITE_OK &&
        (bindResult = sqlite3_bind_blob(
            statement.handle,
            3,
            encrypted.ciphertext.data(),
            static_cast<int>(encrypted.ciphertext.size()),
            SQLITE_TRANSIENT)) == SQLITE_OK &&
        (bindResult = sqlite3_bind_blob(
            statement.handle,
            4,
            credential.id.data(),
            static_cast<int>(credential.id.size()),
            SQLITE_TRANSIENT)) == SQLITE_OK;

    if (!bound) {
        sqlError(database.handle, bindResult, "Liaison pour UPDATE", error);
        rollback(database.handle, "Modification", error);
        return false;
    }

    const int stepResult = sqlite3_step(statement.handle);
    if (stepResult != SQLITE_DONE) {
        sqlError(database.handle, stepResult, "UPDATE", error);
        rollback(database.handle, "Modification", error);
        return false;
    }
    if (sqlite3_changes(database.handle) != 1) {
        error = "UPDATE : nombre de lignes modifiées inattendu.";
        rollback(database.handle, "Modification", error);
        return false;
    }

    return commit(database.handle, "Modification", error);
}

bool CredentialService::remove(
    const std::string& databasePath,
    const SecureBuffer& dataKey,
    const EntryId& entryId,
    std::string& error)
{
    error.clear();

    if (!validKey(dataKey)) {
        error = "La clé du coffre est invalide ou le coffre est verrouillé.";
        return false;
    }

    storage::VaultOperationGuard mutation;
    if (!prepareMutation(databasePath, mutation, error)) return false;

    services::VaultKeyMetadata metadata{};

    if (!loadMetadata(databasePath, metadata, error)) {
        return false;
    }

    Database database;

    if (!openDatabase(databasePath, database, error)) {
        return false;
    }

    if (!beginTransaction(database.handle, "Suppression", error)) {
        return false;
    }

    // Vérifie l'existence et l'authenticité de l'entrée avant suppression.
    Credential existing;
    CredentialWiper existingWiper(existing);

    if (!readEntry(
            database.handle,
            metadata,
            dataKey,
            entryId,
            existing,
            error)) {
        rollback(database.handle, "Suppression", error);
        return false;
    }

    Statement statement;

    if (!prepare(
            database.handle,
            "DELETE FROM entries WHERE entry_id = ?;",
            statement,
            error)) {
        rollback(database.handle, "Suppression", error);
        return false;
    }

    if (!bindEntryId(
            statement.handle, 1, entryId, database.handle, error)) {
        rollback(database.handle, "Suppression", error);
        return false;
    }

    const int stepResult = sqlite3_step(statement.handle);
    if (stepResult != SQLITE_DONE) {
        sqlError(database.handle, stepResult, "DELETE", error);
        rollback(database.handle, "Suppression", error);
        return false;
    }
    if (sqlite3_changes(database.handle) != 1) {
        error = "DELETE : nombre de lignes supprimées inattendu.";
        rollback(database.handle, "Suppression", error);
        return false;
    }

    return commit(database.handle, "Suppression", error);
}

} // namespace passwall::services
