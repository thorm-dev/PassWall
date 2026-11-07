#include <sys/stat.h>
#include <gtest/gtest.h>
#include <sodium.h>
#include <sqlite3.h>

#include "core/crypto_engine.hpp"
#include "storage/vault_storage.hpp"
#include "services/vault_key_service.hpp"
#include "services/vault_lifecycle_service.hpp"

#include <chrono>
#include <array>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <utility>
#include <span>
#include <string>
#include <vector>

TEST(EnvironmentTest, SodiumInitializesSuccessfully)
{
    EXPECT_GE(sodium_init(), 0);
}

TEST(EnvironmentTest, SodiumProvidesVersion)
{
    ASSERT_GE(sodium_init(), 0);
    EXPECT_NE(sodium_version_string(), nullptr);
}

TEST(EnvironmentTest, SQLiteProvidesVersion)
{
    EXPECT_GT(sqlite3_libversion_number(), 0);
    EXPECT_NE(sqlite3_libversion(), nullptr);
}

TEST(CryptoTest, XChaCha20EncryptsAndDecrypts)
{
    ASSERT_GE(sodium_init(), 0);

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};

    randombytes_buf(key.data(), key.size());
    randombytes_buf(nonce.data(), nonce.size());

    const std::string message = "Test cryptographique PassWall";
    std::vector<unsigned char> ciphertext(message.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_size = 0;

    ASSERT_EQ(crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_size,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        nullptr, 0, nullptr, nonce.data(), key.data()), 0);

    ciphertext.resize(ciphertext_size);

    std::vector<unsigned char> plaintext(message.size());
    unsigned long long plaintext_size = 0;

    ASSERT_EQ(crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintext_size, nullptr,
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, nonce.data(), key.data()), 0);

    EXPECT_EQ(std::string(plaintext.begin(), plaintext.begin() + plaintext_size), message);

    sodium_memzero(key.data(), key.size());
    sodium_memzero(plaintext.data(), plaintext.size());
}

TEST(CryptoTest, XChaCha20RejectsModifiedCiphertext)
{
    ASSERT_GE(sodium_init(), 0);

    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{};
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};

    randombytes_buf(key.data(), key.size());
    randombytes_buf(nonce.data(), nonce.size());

    const std::string message = "Donnee a proteger";
    std::vector<unsigned char> ciphertext(message.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_size = 0;

    ASSERT_EQ(crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_size,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        nullptr, 0, nullptr, nonce.data(), key.data()), 0);

    ciphertext.resize(ciphertext_size);
    ciphertext[0] ^= 0x01;

    std::vector<unsigned char> plaintext(message.size());
    unsigned long long plaintext_size = 0;

    EXPECT_EQ(crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintext_size, nullptr,
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, nonce.data(), key.data()), -1);

    sodium_memzero(key.data(), key.size());
    sodium_memzero(plaintext.data(), plaintext.size());
}

TEST(CryptoEngineTest, InitializesSuccessfully)
{
    EXPECT_TRUE(passwall::core::CryptoEngine::initialize());
}

TEST(CryptoEngineTest, GeneratesNonzeroKey)
{
    passwall::core::Key key{};

    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    EXPECT_NE(std::all_of(key.begin(), key.end(), [](unsigned char byte) { return byte == 0; }), true);

    sodium_memzero(key.data(), key.size());
}

TEST(SecureBufferTest, AllocatesAndInitializesMemory)
{
    ASSERT_GE(sodium_init(), 0);

    passwall::core::SecureBuffer buffer(32);

    ASSERT_EQ(buffer.size(), 32U);
    ASSERT_NE(buffer.data(), nullptr);

    for (std::size_t i = 0; i < buffer.size(); ++i) {
        EXPECT_EQ(buffer.data()[i], 0);
    }
}

TEST(SecureBufferTest, SupportsMoveConstruction)
{
    ASSERT_GE(sodium_init(), 0);

    passwall::core::SecureBuffer original(32);
    original.data()[0] = 42;

    passwall::core::SecureBuffer moved(std::move(original));

    EXPECT_TRUE(original.empty());
    ASSERT_EQ(moved.size(), 32U);
    EXPECT_EQ(moved.data()[0], 42);
}

TEST(SecureBufferTest, SupportsMoveAssignment)
{
    ASSERT_GE(sodium_init(), 0);

    passwall::core::SecureBuffer original(32);
    original.data()[0] = 42;

    passwall::core::SecureBuffer destination(16);
    destination = std::move(original);

    EXPECT_TRUE(original.empty());
    ASSERT_EQ(destination.size(), 32U);
    EXPECT_EQ(destination.data()[0], 42);
}

TEST(Argon2idTest, SamePasswordAndSaltProduceSameKey)
{
    ASSERT_GE(sodium_init(), 0);

    const std::string password = "MotDePasseDeTest";
    const auto passwordBytes = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(password.data()), password.size());

    passwall::core::Salt salt{};
    randombytes_buf(salt.data(), salt.size());

    passwall::core::Key firstKey{};
    passwall::core::Key secondKey{};

    const auto firstResult = passwall::core::CryptoEngine::deriveKey(passwordBytes, salt, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, firstKey);
    const auto secondResult = passwall::core::CryptoEngine::deriveKey(passwordBytes, salt, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, secondKey);

    ASSERT_EQ(firstResult, passwall::core::CryptoError::None);
    ASSERT_EQ(secondResult, passwall::core::CryptoError::None);
    EXPECT_EQ(sodium_memcmp(firstKey.data(), secondKey.data(), firstKey.size()), 0);

    sodium_memzero(firstKey.data(), firstKey.size());
    sodium_memzero(secondKey.data(), secondKey.size());
}

TEST(Argon2idTest, DifferentSaltsProduceDifferentKeys)
{
    ASSERT_GE(sodium_init(), 0);

    const std::string password = "MotDePasseDeTest";
    const auto passwordBytes = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(password.data()), password.size());

    passwall::core::Salt firstSalt{};
    passwall::core::Salt secondSalt{};
    randombytes_buf(firstSalt.data(), firstSalt.size());
    randombytes_buf(secondSalt.data(), secondSalt.size());

    passwall::core::Key firstKey{};
    passwall::core::Key secondKey{};

    ASSERT_EQ(passwall::core::CryptoEngine::deriveKey(passwordBytes, firstSalt, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, firstKey), passwall::core::CryptoError::None);
    ASSERT_EQ(passwall::core::CryptoEngine::deriveKey(passwordBytes, secondSalt, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, secondKey), passwall::core::CryptoError::None);

    EXPECT_NE(sodium_memcmp(firstKey.data(), secondKey.data(), firstKey.size()), 0);

    sodium_memzero(firstKey.data(), firstKey.size());
    sodium_memzero(secondKey.data(), secondKey.size());
}

TEST(Argon2idTest, RejectsInvalidParametersAndClearsOutputKey)
{
    ASSERT_GE(sodium_init(), 0);

    const std::string password = "MotDePasseDeTest";
    const auto passwordBytes = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(password.data()), password.size());

    passwall::core::Salt salt{};
    passwall::core::Key key{};
    key.fill(42);

    const auto result = passwall::core::CryptoEngine::deriveKey(passwordBytes, salt, 0, crypto_pwhash_MEMLIMIT_MIN, key);

    EXPECT_EQ(result, passwall::core::CryptoError::InvalidInput);
    EXPECT_TRUE(std::all_of(key.begin(), key.end(), [](unsigned char byte) { return byte == 0; }));
}

TEST(CryptoEngineTest, EncryptsAndDecryptsWithAssociatedData)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    const std::string message = "Secret PassWall";
    const std::string context = "vault-id:entry-id:format-v1";
    const auto plaintext = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(message.data()), message.size());
    const auto associatedData = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(context.data()), context.size());

    passwall::core::EncryptedData encrypted;
    ASSERT_EQ(passwall::core::CryptoEngine::encrypt(plaintext, associatedData, key, encrypted), passwall::core::CryptoError::None);

    passwall::core::SecureBuffer decrypted(0);
    ASSERT_EQ(passwall::core::CryptoEngine::decrypt(encrypted, associatedData, key, decrypted), passwall::core::CryptoError::None);
    ASSERT_EQ(decrypted.size(), message.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(decrypted.data()), decrypted.size()), message);

    sodium_memzero(key.data(), key.size());
}

TEST(CryptoEngineTest, RejectsModifiedCiphertext)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    const std::string message = "Secret PassWall";
    const auto plaintext = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(message.data()), message.size());

    passwall::core::EncryptedData encrypted;
    ASSERT_EQ(passwall::core::CryptoEngine::encrypt(plaintext, {}, key, encrypted), passwall::core::CryptoError::None);

    encrypted.ciphertext[0] ^= 0x01;

    passwall::core::SecureBuffer decrypted(0);
    EXPECT_EQ(passwall::core::CryptoEngine::decrypt(encrypted, {}, key, decrypted), passwall::core::CryptoError::AuthenticationFailed);
    EXPECT_TRUE(decrypted.empty());

    sodium_memzero(key.data(), key.size());
}

TEST(CryptoEngineTest, RejectsWrongKey)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key encryptionKey{};
    passwall::core::Key wrongKey{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(encryptionKey));
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(wrongKey));

    const std::string message = "Secret PassWall";
    const auto plaintext = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(message.data()), message.size());

    passwall::core::EncryptedData encrypted;
    ASSERT_EQ(passwall::core::CryptoEngine::encrypt(plaintext, {}, encryptionKey, encrypted), passwall::core::CryptoError::None);

    passwall::core::SecureBuffer decrypted(0);
    EXPECT_EQ(passwall::core::CryptoEngine::decrypt(encrypted, {}, wrongKey, decrypted), passwall::core::CryptoError::AuthenticationFailed);
    EXPECT_TRUE(decrypted.empty());

    sodium_memzero(encryptionKey.data(), encryptionKey.size());
    sodium_memzero(wrongKey.data(), wrongKey.size());
}

TEST(CryptoEngineTest, RejectsModifiedAssociatedData)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    const std::string message = "Secret PassWall";
    const std::string originalContext = "vault-A:entry-1:v1";
    const std::string modifiedContext = "vault-B:entry-1:v1";
    const auto plaintext = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(message.data()), message.size());
    const auto originalData = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(originalContext.data()), originalContext.size());
    const auto modifiedData = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(modifiedContext.data()), modifiedContext.size());

    passwall::core::EncryptedData encrypted;
    ASSERT_EQ(passwall::core::CryptoEngine::encrypt(plaintext, originalData, key, encrypted), passwall::core::CryptoError::None);

    passwall::core::SecureBuffer decrypted(0);
    EXPECT_EQ(passwall::core::CryptoEngine::decrypt(encrypted, modifiedData, key, decrypted), passwall::core::CryptoError::AuthenticationFailed);
    EXPECT_TRUE(decrypted.empty());

    sodium_memzero(key.data(), key.size());
}

TEST(CryptoEngineTest, EncryptsAndDecryptsEmptyPlaintext)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    passwall::core::EncryptedData encrypted;
    EXPECT_EQ(passwall::core::CryptoEngine::encrypt({}, {}, key, encrypted), passwall::core::CryptoError::None);
    ASSERT_EQ(encrypted.ciphertext.size(), crypto_aead_xchacha20poly1305_ietf_ABYTES);

    passwall::core::SecureBuffer decrypted(0);
    EXPECT_EQ(passwall::core::CryptoEngine::decrypt(encrypted, {}, key, decrypted), passwall::core::CryptoError::None);
    EXPECT_TRUE(decrypted.empty());

    sodium_memzero(key.data(), key.size());
}

TEST(CryptoEngineTest, UsesDifferentNoncesForRepeatedEncryption)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    const std::string message = "Même message";
    const auto plaintext = std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(message.data()), message.size());

    passwall::core::EncryptedData first;
    passwall::core::EncryptedData second;

    ASSERT_EQ(passwall::core::CryptoEngine::encrypt(plaintext, {}, key, first), passwall::core::CryptoError::None);
    ASSERT_EQ(passwall::core::CryptoEngine::encrypt(plaintext, {}, key, second), passwall::core::CryptoError::None);

    EXPECT_NE(sodium_memcmp(first.nonce.data(), second.nonce.data(), first.nonce.size()), 0);

    sodium_memzero(key.data(), key.size());
}

TEST(CryptoEngineTest, RejectsCiphertextShorterThanAuthenticationTag)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    passwall::core::EncryptedData encrypted;
    encrypted.ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_ABYTES - 1);

    passwall::core::SecureBuffer decrypted(0);
    EXPECT_EQ(passwall::core::CryptoEngine::decrypt(encrypted, {}, key, decrypted), passwall::core::CryptoError::InvalidInput);
    EXPECT_TRUE(decrypted.empty());

    sodium_memzero(key.data(), key.size());
}

TEST(CryptoEngineTest, ReplacesPreviousEncryptedOutputOnSuccess)
{
    ASSERT_TRUE(passwall::core::CryptoEngine::initialize());

    passwall::core::Key key{};
    ASSERT_TRUE(passwall::core::CryptoEngine::generateKey(key));

    passwall::core::EncryptedData output;
    output.ciphertext = {1, 2, 3, 4};

    const auto result = passwall::core::CryptoEngine::encrypt({}, {}, key, output);

    EXPECT_EQ(result, passwall::core::CryptoError::None);
    EXPECT_EQ(output.ciphertext.size(), crypto_aead_xchacha20poly1305_ietf_ABYTES);

    sodium_memzero(key.data(), key.size());
}

TEST(VaultStorageTest, CreatesSchemaWithoutPlaintextCredentialColumns)
{
    ASSERT_GE(sodium_init(), 0);

    const auto databasePath = std::filesystem::temp_directory_path() / ("passwall-test-" + std::to_string(randombytes_random()) + ".db");
    const std::string path = databasePath.string();
    std::string error;

    ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(path, error)) << error;

    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.c_str(), &database, SQLITE_OPEN_READONLY, nullptr), SQLITE_OK);

    sqlite3_stmt* statement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(database, "PRAGMA table_info(entries);", -1, &statement, nullptr), SQLITE_OK);

    std::vector<std::string> columns;

    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto* columnName = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
        ASSERT_NE(columnName, nullptr);
        columns.emplace_back(columnName);
    }

    sqlite3_finalize(statement);
    sqlite3_close_v2(database);

    EXPECT_EQ(columns.size(), 4U);
    EXPECT_NE(std::find(columns.begin(), columns.end(), "entry_id"), columns.end());
    EXPECT_NE(std::find(columns.begin(), columns.end(), "entry_version"), columns.end());
    EXPECT_NE(std::find(columns.begin(), columns.end(), "nonce"), columns.end());
    EXPECT_NE(std::find(columns.begin(), columns.end(), "ciphertext"), columns.end());

    EXPECT_EQ(std::find(columns.begin(), columns.end(), "username"), columns.end());
    EXPECT_EQ(std::find(columns.begin(), columns.end(), "password"), columns.end());
    EXPECT_EQ(std::find(columns.begin(), columns.end(), "website"), columns.end());
    EXPECT_EQ(std::find(columns.begin(), columns.end(), "notes"), columns.end());

    std::error_code removeError;
    std::filesystem::remove(databasePath, removeError);
}

TEST(VaultStorageTest, RefusesToOverwriteExistingFile)
{
    const auto databasePath = std::filesystem::temp_directory_path() / ("passwall-existing-" + std::to_string(randombytes_random()) + ".db");

    {
        std::ofstream file(databasePath);
        ASSERT_TRUE(file.is_open());
        file << "Fichier existant à préserver";
    }

    std::string error;
    EXPECT_FALSE(passwall::storage::VaultStorage::createSchema(databasePath.string(), error));
    EXPECT_FALSE(error.empty());

    std::ifstream file(databasePath);
    ASSERT_TRUE(file.is_open());

    std::string content;
    std::getline(file, content);
    EXPECT_EQ(content, "Fichier existant à préserver");

    file.close();

    std::error_code removeError;
    std::filesystem::remove(databasePath, removeError);
}

TEST(VaultStorageTest, CreatesDatabaseWithRestrictivePermissions)
{
    const auto databasePath = std::filesystem::temp_directory_path() / ("passwall-permissions-" + std::to_string(randombytes_random()) + ".db");

    std::string error;
    ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(databasePath.string(), error)) << error;

    struct stat fileStatus {};
    ASSERT_EQ(::stat(databasePath.c_str(), &fileStatus), 0);

    EXPECT_EQ(fileStatus.st_mode & 0777, 0600);

    std::error_code removeError;
    std::filesystem::remove(databasePath, removeError);
}


namespace {

std::span<const unsigned char> asPasswordBytes(const std::string& password)
{
    return {
        reinterpret_cast<const unsigned char*>(password.data()),
        password.size()
    };
}

} // namespace

TEST(VaultKeyServiceTest, CreatesVaultAndUnlocksWithCorrectPassword)
{
    const std::string password = "Mot-de-passe-de-test-42";

    passwall::services::VaultKeyMetadata metadata;
    passwall::core::SecureBuffer originalKey(0);

    const auto createResult = passwall::services::VaultKeyService::create(
        asPasswordBytes(password),
        metadata,
        originalKey);

    ASSERT_EQ(createResult, passwall::core::CryptoError::None);
    ASSERT_EQ(originalKey.size(), passwall::core::KeySize);
    ASSERT_EQ(metadata.operationsLimit, 3);
    ASSERT_EQ(metadata.memoryLimit, 256ULL * 1024 * 1024);

    passwall::core::SecureBuffer unlockedKey(0);

    const auto unlockResult = passwall::services::VaultKeyService::unlock(
        asPasswordBytes(password),
        metadata,
        unlockedKey);

    ASSERT_EQ(unlockResult, passwall::core::CryptoError::None);
    ASSERT_EQ(unlockedKey.size(), originalKey.size());

    EXPECT_EQ(
        sodium_memcmp(originalKey.data(), unlockedKey.data(), originalKey.size()),
        0);
}

TEST(VaultKeyServiceTest, RejectsIncorrectPassword)
{
    const std::string password = "Mot-de-passe-de-test-42";
    const std::string wrongPassword = "Mauvais-mot-de-passe";

    passwall::services::VaultKeyMetadata metadata;
    passwall::core::SecureBuffer originalKey(0);

    ASSERT_EQ(
        passwall::services::VaultKeyService::create(
            asPasswordBytes(password),
            metadata,
            originalKey),
        passwall::core::CryptoError::None);

    passwall::core::SecureBuffer unlockedKey(0);

    EXPECT_EQ(
        passwall::services::VaultKeyService::unlock(
            asPasswordBytes(wrongPassword),
            metadata,
            unlockedKey),
        passwall::core::CryptoError::AuthenticationFailed);

    EXPECT_EQ(unlockedKey.size(), 0);
}

TEST(VaultKeyServiceTest, RejectsUnsupportedArgon2Parameters)
{
    const std::string password = "Mot-de-passe-de-test-42";

    passwall::services::VaultKeyMetadata metadata;
    passwall::core::SecureBuffer originalKey(0);

    ASSERT_EQ(
        passwall::services::VaultKeyService::create(
            asPasswordBytes(password),
            metadata,
            originalKey),
        passwall::core::CryptoError::None);

    metadata.memoryLimit = 1024ULL * 1024 * 1024;

    passwall::core::SecureBuffer unlockedKey(0);

    EXPECT_EQ(
        passwall::services::VaultKeyService::unlock(
            asPasswordBytes(password),
            metadata,
            unlockedKey),
        passwall::core::CryptoError::InvalidInput);

    EXPECT_EQ(unlockedKey.size(), 0);
}


TEST(VaultStorageTest, PersistsMetadataAndUnlocksAfterReopening)
{
    const std::string password = "Mot-de-passe-de-test-42";

    const auto uniqueValue =
        std::chrono::steady_clock::now().time_since_epoch().count();

    const auto databasePath =
        std::filesystem::temp_directory_path() /
        ("passwall_metadata_test_" + std::to_string(uniqueValue) + ".db");

    const std::string path = databasePath.string();
    std::string error;

    passwall::services::VaultKeyMetadata originalMetadata;
    passwall::core::SecureBuffer originalKey(0);

    ASSERT_EQ(
        passwall::services::VaultKeyService::create(
            asPasswordBytes(password),
            originalMetadata,
            originalKey),
        passwall::core::CryptoError::None);

    ASSERT_TRUE(
        passwall::storage::VaultStorage::createSchema(path, error))
        << error;

    ASSERT_TRUE(
        passwall::storage::VaultStorage::writeMetadata(
            path, originalMetadata, error))
        << error;

    // La lecture rouvre le fichier SQLite après son écriture.
    passwall::services::VaultKeyMetadata loadedMetadata;

    ASSERT_TRUE(
        passwall::storage::VaultStorage::readMetadata(
            path, loadedMetadata, error))
        << error;

    EXPECT_EQ(loadedMetadata.vaultId, originalMetadata.vaultId);
    EXPECT_EQ(loadedMetadata.salt, originalMetadata.salt);
    EXPECT_EQ(loadedMetadata.operationsLimit, originalMetadata.operationsLimit);
    EXPECT_EQ(loadedMetadata.memoryLimit, originalMetadata.memoryLimit);
    EXPECT_EQ(loadedMetadata.wrapNonce, originalMetadata.wrapNonce);
    EXPECT_EQ(loadedMetadata.wrappedDek, originalMetadata.wrappedDek);
    EXPECT_EQ(loadedMetadata.formatVersion, originalMetadata.formatVersion);

    // Le mot de passe permet de retrouver la DEK après relecture.
    passwall::core::SecureBuffer reopenedKey(0);

    EXPECT_EQ(
        passwall::services::VaultKeyService::unlock(
            asPasswordBytes(password),
            loadedMetadata,
            reopenedKey),
        passwall::core::CryptoError::None);

    ASSERT_EQ(reopenedKey.size(), originalKey.size());

    EXPECT_EQ(
        sodium_memcmp(
            reopenedKey.data(),
            originalKey.data(),
            originalKey.size()),
        0);

    std::error_code removeError;
    std::filesystem::remove(databasePath, removeError);
}


TEST(VaultLifecycleServiceTest, CreatesUnlocksAndRefusesOverwrite)
{
    const std::string password = "Mot-de-passe-de-test-42";

    const auto uniqueValue =
        std::chrono::steady_clock::now().time_since_epoch().count();

    const auto databasePath =
        std::filesystem::temp_directory_path() /
        ("passwall_lifecycle_test_" +
         std::to_string(uniqueValue) + ".db");

    const std::string path = databasePath.string();
    std::string error;

    passwall::core::SecureBuffer originalKey(0);

    ASSERT_TRUE(
        passwall::services::VaultLifecycleService::createVault(
            path, password, originalKey, error))
        << error;

    ASSERT_EQ(originalKey.size(), passwall::core::KeySize);
    ASSERT_TRUE(std::filesystem::exists(databasePath));

    // Le coffre doit rester intact après une tentative d'écrasement.
    passwall::core::SecureBuffer rejectedKey(0);

    EXPECT_FALSE(
        passwall::services::VaultLifecycleService::createVault(
            path, "Autre-mot-de-passe", rejectedKey, error));

    EXPECT_EQ(rejectedKey.size(), 0);

    // On rouvre le coffre original depuis son fichier SQLite.
    passwall::core::SecureBuffer reopenedKey(0);

    ASSERT_TRUE(
        passwall::services::VaultLifecycleService::unlockVault(
            path, password, reopenedKey, error))
        << error;

    ASSERT_EQ(reopenedKey.size(), originalKey.size());

    EXPECT_EQ(
        sodium_memcmp(
            originalKey.data(),
            reopenedKey.data(),
            originalKey.size()),
        0);

    std::error_code ignored;
    std::filesystem::remove(databasePath, ignored);
}


TEST(VaultLifecycleServiceTest, RejectsIncorrectPassword)
{
    const std::string password = "Mot-de-passe-de-test-42";
    const std::string wrongPassword = "Mauvais-mot-de-passe";

    const auto uniqueValue =
        std::chrono::steady_clock::now().time_since_epoch().count();

    const auto databasePath =
        std::filesystem::temp_directory_path() /
        ("passwall_wrong_password_" +
         std::to_string(uniqueValue) + ".db");

    const std::string path = databasePath.string();
    std::string error;

    passwall::core::SecureBuffer originalKey(0);

    ASSERT_TRUE(
        passwall::services::VaultLifecycleService::createVault(
            path, password, originalKey, error))
        << error;

    passwall::core::SecureBuffer rejectedKey(0);

    EXPECT_FALSE(
        passwall::services::VaultLifecycleService::unlockVault(
            path, wrongPassword, rejectedKey, error));

    EXPECT_FALSE(error.empty());
    EXPECT_EQ(rejectedKey.size(), 0);

    std::error_code ignored;
    std::filesystem::remove(databasePath, ignored);
}


TEST(VaultLifecycleServiceTest, RejectsTamperedArgon2Parameters)
{
    const std::string password = "Mot-de-passe-de-test-42";

    const auto uniqueValue =
        std::chrono::steady_clock::now().time_since_epoch().count();

    const auto databasePath =
        std::filesystem::temp_directory_path() /
        ("passwall_tampered_metadata_" +
         std::to_string(uniqueValue) + ".db");

    const std::string path = databasePath.string();
    std::string error;

    passwall::core::SecureBuffer originalKey(0);

    ASSERT_TRUE(
        passwall::services::VaultLifecycleService::createVault(
            path, password, originalKey, error))
        << error;

    sqlite3* database = nullptr;

    ASSERT_EQ(
        sqlite3_open(path.c_str(), &database),
        SQLITE_OK);

    const int updateResult = sqlite3_exec(
        database,
        "UPDATE vault_metadata "
        "SET argon2_memory = 1073741824 WHERE id = 1;",
        nullptr,
        nullptr,
        nullptr);

    EXPECT_EQ(updateResult, SQLITE_OK);
    EXPECT_EQ(sqlite3_close(database), SQLITE_OK);

    passwall::core::SecureBuffer rejectedKey(0);

    EXPECT_FALSE(
        passwall::services::VaultLifecycleService::unlockVault(
            path, password, rejectedKey, error));

    EXPECT_FALSE(error.empty());
    EXPECT_EQ(rejectedKey.size(), 0);

    std::error_code ignored;
    std::filesystem::remove(databasePath, ignored);
}


TEST(VaultLifecycleServiceTest, PreservesExistingFileAndCleansTemporaryFile)
{
    const auto uniqueValue =
        std::chrono::steady_clock::now().time_since_epoch().count();

    const auto databasePath =
        std::filesystem::temp_directory_path() /
        ("passwall_existing_file_" +
         std::to_string(uniqueValue) + ".db");

    const std::string path = databasePath.string();
    const std::string originalContent = "Fichier existant a conserver";

    {
        std::ofstream file(path, std::ios::binary);
        ASSERT_TRUE(file.is_open());
        file << originalContent;
        ASSERT_TRUE(file.good());
    }

    std::string error;
    passwall::core::SecureBuffer dataKey(0);

    EXPECT_FALSE(
        passwall::services::VaultLifecycleService::createVault(
            path, "Mot-de-passe-de-test-42", dataKey, error));

    EXPECT_FALSE(error.empty());
    EXPECT_EQ(dataKey.size(), 0);

    {
        std::ifstream file(path, std::ios::binary);
        ASSERT_TRUE(file.is_open());

        const std::string actualContent(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

        EXPECT_EQ(actualContent, originalContent);
    }

    const std::string temporaryPrefix =
        "." + databasePath.filename().string() + ".tmp-";

    for (const auto& entry :
         std::filesystem::directory_iterator(databasePath.parent_path())) {
        EXPECT_FALSE(
            entry.path().filename().string().starts_with(temporaryPrefix))
            << "Fichier temporaire restant : " << entry.path().string();
    }

    std::error_code ignored;
    std::filesystem::remove(databasePath, ignored);
}
