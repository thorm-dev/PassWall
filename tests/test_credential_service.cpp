#include "models/credential.hpp"
#include "services/credential_service.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>
#include <sodium.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <QString>

namespace {

namespace fs = std::filesystem;

template <typename T>
concept HasPasswordMember = requires(T value) {
    value.password;
};

template <typename T>
concept HasNotesMember = requires(T value) {
    value.notes;
};

static_assert(!HasPasswordMember<passwall::models::CredentialSummary>);
static_assert(!HasNotesMember<passwall::models::CredentialSummary>);

class CredentialServiceTest : public ::testing::Test {
protected:
    fs::path databasePath;
    passwall::services::VaultKeyMetadata metadata;
    std::unique_ptr<passwall::core::SecureBuffer> dataKey;

    void SetUp() override {
        const auto timestamp =
            std::chrono::steady_clock::now().time_since_epoch().count();

        databasePath =
            fs::temp_directory_path() /
            ("passwall_credential_test_" +
             std::to_string(timestamp) + ".db");

        std::string error;

        ASSERT_TRUE(
            passwall::storage::VaultStorage::createSchema(
                databasePath.string(), error))
            << error;

        dataKey = std::make_unique<passwall::core::SecureBuffer>(0);

        const std::string masterPassword = "test-master-password";

        const auto result = passwall::services::VaultKeyService::create(
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(
                    masterPassword.data()),
                masterPassword.size()),
            metadata,
            *dataKey);

        ASSERT_EQ(static_cast<int>(result), 0)
            << "La création de la clé du coffre a échoué.";

        ASSERT_TRUE(
            passwall::storage::VaultStorage::writeMetadata(
                databasePath.string(), metadata, error))
            << error;
    }

    void TearDown() override {
        dataKey.reset();

        std::error_code error;
        fs::remove(databasePath, error);
        fs::remove(databasePath.string() + "-journal", error);
        fs::remove(databasePath.string() + "-wal", error);
        fs::remove(databasePath.string() + "-shm", error);
    }

    std::string persistentBytes() const {
        std::ifstream file(databasePath, std::ios::binary);
        EXPECT_TRUE(file.is_open());
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }
};

passwall::models::Credential validationCredential()
{
    passwall::models::Credential credential;
    credential.id.fill(0x71);
    credential.version = 97;
    credential.title = "Titre fictif";
    credential.username = "utilisateur-fictif";
    credential.password = "fictitious-validation-password";
    return credential;
}

bool sameCredential(const passwall::models::Credential& first,
                    const passwall::models::Credential& second)
{
    return first.id == second.id && first.version == second.version
        && first.title == second.title && first.username == second.username
        && first.password == second.password && first.url == second.url
        && first.notes == second.notes;
}

struct InvalidRequiredField {
    std::string passwall::models::Credential::* member;
    std::string value;
};

std::array<InvalidRequiredField, 7> invalidRequiredFields()
{
    using passwall::models::Credential;
    return {{{&Credential::title, ""}, {&Credential::username, ""},
             {&Credential::password, ""}, {&Credential::title, " \t\r\n "},
             {&Credential::username, " \t\r\n "},
             {&Credential::title, "\xC2\xA0\xE3\x80\x80"},
             {&Credential::username, "\xE2\x80\xAF\xE2\x80\xA8"}}};
}

TEST(CredentialValidationTest, RejectsEveryUnicodeWhitespaceWithoutMutatingFields)
{
    const std::array<const char*, 26> whitespace = {
        " ", "\t", "\n", "\v", "\f", "\r", "\xC2\x85", "\xC2\xA0",
        "\xE1\x9A\x80", "\xE2\x80\x80", "\xE2\x80\x81", "\xE2\x80\x82",
        "\xE2\x80\x83", "\xE2\x80\x84", "\xE2\x80\x85", "\xE2\x80\x86",
        "\xE2\x80\x87", "\xE2\x80\x88", "\xE2\x80\x89", "\xE2\x80\x8A",
        "\xE2\x80\xA8", "\xE2\x80\xA9", "\xE2\x80\xAF", "\xE2\x81\x9F",
        "\xE3\x80\x80", " \t\xC2\xA0\xE3\x80\x80"
    };
    std::size_t qtWhitespaceCount = 0;
    for (char32_t codepoint = 0; codepoint <= 0xffff; ++codepoint)
        if (QChar::isSpace(codepoint))
            ++qtWhitespaceCount;
    EXPECT_EQ(qtWhitespaceCount, whitespace.size() - 1);
    for (const auto* space : whitespace) {
        // Référence Qt indépendante pour la classification des blancs.
        EXPECT_TRUE(QString::fromUtf8(space).trimmed().isEmpty());
        for (const auto member : {&passwall::models::Credential::title,
                                  &passwall::models::Credential::username}) {
            auto credential = validationCredential();
            credential.*member = space;
            const auto before = credential;
            std::string error;
            EXPECT_FALSE(passwall::services::CredentialService::validate(credential, error));
            EXPECT_FALSE(error.empty());
            EXPECT_TRUE(error.find(credential.password) == std::string::npos);
            EXPECT_TRUE(sameCredential(credential, before));
        }
    }
}

TEST_F(CredentialServiceTest, RequiredFieldsRejectAdditionWithoutWritingAndAllowRetry)
{
    using passwall::services::CredentialService;
    const auto before = persistentBytes();
    for (const auto& invalid : invalidRequiredFields()) {
        auto credential = validationCredential();
        credential.*(invalid.member) = invalid.value;
        const auto sourceBefore = credential;
        std::string validationError;
        EXPECT_FALSE(CredentialService::validate(credential, validationError));
        std::string error;
        EXPECT_FALSE(CredentialService::add(databasePath.string(), *dataKey, credential, error));
        EXPECT_FALSE(error.empty());
        EXPECT_TRUE(error == validationError);
        EXPECT_TRUE(sameCredential(credential, sourceBefore));
        EXPECT_TRUE(persistentBytes() == before);
    }
    auto valid = validationCredential();
    std::string error;
    ASSERT_TRUE(CredentialService::add(databasePath.string(), *dataKey, valid, error));
    EXPECT_TRUE(error.empty());
}

TEST_F(CredentialServiceTest, RequiredFieldsRejectUpdateWithoutWritingAndAllowRetry)
{
    using passwall::services::CredentialService;
    auto original = validationCredential();
    std::string error;
    ASSERT_TRUE(CredentialService::add(databasePath.string(), *dataKey, original, error));
    const auto before = persistentBytes();
    for (const auto& invalid : invalidRequiredFields()) {
        auto credential = original;
        credential.*(invalid.member) = invalid.value;
        const auto sourceBefore = credential;
        std::string validationError;
        EXPECT_FALSE(CredentialService::validate(credential, validationError));
        EXPECT_FALSE(CredentialService::update(databasePath.string(), *dataKey, credential, error));
        EXPECT_FALSE(error.empty());
        EXPECT_TRUE(error == validationError);
        EXPECT_TRUE(sameCredential(credential, sourceBefore));
        EXPECT_TRUE(persistentBytes() == before);
    }
    original.title = "Titre fictif modifié";
    const auto sourceBefore = original;
    ASSERT_TRUE(CredentialService::update(databasePath.string(), *dataKey, original, error));
    EXPECT_TRUE(error.empty());
    EXPECT_TRUE(sameCredential(original, sourceBefore));
}

TEST_F(CredentialServiceTest, RequiredFieldsPreserveExactPasswordsAndOptionalFields)
{
    using passwall::services::CredentialService;
    const std::array<std::string, 4> passwords = {
        " ", " \t\n ", "  fictitious-exact-password  ", "\xC2\xA0"
    };
    for (const auto& password : passwords) {
        auto credential = validationCredential();
        credential.title = "  Titre fictif  ";
        credential.username = "\xC2\xA0utilisateur-fictif\xC2\xA0";
        credential.password = password;
        const auto sourceBefore = credential;
        std::string error;
        ASSERT_TRUE(CredentialService::add(databasePath.string(), *dataKey, credential, error));
        EXPECT_TRUE(credential.title == sourceBefore.title);
        EXPECT_TRUE(credential.username == sourceBefore.username);
        EXPECT_TRUE(credential.password == password);
        passwall::models::Credential loaded;
        ASSERT_TRUE(CredentialService::get(databasePath.string(), *dataKey, credential.id, loaded, error));
        EXPECT_TRUE(sameCredential(loaded, credential));
        credential.password = password + " ";
        const auto beforeUpdate = credential;
        ASSERT_TRUE(CredentialService::update(databasePath.string(), *dataKey, credential, error));
        EXPECT_TRUE(sameCredential(credential, beforeUpdate));
        ASSERT_TRUE(CredentialService::get(databasePath.string(), *dataKey, credential.id, loaded, error));
        EXPECT_TRUE(sameCredential(loaded, credential));
        EXPECT_TRUE(loaded.url.empty());
        EXPECT_TRUE(loaded.notes.empty());
    }
}

TEST_F(CredentialServiceTest, RequiredFieldsKeepAllExistingFieldSizeLimits)
{
    using passwall::models::Credential;
    using passwall::services::CredentialService;
    auto original = validationCredential();
    std::string error;
    ASSERT_TRUE(CredentialService::add(databasePath.string(), *dataKey, original, error));
    const auto before = persistentBytes();
    for (const auto member : {&Credential::title, &Credential::url, &Credential::username,
                              &Credential::password, &Credential::notes}) {
        auto credential = original;
        (credential.*member).assign(1024 * 1024 + 1, 'x');
        const auto sourceBefore = credential;
        EXPECT_FALSE(CredentialService::add(databasePath.string(), *dataKey, credential, error));
        EXPECT_TRUE(error == "Un champ dépasse la taille maximale autorisée.");
        EXPECT_FALSE(CredentialService::update(databasePath.string(), *dataKey, credential, error));
        EXPECT_TRUE(error == "Un champ dépasse la taille maximale autorisée.");
        EXPECT_TRUE(sameCredential(credential, sourceBefore));
        EXPECT_TRUE(persistentBytes() == before);
    }
    original.notes.assign(1024 * 1024, 'x');
    ASSERT_TRUE(CredentialService::update(databasePath.string(), *dataKey, original, error));
}

TEST_F(CredentialServiceTest, CompleteCredentialLifecycle) {
    using passwall::models::Credential;
    using passwall::services::CredentialService;

    std::string error;

    // 1. Ajouter un identifiant.
    Credential original;
    original.title = "Compte de test";
    original.url = "https://example.test";
    original.username = "utilisateur-test";
    original.password = "secret-test-93x";
    original.notes = "Note confidentielle";

    ASSERT_TRUE(
        CredentialService::add(
            databasePath.string(), *dataKey, original, error))
        << error;

    EXPECT_NE(
        original.id,
        passwall::models::EntryId{});

    // 2. Lire l'identifiant ajouté.
    Credential loaded;

    ASSERT_TRUE(
        CredentialService::get(
            databasePath.string(),
            *dataKey,
            original.id,
            loaded,
            error))
        << error;

    EXPECT_EQ(loaded.id, original.id);
    EXPECT_EQ(loaded.title, original.title);
    EXPECT_EQ(loaded.url, original.url);
    EXPECT_EQ(loaded.username, original.username);
    EXPECT_EQ(loaded.password, original.password);
    EXPECT_EQ(loaded.notes, original.notes);

    // 3. Vérifier la liste des identifiants.
    std::vector<Credential> credentials;

    ASSERT_TRUE(
        CredentialService::list(
            databasePath.string(), *dataKey, credentials, error))
        << error;

    ASSERT_EQ(credentials.size(), 1U);
    EXPECT_EQ(credentials.front().id, original.id);

    // 4. Une mauvaise clé ne doit pas déchiffrer l'identifiant.
    passwall::core::SecureBuffer wrongKey(32);
    sodium_memzero(wrongKey.data(), wrongKey.size());
    wrongKey.data()[0] = 0xA5;

    Credential rejected;
    std::string wrongKeyError;

    EXPECT_FALSE(
        CredentialService::get(
            databasePath.string(),
            wrongKey,
            original.id,
            rejected,
            wrongKeyError));

    // 5. Modifier l'identifiant.
    Credential updated = loaded;
    updated.title = "Compte modifié";
    updated.password = "nouveau-secret-74z";
    updated.notes = "Note mise à jour";

    ASSERT_TRUE(
        CredentialService::update(
            databasePath.string(), *dataKey, updated, error))
        << error;

    Credential reloaded;

    ASSERT_TRUE(
        CredentialService::get(
            databasePath.string(),
            *dataKey,
            original.id,
            reloaded,
            error))
        << error;

    EXPECT_EQ(reloaded.title, updated.title);
    EXPECT_EQ(reloaded.password, updated.password);
    EXPECT_EQ(reloaded.notes, updated.notes);

    // 6. Vérifier que les secrets ne sont pas stockés en clair.
    std::ifstream file(databasePath, std::ios::binary);

    ASSERT_TRUE(file.is_open());

const std::string databaseContents{
    std::istreambuf_iterator<char>(file),
    std::istreambuf_iterator<char>()
};

    EXPECT_EQ(
        databaseContents.find("nouveau-secret-74z"),
        std::string::npos);

    EXPECT_EQ(
        databaseContents.find("utilisateur-test"),
        std::string::npos);

    // 7. Supprimer l'identifiant.
    ASSERT_TRUE(
        CredentialService::remove(
            databasePath.string(),
            *dataKey,
            original.id,
            error))
        << error;

    credentials.clear();

    ASSERT_TRUE(
        CredentialService::list(
            databasePath.string(), *dataKey, credentials, error))
        << error;

    EXPECT_TRUE(credentials.empty());

    Credential deleted;
    std::string deletedError;

    EXPECT_FALSE(
        CredentialService::get(
            databasePath.string(),
            *dataKey,
            original.id,
            deleted,
            deletedError));
}


TEST_F(CredentialServiceTest, GetClearsPreviousOutputWhenUnlockKeyIsInvalid) {
    using namespace passwall;

    std::string error;
    models::Credential stored;
    stored.title = "Compte de test";
    stored.url = "https://example.test";
    stored.username = "test-user";
    stored.password = "stored-secret";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, stored, error)) << error;

    models::Credential output;
    output.title = "Ancien titre";
    output.url = "https://old.example";
    output.username = "old-user";
    output.password = "old-secret";
    output.notes = "Anciennes notes";

    core::SecureBuffer wrongKey(32);
    sodium_memzero(wrongKey.data(), wrongKey.size());
    wrongKey.data()[0] = 0xA5;

    std::string getError;
    EXPECT_FALSE(services::CredentialService::get(
        databasePath.string(), wrongKey, stored.id, output, getError));

    EXPECT_TRUE(output.title.empty());
    EXPECT_TRUE(output.url.empty());
    EXPECT_TRUE(output.username.empty());
    EXPECT_TRUE(output.password.empty());
    EXPECT_TRUE(output.notes.empty());
    EXPECT_EQ(output.id, models::EntryId{});
}

TEST_F(CredentialServiceTest, ListClearsPreviousResultsWhenUnlockKeyIsInvalid) {
    using namespace passwall;

    // Il faut au moins une entrée pour que list() tente un déchiffrement.
    std::string error;
    models::Credential stored;
    stored.title = "Compte de test";
    stored.url = "https://list-wrong-key.example";
    stored.username = "test-user";
    stored.password = "stored-secret";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, stored, error)) << error;

    std::vector<models::Credential> output(1);
    output.front().title = "Ancien titre";
    output.front().username = "old-user";
    output.front().password = "old-secret";
    output.front().notes = "Anciennes notes";

    core::SecureBuffer wrongKey(32);
    sodium_memzero(wrongKey.data(), wrongKey.size());
    wrongKey.data()[0] = 0xA5;

    std::string listError;
    EXPECT_FALSE(services::CredentialService::list(
        databasePath.string(), wrongKey, output, listError));
    EXPECT_TRUE(output.empty());
}

TEST_F(CredentialServiceTest, ListsSummariesWithoutSecrets) {
    using namespace passwall;

    std::string error;
    models::Credential first;
    first.title = "Premier compte";
    first.url = "https://first.example";
    first.username = "first-user";
    first.password = "first-secret";
    first.notes = "Premières notes";

    models::Credential second;
    second.title = "Second compte";
    second.url = "https://second.example";
    second.username = "second-user";
    second.password = "second-secret";
    second.notes = "Secondes notes";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, first, error)) << error;
    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, second, error)) << error;

    std::vector<models::CredentialSummary> summaries;
    ASSERT_TRUE(services::CredentialService::listSummaries(
        databasePath.string(), *dataKey, summaries, error)) << error;

    ASSERT_EQ(summaries.size(), 2U);

    const auto findSummary = [&summaries](const models::EntryId& id)
        -> const models::CredentialSummary* {
        for (const auto& summary : summaries) {
            if (summary.id == id) {
                return &summary;
            }
        }
        return nullptr;
    };

    const auto* firstSummary = findSummary(first.id);
    ASSERT_NE(firstSummary, nullptr);
    EXPECT_EQ(firstSummary->version, first.version);
    EXPECT_EQ(firstSummary->title, first.title);
    EXPECT_EQ(firstSummary->url, first.url);
    EXPECT_EQ(firstSummary->username, first.username);

    const auto* secondSummary = findSummary(second.id);
    ASSERT_NE(secondSummary, nullptr);
    EXPECT_EQ(secondSummary->version, second.version);
    EXPECT_EQ(secondSummary->title, second.title);
    EXPECT_EQ(secondSummary->url, second.url);
    EXPECT_EQ(secondSummary->username, second.username);
}

TEST_F(CredentialServiceTest, ListSummariesClearsPreviousResultsWhenUnlockKeyIsInvalid) {
    using namespace passwall;

    std::string error;
    models::Credential stored;
    stored.title = "Compte de test";
    stored.url = "https://summary-wrong-key.example";
    stored.username = "test-user";
    stored.password = "stored-secret";
    stored.notes = "Notes confidentielles";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, stored, error)) << error;

    std::vector<models::CredentialSummary> output(1);
    output.front().title = "Ancien titre";
    output.front().url = "https://old.example";
    output.front().username = "old-user";

    core::SecureBuffer wrongKey(32);
    sodium_memzero(wrongKey.data(), wrongKey.size());
    wrongKey.data()[0] = 0xA5;

    std::string listError;
    EXPECT_FALSE(services::CredentialService::listSummaries(
        databasePath.string(), wrongKey, output, listError));
    EXPECT_TRUE(output.empty());
    EXPECT_FALSE(listError.empty());
}

TEST_F(CredentialServiceTest,
       ListSummariesRejectsTamperedEntryWithoutReturningPartialResults) {
    using namespace passwall;

    std::string error;
    models::Credential first;
    first.title = "Premier compte";
    first.url = "https://first-tamper.example";
    first.username = "first-user";
    first.password = "first-secret";

    models::Credential second;
    second.title = "Second compte";
    second.url = "https://second-tamper.example";
    second.username = "second-user";
    second.password = "second-secret";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, first, error)) << error;
    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, second, error)) << error;

    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open(databasePath.c_str(), &database), SQLITE_OK);
    ASSERT_NE(database, nullptr);

    sqlite3_stmt* orderedEntriesStatement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(
        database,
        "SELECT entry_id FROM entries ORDER BY entry_id;",
        -1,
        &orderedEntriesStatement,
        nullptr), SQLITE_OK);

    std::vector<models::EntryId> orderedEntryIds;

    while (true) {
        const int stepResult = sqlite3_step(orderedEntriesStatement);

        if (stepResult == SQLITE_DONE) {
            break;
        }

        ASSERT_EQ(stepResult, SQLITE_ROW);
        ASSERT_EQ(sqlite3_column_type(orderedEntriesStatement, 0), SQLITE_BLOB);
        ASSERT_EQ(
            sqlite3_column_bytes(orderedEntriesStatement, 0),
            static_cast<int>(models::EntryIdSize));

        const auto* entryId = static_cast<const unsigned char*>(
            sqlite3_column_blob(orderedEntriesStatement, 0));
        ASSERT_NE(entryId, nullptr);

        models::EntryId orderedEntryId{};
        std::copy_n(entryId, orderedEntryId.size(), orderedEntryId.begin());
        orderedEntryIds.push_back(orderedEntryId);
    }

    sqlite3_finalize(orderedEntriesStatement);

    ASSERT_EQ(orderedEntryIds.size(), 2U);

    sqlite3_stmt* updateStatement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(
        database,
        "UPDATE entries SET ciphertext = "
        "substr(ciphertext, 1, length(ciphertext) - 1) "
        "WHERE entry_id = ?1",
        -1,
        &updateStatement,
        nullptr), SQLITE_OK);

    ASSERT_EQ(sqlite3_bind_blob(
        updateStatement, 1, orderedEntryIds[1].data(),
        static_cast<int>(orderedEntryIds[1].size()), SQLITE_TRANSIENT), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(updateStatement), SQLITE_DONE);
    ASSERT_EQ(sqlite3_changes(database), 1);
    sqlite3_finalize(updateStatement);
    sqlite3_close(database);

    std::vector<models::CredentialSummary> summaries(1);
    summaries.front().title = "Résumé précédent";

    std::string listError;
    EXPECT_FALSE(services::CredentialService::listSummaries(
        databasePath.string(), *dataKey, summaries, listError));
    EXPECT_TRUE(summaries.empty());
    EXPECT_FALSE(listError.empty());
}

TEST_F(CredentialServiceTest, PersistsCredentialAfterVaultReopen) {
    using namespace passwall;

    std::string error;
    models::Credential original;
    original.title = "Compte persistant";
    original.url = "https://persistence.example";
    original.username = "persist-user";
    original.password = "persist-secret";
    original.notes = "Donnée conservée";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, original, error)) << error;

    // Relire les métadonnées depuis le fichier SQLite.
    services::VaultKeyMetadata reopenedMetadata;
    ASSERT_TRUE(storage::VaultStorage::readMetadata(
        databasePath.string(), reopenedMetadata, error)) << error;

    // Simuler un nouveau déverrouillage du coffre.
    const std::string masterPassword = "test-master-password";
    core::SecureBuffer reopenedKey(0);

    const auto unlockResult = services::VaultKeyService::unlock(
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(masterPassword.data()),
            masterPassword.size()),
        reopenedMetadata,
        reopenedKey);

    ASSERT_EQ(static_cast<int>(unlockResult), 0);

    models::Credential loaded;
    ASSERT_TRUE(services::CredentialService::get(
        databasePath.string(), reopenedKey, original.id, loaded, error))
        << error;

    EXPECT_EQ(loaded.title, original.title);
    EXPECT_EQ(loaded.url, original.url);
    EXPECT_EQ(loaded.username, original.username);
    EXPECT_EQ(loaded.password, original.password);
    EXPECT_EQ(loaded.notes, original.notes);
}

TEST_F(CredentialServiceTest, RejectsTamperedCiphertext) {
    using namespace passwall;

    std::string error;
    models::Credential original;
    original.title = "Compte à protéger";
    original.url = "https://tamper.example";
    original.username = "tamper-user";
    original.password = "tamper-secret";

    ASSERT_TRUE(services::CredentialService::add(
        databasePath.string(), *dataKey, original, error)) << error;

    sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open(databasePath.c_str(), &database), SQLITE_OK);
    ASSERT_NE(database, nullptr);

    sqlite3_stmt* selectStatement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(
        database,
        "SELECT ciphertext FROM entries WHERE entry_id = ?1",
        -1,
        &selectStatement,
        nullptr), SQLITE_OK);

    ASSERT_EQ(sqlite3_bind_blob(
        selectStatement, 1, original.id.data(),
        static_cast<int>(original.id.size()), SQLITE_TRANSIENT), SQLITE_OK);

    ASSERT_EQ(sqlite3_step(selectStatement), SQLITE_ROW);

    const auto* blob = static_cast<const unsigned char*>(
        sqlite3_column_blob(selectStatement, 0));
    const int blobSize = sqlite3_column_bytes(selectStatement, 0);

    ASSERT_NE(blob, nullptr);
    ASSERT_GT(blobSize, 0);

    std::vector<unsigned char> modified(blob, blob + blobSize);
    sqlite3_finalize(selectStatement);
    selectStatement = nullptr;

    // Modifier le dernier octet du ciphertext.
    modified.back() ^= 0x01;

    sqlite3_stmt* updateStatement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(
        database,
        "UPDATE entries SET ciphertext = ?1 WHERE entry_id = ?2",
        -1,
        &updateStatement,
        nullptr), SQLITE_OK);

    ASSERT_EQ(sqlite3_bind_blob(
        updateStatement, 1, modified.data(),
        static_cast<int>(modified.size()), SQLITE_TRANSIENT), SQLITE_OK);

    ASSERT_EQ(sqlite3_bind_blob(
        updateStatement, 2, original.id.data(),
        static_cast<int>(original.id.size()), SQLITE_TRANSIENT), SQLITE_OK);

    ASSERT_EQ(sqlite3_step(updateStatement), SQLITE_DONE);
    EXPECT_EQ(sqlite3_changes(database), 1);

    sqlite3_finalize(updateStatement);
    sqlite3_close(database);

    // L'authentification AEAD doit détecter l'altération.
    models::Credential rejected;
    std::string tamperError;

    EXPECT_FALSE(services::CredentialService::get(
        databasePath.string(), *dataKey, original.id, rejected, tamperError));
}


} // namespace
