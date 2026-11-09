#include "services/vault_restore_service.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>
#include <sqlite3.h>
#include <sodium.h>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QTemporaryDir>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using namespace passwall::services;
using passwall::core::SecureBuffer;
using passwall::models::Credential;
constexpr std::string_view master = "fictitious-restore-master-v1";
constexpr std::array<std::size_t, 5> fieldSizes{1000, 1100, 1200, 1300, 8192};
std::span<const unsigned char> passwordBytes(std::string_view value)
{
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}
void wipe(Credential& entry) noexcept
{
    for (auto* field : {&entry.title, &entry.url, &entry.username, &entry.password, &entry.notes}) {
        sodium_memzero(field->data(), field->size());
        field->clear();
    }
}
struct EntryCleanup {
    Credential& entry;
    ~EntryCleanup() noexcept { wipe(entry); }
};
bool zero(const void* memory, std::size_t size) noexcept
{
    const auto* bytes = static_cast<const unsigned char*>(memory);
    for (std::size_t i = 0; i < size; ++i) if (bytes[i] != 0) return false;
    return true;
}
enum class Fault { None, AuthPrepare, AuthStep, ThrowAuth, NotesAllocation, Kdf,
                   FileSync, DirectorySync, ThrowDirectorySync, LinkCollision, ThrowCleanupWarning };
struct Allocation {
    void* pointer = nullptr;
    std::size_t size = 0;
    bool wiped = false;
};
struct Probe {
    Fault fault = Fault::None;
    std::string source;
    SnapshotResult* result = nullptr;
    const unsigned char* expectedPassword = nullptr;
    bool borrowedPassword = false, passwordPhase = false, wrappingKeyWiped = false;
    unsigned char* wrappingKey = nullptr;
    int kdfs = 0, entryBuffers = 0;
    int opened = 0, closed = 0, prepared = 0, finalized = 0;
    int sourceOpens = 0, sourceFlags = 0, steps = 0;
    int liveSecure = 0, maxSecure = 0, secureCount = 0, stringCount = 0;
    int allocationsDuringUnwind = 0;
    bool allSecureWiped = true, closedWithStatement = false;
    bool faultInjected = false, throwNextAllocation = false, linked = false;
    bool cleanBeforeLink = false, publicationRecordedBeforeSync = false;
    bool copiedCallbackRan = false, privateFileSafe = false;
    std::array<Allocation, 64> secure{}, strings{};
    std::function<void(int)> afterCopyStep;
    bool stringsWiped() const noexcept
    {
        for (int i = 0; i < stringCount; ++i) if (!strings[i].wiped) return false;
        return true;
    }
};
thread_local Probe* active = nullptr;
struct Scope {
    explicit Scope(Probe& probe) noexcept { active = &probe; }
    ~Scope() noexcept { active = nullptr; }
};
bool inject(Fault fault) noexcept
{
    if (!active || active->fault != fault || active->faultInjected) return false;
    active->faultInjected = true;
    return true;
}
} // namespace

// Isolated linker faults/observations; no hooks, fake crypto, or passwords in
// production diagnostics. Destruction observers only record pointers/booleans.
extern "C" void* realNew(std::size_t) asm("__real__Znwm");
extern "C" void* wrappedNew(std::size_t) asm("__wrap__Znwm");
extern "C" void* wrappedNew(std::size_t size)
{
    if (active) {
        if (std::uncaught_exceptions()) ++active->allocationsDuringUnwind;
        if (active->throwNextAllocation) {
            active->throwNextAllocation = false;
            throw std::bad_alloc{};
        }
        if (active->passwordPhase && size == fieldSizes.back() + 1 && inject(Fault::NotesAllocation))
            throw std::bad_alloc{};
    }
    auto* pointer = realNew(size);
    if (active && active->passwordPhase && active->stringCount < 64) {
        for (auto fieldSize : fieldSizes) if (size == fieldSize + 1) {
            active->strings[active->stringCount++] = {pointer, fieldSize, false};
            break;
        }
    }
    return pointer;
}
extern "C" void* __real_sodium_malloc(std::size_t);
extern "C" void* __wrap_sodium_malloc(std::size_t size)
{
    auto* pointer = __real_sodium_malloc(size);
    if (active && pointer && active->secureCount < 64) {
        active->secure[active->secureCount++] = {pointer, size, false};
        ++active->liveSecure;
        active->maxSecure = std::max(active->maxSecure, active->liveSecure);
        if (size > 32) ++active->entryBuffers;
    }
    return pointer;
}
extern "C" void __real_sodium_memzero(void*, std::size_t);
extern "C" void __wrap_sodium_memzero(void* pointer, std::size_t size)
{
    __real_sodium_memzero(pointer, size);
    if (!active) return;
    if (pointer == active->wrappingKey && size == 32) active->wrappingKeyWiped = zero(pointer, size);
    for (int i = 0; i < active->stringCount; ++i)
        if (active->strings[i].pointer == pointer && active->strings[i].size == size)
            active->strings[i].wiped = zero(pointer, size);
}
extern "C" void __real_sodium_free(void*);
extern "C" void __wrap_sodium_free(void* pointer)
{
    if (active && pointer) {
        for (int i = 0; i < active->secureCount; ++i) {
            auto& allocation = active->secure[i];
            if (allocation.pointer == pointer && !allocation.wiped) {
                allocation.wiped = zero(pointer, allocation.size);
                active->allSecureWiped &= allocation.wiped;
                --active->liveSecure;
                break;
            }
        }
    }
    __real_sodium_free(pointer);
}
extern "C" int __real_crypto_pwhash(unsigned char*, unsigned long long, const char*, unsigned long long,
    const unsigned char*, unsigned long long, std::size_t, int);
extern "C" int __wrap_crypto_pwhash(unsigned char* output, unsigned long long size,
    const char* password, unsigned long long length, const unsigned char* salt,
    unsigned long long operations, std::size_t memory, int algorithm)
{
    if (active) {
        ++active->kdfs;
        active->borrowedPassword = reinterpret_cast<const unsigned char*>(password) == active->expectedPassword;
        active->wrappingKey = output;
        if (inject(Fault::Kdf)) return -1;
    }
    const int code = __real_crypto_pwhash(output, size, password, length, salt, operations, memory, algorithm);
    if (active && code == 0) active->passwordPhase = true;
    return code;
}
extern "C" int __real_sqlite3_open_v2(const char*, sqlite3**, int, const char*);
extern "C" int __wrap_sqlite3_open_v2(const char* path, sqlite3** db, int flags, const char* vfs)
{
    const int code = __real_sqlite3_open_v2(path, db, flags, vfs);
    if (active && *db) {
        ++active->opened;
        if (active->source == path) { ++active->sourceOpens; active->sourceFlags = flags; }
        else if (std::strstr(path, ".passwall-snapshot-") != nullptr) {
            struct stat directory{}, file{};
            const auto parent = std::string(path).substr(0, std::string(path).find_last_of('/'));
            active->privateFileSafe = ::stat(parent.c_str(), &directory) == 0
                && directory.st_uid == ::geteuid() && (directory.st_mode & 0777) == 0700
                && ::stat(path, &file) == 0 && file.st_uid == ::geteuid()
                && S_ISREG(file.st_mode) && (file.st_mode & 0777) == 0600;
        }
    }
    return code;
}
void observeClose(sqlite3* db)
{
    if (active && db) active->closedWithStatement |= sqlite3_next_stmt(db, nullptr) != nullptr;
}
extern "C" int __real_sqlite3_close(sqlite3*);
extern "C" int __wrap_sqlite3_close(sqlite3* db)
{
    observeClose(db);
    const int code = __real_sqlite3_close(db);
    if (active && db && code == SQLITE_OK) ++active->closed;
    return code;
}
extern "C" int __real_sqlite3_close_v2(sqlite3*);
extern "C" int __wrap_sqlite3_close_v2(sqlite3* db)
{
    observeClose(db);
    const int code = __real_sqlite3_close_v2(db);
    if (active && db && code == SQLITE_OK) ++active->closed;
    return code;
}
constexpr const char* authenticationQuery = "SELECT entry_id FROM entries ORDER BY entry_id;";
extern "C" int __real_sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern "C" int __wrap_sqlite3_prepare_v2(sqlite3* db, const char* sql, int size, sqlite3_stmt** statement, const char** tail)
{
    if (active && std::strcmp(sql, authenticationQuery) == 0) {
        if (inject(Fault::ThrowAuth)) throw std::bad_alloc{};
        if (inject(Fault::AuthPrepare)) { *statement = nullptr; return SQLITE_ERROR; }
    }
    const int code = __real_sqlite3_prepare_v2(db, sql, size, statement, tail);
    if (active && *statement) ++active->prepared;
    return code;
}
extern "C" int __real_sqlite3_finalize(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_finalize(sqlite3_stmt* statement)
{
    if (active && statement) ++active->finalized;
    return __real_sqlite3_finalize(statement);
}
extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_step(sqlite3_stmt* statement)
{
    if (active && std::strcmp(sqlite3_sql(statement), authenticationQuery) == 0
        && ++active->steps == 2 && inject(Fault::AuthStep)) return SQLITE_IOERR_READ;
    return __real_sqlite3_step(statement);
}
extern "C" int __real_sqlite3_backup_step(sqlite3_backup*, int);
extern "C" int __wrap_sqlite3_backup_step(sqlite3_backup* backup, int pages)
{
    const int code = __real_sqlite3_backup_step(backup, pages);
    if (active && active->afterCopyStep && !active->copiedCallbackRan) {
        auto* probe = active;
        // Attacker actions own independent connections, not the engine's RAII.
        active = nullptr;
        try { probe->afterCopyStep(code); }
        catch (...) { active = probe; throw; }
        active = probe;
    }
    return code;
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    struct stat status{};
    if (active && ::fstat(fd, &status) == 0) {
        const bool directory = S_ISDIR(status.st_mode);
        if (active->linked && directory) {
            active->publicationRecordedBeforeSync = active->result
                && active->result->publication == SnapshotPublication::PublishedDurabilityUnconfirmed;
            if (inject(Fault::DirectorySync) || inject(Fault::ThrowDirectorySync)) {
                active->throwNextAllocation = active->fault == Fault::ThrowDirectorySync;
                errno = EIO; return -1;
            }
        } else if (!directory && inject(Fault::FileSync)) { errno = EIO; return -1; }
    }
    return __real_fsync(fd);
}
extern "C" int __real_linkat(int, const char*, int, const char*, int);
extern "C" int __wrap_linkat(int from, const char* oldName, int to, const char* name, int flags)
{
    if (active) {
        active->cleanBeforeLink = active->liveSecure == 0 && active->allSecureWiped
            && active->stringsWiped() && active->wrappingKeyWiped
            && active->opened == active->closed && active->prepared == active->finalized;
        if (inject(Fault::LinkCollision)) {
            const int fd = ::openat(to, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            if (fd >= 0) { (void)::write(fd, "fictitious-existing", 19); ::close(fd); }
        }
    }
    const int code = __real_linkat(from, oldName, to, name, flags);
    if (active && code == 0) active->linked = true;
    return code;
}
extern "C" int __real_unlinkat(int, const char*, int);
extern "C" int __wrap_unlinkat(int fd, const char* name, int flags)
{
    if (active && active->linked && std::strcmp(name, "snapshot.pwdb") == 0
        && inject(Fault::ThrowCleanupWarning)) {
        active->throwNextAllocation = true; // Next diagnostic follows successful directory fsync.
        errno = EACCES;
        return -1;
    }
    return __real_unlinkat(fd, name, flags);
}

namespace {
using Db = std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)>;
Db open(const std::string& path)
{
    sqlite3* db = nullptr;
    const int code = sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE, nullptr);
    EXPECT_EQ(code, SQLITE_OK);
    return {db, sqlite3_close_v2};
}
void execute(const std::string& path, const char* sql)
{
    auto db = open(path);
    ASSERT_EQ(sqlite3_exec(db.get(), sql, nullptr, nullptr, nullptr), SQLITE_OK);
}
QByteArray bytes(const std::string& path)
{
    QFile file(QString::fromStdString(path));
    EXPECT_TRUE(file.open(QIODevice::ReadOnly));
    return file.readAll();
}
class VaultRestoreServiceTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suite;
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-restore-case-XXXXXX")};
    std::string source, destination;
    SnapshotResult result;
    Probe probe;
    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        suite = std::make_unique<QTemporaryDir>(QStringLiteral("/tmp/passwall-restore-suite-XXXXXX"));
        ASSERT_TRUE(suite->isValid());
        SecureBuffer key(0); std::string error;
        const auto original = suite->filePath("original.pwdb").toStdString();
        ASSERT_TRUE(VaultLifecycleService::createVault(original, std::string(master), key, error));
        for (int index = 0; index < 3; ++index) {
            Credential credential; EntryCleanup cleanup{credential};
            credential.title.assign(fieldSizes[0], 't'); credential.title[0] = 'A' + index;
            credential.url = "https://restore.example.test/";
            credential.url.resize(fieldSizes[1], 'a');
            credential.username.assign(fieldSizes[2], 'u');
            credential.password.assign(fieldSizes[3], 'p');
            credential.notes.assign(fieldSizes[4], 'n'); credential.notes[0] = 'A' + index;
            ASSERT_TRUE(CredentialService::add(original, key, credential, error));
        }
        key = SecureBuffer(0);
        SnapshotResult snapshot;
        ASSERT_TRUE(VaultSnapshotService::createSnapshot(original,
            suite->filePath("backup.pwdb").toStdString(), snapshot));
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, suite->path());
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, suite->path());
    }
    static void TearDownTestSuite() { suite.reset(); }
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        source = directory.filePath("backup.pwdb").toStdString();
        destination = directory.filePath("restored.pwdb").toStdString();
        ASSERT_TRUE(QFile::copy(suite->filePath("backup.pwdb"), QString::fromStdString(source)));
    }
    bool restore(std::string_view password = master)
    {
        probe.source = source; probe.result = &result;
        probe.expectedPassword = passwordBytes(password).data();
        Scope scope(probe);
        return VaultRestoreService::restoreBackup(source, destination, passwordBytes(password), result);
    }
    void released()
    {
        EXPECT_EQ(probe.opened, probe.closed); EXPECT_EQ(probe.prepared, probe.finalized);
        EXPECT_FALSE(probe.closedWithStatement); EXPECT_EQ(probe.liveSecure, 0);
        EXPECT_TRUE(probe.allSecureWiped); EXPECT_TRUE(probe.stringsWiped());
        EXPECT_EQ(probe.allocationsDuringUnwind, 0);
        EXPECT_TRUE(QDir(directory.path()).entryList({".passwall-snapshot-*"}, QDir::Dirs | QDir::Hidden).isEmpty());
    }
    void rejected()
    {
        EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
        EXPECT_FALSE(result.diagnostic.empty()); EXPECT_FALSE(probe.linked);
        EXPECT_FALSE(QFile::exists(QString::fromStdString(destination))); released();
    }
    auto encryptedRows(const std::string& path)
    {
        std::vector<std::array<QByteArray, 4>> rows;
        auto db = open(path); sqlite3_stmt* raw = nullptr;
        EXPECT_EQ(sqlite3_prepare_v2(db.get(),
            "SELECT entry_id,entry_version,nonce,ciphertext FROM entries ORDER BY entry_id;", -1, &raw, nullptr), SQLITE_OK);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw, sqlite3_finalize);
        int code;
        while ((code = sqlite3_step(raw)) == SQLITE_ROW) {
            std::array<QByteArray, 4> row;
            for (int i = 0; i < 4; ++i)
                row[i] = QByteArray(static_cast<const char*>(sqlite3_column_blob(raw, i)), sqlite3_column_bytes(raw, i));
            rows.push_back(std::move(row));
        }
        EXPECT_EQ(code, SQLITE_DONE);
        return rows;
    }
    void resetSource()
    {
        ASSERT_TRUE(QFile::remove(QString::fromStdString(source)));
        ASSERT_TRUE(QFile::copy(suite->filePath("backup.pwdb"), QString::fromStdString(source)));
        probe = Probe{};
    }
    void makeAuthenticatedInvalidBody(bool missingTitle)
    {
        VaultKeyMetadata metadata; std::string error;
        ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(source, metadata, error));
        SecureBuffer key(0);
        ASSERT_TRUE(VaultKeyService::unlock(passwordBytes(master), metadata, key) == passwall::core::CryptoError::None);
        const auto rows = encryptedRows(source);
        ASSERT_FALSE(rows.empty());
        // Test fixture only: use the documented v1 AAD layout and the REAL
        // CryptoEngine, not replacement encryption/decryption implementations.
        std::array<unsigned char, 52> aad{};
        std::copy(metadata.vaultId.begin(), metadata.vaultId.end(), aad.begin());
        std::memcpy(aad.data() + 16, rows.front()[0].constData(), 16);
        aad[32] = 1;
        constexpr std::array<unsigned char, 16> purpose{
            'P','W','-','E','N','T','R','Y','-','E','N','C','-','v','1',0};
        std::copy(purpose.begin(), purpose.end(), aad.begin() + 36);
        passwall::core::EncryptedData encrypted;
        std::memcpy(encrypted.nonce.data(), rows.front()[2].constData(), encrypted.nonce.size());
        const auto& ciphertext = rows.front()[3];
        encrypted.ciphertext.assign(reinterpret_cast<const unsigned char*>(ciphertext.constData()),
            reinterpret_cast<const unsigned char*>(ciphertext.constData()) + ciphertext.size());
        SecureBuffer plaintext(0);
        const std::span<const unsigned char> keyBytes{key.data(), key.size()};
        ASSERT_TRUE(passwall::core::CryptoEngine::decrypt(encrypted, aad, keyBytes, plaintext) == passwall::core::CryptoError::None);
        ASSERT_GT(plaintext.size(), 24 + fieldSizes[0]);
        if (missingTitle) std::memset(plaintext.data() + 24, ' ', fieldSizes[0]);
        else plaintext.data()[0] = 'X'; // Valid AEAD, invalid serialization magic.
        ASSERT_TRUE(passwall::core::CryptoEngine::encrypt({plaintext.data(), plaintext.size()}, aad,
            keyBytes, encrypted) == passwall::core::CryptoError::None);
        auto db = open(source); sqlite3_stmt* raw = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(db.get(), "UPDATE entries SET nonce=?,ciphertext=? WHERE entry_id=?;",
            -1, &raw, nullptr), SQLITE_OK);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(raw, sqlite3_finalize);
        ASSERT_EQ(sqlite3_bind_blob(raw, 1, encrypted.nonce.data(), encrypted.nonce.size(), SQLITE_TRANSIENT), SQLITE_OK);
        ASSERT_EQ(sqlite3_bind_blob(raw, 2, encrypted.ciphertext.data(), encrypted.ciphertext.size(), SQLITE_TRANSIENT), SQLITE_OK);
        ASSERT_EQ(sqlite3_bind_blob(raw, 3, rows.front()[0].constData(), 16, SQLITE_TRANSIENT), SQLITE_OK);
        ASSERT_EQ(sqlite3_step(raw), SQLITE_DONE);
        ASSERT_EQ(sqlite3_changes(db.get()), 1);
    }
};

TEST_F(VaultRestoreServiceTest, ValidBackupRestoresAllEncryptedRecordsAndReopensWithOriginalPassword)
{
    const auto before = bytes(source); const auto rows = encryptedRows(source);
    ASSERT_TRUE(restore()); EXPECT_EQ(result.publication, SnapshotPublication::Published);
    EXPECT_EQ(bytes(source), before); EXPECT_EQ(encryptedRows(destination), rows);
    EXPECT_EQ(probe.kdfs, 1); EXPECT_TRUE(probe.borrowedPassword);
    EXPECT_EQ(probe.entryBuffers, 3); EXPECT_LE(probe.maxSecure, 2);
    EXPECT_TRUE(probe.cleanBeforeLink); EXPECT_TRUE(probe.privateFileSafe);
    EXPECT_EQ(probe.sourceOpens, 1);
    EXPECT_NE(probe.sourceFlags & SQLITE_OPEN_READONLY, 0); EXPECT_EQ(probe.sourceFlags & SQLITE_OPEN_CREATE, 0);
    EXPECT_TRUE(probe.publicationRecordedBeforeSync); released();
    VaultKeyMetadata original, restored; std::string error;
    ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(source, original, error));
    ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(destination, restored, error));
    EXPECT_TRUE(original.vaultId == restored.vaultId && original.salt == restored.salt
        && original.wrapNonce == restored.wrapNonce && original.wrappedDek == restored.wrappedDek
        && original.operationsLimit == restored.operationsLimit && original.memoryLimit == restored.memoryLimit
        && original.formatVersion == restored.formatVersion);
    SecureBuffer key(0);
    ASSERT_TRUE(VaultKeyService::unlock(passwordBytes(master), restored, key) == passwall::core::CryptoError::None);
    std::vector<passwall::models::CredentialSummary> summaries;
    ASSERT_TRUE(CredentialService::listSummaries(destination, key, summaries, error));
    EXPECT_EQ(summaries.size(), 3U);
    struct stat status{}; ASSERT_EQ(::stat(destination.c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777, 0600); EXPECT_EQ(status.st_uid, ::geteuid());
}
TEST_F(VaultRestoreServiceTest, WrongPasswordDoesNotPublishOrMutateTheBorrowedPassword)
{
    const auto before = bytes(source);
    std::string wrong = "fictitious-wrong-restore-master";
    EXPECT_FALSE(restore(wrong)); EXPECT_TRUE(wrong == "fictitious-wrong-restore-master");
    EXPECT_EQ(probe.kdfs, 1); EXPECT_TRUE(probe.borrowedPassword);
    EXPECT_EQ(bytes(source), before); rejected();
    sodium_memzero(wrong.data(), wrong.size());
}
TEST_F(VaultRestoreServiceTest, EmptyPasswordDoesNotOpenOrCreateAnyFile)
{
    EXPECT_FALSE(restore({})); EXPECT_EQ(probe.opened, 0); rejected();
}
TEST_F(VaultRestoreServiceTest, EveryEntryMustAuthenticateIncludingAfterAValidFirstEntry)
{
    execute(source, "UPDATE entries SET ciphertext=zeroblob(length(ciphertext)) WHERE entry_id="
        "(SELECT entry_id FROM entries ORDER BY entry_id LIMIT 1 OFFSET 1);");
    const auto before = bytes(source);
    EXPECT_FALSE(restore()); EXPECT_EQ(probe.entryBuffers, 2); EXPECT_EQ(probe.stringCount, 5);
    EXPECT_EQ(bytes(source), before); rejected();
}
TEST_F(VaultRestoreServiceTest, AuthenticButMalformedOrBusinessInvalidPlaintextIsRejected)
{
    for (bool missingTitle : {false, true}) {
        resetSource(); makeAuthenticatedInvalidBody(missingTitle);
        const auto before = bytes(source);
        EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 1); EXPECT_EQ(probe.entryBuffers, 1);
        EXPECT_EQ(bytes(source), before); rejected();
    }
}
TEST_F(VaultRestoreServiceTest, TruncatedCiphertextAndUnsupportedEntryVersionFailBeforeKdf)
{
    for (const auto* mutation : {"PRAGMA ignore_check_constraints=ON; UPDATE entries SET ciphertext=x'00';",
             "UPDATE entries SET entry_version=2;", "PRAGMA ignore_check_constraints=ON; UPDATE entries SET nonce=zeroblob(23);"}) {
        resetSource(); execute(source, mutation); const auto before = bytes(source);
        EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 0); EXPECT_EQ(bytes(source), before); rejected();
    }
}
TEST_F(VaultRestoreServiceTest, InvalidMetadataAndUnsupportedFormatAreRejectedBeforeKdf)
{
    for (const auto* mutation : {"UPDATE vault_metadata SET format_version=2;",
             "UPDATE vault_metadata SET argon2_operations=999999;", "UPDATE vault_metadata SET argon2_memory=1;",
             "PRAGMA ignore_check_constraints=ON; UPDATE vault_metadata SET salt=zeroblob(15);",
             "DELETE FROM vault_metadata;"}) {
        resetSource(); execute(source, mutation); const auto before = bytes(source);
        EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 0); EXPECT_EQ(bytes(source), before); rejected();
    }
}
TEST_F(VaultRestoreServiceTest, TamperedWrappedKeyOrVaultIdentityFailsCryptographicAuthentication)
{
    for (const auto* mutation : {"UPDATE vault_metadata SET wrapped_dek=zeroblob(48);",
             "UPDATE vault_metadata SET vault_id=zeroblob(16);"}) {
        resetSource(); execute(source, mutation); const auto before = bytes(source);
        EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 1); EXPECT_EQ(bytes(source), before); rejected();
    }
}
TEST_F(VaultRestoreServiceTest, CorruptedSqliteAndUnexpectedSchemaNeverPublish)
{
    {
        QFile file(QString::fromStdString(source)); ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_GT(file.write("fictitious-not-a-sqlite-file"), 0);
    }
    const auto damaged = bytes(source);
    EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 0); EXPECT_EQ(bytes(source), damaged); rejected();
    resetSource(); execute(source, "CREATE TABLE unexpected(secret TEXT);");
    const auto extra = bytes(source);
    EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 0); EXPECT_EQ(bytes(source), extra); rejected();
}
TEST_F(VaultRestoreServiceTest, ExistingDestinationsAndSourceAreNeverOverwritten)
{
    ASSERT_TRUE(QFile::copy(QString::fromStdString(source), QString::fromStdString(destination)));
    const auto before = bytes(destination);
    EXPECT_FALSE(restore()); EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_EQ(bytes(destination), before); EXPECT_EQ(bytes(source), before); EXPECT_EQ(probe.kdfs, 0); released();
    destination = source; probe = Probe{};
    EXPECT_FALSE(restore()); EXPECT_EQ(bytes(source), before); EXPECT_EQ(probe.kdfs, 0); released();
}
TEST_F(VaultRestoreServiceTest, MissingSourcesAndFifosAreNotCreatedOrBlockedOn)
{
    source += "-missing"; EXPECT_FALSE(restore()); rejected(); EXPECT_EQ(probe.kdfs, 0);
    EXPECT_FALSE(QFile::exists(QString::fromStdString(source)));
    ASSERT_EQ(::mkfifo(source.c_str(), 0600), 0); probe = Probe{};
    EXPECT_FALSE(restore()); rejected(); EXPECT_EQ(probe.kdfs, 0);
}
TEST_F(VaultRestoreServiceTest, SymlinkComponentsAndUnsafeDestinationDirectoriesAreRejected)
{
    const auto original = source;
    source = directory.filePath("source-link.pwdb").toStdString();
    ASSERT_EQ(::symlink(original.c_str(), source.c_str()), 0);
    EXPECT_FALSE(restore()); rejected(); source = original; probe = Probe{};
    ASSERT_EQ(::symlink("absent.pwdb", destination.c_str()), 0);
    EXPECT_FALSE(restore()); EXPECT_TRUE(QFileInfo(QString::fromStdString(destination)).isSymLink()); released();
    ASSERT_TRUE(QDir(directory.path()).mkdir("unsafe"));
    const auto unsafe = directory.filePath("unsafe").toStdString(); ASSERT_EQ(::chmod(unsafe.c_str(), 0777), 0);
    destination = unsafe + "/new.pwdb"; probe = Probe{}; EXPECT_FALSE(restore()); rejected();
    const auto alias = directory.filePath("alias").toStdString();
    ASSERT_EQ(::symlink(directory.path().toStdString().c_str(), alias.c_str()), 0);
    destination = alias + "/new.pwdb"; probe = Probe{}; EXPECT_FALSE(restore()); rejected();
}
TEST_F(VaultRestoreServiceTest, ReplacedSourceIsRefusedAndCannotRedirectFinalPublication)
{
    probe.afterCopyStep = [&](int) {
        if (probe.copiedCallbackRan) return;
        probe.copiedCallbackRan = true;
        ASSERT_EQ(::rename(source.c_str(), (source + "-original").c_str()), 0);
        ASSERT_TRUE(QFile::copy(suite->filePath("backup.pwdb"), QString::fromStdString(source)));
    };
    EXPECT_FALSE(restore()); EXPECT_TRUE(probe.copiedCallbackRan); rejected();
}
TEST_F(VaultRestoreServiceTest, InPlaceSourceChangeAfterCopyCannotAlterTheAuthenticatedPrivateCopy)
{
    const auto original = encryptedRows(source);
    probe.afterCopyStep = [&](int code) {
        if (code != SQLITE_DONE) return;
        probe.copiedCallbackRan = true;
        execute(source, "UPDATE entries SET ciphertext=zeroblob(length(ciphertext));");
    };
    ASSERT_TRUE(restore()); EXPECT_TRUE(probe.copiedCallbackRan);
    EXPECT_EQ(encryptedRows(destination), original); EXPECT_NE(encryptedRows(source), original);
    EXPECT_EQ(probe.sourceOpens, 1); EXPECT_TRUE(probe.cleanBeforeLink); released();
}
TEST_F(VaultRestoreServiceTest, AuthenticationSqlAndAllocationFailuresReleaseSecretsAndAllowRetry)
{
    const auto before = bytes(source);
    for (auto fault : {Fault::AuthPrepare, Fault::AuthStep, Fault::ThrowAuth, Fault::NotesAllocation, Fault::Kdf}) {
        probe = Probe{}; probe.fault = fault;
        EXPECT_FALSE(restore()); EXPECT_TRUE(probe.faultInjected); EXPECT_EQ(bytes(source), before); rejected();
        if (fault == Fault::NotesAllocation) EXPECT_GE(probe.stringCount, 4);
    }
    probe = Probe{}; EXPECT_TRUE(restore()); EXPECT_TRUE(probe.cleanBeforeLink); released();
}
TEST_F(VaultRestoreServiceTest, FileSyncFailureIsBeforePublicationAndDoesNotLeakKeys)
{
    probe.fault = Fault::FileSync;
    EXPECT_FALSE(restore()); EXPECT_TRUE(probe.faultInjected); EXPECT_EQ(probe.entryBuffers, 3); rejected();
}
TEST_F(VaultRestoreServiceTest, DirectorySyncFailureAfterPublicationRetainsTheAuthenticatedFinalFile)
{
    probe.fault = Fault::DirectorySync;
    EXPECT_FALSE(restore()); EXPECT_TRUE(probe.faultInjected);
    EXPECT_EQ(result.publication, SnapshotPublication::PublishedDurabilityUnconfirmed);
    EXPECT_TRUE(probe.cleanBeforeLink); EXPECT_TRUE(probe.publicationRecordedBeforeSync);
    EXPECT_EQ(encryptedRows(source), encryptedRows(destination)); released();
}
TEST_F(VaultRestoreServiceTest, ExceptionAfterPublicationCannotEraseFinalOrPretendNothingWasPublished)
{
    probe.fault = Fault::ThrowDirectorySync;
    EXPECT_FALSE(restore()); EXPECT_TRUE(probe.faultInjected);
    EXPECT_EQ(result.publication, SnapshotPublication::PublishedDurabilityUnconfirmed);
    EXPECT_EQ(encryptedRows(source), encryptedRows(destination)); released();
}
TEST_F(VaultRestoreServiceTest, CleanupDiagnosticExceptionAfterConfirmedPublicationRetainsSuccessAndFinal)
{
    probe.fault = Fault::ThrowCleanupWarning;
    EXPECT_TRUE(restore()); EXPECT_TRUE(probe.faultInjected);
    EXPECT_EQ(result.publication, SnapshotPublication::Published);
    EXPECT_FALSE(result.diagnostic.empty()); EXPECT_EQ(encryptedRows(source), encryptedRows(destination));
    released();
}
TEST_F(VaultRestoreServiceTest, CollisionAtTheFinalLinkPreservesTheConcurrentFile)
{
    probe.fault = Fault::LinkCollision;
    EXPECT_FALSE(restore()); EXPECT_TRUE(probe.faultInjected);
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_EQ(bytes(destination), "fictitious-existing"); EXPECT_TRUE(probe.cleanBeforeLink); released();
}
TEST_F(VaultRestoreServiceTest, EmptyAuthenticatedVaultIsValid)
{
    execute(source, "DELETE FROM entries;");
    ASSERT_TRUE(restore()); EXPECT_EQ(probe.entryBuffers, 0); EXPECT_TRUE(probe.cleanBeforeLink); released();
}
TEST_F(VaultRestoreServiceTest, LocalPreferencesAndAnUnrelatedVaultRemainUntouched)
{
    const auto unrelated = directory.filePath("unrelated.pwdb").toStdString();
    ASSERT_TRUE(QFile::copy(QString::fromStdString(source), QString::fromStdString(unrelated)));
    QSettings settings("PassWall", "PassWall");
    settings.setValue("backup/autoEnabled", true); settings.setValue("vault/lastPath", QString::fromStdString(unrelated));
    settings.sync();
    const auto beforeSettings = bytes(settings.fileName().toStdString()); const auto beforeVault = bytes(unrelated);
    ASSERT_TRUE(restore()); EXPECT_EQ(bytes(settings.fileName().toStdString()), beforeSettings);
    EXPECT_EQ(bytes(unrelated), beforeVault); EXPECT_EQ(probe.kdfs, 1);
    EXPECT_EQ(QDir(directory.path()).entryList(QDir::Files).size(), 3);
    released();
}
TEST_F(VaultRestoreServiceTest, WalIsRefusedWithoutConversionOrCheckpoint)
{
    auto db = open(source); int enabled = 0;
    ASSERT_EQ(sqlite3_db_config(db.get(), SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, &enabled), SQLITE_OK);
    ASSERT_EQ(enabled, 1);
    ASSERT_EQ(sqlite3_exec(db.get(), "PRAGMA journal_mode=WAL; UPDATE vault_metadata SET format_version=format_version;",
        nullptr, nullptr, nullptr), SQLITE_OK);
    const auto before = bytes(source); const auto wal = bytes(source + "-wal");
    EXPECT_FALSE(restore()); EXPECT_EQ(probe.kdfs, 0); rejected();
    EXPECT_EQ(bytes(source), before); EXPECT_EQ(bytes(source + "-wal"), wal);
    sqlite3_stmt* raw = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(db.get(), "PRAGMA journal_mode;", -1, &raw, nullptr), SQLITE_OK);
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(raw, sqlite3_finalize);
    ASSERT_EQ(sqlite3_step(raw), SQLITE_ROW);
    EXPECT_TRUE(std::strcmp(reinterpret_cast<const char*>(sqlite3_column_text(raw, 0)), "wal") == 0);
}
} // namespace
