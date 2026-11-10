#include "services/vault_snapshot_service.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/sqlite_connection_config.hpp"
#include "storage/vault_storage.hpp"
#include "posix_test_io.hpp"

#include <gtest/gtest.h>
#include <sqlite3.h>
#include <sodium.h>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

extern "C" int __real_sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __real_sqlite3_finalize(sqlite3_stmt*);
extern "C" int __real_sqlite3_exec(sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**);

namespace {
using passwall::core::SecureBuffer;
using passwall::models::Credential;
using passwall::services::CredentialService;
using passwall::services::SnapshotPublication;
using passwall::services::SnapshotResult;
using passwall::services::VaultLifecycleService;
using passwall::services::VaultSnapshotService;

enum class Fault {
    None, Open, Prepare, Init, StepIo, Finish, BusyOnce, LockedOnce,
    BusyPersistent, LockedPersistent, PartialThenBusy, BusyBetweenProgress,
    Integrity, IntegrityResult, UnsupportedFilesystem, FileSync,
    DirectorySyncBefore, DirectorySyncAfter, Link, DestinationRace, Cleanup
};

struct Probe {
    Fault fault = Fault::None;
    bool injected = false;
    bool throwDiagnostic = false;
    bool failNextAllocation = false;
    bool allocationFailed = false;
    int allocationsWhileUnwinding = 0;
    int opened = 0;
    int closed = 0;
    int prepared = 0;
    int finalized = 0;
    int initialized = 0;
    int finished = 0;
    int steps = 0;
    int contentionReturns = 0;
    int finishCode = -1;
    int sourceFlags = 0;
    bool sourceReadOnly = false;
    bool policyVerified = false;
    bool closeWithStatement = false;
    bool closeWithBackup = false;
    bool destinationUsedDuringBackup = false;
    bool linked = false;
    bool temporaryPrivate = false;
    bool stepCompleted = false;
    bool callbackRan = false;
    bool simulateSlowCopy = false;
    sqlite3* destination = nullptr;
    sqlite3_backup* backup = nullptr;
    std::function<void()> betweenSteps;
};

thread_local Probe* activeProbe = nullptr;

struct Scope {
    explicit Scope(Probe& probe) noexcept { activeProbe = &probe; }
    ~Scope() noexcept { activeProbe = nullptr; }
};

bool inject(Fault fault)
{
    if (activeProbe == nullptr || activeProbe->fault != fault || activeProbe->injected)
        return false;
    activeProbe->injected = true;
    return true;
}

void diagnosticMayThrow()
{
    if (activeProbe != nullptr && activeProbe->throwDiagnostic)
        activeProbe->failNextAllocation = true;
}

bool policyMatches(sqlite3* database)
{
    int enabled = 0;
    if (sqlite3_db_config(database, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, -1, &enabled) != SQLITE_OK
        || enabled != 1)
        return false;
    constexpr const char* queries[] = {"PRAGMA main.journal_mode;", "PRAGMA main.synchronous;",
        "PRAGMA main.secure_delete;", "PRAGMA temp_store;", "PRAGMA busy_timeout;"};
    constexpr int expected[] = {0, 3, 1, 2, 3000};
    for (int index = 0; index < 5; ++index) {
        sqlite3_stmt* statement = nullptr;
        bool valid = __real_sqlite3_prepare_v2(database, queries[index], -1, &statement, nullptr) == SQLITE_OK;
        valid = valid && __real_sqlite3_step(statement) == SQLITE_ROW;
        if (valid && index == 0) {
            const auto* text = sqlite3_column_text(statement, 0);
            valid = text != nullptr && sqlite3_column_bytes(statement, 0) == 6
                && std::memcmp(text, "delete", 6) == 0;
        } else if (valid) {
            valid = sqlite3_column_type(statement, 0) == SQLITE_INTEGER
                && sqlite3_column_int(statement, 0) == expected[index];
        }
        const int finalized = __real_sqlite3_finalize(statement);
        if (!valid || finalized != SQLITE_OK) return false;
    }
    return true;
}

void observeDestination(sqlite3* database)
{
    if (activeProbe != nullptr && activeProbe->backup != nullptr
        && database == activeProbe->destination)
        activeProbe->destinationUsedDuringBackup = true;
}

void wipe(Credential& credential)
{
    for (auto* text : {&credential.title, &credential.url, &credential.username,
                       &credential.password, &credential.notes}) {
        sodium_memzero(text->data(), text->size());
        text->clear();
    }
}
} // namespace

// Local linker injection, matching the existing storage tests. No production
// fault hooks, allocator changes or replacement VFS are introduced.
using SnapshotClock = std::chrono::steady_clock;
extern "C" SnapshotClock::time_point realSnapshotNow() noexcept
    asm("__real__ZNSt6chrono3_V212steady_clock3nowEv");
extern "C" SnapshotClock::time_point wrappedSnapshotNow() noexcept
    asm("__wrap__ZNSt6chrono3_V212steady_clock3nowEv");
extern "C" SnapshotClock::time_point wrappedSnapshotNow() noexcept
{
    // Advance virtual elapsed time by 10 s per backup_step, without waiting.
    // This also catches any reintroduction of a global steady-clock deadline.
    const auto now = realSnapshotNow();
    return activeProbe != nullptr && activeProbe->simulateSlowCopy
        ? now + std::chrono::seconds(10LL * activeProbe->steps) : now;
}

extern "C" void* realNew(std::size_t) asm("__real__Znwm");
extern "C" void* wrappedNew(std::size_t) asm("__wrap__Znwm");
extern "C" void* wrappedNew(std::size_t size)
{
    if (activeProbe != nullptr) {
        if (std::uncaught_exceptions() != 0) ++activeProbe->allocationsWhileUnwinding;
        if (activeProbe->failNextAllocation) {
            activeProbe->failNextAllocation = false;
            activeProbe->allocationFailed = true;
            throw std::bad_alloc{};
        }
    }
    return realNew(size);
}

extern "C" int __real_sqlite3_open_v2(const char*, sqlite3**, int, const char*);
extern "C" int __wrap_sqlite3_open_v2(const char* path, sqlite3** database, int flags, const char* vfs)
{
    const int code = __real_sqlite3_open_v2(path, database, flags, vfs);
    if (activeProbe != nullptr && *database != nullptr) {
        auto& probe = *activeProbe;
        ++probe.opened;
        if (probe.opened == 1) {
            probe.sourceFlags = flags;
            probe.sourceReadOnly = sqlite3_db_readonly(*database, "main") == 1;
        }
        if (inject(Fault::Open)) return SQLITE_CANTOPEN;
    }
    return code;
}

void observeClose(sqlite3* database)
{
    if (activeProbe != nullptr && database != nullptr) {
        activeProbe->closeWithStatement |= sqlite3_next_stmt(database, nullptr) != nullptr;
        activeProbe->closeWithBackup |= activeProbe->backup != nullptr;
    }
}
extern "C" int __real_sqlite3_close(sqlite3*);
extern "C" int __wrap_sqlite3_close(sqlite3* database)
{
    observeClose(database);
    const int code = __real_sqlite3_close(database);
    if (activeProbe != nullptr && database != nullptr && code == SQLITE_OK) ++activeProbe->closed;
    return code;
}
extern "C" int __real_sqlite3_close_v2(sqlite3*);
extern "C" int __wrap_sqlite3_close_v2(sqlite3* database)
{
    observeClose(database);
    const int code = __real_sqlite3_close_v2(database);
    if (activeProbe != nullptr && database != nullptr && code == SQLITE_OK) ++activeProbe->closed;
    return code;
}

extern "C" int __wrap_sqlite3_prepare_v2(sqlite3* database, const char* sql, int size,
    sqlite3_stmt** statement, const char** tail)
{
    observeDestination(database);
    const bool failure = std::strcmp(sql, "SELECT count(*) FROM main.sqlite_schema;") == 0
        && inject(Fault::Prepare);
    const bool badIntegrity = std::strcmp(sql, "PRAGMA main.integrity_check;") == 0
        && inject(Fault::IntegrityResult);
    const int code = __real_sqlite3_prepare_v2(database,
        failure ? "SELECT * FROM passwall_missing_snapshot_table;"
                : badIntegrity ? "SELECT 'fictitious structural error';" : sql,
        failure || badIntegrity ? -1 : size, statement, tail);
    if (activeProbe != nullptr && *statement != nullptr) ++activeProbe->prepared;
    if (failure) diagnosticMayThrow();
    return code;
}
extern "C" int __wrap_sqlite3_finalize(sqlite3_stmt* statement)
{
    if (activeProbe != nullptr && statement != nullptr) ++activeProbe->finalized;
    return __real_sqlite3_finalize(statement);
}
extern "C" int __wrap_sqlite3_exec(sqlite3* database, const char* sql,
    int (*callback)(void*, int, char**, char**), void* context, char** error)
{
    observeDestination(database);
    return __real_sqlite3_exec(database, sql, callback, context, error);
}
extern "C" int __wrap_sqlite3_step(sqlite3_stmt* statement)
{
    observeDestination(sqlite3_db_handle(statement));
    if (std::strcmp(sqlite3_sql(statement), "PRAGMA main.integrity_check;") == 0
        && inject(Fault::Integrity)) {
        diagnosticMayThrow();
        return SQLITE_IOERR;
    }
    return __real_sqlite3_step(statement);
}

extern "C" sqlite3_backup* __real_sqlite3_backup_init(sqlite3*, const char*, sqlite3*, const char*);
extern "C" sqlite3_backup* __wrap_sqlite3_backup_init(sqlite3* destination, const char* name,
    sqlite3* source, const char* sourceName)
{
    if (activeProbe != nullptr) {
        activeProbe->policyVerified = policyMatches(source) && policyMatches(destination);
        activeProbe->destination = destination;
        if (inject(Fault::Init)) {
            // A real backup_init failure: destination transactions are forbidden.
            __real_sqlite3_exec(destination, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr);
        }
    }
    auto* backup = __real_sqlite3_backup_init(destination, name, source, sourceName);
    if (activeProbe != nullptr && backup != nullptr) {
        activeProbe->backup = backup;
        ++activeProbe->initialized;
    }
    return backup;
}
extern "C" int __real_sqlite3_backup_step(sqlite3_backup*, int);
extern "C" int __wrap_sqlite3_backup_step(sqlite3_backup* backup, int pages)
{
    if (activeProbe != nullptr) {
        auto& probe = *activeProbe;
        ++probe.steps;
        if (probe.fault == Fault::BusyPersistent || probe.fault == Fault::LockedPersistent
            || (probe.fault == Fault::PartialThenBusy && probe.steps > 1)
            || (probe.fault == Fault::BusyBetweenProgress && probe.steps % 3 != 0)) {
            probe.injected = true;
            ++probe.contentionReturns;
            return probe.fault == Fault::LockedPersistent ? SQLITE_LOCKED : SQLITE_BUSY;
        }
        if (inject(Fault::BusyOnce)) {
            ++probe.contentionReturns;
            return SQLITE_BUSY;
        }
        if (inject(Fault::LockedOnce)) {
            ++probe.contentionReturns;
            return SQLITE_LOCKED;
        }
        if (inject(Fault::StepIo)) {
            diagnosticMayThrow();
            return SQLITE_IOERR_WRITE;
        }
    }
    const int code = __real_sqlite3_backup_step(backup, pages);
    if (activeProbe != nullptr) {
        activeProbe->stepCompleted |= code == SQLITE_DONE;
        if (code == SQLITE_OK && activeProbe->betweenSteps && !activeProbe->callbackRan) {
            auto* probe = activeProbe;
            probe->callbackRan = true;
            // The independent writer is not owned by the snapshot engine.
            activeProbe = nullptr;
            try { probe->betweenSteps(); }
            catch (...) { activeProbe = probe; throw; }
            activeProbe = probe;
        }
    }
    return code;
}
extern "C" int __real_sqlite3_backup_finish(sqlite3_backup*);
extern "C" int __wrap_sqlite3_backup_finish(sqlite3_backup* backup)
{
    const int code = __real_sqlite3_backup_finish(backup);
    if (activeProbe != nullptr && backup != nullptr) {
        ++activeProbe->finished;
        activeProbe->finishCode = code;
        activeProbe->backup = nullptr;
        if (inject(Fault::Finish)) {
            diagnosticMayThrow();
            return SQLITE_IOERR_FSYNC;
        }
    }
    return code;
}

extern "C" int __real_fstatfs(int, struct statfs*);
extern "C" int __wrap_fstatfs(int fd, struct statfs* status)
{
    const int code = __real_fstatfs(fd, status);
    if (code == 0 && inject(Fault::UnsupportedFilesystem)) status->f_type = 0x6969; // NFS
    return code;
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    struct stat status{};
    const bool directory = ::fstat(fd, &status) == 0 && S_ISDIR(status.st_mode);
    if (activeProbe != nullptr && !directory) {
        activeProbe->temporaryPrivate = status.st_uid == ::geteuid()
            && (status.st_mode & 0777) == 0600 && S_ISREG(status.st_mode);
    }
    const bool published = activeProbe != nullptr && activeProbe->linked;
    if (inject(directory ? (published ? Fault::DirectorySyncAfter : Fault::DirectorySyncBefore)
                         : Fault::FileSync)) {
        errno = EIO;
        diagnosticMayThrow();
        return -1;
    }
    return __real_fsync(fd);
}
extern "C" int __real_linkat(int, const char*, int, const char*, int);
extern "C" int __wrap_linkat(int from, const char* oldName, int to, const char* newName, int flags)
{
    if (inject(Fault::Link)) {
        errno = EOPNOTSUPP;
        diagnosticMayThrow();
        return -1;
    }
    if (inject(Fault::DestinationRace)) {
        const int fd = ::openat(to, newName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        EXPECT_GE(fd, 0) << "Fictitious destination collision setup failed.";
        if (fd >= 0) {
            constexpr char marker[] = "external-test-file";
            EXPECT_TRUE(passwall::test_io::writeAll(fd, marker, sizeof(marker) - 1));
            EXPECT_EQ(::close(fd), 0);
        }
    }
    const int code = __real_linkat(from, oldName, to, newName, flags);
    if (activeProbe != nullptr && code == 0) activeProbe->linked = true;
    return code;
}
extern "C" int __real_unlinkat(int, const char*, int);
extern "C" int __wrap_unlinkat(int fd, const char* name, int flags)
{
    if (std::strcmp(name, "snapshot.pwdb") == 0 && inject(Fault::Cleanup)) {
        errno = EACCES;
        return -1;
    }
    return __real_unlinkat(fd, name, flags);
}

namespace {
using DatabasePtr = std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)>;

QByteArray fileBytes(const std::string& path)
{
    QFile file(QString::fromStdString(path));
    EXPECT_TRUE(file.open(QIODevice::ReadOnly));
    return file.readAll();
}

class VaultSnapshotServiceTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suite;
    static inline std::vector<Credential> entries;
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-snapshot-case-XXXXXX")};
    std::string source;
    std::string destination;
    SnapshotResult result;
    Probe probe;

    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        suite = std::make_unique<QTemporaryDir>(QStringLiteral("/tmp/passwall-snapshot-suite-XXXXXX"));
        ASSERT_TRUE(suite->isValid());
        SecureBuffer key(0);
        std::string error;
        const auto path = suite->filePath("template.pwdb").toStdString();
        ASSERT_TRUE(VaultLifecycleService::createVault(path, "fictitious-snapshot-master", key, error));
        for (int index = 0; index < 3; ++index) {
            Credential entry;
            entry.title = "Fictitious snapshot entry " + std::to_string(index);
            entry.url = "https://snapshot.example.test";
            entry.username = "fictitious-user";
            entry.password = "fictitious-password";
            entry.notes.assign(48 * 1024, static_cast<char>('a' + index));
            ASSERT_TRUE(CredentialService::add(path, key, entry, error));
            entries.push_back(std::move(entry));
        }
        // No decrypted key remains available to the snapshot calls below.
        key = SecureBuffer(0);
    }
    static void TearDownTestSuite()
    {
        for (auto& entry : entries) wipe(entry);
        entries.clear();
        suite.reset();
    }
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        source = directory.filePath("source.pwdb").toStdString();
        destination = directory.filePath("copy.pwdb").toStdString();
        ASSERT_TRUE(QFile::copy(suite->filePath("template.pwdb"), QString::fromStdString(source)));
    }
    void TearDown() override { EXPECT_TRUE(activeProbe == nullptr); }
    bool snapshot()
    {
        Scope scope(probe);
        return VaultSnapshotService::createSnapshot(source, destination, result);
    }
    void expectReleased()
    {
        EXPECT_EQ(probe.opened, probe.closed);
        EXPECT_EQ(probe.prepared, probe.finalized);
        EXPECT_EQ(probe.initialized, probe.finished);
        EXPECT_FALSE(probe.closeWithStatement);
        EXPECT_FALSE(probe.closeWithBackup);
        EXPECT_FALSE(probe.destinationUsedDuringBackup);
        EXPECT_EQ(probe.allocationsWhileUnwinding, 0);
    }
    void expectNoTemporary()
    {
        const auto names = QDir(directory.path()).entryList(QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot);
        for (const auto& name : names) EXPECT_FALSE(name.startsWith(".passwall-snapshot-"));
    }
    DatabasePtr open(const std::string& path)
    {
        sqlite3* database = nullptr;
        EXPECT_EQ(sqlite3_open_v2(path.c_str(), &database, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
        return DatabasePtr(database, sqlite3_close_v2);
    }
    void execute(const std::string& path, const char* sql)
    {
        auto database = open(path);
        ASSERT_NE(database, nullptr);
        ASSERT_EQ(sqlite3_exec(database.get(), sql, nullptr, nullptr, nullptr), SQLITE_OK);
    }
    void expectValidCopy()
    {
        passwall::services::VaultKeyMetadata before, after;
        std::string error;
        ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(source, before, error));
        ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(destination, after, error));
        EXPECT_TRUE(before.vaultId == after.vaultId && before.salt == after.salt
            && before.wrapNonce == after.wrapNonce && before.wrappedDek == after.wrappedDek
            && before.formatVersion == after.formatVersion
            && before.operationsLimit == after.operationsLimit && before.memoryLimit == after.memoryLimit);
        auto database = open(destination);
        ASSERT_NE(database, nullptr);
        sqlite3_stmt* raw = nullptr;
        const int prepared = sqlite3_prepare_v2(database.get(), "PRAGMA integrity_check;", -1, &raw, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(raw, sqlite3_finalize);
        ASSERT_EQ(prepared, SQLITE_OK);
        ASSERT_EQ(sqlite3_step(raw), SQLITE_ROW);
        const auto* value = sqlite3_column_text(raw, 0);
        EXPECT_TRUE(value != nullptr && std::strcmp(reinterpret_cast<const char*>(value), "ok") == 0);
        EXPECT_EQ(sqlite3_step(raw), SQLITE_DONE);
    }
    std::vector<std::array<QByteArray, 4>> encryptedRecords(const std::string& path)
    {
        auto database = open(path);
        sqlite3_stmt* raw = nullptr;
        const int prepared = sqlite3_prepare_v2(database.get(),
            "SELECT entry_id, entry_version, nonce, ciphertext FROM entries ORDER BY entry_id;",
            -1, &raw, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(raw, sqlite3_finalize);
        EXPECT_EQ(prepared, SQLITE_OK);
        std::vector<std::array<QByteArray, 4>> records;
        if (prepared != SQLITE_OK) return records;
        int code;
        while ((code = sqlite3_step(raw)) == SQLITE_ROW) {
            std::array<QByteArray, 4> record;
            for (int column = 0; column < 4; ++column) {
                if (column == 1) record[column] = QByteArray::number(sqlite3_column_int64(raw, column));
                else record[column] = QByteArray(static_cast<const char*>(sqlite3_column_blob(raw, column)),
                    sqlite3_column_bytes(raw, column));
            }
            records.push_back(std::move(record));
        }
        EXPECT_EQ(code, SQLITE_DONE);
        return records;
    }
};

TEST_F(VaultSnapshotServiceTest, KeylessSnapshotPreservesEncryptedRecordsAndReopensWithOriginalPassword)
{
    const auto before = fileBytes(source);
    ASSERT_TRUE(snapshot()) << result.diagnostic;
    EXPECT_EQ(result.publication, SnapshotPublication::Published);
    EXPECT_TRUE(result.diagnostic.empty());
    EXPECT_TRUE(probe.sourceReadOnly);
    EXPECT_EQ(probe.sourceFlags & SQLITE_OPEN_CREATE, 0);
    EXPECT_TRUE(probe.policyVerified);
    EXPECT_TRUE(probe.temporaryPrivate);
    EXPECT_TRUE(probe.stepCompleted);
    EXPECT_GT(probe.steps, 1);
    EXPECT_TRUE(fileBytes(source) == before);
    // SQLite may update internal header counters in the new database. Compare
    // the actual encrypted records, not a promise of whole-file byte identity.
    EXPECT_TRUE(encryptedRecords(destination) == encryptedRecords(source));
    struct stat a{}, b{};
    ASSERT_EQ(::stat(source.c_str(), &a), 0);
    ASSERT_EQ(::stat(destination.c_str(), &b), 0);
    EXPECT_TRUE(a.st_ino != b.st_ino || a.st_dev != b.st_dev);
    EXPECT_EQ(b.st_mode & 0777, 0600u);
    EXPECT_EQ(b.st_uid, ::geteuid());
    expectReleased();
    expectNoTemporary();
    expectValidCopy();
    SecureBuffer key(0);
    std::string error;
    ASSERT_TRUE(VaultLifecycleService::unlockVault(destination, "fictitious-snapshot-master", key, error));
    for (const auto& expected : entries) {
        Credential loaded;
        ASSERT_TRUE(CredentialService::get(destination, key, expected.id, loaded, error));
        EXPECT_TRUE(loaded.title == expected.title && loaded.username == expected.username
            && loaded.password == expected.password && loaded.notes == expected.notes
            && loaded.url == expected.url);
        wipe(loaded);
    }
}

TEST_F(VaultSnapshotServiceTest, SlowHealthyCopyHasNoGlobalDurationLimit)
{
    probe.simulateSlowCopy = true;
    bool success;
    SnapshotClock::duration simulatedElapsed;
    {
        Scope scope(probe);
        const auto start = SnapshotClock::now();
        success = VaultSnapshotService::createSnapshot(source, destination, result);
        simulatedElapsed = SnapshotClock::now() - start;
    }
    EXPECT_TRUE(success) << result.diagnostic;
    EXPECT_GE(simulatedElapsed, std::chrono::seconds(10));
    EXPECT_GT(probe.steps, 1);
    EXPECT_TRUE(probe.stepCompleted);
    EXPECT_EQ(result.publication, SnapshotPublication::Published);
    expectReleased();
    expectNoTemporary();
    if (success) {
        expectValidCopy();
        EXPECT_TRUE(encryptedRecords(destination) == encryptedRecords(source));
    }
}

TEST_F(VaultSnapshotServiceTest, RejectsExistingFilesSymlinksAndUnexpectedPathsWithoutChanges)
{
    const auto before = fileBytes(source);
    ASSERT_TRUE(QFile::copy(QString::fromStdString(source), QString::fromStdString(destination)));
    EXPECT_FALSE(snapshot());
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_TRUE(fileBytes(destination) == before);
    const auto existing = destination;
    destination = directory.filePath("linked.pwdb").toStdString();
    ASSERT_EQ(::symlink(existing.c_str(), destination.c_str()), 0);
    EXPECT_FALSE(snapshot());
    destination = directory.filePath("dangling.pwdb").toStdString();
    ASSERT_EQ(::symlink("missing.pwdb", destination.c_str()), 0);
    EXPECT_FALSE(snapshot());
    destination = existing + "-new";
    const auto validSource = source;
    source = directory.filePath("source-link").toStdString();
    ASSERT_EQ(::symlink(validSource.c_str(), source.c_str()), 0);
    EXPECT_FALSE(snapshot());
    source = validSource;
    for (const auto& path : {std::string("relative.pwdb"), directory.path().toStdString() + "/../bad.pwdb",
                            std::string("/tmp/bad\0suffix", 15)}) {
        destination = path;
        EXPECT_FALSE(snapshot());
    }
    EXPECT_TRUE(fileBytes(source) == before);
    expectNoTemporary();
}

TEST_F(VaultSnapshotServiceTest, RejectsSymlinkedAndWritableDestinationDirectories)
{
    const auto alias = directory.filePath("alias").toStdString();
    ASSERT_EQ(::symlink(directory.path().toStdString().c_str(), alias.c_str()), 0);
    destination = alias + "/copy.pwdb";
    EXPECT_FALSE(snapshot());
    ASSERT_TRUE(QDir(directory.path()).mkdir("writable"));
    const auto writable = directory.filePath("writable").toStdString();
    ASSERT_EQ(::chmod(writable.c_str(), 0777), 0);
    destination = writable + "/copy.pwdb";
    EXPECT_FALSE(snapshot());
    expectNoTemporary();
}

TEST_F(VaultSnapshotServiceTest, SourceMissingOrNonRegularIsNotCreatedOrRead)
{
    source += "-missing";
    EXPECT_FALSE(snapshot());
    EXPECT_FALSE(QFile::exists(QString::fromStdString(source)));
    ASSERT_EQ(::mkfifo(source.c_str(), 0600), 0);
    EXPECT_FALSE(snapshot()); // O_NONBLOCK ensures a FIFO cannot hang the engine.
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    expectNoTemporary();
}

TEST_F(VaultSnapshotServiceTest, DestinationCreatedAtPublicationIsNeverOverwritten)
{
    const auto before = fileBytes(source);
    probe.fault = Fault::DestinationRace;
    EXPECT_FALSE(snapshot());
    EXPECT_TRUE(probe.injected);
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_TRUE(fileBytes(destination) == "external-test-file");
    EXPECT_TRUE(fileBytes(source) == before);
    expectReleased();
    expectNoTemporary();
}

TEST_F(VaultSnapshotServiceTest, SqlAndPublicationFailuresCleanResourcesAndPreservePriorSnapshot)
{
    ASSERT_TRUE(snapshot()) << result.diagnostic;
    const auto previous = destination;
    const auto before = fileBytes(previous);
    const auto sourceBefore = fileBytes(source);
    int index = 0;
    for (const auto fault : {Fault::Open, Fault::Prepare, Fault::Init, Fault::StepIo,
                            Fault::Finish, Fault::Integrity, Fault::IntegrityResult,
                            Fault::UnsupportedFilesystem, Fault::FileSync,
                            Fault::DirectorySyncBefore, Fault::Link}) {
        SCOPED_TRACE(static_cast<int>(fault));
        probe = Probe{};
        probe.fault = fault;
        destination = directory.filePath("failed-" + QString::number(index++)).toStdString();
        EXPECT_FALSE(snapshot());
        EXPECT_TRUE(probe.injected);
        EXPECT_FALSE(result.diagnostic.empty());
        EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
        EXPECT_FALSE(QFile::exists(QString::fromStdString(destination)));
        EXPECT_TRUE(fileBytes(source) == sourceBefore);
        EXPECT_TRUE(fileBytes(previous) == before);
        expectReleased();
        expectNoTemporary();
    }
    probe = Probe{};
    ASSERT_TRUE(snapshot()); // A recoverable failure leaves no residual lock.
    expectValidCopy();
}

TEST_F(VaultSnapshotServiceTest, ExceptionsBeforeAndAfterPublicationRetainCorrectOutcomeAndReleaseResources)
{
    for (const auto fault : {Fault::Prepare, Fault::StepIo, Fault::Finish,
                            Fault::Integrity, Fault::FileSync, Fault::DirectorySyncAfter}) {
        probe = Probe{};
        probe.fault = fault;
        probe.throwDiagnostic = true;
        destination = directory.filePath("exception-" + QString::number(static_cast<int>(fault))).toStdString();
        EXPECT_THROW(snapshot(), std::bad_alloc);
        EXPECT_TRUE(probe.allocationFailed);
        const bool published = fault == Fault::DirectorySyncAfter;
        EXPECT_EQ(result.publication, published ? SnapshotPublication::PublishedDurabilityUnconfirmed
                                               : SnapshotPublication::NotPublished);
        EXPECT_EQ(QFile::exists(QString::fromStdString(destination)), published);
        expectReleased();
        expectNoTemporary();
        if (published) expectValidCopy();
    }
}

TEST_F(VaultSnapshotServiceTest, DirectorySyncFailureAfterPublicationPreservesFinalAndReportsUncertainty)
{
    probe.fault = Fault::DirectorySyncAfter;
    EXPECT_FALSE(snapshot());
    EXPECT_EQ(result.publication, SnapshotPublication::PublishedDurabilityUnconfirmed);
    EXPECT_FALSE(result.diagnostic.empty());
    EXPECT_TRUE(QFile::exists(QString::fromStdString(destination)));
    expectValidCopy();
    expectReleased();
    expectNoTemporary();
}

TEST_F(VaultSnapshotServiceTest, TemporaryCleanupWarningNeverRemovesPublishedFile)
{
    probe.fault = Fault::Cleanup;
    EXPECT_TRUE(snapshot());
    EXPECT_EQ(result.publication, SnapshotPublication::Published);
    EXPECT_FALSE(result.diagnostic.empty());
    expectValidCopy();
    expectReleased();
    expectNoTemporary(); // Destructor retries only its owned private staging.
}

TEST_F(VaultSnapshotServiceTest, BusyAndLockedCanRecoverButFinishOkWithoutDoneCannotPublish)
{
    for (const auto fault : {Fault::BusyOnce, Fault::LockedOnce}) {
        probe = Probe{};
        probe.fault = fault;
        destination = directory.filePath("retry-" + QString::number(static_cast<int>(fault))).toStdString();
        EXPECT_TRUE(snapshot());
        EXPECT_TRUE(probe.injected);
        EXPECT_TRUE(probe.stepCompleted);
        expectReleased();
        expectValidCopy();
    }
    probe = Probe{};
    probe.fault = Fault::PartialThenBusy;
    destination = directory.filePath("incomplete.pwdb").toStdString();
    EXPECT_FALSE(snapshot());
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_FALSE(probe.stepCompleted);
    EXPECT_EQ(probe.steps, 4); // One real partial step, then three BUSY results.
    EXPECT_EQ(probe.contentionReturns, 3);
    EXPECT_EQ(probe.finished, 1);
    EXPECT_EQ(probe.finishCode, SQLITE_OK); // Does not prove completion.
    EXPECT_FALSE(QFile::exists(QString::fromStdString(destination)));
    expectReleased();
    expectNoTemporary();
}

TEST_F(VaultSnapshotServiceTest, PersistentContentionStopsRetriesAndCleansUnpublishedSnapshot)
{
    const auto before = fileBytes(source);
    for (const auto fault : {Fault::BusyPersistent, Fault::LockedPersistent}) {
        SCOPED_TRACE(static_cast<int>(fault));
        probe = Probe{};
        probe.fault = fault;
        EXPECT_FALSE(snapshot());
        EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
        EXPECT_EQ(probe.steps, 3);
        EXPECT_EQ(probe.contentionReturns, 3);
        EXPECT_EQ(probe.finishCode, SQLITE_OK);
        EXPECT_NE(result.diagnostic.find("3 tentatives consécutives"), std::string::npos);
        const int code = fault == Fault::BusyPersistent ? SQLITE_BUSY : SQLITE_LOCKED;
        EXPECT_NE(result.diagnostic.find("primaire=" + std::to_string(code)), std::string::npos);
        EXPECT_FALSE(QFile::exists(QString::fromStdString(destination)));
        EXPECT_TRUE(fileBytes(source) == before);
        expectReleased();
        expectNoTemporary();
    }
    probe = Probe{};
    ASSERT_TRUE(snapshot()) << result.diagnostic;
    expectValidCopy();
}

TEST_F(VaultSnapshotServiceTest, SuccessfulStepsResetContentionWithoutGlobalRetryLimit)
{
    probe.fault = Fault::BusyBetweenProgress;
    ASSERT_TRUE(snapshot()) << result.diagnostic;
    EXPECT_TRUE(probe.injected);
    EXPECT_GT(probe.contentionReturns, 3); // Total failures are NOT the limit.
    EXPECT_TRUE(probe.stepCompleted);
    EXPECT_EQ(result.publication, SnapshotPublication::Published);
    expectReleased();
    expectNoTemporary();
    expectValidCopy();
    EXPECT_TRUE(encryptedRecords(destination) == encryptedRecords(source));
}

TEST_F(VaultSnapshotServiceTest, ConcurrentReaderAndCommittedWriterProduceOneCoherentSnapshot)
{
    auto reader = open(source);
    ASSERT_EQ(sqlite3_exec(reader.get(), "BEGIN; SELECT count(*) FROM entries;", nullptr, nullptr, nullptr), SQLITE_OK);
    ASSERT_TRUE(snapshot());
    ASSERT_EQ(sqlite3_exec(reader.get(), "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
    reader.reset();
    expectValidCopy();
    expectReleased();

    destination = directory.filePath("concurrent.pwdb").toStdString();
    probe = Probe{};
    probe.betweenSteps = [&] {
        // A real second connection commits BETWEEN incremental source reads.
        // Mutate ciphertext as opaque data; no key is available to this job.
        execute(source, "BEGIN IMMEDIATE; UPDATE entries SET ciphertext=zeroblob(length(ciphertext)); COMMIT;");
    };
    ASSERT_TRUE(snapshot());
    EXPECT_TRUE(probe.callbackRan);
    expectValidCopy();
    EXPECT_TRUE(encryptedRecords(destination) == encryptedRecords(source));
    expectReleased();
    expectNoTemporary();
    // Structural checks deliberately do NOT claim AEAD authentication.
    SecureBuffer key(0);
    std::string error;
    ASSERT_TRUE(VaultLifecycleService::unlockVault(destination, "fictitious-snapshot-master", key, error));
    Credential rejected;
    EXPECT_FALSE(CredentialService::get(destination, key, entries.front().id, rejected, error));
    wipe(rejected);
}

TEST_F(VaultSnapshotServiceTest, UncommittedWriterIsExcludedAndExclusiveContentionRecovers)
{
    const auto before = fileBytes(source);
    auto writer = open(source);
    ASSERT_EQ(sqlite3_exec(writer.get(),
        "BEGIN IMMEDIATE; UPDATE entries SET ciphertext=zeroblob(length(ciphertext));",
        nullptr, nullptr, nullptr), SQLITE_OK);
    ASSERT_TRUE(snapshot()) << result.diagnostic;
    // The reserved writer lock allows a read of the previously committed state.
    ASSERT_EQ(sqlite3_exec(writer.get(), "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
    EXPECT_TRUE(encryptedRecords(destination) == encryptedRecords(source));
    EXPECT_TRUE(fileBytes(source) == before);
    expectReleased();
    expectValidCopy();

    destination = directory.filePath("exclusive.pwdb").toStdString();
    probe = Probe{};
    ASSERT_EQ(sqlite3_exec(writer.get(), "BEGIN EXCLUSIVE;", nullptr, nullptr, nullptr), SQLITE_OK);
    EXPECT_FALSE(snapshot());
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_FALSE(result.diagnostic.empty());
    ASSERT_EQ(sqlite3_exec(writer.get(), "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
    writer.reset();
    expectReleased();
    expectNoTemporary();
    probe = Probe{};
    ASSERT_TRUE(snapshot()) << result.diagnostic;
    expectValidCopy();
}

TEST_F(VaultSnapshotServiceTest, WalRefusalDoesNotCheckpointOrConvertMainAndWal)
{
    {
        auto writer = open(source);
        ASSERT_EQ(sqlite3_db_config(writer.get(), SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(writer.get(), "PRAGMA journal_mode=WAL; UPDATE vault_metadata SET argon2_operations=4;",
            nullptr, nullptr, nullptr), SQLITE_OK);
    }
    const auto before = fileBytes(source);
    const auto wal = fileBytes(source + "-wal");
    ASSERT_GT(wal.size(), 32);
    EXPECT_FALSE(snapshot());
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_NE(result.diagnostic.find("journal_mode"), std::string::npos);
    EXPECT_EQ(probe.initialized, 0);
    EXPECT_TRUE(fileBytes(source) == before);
    EXPECT_TRUE(fileBytes(source + "-wal") == wal);
    expectReleased();
    expectNoTemporary(); // No assertion on SHM, per the validated V1 policy.
}

TEST_F(VaultSnapshotServiceTest, InvalidSchemaMetadataAndEntryFormatNeverPublish)
{
    int index = 0;
    for (const char* mutation : {
        "CREATE TABLE unexpected(value TEXT);",
        "CREATE VIEW unexpected AS SELECT * FROM entries;",
        "CREATE TRIGGER unexpected AFTER DELETE ON entries BEGIN SELECT 1; END;",
        "UPDATE vault_metadata SET format_version=2;",
        "UPDATE vault_metadata SET argon2_memory=1;",
        "DELETE FROM vault_metadata;",
        "UPDATE entries SET entry_version=2;",
        "UPDATE entries SET entry_id=NULL;"}) {
        const auto path = directory.filePath("invalid-" + QString::number(index++)).toStdString();
        ASSERT_TRUE(QFile::copy(suite->filePath("template.pwdb"), QString::fromStdString(path)));
        source = path;
        execute(source, mutation);
        const auto before = fileBytes(source);
        probe = Probe{};
        EXPECT_FALSE(snapshot());
        EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
        EXPECT_FALSE(QFile::exists(QString::fromStdString(destination)));
        EXPECT_TRUE(fileBytes(source) == before);
        expectReleased();
        expectNoTemporary();
    }
}

TEST_F(VaultSnapshotServiceTest, CancellationAtEveryPrepublicationCheckpointCleansResources)
{
    using passwall::services::SnapshotCheckpoint;
    for (auto checkpoint : {SnapshotCheckpoint::BeforeWork, SnapshotCheckpoint::CopyStep,
             SnapshotCheckpoint::BeforeValidation, SnapshotCheckpoint::BeforePublication}) {
        probe = Probe{};
        struct Context { SnapshotCheckpoint target; int calls = 0; } context{checkpoint};
        {
            Scope scope(probe);
            EXPECT_FALSE(VaultSnapshotService::createSnapshot(source, destination, result,
                {[](void* raw, SnapshotCheckpoint point) noexcept {
                    auto& state = *static_cast<Context*>(raw);
                    if (point != state.target) return false;
                    ++state.calls;
                    return true;
                }, &context}));
        }
        EXPECT_EQ(context.calls, 1);
        EXPECT_EQ(result.publication, SnapshotPublication::CancelledBeforePublication);
        EXPECT_FALSE(QFile::exists(QString::fromStdString(destination)));
        if (checkpoint == SnapshotCheckpoint::BeforePublication) {
            EXPECT_TRUE(probe.stepCompleted);
            EXPECT_FALSE(probe.linked);
        }
        expectReleased();
        expectNoTemporary();
    }
}

TEST_F(VaultSnapshotServiceTest, ReplacedSourceCannotBePublishedUnderItsPreviousIdentity)
{
    probe.betweenSteps = [&] {
        ASSERT_EQ(::rename(source.c_str(), (source + "-old").c_str()), 0);
        ASSERT_TRUE(QFile::copy(suite->filePath("template.pwdb"), QString::fromStdString(source)));
    };
    EXPECT_FALSE(snapshot());
    EXPECT_TRUE(probe.callbackRan);
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    EXPECT_FALSE(QFile::exists(QString::fromStdString(destination)));
    expectReleased();
    expectNoTemporary();
}
} // namespace
