#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_storage.hpp"
#include "storage/sqlite_connection_config.hpp"

#include <gtest/gtest.h>
#include <sqlite3.h>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

extern "C" int __real_sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __real_sqlite3_finalize(sqlite3_stmt*);
extern "C" int __real_sqlite3_db_config(sqlite3*, int, ...);

namespace {
using passwall::services::VaultKeyMetadata;
using passwall::services::VaultLifecycleService;
using passwall::storage::VaultStorage;

enum class Fault { None, Schema, Prepare, MissingMetadata, Commit, FileSync, DirectorySync, TemporaryUnlink };

struct ResourceProbe {
    Fault fault = Fault::None;
    bool throwOnDiagnostic = false;
    bool failNextAllocation = false;
    bool allocationFailed = false;
    bool faultInjected = false;
    int connections = 0;
    int closed = 0;
    int statements = 0;
    int businessStatements = 0;
    int configurationStatements = 0;
    int finalized = 0;
    int messages = 0;
    int freed = 0;
    int allocationsWhileUnwinding = 0;
    bool closeWithLiveStatement = false;
    bool closeWithTransaction = false;
    bool unlinkWithLiveConnection = false;
    void* message = nullptr;
    const char* replaceQuery = nullptr;
    const char* replacement = nullptr;
    const char* failSetting = nullptr;
    bool failPrepareConfiguration = false;
    bool throwConfigurationDiagnostic = false;
    bool configurationFaultInjected = false;
    int noCheckpointFault = 0; // setter error/value, getter error/value
    int noCheckpointCalls = 0;
    bool timeoutFailure = false;
    bool observePolicy = false;
    int protectedCloses = 0;
    int businessCalls = 0;
    bool businessWithoutPolicy = false;
    bool journalChangeRequested = false;
    int faultConnection = 0;
    const char* failStepQuery = nullptr;
    int failStepResult = SQLITE_ROW;
};

thread_local ResourceProbe* activeProbe = nullptr;

bool policyMatches(sqlite3* database) noexcept
{
    constexpr const char* queries[] = {"PRAGMA main.journal_mode;", "PRAGMA main.synchronous;",
        "PRAGMA main.secure_delete;", "PRAGMA temp_store;", "PRAGMA busy_timeout;"};
    constexpr int values[] = {0, 3, 1, 2, 3000};
    int enabled = 0;
    if (__real_sqlite3_db_config(database, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, -1, &enabled) != SQLITE_OK
        || enabled != 1)
        return false;
    for (int index = 0; index < 5; ++index) {
        sqlite3_stmt* statement = nullptr;
        bool valid = __real_sqlite3_prepare_v2(database, queries[index], -1, &statement, nullptr) == SQLITE_OK;
        valid = valid && __real_sqlite3_step(statement) == SQLITE_ROW;
        if (valid && index == 0) {
            const auto* value = sqlite3_column_text(statement, 0);
            valid = value != nullptr && sqlite3_column_bytes(statement, 0) == 6
                && std::memcmp(value, "delete", 6) == 0;
        } else if (valid) {
            valid = sqlite3_column_type(statement, 0) == SQLITE_INTEGER
                && sqlite3_column_int(statement, 0) == values[index];
        }
        const int finalized = __real_sqlite3_finalize(statement);
        if (!valid || finalized != SQLITE_OK)
            return false;
    }
    return true;
}

void observeBusiness(sqlite3* database, const char* sql) noexcept
{
    if (activeProbe != nullptr && std::strstr(sql, "PRAGMA") == nullptr) {
        ++activeProbe->businessCalls;
        if (activeProbe->observePolicy)
            activeProbe->businessWithoutPolicy |= !policyMatches(database);
    }
}

class ProbeScope {
public:
    explicit ProbeScope(ResourceProbe& probe) noexcept : previous_(activeProbe)
    {
        activeProbe = &probe;
    }
    ~ProbeScope() noexcept { activeProbe = previous_; }
    ProbeScope(const ProbeScope&) = delete;
    ProbeScope& operator=(const ProbeScope&) = delete;
private:
    ResourceProbe* previous_;
};

bool inject(Fault fault) noexcept
{
    if (activeProbe == nullptr || activeProbe->fault != fault || activeProbe->faultInjected)
        return false;
    activeProbe->faultInjected = true;
    return true;
}

bool configurationFaultApplies() noexcept
{
    return activeProbe != nullptr && (activeProbe->faultConnection == 0
        || activeProbe->connections == activeProbe->faultConnection);
}

void failDiagnosticAllocation() noexcept
{
    if (activeProbe != nullptr && activeProbe->throwOnDiagnostic)
        activeProbe->failNextAllocation = true;
}

void expectReleased(const ResourceProbe& probe)
{
    EXPECT_GT(probe.connections, 0);
    EXPECT_EQ(probe.closed, probe.connections);
    EXPECT_EQ(probe.finalized, probe.statements);
    EXPECT_EQ(probe.freed, probe.messages);
    EXPECT_FALSE(probe.closeWithLiveStatement);
    EXPECT_FALSE(probe.unlinkWithLiveConnection);
    EXPECT_EQ(probe.allocationsWhileUnwinding, 0);
}

void expectSameMetadata(const VaultKeyMetadata& actual, const VaultKeyMetadata& expected)
{
    EXPECT_EQ(actual.vaultId, expected.vaultId);
    EXPECT_EQ(actual.formatVersion, expected.formatVersion);
    EXPECT_EQ(actual.salt, expected.salt);
    EXPECT_EQ(actual.operationsLimit, expected.operationsLimit);
    EXPECT_EQ(actual.memoryLimit, expected.memoryLimit);
    EXPECT_EQ(actual.wrapNonce, expected.wrapNonce);
    EXPECT_EQ(actual.wrappedDek, expected.wrappedDek);
}

class VaultStorageResourcesTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    std::string path;
    std::string error;
    VaultKeyMetadata metadata;

    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        path = (directory.path() + "/fictional-vault.db").toStdString();
        metadata.vaultId.fill(0x31);
        metadata.salt.fill(0x42);
        metadata.wrapNonce.fill(0x53);
        metadata.wrappedDek.fill(0x64);
    }

    QStringList files() const
    {
        return QDir(directory.path()).entryList(QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot);
    }

    void expectWritable()
    {
        sqlite3* database = nullptr;
        ASSERT_EQ(sqlite3_open_v2(path.c_str(), &database, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
        const int begin = sqlite3_exec(database, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr);
        EXPECT_EQ(begin, SQLITE_OK);
        if (begin == SQLITE_OK)
            EXPECT_EQ(sqlite3_exec(database, "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
        EXPECT_EQ(sqlite3_close_v2(database), SQLITE_OK);
    }

    bool createVault(passwall::core::SecureBuffer& key)
    {
        return VaultLifecycleService::createVault(path, "Fictional-storage-test-password", key, error);
    }
};
} // namespace

// All wrappers are confined to passwall_storage_tests. No fault hooks or
// replacement allocator are linked into passwall_app or passwall_tests.
extern "C" void* realNew(std::size_t) asm("__real__Znwm");
extern "C" void* wrappedNew(std::size_t) asm("__wrap__Znwm");
extern "C" void* wrappedNew(std::size_t size)
{
    if (activeProbe != nullptr) {
        if (std::uncaught_exceptions() != 0)
            ++activeProbe->allocationsWhileUnwinding;
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
    const int result = __real_sqlite3_open_v2(path, database, flags, vfs);
    if (activeProbe != nullptr && *database != nullptr)
        ++activeProbe->connections;
    return result;
}

extern "C" int __real_sqlite3_close_v2(sqlite3*);
extern "C" int __wrap_sqlite3_close_v2(sqlite3* database)
{
    if (activeProbe != nullptr && database != nullptr) {
        activeProbe->closeWithLiveStatement |= sqlite3_next_stmt(database, nullptr) != nullptr;
        activeProbe->closeWithTransaction |= sqlite3_get_autocommit(database) == 0;
        if (activeProbe->observePolicy && policyMatches(database))
            ++activeProbe->protectedCloses;
    }
    const int result = __real_sqlite3_close_v2(database);
    if (activeProbe != nullptr && database != nullptr && result == SQLITE_OK)
        ++activeProbe->closed;
    return result;
}

extern "C" int __wrap_sqlite3_db_config(sqlite3* database, int option, ...)
{
    // Only NO_CKPT_ON_CLOSE is called by the sources linked into this target.
    if (option != SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
        return SQLITE_MISUSE;
    va_list arguments;
    va_start(arguments, option);
    const int value = va_arg(arguments, int);
    auto* applied = va_arg(arguments, int*);
    va_end(arguments);
    if (activeProbe != nullptr) {
        ++activeProbe->noCheckpointCalls;
        const int fault = activeProbe->noCheckpointFault;
        if ((value == 1 && fault == 1) || (value == -1 && fault == 3)) {
            activeProbe->configurationFaultInjected = true;
            return SQLITE_ERROR;
        }
        const int result = __real_sqlite3_db_config(database, option, value, applied);
        if ((value == 1 && fault == 2) || (value == -1 && fault == 4)) {
            activeProbe->configurationFaultInjected = true;
            *applied = 0;
        }
        return result;
    }
    return __real_sqlite3_db_config(database, option, value, applied);
}

extern "C" int __real_sqlite3_busy_timeout(sqlite3*, int);
extern "C" int __wrap_sqlite3_busy_timeout(sqlite3* database, int milliseconds)
{
    if (activeProbe != nullptr && activeProbe->timeoutFailure) {
        activeProbe->configurationFaultInjected = true;
        return SQLITE_NOMEM;
    }
    return __real_sqlite3_busy_timeout(database, milliseconds);
}

extern "C" int __real_sqlite3_prepare_v2(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
extern "C" int __wrap_sqlite3_prepare_v2(sqlite3* database, const char* sql, int size,
                                          sqlite3_stmt** statement, const char** tail)
{
    const bool configuration = std::strstr(sql, "PRAGMA") != nullptr;
    if (activeProbe != nullptr && std::strstr(sql, "journal_mode=") != nullptr)
        activeProbe->journalChangeRequested = true;
    observeBusiness(database, sql);
    const bool failure = !configuration && inject(Fault::Prepare);
    if (configurationFaultApplies() && activeProbe->replaceQuery != nullptr
        && std::strcmp(sql, activeProbe->replaceQuery) == 0) {
        activeProbe->configurationFaultInjected = true;
        sql = activeProbe->failPrepareConfiguration
            ? "SELECT * FROM passwall_injected_missing_table;" : activeProbe->replacement;
        if (activeProbe->throwConfigurationDiagnostic)
            activeProbe->failNextAllocation = true;
    }
    const int result = __real_sqlite3_prepare_v2(database,
        failure ? "SELECT * FROM passwall_injected_missing_table;" : sql,
        failure ? -1 : size, statement, tail);
    if (activeProbe != nullptr && *statement != nullptr) {
        ++activeProbe->statements;
        if (configuration)
            ++activeProbe->configurationStatements;
        else
            ++activeProbe->businessStatements;
    }
    return result;
}

extern "C" int __real_sqlite3_finalize(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_finalize(sqlite3_stmt* statement)
{
    if (activeProbe != nullptr && statement != nullptr)
        ++activeProbe->finalized;
    return __real_sqlite3_finalize(statement);
}

extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_step(sqlite3_stmt* statement)
{
    const int result = __real_sqlite3_step(statement);
    if (configurationFaultApplies() && activeProbe->failStepQuery != nullptr
        && std::strcmp(sqlite3_sql(statement), activeProbe->failStepQuery) == 0
        && result == activeProbe->failStepResult) {
        activeProbe->configurationFaultInjected = true;
        return SQLITE_IOERR;
    }
    if (result == SQLITE_DONE && sqlite3_stmt_readonly(statement)
        && std::strstr(sqlite3_sql(statement), "FROM vault_metadata") != nullptr
        && inject(Fault::MissingMetadata))
        failDiagnosticAllocation();
    return result;
}

extern "C" const char* __real_sqlite3_errmsg(sqlite3*);
extern "C" const char* __wrap_sqlite3_errmsg(sqlite3* database)
{
    const char* result = __real_sqlite3_errmsg(database);
    failDiagnosticAllocation();
    return result;
}

extern "C" int __real_sqlite3_exec(sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**);
extern "C" int __wrap_sqlite3_exec(sqlite3* database, const char* sql,
                                    int (*callback)(void*, int, char**, char**), void* context, char** message)
{
    observeBusiness(database, sql);
    if (activeProbe != nullptr && activeProbe->failSetting != nullptr
        && std::strcmp(sql, activeProbe->failSetting) == 0) {
        activeProbe->configurationFaultInjected = true;
        return SQLITE_ERROR;
    }
    const bool failure = (std::strstr(sql, "CREATE TABLE") != nullptr && inject(Fault::Schema))
        || (std::strcmp(sql, "COMMIT;") == 0 && inject(Fault::Commit));
    const int result = __real_sqlite3_exec(database,
        failure ? "SELECT * FROM passwall_injected_missing_table;" : sql,
        callback, context, message);
    if (activeProbe != nullptr && message != nullptr && *message != nullptr) {
        ++activeProbe->messages;
        activeProbe->message = *message;
        failDiagnosticAllocation();
    }
    return result;
}

extern "C" void __real_sqlite3_free(void*);
extern "C" void __wrap_sqlite3_free(void* memory)
{
    if (activeProbe != nullptr && memory != nullptr && memory == activeProbe->message) {
        ++activeProbe->freed;
        activeProbe->message = nullptr;
    }
    __real_sqlite3_free(memory);
}

extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    struct stat status{};
    const bool directory = ::fstat(fd, &status) == 0 && S_ISDIR(status.st_mode);
    if (inject(directory ? Fault::DirectorySync : Fault::FileSync)) {
        errno = EIO;
        failDiagnosticAllocation();
        return -1;
    }
    return __real_fsync(fd);
}

extern "C" int __real_unlink(const char*);
extern "C" int __wrap_unlink(const char* path)
{
    if (activeProbe != nullptr && activeProbe->connections != activeProbe->closed)
        activeProbe->unlinkWithLiveConnection = true;
    if (std::strstr(path, ".tmp-") != nullptr && inject(Fault::TemporaryUnlink)) {
        errno = EACCES;
        failDiagnosticAllocation();
        return -1;
    }
    return __real_unlink(path);
}

TEST_F(VaultStorageResourcesTest, NormalCreateWriteAndReadReleaseEveryResource)
{
    ResourceProbe probe;
    VaultKeyMetadata output;
    bool schema, written, read;
    {
        ProbeScope scope(probe);
        schema = VaultStorage::createSchema(path, error);
        written = VaultStorage::writeMetadata(path, metadata, error);
        read = VaultStorage::readMetadata(path, output, error);
    }
    ASSERT_TRUE(schema);
    ASSERT_TRUE(written) << error;
    ASSERT_TRUE(read) << error;
    EXPECT_EQ(probe.connections, 3);
    EXPECT_EQ(probe.businessStatements, 2);
    expectReleased(probe);
    expectSameMetadata(output, metadata);
    EXPECT_EQ(files().size(), 1);
}

TEST_F(VaultStorageResourcesTest, PrepareFailuresRollBackAndAllowRetry)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    for (const bool write : {true, false}) {
        ResourceProbe probe;
        probe.fault = Fault::Prepare;
        VaultKeyMetadata output;
        bool result;
        {
            ProbeScope scope(probe);
            result = write ? VaultStorage::writeMetadata(path, metadata, error)
                           : VaultStorage::readMetadata(path, output, error);
        }
        EXPECT_FALSE(result);
        EXPECT_FALSE(error.empty());
        EXPECT_TRUE(probe.faultInjected);
        expectReleased(probe);
        EXPECT_FALSE(probe.closeWithTransaction);
        expectWritable();
    }
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    VaultKeyMetadata output;
    ASSERT_TRUE(VaultStorage::readMetadata(path, output, error));
    expectSameMetadata(output, metadata);
}

TEST_F(VaultStorageResourcesTest, OpenDiagnosticExceptionClosesFailedConnection)
{
    const std::string missing = path + "/missing.db";
    ResourceProbe probe;
    probe.throwOnDiagnostic = true;
    bool caught = false;
    {
        ProbeScope scope(probe);
        VaultKeyMetadata output;
        try { (void)VaultStorage::readMetadata(missing, output, error); }
        catch (const std::bad_alloc&) { caught = true; }
    }
    EXPECT_TRUE(caught);
    EXPECT_TRUE(probe.allocationFailed);
    expectReleased(probe);
    EXPECT_TRUE(files().isEmpty());
    EXPECT_TRUE(VaultStorage::createSchema(path, error));
}

TEST_F(VaultStorageResourcesTest, PrepareDiagnosticExceptionsReleaseReadAndWriteConnections)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    for (const bool write : {true, false}) {
        ResourceProbe probe;
        probe.fault = Fault::Prepare;
        probe.throwOnDiagnostic = true;
        std::string diagnostic; // no spare capacity: assigning SQLite's error allocates
        VaultKeyMetadata output;
        bool caught = false;
        {
            ProbeScope scope(probe);
            try {
                if (write)
                    (void)VaultStorage::writeMetadata(path, metadata, diagnostic);
                else
                    (void)VaultStorage::readMetadata(path, output, diagnostic);
            } catch (const std::bad_alloc&) { caught = true; }
        }
        EXPECT_TRUE(caught);
        EXPECT_TRUE(probe.allocationFailed);
        expectReleased(probe);
        expectWritable();
    }
    EXPECT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
}

TEST_F(VaultStorageResourcesTest, ConstraintDiagnosticExceptionFinalizesBeforeCloseAndPreservesMetadata)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    VaultKeyMetadata replacement = metadata;
    replacement.vaultId.fill(0x99);
    ResourceProbe probe;
    probe.throwOnDiagnostic = true;
    bool caught = false;
    {
        ProbeScope scope(probe);
        try { (void)VaultStorage::writeMetadata(path, replacement, error); }
        catch (const std::bad_alloc&) { caught = true; }
    }
    EXPECT_TRUE(caught);
    EXPECT_TRUE(probe.allocationFailed);
    EXPECT_EQ(probe.businessStatements, 1);
    EXPECT_TRUE(probe.closeWithTransaction); // close must roll back the active transaction
    expectReleased(probe);
    expectWritable();
    VaultKeyMetadata output;
    ASSERT_TRUE(VaultStorage::readMetadata(path, output, error));
    expectSameMetadata(output, metadata);
    EXPECT_EQ(replacement.vaultId.front(), 0x99);
}

TEST_F(VaultStorageResourcesTest, MissingMetadataDiagnosticExceptionFinalizesReadStatement)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ResourceProbe probe;
    probe.fault = Fault::MissingMetadata;
    probe.throwOnDiagnostic = true;
    VaultKeyMetadata output = metadata;
    bool caught = false;
    {
        ProbeScope scope(probe);
        try { (void)VaultStorage::readMetadata(path, output, error); }
        catch (const std::bad_alloc&) { caught = true; }
    }
    EXPECT_TRUE(caught);
    EXPECT_TRUE(probe.allocationFailed);
    EXPECT_EQ(probe.businessStatements, 1);
    expectReleased(probe);
    expectSameMetadata(output, VaultKeyMetadata{});
    expectWritable();
    EXPECT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
}

TEST_F(VaultStorageResourcesTest, CommitDiagnosticExceptionRollsBackInsertedMetadata)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ResourceProbe probe;
    probe.fault = Fault::Commit;
    probe.throwOnDiagnostic = true;
    bool caught = false;
    {
        ProbeScope scope(probe);
        try { (void)VaultStorage::writeMetadata(path, metadata, error); }
        catch (const std::bad_alloc&) { caught = true; }
    }
    EXPECT_TRUE(caught);
    EXPECT_TRUE(probe.allocationFailed);
    EXPECT_EQ(probe.messages, 1);
    expectReleased(probe);
    expectWritable();
    VaultKeyMetadata output;
    EXPECT_FALSE(VaultStorage::readMetadata(path, output, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    ASSERT_TRUE(VaultStorage::readMetadata(path, output, error));
    expectSameMetadata(output, metadata);
}

TEST_F(VaultStorageResourcesTest, SchemaFailureAndDiagnosticExceptionRemoveOwnedFiles)
{
    for (const Fault fault : {Fault::Schema, Fault::Commit}) {
        for (const bool allocationFailure : {false, true}) {
            ResourceProbe probe;
            probe.fault = fault;
            probe.throwOnDiagnostic = allocationFailure;
            std::string diagnostic;
            bool result = false, caught = false;
            {
                ProbeScope scope(probe);
                try { result = VaultStorage::createSchema(path, diagnostic); }
                catch (const std::bad_alloc&) { caught = true; }
            }
            EXPECT_FALSE(result);
            EXPECT_EQ(caught, allocationFailure);
            EXPECT_EQ(probe.allocationFailed, allocationFailure);
            EXPECT_EQ(probe.messages, 1);
            expectReleased(probe);
            EXPECT_TRUE(files().isEmpty());
        }
    }
    EXPECT_TRUE(VaultStorage::createSchema(path, error));
}

TEST_F(VaultStorageResourcesTest, CreationMetadataFailureAndExceptionRemoveTemporaryVault)
{
    for (const bool allocationFailure : {false, true}) {
        ResourceProbe probe;
        probe.fault = Fault::Prepare;
        probe.throwOnDiagnostic = allocationFailure;
        std::string diagnostic;
        passwall::core::SecureBuffer key(0);
        bool result = false, caught = false;
        {
            ProbeScope scope(probe);
            try {
                result = VaultLifecycleService::createVault(
                    path, "Fictional-storage-test-password", key, diagnostic);
            } catch (const std::bad_alloc&) { caught = true; }
        }
        EXPECT_FALSE(result);
        EXPECT_EQ(caught, allocationFailure);
        EXPECT_EQ(probe.allocationFailed, allocationFailure);
        expectReleased(probe);
        EXPECT_TRUE(key.empty());
        EXPECT_TRUE(files().isEmpty());
    }
    passwall::core::SecureBuffer key(0);
    EXPECT_TRUE(createVault(key)) << error;
}

TEST_F(VaultStorageResourcesTest, PrepublicationSyncDiagnosticExceptionRemovesTemporaryVault)
{
    ResourceProbe probe;
    probe.fault = Fault::FileSync;
    probe.throwOnDiagnostic = true;
    passwall::core::SecureBuffer key(0);
    bool caught = false;
    {
        ProbeScope scope(probe);
        try { (void)createVault(key); }
        catch (const std::bad_alloc&) { caught = true; }
    }
    EXPECT_TRUE(caught);
    EXPECT_TRUE(probe.allocationFailed);
    expectReleased(probe);
    EXPECT_TRUE(key.empty());
    EXPECT_TRUE(files().isEmpty());
    EXPECT_TRUE(createVault(key)) << error;
}

TEST_F(VaultStorageResourcesTest, PublishedVaultSurvivesDirectorySyncFailureAndException)
{
    for (const bool allocationFailure : {false, true}) {
        const std::string finalPath = path + (allocationFailure ? "-exception" : "-error");
        ResourceProbe probe;
        probe.fault = Fault::DirectorySync;
        probe.throwOnDiagnostic = allocationFailure;
        std::string diagnostic;
        passwall::core::SecureBuffer key(0);
        bool result = false, caught = false;
        {
            ProbeScope scope(probe);
            try {
                result = VaultLifecycleService::createVault(
                    finalPath, "Fictional-storage-test-password", key, diagnostic);
            } catch (const std::bad_alloc&) { caught = true; }
        }
        EXPECT_FALSE(result);
        EXPECT_EQ(caught, allocationFailure);
        EXPECT_EQ(probe.allocationFailed, allocationFailure);
        expectReleased(probe);
        EXPECT_TRUE(key.empty());
        VaultKeyMetadata output;
        ASSERT_TRUE(VaultStorage::readMetadata(finalPath, output, error)) << error;
        EXPECT_TRUE(VaultLifecycleService::unlockVault(
            finalPath, "Fictional-storage-test-password", key, error)) << error;
        EXPECT_FALSE(key.empty());
    }
    EXPECT_EQ(files().size(), 2); // final files only, no temporary alias
}

TEST_F(VaultStorageResourcesTest, PublishedVaultSurvivesTemporaryUnlinkWarning)
{
    ResourceProbe probe;
    probe.fault = Fault::TemporaryUnlink;
    passwall::core::SecureBuffer key(0);
    bool result;
    {
        ProbeScope scope(probe);
        result = createVault(key);
    }
    EXPECT_TRUE(result);
    EXPECT_TRUE(probe.faultInjected);
    EXPECT_FALSE(error.empty());
    expectReleased(probe);
    EXPECT_FALSE(key.empty());
    VaultKeyMetadata output;
    EXPECT_TRUE(VaultStorage::readMetadata(path, output, error));
    EXPECT_EQ(files().size(), 2); // existing contract: success plus temporary-name warning
}

namespace {
using passwall::services::CredentialService;
using passwall::storage::configureSqliteConnection;
using TestDatabase = std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)>;

std::string fileBytes(const std::string& path)
{
    QFile file(QString::fromStdString(path));
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return file.readAll().toStdString();
}

passwall::models::Credential configurationTestCredential()
{
    passwall::models::Credential entry;
    entry.id.fill(0x75);
    entry.title = "Fictional configuration entry";
    entry.username = "fictional-configuration-user";
    entry.password = "fictional-configuration-password";
    entry.notes = "Fictional configuration notes";
    return entry;
}
} // namespace

TEST_F(VaultStorageResourcesTest, V1PolicyIsEffectiveBeforeEveryProductionBusinessPath)
{
    ResourceProbe probe;
    probe.observePolicy = true;
    passwall::core::SecureBuffer key(0), reopened(0);
    auto entry = configurationTestCredential();
    passwall::models::Credential loaded;
    std::vector<passwall::models::Credential> entries;
    std::vector<passwall::models::CredentialSummary> summaries;
    {
        ProbeScope scope(probe);
        ASSERT_TRUE(createVault(key)) << error;
        ASSERT_TRUE(VaultLifecycleService::unlockVault(
            path, "Fictional-storage-test-password", reopened, error)) << error;
        ASSERT_TRUE(CredentialService::add(path, key, entry, error)) << error;
        ASSERT_TRUE(CredentialService::get(path, key, entry.id, loaded, error)) << error;
        ASSERT_TRUE(CredentialService::list(path, key, entries, error)) << error;
        ASSERT_TRUE(CredentialService::listSummaries(path, key, summaries, error)) << error;
        entry.title = "Fictional modified entry";
        ASSERT_TRUE(CredentialService::update(path, key, entry, error)) << error;
        ASSERT_TRUE(CredentialService::remove(path, key, entry.id, error)) << error;
    }
    EXPECT_EQ(probe.connections, 15); // schema, metadata, unlock, then six two-connection operations
    EXPECT_EQ(probe.protectedCloses, probe.connections);
    EXPECT_GT(probe.businessCalls, 0);
    EXPECT_FALSE(probe.businessWithoutPolicy);
    expectReleased(probe);
}

TEST_F(VaultStorageResourcesTest, V1PolicyIsReappliedRatherThanInheritedOnReopen)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    for (int attempt = 0; attempt < 2; ++attempt) {
        sqlite3* raw = nullptr;
        ASSERT_EQ(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
        TestDatabase database(raw, sqlite3_close_v2);
        ASSERT_EQ(sqlite3_exec(raw, "PRAGMA synchronous=OFF; PRAGMA secure_delete=OFF;"
                                   "PRAGMA temp_store=FILE; PRAGMA busy_timeout=1;",
                              nullptr, nullptr, nullptr), SQLITE_OK);
        EXPECT_FALSE(policyMatches(raw));
        ASSERT_TRUE(configureSqliteConnection(raw, error)) << error;
        EXPECT_TRUE(policyMatches(raw));
    }
}

TEST_F(VaultStorageResourcesTest, V1RefusesEveryNoCheckpointActivationAndVerificationFailureBeforePragmas)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    const auto before = fileBytes(path);
    for (int fault = 1; fault <= 4; ++fault) {
        ResourceProbe probe;
        probe.noCheckpointFault = fault;
        VaultKeyMetadata output;
        bool result;
        {
            ProbeScope scope(probe);
            result = VaultStorage::readMetadata(path, output, error);
        }
        EXPECT_FALSE(result);
        EXPECT_NE(error.find("NO_CKPT_ON_CLOSE"), std::string::npos);
        EXPECT_TRUE(probe.configurationFaultInjected);
        EXPECT_EQ(probe.noCheckpointCalls, fault <= 2 ? 1 : 2);
        EXPECT_EQ(probe.configurationStatements, 0);
        EXPECT_EQ(probe.businessCalls, 0);
        expectReleased(probe);
        EXPECT_TRUE(fileBytes(path) == before);
    }
    VaultKeyMetadata output;
    EXPECT_TRUE(VaultStorage::readMetadata(path, output, error));
}

TEST_F(VaultStorageResourcesTest, V1RefusesUnexpectedOrUnverifiablePragmaValuesWithoutWriting)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    const auto before = fileBytes(path);
    struct Case { const char* query; const char* replacement; const char* parameter; };
    const Case cases[] = {
        {"PRAGMA main.journal_mode;", "SELECT 'wal';", "journal_mode"},
        {"PRAGMA main.journal_mode;", "SELECT 'persist';", "journal_mode"},
        {"PRAGMA main.journal_mode;", "SELECT 'off';", "journal_mode"},
        {"PRAGMA main.journal_mode;", "SELECT 'memory';", "journal_mode"},
        {"PRAGMA main.journal_mode;", "SELECT 'delete' WHERE 0;", "journal_mode"},
        {"PRAGMA main.journal_mode;", "SELECT 1;", "journal_mode"},
        {"PRAGMA main.journal_mode;", "SELECT 'delete' UNION ALL SELECT 'delete';", "journal_mode"},
        {"PRAGMA main.synchronous;", "SELECT 2;", "synchronous"},
        {"PRAGMA main.synchronous;", "SELECT '3';", "synchronous"},
        {"PRAGMA main.synchronous;", "SELECT 3 WHERE 0;", "synchronous"},
        {"PRAGMA main.synchronous;", "SELECT 3 UNION ALL SELECT 3;", "synchronous"},
        {"PRAGMA main.secure_delete;", "SELECT 0;", "secure_delete"},
        {"PRAGMA temp_store;", "SELECT 1;", "temp_store"},
        {"PRAGMA busy_timeout;", "SELECT 0;", "busy_timeout"},
        {"PRAGMA compile_options;", "SELECT 'TEMP_STORE=0';", "temp_store"},
        {"PRAGMA compile_options;", "SELECT 'TEMP_STORE=4';", "temp_store"},
        {"PRAGMA compile_options;", "SELECT 'TEMP_STORE=10';", "temp_store"},
        {"PRAGMA compile_options;", "SELECT 'THREADSAFE=1';", "temp_store"},
        {"PRAGMA compile_options;", "SELECT 'TEMP_STORE=1' WHERE 0;", "temp_store"},
        {"PRAGMA compile_options;", "SELECT 1;", "temp_store"},
        {"PRAGMA compile_options;", "SELECT 'TEMP_STORE=1' UNION ALL SELECT 'TEMP_STORE=2';", "temp_store"}
    };
    for (const auto& test : cases) {
        SCOPED_TRACE(test.query);
        ResourceProbe probe;
        probe.replaceQuery = test.query;
        probe.replacement = test.replacement;
        VaultKeyMetadata output;
        bool result;
        {
            ProbeScope scope(probe);
            result = VaultStorage::readMetadata(path, output, error);
        }
        EXPECT_FALSE(result);
        EXPECT_NE(error.find(test.parameter), std::string::npos);
        EXPECT_TRUE(probe.configurationFaultInjected);
        EXPECT_EQ(probe.businessCalls, 0);
        EXPECT_FALSE(probe.journalChangeRequested);
        expectReleased(probe);
        EXPECT_TRUE(fileBytes(path) == before);
    }
    VaultKeyMetadata output;
    ASSERT_TRUE(VaultStorage::readMetadata(path, output, error));
    expectSameMetadata(output, metadata);
}

TEST_F(VaultStorageResourcesTest, V1AcceptsEachVerifiableMemoryCompatibleCompileOption)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    for (const char* option : {"SELECT 'TEMP_STORE=1';", "SELECT 'TEMP_STORE=2';", "SELECT 'TEMP_STORE=3';"}) {
        ResourceProbe probe;
        probe.replaceQuery = "PRAGMA compile_options;";
        probe.replacement = option;
        VaultKeyMetadata output;
        bool result;
        {
            ProbeScope scope(probe);
            result = VaultStorage::readMetadata(path, output, error);
        }
        EXPECT_TRUE(result) << error;
        expectReleased(probe);
    }
}

TEST_F(VaultStorageResourcesTest, V1ConfigurationApiAndSqlErrorsReleaseConnectionsAndPermitRetry)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    const auto before = fileBytes(path);
    struct Case { const char* setting; const char* query; const char* parameter; };
    const Case cases[] = {
        {"PRAGMA main.synchronous=EXTRA;", "PRAGMA main.synchronous;", "synchronous"},
        {"PRAGMA main.secure_delete=ON;", "PRAGMA main.secure_delete;", "secure_delete"},
        {"PRAGMA temp_store=MEMORY;", "PRAGMA temp_store;", "temp_store"},
        {nullptr, "PRAGMA main.journal_mode;", "journal_mode"},
        {nullptr, "PRAGMA compile_options;", "temp_store"},
        {nullptr, "PRAGMA busy_timeout;", "busy_timeout"}
    };
    for (const auto& test : cases) {
        for (const bool preparationFailure : {false, true}) {
            ResourceProbe probe;
            if (preparationFailure) {
                probe.replaceQuery = test.query;
                probe.failPrepareConfiguration = true;
            } else if (test.setting != nullptr) {
                probe.failSetting = test.setting;
            } else {
                continue;
            }
            VaultKeyMetadata output;
            bool result;
            {
                ProbeScope scope(probe);
                result = VaultStorage::readMetadata(path, output, error);
            }
            EXPECT_FALSE(result);
            EXPECT_NE(error.find(test.parameter), std::string::npos);
            EXPECT_TRUE(probe.configurationFaultInjected);
            EXPECT_EQ(probe.businessCalls, 0);
            expectReleased(probe);
            EXPECT_TRUE(fileBytes(path) == before);
        }
    }
    ResourceProbe probe;
    probe.timeoutFailure = true;
    VaultKeyMetadata output;
    bool result;
    {
        ProbeScope scope(probe);
        result = VaultStorage::readMetadata(path, output, error);
    }
    EXPECT_FALSE(result);
    EXPECT_NE(error.find("busy_timeout"), std::string::npos);
    EXPECT_TRUE(probe.configurationFaultInjected);
    EXPECT_EQ(probe.businessCalls, 0);
    expectReleased(probe);
    EXPECT_TRUE(fileBytes(path) == before);
    EXPECT_TRUE(VaultStorage::readMetadata(path, output, error));
}

TEST_F(VaultStorageResourcesTest, V1ConfigurationDiagnosticExceptionFinalizesBeforeClosing)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    const auto before = fileBytes(path);
    ResourceProbe probe;
    probe.replaceQuery = "PRAGMA main.synchronous;";
    probe.replacement = "SELECT 2;";
    probe.throwConfigurationDiagnostic = true;
    bool caught = false;
    VaultKeyMetadata output;
    {
        ProbeScope scope(probe);
        try { (void)VaultStorage::readMetadata(path, output, error); }
        catch (const std::bad_alloc&) { caught = true; }
    }
    EXPECT_TRUE(caught);
    EXPECT_TRUE(probe.allocationFailed);
    EXPECT_EQ(probe.businessCalls, 0);
    expectReleased(probe);
    EXPECT_TRUE(fileBytes(path) == before);
    expectWritable();
    EXPECT_TRUE(VaultStorage::readMetadata(path, output, error));
}

TEST_F(VaultStorageResourcesTest, V1PragmaStepAndEndErrorsRefuseBusinessAndReleaseStatements)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    const auto before = fileBytes(path);
    for (const int resultToFail : {SQLITE_ROW, SQLITE_DONE}) {
        ResourceProbe probe;
        probe.failStepQuery = "PRAGMA main.synchronous;";
        probe.failStepResult = resultToFail;
        VaultKeyMetadata output;
        bool result;
        {
            ProbeScope scope(probe);
            result = VaultStorage::readMetadata(path, output, error);
        }
        EXPECT_FALSE(result);
        EXPECT_TRUE(probe.configurationFaultInjected);
        EXPECT_NE(error.find("synchronous"), std::string::npos);
        EXPECT_EQ(probe.businessCalls, 0);
        expectReleased(probe);
        EXPECT_TRUE(fileBytes(path) == before);
    }
    VaultKeyMetadata output;
    EXPECT_TRUE(VaultStorage::readMetadata(path, output, error));
}

TEST_F(VaultStorageResourcesTest, V1CredentialConnectionConfigurationFailureStopsCrudAndReads)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    passwall::core::SecureBuffer key(passwall::core::KeySize);
    auto entry = configurationTestCredential();
    ASSERT_TRUE(CredentialService::add(path, key, entry, error));
    const auto before = fileBytes(path);
    for (int operation = 0; operation < 6; ++operation) {
        ResourceProbe probe;
        probe.replaceQuery = "PRAGMA main.synchronous;";
        probe.replacement = "SELECT 2;";
        probe.faultConnection = 2; // metadata connection succeeds, credential connection fails
        auto added = configurationTestCredential();
        passwall::models::Credential loaded;
        std::vector<passwall::models::Credential> entries;
        std::vector<passwall::models::CredentialSummary> summaries;
        bool result = true;
        {
            ProbeScope scope(probe);
            switch (operation) {
            case 0: result = CredentialService::add(path, key, added, error); break;
            case 1: result = CredentialService::update(path, key, entry, error); break;
            case 2: result = CredentialService::remove(path, key, entry.id, error); break;
            case 3: result = CredentialService::get(path, key, entry.id, loaded, error); break;
            case 4: result = CredentialService::list(path, key, entries, error); break;
            case 5: result = CredentialService::listSummaries(path, key, summaries, error); break;
            }
        }
        EXPECT_FALSE(result);
        EXPECT_TRUE(probe.configurationFaultInjected);
        EXPECT_NE(error.find("synchronous"), std::string::npos);
        EXPECT_EQ(probe.connections, 2);
        EXPECT_EQ(probe.businessCalls, 1); // only the successfully configured metadata SELECT
        expectReleased(probe);
        EXPECT_TRUE(fileBytes(path) == before);
        EXPECT_TRUE(loaded.password.empty());
        EXPECT_TRUE(loaded.notes.empty());
        EXPECT_TRUE(entries.empty());
        EXPECT_TRUE(summaries.empty());
        EXPECT_TRUE(CredentialService::get(path, key, entry.id, loaded, error));
    }
    entry.title = "Valid update after configuration refusal";
    EXPECT_TRUE(CredentialService::update(path, key, entry, error));
    EXPECT_TRUE(CredentialService::remove(path, key, entry.id, error));
}

TEST_F(VaultStorageResourcesTest, V1NewFileRequiresVerifiedDeleteInitializationAndCleansFailures)
{
    ResourceProbe probe;
    probe.replaceQuery = "PRAGMA main.journal_mode=DELETE;";
    probe.replacement = "SELECT 'wal';";
    bool result;
    {
        ProbeScope scope(probe);
        result = VaultStorage::createSchema(path, error);
    }
    EXPECT_FALSE(result);
    EXPECT_NE(error.find("journal_mode"), std::string::npos);
    EXPECT_TRUE(probe.journalChangeRequested);
    EXPECT_EQ(probe.businessCalls, 0);
    expectReleased(probe);
    EXPECT_TRUE(files().isEmpty());
    EXPECT_TRUE(VaultStorage::createSchema(path, error));
}

TEST_F(VaultStorageResourcesTest, V1RefusesToConfigureInsideTransaction)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    sqlite3* raw = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    TestDatabase database(raw, sqlite3_close_v2);
    ASSERT_EQ(sqlite3_exec(raw, "BEGIN;", nullptr, nullptr, nullptr), SQLITE_OK);
    EXPECT_FALSE(configureSqliteConnection(raw, error));
    EXPECT_NE(error.find("transaction"), std::string::npos);
    EXPECT_EQ(sqlite3_get_autocommit(raw), 0);
    EXPECT_EQ(sqlite3_exec(raw, "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
    EXPECT_TRUE(configureSqliteConnection(raw, error));
}

TEST_F(VaultStorageResourcesTest, V1WalRefusalPreservesDatabaseAndUncheckpointedWalForEveryService)
{
    ASSERT_TRUE(VaultStorage::createSchema(path, error));
    ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
    sqlite3* raw = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    {
        TestDatabase fixture(raw, sqlite3_close_v2);
        ASSERT_EQ(sqlite3_db_config(raw, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(raw, "PRAGMA journal_mode=WAL;"
                                   "UPDATE vault_metadata SET argon2_operations=4;",
                              nullptr, nullptr, nullptr), SQLITE_OK);
    } // no remaining connection: a refusal must not checkpoint on its own close
    const auto beforeMain = fileBytes(path);
    const auto beforeWal = fileBytes(path + "-wal");
    ASSERT_FALSE(beforeMain.empty());
    ASSERT_GT(beforeWal.size(), 32U);
    // If protection itself fails, no journal inspection may initialize the WAL
    // pager. Exercise this with no other open connection, not just in DELETE.
    for (int fault = 1; fault <= 4; ++fault) {
        ResourceProbe failure;
        failure.noCheckpointFault = fault;
        VaultKeyMetadata rejected;
        bool result;
        {
            ProbeScope scope(failure);
            result = VaultStorage::readMetadata(path, rejected, error);
        }
        EXPECT_FALSE(result);
        EXPECT_NE(error.find("NO_CKPT_ON_CLOSE"), std::string::npos);
        EXPECT_EQ(failure.configurationStatements, 0);
        EXPECT_EQ(failure.businessCalls, 0);
        expectReleased(failure);
        EXPECT_TRUE(fileBytes(path) == beforeMain);
        EXPECT_TRUE(fileBytes(path + "-wal") == beforeWal);
    }
    passwall::core::SecureBuffer key(passwall::core::KeySize), unlocked(0);
    auto entry = configurationTestCredential();
    passwall::models::Credential loaded;
    VaultKeyMetadata output;
    std::vector<passwall::models::Credential> entries;
    std::vector<passwall::models::CredentialSummary> summaries;
    ResourceProbe probe;
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(VaultStorage::readMetadata(path, output, error));
        EXPECT_FALSE(VaultStorage::writeMetadata(path, metadata, error));
        EXPECT_FALSE(VaultLifecycleService::unlockVault(path, "Fictional-password", unlocked, error));
        EXPECT_FALSE(CredentialService::add(path, key, entry, error));
        EXPECT_FALSE(CredentialService::get(path, key, entry.id, loaded, error));
        EXPECT_FALSE(CredentialService::list(path, key, entries, error));
        EXPECT_FALSE(CredentialService::listSummaries(path, key, summaries, error));
        EXPECT_FALSE(CredentialService::update(path, key, entry, error));
        EXPECT_FALSE(CredentialService::remove(path, key, entry.id, error));
    }
    EXPECT_NE(error.find("journal_mode"), std::string::npos);
    EXPECT_EQ(probe.connections, 9);
    EXPECT_EQ(probe.businessCalls, 0);
    EXPECT_FALSE(probe.journalChangeRequested);
    expectReleased(probe);
    EXPECT_TRUE(unlocked.empty());
    EXPECT_TRUE(fileBytes(path) == beforeMain);
    EXPECT_TRUE(fileBytes(path + "-wal") == beforeWal);
    EXPECT_TRUE(QFile::exists(QString::fromStdString(path + "-shm")));
    // Deliberately no equality assertion on SHM: SQLite may rebuild its index.
    ASSERT_EQ(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);
    TestDatabase verification(raw, sqlite3_close_v2);
    ASSERT_EQ(sqlite3_db_config(raw, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, nullptr), SQLITE_OK);
    sqlite3_stmt* statement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(raw, "PRAGMA main.journal_mode;", -1, &statement, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(statement), SQLITE_ROW);
    EXPECT_STREQ(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)), "wal");
    EXPECT_EQ(sqlite3_finalize(statement), SQLITE_OK);
}
