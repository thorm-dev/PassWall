#include "models/credential.hpp"
#include "services/credential_service.hpp"
#include "services/vault_lifecycle_service.hpp"

#include <gtest/gtest.h>
#include <sodium.h>
#include <sqlite3.h>

#include <QFile>
#include <QTemporaryDir>

#include <array>
#include <chrono>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <memory>
#include <new>
#include <string>

namespace {
using passwall::core::SecureBuffer;
using passwall::models::Credential;
using passwall::services::CredentialService;

constexpr std::size_t PasswordField = 3;
constexpr std::size_t NotesField = 4;

std::array<const std::string*, 5> fields(const Credential& credential) noexcept
{
    return {&credential.title, &credential.url, &credential.username,
            &credential.password, &credential.notes};
}

void wipeTestCredential(Credential& credential) noexcept
{
    for (auto* field : {&credential.title, &credential.url, &credential.username,
                        &credential.password, &credential.notes}) {
        sodium_memzero(field->data(), field->size());
        field->clear();
    }
}

bool sameCredential(const Credential& first, const Credential& second,
                    bool compareMetadata = true)
{
    return (!compareMetadata || (first.id == second.id && first.version == second.version))
        && first.title == second.title && first.url == second.url
        && first.username == second.username && first.password == second.password
        && first.notes == second.notes;
}

bool allZero(const void* memory, std::size_t size) noexcept
{
    const auto* bytes = static_cast<const unsigned char*>(memory);
    for (std::size_t index = 0; index < size; ++index)
        if (bytes[index] != 0)
            return false;
    return true;
}

enum class CommitBehavior { Normal, ReturnError, Throw };
struct CommitFailure {};

enum class TransactionFault {
    None, BeginBusy, BeginUnconfirmed, CommitActive, CommitEnded,
    CommitPersistedButError, RollbackFailure, RollbackUnconfirmed,
    UnknownState, CommitUnconfirmed, StatementError, StatementAutoRollback
};
enum class TransactionPhase { None, Begin, Statement, Commit, Rollback };

struct StringAllocation {
    void* memory = nullptr;
    std::size_t size = 0;
    std::size_t group = 0;
    std::size_t field = 0;
    bool zeroed = false;
    bool zeroedWhileUnwinding = false;
};

struct PlaintextAllocation {
    void* memory = nullptr;
    std::size_t size = 0;
    bool initialized = false;
    bool containedEntry = false;
    bool zeroed = false;
};

struct MemoryProbe {
    // Références à des données fictives de tailles toutes distinctes. Aucun
    // secret n'est recopié dans les observations, uniquement des adresses et
    // booléens. Les tailles servent à cibler les allocations de cette libstdc++.
    std::array<const Credential*, 2> sources{};
    std::array<StringAllocation, 16> strings{};
    std::array<PlaintextAllocation, 4> plaintexts{};
    std::size_t stringCount = 0;
    std::size_t plaintextCount = 0;
    int failNotesGroup = -1;
    CommitBehavior commitBehavior = CommitBehavior::Normal;
    bool allocationFailureInjected = false;
    bool passwordCopiedBeforeFailure = false;
    bool commitFaultInjected = false;
    bool writePendingAtCommit = false;
    bool copiesZeroedAtCommit = false;
    bool overflow = false;
    TransactionFault transactionFault = TransactionFault::None;
    TransactionPhase phase = TransactionPhase::None;
    sqlite3* transactionDatabase = nullptr;
    int injectedExtended = -1;
    int rollbackCalls = 0;
    int commitCalls = 0;
    int writeSteps = 0;
    bool transactionFaultInjected = false;
    bool closed = false;
    bool closeWithStatements = false;
    bool activeAtClose = false;

    bool allStringsZeroed() const noexcept
    {
        for (std::size_t index = 0; index < stringCount; ++index)
            if (!strings[index].zeroed)
                return false;
        return true;
    }

    std::size_t stringsInGroup(std::size_t group) const noexcept
    {
        std::size_t count = 0;
        for (std::size_t index = 0; index < stringCount; ++index)
            if (strings[index].group == group)
                ++count;
        return count;
    }
};

thread_local MemoryProbe* activeProbe = nullptr;

class ProbeScope final {
public:
    explicit ProbeScope(MemoryProbe& probe) noexcept : previous_(activeProbe)
    {
        activeProbe = &probe;
    }
    ~ProbeScope() { activeProbe = previous_; }
    ProbeScope(const ProbeScope&) = delete;
    ProbeScope& operator=(const ProbeScope&) = delete;
private:
    MemoryProbe* previous_;
};

template<typename Operation>
bool withProbe(MemoryProbe& probe, Operation&& operation)
{
    ProbeScope scope(probe);
    return operation();
}
} // namespace

// Tous ces wrappers sont liés UNIQUEMENT dans passwall_tests. Le chemin
// normal appelle les vraies fonctions ; aucune interface de production changée.
extern "C" void* realNew(std::size_t) asm("__real__Znwm");
extern "C" void* wrappedNew(std::size_t) asm("__wrap__Znwm");
extern "C" void* wrappedNew(std::size_t size)
{
    if (activeProbe != nullptr) {
        auto& probe = *activeProbe;
        for (std::size_t group = 0; group < probe.sources.size(); ++group) {
            if (probe.sources[group] == nullptr)
                continue;
            const auto sourceFields = fields(*probe.sources[group]);
            for (std::size_t field = 0; field < sourceFields.size(); ++field) {
                if (size != sourceFields[field]->size() + 1)
                    continue;
                if (field == NotesField && probe.failNotesGroup == static_cast<int>(group)) {
                    probe.failNotesGroup = -1;
                    probe.allocationFailureInjected = true;
                    for (std::size_t index = 0; index < probe.stringCount; ++index) {
                        const auto& allocation = probe.strings[index];
                        if (allocation.group == group && allocation.field == PasswordField
                            && !allocation.zeroed) {
                            // Le buffer est encore vivant à cet instant précis.
                            probe.passwordCopiedBeforeFailure = std::memcmp(
                                allocation.memory, sourceFields[PasswordField]->data(),
                                allocation.size) == 0;
                        }
                    }
                    throw std::bad_alloc{};
                }
                void* memory = realNew(size);
                if (probe.stringCount < probe.strings.size())
                    probe.strings[probe.stringCount++] =
                        {memory, size - 1, group, field};
                else
                    probe.overflow = true;
                return memory;
            }
        }
    }
    return realNew(size);
}

extern "C" void* __real_sodium_malloc(std::size_t);
extern "C" void* __wrap_sodium_malloc(std::size_t size)
{
    void* memory = __real_sodium_malloc(size);
    if (activeProbe != nullptr && memory != nullptr) {
        auto& probe = *activeProbe;
        for (const auto* source : probe.sources) {
            if (source == nullptr)
                continue;
            std::size_t plaintextSize = 4 + 5 * 4; // En-tête PWC1 existant.
            for (const auto* field : fields(*source))
                plaintextSize += field->size();
            if (size != plaintextSize)
                continue;
            if (probe.plaintextCount < probe.plaintexts.size())
                probe.plaintexts[probe.plaintextCount++] = {memory, size};
            else
                probe.overflow = true;
            break;
        }
    }
    return memory;
}

extern "C" void __real_sodium_memzero(void*, std::size_t);
extern "C" void __wrap_sodium_memzero(void* memory, std::size_t size)
{
    PlaintextAllocation* plaintext = nullptr;
    if (activeProbe != nullptr) {
        for (std::size_t index = 0; index < activeProbe->plaintextCount; ++index) {
            auto& allocation = activeProbe->plaintexts[index];
            if (allocation.memory == memory && allocation.size == size && !allocation.zeroed) {
                // Ne jamais lire le contenu indéterminé de sodium_malloc().
                // Le premier effacement est l'initialisation du SecureBuffer.
                if (allocation.initialized) {
                    allocation.containedEntry = size >= 4
                        && std::memcmp(memory, "PWC1", 4) == 0;
                    plaintext = &allocation;
                } else {
                    allocation.initialized = true;
                }
                break;
            }
        }
    }
    __real_sodium_memzero(memory, size);
    if (activeProbe == nullptr)
        return;
    if (plaintext != nullptr)
        plaintext->zeroed = allZero(memory, size);
    for (std::size_t index = 0; index < activeProbe->stringCount; ++index) {
        auto& allocation = activeProbe->strings[index];
        if (allocation.memory == memory && allocation.size == size && !allocation.zeroed) {
            allocation.zeroed = allZero(memory, size);
            allocation.zeroedWhileUnwinding = std::uncaught_exceptions() > 0;
        }
    }
}

extern "C" int __real_sqlite3_exec(sqlite3*, const char*,
    int (*)(void*, int, char**, char**), void*, char**);
extern "C" int __wrap_sqlite3_exec(sqlite3* database, const char* sql,
    int (*callback)(void*, int, char**, char**), void* context, char** error)
{
    if (activeProbe != nullptr && std::strcmp(sql, "BEGIN IMMEDIATE;") == 0) {
        auto& probe = *activeProbe;
        probe.transactionDatabase = database;
        probe.phase = TransactionPhase::Begin;
        if (probe.transactionFault == TransactionFault::BeginBusy) {
            probe.transactionFaultInjected = true;
            probe.injectedExtended = SQLITE_BUSY_TIMEOUT;
            return SQLITE_BUSY;
        }
        if (probe.transactionFault == TransactionFault::BeginUnconfirmed) {
            probe.transactionFaultInjected = true;
            return SQLITE_OK; // deliberately no transaction, tests the postcondition
        }
    }
    if (activeProbe != nullptr && std::strcmp(sql, "ROLLBACK;") == 0) {
        auto& probe = *activeProbe;
        probe.phase = TransactionPhase::Rollback;
        ++probe.rollbackCalls;
        probe.injectedExtended = -1;
        if (probe.transactionFault == TransactionFault::RollbackFailure) {
            probe.transactionFaultInjected = true;
            probe.injectedExtended = SQLITE_BUSY;
            return SQLITE_BUSY; // real transaction stays active until RAII close
        }
    }
    if (activeProbe != nullptr && std::strcmp(sql, "COMMIT;") == 0) {
        auto& probe = *activeProbe;
        probe.phase = TransactionPhase::Commit;
        ++probe.commitCalls;
        probe.writePendingAtCommit = sqlite3_get_autocommit(database) == 0
            && sqlite3_changes(database) == 1;
        probe.copiesZeroedAtCommit = probe.allStringsZeroed();
        if (probe.commitBehavior != CommitBehavior::Normal) {
            probe.commitFaultInjected = true;
            if (probe.commitBehavior == CommitBehavior::Throw)
                throw CommitFailure{};
            return SQLITE_IOERR;
        }
        const auto fault = probe.transactionFault;
        if (fault == TransactionFault::CommitActive || fault == TransactionFault::CommitEnded
            || fault == TransactionFault::CommitPersistedButError || fault == TransactionFault::RollbackFailure
            || fault == TransactionFault::RollbackUnconfirmed || fault == TransactionFault::UnknownState) {
            probe.transactionFaultInjected = true;
            if (fault == TransactionFault::CommitEnded)
                __real_sqlite3_exec(database, "ROLLBACK;", nullptr, nullptr, nullptr);
            if (fault == TransactionFault::CommitPersistedButError)
                __real_sqlite3_exec(database, "COMMIT;", nullptr, nullptr, nullptr);
            probe.injectedExtended = SQLITE_IOERR_FSYNC;
            return SQLITE_IOERR;
        }
    }
    return __real_sqlite3_exec(database, sql, callback, context, error);
}

extern "C" int __real_sqlite3_extended_errcode(sqlite3*);
extern "C" int __wrap_sqlite3_extended_errcode(sqlite3* database)
{
    if (activeProbe != nullptr && activeProbe->transactionDatabase == database
        && activeProbe->injectedExtended >= 0)
        return activeProbe->injectedExtended;
    return __real_sqlite3_extended_errcode(database);
}

extern "C" int __real_sqlite3_txn_state(sqlite3*, const char*);
extern "C" int __wrap_sqlite3_txn_state(sqlite3* database, const char* schema)
{
    if (activeProbe != nullptr && activeProbe->transactionDatabase == database) {
        const auto fault = activeProbe->transactionFault;
        const auto phase = activeProbe->phase;
        if (((fault == TransactionFault::UnknownState || fault == TransactionFault::CommitUnconfirmed)
             && phase == TransactionPhase::Commit)
            || (fault == TransactionFault::RollbackUnconfirmed && phase == TransactionPhase::Rollback)) {
            activeProbe->transactionFaultInjected = true;
            return -1;
        }
    }
    return __real_sqlite3_txn_state(database, schema);
}

extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_step(sqlite3_stmt* statement)
{
    const int result = __real_sqlite3_step(statement);
    const char* sql = sqlite3_sql(statement);
    if (activeProbe == nullptr || sql == nullptr || result != SQLITE_DONE
        || (std::strncmp(sql, "INSERT INTO entries", 19) != 0
            && std::strncmp(sql, "UPDATE entries", 14) != 0
            && std::strncmp(sql, "DELETE FROM entries", 19) != 0))
        return result;
    auto& probe = *activeProbe;
    ++probe.writeSteps;
    const auto fault = probe.transactionFault;
    if (fault == TransactionFault::StatementError || fault == TransactionFault::StatementAutoRollback) {
        probe.phase = TransactionPhase::Statement;
        probe.transactionFaultInjected = true;
        // A real SQLite constraint, injected AFTER the requested write. OR
        // ROLLBACK really cancels that write; OR ABORT leaves the transaction
        // active. No schema changes and no credential values in this SQL.
        return __real_sqlite3_exec(sqlite3_db_handle(statement),
            fault == TransactionFault::StatementAutoRollback
                ? "INSERT OR ROLLBACK INTO entries SELECT * FROM entries LIMIT 1;"
                : "INSERT OR ABORT INTO entries SELECT * FROM entries LIMIT 1;",
            nullptr, nullptr, nullptr);
    }
    return result;
}

extern "C" int __real_sqlite3_close_v2(sqlite3*);
extern "C" int __wrap_sqlite3_close_v2(sqlite3* database)
{
    if (activeProbe != nullptr && activeProbe->transactionDatabase == database) {
        activeProbe->closed = true;
        activeProbe->closeWithStatements = sqlite3_next_stmt(database, nullptr) != nullptr;
        activeProbe->activeAtClose = sqlite3_get_autocommit(database) == 0;
    }
    return __real_sqlite3_close_v2(database);
}

namespace {
Credential fictionalCredential(bool replacement)
{
    // Longueurs distinctes, hors SSO, pour localiser sans ambiguïté la vraie
    // allocation des notes après celle du mot de passe, sans hook métier.
    Credential credential;
    credential.version = 97;
    credential.title.assign(replacement ? 401 : 257, 't');
    credential.url = "https://example.test/";
    credential.url.resize(replacement ? 617 : 389, 'u');
    credential.username.assign(replacement ? 839 : 521, 'n');
    credential.password.assign(replacement ? 1223 : 1031, 'p');
    credential.notes.assign(replacement ? 1759 : 1543, 'f');
    return credential;
}

class CredentialServiceMemoryTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suiteDirectory;
    static inline SecureBuffer dataKey{0};
    std::unique_ptr<QTemporaryDir> directory;
    std::string path;
    std::string error;
    Credential original;
    Credential incoming;
    Credential sourceBefore;
    MemoryProbe probe;

    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        suiteDirectory = std::make_unique<QTemporaryDir>(
            QStringLiteral("/tmp/passwall-credential-memory-suite-XXXXXX"));
        ASSERT_TRUE(suiteDirectory->isValid());
        std::string error;
        ASSERT_TRUE(passwall::services::VaultLifecycleService::createVault(
            templatePath().toStdString(), "fictitious-memory-test-master", dataKey, error));
    }

    static void TearDownTestSuite()
    {
        dataKey = SecureBuffer(0);
        suiteDirectory.reset();
    }

    static QString templatePath()
    {
        return suiteDirectory->filePath(QStringLiteral("template.pwdb"));
    }

    void SetUp() override
    {
        directory = std::make_unique<QTemporaryDir>(
            QStringLiteral("/tmp/passwall-credential-memory-case-XXXXXX"));
        ASSERT_TRUE(directory->isValid());
        const QString filename = directory->filePath(QStringLiteral("vault.pwdb"));
        ASSERT_TRUE(QFile::copy(templatePath(), filename));
        path = filename.toStdString();
        original = fictionalCredential(false);
        ASSERT_TRUE(CredentialService::add(path, dataKey, original, error));
        incoming = fictionalCredential(true);
        incoming.id = original.id;
        sourceBefore = incoming; // Copie fictive de contrôle, hors injection.
    }

    void TearDown() override
    {
        EXPECT_TRUE(activeProbe == nullptr);
        wipeTestCredential(original);
        wipeTestCredential(incoming);
        wipeTestCredential(sourceBefore);
        directory.reset();
    }

    void observeAddition()
    {
        probe.sources[0] = &incoming;
    }

    void observeUpdate()
    {
        probe.sources[0] = &original;
        probe.sources[1] = &incoming;
    }

    std::string persistentBytes() const
    {
        std::ifstream file(path, std::ios::binary);
        EXPECT_TRUE(file.is_open());
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    void expectCleanup(std::size_t strings, std::size_t plaintexts)
    {
        EXPECT_FALSE(probe.overflow);
        EXPECT_EQ(probe.stringCount, strings);
        EXPECT_TRUE(probe.allStringsZeroed());
        EXPECT_EQ(probe.plaintextCount, plaintexts);
        for (std::size_t index = 0; index < probe.plaintextCount; ++index) {
            EXPECT_TRUE(probe.plaintexts[index].containedEntry);
            EXPECT_TRUE(probe.plaintexts[index].zeroed);
        }
    }

    void expectStored(const Credential& expected)
    {
        Credential loaded;
        const bool success = CredentialService::get(path, dataKey, expected.id, loaded, error);
        EXPECT_TRUE(success);
        EXPECT_TRUE(sameCredential(loaded, expected, false));
        EXPECT_EQ(loaded.version, 1u);
        wipeTestCredential(loaded);
    }

    void expectFailedWithoutChanges(const std::string& before)
    {
        EXPECT_TRUE(sameCredential(incoming, sourceBefore));
        EXPECT_TRUE(persistentBytes() == before);
        expectStored(original);
    }

    void expectRetry(bool adding)
    {
        const bool success = adding
            ? CredentialService::add(path, dataKey, incoming, error)
            : CredentialService::update(path, dataKey, incoming, error);
        ASSERT_TRUE(success);
        EXPECT_TRUE(error.empty());
        expectStored(incoming);
    }
};

TEST_F(CredentialServiceMemoryTest, AddSuccessWipesCopiesAndOnlyPublishesIdAndVersion)
{
    observeAddition();
    ASSERT_TRUE(withProbe(probe, [&] { return CredentialService::add(path, dataKey, incoming, error); }));
    expectCleanup(5, 1);
    EXPECT_TRUE(sameCredential(incoming, sourceBefore, false));
    EXPECT_NE(incoming.id, sourceBefore.id);
    EXPECT_EQ(incoming.version, 1u);
    expectStored(incoming);
    expectStored(original);
}

TEST_F(CredentialServiceMemoryTest, UpdateSuccessAvoidsIncomingCopyAndWipesPreviousEntryEarly)
{
    observeUpdate();
    ASSERT_TRUE(withProbe(probe, [&] { return CredentialService::update(path, dataKey, incoming, error); }));
    expectCleanup(5, 2);
    EXPECT_EQ(probe.stringsInGroup(1), 0u);
    EXPECT_TRUE(probe.copiesZeroedAtCommit);
    EXPECT_TRUE(sameCredential(incoming, sourceBefore));
    expectStored(incoming);
}

TEST_F(CredentialServiceMemoryTest, AddCommitErrorWipesCopiesAndRollsBack)
{
    observeAddition();
    probe.commitBehavior = CommitBehavior::ReturnError;
    const auto before = persistentBytes();
    EXPECT_FALSE(withProbe(probe, [&] { return CredentialService::add(path, dataKey, incoming, error); }));
    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(probe.commitFaultInjected);
    EXPECT_TRUE(probe.writePendingAtCommit);
    expectCleanup(5, 1);
    expectFailedWithoutChanges(before);
    expectRetry(true);
}

TEST_F(CredentialServiceMemoryTest, UpdateCommitErrorWipesCopiesAndRollsBack)
{
    observeUpdate();
    probe.commitBehavior = CommitBehavior::ReturnError;
    const auto before = persistentBytes();
    EXPECT_FALSE(withProbe(probe, [&] { return CredentialService::update(path, dataKey, incoming, error); }));
    EXPECT_FALSE(error.empty());
    EXPECT_TRUE(probe.commitFaultInjected);
    EXPECT_TRUE(probe.writePendingAtCommit);
    expectCleanup(5, 2);
    expectFailedWithoutChanges(before);
    expectRetry(false);
}

TEST_F(CredentialServiceMemoryTest, AddPartialCopyAllocationFailureWipesPasswordWhileUnwinding)
{
    observeAddition();
    probe.failNotesGroup = 0;
    const auto before = persistentBytes();
    EXPECT_THROW(withProbe(probe, [&] { return CredentialService::add(path, dataKey, incoming, error); }), std::bad_alloc);
    EXPECT_TRUE(probe.allocationFailureInjected);
    EXPECT_TRUE(probe.passwordCopiedBeforeFailure);
    expectCleanup(4, 0);
    for (std::size_t index = 0; index < probe.stringCount; ++index)
        EXPECT_TRUE(probe.strings[index].zeroedWhileUnwinding);
    expectFailedWithoutChanges(before);
    expectRetry(true);
}

TEST_F(CredentialServiceMemoryTest, UpdatePartialReadAllocationFailureCleansAndRollsBack)
{
    observeUpdate();
    probe.failNotesGroup = 0;
    const auto before = persistentBytes();
    EXPECT_FALSE(withProbe(probe, [&] { return CredentialService::update(path, dataKey, incoming, error); }));
    EXPECT_TRUE(probe.allocationFailureInjected);
    EXPECT_TRUE(probe.passwordCopiedBeforeFailure);
    EXPECT_FALSE(error.empty());
    expectCleanup(4, 1);
    EXPECT_EQ(probe.stringsInGroup(1), 0u);
    expectFailedWithoutChanges(before);
    expectRetry(false);
}

TEST_F(CredentialServiceMemoryTest, AddExceptionAfterInsertWipesCompleteCopyAndRollsBack)
{
    observeAddition();
    probe.commitBehavior = CommitBehavior::Throw;
    const auto before = persistentBytes();
    EXPECT_THROW(withProbe(probe, [&] { return CredentialService::add(path, dataKey, incoming, error); }), CommitFailure);
    EXPECT_TRUE(probe.commitFaultInjected);
    EXPECT_TRUE(probe.writePendingAtCommit);
    expectCleanup(5, 1);
    for (std::size_t index = 0; index < probe.stringCount; ++index)
        EXPECT_TRUE(probe.strings[index].zeroedWhileUnwinding);
    expectFailedWithoutChanges(before);
    expectRetry(true);
}

TEST_F(CredentialServiceMemoryTest, UpdateExceptionAfterWriteRollsBackWithoutCopyingSource)
{
    observeUpdate();
    probe.commitBehavior = CommitBehavior::Throw;
    const auto before = persistentBytes();
    EXPECT_THROW(withProbe(probe, [&] { return CredentialService::update(path, dataKey, incoming, error); }), CommitFailure);
    EXPECT_TRUE(probe.commitFaultInjected);
    EXPECT_TRUE(probe.writePendingAtCommit);
    expectCleanup(5, 2);
    EXPECT_EQ(probe.stringsInGroup(1), 0u);
    EXPECT_TRUE(probe.copiesZeroedAtCommit);
    expectFailedWithoutChanges(before);
    expectRetry(false);
}

// Same isolated, fictitious vault fixture; no production fault-injection API.
class CredentialTransactionTest : public CredentialServiceMemoryTest {
protected:
    bool run(int operation)
    {
        return withProbe(probe, [&] {
            if (operation == 0)
                return CredentialService::add(path, dataKey, incoming, error);
            if (operation == 1)
                return CredentialService::update(path, dataKey, incoming, error);
            return CredentialService::remove(path, dataKey, original.id, error);
        });
    }

    void expectCode(int primary, int extended)
    {
        EXPECT_NE(error.find("primaire=" + std::to_string(primary)), std::string::npos);
        EXPECT_NE(error.find("étendu=" + std::to_string(extended)), std::string::npos);
        EXPECT_EQ(error.find(incoming.password), std::string::npos);
        EXPECT_EQ(error.find(incoming.notes), std::string::npos);
    }

    void expectClosedAndUnchanged(const std::string& before)
    {
        EXPECT_TRUE(probe.closed);
        EXPECT_FALSE(probe.closeWithStatements);
        expectFailedWithoutChanges(before);
    }

    void addConstraintSurvivor()
    {
        // Ensure an entry remains even after the DELETE under test, so the
        // injected INSERT OR ... SELECT really hits a primary-key constraint.
        auto survivor = fictionalCredential(false);
        ASSERT_TRUE(CredentialService::add(path, dataKey, survivor, error));
        wipeTestCredential(survivor);
    }
};

TEST_F(CredentialTransactionTest, BeginErrorPreservesExtendedCodeAndPublishesNothing)
{
    const auto before = persistentBytes();
    for (int operation = 0; operation < 3; ++operation) {
        probe = MemoryProbe{};
        probe.transactionFault = TransactionFault::BeginBusy;
        EXPECT_FALSE(run(operation));
        expectCode(SQLITE_BUSY, SQLITE_BUSY_TIMEOUT);
        EXPECT_NE(error.find("BEGIN IMMEDIATE"), std::string::npos);
        EXPECT_NE(error.find("BEGIN refusé"), std::string::npos);
        EXPECT_EQ(probe.rollbackCalls, 0);
        EXPECT_EQ(probe.commitCalls, 0);
        EXPECT_EQ(probe.writeSteps, 0);
        expectClosedAndUnchanged(before);
    }
    expectRetry(false);
}

TEST_F(CredentialTransactionTest, BeginSuccessWithoutWriteTransactionDoesNotReachBusinessSql)
{
    probe.transactionFault = TransactionFault::BeginUnconfirmed;
    const auto before = persistentBytes();
    EXPECT_FALSE(run(0));
    EXPECT_NE(error.find("n'est pas confirmée"), std::string::npos);
    EXPECT_EQ(probe.writeSteps, 0);
    EXPECT_EQ(probe.commitCalls, 0);
    expectClosedAndUnchanged(before);
    expectRetry(true);
}

TEST_F(CredentialTransactionTest, CommitErrorWithActiveTransactionConfirmsExplicitRollback)
{
    const auto before = persistentBytes();
    for (int operation = 0; operation < 3; ++operation) {
        probe = MemoryProbe{};
        probe.transactionFault = TransactionFault::CommitActive;
        EXPECT_FALSE(run(operation));
        expectCode(SQLITE_IOERR, SQLITE_IOERR_FSYNC);
        EXPECT_NE(error.find("COMMIT"), std::string::npos);
        EXPECT_NE(error.find("Transaction encore active"), std::string::npos);
        EXPECT_NE(error.find("ROLLBACK explicite confirmé"), std::string::npos);
        EXPECT_EQ(probe.rollbackCalls, 1);
        EXPECT_EQ(probe.commitCalls, 1);
        EXPECT_FALSE(probe.activeAtClose);
        expectClosedAndUnchanged(before);
    }
    expectRetry(false);
}

TEST_F(CredentialTransactionTest, StatementFailurePreservesCodeAcrossFinalizationAndRollback)
{
    addConstraintSurvivor();
    const auto before = persistentBytes();
    for (int operation = 0; operation < 3; ++operation) {
        probe = MemoryProbe{};
        probe.transactionFault = TransactionFault::StatementError;
        EXPECT_FALSE(run(operation));
        expectCode(SQLITE_CONSTRAINT, SQLITE_CONSTRAINT_PRIMARYKEY);
        EXPECT_NE(error.find(operation == 0 ? "INSERT" : operation == 1 ? "UPDATE" : "DELETE"),
                  std::string::npos);
        EXPECT_NE(error.find("ROLLBACK explicite confirmé"), std::string::npos);
        EXPECT_EQ(probe.rollbackCalls, 1);
        EXPECT_EQ(probe.commitCalls, 0);
        expectClosedAndUnchanged(before);
    }
    expectRetry(false);
}

TEST_F(CredentialTransactionTest, SQLiteAutomaticRollbackBeforeCommitIsNotRepeated)
{
    addConstraintSurvivor();
    const auto before = persistentBytes();
    for (int operation = 0; operation < 3; ++operation) {
        probe = MemoryProbe{};
        probe.transactionFault = TransactionFault::StatementAutoRollback;
        EXPECT_FALSE(run(operation));
        expectCode(SQLITE_CONSTRAINT, SQLITE_CONSTRAINT_PRIMARYKEY);
        EXPECT_NE(error.find("Annulation automatique observée avant COMMIT"), std::string::npos);
        EXPECT_EQ(probe.rollbackCalls, 0);
        EXPECT_EQ(probe.commitCalls, 0);
        EXPECT_FALSE(probe.activeAtClose);
        expectClosedAndUnchanged(before);
    }
    expectRetry(false);
}

TEST_F(CredentialTransactionTest, SecondaryRollbackFailureDoesNotReplaceCommitCause)
{
    probe.transactionFault = TransactionFault::RollbackFailure;
    const auto before = persistentBytes();
    EXPECT_FALSE(run(0));
    expectCode(SQLITE_IOERR, SQLITE_IOERR_FSYNC);
    const auto secondary = error.find("Échec secondaire de ROLLBACK");
    ASSERT_NE(secondary, std::string::npos);
    EXPECT_LT(error.find("étendu=" + std::to_string(SQLITE_IOERR_FSYNC)), secondary);
    EXPECT_NE(error.find("primaire=5", secondary), std::string::npos);
    EXPECT_NE(error.find("annulation non confirmée"), std::string::npos);
    EXPECT_EQ(error.find("ROLLBACK explicite confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 1);
    EXPECT_TRUE(probe.activeAtClose); // RAII close must still roll back the real write
    expectClosedAndUnchanged(before);
    expectRetry(true);
}

TEST_F(CredentialTransactionTest, RollbackOkWithoutConfirmedEndIsNotReportedAsSuccess)
{
    probe.transactionFault = TransactionFault::RollbackUnconfirmed;
    const auto before = persistentBytes();
    EXPECT_FALSE(run(1));
    expectCode(SQLITE_IOERR, SQLITE_IOERR_FSYNC);
    EXPECT_NE(error.find("ROLLBACK a retourné SQLITE_OK"), std::string::npos);
    EXPECT_NE(error.find("annulation non confirmée"), std::string::npos);
    EXPECT_EQ(error.find("ROLLBACK explicite confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 1);
    expectClosedAndUnchanged(before);
    expectRetry(false);
}

TEST_F(CredentialTransactionTest, UnknownStateUsesRaiiWithoutClaimingRollback)
{
    probe.transactionFault = TransactionFault::UnknownState;
    const auto before = persistentBytes();
    EXPECT_FALSE(run(1));
    expectCode(SQLITE_IOERR, SQLITE_IOERR_FSYNC);
    EXPECT_NE(error.find("État transactionnel non confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 0);
    EXPECT_TRUE(probe.activeAtClose);
    expectClosedAndUnchanged(before);
    expectRetry(false);
}

TEST_F(CredentialTransactionTest, CommitErrorAfterTransactionEndedDoesNotAssertRollback)
{
    probe.transactionFault = TransactionFault::CommitEnded;
    const auto before = persistentBytes();
    EXPECT_FALSE(run(0));
    expectCode(SQLITE_IOERR, SQLITE_IOERR_FSYNC);
    EXPECT_NE(error.find("résultat persistant non confirmé"), std::string::npos);
    EXPECT_EQ(error.find("ROLLBACK explicite confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 0);
    expectClosedAndUnchanged(before);
    expectRetry(true);
}

TEST_F(CredentialTransactionTest, AutocommitAfterCommitErrorIsNotProofOfRollbackOrSuccess)
{
    probe.transactionFault = TransactionFault::CommitPersistedButError;
    EXPECT_FALSE(run(0));
    expectCode(SQLITE_IOERR, SQLITE_IOERR_FSYNC);
    EXPECT_NE(error.find("résultat persistant non confirmé"), std::string::npos);
    EXPECT_EQ(error.find("ROLLBACK explicite confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 0);
    EXPECT_EQ(probe.commitCalls, 1); // no automatic retry
    EXPECT_TRUE(probe.closed);
    EXPECT_TRUE(sameCredential(incoming, sourceBefore)); // no generated id/version published
    std::vector<passwall::models::CredentialSummary> summaries;
    ASSERT_TRUE(CredentialService::listSummaries(path, dataKey, summaries, error));
    EXPECT_EQ(summaries.size(), 2u); // deliberately committed before injecting the returned error
}

TEST_F(CredentialTransactionTest, CommitOkWithUnknownStateDoesNotPublishIdOrRetry)
{
    probe.transactionFault = TransactionFault::CommitUnconfirmed;
    EXPECT_FALSE(run(0));
    EXPECT_NE(error.find("COMMIT a retourné SQLITE_OK"), std::string::npos);
    EXPECT_NE(error.find("Résultat persistant non confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 0);
    EXPECT_EQ(probe.commitCalls, 1);
    EXPECT_TRUE(probe.closed);
    EXPECT_TRUE(sameCredential(incoming, sourceBefore));
}

TEST_F(CredentialTransactionTest, RealWriterContentionFailsBeginWithinConfiguredTimeoutThenRecovers)
{
    sqlite3* blocker = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.c_str(), &blocker,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr), SQLITE_OK);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> owner(blocker, sqlite3_close_v2);
    ASSERT_EQ(sqlite3_exec(blocker, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr), SQLITE_OK);
    const auto before = persistentBytes();
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(run(0));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    expectCode(SQLITE_BUSY, SQLITE_BUSY);
    EXPECT_NE(error.find("BEGIN IMMEDIATE"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 0);
    EXPECT_EQ(probe.writeSteps, 0);
    EXPECT_GE(elapsed, std::chrono::milliseconds(2500));
    EXPECT_LT(elapsed, std::chrono::seconds(10));
    ASSERT_EQ(sqlite3_exec(blocker, "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
    expectClosedAndUnchanged(before);
    expectRetry(true);
}

TEST_F(CredentialTransactionTest, RealReaderContentionFailsCommitAndConfirmsRollback)
{
    sqlite3* reader = nullptr;
    ASSERT_EQ(sqlite3_open_v2(path.c_str(), &reader,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr), SQLITE_OK);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> owner(reader, sqlite3_close_v2);
    ASSERT_EQ(sqlite3_exec(reader, "BEGIN; SELECT count(*) FROM entries;", nullptr, nullptr, nullptr), SQLITE_OK);
    const auto before = persistentBytes();
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(run(1));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    expectCode(SQLITE_BUSY, SQLITE_BUSY);
    EXPECT_NE(error.find("COMMIT"), std::string::npos);
    EXPECT_NE(error.find("ROLLBACK explicite confirmé"), std::string::npos);
    EXPECT_EQ(probe.rollbackCalls, 1);
    EXPECT_FALSE(probe.activeAtClose);
    EXPECT_GE(elapsed, std::chrono::milliseconds(2500));
    EXPECT_LT(elapsed, std::chrono::seconds(10));
    ASSERT_EQ(sqlite3_exec(reader, "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
    expectClosedAndUnchanged(before);
    expectRetry(false);
}
} // namespace
