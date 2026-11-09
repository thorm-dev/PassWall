#include "services/credential_service.hpp"
#include "services/vault_preferences_store.hpp"
#include "storage/vault_operation_guard.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QSettings>
#include <QTemporaryDir>
#include <sodium.h>
#include <sqlite3.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace passwall::services;
using passwall::storage::VaultOperationGuard;
using passwall::storage::VaultStorage;
using passwall::models::Credential;
namespace {
enum class CommitFault { None, Rollback, PersistedButError, Throw };
struct InjectedException {};
struct Probe {
    QString config;
    QByteArray nativeConfig;
    int opens = 0;
    int syncs = 0;
    int statusCalls = 0;
    int failStatusAt = 0;
    bool failSync = false;
    bool failDirectorySync = false;
    CommitFault commit = CommitFault::None;
    std::function<void()> beforeOpen;
    std::function<void()> beforeBegin;
};
thread_local Probe* active = nullptr;
struct ProbeScope {
    explicit ProbeScope(Probe& probe) : previous(active) { active = &probe; }
    ~ProbeScope() { active = previous; }
    Probe* previous;
};
QByteArray bytes(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}
void writeBytes(const QString& path, const QByteArray& contents)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(file.write(contents), contents.size());
}
Credential fictitious()
{
    Credential value;
    value.title = "Fictitious title";
    value.url = "https://example.invalid";
    value.username = "fictitious-user";
    value.password = "fictitious-password-only";
    value.notes = "fictitious-note-only";
    return value;
}
}

extern "C" int __real_sqlite3_open_v2(const char*, sqlite3**, int, const char*);
extern "C" int __wrap_sqlite3_open_v2(const char* path, sqlite3** db, int flags, const char* vfs)
{
    if (active) {
        ++active->opens;
        if (active->beforeOpen) active->beforeOpen();
    }
    return __real_sqlite3_open_v2(path, db, flags, vfs);
}
extern "C" int __real_sqlite3_exec(sqlite3*, const char*,
    int (*)(void*, int, char**, char**), void*, char**);
extern "C" int __wrap_sqlite3_exec(sqlite3* db, const char* sql,
    int (*callback)(void*, int, char**, char**), void* context, char** error)
{
    if (active && std::strcmp(sql, "BEGIN IMMEDIATE;") == 0 && active->beforeBegin)
        active->beforeBegin();
    if (active && std::strcmp(sql, "COMMIT;") == 0) {
        if (active->commit == CommitFault::Throw) throw InjectedException{};
        if (active->commit == CommitFault::Rollback) return SQLITE_IOERR;
        if (active->commit == CommitFault::PersistedButError) {
            const int result = __real_sqlite3_exec(db, sql, callback, context, error);
            return result == SQLITE_OK ? SQLITE_IOERR : result;
        }
    }
    return __real_sqlite3_exec(db, sql, callback, context, error);
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    if (active) {
        struct stat info {};
        if (active->failDirectorySync && ::fstat(fd, &info) == 0 && S_ISDIR(info.st_mode)) {
            errno = EIO;
            return -1;
        }
        char link[64], target[4096];
        const int count = std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        const auto length = count > 0 ? ::readlink(link, target, sizeof(target)) : -1;
        if (length == active->nativeConfig.size()
            && std::memcmp(target, active->nativeConfig.constData(), length) == 0) {
            ++active->syncs;
            if (active->failSync) { errno = EIO; return -1; }
        }
    }
    return __real_fsync(fd);
}
extern "C" QSettings::Status realStatus(const QSettings*) asm("__real__ZNK9QSettings6statusEv");
extern "C" QSettings::Status wrappedStatus(const QSettings*) asm("__wrap__ZNK9QSettings6statusEv");
extern "C" QSettings::Status wrappedStatus(const QSettings* settings)
{
    if (active && settings->fileName() == active->config
        && ++active->statusCalls == active->failStatusAt)
        return QSettings::AccessError;
    return realStatus(settings);
}

namespace {
class VaultDirtyTrackingTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    QString path, config, error;
    VaultRegistration registered;
    passwall::core::SecureBuffer key{0};
    Credential original;
    Probe probe;

    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        ASSERT_GE(sodium_init(), 0);
        for (auto format : {QSettings::NativeFormat, QSettings::IniFormat}) {
            QSettings::setPath(format, QSettings::UserScope, directory.filePath("settings"));
            QSettings::setPath(format, QSettings::SystemScope, directory.filePath("settings"));
        }
        config = VaultPreferencesStore().fileName();
        ASSERT_TRUE(config.startsWith(directory.path() + '/'));
        path = directory.filePath("main.db");
        makeVault(path);
        key = passwall::core::SecureBuffer(passwall::core::KeySize);
        std::fill_n(key.data(), key.size(), 0x42);
        original = fictitious();
        std::string failure;
        ASSERT_TRUE(CredentialService::add(path.toStdString(), key, original, failure)) << failure;
        ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(path, registered, error),
                  VaultRecognition::Registered) << error.toStdString();
        probe.config = config;
        probe.nativeConfig = QFile::encodeName(config);
    }
    void makeVault(const QString& target)
    {
        std::string failure;
        ASSERT_TRUE(VaultStorage::createSchema(target.toStdString(), failure));
        VaultKeyMetadata metadata;
        metadata.vaultId.fill(0x33); // Same cryptographic ID across these fictitious copies.
        ASSERT_TRUE(VaultStorage::writeMetadata(target.toStdString(), metadata, failure));
    }
    void enable(const QString& id = {})
    {
        ASSERT_TRUE(VaultPreferencesStore().updatePreferences(id.isEmpty() ? registered.localId : id,
            {true, directory.filePath("unused-destination"), 7}, error)) << error.toStdString();
        // This suite exercises post-initial-backup mutation tracking. Step 4
        // now marks activation itself dirty; fixture-only reset, no public clear.
        const auto target = id.isEmpty() ? registered.localId : id;
        rawRegistry([&](auto& root) {
            auto array = root["vaults"].toArray();
            for (qsizetype i = 0; i < array.size(); ++i) {
                auto value = array[i].toObject();
                if (value["localId"].toString() == target) { value["backupRequired"] = false; array[i] = value; }
            }
            root["vaults"] = array;
        });
    }
    VaultRegistration record(const QString& id = {})
    {
        QVector<VaultRegistration> records;
        EXPECT_TRUE(VaultPreferencesStore().list(records, error)) << error.toStdString();
        const auto wanted = id.isEmpty() ? registered.localId : id;
        for (const auto& entry : records) if (entry.localId == wanted) return entry;
        ADD_FAILURE() << "Missing fictitious local registration";
        return {};
    }
    bool mutate(int operation, const QString& target = {})
    {
        const auto file = (target.isEmpty() ? path : target).toStdString();
        std::string failure;
        auto value = fictitious();
        value.id = original.id;
        value.version = original.version;
        const bool ok = operation == 0 ? CredentialService::add(file, key, value, failure)
            : operation == 1 ? CredentialService::update(file, key, value, failure)
            : CredentialService::remove(file, key, original.id, failure);
        error = QString::fromStdString(failure);
        return ok;
    }
    int entryCount()
    {
        std::vector<passwall::models::CredentialSummary> values;
        std::string failure;
        EXPECT_TRUE(CredentialService::listSummaries(path.toStdString(), key, values, failure));
        return int(values.size());
    }
    void rawRegistry(const std::function<void(QJsonObject&)>& change)
    {
        QSettings settings(config, QSettings::IniFormat);
        auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
        change(root);
        settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact));
        settings.sync();
        ASSERT_EQ(settings.status(), QSettings::NoError);
    }
};

TEST_F(VaultDirtyTrackingTest, DisabledBackupsAllowAllCrudWithoutChangingTheRegistry)
{
    const auto before = bytes(config);
    for (int operation = 0; operation < 3; ++operation) ASSERT_TRUE(mutate(operation));
    EXPECT_FALSE(record().backupRequired);
    EXPECT_EQ(bytes(config), before);
}

class DirtyCrudTest : public VaultDirtyTrackingTest, public ::testing::WithParamInterface<int> {};
TEST_P(DirtyCrudTest, PersistsIntentBeforeTheFirstSqliteOpenOfEachDirectMutation)
{
    enable();
    bool observed = false;
    probe.beforeOpen = [&] {
        observed = true;
        EXPECT_GE(probe.syncs, 1);
        EXPECT_TRUE(record().backupRequired);
    };
    {
        ProbeScope scope(probe);
        ASSERT_TRUE(mutate(GetParam())) << error.toStdString();
    }
    EXPECT_TRUE(observed);
    EXPECT_TRUE(record().backupRequired);
}
INSTANTIATE_TEST_SUITE_P(DirectServices, DirtyCrudTest, ::testing::Values(0, 1, 2));

TEST_F(VaultDirtyTrackingTest, RepeatedCrudDoesNotRewriteAnAlreadyDurableIntent)
{
    enable();
    ASSERT_TRUE(mutate(0));
    const auto before = bytes(config);
    struct stat first {}, last {};
    ASSERT_EQ(::stat(QFile::encodeName(config).constData(), &first), 0);
    for (int operation : {0, 1, 2, 0}) {
        ProbeScope scope(probe);
        ASSERT_TRUE(mutate(operation));
    }
    ASSERT_EQ(::stat(QFile::encodeName(config).constData(), &last), 0);
    EXPECT_EQ(first.st_ino, last.st_ino);
    EXPECT_EQ(first.st_mtim.tv_sec, last.st_mtim.tv_sec);
    EXPECT_EQ(first.st_mtim.tv_nsec, last.st_mtim.tv_nsec);
    EXPECT_EQ(bytes(config), before);
    EXPECT_TRUE(record().backupRequired);
    EXPECT_EQ(probe.syncs, 4); // Reconfirmation, not rewriting or clearing.
}

TEST_F(VaultDirtyTrackingTest, DifferentLocalRegistrationsKeepIndependentIntents)
{
    const auto other = directory.filePath("other.db");
    makeVault(other);
    VaultRegistration second;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(other, second, error), VaultRecognition::Registered);
    enable(); enable(second.localId);
    ASSERT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
    EXPECT_FALSE(record(second.localId).backupRequired);
    ASSERT_TRUE(mutate(0, other));
    EXPECT_TRUE(record(second.localId).backupRequired);
}

TEST_F(VaultDirtyTrackingTest, BusyRegistryRefusesAllCrudBeforeSqliteAndAllowsExplicitRetry)
{
    enable();
    const auto before = bytes(path);
    const auto configBefore = bytes(config);
    QLockFile lock(config + ".registry-lock");
    ASSERT_TRUE(lock.tryLock(0));
    {
        ProbeScope scope(probe);
        for (int operation = 0; operation < 3; ++operation) {
            EXPECT_FALSE(mutate(operation));
            EXPECT_FALSE(error.isEmpty());
        }
    }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(bytes(config), configBefore);
    lock.unlock();
    EXPECT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, FailedDurabilityNeverAllowsSqliteEvenWhenTrueIsAlreadyVisible)
{
    enable();
    const auto before = bytes(path);
    probe.failSync = true;
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(mutate(0));
    }
    EXPECT_GE(probe.syncs, 1);
    EXPECT_TRUE(record().backupRequired); // Published, but no durability claim.
    const auto published = bytes(config);
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(mutate(1)); // Already true is not enough after a failed sync.
    }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(bytes(config), published);
    probe.failSync = false;
    { ProbeScope scope(probe); EXPECT_TRUE(mutate(1)); }
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, ReportedQSettingsSyncErrorRefusesMutationAndPreservesTheSource)
{
    enable();
    const auto before = bytes(path);
    probe.failStatusAt = 2; // Actual store: pre-write status, then post-sync status.
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(mutate(0));
    }
    EXPECT_GE(probe.statusCalls, 2);
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_FALSE(error.isEmpty());
    EXPECT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, UnconfirmedDirectorySyncAlsoRefusesSqliteUntilExplicitRetry)
{
    enable();
    const auto before = bytes(path);
    probe.failDirectorySync = true;
    { ProbeScope scope(probe); EXPECT_FALSE(mutate(0)); }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_TRUE(record().backupRequired);
    EXPECT_EQ(bytes(path), before);
    EXPECT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, CorruptIniIsNotTreatedAsDisabledAndIsNotReset)
{
    const auto before = bytes(path);
    const QByteArray corrupt("[broken\nvalue=unparseable\n");
    writeBytes(config, corrupt);
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(mutate(0));
    }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(bytes(config), corrupt);
}

TEST_F(VaultDirtyTrackingTest, MalformedIntentFailsClosedWithoutResettingPreferences)
{
    rawRegistry([](auto& root) {
        auto array = root["vaults"].toArray();
        auto item = array[0].toObject();
        item["backupRequired"] = "not-a-boolean";
        array[0] = item; root["vaults"] = array;
    });
    const auto before = bytes(path), configuration = bytes(config);
    { ProbeScope scope(probe); EXPECT_FALSE(mutate(0)); }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(bytes(config), configuration);
}

TEST_F(VaultDirtyTrackingTest, LegacyRecordWithoutIntentStartsFalseThenPersistsBeforeWriting)
{
    enable();
    rawRegistry([](auto& root) {
        auto array = root["vaults"].toArray();
        auto item = array[0].toObject(); item.remove("backupRequired");
        array[0] = item; root["vaults"] = array;
    });
    EXPECT_FALSE(record().backupRequired);
    ASSERT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, CopyDoesNotInheritOriginalPreferencesOrPendingIntent)
{
    enable(); ASSERT_TRUE(mutate(0));
    const auto copy = directory.filePath("copy.db");
    ASSERT_TRUE(QFile::copy(path, copy));
    const auto saved = bytes(config);
    ASSERT_TRUE(mutate(0, copy)); // Unregistered file gets no implicit authorization.
    EXPECT_EQ(bytes(config), saved);
    VaultRegistration duplicate;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(copy, duplicate, error), VaultRecognition::Registered);
    EXPECT_NE(duplicate.localId, registered.localId);
    EXPECT_EQ(duplicate.file.vaultId, registered.file.vaultId);
    EXPECT_FALSE(duplicate.backup.automatic);
    EXPECT_FALSE(duplicate.backupRequired);
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, UnexpectedReplacementCannotInheritAuthorizationOrStartSqlite)
{
    enable();
    const auto replacement = directory.filePath("replacement.db"); makeVault(replacement);
    ASSERT_TRUE(QFile::rename(path, directory.filePath("old.db")));
    ASSERT_TRUE(QFile::rename(replacement, path));
    const auto before = bytes(path), configuration = bytes(config);
    { ProbeScope scope(probe); EXPECT_FALSE(mutate(0)); }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(bytes(config), configuration);
}

TEST_F(VaultDirtyTrackingTest, MovedRegisteredFileRequiresExplicitReassociation)
{
    enable();
    const auto moved = directory.filePath("moved.db");
    ASSERT_TRUE(QFile::rename(path, moved));
    const auto before = bytes(moved);
    { ProbeScope scope(probe); EXPECT_FALSE(mutate(0, moved)); }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(moved), before);
    EXPECT_FALSE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, ConfirmedRollbackRetainsIntentAndAllowsNextOperation)
{
    enable();
    const auto before = bytes(path);
    probe.commit = CommitFault::Rollback;
    { ProbeScope scope(probe); EXPECT_FALSE(mutate(0)); }
    EXPECT_TRUE(error.contains("ROLLBACK explicite confirmé"));
    EXPECT_EQ(bytes(path), before);
    EXPECT_TRUE(record().backupRequired);
    EXPECT_TRUE(mutate(0));
    EXPECT_EQ(entryCount(), 2);
}

TEST_F(VaultDirtyTrackingTest, CommitActuallyPersistedButReportedAsErrorKeepsIntentAndUnpublishedId)
{
    enable();
    auto value = fictitious(); const auto id = value.id; const auto version = value.version;
    std::string failure;
    probe.commit = CommitFault::PersistedButError;
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(CredentialService::add(path.toStdString(), key, value, failure));
    }
    EXPECT_TRUE(value.id == id);
    EXPECT_EQ(value.version, version);
    EXPECT_NE(failure.find("résultat persistant non confirmé"), std::string::npos);
    EXPECT_TRUE(record().backupRequired);
    EXPECT_EQ(entryCount(), 2); // Injection does not pretend to be a hardware failure.
}

TEST_F(VaultDirtyTrackingTest, ExceptionBeforeSqliteOpenKeepsAlreadyPersistedIntent)
{
    enable();
    const auto before = bytes(path);
    probe.beforeOpen = [] { throw InjectedException{}; };
    {
        ProbeScope scope(probe);
        EXPECT_THROW(mutate(0), InjectedException);
    }
    EXPECT_TRUE(record().backupRequired);
    EXPECT_EQ(bytes(path), before);
    EXPECT_TRUE(mutate(0));
}

TEST_F(VaultDirtyTrackingTest, ExceptionWithTransactionActiveKeepsIntentAndRaiiRollsBack)
{
    enable();
    const auto before = bytes(path);
    probe.commit = CommitFault::Throw;
    { ProbeScope scope(probe); EXPECT_THROW(mutate(0), InjectedException); }
    EXPECT_TRUE(record().backupRequired);
    EXPECT_EQ(bytes(path), before);
    EXPECT_TRUE(mutate(0));
}

TEST_F(VaultDirtyTrackingTest, ChildExitBetweenDurableIntentAndFirstSqliteOpenPreservesIntent)
{
    enable();
    const auto before = bytes(path);
    const pid_t child = ::fork(); ASSERT_GE(child, 0);
    if (child == 0) {
        probe.beforeOpen = [&] { ::_exit(record().backupRequired ? 41 : 42); };
        ProbeScope scope(probe);
        (void)mutate(0);
        ::_exit(43);
    }
    int status = 0; ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status)); EXPECT_EQ(WEXITSTATUS(status), 41);
    EXPECT_EQ(bytes(path), before);
    EXPECT_TRUE(record().backupRequired);
    VaultRegistration recognized;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(path, recognized, error), VaultRecognition::Recognized);
    EXPECT_TRUE(recognized.backupRequired);
}

TEST_F(VaultDirtyTrackingTest, ChildExitAfterCommitRetainsBothWriteAndIntentOnReconstruction)
{
    enable();
    const pid_t child = ::fork(); ASSERT_GE(child, 0);
    if (child == 0) ::_exit(mutate(0) ? 0 : 44);
    int status = 0; ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status)); EXPECT_EQ(WEXITSTATUS(status), 0);
    EXPECT_TRUE(record().backupRequired);
    EXPECT_EQ(entryCount(), 2);
}

TEST_F(VaultDirtyTrackingTest, ExclusiveReservationRefusesCrudBeforeRegistryPersistence)
{
    enable();
    VaultOperationGuard reservation; std::string failure;
    ASSERT_TRUE(reservation.tryReserve(path.toStdString(), failure));
    const auto before = bytes(path), configuration = bytes(config);
    {
        ProbeScope scope(probe);
        for (int operation = 0; operation < 3; ++operation) EXPECT_FALSE(mutate(operation));
    }
    EXPECT_EQ(probe.opens, 0); EXPECT_EQ(probe.syncs, 0);
    EXPECT_EQ(bytes(path), before); EXPECT_EQ(bytes(config), configuration);
    reservation.reset();
    EXPECT_TRUE(mutate(0)); EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, BusinessGuardSpansSqliteButRegistryLockDoesNot)
{
    enable(); bool observed = false;
    probe.beforeBegin = [&] {
        observed = true;
        VaultOperationGuard reservation; std::string failure;
        EXPECT_FALSE(reservation.tryReserve(path.toStdString(), failure));
        QLockFile registry(config + ".registry-lock");
        EXPECT_TRUE(registry.tryLock(0));
    };
    { ProbeScope scope(probe); EXPECT_TRUE(mutate(0)); }
    EXPECT_TRUE(observed);
}

TEST_F(VaultDirtyTrackingTest, ActivationCannotRaceAMutationWhichObservedDisabledBackups)
{
    bool observed = false;
    probe.beforeBegin = [&] {
        observed = true;
        QString failure;
        EXPECT_FALSE(VaultPreferencesStore().updatePreferences(registered.localId,
            {true, directory.filePath("unused-destination"), 7}, failure));
        EXPECT_FALSE(failure.isEmpty());
    };
    { ProbeScope scope(probe); EXPECT_TRUE(mutate(0)); }
    EXPECT_TRUE(observed);
    EXPECT_FALSE(record().backup.automatic);
    EXPECT_FALSE(record().backupRequired);
    enable();
    ASSERT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, DisabledBackupsDoNotRequireSyncEvenWithAPreviousPendingIntent)
{
    enable(); ASSERT_TRUE(mutate(0));
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(registered.localId, {}, error));
    probe.failSync = true;
    { ProbeScope scope(probe); EXPECT_TRUE(mutate(1)); }
    EXPECT_EQ(probe.syncs, 0);
    EXPECT_TRUE(record().backupRequired);
}

TEST_F(VaultDirtyTrackingTest, UnsafeConfigurationRefusesCrudWithoutFollowingItsSymlink)
{
    enable();
    const auto saved = directory.filePath("saved-config.ini");
    ASSERT_TRUE(QFile::rename(config, saved));
    ASSERT_TRUE(QFile::link(saved, config));
    const auto before = bytes(path), configuration = bytes(saved);
    { ProbeScope scope(probe); EXPECT_FALSE(mutate(0)); }
    EXPECT_EQ(probe.opens, 0);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(bytes(saved), configuration);
}

TEST_F(VaultDirtyTrackingTest, PersistenceFailureDoesNotModifyTheCallersCredential)
{
    enable();
    const auto before = bytes(path);
    auto value = fictitious(); const auto originalValue = value;
    probe.failSync = true;
    std::string failure;
    {
        ProbeScope scope(probe);
        EXPECT_FALSE(CredentialService::add(path.toStdString(), key, value, failure));
    }
    EXPECT_TRUE(value.id == originalValue.id && value.version == originalValue.version
        && value.title == originalValue.title && value.url == originalValue.url
        && value.username == originalValue.username && value.password == originalValue.password
        && value.notes == originalValue.notes);
    EXPECT_EQ(bytes(path), before);
    EXPECT_EQ(probe.opens, 0);
}

TEST_F(VaultDirtyTrackingTest, PreferencesAndQtSettingsPreserveIntentWithoutStoringEntrySecrets)
{
    {
        QSettings settings("PassWall", "PassWall");
        settings.setValue("security/autoLockMinutes", 15);
        settings.setValue("unrelated/future", "keep-me");
        settings.sync();
    }
    enable(); ASSERT_TRUE(mutate(0));
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(registered.localId, {}, error));
    EXPECT_TRUE(record().backupRequired); // Disabling is not backup confirmation.
    ASSERT_TRUE(mutate(0));
    EXPECT_TRUE(record().backupRequired);
    QSettings settings(config, QSettings::IniFormat);
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 15);
    EXPECT_EQ(settings.value("unrelated/future").toString(), "keep-me");
    const auto file = bytes(config);
    EXPECT_FALSE(file.contains(original.password.c_str()));
    EXPECT_FALSE(file.contains(original.notes.c_str()));
    EXPECT_FALSE(file.contains(original.username.c_str()));
    EXPECT_FALSE(file.contains(original.title.c_str()));
    const auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    EXPECT_EQ(root["vaults"].toArray().first().toObject()["backup"].toObject().size(), 3);
}
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    QTemporaryDir isolated;
    if (!isolated.isValid()) return 2;
    for (auto format : {QSettings::NativeFormat, QSettings::IniFormat}) {
        QSettings::setPath(format, QSettings::UserScope, isolated.path());
        QSettings::setPath(format, QSettings::SystemScope, isolated.path());
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
