#include "services/vault_replacement_authorization.hpp"
#include "services/vault_replacement_service.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_storage.hpp"
#include "storage/vault_operation_guard.hpp"
#include <gtest/gtest.h>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QProcess>
#include <QLockFile>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>
#include <type_traits>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>
#include <sqlite3.h>

using namespace passwall::services;
using passwall::storage::VaultOperationGuard;

namespace passwall::services {
// A simulated acknowledgement, NOT evidence of real MainWindow cleanup. This
// class is not declared/friended in any production target.
class ReplacementTestAccess {
public:
    static VaultReplacementAuthorization issue(const VaultPreferencesStore& store,
        const QString& id, QString& error) {
        return VaultReplacementAuthorization::acknowledge(
            VaultReplacementAuthorization::reserve(store, id, [] { return true; }, error), error);
    }
    static auto reserve(const VaultPreferencesStore& store, const QString& id, QString& error) {
        return VaultReplacementAuthorization::reserve(store, id, [] { return true; }, error);
    }
    static VaultReplacementAuthorization acknowledge(auto state, QString& error) {
        return VaultReplacementAuthorization::acknowledge(std::move(state), error);
    }
    static void revoke(auto state) { VaultReplacementAuthorization::revoke(state); }
    static bool stage(VaultReplacementAuthorization& a, const QString& path, QString& error) {
        return a.stageCandidate(path, error);
    }
    static bool arm(VaultReplacementAuthorization& a, QString& error) { return a.armPublication(error); }
    static bool finish(VaultReplacementAuthorization& a, QString& error) {
        const auto result = a.finalizePublication(); error = result.diagnostic;
        return result.state == ReplacementFinalizationState::Resolved;
    }
    static bool confirm(const VaultPreferencesStore& store, const QString& id,
        const VaultReplacementIntent& intent, const VaultFileIdentity& observed,
        QString& error, RegistryPersistence* persistence = nullptr) {
        return store.confirmReplacementIdentity(id, intent, observed, error, persistence);
    }
    static bool resolve(const VaultPreferencesStore& store, const QString& id,
        const VaultReplacementIntent& intent, const VaultFileIdentity& observed,
        QString& error, RegistryPersistence* persistence = nullptr) {
        return store.resolveReplacement(id, intent, observed, true, error, persistence);
    }
    // Pure registry transition simulation: no file substituted, no claim of
    // filesystem publication/authentication. The production entry point above
    // additionally checks original pathname AND candidate inode reservations.
    static bool transition(const VaultPreferencesStore& store, const QString& id,
        const VaultReplacementIntent& intent, const VaultFileIdentity& observed,
        bool completed, QString& error) {
        if (!completed) return store.resolveReplacement(id, intent, observed, false, error);
        if (!store.confirmReplacementIdentity(id, intent, observed, error)) return false;
        auto confirmed = intent; confirmed.phase = "identity-confirmed"; confirmed.confirmed = observed;
        return store.resolveReplacement(id, confirmed, observed, true, error);
    }
};
}
namespace {
bool failSync = false;
enum class RegistryFault { None, Open, FileSync, DirectorySync, BeforeSync, SyncError, AfterSync };
RegistryFault registryFault = RegistryFault::None;
std::string faultConfig;
int faultCountdown = 1;
bool sawVisiblePublication = false;
bool descriptorIs(int fd, const std::string& path) {
    char proc[64], actual[4096];
    const int length = std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    if (length <= 0 || length >= int(sizeof(proc))) return false;
    const auto size = ::readlink(proc, actual, sizeof(actual));
    return size >= 0 && std::size_t(size) == path.size()
        && std::memcmp(actual, path.data(), path.size()) == 0;
}
bool trigger(RegistryFault fault) {
    if (registryFault != fault || --faultCountdown != 0) return false;
    registryFault = RegistryFault::None;
    return true;
}
using Authorization = VaultReplacementAuthorization;
static_assert(!std::is_copy_constructible_v<Authorization>);
static_assert(!std::is_copy_assignable_v<Authorization>);
static_assert(std::is_nothrow_move_constructible_v<Authorization>);
static_assert(std::is_nothrow_move_assignable_v<Authorization>);
static_assert(!std::is_constructible_v<Authorization, bool>);
static_assert(!std::is_constructible_v<Authorization, QString, bool>);

class VaultReplacementTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    QString path, candidate, config, error;
    VaultRegistration registered;
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_TRUE(directory.isValid());
        for (auto format : {QSettings::NativeFormat, QSettings::IniFormat}) {
            QSettings::setPath(format, QSettings::UserScope, directory.path());
            QSettings::setPath(format, QSettings::SystemScope, directory.path());
        }
        config = QSettings("PassWall", "PassWall").fileName();
        faultConfig = config.toStdString();
        path = directory.filePath("principal.db");
        candidate = directory.filePath("private-candidate.db");
        makeVault(path, 0x41); makeVault(candidate, 0x42);
        ASSERT_EQ(store().recognizeOrRegister(path, registered, error), VaultRecognition::Registered);
    }
    void TearDown() override { failSync = false; registryFault = RegistryFault::None; faultCountdown = 1; }
    VaultPreferencesStore store() { return VaultPreferencesStore(config); }
    void makeVault(const QString& file, unsigned char id) {
        std::string failure;
        ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(file.toStdString(), failure));
        VaultKeyMetadata metadata; metadata.vaultId.fill(id);
        ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(file.toStdString(), metadata, failure));
    }
    Authorization issue() { return ReplacementTestAccess::issue(store(), registered.localId, error); }
    VaultRegistration read() {
        QVector<VaultRegistration> records;
        EXPECT_TRUE(store().list(records, error));
        for (const auto& record : records) if (record.localId == registered.localId) return record;
        ADD_FAILURE(); return {};
    }
    QByteArray bytes(const QString& file) {
        QFile value(file); EXPECT_TRUE(value.open(QIODevice::ReadOnly)); return value.readAll();
    }
    void corruptRegistry() {
        QSettings settings(config, QSettings::IniFormat);
        settings.setValue("vaultRegistry/data", QByteArray("not-json")); settings.sync();
    }
    // Model an already-observed post-publication layout WITHOUT replacing,
    // renaming or rewriting either vault. Only test registry observations are
    // synthesized. Production finalization must obtain them under 6A locks.
    VaultReplacementIntent modelEngagedLayout() {
        VaultFileIdentity old;
        EXPECT_TRUE(VaultPreferencesStore::inspectVault(candidate, old, error));
        auto previous = old; previous.path = path;
        auto staged = registered.file; staged.path = candidate;
        VaultReplacementIntent intent;
        intent.operationId = QUuid::createUuid().toString(QUuid::WithoutBraces);
        intent.previous = previous;
        intent.previousDigest = QCryptographicHash::hash(bytes(candidate), QCryptographicHash::Sha256);
        intent.candidate = staged; intent.phase = "armed"; intent.recoveryArtifacts = {candidate};
        QSettings settings(config, QSettings::IniFormat);
        auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
        auto records = root["vaults"].toArray(); auto r = records[0].toObject();
        const auto identity = [](const VaultFileIdentity& f) {
            return QJsonObject{{"path", f.path}, {"vaultId", QString::fromLatin1(f.vaultId.toHex())},
                {"device", QString::number(f.device)}, {"inode", QString::number(f.inode)}, {"birthTime", f.birthTime}};
        };
        r["file"] = identity(previous);
        r["replacement"] = QJsonObject{{"version", 1}, {"operation", intent.operationId},
            {"phase", intent.phase}, {"previous", identity(previous)},
            {"previousDigest", QString::fromLatin1(intent.previousDigest.toHex())},
            {"candidate", identity(staged)}, {"artifacts", QJsonArray{candidate}}};
        records[0] = r; root["vaults"] = records;
        settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
        EXPECT_EQ(settings.status(), QSettings::NoError);
        return intent;
    }
    VaultReplacementIntent confirmLayout() {
        auto intent = modelEngagedLayout();
        EXPECT_TRUE(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error));
        return *read().replacement;
    }
    void childProbe(const QString& action, const QString& operation, bool allowed) {
        QProcess child;
        child.start(QCoreApplication::applicationFilePath(), {"--registry-probe", config, path,
            registered.localId, operation, action, allowed ? "allowed" : "blocked"});
        ASSERT_TRUE(child.waitForFinished(5000));
        ASSERT_EQ(child.exitStatus(), QProcess::NormalExit);
        EXPECT_EQ(child.exitCode(), 0) << child.readAllStandardError().constData();
    }
};
}
// Reuse the existing test-only issuer; do not add another production factory.
VaultReplacementAuthorization issueReplacementEngineTest(const VaultPreferencesStore& store,
    const QString& id, QString& error) {
    return ReplacementTestAccess::issue(store, id, error);
}
void replacementRegistrySyncFaultForTest(const QString& config, int ordinal) {
    faultConfig = config.toStdString();
    registryFault = RegistryFault::FileSync; faultCountdown = ordinal;
}
bool replacementEngineSyncFault(int fd);
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd) {
    if (replacementEngineSyncFault(fd)) { errno = EIO; return -1; }
    if (failSync) { failSync = false; errno = EIO; return -1; }
    if ((descriptorIs(fd, faultConfig) && trigger(RegistryFault::FileSync))
        || (descriptorIs(fd, QFileInfo(QString::fromStdString(faultConfig)).absolutePath().toStdString())
            && trigger(RegistryFault::DirectorySync))) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
extern "C" int __real_openat(int, const char*, int, ...);
extern "C" int __wrap_openat(int directory, const char* name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list arguments; va_start(arguments, flags); mode = va_arg(arguments, int); va_end(arguments); }
    if (registryFault == RegistryFault::Open && name
        && std::strcmp(name, QFileInfo(QString::fromStdString(faultConfig)).fileName().toLocal8Bit().constData()) == 0
        && trigger(RegistryFault::Open)) { errno = EACCES; return -1; }
    return __real_openat(directory, name, flags, mode);
}
extern "C" void realSettingsSync(QSettings*) asm("__real__ZN9QSettings4syncEv");
extern "C" void __wrap__ZN9QSettings4syncEv(QSettings* settings) {
    const bool target = settings->fileName().toStdString() == faultConfig;
    if (target && trigger(RegistryFault::BeforeSync)) throw std::bad_alloc();
    if (target && trigger(RegistryFault::SyncError)) {
        const auto parent = QFile::encodeName(QFileInfo(settings->fileName()).absolutePath());
        ::chmod(parent.constData(), 0500);
        realSettingsSync(settings); // Real QSettings AccessError, not a forged status.
        ::chmod(parent.constData(), 0700);
        return;
    }
    realSettingsSync(settings);
    if (target && trigger(RegistryFault::AfterSync)) {
        QFile file(settings->fileName());
        if (file.open(QIODevice::ReadOnly)) sawVisiblePublication = file.readAll().contains("identity-confirmed");
        throw std::bad_alloc();
    }
}
namespace {
TEST_F(VaultReplacementTest, DefaultAuthorityIsNotADeclarationOfCleanup) {
    Authorization empty; EXPECT_FALSE(empty.valid(error)); EXPECT_FALSE(error.isEmpty());
}
TEST_F(VaultReplacementTest, BoundToOneRegistrationAndUniqueOperation) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); EXPECT_EQ(a.localId(), registered.localId);
    const auto operation = a.operationId(); ASSERT_FALSE(QUuid(operation).isNull());
    ASSERT_TRUE(a.abandonPreparation(error)); auto b = issue(); ASSERT_TRUE(b.valid(error));
    EXPECT_NE(operation, b.operationId());
}
TEST_F(VaultReplacementTest, ReservationRefusedWhileBusinessAccessLives) {
    VaultOperationGuard access; std::string failure;
    ASSERT_TRUE(access.tryAccess(path.toStdString(), failure));
    auto a = issue(); EXPECT_FALSE(a.valid(error)); EXPECT_FALSE(read().replacement);
}
TEST_F(VaultReplacementTest, ReservationRefusedWhileAnotherReservationLives) {
    VaultOperationGuard access; std::string failure;
    ASSERT_TRUE(access.tryReserve(path.toStdString(), failure));
    auto a = issue(); EXPECT_FALSE(a.valid(error));
}
TEST_F(VaultReplacementTest, ReservationAloneDoesNotIssueOrPersistAuthority) {
    auto state = ReplacementTestAccess::reserve(store(), registered.localId, error);
    ASSERT_NE(state, nullptr); EXPECT_FALSE(read().replacement);
    ReplacementTestAccess::revoke(state);
    auto a = ReplacementTestAccess::acknowledge(state, error); EXPECT_FALSE(a.valid(error));
}
TEST_F(VaultReplacementTest, UnknownRegistrationRefused) {
    auto a = ReplacementTestAccess::issue(store(), QUuid::createUuid().toString(QUuid::WithoutBraces), error);
    EXPECT_FALSE(a.valid(error));
}
TEST_F(VaultReplacementTest, UnexpectedInitialMetadataCannotReceiveAuthority) {
    sqlite3* raw = nullptr;
    const int opened = sqlite3_open_v2(path.toStdString().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> database(raw, sqlite3_close_v2);
    ASSERT_EQ(opened, SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(raw, "UPDATE vault_metadata SET vault_id=zeroblob(16)", nullptr, nullptr, nullptr), SQLITE_OK);
    database.reset();
    auto a = issue(); EXPECT_FALSE(a.valid(error)); EXPECT_FALSE(read().replacement);
}
TEST_F(VaultReplacementTest, MoveTransfersExclusiveOwnershipAndInvalidatesSource) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); Authorization b(std::move(a));
    EXPECT_FALSE(a.valid(error)); ASSERT_TRUE(b.valid(error));
    Authorization c; c = std::move(b); EXPECT_FALSE(b.valid(error)); EXPECT_TRUE(c.valid(error));
}
TEST_F(VaultReplacementTest, ResetRevokesButNeverErasesRecoveryEvidence) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); a.reset(); EXPECT_FALSE(a.valid(error));
    EXPECT_TRUE(read().replacement); EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::RecoveryRequired);
}
TEST_F(VaultReplacementTest, ScopeExitLeavesAnInterruptedOperationBlocked) {
    { auto a = issue(); ASSERT_TRUE(a.valid(error)); }
    auto restarted = VaultPreferencesStore(config);
    EXPECT_EQ(restarted.recoveryAccess(path, error), VaultRecoveryAccess::RecoveryRequired);
    auto next = issue(); EXPECT_FALSE(next.valid(error));
}
TEST_F(VaultReplacementTest, AnotherVaultRemainsAccessible) {
    auto a = issue(); ASSERT_TRUE(a.valid(error));
    EXPECT_EQ(store().recoveryAccess(candidate, error), VaultRecoveryAccess::Allowed);
    VaultKeyMetadata metadata; std::string failure;
    EXPECT_TRUE(passwall::storage::VaultStorage::readMetadata(candidate.toStdString(), metadata, failure));
}
TEST_F(VaultReplacementTest, PendingIntentPreventsRecognitionAndOldReassociationBypass) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); a.reset(); VaultRegistration output;
    EXPECT_EQ(store().recognizeOrRegister(path, output, error), VaultRecognition::Error);
    EXPECT_FALSE(store().updateIdentityAfterReplacement(registered.localId, registered.file, registered.file, error));
    EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, PendingIntentPreventsDirectSqlAndAuthentication) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); a.reset(); const auto before = bytes(path);
    std::string failure; VaultKeyMetadata metadata;
    EXPECT_FALSE(passwall::storage::VaultStorage::readMetadata(path.toStdString(), metadata, failure));
    EXPECT_FALSE(passwall::storage::VaultStorage::writeMetadata(path.toStdString(), metadata, failure));
    passwall::core::SecureBuffer key(0);
    EXPECT_FALSE(VaultLifecycleService::unlockVault(path.toStdString(), "fictitious-password", key, failure));
    EXPECT_TRUE(failure.find("récupération") != std::string::npos);
    EXPECT_TRUE(key.empty()); EXPECT_EQ(bytes(path), before); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, PendingIntentPreventsDirectCrudWithoutChangingCaller) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); a.reset(); const auto before = bytes(path);
    passwall::core::SecureBuffer key(32); std::fill_n(key.data(), 32, 0x42);
    passwall::models::Credential credential; credential.title = "Fictitious";
    credential.username = "fictitious"; credential.password = "fictitious-password";
    const auto original = credential; std::string failure;
    EXPECT_FALSE(CredentialService::add(path.toStdString(), key, credential, failure));
    EXPECT_TRUE(failure.find("récupération") != std::string::npos);
    EXPECT_FALSE(CredentialService::update(path.toStdString(), key, credential, failure));
    EXPECT_TRUE(failure.find("récupération") != std::string::npos);
    EXPECT_FALSE(CredentialService::remove(path.toStdString(), key, credential.id, failure));
    EXPECT_TRUE(failure.find("récupération") != std::string::npos);
    EXPECT_TRUE(credential.password == original.password); EXPECT_EQ(credential.id, original.id);
    EXPECT_EQ(bytes(path), before);
}
TEST_F(VaultReplacementTest, PendingIntentPreventsSnapshotWithoutPublication) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); a.reset(); SnapshotResult result;
    const auto destination = directory.filePath("export.db");
    EXPECT_FALSE(VaultSnapshotService::createSnapshot(path.toStdString(), destination.toStdString(), result));
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished); EXPECT_FALSE(QFile::exists(destination));
}
TEST_F(VaultReplacementTest, CorruptRegistryIsUnknownNotAnOrdinaryNoncriticalWarning) {
    corruptRegistry(); EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::Unavailable);
    VaultKeyMetadata metadata; std::string failure;
    EXPECT_FALSE(passwall::storage::VaultStorage::readMetadata(path.toStdString(), metadata, failure));
}
TEST_F(VaultReplacementTest, BusyRegistryDoesNotGrantSqlAccess) {
    QLockFile lock(config + ".registry-lock"); ASSERT_TRUE(lock.tryLock(0));
    EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::Unavailable);
    passwall::core::SecureBuffer key(0); std::string failure;
    EXPECT_FALSE(VaultLifecycleService::unlockVault(path.toStdString(), "fictitious", key, failure));
}
TEST_F(VaultReplacementTest, DurabilityFailureCannotIssueAuthority) {
    failSync = true; auto a = issue(); EXPECT_FALSE(a.valid(error));
    // Visibility may survive fsync failure: no automatic rollback of the fence.
    EXPECT_TRUE(read().replacement);
    VaultOperationGuard reservation; std::string failure;
    EXPECT_TRUE(reservation.tryReserve(path.toStdString(), failure));
}
TEST_F(VaultReplacementTest, CandidatePersistenceFailureRevokesAuthorityAndPreservesFence) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); failSync = true;
    EXPECT_FALSE(ReplacementTestAccess::stage(a, candidate, error)); EXPECT_FALSE(a.valid(error));
    EXPECT_TRUE(read().replacement);
    EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::RecoveryRequired);
}
TEST_F(VaultReplacementTest, ArmingPersistenceFailureNeverGrantsPublication) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    failSync = true; EXPECT_FALSE(ReplacementTestAccess::arm(a, error)); EXPECT_FALSE(a.valid(error));
    EXPECT_TRUE(read().replacement); EXPECT_FALSE(ReplacementTestAccess::finish(a, error));
}
TEST_F(VaultReplacementTest, MalformedRecoveryFenceIsUnavailableNotIgnored) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); a.reset();
    QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    auto records = root["vaults"].toArray(); auto record = records[0].toObject();
    auto intent = record["replacement"].toObject(); intent["phase"] = "unknown";
    record["replacement"] = intent; records[0] = record; root["vaults"] = records;
    settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::Unavailable);
}
TEST_F(VaultReplacementTest, OrdinaryMissingRegistryAllowsUnregisteredVault) {
    EXPECT_EQ(VaultPreferencesStore(directory.filePath("new-settings/file.ini")).recoveryAccess(path, error),
        VaultRecoveryAccess::Allowed);
}
TEST_F(VaultReplacementTest, ScopedAbortVerifiesOriginalAndAllowsFreshOperation) {
    const auto before = bytes(path); auto a = issue(); ASSERT_TRUE(a.valid(error));
    ASSERT_TRUE(a.abandonPreparation(error)); EXPECT_FALSE(a.valid(error)); EXPECT_FALSE(read().replacement);
    EXPECT_EQ(bytes(path), before); auto b = issue(); EXPECT_TRUE(b.valid(error));
}
TEST_F(VaultReplacementTest, ChangedContentCannotBeClearedByAnOldPreparation) {
    auto a = issue(); ASSERT_TRUE(a.valid(error));
    QFile changed(path); ASSERT_TRUE(changed.open(QIODevice::Append)); ASSERT_EQ(changed.write("x"), 1); changed.close();
    EXPECT_FALSE(a.abandonPreparation(error)); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, StagedCandidateDoesNotChangePrincipalOrGrantCrud) {
    const auto before = bytes(path); auto a = issue(); ASSERT_TRUE(a.valid(error));
    ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    EXPECT_EQ(bytes(path), before); const auto record = read(); ASSERT_TRUE(record.replacement->candidate);
    EXPECT_EQ(record.replacement->candidate->path, candidate);
    EXPECT_EQ(store().recoveryAccess(candidate, error), VaultRecoveryAccess::RecoveryRequired);
    EXPECT_TRUE(a.abandonPreparation(error)); EXPECT_TRUE(QFile::exists(candidate));
}
TEST_F(VaultReplacementTest, RegisteredCandidateRefused) {
    VaultRegistration other; ASSERT_EQ(store().recognizeOrRegister(candidate, other, error), VaultRecognition::Registered);
    auto a = issue(); ASSERT_TRUE(a.valid(error)); EXPECT_FALSE(ReplacementTestAccess::stage(a, candidate, error));
}
TEST_F(VaultReplacementTest, PrincipalCannotBeItsOwnCandidate) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); EXPECT_FALSE(ReplacementTestAccess::stage(a, path, error));
}
TEST_F(VaultReplacementTest, ArmedIntentNeverClearedFromAbsenceOfCandidate) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    ASSERT_TRUE(ReplacementTestAccess::arm(a, error));
    // Simulated disappearance of a private fictitious artifact, NOT replacement.
    ASSERT_TRUE(QFile::remove(candidate));
    EXPECT_FALSE(a.abandonPreparation(error)); EXPECT_TRUE(read().replacement);
    EXPECT_FALSE(ReplacementTestAccess::finish(a, error)); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, FinalizationRefusesUnchangedPrincipalWithoutReleasingReservation) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    ASSERT_TRUE(ReplacementTestAccess::arm(a, error)); EXPECT_FALSE(ReplacementTestAccess::finish(a, error));
    EXPECT_TRUE(a.valid(error)); VaultOperationGuard access; std::string failure;
    EXPECT_FALSE(access.tryAccess(path.toStdString(), failure));
}
TEST_F(VaultReplacementTest, SimulatedIdentityTransitionPreservesPreferencesCatalogueAndSuspension) {
    // Contract test ONLY: simulate the identity observed after a future swap;
    // the actual principal is never substituted in this phase.
    VaultBackupPreferences prefs{true, directory.filePath("backups"), 4};
    ASSERT_TRUE(store().updatePreferences(registered.localId, prefs, error));
    ASSERT_TRUE(store().suspendAutomaticBackup(registered.localId, error));
    {
        QSettings settings(config, QSettings::IniFormat);
        auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
        auto records = root["vaults"].toArray(); auto record = records[0].toObject();
        record["automaticVersions"] = QJsonArray{QJsonObject{{"kind", "automatic"},
            {"publication", "published"}, {"attempt", QUuid::createUuid().toString(QUuid::WithoutBraces)},
            {"path", directory.filePath("existing-automatic.db")},
            {"createdUtc", "2026-11-09T12:00:00.000Z"}, {"birthTime", ""},
            {"durable", true}, {"device", "1"}, {"inode", "2"}, {"size", "4096"}}};
        records[0] = record; root["vaults"] = records;
        settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    }
    auto a = issue(); ASSERT_TRUE(a.valid(error)); ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    ASSERT_TRUE(ReplacementTestAccess::arm(a, error)); auto record = read();
    auto observed = *record.replacement->candidate; observed.path = path;
    ASSERT_TRUE(ReplacementTestAccess::transition(store(), registered.localId, *record.replacement, observed, true, error));
    const auto after = read(); EXPECT_EQ(after.localId, registered.localId); EXPECT_EQ(after.file, observed);
    ASSERT_EQ(record.automaticVersions.size(), 1);
    EXPECT_EQ(after.backup, prefs); EXPECT_EQ(after.automaticVersions, record.automaticVersions);
    EXPECT_TRUE(after.automaticSuspended); EXPECT_TRUE(after.backupRequired); EXPECT_FALSE(after.replacement);
    EXPECT_FALSE(a.valid(error));
}
TEST_F(VaultReplacementTest, SimulatedTransitionRejectsWrongIdentityAndOperation) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    ASSERT_TRUE(ReplacementTestAccess::arm(a, error)); const auto intent = *read().replacement;
    auto observed = *intent.candidate; observed.path = path; ++observed.inode;
    EXPECT_FALSE(ReplacementTestAccess::transition(store(), registered.localId, intent, observed, true, error));
    auto stale = intent; stale.operationId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    EXPECT_FALSE(ReplacementTestAccess::transition(store(), registered.localId, stale, registered.file, false, error));
    EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, IntentContainsOnlyIdentityAndRecoveryMetadata) {
    auto a = issue(); ASSERT_TRUE(a.valid(error)); QSettings settings(config, QSettings::IniFormat);
    const auto raw = settings.value("vaultRegistry/data").toByteArray();
    const auto root = QJsonDocument::fromJson(raw).object();
    const auto marker = root["vaults"].toArray()[0].toObject()["replacement"].toObject();
    EXPECT_EQ(marker.size(), 6); EXPECT_EQ(marker["version"], 1); EXPECT_EQ(marker["phase"], "prepared");
    EXPECT_FALSE(raw.contains("fictitious-password"));
}

TEST_F(VaultReplacementTest, ArmedStateCannotBeResolvedWithoutProtectedIdentityConfirmation) {
    const auto intent = modelEngagedLayout(); RegistryPersistence persistence;
    EXPECT_FALSE(ReplacementTestAccess::resolve(store(), registered.localId, intent, registered.file, error, &persistence));
    EXPECT_EQ(persistence, RegistryPersistence::NotAttempted);
    EXPECT_EQ(read().replacement->phase, "armed");
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ConfirmedIdentityRemainsProtectedAndKeepsRecoveryReferences) {
    const auto intent = confirmLayout();
    const auto record = read(); EXPECT_EQ(record.file, registered.file);
    EXPECT_EQ(intent.phase, "identity-confirmed"); EXPECT_EQ(intent.confirmed, registered.file);
    EXPECT_EQ(intent.recoveryArtifacts, QStringList{candidate});
    EXPECT_FALSE(record.resolvedReplacement);
    EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::RecoveryRequired);
    const auto before = bytes(path);
    VaultKeyMetadata metadata; std::string failure;
    EXPECT_FALSE(passwall::storage::VaultStorage::readMetadata(path.toStdString(), metadata, failure));
    passwall::core::SecureBuffer key(32); std::fill_n(key.data(), 32, 0x61);
    passwall::models::Credential entry; entry.title = "Fictitious";
    entry.username = "fictitious-user"; entry.password = "fictitious-password";
    EXPECT_FALSE(CredentialService::add(path.toStdString(), key, entry, failure));
    SnapshotResult snapshot;
    EXPECT_FALSE(VaultSnapshotService::createSnapshot(path.toStdString(),
        directory.filePath("ordinary-refused.db").toStdString(), snapshot));
    EXPECT_EQ(bytes(path), before);
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, VisibleIdentityThenFileFsyncFailureNeverDropsRecoveryGate) {
    const auto intent = modelEngagedLayout(); RegistryPersistence persistence;
    registryFault = RegistryFault::FileSync;
    EXPECT_FALSE(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error, &persistence));
    EXPECT_EQ(persistence, RegistryPersistence::Unconfirmed); EXPECT_FALSE(error.isEmpty());
    const auto record = read(); ASSERT_TRUE(record.replacement);
    EXPECT_EQ(record.replacement->phase, "identity-confirmed"); EXPECT_EQ(record.file, registered.file);
    EXPECT_EQ(record.replacement->recoveryArtifacts, intent.recoveryArtifacts);
    EXPECT_EQ(VaultPreferencesStore(config).recoveryAccess(path, error), VaultRecoveryAccess::RecoveryRequired);
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, VisibleIdentityThenDirectoryFsyncFailureKeepsGateAcrossProcesses) {
    const auto intent = modelEngagedLayout(); registryFault = RegistryFault::DirectorySync;
    EXPECT_FALSE(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error));
    EXPECT_EQ(read().replacement->phase, "identity-confirmed");
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ConfigurationOpenFailureAfterPublicationKeepsIdentityProtected) {
    const auto intent = modelEngagedLayout(); registryFault = RegistryFault::Open; faultCountdown = 2;
    EXPECT_FALSE(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error));
    EXPECT_EQ(read().replacement->phase, "identity-confirmed");
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ExceptionBeforePublishingIdentityKeepsArmedRecovery) {
    const auto intent = modelEngagedLayout(); registryFault = RegistryFault::BeforeSync; faultCountdown = 2;
    EXPECT_THROW(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error), std::bad_alloc);
    EXPECT_EQ(read().replacement->phase, "armed"); childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, RealQSettingsSyncErrorDoesNotResolveRecovery) {
    if (::geteuid() == 0) GTEST_SKIP() << "Permission failure requires a non-root test user";
    const auto intent = modelEngagedLayout(); registryFault = RegistryFault::SyncError; faultCountdown = 2;
    EXPECT_FALSE(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error));
    EXPECT_FALSE(error.isEmpty()); EXPECT_TRUE(read().replacement);
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ExceptionAfterVisibleIdentityPublicationRetainsAProtectedVariant) {
    const auto intent = modelEngagedLayout(); registryFault = RegistryFault::AfterSync; faultCountdown = 2;
    sawVisiblePublication = false;
    EXPECT_THROW(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error), std::bad_alloc);
    EXPECT_TRUE(sawVisiblePublication); EXPECT_TRUE(read().replacement);
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ResolutionDurableReceiptPreservesLocalIdentityAndPreferences) {
    const auto before = read(); const auto intent = confirmLayout(); RegistryPersistence persistence;
    ASSERT_TRUE(ReplacementTestAccess::resolve(store(), registered.localId, intent, registered.file, error, &persistence));
    EXPECT_EQ(persistence, RegistryPersistence::Durable);
    const auto record = read(); EXPECT_FALSE(record.replacement); ASSERT_TRUE(record.resolvedReplacement);
    EXPECT_EQ(record.resolvedReplacement->operationId, intent.operationId);
    EXPECT_EQ(record.resolvedReplacement->recoveryArtifacts, intent.recoveryArtifacts);
    EXPECT_EQ(record.file, registered.file); EXPECT_EQ(record.localId, before.localId);
    EXPECT_EQ(record.backup, before.backup); EXPECT_EQ(record.backupRequired, before.backupRequired);
    EXPECT_EQ(record.automaticVersions, before.automaticVersions);
    EXPECT_EQ(record.automaticSuspended, before.automaticSuspended);
    EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::Allowed);
    childProbe("read", intent.operationId, true);
}
TEST_F(VaultReplacementTest, ResolutionVisibleThenFsyncFailureIsSafeAndRetainsReceipt) {
    const auto intent = confirmLayout(); registryFault = RegistryFault::FileSync;
    EXPECT_FALSE(ReplacementTestAccess::resolve(store(), registered.localId, intent, registered.file, error));
    const auto record = read(); EXPECT_FALSE(record.replacement); ASSERT_TRUE(record.resolvedReplacement);
    EXPECT_EQ(record.resolvedReplacement->operationId, intent.operationId);
    EXPECT_TRUE(QFile::exists(candidate)); childProbe("read", intent.operationId, true);
}
TEST_F(VaultReplacementTest, ResolutionDirectorySyncFailureHasOnlySafeObservableVariants) {
    const auto intent = confirmLayout(); registryFault = RegistryFault::DirectorySync;
    EXPECT_FALSE(ReplacementTestAccess::resolve(store(), registered.localId, intent, registered.file, error));
    ASSERT_TRUE(read().resolvedReplacement); childProbe("read", intent.operationId, true);
}
TEST_F(VaultReplacementTest, ExceptionBeforeResolutionLeavesDurablyProtectedIdentity) {
    const auto intent = confirmLayout(); registryFault = RegistryFault::BeforeSync; faultCountdown = 2;
    EXPECT_THROW(ReplacementTestAccess::resolve(store(), registered.localId, intent, registered.file, error), std::bad_alloc);
    EXPECT_EQ(read().replacement->phase, "identity-confirmed"); childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, RestartCanReconfirmAnIdentityAfterFailedDurabilityConfirmation) {
    const auto intent = modelEngagedLayout(); registryFault = RegistryFault::FileSync;
    ASSERT_FALSE(ReplacementTestAccess::confirm(store(), registered.localId, intent, registered.file, error));
    childProbe("resume", intent.operationId, true);
    EXPECT_FALSE(read().replacement); EXPECT_TRUE(read().resolvedReplacement);
}
TEST_F(VaultReplacementTest, ResumeIsIdempotentAndNeverModifiesVaultBytes) {
    const auto intent = confirmLayout(); const auto principalBytes = bytes(path), oldBytes = bytes(candidate);
    auto result = Authorization::resumeFinalization(store(), registered.localId, intent.operationId);
    ASSERT_EQ(result.state, ReplacementFinalizationState::Resolved) << result.diagnostic.toStdString();
    result = Authorization::resumeFinalization(store(), registered.localId, intent.operationId);
    EXPECT_EQ(result.state, ReplacementFinalizationState::Resolved);
    childProbe("resume", intent.operationId, true);
    EXPECT_EQ(bytes(path), principalBytes); EXPECT_EQ(bytes(candidate), oldBytes);
}
TEST_F(VaultReplacementTest, ResumeReportsSafeUnconfirmedResolutionSeparatelyFromFailure) {
    const auto intent = confirmLayout(); registryFault = RegistryFault::FileSync; faultCountdown = 2;
    const auto result = Authorization::resumeFinalization(store(), registered.localId, intent.operationId);
    EXPECT_EQ(result.state, ReplacementFinalizationState::SafeResolutionUnconfirmed);
    EXPECT_FALSE(result.diagnostic.isEmpty()); ASSERT_TRUE(read().resolvedReplacement);
    childProbe("read", intent.operationId, true);
}
TEST_F(VaultReplacementTest, ResumeReportsUnconfirmedIdentityAndKeepsGate) {
    const auto intent = confirmLayout(); registryFault = RegistryFault::FileSync;
    const auto result = Authorization::resumeFinalization(store(), registered.localId, intent.operationId);
    EXPECT_EQ(result.state, ReplacementFinalizationState::IdentityUnconfirmed);
    ASSERT_TRUE(read().replacement); childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ResumeRefusesAnotherOperationUuid) {
    const auto intent = confirmLayout(); const auto before = bytes(config);
    EXPECT_EQ(Authorization::resumeFinalization(store(), registered.localId,
        QUuid::createUuid().toString(QUuid::WithoutBraces)).state, ReplacementFinalizationState::RecoveryRequired);
    EXPECT_EQ(bytes(config), before); EXPECT_TRUE(read().replacement);
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, ResumeNeverAdvancesPreparedOrArmedIntent) {
    { auto a = issue(); const auto operation = a.operationId(); a.reset();
      childProbe("refuse", operation, false); }
    // Do not clear that fence simply to prepare another operation.
    EXPECT_EQ(read().replacement->phase, "prepared");
}
TEST_F(VaultReplacementTest, ResumeDoesNotInferPublicationFromAnArmedLayout) {
    const auto intent = modelEngagedLayout(); childProbe("refuse", intent.operationId, false);
    EXPECT_EQ(read().replacement->phase, "armed");
}
TEST_F(VaultReplacementTest, ResumeRefusesChangedPrincipalIdentity) {
    const auto intent = confirmLayout();
    // Substitute only the TEST REGISTRY's expected inode, never the principal.
    QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    auto records = root["vaults"].toArray(); auto r = records[0].toObject();
    auto file = r["file"].toObject(); file["inode"] = QString::number(registered.file.inode + 1); r["file"] = file;
    auto fence = r["replacement"].toObject(); fence["confirmed"] = file;
    auto staged = file; staged["path"] = candidate; fence["candidate"] = staged; r["replacement"] = fence;
    records[0] = r; root["vaults"] = records;
    settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    EXPECT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::RecoveryRequired);
    childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, MissingOldArtifactCannotResolveConfirmedIdentity) {
    const auto intent = confirmLayout(); const auto oldBytes = bytes(candidate);
    ASSERT_TRUE(QFile::remove(candidate)); // Only a fictitious artifact owned by this fixture.
    EXPECT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::RecoveryRequired);
    EXPECT_TRUE(read().replacement); EXPECT_FALSE(oldBytes.isEmpty());
}
TEST_F(VaultReplacementTest, AlteredOldArtifactDigestCannotResolveConfirmedIdentity) {
    const auto intent = confirmLayout();
    QFile old(candidate); ASSERT_TRUE(old.open(QIODevice::Append)); ASSERT_EQ(old.write("x"), 1); old.close();
    EXPECT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::RecoveryRequired);
    EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, ResumeRefusesWhileAnExclusiveReservationStillLives) {
    const auto intent = confirmLayout(); VaultOperationGuard reservation; std::string failure;
    ASSERT_TRUE(reservation.tryReserve(path.toStdString(), failure));
    EXPECT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::RecoveryRequired);
    EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, ResolvedOldArtifactIsNotAnOrdinaryVaultOrAutomaticVersion) {
    const auto intent = confirmLayout();
    ASSERT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::Resolved);
    EXPECT_EQ(store().recoveryAccess(candidate, error), VaultRecoveryAccess::RecoveryRequired);
    EXPECT_TRUE(read().automaticVersions.isEmpty()); EXPECT_TRUE(QFile::exists(candidate));
}
TEST_F(VaultReplacementTest, ReceiptDoesNotAuthorizeUnexpectedPhysicalFile) {
    const auto intent = confirmLayout();
    ASSERT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::Resolved);
    // Point the test receipt consistently at an inode that isn't present.
    QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    auto records = root["vaults"].toArray(); auto r = records[0].toObject();
    auto file = r["file"].toObject(); file["inode"] = QString::number(registered.file.inode + 1); r["file"] = file;
    auto receipt = r["resolvedReplacement"].toObject(); receipt["confirmed"] = file;
    auto staged = file; staged["path"] = candidate; receipt["candidate"] = staged; r["resolvedReplacement"] = receipt;
    records[0] = r; root["vaults"] = records;
    settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    childProbe("read", intent.operationId, false);
}

TEST_F(VaultReplacementTest, SnapshotOfPrincipalRequiresLivePreparedAuthority) {
    const auto before = bytes(path); auto a = issue(); ASSERT_TRUE(a.valid(error));
    SnapshotResult result; const auto output = directory.filePath("precaution.db");
    ASSERT_TRUE(a.snapshotPrincipal(output.toStdString(), result)) << result.diagnostic;
    EXPECT_EQ(result.publication, SnapshotPublication::Published); EXPECT_TRUE(QFile::exists(output));
    EXPECT_EQ(bytes(path), before); EXPECT_TRUE(read().replacement); EXPECT_TRUE(read().automaticVersions.isEmpty());
    VaultOperationGuard access; std::string failure; EXPECT_FALSE(access.tryAccess(path.toStdString(), failure));
    ASSERT_TRUE(a.abandonPreparation(error));
    VaultKeyMetadata original, copy;
    ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(path.toStdString(), original, failure));
    ASSERT_TRUE(passwall::storage::VaultStorage::readMetadata(output.toStdString(), copy, failure));
    EXPECT_EQ(original.vaultId, copy.vaultId);
}
TEST_F(VaultReplacementTest, SimpleExclusiveReservationCannotBypassRecoveryForSnapshot) {
    { auto a = issue(); a.reset(); }
    VaultOperationGuard reservation; std::string failure;
    ASSERT_TRUE(reservation.tryReserve(path.toStdString(), failure));
    SnapshotResult result; const auto output = directory.filePath("refused.db");
    EXPECT_FALSE(VaultSnapshotService::createSnapshot(path.toStdString(), output.toStdString(), result,
        {}, {}, &reservation)); EXPECT_FALSE(QFile::exists(output));
}
TEST_F(VaultReplacementTest, RevokedAuthorityCannotSnapshotOrPublish) {
    auto a = issue(); a.reset(); SnapshotResult result;
    const auto output = directory.filePath("refused.db");
    EXPECT_FALSE(a.snapshotPrincipal(output.toStdString(), result)); EXPECT_FALSE(QFile::exists(output));
}
TEST_F(VaultReplacementTest, ArmedAuthorityCannotReadTheOldPrincipal) {
    auto a = issue(); ASSERT_TRUE(ReplacementTestAccess::stage(a, candidate, error));
    ASSERT_TRUE(ReplacementTestAccess::arm(a, error)); SnapshotResult result;
    EXPECT_FALSE(a.snapshotPrincipal(directory.filePath("refused.db").toStdString(), result));
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
}
TEST_F(VaultReplacementTest, SnapshotRefusesAChangedOperationIntent) {
    auto a = issue(); QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    auto records = root["vaults"].toArray(); auto r = records[0].toObject(); auto intent = r["replacement"].toObject();
    intent["operation"] = QUuid::createUuid().toString(QUuid::WithoutBraces); r["replacement"] = intent;
    records[0] = r; root["vaults"] = records;
    settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    SnapshotResult result; EXPECT_FALSE(a.snapshotPrincipal(directory.filePath("refused.db").toStdString(), result));
}
TEST_F(VaultReplacementTest, RevocationDuringCopyPreventsPublicationWithoutDanglingReservation) {
    auto a = issue(); SnapshotResult result; const auto output = directory.filePath("refused.db");
    struct Context { Authorization* authority; bool revoked = false; } context{&a};
    SnapshotCancellation revoke{[](void* value, SnapshotCheckpoint point) noexcept {
        auto& c = *static_cast<Context*>(value);
        if (point == SnapshotCheckpoint::CopyStep) { c.authority->reset(); c.revoked = true; }
        return false; // Must be the permission recheck, not cancellation, that refuses.
    }, &context};
    EXPECT_FALSE(a.snapshotPrincipal(output.toStdString(), result, revoke));
    EXPECT_TRUE(context.revoked); EXPECT_FALSE(QFile::exists(output));
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, RevocationImmediatelyBeforePublicationDoesNotPublishSnapshot) {
    auto a = issue(); SnapshotResult result; const auto output = directory.filePath("refused.db");
    SnapshotCancellation revoke{[](void* value, SnapshotCheckpoint point) noexcept {
        if (point == SnapshotCheckpoint::BeforePublication) static_cast<Authorization*>(value)->reset();
        return false;
    }, &a};
    EXPECT_FALSE(a.snapshotPrincipal(output.toStdString(), result, revoke));
    EXPECT_FALSE(QFile::exists(output)); EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
}
TEST_F(VaultReplacementTest, SnapshotCannotOverwriteAnotherVaultOrUseItAsItsSource) {
    auto a = issue(); const auto otherBytes = bytes(candidate); SnapshotResult result;
    EXPECT_FALSE(a.snapshotPrincipal(candidate.toStdString(), result));
    EXPECT_EQ(bytes(candidate), otherBytes); EXPECT_EQ(result.publication, SnapshotPublication::NotPublished);
    // No source argument exists in this capability API; the only source is path.
    VaultOperationGuard unrelated; std::string failure;
    EXPECT_TRUE(unrelated.tryAccess(candidate.toStdString(), failure));
}
TEST_F(VaultReplacementTest, SnapshotCancellationCleansOnlyItsOwnedTemporaryFiles) {
    auto a = issue(); const auto before = QDir(directory.path()).entryList(QDir::AllEntries | QDir::Hidden);
    SnapshotResult result; const auto output = directory.filePath("cancelled.db");
    SnapshotCancellation cancel{[](void*, SnapshotCheckpoint point) noexcept {
        return point == SnapshotCheckpoint::BeforePublication;
    }, nullptr};
    EXPECT_FALSE(a.snapshotPrincipal(output.toStdString(), result, cancel));
    EXPECT_EQ(result.publication, SnapshotPublication::CancelledBeforePublication);
    EXPECT_EQ(QDir(directory.path()).entryList(QDir::AllEntries | QDir::Hidden), before);
    EXPECT_TRUE(a.valid(error)); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, ExceptionAfterResolutionPublicationNeverLosesBothSafeVariants) {
    const auto intent = confirmLayout(); registryFault = RegistryFault::AfterSync; faultCountdown = 5;
    const auto result = Authorization::resumeFinalization(store(), registered.localId, intent.operationId);
    EXPECT_EQ(result.state, ReplacementFinalizationState::SafeResolutionUnconfirmed);
    const auto record = read();
    EXPECT_NE(record.replacement.has_value(), record.resolvedReplacement.has_value());
    if (record.replacement) EXPECT_EQ(record.replacement->phase, "identity-confirmed");
    childProbe("read", intent.operationId, record.resolvedReplacement.has_value());
    EXPECT_TRUE(QFile::exists(candidate));
}
TEST_F(VaultReplacementTest, RealSyncErrorDuringResolutionLeavesASafeProtectedVariant) {
    if (::geteuid() == 0) GTEST_SKIP() << "Permission failure requires a non-root test user";
    const auto intent = confirmLayout(); registryFault = RegistryFault::SyncError; faultCountdown = 2;
    EXPECT_FALSE(ReplacementTestAccess::resolve(store(), registered.localId, intent, registered.file, error));
    EXPECT_TRUE(read().replacement); childProbe("read", intent.operationId, false);
}
TEST_F(VaultReplacementTest, OldResolutionUuidCannotResolveANewPreparation) {
    const auto intent = confirmLayout();
    ASSERT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::Resolved);
    auto next = issue(); ASSERT_TRUE(next.valid(error)); EXPECT_NE(next.operationId(), intent.operationId);
    EXPECT_FALSE(read().resolvedReplacement);
    EXPECT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::RecoveryRequired);
    EXPECT_TRUE(next.valid(error)); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, AnotherVaultRemainsUsableDuringIdentityConfirmation) {
    const auto intent = confirmLayout(); const auto unrelated = directory.filePath("unrelated.db");
    makeVault(unrelated, 0x53); VaultKeyMetadata metadata; std::string failure;
    EXPECT_TRUE(passwall::storage::VaultStorage::readMetadata(unrelated.toStdString(), metadata, failure));
    EXPECT_EQ(metadata.vaultId.front(), 0x53); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, ResolvedReceiptDoesNotFreezeLegitimateSubsequentWrites) {
    const auto intent = confirmLayout();
    ASSERT_EQ(Authorization::resumeFinalization(store(), registered.localId, intent.operationId).state,
        ReplacementFinalizationState::Resolved);
    passwall::core::SecureBuffer key(32); std::fill_n(key.data(), 32, 0x61);
    passwall::models::Credential entry; entry.title = "Fictitious";
    entry.username = "fictitious-user"; entry.password = "fictitious-password";
    std::string failure;
    ASSERT_TRUE(CredentialService::add(path.toStdString(), key, entry, failure)) << failure;
    entry.password = "changed-fictitious-password";
    ASSERT_TRUE(CredentialService::update(path.toStdString(), key, entry, failure)) << failure;
    ASSERT_TRUE(CredentialService::remove(path.toStdString(), key, entry.id, failure)) << failure;
    EXPECT_EQ(store().recoveryAccess(path, error), VaultRecoveryAccess::Allowed);
}
TEST_F(VaultReplacementTest, SnapshotRefusesChangedPrincipalBytesEvenWithTheSameInode) {
    auto a = issue(); QFile changed(path); ASSERT_TRUE(changed.open(QIODevice::Append));
    ASSERT_EQ(changed.write("x"), 1); changed.close(); SnapshotResult result;
    const auto output = directory.filePath("refused.db");
    EXPECT_FALSE(a.snapshotPrincipal(output.toStdString(), result)); EXPECT_FALSE(QFile::exists(output));
    EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementTest, SnapshotSyncFailureDoesNotRevokeOrReleaseTheAuthority) {
    auto a = issue(); failSync = true; SnapshotResult result;
    EXPECT_FALSE(a.snapshotPrincipal(directory.filePath("refused.db").toStdString(), result));
    EXPECT_EQ(result.publication, SnapshotPublication::NotPublished); EXPECT_TRUE(a.valid(error));
    VaultOperationGuard access; std::string failure; EXPECT_FALSE(access.tryAccess(path.toStdString(), failure));
}
} // namespace

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    if (argc == 6 && std::strcmp(argv[1], "--replacement-recover") == 0) {
        VaultPreferencesStore store(QString::fromLocal8Bit(argv[2]));
        const auto result = Authorization::recoverReplacement(store, QString::fromLocal8Bit(argv[3]),
            QString::fromLocal8Bit(argv[4]), ReplacementRecoveryAction::FinalizeExchanged);
        return int(result.layout) == std::atoi(argv[5]) ? 0 : 4;
    }
    if (argc == 8 && std::strcmp(argv[1], "--registry-probe") == 0) {
        VaultPreferencesStore store(QString::fromLocal8Bit(argv[2]));
        const QString path = QString::fromLocal8Bit(argv[3]);
        const QString localId = QString::fromLocal8Bit(argv[4]);
        const QString operation = QString::fromLocal8Bit(argv[5]);
        const QString action = QString::fromLocal8Bit(argv[6]);
        // No test environment, QSettings cache, authority or session inherited
        // from the parent. All operations use this explicit isolated registry.
        if (action != "read") {
            const auto result = Authorization::resumeFinalization(store, localId, operation);
            if ((action == "resume") != (result.state == ReplacementFinalizationState::Resolved)) return 2;
        }
        QString error;
        const bool allowed = store.recoveryAccess(path, error) == VaultRecoveryAccess::Allowed;
        return allowed == (std::strcmp(argv[7], "allowed") == 0) ? 0 : 3;
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
