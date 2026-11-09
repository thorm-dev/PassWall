#include "services/vault_replacement_service.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_storage.hpp"
#include "storage/vault_operation_guard.hpp"
#include <gtest/gtest.h>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QSettings>
#include <QTemporaryDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUuid>
#include <array>
#include <cstring>
#include <functional>
#include <span>
#include <sodium.h>
#include <sqlite3.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace passwall::services;
using passwall::core::SecureBuffer;
using passwall::storage::VaultOperationGuard;
VaultReplacementAuthorization issueReplacementEngineTest(const VaultPreferencesStore&, const QString&, QString&);
void replacementRegistrySyncFaultForTest(const QString&, int ordinal);

namespace {
constexpr std::string_view master = "fictitious-replacement-master-v1";
struct Probe {
    int liveSecrets = 0, decryptions = 0, exchanges = 0;
    bool wiped = true, cleanAtExchange = false, cleanAtCandidatePublication = false, failExchange = false;
    bool failDirectoryAfterExchange = false, throwAuth = false, unsupportedFs = false;
    bool assertReservations = false, reservationsHeld = false;
    bool failPrecautionPublication = false, failPrecautionDurability = false, precautionPublished = false;
    std::function<void()> afterCopyStep;
    QString principal, artifact;
    std::array<std::pair<void*, std::size_t>, 128> allocations {};
};
thread_local Probe* active = nullptr;
bool isZero(const void* pointer, std::size_t size) noexcept {
    const auto* bytes = static_cast<const unsigned char*>(pointer);
    for (std::size_t i = 0; i < size; ++i) if (bytes[i]) return false;
    return true;
}
QByteArray bytes(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}
void sql(const QString& path, const char* statement) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(path.toLocal8Bit().constData(), &db), SQLITE_OK);
    struct Close { sqlite3* db; ~Close() { sqlite3_close(db); } } close{db};
    ASSERT_EQ(sqlite3_exec(db, statement, nullptr, nullptr, nullptr), SQLITE_OK);
}
SecureBuffer password(std::string_view value = master) {
    SecureBuffer result(value.size());
    std::memcpy(result.data(), value.data(), value.size()); return result;
}
struct Control {
    std::function<bool(ReplacementCheckpoint)> function;
    static bool call(void* value, ReplacementCheckpoint point) noexcept {
        return static_cast<Control*>(value)->function(point);
    }
    ReplacementControl callback() { return {&call, this}; }
};
class VaultReplacementEngineTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    QString principal, source, precaution, config, error;
    VaultRegistration registered;
    QByteArray original, sourceBytes;
    Probe probe;
    ReplacementResult result;
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0); ASSERT_TRUE(directory.isValid());
        for (auto format : {QSettings::NativeFormat, QSettings::IniFormat})
            for (auto scope : {QSettings::UserScope, QSettings::SystemScope})
                QSettings::setPath(format, scope, directory.path());
        config = QSettings("PassWall", "PassWall").fileName();
        principal = directory.filePath("principal.db"); source = directory.filePath("selected.db");
        precaution = directory.filePath("precaution.db"); probe.principal = principal;
        std::string failure;
        SecureBuffer key(0);
        ASSERT_TRUE(VaultLifecycleService::createVault(principal.toStdString(), std::string(master), key, failure));
        for (int index = 0; index < 3; ++index) {
            passwall::models::Credential entry;
            entry.title = "fictitious-title"; entry.username = "fictitious-user";
            entry.password = "fictitious-password"; entry.notes = "fictitious-notes";
            ASSERT_TRUE(CredentialService::add(principal.toStdString(), key, entry, failure));
            for (auto* field : {&entry.title, &entry.username, &entry.password, &entry.notes}) {
                sodium_memzero(field->data(), field->size()); field->clear();
            }
            if (index == 1) { ASSERT_TRUE(QFile::copy(principal, source)); ASSERT_EQ(::chmod(source.toLocal8Bit(), 0600), 0); }
        }
        ASSERT_EQ(store().recognizeOrRegister(principal, registered, error), VaultRecognition::Registered);
        original = bytes(principal); sourceBytes = bytes(source);
    }
    void TearDown() override { active = nullptr; }
    VaultPreferencesStore store() const { return VaultPreferencesStore(config); }
    VaultRegistration read() const {
        QVector<VaultRegistration> records; QString failure;
        EXPECT_TRUE(store().list(records, failure));
        for (const auto& r : records) if (r.localId == registered.localId) return r;
        ADD_FAILURE(); return {};
    }
    QString candidatePath(const QString& operation) const {
        return directory.filePath(".passwall-restore-" + operation + "/candidate.db");
    }
    void automatic() {
        VaultBackupPreferences preferences; preferences.automatic = true;
        preferences.directory = directory.filePath("absent-automatic-destination"); preferences.retainedVersions = 11;
        ASSERT_TRUE(store().updatePreferences(registered.localId, preferences, error));
        registered = read();
    }
    bool run(Control* control = nullptr, std::string_view value = master, const QString* destination = nullptr) {
        auto authority = issueReplacementEngineTest(store(), registered.localId, error);
        EXPECT_TRUE(authority.valid(error));
        active = &probe;
        const bool success = authority.replacePrincipal(principal, source, password(value),
            destination ? *destination : precaution, result, control ? control->callback() : ReplacementControl{});
        EXPECT_EQ(probe.liveSecrets, 0); EXPECT_TRUE(probe.wiped); active = nullptr;
        authority.reset(); // simulate the caller leaving its operation scope
        EXPECT_FALSE(authority.valid(error));
        return success;
    }
    void blocked() const {
        QString failure;
        EXPECT_EQ(store().recoveryAccess(principal, failure), VaultRecoveryAccess::RecoveryRequired);
    }
    void unchanged() { EXPECT_TRUE(bytes(principal) == original); EXPECT_TRUE(bytes(source) == sourceBytes); }
    void newProcessRecovery(ReplacementLayout expected) {
        const auto record = read();
        const auto intent = record.replacement ? record.replacement : record.resolvedReplacement;
        ASSERT_TRUE(intent);
        QProcess child;
        child.start(QCoreApplication::applicationFilePath(), {"--replacement-recover", config,
            registered.localId, intent->operationId, QString::number(int(expected))});
        ASSERT_TRUE(child.waitForFinished(10000)); ASSERT_EQ(child.exitStatus(), QProcess::NormalExit);
        EXPECT_EQ(child.exitCode(), 0);
    }
    void crashAt(ReplacementCheckpoint point) {
        const pid_t child = ::fork(); ASSERT_GE(child, 0);
        if (child == 0) {
            auto authority = issueReplacementEngineTest(store(), registered.localId, error);
            if (!authority.valid(error)) ::_exit(80);
            Control control{[&](ReplacementCheckpoint p) { if (p == point) ::_exit(71); return false; }};
            ReplacementResult r;
            const bool completed = authority.replacePrincipal(principal, source, password(), precaution, r, control.callback());
            ::_exit(completed ? 81 : 82);
        }
        int status = 0; ASSERT_EQ(::waitpid(child, &status, 0), child);
        ASSERT_TRUE(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 71);
        blocked();
    }
};
} // namespace

extern "C" void* __real_sodium_malloc(std::size_t);
extern "C" void* __wrap_sodium_malloc(std::size_t size) {
    void* pointer = __real_sodium_malloc(size);
    if (active && pointer) for (auto& item : active->allocations) if (!item.first) {
        item = {pointer, size}; ++active->liveSecrets; break;
    }
    return pointer;
}
extern "C" void __real_sodium_free(void*);
extern "C" void __wrap_sodium_free(void* pointer) {
    if (active && pointer) for (auto& item : active->allocations) if (item.first == pointer) {
        active->wiped &= isZero(pointer, item.second); --active->liveSecrets; item = {}; break;
    }
    __real_sodium_free(pointer);
}
extern "C" int __real_crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char*, unsigned long long*, unsigned char*, const unsigned char*, unsigned long long,
    const unsigned char*, unsigned long long, const unsigned char*, const unsigned char*);
extern "C" int __wrap_crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char* m, unsigned long long* ml,
    unsigned char* ns, const unsigned char* c, unsigned long long cl, const unsigned char* ad,
    unsigned long long al, const unsigned char* np, const unsigned char* k) {
    if (active) ++active->decryptions;
    return __real_crypto_aead_xchacha20poly1305_ietf_decrypt(m, ml, ns, c, cl, ad, al, np, k);
}
extern "C" int __real_sqlite3_step(sqlite3_stmt*);
extern "C" int __wrap_sqlite3_step(sqlite3_stmt* statement) {
    if (active && active->throwAuth && std::strcmp(sqlite3_sql(statement),
        "SELECT entry_id FROM entries ORDER BY entry_id;") == 0) {
        active->throwAuth = false; throw std::bad_alloc();
    }
    return __real_sqlite3_step(statement);
}
extern "C" int __real_fstatfs(int, struct statfs*);
extern "C" int __wrap_fstatfs(int fd, struct statfs* status) {
    const int code = __real_fstatfs(fd, status);
    if (code == 0 && active && active->unsupportedFs) status->f_type = 0x6969; // NFS, simulated only
    return code;
}
bool replacementEngineSyncFault(int) {
    if (active && active->precautionPublished && active->failPrecautionDurability) {
        active->failPrecautionDurability = false; return true;
    }
    if (active && active->exchanges && active->failDirectoryAfterExchange) {
        active->failDirectoryAfterExchange = false; return true;
    }
    return false;
}
extern "C" int __real_linkat(int, const char*, int, const char*, int);
extern "C" int __wrap_linkat(int a, const char* x, int b, const char* y, int flags) {
    const bool precaution = active && std::strcmp(y, "precaution.db") == 0;
    if (precaution && active->failPrecautionPublication) { errno = EACCES; return -1; }
    const int code = __real_linkat(a, x, b, y, flags);
    if (precaution && code == 0) active->precautionPublished = true;
    if (active && code == 0 && std::strcmp(y, "candidate.db") == 0)
        active->cleanAtCandidatePublication = active->liveSecrets == 0;
    return code;
}
extern "C" int __real_sqlite3_backup_step(sqlite3_backup*, int);
extern "C" int __wrap_sqlite3_backup_step(sqlite3_backup* backup, int pages) {
    const int code = __real_sqlite3_backup_step(backup, pages);
    if (active && active->afterCopyStep) {
        auto callback = std::move(active->afterCopyStep); callback();
    }
    return code;
}
extern "C" int __real_renameat2(int, const char*, int, const char*, unsigned);
extern "C" int __wrap_renameat2(int a, const char* x, int b, const char* y, unsigned flags) {
    if (active) {
        ++active->exchanges; active->cleanAtExchange = active->liveSecrets == 0;
        if (active->assertReservations) {
            VaultOperationGuard first, second; std::string error;
            active->reservationsHeld = !first.tryAccess(active->principal.toStdString(), error)
                && !second.tryAccess(active->artifact.toStdString(), error);
        }
        if (active->failExchange) { errno = ENOSYS; return -1; }
    }
    return __real_renameat2(a, x, b, y, flags);
}

namespace {
TEST_F(VaultReplacementEngineTest, AuthenticatesEveryEntryAndReplacesWholeVault) {
    ASSERT_TRUE(run()); EXPECT_EQ(result.outcome, ReplacementOutcome::Replaced);
    EXPECT_EQ(probe.decryptions, 3); EXPECT_EQ(probe.exchanges, 1); EXPECT_TRUE(probe.cleanAtExchange);
    EXPECT_TRUE(probe.cleanAtCandidatePublication);
    EXPECT_TRUE(bytes(source) == sourceBytes); EXPECT_TRUE(bytes(result.recoveryArtifact) == original);
    EXPECT_TRUE(QFile::exists(principal));
    SecureBuffer key(0); std::string failure;
    ASSERT_TRUE(VaultLifecycleService::unlockVault(principal.toStdString(), std::string(master), key, failure));
    std::vector<passwall::models::CredentialSummary> summaries;
    ASSERT_TRUE(CredentialService::listSummaries(principal.toStdString(), key, summaries, failure));
    EXPECT_EQ(summaries.size(), 2u);
    EXPECT_EQ(result.finalization.state, ReplacementFinalizationState::Resolved);
    EXPECT_EQ(store().recoveryAccess(principal, error), VaultRecoveryAccess::Allowed);
}
TEST_F(VaultReplacementEngineTest, WrongPasswordNeverArmsOrChangesPrincipal) {
    EXPECT_FALSE(run(nullptr, "wrong-fictitious-master")); unchanged(); blocked();
    EXPECT_EQ(probe.exchanges, 0); EXPECT_EQ(result.outcome, ReplacementOutcome::NotReplaced);
    EXPECT_EQ(read().replacement->phase, "prepared");
}
TEST_F(VaultReplacementEngineTest, EmptyOwnedPasswordRefused) {
    EXPECT_FALSE(run(nullptr, "")); unchanged(); EXPECT_EQ(probe.decryptions, 0);
}
TEST_F(VaultReplacementEngineTest, InvalidSqliteSourceRefused) {
    QFile f(source); ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate)); f.write("not-sqlite"); f.close();
    EXPECT_FALSE(run()); EXPECT_TRUE(bytes(principal) == original); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, UnsupportedFormatRefused) {
    sql(source, "UPDATE vault_metadata SET format_version=2;"); EXPECT_FALSE(run());
    EXPECT_TRUE(bytes(principal) == original); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, DifferentVaultLineageRefusedBeforeUnwrap) {
    sql(source, "UPDATE vault_metadata SET vault_id=randomblob(16);"); EXPECT_FALSE(run());
    EXPECT_EQ(probe.decryptions, 0); EXPECT_TRUE(bytes(principal) == original);
}
TEST_F(VaultReplacementEngineTest, LastCorruptedEntryAfterValidEntryPreventsExchange) {
    sql(source, "UPDATE entries SET ciphertext=zeroblob(length(ciphertext)) WHERE entry_id="
        "(SELECT entry_id FROM entries ORDER BY entry_id LIMIT 1 OFFSET 1);");
    EXPECT_FALSE(run()); EXPECT_EQ(probe.decryptions, 3); EXPECT_EQ(probe.exchanges, 0);
    EXPECT_TRUE(bytes(principal) == original); blocked();
}
TEST_F(VaultReplacementEngineTest, ExceptionDuringAuthenticationCleansOwnedSecrets) {
    probe.throwAuth = true; EXPECT_FALSE(run()); EXPECT_EQ(probe.exchanges, 0);
    unchanged(); EXPECT_FALSE(result.diagnostic.isEmpty()); blocked();
}
TEST_F(VaultReplacementEngineTest, SourceAliasOfPrincipalRefused) {
    source = principal; EXPECT_FALSE(run()); EXPECT_EQ(probe.decryptions, 0);
    EXPECT_TRUE(bytes(principal) == original);
}
TEST_F(VaultReplacementEngineTest, HardLinkedSourceRefused) {
    const auto link = directory.filePath("linked.db"); ASSERT_EQ(::link(source.toLocal8Bit(), link.toLocal8Bit()), 0);
    source = link; EXPECT_FALSE(run()); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, SymlinkSourceRefused) {
    const auto link = directory.filePath("symlink.db"); ASSERT_EQ(::symlink(source.toLocal8Bit(), link.toLocal8Bit()), 0);
    source = link; EXPECT_FALSE(run()); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, SymlinkParentRefused) {
    const auto link = directory.filePath("symlink-parent"); ASSERT_EQ(::symlink(directory.path().toLocal8Bit(), link.toLocal8Bit()), 0);
    source = link + "/selected.db"; EXPECT_FALSE(run()); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, ModifiedSourceAfterAuthenticationRefused) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::SourceAuthenticated) {
        QFile f(source); EXPECT_TRUE(f.open(QIODevice::Append)); f.write("x"); } return false; }};
    EXPECT_FALSE(run(&c)); EXPECT_EQ(probe.exchanges, 0); EXPECT_TRUE(bytes(principal) == original);
}
TEST_F(VaultReplacementEngineTest, SourceChangedDuringSqliteCopyIsRejected) {
    probe.afterCopyStep = [&] { QFile f(source); EXPECT_TRUE(f.open(QIODevice::Append)); f.write("x"); f.close(); };
    EXPECT_FALSE(run()); EXPECT_EQ(probe.exchanges, 0); EXPECT_TRUE(bytes(principal) == original); blocked();
}
TEST_F(VaultReplacementEngineTest, ModifiedCandidateAfterAuthenticationRefused) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::SourceAuthenticated) {
        const auto r = read(); const auto path = candidatePath(r.replacement->operationId);
        QFile f(path); EXPECT_TRUE(f.open(QIODevice::Append)); f.write("x"); } return false; }};
    EXPECT_FALSE(run(&c)); EXPECT_EQ(probe.exchanges, 0); EXPECT_TRUE(bytes(principal) == original);
}
TEST_F(VaultReplacementEngineTest, AutomaticDisabledRequiresExplicitPrecaution) {
    const QString missing; EXPECT_FALSE(run(nullptr, master, &missing)); unchanged();
    EXPECT_EQ(probe.decryptions, 0); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, PrecautionPrincipalDestinationRefused) {
    EXPECT_FALSE(run(nullptr, master, &principal)); unchanged(); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, PrecautionSourceDestinationRefused) {
    EXPECT_FALSE(run(nullptr, master, &source)); unchanged(); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, ExistingPrecautionNeverOverwritten) {
    QFile f(precaution); ASSERT_TRUE(f.open(QIODevice::WriteOnly)); f.write("third-party-data"); f.close();
    EXPECT_FALSE(run()); EXPECT_EQ(bytes(precaution), QByteArray("third-party-data")); unchanged();
}
TEST_F(VaultReplacementEngineTest, InaccessiblePrecautionPreventsReplacement) {
    precaution = directory.filePath("absent/copy.db"); EXPECT_FALSE(run()); unchanged();
}
TEST_F(VaultReplacementEngineTest, DurablePrecautionCreatedWhilePreparedAndNeverCatalogued) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::PrecautionCreated) {
        EXPECT_EQ(read().replacement->phase, "prepared"); EXPECT_TRUE(QFile::exists(precaution));
        EXPECT_EQ(probe.liveSecrets, 0); EXPECT_TRUE(read().automaticVersions.isEmpty()); } return false; }};
    ASSERT_TRUE(run(&c)); EXPECT_EQ(result.precaution.publication, SnapshotPublication::Published);
    EXPECT_TRUE(read().automaticVersions.isEmpty());
}
TEST_F(VaultReplacementEngineTest, PrecautionPublicationFailurePreventsArm) {
    probe.failPrecautionPublication = true; EXPECT_FALSE(run()); unchanged();
    EXPECT_EQ(result.precaution.publication, SnapshotPublication::NotPublished);
    EXPECT_EQ(read().replacement->phase, "prepared"); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, UnconfirmedPrecautionDurabilityCannotAuthorizeReplacement) {
    probe.failPrecautionDurability = true; EXPECT_FALSE(run()); unchanged();
    EXPECT_EQ(result.precaution.publication, SnapshotPublication::PublishedDurabilityUnconfirmed);
    EXPECT_TRUE(QFile::exists(precaution)); EXPECT_EQ(probe.exchanges, 0);
    EXPECT_EQ(read().replacement->phase, "prepared");
}
TEST_F(VaultReplacementEngineTest, AutomaticEnabledDoesNotRequireExtraCopyOrUsualDestination) {
    automatic(); const QString missing; ASSERT_TRUE(run(nullptr, master, &missing));
    EXPECT_FALSE(QFile::exists(precaution)); EXPECT_TRUE(read().backupRequired);
    EXPECT_EQ(read().backup, registered.backup);
}
TEST_F(VaultReplacementEngineTest, AutomaticEnabledDoesNotValidateAnUnusedPrecautionPath) {
    automatic();
    const auto unavailable = directory.filePath("missing-support/not-used.db");
    ASSERT_TRUE(run(nullptr, master, &unavailable)); EXPECT_FALSE(QFile::exists(unavailable));
    EXPECT_TRUE(read().backupRequired);
}
TEST_F(VaultReplacementEngineTest, CandidatePrivateAndDurableBeforeArm) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::CandidateStaged) {
        const auto r = read(); EXPECT_EQ(r.replacement->phase, "prepared");
        EXPECT_EQ(r.replacement->candidateDigest.size(), 32);
        struct stat file {}, parent {};
        EXPECT_EQ(::stat(result.recoveryArtifact.toLocal8Bit(), &file), 0);
        EXPECT_EQ(::stat(QFileInfo(result.recoveryArtifact).absolutePath().toLocal8Bit(), &parent), 0);
        EXPECT_EQ(file.st_mode & 0777, 0600u); EXPECT_EQ(parent.st_mode & 0777, 0700u);
        EXPECT_EQ(quint64(file.st_dev), registered.file.device); } return false; }};
    ASSERT_TRUE(run(&c));
}
TEST_F(VaultReplacementEngineTest, ArmedIsPersistentBeforeRealExchange) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::BeforeExchange) {
        const auto r = read(); EXPECT_EQ(r.replacement->phase, "armed"); blocked();
        EXPECT_TRUE(bytes(principal) == original); } return false; }};
    ASSERT_TRUE(run(&c));
}
TEST_F(VaultReplacementEngineTest, ReservationsCoverBothNamesAndInodesThroughExchange) {
    probe.assertReservations = true;
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::CandidateStaged) probe.artifact = result.recoveryArtifact;
        if (p == ReplacementCheckpoint::AfterExchange) {
            VaultOperationGuard a, b; std::string failure;
            EXPECT_FALSE(a.tryAccess(principal.toStdString(), failure));
            EXPECT_FALSE(b.tryAccess(result.recoveryArtifact.toStdString(), failure));
            EXPECT_TRUE(bytes(principal) != original); EXPECT_TRUE(bytes(result.recoveryArtifact) == original);
        } return false; }};
    ASSERT_TRUE(run(&c)); EXPECT_TRUE(probe.reservationsHeld);
}
TEST_F(VaultReplacementEngineTest, ChangedPrincipalImmediatelyBeforeExchangeRefused) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::BeforeExchange) {
        QFile f(principal); EXPECT_TRUE(f.open(QIODevice::Append)); f.write("x"); } return false; }};
    EXPECT_FALSE(run(&c)); EXPECT_EQ(probe.exchanges, 0); blocked();
}
TEST_F(VaultReplacementEngineTest, ReplacedCandidateImmediatelyBeforeExchangeRefused) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::BeforeExchange) {
        EXPECT_TRUE(QFile::rename(result.recoveryArtifact, result.recoveryArtifact + ".preserved"));
        EXPECT_TRUE(QFile::copy(source, result.recoveryArtifact)); } return false; }};
    EXPECT_FALSE(run(&c)); EXPECT_EQ(probe.exchanges, 0); EXPECT_TRUE(bytes(principal) == original); blocked();
}
TEST_F(VaultReplacementEngineTest, UnsupportedFilesystemRefusedWithoutSubstitution) {
    probe.unsupportedFs = true; EXPECT_FALSE(run()); unchanged(); EXPECT_EQ(probe.exchanges, 0);
}
TEST_F(VaultReplacementEngineTest, ExchangeUnsupportedLeavesOriginalAndArmedEvidence) {
    probe.failExchange = true; EXPECT_FALSE(run()); unchanged(); blocked();
    EXPECT_EQ(result.outcome, ReplacementOutcome::EngagedRecoveryRequired);
    EXPECT_TRUE(QFile::exists(result.recoveryArtifact));
}
TEST_F(VaultReplacementEngineTest, DirectorySyncFailureAfterExchangePreservesBothVaults) {
    probe.failDirectoryAfterExchange = true; EXPECT_FALSE(run()); blocked();
    EXPECT_EQ(result.outcome, ReplacementOutcome::ReplacedDurabilityUnconfirmed);
    EXPECT_TRUE(bytes(result.recoveryArtifact) == original); EXPECT_TRUE(bytes(principal) != original);
    newProcessRecovery(ReplacementLayout::Resolved);
}
TEST_F(VaultReplacementEngineTest, IdentityConfirmationSyncFailureKeepsRecoveryGate) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::AfterDirectorySync)
        replacementRegistrySyncFaultForTest(config, 1); return false; }};
    ASSERT_FALSE(run(&c)); blocked(); ASSERT_TRUE(read().replacement);
    EXPECT_EQ(read().replacement->phase, "identity-confirmed");
    EXPECT_EQ(result.finalization.state, ReplacementFinalizationState::IdentityUnconfirmed);
    newProcessRecovery(ReplacementLayout::Resolved);
}
TEST_F(VaultReplacementEngineTest, FinalResolutionSyncFailureNeverMeansNoReplacement) {
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::AfterDirectorySync)
        replacementRegistrySyncFaultForTest(config, 2); return false; }};
    ASSERT_FALSE(run(&c)); EXPECT_EQ(result.outcome, ReplacementOutcome::ReplacedFinalizationPending);
    EXPECT_EQ(result.finalization.state, ReplacementFinalizationState::SafeResolutionUnconfirmed);
    EXPECT_TRUE(read().resolvedReplacement); EXPECT_TRUE(bytes(result.recoveryArtifact) == original);
    newProcessRecovery(ReplacementLayout::Resolved);
}
TEST_F(VaultReplacementEngineTest, LocalPreferencesAndSuspensionPreservedWithoutRotation) {
    automatic(); ASSERT_TRUE(store().suspendAutomaticBackup(registered.localId, error));
    const auto before = read(); ASSERT_TRUE(run()); const auto after = read();
    EXPECT_EQ(after.localId, before.localId); EXPECT_EQ(after.backup, before.backup);
    EXPECT_EQ(after.automaticSuspended, before.automaticSuspended); EXPECT_TRUE(after.backupRequired);
    EXPECT_EQ(after.automaticVersions, before.automaticVersions); EXPECT_EQ(after.backupEpoch, before.backupEpoch);
    EXPECT_EQ(after.rotationAttempt, before.rotationAttempt); EXPECT_EQ(after.rotationState, before.rotationState);
    EXPECT_EQ(after.backupAttempt, before.backupAttempt); EXPECT_EQ(after.file.path, before.file.path);
    EXPECT_NE(after.file.inode, before.file.inode);
}
TEST_F(VaultReplacementEngineTest, NonemptyCatalogueAndExistingFilesSurviveRealReplacement) {
    automatic();
    const auto older = directory.filePath("older-automatic.db");
    ASSERT_TRUE(QFile::copy(source, older));
    // Seed the pre-existing legacy catalogue contract (not a deletion receipt).
    // The replacement below is real and must preserve both record AND file.
    QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    auto records = root["vaults"].toArray(); auto record = records[0].toObject();
    record["automaticVersions"] = QJsonArray{QJsonObject{{"kind", "automatic"}, {"publication", "published"},
        {"attempt", QUuid::createUuid().toString(QUuid::WithoutBraces)}, {"path", older},
        {"createdUtc", "2026-11-09T12:00:00.000Z"}, {"birthTime", ""}, {"durable", true},
        {"device", "1"}, {"inode", "2"}, {"size", "4096"}}};
    records[0] = record; root["vaults"] = records;
    settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact)); settings.sync();
    const auto before = read(); ASSERT_EQ(before.automaticVersions.size(), 1);
    ASSERT_TRUE(run()); EXPECT_EQ(read().automaticVersions, before.automaticVersions);
    EXPECT_TRUE(bytes(older) == sourceBytes); EXPECT_TRUE(read().rotationAttempt.isEmpty());
}
TEST_F(VaultReplacementEngineTest, OldArtifactAndRecoveryReferencesRetainedAfterSuccess) {
    ASSERT_TRUE(run()); const auto r = read(); ASSERT_FALSE(r.replacement); ASSERT_TRUE(r.resolvedReplacement);
    EXPECT_TRUE(r.resolvedReplacement->recoveryArtifacts.contains(result.recoveryArtifact));
    EXPECT_TRUE(bytes(result.recoveryArtifact) == original);
    EXPECT_EQ(store().recoveryAccess(result.recoveryArtifact, error), VaultRecoveryAccess::RecoveryRequired);
}
TEST_F(VaultReplacementEngineTest, NoSecretInPersistentEvidenceOrDiagnostics) {
    EXPECT_FALSE(run(nullptr, "wrong-fictitious-master"));
    const auto persisted = bytes(config);
    EXPECT_FALSE(persisted.contains("fictitious-replacement-master"));
    EXPECT_FALSE(persisted.contains("fictitious-password")); EXPECT_FALSE(persisted.contains("fictitious-notes"));
    EXPECT_FALSE(result.diagnostic.contains("wrong-fictitious-master"));
}
TEST_F(VaultReplacementEngineTest, OtherIndependentVaultRemainsUsable) {
    const auto independent = directory.filePath("independent.db");
    SecureBuffer key(0); std::string failure;
    ASSERT_TRUE(VaultLifecycleService::createVault(independent.toStdString(), std::string(master), key, failure));
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::Armed) {
        VaultKeyMetadata metadata;
        EXPECT_TRUE(passwall::storage::VaultStorage::readMetadata(independent.toStdString(), metadata, failure));
    } return false; }};
    ASSERT_TRUE(run(&c));
}
TEST_F(VaultReplacementEngineTest, InvalidCapabilityCannotBeReplacedByAnExclusiveReservation) {
    VaultReplacementAuthorization empty; VaultOperationGuard reservation; std::string failure;
    ASSERT_TRUE(reservation.tryReserve(principal.toStdString(), failure));
    EXPECT_FALSE(empty.replacePrincipal(principal, source, password(), precaution, result, {})); unchanged();
}
TEST_F(VaultReplacementEngineTest, WrongBoundPrincipalRefused) {
    auto authority = issueReplacementEngineTest(store(), registered.localId, error);
    EXPECT_FALSE(authority.replacePrincipal(source, source, password(), precaution, result, {})); unchanged();
}
TEST_F(VaultReplacementEngineTest, CallbackCannotRedirectExchangeByMutatingCallerPrincipalPath) {
    const auto bound = principal;
    const auto unrelated = directory.filePath("unrelated.db");
    ASSERT_TRUE(QFile::copy(source, unrelated)); const auto unrelatedBytes = bytes(unrelated);
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::BeforeWork) {
        principal = unrelated;
    } return false; }};
    ASSERT_TRUE(run(&c));
    EXPECT_EQ(read().file.path, bound); EXPECT_TRUE(bytes(bound) != original);
    EXPECT_TRUE(bytes(unrelated) == unrelatedBytes); EXPECT_TRUE(bytes(result.recoveryArtifact) == original);
}
TEST_F(VaultReplacementEngineTest, RevocationBeforeArmNeverExchanges) {
    auto authority = issueReplacementEngineTest(store(), registered.localId, error);
    Control c{[&](auto p) { if (p == ReplacementCheckpoint::BeforeArm) authority.reset(); return false; }};
    EXPECT_FALSE(authority.replacePrincipal(principal, source, password(), precaution, result, c.callback()));
    unchanged(); EXPECT_TRUE(read().replacement);
}
TEST_F(VaultReplacementEngineTest, CancellationBeforeArmIsNotAReplacement) {
    Control c{[](auto p) { return p == ReplacementCheckpoint::BeforeArm; }};
    EXPECT_FALSE(run(&c)); EXPECT_EQ(result.outcome, ReplacementOutcome::CancelledBeforeEngagement);
    unchanged(); blocked();
}
TEST_F(VaultReplacementEngineTest, FailedAuthenticationRetainsLiveCapabilityForExplicitVerifiedAbandon) {
    auto authority = issueReplacementEngineTest(store(), registered.localId, error);
    EXPECT_FALSE(authority.replacePrincipal(principal, source, password("wrong-fictitious-master"), precaution, result, {}));
    ASSERT_TRUE(authority.valid(error)); ASSERT_TRUE(authority.abandonPreparation(error));
    EXPECT_EQ(store().recoveryAccess(principal, error), VaultRecoveryAccess::Allowed); unchanged();
}
TEST_F(VaultReplacementEngineTest, LateCancellationAfterExchangeNeverClaimsCancellation) {
    Control c{[](auto p) { return p == ReplacementCheckpoint::AfterExchange; }};
    EXPECT_FALSE(run(&c)); EXPECT_EQ(result.outcome, ReplacementOutcome::ReplacedDurabilityUnconfirmed);
    EXPECT_TRUE(bytes(result.recoveryArtifact) == original); blocked(); newProcessRecovery(ReplacementLayout::Resolved);
}
TEST_F(VaultReplacementEngineTest, FailedAuthenticationCleansPrivateUnreferencedCandidate) {
    EXPECT_FALSE(run(nullptr, "wrong-fictitious-master"));
    EXPECT_TRUE(QDir(directory.path()).entryList({".passwall-restore-*"}, QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot).isEmpty());
    VaultOperationGuard guard; std::string failure;
    EXPECT_TRUE(guard.tryReserve(principal.toStdString(), failure)); blocked();
}

class VaultReplacementCrashTest : public VaultReplacementEngineTest,
    public ::testing::WithParamInterface<ReplacementCheckpoint> {};
TEST_P(VaultReplacementCrashTest, PersistentLayoutInNewProcessNeverRepeatsExchange) {
    const auto point = GetParam(); crashAt(point);
    const auto r = read(); ASSERT_TRUE(r.replacement);
    const bool exchanged = point == ReplacementCheckpoint::AfterExchange || point == ReplacementCheckpoint::AfterDirectorySync;
    if (exchanged) {
        EXPECT_TRUE(bytes(principal) != original); EXPECT_TRUE(bytes(r.replacement->candidate->path) == original);
        newProcessRecovery(ReplacementLayout::Resolved);
        EXPECT_TRUE(read().resolvedReplacement); EXPECT_FALSE(read().replacement);
    } else {
        EXPECT_TRUE(bytes(principal) == original);
        newProcessRecovery(point == ReplacementCheckpoint::Armed || point == ReplacementCheckpoint::BeforeExchange
            ? ReplacementLayout::ArmedBeforeExchange : ReplacementLayout::PreparedIntact);
        blocked(); EXPECT_TRUE(bytes(principal) == original);
    }
}
INSTANTIATE_TEST_SUITE_P(RealFiles, VaultReplacementCrashTest, ::testing::Values(
    ReplacementCheckpoint::SourceAuthenticated, ReplacementCheckpoint::CandidateStaged,
    ReplacementCheckpoint::BeforeArm, ReplacementCheckpoint::Armed, ReplacementCheckpoint::BeforeExchange,
    ReplacementCheckpoint::AfterExchange, ReplacementCheckpoint::AfterDirectorySync));

TEST_F(VaultReplacementEngineTest, MissingCandidateAfterArmedRetainsFence) {
    crashAt(ReplacementCheckpoint::Armed); const auto r = read();
    ASSERT_TRUE(QFile::remove(r.replacement->candidate->path));
    newProcessRecovery(ReplacementLayout::Unrecognized); blocked(); EXPECT_TRUE(bytes(principal) == original);
}
TEST_F(VaultReplacementEngineTest, UnexpectedPrincipalAfterExchangeRetainsFenceAndOldFile) {
    crashAt(ReplacementCheckpoint::AfterExchange); const auto r = read();
    ASSERT_TRUE(QFile::rename(principal, principal + ".preserved")); ASSERT_TRUE(QFile::copy(source, principal));
    newProcessRecovery(ReplacementLayout::Unrecognized); blocked();
    EXPECT_TRUE(bytes(r.replacement->candidate->path) == original);
}
TEST_F(VaultReplacementEngineTest, CorruptedNewBytesAfterExchangeRetainFence) {
    crashAt(ReplacementCheckpoint::AfterExchange);
    QFile f(principal); ASSERT_TRUE(f.open(QIODevice::Append)); f.write("x"); f.close();
    newProcessRecovery(ReplacementLayout::Unrecognized); blocked();
}
TEST_F(VaultReplacementEngineTest, CorruptedOldBytesAfterExchangeRetainFence) {
    crashAt(ReplacementCheckpoint::AfterExchange); const auto r = read();
    QFile f(r.replacement->candidate->path); ASSERT_TRUE(f.open(QIODevice::Append)); f.write("x"); f.close();
    newProcessRecovery(ReplacementLayout::Unrecognized); blocked();
}
TEST_F(VaultReplacementEngineTest, InspectionDoesNotFinalizeOrUnlock) {
    crashAt(ReplacementCheckpoint::AfterExchange); const auto r = read();
    const auto inspection = VaultReplacementAuthorization::recoverReplacement(store(), registered.localId,
        r.replacement->operationId, ReplacementRecoveryAction::Inspect);
    EXPECT_EQ(inspection.layout, ReplacementLayout::ArmedAfterExchange); blocked();
    EXPECT_EQ(read().replacement->phase, "armed");
}
TEST_F(VaultReplacementEngineTest, StaleOperationCannotResolveNewerFence) {
    crashAt(ReplacementCheckpoint::AfterExchange);
    const auto result = VaultReplacementAuthorization::recoverReplacement(store(), registered.localId,
        "00000000-0000-4000-8000-000000000001", ReplacementRecoveryAction::FinalizeExchanged);
    EXPECT_EQ(result.layout, ReplacementLayout::Unrecognized); blocked();
}
TEST_F(VaultReplacementEngineTest, UnreadableRegistryNeverPermitsRecovery) {
    crashAt(ReplacementCheckpoint::AfterExchange); const auto r = read();
    QSettings settings(config, QSettings::IniFormat); settings.setValue("vaultRegistry/data", "invalid-json"); settings.sync();
    const auto result = VaultReplacementAuthorization::recoverReplacement(store(), registered.localId,
        r.replacement->operationId, ReplacementRecoveryAction::FinalizeExchanged);
    EXPECT_EQ(result.layout, ReplacementLayout::Unrecognized);
    EXPECT_EQ(store().recoveryAccess(principal, error), VaultRecoveryAccess::Unavailable);
}
} // namespace
