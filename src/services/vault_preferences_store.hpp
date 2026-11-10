#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QObject>
#include <string>
#include "services/backup_protocol.hpp"

namespace passwall::storage { class VaultOperationGuard; }

namespace passwall::services {

class VaultReplacementAuthorization;

class VaultPreferencesEvents final : public QObject {
    Q_OBJECT
signals:
    void changed(QString settingsFile, QString localId, QString path, bool automatic);
};

struct AutomaticBackupVersion {
    QString attemptId, path, createdUtc, birthTime;
    quint64 device = 0, inode = 0, size = 0;
    bool durable = false;
    quint64 order = 0; // Zero means legacy, never retroactively deletable.
    QString destinationEpoch;
    std::optional<BackupFileEvidence> evidence;
    bool operator==(const AutomaticBackupVersion&) const = default;
};

struct VaultBackupPreferences {
    bool automatic = false;
    QString directory;
    int retainedVersions = 7;
    bool operator==(const VaultBackupPreferences&) const = default;
};

// Local evidence, NOT a cryptographic proof of file identity. No machine ID.
struct VaultFileIdentity {
    QString path;
    QByteArray vaultId;
    quint64 device = 0;
    quint64 inode = 0;
    QString birthTime; // Optional statx birth time; unlike ctime, survives CRUD.
    bool operator==(const VaultFileIdentity&) const = default;
};

// Internal version-1 recovery fence, never an authentication capability.
// "prepared"/"armed" block access. "identity-confirmed" still blocks access,
// even after the new identity has been saved. A separate, bounded "resolved"
// receipt can only be published AFTER that protected write was fsynced.
struct VaultReplacementIntent {
    QString operationId;
    VaultFileIdentity previous;
    QByteArray previousDigest;
    std::optional<VaultFileIdentity> candidate;
    // 6B binding to the fully authenticated encrypted candidate. Empty only
    // for earlier 6A contracts; such an armed intent cannot be recovered by 6B.
    QByteArray candidateDigest;
    std::optional<VaultFileIdentity> confirmed;
    QString phase;
    QStringList recoveryArtifacts;
    bool operator==(const VaultReplacementIntent&) const = default;
};

enum class VaultRecoveryAccess { Allowed, RecoveryRequired, Unavailable };

struct VaultRegistration {
    QString localId;
    VaultFileIdentity file;
    VaultBackupPreferences backup;
    // Internal conservative intent, not a fourth user preference. Only a
    // future confirmed backup may clear it; CRUD never does.
    bool backupRequired = false;
    // Armed before launch; a crash leaves retries suspended, never a success.
    bool automaticSuspended = false;
    QString backupAttempt, backupAttemptDestination;
    SnapshotDirectoryIdentity backupDirectory;
    QVector<AutomaticBackupVersion> automaticVersions;
    quint64 automaticOrder = 0;
    QString backupEpoch;
    // Durable one-shot authority. An abandoned prepared/running attempt is NOT
    // automatically reclaimed, even by a later successful backup.
    QString rotationAttempt, rotationState, rotationCandidate;
    std::optional<VaultReplacementIntent> replacement;
    // Last resolved operation only, not an active guard or a second registry.
    // Retains recovery references; never authorizes a different physical file.
    std::optional<VaultReplacementIntent> resolvedReplacement;
};

// Internal persistence boundary, NOT a claim about power-loss-proof hardware.
enum class RegistryPersistence { NotAttempted, Unconfirmed, Durable };

enum class VaultRecognition { Registered, Recognized, ReassociationRequired, Error };

// Uses the existing user QSettings file, with fallbacks disabled. Methods are
// synchronous, contain no secrets and never authenticate/unlock a vault.
// Calls from different processes are serialized by a temporary registry lock;
// ordinary QSettings writers retain Qt's own atomic sync/merge mechanism.
// A reported post-publication permission/durability error is NOT proof that
// nothing was written. Never erase a published vault/configuration to hide it.
class VaultPreferencesStore {
public:
    VaultPreferencesStore();
    // For isolated tests/explicit configuration. Parent must be an application-
    // specific directory: on Unix it is made private, never a shared ancestor.
    explicit VaultPreferencesStore(QString settingsFile);

    [[nodiscard]] QString fileName() const { return settingsFile_; }
    static VaultPreferencesEvents& events();
    // Stored records for management, NOT permission to use them for a file.
    // Call recognizeOrRegister before applying any stored backup authorization.
    [[nodiscard]] bool list(QVector<VaultRegistration>& output, QString& error) const;
    // Non-authorizing display snapshot of the atomically published settings.
    // No registry writer lock/cache sync: GUI observation cannot contend with
    // backup finalization. May be stale or visible before durability is known;
    // NEVER use it as recovery/business/backup admission or as a success proof.
    [[nodiscard]] bool listForDisplay(QVector<VaultRegistration>& output, QString& error) const;
    // Readable ordinary configuration errors remain separate from a recovery
    // fence. An unreadable/ambiguous registry is NOT permission to access SQL.
    // Caller keeps its business guard across this check and the whole access.
    [[nodiscard]] VaultRecoveryAccess recoveryAccess(const QString& path, QString& error) const;
    [[nodiscard]] static bool checkRecoveryAccess(const std::string& path, std::string& error);
    [[nodiscard]] VaultRecognition recognizeOrRegister(
        const QString& path, VaultRegistration& output, QString& error) const;
    [[nodiscard]] bool updatePreferences(const QString& localId,
        const VaultBackupPreferences& preferences, QString& error) const;
    // GUI optimistic concurrency: compare identity AND displayed preferences
    // under the same registry lock as the existing durable update. Internal
    // catalogue/suspension/recovery fields are never taken from this snapshot.
    [[nodiscard]] bool updatePreferencesIfCurrent(const VaultRegistration& expected,
        const VaultBackupPreferences& preferences, QString& error) const;

    // Before ANY SQLite access of a mutation: acquire business access, inspect
    // local filesystem evidence without opening SQLite, then durably record
    // intent if automatic backups are enabled. On success the caller MUST keep
    // access alive through connection close/transaction completion. Unknown
    // files receive no registration or inherited preferences. Configuration
    // errors and ambiguous known identities fail closed. No backup is started.
    [[nodiscard]] bool prepareMutation(const QString& path,
        storage::VaultOperationGuard& access, QString& error) const;
    [[nodiscard]] bool beginAutomaticBackup(const VaultRegistration& expected,
        const SnapshotDirectoryIdentity& directory, const QString& destination,
        const QString& attempt, const storage::VaultOperationGuard& reservation, QString& error,
        bool explicitResume = false) const;
    [[nodiscard]] bool finishAutomaticBackup(const QString& localId, const QString& attempt,
        BackupResult result, bool normalInterruption,
        const storage::VaultOperationGuard& reservation, QString& error) const;
    // False positives are safe; this only SETS intent/suspension, never clears.
    [[nodiscard]] bool suspendAutomaticBackup(const QString& localId, QString& error) const;
    [[nodiscard]] bool claimRotation(const QString& localId, const QString& attempt,
        const storage::VaultOperationGuard& reservation, VaultRegistration& output, QString& error) const;
    [[nodiscard]] bool markRotationDeletion(const QString& localId, const QString& attempt,
        const AutomaticBackupVersion& candidate, const storage::VaultOperationGuard& reservation,
        QString& error) const;
    [[nodiscard]] bool confirmRotationDeletion(const QString& localId, const QString& attempt,
        const QString& candidate, const storage::VaultOperationGuard& reservation, QString& error) const;
    [[nodiscard]] bool completeRotation(const QString& localId, const QString& attempt,
        const storage::VaultOperationGuard& reservation, QString& error) const;

    // Future trusted replacement caller must have authorized and completed the
    // replacement. Compare-and-swap against BOTH the stored old identity and
    // the expected current file. Same pathname only. No copying/authentication.
    [[nodiscard]] bool updateIdentityAfterReplacement(const QString& localId,
        const VaultFileIdentity& previous, const VaultFileIdentity& replacement,
        QString& error) const;

    // Read-only SQLite inspection, not authentication. Rejects symlink paths
    // and hard links on Unix. Caller must not treat metadata as authorization.
    [[nodiscard]] static bool inspectVault(const QString& path,
        VaultFileIdentity& output, QString& error);

private:
    [[nodiscard]] bool updatePreferencesImpl(const QString& localId,
        const VaultRegistration* expected, const VaultBackupPreferences&, QString& error) const;
    friend class VaultReplacementAuthorization;
#ifdef PASSWALL_REPLACEMENT_TESTING
    friend class ReplacementTestAccess;
#endif
    [[nodiscard]] static bool inspect(const QString& path,
        const storage::VaultOperationGuard* reservation, VaultFileIdentity& output, QString& error);
    [[nodiscard]] static bool inspectReserved(const QString& path,
        const storage::VaultOperationGuard& reservation, VaultFileIdentity& output, QString& error);
    [[nodiscard]] bool writeReplacementIntent(const QString& localId,
        const VaultFileIdentity& expected, const VaultReplacementIntent& intent, QString& error) const;
    [[nodiscard]] bool resolveReplacement(const QString& localId,
        const VaultReplacementIntent& expected, const VaultFileIdentity& observed,
        bool completed, QString& error, RegistryPersistence* persistence = nullptr) const;
    [[nodiscard]] bool confirmReplacementIdentity(const QString& localId,
        const VaultReplacementIntent& expected, const VaultFileIdentity& observed,
        QString& error, RegistryPersistence* persistence = nullptr) const;
    QString settingsFile_;
};

} // namespace passwall::services
