#pragma once

#include "services/global_backup_preferences_store.hpp"
#include "services/vault_preferences_store.hpp"
#include "services/vault_snapshot_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QDateTime>
#include <QString>

namespace passwall::services {

class BackupJob;
class InitialBackupRequest;

// Transient preparation result only. It is neither a publication receipt nor
// an authorization derived from vault_id. The snapshot capability keeps the
// exact source identity protected until the future consumer takes ownership.
class PreparedBackupDestination final {
public:
    PreparedBackupDestination() = default;
    PreparedBackupDestination(const PreparedBackupDestination&) = delete;
    PreparedBackupDestination& operator=(const PreparedBackupDestination&) = delete;
    PreparedBackupDestination(PreparedBackupDestination&&) noexcept = default;
    PreparedBackupDestination& operator=(PreparedBackupDestination&&) noexcept = default;

    [[nodiscard]] const QString& vaultPath() const noexcept { return vaultPath_; }
    [[nodiscard]] const QByteArray& vaultId() const noexcept { return vaultId_; }
    // Opaque binding selected by the preparation owner. For an initial backup
    // this is a session generation, never a CRUD mutation generation.
    [[nodiscard]] quint64 bindingGeneration() const noexcept { return bindingGeneration_; }
    [[nodiscard]] const QString& rootDirectory() const noexcept { return rootDirectory_; }
    [[nodiscard]] const QString& familyDirectory() const noexcept { return familyDirectory_; }
    [[nodiscard]] const QString& destinationPath() const noexcept { return destinationPath_; }
    [[nodiscard]] const SnapshotDirectoryIdentity& rootIdentity() const noexcept
        { return rootIdentity_; }
    [[nodiscard]] const SnapshotDirectoryIdentity& familyIdentity() const noexcept
        { return familyIdentity_; }
    [[nodiscard]] const GlobalBackupPreferences& preparedPreferences() const noexcept
        { return preparedPreferences_; }
    [[nodiscard]] const QString& preferencesSourceFile() const noexcept
        { return preferencesSourceFile_; }

private:
    friend class BackupDestinationPreparer;
    VaultFileIdentity sourceIdentity_;
    QString vaultPath_;
    QByteArray vaultId_;
    quint64 bindingGeneration_ = 0;
    QString rootDirectory_;
    QString familyDirectory_;
    QString destinationPath_;
    SnapshotDirectoryIdentity rootIdentity_;
    SnapshotDirectoryIdentity familyIdentity_;
    GlobalBackupPreferences preparedPreferences_;
    QString preferencesSourceFile_;
    storage::VaultOperationGuard snapshotAccess_;
};

class BackupDestinationPreparer final {
public:
    // Acquires a snapshot capability, verifies the physical source and vault_id,
    // creates/opens the private family directory and chooses an unused UTC name.
    // No destination file is created and no worker is launched.
    [[nodiscard]] static bool prepare(const GlobalBackupPreferencesResult& configuration,
					      const VaultFileIdentity& expectedVault, quint64 bindingGeneration,
				      const QDateTime& timestamp, PreparedBackupDestination& output,
				      QString& error,
				      const SnapshotDirectoryIdentity* expectedRoot = nullptr,
				      const SnapshotDirectoryIdentity* expectedFamily = nullptr,
				      storage::VaultOperationGuard* existingSnapshotAccess = nullptr);

    // Rechecks all bindings while the original snapshot capability is alive.
    // A later publisher must still use no-overwrite publication and pass the
    // stored family identity to VaultSnapshotService.
    [[nodiscard]] static bool revalidate(const PreparedBackupDestination& prepared,
						 const VaultFileIdentity& expectedVault, quint64 expectedBindingGeneration,
					 QString& error);

    // Exact configuration revalidation used before a request token is
    // consumed. A non-null current snapshot also protects injected/in-memory
    // configurations used by isolated integration tests. Production results
    // carry sourceFile and are additionally reloaded from disk.
    [[nodiscard]] static bool revalidateConfiguration(
        const PreparedBackupDestination& prepared,
        const GlobalBackupPreferencesResult* current, QString& error);

private:
    friend class InitialBackupRequest;
    friend class AutomaticBackupCoordinator;
    // Revalidates and transfers the already-held capability directly into the
    // asynchronous driver. It never reacquires or exposes the raw guard.
    [[nodiscard]] static bool startPreparedSnapshot(
        PreparedBackupDestination& prepared, const VaultFileIdentity& expectedVault,
        quint64 expectedBindingGeneration, BackupJob& job, QString& error);
};

} // namespace passwall::services
