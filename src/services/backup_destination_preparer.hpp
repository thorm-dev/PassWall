#pragma once

#include "services/backup_series_identity.hpp"
#include "services/global_backup_preferences_store.hpp"
#include "services/vault_preferences_store.hpp"
#include "services/vault_snapshot_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QDateTime>
#include <QString>

namespace passwall::services {

class BackupJob;

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
    // Opaque mutation-generation binding selected by the preparation owner.
    [[nodiscard]] quint64 bindingGeneration() const noexcept { return bindingGeneration_; }
    [[nodiscard]] const QString& rootDirectory() const noexcept { return rootDirectory_; }
    [[nodiscard]] const QString& familyDirectory() const noexcept { return familyDirectory_; }
    [[nodiscard]] const QString& seriesId() const noexcept { return seriesId_; }
    [[nodiscard]] const QString& seriesDirectory() const noexcept { return seriesDirectory_; }
    [[nodiscard]] const QString& destinationPath() const noexcept { return destinationPath_; }
    [[nodiscard]] const SnapshotDirectoryIdentity& rootIdentity() const noexcept
        { return rootIdentity_; }
    [[nodiscard]] const SnapshotDirectoryIdentity& familyIdentity() const noexcept
        { return familyIdentity_; }
    [[nodiscard]] const SnapshotDirectoryIdentity& seriesIdentity() const noexcept
        { return seriesIdentity_; }
    [[nodiscard]] const GlobalBackupPreferences& preparedPreferences() const noexcept
        { return preparedPreferences_; }
    [[nodiscard]] const QString& preferencesSourceFile() const noexcept
        { return preferencesSourceFile_; }
    [[nodiscard]] const std::optional<GlobalBackupPreferencesFileIdentity>&
        preferencesSourceIdentity() const noexcept
        { return preferencesSourceIdentity_; }

private:
    friend class BackupDestinationPreparer;
    VaultFileIdentity sourceIdentity_;
    QString vaultPath_;
    QByteArray vaultId_;
    quint64 bindingGeneration_ = 0;
    QString rootDirectory_;
    QString familyDirectory_;
    QString seriesId_;
    QString seriesDirectory_;
    QString destinationPath_;
    SnapshotDirectoryIdentity rootIdentity_;
    SnapshotDirectoryIdentity familyIdentity_;
    SnapshotDirectoryIdentity seriesIdentity_;
    GlobalBackupPreferences preparedPreferences_;
    QString preferencesSourceFile_;
    std::optional<GlobalBackupPreferencesFileIdentity>
        preferencesSourceIdentity_;
    storage::VaultOperationGuard snapshotAccess_;
};

class BackupDestinationPreparer final {
public:
    // Acquires a snapshot capability, verifies the physical source and vault_id,
    // creates/opens the private family and series directories, then chooses an
    // unused generation name (maximum present number + 1) in that series.
    // UTC is informational. A non-null installation identity is
    // an isolated/test injection; null resolves the real platform identity.
    // No destination file is created and no worker is launched.
    [[nodiscard]] static bool prepare(const GlobalBackupPreferencesResult& configuration,
					      const VaultFileIdentity& expectedVault, quint64 bindingGeneration,
				      const QDateTime& timestamp, PreparedBackupDestination& output,
				      QString& error,
				      const SnapshotDirectoryIdentity* expectedRoot = nullptr,
				      const SnapshotDirectoryIdentity* expectedFamily = nullptr,
				      const SnapshotDirectoryIdentity* expectedSeries = nullptr,
				      storage::VaultOperationGuard* existingSnapshotAccess = nullptr,
				      const BackupInstallationIdentity* installationIdentity = nullptr);

    // Rechecks all bindings while the original snapshot capability is alive.
    // A later publisher must still use no-overwrite publication and pass the
    // stored series-directory identity to VaultSnapshotService.
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
    friend class AutomaticBackupCoordinator;
    // Revalidates and transfers the already-held capability directly into the
    // asynchronous driver. It never reacquires or exposes the raw guard.
    [[nodiscard]] static bool startPreparedSnapshot(
        PreparedBackupDestination& prepared, const VaultFileIdentity& expectedVault,
        quint64 expectedBindingGeneration, BackupJob& job, QString& error);
};

} // namespace passwall::services
