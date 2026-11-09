#pragma once

#include "services/backup_protocol.hpp"
#include "storage/vault_operation_guard.hpp"

namespace passwall::services {
// Synchronous, keyless, Linux-only implementation. Called in the worker, NEVER
// on the GUI thread. Cooperative cancellation cannot interrupt a kernel I/O.
class BackupRotationService final {
public:
    static bool inspectEncryptedFile(const QString& path, BackupFileEvidence& output,
        QString& error, SnapshotCancellation cancellation = {});
    static RotationResult rotate(const QString& settings, const QString& localId,
        const QString& attempt, const QString& source,
        const storage::VaultOperationGuard& reservation, SnapshotCancellation cancellation = {});
};
} // namespace passwall::services
