#pragma once

#include "services/backup_file_evidence.hpp"
#include "services/vault_snapshot_service.hpp"

namespace passwall::services {
// Keyless physical evidence and SHA-256 of a newly produced encrypted copy.
// Does not authenticate its logical contents or authorize deletion.
class BackupPublicationVerifier final {
public:
    static bool inspectEncryptedFile(const QString& path, BackupFileEvidence& output,
        QString& error, SnapshotCancellation cancellation = {});
};
} // namespace passwall::services
