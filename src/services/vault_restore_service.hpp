#pragma once

#include "services/vault_snapshot_service.hpp"
#include <span>
#include <string>

namespace passwall::services {
class VaultRestoreService final {
public:
    // Synchronous Linux/local operation: do not invoke on a GUI thread. Only
    // the backup, its ORIGINAL password and a NEW destination are required.
    // Password is borrowed for this call, never copied, retained or erased by
    // this service; the caller owns its lifetime and secure cleanup.
    // No key/session is returned. vault_id, AEAD bindings and all encrypted
    // records are preserved, not regenerated. No local registration/preferences
    // are read or inherited: a future local registry must give a restored file
    // its own registration identity, not treat vault_id as local authorization.
    // SnapshotResult describes FINAL publication only. true iff Published;
    // other states fail closed. Post-publication failures NEVER remove final.
    // Exceptions are contained; a diagnostic may be empty under allocation
    // failure, but publication state remains authoritative. An authentic old
    // or incomplete historical backup is NOT a freshness/completeness proof.
    [[nodiscard]] static bool restoreBackup(
        const std::string& backupPath,
        const std::string& destinationPath,
        std::span<const unsigned char> masterPassword,
        SnapshotResult& result) noexcept;
};
} // namespace passwall::services
