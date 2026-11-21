#pragma once

#include <array>
#include <string>
#include <cstdint>
namespace passwall::storage { class VaultOperationGuard; }

namespace passwall::services {

class VaultReplacementAuthorization;

struct SnapshotDirectoryIdentity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    bool operator==(const SnapshotDirectoryIdentity&) const = default;
};

struct SnapshotSourceIdentity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    bool operator==(const SnapshotSourceIdentity&) const = default;
};

// Keyless structural information only. A matching vault_id and the presence
// of rows do not authenticate their encrypted contents.
struct SnapshotVaultContents {
    std::array<std::uint8_t, 16> vaultId{};
    bool hasEntries = false;
};

enum class SnapshotPublication {
    NotPublished,
    CancelledBeforePublication,
    Published,
    PublishedDurabilityUnconfirmed
};

enum class SnapshotCheckpoint { BeforeWork, CopyStep, BeforeValidation, BeforePublication };
// Non-owning, synchronous callback; no key or SQLite handle is exposed. Returning
// true cancels BEFORE publication. It must not throw or access the destination DB.
struct SnapshotCancellation {
    bool (*requested)(void*, SnapshotCheckpoint) noexcept = nullptr;
    void* context = nullptr;
};

// Optional trusted in-process verification of the PRIVATE, structurally checked
// copy, after all snapshot SQLite handles close and before fsync/publication.
// Read-only contract: must not modify, replace, retain or expose the temporary
// file/path. false/exception prevents publication. The keyless backup worker
// may hash encrypted bytes here; decryption/authentication stays in restoration.
struct SnapshotVerification {
    bool (*verify)(void*, const std::string&, std::string&) = nullptr;
    void* context = nullptr;
};

struct SnapshotResult {
    SnapshotPublication publication = SnapshotPublication::NotPublished;
    // Constant operation names and numeric error codes, never database values.
    // May contain a cleanup warning even when publication is confirmed.
    std::string diagnostic;
};

class VaultSnapshotService final {
public:
    // Read-only, keyless structural screening used by restoration and backup
    // preparation. This rejects files manifestly incompatible with PassWall V1,
    // but is neither cryptographic authentication nor an authorization. The
    // restore engine must still repeat all source/identity/content checks.
    [[nodiscard]] static bool prevalidateVaultSource(const std::string& path,
        std::string& error, SnapshotSourceIdentity* identity = nullptr,
        SnapshotVaultContents* contents = nullptr);
    // Same directory traversal/permissions/filesystem policy as createSnapshot.
    // Never creates a missing directory or redirects to another destination.
    [[nodiscard]] static bool inspectDestinationDirectory(const std::string& path,
        SnapshotDirectoryIdentity& identity, std::string& error);
    // Synchronous, keyless engine for local Linux/POSIX filesystems. The caller
    // owns authorization and must NOT invoke blocking I/O on the GUI thread.
    // Destination types: ext2/3/4, tmpfs, XFS, Btrfs, F2FS and overlayfs;
    // link/fsync support is still checked. No network/FAT fallback is offered.
    // Absolute paths only; symlink components and unsafe writable ancestors
    // are rejected. Destination parent must be owned by the current UID and
    // not group/other writable. No existing destination is overwritten.
    // Source is opened READONLY, without CREATE or immutable=1. A source that
    // needs writable recovery is refused; there is no read-write fallback.
    // No global time/iteration limit on a progressing copy or source restarts.
    // Three consecutive BUSY/LOCKED results abort the attempt; SQLITE_OK resets
    // this counter. SQLite's V1 busy_timeout remains 3 s per eligible call.
    // This does NOT bound blocking filesystem calls. Cancellation is cooperative,
    // checked between steps and immediately before linkat, never after publication.
    // Cancellation racing with an already entered linkat cannot retract it.
    // The engine itself performs no cryptographic authentication; the optional
    // trusted verification hook belongs to its in-process restore caller.
    // The default call obtains a serialized snapshot access which coexists with
    // business access but excludes replacement. A worker can borrow that typed
    // inherited capability; ordinary business access cannot be exported.
    // A legacy exclusive reservation is still accepted while the historical
    // automatic coordinator depends on exclusive mutation tracking.
    // true means Published, not merely a complete SQLite backup. If allocation
    // throws, RAII cleans owned temporaries; result.publication still records
    // any irreversible publication, set before constructing its diagnostic.
    [[nodiscard]] static bool createSnapshot(
        const std::string& sourcePath,
        const std::string& destinationPath,
        SnapshotResult& result, SnapshotCancellation cancellation = {},
        SnapshotVerification verification = {},
        const storage::VaultOperationGuard* reservation = nullptr,
        const SnapshotDirectoryIdentity* expectedDirectory = nullptr);
private:
    friend class VaultReplacementAuthorization;
    struct ReplacementReadCheck {
        bool (*check)(void*, SnapshotCheckpoint, std::string&);
        void* context;
    };
    [[nodiscard]] static bool createReplacementSnapshot(const std::string& source,
        const std::string& destination, SnapshotResult&, SnapshotCancellation,
        const storage::VaultOperationGuard&, ReplacementReadCheck);
};

} // namespace passwall::services
