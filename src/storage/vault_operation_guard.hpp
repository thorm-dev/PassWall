#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace passwall::services { class VaultReplacementAuthorization; }

namespace passwall::storage {

// Cooperative Linux exclusion. Access guards protect the ENTIRE lifetime of
// read-write connections (even logical reads). Snapshot access coexists with
// them but is serialized per physical source; exclusive reservations exclude
// both modes.
// No SQL, key, credential, PID-based ownership or GUI dependency.
// Fixed private /tmp/.passwall-vault-operations-UID namespace; lock files are
// empty synchronization resources, retained until OS cleanup, NEVER unlinked
// while clients might hold them. Requires one shared local /tmp namespace.
// Does not constrain third parties ignoring this protocol, administrative
// deletion of its namespace, or separate mount namespaces/private /tmp trees.
class VaultOperationGuard final {
public:
    VaultOperationGuard() = default;
    ~VaultOperationGuard() noexcept;
    VaultOperationGuard(const VaultOperationGuard&) = delete;
    VaultOperationGuard& operator=(const VaultOperationGuard&) = delete;
    VaultOperationGuard(VaultOperationGuard&& other) noexcept;
    VaultOperationGuard& operator=(VaultOperationGuard&& other) noexcept;

    [[nodiscard]] bool tryAccess(const std::string& path, std::string& error);
    // Shared with business access, but serialized against another snapshot of
    // the same physical source. This is a distinct transferable capability.
    [[nodiscard]] bool trySnapshotAccess(const std::string& path, std::string& error);
    [[nodiscard]] bool tryReserve(const std::string& path, std::string& error);
    [[nodiscard]] bool attempted() const noexcept { return attempted_; }
    [[nodiscard]] bool contended() const noexcept { return contended_; }
    [[nodiscard]] bool matchesAccess(const std::string& path, std::string& error) const;
    [[nodiscard]] bool matchesSnapshotAccess(const std::string& path, std::string& error) const;
    // Requires a currently valid snapshot capability for path and additionally
    // binds it to the physical file expected by the caller. Device/inode are
    // session evidence only, never a persistent authentication capability.
    [[nodiscard]] bool matchesSnapshotIdentity(const std::string& path,
        std::uint64_t device, std::uint64_t inode, std::string& error) const;
    [[nodiscard]] bool matchesReservation(const std::string& path, std::string& error) const;
    // Ownership transfer in an exec'd keyless snapshot worker only. Ordinary
    // business access cannot export this capability.
    [[nodiscard]] bool adoptSnapshotAccess(const std::string& path,
        std::array<int, 3> handles, std::string& error);
    // Ownership transfer in an exec'd worker only. Validates the inherited lock
    // files against the actual source. Never grants permission for business SQL.
    [[nodiscard]] bool adoptReservation(const std::string& path,
        std::array<int, 2> handles, std::string& error);
    [[nodiscard]] std::array<int, 3> inheritedSnapshotHandles() const noexcept;
    [[nodiscard]] std::array<int, 2> inheritedHandles() const noexcept;
    // Process-local wake-up hint for coordinators waiting on a cooperative
    // reservation. Readability never proves that a particular vault is free:
    // callers must acquire and revalidate a fresh capability after each hint.
    [[nodiscard]] static int releaseNotificationDescriptor() noexcept;
    static void consumeReleaseNotifications() noexcept;
    void reset() noexcept;

private:
    friend class services::VaultReplacementAuthorization;
    // Restore-only: original pathname lock + candidate inode lock, both still
    // exclusively owned. Does not weaken matchesReservation for backups.
    [[nodiscard]] bool matchesReplacement(const std::string& path,
        const VaultOperationGuard& candidate, std::string& error) const;
    [[nodiscard]] bool ownsExclusiveLocks() const;
    enum class Mode { None, Access, Snapshot, Exclusive };
    bool acquire(const std::string& path, Mode mode, std::string& error);
    std::array<int, 2> handles_{-1, -1};
    int snapshotHandle_ = -1;
    std::string pathKey_, fileKey_, snapshotKey_;
    std::uint64_t device_ = 0, inode_ = 0;
    Mode mode_ = Mode::None;
    bool attempted_ = false;
    bool contended_ = false; // Distinguish an occupied lock from an I/O/policy error.
};

} // namespace passwall::storage
