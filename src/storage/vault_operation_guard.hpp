#pragma once

#include <array>
#include <string>

namespace passwall::services { class VaultReplacementAuthorization; }

namespace passwall::storage {

// Cooperative Linux exclusion. Access guards protect the ENTIRE lifetime of
// read-write connections (even logical reads); reservations exclude them.
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
    [[nodiscard]] bool tryReserve(const std::string& path, std::string& error);
    [[nodiscard]] bool contended() const noexcept { return contended_; }
    [[nodiscard]] bool matchesReservation(const std::string& path, std::string& error) const;
    // Ownership transfer in an exec'd worker only. Validates the inherited lock
    // files against the actual source. Never grants permission for business SQL.
    [[nodiscard]] bool adoptReservation(const std::string& path,
        std::array<int, 2> handles, std::string& error);
    [[nodiscard]] std::array<int, 2> inheritedHandles() const noexcept;
    void reset() noexcept;

private:
    friend class services::VaultReplacementAuthorization;
    // Restore-only: original pathname lock + candidate inode lock, both still
    // exclusively owned. Does not weaken matchesReservation for backups.
    [[nodiscard]] bool matchesReplacement(const std::string& path,
        const VaultOperationGuard& candidate, std::string& error) const;
    [[nodiscard]] bool ownsExclusiveLocks() const;
    bool acquire(const std::string& path, bool exclusive, std::string& error);
    std::array<int, 2> handles_{-1, -1};
    std::string pathKey_, fileKey_;
    bool exclusive_ = false;
    bool contended_ = false; // Distinguish an occupied lock from an I/O/policy error.
};

} // namespace passwall::storage
