#pragma once
#include "services/vault_replacement_authorization.hpp"

namespace passwall::services {
class RestoreProcessSession;
class RestoreWorker;

// Narrow PRIVATE bridge, not a public capability factory. Neither the worker
// nor the supervisor is a friend of Authorization: they cannot reserve or
// acknowledge cleanup. Parent and child have separate, limited access paths.
// Child admission is reached only after its OS parent/channel verification.
class RestoreDelegation final {
    RestoreDelegation() = delete;
    friend class RestoreProcessSession;
    static QJsonObject issue(VaultReplacementAuthorization& a, QString& error) { return a.delegate(error); }
    static bool current(const VaultReplacementAuthorization& a) noexcept { return a.delegationCurrent(); }
    static std::array<int, 2> handles(const VaultReplacementAuthorization& a) noexcept { return a.delegationHandles(); }
};
class RestoreWorkerAdmission final {
    RestoreWorkerAdmission() = delete;
    friend class RestoreWorker;
    static VaultReplacementAuthorization receive(const QJsonObject& message, std::array<int, 2> handles,
        std::function<bool()> live, QString& error) {
        return VaultReplacementAuthorization::receiveDelegation(message, handles, std::move(live), error);
    }
    static std::shared_ptr<void> retain(const VaultReplacementAuthorization& a) { return a.state_; }
};
} // namespace passwall::services
