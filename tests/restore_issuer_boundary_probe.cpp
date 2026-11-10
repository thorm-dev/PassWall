// Compile-only probe. NEVER link these stand-in class definitions with the
// real runtime classes (ODR). Their exact names exercise friendship boundaries.
#include "services/restore_delegation.hpp"
#include <type_traits>

namespace passwall::services {
#define VERIFY_NO_ISSUER_ACCESS \
    template<class A> static constexpr bool CanReserve = requires(const VaultPreferencesStore& s, \
        const QString& id, std::function<bool()> check, QString& e) { A::reserve(s, id, check, e); }; \
    template<class A> static constexpr bool CanAcknowledge = requires(QString& e) { A::acknowledge({}, e); }; \
    static_assert(!CanReserve<VaultReplacementAuthorization>); \
    static_assert(!CanAcknowledge<VaultReplacementAuthorization>);
class RestoreWorker {
    VERIFY_NO_ISSUER_ACCESS
    template<class G> static constexpr bool CanDelegate = requires(VaultReplacementAuthorization& a, QString& e) { G::issue(a, e); };
    static_assert(!CanDelegate<RestoreDelegation>);
};
class RestoreProcessSession {
    VERIFY_NO_ISSUER_ACCESS
    template<class G> static constexpr bool CanImport = requires(const QJsonObject& m,
        std::array<int, 2> fds, std::function<bool()> check, QString& e) { G::receive(m, fds, check, e); };
    static_assert(!CanImport<RestoreWorkerAdmission>);
};
#undef VERIFY_NO_ISSUER_ACCESS
static_assert(!std::is_default_constructible_v<RestoreDelegation>);
static_assert(!std::is_default_constructible_v<RestoreWorkerAdmission>);
static_assert(!std::is_constructible_v<VaultReplacementAuthorization, QJsonObject>);
} // namespace passwall::services
