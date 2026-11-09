#pragma once

#include "services/vault_preferences_store.hpp"
#include <memory>
#include <functional>

namespace passwall::gui { class MainWindow; }
namespace passwall::core { class SecureBuffer; }
namespace passwall::services {

struct ReplacementResult;
struct ReplacementControl;
struct ReplacementRecoveryResult;
enum class ReplacementRecoveryAction;

enum class ReplacementFinalizationState {
    NotStarted,
    IdentityUnconfirmed,
    IdentityConfirmedResolutionPending,
    Resolved,
    SafeResolutionUnconfirmed,
    RecoveryRequired
};
struct ReplacementFinalizationResult {
    ReplacementFinalizationState state = ReplacementFinalizationState::NotStarted;
    QString diagnostic;
};

// A local, move-only authority, NOT a serializable token or CRUD permission.
// Issuer: MainWindow, after its real queued external-lock acknowledgement.
// All operations, including destruction/revocation, run on that Qt owner thread.
// Destruction revokes the reservation, but NEVER silently clears a durable fence.
class VaultReplacementAuthorization final {
public:
    VaultReplacementAuthorization() noexcept = default;
    ~VaultReplacementAuthorization() noexcept;
    VaultReplacementAuthorization(const VaultReplacementAuthorization&) = delete;
    VaultReplacementAuthorization& operator=(const VaultReplacementAuthorization&) = delete;
    VaultReplacementAuthorization(VaultReplacementAuthorization&&) noexcept;
    VaultReplacementAuthorization& operator=(VaultReplacementAuthorization&&) noexcept;

    [[nodiscard]] bool valid(QString& error) const;
    [[nodiscard]] QString operationId() const;
    [[nodiscard]] QString localId() const;
    // Capability-scoped abort ONLY before substitution was authorized, after
    // verifying original metadata, physical identity AND the original digest.
    // Never deletes candidate/recovery files. No id-only "clear fence" API.
    [[nodiscard]] bool abandonPreparation(QString& error);
    // The only recovery-gate exception: read THIS unchanged old principal in
    // prepared phase. No caller-selected source or generic bypass flag.
    [[nodiscard]] bool snapshotPrincipal(const std::string& destination, SnapshotResult& result,
        SnapshotCancellation cancellation = {}) const;
    // No issuance, substitution, authentication or automatic unlock. Only a
    // previously confirmed identity (or its resolved receipt) can be resumed.
    [[nodiscard]] static ReplacementFinalizationResult resumeFinalization(
        const VaultPreferencesStore&, const QString& localId, const QString& operationId);
    // 6B synchronous engine, no Widgets/event loop. Before engagement the caller
    // can explicitly abandonPreparation() if the original proofs still match.
    // After arm, the capability is consumed, NEVER its persistent recovery fence.
    // Call on the capability's owner thread, not a newly invented worker thread.
    // Step 7 must establish a constrained delegation before off-thread/process use.
    [[nodiscard]] bool replacePrincipal(const QString& principal, const QString& source,
        core::SecureBuffer password, const QString& precautionDestination,
        ReplacementResult&, ReplacementControl) noexcept;
    // Explicit recovery only: never issues an authority or repeats an exchange.
    [[nodiscard]] static ReplacementRecoveryResult recoverReplacement(
        const VaultPreferencesStore&, const QString& localId, const QString& operationId,
        ReplacementRecoveryAction);
    void reset() noexcept;

private:
    friend class gui::MainWindow;
#ifdef PASSWALL_REPLACEMENT_TESTING
    friend class ReplacementTestAccess; // Only in the separately compiled test binary.
#endif
    struct State;
    std::shared_ptr<State> state_;
    explicit VaultReplacementAuthorization(std::shared_ptr<State>) noexcept;
    static std::shared_ptr<State> reserve(const VaultPreferencesStore&, const QString&,
        std::function<bool()> cleanupStillValid, QString&);
    static VaultReplacementAuthorization acknowledge(std::shared_ptr<State>, QString&);
    static void revoke(const std::shared_ptr<State>&) noexcept;
    static bool active(const std::shared_ptr<State>&) noexcept;
    static bool targetsSession(const std::shared_ptr<State>&, const QString&);
    // Limited transitions used internally by the 6B member engine. They remain
    // private: no external engine friendship grants reserve()/acknowledge().
    // The engine supplies the digest of the fully authenticated private copy.
    [[nodiscard]] bool stageCandidate(const QString& privatePath, QString& error,
        const QByteArray& authenticatedDigest = {});
    [[nodiscard]] bool armPublication(QString& error);
    [[nodiscard]] ReplacementFinalizationResult finalizePublication();
    [[nodiscard]] bool replacementContext(VaultRegistration&, VaultReplacementIntent&, QString&) const;
    [[nodiscard]] bool verifyBeforeExchange(QString&) const;
    [[nodiscard]] bool permitsSnapshot(const std::string&, const storage::VaultOperationGuard&,
        SnapshotCheckpoint, std::string&) const;
};

// The 6B API takes SecureBuffer BY VALUE (explicit ownership move), destroys
// password/DEK/temporary credentials BEFORE publication, and consumes authority
// after engagement. No worker/password transport yet. restoreBackup's existing
// borrowed-span contract is unchanged.
} // namespace passwall::services
