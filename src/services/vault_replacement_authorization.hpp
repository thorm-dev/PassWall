#pragma once

#include "services/vault_preferences_store.hpp"
#include <memory>
#include <array>
#include <functional>
#include <QJsonObject>

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
// Public direct operations run on that Qt owner thread. Private issuance I/O is
// isolated while no authority is published. Delegated execution has its own
// child-thread context, with live admissions by the real owner's GUI thread.
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
    // RestoreWorker alone can adopt a constrained delegated execution context.
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
    friend class RestoreDelegation;
    friend class RestoreWorkerAdmission;
#ifdef PASSWALL_REPLACEMENT_TESTING
    friend class ReplacementTestAccess; // Only in the separately compiled test binary.
#endif
    struct State;
    std::shared_ptr<State> state_;
    explicit VaultReplacementAuthorization(std::shared_ptr<State>) noexcept;
    static std::shared_ptr<State> reserve(const VaultPreferencesStore&, const QString&,
        std::function<bool()> cleanupStillValid, QString&);
    static VaultReplacementAuthorization acknowledge(std::shared_ptr<State>, QString&);
    // Three-part issuance: owner-thread cleanup, secretless I/O, owner-thread
    // revalidation. The state is not otherwise used while its I/O is running.
    static bool beginPreparation(const std::shared_ptr<State>&, QString&);
    static bool prepare(const std::shared_ptr<State>&, QString&);
    static VaultReplacementAuthorization finishPreparation(std::shared_ptr<State>, QString&);
    static void revoke(const std::shared_ptr<State>&) noexcept;
    static bool active(const std::shared_ptr<State>&) noexcept;
    static bool targetsSession(const std::shared_ptr<State>&, const QString&);
    // Read-only GUI consent binding. No I/O, issuance or authorization bypass.
    [[nodiscard]] bool matchesSelection(const VaultRegistration&) const noexcept;
    // Internal delegation only; callers cannot import an authority. The worker
    // additionally verifies the executable parent and private inherited socket.
    [[nodiscard]] QJsonObject delegate(QString& error);
    [[nodiscard]] bool delegationCurrent() const noexcept;
    [[nodiscard]] std::array<int, 2> delegationHandles() const noexcept;
    static VaultReplacementAuthorization receiveDelegation(const QJsonObject&,
        std::array<int, 2>, std::function<bool()>, QString&);
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
// after engagement. RestoreJob owns the private IPC. restoreBackup's existing
// borrowed-span contract is unchanged.
} // namespace passwall::services
