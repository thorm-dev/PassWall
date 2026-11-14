#pragma once

#include "services/vault_replacement_authorization.hpp"

namespace passwall::services {

// These are operation results, NOT another persistent phase machine.
enum class ReplacementOutcome {
    NotReplaced,
    CancelledBeforeEngagement,
    EngagedRecoveryRequired,
    ReplacedDurabilityUnconfirmed,
    ReplacedFinalizationPending,
    Replaced
};
enum class ReplacementCheckpoint {
    BeforeWork, SourceAuthenticated, PrecautionCreated, CandidateStaged,
    BeforeArm, Armed, BeforeExchange, AfterExchange, AfterDirectorySync
};
// Synchronous/non-owning. No secret is exposed. Must not throw. A true return
// before arm confirms cancellation; after arm it can only stop with recovery
// required, NEVER claim cancellation of an exchange that may have happened.
struct ReplacementControl {
    bool (*requested)(void*, ReplacementCheckpoint) noexcept = nullptr;
    void* context = nullptr;
};
struct ReplacementResult {
    ReplacementOutcome outcome = ReplacementOutcome::NotReplaced;
    bool sourceAuthenticationFailed = false; // Master-key rejection; no diagnostic-text parsing by supervisor.
    ReplacementFinalizationResult finalization;
    SnapshotResult precaution;
    QString operationId;
    QString recoveryArtifact;
    QString diagnostic;
};
enum class ReplacementRecoveryAction { Inspect, FinalizeExchanged, AbandonPrepared };
enum class ReplacementLayout {
    Unrecognized, PreparedIntact, ArmedBeforeExchange, ArmedAfterExchange,
    IdentityConfirmed, Resolved, AbandonmentPending, Abandoned
};
struct ReplacementRecoveryResult {
    ReplacementLayout layout = ReplacementLayout::Unrecognized;
    ReplacementFinalizationResult finalization;
    QString diagnostic;
};

} // namespace passwall::services
