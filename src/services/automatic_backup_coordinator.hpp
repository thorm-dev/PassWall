#pragma once

#include "services/backup_trigger_mode.hpp"
#include "services/initial_backup_preparer.hpp"
#include "services/vault_preferences_store.hpp"
#include <QMap>
#include <QPointer>
#include <QSet>
#include <QTimer>
#include <atomic>
#include <memory>
#include <optional>
#include <QVector>

class QSocketNotifier;
namespace passwall::gui { class MainWindow; }

namespace passwall::services {
class BackupJob;
class VaultReplacementAuthorization;

// The initial-copy obligation is not a synthetic CRUD generation. Both kinds
// share the same in-memory arbitration queue and single-use attempt tokens,
// while their distinct bindings remain explicit at the public boundary.
enum class GenerationalBackupRequestKind {
    CrudGeneration,
    InitialCopy
};

// Transient, owner-thread proof for the exact generation attempt that produced
// a published file. It is deliberately not a persistent catalogue entry.
struct MutationBackupPublicationReceipt {
    QString vaultPath;
    QString destination;
    quint64 generation = 0;
    quint64 requestId = 0;
    BackupFileEvidence evidence;
    GenerationalBackupRequestKind kind = GenerationalBackupRequestKind::CrudGeneration;
    quint64 sessionGeneration = 0;
    bool operator==(const MutationBackupPublicationReceipt&) const = default;
};

enum class MutationBackupOutcome {
    Published,
    Failed,
    Unknown
};

// A generation failure pauses only the in-memory generational engine. This is
// deliberately unrelated to the historical persistent suspension stored in
// PassWall.conf and disappears with this coordinator/process.
enum class GenerationalBackupSuspensionReason {
    None,
    Failed,
    Unknown
};

struct GenerationalBackupSuspensionState {
    bool suspended = false;
    GenerationalBackupSuspensionReason reason =
        GenerationalBackupSuspensionReason::None;
    QString vaultPath;
    QByteArray vaultId;
    quint64 device = 0;
    quint64 inode = 0;
    quint64 latestMutationGeneration = 0;
    quint64 latestSessionGeneration = 0;
    bool resumeRequested = false;
    bool workerAlive = false;
    QString diagnostic;
    bool operator==(const GenerationalBackupSuspensionState&) const = default;
};

// Transient close-drain presentation for the generational engine. A drain is
// deliberately distinct from shutdown(): it keeps dispatch and supervision
// alive until every eligible automatic request has reached a real result.
enum class GenerationalShutdownDrainStatus {
    NotRequested,
    Draining,
    WorkerActive,
    Completed,
    CompletedWithFailureOrSuspension
};

struct GenerationalShutdownDrainState {
    GenerationalShutdownDrainStatus status =
        GenerationalShutdownDrainStatus::NotRequested;
    bool workerAlive = false;
    bool requestPending = false;
    quint64 latestMutationGeneration = 0;
    QString diagnostic;
    bool operator==(const GenerationalShutdownDrainState&) const = default;
};

struct GenerationalBackupRequestOffer {
    GenerationalBackupRequestKind kind = GenerationalBackupRequestKind::CrudGeneration;
    QString vaultPath;
    quint64 mutationGeneration = 0;
    quint64 sessionGeneration = 0;
    quint64 requestId = 0;
    bool operator==(const GenerationalBackupRequestOffer&) const = default;
};

enum class InitialBackupArbitration {
    Offered,
    MergedWithExistingRequest,
    Refused
};

enum class InitialBackupInspectionLaunch {
    Started,
    AlreadyRunning,
    AlreadySettled,
    Refused
};

struct InitialBackupInspectionLaunchResult {
    InitialBackupInspectionLaunch outcome = InitialBackupInspectionLaunch::Refused;
    quint64 activityId = 0;
    QString diagnostic;
};

struct InitialBackupInspectionResult {
    quint64 activityId = 0;
    InitialBackupDecision decision = InitialBackupDecision::Refused;
    InitialBackupArbitration arbitration = InitialBackupArbitration::Refused;
    QString diagnostic;
};

// Read-only, transient presentation of the generational engine. These phases
// are coordination hints only: VaultOperationGuard remains the final authority
// for every export, replacement and snapshot.
enum class GenerationalOperationPhase {
    Idle,
    Inspecting,
    PreparedReservation,
    PendingRequest,
    OfferedRequest,
    WaitingForReservation,
    AttemptActive,
    WorkerActive,
    Cancelling,
    Completed,
    Cancelled
};

struct GenerationalOperationState {
    GenerationalOperationPhase phase = GenerationalOperationPhase::Idle;
    GenerationalBackupRequestKind kind = GenerationalBackupRequestKind::CrudGeneration;
    QString vaultPath;
    quint64 mutationGeneration = 0;
    quint64 sessionGeneration = 0;
    quint64 requestId = 0;
    bool reservationHeld = false;
    bool workerAlive = false;
    bool resultObserved = false;
    BackupOutcome workerOutcome = BackupOutcome::Unknown;
    quint64 activityId = 0;
    bool operator==(const GenerationalOperationState&) const = default;
};

enum class BackupUserOperation {
    ManualExport,
    Restoration
};

struct BackupUserOperationAdmission {
    bool compatible = true;
    GenerationalOperationState blockingState;
    QString diagnostic;
};

// Short-lived owner-thread arbitration only. It is neither a replacement
// authority nor a substitute for VaultOperationGuard. In Generational mode it
// prevents a later automatic request from overtaking a manual operation while
// that operation performs the real lock/cleanup and acquires its exclusive
// kernel reservation. The final consumer must still acquire and validate that
// reservation. The capability is move-only and releases its arbitration slot
// by RAII on every refusal/cancellation path.
class ManualBackupOperationAdmission final {
public:
    ManualBackupOperationAdmission() noexcept = default;
    ~ManualBackupOperationAdmission() noexcept;
    ManualBackupOperationAdmission(const ManualBackupOperationAdmission&) = delete;
    ManualBackupOperationAdmission& operator=(const ManualBackupOperationAdmission&) = delete;
    ManualBackupOperationAdmission(ManualBackupOperationAdmission&&) noexcept;
    ManualBackupOperationAdmission& operator=(ManualBackupOperationAdmission&&) noexcept;
    [[nodiscard]] bool valid() const noexcept;
    // Narrow export hand-off: acquires the real exclusive reservation and
    // transfers it directly to BackupJob without exposing the raw guard.
    [[nodiscard]] bool startExport(BackupJob&, const QString& source,
        const QString& destination, QString& error);

private:
    struct State;
    std::shared_ptr<State> state_;
    explicit ManualBackupOperationAdmission(std::shared_ptr<State>) noexcept;
    [[nodiscard]] bool generational() const noexcept;
    [[nodiscard]] bool consumeForExclusive(BackupUserOperation,
        const QString&, QString&);
    [[nodiscard]] bool acquireExclusive(BackupUserOperation,
        const QString&, storage::VaultOperationGuard&, QString&);
    void reset() noexcept;
    friend class AutomaticBackupCoordinator;
    friend class BackupJob;
    friend class VaultReplacementAuthorization;
    friend class gui::MainWindow;
};

// Complete transient result for one exact generation attempt. The coarse
// outcome drives coordination, while workerOutcome and diagnostic retain the
// validated worker/protocol result without creating persistent history.
struct MutationBackupResult {
    QString vaultPath;
    quint64 generation = 0;
    quint64 requestId = 0;
    MutationBackupOutcome outcome = MutationBackupOutcome::Unknown;
    BackupOutcome workerOutcome = BackupOutcome::Unknown;
    QString diagnostic;
    std::optional<MutationBackupPublicationReceipt> publication;
    GenerationalBackupRequestKind kind = GenerationalBackupRequestKind::CrudGeneration;
    quint64 sessionGeneration = 0;
};

// Owner-thread Qt coordinator. No key, credential, retry loop or copy engine;
// only in-memory grouping/coordination timers and generations live here.
// Registry/preflight work runs only from deferred dispatch, never from
// lockVault's cleanup/acknowledgement stack. Copy I/O belongs to the worker.
class AutomaticBackupCoordinator final : public QObject {
    Q_OBJECT
public:
    explicit AutomaticBackupCoordinator(QObject* parent = nullptr);
    AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker, QObject* parent = nullptr);
    AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker,
        int mutationGroupingDelayMs, QObject* parent = nullptr);
    AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker,
        int mutationGroupingDelayMs, int mutationContentionWaitMs,
        QObject* parent = nullptr);
    // Test/integration boundary for the not-yet-enabled generational engine.
    // Production constructors above remain permanently Historical.
    AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker,
        int mutationGroupingDelayMs, int mutationContentionWaitMs,
        BackupTriggerMode triggerMode, QObject* parent = nullptr);
    ~AutomaticBackupCoordinator() override;
    void trackVault(const VaultRegistration& registration);
    void stopModificationGrouping();
    void requestPendingMutationsForLock(const QString& path);
    // Owner-thread admission only. It either retains the prepared InitialCopy
    // in the existing queue or releases it because an exact CRUD request
    // already covers the same physical vault. It never starts a worker.
    [[nodiscard]] InitialBackupArbitration admitInitialBackup(
        InitialBackupRequest request, const InitialBackupAdmission& admission,
        QString& error);
    // Future off-GUI inspection boundary. The returned identifier is transient,
    // session-bound and revocable; it is never a reservation or authorization.
    [[nodiscard]] quint64 beginInitialBackupInspection(
        const VaultFileIdentity& identity, quint64 sessionGeneration, QString& error);
    [[nodiscard]] bool markInitialBackupPrepared(quint64 activityId,
        InitialBackupRequest request, QString& error);
    [[nodiscard]] InitialBackupArbitration admitPreparedInitialBackup(
        quint64 activityId, InitialBackupAdmission admission, QString& error);
    [[nodiscard]] bool cancelInitialBackupInspection(quint64 activityId);
    // Runs the filesystem/SQLite inspection on a dedicated short-lived thread.
    // The optional observer is a deterministic test hook composed with the
    // coordinator's own atomic cancellation; it must outlive the activity.
    [[nodiscard]] InitialBackupInspectionLaunchResult
        startInitialBackupInspectionAsync(
            GlobalBackupPreferencesResult configuration,
            AuthenticatedBackupSession session, QDateTime timestamp,
            InitialBackupCancellation observer = {});
    // Owner-thread notification/revalidation boundary for global preferences.
    // Invalid configurations pause new offers but retain CRUD generations.
    // A live worker is deliberately not interrupted.
    void applyGlobalBackupPreferences(
        GlobalBackupPreferencesResult configuration);
    // Configuration owners use this before replacing an active configuration.
    // It never waits for filesystem work or releases a still-live capability.
    void invalidateInitialBackupInspection();
    [[nodiscard]] bool initialBackupInspectionActive() const noexcept;
    [[nodiscard]] GenerationalBackupSuspensionState
        generationalBackupSuspension(const QString& vaultPath) const;
    // Explicit, owner-thread resumption. A CRUD need is offered exactly once;
    // an InitialCopy-only need asks the integration owner for a fresh secured
    // inspection. No worker is started by this method.
    [[nodiscard]] bool resumeGenerationalBackup(
        const QString& vaultPath, QString& error);
    [[nodiscard]] GenerationalOperationState generationalOperationState(
        const QString& vaultPath) const;
    // Conservative early diagnostic only. A positive answer never replaces
    // the exclusive reservation required by export/restoration.
    [[nodiscard]] BackupUserOperationAdmission admitUserOperation(
        BackupUserOperation operation, const QString& vaultPath) const;
    // Atomic owner-thread arbitration boundary used immediately before a
    // manual operation starts its lock/reservation transition. Historical mode
    // returns a neutral capability and therefore preserves production behavior.
    [[nodiscard]] ManualBackupOperationAdmission acquireUserOperation(
        BackupUserOperation operation, const QString& vaultPath, QString& error);
    // A request token is single-use and only its matching active attempt may
    // settle a mutation generation.
    [[nodiscard]] bool markMutationBackupStarted(
        quint64 requestId, const QString& path, quint64 generation,
        QString destination = {});
    [[nodiscard]] bool markMutationBackupFinished(
        quint64 requestId, MutationBackupOutcome outcome,
        std::optional<MutationBackupPublicationReceipt> receipt = {});
    // Prepared integration boundary only: no production signal is connected to
    // this method in lot 2E. The caller owns destination selection/preflight.
    [[nodiscard]] bool startMutationBackupSnapshot(quint64 requestId,
        const QString& path, quint64 generation, const QString& destination,
        storage::VaultOperationGuard access,
        std::optional<SnapshotDirectoryIdentity> directory, QString& error);
    // Preferred 2I-4E-2 CRUD consumer: the potentially slow preparation is
    // completed beforehand, then this owner-thread boundary revalidates and
    // transfers its single retained capability without reacquisition.
    [[nodiscard]] bool startPreparedMutationBackupSnapshot(quint64 requestId,
        const QString& path, quint64 generation,
        PreparedBackupDestination prepared, QString& error);
    // Consumes exactly one already-prepared InitialCopy offer. Final admission,
    // job creation and signal wiring all run on this object's owner thread.
    [[nodiscard]] bool startInitialBackupSnapshot(
        quint64 requestId, QString& error);
    [[nodiscard]] bool cancelMutationBackupBeforeLaunch(
        quint64 requestId, const QString& path, quint64 generation);
    void requestForLockedVault(const QString& path);
    void resumeAutomaticBackup(const QString& localId);
    void setPaused(bool paused);
    void retryPending(); // Event-driven only: editor closed, operation ended, resumed.
    void cancel(); // Explicit voluntary cancellation suspends subsequent attempts.
    // Owner-thread progressive close boundary for the injectable generational
    // engine. Unlike shutdown(), this does not cancel workers or discard
    // requests. It is idempotent and never blocks waiting for I/O.
    [[nodiscard]] bool beginGenerationalShutdownDrain(QString& error);
    [[nodiscard]] GenerationalShutdownDrainState
        generationalShutdownDrainState() const noexcept
        { return generationalShutdownDrainState_; }
    void shutdown();
    [[nodiscard]] bool isActive() const noexcept;
    // Owner-thread, read-only presentation. A pending resume is not a result
    // and an active child retains its reservation even after finished(Unknown).
    [[nodiscard]] QString activeVaultId() const { return isActive() ? activeId_ : QString{}; }
    [[nodiscard]] bool resumePending(const QString& id) const { return resumes_.contains(id); }
    [[nodiscard]] bool isPaused() const noexcept { return paused_; }
    [[nodiscard]] bool isClosing() const noexcept { return closing_; }
    [[nodiscard]] bool canClose() const noexcept { return closeReady_; }
    [[nodiscard]] BackupTriggerMode triggerMode() const noexcept { return triggerMode_; }
    [[nodiscard]] bool modificationGroupingPending() const noexcept
        { return mutationGroupingTimer_.isActive(); }
    [[nodiscard]] quint64 mutationGeneration() const noexcept { return mutationGeneration_; }
    [[nodiscard]] bool mutationBackupActive() const noexcept
        { return activeMutationBatch_.has_value(); }
    [[nodiscard]] bool mutationContentionPending() const noexcept
        { return waitingMutationBatch_.has_value(); }
signals:
    void notification(QString localId, QString message);
    void completed(QString localId, passwall::services::BackupResult result);
    void copyConfirmed(QString localId, passwall::services::BackupResult result);
    void rotationCompleted(QString localId, passwall::services::RotationResult result);
    void activityChanged(bool active);
    void closeReady();
    void deferred(QString localId);
    // A request is not a started or successful backup. No production consumer
    // is connected while the generational engine remains inactive.
    void generationalBackupRequested(passwall::services::GenerationalBackupRequestOffer offer);
    // Revocation only invalidates an unstarted token. It is not a backup result.
    void generationalBackupRequestInvalidated(quint64 requestId);
    void mutationBatchSettled(passwall::services::MutationBackupResult result);
    void mutationBatchDiagnostic(QString vaultPath, quint64 generation, QString diagnostic);
    void generationalOperationStateChanged(
        passwall::services::GenerationalOperationState state);
    void initialBackupInspectionSettled(
        passwall::services::InitialBackupInspectionResult result);
    void generationalBackupSuspensionChanged(
        passwall::services::GenerationalBackupSuspensionState state);
    void generationalInitialCopyResumeRequested(QString vaultPath);
    void globalBackupReinspectionRequested(QString vaultPath);
    void generationalShutdownDrainChanged(
        passwall::services::GenerationalShutdownDrainState state);
private:
    friend class ManualBackupOperationAdmission;
    struct MutationBatch {
        QString path;
        quint64 generation = 0;
        quint64 session = 0;
        quint64 requestId = 0;
        quint64 device = 0;
        quint64 inode = 0;
        QString destination;
        GenerationalBackupRequestKind kind = GenerationalBackupRequestKind::CrudGeneration;
        std::shared_ptr<InitialBackupRequest> initialCopy;
        QByteArray vaultId;
        quint64 resumeEpoch = 0;
    };
    struct GenerationalSuspension {
        QString path;
        QByteArray vaultId;
        quint64 device = 0;
        quint64 inode = 0;
        quint64 latestMutationGeneration = 0;
        quint64 latestSessionGeneration = 0;
        quint64 epoch = 0;
        quint64 failureRequestId = 0;
        quint64 resumeRequestId = 0;
        GenerationalBackupRequestKind pendingKind =
            GenerationalBackupRequestKind::CrudGeneration;
        GenerationalBackupSuspensionReason reason =
            GenerationalBackupSuspensionReason::Failed;
        QString diagnostic;
        bool resumeRequested = false;
    };
    struct InitialInspectionControl {
        std::atomic_bool cancellationRequested{false};
        std::atomic_bool snapshotReservationHeld{false};
        InitialBackupCancellation observer;
    };
    struct ManualOperationRecord {
        quint64 id = 0;
        std::shared_ptr<ManualBackupOperationAdmission::State> state;
    };
    struct InitialInspectionFingerprint {
        QString path;
        QByteArray vaultId;
        quint64 device = 0;
        quint64 inode = 0;
        quint64 sessionGeneration = 0;
        GlobalBackupPreferencesStatus configurationStatus =
            GlobalBackupPreferencesStatus::Absent;
        GlobalBackupPreferences preferences;
        QString configurationSourceFile;
        bool forceInitialCopy = false;
        quint64 activityId = 0;
    };
    struct InitialInspectionActivity : InitialInspectionFingerprint {
        GenerationalOperationPhase phase = GenerationalOperationPhase::Inspecting;
        std::shared_ptr<InitialBackupRequest> preparedRequest;
        std::shared_ptr<InitialInspectionControl> control;
    };
    void beginModificationSession(const VaultFileIdentity& identity);
    void observeCommittedMutation(const QString& path, quint64 commitGeneration);
    [[nodiscard]] std::optional<MutationBatch> takeScheduledMutationBatch(
        const QString& expectedPath = {});
    void retainLockCapturedMutationBatch(MutationBatch batch);
    void settleMutationBatchesForShutdown();
    void retainReadyMutationBatch(MutationBatch batch);
    [[nodiscard]] bool hasPendingMutationFor(
        const QString& path, quint64 device, quint64 inode) const;
    [[nodiscard]] bool hasPendingInitialCopyFor(
        const QString& path, quint64 device, quint64 inode) const;
    void replacePendingInitialCopyWithMutation(
        const QString& path, quint64 device, quint64 inode);
    [[nodiscard]] GenerationalSuspension* suspensionFor(
        const QString& path, const QByteArray& vaultId,
        quint64 device, quint64 inode);
    [[nodiscard]] const GenerationalSuspension* suspensionFor(
        const QString& path, const QByteArray& vaultId,
        quint64 device, quint64 inode) const;
    void retainSuspendedNeed(const MutationBatch& batch);
    void suspendGenerationalBackup(const MutationBatch& failed,
        MutationBackupOutcome outcome, const QString& diagnostic);
    void publishSuspension(const GenerationalSuspension& suspension);
    void clearSuspensionAfterPublishedResume(const MutationBatch& completed);
    [[nodiscard]] GenerationalBackupRequestOffer offerFor(
        const MutationBatch& batch) const;
    [[nodiscard]] GenerationalOperationState stateFor(
        GenerationalOperationPhase phase, const MutationBatch& batch,
        bool reservationHeld = false, bool workerAlive = false) const;
    void publishOperationState(GenerationalOperationState state);
    [[nodiscard]] bool manualOperationBlocks(const QString& path) const;
    void releaseManualOperation(quint64 id) noexcept;
    void cancelInitialInspectionActivity();
    void captureScheduledMutationForShutdownDrain();
    void evaluateGenerationalShutdownDrain();
    void publishGenerationalShutdownDrain(
        GenerationalShutdownDrainState state);
    [[nodiscard]] bool hasOutstandingGenerationalRequest() const noexcept;
    [[nodiscard]] quint64 latestOutstandingMutationGeneration() const noexcept;
    [[nodiscard]] bool globalPreferencesAllowDispatch() const noexcept;
    [[nodiscard]] bool globalPreferencesMatch(
        const GlobalBackupPreferencesResult& configuration) const noexcept;
    void invalidatePreparedRequestsForGlobalPreferences();
    void retainCrudAfterConfigurationInvalidation(MutationBatch batch);
    void completeInitialBackupInspection(quint64 activityId,
        const std::shared_ptr<InitialInspectionControl>& control,
        InitialBackupPreparation preparation);
    [[nodiscard]] bool initialInspectionMatches(
        const InitialInspectionFingerprint& fingerprint,
        const GlobalBackupPreferencesResult& configuration,
        const AuthenticatedBackupSession& session) const;
    void finishInitialInspectionActivity(quint64 activityId,
        GenerationalOperationPhase terminalPhase,
        std::optional<InitialInspectionFingerprint> completed = std::nullopt);
    void scheduleReadyMutationBatch();
    void dispatchReadyMutationBatch();
    void retryMutationBatchAfterRelease();
    void expireMutationContention();
    void settleUnstartedMutationBatch(MutationBatch batch,
        BackupOutcome outcome, const QString& diagnostic);
    [[nodiscard]] bool finishMutationBackup(quint64 requestId, BackupResult result,
        std::optional<MutationBackupPublicationReceipt> publication = {});
    void superviseGenerationalJob(BackupJob* job, quint64 requestId);
    void dispatch();
    void schedulePending();
    void fail(const QString& id, const QString& message);
    [[nodiscard]] bool usesHistoricalTrigger() const noexcept
        { return triggerMode_ == BackupTriggerMode::Historical; }
    [[nodiscard]] bool usesGenerationalTrigger() const noexcept
        { return triggerMode_ == BackupTriggerMode::Generational; }
    const BackupTriggerMode triggerMode_;
    VaultPreferencesStore store_;
    QString worker_;
    QString activeId_;
    QMap<QString, QString> known_; // path -> local id, automatic only
    QMap<QString, QString> pending_; // local id -> source
    QSet<QString> resumes_, notified_, deferredIds_;
    QPointer<BackupJob> job_;
    QTimer mutationGroupingTimer_;
    QTimer mutationContentionTimer_;
    QSocketNotifier* reservationReleaseNotifier_ = nullptr;
    QString modificationSessionPath_;
    QByteArray modificationSessionVaultId_;
    quint64 modificationSessionDevice_ = 0;
    quint64 modificationSessionInode_ = 0;
    quint64 modificationSessionGeneration_ = 0;
    quint64 mutationGeneration_ = 0;
    quint64 scheduledMutationGeneration_ = 0;
    quint64 scheduledSessionGeneration_ = 0;
    quint64 minimumCommitGeneration_ = 0;
    quint64 lastAcceptedCommitGeneration_ = 0;
    quint64 nextMutationRequestId_ = 0;
    quint64 nextInitialInspectionId_ = 0;
    quint64 nextManualOperationId_ = 0;
    std::optional<InitialInspectionActivity> initialInspectionActivity_;
    std::optional<InitialInspectionFingerprint> completedInitialInspection_;
    std::optional<GlobalBackupPreferencesResult> globalBackupPreferences_;
    QString pendingInitialReinspectionPath_;
    std::optional<MutationBatch> offeredMutationBatch_;
    std::optional<MutationBatch> waitingMutationBatch_;
    std::optional<MutationBatch> activeMutationBatch_;
    QVector<MutationBatch> lockCapturedMutationBatches_;
    QVector<MutationBatch> readyMutationBatches_;
    QVector<GenerationalSuspension> generationalSuspensions_;
    QVector<ManualOperationRecord> manualOperations_;
    quint64 nextSuspensionEpoch_ = 0;
    quint64 mutationJobRequestId_ = 0;
    std::optional<BackupResult> mutationJobResult_;
    std::optional<MutationBackupPublicationReceipt> mutationJobReceipt_;
    std::optional<GenerationalOperationState> mutationWorkerState_;
    std::optional<GenerationalOperationState> lastGenerationalOperationState_;
    bool mutationJobSettled_ = false;
    std::shared_ptr<bool> normalInterruption_;
    bool paused_ = false, queued_ = false, closing_ = false, closeReady_ = false;
    bool mutationDispatchQueued_ = false;
    bool mutationContentionCycle_ = false;
    bool voluntaryCancellation_ = false;
    bool unconfirmedRotationStop_ = false;
    bool generationalShutdownDrainRequested_ = false;
    QString generationalShutdownDrainFailure_;
    GenerationalShutdownDrainState generationalShutdownDrainState_;
};
}

Q_DECLARE_METATYPE(passwall::services::MutationBackupPublicationReceipt)
Q_DECLARE_METATYPE(passwall::services::MutationBackupResult)
Q_DECLARE_METATYPE(passwall::services::GenerationalBackupRequestOffer)
Q_DECLARE_METATYPE(passwall::services::GenerationalOperationState)
Q_DECLARE_METATYPE(passwall::services::InitialBackupInspectionResult)
Q_DECLARE_METATYPE(passwall::services::GenerationalBackupSuspensionState)
Q_DECLARE_METATYPE(passwall::services::GenerationalShutdownDrainState)
