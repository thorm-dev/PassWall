#pragma once

#include "services/backup_trigger_mode.hpp"
#include "services/backup_destination_preparer.hpp"
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

// Request kind remains explicit for the common publication/rotation contract.
enum class GenerationalBackupRequestKind {
    CrudGeneration
};

// Exact, transient preparation facts retained until the matching worker has
// really terminated. They authorize no deletion by themselves; the rotation
// consumer must reload the preferences and the destructive service must still
// reopen and revalidate the complete series.
struct GenerationalBackupRotationContext {
    QString rootDirectory;
    QByteArray vaultId;
    QString seriesId;
    GlobalBackupPreferences preparedPreferences;
    QString preferencesSourceFile;
    std::optional<GlobalBackupPreferencesFileIdentity> preferencesSourceIdentity;
    SnapshotDirectoryIdentity rootIdentity;
    SnapshotDirectoryIdentity familyIdentity;
    SnapshotDirectoryIdentity seriesIdentity;
    bool operator==(const GenerationalBackupRotationContext&) const = default;
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
    std::optional<GenerationalBackupRotationContext> rotationContext;
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
    // Non-secret physical binding copied from the coordinator's immutable
    // batch.  A GUI consumer needs it to prepare a CRUD destination without
    // reinterpreting a path that may already have been substituted.
    VaultFileIdentity vault;
    quint64 mutationGeneration = 0;
    quint64 sessionGeneration = 0;
    quint64 requestId = 0;
    bool operator==(const GenerationalBackupRequestOffer&) const = default;
};

// Read-only, transient presentation of the generational engine. These phases
// are coordination hints only: VaultOperationGuard remains the final authority
// for every export, replacement and snapshot.
enum class GenerationalOperationPhase {
    Idle,
    PendingRequest,
    OfferedRequest,
    WaitingForReservation,
    AttemptActive,
    WorkerActive,
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
    // Exact worker result copied only after all publication/token bindings have
    // been validated. Rotation consumers pass it through unchanged and never
    // synthesize Published from a path or a visible file.
    std::optional<BackupResult> confirmedPublicationResult;
    bool workerTerminated = false;
};

// Owner-thread Qt coordinator. No key, credential, unbounded retry loop or
// copy engine; only in-memory grouping/coordination timers and generations live here.
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
    // Integration owners call this before exposing a real generational
    // session. Until an authoritative Valid result is applied, CRUD needs are
    // retained but no request is offered and no artificial failure is emitted.
    // Foundation tests that inject prepared capabilities remain independent.
    void requireGlobalBackupPreferencesInitialization();
    // Owner-thread notification/revalidation boundary for global preferences.
    // Invalid configurations pause new offers but retain CRUD generations.
    // A live worker is deliberately not interrupted.
    void applyGlobalBackupPreferences(
        GlobalBackupPreferencesResult configuration);
    [[nodiscard]] GenerationalBackupSuspensionState
        generationalBackupSuspension(const QString& vaultPath) const;
    // Explicit, owner-thread resumption. A retained CRUD need is offered exactly
    // once. No worker is started by this method.
    [[nodiscard]] bool resumeGenerationalBackup(
        const QString& vaultPath, QString& error);
    // Explicit fresh generation from the current authenticated vault. A
    // scheduled CRUD batch is accelerated rather than duplicated. The same
    // preparation, reservation, worker and publication proof are used.
    [[nodiscard]] bool requestGenerationalBackup(
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
    [[nodiscard]] bool cancelMutationBackupBeforeLaunch(
        quint64 requestId, const QString& path, quint64 generation);
    // The asynchronous GUI preparation could not produce a destination for
    // this exact unstarted CRUD offer.  This is terminal for the attempt and
    // deliberately installs the existing suspension; it never retries.
    [[nodiscard]] bool failMutationBackupPreparation(
        quint64 requestId, const QString& path, quint64 generation,
        QString diagnostic);
    void requestForLockedVault(const QString& path);
    void resumeAutomaticBackup(const QString& localId);
    void setPaused(bool paused);
    void retryPending(); // Event-driven only: editor closed, operation ended, resumed.
    void cancel(); // Explicit voluntary cancellation suspends subsequent attempts.
    // Owner-thread progressive close boundary for the injectable generational
    // engine. Unlike shutdown(), this does not cancel workers or discard
    // requests. It is idempotent and never blocks waiting for I/O.
    [[nodiscard]] bool beginGenerationalShutdownDrain(QString& error);
    // A user who declined to leave after a terminal failed drain may reopen
    // coordination for a fresh authenticated session. This never clears the
    // suspension, retries a request or revives the invalidated session.
    [[nodiscard]] bool continueAfterGenerationalShutdownFailure(
        QString& error);
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
    // A request is not a started or successful backup.
    void generationalBackupRequested(passwall::services::GenerationalBackupRequestOffer offer);
    // Revocation only invalidates an unstarted token. It is not a backup result.
    void generationalBackupRequestInvalidated(quint64 requestId);
    void mutationBatchSettled(passwall::services::MutationBackupResult result);
    void mutationBatchDiagnostic(QString vaultPath, quint64 generation, QString diagnostic);
    void generationalOperationStateChanged(
        passwall::services::GenerationalOperationState state);
    void generationalBackupSuspensionChanged(
        passwall::services::GenerationalBackupSuspensionState state);
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
        QByteArray vaultId;
        quint64 resumeEpoch = 0;
        std::optional<GenerationalBackupRotationContext> rotationContext;
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
        GenerationalBackupSuspensionReason reason =
            GenerationalBackupSuspensionReason::Failed;
        QString diagnostic;
        bool resumeRequested = false;
    };
    struct ManualOperationRecord {
        quint64 id = 0;
        std::shared_ptr<ManualBackupOperationAdmission::State> state;
    };
    void beginModificationSession(const VaultFileIdentity& identity);
    void observeCommittedMutation(const QString& path, quint64 commitGeneration);
    [[nodiscard]] std::optional<MutationBatch> takeScheduledMutationBatch(
        const QString& expectedPath = {});
    void retainLockCapturedMutationBatch(MutationBatch batch);
    void settleMutationBatchesForShutdown();
    void retainReadyMutationBatch(MutationBatch batch);
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
    void captureScheduledMutationForShutdownDrain();
    void evaluateGenerationalShutdownDrain();
    void publishGenerationalShutdownDrain(
        GenerationalShutdownDrainState state);
    [[nodiscard]] bool hasOutstandingGenerationalRequest() const noexcept;
    [[nodiscard]] quint64 latestOutstandingMutationGeneration() const noexcept;
    [[nodiscard]] bool globalPreferencesAllowDispatch() const noexcept;
    [[nodiscard]] bool globalPreferencesMatch(
        const GlobalBackupPreferencesResult& configuration) const noexcept;
    void reloadGlobalBackupPreferencesAsync(
        const QString& settingsFile, bool persistenceConfirmed);
    void invalidatePreparedRequestsForGlobalPreferences();
    void retainCrudAfterConfigurationInvalidation(MutationBatch batch);
    void scheduleReadyMutationBatch();
    void dispatchReadyMutationBatch();
    void retryMutationBatchAfterRelease();
    void expireMutationContention();
    void settleUnstartedMutationBatch(MutationBatch batch,
        BackupOutcome outcome, const QString& diagnostic);
    [[nodiscard]] bool finishMutationBackup(quint64 requestId, BackupResult result,
        std::optional<MutationBackupPublicationReceipt> publication = {},
        bool workerTerminated = false);
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
    // Shared volatile ordering of admitted backup needs within this session.
    // A manual request reserves an ordinal but is not a committed mutation.
    quint64 backupGeneration_ = 0;
    quint64 mutationGeneration_ = 0; // Latest actual committed mutation ordinal.
    quint64 scheduledMutationGeneration_ = 0;
    quint64 scheduledSessionGeneration_ = 0;
    quint64 minimumCommitGeneration_ = 0;
    quint64 lastAcceptedCommitGeneration_ = 0;
    quint64 nextMutationRequestId_ = 0;
    quint64 nextManualOperationId_ = 0;
    std::optional<GlobalBackupPreferencesResult> globalBackupPreferences_;
    bool globalPreferencesInitializationRequired_ = false;
    quint64 globalPreferencesReloadSerial_ = 0;
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
Q_DECLARE_METATYPE(passwall::services::GenerationalBackupSuspensionState)
Q_DECLARE_METATYPE(passwall::services::GenerationalShutdownDrainState)
