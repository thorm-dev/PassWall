#include "services/automatic_backup_coordinator.hpp"
#include "services/backup_job.hpp"
#include "services/credential_service.hpp"
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QSocketNotifier>
#include <QThread>
#include <QTimer>
#include <QUuid>
#include <algorithm>
#include <mutex>
#include <type_traits>

namespace passwall::services {
namespace {
constexpr int defaultMutationContentionWaitMs = 3000;

static_assert(std::is_nothrow_move_constructible_v<storage::VaultOperationGuard>);
static_assert(std::is_nothrow_move_constructible_v<PreparedBackupDestination>);
static_assert(std::is_nothrow_move_constructible_v<InitialBackupRequest>);

MutationBackupOutcome mutationOutcome(BackupOutcome outcome)
{
    switch (outcome) {
    case BackupOutcome::Published:
        return MutationBackupOutcome::Published;
    case BackupOutcome::FailedBeforePublication:
    case BackupOutcome::CancelledBeforePublication:
        return MutationBackupOutcome::Failed;
    case BackupOutcome::DurabilityUnconfirmed:
    case BackupOutcome::Unknown:
        return MutationBackupOutcome::Unknown;
    }
    return MutationBackupOutcome::Unknown;
}

bool sameVaultIdentity(const VaultFileIdentity& first, const VaultFileIdentity& second)
{
    return first.path == second.path && first.vaultId == second.vaultId
        && first.device != 0 && first.inode != 0
        && first.device == second.device && first.inode == second.inode;
}

QString normalizedPath(const QString& path)
{
    return path.isEmpty() ? QString{}
        : QDir::cleanPath(QFileInfo(path).absoluteFilePath());
}

bool blocksUserOperation(GenerationalOperationPhase phase)
{
    switch (phase) {
    case GenerationalOperationPhase::Inspecting:
    case GenerationalOperationPhase::PreparedReservation:
    case GenerationalOperationPhase::PendingRequest:
    case GenerationalOperationPhase::OfferedRequest:
    case GenerationalOperationPhase::WaitingForReservation:
    case GenerationalOperationPhase::AttemptActive:
    case GenerationalOperationPhase::WorkerActive:
    case GenerationalOperationPhase::Cancelling:
        return true;
    case GenerationalOperationPhase::Idle:
    case GenerationalOperationPhase::Completed:
    case GenerationalOperationPhase::Cancelled:
        return false;
    }
    return true;
}

GenerationalOperationState initialActivityState(GenerationalOperationPhase phase,
    const QString& path, quint64 sessionGeneration, quint64 activityId,
    bool reservationHeld = false)
{
    GenerationalOperationState state;
    state.phase = phase;
    state.kind = GenerationalBackupRequestKind::InitialCopy;
    state.vaultPath = path;
    state.sessionGeneration = sessionGeneration;
    state.reservationHeld = reservationHeld;
    state.activityId = activityId;
    return state;
}

struct AsyncInitialBackupResult {
    std::mutex mutex;
    std::optional<InitialBackupPreparation> preparation;
};
}

struct ManualBackupOperationAdmission::State {
    QPointer<AutomaticBackupCoordinator> owner;
    BackupUserOperation operation = BackupUserOperation::ManualExport;
    QString path;
    QByteArray vaultId;
    quint64 device = 0;
    quint64 inode = 0;
    quint64 id = 0;
    bool historical = false;
    std::atomic_bool active{true};
    std::atomic_bool consumed{false};
};

ManualBackupOperationAdmission::ManualBackupOperationAdmission(
    std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}

ManualBackupOperationAdmission::~ManualBackupOperationAdmission() noexcept
{
    reset();
}

ManualBackupOperationAdmission::ManualBackupOperationAdmission(
    ManualBackupOperationAdmission&& other) noexcept
    : state_(std::move(other.state_)) {}

ManualBackupOperationAdmission& ManualBackupOperationAdmission::operator=(
    ManualBackupOperationAdmission&& other) noexcept
{
    if (this != &other) {
        reset();
        state_ = std::move(other.state_);
    }
    return *this;
}

bool ManualBackupOperationAdmission::valid() const noexcept
{
    return state_ && state_->active.load(std::memory_order_acquire)
        && !state_->consumed.load(std::memory_order_acquire);
}

bool ManualBackupOperationAdmission::generational() const noexcept
{
    return state_ && !state_->historical;
}

bool ManualBackupOperationAdmission::consumeForExclusive(
    BackupUserOperation operation, const QString& vaultPath, QString& error)
{
    error.clear();
    const QString source = normalizedPath(vaultPath);
    if (!state_ || source.isEmpty() || state_->operation != operation
        || state_->path != source
        || !state_->active.load(std::memory_order_acquire)) {
        error = QStringLiteral(
            "Admission manuelle absente, révoquée ou liée à une autre opération.");
        return false;
    }
    bool expected = false;
    if (!state_->consumed.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        error = QStringLiteral("Admission manuelle déjà consommée.");
        return false;
    }
    return true;
}

bool ManualBackupOperationAdmission::acquireExclusive(
    BackupUserOperation operation, const QString& vaultPath,
    storage::VaultOperationGuard& reservation, QString& error)
{
    if (!consumeForExclusive(operation, vaultPath, error)) return false;
    const QString source = normalizedPath(vaultPath);
    std::string reservationError;
    if (!reservation.tryReserve(source.toStdString(), reservationError)
        || !reservation.matchesReservation(source.toStdString(), reservationError)) {
        reservation.reset();
        error = reservationError.empty()
            ? QStringLiteral("Réservation exclusive de l'opération manuelle refusée.")
            : QString::fromStdString(reservationError);
        return false;
    }
    // Generational admissions are tied to the authenticated physical session.
    // The kernel reservation is already held while this metadata is reread, so
    // a cooperative snapshot/replacement cannot interleave here.
    if (!state_->historical && state_->device != 0 && state_->inode != 0) {
        VaultFileIdentity observed;
        QString identityError;
	if (VaultPreferencesStore().recoveryAccess(source, identityError) != VaultRecoveryAccess::Allowed
	    || !VaultPreferencesStore::inspectReserved(source, reservation, observed, identityError)
	    || observed.path != source || observed.vaultId != state_->vaultId
	    || observed.device != state_->device || observed.inode != state_->inode)
	  {
            reservation.reset();
            error = identityError.isEmpty()
	      ? QStringLiteral("Identité physique du coffre devenue incohérente.")
	      : identityError;
            return false;
	  }
    }
    return true;
}

bool ManualBackupOperationAdmission::startExport(BackupJob& job,
    const QString& source, const QString& destination, QString& error)
{
    storage::VaultOperationGuard reservation;
    if (!acquireExclusive(BackupUserOperation::ManualExport,
            source, reservation, error)) {
        reset();
        return false;
    }
    const bool started = job.startReserved(
        source, destination, std::move(reservation), {});
    if (!started)
        error = job.startError();
    // startReserved either owns the physical guard or has synchronously
    // refused and released it. The logical admission can now end in both cases.
    reset();
    return started;
}

void ManualBackupOperationAdmission::reset() noexcept
{
    auto state = std::move(state_);
    if (!state || !state->active.exchange(false, std::memory_order_acq_rel)
        || state->historical || state->id == 0)
        return;
    const QPointer<AutomaticBackupCoordinator> owner = state->owner;
    const quint64 id = state->id;
    if (!owner) return;
    if (QThread::currentThread() == owner->thread()) {
        owner->releaseManualOperation(id);
        return;
    }
    QMetaObject::invokeMethod(owner, [owner, id] {
        if (owner) owner->releaseManualOperation(id);
    }, Qt::QueuedConnection);
}

AutomaticBackupCoordinator::AutomaticBackupCoordinator(QObject* parent)
    : AutomaticBackupCoordinator(VaultPreferencesStore(), BackupJob::siblingWorkerPath(), parent) {}
AutomaticBackupCoordinator::AutomaticBackupCoordinator(VaultPreferencesStore store, QString worker, QObject* parent)
    : AutomaticBackupCoordinator(std::move(store), std::move(worker), 20000, parent) {}
AutomaticBackupCoordinator::AutomaticBackupCoordinator(
    VaultPreferencesStore store, QString worker, int mutationGroupingDelayMs, QObject* parent)
    : AutomaticBackupCoordinator(std::move(store), std::move(worker),
        mutationGroupingDelayMs, defaultMutationContentionWaitMs, parent) {}
AutomaticBackupCoordinator::AutomaticBackupCoordinator(
    VaultPreferencesStore store, QString worker, int mutationGroupingDelayMs,
    int mutationContentionWaitMs, QObject* parent)
    : AutomaticBackupCoordinator(std::move(store), std::move(worker),
        mutationGroupingDelayMs, mutationContentionWaitMs,
        BackupTriggerMode::Historical, parent) {}
AutomaticBackupCoordinator::AutomaticBackupCoordinator(
    VaultPreferencesStore store, QString worker, int mutationGroupingDelayMs,
    int mutationContentionWaitMs, BackupTriggerMode triggerMode, QObject* parent)
    : QObject(parent), triggerMode_(triggerMode), store_(std::move(store)),
      worker_(std::move(worker))
{
    setObjectName(QStringLiteral("automaticBackupCoordinator"));
    mutationGroupingTimer_.setObjectName(QStringLiteral("automaticBackupMutationGroupingTimer"));
    mutationGroupingTimer_.setSingleShot(true);
    mutationGroupingTimer_.setTimerType(Qt::PreciseTimer);
    mutationGroupingTimer_.setInterval(std::max(1, mutationGroupingDelayMs));
    mutationContentionTimer_.setObjectName(QStringLiteral("automaticBackupMutationContentionTimer"));
    mutationContentionTimer_.setSingleShot(true);
    mutationContentionTimer_.setTimerType(Qt::PreciseTimer);
    mutationContentionTimer_.setInterval(std::max(1, mutationContentionWaitMs));
    connect(&mutationGroupingTimer_, &QTimer::timeout, this, [this] {
        // A stale timeout already queued before a restart sees the new timer
        // active and cannot consume the new session's generation.
        if (!usesGenerationalTrigger()
            || mutationGroupingTimer_.isActive()
            || modificationSessionPath_.isEmpty()
            || scheduledMutationGeneration_ == 0
            || scheduledSessionGeneration_ != modificationSessionGeneration_)
            return;
        const QString path = modificationSessionPath_;
        const quint64 generation = scheduledMutationGeneration_;
        const quint64 session = scheduledSessionGeneration_;
        scheduledMutationGeneration_ = 0;
        MutationBatch batch{path, generation, session, 0,
            modificationSessionDevice_, modificationSessionInode_};
        batch.vaultId = modificationSessionVaultId_;
        retainReadyMutationBatch(std::move(batch));
    });
    connect(&mutationContentionTimer_, &QTimer::timeout,
        this, &AutomaticBackupCoordinator::expireMutationContention);
    const int releaseDescriptor = usesGenerationalTrigger()
        ? storage::VaultOperationGuard::releaseNotificationDescriptor() : -1;
    if (releaseDescriptor >= 0) {
        reservationReleaseNotifier_ = new QSocketNotifier(
            releaseDescriptor, QSocketNotifier::Read, this);
        connect(reservationReleaseNotifier_, &QSocketNotifier::activated, this, [this] {
            storage::VaultOperationGuard::consumeReleaseNotifications();
            retryMutationBatchAfterRelease();
        });
    }
    if (usesGenerationalTrigger()) {
        connect(&CredentialService::events(), &CredentialEvents::committed, this,
            [this](const QString& path, CredentialMutation, quint64 generation) {
                if (usesGenerationalTrigger()) observeCommittedMutation(path, generation);
            });
        connect(&GlobalBackupPreferencesStore::events(),
            &GlobalBackupPreferencesEvents::changed, this,
            [this](const QString& settingsFile, bool persistenceConfirmed) {
                if (!usesGenerationalTrigger()) return;
                const QString observed = normalizedPath(settingsFile);
                const QString expected = globalBackupPreferences_
                        && !globalBackupPreferences_->sourceFile.isEmpty()
                    ? normalizedPath(globalBackupPreferences_->sourceFile)
                    : normalizedPath(GlobalBackupPreferencesStore().fileName());
                if (observed.isEmpty() || observed != expected) return;
                auto configuration =
                    GlobalBackupPreferencesStore(settingsFile).load();
                if (!persistenceConfirmed) {
                    configuration.status =
                        GlobalBackupPreferencesStatus::WriteError;
                    configuration.diagnostic = QStringLiteral(
                        "Modification visible, mais persistance des préférences non confirmée.");
                }
                applyGlobalBackupPreferences(std::move(configuration));
            }, Qt::QueuedConnection);
    } else {
        connect(&VaultPreferencesStore::events(), &VaultPreferencesEvents::changed, this,
            [this](const QString& settings, const QString& id, const QString& path, bool enabled) {
                if (!usesHistoricalTrigger() || settings != store_.fileName()) return;
                if (!enabled) { known_.remove(path); pending_.remove(id); resumes_.remove(id); return; }
                known_.insert(path, id);
                pending_.insert(id, path);
                retryPending();
            }, Qt::QueuedConnection);
    }
}
AutomaticBackupCoordinator::~AutomaticBackupCoordinator() { shutdown(); }
void AutomaticBackupCoordinator::trackVault(const VaultRegistration& record)
{
    if (usesGenerationalTrigger()) {
        // A newly authenticated owner session revokes every unconsumed manual
        // admission from the previous session. Ordinary locking does not call
        // trackVault(), so an export/restoration that deliberately locked the
        // vault retains its short transition capability.
        for (const auto& admission : manualOperations_)
            if (admission.state)
                admission.state->active.store(false, std::memory_order_release);
        manualOperations_.clear();
        beginModificationSession(record.file);
        return;
    }
    if (!usesHistoricalTrigger()) return;
    if (record.backup.automatic) known_.insert(record.file.path, record.localId);
    else known_.remove(record.file.path);
}
void AutomaticBackupCoordinator::beginModificationSession(const VaultFileIdentity& identity)
{
    if (!usesGenerationalTrigger()) return;
    stopModificationGrouping();
    if (identity.path.isEmpty() || identity.device == 0 || identity.inode == 0) return;
    modificationSessionPath_ = QDir::cleanPath(QFileInfo(identity.path).absoluteFilePath());
    modificationSessionVaultId_ = identity.vaultId;
    modificationSessionDevice_ = identity.device;
    modificationSessionInode_ = identity.inode;
    minimumCommitGeneration_ = CredentialService::currentCommitGeneration();
    lastAcceptedCommitGeneration_ = minimumCommitGeneration_;
}
void AutomaticBackupCoordinator::stopModificationGrouping()
{
    cancelInitialInspectionActivity();
    completedInitialInspection_.reset();
    pendingInitialReinspectionPath_.clear();
    mutationGroupingTimer_.stop();
    modificationSessionPath_.clear();
    modificationSessionVaultId_.clear();
    modificationSessionDevice_ = 0;
    modificationSessionInode_ = 0;
    mutationGeneration_ = 0;
    scheduledMutationGeneration_ = 0;
    scheduledSessionGeneration_ = 0;
    minimumCommitGeneration_ = CredentialService::currentCommitGeneration();
    lastAcceptedCommitGeneration_ = minimumCommitGeneration_;
    if (++modificationSessionGeneration_ == 0) ++modificationSessionGeneration_;
}

AutomaticBackupCoordinator::GenerationalSuspension*
AutomaticBackupCoordinator::suspensionFor(
    const QString& path, const QByteArray& vaultId,
    quint64 device, quint64 inode)
{
    const auto found = std::find_if(generationalSuspensions_.begin(),
        generationalSuspensions_.end(), [&](const GenerationalSuspension& suspension) {
            return suspension.path == path && suspension.vaultId == vaultId
                && suspension.device == device
                && suspension.inode == inode;
        });
    return found == generationalSuspensions_.end() ? nullptr : &*found;
}

const AutomaticBackupCoordinator::GenerationalSuspension*
AutomaticBackupCoordinator::suspensionFor(
    const QString& path, const QByteArray& vaultId,
    quint64 device, quint64 inode) const
{
    const auto found = std::find_if(generationalSuspensions_.cbegin(),
        generationalSuspensions_.cend(), [&](const GenerationalSuspension& suspension) {
            return suspension.path == path && suspension.vaultId == vaultId
                && suspension.device == device
                && suspension.inode == inode;
        });
    return found == generationalSuspensions_.cend() ? nullptr : &*found;
}

void AutomaticBackupCoordinator::publishSuspension(
    const GenerationalSuspension& suspension)
{
    GenerationalBackupSuspensionState state;
    state.suspended = true;
    state.reason = suspension.reason;
    state.vaultPath = suspension.path;
    state.vaultId = suspension.vaultId;
    state.device = suspension.device;
    state.inode = suspension.inode;
    state.latestMutationGeneration = suspension.latestMutationGeneration;
    state.latestSessionGeneration = suspension.latestSessionGeneration;
    state.resumeRequested = suspension.resumeRequested;
    state.workerAlive = job_ && job_->isActive()
        && ((activeMutationBatch_
                && activeMutationBatch_->path == suspension.path
                && activeMutationBatch_->device == suspension.device
                && activeMutationBatch_->inode == suspension.inode)
            || (mutationWorkerState_
                && mutationWorkerState_->vaultPath == suspension.path));
    state.diagnostic = suspension.diagnostic;
    emit generationalBackupSuspensionChanged(std::move(state));
}

GenerationalBackupSuspensionState
AutomaticBackupCoordinator::generationalBackupSuspension(
    const QString& vaultPath) const
{
    GenerationalBackupSuspensionState state;
    if (!usesGenerationalTrigger()) return state;
    const QString source = normalizedPath(vaultPath);
    const GenerationalSuspension* found = nullptr;
    for (const auto& suspension : generationalSuspensions_)
        if (suspension.path == source
            && (!found || suspension.epoch > found->epoch))
            found = &suspension;
    if (!found) return state;
    state.suspended = true;
    state.reason = found->reason;
    state.vaultPath = found->path;
    state.vaultId = found->vaultId;
    state.device = found->device;
    state.inode = found->inode;
    state.latestMutationGeneration = found->latestMutationGeneration;
    state.latestSessionGeneration = found->latestSessionGeneration;
    state.resumeRequested = found->resumeRequested;
    state.workerAlive = job_ && job_->isActive()
        && ((activeMutationBatch_ && activeMutationBatch_->path == found->path
                && activeMutationBatch_->device == found->device
                && activeMutationBatch_->inode == found->inode)
            || (mutationWorkerState_
                && mutationWorkerState_->vaultPath == found->path));
    state.diagnostic = found->diagnostic;
    return state;
}

void AutomaticBackupCoordinator::retainSuspendedNeed(const MutationBatch& batch)
{
    auto* suspension = suspensionFor(
        batch.path, batch.vaultId, batch.device, batch.inode);
    if (!suspension || batch.resumeEpoch != 0) return;
    if (batch.kind == GenerationalBackupRequestKind::CrudGeneration) {
        const bool newerSession = batch.session > suspension->latestSessionGeneration;
        const bool newerGeneration = batch.session == suspension->latestSessionGeneration
            && batch.generation > suspension->latestMutationGeneration;
        if (newerSession || newerGeneration) {
            suspension->latestSessionGeneration = batch.session;
            suspension->latestMutationGeneration = batch.generation;
        }
        suspension->pendingKind = GenerationalBackupRequestKind::CrudGeneration;
    } else if (suspension->latestMutationGeneration == 0) {
        suspension->pendingKind = GenerationalBackupRequestKind::InitialCopy;
        if (batch.initialCopy)
            suspension->latestSessionGeneration =
                batch.initialCopy->sessionGeneration();
    }
    publishSuspension(*suspension);
}

void AutomaticBackupCoordinator::suspendGenerationalBackup(
    const MutationBatch& failed, MutationBackupOutcome outcome,
    const QString& diagnostic)
{
    if (!usesGenerationalTrigger() || outcome == MutationBackupOutcome::Published)
        return;
    auto* suspension = suspensionFor(
        failed.path, failed.vaultId, failed.device, failed.inode);
    if (!suspension) {
        GenerationalSuspension created;
        created.path = failed.path;
        created.vaultId = failed.vaultId;
        created.device = failed.device;
        created.inode = failed.inode;
        generationalSuspensions_.push_back(std::move(created));
        suspension = &generationalSuspensions_.last();
    }
    const bool sameFailure = failed.requestId != 0
        && suspension->failureRequestId == failed.requestId;
    if (!sameFailure) {
        if (++nextSuspensionEpoch_ == 0) ++nextSuspensionEpoch_;
        suspension->epoch = nextSuspensionEpoch_;
        suspension->failureRequestId = failed.requestId;
        suspension->resumeRequestId = 0;
        suspension->resumeRequested = false;
    }
    suspension->vaultId = failed.vaultId;
    suspension->reason = outcome == MutationBackupOutcome::Unknown
        ? GenerationalBackupSuspensionReason::Unknown
        : GenerationalBackupSuspensionReason::Failed;
    suspension->diagnostic = diagnostic;
    if (failed.kind == GenerationalBackupRequestKind::CrudGeneration) {
        suspension->pendingKind = GenerationalBackupRequestKind::CrudGeneration;
        const bool newerSession = failed.session
            > suspension->latestSessionGeneration;
        const bool newerGeneration = failed.session
                == suspension->latestSessionGeneration
            && failed.generation > suspension->latestMutationGeneration;
        if (newerSession || newerGeneration
            || suspension->latestMutationGeneration == 0) {
            suspension->latestSessionGeneration = failed.session;
            suspension->latestMutationGeneration = failed.generation;
        }
    } else if (suspension->latestMutationGeneration == 0) {
        suspension->pendingKind = GenerationalBackupRequestKind::InitialCopy;
        suspension->latestSessionGeneration = failed.initialCopy
            ? failed.initialCopy->sessionGeneration() : failed.session;
    }

    if (scheduledMutationGeneration_ != 0
        && modificationSessionPath_ == suspension->path
        && modificationSessionVaultId_ == suspension->vaultId
        && modificationSessionDevice_ == suspension->device
        && modificationSessionInode_ == suspension->inode) {
        MutationBatch scheduled{suspension->path, scheduledMutationGeneration_,
            scheduledSessionGeneration_, 0, suspension->device, suspension->inode};
        scheduled.vaultId = modificationSessionVaultId_;
        retainSuspendedNeed(scheduled);
        scheduledMutationGeneration_ = 0;
        scheduledSessionGeneration_ = 0;
        mutationGroupingTimer_.stop();
    }
    const auto absorb = [&](QVector<MutationBatch>& batches) {
        batches.erase(std::remove_if(batches.begin(), batches.end(),
            [&](const MutationBatch& batch) {
                if (batch.path != suspension->path
                    || batch.vaultId != suspension->vaultId
                    || batch.device != suspension->device
                    || batch.inode != suspension->inode
                    || batch.resumeEpoch != 0)
                    return false;
                retainSuspendedNeed(batch);
                return true;
            }), batches.end());
    };
    absorb(lockCapturedMutationBatches_);
    absorb(readyMutationBatches_);
    const auto absorbSingle = [&](std::optional<MutationBatch>& batch) {
        if (!batch || batch->path != suspension->path
            || batch->vaultId != suspension->vaultId
            || batch->device != suspension->device
            || batch->inode != suspension->inode
            || batch->resumeEpoch != 0)
            return;
        const quint64 invalidated = batch->requestId;
        retainSuspendedNeed(*batch);
        batch.reset();
        if (invalidated != 0)
            emit generationalBackupRequestInvalidated(invalidated);
    };
    absorbSingle(offeredMutationBatch_);
    absorbSingle(waitingMutationBatch_);
    if (initialInspectionActivity_
        && initialInspectionActivity_->path == suspension->path
        && initialInspectionActivity_->vaultId == suspension->vaultId
        && initialInspectionActivity_->device == suspension->device
        && initialInspectionActivity_->inode == suspension->inode)
        cancelInitialInspectionActivity();
    publishSuspension(*suspension);
}

void AutomaticBackupCoordinator::clearSuspensionAfterPublishedResume(
    const MutationBatch& completed)
{
    if (completed.resumeEpoch == 0) return;
    auto* suspension = suspensionFor(
        completed.path, completed.vaultId, completed.device, completed.inode);
    if (!suspension || suspension->epoch != completed.resumeEpoch
        || suspension->resumeRequestId != completed.requestId)
        return;
    const bool newerCrud = suspension->pendingKind
            == GenerationalBackupRequestKind::CrudGeneration
        && (completed.kind == GenerationalBackupRequestKind::InitialCopy
            || suspension->latestSessionGeneration > completed.session
            || (suspension->latestSessionGeneration == completed.session
                && suspension->latestMutationGeneration > completed.generation));
    const GenerationalSuspension retained = *suspension;
    generationalSuspensions_.erase(std::remove_if(
        generationalSuspensions_.begin(), generationalSuspensions_.end(),
        [&](const GenerationalSuspension& candidate) {
            return candidate.path == completed.path
                && candidate.vaultId == completed.vaultId
                && candidate.device == completed.device
                && candidate.inode == completed.inode
                && candidate.epoch == completed.resumeEpoch;
        }), generationalSuspensions_.end());
    GenerationalBackupSuspensionState cleared;
    cleared.vaultPath = completed.path;
    cleared.vaultId = completed.vaultId;
    cleared.device = completed.device;
    cleared.inode = completed.inode;
    emit generationalBackupSuspensionChanged(std::move(cleared));
    if (!newerCrud) return;
    MutationBatch followUp{retained.path, retained.latestMutationGeneration,
        retained.latestSessionGeneration, 0, retained.device, retained.inode};
    followUp.vaultId = retained.vaultId;
    if (modificationSessionPath_ == retained.path
        && modificationSessionDevice_ == retained.device
        && modificationSessionInode_ == retained.inode
        && modificationSessionGeneration_ == retained.latestSessionGeneration) {
        scheduledMutationGeneration_ = retained.latestMutationGeneration;
        scheduledSessionGeneration_ = retained.latestSessionGeneration;
        mutationGroupingTimer_.start();
        publishOperationState(stateFor(
            GenerationalOperationPhase::PendingRequest, followUp));
    } else {
        retainReadyMutationBatch(std::move(followUp));
    }
}

bool AutomaticBackupCoordinator::resumeGenerationalBackup(
    const QString& vaultPath, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral("Reprise générationnelle hors du thread propriétaire.");
        return false;
    }
    if (!usesGenerationalTrigger() || closing_
        || generationalShutdownDrainRequested_) {
        error = QStringLiteral("Reprise générationnelle indisponible dans l'état courant.");
        return false;
    }
    const QString source = normalizedPath(vaultPath);
    VaultFileIdentity current;
    if (source.isEmpty() || !VaultPreferencesStore::inspectVault(source, current, error))
        return false;
    auto* suspension = suspensionFor(
        source, current.vaultId, current.device, current.inode);
    if (!suspension || suspension->vaultId != current.vaultId) {
        error = QStringLiteral(
            "Aucune suspension ne correspond à l'identité physique actuelle du coffre.");
        return false;
    }
    if (suspension->resumeRequested) {
        error = QStringLiteral("Une reprise explicite est déjà en attente.");
        return false;
    }
    if ((job_ && job_->isActive()) || activeMutationBatch_ || mutationWorkerState_) {
        error = QStringLiteral(
            "Un ancien worker peut encore agir ; attendre sa terminaison effective.");
        return false;
    }
    suspension->resumeRequested = true;
    suspension->resumeRequestId = 0;
    publishSuspension(*suspension);
    if (suspension->pendingKind == GenerationalBackupRequestKind::InitialCopy
        && suspension->latestMutationGeneration == 0) {
        emit generationalInitialCopyResumeRequested(source);
        return true;
    }
    MutationBatch resumed{source, suspension->latestMutationGeneration,
        suspension->latestSessionGeneration, 0, current.device, current.inode};
    resumed.vaultId = current.vaultId;
    resumed.resumeEpoch = suspension->epoch;
    retainReadyMutationBatch(std::move(resumed));
    return true;
}
void AutomaticBackupCoordinator::requestPendingMutationsForLock(const QString& path)
{
    if (!usesGenerationalTrigger()) return;
    if (generationalShutdownDrainRequested_) {
        // beginGenerationalShutdownDrain() already captured the scheduled
        // generation before GUI cleanup.  Keep the authenticated physical
        // identity until the drain is terminal so that a COMMIT completing
        // concurrently with the lock remains a distinct immediate request.
        mutationGroupingTimer_.stop();
        cancelInitialInspectionActivity();
        evaluateGenerationalShutdownDrain();
        return;
    }
    auto captured = takeScheduledMutationBatch(path);
    if (!captured) return;
    const QString source = captured->path;
    const quint64 session = captured->session;
    retainLockCapturedMutationBatch(std::move(*captured));

    // A request is deliberately delivered only after lockVault() has returned:
    // no present or future consumer may delay secret cleanup or lock approval.
    QTimer::singleShot(0, this, [this, source, session] {
        if (!usesGenerationalTrigger() || closing_) return;
        const auto found = std::find_if(lockCapturedMutationBatches_.begin(),
            lockCapturedMutationBatches_.end(), [&](const MutationBatch& batch) {
                return batch.path == source && batch.session == session;
            });
        if (found == lockCapturedMutationBatches_.end()) return;
        MutationBatch batch = std::move(*found);
        lockCapturedMutationBatches_.erase(found);
        retainReadyMutationBatch(std::move(batch));
    });
}

void AutomaticBackupCoordinator::publishGenerationalShutdownDrain(
    GenerationalShutdownDrainState state)
{
    if (generationalShutdownDrainState_ == state) return;
    generationalShutdownDrainState_ = state;
    emit generationalShutdownDrainChanged(std::move(state));
}

quint64 AutomaticBackupCoordinator::latestOutstandingMutationGeneration() const noexcept
{
    quint64 latest = scheduledMutationGeneration_;
    const auto observe = [&latest](const MutationBatch& batch) {
        if (batch.kind == GenerationalBackupRequestKind::CrudGeneration)
            latest = std::max(latest, batch.generation);
    };
    for (const auto& batch : lockCapturedMutationBatches_) observe(batch);
    for (const auto& batch : readyMutationBatches_) observe(batch);
    if (offeredMutationBatch_) observe(*offeredMutationBatch_);
    if (waitingMutationBatch_) observe(*waitingMutationBatch_);
    if (activeMutationBatch_) observe(*activeMutationBatch_);
    for (const auto& suspension : generationalSuspensions_)
        latest = std::max(latest, suspension.latestMutationGeneration);
    return latest;
}

bool AutomaticBackupCoordinator::hasOutstandingGenerationalRequest() const noexcept
{
    return scheduledMutationGeneration_ != 0
        || !lockCapturedMutationBatches_.isEmpty()
        || !readyMutationBatches_.isEmpty()
        || offeredMutationBatch_.has_value()
        || waitingMutationBatch_.has_value()
        || activeMutationBatch_.has_value()
        || initialInspectionActivity_.has_value()
        || !pendingInitialReinspectionPath_.isEmpty();
}

void AutomaticBackupCoordinator::captureScheduledMutationForShutdownDrain()
{
    if (!usesGenerationalTrigger() || scheduledMutationGeneration_ == 0)
        return;
    mutationGroupingTimer_.stop();
    const bool valid = !modificationSessionPath_.isEmpty()
        && scheduledSessionGeneration_ == modificationSessionGeneration_
        && modificationSessionDevice_ != 0 && modificationSessionInode_ != 0
        && modificationSessionVaultId_.size() == 16;
    if (!valid) {
        scheduledMutationGeneration_ = 0;
        scheduledSessionGeneration_ = 0;
        generationalShutdownDrainFailure_ = QStringLiteral(
            "Génération planifiée incohérente ; vidange refusée par prudence.");
        return;
    }
    MutationBatch batch{modificationSessionPath_, scheduledMutationGeneration_,
        scheduledSessionGeneration_, 0, modificationSessionDevice_,
        modificationSessionInode_};
    batch.vaultId = modificationSessionVaultId_;
    scheduledMutationGeneration_ = 0;
    scheduledSessionGeneration_ = 0;
    retainReadyMutationBatch(std::move(batch));
}

void AutomaticBackupCoordinator::evaluateGenerationalShutdownDrain()
{
    if (!generationalShutdownDrainRequested_) return;
    GenerationalShutdownDrainState state;
    state.workerAlive = job_ && job_->isActive();
    state.requestPending = hasOutstandingGenerationalRequest();
    state.latestMutationGeneration = latestOutstandingMutationGeneration();

    if (state.workerAlive) {
        state.status = GenerationalShutdownDrainStatus::WorkerActive;
        state.diagnostic = QStringLiteral(
            "Vidange en attente de la terminaison effective du worker.");
    } else if (!generationalShutdownDrainFailure_.isEmpty()) {
        state.status =
            GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension;
        state.diagnostic = generationalShutdownDrainFailure_;
    } else if (!generationalSuspensions_.isEmpty()) {
        state.status =
            GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension;
        state.diagnostic = QStringLiteral(
            "Vidange incomplète : une sauvegarde est suspendue après un échec ou un résultat incertain.");
    } else if (!pendingInitialReinspectionPath_.isEmpty()) {
        state.status =
            GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension;
        state.diagnostic = QStringLiteral(
            "Vidange incomplète : une nouvelle inspection initiale serait nécessaire.");
    } else if (state.requestPending && !globalPreferencesAllowDispatch()) {
        state.status =
            GenerationalShutdownDrainStatus::CompletedWithFailureOrSuspension;
        state.diagnostic = QStringLiteral(
            "Vidange incomplète : la configuration globale de sauvegarde n'est plus admissible.");
    } else if (state.requestPending) {
        state.status = GenerationalShutdownDrainStatus::Draining;
        state.diagnostic = initialInspectionActivity_
            ? QStringLiteral("Annulation de l'inspection initiale en cours.")
            : QStringLiteral("Vidange des demandes de sauvegarde en cours.");
    } else {
        state.status = GenerationalShutdownDrainStatus::Completed;
    }
    publishGenerationalShutdownDrain(std::move(state));
}

bool AutomaticBackupCoordinator::beginGenerationalShutdownDrain(QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral(
            "Demande de vidange hors du thread propriétaire.");
        return false;
    }
    if (!usesGenerationalTrigger() || closing_) {
        error = QStringLiteral(
            "Vidange générationnelle indisponible dans l'état courant.");
        return false;
    }
    if (!generationalShutdownDrainRequested_) {
        generationalShutdownDrainRequested_ = true;
        cancelInitialInspectionActivity();
        captureScheduledMutationForShutdownDrain();
        scheduleReadyMutationBatch();
    }
    evaluateGenerationalShutdownDrain();
    return true;
}

quint64 AutomaticBackupCoordinator::beginInitialBackupInspection(
    const VaultFileIdentity& identity, quint64 sessionGeneration, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral("Inspection initiale hors du thread propriétaire.");
        return 0;
    }
    if (!usesGenerationalTrigger() || closing_
        || generationalShutdownDrainRequested_ || sessionGeneration == 0) {
        error = QStringLiteral("Inspection initiale indisponible dans l'état courant.");
        return 0;
    }
    const QString source = normalizedPath(identity.path);
    if (manualOperationBlocks(source)) {
        error = QStringLiteral(
            "Une opération manuelle déjà admise est en cours de réservation exclusive.");
        return 0;
    }
    if (source.isEmpty() || source != modificationSessionPath_
        || identity.device == 0 || identity.inode == 0
        || identity.device != modificationSessionDevice_
        || identity.inode != modificationSessionInode_
        || identity.vaultId != modificationSessionVaultId_) {
        error = QStringLiteral("L'inspection ne correspond pas à la session physique courante.");
        return 0;
    }
    if (const auto* suspension = suspensionFor(
            source, identity.vaultId, identity.device, identity.inode);
        suspension && !suspension->resumeRequested) {
        error = QStringLiteral(
            "Les sauvegardes automatiques sont suspendues jusqu'à une reprise explicite.");
        return 0;
    }
    if (initialInspectionActivity_) {
        error = QStringLiteral("Une inspection de première sauvegarde est déjà active.");
        return 0;
    }
    if (++nextInitialInspectionId_ == 0) ++nextInitialInspectionId_;
    InitialInspectionActivity activity;
    activity.path = source;
    activity.vaultId = identity.vaultId;
    activity.device = identity.device;
    activity.inode = identity.inode;
    activity.sessionGeneration = sessionGeneration;
    activity.activityId = nextInitialInspectionId_;
    initialInspectionActivity_ = std::move(activity);
    publishOperationState(initialActivityState(GenerationalOperationPhase::Inspecting,
        source, sessionGeneration, nextInitialInspectionId_));
    return nextInitialInspectionId_;
}

bool AutomaticBackupCoordinator::markInitialBackupPrepared(quint64 activityId,
    InitialBackupRequest request, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral("Préparation initiale reçue hors du thread propriétaire.");
        return false;
    }
    if (!usesGenerationalTrigger() || closing_
        || generationalShutdownDrainRequested_ || activityId == 0
        || !initialInspectionActivity_
        || initialInspectionActivity_->activityId != activityId
        || initialInspectionActivity_->phase != GenerationalOperationPhase::Inspecting) {
        error = QStringLiteral("Inspection initiale absente, annulée ou obsolète.");
        return false;
    }
    const auto& activity = *initialInspectionActivity_;
    const auto& prepared = request.destination();
    if (request.consumed() || request.sessionGeneration() != activity.sessionGeneration
        || prepared.bindingGeneration() != activity.sessionGeneration
        || prepared.vaultPath() != activity.path
        || prepared.vaultId() != activity.vaultId) {
        error = QStringLiteral("La destination préparée ne correspond pas à l'inspection active.");
        cancelInitialInspectionActivity();
        return false;
    }
    std::shared_ptr<InitialBackupRequest> retained;
    try {
        retained = std::make_shared<InitialBackupRequest>(std::move(request));
    } catch (...) {
        error = QStringLiteral("Impossible de conserver la destination préparée.");
        cancelInitialInspectionActivity();
        return false;
    }
    initialInspectionActivity_->phase = GenerationalOperationPhase::PreparedReservation;
    initialInspectionActivity_->preparedRequest = std::move(retained);
    publishOperationState(initialActivityState(
        GenerationalOperationPhase::PreparedReservation, activity.path,
        activity.sessionGeneration, activity.activityId, true));
    return true;
}

InitialBackupArbitration AutomaticBackupCoordinator::admitPreparedInitialBackup(
    quint64 activityId, InitialBackupAdmission admission, QString& error)
{
    if (QThread::currentThread() != thread() || activityId == 0
        || !initialInspectionActivity_
        || initialInspectionActivity_->activityId != activityId
        || initialInspectionActivity_->phase
            != GenerationalOperationPhase::PreparedReservation
        || !initialInspectionActivity_->preparedRequest) {
        error = QStringLiteral("Préparation initiale absente, annulée ou obsolète.");
        return InitialBackupArbitration::Refused;
    }
    InitialBackupRequest request(
        std::move(*initialInspectionActivity_->preparedRequest));
    admission.inspectionActivityId = activityId;
    return admitInitialBackup(std::move(request), admission, error);
}

bool AutomaticBackupCoordinator::cancelInitialBackupInspection(quint64 activityId)
{
    if (QThread::currentThread() != thread() || activityId == 0
        || !initialInspectionActivity_
        || initialInspectionActivity_->activityId != activityId)
        return false;
    cancelInitialInspectionActivity();
    return true;
}

bool AutomaticBackupCoordinator::initialInspectionMatches(
    const InitialInspectionFingerprint& fingerprint,
    const GlobalBackupPreferencesResult& configuration,
    const AuthenticatedBackupSession& session) const
{
    return fingerprint.path == normalizedPath(session.vault.path)
        && fingerprint.vaultId == session.vault.vaultId
        && fingerprint.device == session.vault.device
        && fingerprint.inode == session.vault.inode
        && fingerprint.sessionGeneration == session.sessionGeneration
        && fingerprint.forceInitialCopy == session.forceInitialCopy
        && fingerprint.configurationStatus == configuration.status
        && fingerprint.preferences == configuration.preferences
        && fingerprint.configurationSourceFile == configuration.sourceFile;
}

bool AutomaticBackupCoordinator::globalPreferencesMatch(
    const GlobalBackupPreferencesResult& configuration) const noexcept
{
    return globalBackupPreferences_
        && globalBackupPreferences_->status == configuration.status
        && globalBackupPreferences_->preferences == configuration.preferences
        && globalBackupPreferences_->sourceFile == configuration.sourceFile;
}

bool AutomaticBackupCoordinator::globalPreferencesAllowDispatch() const noexcept
{
    // Foundation tests may inject prepared requests without a persistent
    // configuration owner. Once a real configuration has been observed,
    // fail closed until it is valid again.
    return !globalBackupPreferences_ || globalBackupPreferences_->valid();
}

void AutomaticBackupCoordinator::retainCrudAfterConfigurationInvalidation(
    MutationBatch batch)
{
    if (batch.kind != GenerationalBackupRequestKind::CrudGeneration) return;
    batch.requestId = 0;
    batch.destination.clear();
    const auto existing = std::find_if(readyMutationBatches_.begin(),
        readyMutationBatches_.end(), [&](const MutationBatch& candidate) {
            return candidate.kind == GenerationalBackupRequestKind::CrudGeneration
                && candidate.path == batch.path
                && candidate.device == batch.device
                && candidate.inode == batch.inode
                && candidate.session == batch.session;
        });
    if (existing == readyMutationBatches_.end())
        readyMutationBatches_.push_back(std::move(batch));
    else if (batch.generation > existing->generation)
        existing->generation = batch.generation;
}

void AutomaticBackupCoordinator::invalidatePreparedRequestsForGlobalPreferences()
{
    completedInitialInspection_.reset();
    if (initialInspectionActivity_)
        pendingInitialReinspectionPath_ = initialInspectionActivity_->path;
    cancelInitialInspectionActivity();

    const auto removeInitialCopies = [&](QVector<MutationBatch>& batches) {
        QVector<GenerationalOperationState> cancelled;
        batches.erase(std::remove_if(batches.begin(), batches.end(),
            [&](const MutationBatch& batch) {
                if (batch.kind != GenerationalBackupRequestKind::InitialCopy)
                    return false;
                if (pendingInitialReinspectionPath_.isEmpty())
                    pendingInitialReinspectionPath_ = batch.path;
                auto state = stateFor(
                    GenerationalOperationPhase::Cancelled, batch);
                state.reservationHeld = false;
                cancelled.push_back(std::move(state));
                return true;
            }), batches.end());
        for (auto& state : cancelled)
            publishOperationState(std::move(state));
    };
    removeInitialCopies(lockCapturedMutationBatches_);
    removeInitialCopies(readyMutationBatches_);

    const auto invalidateSingle = [&](std::optional<MutationBatch>& batch) {
        if (!batch) return;
        const quint64 invalidated = batch->requestId;
        if (batch->kind == GenerationalBackupRequestKind::InitialCopy) {
            if (pendingInitialReinspectionPath_.isEmpty())
                pendingInitialReinspectionPath_ = batch->path;
            auto state = stateFor(
                GenerationalOperationPhase::Cancelled, *batch);
            state.reservationHeld = false;
            batch.reset();
            publishOperationState(std::move(state));
        } else {
            MutationBatch retained = std::move(*batch);
            batch.reset();
            retainCrudAfterConfigurationInvalidation(std::move(retained));
        }
        if (invalidated != 0)
            emit generationalBackupRequestInvalidated(invalidated);
    };
    invalidateSingle(offeredMutationBatch_);
    invalidateSingle(waitingMutationBatch_);
    mutationContentionTimer_.stop();
    mutationContentionCycle_ = false;

    if (!pendingInitialReinspectionPath_.isEmpty()
        && globalPreferencesAllowDispatch())
        emit globalBackupReinspectionRequested(
            pendingInitialReinspectionPath_);
    scheduleReadyMutationBatch();
}

void AutomaticBackupCoordinator::applyGlobalBackupPreferences(
    GlobalBackupPreferencesResult configuration)
{
    if (QThread::currentThread() != thread() || !usesGenerationalTrigger())
        return;
    if (globalPreferencesMatch(configuration)) return;
    globalBackupPreferences_ = std::move(configuration);
    invalidatePreparedRequestsForGlobalPreferences();
    evaluateGenerationalShutdownDrain();
}

InitialBackupInspectionLaunchResult
AutomaticBackupCoordinator::startInitialBackupInspectionAsync(
    GlobalBackupPreferencesResult configuration,
    AuthenticatedBackupSession session, QDateTime timestamp,
    InitialBackupCancellation observer)
{
    InitialBackupInspectionLaunchResult launch;
    if (QThread::currentThread() != thread()) {
        launch.diagnostic = QStringLiteral(
            "Démarrage de l'inspection hors du thread propriétaire.");
        return launch;
    }
    if (!usesGenerationalTrigger() || closing_
        || generationalShutdownDrainRequested_) {
        launch.diagnostic = QStringLiteral(
            "Inspection asynchrone indisponible dans le mode courant.");
        return launch;
    }
    if (!session.authenticated || session.sessionGeneration == 0
        || session.vault.path.isEmpty() || session.vault.vaultId.size() != 16
        || session.vault.device == 0 || session.vault.inode == 0
        || !timestamp.isValid()) {
        launch.diagnostic = QStringLiteral(
            "Session authentifiée, identité ou horodatage d'inspection invalide.");
        return launch;
    }
    applyGlobalBackupPreferences(configuration);
    if (!globalPreferencesAllowDispatch()) {
        launch.diagnostic = configuration.diagnostic.isEmpty()
            ? QStringLiteral("Configuration globale indisponible ou désactivée.")
            : configuration.diagnostic;
        return launch;
    }
    const QString sessionPath = normalizedPath(session.vault.path);
    if (pendingInitialReinspectionPath_ == sessionPath)
        pendingInitialReinspectionPath_.clear();
    const auto* suspended = suspensionFor(sessionPath, session.vault.vaultId,
        session.vault.device, session.vault.inode);
    session.forceInitialCopy = suspended && suspended->resumeRequested
        && suspended->vaultId == session.vault.vaultId
        && suspended->pendingKind == GenerationalBackupRequestKind::InitialCopy
        && suspended->latestMutationGeneration == 0;
    if (initialInspectionActivity_) {
        launch.activityId = initialInspectionActivity_->activityId;
        if (initialInspectionMatches(*initialInspectionActivity_,
                configuration, session)) {
            launch.outcome = InitialBackupInspectionLaunch::AlreadyRunning;
            return launch;
        }
        cancelInitialInspectionActivity();
        launch.diagnostic = QStringLiteral(
            "Inspection antérieure invalidée ; attendre sa terminaison avant une nouvelle inspection.");
        return launch;
    }
    if (completedInitialInspection_
        && initialInspectionMatches(*completedInitialInspection_,
            configuration, session)) {
        launch.outcome = InitialBackupInspectionLaunch::AlreadySettled;
        launch.activityId = completedInitialInspection_->activityId;
        return launch;
    }

    QString error;
    const quint64 activityId = beginInitialBackupInspection(
        session.vault, session.sessionGeneration, error);
    if (activityId == 0) {
        launch.diagnostic = std::move(error);
        return launch;
    }
    auto control = std::make_shared<InitialInspectionControl>();
    control->observer = observer;
    initialInspectionActivity_->configurationStatus = configuration.status;
    initialInspectionActivity_->preferences = configuration.preferences;
    initialInspectionActivity_->configurationSourceFile = configuration.sourceFile;
    initialInspectionActivity_->forceInitialCopy = session.forceInitialCopy;
    initialInspectionActivity_->control = control;

    auto result = std::make_shared<AsyncInitialBackupResult>();
    auto* delivery = new QObject;
    QThread* task = nullptr;
    try {
        task = QThread::create(
            [configuration = std::move(configuration), session = std::move(session),
             timestamp, control, result]() mutable {
                InitialBackupCancellation cancellation;
                cancellation.context = control.get();
                cancellation.requested = [](void* raw, quint64 generation,
                                             InitialBackupCheckpoint checkpoint) noexcept {
                    auto& state = *static_cast<InitialInspectionControl*>(raw);
                    if (checkpoint
                        == InitialBackupCheckpoint::AfterSnapshotReservation)
                        state.snapshotReservationHeld.store(
                            true, std::memory_order_release);
                    if (state.cancellationRequested.load(std::memory_order_acquire))
                        return true;
                    bool observedCancellation = false;
                    try {
                        observedCancellation = state.observer.requested != nullptr
                            && state.observer.requested(
                                state.observer.context, generation, checkpoint);
                    } catch (...) {
                        observedCancellation = true;
                    }
                    return observedCancellation
                        || state.cancellationRequested.load(std::memory_order_acquire);
                };
                InitialBackupPreparation preparation;
                try {
                    preparation = InitialBackupPreparer::prepare(
                        configuration, session, timestamp, cancellation);
                } catch (...) {
                    preparation.decision = InitialBackupDecision::Refused;
                    preparation.diagnostic = QStringLiteral(
                        "Inspection asynchrone interrompue.");
                }
                const std::lock_guard lock(result->mutex);
                result->preparation.emplace(std::move(preparation));
            });
    } catch (...) {
        delete delivery;
        finishInitialInspectionActivity(activityId,
            GenerationalOperationPhase::Cancelled);
        launch.diagnostic = QStringLiteral(
            "Création du thread d'inspection impossible.");
        return launch;
    }

    const QPointer<AutomaticBackupCoordinator> guarded(this);
    QObject::connect(task, &QThread::finished, delivery,
        [task, delivery, guarded, activityId, control, result] {
            std::optional<InitialBackupPreparation> preparation;
            {
                const std::lock_guard lock(result->mutex);
                if (result->preparation)
                    preparation.emplace(std::move(*result->preparation));
                result->preparation.reset();
            }
            if (guarded && preparation)
                guarded->completeInitialBackupInspection(
                    activityId, control, std::move(*preparation));
            task->deleteLater();
            delivery->deleteLater();
        }, Qt::QueuedConnection);
    task->start();
    launch.outcome = InitialBackupInspectionLaunch::Started;
    launch.activityId = activityId;
    return launch;
}

void AutomaticBackupCoordinator::invalidateInitialBackupInspection()
{
    if (QThread::currentThread() != thread()) return;
    completedInitialInspection_.reset();
    cancelInitialInspectionActivity();
}

bool AutomaticBackupCoordinator::initialBackupInspectionActive() const noexcept
{
    return initialInspectionActivity_.has_value();
}

void AutomaticBackupCoordinator::finishInitialInspectionActivity(
    quint64 activityId, GenerationalOperationPhase terminalPhase,
    std::optional<InitialInspectionFingerprint> completed)
{
    if (!initialInspectionActivity_
        || initialInspectionActivity_->activityId != activityId)
        return;
    const QString path = initialInspectionActivity_->path;
    const quint64 sessionGeneration =
        initialInspectionActivity_->sessionGeneration;
    initialInspectionActivity_.reset();
    if (completed) completedInitialInspection_ = std::move(*completed);
    publishOperationState(initialActivityState(terminalPhase, path,
        sessionGeneration, activityId));
    evaluateGenerationalShutdownDrain();
}

void AutomaticBackupCoordinator::completeInitialBackupInspection(
    quint64 activityId,
    const std::shared_ptr<InitialInspectionControl>& control,
    InitialBackupPreparation preparation)
{
    if (QThread::currentThread() != thread()) return;
    if (!initialInspectionActivity_
        || initialInspectionActivity_->activityId != activityId
        || initialInspectionActivity_->control != control) {
        preparation.request.reset();
        return;
    }

    InitialInspectionFingerprint fingerprint = *initialInspectionActivity_;
    const bool sessionCurrent = !closing_
        && !generationalShutdownDrainRequested_
        && initialInspectionActivity_->phase
            != GenerationalOperationPhase::Cancelling
        && !control->cancellationRequested.load(std::memory_order_acquire)
        && modificationSessionPath_ == fingerprint.path
        && modificationSessionVaultId_ == fingerprint.vaultId
        && modificationSessionDevice_ == fingerprint.device
        && modificationSessionInode_ == fingerprint.inode;
    initialInspectionActivity_->control.reset(); // The worker has terminated.

    InitialBackupInspectionResult settled;
    settled.activityId = activityId;
    settled.decision = preparation.decision;
    settled.diagnostic = preparation.diagnostic;
    if (!sessionCurrent || preparation.decision == InitialBackupDecision::Cancelled) {
        preparation.request.reset(); // Release before publishing Cancelled.
        settled.decision = InitialBackupDecision::Cancelled;
        if (settled.diagnostic.isEmpty() && !sessionCurrent)
            settled.diagnostic = QStringLiteral(
                "Inspection invalidée par le cycle de session ou la configuration.");
        finishInitialInspectionActivity(activityId,
            GenerationalOperationPhase::Cancelled, fingerprint);
        emit initialBackupInspectionSettled(std::move(settled));
        return;
    }

    if (preparation.decision != InitialBackupDecision::Prepared
        || !preparation.request) {
        preparation.request.reset();
        finishInitialInspectionActivity(activityId,
            GenerationalOperationPhase::Completed, fingerprint);
        emit initialBackupInspectionSettled(std::move(settled));
        return;
    }

    QString admissionError;
    if (!markInitialBackupPrepared(activityId,
            std::move(*preparation.request), admissionError)) {
        preparation.request.reset();
        completedInitialInspection_ = fingerprint;
        settled.decision = InitialBackupDecision::Refused;
        settled.diagnostic = std::move(admissionError);
        emit initialBackupInspectionSettled(std::move(settled));
        return;
    }
    preparation.request.reset();

    InitialBackupAdmission admission;
    admission.currentVault.path = modificationSessionPath_;
    admission.currentVault.vaultId = modificationSessionVaultId_;
    admission.currentVault.device = modificationSessionDevice_;
    admission.currentVault.inode = modificationSessionInode_;
    admission.currentSessionGeneration = fingerprint.sessionGeneration;
    admission.triggerMode = triggerMode_;
    admission.sessionCurrent = true;
    admission.closing = closing_ || generationalShutdownDrainRequested_;
    admission.operationAdmissible = !closing_
        && !generationalShutdownDrainRequested_;
    admission.inspectionActivityId = activityId;
    settled.arbitration = admitPreparedInitialBackup(
        activityId, admission, admissionError);
    completedInitialInspection_ = fingerprint;
    if (settled.arbitration == InitialBackupArbitration::Refused) {
        settled.decision = InitialBackupDecision::Refused;
        settled.diagnostic = std::move(admissionError);
    }
    emit initialBackupInspectionSettled(std::move(settled));
}

GenerationalOperationState AutomaticBackupCoordinator::stateFor(
    GenerationalOperationPhase phase, const MutationBatch& batch,
    bool reservationHeld, bool workerAlive) const
{
    GenerationalOperationState state;
    state.phase = phase;
    state.kind = batch.kind;
    state.vaultPath = batch.path;
    state.mutationGeneration = batch.generation;
    state.sessionGeneration = batch.kind == GenerationalBackupRequestKind::InitialCopy
        && batch.initialCopy ? batch.initialCopy->sessionGeneration() : batch.session;
    state.requestId = batch.requestId;
    state.reservationHeld = reservationHeld
        || (batch.kind == GenerationalBackupRequestKind::InitialCopy
            && batch.initialCopy && !batch.initialCopy->consumed());
    state.workerAlive = workerAlive;
    return state;
}

void AutomaticBackupCoordinator::publishOperationState(GenerationalOperationState state)
{
    lastGenerationalOperationState_ = state;
    emit generationalOperationStateChanged(std::move(state));
}

void AutomaticBackupCoordinator::cancelInitialInspectionActivity()
{
    if (!initialInspectionActivity_) return;
    if (initialInspectionActivity_->control) {
        initialInspectionActivity_->control->cancellationRequested.store(
            true, std::memory_order_release);
        if (initialInspectionActivity_->phase
            != GenerationalOperationPhase::Cancelling) {
            initialInspectionActivity_->phase =
                GenerationalOperationPhase::Cancelling;
            publishOperationState(initialActivityState(
                GenerationalOperationPhase::Cancelling,
                initialInspectionActivity_->path,
                initialInspectionActivity_->sessionGeneration,
                initialInspectionActivity_->activityId,
                initialInspectionActivity_->control->snapshotReservationHeld.load(
                    std::memory_order_acquire)));
        }
        return;
    }
    finishInitialInspectionActivity(initialInspectionActivity_->activityId,
        GenerationalOperationPhase::Cancelled);
}

GenerationalOperationState AutomaticBackupCoordinator::generationalOperationState(
    const QString& vaultPath) const
{
    const QString source = normalizedPath(vaultPath);
    if (!usesGenerationalTrigger() || source.isEmpty()) return {};
    const auto matches = [&](const MutationBatch& batch) { return batch.path == source; };
    if (mutationWorkerState_ && mutationWorkerState_->vaultPath == source)
        return *mutationWorkerState_;
    if (activeMutationBatch_ && matches(*activeMutationBatch_))
        return stateFor(GenerationalOperationPhase::AttemptActive,
            *activeMutationBatch_, false, false);
    if (initialInspectionActivity_ && initialInspectionActivity_->path == source) {
        const auto& activity = *initialInspectionActivity_;
        return initialActivityState(activity.phase, activity.path,
            activity.sessionGeneration, activity.activityId,
            activity.phase == GenerationalOperationPhase::PreparedReservation
                || (activity.control
                    && activity.control->snapshotReservationHeld.load(
                        std::memory_order_acquire)));
    }
    if (waitingMutationBatch_ && matches(*waitingMutationBatch_))
        return stateFor(GenerationalOperationPhase::WaitingForReservation,
            *waitingMutationBatch_);
    if (offeredMutationBatch_ && matches(*offeredMutationBatch_))
        return stateFor(GenerationalOperationPhase::OfferedRequest,
            *offeredMutationBatch_);
    const auto ready = std::find_if(readyMutationBatches_.cbegin(),
        readyMutationBatches_.cend(), matches);
    if (ready != readyMutationBatches_.cend())
        return stateFor(GenerationalOperationPhase::PendingRequest, *ready);
    const auto captured = std::find_if(lockCapturedMutationBatches_.cbegin(),
        lockCapturedMutationBatches_.cend(), matches);
    if (captured != lockCapturedMutationBatches_.cend())
        return stateFor(GenerationalOperationPhase::PendingRequest, *captured);
    if (scheduledMutationGeneration_ != 0 && modificationSessionPath_ == source) {
        MutationBatch scheduled{source, scheduledMutationGeneration_,
            scheduledSessionGeneration_, 0, modificationSessionDevice_,
            modificationSessionInode_};
        scheduled.vaultId = modificationSessionVaultId_;
        return stateFor(GenerationalOperationPhase::PendingRequest, scheduled);
    }
    if (lastGenerationalOperationState_
        && lastGenerationalOperationState_->vaultPath == source)
        return *lastGenerationalOperationState_;
    return {};
}

BackupUserOperationAdmission AutomaticBackupCoordinator::admitUserOperation(
    BackupUserOperation operation, const QString& vaultPath) const
{
    BackupUserOperationAdmission admission;
    const QString source = normalizedPath(vaultPath);
    if (usesGenerationalTrigger() && generationalShutdownDrainRequested_) {
        admission.compatible = false;
        admission.diagnostic = QStringLiteral(
            "Opération manuelle différée : la vidange de fermeture est en cours.");
        return admission;
    }
    if (usesGenerationalTrigger() && manualOperationBlocks(source)) {
        admission.compatible = false;
        admission.diagnostic = operation == BackupUserOperation::ManualExport
            ? QStringLiteral("Export différé : une autre opération manuelle possède déjà l'admission de ce coffre.")
            : QStringLiteral("Restauration différée : une autre opération manuelle possède déjà l'admission de ce coffre.");
        return admission;
    }
    admission.blockingState = generationalOperationState(vaultPath);
    if (!blocksUserOperation(admission.blockingState.phase)) return admission;
    admission.compatible = false;
    admission.diagnostic = operation == BackupUserOperation::ManualExport
        ? QStringLiteral("Export différé : une sauvegarde automatique concernant ce coffre est en préparation ou encore supervisée.")
        : QStringLiteral("Restauration différée : une sauvegarde automatique concernant ce coffre est en préparation ou encore supervisée.");
    return admission;
}

ManualBackupOperationAdmission AutomaticBackupCoordinator::acquireUserOperation(
    BackupUserOperation operation, const QString& vaultPath, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral(
            "Admission d'opération manuelle hors du thread propriétaire.");
        return {};
    }
    const QString source = normalizedPath(vaultPath);
    if (source.isEmpty() || closing_ || generationalShutdownDrainRequested_) {
        error = QStringLiteral(
            "Chemin de coffre invalide ou coordinateur en cours de fermeture.");
        return {};
    }
    const auto diagnostic = admitUserOperation(operation, source);
    if (!diagnostic.compatible) {
        error = diagnostic.diagnostic;
        return {};
    }
    try {
        auto state = std::make_shared<ManualBackupOperationAdmission::State>();
        state->operation = operation;
        state->path = source;
        if (usesHistoricalTrigger()) {
            state->historical = true;
            return ManualBackupOperationAdmission(std::move(state));
        }
        if (!usesGenerationalTrigger()) {
            error = QStringLiteral("Mode de sauvegarde inconnu.");
            return {};
        }
        if (++nextManualOperationId_ == 0) ++nextManualOperationId_;
        state->owner = this;
        state->id = nextManualOperationId_;
        if (source == modificationSessionPath_) {
            state->vaultId = modificationSessionVaultId_;
            state->device = modificationSessionDevice_;
            state->inode = modificationSessionInode_;
        }
        manualOperations_.push_back({state->id, state});
        return ManualBackupOperationAdmission(std::move(state));
    } catch (...) {
        error = QStringLiteral(
            "Impossible de conserver l'admission de l'opération manuelle.");
        return {};
    }
}

bool AutomaticBackupCoordinator::manualOperationBlocks(const QString& path) const
{
    if (!usesGenerationalTrigger() || path.isEmpty()) return false;
    return std::any_of(manualOperations_.cbegin(), manualOperations_.cend(),
        [&](const ManualOperationRecord& record) {
            return record.state
                && record.state->active.load(std::memory_order_acquire)
                && record.state->path == path;
        });
}

void AutomaticBackupCoordinator::releaseManualOperation(quint64 id) noexcept
{
    if (QThread::currentThread() != thread()) {
        const QPointer<AutomaticBackupCoordinator> guarded(this);
        QMetaObject::invokeMethod(this, [guarded, id] {
            if (guarded) guarded->releaseManualOperation(id);
        }, Qt::QueuedConnection);
        return;
    }
    manualOperations_.erase(std::remove_if(manualOperations_.begin(),
        manualOperations_.end(), [id](const ManualOperationRecord& record) {
            return record.id == id;
        }), manualOperations_.end());
    scheduleReadyMutationBatch();
    evaluateGenerationalShutdownDrain();
}

InitialBackupArbitration AutomaticBackupCoordinator::admitInitialBackup(
    InitialBackupRequest request, const InitialBackupAdmission& admission,
    QString& error)
{
    error.clear();
    const quint64 trackedActivity = admission.inspectionActivityId;
    const auto finishTrackedActivity = [this, trackedActivity](bool cancelled) {
        if (trackedActivity == 0 || !initialInspectionActivity_
            || initialInspectionActivity_->activityId != trackedActivity)
            return;
        const QString path = initialInspectionActivity_->path;
        const quint64 sessionGeneration = initialInspectionActivity_->sessionGeneration;
        initialInspectionActivity_.reset();
        if (cancelled)
            publishOperationState(initialActivityState(
                GenerationalOperationPhase::Cancelled, path,
                sessionGeneration, trackedActivity));
    };
    const auto refuse = [&error, &finishTrackedActivity,
                         &request](QString diagnostic) {
        // Release the local single-use snapshot capability before exposing a
        // terminal state. A caller observing Cancelled must never race a guard
        // which is merely waiting for this stack frame to unwind.
        request = InitialBackupRequest(0, PreparedBackupDestination{});
        finishTrackedActivity(true);
        error = std::move(diagnostic);
        return InitialBackupArbitration::Refused;
    };
    try {
        if (QThread::currentThread() != thread())
            return refuse(QStringLiteral(
                "Arbitrage de la première sauvegarde hors du thread propriétaire."));
        if (!usesGenerationalTrigger()
            || admission.triggerMode != BackupTriggerMode::Generational)
            return refuse(QStringLiteral(
                "Le moteur générationnel n'est pas sélectionné pour cette demande."));
        if (closing_ || generationalShutdownDrainRequested_
            || admission.closing || !admission.sessionCurrent)
            return refuse(QStringLiteral(
                "Session fermée, invalidée ou en cours de fermeture."));
        if (!admission.operationAdmissible)
            return refuse(QStringLiteral(
                "Une opération incompatible empêche la première sauvegarde."));
        if (request.consumed() || request.sessionGeneration() == 0
            || admission.currentSessionGeneration != request.sessionGeneration())
            return refuse(QStringLiteral(
                "Génération de session obsolète ou demande déjà consommée."));
        if (trackedActivity != 0
            && (!initialInspectionActivity_
                || initialInspectionActivity_->activityId != trackedActivity
                || initialInspectionActivity_->phase
                    != GenerationalOperationPhase::PreparedReservation
                || initialInspectionActivity_->sessionGeneration
                    != request.sessionGeneration()))
            return refuse(QStringLiteral(
                "L'activité préparatoire est absente, annulée ou obsolète."));
        if (trackedActivity == 0 && initialInspectionActivity_)
            return refuse(QStringLiteral(
                "Une activité préparatoire suivie exige son identifiant d'admission."));

        const QString source = admission.currentVault.path.isEmpty()
            ? QString{}
            : QDir::cleanPath(QFileInfo(admission.currentVault.path).absoluteFilePath());
        if (manualOperationBlocks(source))
            return refuse(QStringLiteral(
                "Une opération manuelle déjà admise a priorité sur cette première sauvegarde."));
        const auto& prepared = request.destination();
        if (source.isEmpty() || source != modificationSessionPath_
            || source != prepared.vaultPath()
            || modificationSessionDevice_ != admission.currentVault.device
            || modificationSessionInode_ != admission.currentVault.inode
            || prepared.vaultId() != admission.currentVault.vaultId
            || prepared.bindingGeneration() != request.sessionGeneration())
            return refuse(QStringLiteral(
                "La demande ne correspond plus à la session de coffre courante."));

        VaultFileIdentity current = admission.currentVault;
        current.path = source;
        VaultFileIdentity observed;
        QString inspectionError;
        if (!VaultPreferencesStore::inspectVault(source, observed, inspectionError)
            || !sameVaultIdentity(current, observed))
            return refuse(inspectionError.isEmpty()
                ? QStringLiteral("L'identité physique du coffre est devenue incohérente.")
                : inspectionError);
        if (!BackupDestinationPreparer::revalidate(
                prepared, current, request.sessionGeneration(), error)) {
            if (error.isEmpty())
                error = QStringLiteral("Revalidation de la première sauvegarde refusée.");
            return refuse(error);
        }

        auto* suspension = suspensionFor(
            source, current.vaultId, current.device, current.inode);
        if (suspension
            && (!suspension->resumeRequested
                || suspension->vaultId != current.vaultId))
            return refuse(QStringLiteral(
                "La sauvegarde automatique reste suspendue ou son identité a changé."));
        if (suspension && suspension->pendingKind
                == GenerationalBackupRequestKind::CrudGeneration
            && suspension->latestMutationGeneration != 0) {
            const quint64 sessionGeneration = request.sessionGeneration();
            request = InitialBackupRequest(0, PreparedBackupDestination{});
            finishTrackedActivity(false);
            MutationBatch resumed{source, suspension->latestMutationGeneration,
                suspension->latestSessionGeneration, 0,
                current.device, current.inode};
            resumed.vaultId = current.vaultId;
            resumed.resumeEpoch = suspension->epoch;
            retainReadyMutationBatch(std::move(resumed));
            publishOperationState(initialActivityState(
                GenerationalOperationPhase::Completed, source,
                sessionGeneration, trackedActivity));
            return InitialBackupArbitration::MergedWithExistingRequest;
        }

        if (hasPendingMutationFor(source, current.device, current.inode)
            || hasPendingInitialCopyFor(source, current.device, current.inode)) {
            // The existing request covers the need. Release the local
            // capability before exposing the terminal merge state; no raw
            // guard is copied or exposed.
            const quint64 requestSessionGeneration = request.sessionGeneration();
            request = InitialBackupRequest(0, PreparedBackupDestination{});
            finishTrackedActivity(false);
            publishOperationState(initialActivityState(
                GenerationalOperationPhase::Completed, source,
                requestSessionGeneration, trackedActivity));
            return InitialBackupArbitration::MergedWithExistingRequest;
        }

        auto retained = std::make_shared<InitialBackupRequest>(std::move(request));
        MutationBatch batch;
        batch.path = source;
        batch.session = modificationSessionGeneration_;
        batch.device = current.device;
        batch.inode = current.inode;
        batch.kind = GenerationalBackupRequestKind::InitialCopy;
        batch.initialCopy = std::move(retained);
        batch.vaultId = current.vaultId;
        if (suspension) batch.resumeEpoch = suspension->epoch;
        finishTrackedActivity(false);
        retainReadyMutationBatch(std::move(batch));
        return InitialBackupArbitration::Offered;
    } catch (...) {
        return refuse(QStringLiteral(
            "Arbitrage de la première sauvegarde interrompu."));
    }
}
std::optional<AutomaticBackupCoordinator::MutationBatch>
AutomaticBackupCoordinator::takeScheduledMutationBatch(const QString& expectedPath)
{
    if (!usesGenerationalTrigger()) return {};
    const QString source = expectedPath.isEmpty()
        ? modificationSessionPath_
        : QDir::cleanPath(QFileInfo(expectedPath).absoluteFilePath());
    const bool pending = !closing_
        && !source.isEmpty()
        && source == modificationSessionPath_
        && scheduledMutationGeneration_ != 0
        && scheduledSessionGeneration_ == modificationSessionGeneration_
        && modificationSessionDevice_ != 0
        && modificationSessionInode_ != 0;
    std::optional<MutationBatch> batch;
    if (pending) {
        batch = MutationBatch{source, scheduledMutationGeneration_,
            scheduledSessionGeneration_, 0,
            modificationSessionDevice_, modificationSessionInode_};
        batch->vaultId = modificationSessionVaultId_;
    }
    // End the unlocked session synchronously. This both cancels its deadline
    // and makes a repeated/reentrant lock unable to capture the same generation.
    stopModificationGrouping();
    return batch;
}
void AutomaticBackupCoordinator::retainLockCapturedMutationBatch(MutationBatch batch)
{
    if (!usesGenerationalTrigger()) return;
    if (suspensionFor(batch.path, batch.vaultId, batch.device, batch.inode)
        && batch.resumeEpoch == 0) {
        retainSuspendedNeed(batch);
        return;
    }
    const auto existing = std::find_if(lockCapturedMutationBatches_.begin(),
        lockCapturedMutationBatches_.end(), [&](const MutationBatch& value) {
            return value.path == batch.path && value.session == batch.session;
        });
    if (existing == lockCapturedMutationBatches_.end()) {
        lockCapturedMutationBatches_.push_back(std::move(batch));
        publishOperationState(stateFor(GenerationalOperationPhase::PendingRequest,
            lockCapturedMutationBatches_.constLast()));
    } else {
        if (batch.generation > existing->generation)
            existing->generation = batch.generation;
        publishOperationState(stateFor(
            GenerationalOperationPhase::PendingRequest, *existing));
    }
}
void AutomaticBackupCoordinator::retainReadyMutationBatch(MutationBatch batch)
{
    const QString retainedPath = batch.path;
    const quint64 retainedDevice = batch.device;
    const quint64 retainedInode = batch.inode;
    const bool validCrud = batch.kind == GenerationalBackupRequestKind::CrudGeneration
        && batch.generation != 0 && !batch.initialCopy;
    const bool validInitial = batch.kind == GenerationalBackupRequestKind::InitialCopy
        && batch.generation == 0 && batch.initialCopy;
    if (!usesGenerationalTrigger() || closing_ || batch.path.isEmpty()
        || (!validCrud && !validInitial) || batch.session == 0
        || batch.device == 0 || batch.inode == 0 || batch.vaultId.size() != 16)
        return;
    if (suspensionFor(batch.path, batch.vaultId, batch.device, batch.inode)
        && batch.resumeEpoch == 0) {
        retainSuspendedNeed(batch);
        return;
    }
    const auto existing = std::find_if(readyMutationBatches_.begin(), readyMutationBatches_.end(),
        [&](const MutationBatch& value) {
            const bool samePhysicalVault = value.path == batch.path
                && value.device == batch.device && value.inode == batch.inode;
            if (!samePhysicalVault) return false;
            return value.kind == GenerationalBackupRequestKind::InitialCopy
                || batch.kind == GenerationalBackupRequestKind::InitialCopy
                || value.session == batch.session;
        });
    if (existing == readyMutationBatches_.end())
        readyMutationBatches_.push_back(std::move(batch));
    else if (existing->kind == GenerationalBackupRequestKind::InitialCopy
        && batch.kind == GenerationalBackupRequestKind::CrudGeneration)
        *existing = std::move(batch);
    else if (existing->kind == GenerationalBackupRequestKind::CrudGeneration
        && batch.kind == GenerationalBackupRequestKind::CrudGeneration
        && batch.generation > existing->generation)
        existing->generation = batch.generation;
    const auto pending = std::find_if(readyMutationBatches_.cbegin(),
        readyMutationBatches_.cend(), [&](const MutationBatch& value) {
            return value.path == retainedPath && value.device == retainedDevice
                && value.inode == retainedInode;
        });
    if (pending != readyMutationBatches_.cend())
        publishOperationState(stateFor(
            GenerationalOperationPhase::PendingRequest, *pending));
    scheduleReadyMutationBatch();
    evaluateGenerationalShutdownDrain();
}

bool AutomaticBackupCoordinator::hasPendingMutationFor(
    const QString& path, quint64 device, quint64 inode) const
{
    if (scheduledMutationGeneration_ != 0
        && scheduledSessionGeneration_ == modificationSessionGeneration_
        && modificationSessionPath_ == path
        && modificationSessionDevice_ == device
        && modificationSessionInode_ == inode)
        return true;
    const auto matches = [&](const MutationBatch& batch) {
        return batch.kind == GenerationalBackupRequestKind::CrudGeneration
            && batch.path == path && batch.device == device && batch.inode == inode;
    };
    return std::any_of(lockCapturedMutationBatches_.cbegin(),
               lockCapturedMutationBatches_.cend(), matches)
        || std::any_of(readyMutationBatches_.cbegin(),
               readyMutationBatches_.cend(), matches)
        || (offeredMutationBatch_ && matches(*offeredMutationBatch_))
        || (waitingMutationBatch_ && matches(*waitingMutationBatch_))
        || (activeMutationBatch_ && matches(*activeMutationBatch_));
}

bool AutomaticBackupCoordinator::hasPendingInitialCopyFor(
    const QString& path, quint64 device, quint64 inode) const
{
    const auto matches = [&](const MutationBatch& batch) {
        return batch.kind == GenerationalBackupRequestKind::InitialCopy
            && batch.path == path && batch.device == device && batch.inode == inode;
    };
    return std::any_of(lockCapturedMutationBatches_.cbegin(),
               lockCapturedMutationBatches_.cend(), matches)
        || std::any_of(readyMutationBatches_.cbegin(),
               readyMutationBatches_.cend(), matches)
        || (offeredMutationBatch_ && matches(*offeredMutationBatch_))
        || (waitingMutationBatch_ && matches(*waitingMutationBatch_))
        || (activeMutationBatch_ && matches(*activeMutationBatch_));
}

void AutomaticBackupCoordinator::replacePendingInitialCopyWithMutation(
    const QString& path, quint64 device, quint64 inode)
{
    const auto matches = [&](const MutationBatch& batch) {
        return batch.kind == GenerationalBackupRequestKind::InitialCopy
            && batch.path == path && batch.device == device && batch.inode == inode;
    };
    const auto removeFrom = [&](QVector<MutationBatch>& batches) {
        QVector<GenerationalOperationState> cancelled;
        batches.erase(std::remove_if(batches.begin(), batches.end(), [&](const MutationBatch& batch) {
            if (!matches(batch)) return false;
            auto state = stateFor(GenerationalOperationPhase::Cancelled, batch);
            state.reservationHeld = false;
            cancelled.push_back(std::move(state));
            return true;
        }), batches.end());
        for (auto& state : cancelled) publishOperationState(std::move(state));
    };
    removeFrom(lockCapturedMutationBatches_);
    removeFrom(readyMutationBatches_);
    const auto invalidate = [&](std::optional<MutationBatch>& batch) {
        if (!batch || !matches(*batch)) return;
        auto state = stateFor(GenerationalOperationPhase::Cancelled, *batch);
        state.reservationHeld = false;
        const quint64 staleRequestId = batch->requestId;
        batch.reset();
        publishOperationState(std::move(state));
        if (staleRequestId != 0)
            emit generationalBackupRequestInvalidated(staleRequestId);
    };
    invalidate(offeredMutationBatch_);
    invalidate(waitingMutationBatch_);
}

GenerationalBackupRequestOffer AutomaticBackupCoordinator::offerFor(
    const MutationBatch& batch) const
{
    GenerationalBackupRequestOffer offer;
    offer.kind = batch.kind;
    offer.vaultPath = batch.path;
    offer.requestId = batch.requestId;
    if (batch.kind == GenerationalBackupRequestKind::CrudGeneration)
        offer.mutationGeneration = batch.generation;
    else if (batch.initialCopy)
        offer.sessionGeneration = batch.initialCopy->sessionGeneration();
    return offer;
}
void AutomaticBackupCoordinator::scheduleReadyMutationBatch()
{
    if (!usesGenerationalTrigger() || !globalPreferencesAllowDispatch()
        || mutationDispatchQueued_ || closing_ || activeMutationBatch_
        || offeredMutationBatch_ || waitingMutationBatch_ || readyMutationBatches_.isEmpty())
        return;
    if (std::none_of(readyMutationBatches_.cbegin(), readyMutationBatches_.cend(),
            [&](const MutationBatch& batch) {
                return !manualOperationBlocks(batch.path);
            }))
        return;
    mutationDispatchQueued_ = true;
    QTimer::singleShot(0, this, [this] {
        mutationDispatchQueued_ = false;
        if (usesGenerationalTrigger()) dispatchReadyMutationBatch();
    });
}
void AutomaticBackupCoordinator::dispatchReadyMutationBatch()
{
    if (!usesGenerationalTrigger() || !globalPreferencesAllowDispatch()
        || closing_ || activeMutationBatch_
        || offeredMutationBatch_ || waitingMutationBatch_
        || readyMutationBatches_.isEmpty())
        return;
    const auto eligible = std::find_if(readyMutationBatches_.cbegin(),
        readyMutationBatches_.cend(), [&](const MutationBatch& batch) {
            return !manualOperationBlocks(batch.path);
        });
    if (eligible == readyMutationBatches_.cend()) return;
    const qsizetype eligibleIndex = std::distance(
        readyMutationBatches_.cbegin(), eligible);
    MutationBatch batch = readyMutationBatches_.takeAt(eligibleIndex);
    if (++nextMutationRequestId_ == 0) ++nextMutationRequestId_;
    batch.requestId = nextMutationRequestId_;
    if (batch.resumeEpoch != 0) {
        auto* suspension = suspensionFor(
            batch.path, batch.vaultId, batch.device, batch.inode);
        if (!suspension || suspension->epoch != batch.resumeEpoch
            || !suspension->resumeRequested) {
            publishOperationState(stateFor(
                GenerationalOperationPhase::Cancelled, batch));
            scheduleReadyMutationBatch();
            return;
        }
        suspension->resumeRequestId = batch.requestId;
        publishSuspension(*suspension);
    }
    offeredMutationBatch_ = batch;
    publishOperationState(stateFor(
        GenerationalOperationPhase::OfferedRequest, batch));
    emit generationalBackupRequested(offerFor(batch));
    evaluateGenerationalShutdownDrain();
}
void AutomaticBackupCoordinator::retryMutationBatchAfterRelease()
{
    if (!usesGenerationalTrigger() || !globalPreferencesAllowDispatch()
        || closing_ || activeMutationBatch_ || offeredMutationBatch_
        || !waitingMutationBatch_ || !mutationContentionCycle_
        || manualOperationBlocks(waitingMutationBatch_->path))
        return;
    MutationBatch batch = std::move(*waitingMutationBatch_);
    waitingMutationBatch_.reset();
    if (++nextMutationRequestId_ == 0) ++nextMutationRequestId_;
    batch.requestId = nextMutationRequestId_;
    if (batch.resumeEpoch != 0) {
        auto* suspension = suspensionFor(
            batch.path, batch.vaultId, batch.device, batch.inode);
        if (!suspension || suspension->epoch != batch.resumeEpoch
            || !suspension->resumeRequested)
            return;
        suspension->resumeRequestId = batch.requestId;
        publishSuspension(*suspension);
    }
    offeredMutationBatch_ = batch;
    publishOperationState(stateFor(
        GenerationalOperationPhase::OfferedRequest, batch));
    emit generationalBackupRequested(offerFor(batch));
    evaluateGenerationalShutdownDrain();
}
void AutomaticBackupCoordinator::settleUnstartedMutationBatch(MutationBatch batch,
    BackupOutcome outcome, const QString& diagnostic)
{
    if (!usesGenerationalTrigger()) return;
    mutationContentionTimer_.stop();
    mutationContentionCycle_ = false;
    const auto terminalPhase = outcome == BackupOutcome::CancelledBeforePublication
        ? GenerationalOperationPhase::Cancelled
        : GenerationalOperationPhase::Completed;
    const MutationBackupOutcome coarseOutcome = mutationOutcome(outcome);
    if (coarseOutcome != MutationBackupOutcome::Published)
        suspendGenerationalBackup(batch, coarseOutcome, diagnostic);
    if (batch.kind == GenerationalBackupRequestKind::InitialCopy) {
        const quint64 sessionGeneration = batch.initialCopy
            ? batch.initialCopy->sessionGeneration() : 0;
        auto terminal = stateFor(terminalPhase, batch);
        terminal.reservationHeld = false;
        batch.initialCopy.reset(); // Release the capability before notifying observers.
        publishOperationState(std::move(terminal));
        if (batch.requestId != 0)
            emit generationalBackupRequestInvalidated(batch.requestId);
        emit mutationBatchSettled(MutationBackupResult{
            batch.path, 0, batch.requestId, mutationOutcome(outcome), outcome,
            diagnostic, {}, GenerationalBackupRequestKind::InitialCopy,
            sessionGeneration});
        scheduleReadyMutationBatch();
        evaluateGenerationalShutdownDrain();
        return;
    }
    if (!diagnostic.isEmpty())
        emit mutationBatchDiagnostic(batch.path, batch.generation, diagnostic);
    publishOperationState(stateFor(terminalPhase, batch));
    emit mutationBatchSettled(MutationBackupResult{batch.path, batch.generation,
        batch.requestId, mutationOutcome(outcome), outcome, diagnostic, {}});
    scheduleReadyMutationBatch();
    evaluateGenerationalShutdownDrain();
}
void AutomaticBackupCoordinator::expireMutationContention()
{
    if (!usesGenerationalTrigger() || !mutationContentionCycle_) return;
    std::optional<MutationBatch> expired;
    if (waitingMutationBatch_) {
        expired = std::move(waitingMutationBatch_);
        waitingMutationBatch_.reset();
    } else if (offeredMutationBatch_) {
        expired = std::move(offeredMutationBatch_);
        offeredMutationBatch_.reset();
    }
    if (!expired) {
        mutationContentionCycle_ = false;
        return;
    }
    settleUnstartedMutationBatch(std::move(*expired), BackupOutcome::FailedBeforePublication,
        QStringLiteral("Réservation d'instantané toujours indisponible ; sauvegarde non démarrée."));
}
bool AutomaticBackupCoordinator::markMutationBackupStarted(
    quint64 requestId, const QString& path, quint64 generation, QString destination)
{
    if (!usesGenerationalTrigger() || closing_ || activeMutationBatch_ || !offeredMutationBatch_
        || offeredMutationBatch_->kind != GenerationalBackupRequestKind::CrudGeneration
        || requestId == 0 || requestId != offeredMutationBatch_->requestId
        || generation != offeredMutationBatch_->generation)
        return false;
    const QString source = path.isEmpty()
        ? QString{} : QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    if (source != offeredMutationBatch_->path) return false;
    if (!destination.isEmpty()) {
        destination = QDir::cleanPath(QFileInfo(destination).absoluteFilePath());
        if (!backup_protocol::validPath(destination)) return false;
    }
    mutationContentionTimer_.stop();
    mutationContentionCycle_ = false;
    offeredMutationBatch_->destination = std::move(destination);
    activeMutationBatch_ = std::move(offeredMutationBatch_);
    offeredMutationBatch_.reset();
    publishOperationState(stateFor(
        GenerationalOperationPhase::AttemptActive, *activeMutationBatch_));
    return true;
}
bool AutomaticBackupCoordinator::markMutationBackupFinished(
    quint64 requestId, MutationBackupOutcome outcome,
    std::optional<MutationBackupPublicationReceipt> receipt)
{
    if (!usesGenerationalTrigger() || !activeMutationBatch_
        || activeMutationBatch_->kind
            != GenerationalBackupRequestKind::CrudGeneration)
        return false;
    BackupResult result;
    switch (outcome) {
    case MutationBackupOutcome::Published:
        result.outcome = BackupOutcome::Published;
        if (receipt) {
            result.receipt = receipt->evidence;
            result.publishedPath = receipt->destination;
        }
        break;
    case MutationBackupOutcome::Failed:
        result.outcome = BackupOutcome::FailedBeforePublication;
        break;
    case MutationBackupOutcome::Unknown:
        result.outcome = BackupOutcome::Unknown;
        break;
    }
    return finishMutationBackup(requestId, std::move(result), std::move(receipt));
}
bool AutomaticBackupCoordinator::finishMutationBackup(
    quint64 requestId, BackupResult result,
    std::optional<MutationBackupPublicationReceipt> publication)
{
    if (!usesGenerationalTrigger() || !activeMutationBatch_ || requestId == 0
        || requestId != activeMutationBatch_->requestId)
        return false;
    const MutationBatch completed = *activeMutationBatch_;
    const quint64 completedSessionGeneration =
        completed.kind == GenerationalBackupRequestKind::InitialCopy
            && completed.initialCopy
        ? completed.initialCopy->sessionGeneration() : 0;
    const MutationBackupOutcome outcome = mutationOutcome(result.outcome);
    if (outcome == MutationBackupOutcome::Published) {
        if (!publication || !result.receipt
            || publication->requestId != completed.requestId
            || publication->generation != completed.generation
            || publication->kind != completed.kind
            || publication->sessionGeneration != completedSessionGeneration
            || publication->vaultPath != completed.path
            || completed.destination.isEmpty()
            || publication->destination != completed.destination
            || result.publishedPath != completed.destination
            || publication->evidence != *result.receipt
            || !publication->evidence.permitsDeletion())
            return false;
    } else if (publication) {
        return false;
    }
    const bool workerStillAlive = mutationWorkerState_
        && mutationWorkerState_->requestId == completed.requestId
        && job_ && job_->isActive();
    const QString suspensionDiagnostic = result.diagnostic;
    if (outcome != MutationBackupOutcome::Published)
        suspendGenerationalBackup(completed, outcome, suspensionDiagnostic);
    activeMutationBatch_.reset();
    if (outcome == MutationBackupOutcome::Published)
        clearSuspensionAfterPublishedResume(completed);
    if (!workerStillAlive)
        publishOperationState(stateFor(
            GenerationalOperationPhase::Completed, completed));
    emit mutationBatchSettled(MutationBackupResult{completed.path,
        completed.generation, completed.requestId, outcome, result.outcome,
        std::move(result.diagnostic), std::move(publication), completed.kind,
        completedSessionGeneration});
    // A terminal failure is retained by the volatile suspension instead of
    // being requeued. Only an explicit resume can create the next attempt.
    scheduleReadyMutationBatch();
    evaluateGenerationalShutdownDrain();
    return true;
}
bool AutomaticBackupCoordinator::startMutationBackupSnapshot(
    quint64 requestId, const QString& path, quint64 generation, const QString& destination,
    storage::VaultOperationGuard access,
    std::optional<SnapshotDirectoryIdentity> directory, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral(
            "Consommation de la génération CRUD hors du thread propriétaire.");
        return false;
    }
    if (!usesGenerationalTrigger()) {
        error = QStringLiteral("Le moteur générationnel n'est pas sélectionné.");
        return false;
    }
    if (!globalPreferencesAllowDispatch() || closing_ || activeMutationBatch_) {
        error = QStringLiteral("Une sauvegarde générationnelle est déjà active ou le coordinateur se ferme.");
        return false;
    }
    const QString source = path.isEmpty()
        ? QString{} : QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    const QString target = destination.isEmpty()
        ? QString{} : QDir::cleanPath(QFileInfo(destination).absoluteFilePath());
    if (!offeredMutationBatch_ || requestId == 0
        || offeredMutationBatch_->kind != GenerationalBackupRequestKind::CrudGeneration
        || requestId != offeredMutationBatch_->requestId
        || generation != offeredMutationBatch_->generation
        || source != offeredMutationBatch_->path) {
        error = QStringLiteral("Demande générationnelle absente, obsolète ou incohérente.");
        return false;
    }
    if (!backup_protocol::validPath(target) || target != destination) {
        error = QStringLiteral("Destination générationnelle invalide ou non canonique.");
        return false;
    }
    std::string accessError;
    if (!access.matchesSnapshotAccess(source.toStdString(), accessError)) {
        if (access.contended()) {
            waitingMutationBatch_ = std::move(offeredMutationBatch_);
            offeredMutationBatch_.reset();
            if (!mutationContentionCycle_) {
                mutationContentionCycle_ = true;
                mutationContentionTimer_.start();
            }
            publishOperationState(stateFor(
                GenerationalOperationPhase::WaitingForReservation,
                *waitingMutationBatch_));
            error = QStringLiteral("Réservation d'instantané temporairement indisponible ; attente d'une libération.");
            return false;
        }
        if (access.attempted()) {
            MutationBatch rejected = std::move(*offeredMutationBatch_);
            offeredMutationBatch_.reset();
            error = accessError.empty()
                ? QStringLiteral("Réservation d'instantané définitivement refusée.")
                : QString::fromStdString(accessError);
            settleUnstartedMutationBatch(std::move(rejected),
                BackupOutcome::FailedBeforePublication, error);
            return false;
        }
        error = accessError.empty()
            ? QStringLiteral("Réservation d'instantané absente ou incompatible.")
            : QString::fromStdString(accessError);
        return false;
    }
    if (job_) {
        // Normally the historical job owns an exclusive reservation, so the
        // attempted snapshot above enters the contention branch. Keep this
        // defensive check: a capability alone must never authorize a second
        // worker inside the coordinator.
        error = QStringLiteral("Une autre sauvegarde est encore active.");
        return false;
    }
    const quint64 expectedDevice = offeredMutationBatch_->device;
    const quint64 expectedInode = offeredMutationBatch_->inode;
    if (!access.matchesSnapshotIdentity(source.toStdString(),
            expectedDevice, expectedInode, accessError)) {
        // A valid capability for the current pathname proves that this is not
        // transient contention: the physical source no longer matches the
        // authenticated session that emitted the request. Consume this stale
        // generation as a confirmed pre-publication failure; never run a
        // worker against the replacement file and never retry it in a loop.
        error = accessError.empty()
            ? QStringLiteral("Identité physique du coffre divergente ; demande annulée.")
            : QString::fromStdString(accessError);
        static_cast<void>(markMutationBackupStarted(requestId, source, generation));
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    VaultFileIdentity observed;
    QString identityError;
    if (!VaultPreferencesStore::inspectVault(source, observed, identityError)
        || observed.path != source
        || observed.device != expectedDevice || observed.inode != expectedInode
        || observed.vaultId != offeredMutationBatch_->vaultId) {
        error = identityError.isEmpty()
            ? QStringLiteral("Identité ou vault_id du coffre divergents ; demande annulée.")
            : identityError;
        static_cast<void>(markMutationBackupStarted(requestId, source, generation));
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    if (!markMutationBackupStarted(requestId, source, generation, target)) {
        error = QStringLiteral("Demande générationnelle absente, obsolète ou incohérente.");
        return false;
    }

    BackupJob* job = nullptr;
    try {
        job = new BackupJob(worker_, this);
    } catch (...) {
        error = QStringLiteral("Impossible de préparer le processus de sauvegarde.");
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    // From this point the generation is attempted before any worker can be
    // launched. A preparation/start failure settles it without auto-retry.
    superviseGenerationalJob(job, requestId);
    if (!job->startSnapshotReserved(source, destination, std::move(access), {}, directory)) {
        error = job->startError();
        job_.clear();
        mutationJobRequestId_ = 0;
        mutationJobResult_.reset();
        mutationJobReceipt_.reset();
        mutationJobSettled_ = false;
        job->deleteLater();
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    mutationWorkerState_ = stateFor(GenerationalOperationPhase::WorkerActive,
        *activeMutationBatch_, true, true);
    publishOperationState(*mutationWorkerState_);
    emit activityChanged(true);
    evaluateGenerationalShutdownDrain();
    return true;
}

bool AutomaticBackupCoordinator::startPreparedMutationBackupSnapshot(
    quint64 requestId, const QString& path, quint64 generation,
    PreparedBackupDestination prepared, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral(
            "Consommation de la génération préparée hors du thread propriétaire.");
        return false;
    }
    if (!usesGenerationalTrigger() || !globalPreferencesAllowDispatch()
        || closing_ || activeMutationBatch_ || job_) {
        error = QStringLiteral(
            "Une sauvegarde générationnelle est déjà active ou le coordinateur se ferme.");
        return false;
    }
    const QString source = path.isEmpty()
        ? QString{} : QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    if (!offeredMutationBatch_ || requestId == 0
        || offeredMutationBatch_->kind
            != GenerationalBackupRequestKind::CrudGeneration
        || offeredMutationBatch_->requestId != requestId
        || offeredMutationBatch_->generation != generation
        || offeredMutationBatch_->path != source
        || offeredMutationBatch_->vaultId.size() != 16) {
        error = QStringLiteral(
            "Demande CRUD préparée absente, obsolète ou incohérente.");
        return false;
    }

    const VaultFileIdentity expected{source, offeredMutationBatch_->vaultId,
        offeredMutationBatch_->device, offeredMutationBatch_->inode};
    const QString destination = prepared.destinationPath();
    if (prepared.vaultPath() != source
        || prepared.vaultId() != expected.vaultId
        || prepared.bindingGeneration() != generation
        || destination.isEmpty()) {
        error = QStringLiteral(
            "Destination préparée liée à un autre coffre ou à une autre génération.");
        return false;
    }
    const auto* currentConfiguration = globalBackupPreferences_
        ? &*globalBackupPreferences_ : nullptr;
    if (!BackupDestinationPreparer::revalidateConfiguration(
            prepared, currentConfiguration, error)) {
        MutationBatch retained = std::move(*offeredMutationBatch_);
        offeredMutationBatch_.reset();
        emit generationalBackupRequestInvalidated(requestId);
        retainCrudAfterConfigurationInvalidation(std::move(retained));
        scheduleReadyMutationBatch();
        return false;
    }
    if (!markMutationBackupStarted(
            requestId, source, generation, destination)) {
        error = QStringLiteral(
            "Demande CRUD préparée absente, obsolète ou déjà consommée.");
        return false;
    }

    BackupJob* job = nullptr;
    try {
        job = new BackupJob(worker_, this);
    } catch (...) {
        error = QStringLiteral("Impossible de préparer le processus de sauvegarde.");
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    superviseGenerationalJob(job, requestId);
    if (!BackupDestinationPreparer::startPreparedSnapshot(
            prepared, expected, generation, *job, error)) {
        if (error.isEmpty())
            error = QStringLiteral("Démarrage de la génération préparée refusé.");
        job_.clear();
        mutationJobRequestId_ = 0;
        mutationJobResult_.reset();
        mutationJobReceipt_.reset();
        mutationJobSettled_ = false;
        job->deleteLater();
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    mutationWorkerState_ = stateFor(GenerationalOperationPhase::WorkerActive,
        *activeMutationBatch_, true, true);
    publishOperationState(*mutationWorkerState_);
    emit activityChanged(true);
    evaluateGenerationalShutdownDrain();
    return true;
}

bool AutomaticBackupCoordinator::startInitialBackupSnapshot(
    quint64 requestId, QString& error)
{
    error.clear();
    if (QThread::currentThread() != thread()) {
        error = QStringLiteral(
            "Consommation de la première sauvegarde hors du thread propriétaire.");
        return false;
    }
    if (!usesGenerationalTrigger() || !globalPreferencesAllowDispatch()
        || closing_ || activeMutationBatch_ || job_) {
        error = QStringLiteral(
            "Une sauvegarde générationnelle est déjà active ou le coordinateur se ferme.");
        return false;
    }
    if (!offeredMutationBatch_ || requestId == 0
        || offeredMutationBatch_->requestId != requestId
        || offeredMutationBatch_->kind != GenerationalBackupRequestKind::InitialCopy
        || !offeredMutationBatch_->initialCopy
        || offeredMutationBatch_->initialCopy->consumed()) {
        error = QStringLiteral(
            "Demande de première sauvegarde absente, obsolète ou déjà consommée.");
        return false;
    }

    auto& offered = *offeredMutationBatch_;
    const quint64 sessionGeneration = offered.initialCopy->sessionGeneration();
    const QString destination =
        offered.initialCopy->destination().destinationPath();
    const bool sessionCurrent = !modificationSessionPath_.isEmpty()
        && offered.session == modificationSessionGeneration_
        && offered.path == modificationSessionPath_
        && offered.vaultId == modificationSessionVaultId_
        && offered.device == modificationSessionDevice_
        && offered.inode == modificationSessionInode_;
    if (!sessionCurrent || destination.isEmpty()) {
        MutationBatch rejected = std::move(offered);
        offeredMutationBatch_.reset();
        error = QStringLiteral(
            "La première sauvegarde ne correspond plus à la session courante.");
        settleUnstartedMutationBatch(std::move(rejected),
            BackupOutcome::FailedBeforePublication, error);
        return false;
    }
    const auto* currentConfiguration = globalBackupPreferences_
        ? &*globalBackupPreferences_ : nullptr;
    if (!BackupDestinationPreparer::revalidateConfiguration(
            offered.initialCopy->destination(), currentConfiguration, error)) {
        const QString stalePath = offered.path;
        const quint64 staleRequestId = offered.requestId;
        offeredMutationBatch_.reset();
        emit generationalBackupRequestInvalidated(staleRequestId);
        pendingInitialReinspectionPath_ = stalePath;
        if (globalPreferencesAllowDispatch())
            emit globalBackupReinspectionRequested(stalePath);
        scheduleReadyMutationBatch();
        return false;
    }

    InitialBackupAdmission admission;
    admission.currentVault.path = modificationSessionPath_;
    admission.currentVault.vaultId = modificationSessionVaultId_;
    admission.currentVault.device = modificationSessionDevice_;
    admission.currentVault.inode = modificationSessionInode_;
    admission.currentSessionGeneration = sessionGeneration;
    admission.triggerMode = triggerMode_;
    admission.sessionCurrent = true;
    admission.closing = false;
    admission.operationAdmissible = true;

    mutationContentionTimer_.stop();
    mutationContentionCycle_ = false;
    offered.destination = destination;
    activeMutationBatch_ = std::move(offeredMutationBatch_);
    offeredMutationBatch_.reset();
    publishOperationState(stateFor(
        GenerationalOperationPhase::AttemptActive, *activeMutationBatch_, true));

    BackupJob* job = nullptr;
    try {
        job = new BackupJob(worker_, this);
    } catch (...) {
        error = QStringLiteral("Impossible de préparer le processus de sauvegarde.");
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    superviseGenerationalJob(job, requestId);
    if (!activeMutationBatch_->initialCopy->admitAndStart(
            *job, admission, error)) {
        if (error.isEmpty())
            error = QStringLiteral("Démarrage de la première sauvegarde refusé.");
        job_.clear();
        mutationJobRequestId_ = 0;
        mutationJobResult_.reset();
        mutationJobReceipt_.reset();
        mutationJobSettled_ = false;
        job->deleteLater();
        static_cast<void>(finishMutationBackup(requestId,
            BackupResult{BackupOutcome::FailedBeforePublication, error}));
        return false;
    }
    mutationWorkerState_ = stateFor(GenerationalOperationPhase::WorkerActive,
        *activeMutationBatch_, true, true);
    publishOperationState(*mutationWorkerState_);
    emit activityChanged(true);
    evaluateGenerationalShutdownDrain();
    return true;
}

void AutomaticBackupCoordinator::superviseGenerationalJob(
    BackupJob* job, quint64 requestId)
{
    Q_ASSERT(job != nullptr);
    Q_ASSERT(QThread::currentThread() == thread());
    Q_ASSERT(activeMutationBatch_ && activeMutationBatch_->requestId == requestId);
    Q_ASSERT(!job_);
    job_ = job;
    mutationJobRequestId_ = requestId;
    mutationJobResult_.reset();
    mutationJobReceipt_.reset();
    mutationJobSettled_ = false;
    connect(job, &BackupJob::finished, this,
        [this, job, requestId](BackupResult result) {
            if (job_ != job || mutationJobRequestId_ != requestId) return;
            mutationJobReceipt_.reset();
            if (result.outcome == BackupOutcome::Published
                && activeMutationBatch_
                && activeMutationBatch_->requestId == requestId
                && result.receipt
                && result.publishedPath == activeMutationBatch_->destination
                && result.receipt->permitsDeletion()) {
                const quint64 sessionGeneration =
                    activeMutationBatch_->kind
                        == GenerationalBackupRequestKind::InitialCopy
                        && activeMutationBatch_->initialCopy
                    ? activeMutationBatch_->initialCopy->sessionGeneration() : 0;
                mutationJobReceipt_ = MutationBackupPublicationReceipt{
                    activeMutationBatch_->path, activeMutationBatch_->destination,
                    activeMutationBatch_->generation, requestId, *result.receipt,
                    activeMutationBatch_->kind, sessionGeneration};
            } else if (result.outcome == BackupOutcome::Published) {
                result = {BackupOutcome::Unknown,
                    QStringLiteral("Preuve de publication absente ou incohérente.")};
            }
            mutationJobResult_ = std::move(result);
            if (activeMutationBatch_
                && mutationOutcome(mutationJobResult_->outcome)
                    != MutationBackupOutcome::Published) {
                suspendGenerationalBackup(*activeMutationBatch_,
                    mutationOutcome(mutationJobResult_->outcome),
                    mutationJobResult_->diagnostic);
            }
            if (mutationWorkerState_) {
                mutationWorkerState_->resultObserved = true;
                mutationWorkerState_->workerOutcome = mutationJobResult_->outcome;
                publishOperationState(*mutationWorkerState_);
            }
            if (closing_ && mutationOutcome(mutationJobResult_->outcome)
                    == MutationBackupOutcome::Unknown) {
                if (!mutationJobSettled_) {
                    mutationJobSettled_ = finishMutationBackup(
                        requestId, *mutationJobResult_);
                }
                closeReady_ = true;
                emit closeReady(); // The independent supervisor still owns the live child and locks.
            }
            evaluateGenerationalShutdownDrain();
        });
    connect(job, &BackupJob::processTerminated, this, [this, job, requestId] {
        if (job_ != job || mutationJobRequestId_ != requestId) return;
        const bool resultAlreadySettled = mutationJobSettled_;
        BackupResult result = mutationJobResult_.value_or(BackupResult{
            BackupOutcome::Unknown,
            QStringLiteral("Résultat du worker absent après sa terminaison.")});
        auto publication = std::move(mutationJobReceipt_);
        mutationJobResult_.reset();
        mutationJobReceipt_.reset();
        mutationJobRequestId_ = 0;
        job_.clear();
        job->deleteLater();
        emit activityChanged(false);
        if (!mutationJobSettled_) {
            if (!finishMutationBackup(requestId, result, std::move(publication))
                && result.outcome == BackupOutcome::Published) {
                static_cast<void>(finishMutationBackup(requestId,
                    BackupResult{BackupOutcome::Unknown,
                        QStringLiteral("Preuve de publication générationnelle incohérente.")}));
            }
        }
        if (resultAlreadySettled && mutationWorkerState_) {
            auto terminal = *mutationWorkerState_;
            terminal.phase = GenerationalOperationPhase::Completed;
            terminal.reservationHeld = false;
            terminal.workerAlive = false;
            publishOperationState(std::move(terminal));
        }
        mutationWorkerState_.reset();
        mutationJobSettled_ = false;
        if (closing_) {
            closeReady_ = true;
            emit closeReady();
        } else retryPending();
        evaluateGenerationalShutdownDrain();
    });
}
bool AutomaticBackupCoordinator::cancelMutationBackupBeforeLaunch(
    quint64 requestId, const QString& path, quint64 generation)
{
    if (!usesGenerationalTrigger()) return false;
    const QString source = path.isEmpty()
        ? QString{} : QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    std::optional<MutationBatch> cancelled;
    auto matches = [&](const std::optional<MutationBatch>& batch) {
        return batch && requestId != 0 && batch->requestId == requestId
            && batch->kind == GenerationalBackupRequestKind::CrudGeneration
            && batch->generation == generation && batch->path == source;
    };
    if (matches(waitingMutationBatch_)) {
        cancelled = std::move(waitingMutationBatch_);
        waitingMutationBatch_.reset();
    } else if (matches(offeredMutationBatch_)) {
        cancelled = std::move(offeredMutationBatch_);
        offeredMutationBatch_.reset();
    }
    if (!cancelled) return false;
    settleUnstartedMutationBatch(std::move(*cancelled), BackupOutcome::CancelledBeforePublication,
        QStringLiteral("Demande de sauvegarde annulée avant lancement."));
    return true;
}
void AutomaticBackupCoordinator::observeCommittedMutation(
    const QString& path, quint64 commitGeneration)
{
    if (!usesGenerationalTrigger() || closing_ || modificationSessionPath_.isEmpty()
        || commitGeneration <= minimumCommitGeneration_
        || commitGeneration <= lastAcceptedCommitGeneration_)
        return;
    const QString source = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    if (source != modificationSessionPath_) return;
    lastAcceptedCommitGeneration_ = commitGeneration;
    if (++mutationGeneration_ == 0) ++mutationGeneration_;
    MutationBatch committed{source, mutationGeneration_,
        modificationSessionGeneration_, 0, modificationSessionDevice_,
        modificationSessionInode_};
    committed.vaultId = modificationSessionVaultId_;
    if (auto* suspension = suspensionFor(source, modificationSessionVaultId_,
            modificationSessionDevice_, modificationSessionInode_)) {
        retainSuspendedNeed(committed);
        if (suspension->resumeRequested
            && !(activeMutationBatch_
                && activeMutationBatch_->resumeEpoch == suspension->epoch)) {
            const quint64 epoch = suspension->epoch;
            const auto removeResume = [&](QVector<MutationBatch>& batches) {
                batches.erase(std::remove_if(batches.begin(), batches.end(),
                    [&](const MutationBatch& batch) {
                        return batch.path == source && batch.resumeEpoch == epoch;
                    }), batches.end());
            };
            removeResume(lockCapturedMutationBatches_);
            removeResume(readyMutationBatches_);
            const auto invalidateResume = [&](std::optional<MutationBatch>& batch) {
                if (!batch || batch->path != source || batch->resumeEpoch != epoch)
                    return;
                const quint64 stale = batch->requestId;
                batch.reset();
                if (stale != 0) emit generationalBackupRequestInvalidated(stale);
            };
            invalidateResume(offeredMutationBatch_);
            invalidateResume(waitingMutationBatch_);
            suspension->resumeRequestId = 0;
            committed.resumeEpoch = epoch;
            retainReadyMutationBatch(std::move(committed));
        }
        evaluateGenerationalShutdownDrain();
        return;
    }
    if (generationalShutdownDrainRequested_) {
        replacePendingInitialCopyWithMutation(source,
            modificationSessionDevice_, modificationSessionInode_);
        retainReadyMutationBatch(std::move(committed));
        evaluateGenerationalShutdownDrain();
        return;
    }
    scheduledMutationGeneration_ = mutationGeneration_;
    scheduledSessionGeneration_ = modificationSessionGeneration_;
    // A CRUD commit that arrives after an InitialCopy inspection owns the next
    // snapshot need. Invalidate any unstarted initial offer, release its held
    // capability by RAII and honor the freshly restarted twenty-second delay.
    replacePendingInitialCopyWithMutation(source,
        modificationSessionDevice_, modificationSessionInode_);
    MutationBatch scheduled{source, scheduledMutationGeneration_,
        scheduledSessionGeneration_, 0, modificationSessionDevice_,
        modificationSessionInode_};
    scheduled.vaultId = modificationSessionVaultId_;
    publishOperationState(stateFor(
        GenerationalOperationPhase::PendingRequest, scheduled));
    mutationGroupingTimer_.start();
}
void AutomaticBackupCoordinator::requestForLockedVault(const QString& path)
{
    if (!usesHistoricalTrigger()) return;
    const auto source = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    if (closing_ || path.isEmpty() || !known_.contains(source)) return;
    pending_.insert(known_.value(source), source);
    retryPending();
}
void AutomaticBackupCoordinator::resumeAutomaticBackup(const QString& id)
{
    if (!usesHistoricalTrigger() || closing_) return;
    resumes_.insert(id); notified_.remove(id);
    // Lookup and verification are deferred, not a synchronous GUI callback.
    pending_.insert(id, {});
    retryPending();
}
void AutomaticBackupCoordinator::setPaused(bool paused)
{
    paused_ = paused;
    if (!paused) retryPending();
}
void AutomaticBackupCoordinator::retryPending()
{
    if (!usesHistoricalTrigger()) return;
    deferredIds_.clear();
    schedulePending();
}
void AutomaticBackupCoordinator::schedulePending()
{
    if (!usesHistoricalTrigger() || queued_ || paused_ || closing_ || job_ || pending_.isEmpty()) return;
    bool runnable = false;
    for (auto it = pending_.cbegin(); it != pending_.cend(); ++it)
        if (!deferredIds_.contains(it.key())) { runnable = true; break; }
    if (!runnable) return;
    queued_ = true;
    QTimer::singleShot(0, this, [this] {
        queued_ = false;
        if (usesHistoricalTrigger()) dispatch();
    });
}
bool AutomaticBackupCoordinator::isActive() const noexcept { return job_ && job_->isActive(); }
void AutomaticBackupCoordinator::cancel()
{
    if (job_) { voluntaryCancellation_ = true; job_->cancel(); }
}
void AutomaticBackupCoordinator::shutdown()
{
    if (closing_) return;
    for (const auto& admission : manualOperations_)
        if (admission.state)
            admission.state->active.store(false, std::memory_order_release);
    manualOperations_.clear();
    cancelInitialInspectionActivity();
    // A direct destruction path must not silently erase the last committed
    // generation even when MainWindow did not get a normal closeEvent.
    if (auto captured = takeScheduledMutationBatch())
        retainLockCapturedMutationBatch(std::move(*captured));
    closing_ = true;
    pending_.clear();
    settleMutationBatchesForShutdown();
    mutationDispatchQueued_ = false;
    if (normalInterruption_) *normalInterruption_ = !voluntaryCancellation_;
    if (job_) {
        job_->cancel();
        if (unconfirmedRotationStop_) { closeReady_ = true; emit closeReady(); }
    }
    else { closeReady_ = true; emit closeReady(); }
    evaluateGenerationalShutdownDrain();
}
void AutomaticBackupCoordinator::settleMutationBatchesForShutdown()
{
    if (!usesGenerationalTrigger()) return;
    mutationContentionTimer_.stop();
    mutationContentionCycle_ = false;
    QVector<MutationBatch> notStarted = std::move(lockCapturedMutationBatches_);
    lockCapturedMutationBatches_.clear();
    for (MutationBatch& batch : readyMutationBatches_)
        notStarted.push_back(std::move(batch));
    readyMutationBatches_.clear();
    if (offeredMutationBatch_) {
        notStarted.push_back(std::move(*offeredMutationBatch_));
        offeredMutationBatch_.reset();
    }
    if (waitingMutationBatch_) {
        notStarted.push_back(std::move(*waitingMutationBatch_));
        waitingMutationBatch_.reset();
    }
    for (MutationBatch& batch : notStarted)
        settleUnstartedMutationBatch(std::move(batch),
            BackupOutcome::CancelledBeforePublication,
            QStringLiteral("Fermeture normale avant lancement ; sauvegarde générationnelle non effectuée."));
    // A simulated/external attempt has no supervised child capable of
    // producing a later result. Its state is therefore explicitly unknown.
    // A real BackupJob remains owned and is cancelled below; its process result
    // settles the active generation without releasing its live reservation.
    if (activeMutationBatch_ && mutationJobRequestId_ == 0) {
        const MutationBatch active = *activeMutationBatch_;
        activeMutationBatch_.reset();
        const QString diagnostic = QStringLiteral(
            "Fermeture pendant une tentative active ; résultat non confirmé.");
        emit mutationBatchDiagnostic(active.path, active.generation, diagnostic);
        publishOperationState(stateFor(
            GenerationalOperationPhase::Completed, active));
        emit mutationBatchSettled(MutationBackupResult{active.path,
            active.generation, active.requestId, MutationBackupOutcome::Unknown,
            BackupOutcome::Unknown, diagnostic, {}});
    }
}
void AutomaticBackupCoordinator::fail(const QString& id, const QString& message)
{
    if (!usesHistoricalTrigger()) return;
    const QPointer<AutomaticBackupCoordinator> guarded(this);
    QString error;
    const bool saved = store_.suspendAutomaticBackup(id, error);
    if (!notified_.contains(id)) {
        notified_.insert(id);
        emit notification(id, message + (saved ? QString() :
            QStringLiteral(" Suspension persistante non confirmée ; vérifier la configuration.")));
    }
    if (guarded) guarded->schedulePending();
}
void AutomaticBackupCoordinator::dispatch()
{
    if (!usesHistoricalTrigger() || paused_ || closing_ || job_ || pending_.isEmpty()) return;
    auto next = pending_.cbegin();
    while (next != pending_.cend() && deferredIds_.contains(next.key())) ++next;
    if (next == pending_.cend()) return;
    const auto id = next.key();
    pending_.remove(id);
    try {
        QVector<VaultRegistration> records;
        QString error;
        if (!store_.list(records, error)) { fail(id, error); return; }
        const auto found = std::find_if(records.cbegin(), records.cend(),
            [&](const auto& value) { return value.localId == id; });
        if (found == records.cend()) { fail(id, QStringLiteral("Coffre enregistré introuvable.")); return; }
        auto record = *found;
        if (record.replacement) {
            // Recovery is not a backup failure. Do not arm an attempt, suspend
            // backups or retain a request that would rotate immediately after
            // restoration. A future normal lock/explicit resume can enqueue it.
            resumes_.remove(id);
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            emit deferred(id);
            if (guarded) guarded->schedulePending();
            return;
        }
        const bool resume = resumes_.remove(id);
        if (resume && record.backup.automatic) {
            if (!store_.suspendAutomaticBackup(id, error)) { fail(id, error); return; }
            record.backupRequired = true;
        }
        if (!record.backup.automatic || !record.backupRequired
            || ((record.automaticSuspended || notified_.contains(id)) && !resume)) {
            schedulePending(); return;
        }
        storage::VaultOperationGuard reservation;
        std::string failure;
        if (!reservation.tryReserve(record.file.path.toStdString(), failure)) {
            if (reservation.contended()) {
                pending_.insert(id, record.file.path);
                if (resume) resumes_.insert(id);
                deferredIds_.insert(id);
                const QPointer<AutomaticBackupCoordinator> guarded(this);
                emit deferred(id); // No spin, timer or false storage error.
                if (guarded) guarded->schedulePending();
            } else fail(id, QString::fromStdString(failure));
            return;
        }
        SnapshotDirectoryIdentity directory;
        if (!VaultSnapshotService::inspectDestinationDirectory(record.backup.directory.toStdString(), directory, failure)) {
            fail(id, QString::fromStdString(failure)); return;
        }
        const auto token = QUuid::createUuid().toString(QUuid::WithoutBraces);
        const auto stem = QFileInfo(record.file.path).completeBaseName() + '_'
            + QDateTime::currentDateTime().toString(QStringLiteral("dd-MM-yyyy_HH-mm-ss"));
        QString destination = QDir(record.backup.directory).filePath(stem + ".db");
        // Never overwrite: even a later collision is rejected by linkat().
        const bool catalogued = std::any_of(record.automaticVersions.cbegin(), record.automaticVersions.cend(),
            [&](const auto& version) { return version.path == destination; });
        // A missing pathname may still belong to an uncertain deletion. Never
        // reuse it and accidentally associate a new inode with that old record.
        if (catalogued || QFileInfo::exists(destination) || QFileInfo(destination).isSymLink())
            destination = QDir(record.backup.directory).filePath(stem + '_' + token + ".db");
        if (!store_.beginAutomaticBackup(record, directory, destination, token, reservation, error, resume)) {
            fail(id, error); return;
        }
        const auto interrupted = std::make_shared<bool>(false);
        auto* job = new BackupJob(worker_, this);
        job_ = job;
        activeId_ = id;
        voluntaryCancellation_ = false;
        unconfirmedRotationStop_ = false;
        normalInterruption_ = interrupted;
        const auto store = store_;
        connect(job, &BackupJob::copyConfirmed, this, [this, id](BackupResult result) {
            emit copyConfirmed(id, result);
        });
        connect(job, &BackupJob::rotationFinished, this, [this, id](RotationResult result) {
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            unconfirmedRotationStop_ = result.outcome == RotationOutcome::Unknown;
            emit rotationCompleted(id, result);
            if (guarded && result.outcome != RotationOutcome::Complete)
                emit notification(id, QStringLiteral("Sauvegarde créée ; rotation non terminée : ") + result.diagnostic);
            if (guarded && closing_ && unconfirmedRotationStop_) { closeReady_ = true; emit closeReady(); }
            // No backupRequired rearm, no automatic-backup suspension. The
            // durable rotation latch independently prevents uncertain retries.
        });
        connect(job, &BackupJob::finished, this, [this, id, job](BackupResult result) {
            if (job_ != job) return;
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            if (result.outcome != BackupOutcome::Published
                && !(closing_ && result.outcome == BackupOutcome::CancelledBeforePublication)
                && !notified_.contains(id)) {
                notified_.insert(id);
                QString diagnostic = result.diagnostic;
                if (diagnostic.contains("errno=28]") || diagnostic.contains("primaire=13,"))
                    diagnostic = QStringLiteral("Espace insuffisant. ") + diagnostic;
                else if (diagnostic.contains("errno=13]"))
                    diagnostic = QStringLiteral("Permission refusée. ") + diagnostic;
                emit notification(id, diagnostic.isEmpty()
                    ? QStringLiteral("Sauvegarde automatique non confirmée ; reprise manuelle nécessaire.") : diagnostic);
            }
            if (!guarded) return;
            emit completed(id, result);
            if (!guarded) return;
            if (closing_ && result.outcome == BackupOutcome::Unknown) {
                closeReady_ = true; emit closeReady(); // Supervisor/child keep the locks.
            }
        });
        connect(job, &BackupJob::processTerminated, this, [this, job] {
            if (job_ != job) return;
            const QPointer<AutomaticBackupCoordinator> guarded(this);
            job_.clear(); activeId_.clear(); job->deleteLater();
            emit activityChanged(false);
            if (!guarded) return;
            if (closing_) { closeReady_ = true; emit closeReady(); }
            else retryPending();
        });
        const bool started = job->startReserved(record.file.path, destination, std::move(reservation),
            [store, id, token, interrupted](BackupResult& result, const storage::VaultOperationGuard& lease) {
                QString error;
                if (!store.finishAutomaticBackup(id, token, result, *interrupted, lease, error))
                    result = {BackupOutcome::Unknown, error};
            }, directory, AutomaticBackupContext{store_.fileName(), id, token});
        if (!started) {
            job_.clear(); activeId_.clear(); job->deleteLater(); fail(id, job->startError());
        } else emit activityChanged(true);
    } catch (...) {
        if (job_ && !job_->isActive()) { job_->deleteLater(); job_.clear(); }
        if (job_) job_->cancel();
        fail(id, QStringLiteral("Erreur inattendue ; sauvegarde automatique suspendue."));
    }
}
}
