#pragma once

#include "services/backup_destination_preparer.hpp"
#include "services/backup_trigger_mode.hpp"

#include <QDateTime>
#include <QString>

#include <optional>

namespace passwall::services {

class BackupJob;

// Trusted in-process description supplied only after a real vault unlock.
// It is not a persisted authorization and carries no secret.
struct AuthenticatedBackupSession {
    VaultFileIdentity vault;
    quint64 sessionGeneration = 0;
    quint64 pendingMutationGeneration = 0;
    bool authenticated = false;
    // Set only by an explicit in-process resume after an InitialCopy failure.
    // An uncertain but structurally readable prior output must not suppress the
    // fresh copy requested by the user. This flag is never persisted.
    bool forceInitialCopy = false;
};

enum class InitialBackupCheckpoint {
    BeforeInspection,
    AfterSnapshotReservation,
    DuringFamilyInspection,
    BeforeDestinationPreparation,
    BeforeReturn
};

// The future asynchronous owner checks that the exact authenticated session is
// still current. The callback must be noexcept and must not retain this object.
struct InitialBackupCancellation {
    bool (*requested)(void*, quint64, InitialBackupCheckpoint) noexcept = nullptr;
    void* context = nullptr;
};

enum class InitialBackupDecision {
    Prepared,
    EmptyVault,
    ExistingAdmissibleBackup,
    CoveredByPendingMutation,
    ConfigurationUnavailable,
    Cancelled,
    Refused
};

// Owner-thread facts which must be sampled immediately before consuming a
// prepared request. They are an in-process admission context, never a durable
// authorization or a substitute for the retained kernel capability.
struct InitialBackupAdmission {
    VaultFileIdentity currentVault;
    quint64 currentSessionGeneration = 0;
    BackupTriggerMode triggerMode = BackupTriggerMode::Historical;
    bool sessionCurrent = false;
    bool closing = false;
    bool operationAdmissible = false;
    // Optional 2I-4D activity binding. A future asynchronous inspection uses
    // this owner-issued identifier so that a late result cannot be admitted
    // after its session activity was invalidated. Zero preserves the isolated
    // synchronous foundation tests until the production consumer is connected.
    quint64 inspectionActivityId = 0;
};

// Distinct transient, move-only request. Its session binding is deliberately
// separate from CRUD mutation generations. A start attempt consumes it even
// when final admission or worker preparation fails.
class InitialBackupRequest final {
public:
    InitialBackupRequest(quint64 sessionGeneration, PreparedBackupDestination destination) noexcept;
    InitialBackupRequest(const InitialBackupRequest&) = delete;
    InitialBackupRequest& operator=(const InitialBackupRequest&) = delete;
    InitialBackupRequest(InitialBackupRequest&& other) noexcept;
    InitialBackupRequest& operator=(InitialBackupRequest&& other) noexcept;

    [[nodiscard]] quint64 sessionGeneration() const noexcept { return sessionGeneration_; }
    [[nodiscard]] const PreparedBackupDestination& destination() const noexcept { return destination_; }
    [[nodiscard]] bool consumed() const noexcept { return consumed_; }

    // Must run on job.thread(). No event loop is entered between revalidation
    // and ownership transfer to BackupJob::startSnapshotReserved().
    [[nodiscard]] bool admitAndStart(
        BackupJob& job, const InitialBackupAdmission& admission, QString& error);

private:
    quint64 sessionGeneration_ = 0;
    PreparedBackupDestination destination_;
    bool consumed_ = false;
};

struct InitialBackupPreparation {
    InitialBackupDecision decision = InitialBackupDecision::Refused;
    std::optional<InitialBackupRequest> request;
    QString diagnostic;
};

class InitialBackupPreparer final {
public:
    // Synchronous filesystem/SQLite inspection. Its GUI-cycle consumer runs it
    // outside the GUI thread and provides cancellation to reject stale sessions.
    // No worker or snapshot is launched by this operation.
    [[nodiscard]] static InitialBackupPreparation prepare(
        const GlobalBackupPreferencesResult& configuration,
        const AuthenticatedBackupSession& session,
        const QDateTime& timestamp,
        InitialBackupCancellation cancellation);
};

} // namespace passwall::services
