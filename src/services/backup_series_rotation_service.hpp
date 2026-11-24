#pragma once

#include "services/backup_protocol.hpp"
#include "services/backup_series_inspector.hpp"

#include <QVector>

#include <optional>

namespace passwall::services {

enum class BackupSeriesRotationOutcome {
    NoRotationNecessary,
    Complete,
    Refused,
    Partial,
    DeletionDurabilityUnconfirmed,
    Unknown
};

enum class BackupSeriesRotationCheckpoint {
    BeforeInspection,
    BeforeCandidateReservation,
    BeforeCandidateRevalidation,
    BeforeUnlink,
    AfterDeletion
};

// Optional synchronous cancellation/observation boundary. Returning true
// stops before the next destructive action. The callback owns no capability;
// tests also use it to exercise same-UID substitutions at explicit boundaries.
struct BackupSeriesRotationControl {
    bool (*stopRequested)(void*, BackupSeriesRotationCheckpoint,
        const QString&) noexcept = nullptr;
    void* context = nullptr;
};

struct BackupSeriesRotationRequest {
    QString rootDirectory;
    QByteArray vaultId;
    QString seriesId;
    quint64 retainedVersions = 7;
    std::optional<SnapshotDirectoryIdentity> expectedRoot;
    std::optional<SnapshotDirectoryIdentity> expectedFamily;
    std::optional<SnapshotDirectoryIdentity> expectedSeries;
    // Must be the terminal result delivered for the newly published file.
    // PublishedPath and receipt are revalidated; this struct is not itself a
    // cryptographic capability and only trusted in-process owners may call.
    BackupResult publication;
    BackupSeriesRotationControl control;
};

struct BackupSeriesRotationResult {
    BackupSeriesRotationOutcome outcome = BackupSeriesRotationOutcome::Unknown;
    // Entries for which unlinkat returned success, in actual deletion order.
    QVector<BackupSeriesVersion> deleted;
    // Leading entries in deleted whose containing directory fsync succeeded.
    quint64 durableDeletions = 0;
    QString diagnostic;
};

// Explicit, synchronous and destructive. It is deliberately not connected to
// BackupJob, the automatic coordinator or MainWindow. Call only off the GUI
// thread after a terminal Published result; rotation never changes that result.
class BackupSeriesRotationService final {
public:
    [[nodiscard]] static BackupSeriesRotationResult rotate(
        const BackupSeriesRotationRequest& request);
};

} // namespace passwall::services
