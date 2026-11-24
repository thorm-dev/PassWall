#pragma once

#include "services/vault_snapshot_service.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QVector>

#include <optional>

namespace passwall::services {

enum class BackupSeriesInspectionOutcome {
    Complete,
    InvalidRequest,
    Unsafe
};

// Transient evidence for a future destructive boundary. It is neither
// persisted nor sufficient to authorize deletion: that boundary must revalidate
// the directory, named entry and physical identity, without reading old contents.
// Device/inode values can be reused and same-UID processes can race these
// observations; they are evidence for revalidation, not an atomic capability.
struct BackupSeriesFileIdentity {
    quint64 device = 0;
    quint64 inode = 0;
    quint64 size = 0;
    quint64 owner = 0;
    quint64 linkCount = 0;
    quint32 permissions = 0;
    qint64 modifiedSeconds = 0;
    quint32 modifiedNanoseconds = 0;
    qint64 changedSeconds = 0;
    quint32 changedNanoseconds = 0;
    bool operator==(const BackupSeriesFileIdentity&) const = default;
};

struct BackupSeriesVersion {
    QString fileName;
    QString path;
    // UTC is informational; the generation number determines rotation order.
    QDateTime timestampUtc;
    quint64 generation = 0;
    BackupSeriesFileIdentity identity;
    bool operator==(const BackupSeriesVersion&) const = default;
};

struct BackupSeriesObjectIssue {
    QString fileName;
    QString diagnostic;
    bool operator==(const BackupSeriesObjectIssue&) const = default;
};

enum class BackupSeriesInspectionCheckpoint {
    CandidateValidated,
    BeforeFinalRevalidation
};

// Optional synchronous observation hook. It owns nothing and grants no
// authority. Production callers normally omit it; deterministic tests use it
// to exercise concurrent disappearance/substitution before final revalidation.
struct BackupSeriesInspectionObserver {
    void (*reached)(void*, BackupSeriesInspectionCheckpoint,
        const QString&) noexcept = nullptr;
    void* context = nullptr;
};

struct BackupSeriesInspectionRequest {
    QString rootDirectory;
    QByteArray vaultId;
    QString seriesId;
    quint64 retainedVersions = 7;
    std::optional<SnapshotDirectoryIdentity> expectedRoot;
    std::optional<SnapshotDirectoryIdentity> expectedFamily;
    std::optional<SnapshotDirectoryIdentity> expectedSeries;
    BackupSeriesInspectionObserver observer;
};

struct BackupSeriesInspectionResult {
    BackupSeriesInspectionOutcome outcome = BackupSeriesInspectionOutcome::Unsafe;
    QString rootDirectory;
    QString familyDirectory;
    QString seriesDirectory;
    SnapshotDirectoryIdentity rootIdentity;
    SnapshotDirectoryIdentity familyIdentity;
    SnapshotDirectoryIdentity seriesIdentity;
    // Both vectors are ordered from the lowest generation number to the highest.
    // Admissible here means naming and physical checks only, not vault integrity.
    QVector<BackupSeriesVersion> admissible;
    QVector<BackupSeriesVersion> excess;
    // Clearly unmanaged names are ignored without making an otherwise complete
    // calculation unsafe. Canonical-looking but unverifiable objects are
    // ambiguities and suppress the entire excess selection.
    QVector<BackupSeriesObjectIssue> outsideConvention;
    QVector<BackupSeriesObjectIssue> ambiguities;
    QString diagnostic;

    [[nodiscard]] bool selectionComplete() const noexcept
    {
        return outcome == BackupSeriesInspectionOutcome::Complete;
    }
};

// Synchronous and potentially blocking: callers must keep it off the GUI
// thread. This service lists directories and reads file metadata only; it never
// opens or reads vault contents, and has no deletion/rename/create API.
class BackupSeriesInspector final {
public:
    [[nodiscard]] static BackupSeriesInspectionResult inspect(
        const BackupSeriesInspectionRequest& request);
};

} // namespace passwall::services
