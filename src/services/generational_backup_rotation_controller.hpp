#pragma once

#include "services/automatic_backup_coordinator.hpp"
#include "services/backup_series_rotation_service.hpp"

#include <QObject>
#include <QPointer>
#include <QSet>
#include <QVector>

#include <memory>

namespace passwall::services {

struct GenerationalBackupRotationResult {
    quint64 requestId = 0;
    quint64 generation = 0;
    quint64 sessionGeneration = 0;
    GenerationalBackupRequestKind kind =
        GenerationalBackupRequestKind::CrudGeneration;
    QString publishedPath;
    BackupSeriesRotationResult rotation;
};

// Owner-thread bridge between a genuinely settled generational publication
// and the synchronous destructive service. It owns a volatile FIFO, executes
// one rotation at a time off-thread and never changes the backup result.
// Production does not instantiate this component while Historical is active.
class GenerationalBackupRotationController final : public QObject {
    Q_OBJECT
public:
    explicit GenerationalBackupRotationController(
        AutomaticBackupCoordinator& coordinator, QObject* parent = nullptr);
    ~GenerationalBackupRotationController() override;

    [[nodiscard]] bool idle() const noexcept;
    // Normal window close supervises all already accepted publications to a
    // terminal rotation result. New eligible publications from the ongoing
    // backup drain remain accepted until the coordinator itself is terminal.
    void beginShutdownDrain() noexcept;
    // Withdraws only the close intent after the FIFO is terminal. It neither
    // retries nor changes any rotation result.
    [[nodiscard]] bool continueAfterShutdownDrain() noexcept;

signals:
    void rotationSettled(
        passwall::services::GenerationalBackupRotationResult result);
    void busyChanged(bool busy);
    void shutdownDrainCompleted();

private:
    struct Work;
    void consumePublication(MutationBackupResult result);
    void startNext();
    void finishWork(const std::shared_ptr<Work>& work);
    void reject(const MutationBackupResult& publication, QString diagnostic);
    void preferencesChanged(const QString& settingsFile);

    QPointer<AutomaticBackupCoordinator> coordinator_;
    QVector<MutationBackupResult> pending_;
    QSet<quint64> acceptedRequestIds_;
    std::shared_ptr<Work> active_;
    bool shutdownDrainRequested_ = false;
};

} // namespace passwall::services

Q_DECLARE_METATYPE(passwall::services::GenerationalBackupRotationResult)

#ifdef PASSWALL_GUI_TESTING
namespace passwall::tests {
using GenerationalRotationCheckpointHook = void (*)(void*,
    services::BackupSeriesRotationCheckpoint) noexcept;
void setGenerationalRotationCheckpointHook(
    GenerationalRotationCheckpointHook hook, void* context) noexcept;
}
#endif
