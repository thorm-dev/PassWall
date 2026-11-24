#pragma once

#include "services/automatic_backup_coordinator.hpp"
#include "services/generational_backup_rotation_controller.hpp"

#include <QObject>
#include <QHash>
#include <QPointer>

#include <optional>

class QDialog;
class QWidget;

namespace passwall::gui {

// Test-route-only, in-memory presentation of the existing generational
// coordinator. It owns no token, reservation, retry policy or persistent
// history: the coordinator remains the sole authority for explicit resumption.
class GenerationalBackupStatusController final : public QObject {
    Q_OBJECT
public:
    GenerationalBackupStatusController(
        services::AutomaticBackupCoordinator& coordinator,
        services::GenerationalBackupRotationController& rotation,
        QWidget* parent);
    ~GenerationalBackupStatusController() override;

    void setAuthenticatedVault(const services::VaultFileIdentity& vault);
    void invalidateAuthenticatedSession() noexcept;
    void preferencesReadSettled(
        services::GlobalBackupPreferencesStatus status);
    void preferencesWriteSettled(
        services::GlobalBackupPreferencesStatus status);
    void open();

    [[nodiscard]] QString backupStatus() const { return backupStatus_; }
    [[nodiscard]] QString backupDetail() const { return backupDetail_; }
    [[nodiscard]] QString lastBackupResultStatus() const {
        return lastBackupResultStatus_;
    }
    [[nodiscard]] QString lastBackupResultDetail() const {
        return lastBackupResultDetail_;
    }
    [[nodiscard]] QString rotationStatus() const { return rotationStatus_; }
    [[nodiscard]] QString rotationDetail() const { return rotationDetail_; }
    [[nodiscard]] QString configurationStatus() const {
        return configurationStatus_;
    }
    [[nodiscard]] bool retryAvailable() const noexcept;

signals:
    void presentationChanged(QString summary, bool attentionRequired);

private:
    struct ObservedRequest {
        services::VaultFileIdentity vault;
        services::GenerationalBackupRequestKind kind =
            services::GenerationalBackupRequestKind::CrudGeneration;
        quint64 mutationGeneration = 0;
        quint64 sessionGeneration = 0;
        QString publishedPath;
    };

    void consumeOffer(services::GenerationalBackupRequestOffer offer);
    void consumeOperationState(services::GenerationalOperationState state);
    void consumeBackupResult(services::MutationBackupResult result);
    void consumeSuspension(
        services::GenerationalBackupSuspensionState state);
    void consumeRotation(
        services::GenerationalBackupRotationResult result);
    void requestRetry();
    void requestManualBackup();
    void resetForDifferentVault();
    void updateDialog();
    void publishPresentation();
    [[nodiscard]] bool tracksPath(const QString& path) const;
    [[nodiscard]] bool suspensionMatchesCurrentVault() const noexcept;

    QPointer<services::AutomaticBackupCoordinator> coordinator_;
    QPointer<services::GenerationalBackupRotationController> rotation_;
    QPointer<QDialog> dialog_;
    std::optional<services::VaultFileIdentity> trackedVault_;
    std::optional<services::GenerationalBackupSuspensionState> suspension_;
    QHash<quint64, ObservedRequest> acceptedRequests_;
    QHash<quint64, ObservedRequest> publishedRequests_;
    QHash<quint64, services::GenerationalBackupRotationResult>
        deferredRotationResults_;
    bool authenticatedSessionCurrent_ = false;
    bool terminalBackupResultObserved_ = false;
    bool backupAttentionRequired_ = false;
    bool rotationAttentionRequired_ = false;
    bool configurationAttentionRequired_ = false;
    QString backupStatus_;
    QString backupDetail_;
    QString lastBackupResultStatus_;
    QString lastBackupResultDetail_;
    QString rotationStatus_;
    QString rotationDetail_;
    QString configurationStatus_;
};

} // namespace passwall::gui
