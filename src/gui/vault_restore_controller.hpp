#pragma once
#include "services/restore_job.hpp"
#include "services/vault_preferences_store.hpp"
#include <QObject>
#include <QPointer>
#include <optional>
#include <QSet>

namespace passwall::gui {
class MainWindow;
class VaultRestoreDialog;
// GUI coordination only: no authority factory, SQL, crypto or password storage.
class VaultRestoreController final : public QObject {
    Q_OBJECT
public:
    explicit VaultRestoreController(MainWindow&);
    ~VaultRestoreController() override;
    void open();
    void onLock(bool security);
    bool hasSensitiveInput() const;
    void recoveryConfirmed(const QString& localId);
signals:
    // Completion of the real asynchronous preparation, including a stale reply.
    void preparationSettled(bool current);
private:
    enum class AutomaticAbandonReason {
        Cancellation, AuthenticationRejected, NonEngagedFailure, StartupRefused
    };
    void load();
    void prepare();
    void authorizeAfterPrevalidation(quint64 serial, quint64 securityGeneration);
    void execute();
    void cancel();
    void abandonPrepared(AutomaticAbandonReason);
    void fail(const QString&);
    void phase(services::ReplacementCheckpoint);
    void displayResult(bool terminated);
    MainWindow& owner_;
    QPointer<VaultRestoreDialog> dialog_;
    QPointer<services::RestoreJob> job_;
    QVector<services::VaultRegistration> records_;
    services::VaultRegistration selected_;
    services::VaultReplacementAuthorization authority_;
    std::optional<services::RestoreResult> result_;
    QString source_, precaution_, principalId_, operationId_;
    QString automaticAbandonDiagnostic_;
    QSet<QString> uncertain_; // No GUI retry of an unconfirmed operation in this application lifetime.
    quint64 generation_ = 0;
    enum class Stage { Idle, Loading, Choosing, Prevalidating, Preparing, Password, Running, Resolving, Result } stage_ = Stage::Idle;
    bool cleanup_ = false, cancelled_ = false, engaged_ = false, finalReported_ = false;
    std::optional<AutomaticAbandonReason> automaticAbandonPending_;
};
} // namespace passwall::gui
