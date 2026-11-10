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
signals:
    // Completion of the real asynchronous preparation, including a stale reply.
    void preparationSettled(bool current);
private:
    void load();
    void prepare();
    void execute();
    void cancel();
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
    QString source_, precaution_, principalId_;
    QSet<QString> uncertain_; // No GUI retry of an unconfirmed operation in this application lifetime.
    quint64 generation_ = 0;
    enum class Stage { Idle, Loading, Choosing, Preparing, Password, Running, Result } stage_ = Stage::Idle;
    bool cleanup_ = false, cancelled_ = false, engaged_ = false, finalReported_ = false;
};
} // namespace passwall::gui
