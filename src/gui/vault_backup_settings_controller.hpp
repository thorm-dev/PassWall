#pragma once
#include "services/automatic_backup_coordinator.hpp"
#include <QObject>
#include <QPointer>
#include <optional>

namespace passwall::gui {
class MainWindow;
class VaultBackupSettingsDialog;
class VaultBackupSettingsController final : public QObject {
    Q_OBJECT
public:
    explicit VaultBackupSettingsController(MainWindow&);
    ~VaultBackupSettingsController() override;
    void open();
signals:
    void readSettled(bool current);
    void writeSettled(QString localId, bool durable);
private:
    void load(bool resetForm);
    void refresh();
    void updateActions();
    void save();
    void resume();
    MainWindow& owner_;
    services::VaultPreferencesStore store_;
    QPointer<VaultBackupSettingsDialog> dialog_;
    std::optional<services::VaultRegistration> displayed_, current_;
    QMap<QString, services::BackupResult> results_; // Observed outcomes only, never authorizations.
    QMap<QString, QString> diagnostics_;
    quint64 selection_ = 0, read_ = 0;
    bool reading_ = false, writing_ = false, refreshQueued_ = false;
};
}
