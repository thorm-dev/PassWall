#pragma once

#include "services/global_backup_preferences_store.hpp"

#include <QObject>
#include <QPointer>

namespace passwall::gui {

class GlobalBackupPreferencesDialog;

// Isolated controller for the future global preferences entry point. It has no
// MainWindow or backup-engine dependency and therefore cannot select a trigger
// mode, launch a worker or modify the historical per-vault registry.
class GlobalBackupPreferencesController final : public QObject {
    Q_OBJECT
public:
    explicit GlobalBackupPreferencesController(
        services::GlobalBackupPreferencesStore store = {},
        QObject* parent = nullptr);
    ~GlobalBackupPreferencesController() override;

    void open();
    // One-shot, non-modal initial proposal. The physical preferences file is
    // read off the GUI thread and the dialog is shown only for a non-Valid
    // result. No refusal state is persisted; open() remains available later.
    void offerInitialConfiguration();

signals:
    // Full authoritative read result for the backup coordinator. The status
    // signal below remains presentation-only and deliberately carries no
    // configuration or provenance.
    void configurationRead(
        passwall::services::GlobalBackupPreferencesResult configuration);
    void readSettled(passwall::services::GlobalBackupPreferencesStatus status);
    void writeSettled(passwall::services::GlobalBackupPreferencesStatus status);

private:
    void ensureDialog();
    void load();
    void startLoad(bool onlyIfConfigurationNeeded);
    void save();

    services::GlobalBackupPreferencesStore store_;
    QPointer<GlobalBackupPreferencesDialog> dialog_;
    quint64 operationSerial_ = 0;
    bool reading_ = false;
    bool writing_ = false;
    bool initialOfferMade_ = false;
};

} // namespace passwall::gui
