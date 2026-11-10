#pragma once
#include "services/vault_preferences_store.hpp"
#include <QDialog>

class QComboBox;
class QCheckBox;
class QLineEdit;
class QSpinBox;
class QPushButton;
class QLabel;
namespace passwall::gui {
// Presentation only. No SQL, settings writer, reservation or copy engine.
class VaultBackupSettingsDialog final : public QDialog {
    Q_OBJECT
public:
    VaultBackupSettingsDialog();
    QString selectedId() const;
    void setRecords(const QVector<services::VaultRegistration>&, const QString& selected);
    void setPreferences(const services::VaultBackupPreferences&);
    bool preferences(services::VaultBackupPreferences&) const;
    void setActions(bool editable, bool resumable);
    void state(const QString&, const QString& rotation);
    void feedback(const QString&);
signals:
    void selectionChanged(QString);
    void saveRequested();
    void resumeRequested();
    void reloadRequested();
    void draftChanged();
private:
    QComboBox* vault_;
    QCheckBox* automatic_;
    QLineEdit* directory_;
    QSpinBox* retained_;
    QPushButton *save_, *resume_, *browse_;
    QLabel *state_, *rotation_, *feedback_;
};
}
