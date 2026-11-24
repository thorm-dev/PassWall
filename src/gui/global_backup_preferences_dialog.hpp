#pragma once

#include "services/global_backup_preferences_store.hpp"

#include <QDialog>

class QLabel;
class QLineEdit;
class QPushButton;

namespace passwall::gui {

// Presentation only. Persistence and destination admission remain service
// responsibilities; this dialog never creates or changes the selected root.
class GlobalBackupPreferencesDialog final : public QDialog {
    Q_OBJECT
public:
    explicit GlobalBackupPreferencesDialog(QWidget* parent = nullptr);

    void setPreferences(const services::GlobalBackupPreferences& preferences);
    [[nodiscard]] bool preferences(
        services::GlobalBackupPreferences& output, QString& diagnostic) const;
    void setBusy(bool busy);
    void setStatus(const QString& text);
    void setFeedback(const QString& text);

signals:
    void saveRequested();
    void reloadRequested();
    void draftChanged();

private:
    QLineEdit* rootDirectory_ = nullptr;
    QLineEdit* retainedVersions_ = nullptr;
    QPushButton* browse_ = nullptr;
    QPushButton* save_ = nullptr;
    QPushButton* reload_ = nullptr;
    QLabel* status_ = nullptr;
    QLabel* feedback_ = nullptr;
};

} // namespace passwall::gui
