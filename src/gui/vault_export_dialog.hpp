#pragma once

#include "services/backup_protocol.hpp"
#include <QDialog>

class QLabel;
class QProgressBar;
class QPushButton;

namespace passwall::gui {
// No source path, key or credential. Owned by MainWindow, not parented to it:
// an unrelated system/manual lock must not reject this keyless operation UI.
class VaultExportDialog final : public QDialog {
    Q_OBJECT
public:
    VaultExportDialog();
    void cancellationPending();
    void showResult(const services::BackupResult& result, bool closing);
    void reject() override;
signals:
    void cancellationRequested();
private:
    QLabel* status_;
    QProgressBar* activity_;
    QPushButton* button_;
    bool running_ = true;
    bool cancellationPending_ = false;
};
} // namespace passwall::gui
