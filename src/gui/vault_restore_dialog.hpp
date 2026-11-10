#pragma once
#include "services/restore_job.hpp"
#include "services/vault_preferences_store.hpp"
#include <QDialog>
#include <QSet>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QWidget;

namespace passwall::gui {
// Independent modeless window. No authority, key or durable password copy.
class VaultRestoreDialog final : public QDialog {
    Q_OBJECT
public:
    VaultRestoreDialog();
    ~VaultRestoreDialog() override;
    void setRegistrations(const QVector<services::VaultRegistration>& records, const QSet<QString>& uncertain = {});
    QString selectedId() const;
    QString source() const;
    QString precaution() const;
    bool confirmed() const;
    bool hasPassword() const;
    core::SecureBuffer takePassword();
    void clearPassword() noexcept;
    void choosing();
    void preparing();
    void awaitingPassword();
    void running(const QString& message, bool cancellationPossible = true);
    void validationError(const QString& message);
    void showError(const QString& message);
    void showResult(const services::RestoreResult&, bool terminated, bool cleaned);
    static QString resultMessage(const services::RestoreResult&, bool terminated, bool cleaned);
    void reject() override;
signals:
    void preparationRequested();
    void executionRequested();
    void cancellationRequested();
    void closingRequested();
private:
    void updateSelection();
    void chooseFile(QLineEdit*, bool save);
    QWidget* choices_;
    QWidget* precautionRow_;
    QComboBox* principal_;
    QLineEdit* source_;
    QLineEdit* precaution_;
    QLineEdit* password_;
    QCheckBox* confirmation_;
    QLabel* policy_;
    QLabel* status_;
    QProgressBar* activity_;
    QPushButton* primary_;
    QPushButton* cancel_;
    QVector<services::VaultRegistration> records_;
    QSet<QString> uncertain_;
    enum class Stage { Choosing, Preparing, Password, Running, Result } stage_ = Stage::Preparing;
};
} // namespace passwall::gui
