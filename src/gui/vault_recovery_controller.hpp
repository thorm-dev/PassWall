#pragma once
#include "services/vault_replacement_service.hpp"
#include <QObject>
#include <QPointer>

class QDialog;
class QComboBox;
class QLabel;
class QPushButton;
class QCheckBox;
class QProgressBar;
namespace passwall::gui {
class MainWindow;
// Presentation only. No SQL, secrets, marker writes or replacement authority.
class VaultRecoveryController final : public QObject {
    Q_OBJECT
public:
    explicit VaultRecoveryController(MainWindow&);
    ~VaultRecoveryController() override;
    void open();
signals:
    void settled(bool current);
private:
    void load();
    void inspect();
    void resolve();
    void perform(services::ReplacementRecoveryAction);
    void display(const services::ReplacementRecoveryResult&, bool executed);
    void busy(bool);
    MainWindow& owner_;
    QPointer<QDialog> dialog_;
    QComboBox* selection_ = nullptr;
    QLabel* status_ = nullptr;
    QPushButton *inspect_ = nullptr, *resolve_ = nullptr, *reload_ = nullptr;
    QCheckBox* confirmation_ = nullptr;
    QProgressBar* activity_ = nullptr;
    QVector<services::VaultRegistration> records_;
    QString local_, operation_;
    quint64 generation_ = 0;
    bool active_ = false;
    services::ReplacementRecoveryAction offered_ = services::ReplacementRecoveryAction::Inspect;
};
}
