#pragma once
#include "core/crypto_engine.hpp"
#include "services/vault_replacement_service.hpp"
#include <QObject>
#include <QPointer>
namespace passwall::gui { class MainWindow; }

namespace passwall::services {
class RestoreProcessSession;
enum class RestoreOutcome { Refused, TransportFailed, EngineResult, SourceAuthenticationFailed, Unknown };
enum class RestoreCleanup { Pending, ConfirmedByWorker, ConfirmedProcessTermination };
struct RestoreResult {
    RestoreOutcome outcome = RestoreOutcome::Unknown;
    ReplacementResult replacement;
    QString diagnostic;
    // Never interpret the default NotReplaced as evidence after a lost result.
    // A known business result can coexist with uncertain/abnormal supervision.
    bool replacementStatusKnown = false;
};

// Single-use, owner-thread facade. Destruction cancels without waiting; its
// independent supervisor retains the authority, locks and QProcess until reap.
// No secret is ever passed to QProcess::write(). No healthy-run time limit.
class RestoreJob final : public QObject {
    Q_OBJECT
public:
    explicit RestoreJob(QObject* parent = nullptr);
    explicit RestoreJob(QString trustedWorker, QObject* parent = nullptr);
    ~RestoreJob() override;
    bool start(VaultReplacementAuthorization authority, const QString& source,
               core::SecureBuffer password, const QString& precaution);
    void cancel();
    [[nodiscard]] bool isActive() const noexcept { return active_; }
    [[nodiscard]] RestoreCleanup cleanup() const noexcept { return cleanup_; }
    [[nodiscard]] QString startError() const { return startError_; }
    static QString siblingWorkerPath();
signals:
    void phaseChanged(passwall::services::ReplacementCheckpoint phase);
    void cancellationReceived();
    void secretsCleared(passwall::services::RestoreCleanup proof);
    void resultReceived(passwall::services::RestoreResult result); // NOT termination/success.
    void finished(passwall::services::RestoreResult result);
    void processTerminated();
private:
    friend class RestoreProcessSession;
    friend class gui::MainWindow;
    std::function<void(RestoreCleanup)> cleanupObserver_;
    std::function<void()> terminationObserver_;
    QString worker_, startError_;
    QPointer<RestoreProcessSession> session_;
    bool started_ = false, active_ = false;
    RestoreCleanup cleanup_ = RestoreCleanup::Pending;
};
} // namespace passwall::services
