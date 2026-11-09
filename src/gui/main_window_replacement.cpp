#include "gui/main_window.hpp"
#include "services/vault_preferences_store.hpp"
#include "services/automatic_backup_coordinator.hpp"
#include <QScopeGuard>

namespace passwall::gui {
bool MainWindow::recoveryAllowsCurrentSession() const noexcept
{
    try {
        QString error;
        return services::VaultPreferencesStore().recoveryAccess(vaultPath_, error)
            == services::VaultRecoveryAccess::Allowed;
    } catch (...) { return false; }
}
void MainWindow::requestReplacementAuthorization(const QString& localId,
    std::function<void(services::VaultReplacementAuthorization, QString)> completion)
{
    using Authorization = services::VaultReplacementAuthorization;
    if (!isSessionThread()) qFatal("Replacement preparation must run on the vault owner's thread");
    if (!completion) return;
    const QPointer<MainWindow> guarded(this);
    const auto deliver = [&](services::VaultReplacementAuthorization authority, QString error) noexcept {
        try { completion(std::move(authority), std::move(error)); } catch (...) {}
    };
    if (externalLockBlocksAccess() || vaultLockInProgress_ || !ensureLifecycleProtection() || !guarded
#ifdef Q_OS_LINUX
        || hasOpenCredentialEditor() || exportInProgress_
        || (automaticBackup_ && automaticBackup_->isActive())
#endif
    ) {
        deliver({}, QStringLiteral("Une opération incompatible ou un éditeur est encore actif."));
        return;
    }
    // Set before registry/reservation work. No nested UI loop, no blocking flock.
    replacementTransition_ = true;
    bool handedOff = false;
    const auto restore = qScopeGuard([&] { if (guarded && !handedOff) guarded->replacementTransition_ = false; });
    std::shared_ptr<Authorization::State> state;
    try {
        QString error;
        state = Authorization::reserve(services::VaultPreferencesStore(), localId,
            [guarded] { return guarded && guarded->isSessionThread()
                && guarded->hasLifecycleProtection() && guarded->isFullyLocked(); }, error);
        if (!state) { deliver({}, error); return; }
        if (!Authorization::targetsSession(state, vaultPath_)) {
            Authorization::revoke(state);
            deliver({}, QStringLiteral("Verrouillez le coffre actif avant de préparer un autre coffre."));
            return;
        }
        replacement_ = state;
        requestLock([guarded, state, completion](bool cleaned) mutable {
            Authorization authority;
            QString error;
            try {
                if (guarded && cleaned && guarded->isFullyLocked()
                    && guarded->hasLifecycleProtection() && Authorization::active(state))
                    authority = Authorization::acknowledge(state, error);
                else error = QStringLiteral("Nettoyage non acquitté ou préparation invalidée.");
            } catch (...) {
                error = QStringLiteral("Erreur de préparation ; aucune publication autorisée.");
            }
            if (guarded) guarded->replacementTransition_ = false;
            if (!authority.state_) Authorization::revoke(state);
            completion(std::move(authority), error);
        }, LockReason::ReplacementPreparation);
        handedOff = true;
    } catch (...) {
        Authorization::revoke(state);
        deliver({}, QStringLiteral("Impossible de préparer le remplacement du coffre."));
    }
}
} // namespace passwall::gui
