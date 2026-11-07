#pragma once

#include "models/credential.hpp"
#include "native/native_vault_access.hpp"

#include <QObject>
#include <QPointer>

#include <string>

class QDialog;
class QLineEdit;
class QTextEdit;

namespace passwall::gui {

namespace detail {
void wipeString(std::string& value) noexcept;
void wipeCredential(models::Credential& credential) noexcept;
} // namespace detail

// Contexte local : le credential emprunté doit vivre plus longtemps que lui.
// Aucune copie du credential n'est conservée. Les widgets sont observés par
// QPointer et les connexions Qt utilisent ce contexte comme récepteur.
class CredentialEditorContext final : public QObject {
public:
    CredentialEditorContext(
        models::Credential& credential,
        native::VaultLease lease);
    ~CredentialEditorContext() override;

    void bindDialog(
        QDialog& dialog,
        QLineEdit& title,
        QLineEdit& url,
        QLineEdit& username,
        QLineEdit& password,
        QTextEdit& notes);
    void invalidate();
    void rejectDialog();

    [[nodiscard]] bool isInvalidated() const noexcept;
    [[nodiscard]] bool canCommit(native::VaultLease current) const noexcept;

private:
    void clearDialogFields();

    models::Credential& credential_;
    const native::VaultLease lease_;
    bool invalidated_ = false;
    bool rejectionRequested_ = false;
    QPointer<QDialog> dialog_;
    QPointer<QLineEdit> title_;
    QPointer<QLineEdit> url_;
    QPointer<QLineEdit> username_;
    QPointer<QLineEdit> password_;
    QPointer<QTextEdit> notes_;
};

} // namespace passwall::gui
