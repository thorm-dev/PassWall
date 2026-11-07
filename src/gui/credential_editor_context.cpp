#include "credential_editor_context.hpp"

#include <QDialog>
#include <QLineEdit>
#include <QSignalBlocker>
#include <QTextEdit>

#include <sodium.h>

namespace passwall::gui {

namespace detail {

void wipeString(std::string& value) noexcept
{
    if (!value.empty()) {
        sodium_memzero(value.data(), value.size());
    }
    value.clear();
}

void wipeCredential(models::Credential& credential) noexcept
{
    wipeString(credential.title);
    wipeString(credential.url);
    wipeString(credential.username);
    wipeString(credential.password);
    wipeString(credential.notes);
    sodium_memzero(credential.id.data(), credential.id.size());
    credential.version = 0;
}

} // namespace detail

CredentialEditorContext::CredentialEditorContext(
    models::Credential& credential,
    native::VaultLease lease)
    : credential_(credential)
    , lease_(lease)
{
}

CredentialEditorContext::~CredentialEditorContext()
{
    detail::wipeCredential(credential_);
}

void CredentialEditorContext::bindDialog(
    QDialog& dialog,
    QLineEdit& title,
    QLineEdit& url,
    QLineEdit& username,
    QLineEdit& password,
    QTextEdit& notes)
{
    dialog_ = &dialog;
    title_ = &title;
    url_ = &url;
    username_ = &username;
    password_ = &password;
    notes_ = &notes;
    rejectionRequested_ = false;
    if (invalidated_) {
        // Un contexte invalidé ne peut pas être réutilisé avec un nouvel UI.
        clearDialogFields();
        rejectDialog();
    }
}

void CredentialEditorContext::invalidate()
{
    if (invalidated_) {
        return;
    }
    // Fermer d'abord l'autorisation de sauvegarder, avant tout signal Qt.
    invalidated_ = true;
    detail::wipeCredential(credential_);
    clearDialogFields();
}

void CredentialEditorContext::rejectDialog()
{
    invalidate();
    if (rejectionRequested_) {
        return;
    }
    rejectionRequested_ = true;
    // clear() réduit la durée de vie des données accessibles, mais ne garantit
    // pas l'effacement des anciennes allocations internes de Qt.
    if (!dialog_.isNull()) {
        dialog_->setEnabled(false);
    }
    if (!dialog_.isNull()) {
        dialog_->reject();
    }
}

void CredentialEditorContext::clearDialogFields()
{
    const auto clearField = [](const auto& field) {
        if (!field.isNull()) {
            const QSignalBlocker blocker(field.data());
            field->clear();
        }
    };
    clearField(title_);
    clearField(url_);
    clearField(username_);
    clearField(password_);
    clearField(notes_);
}

bool CredentialEditorContext::isInvalidated() const noexcept
{
    return invalidated_;
}

bool CredentialEditorContext::canCommit(native::VaultLease current) const noexcept
{
    return !invalidated_ && lease_.unlocked && lease_.generation != 0 &&
           current.unlocked && current.generation == lease_.generation;
}

} // namespace passwall::gui
