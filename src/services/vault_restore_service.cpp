#include "services/vault_restore_service.hpp"

#include "services/credential_service.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

namespace passwall::services {
namespace {
struct Authentication {
    std::span<const unsigned char> password;
};

bool authenticatePrivateCopy(void* context, const std::string& privatePath, std::string& error)
{
    const auto password = static_cast<const Authentication*>(context)->password;
    VaultKeyMetadata metadata;
    if (!storage::VaultStorage::readMetadata(privatePath, metadata, error)) return false;
    core::SecureBuffer key(0);
    // Existing bounded Argon2id + AEAD DEK unwrap; no GUI/session state involved.
    const auto code = VaultKeyService::unlock(password, metadata, key);
    if (code != core::CryptoError::None) {
        error = code == core::CryptoError::AuthenticationFailed
            ? "Mot de passe maître incorrect ou données cryptographiques altérées."
            : "Authentification du coffre impossible : paramètres invalides ou ressources indisponibles.";
        return false;
    }
    return CredentialService::authenticateAll(privatePath, key, error);
    // key and every entry have been wiped before the engine can publish.
}
} // namespace

bool VaultRestoreService::restoreBackup(const std::string& backupPath,
    const std::string& destinationPath, std::span<const unsigned char> masterPassword,
    SnapshotResult& result) noexcept
{
    result.publication = SnapshotPublication::NotPublished;
    result.diagnostic.clear();
    try {
        if (masterPassword.empty() || masterPassword.data() == nullptr) {
            result.diagnostic = "Le mot de passe maître de la sauvegarde est obligatoire.";
            return false;
        }
        Authentication authentication{masterPassword};
        return VaultSnapshotService::createSnapshot(backupPath, destinationPath, result, {},
            {&authenticatePrivateCopy, &authentication});
    } catch (...) {
        // Snapshot RAII and authentication RAII already ran. Never print what()
        // or guess that a final file is absent after irreversible publication.
        try { result.diagnostic = "Erreur interne de restauration ; consulter l'état de publication."; }
        catch (...) { result.diagnostic.clear(); }
        return result.publication == SnapshotPublication::Published;
    }
}
} // namespace passwall::services
