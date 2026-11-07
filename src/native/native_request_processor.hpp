#pragma once

#include "core/crypto_engine.hpp"
#include "native/native_vault_access.hpp"

#include <QJsonObject>

#include <cstdint>
#include <span>

namespace passwall::native {

namespace detail {
class NativeRequestResponseBuilder;
}

// Réponse propriétaire du processeur. Elle peut contenir un secret uniquement
// pour get_credential. Le payload est un SecureBuffer non copiable : sa
// propriété ne peut quitter la réponse que par takePayload() sur une rvalue.
class NativeRequestResponse final {
public:
    explicit NativeRequestResponse(
        bool requestVaultActivation = false) noexcept;
    ~NativeRequestResponse();

    NativeRequestResponse(const NativeRequestResponse&) = delete;
    NativeRequestResponse& operator=(const NativeRequestResponse&) = delete;

    NativeRequestResponse(NativeRequestResponse&& other) noexcept;
    NativeRequestResponse& operator=(NativeRequestResponse&& other) noexcept;

    [[nodiscard]] bool hasPayload() const noexcept;
    [[nodiscard]] std::span<const unsigned char> payloadView() const noexcept;
    // Une génération non nulle lie cette réponse à la session qui a produit
    // son payload. Cette métadonnée ne contient aucun secret.
    [[nodiscard]] bool hasSessionGeneration() const noexcept;
    [[nodiscard]] std::uint64_t sessionGeneration() const noexcept;

    // Transfère le buffer au composant de transport. Après cet appel, cette
    // réponse ne possède plus de payload à effacer.
    [[nodiscard]] core::SecureBuffer takePayload() && noexcept;

    // Utilisé par le propriétaire courant si la réponse ne doit finalement
    // pas être transmise, ainsi que par le destructeur.
    void wipePayload() noexcept;

    bool requestVaultActivation = false;

private:
    friend class detail::NativeRequestResponseBuilder;

    explicit NativeRequestResponse(
        core::SecureBuffer&& payload,
        bool requestVaultActivation,
        std::uint64_t sessionGeneration) noexcept;

    core::SecureBuffer payload_{0};
    std::uint64_t sessionGeneration_ = 0;
};

// Traite la logique Native Messaging sans dépendre de MainWindow, de widgets
// Qt ou de CredentialService. NativeVaultAccess fournit le seul accès au
// coffre et garantit la validité de la session représentée par VaultLease.
class NativeRequestProcessor final {
public:
    explicit NativeRequestProcessor(NativeVaultAccess& vaultAccess) noexcept;

    [[nodiscard]] NativeRequestResponse handle(
        const QJsonObject& request) const;

private:
    NativeVaultAccess& vaultAccess_;
};

} // namespace passwall::native
