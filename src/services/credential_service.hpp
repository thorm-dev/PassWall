#pragma once

#include "core/crypto_engine.hpp"
#include "models/credential.hpp"

#include <string>
#include <vector>

namespace passwall::services {

class CredentialService {
public:
    // Validation sans mutation ni accès au stockage. Titre et utilisateur
    // doivent contenir autre chose que des blancs Unicode. Le mot de passe
    // est une donnée exacte : seule sa vacuité est interdite, sans trim.
    [[nodiscard]] static bool validate(
        const models::Credential& credential,
        std::string& error);

    [[nodiscard]] static bool add(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        models::Credential& credential,
        std::string& error);

    [[nodiscard]] static bool list(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        std::vector<models::Credential>& credentials,
        std::string& error);

    [[nodiscard]] static bool listSummaries(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        std::vector<models::CredentialSummary>& summaries,
        std::string& error);

    [[nodiscard]] static bool get(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        const models::EntryId& entryId,
        models::Credential& credential,
        std::string& error);

    [[nodiscard]] static bool update(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        const models::Credential& credential,
        std::string& error);

    [[nodiscard]] static bool remove(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        const models::EntryId& entryId,
        std::string& error);
};

} // namespace passwall::services
