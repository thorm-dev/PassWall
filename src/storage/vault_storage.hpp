
#pragma once

#include "services/vault_key_service.hpp"

#include <string>

namespace passwall::storage {

class VaultStorage {
public:
    [[nodiscard]] static bool createSchema(
        const std::string& databasePath,
        std::string& error);

    [[nodiscard]] static bool writeMetadata(
        const std::string& databasePath,
        const services::VaultKeyMetadata& metadata,
        std::string& error);

    [[nodiscard]] static bool readMetadata(
        const std::string& databasePath,
        services::VaultKeyMetadata& metadata,
        std::string& error);
};

} // namespace passwall::storage
