
#pragma once

#include "core/crypto_engine.hpp"

#include <string>

namespace passwall::services {

class VaultLifecycleService {
public:
    [[nodiscard]] static bool createVault(
        const std::string& databasePath,
        const std::string& masterPassword,
        core::SecureBuffer& dataKey,
        std::string& error);

    [[nodiscard]] static bool unlockVault(
        const std::string& databasePath,
        const std::string& masterPassword,
        core::SecureBuffer& dataKey,
        std::string& error);
};

} // namespace passwall::services
