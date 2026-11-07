
#pragma once

#include "core/crypto_engine.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace passwall::services
{
inline constexpr int VaultFormatVersion = 1;
inline constexpr std::uint64_t VaultArgon2Operations = 3;
inline constexpr std::size_t VaultArgon2Memory = 256ULL * 1024 * 1024;
inline constexpr std::size_t WrappedKeySize = 32 + 16;

struct VaultKeyMetadata {
    std::array<unsigned char, 16> vaultId{};
    core::Salt salt{};
    std::uint64_t operationsLimit = VaultArgon2Operations;
    std::size_t memoryLimit = VaultArgon2Memory;
    int formatVersion = VaultFormatVersion;
    core::Nonce wrapNonce{};
    std::array<unsigned char, WrappedKeySize> wrappedDek{};
};

class VaultKeyService {
public:
    [[nodiscard]] static core::CryptoError create(
        std::span<const unsigned char> masterPassword,
        VaultKeyMetadata& metadata,
        core::SecureBuffer& dataKey);

    [[nodiscard]] static core::CryptoError unlock(
        std::span<const unsigned char> masterPassword,
        const VaultKeyMetadata& metadata,
        core::SecureBuffer& dataKey);
};

} // namespace passwall::services
