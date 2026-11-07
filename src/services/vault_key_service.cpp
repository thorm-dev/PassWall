
#include "services/vault_key_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

namespace passwall::services {
namespace {

using core::CryptoEngine;
using core::CryptoError;
using core::EncryptedData;
using core::Key;
using core::SecureBuffer;

constexpr std::array<unsigned char, 20> WrapPurpose = {
    'P', 'a', 's', 's', 'W', 'a', 'l', 'l', '-',
    'D', 'E', 'K', '-', 'w', 'r', 'a', 'p', '-', 'v', '1'
};

using AssociatedData = std::array<unsigned char, 40>;

// Efface automatiquement une clé temporaire à la sortie de sa portée.
class KeyWiper
{
public:
    explicit KeyWiper(Key& key) noexcept
        : key_(key)
    {
    }

    ~KeyWiper() noexcept
    {
        sodium_memzero(key_.data(), key_.size());
    }

    KeyWiper(const KeyWiper&) = delete;
    KeyWiper& operator=(const KeyWiper&) = delete;

private:
    Key& key_;
};

AssociatedData makeAssociatedData(const VaultKeyMetadata& metadata)
{
    AssociatedData data{};

    std::copy(metadata.vaultId.begin(), metadata.vaultId.end(), data.begin());

    const auto version = static_cast<std::uint32_t>(metadata.formatVersion);

    data[16] = static_cast<unsigned char>(version & 0xFF);
    data[17] = static_cast<unsigned char>((version >> 8) & 0xFF);
    data[18] = static_cast<unsigned char>((version >> 16) & 0xFF);
    data[19] = static_cast<unsigned char>((version >> 24) & 0xFF);

    std::copy(WrapPurpose.begin(), WrapPurpose.end(), data.begin() + 20);

    return data;
}

bool validMetadata(const VaultKeyMetadata& metadata)
{
    if (metadata.formatVersion != VaultFormatVersion) {
        return false;
    }

    // Bornes applicatives : ne jamais accepter des paramètres
    // arbitrairement élevés provenant d'un fichier SQLite modifié.
    if (metadata.operationsLimit < 3 ||
        metadata.operationsLimit > 4) {
        return false;
    }

    if (metadata.memoryLimit < 256ULL * 1024 * 1024 ||
        metadata.memoryLimit > 512ULL * 1024 * 1024) {
        return false;
    }

    return true;
}

} // namespace

CryptoError VaultKeyService::create(
    std::span<const unsigned char> masterPassword,
    VaultKeyMetadata& metadata,
    SecureBuffer& dataKey)
{
    metadata = VaultKeyMetadata{};

    if (masterPassword.empty() || masterPassword.data() == nullptr) {
        return CryptoError::InvalidInput;
    }

    if (!CryptoEngine::initialize()) {
        return CryptoError::InitializationFailed;
    }

    VaultKeyMetadata candidate{};
    Key wrappingKey{};
    Key rawDataKey{};

    KeyWiper wrappingKeyWiper(wrappingKey);
    KeyWiper rawDataKeyWiper(rawDataKey);

    randombytes_buf(candidate.vaultId.data(), candidate.vaultId.size());
    randombytes_buf(candidate.salt.data(), candidate.salt.size());

    candidate.operationsLimit = VaultArgon2Operations;
    candidate.memoryLimit = VaultArgon2Memory;
    candidate.formatVersion = VaultFormatVersion;

    CryptoError result = CryptoEngine::deriveKey(
        masterPassword,
        candidate.salt,
        candidate.operationsLimit,
        candidate.memoryLimit,
        wrappingKey);

    if (result != CryptoError::None) {
        return result;
    }

    if (!CryptoEngine::generateKey(rawDataKey)) {
        return CryptoError::InitializationFailed;
    }

    const AssociatedData associatedData = makeAssociatedData(candidate);

    EncryptedData encryptedDek{};

    result = CryptoEngine::encrypt(
        std::span<const unsigned char>(
            rawDataKey.data(), rawDataKey.size()),
        associatedData,
        wrappingKey,
        encryptedDek);

    if (result != CryptoError::None) {
        return result;
    }

    if (encryptedDek.ciphertext.size() != candidate.wrappedDek.size()) {
        return CryptoError::EncryptionFailed;
    }

    candidate.wrapNonce = encryptedDek.nonce;

    std::copy(
        encryptedDek.ciphertext.begin(),
        encryptedDek.ciphertext.end(),
        candidate.wrappedDek.begin());

    SecureBuffer candidateDataKey(core::KeySize);

    if (candidateDataKey.size() != core::KeySize) {
        return CryptoError::AllocationFailed;
    }

    std::memcpy(
        candidateDataKey.data(),
        rawDataKey.data(),
        rawDataKey.size());

    metadata = candidate;
    dataKey = std::move(candidateDataKey);

    return CryptoError::None;
}

CryptoError VaultKeyService::unlock(
    std::span<const unsigned char> masterPassword,
    const VaultKeyMetadata& metadata,
    SecureBuffer& dataKey)
{
    dataKey = SecureBuffer(0);

    if (masterPassword.empty() || masterPassword.data() == nullptr ||
        !validMetadata(metadata)) {
        return CryptoError::InvalidInput;
    }

    if (!CryptoEngine::initialize()) {
        return CryptoError::InitializationFailed;
    }

    Key wrappingKey{};
    KeyWiper wrappingKeyWiper(wrappingKey);

    const CryptoError deriveResult = CryptoEngine::deriveKey(
        masterPassword,
        metadata.salt,
        metadata.operationsLimit,
        metadata.memoryLimit,
        wrappingKey);

    if (deriveResult != CryptoError::None) {
        return deriveResult;
    }

    EncryptedData encryptedDek{};
    encryptedDek.nonce = metadata.wrapNonce;

    try {
        encryptedDek.ciphertext.assign(
            metadata.wrappedDek.begin(),
            metadata.wrappedDek.end());
    } catch (...) {
        return CryptoError::AllocationFailed;
    }

    const AssociatedData associatedData = makeAssociatedData(metadata);

    SecureBuffer decryptedDek(0);

    const CryptoError decryptResult = CryptoEngine::decrypt(
        encryptedDek,
        associatedData,
        wrappingKey,
        decryptedDek);

    if (decryptResult != CryptoError::None) {
        return decryptResult;
    }

    if (decryptedDek.size() != core::KeySize) {
        return CryptoError::AuthenticationFailed;
    }

    dataKey = std::move(decryptedDek);

    return CryptoError::None;
}

} // namespace passwall::services
