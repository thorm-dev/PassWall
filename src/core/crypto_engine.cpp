
#include "crypto_engine.hpp"

#include <sodium.h>

#include <new>
#include <utility>
#include <limits>
#include <stdexcept>

namespace passwall::core {

SecureBuffer::SecureBuffer(std::size_t size) : size_(size)
{
    if (size_ == 0)
        return;
    data_ = static_cast<unsigned char*>(sodium_malloc(size_));
    if (data_ == nullptr)
    {
        size_ = 0;
        throw std::bad_alloc();
    }
    sodium_memzero(data_, size_);
}

SecureBuffer::~SecureBuffer()
{
    if (data_ != nullptr)
    {
        sodium_memzero(data_, size_);
        sodium_free(data_);
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0))
{
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept
{
    if (this != &other)
    {
        if (data_ != nullptr)
        {
            sodium_memzero(data_, size_);
            sodium_free(data_);
        }
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

unsigned char* SecureBuffer::data() noexcept
{
    return data_;
}

const unsigned char* SecureBuffer::data() const noexcept
{
    return data_;
}

std::size_t SecureBuffer::size() const noexcept
{
    return size_;
}

bool SecureBuffer::empty() const noexcept
{
    return size_ == 0;
}

bool CryptoEngine::initialize() noexcept
{
    return sodium_init() >= 0;
}

bool CryptoEngine::generateKey(Key& key) noexcept
{
    if (!initialize())
    {
        sodium_memzero(key.data(), key.size());
        return false;
    }
    randombytes_buf(key.data(), key.size());
    return true;
}

CryptoError CryptoEngine::deriveKey(std::span<const unsigned char> password, const Salt& salt, std::uint64_t operationsLimit, std::size_t memoryLimit, Key& key) noexcept
{
    sodium_memzero(key.data(), key.size());
    if (!initialize())
        return CryptoError::InitializationFailed;
    if (password.empty() || password.data() == nullptr)
        return CryptoError::InvalidInput;
    if (operationsLimit < crypto_pwhash_OPSLIMIT_MIN ||
        operationsLimit > crypto_pwhash_OPSLIMIT_MAX ||
        memoryLimit < crypto_pwhash_MEMLIMIT_MIN ||
        memoryLimit > crypto_pwhash_MEMLIMIT_MAX)
            return CryptoError::InvalidInput;
    const int result = crypto_pwhash(
        key.data(),
        key.size(),
        reinterpret_cast<const char*>(password.data()),
        static_cast<unsigned long long>(password.size()),
        salt.data(),
        static_cast<unsigned long long>(operationsLimit),
        memoryLimit,
        crypto_pwhash_ALG_ARGON2ID13);
    if (result != 0)
    {
        sodium_memzero(key.data(), key.size());
        return CryptoError::KeyDerivationFailed;
    }
    return CryptoError::None;
}

CryptoError CryptoEngine::encrypt(
    std::span<const unsigned char> plaintext,
    std::span<const unsigned char> associatedData,
    std::span<const unsigned char> key,
    EncryptedData& output) noexcept
{
    output = EncryptedData{};

    if (!initialize())
        return CryptoError::InitializationFailed;
    if (key.size() != KeySize || key.data() == nullptr)
        return CryptoError::InvalidInput;
    if (plaintext.size() >
            std::numeric_limits<std::size_t>::max() -
                crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        plaintext.size() >
            std::numeric_limits<unsigned long long>::max() ||
        associatedData.size() >
            std::numeric_limits<unsigned long long>::max())
        return CryptoError::InvalidInput;
    try {
        EncryptedData candidate;
        randombytes_buf(candidate.nonce.data(), candidate.nonce.size());

        candidate.ciphertext.resize(
            plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

        unsigned long long ciphertextSize = 0;

        const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
            candidate.ciphertext.data(),
            &ciphertextSize,
            plaintext.data(),
            static_cast<unsigned long long>(plaintext.size()),
            associatedData.data(),
            static_cast<unsigned long long>(associatedData.size()),
            nullptr,
            candidate.nonce.data(),
            key.data());

        if (result != 0) {
            sodium_memzero(candidate.nonce.data(), candidate.nonce.size());

            if (!candidate.ciphertext.empty()) {
                sodium_memzero(
                    candidate.ciphertext.data(),
                    candidate.ciphertext.size());
            }

            return CryptoError::EncryptionFailed;
        }

        candidate.ciphertext.resize(
            static_cast<std::size_t>(ciphertextSize));

        output = std::move(candidate);
        return CryptoError::None;
    }
    catch (const std::bad_alloc&) {
        return CryptoError::AllocationFailed;
    }
    catch (...) {
        return CryptoError::EncryptionFailed;
    }
}

CryptoError CryptoEngine::decrypt(
    const EncryptedData& input,
    std::span<const unsigned char> associatedData,
    std::span<const unsigned char> key,
    SecureBuffer& plaintext) noexcept
{
    plaintext = SecureBuffer(0);

    if (!initialize())
        return CryptoError::InitializationFailed;
    if (key.size() != KeySize || key.data() == nullptr)
        return CryptoError::InvalidInput;
    if (input.ciphertext.size() <
            crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        input.ciphertext.size() >
            std::numeric_limits<unsigned long long>::max() ||
        associatedData.size() >
            std::numeric_limits<unsigned long long>::max())
        return CryptoError::InvalidInput;
    const std::size_t plaintextSize =
        input.ciphertext.size() -
        crypto_aead_xchacha20poly1305_ietf_ABYTES;

    try {
        SecureBuffer candidate(plaintextSize);
        unsigned long long decryptedSize = 0;

        const int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            candidate.data(),
            &decryptedSize,
            nullptr,
            input.ciphertext.data(),
            static_cast<unsigned long long>(input.ciphertext.size()),
            associatedData.data(),
            static_cast<unsigned long long>(associatedData.size()),
            input.nonce.data(),
            key.data());

        if (result != 0)
            return CryptoError::AuthenticationFailed;
        if (decryptedSize != plaintextSize)
            return CryptoError::DecryptionFailed;
        plaintext = std::move(candidate);
        return CryptoError::None;
    }
    catch (const std::bad_alloc&)
    {
        return CryptoError::AllocationFailed;
    }
    catch (...)
    {
        return CryptoError::DecryptionFailed;
    }
}

} // namespace passwall::core
