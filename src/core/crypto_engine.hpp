#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace passwall::core
{

    inline constexpr std::size_t KeySize = 32;
    inline constexpr std::size_t NonceSize = 24;
    inline constexpr std::size_t SaltSize = 16;
    inline constexpr std::size_t AuthenticationTagSize = 16;

    using Key = std::array<unsigned char, KeySize>;
    using Salt = std::array<unsigned char, SaltSize>;
    using Nonce = std::array<unsigned char, NonceSize>;

    struct EncryptedData
    {
        Nonce nonce{};
        std::vector<unsigned char> ciphertext;
    };

    enum class CryptoError
    {
        None,
        InitializationFailed,
        InvalidInput,
        AllocationFailed,
        KeyDerivationFailed,
        EncryptionFailed,
        DecryptionFailed,
        AuthenticationFailed
    };

    class SecureBuffer
    {
    public:
        explicit SecureBuffer(std::size_t size);
        ~SecureBuffer();

        SecureBuffer(const SecureBuffer &) = delete;
        SecureBuffer &operator=(const SecureBuffer &) = delete;

        SecureBuffer(SecureBuffer &&other) noexcept;
        SecureBuffer &operator=(SecureBuffer &&other) noexcept;

        [[nodiscard]] unsigned char *data() noexcept;
        [[nodiscard]] const unsigned char *data() const noexcept;
        [[nodiscard]] std::size_t size() const noexcept;
        [[nodiscard]] bool empty() const noexcept;

    private:
        unsigned char *data_ = nullptr;
        std::size_t size_ = 0;
    };

    class CryptoEngine
    {
    public:
        [[nodiscard]] static bool initialize() noexcept;

        [[nodiscard]] static bool generateKey(Key &key) noexcept;

        [[nodiscard]] static CryptoError deriveKey(
            std::span<const unsigned char> password,
            const Salt &salt,
            std::uint64_t operationsLimit,
            std::size_t memoryLimit,
            Key &key) noexcept;

        [[nodiscard]] static CryptoError encrypt(
            std::span<const unsigned char> plaintext,
            std::span<const unsigned char> associatedData,
            std::span<const unsigned char> key,
            EncryptedData &output) noexcept;

        [[nodiscard]] static CryptoError decrypt(
            const EncryptedData &input,
            std::span<const unsigned char> associatedData,
            std::span<const unsigned char> key,
            SecureBuffer &plaintext) noexcept;
    };

} // namespace passwall::core