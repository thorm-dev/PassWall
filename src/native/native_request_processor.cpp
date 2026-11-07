#include "native/native_request_processor.hpp"

#include "core/site_matcher.hpp"
#include "native/entry_id_parser.hpp"
#include "native/native_message_limits.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>

#include <sodium.h>

#include <cstddef>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace passwall::native {

namespace detail {

class NativeRequestResponseBuilder final {
public:
    static NativeRequestResponse fromPayload(
        core::SecureBuffer&& payload,
        bool requestVaultActivation,
        std::uint64_t sessionGeneration = 0) noexcept;
};

} // namespace detail

namespace {

static_assert(
    NativeMessageFrameHeaderBytes == sizeof(std::uint32_t));

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

class CredentialWiper final {
public:
    explicit CredentialWiper(models::Credential& credential) noexcept
        : credential_(credential)
    {
    }

    ~CredentialWiper()
    {
        wipeCredential(credential_);
    }

    CredentialWiper(const CredentialWiper&) = delete;
    CredentialWiper& operator=(const CredentialWiper&) = delete;

private:
    models::Credential& credential_;
};

void wipeSummary(models::CredentialSummary& summary) noexcept
{
    wipeString(summary.title);
    wipeString(summary.url);
    wipeString(summary.username);
    sodium_memzero(summary.id.data(), summary.id.size());
    summary.version = 0;
}

class SummaryVectorWiper final {
public:
    explicit SummaryVectorWiper(
        std::vector<models::CredentialSummary>& summaries) noexcept
        : summaries_(summaries)
    {
    }

    ~SummaryVectorWiper()
    {
        for (auto& summary : summaries_) {
            wipeSummary(summary);
        }
        summaries_.clear();
    }

    SummaryVectorWiper(const SummaryVectorWiper&) = delete;
    SummaryVectorWiper& operator=(const SummaryVectorWiper&) = delete;

private:
    std::vector<models::CredentialSummary>& summaries_;
};

bool isValidUtf8(const std::string& value) noexcept
{
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    const std::size_t size = value.size();

    for (std::size_t index = 0; index < size;) {
        const unsigned char first = bytes[index];

        if (first <= 0x7f) {
            ++index;
            continue;
        }

        const auto continuationAt =
            [&bytes, size, index](std::size_t offset) noexcept {
                return index + offset < size &&
                    bytes[index + offset] >= 0x80 &&
                    bytes[index + offset] <= 0xbf;
            };

        if (first >= 0xc2 && first <= 0xdf) {
            if (!continuationAt(1)) {
                return false;
            }
            index += 2;
            continue;
        }

        if (first == 0xe0) {
            if (index + 2 >= size ||
                bytes[index + 1] < 0xa0 || bytes[index + 1] > 0xbf ||
                !continuationAt(2)) {
                return false;
            }
            index += 3;
            continue;
        }

        if ((first >= 0xe1 && first <= 0xec) ||
            (first >= 0xee && first <= 0xef)) {
            if (!continuationAt(1) || !continuationAt(2)) {
                return false;
            }
            index += 3;
            continue;
        }

        // U+D800 à U+DFFF ne sont pas des points de code Unicode valides.
        if (first == 0xed) {
            if (index + 2 >= size ||
                bytes[index + 1] < 0x80 || bytes[index + 1] > 0x9f ||
                !continuationAt(2)) {
                return false;
            }
            index += 3;
            continue;
        }

        if (first == 0xf0) {
            if (index + 3 >= size ||
                bytes[index + 1] < 0x90 || bytes[index + 1] > 0xbf ||
                !continuationAt(2) || !continuationAt(3)) {
                return false;
            }
            index += 4;
            continue;
        }

        if (first >= 0xf1 && first <= 0xf3) {
            if (!continuationAt(1) || !continuationAt(2) ||
                !continuationAt(3)) {
                return false;
            }
            index += 4;
            continue;
        }

        // U+10FFFF est la limite supérieure autorisée.
        if (first == 0xf4) {
            if (index + 3 >= size ||
                bytes[index + 1] < 0x80 || bytes[index + 1] > 0x8f ||
                !continuationAt(2) || !continuationAt(3)) {
                return false;
            }
            index += 4;
            continue;
        }

        return false;
    }

    return true;
}

bool addSize(std::size_t& total, std::size_t additional) noexcept
{
    if (total > std::numeric_limits<std::size_t>::max() - additional) {
        return false;
    }
    total += additional;
    return true;
}

bool escapedJsonStringSize(
    const std::string& value,
    std::size_t& size) noexcept
{
    size = 2;

    for (const unsigned char byte : value) {
        std::size_t additional = 1;

        switch (byte) {
        case '"':
        case '\\':
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            additional = 2;
            break;
        default:
            if (byte < 0x20) {
                additional = 6;
            }
            break;
        }

        if (!addSize(size, additional)) {
            return false;
        }
    }

    return true;
}

void appendBytes(
    unsigned char*& output,
    std::string_view value) noexcept
{
    std::memcpy(output, value.data(), value.size());
    output += value.size();
}

bool copyToSecureBuffer(
    std::span<const unsigned char> bytes,
    core::SecureBuffer& output) noexcept
{
    if (bytes.empty() || bytes.size() > NativeMessageMaxPayloadBytes) {
        return false;
    }

    try {
        core::SecureBuffer candidate(bytes.size());
        std::memcpy(candidate.data(), bytes.data(), bytes.size());
        output = std::move(candidate);
        return true;
    } catch (...) {
        return false;
    }
}

NativeRequestResponse responseFromBytes(
    std::span<const unsigned char> bytes,
    bool requestVaultActivation = false,
    std::uint64_t sessionGeneration = 0) noexcept
{
    core::SecureBuffer payload(0);
    if (!copyToSecureBuffer(bytes, payload)) {
        return NativeRequestResponse(requestVaultActivation);
    }

    return detail::NativeRequestResponseBuilder::fromPayload(
        std::move(payload), requestVaultActivation, sessionGeneration);
}

NativeRequestResponse errorResponse(
    const char* error,
    bool requestVaultActivation = false,
    std::uint64_t sessionGeneration = 0) noexcept
{
    static constexpr std::string_view Prefix = "{\"ok\":false,\"error\":\"";
    static constexpr std::string_view Suffix = "\"}";

    try {
        const std::string_view errorText(error);
        std::size_t size = Prefix.size();
        if (!addSize(size, errorText.size()) ||
            !addSize(size, Suffix.size()) ||
            size > NativeMessageMaxPayloadBytes) {
            return NativeRequestResponse(requestVaultActivation);
        }

        core::SecureBuffer payload(size);
        unsigned char* output = payload.data();
        appendBytes(output, Prefix);
        appendBytes(output, errorText);
        appendBytes(output, Suffix);

        return detail::NativeRequestResponseBuilder::fromPayload(
            std::move(payload), requestVaultActivation, sessionGeneration);
    } catch (...) {
        return NativeRequestResponse(requestVaultActivation);
    }
}

NativeRequestResponse lockedResponse(
    bool requestVaultActivation,
    std::uint64_t sessionGeneration = 0) noexcept
{
    static constexpr std::string_view Payload =
        "{\"ok\":false,\"error\":\"vault_locked\",\"message\":"
        "\"Déverrouille le coffre dans PassWall.\"}";

    return responseFromBytes(
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(Payload.data()),
            Payload.size()),
        requestVaultActivation, sessionGeneration);
}

// Les caractères JSON de contrôle sont échappés et les séquences UTF-8 déjà
// validées sont conservées. La taille exacte a été réservée avant cet appel.
void appendJsonString(
    unsigned char*& output,
    const std::string& value) noexcept
{
    static constexpr char hex[] = "0123456789abcdef";

    *output++ = '"';

    for (const unsigned char byte : value) {
        switch (byte) {
        case '"':
            appendBytes(output, "\\\"");
            break;
        case '\\':
            appendBytes(output, "\\\\");
            break;
        case '\b':
            appendBytes(output, "\\b");
            break;
        case '\f':
            appendBytes(output, "\\f");
            break;
        case '\n':
            appendBytes(output, "\\n");
            break;
        case '\r':
            appendBytes(output, "\\r");
            break;
        case '\t':
            appendBytes(output, "\\t");
            break;
        default:
            if (byte < 0x20) {
                const char escaped[] = {
                    '\\', 'u', '0', '0',
                    hex[(byte >> 4) & 0x0f],
                    hex[byte & 0x0f]
                };
                appendBytes(output, std::string_view(escaped, sizeof(escaped)));
            } else {
                *output++ = byte;
            }
            break;
        }
    }

    *output++ = '"';
}

NativeRequestResponse accessFailureResponse(
    VaultAccessResult result,
    const NativeVaultAccess& vaultAccess,
    std::uint64_t sessionGeneration)
{
    if (result == VaultAccessResult::Locked ||
        result == VaultAccessResult::SessionChanged) {
        return lockedResponse(
            !vaultAccess.acquireLease().unlocked, sessionGeneration);
    }

    return errorResponse("vault_access_failed", false, sessionGeneration);
}

enum class SecretResponseBuildResult {
    Success,
    TooLarge,
    Failed
};

SecretResponseBuildResult buildSecretResponse(
    core::SecureBuffer& payload,
    const models::Credential& credential) noexcept
{
    static constexpr std::string_view Prefix =
        "{\"ok\":true,\"type\":\"credential_selected\",\"username\":";
    static constexpr std::string_view PasswordSeparator = ",\"password\":";

    std::size_t usernameSize = 0;
    std::size_t passwordSize = 0;

    if (!escapedJsonStringSize(credential.username, usernameSize) ||
        !escapedJsonStringSize(credential.password, passwordSize)) {
        return SecretResponseBuildResult::Failed;
    }

    std::size_t totalSize = Prefix.size();
    if (!addSize(totalSize, usernameSize) ||
        !addSize(totalSize, PasswordSeparator.size()) ||
        !addSize(totalSize, passwordSize) ||
        !addSize(totalSize, 1)) {
        return SecretResponseBuildResult::Failed;
    }

    if (totalSize > NativeMessageMaxPayloadBytes) {
        return SecretResponseBuildResult::TooLarge;
    }

    try {
        core::SecureBuffer candidate(totalSize);
        unsigned char* output = candidate.data();
        appendBytes(output, Prefix);
        appendJsonString(output, credential.username);
        appendBytes(output, PasswordSeparator);
        appendJsonString(output, credential.password);
        *output++ = '}';

        if (output != candidate.data() + candidate.size()) {
            return SecretResponseBuildResult::Failed;
        }

        payload = std::move(candidate);
    } catch (...) {
        return SecretResponseBuildResult::Failed;
    }

    return SecretResponseBuildResult::Success;
}

NativeRequestResponse handleRequest(
    NativeVaultAccess& vaultAccess,
    const QJsonObject& request)
{
    const QString type = request.value("type").toString();
    if (type != QStringLiteral("search_credentials") &&
        type != QStringLiteral("get_credential")) {
        return errorResponse("unsupported_request");
    }

    const VaultLease lease = vaultAccess.acquireLease();
    if (!lease.unlocked) {
        return lockedResponse(true);
    }

    try {
    const QString requestedUrl = request.value("url").toString();
    if (!core::SiteMatcher::isValidHttpUrl(requestedUrl)) {
        return errorResponse("invalid_url", false, lease.generation);
    }

    if (!vaultAccess.isLeaseCurrent(lease)) {
        return lockedResponse(
            !vaultAccess.acquireLease().unlocked, lease.generation);
    }

    if (type == QStringLiteral("search_credentials")) {
        std::vector<models::CredentialSummary> summaries;
        SummaryVectorWiper summariesWiper(summaries);

        const VaultAccessResult result =
            vaultAccess.copySummaries(lease, summaries);
        if (result != VaultAccessResult::Success) {
            return accessFailureResponse(result, vaultAccess, lease.generation);
        }
        if (!vaultAccess.isLeaseCurrent(lease)) {
            return lockedResponse(
                !vaultAccess.acquireLease().unlocked, lease.generation);
        }

        QJsonArray matches;
        for (const auto& summary : summaries) {
            if (!isValidUtf8(summary.url) ||
                !core::SiteMatcher::matchesOrigin(
                    requestedUrl, summary.url)) {
                if (!isValidUtf8(summary.url)) {
                    return errorResponse(
                        "vault_access_failed", false, lease.generation);
                }
                continue;
            }

            if (!isValidUtf8(summary.title) ||
                !isValidUtf8(summary.username)) {
                return errorResponse(
                    "vault_access_failed", false, lease.generation);
            }

            QString title = QString::fromUtf8(
                summary.title.data(),
                static_cast<qsizetype>(summary.title.size()));
            if (title.isEmpty()) {
                title = QStringLiteral("(Sans titre)");
            }

            const QByteArray idBytes(
                reinterpret_cast<const char*>(summary.id.data()),
                static_cast<qsizetype>(summary.id.size()));

            matches.append(QJsonObject{
                {"id", QString::fromLatin1(idBytes.toHex())},
                {"title", title},
                {"username", QString::fromUtf8(
                    summary.username.data(),
                    static_cast<qsizetype>(summary.username.size()))}
            });
        }

        if (!vaultAccess.isLeaseCurrent(lease)) {
            return lockedResponse(
                !vaultAccess.acquireLease().unlocked, lease.generation);
        }

        try {
            const QByteArray payload = QJsonDocument(QJsonObject{
                {"ok", true},
                {"type", "credential_matches"},
                {"credentials", matches}
            }).toJson(QJsonDocument::Compact);

            if (payload.isEmpty() ||
                payload.size() >
                    static_cast<qsizetype>(NativeMessageMaxPayloadBytes)) {
                return errorResponse(
                    "response_too_large", false, lease.generation);
            }

            return responseFromBytes(
                std::span<const unsigned char>(
                    reinterpret_cast<const unsigned char*>(payload.constData()),
                    static_cast<std::size_t>(payload.size())),
                false, lease.generation);
        } catch (...) {
            return errorResponse("vault_access_failed", false, lease.generation);
        }
    }

    const QJsonValue requestedIdValue = request.value("id");
    models::EntryId entryId{};
    if (!requestedIdValue.isString() ||
        !parseCanonicalEntryId(requestedIdValue.toString(), entryId)) {
        return errorResponse(
            "invalid_credential_id", false, lease.generation);
    }

    std::vector<models::CredentialSummary> summaries;
    SummaryVectorWiper summariesWiper(summaries);

    const VaultAccessResult summariesResult =
        vaultAccess.copySummaries(lease, summaries);
    if (summariesResult != VaultAccessResult::Success) {
        return accessFailureResponse(
            summariesResult, vaultAccess, lease.generation);
    }
    if (!vaultAccess.isLeaseCurrent(lease)) {
        return lockedResponse(
            !vaultAccess.acquireLease().unlocked, lease.generation);
    }

    bool found = false;
    for (const auto& summary : summaries) {
        if (summary.id != entryId) {
            continue;
        }
        if (!isValidUtf8(summary.url)) {
            return errorResponse(
                "vault_access_failed", false, lease.generation);
        }
        if (core::SiteMatcher::matchesOrigin(requestedUrl, summary.url)) {
            found = true;
            break;
        }
    }
    if (!found) {
        return errorResponse(
            "credential_not_found", false, lease.generation);
    }

    models::Credential credential;
    CredentialWiper credentialWiper(credential);

    const VaultAccessResult credentialResult =
        vaultAccess.loadCredential(lease, entryId, credential);
    if (credentialResult != VaultAccessResult::Success) {
        if (credentialResult == VaultAccessResult::Locked ||
            credentialResult == VaultAccessResult::SessionChanged) {
            return lockedResponse(
                !vaultAccess.acquireLease().unlocked, lease.generation);
        }

        return errorResponse(
            "credential_not_found", false, lease.generation);
    }
    if (!vaultAccess.isLeaseCurrent(lease)) {
        return lockedResponse(
            !vaultAccess.acquireLease().unlocked, lease.generation);
    }
    if (!isValidUtf8(credential.url) ||
        !isValidUtf8(credential.username) ||
        !isValidUtf8(credential.password)) {
        return errorResponse("vault_access_failed", false, lease.generation);
    }
    if (credential.id != entryId ||
        !core::SiteMatcher::matchesOrigin(requestedUrl, credential.url)) {
        return errorResponse(
            "credential_not_found", false, lease.generation);
    }
    if (!vaultAccess.isLeaseCurrent(lease)) {
        return lockedResponse(
            !vaultAccess.acquireLease().unlocked, lease.generation);
    }

    core::SecureBuffer payload(0);
    const SecretResponseBuildResult buildResult =
        buildSecretResponse(payload, credential);
    if (buildResult == SecretResponseBuildResult::TooLarge) {
        return errorResponse("response_too_large", false, lease.generation);
    }
    if (buildResult != SecretResponseBuildResult::Success) {
        return errorResponse("vault_access_failed", false, lease.generation);
    }

    // Dans l'architecture actuelle, le contrat mono-thread exclut toute
    // invalidation entre ce contrôle et le retour. Le contrôle final efface
    // néanmoins le secret si un adaptateur ne respecte pas ce contrat ; le
    // futur transport devra conserver cette propriété jusqu'à sa mise en file.
    if (!vaultAccess.isLeaseCurrent(lease)) {
        payload = core::SecureBuffer(0);
        return lockedResponse(
            !vaultAccess.acquireLease().unlocked, lease.generation);
    }

    return detail::NativeRequestResponseBuilder::fromPayload(
        std::move(payload), false, lease.generation);
    } catch (...) {
        return errorResponse("vault_access_failed", false, lease.generation);
    }
}

} // namespace

NativeRequestResponse::NativeRequestResponse(
    bool requestVaultActivationValue) noexcept
    : requestVaultActivation(requestVaultActivationValue)
{
}

NativeRequestResponse::NativeRequestResponse(
    core::SecureBuffer&& payload,
    bool requestVaultActivationValue,
    std::uint64_t sessionGenerationValue) noexcept
    : requestVaultActivation(requestVaultActivationValue)
    , payload_(std::move(payload))
    , sessionGeneration_(sessionGenerationValue)
{
}

NativeRequestResponse::~NativeRequestResponse()
{
    wipePayload();
}

NativeRequestResponse::NativeRequestResponse(
    NativeRequestResponse&& other) noexcept
    : requestVaultActivation(other.requestVaultActivation)
    , payload_(std::move(other.payload_))
    , sessionGeneration_(other.sessionGeneration_)
{
    other.requestVaultActivation = false;
    other.sessionGeneration_ = 0;
}

NativeRequestResponse& NativeRequestResponse::operator=(
    NativeRequestResponse&& other) noexcept
{
    if (this != &other) {
        wipePayload();
        payload_ = std::move(other.payload_);
        requestVaultActivation = other.requestVaultActivation;
        sessionGeneration_ = other.sessionGeneration_;
        other.requestVaultActivation = false;
        other.sessionGeneration_ = 0;
    }
    return *this;
}

bool NativeRequestResponse::hasPayload() const noexcept
{
    return !payload_.empty();
}

std::span<const unsigned char> NativeRequestResponse::payloadView() const noexcept
{
    if (payload_.empty()) {
        return {};
    }

    return {payload_.data(), payload_.size()};
}

bool NativeRequestResponse::hasSessionGeneration() const noexcept
{
    return sessionGeneration_ != 0;
}

std::uint64_t NativeRequestResponse::sessionGeneration() const noexcept
{
    return sessionGeneration_;
}

core::SecureBuffer NativeRequestResponse::takePayload() && noexcept
{
    core::SecureBuffer payload = std::move(payload_);
    requestVaultActivation = false;
    sessionGeneration_ = 0;
    return payload;
}

void NativeRequestResponse::wipePayload() noexcept
{
    payload_ = core::SecureBuffer(0);
    sessionGeneration_ = 0;
}

NativeRequestResponse detail::NativeRequestResponseBuilder::fromPayload(
    core::SecureBuffer&& payload,
    bool requestVaultActivation,
    std::uint64_t sessionGeneration) noexcept
{
    return NativeRequestResponse(
        std::move(payload), requestVaultActivation, sessionGeneration);
}

NativeRequestProcessor::NativeRequestProcessor(
    NativeVaultAccess& vaultAccess) noexcept
    : vaultAccess_(vaultAccess)
{
}

NativeRequestResponse NativeRequestProcessor::handle(
    const QJsonObject& request) const
{
    // SecureBuffer repose sur l'allocateur de libsodium. L'initialisation est
    // idempotente et doit aussi avoir eu lieu pour répondre à un coffre encore
    // verrouillé, avant tout déchiffrement.
    if (!core::CryptoEngine::initialize()) {
        return NativeRequestResponse{};
    }

    try {
        return handleRequest(vaultAccess_, request);
    } catch (...) {
        return errorResponse("vault_access_failed");
    }
}

} // namespace passwall::native
