#include "native/native_request_processor.hpp"
#include "native/native_message_limits.hpp"

#include <gtest/gtest.h>

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

#include <sodium.h>

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using passwall::models::Credential;
using passwall::models::CredentialSummary;
using passwall::core::SecureBuffer;
using passwall::native::NativeRequestProcessor;
using passwall::native::NativeRequestResponse;
using passwall::native::NativeVaultAccess;
using passwall::native::VaultAccessResult;
using passwall::native::VaultLease;

static_assert(!std::is_copy_constructible_v<NativeRequestResponse>);
static_assert(!std::is_copy_assignable_v<NativeRequestResponse>);
static_assert(std::is_nothrow_move_constructible_v<NativeRequestResponse>);
static_assert(std::is_nothrow_move_assignable_v<NativeRequestResponse>);
static_assert(!std::is_copy_constructible_v<SecureBuffer>);
static_assert(!std::is_copy_assignable_v<SecureBuffer>);
static_assert(std::is_nothrow_move_constructible_v<SecureBuffer>);
static_assert(std::is_nothrow_move_assignable_v<SecureBuffer>);
static_assert(std::is_same_v<
    decltype(std::declval<NativeRequestResponse&&>().takePayload()),
    SecureBuffer>);
static_assert(std::is_same_v<
    decltype(std::declval<const NativeRequestResponse&>().payloadView()),
    std::span<const unsigned char>>);

template <typename T>
concept ExposesQByteArrayPayload = requires(const T& response) {
    { response.payload() } -> std::same_as<const QByteArray&>;
};

template <typename T>
concept TransfersPayloadFromLvalue = requires(T& response) {
    response.takePayload();
};

static_assert(!ExposesQByteArrayPayload<NativeRequestResponse>);
static_assert(!TransfersPayloadFromLvalue<NativeRequestResponse>);

namespace {

void clearCredential(Credential& credential)
{
    credential = Credential{};
}

class FakeNativeVaultAccess final : public NativeVaultAccess {
public:
    VaultLease acquireLease() const noexcept override
    {
        return {unlocked, generation};
    }

    bool isLeaseCurrent(const VaultLease& lease) const noexcept override
    {
        ++leaseCurrentCalls;
        if (invalidateOnLeaseCheck == leaseCurrentCalls) {
            ++generation;
        }

        return lease.unlocked && unlocked &&
               lease.generation == generation;
    }

    VaultAccessResult copySummaries(
        const VaultLease& lease,
        std::vector<CredentialSummary>& output) override
    {
        ++copySummariesCalls;
        output.clear();

        if (!isLeaseCurrent(lease)) {
            return VaultAccessResult::SessionChanged;
        }
        if (summariesResult != VaultAccessResult::Success) {
            applyResultStateChange(summariesResult);
            return summariesResult;
        }

        output = summaries;
        if (throwDuringCopySummaries) {
            throw std::runtime_error("copy summaries failure");
        }
        if (changeGenerationDuringCopySummaries) {
            ++generation;
        }
        return VaultAccessResult::Success;
    }

    VaultAccessResult loadCredential(
        const VaultLease& lease,
        const passwall::models::EntryId& entryId,
        Credential& output) override
    {
        ++loadCredentialCalls;
        clearCredential(output);

        if (!isLeaseCurrent(lease)) {
            return VaultAccessResult::SessionChanged;
        }
        if (credentialResult != VaultAccessResult::Success) {
            applyResultStateChange(credentialResult);
            return credentialResult;
        }
        if (credential.id != entryId) {
            return VaultAccessResult::NotFound;
        }

        output = credential;
        if (throwDuringLoadCredential) {
            throw std::runtime_error("load credential failure");
        }
        if (changeGenerationDuringLoad) {
            ++generation;
        }
        return VaultAccessResult::Success;
    }

private:
    void applyResultStateChange(VaultAccessResult result)
    {
        if (result == VaultAccessResult::Locked) {
            unlocked = false;
            ++generation;
        } else if (result == VaultAccessResult::SessionChanged) {
            ++generation;
        }
    }

public:

    bool unlocked = true;
    mutable std::uint64_t generation = 1;
    std::vector<CredentialSummary> summaries;
    Credential credential;
    VaultAccessResult summariesResult = VaultAccessResult::Success;
    VaultAccessResult credentialResult = VaultAccessResult::Success;
    bool throwDuringCopySummaries = false;
    bool throwDuringLoadCredential = false;
    bool changeGenerationDuringCopySummaries = false;
    bool changeGenerationDuringLoad = false;
    mutable int invalidateOnLeaseCheck = 0;
    mutable int leaseCurrentCalls = 0;
    int copySummariesCalls = 0;
    int loadCredentialCalls = 0;
};

Credential makeCredential(
    unsigned char firstIdByte = 1,
    const std::string& url = "https://example.com/login")
{
    Credential credential;
    credential.id[0] = firstIdByte;
    credential.title = "Compte de test";
    credential.url = url;
    credential.username = "alice";
    credential.password = "secret-test";
    credential.notes = "note-privee";
    return credential;
}

CredentialSummary makeSummary(const Credential& credential)
{
    CredentialSummary summary;
    summary.id = credential.id;
    summary.version = credential.version;
    summary.title = credential.title;
    summary.url = credential.url;
    summary.username = credential.username;
    return summary;
}

QString entryIdText(const passwall::models::EntryId& entryId)
{
    return QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(entryId.data()),
        static_cast<qsizetype>(entryId.size())).toHex());
}

QJsonObject makeRequest(const QString& type, const QString& url)
{
    return {
        {"type", type},
        {"url", url}
    };
}

QJsonObject parseResponse(const NativeRequestResponse& response)
{
    EXPECT_TRUE(response.hasPayload());
    if (!response.hasPayload()) {
        return {};
    }

    const std::span<const unsigned char> bytes = response.payloadView();
    QByteArray json(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<qsizetype>(bytes.size()));
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(json, &error);

    if (!json.isEmpty()) {
        sodium_memzero(
            json.data(), static_cast<std::size_t>(json.size()));
        json.clear();
    }

    EXPECT_EQ(error.error, QJsonParseError::NoError);
    EXPECT_TRUE(document.isObject());
    return document.object();
}

bool payloadContains(
    const NativeRequestResponse& response,
    std::string_view needle)
{
    const std::span<const unsigned char> bytes = response.payloadView();
    const auto* needleBegin = reinterpret_cast<const unsigned char*>(
        needle.data());

    return std::search(
        bytes.begin(), bytes.end(), needleBegin, needleBegin + needle.size())
        != bytes.end();
}

NativeRequestResponse handle(
    FakeNativeVaultAccess& vault,
    const QJsonObject& request)
{
    NativeRequestProcessor processor(vault);
    return processor.handle(request);
}

QJsonObject getCredentialRequest(const Credential& credential)
{
    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(credential.id));
    return request;
}

constexpr std::string_view CredentialResponsePrefix =
    "{\"ok\":true,\"type\":\"credential_selected\",\"username\":";
constexpr std::string_view CredentialResponsePasswordSeparator =
    ",\"password\":";

std::size_t credentialResponseSizeForAscii(
    const std::string& username,
    const std::string& password)
{
    return CredentialResponsePrefix.size() + 2 + username.size() +
        CredentialResponsePasswordSeparator.size() + 2 + password.size() +
        1;
}

} // namespace

TEST(NativeRequestResponseTest, IsMoveOnlyAndTransfersThenWipesPayload)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};

    NativeRequestResponse response = handle(
        vault, getCredentialRequest(vault.credential));
    ASSERT_TRUE(response.hasPayload());
    EXPECT_TRUE(response.hasSessionGeneration());
    EXPECT_EQ(response.sessionGeneration(), vault.generation);

    NativeRequestResponse movedResponse(std::move(response));
    EXPECT_FALSE(response.hasPayload());
    EXPECT_FALSE(response.hasSessionGeneration());
    EXPECT_TRUE(movedResponse.hasSessionGeneration());
    EXPECT_EQ(movedResponse.sessionGeneration(), vault.generation);

    SecureBuffer transferred = std::move(movedResponse).takePayload();
    EXPECT_FALSE(movedResponse.hasPayload());
    EXPECT_FALSE(movedResponse.hasSessionGeneration());
    EXPECT_FALSE(response.hasSessionGeneration());
    ASSERT_FALSE(transferred.empty());
    EXPECT_TRUE(std::search(
        transferred.data(), transferred.data() + transferred.size(),
        reinterpret_cast<const unsigned char*>("secret-test"),
        reinterpret_cast<const unsigned char*>("secret-test") + 11)
        != transferred.data() + transferred.size());

    transferred = SecureBuffer(0);
    EXPECT_TRUE(transferred.empty());

    NativeRequestResponse explicitlyWiped = handle(
        vault, getCredentialRequest(vault.credential));
    ASSERT_TRUE(explicitlyWiped.hasPayload());
    explicitlyWiped.wipePayload();
    EXPECT_FALSE(explicitlyWiped.hasPayload());
    EXPECT_FALSE(explicitlyWiped.hasSessionGeneration());
}

TEST(NativeRequestProcessorTest, SearchesUnlockedVaultWithSummariesOnly)
{
    FakeNativeVaultAccess vault;
    const Credential credential = makeCredential();
    vault.summaries = {makeSummary(credential)};
    vault.credential = credential;

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com/account"));
    const QJsonObject json = parseResponse(response);

    ASSERT_TRUE(json["ok"].toBool());
    const QJsonArray matches = json["credentials"].toArray();
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0].toObject()["id"].toString(), entryIdText(credential.id));
    EXPECT_EQ(matches[0].toObject()["title"].toString(),
              QStringLiteral("Compte de test"));
    EXPECT_EQ(matches[0].toObject()["username"].toString(),
              QStringLiteral("alice"));
    EXPECT_EQ(vault.loadCredentialCalls, 0);
    EXPECT_TRUE(response.hasSessionGeneration());
    EXPECT_EQ(response.sessionGeneration(), vault.generation);
}

TEST(NativeRequestProcessorTest, RejectsUnsupportedRequestWithoutSecret)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};

    const auto response = handle(vault, {{"type", "unknown_request"}});
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("unsupported_request"));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
    EXPECT_FALSE(payloadContains(response, "note-privee"));
    EXPECT_EQ(vault.copySummariesCalls, 0);
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, RejectsSearchWhenVaultIsLocked)
{
    FakeNativeVaultAccess vault;
    vault.unlocked = false;

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com"));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_TRUE(response.requestVaultActivation);
    EXPECT_EQ(vault.copySummariesCalls, 0);
    EXPECT_EQ(vault.loadCredentialCalls, 0);
    EXPECT_FALSE(response.hasSessionGeneration());
}

TEST(NativeRequestProcessorTest, SearchNeverReturnsPasswordOrNotes)
{
    FakeNativeVaultAccess vault;
    const Credential credential = makeCredential();
    vault.summaries = {makeSummary(credential)};
    vault.credential = credential;

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com"));
    const QJsonObject json = parseResponse(response);
    const QJsonObject match = json["credentials"].toArray()[0].toObject();

    EXPECT_FALSE(match.contains("password"));
    EXPECT_FALSE(match.contains("notes"));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
    EXPECT_FALSE(payloadContains(response, "note-privee"));
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, SearchesOnlyExactMatchingOrigin)
{
    FakeNativeVaultAccess vault;
    const Credential matching = makeCredential(
        1, "https://example.com/login");
    const Credential subdomain = makeCredential(
        2, "https://sub.example.com/login");
    const Credential otherDomain = makeCredential(
        3, "https://other.example/login");
    vault.credential = matching;
    vault.summaries = {
        makeSummary(matching),
        makeSummary(subdomain),
        makeSummary(otherDomain)
    };

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com/account"));
    const QJsonObject json = parseResponse(response);
    const QJsonArray matches = json["credentials"].toArray();

    ASSERT_TRUE(json["ok"].toBool());
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0].toObject()["id"].toString(),
              entryIdText(matching.id));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, GetsCredentialAfterMatchingSummaryAndOrigin)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com/account");
    request.insert("id", entryIdText(vault.credential.id));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    EXPECT_TRUE(json["ok"].toBool());
    EXPECT_EQ(json["type"].toString(),
              QStringLiteral("credential_selected"));
    EXPECT_EQ(json["username"].toString(), QStringLiteral("alice"));
    EXPECT_EQ(json["password"].toString(), QStringLiteral("secret-test"));
    EXPECT_EQ(vault.loadCredentialCalls, 1);
    EXPECT_TRUE(response.hasSessionGeneration());
    EXPECT_EQ(response.sessionGeneration(), vault.generation);
}

TEST(NativeRequestProcessorTest, RejectsInvalidCredentialIdWithoutLoading)
{
    FakeNativeVaultAccess vault;
    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", QStringLiteral("not-an-entry-id"));

    const QJsonObject json = parseResponse(handle(vault, request));

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("invalid_credential_id"));
    EXPECT_EQ(vault.copySummariesCalls, 0);
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, RejectsNonStringCredentialIdWithoutLoading)
{
    FakeNativeVaultAccess vault;
    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", QJsonValue(42));

    const QJsonObject json = parseResponse(handle(vault, request));

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("invalid_credential_id"));
    EXPECT_EQ(vault.copySummariesCalls, 0);
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, RejectsMalformedUrlWithoutLoading)
{
    FakeNativeVaultAccess vault;

    const QJsonObject json = parseResponse(handle(
        vault,
        makeRequest("search_credentials", "file:///etc/passwd")));

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("invalid_url"));
    EXPECT_EQ(vault.copySummariesCalls, 0);
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, RejectsDifferentOriginWithoutLoading)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};

    QJsonObject request = makeRequest(
        "get_credential", "https://evil.example");
    request.insert("id", entryIdText(vault.credential.id));

    const QJsonObject json = parseResponse(handle(vault, request));

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("credential_not_found"));
    EXPECT_EQ(vault.loadCredentialCalls, 0);
}

TEST(NativeRequestProcessorTest, RejectsUnknownCanonicalCredentialIdWithoutLoading)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};

    passwall::models::EntryId unknownId{};
    unknownId.back() = 0xff;
    ASSERT_NE(unknownId, vault.credential.id);

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(unknownId));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("credential_not_found"));
    EXPECT_EQ(vault.loadCredentialCalls, 0);
    EXPECT_FALSE(payloadContains(response, "secret-test"));
    EXPECT_FALSE(payloadContains(response, "note-privee"));
}

TEST(NativeRequestProcessorTest, RejectsEntryDeletedBetweenSummaryAndLoad)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};
    vault.credentialResult = VaultAccessResult::NotFound;

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(vault.credential.id));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("credential_not_found"));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, RejectsEntryWhoseUrlChangesDuringLoad)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential(
        1, "https://evil.example/login");
    Credential previous = vault.credential;
    previous.url = "https://example.com/login";
    vault.summaries = {makeSummary(previous)};

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(vault.credential.id));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("credential_not_found"));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, RejectsGenerationChangeDuringLoad)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};
    vault.changeGenerationDuringLoad = true;

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(vault.credential.id));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_FALSE(response.requestVaultActivation);
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, HidesVaultAccessFailureAndReturnsNoSecret)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};
    vault.credentialResult = VaultAccessResult::Failed;

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(vault.credential.id));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("credential_not_found"));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, HidesPartialSearchResultsOnAccessFailure)
{
    FakeNativeVaultAccess vault;
    vault.summaries = {makeSummary(makeCredential())};
    vault.summariesResult = VaultAccessResult::Failed;

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com"));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(),
              QStringLiteral("vault_access_failed"));
    EXPECT_FALSE(payloadContains(response, "credential_matches"));
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, EscapesSpecialCharactersAndUtf8Password)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.credential.password =
        std::string("quote\" slash\\ backspace\b formfeed\f newline\n carriage\r tab\t ") +
        std::string(1, static_cast<char>(0x01)) +
        "\xC3\xA9\xF0\x9F\x94\x90";
    vault.summaries = {makeSummary(vault.credential)};

    QJsonObject request = makeRequest(
        "get_credential", "https://example.com");
    request.insert("id", entryIdText(vault.credential.id));

    const auto response = handle(vault, request);
    const QJsonObject json = parseResponse(response);

    ASSERT_TRUE(json["ok"].toBool());
    EXPECT_EQ(json["password"].toString(), QString::fromUtf8(
        vault.credential.password.data(),
        static_cast<qsizetype>(vault.credential.password.size())));
}

TEST(NativeRequestProcessorTest, AcceptsValidUtf8CredentialFields)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.credential.title = "Compte Ã©ð";
    vault.credential.username = "utilisateur-Ã©";
    vault.credential.password = "mot-de-passe-ð";
    vault.summaries = {makeSummary(vault.credential)};

    const QJsonObject search = parseResponse(handle(
        vault,
        makeRequest("search_credentials", "https://example.com")));
    ASSERT_TRUE(search["ok"].toBool());
    ASSERT_EQ(search["credentials"].toArray().size(), 1);
    EXPECT_EQ(search["credentials"].toArray()[0].toObject()["title"].toString(),
              QString::fromUtf8("Compte Ã©ð"));

    const QJsonObject credential = parseResponse(
        handle(vault, getCredentialRequest(vault.credential)));
    ASSERT_TRUE(credential["ok"].toBool());
    EXPECT_EQ(credential["username"].toString(),
              QString::fromUtf8("utilisateur-Ã©"));
    EXPECT_EQ(credential["password"].toString(),
              QString::fromUtf8("mot-de-passe-ð"));
}

TEST(NativeRequestProcessorTest, RejectsInvalidUtf8PasswordWithoutLeakingIt)
{
    struct InvalidUtf8Case final {
        const char* name;
        std::string value;
    };

    const std::vector<InvalidUtf8Case> cases{
        {"isolated continuation", std::string("\x80", 1)},
        {"incomplete sequence", std::string("\xE2\x82", 2)},
        {"overlong sequence", std::string("\xC0\xAF", 2)},
        {"UTF-16 surrogate", std::string("\xED\xA0\x80", 3)},
        {"above U+10FFFF", std::string("\xF4\x90\x80\x80", 4)}
    };

    for (const InvalidUtf8Case& testCase : cases) {
        SCOPED_TRACE(testCase.name);

        FakeNativeVaultAccess vault;
        vault.credential = makeCredential();
        vault.credential.password = testCase.value;
        vault.summaries = {makeSummary(vault.credential)};

        const auto response = handle(
            vault, getCredentialRequest(vault.credential));
        const QJsonObject json = parseResponse(response);

        EXPECT_FALSE(json["ok"].toBool());
        EXPECT_EQ(json["error"].toString(),
                  QStringLiteral("vault_access_failed"));
        EXPECT_FALSE(payloadContains(response, testCase.value));
    }
}

TEST(NativeRequestProcessorTest, RejectsInvalidUtf8SearchMetadata)
{
    FakeNativeVaultAccess invalidTitle;
    invalidTitle.credential = makeCredential();
    invalidTitle.summaries = {makeSummary(invalidTitle.credential)};
    invalidTitle.summaries[0].title = std::string("\x80", 1);

    const QJsonObject titleResponse = parseResponse(handle(
        invalidTitle,
        makeRequest("search_credentials", "https://example.com")));
    EXPECT_FALSE(titleResponse["ok"].toBool());
    EXPECT_EQ(titleResponse["error"].toString(),
              QStringLiteral("vault_access_failed"));

    FakeNativeVaultAccess invalidUsername;
    invalidUsername.credential = makeCredential();
    invalidUsername.summaries = {makeSummary(invalidUsername.credential)};
    invalidUsername.summaries[0].username = std::string("\xED\xA0\x80", 3);

    const QJsonObject usernameResponse = parseResponse(handle(
        invalidUsername,
        makeRequest("search_credentials", "https://example.com")));
    EXPECT_FALSE(usernameResponse["ok"].toBool());
    EXPECT_EQ(usernameResponse["error"].toString(),
              QStringLiteral("vault_access_failed"));
}

TEST(NativeRequestProcessorTest, ReturnsLockedForCopySummariesLocked)
{
    FakeNativeVaultAccess vault;
    vault.summariesResult = VaultAccessResult::Locked;

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com"));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_TRUE(response.requestVaultActivation);
}

TEST(NativeRequestProcessorTest, ReturnsLockedForCopySummariesSessionChange)
{
    FakeNativeVaultAccess vault;
    vault.summariesResult = VaultAccessResult::SessionChanged;

    const auto response = handle(
        vault,
        makeRequest("search_credentials", "https://example.com"));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_FALSE(response.requestVaultActivation);
}

TEST(NativeRequestProcessorTest, ReturnsLockedForLoadCredentialLocked)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};
    vault.credentialResult = VaultAccessResult::Locked;

    const auto response = handle(
        vault, getCredentialRequest(vault.credential));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_TRUE(response.requestVaultActivation);
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, ReturnsLockedForLoadCredentialSessionChange)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};
    vault.credentialResult = VaultAccessResult::SessionChanged;

    const auto response = handle(
        vault, getCredentialRequest(vault.credential));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_FALSE(response.requestVaultActivation);
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, WipesSecretWhenLeaseChangesAfterResponseBuild)
{
    FakeNativeVaultAccess vault;
    vault.credential = makeCredential();
    vault.summaries = {makeSummary(vault.credential)};
    // Le faux coffre vérifie le lease à l'entrée de copySummaries() et de
    // loadCredential(), puis le processeur le vérifie cinq fois. La septième
    // vérification est celle effectuée après la construction de la réponse.
    vault.invalidateOnLeaseCheck = 7;

    const auto response = handle(
        vault, getCredentialRequest(vault.credential));
    const QJsonObject json = parseResponse(response);

    EXPECT_FALSE(json["ok"].toBool());
    EXPECT_EQ(json["error"].toString(), QStringLiteral("vault_locked"));
    EXPECT_FALSE(response.requestVaultActivation);
    EXPECT_FALSE(payloadContains(response, "secret-test"));
}

TEST(NativeRequestProcessorTest, ConvertsAdapterExceptionsToGenericError)
{
    FakeNativeVaultAccess summariesException;
    summariesException.summaries = {makeSummary(makeCredential())};
    summariesException.throwDuringCopySummaries = true;

    const auto summariesResponse = handle(
        summariesException,
        makeRequest("search_credentials", "https://example.com"));
    const QJsonObject summariesJson = parseResponse(summariesResponse);
    EXPECT_FALSE(summariesJson["ok"].toBool());
    EXPECT_EQ(summariesJson["error"].toString(),
              QStringLiteral("vault_access_failed"));
    EXPECT_FALSE(payloadContains(summariesResponse, "credential_matches"));

    FakeNativeVaultAccess credentialException;
    credentialException.credential = makeCredential();
    credentialException.summaries = {makeSummary(credentialException.credential)};
    credentialException.throwDuringLoadCredential = true;

    const auto credentialResponse = handle(
        credentialException,
        getCredentialRequest(credentialException.credential));
    const QJsonObject credentialJson = parseResponse(credentialResponse);
    EXPECT_FALSE(credentialJson["ok"].toBool());
    EXPECT_EQ(credentialJson["error"].toString(),
              QStringLiteral("vault_access_failed"));
    EXPECT_FALSE(payloadContains(credentialResponse, "secret-test"));
}

TEST(NativeRequestProcessorTest, EnforcesPayloadLimitAfterJsonEscaping)
{
    const std::string username = "a";
    const std::size_t fixedSize = credentialResponseSizeForAscii(username, "");
    const std::size_t maxPayload =
        passwall::native::NativeMessageMaxPayloadBytes;
    ASSERT_LT(fixedSize + 1, maxPayload);

    const auto makeVault = [&username](std::string password) {
        FakeNativeVaultAccess vault;
        vault.credential = makeCredential();
        vault.credential.username = username;
        vault.credential.password = std::move(password);
        vault.summaries = {makeSummary(vault.credential)};
        return vault;
    };

    FakeNativeVaultAccess below = makeVault(
        std::string(maxPayload - fixedSize - 1, 'x'));
    const auto belowResponse = handle(
        below, getCredentialRequest(below.credential));
    const QJsonObject belowJson = parseResponse(belowResponse);
    EXPECT_TRUE(belowJson["ok"].toBool());
    EXPECT_EQ(
        belowResponse.payloadView().size(),
        maxPayload - 1);

    FakeNativeVaultAccess exact = makeVault(
        std::string(maxPayload - fixedSize, 'x'));
    const auto exactResponse = handle(
        exact, getCredentialRequest(exact.credential));
    const QJsonObject exactJson = parseResponse(exactResponse);
    EXPECT_TRUE(exactJson["ok"].toBool());
    EXPECT_EQ(
        exactResponse.payloadView().size(),
        maxPayload);

    FakeNativeVaultAccess above = makeVault(
        std::string(maxPayload - fixedSize + 1, 'x'));
    const auto aboveResponse = handle(
        above, getCredentialRequest(above.credential));
    const QJsonObject aboveJson = parseResponse(aboveResponse);
    EXPECT_FALSE(aboveJson["ok"].toBool());
    EXPECT_EQ(aboveJson["error"].toString(),
              QStringLiteral("response_too_large"));
    EXPECT_FALSE(payloadContains(aboveResponse, "credential_selected"));

    FakeNativeVaultAccess escaped = makeVault(
        std::string((maxPayload - fixedSize) / 2, '\x01'));
    const auto escapedResponse = handle(
        escaped, getCredentialRequest(escaped.credential));
    const QJsonObject escapedJson = parseResponse(escapedResponse);
    EXPECT_FALSE(escapedJson["ok"].toBool());
    EXPECT_EQ(escapedJson["error"].toString(),
              QStringLiteral("response_too_large"));
}
