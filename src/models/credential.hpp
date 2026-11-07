
#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace passwall::models {

inline constexpr std::size_t EntryIdSize = 16;

using EntryId = std::array<unsigned char, EntryIdSize>;

struct Credential {
    EntryId id{};
    std::uint32_t version = 1;

    std::string title;
    std::string url;
    std::string username;
    std::string password;
    std::string notes;
};

struct CredentialSummary {
    EntryId id{};
    std::uint32_t version = 1;

    std::string title;
    std::string url;
    std::string username;
};

} // namespace passwall::models
