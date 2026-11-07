#include "native/entry_id_parser.hpp"

#include <cstddef>

namespace passwall::native {
namespace {

int hexNibble(const QChar character)
{
    const ushort value = character.unicode();

    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }

    return -1;
}

} // namespace

bool parseCanonicalEntryId(
    const QString& text,
    models::EntryId& entryId)
{
    if (text.size() != static_cast<qsizetype>(models::EntryIdSize * 2)) {
        return false;
    }

    models::EntryId parsed{};
    for (std::size_t index = 0; index < parsed.size(); ++index) {
        const int highNibble = hexNibble(text.at(
            static_cast<qsizetype>(index * 2)));
        const int lowNibble = hexNibble(text.at(
            static_cast<qsizetype>(index * 2 + 1)));

        if (highNibble < 0 || lowNibble < 0) {
            return false;
        }

        parsed[index] = static_cast<unsigned char>(
            (highNibble << 4) | lowNibble);
    }

    entryId = parsed;
    return true;
}

} // namespace passwall::native
