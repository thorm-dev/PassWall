#pragma once

#include "models/credential.hpp"

#include <QString>

namespace passwall::native {

// Accepte uniquement la représentation canonique produite par QByteArray::toHex():
// exactement 2 * EntryIdSize caractères ASCII minuscules ([0-9a-f]).
bool parseCanonicalEntryId(
    const QString& text,
    models::EntryId& entryId);

} // namespace passwall::native
