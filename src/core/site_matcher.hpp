#pragma once

#include <QString>

#include <string>

namespace passwall::core {

class SiteMatcher final {
public:
    // Vérifie qu'une URL est valide et utilise HTTP ou HTTPS.
    static bool isValidHttpUrl(const QString& url);

    // Compare les origines : protocole, hôte et port.
    // Une URL enregistrée sans protocole est interprétée comme HTTPS.
    static bool matchesOrigin(
        const QString& requestedUrl,
        const std::string& storedUrl);
};

} // namespace passwall::core