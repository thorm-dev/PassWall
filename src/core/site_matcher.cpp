#include "core/site_matcher.hpp"

#include <QUrl>

namespace passwall::core {
namespace {

bool parseHttpUrl(const QString& input, QUrl& output)
{
    output = QUrl(input, QUrl::StrictMode);

    if (!output.isValid()) {
        return false;
    }

    const QString scheme = output.scheme().toLower();

    if (scheme != QStringLiteral("https") &&
        scheme != QStringLiteral("http")) {
        return false;
    }

    if (output.host().isEmpty() ||
        !output.userInfo().isEmpty()) {
        return false;
    }

    // Refuser les ports explicitement invalides.
    if (output.port(-1) == -1 &&
        output.authority().contains(QLatin1Char(':')) &&
        !output.authority().startsWith(QLatin1Char('['))) {
        const QString authority = output.authority();
        const qsizetype colon = authority.lastIndexOf(QLatin1Char(':'));

        if (colon >= 0 &&
            colon + 1 < authority.size()) {
            bool ok = false;
            const int port = authority.mid(colon + 1).toInt(&ok);

            if (!ok || port < 1 || port > 65535) {
                return false;
            }
        }
    }

    return true;
}

int effectivePort(const QUrl& url)
{
    const int defaultPort =
        url.scheme().compare(QStringLiteral("https"),
                             Qt::CaseInsensitive) == 0
            ? 443
            : 80;

    return url.port(defaultPort);
}

} // namespace

bool SiteMatcher::isValidHttpUrl(const QString& url)
{
    QUrl parsed;
    return parseHttpUrl(url, parsed);
}

bool SiteMatcher::matchesOrigin(
    const QString& requestedUrl,
    const std::string& storedUrl)
{
    QUrl requested;

    if (!parseHttpUrl(requestedUrl, requested)) {
        return false;
    }

    QString stored = QString::fromUtf8(
        storedUrl.data(),
        static_cast<qsizetype>(storedUrl.size())).trimmed();

    if (stored.isEmpty()) {
        return false;
    }

    // Conserver la compatibilité avec les URL sans protocole.
    if (!stored.contains(QStringLiteral("://"))) {
        stored.prepend(QStringLiteral("https://"));
    }

    QUrl saved;

    if (!parseHttpUrl(stored, saved)) {
        return false;
    }

    return requested.scheme().compare(
               saved.scheme(), Qt::CaseInsensitive) == 0 &&
           requested.host().compare(
               saved.host(), Qt::CaseInsensitive) == 0 &&
           effectivePort(requested) == effectivePort(saved);
}

} // namespace passwall::core