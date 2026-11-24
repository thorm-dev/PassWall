#pragma once

#include <QDateTime>
#include <QRegularExpression>
#include <QString>
#include <QTimeZone>

namespace passwall::services {

// Generation numbers belong to the files in one series, not to the
// coordinator's transient request identifiers. UTC is informational only.
inline QString backupGenerationName(quint64 generation, const QDateTime& timestamp)
{
    const QString utc = timestamp.toUTC().toString(QStringLiteral("yyyy-MM-dd_HH-mm-ss"));
    if (generation == 0 || !timestamp.isValid() || utc.size() != 19)
        return {};
    return QStringLiteral("generation_%1_%2.pwdb").arg(generation).arg(utc);
}

inline bool parseBackupGenerationName(const QString& name, quint64& generation,
    QDateTime& timestamp)
{
    generation = 0;
    timestamp = {};
    static const QRegularExpression expression(QStringLiteral(
        R"(\Ageneration_([1-9][0-9]*)_([0-9]{4}-[0-9]{2}-[0-9]{2})_([0-9]{2}-[0-9]{2}-[0-9]{2})\.pwdb\z)"));
    const auto match = expression.match(name);
    if (!match.hasMatch()) return false;
    bool ok = false;
    const quint64 number = match.captured(1).toULongLong(&ok);
    if (!ok || number == 0) return false;
    const QDateTime dateTime(QDate::fromString(match.captured(2), QStringLiteral("yyyy-MM-dd")),
        QTime::fromString(match.captured(3), QStringLiteral("HH-mm-ss")), QTimeZone::utc());
    if (backupGenerationName(number, dateTime) != name) return false;
    generation = number;
    timestamp = dateTime;
    return true;
}

// Only files claiming the managed backup naming convention can make its
// ordering ambiguous. Auxiliary files must remain outside the selection.
inline bool isBackupGenerationCandidate(const QString& name)
{
    return name.startsWith(QStringLiteral("generation_"))
        && name.endsWith(QStringLiteral(".pwdb"));
}

} // namespace passwall::services
