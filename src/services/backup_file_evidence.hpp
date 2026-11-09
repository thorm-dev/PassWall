#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QString>

namespace passwall::services {
// Evidence about encrypted bytes only. Not a MAC, nor a defence against a
// malicious process with the same UID. Empty birth/mount evidence is readable
// for portability but NEVER grants automatic deletion permission.
struct BackupFileEvidence {
    quint64 device = 0, inode = 0, size = 0, mount = 0;
    quint64 directoryDevice = 0, directoryInode = 0, directoryMount = 0;
    QString birth, modified, changed, directoryBirth;
    QByteArray sha256;
    bool operator==(const BackupFileEvidence&) const = default;
    [[nodiscard]] bool permitsDeletion() const noexcept {
        return inode && size && mount && directoryInode && directoryMount
            && !birth.isEmpty() && !directoryBirth.isEmpty()
            && !modified.isEmpty() && !changed.isEmpty() && sha256.size() == 32;
    }
};

inline QJsonObject encodeBackupEvidence(const BackupFileEvidence& e)
{
    return {{"v", 1}, {"device", QString::number(e.device)}, {"inode", QString::number(e.inode)},
        {"size", QString::number(e.size)}, {"mount", QString::number(e.mount)},
        {"directoryDevice", QString::number(e.directoryDevice)},
        {"directoryInode", QString::number(e.directoryInode)},
        {"directoryMount", QString::number(e.directoryMount)}, {"birth", e.birth},
        {"modified", e.modified}, {"changed", e.changed}, {"directoryBirth", e.directoryBirth},
        {"sha256", QString::fromLatin1(e.sha256.toHex())}};
}

inline bool decodeBackupEvidence(const QJsonValue& value, BackupFileEvidence& output)
{
    const auto o = value.toObject();
    BackupFileEvidence e;
    const auto number = [&](const char* key, quint64& target) {
        const auto v = o.value(key);
        bool ok = false;
        target = v.toString().toULongLong(&ok);
        return v.isString() && ok && QString::number(target) == v.toString();
    };
    const auto timestamp = [&](const char* key, QString& target, bool optional) {
        const auto v = o.value(key); target = v.toString();
        if (!v.isString()) return false;
        if (target.isEmpty()) return optional;
        const auto pieces = target.split(':');
        if (pieces.size() != 2) return false;
        bool a = false, b = false;
        const auto seconds = pieces[0].toLongLong(&a);
        const auto nanos = pieces[1].toUInt(&b);
        return a && b && nanos < 1000000000 && QString::number(seconds) == pieces[0]
            && QString::number(nanos) == pieces[1];
    };
    const auto hex = o["sha256"].toString();
    e.sha256 = QByteArray::fromHex(hex.toLatin1());
    if (!value.isObject() || o.size() != 13 || o["v"] != QJsonValue(1)
        || !number("device", e.device) || !number("inode", e.inode) || !number("size", e.size)
        || !number("mount", e.mount) || !number("directoryDevice", e.directoryDevice)
        || !number("directoryInode", e.directoryInode) || !number("directoryMount", e.directoryMount)
        || !timestamp("birth", e.birth, true) || !timestamp("modified", e.modified, false)
        || !timestamp("changed", e.changed, false) || !timestamp("directoryBirth", e.directoryBirth, true)
        || !o["sha256"].isString() || e.sha256.size() != 32 || hex != QString::fromLatin1(e.sha256.toHex())
        || !e.inode || !e.size || !e.directoryInode) return false;
    output = std::move(e);
    return true;
}
} // namespace passwall::services
