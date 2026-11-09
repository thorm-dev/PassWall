#pragma once

#include <QByteArray>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaType>
#include <QString>
#include "services/vault_snapshot_service.hpp"
#include "services/backup_file_evidence.hpp"
#include <optional>

namespace passwall::services {

enum class BackupOutcome { FailedBeforePublication, Published, DurabilityUnconfirmed,
                           CancelledBeforePublication, Unknown };
struct BackupResult {
    BackupOutcome outcome = BackupOutcome::Unknown;
    QString diagnostic;
    std::optional<BackupFileEvidence> receipt;
};

struct AutomaticBackupContext { QString settingsFile, localId, attempt; };
enum class RotationOutcome { Complete, Refused, Cancelled, Unknown };
struct RotationResult {
    RotationOutcome outcome = RotationOutcome::Unknown;
    QString diagnostic;
    int deleted = 0;
};

namespace backup_protocol {
inline constexpr qsizetype requestLimit = 32768;
inline constexpr qsizetype resultLimit = 4096;
inline constexpr int cooperativeCancelMs = 1000;
inline constexpr int terminateMs = 1000;
inline constexpr int killReportMs = 1000;

inline bool validPath(const QString& path)
{
    return !path.isEmpty() && !path.contains(QChar::Null) && QDir::isAbsolutePath(path)
        && path.toUtf8().size() <= 4096;
}
inline QByteArray request(const QString& source, const QString& destination,
    const std::optional<SnapshotDirectoryIdentity>& directory = {}, bool receipt = false)
{
    QJsonObject object{{"v", 1}, {"source", source}, {"destination", destination}};
    if (directory) object.insert("directoryIdentity", QJsonObject{
        {"device", QString::number(directory->device)}, {"inode", QString::number(directory->inode)}});
    if (receipt) object.insert("receipt", true);
    return QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n';
}
inline bool parseRequest(const QByteArray& bytes, QString& source, QString& destination,
    std::optional<SnapshotDirectoryIdentity>* directory = nullptr, bool* receipt = nullptr)
{
    if (directory) directory->reset();
    if (receipt) *receipt = false;
    if (bytes.size() > requestLimit) return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    const auto object = document.object();
    if (error.error != QJsonParseError::NoError || !document.isObject()
        || object.size() < 3 || object.size() > 5
        || object.value("v") != QJsonValue(1) || !object.value("source").isString()
        || !object.value("destination").isString()) return false;
    for (auto it = object.begin(); it != object.end(); ++it)
        if (it.key() != "v" && it.key() != "source" && it.key() != "destination"
            && it.key() != "directoryIdentity" && it.key() != "receipt") return false;
    if (object.contains("receipt")) {
        if (object["receipt"] != QJsonValue(true)) return false;
        if (receipt) *receipt = true;
    }
    if (object.contains("directoryIdentity")) {
        const auto identity = object.value("directoryIdentity").toObject();
        if (identity.size() != 2 || !identity["device"].isString() || !identity["inode"].isString()) return false;
        bool a = false, b = false;
        const auto device = identity["device"].toString().toULongLong(&a);
        const auto inode = identity["inode"].toString().toULongLong(&b);
        if (!a || !b || inode == 0 || QString::number(device) != identity["device"].toString()
            || QString::number(inode) != identity["inode"].toString()) return false;
        if (directory) *directory = SnapshotDirectoryIdentity{device, inode};
    }
    source = object.value("source").toString();
    destination = object.value("destination").toString();
    return validPath(source) && validPath(destination);
}
inline QString name(BackupOutcome outcome)
{
    switch (outcome) {
    case BackupOutcome::FailedBeforePublication: return QStringLiteral("failed");
    case BackupOutcome::Published: return QStringLiteral("published");
    case BackupOutcome::DurabilityUnconfirmed: return QStringLiteral("durability-unconfirmed");
    case BackupOutcome::CancelledBeforePublication: return QStringLiteral("cancelled");
    default: return QStringLiteral("unknown");
    }
}
inline QByteArray result(const BackupResult& value)
{
    QJsonObject object{{"v", 1}, {"outcome", name(value.outcome)},
        {"diagnostic", value.diagnostic.left(1024)}};
    if (value.receipt) object.insert("receipt", encodeBackupEvidence(*value.receipt));
    return QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n';
}
inline bool parseResult(const QByteArray& bytes, BackupResult& value)
{
    if (bytes.isEmpty() || bytes.size() > resultLimit) return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    const auto object = document.object();
    if (error.error != QJsonParseError::NoError || !document.isObject()
        || (object.size() != 3 && object.size() != 4)
        || object.value("v") != QJsonValue(1) || !object.value("outcome").isString()
        || !object.value("diagnostic").isString()
        || object.value("diagnostic").toString().size() > 1024) return false;
    for (auto outcome : {BackupOutcome::FailedBeforePublication, BackupOutcome::Published,
             BackupOutcome::DurabilityUnconfirmed, BackupOutcome::CancelledBeforePublication}) {
        if (object.value("outcome").toString() == name(outcome)) {
            value = {outcome, object.value("diagnostic").toString()};
            if (object.size() == 4) {
                BackupFileEvidence evidence;
                if ((outcome != BackupOutcome::Published && outcome != BackupOutcome::DurabilityUnconfirmed)
                    || !decodeBackupEvidence(object.value("receipt"), evidence)) return false;
                value.receipt = std::move(evidence);
            }
            return true;
        }
    }
    return false;
}

inline QByteArray rotationRequest(const QString& source, const AutomaticBackupContext& context)
{
    return QJsonDocument(QJsonObject{{"v", 1}, {"source", source}, {"settings", context.settingsFile},
        {"localId", context.localId}, {"attempt", context.attempt}}).toJson(QJsonDocument::Compact) + '\n';
}
inline bool parseRotationRequest(const QByteArray& bytes, QString& source, AutomaticBackupContext& context)
{
    if (bytes.size() > requestLimit) return false;
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(bytes, &error);
    const auto o = doc.object();
    if (error.error != QJsonParseError::NoError || !doc.isObject() || o.size() != 5 || o["v"] != QJsonValue(1)
        || !o["source"].isString() || !o["settings"].isString()
        || !o["localId"].isString() || !o["attempt"].isString()) return false;
    source = o["source"].toString();
    context = {o["settings"].toString(), o["localId"].toString(), o["attempt"].toString()};
    return validPath(source) && QDir::cleanPath(source) == source
        && validPath(context.settingsFile) && QDir::cleanPath(context.settingsFile) == context.settingsFile;
}
inline QByteArray rotationResult(const RotationResult& r)
{
    QString state = "unknown";
    switch (r.outcome) {
    case RotationOutcome::Complete: state = "complete"; break;
    case RotationOutcome::Refused: state = "refused"; break;
    case RotationOutcome::Cancelled: state = "cancelled"; break;
    case RotationOutcome::Unknown: break;
    }
    return QJsonDocument(QJsonObject{{"v", 1}, {"operation", "rotation"}, {"outcome", state},
        {"diagnostic", r.diagnostic.left(1024)}, {"deleted", r.deleted}}).toJson(QJsonDocument::Compact) + '\n';
}
inline bool parseRotationResult(const QByteArray& bytes, RotationResult& r)
{
    if (bytes.isEmpty() || bytes.size() > resultLimit) return false;
    QJsonParseError error;
    const auto doc = QJsonDocument::fromJson(bytes, &error);
    const auto o = doc.object();
    if (error.error != QJsonParseError::NoError || !doc.isObject() || o.size() != 5
        || o["v"] != QJsonValue(1) || o["operation"] != "rotation" || !o["diagnostic"].isString()
        || o["diagnostic"].toString().size() > 1024 || !o["deleted"].isDouble()
        || o["deleted"].toInt(-1) < 0 || o["deleted"] != QJsonValue(o["deleted"].toInt())) return false;
    for (auto state : {RotationOutcome::Complete, RotationOutcome::Refused, RotationOutcome::Cancelled, RotationOutcome::Unknown}) {
        const auto text = state == RotationOutcome::Complete ? "complete" :
            state == RotationOutcome::Refused ? "refused" : state == RotationOutcome::Cancelled ? "cancelled" : "unknown";
        if (o["outcome"] == text) {
            r = {state, o["diagnostic"].toString(), o["deleted"].toInt()}; return true;
        }
    }
    return false;
}
} // namespace backup_protocol
} // namespace passwall::services

Q_DECLARE_METATYPE(passwall::services::BackupResult)
Q_DECLARE_METATYPE(passwall::services::RotationResult)
