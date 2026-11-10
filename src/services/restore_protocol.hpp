#pragma once

// Private LOCAL protocol. JSON is metadata only. Password frames are read/written
// directly from owned SecureBuffer, never from a Qt/process/JSON owning buffer.
#include "services/vault_replacement_service.hpp"
#include <QJsonDocument>
#include <QJsonObject>
#include <QtEndian>
#include <array>
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace passwall::services::restore_protocol {
enum Type : unsigned char { Begin = 1, Probe, Permit, Ready, Password, Received,
    Cleaned, Phase, Result, CancelReceived };
inline constexpr quint32 metadataLimit = 32768, passwordLimit = 1048576;
inline constexpr int cooperativeMs = 1000, terminateMs = 1000, unknownMs = 1000;
inline std::array<char, 5> header(Type type, quint32 size) {
    std::array<char, 5> result{};
    qToLittleEndian(size, result.data()); result[4] = char(type); return result;
}
inline bool transfer(int fd, void* data, std::size_t size, bool writing,
                     bool (*stopped)() noexcept = nullptr) noexcept {
    auto* bytes = static_cast<char*>(data);
    while (size) {
        if (stopped && stopped()) return false;
        const auto count = writing ? ::send(fd, bytes, size, MSG_NOSIGNAL | MSG_DONTWAIT)
            : ::recv(fd, bytes, size, MSG_DONTWAIT);
        if (count > 0) { bytes += count; size -= count; continue; }
        if (count == 0) return false;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return false;
        pollfd wait{fd, short(writing ? POLLOUT : POLLIN), 0};
        int ready;
        do { ready = ::poll(&wait, 1, -1); } while (ready < 0 && errno == EINTR && !(stopped && stopped()));
        if (ready <= 0 || (wait.revents & (POLLERR | POLLNVAL))) return false;
        // POLLHUP can accompany the last readable bytes. recv decides EOF.
    }
    return true;
}
inline bool send(int fd, Type type, const QJsonObject& object = {}) {
    auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    if (bytes.size() > metadataLimit) return false;
    auto prefix = header(type, bytes.size());
    return transfer(fd, prefix.data(), prefix.size(), true)
        && transfer(fd, bytes.data(), bytes.size(), true);
}
inline bool readHeader(int fd, Type& type, quint32& size, bool (*stop)() noexcept = nullptr) {
    std::array<char, 5> prefix{};
    if (!transfer(fd, prefix.data(), prefix.size(), false, stop)) return false;
    size = qFromLittleEndian<quint32>(prefix.data());
    type = Type(static_cast<unsigned char>(prefix[4]));
    return type >= Begin && type <= CancelReceived
        && size <= (type == Password ? passwordLimit : metadataLimit);
}
inline bool readObject(int fd, quint32 size, QJsonObject& object, bool (*stop)() noexcept = nullptr) {
    if (size > metadataLimit) return false;
    QByteArray bytes(size, Qt::Uninitialized);
    if (!transfer(fd, bytes.data(), size, false, stop)) return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    object = document.object(); return true;
}
inline bool bound(const QJsonObject& object, const QString& operation, const QString& session) {
    return object["operation"].isString() && object["operation"].toString() == operation
        && object["session"].isString() && object["session"].toString() == session;
}
inline QJsonObject encode(const ReplacementResult& r) {
    return {{"outcome", int(r.outcome)}, {"finalization", int(r.finalization.state)},
        {"operation", r.operationId}, {"artifact", r.recoveryArtifact},
        {"diagnostic", r.diagnostic.left(4096)}, {"finalDiagnostic", r.finalization.diagnostic.left(4096)},
        {"precaution", int(r.precaution.publication)}, {"authenticationFailed", r.sourceAuthenticationFailed},
        {"precautionDiagnostic", QString::fromStdString(r.precaution.diagnostic).left(4096)}};
}
inline bool decode(const QJsonObject& o, ReplacementResult& r) {
    const auto number = [&](const char* key, int limit) {
        return o[key].isDouble() && o[key].toInt(-1) >= 0 && o[key].toInt(-1) <= limit
            && o[key].toDouble() == o[key].toInt(-1);
    };
    if (!o["authenticationFailed"].isBool() || !number("outcome", int(ReplacementOutcome::Replaced))
        || !number("finalization", int(ReplacementFinalizationState::RecoveryRequired))
        || !number("precaution", int(SnapshotPublication::PublishedDurabilityUnconfirmed))) return false;
    for (const auto* key : {"operation", "artifact", "diagnostic", "finalDiagnostic", "precautionDiagnostic"})
        if (!o[key].isString() || o[key].toString().size() > 4096) return false;
    r.outcome = ReplacementOutcome(o["outcome"].toInt());
    r.sourceAuthenticationFailed = o["authenticationFailed"].toBool();
    r.finalization.state = ReplacementFinalizationState(o["finalization"].toInt());
    r.operationId = o["operation"].toString(); r.recoveryArtifact = o["artifact"].toString();
    r.diagnostic = o["diagnostic"].toString(); r.finalization.diagnostic = o["finalDiagnostic"].toString();
    r.precaution.publication = SnapshotPublication(o["precaution"].toInt());
    r.precaution.diagnostic = o["precautionDiagnostic"].toString().toStdString(); return true;
}
inline bool consistent(const ReplacementResult& r, int phase) {
    if (r.sourceAuthenticationFailed && r.outcome != ReplacementOutcome::NotReplaced) return false;
    switch (r.outcome) {
    case ReplacementOutcome::NotReplaced:
    case ReplacementOutcome::CancelledBeforeEngagement:
        return phase < int(ReplacementCheckpoint::Armed);
    case ReplacementOutcome::EngagedRecoveryRequired:
        return phase >= int(ReplacementCheckpoint::BeforeArm) && phase < int(ReplacementCheckpoint::AfterExchange);
    case ReplacementOutcome::ReplacedDurabilityUnconfirmed:
        return phase >= int(ReplacementCheckpoint::AfterExchange);
    case ReplacementOutcome::ReplacedFinalizationPending:
        return phase == int(ReplacementCheckpoint::AfterDirectorySync);
    case ReplacementOutcome::Replaced:
        return phase == int(ReplacementCheckpoint::AfterDirectorySync)
            && r.finalization.state == ReplacementFinalizationState::Resolved;
    }
    return false;
}
} // namespace passwall::services::restore_protocol
