#include "native_bridge_server.hpp"
#include "native/native_message_limits.hpp"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QMetaObject>
#include <QPointer>
#include <QStandardPaths>
#include <QThread>
#include <QTimer>
#include <QtEndian>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

namespace passwall::native {

namespace {

constexpr qsizetype MaxBufferedBytes =
    static_cast<qsizetype>(NativeMessageMaxPayloadBytes) +
    static_cast<qsizetype>(NativeMessageFrameHeaderBytes);
constexpr qsizetype IncomingReadChunkBytes = 16 * 1024;
constexpr std::size_t OutgoingWriteChunkBytes = 64 * 1024;
constexpr int IncompleteFrameTimeoutMs = 5000;

QPointer<NativeBridgeServer> currentBridge;

// Efface explicitement une copie locale avant sa libération. Cela ne couvre
// pas les copies éventuelles détenues par Qt, le socket ou le système.
void wipeByteArray(QByteArray& bytes) noexcept
{
    if (!bytes.isEmpty()) {
        sodium_memzero(bytes.data(), static_cast<std::size_t>(bytes.size()));
        bytes.clear();
    }
}

bool copyToSecureBuffer(
    const QByteArray& source,
    core::SecureBuffer& destination) noexcept
{
    if (source.isEmpty() ||
        source.size() > static_cast<qsizetype>(NativeMessageMaxPayloadBytes) ||
        !core::CryptoEngine::initialize()) {
        return false;
    }

    try {
        core::SecureBuffer candidate(static_cast<std::size_t>(source.size()));
        std::memcpy(candidate.data(), source.constData(), candidate.size());
        destination = std::move(candidate);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

class NativeBridgeServer::ConnectionState final : public QObject
{
public:
    enum class SendPhase {
        Idle,
        Header,
        Payload,
        Draining
    };

    explicit ConnectionState(QLocalSocket* socketValue)
        : QObject(socketValue)
        , socket(socketValue)
        , incompleteFrameTimer(this)
    {
        incompleteFrameTimer.setSingleShot(true);
    }

    ~ConnectionState() override
    {
        wipeByteArray(inputBuffer);
        payload = core::SecureBuffer(0);
    }

    void clearOutgoing() noexcept
    {
        payload = core::SecureBuffer(0);
        header.fill(0);
        headerOffset = 0;
        payloadOffset = 0;
        responseSessionGeneration = 0;
        phase = SendPhase::Idle;
    }

    [[nodiscard]] bool isSending() const noexcept
    {
        return phase != SendPhase::Idle;
    }

    QLocalSocket* socket = nullptr;
    QByteArray inputBuffer;
    QTimer incompleteFrameTimer;
    std::array<unsigned char, NativeMessageFrameHeaderBytes> header{};
    core::SecureBuffer payload{0};
    std::size_t headerOffset = 0;
    std::size_t payloadOffset = 0;
    std::uint64_t responseSessionGeneration = 0;
    SendPhase phase = SendPhase::Idle;
    bool closing = false;
};

NativeBridgeServer::NativeBridgeServer(QObject* parent)
    : QObject(parent)
{
    currentBridge = this;
    server_.setSocketOptions(QLocalServer::UserAccessOption);

    connect(
        &server_,
        &QLocalServer::newConnection,
        this,
        [this]() {
            while (server_.hasPendingConnections()) {
                QLocalSocket* socket = server_.nextPendingConnection();
                if (socket != nullptr) {
                    handleConnection(socket);
                }
            }
        });
}

NativeBridgeServer::~NativeBridgeServer()
{
    stop();
    destroyConnectionStates();
    if (currentBridge == this) {
        currentBridge.clear();
    }
}

void NativeBridgeServer::invalidateCurrentSession(
    std::uint64_t newGeneration) noexcept
{
    const QPointer<NativeBridgeServer> bridge = currentBridge;
    if (bridge.isNull() || QThread::currentThread() != bridge->thread()) {
        return;
    }

    bridge->invalidateSession(newGeneration);
}

void NativeBridgeServer::invalidateSession(
    std::uint64_t newGeneration) noexcept
{
    if (QThread::currentThread() != thread()) {
        return;
    }

    activeSessionGeneration_ = newGeneration;

    const QSet<ConnectionState*> connections = connections_;
    for (ConnectionState* rawConnection : connections) {
        const QPointer<ConnectionState> connection(rawConnection);
        if (connection.isNull() ||
            connection->responseSessionGeneration == 0 ||
            connection->responseSessionGeneration == newGeneration) {
            continue;
        }

        abortConnection(connection.data());
    }
}

void NativeBridgeServer::setActivationHandler(std::function<void()> handler)
{
    activationHandler_ = std::move(handler);
}

void NativeBridgeServer::setRequestHandler(
    std::function<NativeRequestResponse(const QJsonObject&)> handler)
{
    requestHandler_ = std::move(handler);
}

void NativeBridgeServer::setPayloadSegmentAcceptedHandlerForTesting(
    std::function<void(std::uint64_t, std::size_t)> handler)
{
    payloadSegmentAcceptedHandlerForTesting_ = std::move(handler);
}

bool NativeBridgeServer::start(QString& error)
{
    const QString runtimeDirectory =
        QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);

    if (runtimeDirectory.isEmpty() || !QDir(runtimeDirectory).exists()) {
        error = QStringLiteral("Répertoire d'exécution utilisateur indisponible.");
        return false;
    }

    return startAtPath(
        runtimeDirectory + QStringLiteral("/passwall-native-bridge.sock"),
        error);
}

bool NativeBridgeServer::startAtPath(
    const QString& socketPath,
    QString& error)
{
    if (socketPath.isEmpty()) {
        error = QStringLiteral("Le chemin du socket ne peut pas être vide.");
        return false;
    }

    if (server_.isListening() || !socketPath_.isEmpty()) {
        error = QStringLiteral("Le serveur PassWall est déjà démarré.");
        return false;
    }

    if (QFile::exists(socketPath)) {
        error = QStringLiteral(
            "Un chemin de socket existe déjà. "
            "Vérifie qu'aucune instance de PassWall n'est active.");
        return false;
    }

    if (!server_.listen(socketPath)) {
        error = server_.errorString();
        return false;
    }

    socketPath_ = socketPath;
    return true;
}

void NativeBridgeServer::stop()
{
    const QSet<ConnectionState*> connections = connections_;
    for (ConnectionState* connection : connections) {
        abortConnection(connection);
    }

    server_.close();
    if (!socketPath_.isEmpty()) {
        QFile::remove(socketPath_);
        socketPath_.clear();
    }
}

void NativeBridgeServer::handleConnection(QLocalSocket* socket)
{
    if (socket == nullptr) {
        return;
    }

    auto* connection = new ConnectionState(socket);
    connections_.insert(connection);
    updateReadBufferLimit(connection);

    connect(
        &connection->incompleteFrameTimer,
        &QTimer::timeout,
        connection,
        [this, connection]() { abortConnection(connection); });

    connect(
        socket,
        &QLocalSocket::readyRead,
        connection,
        [this, connection]() { handleReadyRead(connection); });

    connect(
        socket,
        &QIODevice::bytesWritten,
        connection,
        [this, connection](qint64) { pumpWrite(connection); });

    connect(
        socket,
        &QLocalSocket::errorOccurred,
        connection,
        [this, connection](QLocalSocket::LocalSocketError) {
            abortConnection(connection);
        });

    connect(
        socket,
        &QLocalSocket::disconnected,
        connection,
        [this, connection, socket]() {
            connection->closing = true;
            connection->incompleteFrameTimer.stop();
            wipeByteArray(connection->inputBuffer);
            connection->clearOutgoing();
            socket->deleteLater();
        });

    connect(
        connection,
        &QObject::destroyed,
        this,
        [this, connection]() { connections_.remove(connection); });

    connection->incompleteFrameTimer.start(IncompleteFrameTimeoutMs);
}

void NativeBridgeServer::updateReadBufferLimit(
    ConnectionState* connection) noexcept
{
    if (connection == nullptr || connection->socket == nullptr ||
        connection->closing) {
        return;
    }

    const qsizetype buffered = connection->inputBuffer.size();
    const qsizetype remaining = buffered >= MaxBufferedBytes
        ? 1
        : MaxBufferedBytes - buffered;
    connection->socket->setReadBufferSize(remaining);
}

void NativeBridgeServer::handleReadyRead(ConnectionState* connection)
{
    if (connection == nullptr || connection->socket == nullptr ||
        connection->closing ||
        connection->socket->state() == QLocalSocket::UnconnectedState) {
        return;
    }

    while (connection->socket->bytesAvailable() > 0) {
        const qsizetype remaining =
            MaxBufferedBytes - connection->inputBuffer.size();
        if (remaining <= 0) {
            abortConnection(connection);
            return;
        }

        const qint64 readable = std::min<qint64>(
            connection->socket->bytesAvailable(),
            std::min<qint64>(remaining, IncomingReadChunkBytes));
        if (readable <= 0) {
            break;
        }

        QByteArray chunk = connection->socket->read(readable);
        if (chunk.isEmpty()) {
            break;
        }

        connection->inputBuffer.append(chunk);
        wipeByteArray(chunk);

        if (connection->inputBuffer.size() > MaxBufferedBytes) {
            abortConnection(connection);
            return;
        }
    }

    updateReadBufferLimit(connection);
    if (!connection->isSending()) {
        processNextFrame(connection);
    }
}

void NativeBridgeServer::processNextFrame(ConnectionState* connection)
{
    if (connection == nullptr || connection->socket == nullptr ||
        connection->closing || connection->isSending()) {
        return;
    }

    if (connection->inputBuffer.size() <
        static_cast<qsizetype>(NativeMessageFrameHeaderBytes)) {
        connection->incompleteFrameTimer.start(IncompleteFrameTimeoutMs);
        return;
    }

    const auto* header = reinterpret_cast<const uchar*>(
        connection->inputBuffer.constData());
    const quint32 length = qFromLittleEndian<quint32>(header);
    if (length == 0 || length > NativeMessageMaxPayloadBytes) {
        abortConnection(connection);
        return;
    }

    const qsizetype frameSize =
        static_cast<qsizetype>(NativeMessageFrameHeaderBytes) +
        static_cast<qsizetype>(length);
    if (connection->inputBuffer.size() < frameSize) {
        connection->incompleteFrameTimer.start(IncompleteFrameTimeoutMs);
        return;
    }

    QByteArray payload = connection->inputBuffer.mid(
        static_cast<qsizetype>(NativeMessageFrameHeaderBytes), length);
    sodium_memzero(connection->inputBuffer.data(),
                   static_cast<std::size_t>(frameSize));
    connection->inputBuffer.remove(0, frameSize);
    updateReadBufferLimit(connection);
    connection->incompleteFrameTimer.stop();

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    wipeByteArray(payload);

    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        queuePublicResponse(connection, QJsonObject{
            {"ok", false},
            {"error", "Message JSON invalide"}});
        return;
    }

    const QJsonObject request = document.object();
    const QString type = request.value("type").toString();
    if (type == QStringLiteral("ping")) {
        queuePublicResponse(connection, QJsonObject{
            {"ok", true},
            {"message", "PassWall Qt bridge opérationnel"},
            {"receivedType", "ping"}});
        return;
    }

    if (type == QStringLiteral("activate")) {
        try {
            if (activationHandler_) {
                activationHandler_();
                queuePublicResponse(connection, QJsonObject{
                    {"ok", true},
                    {"message", "Demande d'activation traitée"},
                    {"receivedType", "activate"}});
            } else {
                queuePublicResponse(connection, QJsonObject{
                    {"ok", false},
                    {"error", "Gestionnaire d'activation indisponible"}});
            }
        } catch (...) {
            abortConnection(connection);
        }
        return;
    }

    if (!requestHandler_) {
        queuePublicResponse(connection, QJsonObject{
            {"ok", false},
            {"error", "Gestionnaire de requêtes indisponible"}});
        return;
    }

    try {
        NativeRequestResponse response = requestHandler_(request);
        queueProcessorResponse(connection, std::move(response));
    } catch (...) {
        abortConnection(connection);
    }
}

void NativeBridgeServer::queuePublicResponse(
    ConnectionState* connection,
    const QJsonObject& response)
{
    QByteArray serialized;
    try {
        serialized = QJsonDocument(response).toJson(QJsonDocument::Compact);
        core::SecureBuffer payload(0);
        if (!copyToSecureBuffer(serialized, payload)) {
            wipeByteArray(serialized);
            abortConnection(connection);
            return;
        }

        wipeByteArray(serialized);
        queuePayload(connection, std::move(payload), 0);
    } catch (...) {
        wipeByteArray(serialized);
        abortConnection(connection);
    }
}

void NativeBridgeServer::queueProcessorResponse(
    ConnectionState* connection,
    NativeRequestResponse&& response)
{
    try {
        const std::uint64_t sessionGeneration =
            response.sessionGeneration();
        if (!isResponseSessionCurrent(sessionGeneration)) {
            response.wipePayload();
            abortConnection(connection);
            return;
        }

        if (response.requestVaultActivation && activationHandler_) {
            activationHandler_();
        }

        if (!response.hasPayload()) {
            abortConnection(connection);
            return;
        }

        queuePayload(
            connection,
            std::move(response).takePayload(),
            sessionGeneration);
    } catch (...) {
        abortConnection(connection);
    }
}

void NativeBridgeServer::queuePayload(
    ConnectionState* connection,
    core::SecureBuffer&& payload,
    std::uint64_t sessionGeneration)
{
    if (connection == nullptr || connection->socket == nullptr ||
        connection->closing || connection->isSending() || payload.empty() ||
        payload.size() > NativeMessageMaxPayloadBytes ||
        !isResponseSessionCurrent(sessionGeneration)) {
        abortConnection(connection);
        return;
    }

    const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
    for (std::size_t index = 0; index < connection->header.size(); ++index) {
        connection->header[index] = static_cast<unsigned char>(
            (length >> (index * 8U)) & 0xffU);
    }

    connection->payload = std::move(payload);
    connection->headerOffset = 0;
    connection->payloadOffset = 0;
    connection->responseSessionGeneration = sessionGeneration;
    connection->phase = ConnectionState::SendPhase::Header;
    pumpWrite(connection);
}

void NativeBridgeServer::pumpWrite(ConnectionState* connection)
{
    if (connection == nullptr || connection->socket == nullptr ||
        connection->closing || !connection->isSending()) {
        return;
    }

    QLocalSocket* socket = connection->socket;
    while (!connection->closing) {
        if (!isResponseSessionCurrent(
                connection->responseSessionGeneration)) {
            abortConnection(connection);
            return;
        }

        if (socket->state() == QLocalSocket::UnconnectedState) {
            abortConnection(connection);
            return;
        }
        if (socket->bytesToWrite() != 0) {
            return;
        }

        if (connection->phase == ConnectionState::SendPhase::Header) {
            if (connection->headerOffset == connection->header.size()) {
                connection->phase = ConnectionState::SendPhase::Payload;
                continue;
            }

            const std::size_t remaining =
                connection->header.size() - connection->headerOffset;
            const qint64 written = socket->write(
                reinterpret_cast<const char*>(
                    connection->header.data() + connection->headerOffset),
                static_cast<qint64>(remaining));
            if (written <= 0 || static_cast<std::size_t>(written) > remaining) {
                abortConnection(connection);
                return;
            }

            connection->headerOffset += static_cast<std::size_t>(written);
            continue;
        }

        if (connection->phase == ConnectionState::SendPhase::Payload) {
            if (connection->payloadOffset == connection->payload.size()) {
                connection->payload = core::SecureBuffer(0);
                connection->phase = ConnectionState::SendPhase::Draining;
                continue;
            }

            const std::size_t remaining =
                connection->payload.size() - connection->payloadOffset;
            const std::size_t requested = std::min(
                remaining, OutgoingWriteChunkBytes);
            const qint64 written = socket->write(
                reinterpret_cast<const char*>(
                    connection->payload.data() + connection->payloadOffset),
                static_cast<qint64>(requested));
            if (written <= 0 || static_cast<std::size_t>(written) > requested) {
                abortConnection(connection);
                return;
            }

            // QLocalSocket a accepté cette portion pendant write(). La copie
            // locale ne sera plus relue, même si Qt conserve sa propre copie.
            sodium_memzero(
                connection->payload.data() + connection->payloadOffset,
                static_cast<std::size_t>(written));
            connection->payloadOffset += static_cast<std::size_t>(written);

            if (payloadSegmentAcceptedHandlerForTesting_) {
                try {
                    payloadSegmentAcceptedHandlerForTesting_(
                        connection->responseSessionGeneration,
                        static_cast<std::size_t>(written));
                } catch (...) {
                    abortConnection(connection);
                    return;
                }
            }

            if (connection->closing || !isResponseSessionCurrent(
                    connection->responseSessionGeneration)) {
                abortConnection(connection);
                return;
            }
            continue;
        }

        if (connection->phase == ConnectionState::SendPhase::Draining) {
            finishResponse(connection);
        }
        return;
    }
}

void NativeBridgeServer::finishResponse(ConnectionState* connection)
{
    if (connection == nullptr || connection->closing ||
        connection->socket == nullptr || connection->socket->bytesToWrite() != 0) {
        return;
    }

    if (!isResponseSessionCurrent(connection->responseSessionGeneration)) {
        abortConnection(connection);
        return;
    }

    connection->clearOutgoing();
    if (connection->inputBuffer.isEmpty()) {
        connection->incompleteFrameTimer.start(IncompleteFrameTimeoutMs);
        return;
    }

    const QPointer<NativeBridgeServer> bridge(this);
    const QPointer<ConnectionState> guardedConnection(connection);
    QMetaObject::invokeMethod(
        connection,
        [bridge, guardedConnection]() {
            if (bridge.isNull() || guardedConnection.isNull() ||
                !bridge->connections_.contains(guardedConnection.data())) {
                return;
            }

            if (!bridge->isResponseSessionCurrent(
                    guardedConnection->responseSessionGeneration)) {
                bridge->abortConnection(guardedConnection.data());
                return;
            }

            bridge->processNextFrame(guardedConnection.data());
        },
        Qt::QueuedConnection);
}

bool NativeBridgeServer::isResponseSessionCurrent(
    std::uint64_t sessionGeneration) const noexcept
{
    return sessionGeneration == 0 ||
        (activeSessionGeneration_ != 0 &&
         sessionGeneration == activeSessionGeneration_);
}

void NativeBridgeServer::abortConnection(ConnectionState* connection) noexcept
{
    if (connection == nullptr || connection->closing) {
        return;
    }

    connection->closing = true;
    connection->incompleteFrameTimer.stop();
    wipeByteArray(connection->inputBuffer);
    connection->clearOutgoing();

    if (connection->socket != nullptr &&
        connection->socket->state() != QLocalSocket::UnconnectedState) {
        connection->socket->abort();
    }
}

void NativeBridgeServer::destroyConnectionStates() noexcept
{
    // ConnectionState est enfant du QLocalSocket. Sans destruction explicite
    // ici, il pourrait n'être détruit que pendant la destruction du membre
    // server_, après celle de connections_. Son signal destroyed() tenterait
    // alors de retirer un élément d'un QSet dont la durée de vie est terminée.
    const QSet<ConnectionState*> connections = connections_;
    for (ConnectionState* rawConnection : connections) {
        const QPointer<ConnectionState> connection(rawConnection);
        if (connection.isNull()) {
            continue;
        }

        abortConnection(connection.data());
        if (!connection.isNull()) {
            delete connection.data();
        }
    }

    connections_.clear();
}

} // namespace passwall::native
