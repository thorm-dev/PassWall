
#pragma once

#include "native/native_request_processor.hpp"

#include <QLocalServer>
#include <QObject>
#include <QJsonObject>
#include <QSet>
#include <QString>

#include <cstddef>
#include <cstdint>
#include <functional>

class QLocalSocket;

namespace passwall::native {

class NativeBridgeServer final : public QObject
{
    Q_OBJECT

public:
    explicit NativeBridgeServer(QObject* parent = nullptr);
    ~NativeBridgeServer() override;

    bool start(QString& error);
    bool startAtPath(const QString& socketPath, QString& error);
    void stop();

    // Invalide synchroniquement les réponses liées à une génération plus
    // ancienne. Les octets déjà acceptés par Qt ou le noyau ne peuvent pas
    // être rappelés, mais le SecureBuffer restant est effacé avant l'abandon
    // de la connexion.
    void invalidateSession(std::uint64_t newGeneration) noexcept;

    // L'application ne possède qu'un bridge sur son thread Qt. Ce point
    // d'entrée permet à MainWindow d'invalider ce bridge sans exposer les
    // détails de transport à NativeRequestProcessor.
    static void invalidateCurrentSession(
        std::uint64_t newGeneration) noexcept;

    void setActivationHandler(std::function<void()> handler);

    void setRequestHandler(
        std::function<NativeRequestResponse(const QJsonObject&)> handler);

    // Point d'observation sans accès au payload, réservé aux tests de
    // transmission segmentée. Il est vide en production.
    void setPayloadSegmentAcceptedHandlerForTesting(
        std::function<void(std::uint64_t, std::size_t)> handler);

private:
    class ConnectionState;

    void handleConnection(QLocalSocket* socket);
    void handleReadyRead(ConnectionState* connection);
    void processNextFrame(ConnectionState* connection);
    void queuePublicResponse(
        ConnectionState* connection,
        const QJsonObject& response);
    void queueProcessorResponse(
        ConnectionState* connection,
        NativeRequestResponse&& response);
    void queuePayload(
        ConnectionState* connection,
        core::SecureBuffer&& payload,
        std::uint64_t sessionGeneration);
    void pumpWrite(ConnectionState* connection);
    void abortConnection(ConnectionState* connection) noexcept;
    void destroyConnectionStates() noexcept;
    void finishResponse(ConnectionState* connection);
    void updateReadBufferLimit(ConnectionState* connection) noexcept;
    [[nodiscard]] bool isResponseSessionCurrent(
        std::uint64_t sessionGeneration) const noexcept;

    QLocalServer server_;
    QString socketPath_;

    std::function<void()> activationHandler_;
    std::function<NativeRequestResponse(const QJsonObject&)> requestHandler_;
    std::function<void(std::uint64_t, std::size_t)>
        payloadSegmentAcceptedHandlerForTesting_;
    QSet<ConnectionState*> connections_;
    std::uint64_t activeSessionGeneration_ = 0;
};

} // namespace passwall::native
