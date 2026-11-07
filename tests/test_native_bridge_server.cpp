
#include "native/native_bridge_server.hpp"
#include "native/native_message_limits.hpp"
#include "native/native_request_processor.hpp"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QMetaObject>
#include <QTemporaryDir>
#include <QThread>
#include <QtEndian>

#include <gtest/gtest.h>

#include <functional>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using passwall::models::Credential;
using passwall::models::CredentialSummary;
using passwall::native::NativeRequestProcessor;
using passwall::native::NativeVaultAccess;
using passwall::native::VaultAccessResult;
using passwall::native::VaultLease;

namespace {

QCoreApplication& ensureQtApplication()
{
    static int argc = 1;
    static char arg0[] = "passwall_tests";
    static char* argv[] = {arg0, nullptr};

    static QCoreApplication app(argc, argv);
    return app;
}

bool waitUntil(
    const std::function<bool()>& condition,
    int timeoutMs)
{
    QCoreApplication& app = ensureQtApplication();
    QElapsedTimer elapsed;
    elapsed.start();

    while (!condition()) {
        app.processEvents(QEventLoop::AllEvents, 20);

        if (elapsed.elapsed() >= timeoutMs) {
            return condition();
        }

        QThread::msleep(5);
    }

    return true;
}

void processEventsFor(int durationMs)
{
    QCoreApplication& app = ensureQtApplication();
    QElapsedTimer elapsed;
    elapsed.start();

    while (elapsed.elapsed() < durationMs) {
        app.processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(5);
    }
}

QByteArray makeFrame(const QJsonObject& object)
{
    const QByteArray payload =
        QJsonDocument(object).toJson(QJsonDocument::Compact);

    const quint32 length =
        qToLittleEndian(static_cast<quint32>(payload.size()));

    QByteArray frame;
    frame.append(
        reinterpret_cast<const char*>(&length),
        sizeof(length));
    frame.append(payload);

    return frame;
}

QByteArray makeHeader(quint32 length)
{
    const quint32 littleEndianLength = qToLittleEndian(length);

    QByteArray header;
    header.append(
        reinterpret_cast<const char*>(&littleEndianLength),
        sizeof(littleEndianLength));

    return header;
}

Credential makeCredential()
{
    Credential credential;
    credential.id[0] = 0x42;
    credential.version = 1;
    credential.title = "Compte bridge";
    credential.url = "https://example.com/login";
    credential.username = "alice";
    credential.password = "bridge-secret";
    credential.notes = "note-privee";
    return credential;
}

CredentialSummary makeSummary(const Credential& credential)
{
    CredentialSummary summary;
    summary.id = credential.id;
    summary.version = credential.version;
    summary.title = credential.title;
    summary.url = credential.url;
    summary.username = credential.username;
    return summary;
}

QString entryIdText(const passwall::models::EntryId& entryId)
{
    return QString::fromLatin1(QByteArray(
        reinterpret_cast<const char*>(entryId.data()),
        static_cast<qsizetype>(entryId.size())).toHex());
}

class BridgeTestVault final : public NativeVaultAccess
{
public:
    VaultLease acquireLease() const noexcept override
    {
        return {unlocked, generation};
    }

    bool isLeaseCurrent(const VaultLease& lease) const noexcept override
    {
        return lease.unlocked && unlocked && lease.generation == generation;
    }

    VaultAccessResult copySummaries(
        const VaultLease& lease,
        std::vector<CredentialSummary>& output) override
    {
        output.clear();
        if (!isLeaseCurrent(lease)) {
            return VaultAccessResult::SessionChanged;
        }
        output = summaries;
        return VaultAccessResult::Success;
    }

    VaultAccessResult loadCredential(
        const VaultLease& lease,
        const passwall::models::EntryId& entryId,
        Credential& output) override
    {
        output = Credential{};
        if (!isLeaseCurrent(lease)) {
            return VaultAccessResult::SessionChanged;
        }
        if (credential.id != entryId) {
            return VaultAccessResult::NotFound;
        }

        output = credential;
        if (invalidateDuringLoad) {
            ++generation;
        }
        return VaultAccessResult::Success;
    }

    bool unlocked = true;
    mutable std::uint64_t generation = 1;
    bool invalidateDuringLoad = false;
    Credential credential = makeCredential();
    std::vector<CredentialSummary> summaries = {makeSummary(credential)};
};

void installProcessorHandler(
    passwall::native::NativeBridgeServer& server,
    BridgeTestVault& vault)
{
    server.invalidateSession(vault.generation);
    server.setRequestHandler([&vault](const QJsonObject& request) {
        NativeRequestProcessor processor(vault);
        return processor.handle(request);
    });
}

bool readResponse(
    QLocalSocket& socket,
    QJsonObject& response,
    int timeoutMs = 1500)
{
    if (!waitUntil(
            [&socket]() {
                return socket.bytesAvailable() >= 4;
            },
            timeoutMs)) {
        return false;
    }

    const QByteArray header = socket.read(4);

    if (header.size() != 4) {
        return false;
    }

    const auto* bytes =
        reinterpret_cast<const uchar*>(header.constData());

    const quint32 length = qFromLittleEndian<quint32>(bytes);

    if (length == 0 ||
        length > passwall::native::NativeMessageMaxPayloadBytes) {
        return false;
    }

    if (!waitUntil(
            [&socket, length]() {
                return socket.bytesAvailable()
                    >= static_cast<qint64>(length);
            },
            timeoutMs)) {
        return false;
    }

    const QByteArray payload = socket.read(length);

    if (payload.size() != static_cast<qsizetype>(length)) {
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument document =
        QJsonDocument::fromJson(payload, &parseError);

    if (parseError.error != QJsonParseError::NoError ||
        !document.isObject()) {
        return false;
    }

    response = document.object();
    return true;
}

class NativeBridgeServerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ensureQtApplication();

        tempDir_ = std::make_unique<QTemporaryDir>();
        ASSERT_TRUE(tempDir_->isValid());

        server_ =
            std::make_unique<passwall::native::NativeBridgeServer>();

        socketPath_ = tempDir_->filePath("test-bridge.sock");

        QString error;
        ASSERT_TRUE(server_->startAtPath(socketPath_, error))
            << error.toStdString();
    }

    void TearDown() override
    {
        if (server_) {
            server_->stop();
        }

        server_.reset();
        tempDir_.reset();
    }

    bool connectClient(QLocalSocket& socket)
    {
        socket.connectToServer(socketPath_);

        return waitUntil(
            [&socket]() {
                return socket.state()
                    == QLocalSocket::ConnectedState;
            },
            1000);
    }

    std::unique_ptr<QTemporaryDir> tempDir_;
    std::unique_ptr<passwall::native::NativeBridgeServer> server_;
    QString socketPath_;
};

TEST(NativeBridgeServerLifetimeTest, DestroysWithoutClient)
{
    ensureQtApplication();

    auto server =
        std::make_unique<passwall::native::NativeBridgeServer>();
    server.reset();

    SUCCEED();
}

TEST_F(NativeBridgeServerTest, PingReceivesValidJsonResponse)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    const QByteArray frame = makeFrame({
        {"type", "ping"}
    });

    ASSERT_EQ(
        socket.write(frame),
        static_cast<qint64>(frame.size()));
    socket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(socket, response));

    EXPECT_TRUE(response.value("ok").toBool());
    EXPECT_EQ(
        response.value("receivedType").toString(),
        QStringLiteral("ping"));
}

TEST_F(NativeBridgeServerTest, DestroysAfterAcceptedConnection)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    server_.reset();

    EXPECT_EQ(server_.get(), nullptr);
    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
}

TEST_F(NativeBridgeServerTest, DestroysAfterPeerDisconnection)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    socket.abort();
    ASSERT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
    processEventsFor(50);

    server_.reset();

    EXPECT_EQ(server_.get(), nullptr);
}

TEST_F(NativeBridgeServerTest, DestroysWithPendingResponseState)
{
    BridgeTestVault vault;
    vault.credential.password.assign(180 * 1024, 'x');
    vault.summaries = {makeSummary(vault.credential)};
    installProcessorHandler(*server_, vault);

    bool payloadSegmentAccepted = false;
    server_->setPayloadSegmentAcceptedHandlerForTesting(
        [&payloadSegmentAccepted](std::uint64_t, std::size_t) {
            payloadSegmentAccepted = true;
        });

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    ASSERT_TRUE(waitUntil(
        [&payloadSegmentAccepted]() { return payloadSegmentAccepted; },
        1500));

    server_.reset();

    EXPECT_EQ(server_.get(), nullptr);
    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
}

TEST_F(NativeBridgeServerTest,
       DestroysAfterADeferredContinuationMayHaveBeenQueued)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    QByteArray requests = makeFrame({{"type", "ping"}});
    requests.append(makeFrame({{"type", "ping"}}));
    ASSERT_EQ(socket.write(requests), static_cast<qint64>(requests.size()));
    socket.flush();

    QJsonObject firstResponse;
    ASSERT_TRUE(readResponse(socket, firstResponse));

    QMetaObject::invokeMethod(
        &ensureQtApplication(),
        [this]() { server_.reset(); },
        Qt::QueuedConnection);
    processEventsFor(100);

    EXPECT_EQ(server_.get(), nullptr);
}

TEST_F(NativeBridgeServerTest, ReassemblesFragmentedFrame)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    const QByteArray frame = makeFrame({
        {"type", "ping"}
    });

    ASSERT_GT(frame.size(), 2);

    // Envoyer uniquement le début de la trame.
    ASSERT_EQ(socket.write(frame.left(2)), 2);
    socket.flush();

    // Laisser le serveur traiter ce premier fragment.
    processEventsFor(100);

    // Envoyer le reste de la trame.
    const QByteArray remainder = frame.mid(2);

    ASSERT_EQ(
        socket.write(remainder),
        static_cast<qint64>(remainder.size()));
    socket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(socket, response));

    EXPECT_TRUE(response.value("ok").toBool());
    EXPECT_EQ(
        response.value("receivedType").toString(),
        QStringLiteral("ping"));
}

TEST_F(NativeBridgeServerTest, RejectsZeroLengthFrame)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    const QByteArray invalidHeader = makeHeader(0);

    ASSERT_EQ(
        socket.write(invalidHeader),
        static_cast<qint64>(invalidHeader.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state()
                == QLocalSocket::UnconnectedState;
        },
        1500));
}

TEST_F(NativeBridgeServerTest, ClosesConnectionWithIncompleteFrame)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    // La trame annonce 10 octets de JSON, mais seuls 2 sont envoyés.
    QByteArray incompleteFrame = makeHeader(10);
    incompleteFrame.append("{}");

    ASSERT_EQ(
        socket.write(incompleteFrame),
        static_cast<qint64>(incompleteFrame.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state()
                == QLocalSocket::UnconnectedState;
        },
        6500));
}


TEST_F(NativeBridgeServerTest, RejectsOversizedFrame)
{
    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    const QByteArray invalidHeader =
        makeHeader(passwall::native::NativeMessageMaxPayloadBytes + 1);

    ASSERT_EQ(
        socket.write(invalidHeader),
        static_cast<qint64>(invalidHeader.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state()
                == QLocalSocket::UnconnectedState;
        },
        1500));
}


TEST_F(NativeBridgeServerTest, BridgesProcessorCredentialResponse)
{
    BridgeTestVault vault;
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(socket, response));
    EXPECT_TRUE(response.value("ok").toBool());
    EXPECT_EQ(response.value("type").toString(), QStringLiteral("credential_selected"));
    EXPECT_EQ(response.value("username").toString(), QStringLiteral("alice"));
    EXPECT_EQ(response.value("password").toString(), QStringLiteral("bridge-secret"));
}

TEST_F(NativeBridgeServerTest, BridgesProcessorSearchWithoutSecret)
{
    BridgeTestVault vault;
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "search_credentials"},
        {"url", "https://example.com/account"}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(socket, response));
    EXPECT_TRUE(response.value("ok").toBool());
    EXPECT_EQ(response.value("type").toString(), QStringLiteral("credential_matches"));
    EXPECT_FALSE(response.contains("password"));
    EXPECT_FALSE(response.contains("notes"));
}

TEST_F(NativeBridgeServerTest, ReturnsLockedResponseWithoutSecretAfterLeaseInvalidation)
{
    BridgeTestVault vault;
    vault.invalidateDuringLoad = true;
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(socket, response));
    EXPECT_FALSE(response.value("ok").toBool());
    EXPECT_EQ(response.value("error").toString(), QStringLiteral("vault_locked"));
    EXPECT_FALSE(response.contains("password"));
}

TEST_F(NativeBridgeServerTest, KeepsTwoProcessorResponsesFramedAndOrdered)
{
    BridgeTestVault vault;
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    QByteArray requests = makeFrame({
        {"type", "search_credentials"},
        {"url", "https://example.com/account"}
    });
    requests.append(makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    }));
    ASSERT_EQ(socket.write(requests), static_cast<qint64>(requests.size()));
    socket.flush();

    QJsonObject firstResponse;
    QJsonObject secondResponse;
    ASSERT_TRUE(readResponse(socket, firstResponse));
    ASSERT_TRUE(readResponse(socket, secondResponse));

    EXPECT_EQ(firstResponse.value("type").toString(),
              QStringLiteral("credential_matches"));
    EXPECT_EQ(secondResponse.value("type").toString(),
              QStringLiteral("credential_selected"));
    EXPECT_EQ(secondResponse.value("password").toString(),
              QStringLiteral("bridge-secret"));
}

TEST_F(NativeBridgeServerTest, StreamsLargeProcessorPayloadInMultipleChunks)
{
    BridgeTestVault vault;
    vault.credential.password.assign(180 * 1024, 'x');
    vault.summaries = {makeSummary(vault.credential)};
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(socket, response, 5000));
    EXPECT_EQ(response.value("password").toString().size(), 180 * 1024);
}

TEST_F(NativeBridgeServerTest, RejectsResponseBoundToAnOlderSession)
{
    BridgeTestVault vault;
    installProcessorHandler(*server_, vault);
    server_->invalidateSession(vault.generation + 1);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
}

TEST_F(NativeBridgeServerTest,
       CancelsPendingSecretAfterFirstAcceptedPayloadSegment)
{
    BridgeTestVault vault;
    vault.credential.password.assign(180 * 1024, 'x');
    vault.summaries = {makeSummary(vault.credential)};
    installProcessorHandler(*server_, vault);

    std::size_t acceptedPayloadSegments = 0;
    server_->setPayloadSegmentAcceptedHandlerForTesting(
        [this, &vault, &acceptedPayloadSegments](
            std::uint64_t generation,
            std::size_t acceptedBytes) {
            EXPECT_EQ(generation, vault.generation);
            EXPECT_GT(acceptedBytes, 0U);
            ++acceptedPayloadSegments;

            if (acceptedPayloadSegments == 1) {
                ++vault.generation;
                server_->invalidateSession(vault.generation);
            }
        });

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
    EXPECT_EQ(acceptedPayloadSegments, 1U);
}

TEST_F(NativeBridgeServerTest,
       ANewUnlockedSessionDoesNotAuthorizeAnOlderResponse)
{
    BridgeTestVault vault;
    installProcessorHandler(*server_, vault);

    // Les générations 2 puis 3 représentent verrouillage puis nouveau
    // déverrouillage. Le faux coffre produit toujours une réponse de la
    // génération 1, qui doit rester refusée.
    server_->invalidateSession(vault.generation + 1);
    server_->invalidateSession(vault.generation + 2);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
}

TEST_F(NativeBridgeServerTest,
       SessionInvalidationDoesNotCancelASecondCurrentConnection)
{
    BridgeTestVault vault;
    vault.credential.password.assign(180 * 1024, 'x');
    vault.summaries = {makeSummary(vault.credential)};
    installProcessorHandler(*server_, vault);

    bool invalidatedFirstSession = false;
    server_->setPayloadSegmentAcceptedHandlerForTesting(
        [this, &vault, &invalidatedFirstSession](
            std::uint64_t,
            std::size_t) {
            if (!invalidatedFirstSession) {
                invalidatedFirstSession = true;
                ++vault.generation;
                server_->invalidateSession(vault.generation);
            }
        });

    QLocalSocket staleSocket;
    ASSERT_TRUE(connectClient(staleSocket));
    const QByteArray staleFrame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(
        staleSocket.write(staleFrame),
        static_cast<qint64>(staleFrame.size()));
    staleSocket.flush();

    ASSERT_TRUE(waitUntil(
        [&staleSocket]() {
            return staleSocket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
    ASSERT_TRUE(invalidatedFirstSession);

    QLocalSocket currentSocket;
    ASSERT_TRUE(connectClient(currentSocket));
    const QByteArray currentFrame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(
        currentSocket.write(currentFrame),
        static_cast<qint64>(currentFrame.size()));
    currentSocket.flush();

    QJsonObject response;
    ASSERT_TRUE(readResponse(currentSocket, response, 5000));
    EXPECT_TRUE(response.value("ok").toBool());
    EXPECT_EQ(response.value("password").toString().size(), 180 * 1024);
}

TEST_F(NativeBridgeServerTest,
       DeferredContinuationDoesNotReuseDestroyedConnectionState)
{
    BridgeTestVault vault;
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));

    bool disconnectionQueued = false;
    server_->setPayloadSegmentAcceptedHandlerForTesting(
        [&socket, &disconnectionQueued](std::uint64_t, std::size_t) {
            if (disconnectionQueued) {
                return;
            }

            disconnectionQueued = true;
            QMetaObject::invokeMethod(
                &socket,
                [&socket]() { socket.abort(); },
                Qt::QueuedConnection);
        });

    QByteArray requests = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    requests.append(makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    }));
    ASSERT_EQ(socket.write(requests), static_cast<qint64>(requests.size()));
    socket.flush();

    EXPECT_TRUE(waitUntil(
        [&socket]() {
            return socket.state() == QLocalSocket::UnconnectedState;
        },
        1500));
    EXPECT_TRUE(disconnectionQueued);
}

TEST_F(NativeBridgeServerTest, DisconnectionDuringProcessorTransmissionIsHandled)
{
    BridgeTestVault vault;
    vault.credential.password.assign(180 * 1024, 'x');
    vault.summaries = {makeSummary(vault.credential)};
    installProcessorHandler(*server_, vault);

    QLocalSocket socket;
    ASSERT_TRUE(connectClient(socket));
    const QByteArray frame = makeFrame({
        {"type", "get_credential"},
        {"url", "https://example.com/login"},
        {"id", entryIdText(vault.credential.id)}
    });
    ASSERT_EQ(socket.write(frame), static_cast<qint64>(frame.size()));
    socket.flush();
    socket.abort();

    processEventsFor(100);
    EXPECT_EQ(socket.state(), QLocalSocket::UnconnectedState);
}

TEST_F(NativeBridgeServerTest, KeepsClientResponsesIndependent)
{
    QLocalSocket firstClient;
    QLocalSocket secondClient;

    ASSERT_TRUE(connectClient(firstClient));
    ASSERT_TRUE(connectClient(secondClient));

    // Le premier client envoie une requête ping valide.
    const QByteArray pingFrame = makeFrame({
        {"type", "ping"}
    });

    ASSERT_EQ(
        firstClient.write(pingFrame),
        static_cast<qint64>(pingFrame.size()));
    firstClient.flush();

    // Le second client envoie une trame dont le JSON est invalide.
    const QByteArray invalidPayload = "{";
    const quint32 length =
        qToLittleEndian(
            static_cast<quint32>(invalidPayload.size()));

    QByteArray invalidFrame;
    invalidFrame.append(
        reinterpret_cast<const char*>(&length),
        sizeof(length));
    invalidFrame.append(invalidPayload);

    ASSERT_EQ(
        secondClient.write(invalidFrame),
        static_cast<qint64>(invalidFrame.size()));
    secondClient.flush();

    QJsonObject firstResponse;
    QJsonObject secondResponse;

    ASSERT_TRUE(readResponse(firstClient, firstResponse));
    ASSERT_TRUE(readResponse(secondClient, secondResponse));

    EXPECT_TRUE(firstResponse.value("ok").toBool());
    EXPECT_EQ(
        firstResponse.value("receivedType").toString(),
        QStringLiteral("ping"));

    EXPECT_FALSE(secondResponse.value("ok").toBool());
    EXPECT_EQ(
        secondResponse.value("error").toString(),
        QStringLiteral("Message JSON invalide"));
}


} // namespace
