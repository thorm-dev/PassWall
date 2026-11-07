
#include "native_message_limits.hpp"
#include "core/crypto_engine.hpp"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <thread>

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sodium.h>

using json = nlohmann::json;

namespace {

constexpr int kStartupAttempts = 100;
constexpr auto kStartupDelay = std::chrono::milliseconds(100);

const std::string kConnectionError =
    "Impossible de joindre PassWall. Vérifie que l'application est ouverte.";

void wipeString(std::string& value) noexcept
{
    if (!value.empty()) {
        sodium_memzero(value.data(), value.size());
    }
    value.clear();
}

class StringWiper final {
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}
    ~StringWiper() { wipeString(value_); }

    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;

private:
    std::string& value_;
};

class ScopedSocket {
public:
    explicit ScopedSocket(int fd) : fd_(fd) {}
    ~ScopedSocket()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;

    int get() const { return fd_; }

private:
    int fd_;
};

class ScopedFd {
public:
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd()
    {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const { return fd_; }

private:
    int fd_;
};

void encodeLength(std::uint32_t length, unsigned char header[4])
{
    header[0] = static_cast<unsigned char>(length & 0xff);
    header[1] = static_cast<unsigned char>((length >> 8) & 0xff);
    header[2] = static_cast<unsigned char>((length >> 16) & 0xff);
    header[3] = static_cast<unsigned char>((length >> 24) & 0xff);
}

std::uint32_t decodeLength(const unsigned char header[4])
{
    return static_cast<std::uint32_t>(header[0])
        | (static_cast<std::uint32_t>(header[1]) << 8)
        | (static_cast<std::uint32_t>(header[2]) << 16)
        | (static_cast<std::uint32_t>(header[3]) << 24);
}

bool sendAll(int fd, const void* data, std::size_t size)
{
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t sent = 0;

    while (sent < size) {
        const ssize_t result =
            ::send(fd, bytes + sent, size - sent, MSG_NOSIGNAL);

        if (result < 0 && errno == EINTR) {
            continue;
        }

        if (result <= 0) {
            return false;
        }

        sent += static_cast<std::size_t>(result);
    }

    return true;
}

bool receiveAll(int fd, void* data, std::size_t size)
{
    auto* bytes = static_cast<unsigned char*>(data);
    std::size_t received = 0;

    while (received < size) {
        const ssize_t result =
            ::recv(fd, bytes + received, size - received, 0);

        if (result < 0 && errno == EINTR) {
            continue;
        }

        if (result <= 0) {
            return false;
        }

        received += static_cast<std::size_t>(result);
    }

    return true;
}

bool writeAllToStdout(const void* data, std::size_t size)
{
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t written = 0;

    while (written < size) {
        const ssize_t result = ::write(
            STDOUT_FILENO, bytes + written, size - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(result);
    }

    return true;
}

bool writeNativeMessage(const passwall::core::SecureBuffer& message)
{
    if (message.empty() ||
        message.size() > passwall::native::NativeMessageMaxPayloadBytes) {
        return false;
    }

    unsigned char header[4];
    encodeLength(static_cast<std::uint32_t>(message.size()), header);

    return writeAllToStdout(header, sizeof(header)) &&
        writeAllToStdout(message.data(), message.size());
}

bool copyToSecureBuffer(
    std::string_view source,
    passwall::core::SecureBuffer& destination) noexcept
{
    if (source.empty() ||
        source.size() > passwall::native::NativeMessageMaxPayloadBytes) {
        return false;
    }

    try {
        passwall::core::SecureBuffer candidate(source.size());
        std::memcpy(candidate.data(), source.data(), source.size());
        destination = std::move(candidate);
        return true;
    } catch (...) {
        return false;
    }
}

bool buildErrorResponse(
    std::string_view error,
    passwall::core::SecureBuffer& response) noexcept
{
    try {
        std::string serialized = json{
            {"ok", false},
            {"error", std::string(error)}
        }.dump();
        StringWiper serializedWiper(serialized);
        return copyToSecureBuffer(serialized, response);
    } catch (...) {
        return false;
    }
}

bool forwardToQt(
    const std::string& request,
    passwall::core::SecureBuffer& response,
                 std::string& error)
{
    response = passwall::core::SecureBuffer(0);

    if (request.empty() ||
        request.size() > passwall::native::NativeMessageMaxPayloadBytes) {
        error = "Demande Native Messaging trop volumineuse.";
        return false;
    }

    const char* runtimeDirectory = std::getenv("XDG_RUNTIME_DIR");

    if (runtimeDirectory == nullptr || runtimeDirectory[0] == '\0') {
        error = "Variable XDG_RUNTIME_DIR indisponible.";
        return false;
    }

    const std::string socketPath =
        std::string(runtimeDirectory) + "/passwall-native-bridge.sock";

    sockaddr_un address{};
    address.sun_family = AF_UNIX;

    if (socketPath.size() >= sizeof(address.sun_path)) {
        error = "Chemin du socket local trop long.";
        return false;
    }

    std::memcpy(address.sun_path, socketPath.c_str(),
                socketPath.size() + 1);

    ScopedSocket socket(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));

    if (socket.get() < 0) {
        error = "Impossible de créer la connexion locale.";
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = 3;

    ::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO,
                 &timeout, sizeof(timeout));
    ::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO,
                 &timeout, sizeof(timeout));

    if (::connect(socket.get(),
                  reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) < 0) {
        error = kConnectionError;
        return false;
    }

    unsigned char requestHeader[4];
    encodeLength(static_cast<std::uint32_t>(request.size()),
                 requestHeader);

    if (!sendAll(socket.get(), requestHeader, sizeof(requestHeader))
        || !sendAll(socket.get(), request.data(), request.size())) {
        error = "Échec de l'envoi de la demande à PassWall.";
        return false;
    }

    unsigned char responseHeader[4];

    if (!receiveAll(socket.get(), responseHeader, sizeof(responseHeader))) {
        error = "PassWall n'a pas envoyé de réponse.";
        return false;
    }

    const std::uint32_t responseLength = decodeLength(responseHeader);

    if (responseLength == 0 ||
        responseLength > passwall::native::NativeMessageMaxPayloadBytes) {
        error = "Taille de réponse invalide.";
        return false;
    }

    try {
        passwall::core::SecureBuffer candidate(responseLength);
        if (!receiveAll(socket.get(), candidate.data(), candidate.size())) {
            error = "Réponse incomplète reçue de PassWall.";
            return false;
        }

        response = std::move(candidate);
    } catch (...) {
        error = "Mémoire insuffisante pour recevoir la réponse de PassWall.";
        return false;
    }

    return true;
}

bool getApplicationPath(std::string& appPath, std::string& error)
{
    std::vector<char> executablePath(PATH_MAX + 1, '\0');

    const ssize_t length = ::readlink(
        "/proc/self/exe", executablePath.data(), PATH_MAX);

    if (length <= 0) {
        error = "Impossible de déterminer le chemin de l'hôte natif.";
        return false;
    }

    const std::string hostPath(executablePath.data(),
                               static_cast<std::size_t>(length));

    const std::size_t slash = hostPath.find_last_of('/');

    if (slash == std::string::npos) {
        error = "Chemin de l'hôte natif invalide.";
        return false;
    }

    appPath = hostPath.substr(0, slash + 1) + "passwall_app";

    if (::access(appPath.c_str(), X_OK) != 0) {
        error = "Exécutable PassWall introuvable ou non exécutable : "
            + appPath;
        return false;
    }

    return true;
}

bool launchPassWall(std::string& error)
{
    std::string appPath;

    if (!getApplicationPath(appPath, error)) {
        return false;
    }

    const pid_t pid = ::fork();

    if (pid < 0) {
        error = "Impossible de démarrer PassWall : fork a échoué.";
        return false;
    }

    if (pid == 0) {
        // Détacher le processus enfant de l'hôte Native Messaging.
        if (::setsid() < 0) {
            _exit(126);
        }

        // Ne jamais partager les flux du protocole Firefox avec Qt.
        const int nullFd = ::open("/dev/null", O_RDWR);
        if (nullFd < 0) {
            _exit(126);
        }

        if (::dup2(nullFd, STDIN_FILENO) < 0 ||
            ::dup2(nullFd, STDOUT_FILENO) < 0) {
            if (nullFd > STDERR_FILENO) {
                ::close(nullFd);
            }
            _exit(126);
        }

        if (nullFd > STDERR_FILENO) {
            ::close(nullFd);
        }

        // Utiliser XWayland, dont l'activation de fenêtre a été testée.
        if (::setenv("QT_QPA_PLATFORM", "xcb", 1) != 0) {
            _exit(126);
        }

        ::execl(appPath.c_str(), appPath.c_str(),
                static_cast<char*>(nullptr));

        _exit(127);
    }

    return true;
}

bool forwardWithAutostart(const std::string& request,
                          passwall::core::SecureBuffer& response,
                          std::string& error)
{
    // Chemin normal : PassWall est déjà disponible.
    if (forwardToQt(request, response, error)) {
        return true;
    }

    if (error != kConnectionError) {
        return false;
    }

    const char* runtimeDirectory = std::getenv("XDG_RUNTIME_DIR");

    if (runtimeDirectory == nullptr || runtimeDirectory[0] == '\0') {
        error = "Variable XDG_RUNTIME_DIR indisponible.";
        return false;
    }

    const std::string lockPath =
        std::string(runtimeDirectory) + "/passwall-native-launch.lock";

    ScopedFd lockFd(::open(
        lockPath.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600));

    if (lockFd.get() < 0 || ::flock(lockFd.get(), LOCK_EX) < 0) {
        error = "Impossible de sécuriser le démarrage de PassWall.";
        return false;
    }

    // Une autre requête a peut-être démarré PassWall pendant l'attente.
    if (forwardToQt(request, response, error)) {
        return true;
    }

    if (error != kConnectionError) {
        return false;
    }

    if (!launchPassWall(error)) {
        return false;
    }

    // Attendre que le serveur Qt soit prêt avant d'abandonner la requête.
    for (int attempt = 0; attempt < kStartupAttempts; ++attempt) {
        std::this_thread::sleep_for(kStartupDelay);

        if (forwardToQt(request, response, error)) {
            return true;
        }

        if (error != kConnectionError) {
            return false;
        }
    }

    error = "PassWall a été lancé, mais son serveur local ne répond pas "
        "après 10 secondes. Vérifie les erreurs de démarrage de l'application.";
    return false;
}

bool ignoreSigPipe()
{
    struct sigaction action {};
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    return ::sigaction(SIGPIPE, &action, nullptr) == 0;
}

} // namespace

int main()
{
    if (!passwall::core::CryptoEngine::initialize() || !ignoreSigPipe()) {
        return 1;
    }

    while (true) {
        unsigned char header[4];

        std::cin.read(reinterpret_cast<char*>(header), sizeof(header));

        const std::streamsize headerBytes = std::cin.gcount();

        if (headerBytes == 0 && std::cin.eof()) {
            return 0;
        }

        if (headerBytes != static_cast<std::streamsize>(sizeof(header))) {
            return 1;
        }

        const std::uint32_t length = decodeLength(header);

        if (length == 0 ||
            length > passwall::native::NativeMessageMaxPayloadBytes) {
            return 1;
        }

        std::string input(length, '\0');
        StringWiper inputWiper(input);

        std::cin.read(input.data(), static_cast<std::streamsize>(length));

        if (std::cin.gcount() != static_cast<std::streamsize>(length)) {
            return 1;
        }

        passwall::core::SecureBuffer output(0);
        bool hasResponse = false;

        try {
            const json request = json::parse(input);

            if (!request.is_object()) {
                hasResponse = buildErrorResponse(
                    "La demande doit être un objet JSON.", output);
            } else {
                std::string serializedRequest = request.dump();
                StringWiper requestWiper(serializedRequest);
                std::string error;
                StringWiper errorWiper(error);

                if (forwardWithAutostart(
                        serializedRequest, output, error)) {
                    hasResponse = !output.empty();
                } else {
                    hasResponse = buildErrorResponse(error, output);
                }
            }
        } catch (...) {
            output = passwall::core::SecureBuffer(0);
            hasResponse = buildErrorResponse(
                "La demande reçue n'est pas un JSON valide.", output);
        }

        if (!hasResponse || !writeNativeMessage(output)) {
            return 1;
        }
    }
}
