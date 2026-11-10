// Test-worker-only instrumentation. No secret bytes or pointers are printed.
#include "services/restore_protocol.hpp"
#include <array>
#include <cstddef>
#include <sys/socket.h>
#include <unistd.h>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <fcntl.h>
#include <poll.h>
namespace {
struct Allocation { void* data = nullptr; std::size_t size = 0; };
std::array<Allocation, 128> allocated{};
int lastType = 0;
void hold(const QByteArray& file) {
    if (file.isEmpty()) return;
    const int fd = ::open(file.constData(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) ::_exit(93);
    char release;
    for (;;) {
        const auto n = ::read(fd, &release, 1);
        if (n == 1) break;
        if (n < 0 && errno != EINTR && errno != EAGAIN) ::_exit(94);
        pollfd wait{fd, POLLIN, 0};
        if (::poll(&wait, 1, -1) < 0 && errno != EINTR) ::_exit(94);
    }
    ::close(fd);
}
}
extern "C" void* __real_sodium_malloc(std::size_t);
extern "C" void* __wrap_sodium_malloc(std::size_t size) {
    void* data = __real_sodium_malloc(size);
    if (data) {
        for (auto& a : allocated) if (!a.data) { a = {data, size}; return data; }
        ::_exit(90);
    }
    return data;
}
extern "C" void __real_sodium_free(void*);
extern "C" void __wrap_sodium_free(void* data) {
    for (auto& a : allocated) if (a.data == data && data) {
        const auto* bytes = static_cast<const unsigned char*>(data);
        for (std::size_t i = 0; i < a.size; ++i) if (bytes[i]) ::_exit(91);
        a = {}; break;
    }
    __real_sodium_free(data);
}
extern "C" ssize_t __real_send(int, const void*, size_t, int);
extern "C" ssize_t __wrap_send(int fd, const void* data, size_t size, int flags) {
    namespace wire = passwall::services::restore_protocol;
    if (size == 5) lastType = static_cast<const unsigned char*>(data)[4];
    if (size == 5 && lastType == wire::Cleaned)
        for (const auto& a : allocated) if (a.data) ::_exit(92);
    const bool body = size > 5 && static_cast<const char*>(data)[0] == '{';
    QJsonObject message;
    if (body) message = QJsonDocument::fromJson(QByteArray::fromRawData(static_cast<const char*>(data), size)).object();
    if (body && lastType == wire::Result && qEnvironmentVariableIsSet("PW_RESTORE_LOSE_RESULT")) ::_exit(87);
    const auto sent = __real_send(fd, data, size, flags);
    if (body && sent == ssize_t(size)) {
        if (lastType == wire::Phase) {
            const auto phase = QByteArray::number(message["phase"].toInt());
            if (qgetenv("PW_RESTORE_CRASH_PHASE") == phase) ::_exit(87);
            if (qgetenv("PW_RESTORE_HOLD_PHASE") == phase) hold(qgetenv("PW_RESTORE_HOLD_FIFO"));
        } else if (lastType == wire::Result) {
            const auto fault = qgetenv("PW_RESTORE_TRAILING_RESULT");
            if (fault == "byte") {
                char extra = '!'; if (__real_send(fd, &extra, 1, flags) != 1) ::_exit(95);
            } else if (fault == "duplicate") {
                const auto prefix = wire::header(wire::Result, size);
                if (__real_send(fd, prefix.data(), prefix.size(), flags) != ssize_t(prefix.size())
                    || __real_send(fd, data, size, flags) != ssize_t(size)) ::_exit(95);
            }
            hold(qgetenv("PW_RESTORE_HOLD_RESULT"));
        }
    }
    return sent;
}
