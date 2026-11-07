#pragma once

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusVirtualObject>
#include <QHash>
#include <QTimer>
#include <functional>
#include <memory>

namespace passwall::platform {
class LinuxInstanceLock;
class SessionLockBusReceiver;

// User bus, no activation file, no unlock/secret API. Public contract:
//   destination org.passwall.PassWall
//   path /org/passwall/PassWall
//   interface org.passwall.PassWall.Control1 ; method Lock() -> ()
// An empty METHOD_RETURN means complete cleanup; any error is NOT an ack.
// The vault callback MUST finish on this thread and call completion only AFTER
// the outer lock has completed. Availability loss must synchronously close the
// vault's access gate. No reconnect/automatic unlock: failure requires restart.
// Lock is punctual: after acknowledgement a fresh manual authentication is
// permitted, with the chosen vault's own master password. No session is restored.
class SessionLockService final : public QDBusVirtualObject {
    Q_OBJECT
public:
    using Completion = std::function<void(bool)>;
    using LockRequest = std::function<void(Completion)>;
    static constexpr auto Service = "org.passwall.PassWall";
    static constexpr auto Path = "/org/passwall/PassWall";
    static constexpr auto Interface = "org.passwall.PassWall.Control1";
    SessionLockService(const LinuxInstanceLock& instance, LockRequest lockRequest,
                       QObject* parent = nullptr);
    ~SessionLockService() override;
    void start(const QString& busAddress);
    void stop();
    [[nodiscard]] bool isAvailable() const noexcept;
    QString introspect(const QString&) const override;
    bool handleMessage(const QDBusMessage&, const QDBusConnection&) override;
signals:
    void availabilityChanged(bool available);
private:
    void requestName(quint64 epoch);
    void finish(quint64 epoch, quint64 id, bool cleaned);
    void fail();
    const LinuxInstanceLock& instance_;
    LockRequest lockRequest_;
    std::unique_ptr<QDBusConnection> bus_;
    QString connectionName_;
    SessionLockBusReceiver* receiver_ = nullptr;
    QTimer health_;
    QHash<quint64, QDBusMessage> pending_;
    quint64 epoch_ = 0;
    quint64 nextId_ = 0;
    bool running_ = false;
    bool ready_ = false;
};
} // namespace passwall::platform
