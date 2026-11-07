#include "session_lock_service.hpp"
#include "linux_instance_lock.hpp"

#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusError>
#include <QDebug>
#include <QPointer>
#include <QThread>
#include <QUuid>
#include <limits>
#include <utility>

namespace passwall::platform {
class SessionLockBusReceiver final : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
    std::function<void(const QDBusMessage&)> receive;
public slots:
    void dispatch(const QDBusMessage& message) {
        const auto callback = receive;
        if (callback) callback(message);
    }
};

SessionLockService::SessionLockService(const LinuxInstanceLock& instance,
    LockRequest lockRequest, QObject* parent)
    : QDBusVirtualObject(parent), instance_(instance), lockRequest_(std::move(lockRequest))
{
    health_.setInterval(100);
    connect(&health_, &QTimer::timeout, this, [this] {
        if (running_ && (!bus_ || !bus_->isConnected() || !instance_.isHeld()))
            fail();
    });
}
SessionLockService::~SessionLockService() { stop(); }
bool SessionLockService::isAvailable() const noexcept
{
    return QThread::currentThread() == thread() && running_ && ready_ &&
        instance_.isHeld() && bus_ && bus_->isConnected();
}
QString SessionLockService::introspect(const QString&) const
{
    return QStringLiteral(
        "<interface name=\"org.passwall.PassWall.Control1\"><method name=\"Lock\"/></interface>");
}
void SessionLockService::start(const QString& address)
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (running_)
        return;
    if (!instance_.isHeld() || address.isEmpty()) {
        emit availabilityChanged(false);
        return;
    }
    if (epoch_ == std::numeric_limits<quint64>::max())
        std::terminate();
    const quint64 epoch = ++epoch_;
    running_ = true;
    ready_ = false;
    connectionName_ = QStringLiteral("passwall-control-") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    // Startup only, before any key is usable. Qt's connection handshake may
    // synchronize internally; no blocking remote method is used thereafter.
    bus_ = std::make_unique<QDBusConnection>(QDBusConnection::connectToBus(address, connectionName_));
    if (!bus_->isConnected() || !bus_->registerVirtualObject(QString::fromLatin1(Path), this)) {
        fail();
        return;
    }
    receiver_ = new SessionLockBusReceiver(this);
    receiver_->receive = [this, epoch](const QDBusMessage& message) {
        if (!running_ || epoch != epoch_)
            return;
        if (message.interface() == QStringLiteral("org.freedesktop.DBus.Local")) {
            fail();
            return;
        }
        const auto args = message.arguments();
        if (message.service() != QStringLiteral("org.freedesktop.DBus") || args.size() != 3)
            return;
        const auto name = args[0].toString();
        if (name == QString::fromLatin1(Service)) {
            if (!bus_ || args[2].toString() != bus_->baseService())
                fail();
            return;
        }
    };
    // The bus driver and empty sender do not trigger Qt's synchronous
    // GetNameOwner path fixed in the logind backend.
    if (!bus_->connect(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
            QStringLiteral("org.freedesktop.DBus"), QStringLiteral("NameOwnerChanged"),
            receiver_, SLOT(dispatch(QDBusMessage))) ||
        !bus_->connect(QString(), QStringLiteral("/org/freedesktop/DBus/Local"),
            QStringLiteral("org.freedesktop.DBus.Local"), QStringLiteral("Disconnected"),
            receiver_, SLOT(dispatch(QDBusMessage)))) {
        fail();
        return;
    }
    // Qt's internal AddMatch is not acknowledged. Confirm surveillance before
    // publishing availability, just as in the hardened logind backend.
    auto match = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"), QStringLiteral("AddMatch"));
    match.setArguments({QStringLiteral("type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.passwall.PassWall'")});
    auto* subscription = new QDBusPendingCallWatcher(bus_->asyncCall(match, 1500), this);
    connect(subscription, &QDBusPendingCallWatcher::finished, this, [this, epoch](QDBusPendingCallWatcher* call) {
        const QDBusPendingReply<> reply = *call;
        call->deleteLater();
        if (!running_ || epoch != epoch_)
            return;
        if (reply.isError())
            fail();
        else
            requestName(epoch);
    });
    health_.start();
}
void SessionLockService::requestName(quint64 epoch)
{
    auto request = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.DBus"),
        QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"), QStringLiteral("RequestName"));
    // DO_NOT_QUEUE only: never replace an existing owner, never wait for it.
    request.setArguments({QString::fromLatin1(Service), QVariant::fromValue(uint(4))});
    auto* watcher = new QDBusPendingCallWatcher(bus_->asyncCall(request, 1500), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, epoch](QDBusPendingCallWatcher* call) {
        const QDBusPendingReply<uint> reply = *call;
        call->deleteLater();
        if (!running_ || epoch != epoch_)
            return;
        if (reply.isError() || reply.value() != 1U || !instance_.isHeld()) {
            if (!reply.isError() && reply.value() != 1U)
                qWarning("PassWall control name already owned; existing owner preserved.");
            fail();
            return;
        }
        ready_ = true;
        emit availabilityChanged(true);
    });
}
void SessionLockService::fail()
{
    qWarning("PassWall control unavailable; vault access must remain closed.");
    stop();
}
void SessionLockService::stop()
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (!running_)
        return;
    running_ = false;
    ready_ = false;
    if (epoch_ == std::numeric_limits<quint64>::max())
        std::terminate();
    ++epoch_;
    health_.stop();
    // Revoke access / clean keys BEFORE dropping the control endpoint.
    emit availabilityChanged(false);
    if (receiver_) {
        receiver_->receive = {};
        receiver_->deleteLater();
        receiver_ = nullptr;
    }
    const auto pending = std::exchange(pending_, {});
    if (bus_) {
        for (const auto& message : pending)
            bus_->send(message.createErrorReply(QStringLiteral("org.passwall.Error.Stopping"),
                QStringLiteral("Application stopping; cleanup not acknowledged.")));
        bus_->unregisterObject(QString::fromLatin1(Path));
        // Closing our dedicated connection releases ONLY names we own.
        QDBusConnection::disconnectFromBus(connectionName_);
        bus_.reset();
    }
}
bool SessionLockService::handleMessage(const QDBusMessage& message, const QDBusConnection& connection)
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (message.interface() == QStringLiteral("org.freedesktop.DBus.Introspectable") &&
        message.member() == QStringLiteral("Introspect") && message.arguments().isEmpty()) {
        connection.send(message.createReply(QStringLiteral("<node>") + introspect(message.path()) + QStringLiteral("</node>")));
        return true;
    }
    if (message.interface() != QString::fromLatin1(Interface) || message.member() != QStringLiteral("Lock")) {
        connection.send(message.createErrorReply(QDBusError::UnknownMethod, QStringLiteral("Only Lock is supported.")));
        return true;
    }
    if (!message.arguments().isEmpty() || !isAvailable() || pending_.size() >= 64 ||
        nextId_ == std::numeric_limits<quint64>::max()) {
        connection.send(message.createErrorReply(QStringLiteral("org.passwall.Error.Unavailable"),
            QStringLiteral("Lock request unavailable or invalid.")));
        return true;
    }
    message.setDelayedReply(true);
    const quint64 id = ++nextId_;
    const quint64 epoch = epoch_;
    pending_.insert(id, message);
    const QPointer<SessionLockService> guarded(this);
    try {
        lockRequest_([guarded, epoch, id](bool cleaned) {
            if (guarded)
                guarded->finish(epoch, id, cleaned);
        });
    } catch (...) {
        if (guarded)
            guarded->finish(epoch, id, false);
    }
    return true;
}
void SessionLockService::finish(quint64 epoch, quint64 id, bool cleaned)
{
    Q_ASSERT(QThread::currentThread() == thread());
    if (!running_ || epoch != epoch_ || !pending_.contains(id))
        return;
    const auto message = pending_.take(id);
    if (cleaned && isAvailable())
        bus_->send(message.createReply());
    else {
        if (bus_)
            bus_->send(message.createErrorReply(QStringLiteral("org.passwall.Error.CleanupFailed"),
                QStringLiteral("Cleanup could not be confirmed.")));
        fail();
    }
}
} // namespace passwall::platform

#include "session_lock_service.moc"
