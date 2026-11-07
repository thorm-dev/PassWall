#include "linux_session_monitor.hpp"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusUnixFileDescriptor>
#include <QFutureWatcher>
#include <QPointer>
#include <QPromise>
#include <QThreadPool>
#include <QUuid>
#include <QVariantMap>

#include <fcntl.h>
#include <exception>
#include <limits>

namespace passwall::platform {
namespace {
const QString service = QStringLiteral("org.freedesktop.login1");
const QString path = QStringLiteral("/org/freedesktop/login1");
const QString manager = QStringLiteral("org.freedesktop.login1.Manager");
constexpr int callTimeoutMs = 1500;

void advanceGeneration(quint64& generation)
{
    if (generation == std::numeric_limits<quint64>::max())
        std::terminate();
    ++generation;
}

// Even connectToBus() performs a synchronous authentication/Hello handshake
// in Qt 6.8. Run ONLY that handshake in a pool task, never on the GUI thread.
// The task owns no application QObject, vault pointer, secret, or inhibitor. A discarded
// future closes its otherwise unclaimed connection through this RAII result.
struct BusAttempt final {
    explicit BusAttempt(const QString& address, const QString& name)
        : connection(address.isEmpty()
            ? QDBusConnection::connectToBus(QDBusConnection::SystemBus, name)
            : QDBusConnection::connectToBus(address, name)) {}
    ~BusAttempt()
    {
        if (!adopted)
            QDBusConnection::disconnectFromBus(connection.name());
    }
    QDBusConnection connection;
    bool adopted = false;
};
}

// One receiver per connection, created and destroyed on the owner's Qt thread.
// An already queued signal must not acquire the identity of a replacement bus
// (unique names such as :1.0 CAN be reused by a restarted bus).
class LogindSignalReceiver final : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
    std::function<void(const QDBusMessage&)> receive;
public slots:
    void dispatch(const QDBusMessage& message)
    {
        // Keep the callable alive if handling the signal retires this receiver.
        const auto handler = receive;
        if (handler)
            handler(message);
    }
};

class LogindDBusBackend final : public Login1Backend {
    Q_OBJECT
public:
    explicit LogindDBusBackend(QString busAddress)
        : poll_(this), busAddress_(std::move(busAddress))
    {
        poll_.setInterval(1000);
        connect(&poll_, &QTimer::timeout, this, [this]() {
            if (connector_)
                return; // At most one connection handshake in flight.
            if (!bus_ || !bus_->isConnected()) {
                lostConnection();
                connectBus();
            } else if (subscriptionsReady_ && owner_.isEmpty() && !queryingOwner_) {
                queryOwner();
            }
        });
    }
    ~LogindDBusBackend() override { stop(); }

    void start() override
    {
        if (running_)
            return;
        running_ = true;
        poll_.start();
        connectBus();
    }
    void stop() override
    {
        running_ = false;
        poll_.stop();
        advanceGeneration(revision_);
        advanceGeneration(connectionGeneration_);
        owner_.clear();
        queryingOwner_ = false;
        subscriptionsReady_ = false;
        // Destroy completed replies too: their Qt UNIX_FD copies must not keep
        // an inhibitor alive after shutdown of this backend.
        for (auto* pending : findChildren<QDBusPendingCallWatcher*>())
            delete pending;
        for (auto* connector : findChildren<QFutureWatcherBase*>())
            delete connector;
        connector_ = nullptr; // No waiting for a connection handshake here.
        disconnectBus();
    }

    void inhibit(InhibitResult completion) override
    {
        if (!running_ || !bus_ || !bus_->isConnected() ||
            !subscriptionsReady_ || owner_.isEmpty()) {
            completion(InhibitorFd{});
            return;
        }
        auto message = QDBusMessage::createMethodCall(owner_, path, manager,
                                                     QStringLiteral("Inhibit"));
        message.setArguments({QStringLiteral("sleep:shutdown"),
                              QStringLiteral("PassWall"),
                              QStringLiteral("Lock vault and clear secrets"),
                              QStringLiteral("delay")});
        const quint64 revision = revision_;
        auto* pending = new QDBusPendingCallWatcher(
            bus_->asyncCall(message, callTimeoutMs), this);
        connect(pending, &QDBusPendingCallWatcher::finished, this,
                [this, revision, completion = std::move(completion)](
                    QDBusPendingCallWatcher* watcher) mutable {
            InhibitorFd fd;
            {
                QDBusPendingReply<QDBusUnixFileDescriptor> reply = *watcher;
                if (!reply.isError() && reply.value().isValid()) {
                    // Qt's FD value is implicitly shared with the pending
                    // message. Keep one explicit CLOEXEC duplicate, then
                    // destroy ALL Qt copies before handing it to the monitor.
                    fd = InhibitorFd(::fcntl(reply.value().fileDescriptor(),
                                             F_DUPFD_CLOEXEC, 3));
                }
            }
            const QPointer<QDBusPendingCallWatcher> guard(watcher);
            QMetaObject::invokeMethod(this,
                [this, revision, guard, fd = std::move(fd),
                 completion = std::move(completion)]() mutable {
                    // Deferred until the finished signal has unwound, rather
                    // than deleting its sender from inside that signal.
                    delete guard.data();
                    if (running_ && revision == revision_) {
                        if (!bus_ || !bus_->isConnected()) {
                            lostConnection();
                            return;
                        }
                        completion(std::move(fd));
                    }
                }, Qt::QueuedConnection);
        });
    }

    void readState(StateResult completion) override
    {
        if (!running_ || !bus_ || !bus_->isConnected() ||
            !subscriptionsReady_ || owner_.isEmpty()) {
            completion(std::nullopt);
            return;
        }
        auto message = QDBusMessage::createMethodCall(
            owner_, path, QStringLiteral("org.freedesktop.DBus.Properties"),
            QStringLiteral("GetAll"));
        message.setArguments({manager});
        const quint64 revision = revision_;
        auto* pending = new QDBusPendingCallWatcher(
            bus_->asyncCall(message, callTimeoutMs), this);
        connect(pending, &QDBusPendingCallWatcher::finished, this,
                [this, revision, completion = std::move(completion)](
                    QDBusPendingCallWatcher* watcher) mutable {
            QDBusPendingReply<QVariantMap> reply = *watcher;
            std::optional<Login1State> state;
            if (!reply.isError()) {
                const auto properties = reply.value();
                const auto sleep = properties.value(QStringLiteral("PreparingForSleep"));
                const auto shutdown = properties.value(QStringLiteral("PreparingForShutdown"));
                if (sleep.metaType().id() == QMetaType::Bool &&
                    shutdown.metaType().id() == QMetaType::Bool)
                    state = Login1State{sleep.toBool(), shutdown.toBool()};
            }
            const QPointer<QDBusPendingCallWatcher> guard(watcher);
            QMetaObject::invokeMethod(this,
                [this, revision, guard, state,
                 completion = std::move(completion)]() mutable {
                    delete guard.data();
                    if (running_ && revision == revision_) {
                        if (!bus_ || !bus_->isConnected()) {
                            lostConnection();
                            return;
                        }
                        completion(state);
                    }
                }, Qt::QueuedConnection);
        });
    }

private:
    void busSignal(quint64 connectionGeneration, const QDBusMessage& message)
    {
        if (!running_ || connectionGeneration != connectionGeneration_ || !bus_)
            return;
        if (!bus_->isConnected()) {
            lostConnection();
            return;
        }
        const auto arguments = message.arguments();
        if (message.interface() == QStringLiteral("org.freedesktop.DBus.Local") &&
            message.member() == QStringLiteral("Disconnected")) {
            lostConnection();
            return;
        }
        if (message.service() == QStringLiteral("org.freedesktop.DBus") &&
            message.interface() == QStringLiteral("org.freedesktop.DBus") &&
            message.member() == QStringLiteral("NameOwnerChanged")) {
            if (arguments.size() != 3 ||
                arguments[0].metaType().id() != QMetaType::QString ||
                arguments[1].metaType().id() != QMetaType::QString ||
                arguments[2].metaType().id() != QMetaType::QString) {
                lostConnection();
                return;
            }
            if (arguments[0].toString() != service)
                return;
            advanceGeneration(revision_);
            const quint64 revision = revision_;
            owner_.clear();
            queryingOwner_ = false;
            // A notification is a reason to revoke, NOT proof of a new owner.
            emit availabilityChanged(false);
            if (running_ && revision == revision_ && subscriptionsReady_)
                queryOwner();
            return;
        }
        // Wildcard Qt filters never resolve a service synchronously. The bus
        // assigns the sender; only the asynchronously confirmed owner is used.
        if (owner_.isEmpty() || message.service() != owner_ ||
            message.path() != path || message.interface() != manager)
            return;
        if (arguments.size() != 1 || arguments[0].metaType().id() != QMetaType::Bool) {
            lostConnection();
            return;
        }
        if (message.member() == QStringLiteral("PrepareForSleep"))
            emit prepareForSleep(arguments[0].toBool());
        else if (message.member() == QStringLiteral("PrepareForShutdown"))
            emit prepareForShutdown(arguments[0].toBool());
    }

    void disconnectBus()
    {
        if (receiver_) {
            receiver_->receive = {};
            receiver_->deleteLater();
            receiver_ = nullptr;
        }
        if (!bus_)
            return;
        const QString name = bus_->name();
        bus_.reset();
        QDBusConnection::disconnectFromBus(name);
    }
    void lostConnection()
    {
        if (!running_)
            return;
        advanceGeneration(revision_);
        advanceGeneration(connectionGeneration_);
        const quint64 revision = revision_;
        owner_.clear();
        queryingOwner_ = false;
        subscriptionsReady_ = false;
        emit availabilityChanged(false);
        // Cleanup may reenter stop/start; do not disconnect a newer attempt.
        if (revision == revision_)
            disconnectBus();
    }
    void connectBus()
    {
        if (!running_ || connector_)
            return;
        // A dedicated connection can be recreated after bus loss without
        // disconnecting any other Qt component's shared systemBus().
        const QString name = QStringLiteral("passwall-logind-") +
            QUuid::createUuid().toString(QUuid::WithoutBraces);
        QPromise<std::shared_ptr<BusAttempt>> promise;
        auto* watcher = new QFutureWatcher<std::shared_ptr<BusAttempt>>(this);
        connector_ = watcher;
        const quint64 revision = revision_;
        connect(watcher, &QFutureWatcherBase::finished, this,
                [this, watcher, revision]() {
            const auto result = watcher->result();
            const QPointer<QFutureWatcherBase> guard(watcher);
            QMetaObject::invokeMethod(this, [this, guard, result, revision]() {
                if (connector_ == guard.data())
                    connector_ = nullptr;
                delete guard.data();
                if (!running_ || revision != revision_)
                    return;
                if (!result) {
                    lostConnection();
                    return;
                }
                bus_ = std::make_unique<QDBusConnection>(result->connection);
                result->adopted = true;
                advanceGeneration(connectionGeneration_);
                subscribe();
            }, Qt::QueuedConnection);
        });
        watcher->setFuture(promise.future());
        QThreadPool::globalInstance()->start(
            [promise = std::move(promise), address = busAddress_, name]() mutable {
                promise.start();
                std::shared_ptr<BusAttempt> result;
                try {
                    result = std::make_shared<BusAttempt>(address, name);
                } catch (...) {
                    // No exception crosses into the owner's event loop.
                }
                promise.addResult(std::move(result));
                promise.finish();
            });
    }
    void subscribe()
    {
        if (!bus_->isConnected() ||
            !bus_->connectionCapabilities().testFlag(
                QDBusConnection::UnixFileDescriptorPassing)) {
            lostConnection();
            return;
        }
        const quint64 generation = connectionGeneration_;
        receiver_ = new LogindSignalReceiver(this);
        receiver_->receive = [this, generation](const QDBusMessage& message) {
            busSignal(generation, message);
        };
        // Qt 6.8.2 addSignalHookImpl() resolves even unique service names
        // synchronously. ONLY the bus driver and empty sender avoid that path.
        const bool owner = bus_->connect(
            QStringLiteral("org.freedesktop.DBus"),
            QStringLiteral("/org/freedesktop/DBus"),
            QStringLiteral("org.freedesktop.DBus"), QStringLiteral("NameOwnerChanged"),
            receiver_, SLOT(dispatch(QDBusMessage)));
        const bool sleep = bus_->connect(QString(), path, manager,
            QStringLiteral("PrepareForSleep"), receiver_, SLOT(dispatch(QDBusMessage)));
        const bool shutdown = bus_->connect(QString(), path, manager,
            QStringLiteral("PrepareForShutdown"), receiver_, SLOT(dispatch(QDBusMessage)));
        const bool disconnect = bus_->connect(QString(),
            QStringLiteral("/org/freedesktop/DBus/Local"),
            QStringLiteral("org.freedesktop.DBus.Local"),
            QStringLiteral("Disconnected"), receiver_, SLOT(dispatch(QDBusMessage)));
        if (!owner || !sleep || !shutdown || !disconnect) {
            lostConnection();
            return;
        }
        confirmSubscription(0, generation);
    }
    void confirmSubscription(int index, quint64 generation)
    {
        if (!running_ || generation != connectionGeneration_ || !bus_)
            return;
        // Qt's AddMatch uses a NULL DBusError: it does NOT wait for the broker's
        // acknowledgement. Verify the needed rules asynchronously, fail-closed
        // on refusal or timeout. Duplicates die with this dedicated connection.
        static const QStringList rules{
            QStringLiteral("type='signal',sender='org.freedesktop.DBus',path='/org/freedesktop/DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.login1'"),
            QStringLiteral("type='signal',path='/org/freedesktop/login1',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'"),
            QStringLiteral("type='signal',path='/org/freedesktop/login1',interface='org.freedesktop.login1.Manager',member='PrepareForShutdown'")
        };
        if (index == rules.size()) {
            subscriptionsReady_ = true;
            queryOwner();
            return;
        }
        auto message = QDBusMessage::createMethodCall(
            QStringLiteral("org.freedesktop.DBus"),
            QStringLiteral("/org/freedesktop/DBus"),
            QStringLiteral("org.freedesktop.DBus"), QStringLiteral("AddMatch"));
        message.setArguments({rules[index]});
        auto* pending = new QDBusPendingCallWatcher(
            bus_->asyncCall(message, callTimeoutMs), this);
        connect(pending, &QDBusPendingCallWatcher::finished, this,
                [this, generation, index](QDBusPendingCallWatcher* watcher) {
            QDBusPendingReply<> reply = *watcher;
            const bool success = !reply.isError();
            const QPointer<QDBusPendingCallWatcher> guard(watcher);
            QMetaObject::invokeMethod(this, [this, generation, index, success, guard] {
                delete guard.data();
                if (!running_ || generation != connectionGeneration_)
                    return;
                if (!success || !bus_ || !bus_->isConnected())
                    lostConnection();
                else
                    confirmSubscription(index + 1, generation);
            }, Qt::QueuedConnection);
        });
    }
    void queryOwner()
    {
        if (!running_ || !bus_ || !subscriptionsReady_ || queryingOwner_)
            return;
        queryingOwner_ = true;
        const quint64 revision = revision_;
        auto message = QDBusMessage::createMethodCall(
            QStringLiteral("org.freedesktop.DBus"),
            QStringLiteral("/org/freedesktop/DBus"),
            QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetNameOwner"));
        message.setArguments({service});
        auto* pending = new QDBusPendingCallWatcher(
            bus_->asyncCall(message, callTimeoutMs), this);
        connect(pending, &QDBusPendingCallWatcher::finished, this,
                [this, revision](QDBusPendingCallWatcher* watcher) {
            QDBusPendingReply<QString> reply = *watcher;
            const QString owner = reply.isError() ? QString{} : reply.value();
            const QPointer<QDBusPendingCallWatcher> guard(watcher);
            QMetaObject::invokeMethod(this, [this, revision, guard, owner]() {
                delete guard.data();
                if (!running_ || revision != revision_)
                    return;
                queryingOwner_ = false;
                if (!bus_ || !bus_->isConnected() || !subscriptionsReady_) {
                    lostConnection();
                    return;
                }
                if (!owner.startsWith(QLatin1Char(':'))) {
                    emit availabilityChanged(false);
                    return;
                }
                owner_ = owner;
                emit availabilityChanged(true);
            }, Qt::QueuedConnection);
        });
    }
    QTimer poll_;
    const QString busAddress_;
    std::unique_ptr<QDBusConnection> bus_;
    QFutureWatcher<std::shared_ptr<BusAttempt>>* connector_ = nullptr;
    QPointer<LogindSignalReceiver> receiver_;
    QString owner_;
    quint64 revision_ = 0;
    quint64 connectionGeneration_ = 0;
    bool running_ = false;
    bool queryingOwner_ = false;
    bool subscriptionsReady_ = false;
};

std::unique_ptr<Login1Backend> makeLogindDBusBackend(const QString& busAddress)
{
    return std::make_unique<LogindDBusBackend>(busAddress);
}
} // namespace passwall::platform

#include "logind_dbus_backend.moc"
