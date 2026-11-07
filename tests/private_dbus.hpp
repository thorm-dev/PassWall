#pragma once

#include <QCoreApplication>
#include <QDBusConnection>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <QUuid>
#include <functional>

namespace passwall::tests {
inline bool waitFor(const std::function<bool()>& condition, int timeout = 2500)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!condition() && elapsed.elapsed() < timeout) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return condition();
}

// Own private broker, socket and connections. Never connects to the real bus.
class PrivateDBus final {
public:
    PrivateDBus() : directory_(QStringLiteral("/tmp/pw-control-bus-XXXXXX"))
    {
        if (!directory_.isValid())
            return;
        broker_.setProgram(QStringLiteral("dbus-daemon"));
        broker_.setArguments({QStringLiteral("--session"), QStringLiteral("--nofork"),
            QStringLiteral("--nopidfile"), QStringLiteral("--print-address=1"),
            QStringLiteral("--address=unix:path=") + directory_.filePath(QStringLiteral("bus"))});
        broker_.start();
        if (broker_.waitForStarted(1000) && broker_.waitForReadyRead(1000))
            address_ = QString::fromUtf8(broker_.readLine()).trimmed();
    }
    ~PrivateDBus()
    {
        for (const auto& name : connections_)
            QDBusConnection::disconnectFromBus(name);
        stop();
    }
    bool isValid() const { return address_.startsWith(QStringLiteral("unix:path=")); }
    QString address() const { return address_; }
    QDBusConnection connect()
    {
        const auto name = QUuid::createUuid().toString();
        connections_.append(name);
        return QDBusConnection::connectToBus(address_, name);
    }
    void stop()
    {
        if (broker_.state() == QProcess::NotRunning)
            return;
        broker_.terminate();
        if (!broker_.waitForFinished(1000)) {
            broker_.kill();
            broker_.waitForFinished(1000);
        }
    }
private:
    QTemporaryDir directory_;
    QProcess broker_;
    QString address_;
    QStringList connections_;
};
} // namespace passwall::tests
