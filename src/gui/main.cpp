
#include "main_window.hpp"
#include "native/native_bridge_server.hpp"
#ifdef Q_OS_LINUX
#include "platform/linux_session_monitor.hpp"
#include "platform/linux_instance_lock.hpp"
#include "platform/session_lock_service.hpp"
#endif

#include <QApplication>
#include <QDebug>
#include <QPointer>

int main(int argc, char* argv[])
{
#ifdef Q_OS_LINUX
    // Outlives QApplication, the window, DBus registration and every service.
    QString instanceError;
    auto instance = passwall::platform::LinuxInstanceLock::acquire(instanceError);
    if (!instance) {
        qCritical().noquote() << instanceError;
        return 1;
    }
    if (!instance->prepareNativeBridgeSocket(instanceError)) {
        qCritical().noquote() << instanceError;
        return 1;
    }
#endif
    QApplication application(argc, argv);

    QApplication::setApplicationName("PassWall");
    QApplication::setOrganizationName("PassWall");

    passwall::native::NativeBridgeServer bridge;

    QString bridgeError;

    if (!bridge.start(bridgeError)) {
        qWarning() << "Serveur local PassWall indisponible:"
                   << bridgeError;
    }

    passwall::gui::MainWindow window;

#ifdef Q_OS_LINUX
    // Created after the window: its destructor still has a live vault owner.
    passwall::platform::LinuxSessionMonitor sessionMonitor(
        passwall::platform::makeLogindDBusBackend(), &application);
    passwall::platform::SessionLockService control(*instance,
        [&window](auto completion) { window.requestExternalLock(std::move(completion)); });
    Q_ASSERT(sessionMonitor.thread() == window.thread());
    const QPointer<passwall::platform::LinuxSessionMonitor> monitor(&sessionMonitor);
    const QPointer<passwall::platform::SessionLockService> guardedControl(&control);
    const auto protectionChanged = [&window, monitor, guardedControl]() {
        window.setLifecycleProtectionAvailable(monitor && monitor->protectionIsOperational() &&
            guardedControl && guardedControl->isAvailable());
    };
    window.setLifecycleProtectionValidator(
        [monitor, guardedControl]() { return monitor && monitor->protectionIsOperational() &&
            guardedControl && guardedControl->isAvailable(); },
        [monitor]() { if (monitor) monitor->invalidateProtection(); });
    QObject::connect(&sessionMonitor,
        &passwall::platform::LinuxSessionMonitor::protectionChanged,
        &window, protectionChanged,
        Qt::DirectConnection);
    QObject::connect(&control, &passwall::platform::SessionLockService::availabilityChanged,
        &window, protectionChanged, Qt::DirectConnection);
    QObject::connect(&window, &passwall::gui::MainWindow::lifecycleSecretsCleared,
        &sessionMonitor, &passwall::platform::LinuxSessionMonitor::acknowledgeLocked,
        Qt::DirectConnection);
    sessionMonitor.start();
    control.start(qEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS"));
#endif

    bridge.setActivationHandler([&window]() {
        window.activateFromNativeRequest();
    });

    bridge.setRequestHandler(
        [&window](const QJsonObject& request) {
            return window.handleNativeRequest(request);
        });

    window.show();

    const int result = application.exec();

#ifdef Q_OS_LINUX
    control.stop(); // fail-closed cleanup before dropping the control name
    sessionMonitor.stop(); // cleanup + acknowledgement BEFORE releasing the FD
#endif
    bridge.stop();

    return result;
}
