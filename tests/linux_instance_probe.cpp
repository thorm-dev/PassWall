#include "platform/linux_instance_lock.hpp"
#include "platform/session_lock_service.hpp"

#include <QCoreApplication>
#include <QLocalServer>
#include <QSocketNotifier>
#include <cstdio>
#include <unistd.h>

int main(int argc, char** argv)
{
    if (argc < 2)
        return 2;
    QString error;
    auto instance = passwall::platform::LinuxInstanceLock::acquireInDirectoryForTesting(
        QString::fromLocal8Bit(argv[1]), error);
    if (!instance) {
        std::fprintf(stderr, "Instance denied.\n");
        return 3;
    }
    QCoreApplication application(argc, argv);
    QLocalServer socket;
    std::unique_ptr<passwall::platform::SessionLockService> control;
    if (argc >= 3) {
        control = std::make_unique<passwall::platform::SessionLockService>(*instance,
            [&application](auto completion) {
                QMetaObject::invokeMethod(&application, [completion] { completion(true); }, Qt::QueuedConnection);
            });
        QObject::connect(control.get(), &passwall::platform::SessionLockService::availabilityChanged,
            &application, [&](bool ready) {
                if (ready) {
                    std::puts("READY");
                    std::fflush(stdout);
                }
            });
        control->start(QString::fromLocal8Bit(argv[2]));
    } else {
        if (!socket.listen(QString::fromLocal8Bit(argv[1]) + QStringLiteral("/passwall-native-bridge.sock")))
            return 4;
        std::puts("READY");
        std::fflush(stdout);
    }
    QSocketNotifier input(STDIN_FILENO, QSocketNotifier::Read);
    QObject::connect(&input, &QSocketNotifier::activated, &application, [&] {
        char data[16];
        (void)::read(STDIN_FILENO, data, sizeof(data));
        application.quit();
    });
    return application.exec();
}
