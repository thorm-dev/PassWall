#include <QCoreApplication>
#include <QFile>
#include <QTimer>

#include <csignal>

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    if (application.arguments().size() == 3 &&
        application.arguments()[1] == QStringLiteral("--activation-probe")) {
        QFile probe(application.arguments()[2]);
        return probe.open(QIODevice::WriteOnly) && probe.write("activated\n") == 10 ? 0 : 72;
    }
    if (application.arguments() != QStringList{application.arguments()[0], QStringLiteral("-p")})
        return 70;
    QFile log(qEnvironmentVariable("PASSWALL_TEST_LOCKER_LOG"));
    if (!log.open(QIODevice::WriteOnly | QIODevice::Append) || log.write("started\n") != 8 || !log.flush())
        return 71;
    // All substitution controls are confined to this fake, never swaylock.
    QTimer::singleShot(qEnvironmentVariableIntValue("PASSWALL_TEST_LOCKER_HOLD_MS"), [&] {
        if (qEnvironmentVariableIsSet("PASSWALL_TEST_LOCKER_CRASH"))
            std::raise(SIGKILL);
        application.exit(qEnvironmentVariableIntValue("PASSWALL_TEST_LOCKER_EXIT_CODE"));
    });
    return application.exec();
}
