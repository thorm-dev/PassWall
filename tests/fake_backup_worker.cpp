// Deliberately faulty protocol peer. Never linked to production.
#include "services/backup_protocol.hpp"
#include "services/backup_rotation_service.hpp"
#include <QCoreApplication>
#include <QFile>
#include <QThread>
#include <csignal>
#include <poll.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    QByteArray bytes;
    char byte;
    while (::read(0, &byte, 1) == 1 && bytes.size() < 32768) {
        bytes += byte;
        if (byte == '\n') break;
    }
    QString source, destination;
    using namespace passwall::services;
    const bool rotation = application.arguments().contains("--rotation-v1");
    AutomaticBackupContext context;
    if (rotation ? !backup_protocol::parseRotationRequest(bytes, source, context)
                 : !backup_protocol::parseRequest(bytes, source, destination)) return 1;
    if (rotation) {
        const auto args = application.arguments();
        passwall::storage::VaultOperationGuard reservation;
        std::string error;
        if (args.size() != 4 || !reservation.adoptReservation(source.toStdString(),
            {args[2].toInt(), args[3].toInt()}, error)) return 1;
        QFile fault(source + ".fake-rotation-mode");
        if (fault.open(QIODevice::ReadOnly)) {
            const auto mode = fault.readAll();
            if (mode == "missing") return 0;
            if (mode == "malformed") { (void)::write(1, "invalid", 7); return 0; }
        }
        const auto result = backup_protocol::rotationResult(BackupRotationService::rotate(
            context.settingsFile, context.localId, context.attempt, source, reservation));
        return ::write(1, result.constData(), result.size()) == result.size() ? 0 : 1;
    }
    QString mode = source.mid(1);
    QFile selection(source + ".fake-mode");
    if (selection.open(QIODevice::ReadOnly)) mode = QString::fromUtf8(selection.readAll());
    if (mode == "ignore") ::signal(SIGTERM, SIG_IGN);
    QFile ready(destination + ".ready");
    if (!ready.open(QIODevice::WriteOnly)) return 1;
    const auto pid = QByteArray::number(::getpid());
    if (ready.write(pid) != pid.size()) return 1;
    ready.close();
    if (mode == "orphan") {
        // Deliberately ignores parent loss; tests exercise inherited locks,
        // not a claim that every helper can always be killed immediately.
        while (!QFile::exists(destination + ".exit")) QThread::msleep(5);
        return 0;
    }
    if (mode == "crash") { ::raise(SIGKILL); return 1; }
    if (mode == "missing") return 0;
    if (mode == "malformed") { (void)::write(1, "not-json", 8); return 0; }
    if (mode == "partial") { (void)::write(1, "{\"v\":1", 6); return 0; }
    if (mode == "oversize") {
        const QByteArray flood(65536, 'x');
        (void)::write(1, flood.constData(), flood.size());
        return 0;
    }
    if (mode == "ignore") {
        for (;;) ::pause();
    }
    if (mode == "slow") QThread::msleep(250);
    if (mode == "slow-published-file") QThread::msleep(250);
    if (mode == "published-file" || mode == "slow-published-file" || mode == "durability-file") {
        if (!QFile::copy(source, destination)) return 1;
        QFile::setPermissions(destination, QFile::ReadOwner | QFile::WriteOwner);
    }
    if (mode == "cancel" || mode == "late") {
        struct pollfd input{0, POLLIN, 0};
        if (::poll(&input, 1, 5000) <= 0) return 1;
        if (::read(0, &byte, 1) < 0) return 1;
    }
    const auto outcome = mode == "cancel" ? BackupOutcome::CancelledBeforePublication :
        (mode == "failed" || mode == "enospc") ? BackupOutcome::FailedBeforePublication :
        (mode == "durability" || mode == "durability-file") ? BackupOutcome::DurabilityUnconfirmed : BackupOutcome::Published;
    BackupResult value{outcome, mode == "enospc" ? QStringLiteral("Écriture [errno=28].") : QString()};
    if (mode == "published-file" || mode == "slow-published-file" || mode == "durability-file") {
        BackupFileEvidence evidence; QString error;
        if (!BackupRotationService::inspectEncryptedFile(destination, evidence, error)) return 1;
        value.receipt = evidence;
    }
    const auto result = backup_protocol::result(value);
    // Fragmented output is legal; terminal parsing occurs only after exit.
    for (auto part : {result.first(5), result.sliced(5)})
        if (::write(1, part.constData(), part.size()) != part.size()) return 1;
    return 0;
}
