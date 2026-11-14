#include "services/restore_executable_trust.hpp"

#include <QFile>
#include <sys/stat.h>
#include <unistd.h>

namespace passwall::services::restore_executable_trust {
namespace {
Failure inspect(const QString& path, struct stat& metadata) noexcept
{
    try {
        const auto encoded = QFile::encodeName(path);
        if (::lstat(encoded.constData(), &metadata) != 0) return Failure::Missing;
        if (!S_ISREG(metadata.st_mode)) return Failure::NotRegular;
        if (metadata.st_uid != ::geteuid()) return Failure::WrongOwner;
        if (metadata.st_mode & 0022) return Failure::WritableByOthers;
        if (!(metadata.st_mode & 0100)) return Failure::NotOwnerExecutable;
        return Failure::None;
    } catch (...) {
        return Failure::Missing;
    }
}
}

Failure executable(const QString& path) noexcept
{
    struct stat metadata {};
    return inspect(path, metadata);
}

Failure processExecutable(pid_t process, const QString& expected) noexcept
{
    struct stat trusted {}, actual {};
    if (const auto failure = inspect(expected, trusted); failure != Failure::None) return failure;
    try {
        const auto proc = QByteArray("/proc/") + QByteArray::number(process) + "/exe";
        if (::stat(proc.constData(), &actual) != 0) return Failure::ProcessUnavailable;
    } catch (...) {
        return Failure::ProcessUnavailable;
    }
    if (actual.st_dev != trusted.st_dev || actual.st_ino != trusted.st_ino)
        return Failure::IdentityMismatch;
    return Failure::None;
}

QString diagnostic(Failure failure, const QString& subject)
{
    switch (failure) {
    case Failure::None: return {};
    case Failure::Missing: return QStringLiteral("%1 introuvable.").arg(subject);
    case Failure::NotRegular: return QStringLiteral("%1 n'est pas un fichier ordinaire.").arg(subject);
    case Failure::WrongOwner: return QStringLiteral("%1 n'appartient pas à l'utilisateur courant.").arg(subject);
    case Failure::WritableByOthers:
        return QStringLiteral("%1 possède des permissions non sûres ; retirer l'écriture du groupe et des autres utilisateurs (0755 attendu).").arg(subject);
    case Failure::NotOwnerExecutable: return QStringLiteral("%1 n'est pas exécutable par son propriétaire.").arg(subject);
    case Failure::ProcessUnavailable: return QStringLiteral("L'identité du processus %1 ne peut pas être vérifiée.").arg(subject);
    case Failure::IdentityMismatch:
        return QStringLiteral("Le processus %1 ne correspond plus à l'exécutable attendu ; redémarrer PassWall après compilation ou déploiement.").arg(subject);
    }
    return QStringLiteral("%1 ne satisfait pas les contrôles de sécurité.").arg(subject);
}

} // namespace passwall::services::restore_executable_trust
