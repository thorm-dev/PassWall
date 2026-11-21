#include "services/initial_backup_preparer.hpp"

#include "services/backup_job.hpp"
#include "services/vault_preferences_store.hpp"
#include "services/vault_snapshot_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QThread>

#include <cerrno>
#include <string>
#include <utility>

#ifdef Q_OS_UNIX
#include <sys/stat.h>
#endif

namespace passwall::services {
namespace {

bool sameVault(const VaultFileIdentity& expected, const VaultFileIdentity& observed)
{
    return expected.path == observed.path && expected.vaultId == observed.vaultId
        && expected.device != 0 && expected.inode != 0
        && expected.device == observed.device && expected.inode == observed.inode;
}

bool cancellationRequested(const InitialBackupCancellation& cancellation,
    quint64 sessionGeneration, InitialBackupCheckpoint checkpoint) noexcept
{
    return cancellation.requested != nullptr
        && cancellation.requested(cancellation.context, sessionGeneration, checkpoint);
}

InitialBackupPreparation decision(InitialBackupDecision value, QString diagnostic = {})
{
    InitialBackupPreparation result;
    result.decision = value;
    result.diagnostic = std::move(diagnostic);
    return result;
}

bool managedBackupName(const QString& name)
{
    static const QRegularExpression expression(QStringLiteral(
        R"(^([0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2})(?:_([1-9][0-9]*))?\.pwdb$)"));
    const auto match = expression.match(name);
    if (!match.hasMatch()) return false;
    const QDateTime timestamp = QDateTime::fromString(
        match.captured(1), QStringLiteral("yyyy-MM-dd_HH-mm-ss"));
    if (!timestamp.isValid()) return false;
    const QString suffix = match.captured(2);
    if (suffix.isEmpty()) return true;
    bool valid = false;
    const qulonglong number = suffix.toULongLong(&valid);
    return valid && number >= 2;
}

QByteArray vaultIdBytes(const SnapshotVaultContents& contents)
{
    return QByteArray(reinterpret_cast<const char*>(contents.vaultId.data()),
        static_cast<qsizetype>(contents.vaultId.size()));
}

} // namespace

InitialBackupRequest::InitialBackupRequest(
    quint64 sessionGeneration, PreparedBackupDestination destination) noexcept
    : sessionGeneration_(sessionGeneration), destination_(std::move(destination)) {}

InitialBackupRequest::InitialBackupRequest(InitialBackupRequest&& other) noexcept
    : sessionGeneration_(std::exchange(other.sessionGeneration_, 0)),
      destination_(std::move(other.destination_)),
      consumed_(std::exchange(other.consumed_, true)) {}

InitialBackupRequest& InitialBackupRequest::operator=(InitialBackupRequest&& other) noexcept
{
    if (this != &other) {
        sessionGeneration_ = std::exchange(other.sessionGeneration_, 0);
        destination_ = std::move(other.destination_);
        consumed_ = std::exchange(other.consumed_, true);
    }
    return *this;
}

bool InitialBackupRequest::admitAndStart(
    BackupJob& job, const InitialBackupAdmission& admission, QString& error)
{
    error.clear();
    if (consumed_) {
        error = QStringLiteral("Demande de première sauvegarde déjà consommée.");
        return false;
    }
    consumed_ = true;
    const auto reject = [this, &error](const QString& diagnostic) {
        destination_ = {};
        error = diagnostic;
        return false;
    };
    try {
        if (QThread::currentThread() != job.thread())
            return reject(QStringLiteral(
                "Admission de la sauvegarde hors du thread propriétaire."));
        if (admission.triggerMode != BackupTriggerMode::Generational)
            return reject(QStringLiteral(
                "Le moteur générationnel n'est pas sélectionné pour cette demande."));
        if (admission.closing || !admission.sessionCurrent)
            return reject(QStringLiteral(
                "Session fermée, invalidée ou en cours de fermeture."));
        if (!admission.operationAdmissible)
            return reject(QStringLiteral(
                "Une opération incompatible empêche la première sauvegarde."));
        if (sessionGeneration_ == 0
            || admission.currentSessionGeneration != sessionGeneration_)
            return reject(QStringLiteral(
                "Génération de session obsolète ou incohérente."));
        if (!BackupDestinationPreparer::startPreparedSnapshot(
                destination_, admission.currentVault, sessionGeneration_, job, error)) {
            if (error.isEmpty())
                error = QStringLiteral("Admission finale de la première sauvegarde refusée.");
            return false;
        }
        return true;
    } catch (...) {
        return reject(QStringLiteral(
            "Admission finale de la première sauvegarde interrompue."));
    }
}

InitialBackupPreparation InitialBackupPreparer::prepare(
    const GlobalBackupPreferencesResult& configuration,
    const AuthenticatedBackupSession& session,
    const QDateTime& timestamp,
    InitialBackupCancellation cancellation)
{
    try {
        if (!configuration.valid())
            return decision(InitialBackupDecision::ConfigurationUnavailable,
                configuration.diagnostic.isEmpty()
                    ? QStringLiteral("Configuration globale absente ou invalide.")
                    : configuration.diagnostic);
        if (configuration.preferences.rootDirectory.isEmpty()
            || configuration.preferences.retainedVersions
                < GlobalBackupPreferencesStore::MinimumRetainedVersions)
            return decision(InitialBackupDecision::ConfigurationUnavailable,
                QStringLiteral("Configuration globale incomplète ou invalide."));
        if (!session.authenticated || session.sessionGeneration == 0
            || session.vault.path.isEmpty() || session.vault.vaultId.size() != 16
            || session.vault.device == 0 || session.vault.inode == 0)
            return decision(InitialBackupDecision::Refused,
                QStringLiteral("Session authentifiée ou identité du coffre invalide."));
        if (!timestamp.isValid())
            return decision(InitialBackupDecision::Refused,
                QStringLiteral("Horodatage de la demande invalide."));
        if (cancellation.requested == nullptr)
            return decision(InitialBackupDecision::Refused,
                QStringLiteral("Contrôle de durée de vie de session absent."));
        if (cancellationRequested(cancellation, session.sessionGeneration,
                InitialBackupCheckpoint::BeforeInspection))
            return decision(InitialBackupDecision::Cancelled);

#ifndef Q_OS_UNIX
        Q_UNUSED(timestamp);
        return decision(InitialBackupDecision::Refused,
            QStringLiteral("Inspection sécurisée indisponible sur cette plateforme."));
#else
        storage::VaultOperationGuard sourceAccess;
        std::string reservationError;
        if (!sourceAccess.trySnapshotAccess(
                session.vault.path.toStdString(), reservationError))
            return decision(InitialBackupDecision::Refused,
                reservationError.empty()
                    ? QStringLiteral("Réservation d'instantané impossible.")
                    : QString::fromStdString(reservationError));
        if (!sourceAccess.matchesSnapshotIdentity(session.vault.path.toStdString(),
                session.vault.device, session.vault.inode, reservationError))
            return decision(InitialBackupDecision::Refused,
                reservationError.empty()
                    ? QStringLiteral("Identité physique du coffre divergente.")
                    : QString::fromStdString(reservationError));
        if (cancellationRequested(cancellation, session.sessionGeneration,
                InitialBackupCheckpoint::AfterSnapshotReservation))
            return decision(InitialBackupDecision::Cancelled);

        VaultFileIdentity observedVault;
        QString identityError;
        if (!VaultPreferencesStore::inspectVault(
                session.vault.path, observedVault, identityError)
            || !sameVault(session.vault, observedVault))
            return decision(InitialBackupDecision::Refused,
                identityError.isEmpty()
                    ? QStringLiteral("Le coffre ouvert ne correspond plus à la session.")
                    : identityError);

        SnapshotSourceIdentity sourceIdentity;
        SnapshotVaultContents sourceContents;
        std::string sourceError;
        if (!VaultSnapshotService::prevalidateVaultSource(
                session.vault.path.toStdString(), sourceError,
                &sourceIdentity, &sourceContents)
            || sourceIdentity.device != session.vault.device
            || sourceIdentity.inode != session.vault.inode
            || vaultIdBytes(sourceContents) != session.vault.vaultId)
            return decision(InitialBackupDecision::Refused,
                sourceError.empty()
                    ? QStringLiteral("Contenu ou identité du coffre incohérent.")
                    : QString::fromStdString(sourceError));
        if (!sourceContents.hasEntries)
            return decision(InitialBackupDecision::EmptyVault);
        if (session.pendingMutationGeneration != 0)
            return decision(InitialBackupDecision::CoveredByPendingMutation);

        SnapshotDirectoryIdentity rootIdentity;
        std::string directoryError;
        const QString root = configuration.preferences.rootDirectory;
        if (!VaultSnapshotService::inspectDestinationDirectory(
                root.toStdString(), rootIdentity, directoryError))
            return decision(InitialBackupDecision::Refused,
                directoryError.empty()
                    ? QStringLiteral("Racine de sauvegarde refusée.")
                    : QString::fromStdString(directoryError));

        const QString family = QDir(root).filePath(
            QString::fromLatin1(session.vault.vaultId.toHex()));
        SnapshotDirectoryIdentity familyIdentity;
        bool familyPresent = false;
        struct stat familyStatus {};
        const QByteArray encodedFamily = QFile::encodeName(family);
        if (::lstat(encodedFamily.constData(), &familyStatus) == 0) {
            familyPresent = true;
            if (!S_ISDIR(familyStatus.st_mode)
                || !VaultSnapshotService::inspectDestinationDirectory(
                    family.toStdString(), familyIdentity, directoryError))
                return decision(InitialBackupDecision::Refused,
                    directoryError.empty()
                        ? QStringLiteral("Dossier familial ambigu ou non protégé.")
                        : QString::fromStdString(directoryError));
        } else if (errno != ENOENT) {
            return decision(InitialBackupDecision::Refused,
                QStringLiteral("Présence du dossier familial impossible à vérifier."));
        }

        if (familyPresent && !session.forceInitialCopy) {
            const QStringList entries = QDir(family).entryList(
                QDir::AllEntries | QDir::Hidden | QDir::System
                    | QDir::NoDotAndDotDot,
                QDir::Name);
            for (const QString& name : entries) {
                if (cancellationRequested(cancellation, session.sessionGeneration,
                        InitialBackupCheckpoint::DuringFamilyInspection))
                    return decision(InitialBackupDecision::Cancelled);
                if (!managedBackupName(name)) continue;
                SnapshotVaultContents backupContents;
                std::string backupError;
                const QString candidate = QDir(family).filePath(name);
                if (VaultSnapshotService::prevalidateVaultSource(
                        candidate.toStdString(), backupError, nullptr, &backupContents)
                    && vaultIdBytes(backupContents) == session.vault.vaultId) {
                    SnapshotDirectoryIdentity stableFamily;
                    if (!VaultSnapshotService::inspectDestinationDirectory(
                            family.toStdString(), stableFamily, directoryError)
                        || stableFamily != familyIdentity)
                        return decision(InitialBackupDecision::Refused,
                            QStringLiteral("Le dossier familial a changé pendant l'inspection."));
                    if (!sourceAccess.matchesSnapshotIdentity(
                            session.vault.path.toStdString(), session.vault.device,
                            session.vault.inode, reservationError))
                        return decision(InitialBackupDecision::Refused,
                            QStringLiteral("Le coffre a changé pendant l'inspection."));
                    return decision(InitialBackupDecision::ExistingAdmissibleBackup);
                }
            }
            SnapshotDirectoryIdentity stableFamily;
            if (!VaultSnapshotService::inspectDestinationDirectory(
                    family.toStdString(), stableFamily, directoryError)
                || stableFamily != familyIdentity)
                return decision(InitialBackupDecision::Refused,
                    QStringLiteral("Le dossier familial a changé pendant l'inspection."));
        }

        SnapshotDirectoryIdentity stableRoot;
        if (!VaultSnapshotService::inspectDestinationDirectory(
                root.toStdString(), stableRoot, directoryError)
            || stableRoot != rootIdentity)
            return decision(InitialBackupDecision::Refused,
                QStringLiteral("La racine de sauvegarde a changé pendant l'inspection."));
        if (cancellationRequested(cancellation, session.sessionGeneration,
                InitialBackupCheckpoint::BeforeDestinationPreparation))
            return decision(InitialBackupDecision::Cancelled);

        PreparedBackupDestination destination;
        QString preparationError;
        if (!BackupDestinationPreparer::prepare(configuration, session.vault,
                session.sessionGeneration, timestamp, destination, preparationError,
                &rootIdentity, familyPresent ? &familyIdentity : nullptr, &sourceAccess))
            return decision(InitialBackupDecision::Refused, preparationError);
        if (cancellationRequested(cancellation, session.sessionGeneration,
                InitialBackupCheckpoint::BeforeReturn))
            return decision(InitialBackupDecision::Cancelled);

        InitialBackupPreparation result;
        result.decision = InitialBackupDecision::Prepared;
        result.request.emplace(
            session.sessionGeneration, std::move(destination));
        return result;
#endif
    } catch (...) {
        return decision(InitialBackupDecision::Refused,
            QStringLiteral("Préparation de la première sauvegarde interrompue."));
    }
}

} // namespace passwall::services
