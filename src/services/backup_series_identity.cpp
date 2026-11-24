#include "services/backup_series_identity.hpp"

#include <QCryptographicHash>

#if defined(Q_OS_LINUX) && defined(PASSWALL_HAS_SYSTEMD_ID128)
#include <systemd/sd-id128.h>
#endif

namespace passwall::services {
namespace {

bool fail(QString& error, const QString& diagnostic)
{
    error = diagnostic;
    return false;
}

void appendLength(QByteArray& output, qsizetype size)
{
    output.append(static_cast<char>((size >> 8) & 0xff));
    output.append(static_cast<char>(size & 0xff));
}

#if defined(Q_OS_LINUX) && defined(PASSWALL_HAS_SYSTEMD_ID128)
// Fixed, randomly generated PassWall application id.  It is intentionally not
// derived from a machine, vault or user and must remain stable once published.
#define PASSWALL_APPLICATION_ID \
    SD_ID128_MAKE(8a,62,7a,eb,6f,47,4f,ab,87,c7,54,e4,bf,18,b6,a5)
#endif

} // namespace

bool BackupSeriesIdentityService::currentInstallation(
    BackupInstallationIdentity& output, QString& error)
{
    output = {};
    error.clear();
#if defined(Q_OS_LINUX) && defined(PASSWALL_HAS_SYSTEMD_ID128)
    sd_id128_t observed = SD_ID128_NULL;
    if (sd_id128_get_machine_app_specific(
            PASSWALL_APPLICATION_ID, &observed) < 0)
        return fail(error, QStringLiteral(
            "Identité spécifique à PassWall impossible à obtenir."));
    output.domain =
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1;
    output.value = QByteArray(
        reinterpret_cast<const char*>(observed.bytes),
        static_cast<qsizetype>(sizeof(observed.bytes)));
    return true;
#elif defined(Q_OS_LINUX)
    return fail(error, QStringLiteral(
        "Support libsystemd de l'identité stable indisponible dans cette version."));
#elif defined(Q_OS_WIN)
    return fail(error, QStringLiteral(
        "Identité stable d'installation non implémentée sous Windows."));
#else
    return fail(error, QStringLiteral(
        "Identité stable d'installation indisponible sur cette plateforme."));
#endif
}

bool BackupSeriesIdentityService::deriveSeriesId(
    const BackupInstallationIdentity& installation,
    const QByteArray& vaultId, QString& output, QString& error)
{
    output.clear();
    error.clear();
    if (installation.domain
            != BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1
        || installation.value.size() != InstallationIdentitySize)
        return fail(error, QStringLiteral(
            "Identité d'installation absente, invalide ou non prise en charge."));
    if (vaultId.size() != VaultIdSize)
        return fail(error, QStringLiteral("vault_id invalide pour la série."));

    QByteArray canonical;
    constexpr char Domain[] = "PassWall backup series";
    canonical.reserve(static_cast<qsizetype>(sizeof(Domain)) + 2
        + installation.value.size() + vaultId.size() + 4);
    canonical.append(Domain, static_cast<qsizetype>(sizeof(Domain)));
    canonical.append(static_cast<char>(1)); // Derivation format version.
    canonical.append(static_cast<char>(installation.domain));
    appendLength(canonical, installation.value.size());
    canonical.append(installation.value);
    appendLength(canonical, vaultId.size());
    canonical.append(vaultId);

    const QByteArray digest = QCryptographicHash::hash(
        canonical, QCryptographicHash::Sha256);
    if (digest.size() != SeriesIdSize)
        return fail(error, QStringLiteral(
            "Dérivation de l'identifiant de série impossible."));
    output = QString::fromLatin1(digest.toHex());
    if (output.size() != EncodedSeriesIdSize) {
        output.clear();
        return fail(error, QStringLiteral(
            "Encodage de l'identifiant de série impossible."));
    }
    return true;
}

} // namespace passwall::services
