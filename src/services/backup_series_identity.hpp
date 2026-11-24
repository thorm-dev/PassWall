#pragma once

#include <QByteArray>
#include <QString>

namespace passwall::services {

// Domain separation is part of the stable derivation format.  The Windows
// value is reserved so that a future, verified platform identity cannot share
// the Linux derivation domain; no Windows identity source is implemented here.
enum class BackupInstallationIdentityDomain : quint8 {
    LinuxSystemdMachineAppSpecificV1 = 1,
    WindowsReservedV1 = 2
};

// Non-secret, transient input.  Linux values are the application-specific
// result returned by systemd, never the raw machine-id.
struct BackupInstallationIdentity {
    BackupInstallationIdentityDomain domain =
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1;
    QByteArray value;
    bool operator==(const BackupInstallationIdentity&) const = default;
};

class BackupSeriesIdentityService final {
public:
    static constexpr qsizetype InstallationIdentitySize = 16;
    static constexpr qsizetype VaultIdSize = 16;
    static constexpr qsizetype SeriesIdSize = 32;
    static constexpr qsizetype EncodedSeriesIdSize = SeriesIdSize * 2;

    // Linux uses sd_id128_get_machine_app_specific() with PassWall's fixed
    // application id.  Failure is explicit: no random or path-derived fallback
    // is ever generated.  Windows remains deliberately unimplemented.
    [[nodiscard]] static bool currentInstallation(
        BackupInstallationIdentity& output, QString& error);

    // Versioned, canonical derivation.  The returned identifier is lowercase
    // hexadecimal and is suitable as one path component only; it is not an
    // authentication or restoration authority.
    [[nodiscard]] static bool deriveSeriesId(
        const BackupInstallationIdentity& installation,
        const QByteArray& vaultId, QString& output, QString& error);
};

} // namespace passwall::services
