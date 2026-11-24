#include "services/backup_series_identity.hpp"

#include <gtest/gtest.h>

using passwall::services::BackupInstallationIdentity;
using passwall::services::BackupInstallationIdentityDomain;
using passwall::services::BackupSeriesIdentityService;

namespace {

BackupInstallationIdentity fictitiousInstallation(unsigned char byte)
{
    return {BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
        QByteArray(BackupSeriesIdentityService::InstallationIdentitySize,
            static_cast<char>(byte))};
}

TEST(BackupSeriesIdentityTest, StableForRepeatedCalls)
{
    const auto installation = fictitiousInstallation(0x11);
    const QByteArray vaultId(BackupSeriesIdentityService::VaultIdSize, '\x42');
    QString first, second, error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        installation, vaultId, first, error)) << error.toStdString();
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        installation, vaultId, second, error)) << error.toStdString();
    EXPECT_EQ(first, second);
    EXPECT_EQ(first.size(), BackupSeriesIdentityService::EncodedSeriesIdSize);
}

TEST(BackupSeriesIdentityTest, DifferentInstallationsUseDifferentSeries)
{
    const QByteArray vaultId(BackupSeriesIdentityService::VaultIdSize, '\x42');
    QString first, second, error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        fictitiousInstallation(0x21), vaultId, first, error));
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        fictitiousInstallation(0x22), vaultId, second, error));
    EXPECT_NE(first, second);
}

TEST(BackupSeriesIdentityTest, DifferentVaultIdsUseDifferentSeries)
{
    const auto installation = fictitiousInstallation(0x31);
    QString first, second, error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(installation,
        QByteArray(BackupSeriesIdentityService::VaultIdSize, '\x41'), first, error));
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(installation,
        QByteArray(BackupSeriesIdentityService::VaultIdSize, '\x42'), second, error));
    EXPECT_NE(first, second);
}

TEST(BackupSeriesIdentityTest, DerivationIsIndependentOfVaultPathAndInode)
{
    const auto installation = fictitiousInstallation(0x51);
    const QByteArray vaultId(BackupSeriesIdentityService::VaultIdSize, '\x52');
    // Path and physical identity are deliberately not accepted by this API.
    // Two moved/recreated principals with the same vault_id therefore derive
    // the same local series while later admission still checks their inode.
    QString beforeMove, afterMove, error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        installation, vaultId, beforeMove, error));
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(
        installation, vaultId, afterMove, error));
    EXPECT_EQ(beforeMove, afterMove);
}

TEST(BackupSeriesIdentityTest, RawInstallationIdentityIsNotExposed)
{
    BackupInstallationIdentity installation{
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1,
        QByteArray::fromHex("00112233445566778899aabbccddeeff")};
    QString seriesId, error;
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(installation,
        QByteArray(BackupSeriesIdentityService::VaultIdSize, '\x61'),
        seriesId, error));
    EXPECT_FALSE(seriesId.contains(QString::fromLatin1(installation.value.toHex())));
    EXPECT_EQ(seriesId, seriesId.toLower());
}

TEST(BackupSeriesIdentityTest, MissingOrUnverifiedIdentityFailsClosed)
{
    QString seriesId, error;
    BackupInstallationIdentity missing;
    EXPECT_FALSE(BackupSeriesIdentityService::deriveSeriesId(missing,
        QByteArray(BackupSeriesIdentityService::VaultIdSize, '\x71'),
        seriesId, error));
    EXPECT_TRUE(seriesId.isEmpty());
    EXPECT_FALSE(error.isEmpty());

    BackupInstallationIdentity windowsReserved{
        BackupInstallationIdentityDomain::WindowsReservedV1,
        QByteArray(BackupSeriesIdentityService::InstallationIdentitySize, '\x72')};
    error.clear();
    EXPECT_FALSE(BackupSeriesIdentityService::deriveSeriesId(windowsReserved,
        QByteArray(BackupSeriesIdentityService::VaultIdSize, '\x73'),
        seriesId, error));
    EXPECT_FALSE(error.isEmpty());
}

} // namespace
