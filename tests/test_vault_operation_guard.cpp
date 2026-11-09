#include "storage/vault_operation_guard.hpp"
#include "storage/vault_storage.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include <gtest/gtest.h>
#include <sodium.h>
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <filesystem>
#include <algorithm>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using passwall::storage::VaultOperationGuard;
using passwall::storage::VaultStorage;
using passwall::services::CredentialService;
using passwall::services::VaultLifecycleService;
class VaultOperationGuardTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    std::string path, other, error;
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        ASSERT_GE(sodium_init(), 0);
        path = directory.filePath("vault.db").toStdString();
        other = directory.filePath("other.db").toStdString();
        ASSERT_TRUE(VaultStorage::createSchema(path, error));
        ASSERT_TRUE(VaultStorage::createSchema(other, error));
        passwall::services::VaultKeyMetadata metadata;
        metadata.vaultId.fill(0x42);
        ASSERT_TRUE(VaultStorage::writeMetadata(path, metadata, error));
        ASSERT_TRUE(VaultStorage::writeMetadata(other, metadata, error));
    }
    QByteArray contents()
    {
        QFile file(QString::fromStdString(path));
        if (!file.open(QIODevice::ReadOnly)) return {};
        return file.readAll();
    }
};
TEST_F(VaultOperationGuardTest, ReservationExcludesOtherAccessesUntilReleased)
{
    VaultOperationGuard reservation, contender;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    EXPECT_FALSE(contender.tryReserve(path, error));
    EXPECT_FALSE(contender.tryAccess(path, error));
    EXPECT_FALSE(error.empty());
    reservation.reset();
    EXPECT_TRUE(contender.tryReserve(path, error));
}
TEST_F(VaultOperationGuardTest, ExistingBusinessAccessRefusesAReservationWithoutWaiting)
{
    VaultOperationGuard access, second, reservation;
    ASSERT_TRUE(access.tryAccess(path, error));
    EXPECT_TRUE(second.tryAccess(path, error));
    EXPECT_FALSE(reservation.tryReserve(path, error));
}
TEST_F(VaultOperationGuardTest, OtherVaultRemainsUsableEvenWithIdenticalContent)
{
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    EXPECT_TRUE(access.tryAccess(other, error));
    EXPECT_TRUE(VaultStorage::createSchema(directory.filePath("third.db").toStdString(), error));
}
TEST_F(VaultOperationGuardTest, ReservedMissingTargetCannotBeCreatedByLifecycleOrStorage)
{
    const auto target = directory.filePath("future-target.db").toStdString();
    VaultOperationGuard reservation;
    ASSERT_TRUE(reservation.tryReserve(target, error));
    passwall::core::SecureBuffer key(0);
    EXPECT_FALSE(VaultLifecycleService::createVault(target, "Fictitious master", key, error));
    EXPECT_TRUE(key.empty());
    EXPECT_FALSE(VaultStorage::createSchema(target, error));
    EXPECT_FALSE(QFile::exists(QString::fromStdString(target)));
    reservation.reset();
    EXPECT_TRUE(VaultStorage::createSchema(target, error));
}
TEST_F(VaultOperationGuardTest, ReservationCapabilityIsSourceSpecificAndAccessCannotExportIt)
{
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    EXPECT_TRUE(reservation.matchesReservation(path, error));
    EXPECT_FALSE(reservation.matchesReservation(other, error));
    ASSERT_TRUE(access.tryAccess(other, error));
    EXPECT_TRUE((access.inheritedHandles() == std::array<int, 2>{-1, -1}));
    EXPECT_FALSE(access.matchesReservation(other, error));
    reservation.reset();
    EXPECT_FALSE(reservation.matchesReservation(path, error));
}
TEST_F(VaultOperationGuardTest, DirectCrudAndReadWriteReadsAreRefusedWithoutChangingDatabase)
{
    passwall::core::SecureBuffer key(passwall::core::KeySize);
    std::fill_n(key.data(), key.size(), 0x42);
    passwall::models::Credential credential;
    credential.title = "Fictitious title";
    credential.username = "Fictitious username";
    credential.password = "Fictitious password";
    ASSERT_TRUE(CredentialService::add(path, key, credential, error));
    const auto original = credential;
    const auto before = contents();
    VaultOperationGuard reservation;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    EXPECT_FALSE(CredentialService::add(path, key, credential, error));
    EXPECT_TRUE(credential.id == original.id);
    EXPECT_FALSE(CredentialService::update(path, key, credential, error));
    EXPECT_FALSE(CredentialService::remove(path, key, credential.id, error));
    std::vector<passwall::models::CredentialSummary> summaries;
    EXPECT_FALSE(CredentialService::listSummaries(path, key, summaries, error));
    EXPECT_TRUE(summaries.empty());
    passwall::services::VaultKeyMetadata metadata;
    EXPECT_FALSE(VaultStorage::readMetadata(path, metadata, error));
    EXPECT_FALSE(VaultStorage::writeMetadata(path, metadata, error));
    passwall::core::SecureBuffer output(0);
    EXPECT_FALSE(VaultLifecycleService::unlockVault(path, "Fictitious master", output, error));
    EXPECT_TRUE(output.empty());
    EXPECT_EQ(contents(), before);
    reservation.reset();
    EXPECT_TRUE(CredentialService::remove(path, key, credential.id, error));
}
TEST_F(VaultOperationGuardTest, DotAliasesCannotBypassAndSymbolicAliasesAreRefused)
{
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    EXPECT_FALSE(access.tryAccess(directory.path().toStdString() + "/./vault.db", error));
    const auto link = directory.filePath("alias.db");
    ASSERT_TRUE(QFile::link(QString::fromStdString(path), link));
    EXPECT_FALSE(access.tryAccess(link.toStdString(), error));
    const auto parent = directory.filePath("alias-parent");
    ASSERT_TRUE(QFile::link(directory.path(), parent));
    EXPECT_FALSE(access.tryAccess((parent + "/vault.db").toStdString(), error));
    EXPECT_FALSE(access.tryAccess((parent + "/../vault.db").toStdString(), error));
}
TEST_F(VaultOperationGuardTest, HardLinkedFileCannotBypassReservation)
{
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    const auto alias = directory.filePath("hard.db").toStdString();
    ASSERT_EQ(::link(path.c_str(), alias.c_str()), 0);
    EXPECT_FALSE(access.tryAccess(alias, error));
}
TEST_F(VaultOperationGuardTest, RenamedFileRemainsProtectedByItsFileIdentity)
{
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    const auto moved = directory.filePath("moved.db").toStdString();
    ASSERT_EQ(::rename(path.c_str(), moved.c_str()), 0);
    EXPECT_FALSE(access.tryAccess(moved, error));
}
TEST_F(VaultOperationGuardTest, ReservationOfNameSurvivesReplacementOfSqliteInode)
{
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    // Fictitious replacement only: no production restoration is implemented.
    ASSERT_EQ(::rename(other.c_str(), path.c_str()), 0);
    EXPECT_FALSE(access.tryAccess(path, error));
}
TEST_F(VaultOperationGuardTest, ParentDirectoryRenameDoesNotCreateAnotherLockNamespace)
{
    const auto nested = directory.filePath("nested");
    ASSERT_TRUE(QDir().mkdir(nested));
    const auto source = (nested + "/vault.db").toStdString();
    ASSERT_TRUE(VaultStorage::createSchema(source, error));
    VaultOperationGuard reservation, access;
    ASSERT_TRUE(reservation.tryReserve(source, error));
    const auto moved = directory.filePath("renamed");
    ASSERT_TRUE(QDir().rename(nested, moved));
    EXPECT_FALSE(access.tryAccess((moved + "/vault.db").toStdString(), error));
}
TEST_F(VaultOperationGuardTest, MoveAndExceptionUnwindingReleaseAllDescriptors)
{
    auto fdCount = [] { return std::distance(std::filesystem::directory_iterator("/proc/self/fd"),
                                           std::filesystem::directory_iterator{}); };
    const auto before = fdCount();
    for (int i = 0; i < 20; ++i) {
        try {
            VaultOperationGuard first;
            ASSERT_TRUE(first.tryReserve(path, error));
            VaultOperationGuard moved(std::move(first));
            first.reset();
            VaultOperationGuard blocked;
            EXPECT_FALSE(blocked.tryAccess(path, error));
            throw std::runtime_error("Fictitious exception");
        } catch (const std::runtime_error&) {}
    }
    EXPECT_EQ(fdCount(), before);
    VaultOperationGuard access;
    EXPECT_TRUE(access.tryAccess(path, error));
}
TEST_F(VaultOperationGuardTest, ChildRetainsKernelReservationAfterParentDropsItsCopy)
{
    VaultOperationGuard reservation;
    ASSERT_TRUE(reservation.tryReserve(path, error));
    int channel[2]; ASSERT_EQ(::pipe(channel), 0);
    const auto child = ::fork(); ASSERT_GE(child, 0);
    if (child == 0) {
        ::close(channel[1]); char byte;
        (void)::read(channel[0], &byte, 1);
        ::_exit(0); // OS closes the inherited open file descriptions.
    }
    ::close(channel[0]);
    reservation.reset();
    VaultOperationGuard access;
    EXPECT_FALSE(access.tryAccess(path, error));
    EXPECT_EQ(::write(channel[1], "x", 1), 1);
    ::close(channel[1]); int status;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    EXPECT_TRUE(access.tryAccess(path, error));
}
} // namespace
