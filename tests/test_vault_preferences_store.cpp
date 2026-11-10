#include "services/vault_preferences_store.hpp"
#include "storage/vault_storage.hpp"

#include <gtest/gtest.h>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>
#include <sqlite3.h>
#include <cerrno>
#ifdef Q_OS_UNIX
#include "posix_test_io.hpp"
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace passwall::services;
namespace {
#ifdef Q_OS_LINUX
// Inject a reported sync error AFTER writing. The test also checks restoration
// of QSettings' shared cache: failed preferences must not be returned as saved.
thread_local int statusUntilFailure = 0;
thread_local bool failConfigSync = false;
#endif
QByteArray contents(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}

class VaultPreferencesStoreTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    QString config;
    QString first;
    QString error;

    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        config = directory.filePath("settings/PassWall.ini");
        first = directory.filePath("first.db");
        makeVault(first, 0x42);
    }
    void TearDown() override
    {
#ifdef Q_OS_LINUX
        statusUntilFailure = 0;
        failConfigSync = false;
#endif
    }
    void makeVault(const QString& path, unsigned char id)
    {
        // Real storage schema, fictitious metadata only. These tests do not
        // claim cryptographic authentication; GUI tests use real lifecycle calls.
        std::string failure;
        ASSERT_TRUE(passwall::storage::VaultStorage::createSchema(path.toStdString(), failure));
        VaultKeyMetadata metadata;
        metadata.vaultId.fill(id);
        ASSERT_TRUE(passwall::storage::VaultStorage::writeMetadata(path.toStdString(), metadata, failure));
    }
    VaultRegistration registerFirst()
    {
        VaultRegistration record;
        EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, record, error),
                  VaultRecognition::Registered) << error.toStdString();
        return record;
    }
    VaultBackupPreferences enabled() const
    {
        return {true, directory.filePath("backup-folder-not-created"), 3};
    }
    void setRawRegistry(const QByteArray& bytes)
    {
        ASSERT_TRUE(QDir().mkpath(QFileInfo(config).absolutePath()));
        QSettings settings(config, QSettings::IniFormat);
        settings.setValue("vaultRegistry/data", bytes);
        settings.sync();
        ASSERT_EQ(settings.status(), QSettings::NoError);
    }
};
}

#ifdef Q_OS_LINUX
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int descriptor)
{
    if (failConfigSync) {
        failConfigSync = false;
        errno = EIO;
        return -1;
    }
    return __real_fsync(descriptor);
}
extern "C" QSettings::Status realSettingsStatus(const QSettings*)
    asm("__real__ZNK9QSettings6statusEv");
extern "C" QSettings::Status wrappedSettingsStatus(const QSettings*)
    asm("__wrap__ZNK9QSettings6statusEv");
extern "C" QSettings::Status wrappedSettingsStatus(const QSettings* settings)
{
    if (statusUntilFailure > 0 && --statusUntilFailure == 0)
        return QSettings::AccessError;
    return realSettingsStatus(settings);
}
#endif

namespace {
TEST_F(VaultPreferencesStoreTest, MissingConfigurationLoadsEmptyWithoutCreatingPreferencesFile)
{
    QVector<VaultRegistration> records;
    ASSERT_TRUE(VaultPreferencesStore(config).list(records, error));
    EXPECT_TRUE(records.isEmpty());
    EXPECT_FALSE(QFileInfo::exists(config));
}

TEST_F(VaultPreferencesStoreTest, FirstRegistrationHasRandomLocalIdAndExactlyThreeDefaults)
{
    const auto record = registerFirst();
    EXPECT_FALSE(QUuid(record.localId).isNull());
    EXPECT_NE(record.localId, QString::fromLatin1(record.file.vaultId.toHex()));
    EXPECT_FALSE(record.backup.automatic);
    EXPECT_TRUE(record.backup.directory.isEmpty());
    EXPECT_EQ(record.backup.retainedVersions, 7);
    QSettings settings(config, QSettings::IniFormat);
    const auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    EXPECT_EQ(root["version"].toInt(), 1);
    EXPECT_EQ(root["vaults"].toArray().first().toObject()["backup"].toObject().size(), 3);
}

TEST_F(VaultPreferencesStoreTest, ConditionalUpdateRejectsStalePreferencesWithoutWriting)
{
    const auto expected = registerFirst(); const VaultPreferencesStore store(config);
    ASSERT_TRUE(store.updatePreferences(expected.localId, {false, {}, 9}, error));
    const auto before = contents(config);
    EXPECT_FALSE(store.updatePreferencesIfCurrent(expected, {false, {}, 2}, error));
    EXPECT_EQ(contents(config), before); EXPECT_TRUE(error.contains("actualisez"));
    QVector<VaultRegistration> records; ASSERT_TRUE(store.list(records, error)); ASSERT_EQ(records.size(), 1);
    ASSERT_TRUE(store.updatePreferencesIfCurrent(records.first(), {false, {}, 2}, error));
    ASSERT_TRUE(VaultPreferencesStore(config).list(records, error)); EXPECT_EQ(records.first().backup.retainedVersions, 2);
}

TEST_F(VaultPreferencesStoreTest, ConditionalUpdateRejectsAnotherIdentityEvenWithTheSameLocalId)
{
    auto expected = registerFirst(); ++expected.file.inode; const auto before = contents(config);
    EXPECT_FALSE(VaultPreferencesStore(config).updatePreferencesIfCurrent(expected, {false, {}, 4}, error));
    EXPECT_EQ(contents(config), before);
}

TEST_F(VaultPreferencesStoreTest, ConditionalUpdatePreservesInternalChangesNotPresentInTheDisplayedSnapshot)
{
    const auto expected = registerFirst(); const VaultPreferencesStore store(config);
    ASSERT_TRUE(store.suspendAutomaticBackup(expected.localId, error));
    ASSERT_TRUE(store.updatePreferencesIfCurrent(expected, {false, {}, 4}, error));
    QVector<VaultRegistration> records; ASSERT_TRUE(store.list(records, error)); ASSERT_EQ(records.size(), 1);
    const auto& current = records.first(); EXPECT_EQ(current.localId, expected.localId); EXPECT_TRUE(current.file == expected.file);
    EXPECT_TRUE(current.automaticSuspended); EXPECT_TRUE(current.backupRequired); EXPECT_EQ(current.backup.retainedVersions, 4);
}

TEST_F(VaultPreferencesStoreTest, DisplaySnapshotDoesNotTakeTheBusinessRegistryWriterLock)
{
    const auto expected = registerFirst(); const VaultPreferencesStore store(config); const auto before = contents(config);
    QLockFile writer(config + ".registry-lock"); writer.setStaleLockTime(0); ASSERT_TRUE(writer.tryLock(0));
    QVector<VaultRegistration> records; ASSERT_TRUE(store.listForDisplay(records, error)); ASSERT_EQ(records.size(), 1);
    EXPECT_EQ(records.first().localId, expected.localId); EXPECT_EQ(contents(config), before);
    // This observation is NOT admission: ordinary locked queries and writes
    // must still refuse while the other writer owns the registry lock.
    EXPECT_FALSE(store.list(records, error)); EXPECT_FALSE(store.updatePreferencesIfCurrent(expected, {false, {}, 3}, error));
    EXPECT_EQ(contents(config), before); writer.unlock();
    EXPECT_TRUE(store.updatePreferencesIfCurrent(expected, {false, {}, 3}, error));
}

TEST_F(VaultPreferencesStoreTest, CorruptDisplaySnapshotIsRejectedWithoutPartialRecordsOrReset)
{
    const auto original = registerFirst(); setRawRegistry("{invalid"); const auto before = contents(config);
    QVector<VaultRegistration> records{original};
    EXPECT_FALSE(VaultPreferencesStore(config).listForDisplay(records, error)); EXPECT_TRUE(records.isEmpty());
    EXPECT_EQ(contents(config), before); EXPECT_FALSE(error.isEmpty());
}

TEST_F(VaultPreferencesStoreTest, UpdatesPersistAcrossReconstructionAndPreserveOtherVaultAndSettings)
{
    QDir().mkpath(QFileInfo(config).absolutePath());
    QSettings settings(config, QSettings::IniFormat);
    settings.setValue("security/autoLockMinutes", 15);
    settings.setValue("vault/lastPath", first);
    settings.setValue("unknown/future", "preserved");
    settings.sync();
    const auto original = registerFirst();
    ASSERT_TRUE(VaultPreferencesStore(config).updatePreferences(original.localId, enabled(), error));
    const QString second = directory.filePath("second.db");
    makeVault(second, 0x43);
    VaultRegistration other;
    ASSERT_EQ(VaultPreferencesStore(config).recognizeOrRegister(second, other, error), VaultRecognition::Registered);
    EXPECT_NE(original.localId, other.localId);
    QVector<VaultRegistration> records;
    ASSERT_TRUE(VaultPreferencesStore(config).list(records, error));
    ASSERT_EQ(records.size(), 2);
    EXPECT_TRUE(records[0].backup == enabled());
    EXPECT_TRUE(records[1].backup == VaultBackupPreferences{});
    settings.sync();
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 15);
    EXPECT_EQ(settings.value("vault/lastPath").toString(), first);
    EXPECT_EQ(settings.value("unknown/future").toString(), "preserved");
}

TEST_F(VaultPreferencesStoreTest, SameVaultIdCopyGetsIndependentDefaultsAndOriginalIsRecognized)
{
    const auto original = registerFirst();
    ASSERT_TRUE(VaultPreferencesStore(config).updatePreferences(original.localId, enabled(), error));
    const QString copy = directory.filePath("copy.db");
    ASSERT_TRUE(QFile::copy(first, copy));
    VaultRegistration duplicate;
    ASSERT_EQ(VaultPreferencesStore(config).recognizeOrRegister(copy, duplicate, error), VaultRecognition::Registered);
    EXPECT_EQ(duplicate.file.vaultId, original.file.vaultId);
    EXPECT_NE(duplicate.localId, original.localId);
    EXPECT_TRUE(duplicate.backup == VaultBackupPreferences{});
    VaultRegistration recognized;
    ASSERT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, recognized, error), VaultRecognition::Recognized);
    EXPECT_EQ(recognized.localId, original.localId);
    EXPECT_TRUE(recognized.backup == enabled());
}

TEST_F(VaultPreferencesStoreTest, PreferencesAreWrittenToDiskNotOnlyKeptInQtCache)
{
    const auto record = registerFirst();
    ASSERT_TRUE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
    const auto independent = directory.filePath("independent.ini");
    ASSERT_TRUE(QFile::copy(config, independent));
    // Different filename => fresh QSettings cache, reading the physical bytes.
    QSettings disk(independent, QSettings::IniFormat);
    const auto root = QJsonDocument::fromJson(disk.value("vaultRegistry/data").toByteArray()).object();
    const auto backup = root["vaults"].toArray().first().toObject()["backup"].toObject();
    EXPECT_TRUE(backup["automatic"].toBool());
    EXPECT_EQ(backup["directory"].toString(), enabled().directory);
    EXPECT_EQ(backup["retainedVersions"].toInt(), 3);
}

TEST_F(VaultPreferencesStoreTest, SystemScopePreferencesNeverAuthorizeAUserRegistration)
{
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, directory.filePath("user"));
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, directory.filePath("system"));
    QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, directory.filePath("user"));
    QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, directory.filePath("system"));
    const auto systemFile = QSettings(QSettings::SystemScope, "PassWall", "PassWall").fileName();
    VaultRegistration systemRecord;
    ASSERT_EQ(VaultPreferencesStore(systemFile).recognizeOrRegister(first, systemRecord, error), VaultRecognition::Registered)
        << error.toStdString();
    ASSERT_TRUE(VaultPreferencesStore(systemFile).updatePreferences(systemRecord.localId, enabled(), error));
    VaultRegistration userRecord;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(first, userRecord, error), VaultRecognition::Registered);
    EXPECT_NE(systemRecord.localId, userRecord.localId);
    EXPECT_TRUE(userRecord.backup == VaultBackupPreferences{});
}

TEST_F(VaultPreferencesStoreTest, MovedFileRequiresExplicitReassociation)
{
    registerFirst();
    const auto before = contents(config);
    const QString moved = directory.filePath("moved.db");
    ASSERT_TRUE(QFile::rename(first, moved));
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(moved, output, error), VaultRecognition::ReassociationRequired);
    EXPECT_TRUE(output.localId.isEmpty());
    EXPECT_FALSE(error.isEmpty());
    EXPECT_EQ(contents(config), before);
}

TEST_F(VaultPreferencesStoreTest, CopyWithMissingOriginalIsConservativelyAmbiguous)
{
    registerFirst();
    const QString copy = directory.filePath("copy.db");
    ASSERT_TRUE(QFile::copy(first, copy));
    ASSERT_TRUE(QFile::remove(first));
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(copy, output, error), VaultRecognition::ReassociationRequired);
}

TEST_F(VaultPreferencesStoreTest, UnexpectedReplacementDoesNotInheritPreferences)
{
    const auto original = registerFirst();
    ASSERT_TRUE(VaultPreferencesStore(config).updatePreferences(original.localId, enabled(), error));
    const QString replacement = directory.filePath("replacement.db");
    ASSERT_TRUE(QFile::copy(first, replacement)); // Even the same vault_id is insufficient.
    ASSERT_TRUE(QFile::rename(first, directory.filePath("old.db")));
    ASSERT_TRUE(QFile::rename(replacement, first));
    const auto before = contents(config);
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, output, error), VaultRecognition::ReassociationRequired);
    EXPECT_TRUE(output.localId.isEmpty());
    EXPECT_FALSE(VaultPreferencesStore(config).updatePreferences(original.localId, {}, error));
    EXPECT_EQ(contents(config), before);
}

TEST_F(VaultPreferencesStoreTest, AuthorizedReplacementPreservesLocalIdAndPreferencesAndRejectsStaleRequest)
{
    const auto original = registerFirst();
    ASSERT_TRUE(VaultPreferencesStore(config).updatePreferences(original.localId, enabled(), error));
    const QString replacement = directory.filePath("replacement.db");
    makeVault(replacement, 0x66); // Authorized replacement may have another lineage.
    ASSERT_TRUE(QFile::rename(first, directory.filePath("previous.db")));
    ASSERT_TRUE(QFile::rename(replacement, first));
    VaultFileIdentity current;
    ASSERT_TRUE(VaultPreferencesStore::inspectVault(first, current, error));
    ASSERT_TRUE(VaultPreferencesStore(config).updateIdentityAfterReplacement(original.localId, original.file, current, error));
    EXPECT_FALSE(VaultPreferencesStore(config).updateIdentityAfterReplacement(original.localId, original.file, current, error));
    VaultRegistration recognized;
    ASSERT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, recognized, error), VaultRecognition::Recognized);
    EXPECT_EQ(recognized.localId, original.localId);
    EXPECT_TRUE(recognized.backup == enabled());
}

TEST_F(VaultPreferencesStoreTest, AuthorizedReplacementRejectsWrongExpectedCurrentIdentityAndDifferentPath)
{
    const auto original = registerFirst();
    auto wrong = original.file;
    ++wrong.inode;
    EXPECT_FALSE(VaultPreferencesStore(config).updateIdentityAfterReplacement(original.localId, original.file, wrong, error));
    wrong = original.file;
    wrong.path = directory.filePath("other.db");
    EXPECT_FALSE(VaultPreferencesStore(config).updateIdentityAfterReplacement(original.localId, original.file, wrong, error));
}

TEST_F(VaultPreferencesStoreTest, SymlinkAndNonCanonicalAliasesNeverReceivePreferences)
{
    registerFirst();
    const QString alias = directory.filePath("alias.db");
    ASSERT_TRUE(QFile::link(first, alias));
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(alias, output, error), VaultRecognition::ReassociationRequired);
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(directory.path() + "/./first.db", output, error), VaultRecognition::ReassociationRequired);
    const QString parentAlias = directory.filePath("parent-alias");
    ASSERT_TRUE(QFile::link(directory.path(), parentAlias));
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(parentAlias + "/first.db", output, error), VaultRecognition::ReassociationRequired);
}

#ifdef Q_OS_UNIX
TEST_F(VaultPreferencesStoreTest, HardLinkedVaultIsRejected)
{
    registerFirst();
    const auto alias = QFile::encodeName(directory.filePath("hardlink.db"));
    ASSERT_EQ(::link(QFile::encodeName(first).constData(), alias.constData()), 0);
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, output, error), VaultRecognition::ReassociationRequired);
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(QString::fromLocal8Bit(alias), output, error), VaultRecognition::ReassociationRequired);
}

TEST_F(VaultPreferencesStoreTest, ConfigurationDirectoryAndFileAreOwnerOnly)
{
    registerFirst();
    struct stat info {};
    ASSERT_EQ(::stat(QFile::encodeName(config).constData(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0600);
    EXPECT_EQ(info.st_uid, ::geteuid());
    ASSERT_EQ(::stat(QFile::encodeName(QFileInfo(config).absolutePath()).constData(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0700);
}

TEST_F(VaultPreferencesStoreTest, AnotherProcessHoldingRegistryLockPreventsLostUpdates)
{
    const auto record = registerFirst();
    int ready[2], release[2];
    ASSERT_EQ(::pipe(ready), 0);
    ASSERT_EQ(::pipe(release), 0);
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ::close(ready[0]);
        ::close(release[1]);
        bool locked = false, exchanged = false;
        {
            QLockFile lock(config + ".registry-lock");
            locked = lock.tryLock(0);
            const char result = locked ? '1' : '0';
            char finish;
            exchanged = passwall::test_io::writeAll(ready[1], &result, 1)
                && passwall::test_io::readSome(release[0], &finish, 1) == 1 && finish == 'x';
        }
        ::_exit(locked && exchanged ? 0 : 1);
    }
    ::close(ready[1]);
    ::close(release[0]);
    char result = '0';
    EXPECT_EQ(passwall::test_io::readSome(ready[0], &result, 1), 1);
    EXPECT_EQ(result, '1');
    EXPECT_FALSE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
    EXPECT_TRUE(passwall::test_io::writeAll(release[1], "x", 1));
    ::close(ready[0]);
    ::close(release[1]);
    int status = 0;
    EXPECT_EQ(::waitpid(child, &status, 0), child);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    EXPECT_TRUE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
}
#endif

TEST_F(VaultPreferencesStoreTest, CorruptRegistryIsNotResetAndOutputIsEmpty)
{
    setRawRegistry("{not valid JSON");
    const auto before = contents(config);
    QVector<VaultRegistration> records{VaultRegistration{}};
    EXPECT_FALSE(VaultPreferencesStore(config).list(records, error));
    EXPECT_TRUE(records.isEmpty());
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, output, error), VaultRecognition::Error);
    EXPECT_EQ(contents(config), before);
}

TEST_F(VaultPreferencesStoreTest, UnsupportedSchemaAndInvalidPreferencesAreNotReset)
{
    setRawRegistry(R"({"version":2,"vaults":[]})");
    QVector<VaultRegistration> output;
    EXPECT_FALSE(VaultPreferencesStore(config).list(output, error));
    setRawRegistry(R"({"version":1,"vaults":[{}]})");
    EXPECT_FALSE(VaultPreferencesStore(config).list(output, error));
}

TEST_F(VaultPreferencesStoreTest, InvalidIniDoesNotOverwriteOtherSettings)
{
    QDir().mkpath(QFileInfo(config).absolutePath());
    QFile file(config);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_GT(file.write("[broken\nsecurity=preserve\n"), 0);
    file.close();
    const auto before = contents(config);
    VaultRegistration record;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, record, error), VaultRecognition::Error);
    EXPECT_EQ(contents(config), before);
}

TEST_F(VaultPreferencesStoreTest, InvalidUpdatesPreserveConfigurationAndAllowNextValidOperation)
{
    const auto record = registerFirst();
    const auto before = contents(config);
    for (const auto& value : {VaultBackupPreferences{false, {}, 0},
                             VaultBackupPreferences{false, {}, -1},
                             VaultBackupPreferences{true, {}, 7},
                             VaultBackupPreferences{true, "relative/path", 7},
                             VaultBackupPreferences{true, "/path/../alias", 7},
                             VaultBackupPreferences{true, QString("/path") + QChar::Null, 7}}) {
        EXPECT_FALSE(VaultPreferencesStore(config).updatePreferences(record.localId, value, error));
        EXPECT_FALSE(error.isEmpty());
        EXPECT_EQ(contents(config), before);
    }
    EXPECT_TRUE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
}

TEST_F(VaultPreferencesStoreTest, BusyRegistryFailsExplicitlyWithoutMutationAndRecovers)
{
    const auto record = registerFirst();
    const auto before = contents(config);
    {
        QLockFile lock(config + ".registry-lock");
        ASSERT_TRUE(lock.tryLock(0));
        EXPECT_FALSE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
        EXPECT_EQ(contents(config), before);
    }
    EXPECT_TRUE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
}

TEST_F(VaultPreferencesStoreTest, ConfigWritePathFailureDoesNotAlterVaultAndNextOperationWorks)
{
    const auto before = contents(first);
    ASSERT_TRUE(QDir().mkpath(config)); // A directory cannot be a preferences file.
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, output, error), VaultRecognition::Error);
    EXPECT_TRUE(output.localId.isEmpty());
    EXPECT_EQ(contents(first), before);
    ASSERT_TRUE(QDir().rmdir(config));
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, output, error), VaultRecognition::Registered);
}

#ifdef Q_OS_LINUX
TEST_F(VaultPreferencesStoreTest, ReportedSyncFailureDoesNotPublishPreferencesThroughSharedCache)
{
    const auto record = registerFirst();
    const auto vaultBefore = contents(first);
    statusUntilFailure = 3; // Fresh validation, cached read, then sync after mutation.
    EXPECT_FALSE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
    EXPECT_FALSE(error.isEmpty());
    QVector<VaultRegistration> records;
    ASSERT_TRUE(VaultPreferencesStore(config).list(records, error));
    ASSERT_EQ(records.size(), 1);
    EXPECT_TRUE(records[0].backup == VaultBackupPreferences{});
    EXPECT_EQ(contents(first), vaultBefore);
    EXPECT_TRUE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
}

TEST_F(VaultPreferencesStoreTest, PostPublicationSyncErrorReportsUncertaintyWithoutErasingPublishedConfiguration)
{
    const auto record = registerFirst();
    failConfigSync = true;
    EXPECT_FALSE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
    EXPECT_TRUE(error.contains("publiée"));
    EXPECT_TRUE(error.contains("durabilité"));
    QVector<VaultRegistration> records;
    ASSERT_TRUE(VaultPreferencesStore(config).list(records, error));
    ASSERT_EQ(records.size(), 1);
    EXPECT_TRUE(records[0].backup == enabled());
    EXPECT_TRUE(QFileInfo::exists(first));
}
#endif

TEST_F(VaultPreferencesStoreTest, ConfigurationSymlinkDoesNotModifyItsTarget)
{
    registerFirst();
    const auto target = directory.filePath("untouched.ini");
    ASSERT_TRUE(QFile::rename(config, target));
    const auto before = contents(target);
    ASSERT_TRUE(QFile::link(target, config));
    VaultRegistration output;
    EXPECT_EQ(VaultPreferencesStore(config).recognizeOrRegister(first, output, error), VaultRecognition::Error);
    EXPECT_EQ(contents(target), before);
}

TEST_F(VaultPreferencesStoreTest, RecognitionIsReadOnlyAndStoresNoCryptographicSecret)
{
    const auto before = contents(first);
    registerFirst();
    EXPECT_EQ(contents(first), before);
    EXPECT_FALSE(QFileInfo::exists(first + "-journal"));
    QSettings settings(config, QSettings::IniFormat);
    const auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    const auto object = root["vaults"].toArray().first().toObject();
    EXPECT_EQ(object.keys(), (QStringList{"automaticOrder", "automaticState", "automaticVersions", "backup", "backupEpoch", "backupRequired", "file", "localId", "rotation"}));
    EXPECT_EQ(object["backupRequired"], QJsonValue(false));
    EXPECT_EQ(object["file"].toObject().keys(),
              (QStringList{"birthTime", "device", "inode", "path", "vaultId"}));
    EXPECT_FALSE(contents(config).contains("wrapped_dek"));
    EXPECT_FALSE(contents(config).contains("password"));
}

TEST_F(VaultPreferencesStoreTest, DuplicateLocalIdentifiersOrPathsFailClosed)
{
    registerFirst();
    QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    auto records = root["vaults"].toArray();
    records.push_back(records.first());
    root["vaults"] = records;
    setRawRegistry(QJsonDocument(root).toJson(QJsonDocument::Compact));
    QVector<VaultRegistration> output;
    EXPECT_FALSE(VaultPreferencesStore(config).list(output, error));
    EXPECT_TRUE(output.isEmpty());
}

TEST_F(VaultPreferencesStoreTest, UnknownVersionOneInternalExtensionsSurviveUpdatingPreferences)
{
    const auto record = registerFirst();
    QSettings settings(config, QSettings::IniFormat);
    auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    root["futureInternal"] = QJsonObject{{"placeholder", true}};
    auto records = root["vaults"].toArray();
    auto object = records.first().toObject();
    object["internal"] = QJsonObject{{"placeholder", 1}};
    records[0] = object;
    root["vaults"] = records;
    setRawRegistry(QJsonDocument(root).toJson(QJsonDocument::Compact));
    ASSERT_TRUE(VaultPreferencesStore(config).updatePreferences(record.localId, enabled(), error));
    settings.sync();
    const auto saved = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
    EXPECT_EQ(saved["futureInternal"], root["futureInternal"]);
    EXPECT_EQ(saved["vaults"].toArray().first().toObject()["internal"], object["internal"]);
}
} // namespace
