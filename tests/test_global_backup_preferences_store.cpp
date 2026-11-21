#include "services/global_backup_preferences_store.hpp"

#include <gtest/gtest.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>

#include <limits>

#ifdef Q_OS_UNIX
#include <sys/stat.h>
#include <unistd.h>
#endif

using passwall::services::GlobalBackupPreferences;
using passwall::services::GlobalBackupPreferencesStatus;
using passwall::services::GlobalBackupPreferencesStore;

namespace {

QByteArray contents(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return file.readAll();
}

void writeRaw(const QString& path, const QByteArray& bytes)
{
    ASSERT_TRUE(QDir().mkpath(QFileInfo(path).absolutePath()));
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(file.write(bytes), bytes.size());
    file.close();
    ASSERT_TRUE(QFile::setPermissions(path,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
}

class GlobalBackupPreferencesStoreTest : public ::testing::Test {
protected:
    QTemporaryDir temporary;
    QString settingsRoot;
    QString preferencesFile;
    QString backupRoot;

    void SetUp() override
    {
        ASSERT_TRUE(temporary.isValid());
        settingsRoot = temporary.filePath(QStringLiteral("settings"));
        for (const auto format : {QSettings::IniFormat, QSettings::NativeFormat}) {
            QSettings::setPath(format, QSettings::UserScope, settingsRoot);
            QSettings::setPath(format, QSettings::SystemScope, settingsRoot);
        }
        preferencesFile = GlobalBackupPreferencesStore().fileName();
        backupRoot = temporary.filePath(QStringLiteral("backups"));
        ASSERT_TRUE(QDir().mkpath(backupRoot));
    }

    GlobalBackupPreferences preferences(quint64 retained = 7) const
    {
        return {backupRoot, retained};
    }

    void writeSettings(bool root = true, bool retention = true,
        const QVariant& retainedValue = QStringLiteral("7"))
    {
        ASSERT_TRUE(QDir().mkpath(QFileInfo(preferencesFile).absolutePath()));
        QSettings settings(preferencesFile, QSettings::IniFormat);
        settings.setFallbacksEnabled(false);
        settings.setValue(QStringLiteral("format/version"), 1);
        if (root)
            settings.setValue(QStringLiteral("backup/rootDirectory"), backupRoot);
        if (retention)
            settings.setValue(QStringLiteral("backup/retainedVersions"), retainedValue);
        settings.sync();
        ASSERT_EQ(settings.status(), QSettings::NoError);
        ASSERT_TRUE(QFile::setPermissions(preferencesFile,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    }
};

TEST_F(GlobalBackupPreferencesStoreTest, AbsentConfigurationIsExplicitAndKeepsSevenAsDefault)
{
    const auto loaded = GlobalBackupPreferencesStore().load();
    EXPECT_EQ(loaded.status, GlobalBackupPreferencesStatus::Absent);
    EXPECT_FALSE(loaded.valid());
    EXPECT_TRUE(loaded.preferences.rootDirectory.isEmpty());
    EXPECT_EQ(loaded.preferences.retainedVersions, 7U);
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesStoreTest, ValidPreferencesPersistWithoutAnUpperRetentionLimit)
{
    const quint64 retained = std::numeric_limits<quint64>::max();
    const auto saved = GlobalBackupPreferencesStore().save(preferences(retained));
    ASSERT_EQ(saved.status, GlobalBackupPreferencesStatus::Valid)
        << saved.diagnostic.toStdString();

    const auto loaded = GlobalBackupPreferencesStore().load();
    ASSERT_EQ(loaded.status, GlobalBackupPreferencesStatus::Valid)
        << loaded.diagnostic.toStdString();
    EXPECT_EQ(loaded.preferences, preferences(retained));
    EXPECT_EQ(loaded.sourceFile, preferencesFile);
}

TEST_F(GlobalBackupPreferencesStoreTest, ConfirmedSaveNotifiesOnlyTheAffectedFile)
{
    QSignalSpy changed(&GlobalBackupPreferencesStore::events(),
        &passwall::services::GlobalBackupPreferencesEvents::changed);
    const auto saved = GlobalBackupPreferencesStore().save(preferences(9));
    ASSERT_EQ(saved.status, GlobalBackupPreferencesStatus::Valid)
        << saved.diagnostic.toStdString();
    EXPECT_EQ(saved.sourceFile, preferencesFile);
    ASSERT_EQ(changed.count(), 1);
    const auto notification = changed.takeFirst();
    EXPECT_EQ(notification.at(0).toString(), preferencesFile);
    EXPECT_TRUE(notification.at(1).toBool());

    EXPECT_EQ(GlobalBackupPreferencesStore().save(preferences(6)).status,
        GlobalBackupPreferencesStatus::Invalid);
    EXPECT_EQ(changed.count(), 0);
}

TEST_F(GlobalBackupPreferencesStoreTest, RetentionBelowSevenIsInvalidAndDoesNotCreateAFile)
{
    const auto saved = GlobalBackupPreferencesStore().save(preferences(6));
    EXPECT_EQ(saved.status, GlobalBackupPreferencesStatus::Invalid);
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesStoreTest, IncompleteConfigurationIsDistinctFromAbsence)
{
    writeSettings(true, false);
    const auto loaded = GlobalBackupPreferencesStore().load();
    EXPECT_EQ(loaded.status, GlobalBackupPreferencesStatus::Invalid);
    EXPECT_TRUE(loaded.diagnostic.contains(QStringLiteral("incomplète")));
}

TEST_F(GlobalBackupPreferencesStoreTest, InvalidAndCorruptConfigurationAreReportedWithoutRewrite)
{
    writeSettings(true, true, QStringLiteral("six"));
    const QByteArray invalid = contents(preferencesFile);
    EXPECT_EQ(GlobalBackupPreferencesStore().load().status,
        GlobalBackupPreferencesStatus::Invalid);
    EXPECT_EQ(contents(preferencesFile), invalid);

    const QByteArray corrupt("[broken\nvalue=unparseable\n");
    writeRaw(preferencesFile, corrupt);
    EXPECT_EQ(GlobalBackupPreferencesStore().load().status,
        GlobalBackupPreferencesStatus::Invalid);
    EXPECT_EQ(contents(preferencesFile), corrupt);

    const auto repaired = GlobalBackupPreferencesStore().save(preferences(9));
    ASSERT_EQ(repaired.status, GlobalBackupPreferencesStatus::Valid)
        << repaired.diagnostic.toStdString();
    const auto reloaded = GlobalBackupPreferencesStore().load();
    ASSERT_EQ(reloaded.status, GlobalBackupPreferencesStatus::Valid);
    EXPECT_EQ(reloaded.preferences, preferences(9));
}

TEST_F(GlobalBackupPreferencesStoreTest, UnsafeFileIsAReadErrorAndCannotBeOverwritten)
{
    ASSERT_TRUE(QDir().mkpath(preferencesFile));
    EXPECT_EQ(GlobalBackupPreferencesStore().load().status,
        GlobalBackupPreferencesStatus::ReadError);
    EXPECT_EQ(GlobalBackupPreferencesStore().save(preferences(8)).status,
        GlobalBackupPreferencesStatus::WriteError);
    EXPECT_TRUE(QFileInfo(preferencesFile).isDir());
}

TEST_F(GlobalBackupPreferencesStoreTest, UnwritableConfigurationLocationIsAWriteError)
{
    const QString blocked = temporary.filePath(QStringLiteral("blocked"));
    writeRaw(blocked, QByteArrayLiteral("not-a-directory"));
    const GlobalBackupPreferencesStore store(
        blocked + QStringLiteral("/BackupPreferences.ini"));
    const auto saved = store.save(preferences());
    EXPECT_EQ(saved.status, GlobalBackupPreferencesStatus::WriteError);
}

TEST_F(GlobalBackupPreferencesStoreTest, RelativeOrRootDestinationIsInvalid)
{
    auto relative = preferences();
    relative.rootDirectory = QStringLiteral("relative/backups");
    EXPECT_EQ(GlobalBackupPreferencesStore().save(relative).status,
        GlobalBackupPreferencesStatus::Invalid);
    auto root = preferences();
    root.rootDirectory = QStringLiteral("/");
    EXPECT_EQ(GlobalBackupPreferencesStore().save(root).status,
        GlobalBackupPreferencesStatus::Invalid);
}

TEST_F(GlobalBackupPreferencesStoreTest, SavingNeverChangesTheChosenBackupDirectoryPermissions)
{
#ifdef Q_OS_UNIX
    ASSERT_EQ(::chmod(QFile::encodeName(backupRoot).constData(), 0775), 0);
    struct stat before {}, after {};
    ASSERT_EQ(::stat(QFile::encodeName(backupRoot).constData(), &before), 0);
#endif
    ASSERT_EQ(GlobalBackupPreferencesStore().save(preferences()).status,
        GlobalBackupPreferencesStatus::Valid);
#ifdef Q_OS_UNIX
    ASSERT_EQ(::stat(QFile::encodeName(backupRoot).constData(), &after), 0);
    EXPECT_EQ(before.st_mode & 0777, after.st_mode & 0777);
    struct stat configuration {};
    ASSERT_EQ(::stat(QFile::encodeName(preferencesFile).constData(), &configuration), 0);
    EXPECT_EQ(configuration.st_mode & 0777, 0600);
#endif
}

TEST_F(GlobalBackupPreferencesStoreTest, HistoricalPassWallConfigurationRemainsIndependent)
{
    QSettings historical(QStringLiteral("PassWall"), QStringLiteral("PassWall"));
    historical.setFallbacksEnabled(false);
    historical.setValue(QStringLiteral("vaultRegistry/data"),
        QByteArrayLiteral("fictitious-historical-proof"));
    historical.sync();
    ASSERT_EQ(historical.status(), QSettings::NoError);
    const QString historicalFile = historical.fileName();
    const QByteArray before = contents(historicalFile);

    ASSERT_NE(QFileInfo(preferencesFile).absoluteFilePath(),
        QFileInfo(historicalFile).absoluteFilePath());
    ASSERT_EQ(GlobalBackupPreferencesStore().save(preferences()).status,
        GlobalBackupPreferencesStatus::Valid);
    EXPECT_EQ(contents(historicalFile), before);
    EXPECT_EQ(historical.value(QStringLiteral("vaultRegistry/data")).toByteArray(),
        QByteArrayLiteral("fictitious-historical-proof"));
}

} // namespace
