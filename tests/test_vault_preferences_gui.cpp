#include "gui/main_window.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/vault_preferences_store.hpp"

#include <gtest/gtest.h>
#include <QApplication>
#include <QFile>
#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QTimer>
#include <memory>

namespace {
using passwall::gui::MainWindow;
using namespace passwall::services;

class VaultPreferencesGuiTest : public ::testing::Test {
protected:
    QTemporaryDir directory;
    std::unique_ptr<MainWindow> window;
    QString path;
    void recreateWindow()
    {
        window.reset();
        QApplication::processEvents();
        window = MainWindow::createForHistoricalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
    }
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, directory.path());
        // No personal/system fallback is consulted by these tests either.
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, directory.path());
        QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, directory.path());
        QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, directory.path());
        QSettings settings("PassWall", "PassWall");
        settings.setValue("security/autoLockMinutes", 5);
        settings.setValue("unrelated/value", "keep");
        settings.sync();
        path = directory.filePath("fictitious.db");
        recreateWindow();
    }
    void TearDown() override { window.reset(); QApplication::processEvents(); }
    void click(const char* name)
    {
        auto* button = window->findChild<QPushButton*>(QString::fromLatin1(name));
        ASSERT_NE(button, nullptr);
        button->click();
    }
    void field(const char* name, const QString& value)
    {
        auto* edit = window->findChild<QLineEdit*>(QString::fromLatin1(name));
        ASSERT_NE(edit, nullptr);
        edit->setText(value);
    }
    void create()
    {
        click("createPageButton");
        field("createPathEdit", path);
        field("createPasswordEdit", "fictitious-registry-master");
        field("confirmPasswordEdit", "fictitious-registry-master");
        click("createVaultButton");
    }
};

TEST_F(VaultPreferencesGuiTest, AbsentLastPathLeavesUnlockFieldEmpty)
{
    QSettings settings("PassWall", "PassWall");
    ASSERT_FALSE(settings.contains("vault/lastPath"));
    auto* field = window->findChild<QLineEdit*>("unlockPathEdit");
    ASSERT_NE(field, nullptr);
    EXPECT_TRUE(field->text().isEmpty());

    settings.setValue("vault/lastPath", QString{});
    settings.sync();
    recreateWindow();
    EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPathEdit")->text().isEmpty());
    EXPECT_TRUE(settings.value("vault/lastPath").toString().isEmpty());
}

TEST_F(VaultPreferencesGuiTest, AvailableOrdinaryLastPathIsPrefilledWithoutVaultInspection)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("not-a-sqlite-vault"), 18);
    file.close();
    QSettings settings("PassWall", "PassWall");
    settings.setValue("vault/lastPath", path);
    settings.sync();

    recreateWindow();

    EXPECT_EQ(window->findChild<QLineEdit*>("unlockPathEdit")->text(), path);
}

TEST_F(VaultPreferencesGuiTest, UnavailableLastPathIsNotPrefilledOrDeleted)
{
    passwall::core::SecureBuffer key(0);
    std::string lifecycleError;
    const QString registered = directory.filePath("registered.db");
    ASSERT_TRUE(VaultLifecycleService::createVault(
        registered.toStdString(), "fictitious-registry-master", key, lifecycleError));
    key = passwall::core::SecureBuffer(0);
    VaultRegistration registration;
    QString registryError;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(
        registered, registration, registryError), VaultRecognition::Registered);
    QSettings settings("PassWall", "PassWall");
    const QByteArray registry = settings.value("vaultRegistry/data").toByteArray();
    const QString missing = directory.filePath("removed.db");
    settings.setValue("vault/lastPath", missing);
    settings.sync();

    recreateWindow();

    EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPathEdit")->text().isEmpty());
    settings.sync();
    EXPECT_EQ(settings.value("vault/lastPath").toString(), missing);
    EXPECT_EQ(settings.value("vaultRegistry/data").toByteArray(), registry);
    EXPECT_EQ(settings.value("unrelated/value").toString(), "keep");
}

TEST_F(VaultPreferencesGuiTest, UnreadableLastPathIsNotPrefilledOrDeleted)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("fictitious"), 10);
    file.close();
    ASSERT_TRUE(QFile::setPermissions(path, QFileDevice::WriteOwner));
    QSettings settings("PassWall", "PassWall");
    settings.setValue("vault/lastPath", path);
    settings.sync();

    recreateWindow();

    EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPathEdit")->text().isEmpty());
    settings.sync();
    EXPECT_EQ(settings.value("vault/lastPath").toString(), path);
    ASSERT_TRUE(QFile::setPermissions(path,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
}

#ifdef Q_OS_UNIX
TEST_F(VaultPreferencesGuiTest, SymlinkLastPathIsNotPrefilledOrDeleted)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    file.close();
    const QString alias = directory.filePath("ambiguous-link.db");
    ASSERT_TRUE(QFile::link(path, alias));
    QSettings settings("PassWall", "PassWall");
    settings.setValue("vault/lastPath", alias);
    settings.sync();

    recreateWindow();

    EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPathEdit")->text().isEmpty());
    settings.sync();
    EXPECT_EQ(settings.value("vault/lastPath").toString(), alias);
}
#endif

TEST_F(VaultPreferencesGuiTest, BrowserSelectionDoesNotPersistBeforeAuthentication)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    file.close();
    const QString previous = directory.filePath("temporarily-unavailable.db");
    QSettings settings("PassWall", "PassWall");
    settings.setValue("vault/lastPath", previous);
    settings.sync();
    recreateWindow();

    bool dialogFound = false;
    QTimer picker;
    picker.setInterval(1);
    QObject::connect(&picker, &QTimer::timeout, window.get(), [&] {
        auto* dialog = window->findChild<QFileDialog*>();
        if (!dialog)
            dialog = qobject_cast<QFileDialog*>(QApplication::activeModalWidget());
        if (!dialog)
            return;
        dialogFound = true;
        picker.stop();
        dialog->selectFile(path);
        static_cast<QDialog*>(dialog)->accept();
    });
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, window.get(), [&] {
        if (auto* dialog = qobject_cast<QFileDialog*>(QApplication::activeModalWidget()))
            dialog->reject();
    });
    picker.start();
    watchdog.start(1000);
    click("openPageButton");
    click("unlockBrowseButton");
    picker.stop();
    watchdog.stop();

    ASSERT_TRUE(dialogFound);
    EXPECT_EQ(window->findChild<QLineEdit*>("unlockPathEdit")->text(), path);
    settings.sync();
    EXPECT_EQ(settings.value("vault/lastPath").toString(), previous);
}

TEST_F(VaultPreferencesGuiTest, SuccessfulAuthenticationPublishesLastPath)
{
    passwall::core::SecureBuffer key(0);
    std::string error;
    ASSERT_TRUE(VaultLifecycleService::createVault(
        path.toStdString(), "fictitious-registry-master", key, error));
    key = passwall::core::SecureBuffer(0);
    const QString previous = directory.filePath("temporarily-unavailable.db");
    QSettings settings("PassWall", "PassWall");
    settings.setValue("vault/lastPath", previous);
    settings.sync();
    recreateWindow();

    click("openPageButton");
    field("unlockPathEdit", path);
    field("unlockPasswordEdit", "fictitious-registry-master");
    click("unlockVaultButton");

    EXPECT_TRUE(window->acquireLease().unlocked);
    settings.sync();
    EXPECT_EQ(settings.value("vault/lastPath").toString(), path);
    EXPECT_EQ(settings.value("unrelated/value").toString(), "keep");
}

TEST_F(VaultPreferencesGuiTest, CreationRegistersDefaultsAndPreservesUnrelatedSettings)
{
    create();
    EXPECT_TRUE(window->acquireLease().unlocked);
    QVector<VaultRegistration> records;
    QString error;
    ASSERT_TRUE(VaultPreferencesStore().list(records, error)) << error.toStdString();
    ASSERT_EQ(records.size(), 1);
    EXPECT_EQ(records[0].file.path, path);
    EXPECT_TRUE(records[0].backup == VaultBackupPreferences{});
    QSettings settings("PassWall", "PassWall");
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 5);
    EXPECT_EQ(settings.value("unrelated/value").toString(), "keep");
    EXPECT_EQ(settings.value("vault/lastPath").toString(), path);
}

TEST_F(VaultPreferencesGuiTest, SuccessfulOpenRecognizesOriginalAndRegistersIndependentCopy)
{
    create();
    VaultRegistration original;
    QString error;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(path, original, error), VaultRecognition::Recognized);
    const VaultBackupPreferences preferences{true, directory.filePath("backups"), 4};
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(original.localId, preferences, error));
    click("lockVaultButton");
    field("unlockPathEdit", path);
    field("unlockPasswordEdit", "fictitious-registry-master");
    click("unlockVaultButton");
    EXPECT_TRUE(window->acquireLease().unlocked);
    click("lockVaultButton");
    const auto copy = directory.filePath("copy.db");
    ASSERT_TRUE(QFile::copy(path, copy));
    field("unlockPathEdit", copy);
    field("unlockPasswordEdit", "fictitious-registry-master");
    click("unlockVaultButton");
    EXPECT_TRUE(window->acquireLease().unlocked);
    QVector<VaultRegistration> records;
    ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    ASSERT_EQ(records.size(), 2);
    EXPECT_TRUE(records[0].backup == preferences);
    EXPECT_TRUE(records[1].backup == VaultBackupPreferences{});
    EXPECT_NE(records[0].localId, records[1].localId);
}

TEST_F(VaultPreferencesGuiTest, OrdinaryReassociationIncidentPreservesSessionWithNonModalNotice)
{
    create();
    click("lockVaultButton");
    // Readable registry, no restoration fence: an ordinary association problem
    // remains a modeless warning, unlike an unknown/corrupt recovery registry.
    {
        QSettings settings("PassWall", "PassWall");
        auto root = QJsonDocument::fromJson(settings.value("vaultRegistry/data").toByteArray()).object();
        auto records = root["vaults"].toArray(); ASSERT_EQ(records.size(), 1);
        auto record = records[0].toObject(); auto file = record["file"].toObject();
        file["inode"] = "0"; record["file"] = file; records[0] = record; root["vaults"] = records;
        settings.setValue("vaultRegistry/data", QJsonDocument(root).toJson(QJsonDocument::Compact));
        settings.sync();
    }
    field("unlockPathEdit", path);
    field("unlockPasswordEdit", "fictitious-registry-master");
    click("unlockVaultButton");
    EXPECT_TRUE(QFile::exists(path));
    EXPECT_TRUE(window->acquireLease().unlocked);
    auto* warning = window->findChild<QMessageBox*>("vaultRegistrationWarning");
    ASSERT_NE(warning, nullptr);
    EXPECT_FALSE(warning->isModal());
    auto* timer = window->findChild<QTimer*>("vaultInactivityTimer");
    ASSERT_NE(timer, nullptr);
    EXPECT_TRUE(timer->isActive());
    EXPECT_TRUE(window->findChild<QLineEdit*>("createPasswordEdit")->text().isEmpty());
    passwall::core::SecureBuffer key(0);
    std::string error;
    EXPECT_TRUE(VaultLifecycleService::unlockVault(path.toStdString(), "fictitious-registry-master", key, error));
}

TEST_F(VaultPreferencesGuiTest, FailedAuthenticationDoesNotRegisterOrPublishSession)
{
    {
        passwall::core::SecureBuffer key(0);
        std::string error;
        ASSERT_TRUE(VaultLifecycleService::createVault(path.toStdString(), "fictitious-registry-master", key, error));
    }
    click("openPageButton");
    field("unlockPathEdit", path);
    field("unlockPasswordEdit", "fictitious-wrong-master");
    QTimer dismiss;
    QObject::connect(&dismiss, &QTimer::timeout, window.get(), [&] {
        for (auto* message : window->findChildren<QMessageBox*>()) message->accept();
    });
    dismiss.start(5);
    click("unlockVaultButton");
    EXPECT_FALSE(window->acquireLease().unlocked);
    QVector<VaultRegistration> records;
    QString error;
    ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    EXPECT_TRUE(records.isEmpty());
    QSettings settings("PassWall", "PassWall");
    EXPECT_FALSE(settings.contains("vault/lastPath"));
}

TEST_F(VaultPreferencesGuiTest, CorruptIniRefusesCreationWithoutPublishingOrRewriting)
{
    const QString settingsFile = QSettings("PassWall", "PassWall").fileName();
    const QByteArray invalid("[broken\nprivate-existing-setting=keep\n");
    {
        QFile file(settingsFile);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(file.write(invalid), invalid.size());
    }
    QTimer dismiss;
    QObject::connect(&dismiss, &QTimer::timeout, window.get(), [&] {
        for (auto* message : window->findChildren<QMessageBox*>()) message->accept();
    });
    dismiss.start(5);
    create();
    EXPECT_FALSE(QFile::exists(path));
    EXPECT_FALSE(window->acquireLease().unlocked);
    QFile file(settingsFile);
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    EXPECT_EQ(file.readAll(), invalid);
    EXPECT_TRUE(window->findChild<QLineEdit*>("createPasswordEdit")->text().isEmpty());
}
} // namespace
