#include "gui/main_window.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/vault_preferences_store.hpp"

#include <gtest/gtest.h>
#include <QApplication>
#include <QFile>
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
        window = std::make_unique<MainWindow>();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
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
