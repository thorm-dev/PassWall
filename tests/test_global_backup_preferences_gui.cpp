#include "gui/global_backup_preferences_controller.hpp"
#include "gui/global_backup_preferences_dialog.hpp"

#include <gtest/gtest.h>

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>

#include <functional>
#include <limits>
#include <memory>
#include <utility>

namespace {

using passwall::gui::GlobalBackupPreferencesController;
using passwall::gui::GlobalBackupPreferencesDialog;
using passwall::services::GlobalBackupPreferences;
using passwall::services::GlobalBackupPreferencesResult;
using passwall::services::GlobalBackupPreferencesStatus;
using passwall::services::GlobalBackupPreferencesStore;

bool waitFor(const std::function<bool()>& predicate, int timeoutMs = 2000)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (!predicate() && elapsed.elapsed() < timeoutMs)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    return predicate();
}

QByteArray bytes(const QString& path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray{};
}

class GlobalBackupPreferencesGuiTest : public ::testing::Test {
protected:
    QTemporaryDir temporary;
    QString settingsRoot;
    QString preferencesFile;
    QString backupRoot;
    std::unique_ptr<GlobalBackupPreferencesController> controller;
    QPointer<GlobalBackupPreferencesDialog> dialog;
    int reads = 0;
    int configurationReads = 0;
    int writes = 0;
    GlobalBackupPreferencesResult lastConfiguration;
    GlobalBackupPreferencesStatus readStatus = GlobalBackupPreferencesStatus::Absent;
    GlobalBackupPreferencesStatus writeStatus = GlobalBackupPreferencesStatus::Absent;

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
        createController(preferencesFile);
    }

    void TearDown() override
    {
        if (dialog) dialog->reject();
        controller.reset();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents();
    }

    void createController(const QString& file)
    {
        if (dialog) dialog->reject();
        controller.reset();
        dialog.clear();
        reads = 0;
        configurationReads = 0;
        writes = 0;
        lastConfiguration = {};
        controller = std::make_unique<GlobalBackupPreferencesController>(
            GlobalBackupPreferencesStore(file));
        QObject::connect(controller.get(),
            &GlobalBackupPreferencesController::configurationRead,
            controller.get(), [this](GlobalBackupPreferencesResult result) {
                ++configurationReads;
                lastConfiguration = std::move(result);
            });
        QObject::connect(controller.get(),
            &GlobalBackupPreferencesController::readSettled,
            controller.get(), [this](GlobalBackupPreferencesStatus status) {
                ++reads;
                readStatus = status;
            });
        QObject::connect(controller.get(),
            &GlobalBackupPreferencesController::writeSettled,
            controller.get(), [this](GlobalBackupPreferencesStatus status) {
                ++writes;
                writeStatus = status;
            });
    }

    void open()
    {
        controller->open();
        ASSERT_TRUE(waitFor([&] {
            for (auto* widget : QApplication::topLevelWidgets()) {
                if (widget->objectName()
                    == QStringLiteral("globalBackupPreferencesDialog")) {
                    dialog = qobject_cast<GlobalBackupPreferencesDialog*>(widget);
                    break;
                }
            }
            return dialog && reads == 1;
        }));
    }

    template<class T>
    T* widget(const char* name) const
    {
        return dialog->findChild<T*>(QString::fromLatin1(name));
    }

    QString status() const
    {
        return widget<QLabel>("globalBackupStatusLabel")->text();
    }

    QString feedback() const
    {
        return widget<QLabel>("globalBackupFeedbackLabel")->text();
    }

    void draft(const QString& root, const QString& retained)
    {
        widget<QLineEdit>("globalBackupRootEdit")->setText(root);
        widget<QLineEdit>("globalBackupRetentionEdit")->setText(retained);
    }

    void save()
    {
        const int prior = writes;
        widget<QPushButton>("globalBackupSaveButton")->click();
        ASSERT_TRUE(waitFor([&] { return writes > prior; }));
    }

    void reload()
    {
        const int prior = reads;
        widget<QPushButton>("globalBackupReloadButton")->click();
        ASSERT_TRUE(waitFor([&] { return reads > prior; }));
    }
};

TEST_F(GlobalBackupPreferencesGuiTest,
    AbsentConfigurationShowsSevenWithoutCreatingAFile)
{
    open();
    EXPECT_EQ(readStatus, GlobalBackupPreferencesStatus::Absent);
    EXPECT_EQ(configurationReads, 1);
    EXPECT_EQ(lastConfiguration.status,
        GlobalBackupPreferencesStatus::Absent);
    EXPECT_EQ(lastConfiguration.sourceFile, preferencesFile);
    EXPECT_TRUE(status().contains(QStringLiteral("Aucune configuration")));
    EXPECT_TRUE(widget<QLineEdit>("globalBackupRootEdit")->text().isEmpty());
    EXPECT_EQ(widget<QLineEdit>("globalBackupRetentionEdit")->text(),
        QStringLiteral("7"));
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    InitialOfferStaysHiddenForAnAlreadyValidConfiguration)
{
    ASSERT_EQ(GlobalBackupPreferencesStore(preferencesFile).save(
        {backupRoot, 9}).status, GlobalBackupPreferencesStatus::Valid);
    controller->offerInitialConfiguration();
    ASSERT_TRUE(waitFor([&] { return reads == 1; }));
    EXPECT_EQ(readStatus, GlobalBackupPreferencesStatus::Valid);
    EXPECT_EQ(configurationReads, 1);
    EXPECT_EQ(lastConfiguration.status,
        GlobalBackupPreferencesStatus::Valid);
    EXPECT_EQ(lastConfiguration.preferences,
        (GlobalBackupPreferences{backupRoot, 9}));
    EXPECT_EQ(lastConfiguration.sourceFile, preferencesFile);
    EXPECT_TRUE(dialog.isNull());
    EXPECT_EQ(controller->findChild<GlobalBackupPreferencesDialog*>(), nullptr);
}

TEST_F(GlobalBackupPreferencesGuiTest,
    InitialOfferIsNonModalAndOccursOnlyOncePerControllerSession)
{
    controller->offerInitialConfiguration();
    ASSERT_TRUE(waitFor([&] {
        for (auto* widget : QApplication::topLevelWidgets()) {
            if (widget->objectName()
                == QStringLiteral("globalBackupPreferencesDialog")) {
                dialog = qobject_cast<GlobalBackupPreferencesDialog*>(widget);
                break;
            }
        }
        return reads == 1 && dialog;
    }));
    EXPECT_FALSE(dialog->isModal());
    dialog->reject();
    ASSERT_TRUE(waitFor([&] { return dialog.isNull(); }));

    controller->offerInitialConfiguration();
    QCoreApplication::processEvents();
    EXPECT_EQ(reads, 1);
    EXPECT_TRUE(dialog.isNull());
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    ReopeningVisiblePreferencesKeepsOneDialogAndDoesNotWrite)
{
    open();
    ASSERT_TRUE(dialog);
    const auto originalDialog = dialog;
    draft(backupRoot, QStringLiteral("13"));
    controller->open();
    QCoreApplication::processEvents();

    int matchingDialogs = 0;
    for (auto* candidate : QApplication::topLevelWidgets()) {
        if (candidate->objectName()
            == QStringLiteral("globalBackupPreferencesDialog")) {
            ++matchingDialogs;
            EXPECT_EQ(candidate, originalDialog.data());
        }
    }
    EXPECT_EQ(matchingDialogs, 1);
    EXPECT_EQ(widget<QLineEdit>("globalBackupRetentionEdit")->text(),
        QStringLiteral("13"));
    EXPECT_FALSE(dialog->isModal());
    EXPECT_FALSE(dialog->testAttribute(Qt::WA_QuitOnClose));
    EXPECT_EQ(reads, 1);
    EXPECT_EQ(writes, 0);
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));

    dialog->reject();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    ASSERT_TRUE(originalDialog.isNull());
    EXPECT_EQ(writes, 0);
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    ValidPreferencesDisplayTheCompleteUnsignedRetentionDomain)
{
    const quint64 retained = std::numeric_limits<quint64>::max();
    ASSERT_EQ(GlobalBackupPreferencesStore(preferencesFile).save(
        {backupRoot, retained}).status, GlobalBackupPreferencesStatus::Valid);
    open();
    EXPECT_EQ(readStatus, GlobalBackupPreferencesStatus::Valid);
    EXPECT_EQ(widget<QLineEdit>("globalBackupRootEdit")->text(), backupRoot);
    EXPECT_EQ(widget<QLineEdit>("globalBackupRetentionEdit")->text(),
        QString::number(retained));
    EXPECT_TRUE(status().contains(QStringLiteral("encore contrôlée")));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    RetentionBelowSevenIsRejectedBeforePersistence)
{
    open();
    draft(backupRoot, QStringLiteral("6"));
    save();
    EXPECT_EQ(writeStatus, GlobalBackupPreferencesStatus::Invalid);
    EXPECT_TRUE(feedback().contains(QStringLiteral("au moins égal à sept")));
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    InvalidPathsAreExplainedAndNeverPersisted)
{
    open();
    const auto reject = [&](const QString& path, const QString& fragment) {
        draft(path, QStringLiteral("7"));
        save();
        EXPECT_EQ(writeStatus, GlobalBackupPreferencesStatus::Invalid);
        EXPECT_TRUE(feedback().contains(fragment)) << feedback().toStdString();
        EXPECT_FALSE(QFileInfo::exists(preferencesFile));
    };
    reject(QStringLiteral("relative/backups"), QStringLiteral("absolu"));
    reject(QStringLiteral("/"), QStringLiteral("racine du système"));
    reject(backupRoot + QStringLiteral("/../backups"),
        QStringLiteral("normalisé"));

    const QString file = temporary.filePath(QStringLiteral("not-a-directory"));
    QFile ordinary(file);
    ASSERT_TRUE(ordinary.open(QIODevice::WriteOnly));
    ordinary.close();
    reject(file, QStringLiteral("ne désigne pas un dossier"));

    const QString alias = temporary.filePath(QStringLiteral("backup-link"));
    ASSERT_TRUE(QFile::link(backupRoot, alias));
    reject(alias, QStringLiteral("lien symbolique"));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    ClosingADraftPerformsNoWrite)
{
    open();
    draft(backupRoot, QStringLiteral("11"));
    widget<QPushButton>("globalBackupCloseButton")->click();
    ASSERT_TRUE(waitFor([&] { return dialog.isNull(); }));
    EXPECT_EQ(writes, 0);
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    ConfirmedSaveCanBeReloadedWithoutClaimingOperationalAccess)
{
    open();
    const QString futureRoot = temporary.filePath(QStringLiteral("future-backups"));
    ASSERT_FALSE(QFileInfo::exists(futureRoot));
    draft(futureRoot, QStringLiteral("11"));
    save();
    ASSERT_EQ(writeStatus, GlobalBackupPreferencesStatus::Valid)
        << feedback().toStdString();
    EXPECT_TRUE(feedback().contains(QStringLiteral("n'est pas déclarée opérationnelle")));
    const auto loaded = GlobalBackupPreferencesStore(preferencesFile).load();
    ASSERT_EQ(loaded.status, GlobalBackupPreferencesStatus::Valid);
    EXPECT_EQ(loaded.preferences, GlobalBackupPreferences({futureRoot, 11}));
    EXPECT_FALSE(QFileInfo::exists(futureRoot));

    draft(temporary.filePath(QStringLiteral("unsaved")), QStringLiteral("25"));
    reload();
    EXPECT_EQ(widget<QLineEdit>("globalBackupRootEdit")->text(), futureRoot);
    EXPECT_EQ(widget<QLineEdit>("globalBackupRetentionEdit")->text(),
        QStringLiteral("11"));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    PersistenceFailureNeverProducesSuccessFeedback)
{
    const QString blocked = temporary.filePath(QStringLiteral("blocked"));
    QFile obstruction(blocked);
    ASSERT_TRUE(obstruction.open(QIODevice::WriteOnly));
    obstruction.close();
    createController(blocked + QStringLiteral("/BackupPreferences.ini"));
    open();
    draft(backupRoot, QStringLiteral("9"));
    save();
    EXPECT_EQ(writeStatus, GlobalBackupPreferencesStatus::WriteError);
    EXPECT_TRUE(status().contains(QStringLiteral("n'est pas confirmée")));
    EXPECT_TRUE(feedback().contains(QStringLiteral("Aucune réussite")));
    EXPECT_FALSE(feedback().contains(QStringLiteral("enregistrées durablement")));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    InvalidAndUnreadableFilesRemainDistinctFromAbsence)
{
    ASSERT_TRUE(QDir().mkpath(QFileInfo(preferencesFile).absolutePath()));
    QFile invalid(preferencesFile);
    ASSERT_TRUE(invalid.open(QIODevice::WriteOnly));
    const QByteArray malformed("[broken\nvalue=six\n");
    ASSERT_EQ(invalid.write(malformed), malformed.size());
    invalid.close();
    ASSERT_TRUE(QFile::setPermissions(preferencesFile,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    const QByteArray invalidContents = bytes(preferencesFile);
    open();
    EXPECT_EQ(readStatus, GlobalBackupPreferencesStatus::Invalid);
    EXPECT_EQ(configurationReads, 1);
    EXPECT_EQ(lastConfiguration.status,
        GlobalBackupPreferencesStatus::Invalid);
    EXPECT_EQ(lastConfiguration.sourceFile, preferencesFile);
    EXPECT_TRUE(status().contains(QStringLiteral("invalide")));
    EXPECT_EQ(bytes(preferencesFile), invalidContents);

    dialog->reject();
    controller.reset();
    ASSERT_TRUE(QFile::remove(preferencesFile));
    ASSERT_TRUE(QDir().mkpath(preferencesFile));
    createController(preferencesFile);
    open();
    EXPECT_EQ(readStatus, GlobalBackupPreferencesStatus::ReadError);
    EXPECT_EQ(configurationReads, 1);
    EXPECT_EQ(lastConfiguration.status,
        GlobalBackupPreferencesStatus::ReadError);
    EXPECT_EQ(lastConfiguration.sourceFile, preferencesFile);
    EXPECT_TRUE(status().contains(QStringLiteral("lues en sécurité")));
}

TEST_F(GlobalBackupPreferencesGuiTest,
    GlobalSaveLeavesHistoricalPassWallPreferencesByteIdentical)
{
    QSettings historical(QStringLiteral("PassWall"), QStringLiteral("PassWall"));
    historical.setFallbacksEnabled(false);
    historical.setValue(QStringLiteral("vaultRegistry/data"),
        QByteArrayLiteral("fictitious-historical-registry"));
    historical.setValue(QStringLiteral("backup/historicalFixture"),
        QStringLiteral("unchanged"));
    historical.sync();
    ASSERT_EQ(historical.status(), QSettings::NoError);
    const QString historicalFile = historical.fileName();
    const QByteArray before = bytes(historicalFile);

    open();
    draft(backupRoot, QStringLiteral("12"));
    save();
    ASSERT_EQ(writeStatus, GlobalBackupPreferencesStatus::Valid);
    EXPECT_NE(QFileInfo(preferencesFile).absoluteFilePath(),
        QFileInfo(historicalFile).absoluteFilePath());
    EXPECT_EQ(bytes(historicalFile), before);
    EXPECT_EQ(historical.value(QStringLiteral("vaultRegistry/data")).toByteArray(),
        QByteArrayLiteral("fictitious-historical-registry"));
    EXPECT_EQ(historical.value(QStringLiteral("backup/historicalFixture")).toString(),
        QStringLiteral("unchanged"));
    EXPECT_EQ(dialog->findChild<QWidget*>(QStringLiteral("backupAutomaticCheck")),
        nullptr);
}

} // namespace

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
