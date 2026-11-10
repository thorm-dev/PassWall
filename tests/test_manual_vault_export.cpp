#include "gui/main_window.hpp"
#include "gui/credential_editor_context.hpp"
#include "services/backup_job.hpp"
#include "services/automatic_backup_coordinator.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/credential_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <gtest/gtest.h>
#include <sodium.h>
#include <QApplication>
#include <QDialogButtonBox>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QProgressBar>
#include <QProcess>
#include <QPushButton>
#include <QScopeGuard>
#include <QSettings>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTemporaryDir>
#include <QTextEdit>
#include <QThread>
#include <QTimer>
#include <functional>
#include <memory>

namespace {
using passwall::gui::MainWindow;
using passwall::services::BackupJob;
struct LaunchProbe {
    QString executable, fakeMode, source, destination;
    int starts = 0;
    std::function<void()> beforeStart;
};
thread_local LaunchProbe* activeExportProbe = nullptr;
thread_local bool suppressExportStops = false;
thread_local QPointer<QProcess> suppressedExportProcess;
bool until(const std::function<bool()>& predicate, int limit = 7000)
{
    QElapsedTimer timer; timer.start();
    while (!predicate() && timer.elapsed() < limit) {
        QApplication::processEvents(QEventLoop::AllEvents, 5);
        QThread::msleep(1);
    }
    return predicate();
}
} // namespace

extern "C" void realExportKill(QProcess*) asm("__real__ZN8QProcess4killEv");
extern "C" void wrappedExportKill(QProcess*) asm("__wrap__ZN8QProcess4killEv");
extern "C" void wrappedExportKill(QProcess* process)
{
    if (suppressExportStops) suppressedExportProcess = process;
    else realExportKill(process);
}
extern "C" void realExportTerminate(QProcess*) asm("__real__ZN8QProcess9terminateEv");
extern "C" void wrappedExportTerminate(QProcess*) asm("__wrap__ZN8QProcess9terminateEv");
extern "C" void wrappedExportTerminate(QProcess* process)
{
    if (suppressExportStops) suppressedExportProcess = process;
    else realExportTerminate(process);
}

// Reuse the same isolated Qt stop wrappers for the restore supervisor tests.
// This models an unconfirmed stop, not an actual unkillable kernel process.
namespace passwall::tests {
void suppressGuiStopsForRestore(bool value) { suppressExportStops = value; }
bool guiRestoreStopWasRequested() { return !suppressedExportProcess.isNull(); }
void releaseGuiRestoreStop() {
    suppressExportStops = false;
    if (suppressedExportProcess) realExportKill(suppressedExportProcess);
    suppressedExportProcess.clear();
}
}

// Test-only linker instrumentation. No factory, executable override or fake
// locking implementation is exposed in the production MainWindow API.
extern "C" QString realWorkerPath() asm("__real__ZN8passwall8services9BackupJob17siblingWorkerPathEv");
extern "C" QString wrappedWorkerPath() asm("__wrap__ZN8passwall8services9BackupJob17siblingWorkerPathEv");
extern "C" QString wrappedWorkerPath()
{
    return activeExportProbe && !activeExportProbe->executable.isEmpty()
        ? activeExportProbe->executable : realWorkerPath();
}
extern "C" bool realBackupStart(BackupJob*, const QString&, const QString&)
    asm("__real__ZN8passwall8services9BackupJob5startERK7QStringS4_");
extern "C" bool wrappedBackupStart(BackupJob*, const QString&, const QString&)
    asm("__wrap__ZN8passwall8services9BackupJob5startERK7QStringS4_");
extern "C" bool wrappedBackupStart(BackupJob* job, const QString& source, const QString& destination)
{
    if (activeExportProbe) {
        auto& probe = *activeExportProbe;
        ++probe.starts; probe.source = source; probe.destination = destination;
        if (probe.beforeStart) probe.beforeStart();
        if (!probe.fakeMode.isEmpty()) {
            // Keep the REAL reserved source; only the fake peer's behavior is
            // selected through a sidecar in this isolated test directory.
            QFile mode(source + ".fake-mode");
            if (!mode.open(QIODevice::WriteOnly) || mode.write(probe.fakeMode.toUtf8()) < 0)
                return false;
        }
    }
    return realBackupStart(job, source, destination);
}

namespace {
class ManualVaultExportTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suite;
    static inline passwall::models::EntryId entryId{};
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-manual-export-case-XXXXXX")};
    std::unique_ptr<MainWindow> window;
    QString source, destination;
    LaunchProbe probe;

    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        suite = std::make_unique<QTemporaryDir>(QStringLiteral("/tmp/passwall-manual-export-suite-XXXXXX"));
        ASSERT_TRUE(suite->isValid());
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, suite->path());
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, suite->path());
        QApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
        passwall::core::SecureBuffer key(0);
        std::string error;
        const auto path = suite->filePath("template.pwdb").toStdString();
        ASSERT_TRUE(passwall::services::VaultLifecycleService::createVault(
            path, "fictitious-export-master", key, error));
        passwall::models::Credential credential;
        const auto wipe = qScopeGuard([&] { passwall::gui::detail::wipeCredential(credential); });
        credential.title = "Fictitious export entry";
        credential.username = "fictitious-user";
        credential.password = "fictitious-export-password";
        credential.notes = "Fictitious notes";
        ASSERT_TRUE(passwall::services::CredentialService::add(path, key, credential, error));
        entryId = credential.id;
    }
    static void TearDownTestSuite() { suite.reset(); }
    void SetUp() override
    {
        ASSERT_TRUE(directory.isValid());
        source = directory.filePath("source.pwdb");
        destination = directory.filePath("backup.pwdb");
        ASSERT_TRUE(QFile::copy(suite->filePath("template.pwdb"), source));
        QSettings settings("PassWall", "PassWall");
        settings.clear(); settings.setValue("security/autoLockMinutes", 1);
        window = std::make_unique<MainWindow>();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        activeExportProbe = &probe;
        bounded([&] { unlock(source); });
        ASSERT_TRUE(window->acquireLease().unlocked);
        ASSERT_TRUE(button("exportVaultButton")->isEnabled());
    }
    void TearDown() override
    {
        probe.beforeStart = {};
        window.reset();
        activeExportProbe = nullptr;
        QApplication::processEvents();
        QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
    QPushButton* button(const char* name) const
    {
        return window->findChild<QPushButton*>(QString::fromLatin1(name));
    }
    QTimer* inactivity() const { return window->findChild<QTimer*>("vaultInactivityTimer"); }
    void unlock(const QString& path)
    {
        button("openPageButton")->click();
        window->findChild<QLineEdit*>("unlockPathEdit")->setText(path);
        window->findChild<QLineEdit*>("unlockPasswordEdit")->setText("fictitious-export-master");
        button("unlockVaultButton")->click();
    }
    passwall::services::AutomaticBackupCoordinator* prepareAutomatic()
    {
        auto* automatic = window->findChild<passwall::services::AutomaticBackupCoordinator*>();
        EXPECT_NE(automatic, nullptr);
        if (!automatic) return nullptr;
        automatic->setPaused(true);
        const auto folder = directory.filePath("automatic");
        EXPECT_TRUE(QDir().mkpath(folder));
        EXPECT_TRUE(QFile::setPermissions(folder, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
        QVector<passwall::services::VaultRegistration> records; QString error;
        EXPECT_TRUE(passwall::services::VaultPreferencesStore().list(records, error));
        for (const auto& record : records) if (record.file.path == source) {
            EXPECT_TRUE(passwall::services::VaultPreferencesStore().updatePreferences(record.localId,
                {true, folder, 7}, error));
        }
        QApplication::processEvents(); // Deliver activation, while deliberately paused.
        EXPECT_FALSE(automatic->isActive());
        return automatic;
    }
    void bounded(const std::function<void()>& action)
    {
        QTimer deadline;
        deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &deadline, [] {
            ADD_FAILURE() << "Unexpected modal interaction in manual export test.";
            for (auto* widget : QApplication::topLevelWidgets())
                if (auto* dialog = qobject_cast<QDialog*>(widget)) dialog->reject();
        });
        deadline.start(5000); action();
    }
    // Exercise the real button/slot, real Qt dialogs and real cleanup barrier.
    void exportThroughDialogs(bool confirm = true,
        std::function<void(QFileDialog&)> selectionAction = {},
        std::function<void(QMessageBox&)> confirmationAction = {})
    {
        bool selected = false, confirmed = false;
        QTimer inspector;
        QObject::connect(&inspector, &QTimer::timeout, &inspector, [&] {
            if (auto* selection = window->findChild<QFileDialog*>("vaultExportDestinationDialog");
                selection && selection->isVisible() && !selected) {
                selected = true;
                EXPECT_EQ(inactivity()->isActive(), QSettings("PassWall", "PassWall")
                    .value("security/autoLockMinutes", 5).toInt() > 0);
                EXPECT_FALSE(QFile::exists(destination));
                if (selectionAction) selectionAction(*selection);
                else {
                    selection->selectFile(destination);
                    static_cast<QDialog*>(selection)->accept();
                }
            }
            if (auto* confirmation = window->findChild<QMessageBox*>("vaultExportConfirmationDialog");
                confirmation && confirmation->isVisible() && !confirmed) {
                confirmed = true;
                if (confirmationAction) confirmationAction(*confirmation);
                else if (confirm) confirmation->findChild<QPushButton*>("vaultExportConfirmButton")->click();
                else confirmation->reject();
            }
        });
        inspector.start(1);
        bounded([&] { button("exportVaultButton")->click(); });
    }
    QDialog* progress() const
    {
        for (auto* widget : QApplication::topLevelWidgets())
            if (widget->objectName() == "vaultExportProgressDialog") return qobject_cast<QDialog*>(widget);
        return nullptr;
    }
    QString status() const
    {
        return progress() ? progress()->findChild<QLabel*>("vaultExportStatusLabel")->text() : QString();
    }
    void waitForResult()
    {
        ASSERT_TRUE(until([&] {
            return progress() && progress()->findChild<QProgressBar*>("vaultExportActivity")->isHidden();
        }));
    }
    void fake(const char* mode)
    {
        probe.executable = QString::fromLatin1(EXPORT_FAKE_WORKER);
        probe.fakeMode = QString::fromLatin1(mode);
    }
    void waitForFake()
    {
        ASSERT_TRUE(until([&] { return QFile::exists(destination + ".ready"); }));
        ASSERT_NE(progress(), nullptr);
    }
    void expectNoLaunch()
    {
        QApplication::processEvents();
        EXPECT_EQ(probe.starts, 0);
        EXPECT_FALSE(QFile::exists(destination));
        EXPECT_EQ(progress(), nullptr);
    }
};

TEST_F(ManualVaultExportTest, LockedVaultCannotExportEvenWithAProgrammaticSignal)
{
    button("lockVaultButton")->click();
    EXPECT_FALSE(button("exportVaultButton")->isEnabled());
    QMetaObject::invokeMethod(button("exportVaultButton"), "clicked", Qt::DirectConnection);
    expectNoLaunch();
}
TEST_F(ManualVaultExportTest, DestinationCancellationLeavesOriginalSessionAndTimerActive)
{
    const auto lease = window->acquireLease();
    exportThroughDialogs(true, [](QFileDialog& dialog) { dialog.reject(); });
    expectNoLaunch(); EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_TRUE(inactivity()->isActive());
}
TEST_F(ManualVaultExportTest, InactivityDuringDestinationSelectionInvalidatesAuthorization)
{
    exportThroughDialogs(true, [&](QFileDialog&) {
        QMetaObject::invokeMethod(inactivity(), "timeout", Qt::DirectConnection);
    });
    expectNoLaunch(); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(ManualVaultExportTest, NewVaultDuringSelectionCannotReuseTheOldAuthorization)
{
    const auto other = directory.filePath("other.pwdb");
    ASSERT_TRUE(QFile::copy(source, other));
    exportThroughDialogs(true, [&](QFileDialog& dialog) {
        button("lockVaultButton")->click(); unlock(other);
        dialog.selectFile(destination); static_cast<QDialog*>(&dialog)->accept();
    });
    expectNoLaunch(); EXPECT_TRUE(window->acquireLease().unlocked);
}
TEST_F(ManualVaultExportTest, ConfirmationRefusalDoesNotLockOrLaunch)
{
    const auto lease = window->acquireLease();
    exportThroughDialogs(false); expectNoLaunch(); EXPECT_TRUE(window->isLeaseCurrent(lease));
}
TEST_F(ManualVaultExportTest, InactivityDuringConfirmationNeverStartsTheWorker)
{
    exportThroughDialogs(true, {}, [&](QMessageBox&) {
        QMetaObject::invokeMethod(inactivity(), "timeout", Qt::DirectConnection);
    });
    expectNoLaunch(); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(ManualVaultExportTest, ReauthenticationOfSameVaultDuringConfirmationIsNotAuthorization)
{
    exportThroughDialogs(true, {}, [&](QMessageBox& confirmation) {
        button("lockVaultButton")->click(); unlock(source);
        confirmation.findChild<QPushButton*>("vaultExportConfirmButton")->click();
    });
    expectNoLaunch(); EXPECT_TRUE(window->acquireLease().unlocked);
}
TEST_F(ManualVaultExportTest, RealCleanupPrecedesLaunchAndSnapshotReopensWithOriginalPassword)
{
    const auto oldLease = window->acquireLease();
    bool invalidated = false, verified = false;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, window.get(), [&] { invalidated = true; });
    probe.beforeStart = [&] {
        verified = true;
        EXPECT_TRUE(invalidated);
        EXPECT_FALSE(window->isLeaseCurrent(oldLease));
        EXPECT_FALSE(window->acquireLease().unlocked);
        EXPECT_FALSE(inactivity()->isActive());
        EXPECT_EQ(window->findChild<QListWidget*>("credentialsList")->count(), 0);
        EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPasswordEdit")->text().isEmpty());
        EXPECT_FALSE(QFile::exists(destination));
    };
    exportThroughDialogs(); waitForResult();
    EXPECT_TRUE(verified); EXPECT_EQ(probe.starts, 1);
    EXPECT_EQ(probe.source, source); EXPECT_EQ(probe.destination, destination);
    EXPECT_TRUE(status().contains("réussie"));
    EXPECT_FALSE(window->acquireLease().unlocked);
    passwall::core::SecureBuffer key(0);
    std::string error;
    ASSERT_TRUE(passwall::services::VaultLifecycleService::unlockVault(
        destination.toStdString(), "fictitious-export-master", key, error));
    passwall::models::Credential credential;
    const auto wipe = qScopeGuard([&] { passwall::gui::detail::wipeCredential(credential); });
    ASSERT_TRUE(passwall::services::CredentialService::get(destination.toStdString(), key, entryId, credential, error));
    EXPECT_TRUE(credential.password == "fictitious-export-password");
    EXPECT_TRUE(credential.notes == "Fictitious notes");
}
TEST_F(ManualVaultExportTest, InconsistentCleanupCannotLaunchAnExport)
{
    auto* pages = window->findChild<QStackedWidget*>("stackedWidget");
    bool injected = false;
    QObject::connect(pages, &QStackedWidget::currentChanged, window.get(), [&](int) {
        if (!injected && pages->currentWidget()->objectName() == "pageWelcome") {
            injected = true;
            window->findChild<QLineEdit*>("credentialSearchEdit")->setText("fictitious-incomplete-cleanup");
        }
    });
    exportThroughDialogs();
    ASSERT_TRUE(until([&] { return window->statusBar()->currentMessage().contains("non confirmé"); }));
    EXPECT_TRUE(injected); expectNoLaunch();
}
TEST_F(ManualVaultExportTest, UnsavedEditorIsNeitherDiscardedNorExported)
{
    const auto lease = window->acquireLease();
    auto* list = window->findChild<QListWidget*>("credentialsList"); list->setCurrentRow(0);
    bool checked = false;
    QTimer::singleShot(0, window.get(), [&] {
        auto* editor = window->findChild<QDialog*>("credentialEditorDialog");
        ASSERT_NE(editor, nullptr);
        auto* notes = editor->findChild<QTextEdit*>("credentialNotesEdit");
        notes->setPlainText("Fictitious unsaved changes");
        QMetaObject::invokeMethod(button("exportVaultButton"), "clicked", Qt::DirectConnection);
        checked = true;
        EXPECT_TRUE(editor->isVisible()); EXPECT_TRUE(window->isLeaseCurrent(lease));
        EXPECT_TRUE(notes->toPlainText() == "Fictitious unsaved changes");
        EXPECT_EQ(window->findChild<QFileDialog*>("vaultExportDestinationDialog"), nullptr);
        editor->reject();
    });
    bounded([&] { button("editCredentialButton")->click(); });
    EXPECT_TRUE(checked); expectNoLaunch();
}
TEST_F(ManualVaultExportTest, OpenEditorRefusesBusinessReservationWithoutDiscardingFields)
{
    auto* list = window->findChild<QListWidget*>("credentialsList"); list->setCurrentRow(0);
    bool checked = false;
    QTimer::singleShot(0, window.get(), [&] {
        auto* editor = window->findChild<QDialog*>("credentialEditorDialog");
        ASSERT_NE(editor, nullptr);
        auto* notes = editor->findChild<QTextEdit*>("credentialNotesEdit");
        notes->setPlainText("Fictitious unsaved editing");
        passwall::storage::VaultOperationGuard reservation;
        std::string error;
        EXPECT_FALSE(reservation.tryReserve(source.toStdString(), error));
        EXPECT_TRUE(notes->toPlainText() == "Fictitious unsaved editing");
        checked = true;
        editor->reject();
    });
    bounded([&] { button("editCredentialButton")->click(); });
    EXPECT_TRUE(checked);
    passwall::storage::VaultOperationGuard reservation;
    std::string error;
    EXPECT_TRUE(reservation.tryReserve(source.toStdString(), error));
}

TEST_F(ManualVaultExportTest, DifferentVaultCanOpenWhileSourceRemainsReserved)
{
    const auto other = directory.filePath("other.pwdb");
    ASSERT_TRUE(QFile::copy(source, other));
    fake("cancel"); exportThroughDialogs(); waitForFake();
    bounded([&] { unlock(other); });
    EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_TRUE(progress()->isVisible());
    progress()->reject(); waitForResult();
    EXPECT_TRUE(status().contains("annulée"));
    EXPECT_TRUE(window->acquireLease().unlocked);
}

TEST_F(ManualVaultExportTest, ExistingDestinationIsPreservedAndClearlyRefused)
{
    QFile file(destination); ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    const QByteArray marker("preexisting-fictitious-backup");
    ASSERT_EQ(file.write(marker), marker.size()); file.close();
    // The selector's no-premature-file assertion is deliberately overridden here.
    QString selected = destination; destination = directory.filePath("unused.pwdb");
    exportThroughDialogs(true, [&](QFileDialog& dialog) {
        dialog.selectFile(selected); static_cast<QDialog*>(&dialog)->accept();
    });
    waitForResult(); EXPECT_TRUE(status().contains("échouée")); EXPECT_TRUE(status().contains("existe déjà"));
    ASSERT_TRUE(file.open(QIODevice::ReadOnly)); EXPECT_EQ(file.readAll(), "preexisting-fictitious-backup");
}
TEST_F(ManualVaultExportTest, SymlinkDestinationNeverOverwritesItsTargetOrFallsBack)
{
    const auto link = directory.filePath("link.pwdb");
    ASSERT_TRUE(QFile::link(source, link));
    exportThroughDialogs(true, [&](QFileDialog& dialog) {
        dialog.selectFile(link); static_cast<QDialog*>(&dialog)->accept();
    });
    waitForResult(); EXPECT_TRUE(status().contains("échouée"));
    EXPECT_FALSE(QFile::exists(destination));
    EXPECT_TRUE(QFileInfo(link).isSymLink()); EXPECT_TRUE(QFile::exists(source));
}
TEST_F(ManualVaultExportTest, MissingWorkerIsAnExplicitFailureWithoutReopeningTheVault)
{
    probe.executable = directory.filePath("missing-worker");
    exportThroughDialogs(); waitForResult();
    EXPECT_TRUE(status().contains("échouée")); EXPECT_TRUE(status().contains("démarrer"));
    EXPECT_FALSE(window->acquireLease().unlocked); EXPECT_FALSE(QFile::exists(destination));
}
TEST_F(ManualVaultExportTest, NormalWorkerFailureIsNotReportedAsSuccess)
{
    fake("failed"); exportThroughDialogs(); waitForResult();
    EXPECT_TRUE(status().contains("échouée")); EXPECT_FALSE(status().contains("réussie"));
}
TEST_F(ManualVaultExportTest, CooperativeCancellationIsRequestedBeforeItIsConfirmed)
{
    fake("cancel"); exportThroughDialogs(); waitForFake();
    auto* cancel = progress()->findChild<QPushButton*>("vaultExportCancelButton"); cancel->click();
    EXPECT_TRUE(status().contains("Annulation demandée")); EXPECT_FALSE(cancel->isEnabled());
    waitForResult(); EXPECT_TRUE(status().contains("annulée avant publication"));
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(ManualVaultExportTest, CrashIsUnknownNotSuccessOrConfirmedCancellation)
{
    fake("crash"); exportThroughDialogs(); waitForResult();
    EXPECT_TRUE(status().contains("Résultat incertain")); EXPECT_TRUE(status().contains("peut avoir été créé"));
    EXPECT_FALSE(status().contains("réussie")); EXPECT_FALSE(status().contains("annulée avant publication"));
}
TEST_F(ManualVaultExportTest, UnconfirmedDurabilityIsDistinctFromSuccess)
{
    fake("durability"); exportThroughDialogs(); waitForResult();
    EXPECT_TRUE(status().contains("fichier a été publié")); EXPECT_TRUE(status().contains("durabilité n'est pas confirmée"));
    EXPECT_FALSE(status().contains("réussie"));
}
TEST_F(ManualVaultExportTest, ProgressIsModelessResponsiveAndUnaffectedByAnotherVaultLock)
{
    fake("cancel"); exportThroughDialogs(); waitForFake();
    ASSERT_FALSE(progress()->isModal());
    auto* activity = progress()->findChild<QProgressBar*>("vaultExportActivity");
    EXPECT_EQ(activity->minimum(), 0); EXPECT_EQ(activity->maximum(), 0);
    int beats = 0; QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, &heartbeat, [&] { ++beats; }); heartbeat.start(5);
    ASSERT_TRUE(until([&] { return beats >= 5; }));
    button("lockVaultButton")->click();
    EXPECT_TRUE(progress()->isVisible()); EXPECT_FALSE(activity->isHidden());
    EXPECT_TRUE(progress()->findChild<QPushButton*>("vaultExportCancelButton")->isEnabled());
    progress()->close(); // Window-manager close means cancellation, not disappearance.
    waitForResult(); EXPECT_TRUE(status().contains("annulée"));
}
TEST_F(ManualVaultExportTest, RepeatedInvocationCannotCreateConcurrentExports)
{
    fake("cancel");
    exportThroughDialogs(true, [&](QFileDialog& dialog) {
        QMetaObject::invokeMethod(button("exportVaultButton"), "clicked", Qt::DirectConnection);
        EXPECT_EQ(window->findChildren<QFileDialog*>("vaultExportDestinationDialog").size(), 1);
        dialog.selectFile(destination); static_cast<QDialog*>(&dialog)->accept();
    });
    waitForFake();
    QMetaObject::invokeMethod(button("exportVaultButton"), "clicked", Qt::DirectConnection);
    EXPECT_EQ(probe.starts, 1); EXPECT_FALSE(button("exportVaultButton")->isEnabled());
    progress()->reject(); waitForResult();
}
TEST_F(ManualVaultExportTest, ReservedVaultCannotReopenAndCloseStillRequestsCancellation)
{
    fake("cancel"); exportThroughDialogs(); waitForFake();
    bool refused = false;
    QTimer dismiss;
    QObject::connect(&dismiss, &QTimer::timeout, window.get(), [&] {
        for (auto* message : window->findChildren<QMessageBox*>()) {
            refused = true;
            EXPECT_TRUE(message->text().contains("réservé"));
            message->accept();
        }
    });
    dismiss.start(5);
    bounded([&] { unlock(source); });
    dismiss.stop();
    EXPECT_TRUE(refused);
    EXPECT_FALSE(window->acquireLease().unlocked);
    QElapsedTimer timer; timer.start();
    EXPECT_FALSE(window->close());
    EXPECT_LT(timer.elapsed(), 200);
    EXPECT_TRUE(window->isVisible()); EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_TRUE(until([&] { return !window->isVisible(); }));
    EXPECT_FALSE(QFile::exists(destination));
}
TEST_F(ManualVaultExportTest, CloseWithUnknownOutcomeKeepsAnExplicitNonmodalNotice)
{
    fake("ignore"); exportThroughDialogs(); waitForFake();
    QElapsedTimer timer; timer.start(); EXPECT_FALSE(window->close()); EXPECT_LT(timer.elapsed(), 200);
    waitForResult(); EXPECT_TRUE(window->isVisible()); EXPECT_TRUE(status().contains("Résultat incertain"));
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_EQ(progress()->findChild<QPushButton*>("vaultExportCancelButton")->text(), "Fermer PassWall");
    progress()->findChild<QPushButton*>("vaultExportCancelButton")->click();
    ASSERT_TRUE(until([&] { return !window->isVisible(); }));
}
TEST_F(ManualVaultExportTest, UnknownLiveWorkerRemainsReservedAfterBoundedWindowClose)
{
    const auto restore = qScopeGuard([] {
        suppressExportStops = false;
        if (suppressedExportProcess) realExportKill(suppressedExportProcess);
        suppressedExportProcess.clear();
    });
    suppressExportStops = true;
    fake("ignore"); exportThroughDialogs(); waitForFake();
    EXPECT_FALSE(window->close());
    waitForResult();
    EXPECT_TRUE(status().contains("Résultat incertain"));
    auto* job = window->findChild<BackupJob*>();
    ASSERT_NE(job, nullptr); EXPECT_TRUE(job->isActive());
    passwall::storage::VaultOperationGuard access;
    std::string error;
    EXPECT_FALSE(access.tryAccess(source.toStdString(), error));
    progress()->findChild<QPushButton*>("vaultExportCancelButton")->click();
    ASSERT_TRUE(until([&] { return !window->isVisible(); }));
    window.reset(); // No QProcess destruction/wait; independent supervisor owns it.
    EXPECT_FALSE(access.tryAccess(source.toStdString(), error));
    ASSERT_TRUE(suppressedExportProcess);
    suppressExportStops = false; realExportKill(suppressedExportProcess);
    ASSERT_TRUE(until([&] { return access.tryAccess(source.toStdString(), error); }));
}

TEST_F(ManualVaultExportTest, CloseBeforeQueuedCleanupAcknowledgementPreventsLaunch)
{
    exportThroughDialogs();
    EXPECT_FALSE(window->close());
    ASSERT_TRUE(until([&] { return !window->isVisible(); }));
    expectNoLaunch();
}
TEST_F(ManualVaultExportTest, CancellationLosingThePublicationRaceShowsPublicationNotCancellation)
{
    fake("late"); exportThroughDialogs(); waitForFake();
    progress()->reject(); waitForResult();
    EXPECT_TRUE(status().contains("réussie"));
    EXPECT_FALSE(status().contains("annulée avant publication"));
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(ManualVaultExportTest, DisabledInactivityPolicyIsNotChangedByExportDialogs)
{
    window.reset();
    QSettings("PassWall", "PassWall").setValue("security/autoLockMinutes", 0);
    window = std::make_unique<MainWindow>();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true); window->show();
    bounded([&] { unlock(source); });
    const auto lease = window->acquireLease();
    ASSERT_TRUE(lease.unlocked); ASSERT_FALSE(inactivity()->isActive());
    exportThroughDialogs(false);
    expectNoLaunch(); EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_FALSE(inactivity()->isActive());
    EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 0);
}
TEST_F(ManualVaultExportTest, RelativeSourceIsCapturedAbsolutelyWithoutChangingItsAuthorization)
{
    button("lockVaultButton")->click();
    const auto previousDirectory = QDir::currentPath();
    const auto restoreDirectory = qScopeGuard([&] { QDir::setCurrent(previousDirectory); });
    ASSERT_TRUE(QDir::setCurrent(directory.path()));
    bounded([&] { unlock(QStringLiteral("source.pwdb")); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    exportThroughDialogs(); waitForResult();
    EXPECT_EQ(probe.source, source);
    EXPECT_TRUE(status().contains("réussie")); EXPECT_TRUE(QFile::exists(destination));
}
TEST_F(ManualVaultExportTest, AutomaticBackupStartsAfterManualLockHasClearedTheSession)
{
    auto* automatic = prepareAutomatic(); ASSERT_NE(automatic, nullptr);
    auto count = std::make_shared<int>(0);
    QObject::connect(automatic, &passwall::services::AutomaticBackupCoordinator::activityChanged, automatic,
        [this](bool active) {
            if (active) {
                EXPECT_FALSE(window->acquireLease().unlocked);
                EXPECT_FALSE(inactivity()->isActive());
                EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPasswordEdit")->text().isEmpty());
            }
        });
    QObject::connect(automatic, &passwall::services::AutomaticBackupCoordinator::completed, automatic,
        [count](const QString&, passwall::services::BackupResult result) {
            EXPECT_EQ(result.outcome, passwall::services::BackupOutcome::Published); ++*count;
        });
    button("lockVaultButton")->click();
    EXPECT_FALSE(window->acquireLease().unlocked); EXPECT_FALSE(automatic->isActive());
    ASSERT_TRUE(until([&] { return *count == 1; }));
}
TEST_F(ManualVaultExportTest, AutomaticBackupFollowsInactivityCleanupWithoutRearmingTheTimer)
{
    auto* automatic = prepareAutomatic(); ASSERT_NE(automatic, nullptr);
    auto count = std::make_shared<int>(0);
    QObject::connect(automatic, &passwall::services::AutomaticBackupCoordinator::completed, automatic,
        [count](const QString&, passwall::services::BackupResult result) {
            EXPECT_EQ(result.outcome, passwall::services::BackupOutcome::Published); ++*count;
        });
    ASSERT_TRUE(QMetaObject::invokeMethod(inactivity(), "timeout", Qt::DirectConnection));
    EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_TRUE(until([&] { return *count == 1; })); EXPECT_FALSE(inactivity()->isActive());
}
TEST_F(ManualVaultExportTest, AutomaticBackupDoesNotRunBeforeTheExternalCleanupAcknowledgement)
{
    auto* automatic = prepareAutomatic(); ASSERT_NE(automatic, nullptr);
    auto acknowledged = std::make_shared<bool>(false);
    auto done = std::make_shared<bool>(false);
    QObject::connect(automatic, &passwall::services::AutomaticBackupCoordinator::activityChanged, automatic,
        [acknowledged](bool active) { if (active) EXPECT_TRUE(*acknowledged); });
    QObject::connect(automatic, &passwall::services::AutomaticBackupCoordinator::completed, automatic,
        [done](const QString&, passwall::services::BackupResult result) {
            EXPECT_EQ(result.outcome, passwall::services::BackupOutcome::Published); *done = true;
        });
    window->requestExternalLock([acknowledged](bool cleaned) { EXPECT_TRUE(cleaned); *acknowledged = true; });
    EXPECT_FALSE(*acknowledged); EXPECT_FALSE(automatic->isActive());
    ASSERT_TRUE(until([&] { return *done; })); EXPECT_TRUE(*acknowledged);
}
TEST_F(ManualVaultExportTest, AutomaticBackupDefersDuringSystemTransitionAndNeverUnlocksOnResume)
{
    auto* automatic = prepareAutomatic(); ASSERT_NE(automatic, nullptr);
    auto done = std::make_shared<bool>(false);
    QObject::connect(automatic, &passwall::services::AutomaticBackupCoordinator::completed, automatic,
        [done](const QString&, passwall::services::BackupResult result) {
            EXPECT_EQ(result.outcome, passwall::services::BackupOutcome::Published); *done = true;
        });
    window->setLifecycleProtectionAvailable(false);
    QApplication::processEvents(); QApplication::processEvents();
    EXPECT_FALSE(window->acquireLease().unlocked); EXPECT_FALSE(automatic->isActive()); EXPECT_FALSE(*done);
    window->setLifecycleProtectionAvailable(true);
    ASSERT_TRUE(until([&] { return *done; })); EXPECT_FALSE(window->acquireLease().unlocked);
}
} // namespace
