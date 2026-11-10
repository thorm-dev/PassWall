#include "gui/main_window.hpp"
#include "gui/credential_editor_context.hpp"
#include "gui/vault_backup_settings_controller.hpp"
#include "gui/vault_backup_settings_dialog.hpp"
#include "services/credential_service.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "storage/vault_operation_guard.hpp"
#include "private_dbus.hpp"
#include <gtest/gtest.h>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScopeGuard>
#include <QSettings>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QTimer>
#include <QWindow>
#include <atomic>
#include <limits>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sodium.h>

namespace passwall::tests {
void setBackupSettingsTestWorker(QString);
void holdSettingsSync(); bool settingsSyncEntered(); void releaseSettingsSync(); void failSettingsSync();
void suppressGuiStopsForRestore(bool); void releaseGuiRestoreStop();
}
namespace { std::atomic<bool> unsupportedSettingsDestination{false}; }
extern "C" int __real_fstatfs(int, struct statfs*);
extern "C" int __wrap_fstatfs(int fd, struct statfs* value)
{
    const int result = __real_fstatfs(fd, value);
    if (result == 0 && unsupportedSettingsDestination) value->f_type = NFS_SUPER_MAGIC;
    return result;
}

namespace {
using namespace passwall::services;
using passwall::gui::MainWindow;
using passwall::gui::VaultBackupSettingsController;
using passwall::gui::VaultBackupSettingsDialog;
using passwall::tests::waitFor;
constexpr auto master = "fictitious-backup-settings-master";
QByteArray bytes(const QString& path) { QFile file(path); return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray{}; }
void touch(const QString& path, const QByteArray& value) {
    QFile file(path); ASSERT_TRUE(file.open(QIODevice::WriteOnly)); ASSERT_EQ(file.write(value), value.size());
}
class VaultBackupSettingsGuiTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suite;
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-backup-settings-XXXXXX")};
    QString principal, destination, error, noticeText;
    VaultRegistration original;
    std::unique_ptr<MainWindow> window;
    QPointer<VaultBackupSettingsDialog> dialog;
    AutomaticBackupCoordinator* coordinator = nullptr;
    VaultBackupSettingsController* controller = nullptr;
    int reads = 0, writes = 0, completed = 0, notices = 0, staleReads = 0;
    bool saved = false;
    BackupResult last;
    static void SetUpTestSuite() {
        ASSERT_GE(sodium_init(), 0); suite = std::make_unique<QTemporaryDir>("/tmp/passwall-backup-settings-suite-XXXXXX");
        ASSERT_TRUE(suite->isValid());
        for (auto format : {QSettings::IniFormat, QSettings::NativeFormat}) {
            QSettings::setPath(format, QSettings::UserScope, suite->filePath("settings"));
            QSettings::setPath(format, QSettings::SystemScope, suite->filePath("settings"));
        }
        passwall::core::SecureBuffer key(0); std::string failure;
        ASSERT_TRUE(VaultLifecycleService::createVault(suite->filePath("template.db").toStdString(), master, key, failure));
        passwall::models::Credential c; const auto wipe = qScopeGuard([&] { passwall::gui::detail::wipeCredential(c); });
        c.title = "Fictitious account"; c.username = "fictitious-user"; c.password = "fictitious-credential";
        ASSERT_TRUE(CredentialService::add(suite->filePath("template.db").toStdString(), key, c, failure));
    }
    static void TearDownTestSuite() { suite.reset(); }
    void SetUp() override {
        ASSERT_TRUE(directory.isValid());
        for (auto format : {QSettings::IniFormat, QSettings::NativeFormat}) {
            QSettings::setPath(format, QSettings::UserScope, directory.filePath("settings"));
            QSettings::setPath(format, QSettings::SystemScope, directory.filePath("settings"));
        }
        principal = directory.filePath("principal.db"); destination = directory.filePath("backups");
        ASSERT_TRUE(QFile::copy(suite->filePath("template.db"), principal)); makeDirectory(destination);
        ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(principal, original, error), VaultRecognition::Registered);
        newWindow();
    }
    void newWindow() {
        window = std::make_unique<MainWindow>(); window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true); window->show();
        coordinator = window->findChild<AutomaticBackupCoordinator*>(); ASSERT_NE(coordinator, nullptr);
        coordinator->setPaused(true); // Most preference tests intentionally hold the existing dispatch, not a fake engine.
        QObject::connect(coordinator, &AutomaticBackupCoordinator::completed, window.get(), [this](const QString&, auto r) { ++completed; last = r; });
        QObject::connect(coordinator, &AutomaticBackupCoordinator::notification, window.get(),
            [this](const QString&, const QString& text) { ++notices; noticeText = text; });
    }
    void TearDown() override {
        unsupportedSettingsDestination = false; passwall::tests::releaseSettingsSync();
        passwall::tests::releaseGuiRestoreStop(); passwall::tests::setBackupSettingsTestWorker({});
        if (coordinator) { coordinator->shutdown(); EXPECT_TRUE(waitFor([&] { return !coordinator->isActive(); }, 10000)); }
        window.reset(); QApplication::processEvents(); QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
    void makeDirectory(const QString& path) {
        ASSERT_TRUE(QDir().mkpath(path)); ASSERT_TRUE(QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner));
    }
    template<class T> T* widget(const char* name) { return dialog->findChild<T*>(QString::fromLatin1(name)); }
    QString state() { return widget<QLabel>("backupStateLabel")->text(); }
    QString feedback() { return widget<QLabel>("backupFeedbackLabel")->text(); }
    VaultRegistration record(const QString& id = {}) {
        QVector<VaultRegistration> records; EXPECT_TRUE(VaultPreferencesStore().listForDisplay(records, error));
        for (const auto& r : records) if (r.localId == (id.isEmpty() ? original.localId : id)) return r;
        ADD_FAILURE(); return {};
    }
    void open() {
        window->findChild<QAction*>("backupSettingsAction")->trigger();
        for (auto* w : QApplication::topLevelWidgets()) if (w->objectName() == "vaultBackupSettingsDialog") dialog = qobject_cast<VaultBackupSettingsDialog*>(w);
        ASSERT_TRUE(dialog); controller = window->findChild<VaultBackupSettingsController*>(); ASSERT_NE(controller, nullptr);
        QObject::connect(controller, &VaultBackupSettingsController::readSettled, window.get(), [this](bool current) { if (current) ++reads; else ++staleReads; });
        QObject::connect(controller, &VaultBackupSettingsController::writeSettled, window.get(), [this](const QString&, bool ok) { ++writes; saved = ok; });
        ASSERT_TRUE(waitFor([&] { return widget<QComboBox>("backupVaultCombo")->count() > 0; }));
        EXPECT_EQ(widget<QComboBox>("backupVaultCombo")->currentIndex(), -1);
    }
    void select(const QString& id = {}) {
        if (!dialog || !dialog->isVisible()) { dialog.clear(); open(); }
        const auto prior = reads;
        auto* combo = widget<QComboBox>("backupVaultCombo"); combo->setCurrentIndex(combo->findData(id.isEmpty() ? original.localId : id));
        ASSERT_TRUE(waitFor([&] { return reads > prior; }));
    }
    void edit(bool automatic, const QString& path, int retained = 7) {
        ASSERT_TRUE(waitFor([&] { return widget<QPushButton>("backupSaveButton")->isEnabled(); })) << state().toStdString();
        widget<QCheckBox>("backupAutomaticCheck")->setChecked(automatic);
        widget<QLineEdit>("backupDirectoryEdit")->setText(path); widget<QSpinBox>("backupRetentionSpin")->setValue(retained);
    }
    void save() {
        saved = false;
        ASSERT_TRUE(widget<QPushButton>("backupSaveButton")->isEnabled()) << state().toStdString();
        const auto count = writes, readCount = reads; widget<QPushButton>("backupSaveButton")->click();
        ASSERT_TRUE(waitFor([&] { return writes > count; })); ASSERT_TRUE(waitFor([&] { return reads > readCount; }));
    }
    void reload() {
        const auto count = reads; widget<QPushButton>("backupReloadButton")->click(); ASSERT_TRUE(waitFor([&] { return reads > count; }));
    }
    bool complete(int target = 1) { return waitFor([&] { return completed >= target && !coordinator->isActive(); }, 15000); }
    void unlock() {
        window->findChild<QLineEdit*>("unlockPathEdit")->setText(principal);
        window->findChild<QLineEdit*>("unlockPasswordEdit")->setText(master);
        window->findChild<QPushButton*>("unlockVaultButton")->click(); ASSERT_TRUE(window->acquireLease().unlocked);
        coordinator->setPaused(true);
    }
    void fakeWorker(const QByteArray& mode) {
        // The trusted worker path is fixed at coordinator construction, not
        // mutable at launch. Reconstruct only the test window to select a peer.
        window.reset(); passwall::tests::setBackupSettingsTestWorker(QString::fromLatin1(EXPORT_FAKE_WORKER));
        touch(principal + ".fake-mode", mode); newWindow();
    }
};

TEST_F(VaultBackupSettingsGuiTest, DefaultsRequireAnExplicitPrincipalAndNeverStartAResume)
{
    open(); EXPECT_FALSE(widget<QPushButton>("backupSaveButton")->isEnabled());
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled()); select();
    EXPECT_FALSE(widget<QCheckBox>("backupAutomaticCheck")->isChecked());
    EXPECT_TRUE(widget<QLineEdit>("backupDirectoryEdit")->text().isEmpty()); EXPECT_EQ(widget<QSpinBox>("backupRetentionSpin")->value(), 7);
    EXPECT_TRUE(state().contains("désactivées")); EXPECT_EQ(completed, 0); EXPECT_FALSE(coordinator->resumePending(original.localId));
}
TEST_F(VaultBackupSettingsGuiTest, ThreePreferencesPersistWithoutTouchingAnotherPrincipalOrPortableCopy)
{
    const auto copy = directory.filePath("portable.db"); ASSERT_TRUE(QFile::copy(principal, copy));
    VaultRegistration other; ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(copy, other, error), VaultRecognition::Registered);
    select(); edit(true, destination, 4); save(); ASSERT_TRUE(saved);
    EXPECT_TRUE(record().backup == VaultBackupPreferences({true, destination, 4})); EXPECT_TRUE(record().backupRequired);
    EXPECT_TRUE(record(other.localId).backup == VaultBackupPreferences{});
    dialog->reject(); QApplication::processEvents(); select(other.localId);
    EXPECT_FALSE(widget<QCheckBox>("backupAutomaticCheck")->isChecked()); EXPECT_EQ(widget<QSpinBox>("backupRetentionSpin")->value(), 7);
    EXPECT_TRUE(bytes(VaultPreferencesStore().fileName()).indexOf(master) < 0);
}
TEST_F(VaultBackupSettingsGuiTest, MissingDestinationRefusesActivationWithoutCreatingAnything)
{
    select(); edit(true, {}); save(); EXPECT_FALSE(saved); EXPECT_FALSE(record().backup.automatic);
    const auto missing = directory.filePath("absent/device"); edit(true, missing); save();
    EXPECT_FALSE(saved); EXPECT_FALSE(QFile::exists(missing)); EXPECT_FALSE(record().backup.automatic); EXPECT_EQ(completed, 0);
}
TEST_F(VaultBackupSettingsGuiTest, SymlinkAndUnsupportedDestinationAreRefusedWithoutFallback)
{
    const auto alias = directory.filePath("alias"); ASSERT_TRUE(QFile::link(destination, alias)); select(); edit(true, alias); save();
    EXPECT_FALSE(saved); EXPECT_FALSE(record().backup.automatic);
    unsupportedSettingsDestination = true; const auto reset = qScopeGuard([] { unsupportedSettingsDestination = false; });
    edit(true, destination); save(); EXPECT_FALSE(saved); EXPECT_TRUE(feedback().contains("non prise en charge")); EXPECT_FALSE(record().backup.automatic);
}
TEST_F(VaultBackupSettingsGuiTest, InvalidRetentionCannotReachPersistence)
{
    select(); auto* spin = widget<QSpinBox>("backupRetentionSpin");
    EXPECT_EQ(spin->minimum(), 1); EXPECT_EQ(spin->maximum(), std::numeric_limits<int>::max());
    spin->findChild<QLineEdit*>()->setText("0"); widget<QPushButton>("backupSaveButton")->click();
    EXPECT_EQ(writes, 0); EXPECT_EQ(record().backup.retainedVersions, 7); EXPECT_TRUE(feedback().contains("entier"));
    EXPECT_FALSE(VaultPreferencesStore().updatePreferencesIfCurrent(record(), {false, {}, 0}, error));
}
TEST_F(VaultBackupSettingsGuiTest, ConcurrentPreferenceUpdateCannotBeOverwrittenByTheDisplayedSnapshot)
{
    select(); ASSERT_TRUE(VaultPreferencesStore().updatePreferences(original.localId, {false, {}, 9}, error));
    edit(false, {}, 2); save(); EXPECT_FALSE(saved); EXPECT_EQ(record().backup.retainedVersions, 9);
    EXPECT_TRUE(state().contains("actualisez")); reload(); EXPECT_EQ(widget<QSpinBox>("backupRetentionSpin")->value(), 9);
    edit(false, {}, 3); save(); EXPECT_TRUE(saved); EXPECT_EQ(record().backup.retainedVersions, 3);
}
TEST_F(VaultBackupSettingsGuiTest, OldReadCannotPopulateAnotherPrincipalAfterSelectionChanges)
{
    VaultRegistration other; const auto copy = directory.filePath("other.db"); ASSERT_TRUE(QFile::copy(principal, copy));
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(copy, other, error), VaultRecognition::Registered);
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(other.localId, {false, {}, 11}, error)); open();
    auto* combo = widget<QComboBox>("backupVaultCombo"); combo->setCurrentIndex(combo->findData(original.localId));
    combo->setCurrentIndex(combo->findData(other.localId)); ASSERT_TRUE(waitFor([&] { return staleReads > 0 && widget<QPushButton>("backupSaveButton")->isEnabled(); }));
    EXPECT_EQ(dialog->selectedId(), other.localId); EXPECT_EQ(widget<QSpinBox>("backupRetentionSpin")->value(), 11);
}
TEST_F(VaultBackupSettingsGuiTest, PersistenceFailureIsNotSuccessAndCanBeExplicitlyReconfirmed)
{
    select(); edit(false, {}, 8); passwall::tests::failSettingsSync(); save();
    EXPECT_FALSE(saved); EXPECT_TRUE(feedback().contains("non confirmé")); EXPECT_FALSE(feedback().contains("enregistrées durablement"));
    reload(); edit(false, {}, 6); save(); EXPECT_TRUE(saved); EXPECT_EQ(record().backup.retainedVersions, 6);
}
TEST_F(VaultBackupSettingsGuiTest, SlowPersistenceKeepsQtResponsiveAndLateCompletionCannotModifyAnotherForm)
{
    VaultRegistration other; const auto copy = directory.filePath("other.db"); ASSERT_TRUE(QFile::copy(principal, copy));
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(copy, other, error), VaultRecognition::Registered);
    select(); edit(false, {}, 8); passwall::tests::holdSettingsSync();
    const auto release = qScopeGuard([] { passwall::tests::releaseSettingsSync(); });
    widget<QPushButton>("backupSaveButton")->click(); ASSERT_TRUE(waitFor([] { return passwall::tests::settingsSyncEntered(); }));
    bool event = false; QTimer::singleShot(0, window.get(), [&] { event = true; }); ASSERT_TRUE(waitFor([&] { return event; }));
    auto* combo = widget<QComboBox>("backupVaultCombo"); combo->setCurrentIndex(combo->findData(other.localId));
    passwall::tests::releaseSettingsSync(); ASSERT_TRUE(waitFor([&] { return writes == 1 && widget<QPushButton>("backupSaveButton")->isEnabled(); }));
    EXPECT_EQ(dialog->selectedId(), other.localId); EXPECT_EQ(widget<QSpinBox>("backupRetentionSpin")->value(), 7);
    EXPECT_FALSE(feedback().contains("enregistrées durablement")); EXPECT_EQ(record().backup.retainedVersions, 8);
}
TEST_F(VaultBackupSettingsGuiTest, IncompatibleBusinessAccessRefusesSavingWithoutDiscardingAnything)
{
    select(); passwall::storage::VaultOperationGuard access; std::string failure; ASSERT_TRUE(access.tryAccess(principal.toStdString(), failure));
    edit(false, {}, 3); save(); EXPECT_FALSE(saved); EXPECT_EQ(record().backup.retainedVersions, 7);
    access.reset(); reload(); edit(false, {}, 3); save(); EXPECT_TRUE(saved);
}
TEST_F(VaultBackupSettingsGuiTest, RealActivationCreatesInitialSnapshotWhileTheVaultRemainsLocked)
{
    coordinator->setPaused(false); select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(complete()) << noticeText.toStdString();
    EXPECT_EQ(last.outcome, BackupOutcome::Published); const auto r = record(); ASSERT_EQ(r.automaticVersions.size(), 1);
    EXPECT_TRUE(r.automaticVersions.first().durable); EXPECT_TRUE(QFile::exists(r.automaticVersions.first().path));
    EXPECT_FALSE(r.backupRequired); EXPECT_FALSE(r.automaticSuspended); EXPECT_FALSE(window->acquireLease().unlocked);
    reload(); EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled());
}
TEST_F(VaultBackupSettingsGuiTest, ActivationWhileUnlockedKeepsTheSessionAndCrudWaitsForLock)
{
    unlock(); const auto lease = window->acquireLease(); coordinator->setPaused(false); select(); edit(true, destination); save();
    ASSERT_TRUE(saved); ASSERT_TRUE(complete()) << noticeText.toStdString();
    EXPECT_TRUE(window->isLeaseCurrent(lease)); const auto first = record().automaticVersions.size();
    passwall::core::SecureBuffer key(0); std::string failure;
    ASSERT_TRUE(VaultLifecycleService::unlockVault(principal.toStdString(), master, key, failure));
    passwall::models::Credential c; const auto wipe = qScopeGuard([&] { passwall::gui::detail::wipeCredential(c); });
    c.title = "Fictitious second"; c.username = "fictitious-user"; c.password = "fictitious-exact";
    ASSERT_TRUE(CredentialService::add(principal.toStdString(), key, c, failure)); c.title = "Fictitious changed";
    ASSERT_TRUE(CredentialService::update(principal.toStdString(), key, c, failure));
    QApplication::processEvents(); EXPECT_EQ(record().automaticVersions.size(), first); EXPECT_EQ(completed, 1); EXPECT_TRUE(record().backupRequired);
    window->findChild<QPushButton*>("lockVaultButton")->click(); ASSERT_TRUE(complete(2)) << noticeText.toStdString();
    EXPECT_FALSE(window->isLeaseCurrent(lease)); EXPECT_EQ(record().automaticVersions.size(), first + 1); EXPECT_FALSE(record().backupRequired);
    coordinator->requestForLockedVault(principal); QApplication::processEvents(); EXPECT_EQ(completed, 2);
}
TEST_F(VaultBackupSettingsGuiTest, ActivationIsDeferredUntilAnExistingReservationEnds)
{
    select(); edit(true, destination); save(); ASSERT_TRUE(saved); passwall::storage::VaultOperationGuard guard; std::string failure;
    ASSERT_TRUE(guard.tryReserve(principal.toStdString(), failure)); coordinator->setPaused(false);
    int deferred = 0; QObject observer; QObject::connect(coordinator, &AutomaticBackupCoordinator::deferred, &observer, [&] { ++deferred; });
    ASSERT_TRUE(waitFor([&] { return deferred > 0; })); EXPECT_EQ(completed, 0); EXPECT_FALSE(record().automaticSuspended);
    guard.reset(); coordinator->retryPending(); ASSERT_TRUE(complete()) << noticeText.toStdString(); EXPECT_EQ(last.outcome, BackupOutcome::Published);
}
TEST_F(VaultBackupSettingsGuiTest, ConfirmedFailureSuspendsAndOnlyExplicitResumeCopiesTheCurrentState)
{
    fakeWorker("failed");
    coordinator->setPaused(false); select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(complete()) << noticeText.toStdString(); ASSERT_TRUE(record().automaticSuspended);
    reload(); EXPECT_TRUE(state().contains("suspendues après échec")); EXPECT_TRUE(widget<QPushButton>("backupResumeButton")->isEnabled());
    const auto attempt = completed; coordinator->requestForLockedVault(principal); QApplication::processEvents(); EXPECT_EQ(completed, attempt);
    // Change destination through the real form: suspension survives saving, no implicit retry.
    const auto next = directory.filePath("new-backups"); makeDirectory(next); edit(true, next, 5); save(); ASSERT_TRUE(saved);
    EXPECT_TRUE(record().automaticSuspended); EXPECT_EQ(completed, attempt);
    // A fresh coordinator with the REAL worker still must not auto-resume.
    window.reset(); passwall::tests::setBackupSettingsTestWorker({}); newWindow(); select();
    EXPECT_TRUE(record().automaticSuspended); EXPECT_EQ(completed, attempt);
    widget<QPushButton>("backupResumeButton")->click(); widget<QPushButton>("backupResumeButton")->click();
    EXPECT_TRUE(coordinator->resumePending(original.localId)); coordinator->setPaused(false);
    ASSERT_TRUE(complete(attempt + 1)) << noticeText.toStdString(); EXPECT_EQ(last.outcome, BackupOutcome::Published);
    EXPECT_FALSE(record().automaticSuspended); EXPECT_FALSE(record().backupRequired); EXPECT_EQ(record().automaticVersions.size(), 1);
    EXPECT_TRUE(record().automaticVersions.first().path.startsWith(next + '/'));
}
TEST_F(VaultBackupSettingsGuiTest, ResumeWithStillMissingDestinationFailsAgainWithoutAutomaticRetry)
{
    select(); edit(true, destination); save(); ASSERT_TRUE(saved); ASSERT_TRUE(QDir().rmdir(destination));
    coordinator->setPaused(false); ASSERT_TRUE(waitFor([&] { return notices == 1; })); reload();
    EXPECT_TRUE(record().automaticSuspended); const auto count = notices;
    widget<QPushButton>("backupResumeButton")->click(); ASSERT_TRUE(waitFor([&] { return notices == count + 1; }));
    EXPECT_TRUE(record().automaticSuspended); EXPECT_FALSE(QFile::exists(destination)); EXPECT_EQ(completed, 0);
    coordinator->requestForLockedVault(principal); QApplication::processEvents(); EXPECT_EQ(notices, count + 1);
}
TEST_F(VaultBackupSettingsGuiTest, DisablingThenReenablingDoesNotSilentlyLiftAnExistingSuspension)
{
    select(); edit(true, destination); save(); ASSERT_TRUE(VaultPreferencesStore().suspendAutomaticBackup(original.localId, error)); reload();
    edit(false, destination); save(); EXPECT_TRUE(saved); EXPECT_TRUE(record().automaticSuspended);
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled());
    edit(true, destination); save(); EXPECT_TRUE(saved); EXPECT_TRUE(record().automaticSuspended); EXPECT_EQ(completed, 0);
}
TEST_F(VaultBackupSettingsGuiTest, ResumeRequiresSavingTheEditedDestinationAndNeverUsesAnUncommittedDraft)
{
    select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(VaultPreferencesStore().suspendAutomaticBackup(original.localId, error)); reload();
    ASSERT_TRUE(widget<QPushButton>("backupResumeButton")->isEnabled());
    const auto next = directory.filePath("changed-backups"); makeDirectory(next); edit(true, next);
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled()); EXPECT_TRUE(state().contains("non enregistrées"));
    widget<QPushButton>("backupResumeButton")->click(); EXPECT_FALSE(coordinator->resumePending(original.localId));
    EXPECT_EQ(record().backup.directory, destination); save(); ASSERT_TRUE(saved);
    EXPECT_TRUE(record().automaticSuspended); EXPECT_TRUE(widget<QPushButton>("backupResumeButton")->isEnabled());
    EXPECT_FALSE(coordinator->resumePending(original.localId)); EXPECT_EQ(completed, 0);
}
TEST_F(VaultBackupSettingsGuiTest, LateResumeOutcomeCannotOverwriteTheNewlySelectedPrincipal)
{
    VaultRegistration other; const auto copy = directory.filePath("other.db"); ASSERT_TRUE(QFile::copy(principal, copy));
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(copy, other, error), VaultRecognition::Registered);
    select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(VaultPreferencesStore().suspendAutomaticBackup(original.localId, error)); reload();
    widget<QPushButton>("backupResumeButton")->click();
    widget<QComboBox>("backupVaultCombo")->setCurrentIndex(widget<QComboBox>("backupVaultCombo")->findData(other.localId));
    coordinator->setPaused(false); ASSERT_TRUE(complete()) << noticeText.toStdString(); reload();
    EXPECT_EQ(dialog->selectedId(), other.localId); EXPECT_FALSE(widget<QCheckBox>("backupAutomaticCheck")->isChecked());
    EXPECT_EQ(widget<QSpinBox>("backupRetentionSpin")->value(), 7); EXPECT_TRUE(state().contains("désactivées"));
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled()); EXPECT_TRUE(record(other.localId).backup == VaultBackupPreferences{});
    EXPECT_EQ(record().automaticVersions.size(), 1); EXPECT_FALSE(record().automaticSuspended);
}
TEST_F(VaultBackupSettingsGuiTest, RetentionAndDestinationChangesKeepTheCatalogueAndDoNotDeleteFiles)
{
    coordinator->setPaused(false); select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(complete()) << noticeText.toStdString();
    const auto before = record(); ASSERT_FALSE(before.automaticVersions.isEmpty());
    const auto old = before.automaticVersions.first().path; const auto data = bytes(old);
    touch(directory.filePath("manual-export.db"), "fictitious-manual"); touch(destination + "/unknown.db", "fictitious-unknown");
    const auto next = directory.filePath("next-backups"); makeDirectory(next); edit(true, next, 1); save(); EXPECT_TRUE(saved);
    EXPECT_TRUE(record().automaticVersions == before.automaticVersions); EXPECT_TRUE(bytes(old) == data);
    EXPECT_TRUE(QFile::exists(directory.filePath("manual-export.db"))); EXPECT_TRUE(QFile::exists(destination + "/unknown.db"));
    EXPECT_EQ(completed, 1); EXPECT_TRUE(record().backupEpoch != before.backupEpoch);
}
TEST_F(VaultBackupSettingsGuiTest, RotationLatchIsIndependentOfCopySuspensionAndSurvivesPreferenceChanges)
{
    fakeWorker("published-file"); touch(principal + ".fake-rotation-mode", "missing");
    coordinator->setPaused(false); select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(complete()) << noticeText.toStdString();
    ASSERT_EQ(last.outcome, BackupOutcome::Published); const auto before = record(); ASSERT_FALSE(before.rotationAttempt.isEmpty());
    EXPECT_FALSE(before.automaticSuspended); reload();
    EXPECT_TRUE(widget<QLabel>("backupRotationLabel")->text().contains("Suppressions de rotation bloquées"));
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled()); edit(true, destination, 2); save();
    EXPECT_TRUE(saved); EXPECT_EQ(record().rotationAttempt, before.rotationAttempt); EXPECT_TRUE(record().automaticVersions == before.automaticVersions);
}
TEST_F(VaultBackupSettingsGuiTest, UnknownWithALiveChildNeverEnablesResumeOrReleasesItsReservation)
{
    fakeWorker("orphan");
    passwall::tests::suppressGuiStopsForRestore(true); coordinator->setPaused(false); select(); edit(true, destination); save();
    ASSERT_TRUE(waitFor([&] { return coordinator->isActive() && !record().backupAttemptDestination.isEmpty()
        && QFile::exists(record().backupAttemptDestination + ".ready"); }));
    const auto path = record().backupAttemptDestination; coordinator->cancel(); ASSERT_TRUE(waitFor([&] { return completed == 1; }, 7000));
    EXPECT_EQ(last.outcome, BackupOutcome::Unknown); EXPECT_TRUE(coordinator->isActive()); reload();
    EXPECT_TRUE(state().contains("processus encore actif")); EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled());
    passwall::storage::VaultOperationGuard guard; std::string failure; EXPECT_FALSE(guard.tryReserve(principal.toStdString(), failure));
    touch(path + ".exit", {}); ASSERT_TRUE(waitFor([&] { return !coordinator->isActive(); }));
    passwall::tests::releaseGuiRestoreStop(); reload(); EXPECT_TRUE(state().contains("résultat incertain"));
    EXPECT_TRUE(widget<QPushButton>("backupResumeButton")->isEnabled()); EXPECT_TRUE(guard.tryReserve(principal.toStdString(), failure));
    guard.reset(); touch(principal + ".fake-mode", "cancel"); widget<QPushButton>("backupResumeButton")->click();
    ASSERT_TRUE(waitFor([&] { return coordinator->isActive(); })); reload();
    EXPECT_TRUE(state().contains("en cours")); EXPECT_FALSE(state().contains("Résultat incertain"));
    coordinator->cancel(); ASSERT_TRUE(complete(2)) << noticeText.toStdString();
}
TEST_F(VaultBackupSettingsGuiTest, RecoveryFenceBlocksPreferencesAndResumeWithoutClearingItsMarker)
{
    select(); std::optional<VaultReplacementAuthorization> authority;
    window->requestReplacementAuthorization(original.localId, [&](auto value, QString) { authority.emplace(std::move(value)); });
    ASSERT_TRUE(waitFor([&] { return authority.has_value(); }, 10000)); ASSERT_FALSE(authority->operationId().isEmpty());
    const auto operation = authority->operationId(); authority.reset(); reload();
    EXPECT_TRUE(state().contains("Récupération")); EXPECT_FALSE(widget<QPushButton>("backupSaveButton")->isEnabled());
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled()); ASSERT_TRUE(record().replacement);
    EXPECT_EQ(record().replacement->operationId, operation);
}
TEST_F(VaultBackupSettingsGuiTest, ClosingPreferencesDoesNotCancelAnAuthorizedBackupOrCreateAnotherDialog)
{
    select(); const auto originalDialog = dialog;
    window->findChild<QAction*>("backupSettingsAction")->trigger(); EXPECT_TRUE(dialog == originalDialog);
    edit(true, destination); save(); ASSERT_TRUE(saved); dialog->reject(); coordinator->setPaused(false);
    ASSERT_TRUE(complete()) << noticeText.toStdString();
    EXPECT_EQ(last.outcome, BackupOutcome::Published); EXPECT_FALSE(record().automaticSuspended);
}
TEST_F(VaultBackupSettingsGuiTest, PreferencesAreTransientAndDoNotBecomeAnotherPrimaryWindowOnApplicationClose)
{
    select(); EXPECT_EQ(dialog->parentWidget(), nullptr); EXPECT_FALSE(dialog->isModal());
    EXPECT_FALSE(dialog->testAttribute(Qt::WA_QuitOnClose));
    EXPECT_FALSE(window->findChildren<QDialog*>().contains(dialog.data()));
    ASSERT_NE(dialog->windowHandle(), nullptr); ASSERT_NE(window->windowHandle(), nullptr);
    EXPECT_EQ(dialog->windowHandle()->transientParent(), window->windowHandle());
    window->close(); ASSERT_TRUE(waitFor([&] { return !window->isVisible(); }));
    window.reset(); coordinator = nullptr; controller = nullptr; EXPECT_TRUE(dialog.isNull());
}
TEST_F(VaultBackupSettingsGuiTest, AnObservedUnknownCannotBecomeSuccessFromADisplaySnapshotAlone)
{
    coordinator->setPaused(false); select(); edit(true, destination); save(); ASSERT_TRUE(saved);
    ASSERT_TRUE(complete()) << noticeText.toStdString(); EXPECT_FALSE(record().automaticSuspended);
    // Presentation-only fault: no invented persistent suspension or authority.
    // The real copy above is confirmed; this tests conservative contradictory delivery.
    emit coordinator->completed(original.localId, {BackupOutcome::Unknown, QStringLiteral("Fictitious lost confirmation")});
    reload(); EXPECT_TRUE(state().contains("résultat incertain")); EXPECT_FALSE(state().contains("aucune modification en attente"));
    EXPECT_FALSE(widget<QPushButton>("backupResumeButton")->isEnabled()); EXPECT_FALSE(record().automaticSuspended);
}
}
