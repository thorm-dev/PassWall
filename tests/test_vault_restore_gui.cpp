#include "gui/main_window.hpp"
#include "gui/vault_restore_dialog.hpp"
#include "gui/vault_restore_controller.hpp"
#include "gui/vault_recovery_controller.hpp"
#include "services/credential_service.hpp"
#include "services/global_backup_preferences_store.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "storage/vault_operation_guard.hpp"
#include "private_dbus.hpp" // Existing bounded event-driven waitFor helper.
#include "posix_test_io.hpp"
#include <gtest/gtest.h>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDialog>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScopeGuard>
#include <QSettings>
#include <QStatusBar>
#include <QTemporaryDir>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sodium.h>
#include <sqlite3.h>

namespace passwall::tests {
void suppressGuiStopsForRestore(bool); void releaseGuiRestoreStop();
void overrideRestoreExecutablePaths(const QString&, const QString&);
void holdSettingsSync(); bool settingsSyncEntered(); void releaseSettingsSync(); void failSettingsSync();
void failSettingsSyncWhenPublished(const QString&, const QByteArray&);
bool publishedSettingsSyncFailed();
}

namespace {
using namespace passwall::services;
using passwall::core::SecureBuffer;
using passwall::gui::MainWindow;
using passwall::gui::VaultRestoreDialog;
using passwall::gui::VaultRestoreController;
using passwall::storage::VaultOperationGuard;
using passwall::tests::waitFor;
constexpr auto master = "fictitious-gui-restore-master";
QByteArray bytes(const QString& path) {
    QFile file(path); if (!file.open(QIODevice::ReadOnly)) { ADD_FAILURE(); return {}; }
    return file.readAll();
}
// Compare the complete encrypted SQL content, not SQLite's mutable file header.
auto encryptedState(const QString& path) {
    std::vector<std::vector<QByteArray>> rows;
    sqlite3* raw = nullptr;
    const auto code = sqlite3_open_v2(QFile::encodeName(path).constData(), &raw, SQLITE_OPEN_READONLY, nullptr);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> database(raw, sqlite3_close_v2);
    EXPECT_EQ(code, SQLITE_OK); if (code != SQLITE_OK) return rows;
    for (const auto* sql : {"SELECT * FROM vault_metadata ORDER BY id;", "SELECT * FROM entries ORDER BY entry_id;"}) {
        sqlite3_stmt* statement = nullptr;
        const auto prepared = sqlite3_prepare_v2(raw, sql, -1, &statement, nullptr);
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> cleanup(statement, sqlite3_finalize);
        EXPECT_EQ(prepared, SQLITE_OK); if (prepared != SQLITE_OK) return rows;
        int step;
        while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
            std::vector<QByteArray> row;
            for (int i = 0; i < sqlite3_column_count(statement); ++i)
                row.emplace_back(static_cast<const char*>(sqlite3_column_blob(statement, i)), sqlite3_column_bytes(statement, i));
            rows.push_back(std::move(row));
        }
        EXPECT_EQ(step, SQLITE_DONE);
    }
    return rows;
}
class VaultRestoreGuiTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suite;
    QTemporaryDir directory{QStringLiteral("/tmp/passwall-restore-gui-XXXXXX")};
    std::unique_ptr<MainWindow> window;
    QPointer<VaultRestoreDialog> dialog;
    QString principal, source, precaution, local;
    static void settingsAt(const QString& path) {
        for (auto format : {QSettings::NativeFormat, QSettings::IniFormat})
            for (auto scope : {QSettings::UserScope, QSettings::SystemScope}) QSettings::setPath(format, scope, path);
    }
    static void SetUpTestSuite() {
        ASSERT_GE(sodium_init(), 0);
        suite = std::make_unique<QTemporaryDir>("/tmp/passwall-restore-gui-suite-XXXXXX");
        ASSERT_TRUE(suite->isValid()); settingsAt(suite->path());
        SecureBuffer key(0); std::string error;
        const auto old = suite->filePath("old.db").toStdString();
        ASSERT_TRUE(VaultLifecycleService::createVault(old, master, key, error));
        passwall::models::Credential entry; entry.title = "Fictitious older entry"; entry.username = "fictitious-user";
        entry.password = "fictitious-entry-password"; entry.notes = "fictitious notes";
        const auto cleanup = qScopeGuard([&] {
            for (auto* s : {&entry.password, &entry.notes}) { sodium_memzero(s->data(), s->size()); s->clear(); }
        });
        ASSERT_TRUE(CredentialService::add(old, key, entry, error));
        ASSERT_TRUE(QFile::copy(QString::fromStdString(old), suite->filePath("current.db")));
        entry.title = "Fictitious current entry";
        ASSERT_TRUE(CredentialService::update(suite->filePath("current.db").toStdString(), key, entry, error));
    }
    static void TearDownTestSuite() { suite.reset(); }
    void SetUp() override {
        ASSERT_TRUE(directory.isValid()); settingsAt(directory.path());
        principal = directory.filePath("principal.db"); source = directory.filePath("external-selected.db");
        precaution = directory.filePath("exceptional-copy.db");
        ASSERT_TRUE(QFile::copy(suite->filePath("current.db"), principal));
        ASSERT_TRUE(QFile::copy(suite->filePath("old.db"), source));
        VaultRegistration record; QString error;
        ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(principal, record, error), VaultRecognition::Registered);
        local = record.localId;
        QSettings settings("PassWall", "PassWall"); settings.setValue("security/autoLockMinutes", 1);
        settings.setValue("unrelated/value", "keep"); settings.sync(); newWindow();
    }
    void newWindow() {
        window = MainWindow::createForHistoricalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true); window->show();
    }
#ifdef PASSWALL_GUI_TESTING
    void newGenerationalWindow() {
        window = MainWindow::createForGenerationalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true); window->show();
    }
#endif
    void TearDown() override { window.reset(); QApplication::processEvents(); }
    template<class T> T* widget(const char* name) { return dialog->findChild<T*>(QString::fromLatin1(name)); }
    void open() {
        auto* action = window->findChild<QAction*>("restoreVaultAction"); ASSERT_NE(action, nullptr); action->trigger();
        for (auto* w : QApplication::topLevelWidgets())
            if (w->objectName() == "vaultRestoreDialog") dialog = qobject_cast<VaultRestoreDialog*>(w);
        ASSERT_TRUE(dialog);
        ASSERT_TRUE(waitFor([&] { return widget<QComboBox>("restorePrincipalCombo")->count() > 0
            || widget<QLabel>("restoreStatusLabel")->text().contains("impossible"); }, 10000));
        EXPECT_EQ(widget<QComboBox>("restorePrincipalCombo")->currentIndex(), -1);
    }
    void choose(const QString& target = {}) {
        open(); ASSERT_TRUE(dialog);
        auto* combo = widget<QComboBox>("restorePrincipalCombo");
        const auto index = combo->findText(target.isEmpty() ? principal : target); ASSERT_GE(index, 0); combo->setCurrentIndex(index);
        widget<QLineEdit>("restoreSourceEdit")->setText(source);
        widget<QLineEdit>("restorePrecautionEdit")->setText(precaution);
        widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    }
    void prepare() {
        widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
        widget<QPushButton>("restorePrepareButton")->click();
        ASSERT_TRUE(waitFor([&] { return widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled()
            || widget<QPushButton>("restoreCancelButton")->text() == "Fermer"; }, 10000));
        ASSERT_TRUE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled()) << status().toStdString();
    }
    RestoreJob* execute(const char* password = master) {
        widget<QLineEdit>("restoreMasterPasswordEdit")->setText(QString::fromUtf8(password));
        widget<QPushButton>("restorePrepareButton")->click();
        EXPECT_TRUE(widget<QLineEdit>("restoreMasterPasswordEdit")->text().isEmpty());
        return window->findChild<RestoreJob*>();
    }
    void done() {
        ASSERT_TRUE(waitFor([&] { return dialog && widget<QProgressBar>("restoreActivity")->isHidden()
            && widget<QPushButton>("restoreCancelButton")->text() == "Fermer"; }, 20000));
    }
    void leavePreparedForRecovery() {
        // Simulate a restart after 6A preparation without inventing an engine
        // refusal: precise non-engaged worker results are now auto-abandoned.
        choose(); prepare();
        window.reset(); QApplication::processEvents(); newWindow();
        ASSERT_TRUE(record().replacement);
        ASSERT_EQ(record().replacement->phase, "prepared");
    }
    QString status() { return widget<QLabel>("restoreStatusLabel")->text(); }
    VaultRegistration record() {
        QVector<VaultRegistration> records; QString error;
        EXPECT_TRUE(VaultPreferencesStore().list(records, error));
        for (const auto& r : records) if (r.localId == local) return r;
        ADD_FAILURE(); return {};
    }
    void unlock() {
        window->findChild<QLineEdit*>("unlockPathEdit")->setText(principal);
        window->findChild<QLineEdit*>("unlockPasswordEdit")->setText(master);
        window->findChild<QPushButton*>("unlockVaultButton")->click(); ASSERT_TRUE(window->acquireLease().unlocked);
    }
    QPointer<QDialog> recovery;
    template<class T> T* recoveryWidget(const char* name) { return recovery->findChild<T*>(QString::fromLatin1(name)); }
    void openRecovery() {
        window->findChild<QAction*>("recoverVaultAction")->trigger();
        for (auto* w : QApplication::topLevelWidgets())
            if (w->objectName() == "vaultRecoveryDialog") recovery = qobject_cast<QDialog*>(w);
        ASSERT_TRUE(recovery);
        ASSERT_TRUE(waitFor([&] { return !recoveryWidget<QProgressBar>("recoveryActivity")->isVisible(); }, 10000));
        auto* combo = recoveryWidget<QComboBox>("recoveryVaultCombo");
        ASSERT_EQ(combo->currentIndex(), -1);
        const auto index = combo->findText(principal); ASSERT_GE(index, 0); combo->setCurrentIndex(index);
    }
    void examineRecovery() {
        recoveryWidget<QPushButton>("recoveryInspectButton")->click();
        ASSERT_TRUE(waitFor([&] { return !recoveryWidget<QProgressBar>("recoveryActivity")->isVisible(); }, 10000));
    }
    void resolveRecovery() {
        recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
        ASSERT_TRUE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
        recoveryWidget<QPushButton>("recoveryResolveButton")->click();
        ASSERT_TRUE(waitFor([&] { return !recoveryWidget<QProgressBar>("recoveryActivity")->isVisible(); }, 10000));
    }
    struct Hold {
        QByteArray path, variable;
        int fd = -1;
        Hold(const QString& file, const char* env, const char* phase = nullptr) : path(QFile::encodeName(file)), variable(env) {
            if (::mkfifo(path.constData(), 0600) == 0) fd = ::open(path.constData(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
            qputenv(env, phase ? QByteArray(phase) : path);
            if (phase) qputenv("PW_RESTORE_HOLD_FIFO", path);
        }
        void release() { if (fd >= 0) { EXPECT_TRUE(passwall::test_io::writeAll(fd, "x", 1)); ::close(fd); fd = -1; } }
        ~Hold() { release(); qunsetenv(variable.constData()); qunsetenv("PW_RESTORE_HOLD_FIFO"); }
    };
};

TEST_F(VaultRestoreGuiTest, SelectionAndMissingConfirmationCannotLockOrLaunch)
{
    unlock(); const auto before = bytes(principal); const auto lease = window->acquireLease(); choose();
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(false);
    widget<QPushButton>("restorePrepareButton")->click();
    EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_TRUE(bytes(principal) == before);
    EXPECT_FALSE(window->findChild<RestoreJob*>()); EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled());
}
TEST_F(VaultRestoreGuiTest, UnsafeWorkerPermissionsAreRefusedBeforeLockOrPersistentPreparation)
{
    const auto fakeWorker = directory.filePath("unsafe-restore-worker");
    QFile file(fakeWorker); ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("not executed"), 12); file.close();
    ASSERT_EQ(::chmod(QFile::encodeName(fakeWorker).constData(), 0775), 0);
    passwall::tests::overrideRestoreExecutablePaths(fakeWorker, {});
    const auto reset = qScopeGuard([] { passwall::tests::overrideRestoreExecutablePaths({}, {}); });
    unlock(); const auto lease = window->acquireLease(); choose();
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().contains("permissions non sûres"); }, 3000));
    EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, ChangedApplicationInodeIsRefusedBeforeLockOrPersistentPreparation)
{
    const auto otherApplication = directory.filePath("different-passwall-app");
    QFile file(otherApplication); ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("not executed"), 12); file.close();
    ASSERT_EQ(::chmod(QFile::encodeName(otherApplication).constData(), 0755), 0);
    passwall::tests::overrideRestoreExecutablePaths({}, otherApplication);
    const auto reset = qScopeGuard([] { passwall::tests::overrideRestoreExecutablePaths({}, {}); });
    unlock(); const auto lease = window->acquireLease(); choose();
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().contains("ne correspond plus"); }, 3000));
    EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, WorkerPermissionChangeAfterPreparationIsReportedByTheInterface)
{
    choose(); prepare(); ASSERT_TRUE(record().replacement);
    const auto fakeWorker = directory.filePath("late-unsafe-restore-worker");
    QFile file(fakeWorker); ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("not executed"), 12); file.close();
    ASSERT_EQ(::chmod(QFile::encodeName(fakeWorker).constData(), 0775), 0);
    passwall::tests::overrideRestoreExecutablePaths(fakeWorker, {});
    const auto reset = qScopeGuard([] { passwall::tests::overrideRestoreExecutablePaths({}, {}); });
    const QPointer<RestoreJob> rejected = execute();
    ASSERT_TRUE(waitFor([&] { return status().contains("permissions non sûres")
        && widget<QPushButton>("restoreCancelButton")->text() == "Fermer"; }, 3000));
    EXPECT_TRUE(!rejected || !rejected->isActive());
    EXPECT_FALSE(record().replacement); ASSERT_TRUE(record().resolvedReplacement);
    EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, ChangingAChosenPathInvalidatesTheConfirmation)
{
    choose(); ASSERT_TRUE(widget<QCheckBox>("restoreConfirmationCheck")->isChecked());
    widget<QLineEdit>("restoreSourceEdit")->setText(directory.filePath("another-source.db"));
    EXPECT_FALSE(widget<QCheckBox>("restoreConfirmationCheck")->isChecked());
    widget<QPushButton>("restorePrepareButton")->click(); EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, SourcePickerOffersPwdbAndDbWithAllFilesChoice)
{
    open();
    QPushButton* browse = nullptr;
    for (auto* button : dialog->findChildren<QPushButton*>())
        if (button->text() == "Parcourir…") { browse = button; break; }
    ASSERT_NE(browse, nullptr); browse->click(); QApplication::processEvents();
    auto* picker = dialog->findChild<QFileDialog*>(); ASSERT_NE(picker, nullptr);
    EXPECT_TRUE(picker->nameFilters().contains(
        "Sauvegardes PassWall (*.pwdb *.db)"));
    EXPECT_TRUE(picker->nameFilters().contains("Tous les fichiers (*)"));
    picker->reject();
}
TEST_F(VaultRestoreGuiTest, FullGuiChainRestoresExternalBackupPreservesPrincipalConfigurationAndStaysLocked)
{
    const auto originalSource = bytes(source); const auto originalPrincipal = bytes(principal);
    const auto originalState = encryptedState(principal);
    auto preferences = record().backup; preferences.retainedVersions = 9; QString error;
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(local, preferences, error));
    unlock(); const auto lease = window->acquireLease(); choose(); prepare();
    EXPECT_FALSE(window->isLeaseCurrent(lease)); EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().startsWith("Restauration confirmée")) << status().toStdString();
    EXPECT_TRUE(bytes(source) == originalSource); EXPECT_TRUE(bytes(principal) != originalPrincipal);
    EXPECT_TRUE(encryptedState(precaution) == originalState);
    EXPECT_TRUE(encryptedState(principal) == encryptedState(source)); EXPECT_FALSE(window->acquireLease().unlocked);
    const auto r = record(); EXPECT_TRUE(r.backup == preferences); EXPECT_TRUE(r.automaticVersions.isEmpty());
    EXPECT_FALSE(r.replacement); ASSERT_TRUE(r.resolvedReplacement);
    EXPECT_FALSE(r.resolvedReplacement->recoveryArtifacts.isEmpty());
    for (const auto& path : r.resolvedReplacement->recoveryArtifacts) EXPECT_TRUE(QFile::exists(path));
    SecureBuffer key(0); std::string failure;
    ASSERT_TRUE(VaultLifecycleService::unlockVault(principal.toStdString(), master, key, failure));
    std::vector<passwall::models::CredentialSummary> entries;
    ASSERT_TRUE(CredentialService::listSummaries(principal.toStdString(), key, entries, failure));
    ASSERT_EQ(entries.size(), 1); EXPECT_EQ(entries[0].title, "Fictitious older entry");
    QSettings settings("PassWall", "PassWall"); EXPECT_EQ(settings.value("unrelated/value").toString(), "keep");
    EXPECT_FALSE(bytes(settings.fileName()).contains(master)); EXPECT_FALSE(status().contains(master));
    auto response = window->handleNativeRequest({{"type", "search_credentials"}, {"url", "https://example.test"}});
    ASSERT_TRUE(response.hasPayload()); const auto payload = response.payloadView();
    const auto native = QJsonDocument::fromJson(QByteArray::fromRawData(
        reinterpret_cast<const char*>(payload.data()), payload.size())).object();
    EXPECT_FALSE(native["ok"].toBool()); EXPECT_FALSE(native.contains("password"));
}
TEST_F(VaultRestoreGuiTest, ExplicitOtherPrincipalDoesNotRedirectToTheCurrentlyOpenVault)
{
    const auto other = directory.filePath("other-principal.db");
    ASSERT_TRUE(QFile::copy(suite->filePath("current.db"), other));
    VaultRegistration otherRecord; QString error;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(other, otherRecord, error), VaultRecognition::Registered);
    unlock(); const auto firstBefore = bytes(principal); choose(other); prepare(); ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().startsWith("Restauration confirmée")); EXPECT_TRUE(bytes(principal) == firstBefore);
    EXPECT_TRUE(bytes(other) != firstBefore); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, WrongMasterCannotReplaceOrPublishAnUnlockedSession)
{
    const auto before = bytes(principal); choose(); prepare(); ASSERT_NE(execute("fictitious-wrong-master"), nullptr); done();
    EXPECT_EQ(status(), "Mot de passe maître incorrect") << status().toStdString();
    EXPECT_TRUE(bytes(principal) == before);
    EXPECT_FALSE(window->acquireLease().unlocked); EXPECT_FALSE(record().replacement);
    ASSERT_TRUE(record().resolvedReplacement); EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
    EXPECT_TRUE(widget<QLineEdit>("restoreMasterPasswordEdit")->text().isEmpty());
    EXPECT_FALSE(status().contains("fictitious-wrong-master"));
    unlock();
}
TEST_F(VaultRestoreGuiTest, InvalidSourceCannotReplacePrincipal)
{
    { QFile f(source); ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate)); ASSERT_EQ(f.write("not-a-vault"), 11); }
    unlock(); const auto lease = window->acquireLease(); const auto before = bytes(principal); choose();
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().startsWith("Sauvegarde refusée avant verrouillage"); }, 10000));
    EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_TRUE(bytes(principal) == before);
    EXPECT_FALSE(record().replacement); EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, MissingAndNonRegularSourcesNeverCreatePersistentPreparation)
{
    const auto before = bytes(principal); choose();
    widget<QLineEdit>("restoreSourceEdit")->setText(directory.filePath("missing.db"));
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().startsWith("Sauvegarde refusée avant verrouillage"); }, 10000));
    EXPECT_FALSE(record().replacement); EXPECT_TRUE(bytes(principal) == before);

    const auto fifo = directory.filePath("selected-fifo.db");
    ASSERT_EQ(::mkfifo(QFile::encodeName(fifo).constData(), 0600), 0);
    widget<QLineEdit>("restoreSourceEdit")->setText(fifo);
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().startsWith("Sauvegarde refusée avant verrouillage"); }, 10000));
    EXPECT_FALSE(record().replacement); EXPECT_TRUE(bytes(principal) == before);
}
TEST_F(VaultRestoreGuiTest, StructurallyIncompatibleSqliteNeverCreatesPersistentPreparation)
{
    const auto invalid = directory.filePath("structurally-invalid.db"); sqlite3* database = nullptr;
    ASSERT_EQ(sqlite3_open(QFile::encodeName(invalid).constData(), &database), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(database, "CREATE TABLE unrelated(value TEXT);", nullptr, nullptr, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_close(database), SQLITE_OK);
    ASSERT_EQ(::chmod(QFile::encodeName(invalid).constData(), 0600), 0);
    choose(); widget<QLineEdit>("restoreSourceEdit")->setText(invalid);
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().startsWith("Sauvegarde refusée avant verrouillage"); }, 10000));
    EXPECT_FALSE(record().replacement); EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, PrincipalItselfCannotBeSelectedAsTheBackupSource)
{
    unlock(); const auto lease = window->acquireLease(); choose();
    widget<QLineEdit>("restoreSourceEdit")->setText(principal);
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    ASSERT_TRUE(waitFor([&] { return status().contains("source est le coffre principal"); }, 10000));
    EXPECT_TRUE(window->isLeaseCurrent(lease)); EXPECT_FALSE(record().replacement);
}
TEST_F(VaultRestoreGuiTest, SourceChangedAfterPrevalidationIsRefusedAndPreparedStateIsSafelyAbandoned)
{
    const auto before = encryptedState(principal); choose(); prepare();
    { QFile f(source); ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate)); ASSERT_EQ(f.write("changed-after-prevalidation"), 27); }
    ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().startsWith("Restauration refusée avant engagement")) << status().toStdString();
    EXPECT_FALSE(record().replacement); ASSERT_TRUE(record().resolvedReplacement);
    EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
    EXPECT_EQ(encryptedState(principal), before); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, DifferentCryptographicLineageCannotReplacePrincipal)
{
    source = directory.filePath("other-lineage.db"); SecureBuffer key(0); std::string error;
    ASSERT_TRUE(VaultLifecycleService::createVault(source.toStdString(), master, key, error)); key = SecureBuffer(0);
    const auto before = bytes(principal); choose(); prepare(); ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().contains("autre lignée de coffre")) << status().toStdString();
    EXPECT_FALSE(status().startsWith("Restauration confirmée")); EXPECT_TRUE(bytes(principal) == before);
}
TEST_F(VaultRestoreGuiTest, MissingMandatoryPrecautionDoesNotPrepareOrWrite)
{
    choose(); widget<QLineEdit>("restorePrecautionEdit")->clear();
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    EXPECT_FALSE(record().replacement); EXPECT_FALSE(window->findChild<RestoreJob*>());
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled());
    widget<QLineEdit>("restorePrecautionEdit")->setText(precaution); prepare();
}
TEST_F(VaultRestoreGuiTest, FailedPrecautionPreservesBothExistingFilesAndRefusesSubstitution)
{
    { QFile f(precaution); ASSERT_TRUE(f.open(QIODevice::WriteOnly)); ASSERT_EQ(f.write("keep"), 4); }
    const auto before = bytes(principal); choose(); prepare(); ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().startsWith("Restauration refusée avant engagement")); EXPECT_TRUE(bytes(principal) == before);
    EXPECT_TRUE(bytes(precaution) == "keep");
    EXPECT_FALSE(record().replacement); ASSERT_TRUE(record().resolvedReplacement);
    EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
}
TEST_F(VaultRestoreGuiTest, AutomaticPolicyDoesNotRequireExtraCopyOrAvailableAutomaticDestination)
{
    window.reset(); auto p = record().backup; p.automatic = true; p.directory = directory.filePath("absent-device/backups");
    QString error; ASSERT_TRUE(VaultPreferencesStore().updatePreferences(local, p, error)); newWindow();
    choose(); widget<QLineEdit>("restorePrecautionEdit")->clear(); prepare();
    auto* job = execute(); ASSERT_NE(job, nullptr); bool copyPhaseSeen = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto point) {
        if (point == ReplacementCheckpoint::PrecautionCreated) {
            copyPhaseSeen = true;
            EXPECT_TRUE(status().startsWith("Aucune copie de précaution supplémentaire requise"));
            EXPECT_FALSE(status().contains("Copie de précaution confirmée"));
        }
    });
    done(); EXPECT_TRUE(copyPhaseSeen);
    EXPECT_TRUE(status().startsWith("Restauration confirmée")) << status().toStdString();
    EXPECT_FALSE(QFile::exists(precaution)); EXPECT_FALSE(QFile::exists(p.directory));
    EXPECT_TRUE(record().backup == p); EXPECT_TRUE(record().backupRequired); EXPECT_TRUE(record().automaticVersions.isEmpty());
}
#ifdef PASSWALL_GUI_TESTING
TEST_F(VaultRestoreGuiTest,
    GenerationalPolicyRequiresAndPublishesPrecautionDespiteHistoricalAutomaticTrue)
{
    window.reset();
    QApplication::processEvents();
    auto preferences = record().backup;
    preferences.automatic = true;
    preferences.directory = directory.filePath("unused-historical-destination");
    QString error;
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(
        local, preferences, error)) << error.toStdString();
    newGenerationalWindow();

    choose();
    EXPECT_TRUE(widget<QLineEdit>("restorePrecautionEdit")->isVisible());
    EXPECT_TRUE(widget<QLabel>("restorePolicyLabel")->text().contains(
        "Mode générationnel"));
    widget<QLineEdit>("restorePrecautionEdit")->clear();
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled());

    const auto principalBefore = encryptedState(principal);
    widget<QLineEdit>("restorePrecautionEdit")->setText(precaution);
    prepare();
    auto* job = execute();
    ASSERT_NE(job, nullptr);
    bool precautionConfirmed = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(),
        [&](auto point) {
            if (point == ReplacementCheckpoint::PrecautionCreated) {
                precautionConfirmed = true;
                EXPECT_TRUE(status().startsWith(
                    "Copie de précaution confirmée"));
            }
        });
    done();
    EXPECT_TRUE(precautionConfirmed);
    EXPECT_TRUE(status().startsWith("Restauration confirmée"))
        << status().toStdString();
    EXPECT_EQ(encryptedState(precaution), principalBefore);
    EXPECT_FALSE(QFile::exists(preferences.directory));
    EXPECT_EQ(record().backup, preferences);
}

TEST_F(VaultRestoreGuiTest,
    GenerationalValidGlobalPreferencesNeverDispenseHistoricalPrecaution)
{
    const QString globalRoot = directory.filePath("configured-generation-root");
    ASSERT_TRUE(QDir().mkpath(globalRoot));
    const auto saved = GlobalBackupPreferencesStore().save({globalRoot, 7});
    ASSERT_TRUE(saved.valid()) << saved.diagnostic.toStdString();
    ASSERT_FALSE(record().backup.automatic);

    window.reset();
    QApplication::processEvents();
    newGenerationalWindow();
    choose();
    widget<QLineEdit>("restorePrecautionEdit")->clear();
    widget<QCheckBox>("restoreConfirmationCheck")->setChecked(true);
    widget<QPushButton>("restorePrepareButton")->click();
    EXPECT_TRUE(widget<QLabel>("restorePolicyLabel")->text().contains(
        "Mode générationnel"));
    EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled());
    EXPECT_TRUE(QDir(globalRoot).isEmpty());
}
#endif
TEST_F(VaultRestoreGuiTest, SecurityLockWipesMasterBeforePositiveGlobalAcknowledgement)
{
    choose(); prepare(); widget<QLineEdit>("restoreMasterPasswordEdit")->setText(master); bool acknowledged = false;
    window->requestExternalLock([&](bool clean) {
        acknowledged = clean; EXPECT_TRUE(widget<QLineEdit>("restoreMasterPasswordEdit")->text().isEmpty());
    });
    EXPECT_TRUE(widget<QLineEdit>("restoreMasterPasswordEdit")->text().isEmpty());
    ASSERT_TRUE(waitFor([&] { return acknowledged; }));
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled());
    EXPECT_FALSE(window->findChild<RestoreJob*>()); EXPECT_TRUE(record().replacement);
}
TEST_F(VaultRestoreGuiTest, InactivitySettingDuringSensitiveWorkerNeitherReopensNorCancelsRestore)
{
    Hold hold(directory.filePath("policy-worker-fifo"), "PW_RESTORE_HOLD_PHASE", "0"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr);
    ASSERT_TRUE(job->isActive()) << status().toStdString();
    bool sensitive = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto phase) {
        sensitive = phase == ReplacementCheckpoint::BeforeWork;
    });
    ASSERT_TRUE(waitFor([&] { return sensitive; }));
    auto* timer = window->findChild<QTimer*>("vaultInactivityTimer"); ASSERT_NE(timer, nullptr);
    ASSERT_FALSE(timer->isActive());
    QTimer::singleShot(0, window.get(), [&] {
        auto* setting = window->findChild<QInputDialog*>("autoLockDurationDialog"); ASSERT_NE(setting, nullptr);
        setting->findChild<QComboBox*>()->setCurrentIndex(4); setting->accept();
    });
    window->findChild<QAction*>("autoLockDurationAction")->trigger();
    EXPECT_FALSE(timer->isActive()); EXPECT_FALSE(window->acquireLease().unlocked); EXPECT_TRUE(job->isActive());
    EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 60);
    hold.release(); done();
    EXPECT_TRUE(status().startsWith("Restauration confirmée")); EXPECT_FALSE(timer->isActive());
    unlock(); EXPECT_TRUE(timer->isActive()); EXPECT_EQ(timer->interval(), 3'600'000);
}
TEST_F(VaultRestoreGuiTest, LatePreparationAfterSecurityLockCannotAuthorizeOrEnablePassword)
{
    choose(); bool settled = false, current = true;
    auto* controller = window->findChild<VaultRestoreController*>(); ASSERT_NE(controller, nullptr);
    QObject::connect(controller, &VaultRestoreController::preparationSettled, window.get(), [&](bool c) { settled = true; current = c; });
    widget<QPushButton>("restorePrepareButton")->click();
    window->requestExternalLock([](bool) {}); // Before queued completion, regardless of the background I/O speed.
    ASSERT_TRUE(waitFor([&] { return settled; }, 10000)); EXPECT_FALSE(current);
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled()); EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, IncompatibleReservationRefusesTheRealPreparation)
{
    passwall::storage::VaultOperationGuard guard; std::string error; ASSERT_TRUE(guard.tryReserve(principal.toStdString(), error));
    choose(); bool settled = false;
    QObject::connect(window->findChild<VaultRestoreController*>(), &VaultRestoreController::preparationSettled,
        window.get(), [&](bool) { settled = true; });
    widget<QPushButton>("restorePrepareButton")->click(); ASSERT_TRUE(waitFor([&] { return settled; }));
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled()); EXPECT_FALSE(record().replacement);
}
TEST_F(VaultRestoreGuiTest, ChangedPreferencesCannotReuseThePreviouslyDisplayedConsent)
{
    choose(); auto p = record().backup; p.retainedVersions = 12; QString error;
    ASSERT_TRUE(VaultPreferencesStore().updatePreferences(local, p, error));
    bool settled = false;
    QObject::connect(window->findChild<VaultRestoreController*>(), &VaultRestoreController::preparationSettled,
        window.get(), [&](bool) { settled = true; });
    widget<QPushButton>("restorePrepareButton")->click(); ASSERT_TRUE(waitFor([&] { return settled; }, 10000));
    EXPECT_FALSE(widget<QLineEdit>("restoreMasterPasswordEdit")->isEnabled());
    EXPECT_TRUE(status().contains("ont changé")); EXPECT_FALSE(window->findChild<RestoreJob*>());
}
TEST_F(VaultRestoreGuiTest, CancellationBeforeEngagementUsesTheRealJobAndKeepsPrincipal)
{
    const auto before = bytes(principal); choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr);
    bool observed = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p == ReplacementCheckpoint::BeforeArm) { observed = true; widget<QPushButton>("restoreCancelButton")->click(); }
    });
    done(); EXPECT_TRUE(observed); EXPECT_EQ(status(), "Restauration annulée");
    EXPECT_TRUE(bytes(principal) == before); EXPECT_FALSE(record().replacement);
    ASSERT_TRUE(record().resolvedReplacement); EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
}
TEST_F(VaultRestoreGuiTest, LateCancellationNeverClaimsThatAnExchangedPrincipalWasNotReplaced)
{
    const auto before = bytes(principal); choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p == ReplacementCheckpoint::AfterExchange) widget<QPushButton>("restoreCancelButton")->click();
    });
    done(); EXPECT_TRUE(status().contains("durabilité n'est pas confirmée"));
    EXPECT_TRUE(bytes(principal) != before); EXPECT_FALSE(status().contains("Annulation confirmée"));
}
TEST_F(VaultRestoreGuiTest, ReceivedBusinessResultIsNotSuccessUntilActualProcessTermination)
{
    Hold hold(directory.filePath("result-fifo"), "PW_RESTORE_HOLD_RESULT"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr); bool received = false;
    QObject::connect(job, &RestoreJob::resultReceived, window.get(), [&](auto) { received = true; });
    ASSERT_TRUE(waitFor([&] { return received; }, 15000)); EXPECT_TRUE(job->isActive());
    EXPECT_TRUE(status().contains("Attente de la terminaison")); EXPECT_FALSE(status().startsWith("Restauration confirmée"));
    EXPECT_FALSE(widget<QProgressBar>("restoreActivity")->isHidden()); hold.release(); done();
    EXPECT_TRUE(status().startsWith("Restauration confirmée"));
}
TEST_F(VaultRestoreGuiTest, ClosingTheDialogCancelsButDoesNotDestroyTheSupervisorOrReservation)
{
    const auto before = bytes(principal);
    Hold hold(directory.filePath("phase-fifo"), "PW_RESTORE_HOLD_PHASE", "0"); ASSERT_GE(hold.fd, 0);
    choose(); prepare();
    const auto prepared = record(); ASSERT_TRUE(prepared.replacement);
    const auto operationId = prepared.replacement->operationId;
    auto* job = execute(); ASSERT_NE(job, nullptr); bool phaseSeen = false, terminated = false;
    bool abandonmentResolved = false;
    std::optional<RestoreResult> result;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto) { phaseSeen = true; });
    QObject::connect(job, &RestoreJob::finished, window.get(), [&](auto value) { result = std::move(value); });
    QObject::connect(job, &RestoreJob::processTerminated, window.get(), [&] { terminated = true; });
    QObject::connect(window->statusBar(), &QStatusBar::messageChanged, window.get(),
        [&](const QString& message) {
            if (message == "Restauration annulée") abandonmentResolved = true;
        });
    ASSERT_TRUE(waitFor([&] { return phaseSeen; })); dialog->reject();
    EXPECT_TRUE(job->isActive()); passwall::storage::VaultOperationGuard access; std::string error;
    EXPECT_FALSE(access.tryReserve(principal.toStdString(), error)); hold.release();
    ASSERT_TRUE(waitFor([&] { return terminated; }, 10000));
    ASSERT_TRUE(waitFor([&] { return abandonmentResolved; }, 10000));
    QString recoveryError;
    ASSERT_EQ(VaultPreferencesStore().recoveryAccess(principal, recoveryError),
        VaultRecoveryAccess::Allowed) << recoveryError.toStdString();
    ASSERT_TRUE(result); ASSERT_TRUE(result->replacementStatusKnown);
    EXPECT_EQ(result->outcome, RestoreOutcome::EngineResult);
    EXPECT_EQ(result->replacement.outcome, ReplacementOutcome::CancelledBeforeEngagement);
    EXPECT_EQ(result->replacement.operationId, operationId);
    EXPECT_EQ(bytes(principal), before);
    const auto resolved = record();
    EXPECT_FALSE(resolved.replacement); ASSERT_TRUE(resolved.resolvedReplacement);
    EXPECT_EQ(resolved.resolvedReplacement->operationId, operationId);
    EXPECT_EQ(resolved.resolvedReplacement->phase, "abandoned");
    error.clear(); ASSERT_TRUE(access.tryReserve(principal.toStdString(), error)) << error;
    access.reset(); error.clear();
    EXPECT_TRUE(access.tryReserve(principal.toStdString(), error)) << error;
    access.reset();
}
TEST_F(VaultRestoreGuiTest, DestroyingMainWindowDoesNotWaitForTheHeldChildOrReleaseItsReservation)
{
    Hold hold(directory.filePath("phase-fifo"), "PW_RESTORE_HOLD_PHASE", "0"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr); bool seen = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto) { seen = true; });
    ASSERT_TRUE(waitFor([&] { return seen; }));
    QElapsedTimer time; time.start(); window.reset(); EXPECT_LT(time.elapsed(), 1000);
    passwall::storage::VaultOperationGuard access; std::string error;
    EXPECT_FALSE(access.tryReserve(principal.toStdString(), error)); hold.release();
    ASSERT_TRUE(waitFor([&] { return access.tryReserve(principal.toStdString(), error); }, 10000));
}
TEST_F(VaultRestoreGuiTest, PersistentRecoveryIsVisibleAfterRestartWithoutResetOrNewPreparation)
{
    choose(); prepare(); window->requestExternalLock([](bool) {});
    ASSERT_TRUE(record().replacement); const auto op = record().replacement->operationId;
    window.reset(); QApplication::processEvents(); newWindow(); open();
    widget<QComboBox>("restorePrincipalCombo")->setCurrentIndex(widget<QComboBox>("restorePrincipalCombo")->findText(principal));
    EXPECT_TRUE(widget<QLabel>("restorePolicyLabel")->text().contains("Récupération nécessaire"));
    EXPECT_FALSE(widget<QPushButton>("restorePrepareButton")->isEnabled()); EXPECT_EQ(record().replacement->operationId, op);
    SecureBuffer key(0); std::string error;
    EXPECT_FALSE(VaultLifecycleService::unlockVault(principal.toStdString(), master, key, error)); EXPECT_TRUE(key.empty());
}
TEST_F(VaultRestoreGuiTest, RepeatedMenuRequestsCannotStartAnotherConcurrentRestoration)
{
    Hold hold(directory.filePath("phase-fifo"), "PW_RESTORE_HOLD_PHASE", "0"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr); bool seen = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto) { seen = true; });
    ASSERT_TRUE(waitFor([&] { return seen; })); const auto original = dialog;
    window->findChild<QAction*>("restoreVaultAction")->trigger(); EXPECT_TRUE(dialog == original);
    widget<QPushButton>("restorePrepareButton")->click(); EXPECT_EQ(window->findChildren<RestoreJob*>().size(), 1);
    widget<QPushButton>("restoreCancelButton")->click(); hold.release(); done();
}
TEST_F(VaultRestoreGuiTest, UnknownSupervisionCannotBeUpgradedByALateBusinessNotification)
{
    const auto reset = qScopeGuard([] { passwall::tests::releaseGuiRestoreStop(); });
    passwall::tests::suppressGuiStopsForRestore(true);
    Hold hold(directory.filePath("result-fifo"), "PW_RESTORE_HOLD_RESULT"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr);
    std::optional<RestoreResult> business; bool unknown = false;
    QObject::connect(job, &RestoreJob::resultReceived, window.get(), [&](auto r) { business = r; });
    QObject::connect(job, &RestoreJob::finished, window.get(), [&](auto r) { unknown = r.outcome == RestoreOutcome::Unknown; });
    ASSERT_TRUE(waitFor([&] { return business.has_value(); }, 15000));
    widget<QPushButton>("restoreCancelButton")->click(); ASSERT_TRUE(waitFor([&] { return unknown; }, 7000));
    EXPECT_TRUE(job->isActive()); EXPECT_TRUE(status().startsWith("Résultat incertain"));
    // Consumer-order fault only; real worker/result/Unknown above. Never an authority issuer.
    emit job->resultReceived(*business);
    EXPECT_TRUE(status().startsWith("Résultat incertain"));
    hold.release(); done(); EXPECT_TRUE(status().startsWith("Résultat incertain"));
    dialog->reject(); QApplication::processEvents(); open();
    widget<QComboBox>("restorePrincipalCombo")->setCurrentIndex(widget<QComboBox>("restorePrincipalCombo")->findText(principal));
    EXPECT_FALSE(widget<QPushButton>("restorePrepareButton")->isEnabled());
    EXPECT_TRUE(widget<QLabel>("restorePolicyLabel")->text().contains("Récupération nécessaire"));
}
TEST_F(VaultRestoreGuiTest, WrongPasswordWaitsForActualWorkerTerminationBeforeAutomaticAbandon)
{
    Hold hold(directory.filePath("wrong-master-result-fifo"), "PW_RESTORE_HOLD_RESULT"); ASSERT_GE(hold.fd, 0);
    const auto before = encryptedState(principal); choose(); prepare();
    auto* job = execute("fictitious-wrong-master"); ASSERT_NE(job, nullptr); bool received = false;
    QObject::connect(job, &RestoreJob::resultReceived, window.get(), [&](const auto& result) {
        received = result.outcome == RestoreOutcome::SourceAuthenticationFailed;
    });
    ASSERT_TRUE(waitFor([&] { return received; }, 15000));
    ASSERT_TRUE(job->isActive()); ASSERT_TRUE(record().replacement);
    EXPECT_EQ(record().replacement->phase, "prepared");
    VaultOperationGuard guard; std::string error;
    EXPECT_FALSE(guard.tryReserve(principal.toStdString(), error));
    EXPECT_FALSE(status().startsWith("Mot de passe maître incorrect"));
    hold.release(); done();
    EXPECT_EQ(status(), "Mot de passe maître incorrect"); EXPECT_FALSE(record().replacement);
    EXPECT_EQ(encryptedState(principal), before); EXPECT_TRUE(guard.tryReserve(principal.toStdString(), error));
}
TEST_F(VaultRestoreGuiTest, CancellingPasswordEntryAutomaticallyAbandonsPreparedAndNeverOpensTheVault)
{
    const auto before = encryptedState(principal); choose(); prepare();
    widget<QLineEdit>("restoreMasterPasswordEdit")->setText(master);
    widget<QPushButton>("restoreCancelButton")->click(); done();
    EXPECT_EQ(status(), "Restauration annulée"); EXPECT_FALSE(record().replacement);
    ASSERT_TRUE(record().resolvedReplacement); EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
    EXPECT_EQ(encryptedState(principal), before); EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_FALSE(window->findChild<RestoreJob*>()); unlock();
}
TEST_F(VaultRestoreGuiTest, AutomaticAbandonPersistenceFailureKeepsPreparedAndRequiresManualRecovery)
{
    choose(); prepare(); passwall::tests::failSettingsSync();
    widget<QPushButton>("restoreCancelButton")->click(); done();
    EXPECT_TRUE(status().contains("récupération manuelle nécessaire"));
    ASSERT_TRUE(record().replacement); EXPECT_TRUE(record().replacement->phase == "prepared"
        || record().replacement->phase == "abandon-confirmed");
    EXPECT_FALSE(window->acquireLease().unlocked);
    openRecovery(); examineRecovery(); resolveRecovery();
    EXPECT_FALSE(record().replacement); EXPECT_FALSE(window->acquireLease().unlocked); unlock();
}
TEST_F(VaultRestoreGuiTest, NonEngagedWorkerFailureWithUnconfirmedAbandonKeepsRecoveryRequired)
{
    choose(); prepare();
    { QFile f(source); ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
      ASSERT_EQ(f.write("invalid-after-prevalidation"), 27); }
    passwall::tests::failSettingsSync();
    ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().contains("récupération manuelle nécessaire"));
    ASSERT_TRUE(record().replacement); EXPECT_TRUE(record().replacement->phase == "prepared"
        || record().replacement->phase == "abandon-confirmed");
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, RecoveryRefusesLiveWorkerEvenAfterItHasSentItsBusinessResult)
{
    Hold hold(directory.filePath("recovery-result-fifo"), "PW_RESTORE_HOLD_RESULT"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr); bool received = false;
    QObject::connect(job, &RestoreJob::resultReceived, window.get(), [&](auto) { received = true; });
    ASSERT_TRUE(waitFor([&] { return received; }, 15000)); ASSERT_TRUE(job->isActive());
    openRecovery(); examineRecovery();
    EXPECT_FALSE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("active"));
    hold.release(); done();
}
TEST_F(VaultRestoreGuiTest, RecoveryChangedPrincipalHasNoActionAndDoesNotClearFence)
{
    leavePreparedForRecovery();
    QFile file(principal); ASSERT_TRUE(file.open(QIODevice::Append)); ASSERT_EQ(file.write("x"), 1); file.close();
    openRecovery(); examineRecovery(); EXPECT_FALSE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
    EXPECT_TRUE(record().replacement);
}
TEST_F(VaultRestoreGuiTest, RecoveryArmedAfterExchangeFinalizesWithoutAnotherExchangeOrDeletingOldPrincipal)
{
    const auto before = bytes(principal); choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto phase) {
        if (phase == ReplacementCheckpoint::AfterExchange) widget<QPushButton>("restoreCancelButton")->click();
    });
    done(); ASSERT_TRUE(record().replacement); EXPECT_EQ(record().replacement->phase, "armed");
    const auto artifact = record().replacement->candidate->path;
    ASSERT_EQ(bytes(artifact), before); const auto replaced = bytes(principal);
    openRecovery(); examineRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("déjà effectué"));
    resolveRecovery(); EXPECT_FALSE(record().replacement); EXPECT_EQ(bytes(artifact), before);
    EXPECT_EQ(bytes(principal), replaced); EXPECT_FALSE(window->acquireLease().unlocked); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoverySyncFailureKeepsRestrictionAndExplicitRetryConfirmsDurability)
{
    leavePreparedForRecovery(); openRecovery(); examineRecovery();
    passwall::tests::failSettingsSync(); resolveRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("non confirmée"));
    EXPECT_TRUE(record().replacement); EXPECT_FALSE(window->acquireLease().unlocked);
    examineRecovery(); resolveRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("durablement confirmée")); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoveryArmedBeforeExchangeOffersNoActionAndPreservesBothFiles)
{
    qputenv("PW_RESTORE_CRASH_PHASE", "6"); // Real child exits at BeforeExchange, after durable arm.
    const auto reset = qScopeGuard([] { qunsetenv("PW_RESTORE_CRASH_PHASE"); });
    const auto original = bytes(principal);
    choose(); prepare(); ASSERT_NE(execute(), nullptr); done();
    ASSERT_TRUE(record().replacement); ASSERT_EQ(record().replacement->phase, "armed");
    ASSERT_TRUE(record().replacement->candidate);
    const auto artifact = record().replacement->candidate->path;
    const auto candidate = bytes(artifact);
    window.reset(); QApplication::processEvents(); newWindow();
    openRecovery(); examineRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("avant échange"));
    recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
    EXPECT_FALSE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
    recoveryWidget<QPushButton>("recoveryResolveButton")->click();
    EXPECT_EQ(record().replacement->phase, "armed");
    EXPECT_EQ(bytes(principal), original); EXPECT_EQ(bytes(artifact), candidate);
    SecureBuffer key(0); std::string error;
    EXPECT_FALSE(VaultLifecycleService::unlockVault(principal.toStdString(), master, key, error));
    EXPECT_TRUE(key.empty()); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, RecoveryIdentityConfirmedAfterInterruptedSyncResumesAfterRestart)
{
    qputenv("PW_RESTORE_CRASH_PHASE", "7"); // Actual exchange, no finalization by the child.
    const auto reset = qScopeGuard([] {
        qunsetenv("PW_RESTORE_CRASH_PHASE"); passwall::tests::failSettingsSyncWhenPublished({}, {});
    });
    const auto original = bytes(principal);
    choose(); prepare(); ASSERT_NE(execute(), nullptr); done();
    ASSERT_TRUE(record().replacement); ASSERT_EQ(record().replacement->phase, "armed");
    const auto artifact = record().replacement->candidate->path;
    const auto restored = bytes(principal);
    openRecovery(); examineRecovery();
    passwall::tests::failSettingsSyncWhenPublished(VaultPreferencesStore().fileName(), "identity-confirmed");
    resolveRecovery();
    ASSERT_TRUE(passwall::tests::publishedSettingsSyncFailed());
    ASSERT_TRUE(record().replacement); EXPECT_EQ(record().replacement->phase, "identity-confirmed");
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("non confirmée"));
    window.reset(); QApplication::processEvents(); newWindow();
    openRecovery(); examineRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("déjà effectué"));
    resolveRecovery();
    EXPECT_FALSE(record().replacement); EXPECT_TRUE(record().resolvedReplacement);
    EXPECT_EQ(bytes(principal), restored); EXPECT_EQ(bytes(artifact), original);
    EXPECT_FALSE(window->acquireLease().unlocked); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoveryVisibleAbandonedReceiptWithFailedLastSyncIsNotGuiSuccess)
{
    const auto reset = qScopeGuard([] { passwall::tests::failSettingsSyncWhenPublished({}, {}); });
    choose(); prepare(); widget<QPushButton>("restoreCancelButton")->click(); done();
    EXPECT_FALSE(record().replacement); ASSERT_TRUE(record().resolvedReplacement);
    EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
    const auto original = bytes(principal);
    openRecovery(); examineRecovery();
    passwall::tests::failSettingsSyncWhenPublished(VaultPreferencesStore().fileName(), "abandoned");
    resolveRecovery();
    ASSERT_TRUE(passwall::tests::publishedSettingsSyncFailed());
    EXPECT_FALSE(record().replacement); ASSERT_TRUE(record().resolvedReplacement);
    EXPECT_EQ(record().resolvedReplacement->phase, "abandoned");
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("non confirmée"));
    // The button's visual state reflects logind availability, not this
    // per-recovery latch. Exercise the real authentication entry point.
    window->findChild<QLineEdit*>("unlockPathEdit")->setText(principal);
    window->findChild<QLineEdit*>("unlockPasswordEdit")->setText(master);
    window->findChild<QPushButton*>("unlockVaultButton")->click();
    EXPECT_FALSE(window->acquireLease().unlocked);
    examineRecovery(); resolveRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("durablement confirmée"));
    EXPECT_EQ(bytes(principal), original); EXPECT_FALSE(window->acquireLease().unlocked); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoveryRevokedInspectionCannotOfferActionOrPublishSession)
{
    leavePreparedForRecovery(); openRecovery();
    recoveryWidget<QPushButton>("recoveryInspectButton")->click();
    window->setLifecycleProtectionAvailable(false);
    ASSERT_TRUE(waitFor([&] { return !recoveryWidget<QProgressBar>("recoveryActivity")->isVisible(); }, 10000));
    recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
    EXPECT_FALSE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
    EXPECT_TRUE(record().replacement); EXPECT_FALSE(window->acquireLease().unlocked);
    window->setLifecycleProtectionAvailable(true); examineRecovery(); resolveRecovery(); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoveryAsyncSyncKeepsGuiResponsiveAndDialogCloseDoesNotReleaseReservation)
{
    leavePreparedForRecovery(); openRecovery(); examineRecovery();
    const auto release = qScopeGuard([] { passwall::tests::releaseSettingsSync(); });
    passwall::tests::holdSettingsSync();
    recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
    recoveryWidget<QPushButton>("recoveryResolveButton")->click();
    ASSERT_TRUE(waitFor([] { return passwall::tests::settingsSyncEntered(); }, 10000));
    bool heartbeat = false; QTimer::singleShot(0, [&] { heartbeat = true; });
    ASSERT_TRUE(waitFor([&] { return heartbeat; }));
    VaultOperationGuard guard; std::string error; EXPECT_FALSE(guard.tryReserve(principal.toStdString(), error));
    QTimer::singleShot(0, window.get(), [&] {
        auto* setting = window->findChild<QInputDialog*>("autoLockDurationDialog"); ASSERT_NE(setting, nullptr);
        setting->findChild<QComboBox*>()->setCurrentIndex(1); setting->accept();
    });
    window->findChild<QAction*>("autoLockDurationAction")->trigger();
    // Registry contention refuses persistence without blocking this GUI or
    // releasing the recovery task's guards. A locked vault never rearms.
    auto* timer = window->findChild<QTimer*>("vaultInactivityTimer");
    ASSERT_NE(timer, nullptr); EXPECT_FALSE(timer->isActive());
    EXPECT_FALSE(guard.tryReserve(principal.toStdString(), error));
    recovery->reject(); QApplication::processEvents(); EXPECT_FALSE(guard.tryReserve(principal.toStdString(), error));
    // Reopening does not consume the old delivery or turn it into a new offer.
    window->findChild<QAction*>("recoverVaultAction")->trigger();
    for (auto* w : QApplication::topLevelWidgets())
        if (w->objectName() == "vaultRecoveryDialog") recovery = qobject_cast<QDialog*>(w);
    ASSERT_TRUE(recovery); EXPECT_TRUE(recoveryWidget<QProgressBar>("recoveryActivity")->isVisible());
    bool settled = false;
    QObject observer;
    QObject::connect(window->findChild<passwall::gui::VaultRecoveryController*>(), &passwall::gui::VaultRecoveryController::settled,
        &observer, [&](bool current) { EXPECT_FALSE(current); settled = true; });
    passwall::tests::releaseSettingsSync(); ASSERT_TRUE(waitFor([&] { return settled; }, 10000));
    EXPECT_TRUE(guard.tryReserve(principal.toStdString(), error));
    EXPECT_FALSE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("Ancienne opération"));
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, RecoverySecurityLockRevokesDeferredResolutionAndOldReplyCannotAuthorizeAccess)
{
    leavePreparedForRecovery(); openRecovery(); examineRecovery();
    const auto release = qScopeGuard([] { passwall::tests::releaseSettingsSync(); }); passwall::tests::holdSettingsSync();
    recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
    recoveryWidget<QPushButton>("recoveryResolveButton")->click();
    ASSERT_TRUE(waitFor([] { return passwall::tests::settingsSyncEntered(); }, 10000));
    bool locked = false; window->requestExternalLock([&](bool clean) { locked = clean; });
    ASSERT_TRUE(waitFor([&] { return locked; })); passwall::tests::releaseSettingsSync();
    ASSERT_TRUE(waitFor([&] { return !recoveryWidget<QProgressBar>("recoveryActivity")->isVisible(); }, 10000));
    EXPECT_TRUE(record().replacement); EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("non confirmée"));
    examineRecovery(); resolveRecovery(); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoveryClosingMainWindowNeverWaitsForDiskSyncOrDropsItsExclusion)
{
    leavePreparedForRecovery(); openRecovery(); examineRecovery();
    const auto release = qScopeGuard([] { passwall::tests::releaseSettingsSync(); }); passwall::tests::holdSettingsSync();
    recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
    recoveryWidget<QPushButton>("recoveryResolveButton")->click();
    ASSERT_TRUE(waitFor([] { return passwall::tests::settingsSyncEntered(); }, 10000));
    QElapsedTimer time; time.start(); window.reset(); EXPECT_LT(time.elapsed(), 1000);
    VaultOperationGuard guard; std::string error;
    EXPECT_FALSE(guard.tryReserve(principal.toStdString(), error));
    passwall::tests::releaseSettingsSync();
    ASSERT_TRUE(waitFor([&] { return guard.tryReserve(principal.toStdString(), error); }, 10000)); guard.reset();
    EXPECT_TRUE(record().replacement); newWindow(); openRecovery(); examineRecovery(); resolveRecovery(); unlock();
}
TEST_F(VaultRestoreGuiTest, RecoveryLateResultCannotActOnAnotherVaultSelection)
{
    leavePreparedForRecovery();
    const auto other = directory.filePath("another-principal.db"); ASSERT_TRUE(QFile::copy(source, other));
    VaultRegistration registered; QString error;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(other, registered, error), VaultRecognition::Registered);
    bool prepared = false;
    window->requestReplacementAuthorization(registered.localId, [&](auto authority, auto) { prepared = !authority.operationId().isEmpty(); });
    ASSERT_TRUE(waitFor([&] { return prepared; }, 10000));
    openRecovery(); examineRecovery();
    const auto release = qScopeGuard([] { passwall::tests::releaseSettingsSync(); }); passwall::tests::holdSettingsSync();
    recoveryWidget<QCheckBox>("recoveryConfirmationCheck")->setChecked(true);
    recoveryWidget<QPushButton>("recoveryResolveButton")->click();
    ASSERT_TRUE(waitFor([] { return passwall::tests::settingsSyncEntered(); }, 10000));
    auto* combo = recoveryWidget<QComboBox>("recoveryVaultCombo"); const auto index = combo->findText(other); ASSERT_GE(index, 0);
    combo->setCurrentIndex(index); // Deliberately force a stale delivery, despite the disabled user control.
    passwall::tests::releaseSettingsSync();
    ASSERT_TRUE(waitFor([&] { return !recoveryWidget<QProgressBar>("recoveryActivity")->isVisible(); }, 10000));
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("Ancienne opération"));
    EXPECT_FALSE(recoveryWidget<QPushButton>("recoveryResolveButton")->isEnabled());
    QVector<VaultRegistration> records; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    for (const auto& r : records) if (r.localId == registered.localId) EXPECT_TRUE(r.replacement);
}
TEST_F(VaultRestoreGuiTest, RecoveryResolvedReplacementIsOnlyReconfirmedAndOldPrincipalIsRetained)
{
    const auto before = bytes(principal); choose(); prepare(); ASSERT_NE(execute(), nullptr); done();
    ASSERT_TRUE(record().resolvedReplacement); const auto op = record().resolvedReplacement->operationId;
    const auto artifact = record().resolvedReplacement->candidate->path; const auto replaced = bytes(principal);
    openRecovery(); examineRecovery();
    EXPECT_TRUE(recoveryWidget<QLabel>("recoveryStatusLabel")->text().contains("déjà résolu"));
    resolveRecovery(); EXPECT_EQ(record().resolvedReplacement->operationId, op);
    EXPECT_EQ(bytes(principal), replaced); EXPECT_EQ(bytes(artifact), before); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(VaultRestoreGuiTest, RecoveryActualWorkerCrashBeforeArmLeavesPreparedForControlledRecovery)
{
    qputenv("PW_RESTORE_CRASH_PHASE", "0");
    const auto reset = qScopeGuard([] { qunsetenv("PW_RESTORE_CRASH_PHASE"); });
    choose(); prepare(); ASSERT_NE(execute(), nullptr); done(); ASSERT_TRUE(record().replacement);
    EXPECT_EQ(record().replacement->phase, "prepared");
    qunsetenv("PW_RESTORE_CRASH_PHASE");
    window.reset(); QApplication::processEvents(); newWindow();
    openRecovery(); examineRecovery(); resolveRecovery(); EXPECT_FALSE(record().replacement); unlock();
}
TEST(VaultRestoreDialogTest, Utf8PasswordIsExactAndGuiFieldIsClearedBeforeReturningOwnership)
{
    VaultRestoreDialog dialog; const QString value = QStringLiteral("  fictif-é-密碼  ");
    dialog.findChild<QLineEdit*>("restoreMasterPasswordEdit")->setText(value);
    const auto expected = value.toUtf8(); auto owned = dialog.takePassword();
    EXPECT_TRUE(owned.size() == std::size_t(expected.size()) && std::memcmp(owned.data(), expected.constData(), owned.size()) == 0);
    EXPECT_FALSE(dialog.hasPassword());
}
class VaultRestoreResultTest : public ::testing::TestWithParam<ReplacementOutcome> {};
TEST_P(VaultRestoreResultTest, EachOutcomeHasConservativePresentationAndNeverSucceedsBeforeTermination)
{
    RestoreResult r; r.outcome = RestoreOutcome::EngineResult; r.replacementStatusKnown = true;
    r.replacement.outcome = GetParam(); r.replacement.finalization.state = ReplacementFinalizationState::Resolved;
    EXPECT_FALSE(VaultRestoreDialog::resultMessage(r, false, true).startsWith("Restauration confirmée"));
    EXPECT_FALSE(VaultRestoreDialog::resultMessage(r, true, false).startsWith("Restauration confirmée"));
    EXPECT_EQ(VaultRestoreDialog::resultMessage(r, true, true).startsWith("Restauration confirmée"), GetParam() == ReplacementOutcome::Replaced);
    r.outcome = RestoreOutcome::Unknown;
    EXPECT_TRUE(VaultRestoreDialog::resultMessage(r, true, true).startsWith("Résultat incertain"));
}
INSTANTIATE_TEST_SUITE_P(Outcomes, VaultRestoreResultTest, ::testing::Values(ReplacementOutcome::NotReplaced,
    ReplacementOutcome::CancelledBeforeEngagement, ReplacementOutcome::EngagedRecoveryRequired,
    ReplacementOutcome::ReplacedDurabilityUnconfirmed, ReplacementOutcome::ReplacedFinalizationPending, ReplacementOutcome::Replaced));
} // namespace
