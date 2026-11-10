#include "gui/main_window.hpp"
#include "gui/vault_restore_dialog.hpp"
#include "gui/vault_restore_controller.hpp"
#include "services/credential_service.hpp"
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
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScopeGuard>
#include <QSettings>
#include <QTemporaryDir>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sodium.h>
#include <sqlite3.h>

namespace passwall::tests { void suppressGuiStopsForRestore(bool); void releaseGuiRestoreStop(); }

namespace {
using namespace passwall::services;
using passwall::core::SecureBuffer;
using passwall::gui::MainWindow;
using passwall::gui::VaultRestoreDialog;
using passwall::gui::VaultRestoreController;
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
        window = std::make_unique<MainWindow>();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true); window->show();
    }
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
TEST_F(VaultRestoreGuiTest, ChangingAChosenPathInvalidatesTheConfirmation)
{
    choose(); ASSERT_TRUE(widget<QCheckBox>("restoreConfirmationCheck")->isChecked());
    widget<QLineEdit>("restoreSourceEdit")->setText(directory.filePath("another-source.db"));
    EXPECT_FALSE(widget<QCheckBox>("restoreConfirmationCheck")->isChecked());
    widget<QPushButton>("restorePrepareButton")->click(); EXPECT_FALSE(record().replacement);
    EXPECT_FALSE(window->findChild<RestoreJob*>());
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
    EXPECT_TRUE(status().contains("Mot de passe maître incorrect")); EXPECT_TRUE(bytes(principal) == before);
    EXPECT_FALSE(window->acquireLease().unlocked); EXPECT_TRUE(record().replacement);
    EXPECT_TRUE(widget<QLineEdit>("restoreMasterPasswordEdit")->text().isEmpty());
    EXPECT_FALSE(status().contains("fictitious-wrong-master"));
}
TEST_F(VaultRestoreGuiTest, InvalidSourceCannotReplacePrincipal)
{
    { QFile f(source); ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Truncate)); ASSERT_EQ(f.write("not-a-vault"), 11); }
    const auto before = bytes(principal); choose(); prepare(); ASSERT_NE(execute(), nullptr); done();
    EXPECT_TRUE(status().startsWith("Échec avant remplacement")); EXPECT_TRUE(bytes(principal) == before);
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
    EXPECT_TRUE(status().startsWith("Échec avant remplacement")); EXPECT_TRUE(bytes(principal) == before);
    EXPECT_TRUE(bytes(precaution) == "keep");
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
    done(); EXPECT_TRUE(observed); EXPECT_TRUE(status().startsWith("Annulation confirmée"));
    EXPECT_TRUE(bytes(principal) == before); EXPECT_TRUE(record().replacement);
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
    Hold hold(directory.filePath("phase-fifo"), "PW_RESTORE_HOLD_PHASE", "0"); ASSERT_GE(hold.fd, 0);
    choose(); prepare(); auto* job = execute(); ASSERT_NE(job, nullptr); bool phaseSeen = false, terminated = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto) { phaseSeen = true; });
    QObject::connect(job, &RestoreJob::processTerminated, window.get(), [&] { terminated = true; });
    ASSERT_TRUE(waitFor([&] { return phaseSeen; })); dialog->reject();
    EXPECT_TRUE(job->isActive()); passwall::storage::VaultOperationGuard access; std::string error;
    EXPECT_FALSE(access.tryReserve(principal.toStdString(), error)); hold.release();
    ASSERT_TRUE(waitFor([&] { return terminated; }, 10000)); EXPECT_TRUE(access.tryReserve(principal.toStdString(), error));
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
