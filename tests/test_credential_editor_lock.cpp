#include "gui/credential_editor_context.hpp"
#include "gui/global_backup_preferences_controller.hpp"
#include "gui/global_backup_preferences_dialog.hpp"
#include "gui/generational_backup_status_controller.hpp"
#include "gui/main_window.hpp"
#include "services/credential_service.hpp"
#include "services/automatic_backup_coordinator.hpp"
#include "services/backup_job.hpp"
#include "services/backup_series_identity.hpp"
#include "services/restore_protocol.hpp"
#include "storage/vault_operation_guard.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/global_backup_preferences_store.hpp"
#include "services/generational_backup_rotation_controller.hpp"
#ifdef Q_OS_LINUX
#include "fake_login1_backend.hpp"
#include "platform/linux_instance_lock.hpp"
#include "platform/session_lock_service.hpp"
#include "private_dbus.hpp"
#include <QDBusPendingReply>
#include <optional>
#endif

#include <gtest/gtest.h>
#include <sodium.h>
#include <sqlite3.h>

#include <QAbstractItemModel>
#include <QAction>
#include <QComboBox>
#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDirIterator>
#include <QEvent>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QInputDialog>
#include <QKeyEvent>
#include <QLineEdit>
#include <QLabel>
#include <QJsonDocument>
#include <QListWidget>
#include <QMessageBox>
#include <QLockFile>
#include <QPushButton>
#include <QSettings>
#include <QStringList>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTemporaryDir>
#include <QTextEdit>
#include <QToolButton>
#include <QTimer>
#include <QScopeGuard>
#include <QSignalBlocker>
#include <cstring>
#include <cstdio>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#ifdef Q_OS_LINUX
namespace passwall::tests {
QString restoreWorkerPathOverride;
QString restoreApplicationPathOverride;
void setBackupSettingsTestWorker(QString path);
void overrideRestoreExecutablePaths(const QString& worker, const QString& application)
{
    restoreWorkerPathOverride = worker;
    restoreApplicationPathOverride = application;
}
}
extern "C" QString wrappedRestoreWorkerPath() asm("__wrap__ZN8passwall8services10RestoreJob17siblingWorkerPathEv");
extern "C" QString wrappedRestoreWorkerPath() {
    return passwall::tests::restoreWorkerPathOverride.isEmpty()
        ? QString::fromUtf8(RESTORE_TEST_WORKER) : passwall::tests::restoreWorkerPathOverride;
}
extern "C" QString wrappedRestoreApplicationPath() asm("__wrap__ZN8passwall8services10RestoreJob22siblingApplicationPathEv");
extern "C" QString wrappedRestoreApplicationPath() {
    return passwall::tests::restoreApplicationPathOverride.isEmpty()
        ? QCoreApplication::applicationFilePath() : passwall::tests::restoreApplicationPathOverride;
}
namespace {
std::atomic<bool> pausePreparationSync{false}, preparationSyncEntered{false}, releasePreparationSync{false};
std::atomic<bool> failPreparationSync{false};
std::mutex preparationSyncMutex;
std::condition_variable preparationSyncCondition;
struct RotationCheckpointPause {
    passwall::services::BackupSeriesRotationCheckpoint checkpoint =
        passwall::services::BackupSeriesRotationCheckpoint::BeforeInspection;
    std::atomic_bool entered{false};
    std::atomic_bool released{false};
    std::mutex mutex;
    std::condition_variable condition;
};
void pauseGenerationalRotation(void* raw,
    passwall::services::BackupSeriesRotationCheckpoint checkpoint) noexcept
{
    auto& pause = *static_cast<RotationCheckpointPause*>(raw);
    if (checkpoint != pause.checkpoint
        || pause.entered.exchange(true))
        return;
    std::unique_lock lock(pause.mutex);
    pause.condition.wait(lock, [&] { return pause.released.load(); });
}
std::mutex phaseSyncMutex;
QString phaseSyncPath;
QByteArray phaseSyncMarker;
std::atomic<bool> phaseSyncFailed{false};
const auto guiTestThread = std::this_thread::get_id();
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd) {
    // GUI recovery tests only: fail the actual registry fsync AFTER the
    // requested phase is visible, not an unrelated vault/directory sync.
    {
        std::lock_guard lock(phaseSyncMutex);
        if (!phaseSyncPath.isEmpty() && std::this_thread::get_id() != guiTestThread) {
            char link[64], path[4096];
            const int length = std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            const auto size = length > 0 && length < int(sizeof(link)) ? ::readlink(link, path, sizeof(path)) : -1;
            const auto expected = QFile::encodeName(phaseSyncPath);
            if (size == expected.size() && std::memcmp(path, expected.constData(), size) == 0) {
                QFile file(phaseSyncPath);
                if (file.open(QIODevice::ReadOnly) && file.readAll().contains(phaseSyncMarker)) {
                    phaseSyncPath.clear(); phaseSyncFailed = true;
                    errno = EIO; return -1;
                }
            }
        }
    }
    if (std::this_thread::get_id() != guiTestThread && failPreparationSync.exchange(false)) {
        errno = EIO; return -1;
    }
    if (pausePreparationSync && std::this_thread::get_id() != guiTestThread) {
        preparationSyncEntered = true;
        std::unique_lock lock(preparationSyncMutex);
        preparationSyncCondition.wait(lock, [] { return releasePreparationSync.load(); });
    }
    return __real_fsync(fd);
}
namespace {
thread_local QString restoreGrantFault;
thread_local int restoreSendSlice = 0, restoreSendInterruptions = 0;
thread_local bool restorePasswordHeaderSent = false;
}
extern "C" ssize_t __real_send(int, const void*, size_t, int);
extern "C" ssize_t __wrap_send(int fd, const void* data, size_t size, int flags) {
    namespace wire = passwall::services::restore_protocol;
    const auto* bytes = static_cast<const char*>(data);
    if (size >= 5 && static_cast<unsigned char>(bytes[4]) == wire::Password
        && qFromLittleEndian<quint32>(bytes) <= wire::passwordLimit) restorePasswordHeaderSent = true;
    if (size > 5 && static_cast<unsigned char>(bytes[4]) == wire::Begin && !restoreGrantFault.isEmpty()) {
        const auto original = QByteArray::fromRawData(bytes + 5, size - 5);
        auto message = QJsonDocument::fromJson(original).object(); auto grant = message["grant"].toObject();
        const auto different = [](QString value) { value[0] = value[0] == '0' ? '1' : '0'; return value; };
        if (restoreGrantFault == "uuid") grant["operation"] = message["operation"] = different(message["operation"].toString());
        if (restoreGrantFault == "principal") grant["principal"] = grant["principal"].toString() + ".other";
        if (restoreGrantFault == "vault") grant["vault"] = different(grant["vault"].toString());
        if (restoreGrantFault == "inode") grant["inode"] = "0";
        if (restoreGrantFault == "policy") grant["precaution-policy"] = "invalid";
        if (restoreGrantFault == "session") message["session"] = different(message["session"].toString());
        if (restoreGrantFault == "protocol") message["v"] = 2;
        message["grant"] = grant;
        auto changed = QJsonDocument(message).toJson(QJsonDocument::Compact);
        const auto header = wire::header(wire::Begin, changed.size());
        changed.prepend(header.data(), header.size());
        if (restoreGrantFault == "duplicate") changed += changed;
        const auto sent = __real_send(fd, changed.constData(), changed.size(), flags);
        return sent == changed.size() ? ssize_t(size) : -1;
    }
    if (restoreSendInterruptions > 0) { errno = restoreSendInterruptions-- == 2 ? EINTR : EAGAIN; return -1; }
    return __real_send(fd, data, restoreSendSlice ? std::min<size_t>(size, restoreSendSlice) : size, flags);
}
namespace passwall::tests {
// Reuse the existing background fsync barrier for settings GUI tests too.
void holdSettingsSync() {
    preparationSyncEntered = false; releasePreparationSync = false; pausePreparationSync = true;
}
bool settingsSyncEntered() { return preparationSyncEntered.load(); }
void releaseSettingsSync() {
    releasePreparationSync = true; pausePreparationSync = false; preparationSyncCondition.notify_all();
}
void failSettingsSync() { failPreparationSync = true; }
void failSettingsSyncWhenPublished(const QString& path, const QByteArray& marker) {
    std::lock_guard lock(phaseSyncMutex);
    phaseSyncPath = path; phaseSyncMarker = marker; phaseSyncFailed = false;
}
bool publishedSettingsSyncFailed() { return phaseSyncFailed.load(); }
void suppressGuiStopsForRestore(bool);
bool guiRestoreStopWasRequested();
void releaseGuiRestoreStop();
}
#endif

#include <functional>
#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using passwall::core::SecureBuffer;
using passwall::gui::CredentialEditorContext;
using passwall::gui::MainWindow;
using passwall::gui::detail::wipeCredential;
using passwall::models::Credential;
using passwall::native::VaultLease;
using passwall::services::CredentialService;

// Données exclusivement fictives. Les assertions sur les secrets utilisent
// des booléens pour ne pas imprimer leur contenu en cas d'échec.
Credential makeCredential()
{
    Credential credential;
    credential.id.fill(0x42);
    credential.title = "Compte fictif";
    credential.url = "https://example.test";
    credential.username = "utilisateur-fictif";
    credential.password = "fictitious-password-initial";
    credential.notes = "fictitious-notes-initial";
    return credential;
}

#ifdef Q_OS_LINUX
QString generationalStatusDiagnostic(
    const passwall::services::AutomaticBackupCoordinator* coordinator,
    const passwall::gui::GenerationalBackupStatusController* status,
    const QString& vaultPath, qsizetype publicationCount,
    qsizetype rotationCount)
{
    if (!coordinator || !status)
        return QStringLiteral("contrôleur de diagnostic absent");
    const auto operation = coordinator->generationalOperationState(vaultPath);
    const auto suspension = coordinator->generationalBackupSuspension(vaultPath);
    return QStringLiteral(
        "backup='%1'; backupDetail='%2'; lastBackup='%3'; "
        "lastBackupDetail='%4'; rotation='%5'; rotationDetail='%6'; "
        "suspended=%7; suspensionReason=%8; suspensionWorkerAlive=%9; "
        "resumeRequested=%10; phase=%11; operationWorkerAlive=%12; "
        "requestId=%13; mutationGeneration=%14; sessionGeneration=%15; "
        "publications=%16; rotations=%17; suspensionVaultId=%18; "
        "device=%19; inode=%20")
        .arg(status->backupStatus(), status->backupDetail(),
            status->lastBackupResultStatus(),
            status->lastBackupResultDetail())
        .arg(status->rotationStatus(), status->rotationDetail())
        .arg(suspension.suspended)
        .arg(static_cast<int>(suspension.reason))
        .arg(suspension.workerAlive)
        .arg(suspension.resumeRequested)
        .arg(static_cast<int>(operation.phase))
        .arg(operation.workerAlive)
        .arg(operation.requestId)
        .arg(operation.mutationGeneration)
        .arg(operation.sessionGeneration)
        .arg(publicationCount)
        .arg(rotationCount)
        .arg(QString::fromLatin1(suspension.vaultId.toHex()))
        .arg(suspension.device)
        .arg(suspension.inode);
}

QString vaultCorrelationDiagnostic(
    const passwall::services::VaultFileIdentity& expected,
    const passwall::services::VaultFileIdentity& received)
{
    return QStringLiteral(
        "expected={path='%1', vaultId=%2, device=%3, inode=%4, birth='%5'}; "
        "received={path='%6', vaultId=%7, device=%8, inode=%9, birth='%10'}")
        .arg(expected.path, QString::fromLatin1(expected.vaultId.toHex()))
        .arg(expected.device)
        .arg(expected.inode)
        .arg(expected.birthTime)
        .arg(received.path, QString::fromLatin1(received.vaultId.toHex()))
        .arg(received.device)
        .arg(received.inode)
        .arg(received.birthTime);
}
#endif

struct EditorFields {
    QDialog dialog;
    QLineEdit title{&dialog};
    QLineEdit url{&dialog};
    QLineEdit username{&dialog};
    QLineEdit password{&dialog};
    QTextEdit notes{&dialog};

    void bind(CredentialEditorContext& context)
    {
        title.setText(QStringLiteral("Compte fictif"));
        url.setText(QStringLiteral("https://example.test"));
        username.setText(QStringLiteral("utilisateur-fictif"));
        password.setText(QStringLiteral("fictitious-password-initial"));
        notes.setPlainText(QStringLiteral("fictitious-notes-initial"));
        context.bindDialog(dialog, title, url, username, password, notes);
    }

    void expectEmpty() const
    {
        EXPECT_TRUE(title.text().isEmpty());
        EXPECT_TRUE(url.text().isEmpty());
        EXPECT_TRUE(username.text().isEmpty());
        EXPECT_TRUE(password.text().isEmpty());
        EXPECT_TRUE(notes.toPlainText().isEmpty());
    }
};

TEST(CredentialEditorContextTest, WipesBeforeRejectWithoutWaitingForAnyNotification)
{
    Credential credential = makeCredential();
    EditorFields fields;
    CredentialEditorContext context(credential, {true, 1});
    fields.bind(context);
    QDialog notification;
    notification.show();
    fields.dialog.show();
    bool rejected = false;
    QObject::connect(&fields.dialog, &QDialog::rejected, &context, [&]() {
        rejected = true;
        EXPECT_TRUE(notification.isVisible());
        EXPECT_TRUE(credential.password.empty());
        EXPECT_TRUE(credential.notes.empty());
        EXPECT_TRUE(credential.title.empty());
        EXPECT_TRUE(credential.id == passwall::models::EntryId{});
        EXPECT_EQ(credential.version, 0U);
        fields.expectEmpty();
        EXPECT_FALSE(context.canCommit({true, 1}));
    });

    context.invalidate();
    EXPECT_FALSE(rejected);
    EXPECT_TRUE(fields.dialog.isVisible());
    EXPECT_TRUE(credential.password.empty());
    EXPECT_TRUE(credential.notes.empty());
    fields.expectEmpty();
    context.rejectDialog();

    EXPECT_TRUE(rejected);
    EXPECT_TRUE(notification.isVisible());
    EXPECT_FALSE(fields.dialog.isEnabled());
    fields.expectEmpty();
}

TEST(CredentialEditorContextTest, RepeatedAndReentrantInvalidationIsSafe)
{
    Credential credential = makeCredential();
    EditorFields fields;
    CredentialEditorContext context(credential, {true, 1});
    fields.bind(context);
    int rejections = 0;
    QObject::connect(&fields.dialog, &QDialog::rejected, &context, [&]() {
        ++rejections;
        context.invalidate();
        context.rejectDialog();
    });

    context.invalidate();
    context.rejectDialog();
    context.invalidate();
    context.rejectDialog();

    EXPECT_EQ(rejections, 1);
    EXPECT_TRUE(credential.password.empty());
    EXPECT_TRUE(credential.notes.empty());
    fields.expectEmpty();
}

TEST(CredentialEditorContextTest, CannotCommitAfterLockOrNewSession)
{
    Credential credential = makeCredential();
    CredentialEditorContext context(credential, {true, 1});
    EXPECT_TRUE(context.canCommit({true, 1}));
    EXPECT_FALSE(context.canCommit({false, 2}));
    EXPECT_FALSE(context.canCommit({true, 3}));
    context.invalidate();
    EXPECT_FALSE(context.canCommit({true, 1}));
    EXPECT_FALSE(context.canCommit({true, 3}));
}

TEST(CredentialEditorContextTest, AllCredentialsCanBeWipedBeforeAnyDialogRejects)
{
    Credential first = makeCredential();
    Credential second = makeCredential();
    EditorFields firstFields;
    EditorFields secondFields;
    CredentialEditorContext firstContext(first, {true, 1});
    CredentialEditorContext secondContext(second, {true, 1});
    firstFields.bind(firstContext);
    secondFields.bind(secondContext);
    bool checked = false;
    QObject::connect(&firstFields.dialog, &QDialog::rejected, &firstContext, [&]() {
        checked = true;
        EXPECT_TRUE(first.password.empty());
        EXPECT_TRUE(first.notes.empty());
        EXPECT_TRUE(second.password.empty());
        EXPECT_TRUE(second.notes.empty());
        secondFields.expectEmpty();
    });
    firstContext.invalidate();
    secondContext.invalidate();
    firstContext.rejectDialog();
    secondContext.rejectDialog();
    EXPECT_TRUE(checked);
}

TEST(CredentialEditorContextTest, DestroyedDialogLeavesNoDanglingWidgetAccess)
{
    Credential credential = makeCredential();
    CredentialEditorContext context(credential, {true, 1});
    {
        EditorFields fields;
        fields.bind(context);
    }
    context.invalidate();
    EXPECT_TRUE(credential.password.empty());
    EXPECT_TRUE(credential.notes.empty());
}

TEST(CredentialEditorContextTest, InvalidatedContextCannotBindANewUsableDialog)
{
    Credential credential = makeCredential();
    CredentialEditorContext context(credential, {true, 1});
    context.invalidate();
    EditorFields fields;
    fields.bind(context);
    fields.expectEmpty();
    EXPECT_TRUE(context.isInvalidated());
    EXPECT_FALSE(context.canCommit({true, 1}));
    EXPECT_FALSE(fields.dialog.isEnabled());
}

TEST(CredentialEditorContextTest, ScopeExitStillWipesOnException)
{
    Credential credential = makeCredential();
    try {
        CredentialEditorContext context(credential, {true, 1});
        throw std::runtime_error("synthetic-editor-error");
    } catch (const std::runtime_error&) {
    }
    EXPECT_TRUE(credential.password.empty());
    EXPECT_TRUE(credential.notes.empty());
}

class MainWindowEditorLockTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suiteDirectory;
    static inline SecureBuffer verificationKey{0};
    static inline passwall::models::EntryId entryId{};
    std::unique_ptr<QTemporaryDir> testDirectory;
    std::unique_ptr<MainWindow> window;
    QString vaultPath;

    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        const auto root = qEnvironmentVariable("PW_RESTORE_PARENT_ROOT");
        suiteDirectory = std::make_unique<QTemporaryDir>(root.isEmpty()
            ? QStringLiteral("/tmp/passwall-editor-lock-suite-XXXXXX") : root + "/suite-XXXXXX");
        ASSERT_TRUE(suiteDirectory->isValid());
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                           suiteDirectory->path());
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope,
                           suiteDirectory->path());

        std::string error;
        ASSERT_TRUE(passwall::services::VaultLifecycleService::createVault(
            suiteDirectory->filePath(QStringLiteral("template.pwdb")).toStdString(),
            "fictitious-master-password", verificationKey, error));
        Credential credential = makeCredential();
        const bool added = CredentialService::add(
            suiteDirectory->filePath(QStringLiteral("template.pwdb")).toStdString(),
            verificationKey, credential, error);
        entryId = credential.id;
        wipeCredential(credential);
        ASSERT_TRUE(added);
    }

    static void TearDownTestSuite()
    {
        verificationKey = SecureBuffer(0);
        suiteDirectory.reset();
    }

    void SetUp() override
    {
        const auto root = qEnvironmentVariable("PW_RESTORE_PARENT_ROOT");
        testDirectory = std::make_unique<QTemporaryDir>(root.isEmpty()
            ? QStringLiteral("/tmp/passwall-editor-lock-case-XXXXXX") : root + "/case-XXXXXX");
        ASSERT_TRUE(testDirectory->isValid());
        vaultPath = testDirectory->filePath(QStringLiteral("vault.pwdb"));
        ASSERT_TRUE(QFile::copy(
            suiteDirectory->filePath(QStringLiteral("template.pwdb")), vaultPath));
        // Each case opens a copy with the same vault_id then removes it. Do not
        // reuse the previous case's registry (a missing original is deliberately
        // ambiguous); preserve the original assertions on locking/dialogs.
        QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, testDirectory->path());
        QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, testDirectory->path());
        QSettings settings("PassWall", "PassWall");
        settings.setValue("security/autoLockMinutes", 1);
        settings.setValue("vault/lastPath", vaultPath);
        window = MainWindow::createForHistoricalTests();
        // Existing editor/timer tests inject available lifecycle protection;
        // dedicated Linux tests below exercise the actual monitor handshake.
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        runBounded([&]() { unlock(); });
        ASSERT_TRUE(window->acquireLease().unlocked);
        auto* list = window->findChild<QListWidget*>(QStringLiteral("credentialsList"));
        ASSERT_NE(list, nullptr);
        ASSERT_EQ(list->count(), 1);
        list->setCurrentRow(0);
    }

    void TearDown() override
    {
        window.reset();
        testDirectory.reset();
        QApplication::processEvents();
    }

    void runBounded(const std::function<void()>& action)
    {
        QTimer watchdog;
        watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, [&]() {
            ADD_FAILURE() << "Une interaction modale inattendue a bloque le test.";
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* dialog = qobject_cast<QDialog*>(widget)) {
                    dialog->reject();
                }
            }
        });
        watchdog.start(5000);
        action();
        watchdog.stop();
    }

    void unlock()
    {
        window->findChild<QPushButton*>(QStringLiteral("openPageButton"))->click();
        window->findChild<QLineEdit*>(QStringLiteral("unlockPathEdit"))->setText(vaultPath);
        window->findChild<QLineEdit*>(QStringLiteral("unlockPasswordEdit"))->setText(
            QStringLiteral("fictitious-master-password"));
        window->findChild<QPushButton*>(QStringLiteral("unlockVaultButton"))->click();
    }

    void lock()
    {
        window->findChild<QPushButton*>(QStringLiteral("lockVaultButton"))->click();
    }

    void restartLockedWindow(int autoLockMinutes = 1)
    {
        window.reset();
        QSettings settings("PassWall", "PassWall");
        settings.setValue("security/autoLockMinutes", autoLockMinutes);
        settings.sync();
        newLockedWindow();
    }

    void newLockedWindow()
    {
        window = MainWindow::createForHistoricalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        EXPECT_FALSE(window->acquireLease().unlocked);
    }

#ifdef PASSWALL_GUI_TESTING
    void restartWithGenerationalCoordinator()
    {
        window.reset();
        QApplication::processEvents();
        window = MainWindow::createForGenerationalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        runBounded([&] { unlock(); });
        ASSERT_TRUE(window->acquireLease().unlocked);
    }

    void restartWithGenerationalProductionComposition()
    {
        window.reset();
        QApplication::processEvents();
        window = MainWindow::createForGenerationalProductionCompositionTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        runBounded([&] { unlock(); });
        ASSERT_TRUE(window->acquireLease().unlocked);
    }
#endif

    QMessageBox* migrationNotice() const
    {
        return window->findChild<QMessageBox*>(QStringLiteral("autoLockMigrationNotice"));
    }

    void chooseInactivityDuration(int minutes, bool accept = true)
    {
        QTimer::singleShot(0, window.get(), [&, minutes, accept] {
            auto* dialog = window->findChild<QInputDialog*>("autoLockDurationDialog");
            ASSERT_NE(dialog, nullptr);
            auto* combo = dialog->findChild<QComboBox*>(); ASSERT_NE(combo, nullptr);
            EXPECT_FALSE(combo->isEditable());
            EXPECT_EQ(dialog->comboBoxItems(), (QStringList{"1 minute", "5 minutes", "15 minutes", "30 minutes", "60 minutes"}));
            constexpr std::array durations{1, 5, 15, 30, 60};
            const auto found = std::find(durations.begin(), durations.end(), minutes);
            ASSERT_NE(found, durations.end());
            combo->setCurrentIndex(int(found - durations.begin()));
            if (accept) dialog->accept(); else dialog->reject();
        });
        runBounded([&] { window->findChild<QAction*>("autoLockDurationAction")->trigger(); });
    }

    QTimer* inactivityTimer() const
    {
        return window->findChild<QTimer*>(QStringLiteral("vaultInactivityTimer"));
    }

    void corruptEntryCiphertext()
    {
        sqlite3* handle = nullptr;
        const int result = sqlite3_open(vaultPath.toStdString().c_str(), &handle);
        const std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(
            handle, sqlite3_close);
        ASSERT_EQ(result, SQLITE_OK);
        // Les métadonnées de clé restent valides : le déverrouillage réussit,
        // mais listSummaries() échoue réellement au déchiffrement de l'entrée.
        ASSERT_EQ(sqlite3_exec(database.get(),
            "UPDATE entries SET ciphertext = zeroblob(length(ciphertext));",
            nullptr, nullptr, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_changes(database.get()), 1);
    }

    void duringRefreshError(
        QObject& scope, const std::function<void(QMessageBox&)>& action)
    {
        QTimer::singleShot(0, &scope, [this, action]() {
            auto* warning = window->findChild<QMessageBox*>();
            ASSERT_NE(warning, nullptr);
            EXPECT_TRUE(warning->isVisible());
            action(*warning);
        });
    }

    void expectLockedAfterRefresh(const char* pageName = "pageWelcome")
    {
        ASSERT_NE(inactivityTimer(), nullptr);
        EXPECT_FALSE(inactivityTimer()->isActive());
        EXPECT_FALSE(window->acquireLease().unlocked);
        auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
        ASSERT_NE(pages, nullptr);
        EXPECT_TRUE(pages->currentWidget() ==
                    window->findChild<QWidget*>(QString::fromLatin1(pageName)));
        EXPECT_EQ(window->findChild<QListWidget*>(
            QStringLiteral("credentialsList"))->count(), 0);
    }

    void runEditor(bool adding, const std::function<void(QDialog&)>& action)
    {
        runBounded([&]() {
            QTimer::singleShot(0, window.get(), [&]() {
                auto* editor = window->findChild<QDialog*>(
                    QStringLiteral("credentialEditorDialog"));
                ASSERT_NE(editor, nullptr);
                action(*editor);
            });
            window->findChild<QPushButton*>(adding
                ? QStringLiteral("addCredentialButton")
                : QStringLiteral("editCredentialButton"))->click();
        });
    }

    static void expectFieldsEmpty(QDialog& editor)
    {
        for (const QString& name : {
                 QStringLiteral("credentialTitleEdit"),
                 QStringLiteral("credentialUrlEdit"),
                 QStringLiteral("credentialUsernameEdit"),
                 QStringLiteral("credentialPasswordEdit")}) {
            auto* field = editor.findChild<QLineEdit*>(name);
            ASSERT_NE(field, nullptr);
            EXPECT_TRUE(field->text().isEmpty());
        }
        auto* notes = editor.findChild<QTextEdit*>(QStringLiteral("credentialNotesEdit"));
        ASSERT_NE(notes, nullptr);
        EXPECT_TRUE(notes->toPlainText().isEmpty());
    }

    void expectStoredEntry(bool changed = false)
    {
        Credential loaded;
        std::string error;
        const bool found = CredentialService::get(
            vaultPath.toStdString(), verificationKey, entryId, loaded, error);
        EXPECT_TRUE(found);
        const std::string_view expectedPassword = changed
            ? "fictitious-password-edited" : "fictitious-password-initial";
        const std::string_view expectedNotes = changed
            ? "fictitious-notes-edited" : "fictitious-notes-initial";
        EXPECT_TRUE(loaded.password == expectedPassword);
        EXPECT_TRUE(loaded.notes == expectedNotes);
        wipeCredential(loaded);
    }

    void expectEntryCount(std::size_t expected)
    {
        std::vector<passwall::models::CredentialSummary> summaries;
        std::string error;
        ASSERT_TRUE(CredentialService::listSummaries(
            vaultPath.toStdString(), verificationKey, summaries, error));
        EXPECT_EQ(summaries.size(), expected);
    }
#ifdef Q_OS_LINUX
    void commitGenerationalCredential(const char* title)
    {
        Credential added = makeCredential();
        added.id = {};
        added.title = title;
        const auto wipe = qScopeGuard([&] { wipeCredential(added); });
        std::string error;
        ASSERT_TRUE(CredentialService::add(
            vaultPath.toStdString(), verificationKey, added, error,
            passwall::services::BackupTriggerMode::Generational))
            << error;
    }

    passwall::services::VaultReplacementAuthorization prepareReplacement()
    {
        using namespace passwall::services;
        QVector<VaultRegistration> records; QString error;
        if (!VaultPreferencesStore().list(records, error) || records.size() != 1) { ADD_FAILURE(); return {}; }
        std::optional<VaultReplacementAuthorization> authority;
        window->requestReplacementAuthorization(records[0].localId,
            [&](VaultReplacementAuthorization value, QString failure) {
                error = failure; authority.emplace(std::move(value));
            });
        if (!passwall::tests::waitFor([&] { return authority.has_value(); }, 10000)) { ADD_FAILURE(); return {}; }
        EXPECT_TRUE(authority->valid(error)) << error.toStdString();
        return std::move(*authority);
    }
    QString restoreSource()
    {
        const auto path = testDirectory->filePath("selected-restore.db");
        EXPECT_TRUE(QFile::copy(vaultPath, path)); return path;
    }
    static QByteArray encryptedBytes(const QString& path)
    {
        QFile file(path); if (!file.open(QIODevice::ReadOnly)) { ADD_FAILURE(); return {}; }
        return file.readAll();
    }
    struct RestoreObservation {
        passwall::services::RestoreResult result;
        passwall::services::RestoreCleanup cleanup = passwall::services::RestoreCleanup::Pending;
        bool finished = false, terminated = false, received = false;
    };
    passwall::services::RestoreJob* startRestore(RestoreObservation& o, const QString& source, bool wrong = false)
    {
        auto authority = prepareReplacement();
        const std::string_view text = wrong ? "fictitious-wrong-master" : "fictitious-master-password";
        SecureBuffer password(text.size()); std::memcpy(password.data(), text.data(), text.size());
        auto* job = window->startReplacementOperation(std::move(authority), source, std::move(password),
            testDirectory->filePath("exceptional-precaution.db"));
        if (!job) { ADD_FAILURE(); return nullptr; }
        using Job = passwall::services::RestoreJob;
        QObject::connect(job, &Job::finished, window.get(), [&](auto r) { o.result = r; o.finished = true; });
        QObject::connect(job, &Job::resultReceived, window.get(), [&](auto) { o.received = true; });
        QObject::connect(job, &Job::secretsCleared, window.get(), [&](auto p) { o.cleanup = p; });
        QObject::connect(job, &Job::processTerminated, window.get(), [&] { o.terminated = true; });
        return job;
    }
#endif

    void rejectInvalidRequiredFields(bool adding)
    {
        struct InvalidField { const char* name; QString value; };
        const std::array<InvalidField, 7> cases = {{
            {"credentialTitleEdit", QString()},
            {"credentialUsernameEdit", QString()},
            {"credentialPasswordEdit", QString()},
            {"credentialTitleEdit", QStringLiteral(" \t ")},
            {"credentialUsernameEdit", QStringLiteral(" \t ")},
            {"credentialTitleEdit", QStringLiteral("\u00a0\u3000")},
            {"credentialUsernameEdit", QStringLiteral("\u202f\u2028")}
        }};
        QFile database(vaultPath);
        ASSERT_TRUE(database.open(QIODevice::ReadOnly));
        const QByteArray before = database.readAll();
        database.close();
        for (const auto& invalid : cases) {
            Credential candidate = makeCredential();
            const auto value = invalid.value.toStdString();
            const std::string_view field = invalid.name;
            if (field == "credentialTitleEdit") candidate.title = value;
            if (field == "credentialUsernameEdit") candidate.username = value;
            if (field == "credentialPasswordEdit") candidate.password = value;
            std::string expectedError;
            ASSERT_FALSE(CredentialService::validate(candidate, expectedError));
            wipeCredential(candidate);

            bool notificationSeen = false;
            QTimer inspector;
            inspector.setInterval(1);
            QObject::connect(&inspector, &QTimer::timeout, window.get(), [&]() {
                auto* warning = window->findChild<QMessageBox*>();
                if (warning == nullptr || !warning->isVisible())
                    return;
                notificationSeen = true;
                EXPECT_TRUE(warning->text() == QString::fromStdString(expectedError));
                auto* editor = window->findChild<QDialog*>(QStringLiteral("credentialEditorDialog"));
                ASSERT_NE(editor, nullptr);
                // Nettoyé AVANT la fermeture de la notification, sans attendre
                // les destructeurs des variables locales de l'éditeur.
                expectFieldsEmpty(*editor);
                warning->accept();
                inspector.stop();
            });
            inspector.start();
            runEditor(adding, [&](QDialog& editor) {
                editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
                    QStringLiteral("Compte fictif"));
                editor.findChild<QLineEdit*>(QStringLiteral("credentialUsernameEdit"))->setText(
                    QStringLiteral("utilisateur-fictif"));
                editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
                    QStringLiteral("fictitious-password-initial"));
                editor.findChild<QLineEdit*>(QString::fromLatin1(invalid.name))->setText(invalid.value);
                editor.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
            });
            inspector.stop();
            EXPECT_TRUE(notificationSeen);
            ASSERT_TRUE(database.open(QIODevice::ReadOnly));
            EXPECT_TRUE(database.readAll() == before);
            database.close();
            EXPECT_TRUE(window->acquireLease().unlocked);
            expectEntryCount(1);
            expectStoredEntry();
        }
    }
#ifdef Q_OS_LINUX
    struct ControlHarness {
        passwall::tests::PrivateDBus bus;
        QTemporaryDir runtime{QStringLiteral("/tmp/pw-editor-control-XXXXXX")};
        std::unique_ptr<passwall::platform::LinuxInstanceLock> instance;
        std::unique_ptr<QDBusConnection> client;
        int received = 0;
        std::unique_ptr<passwall::platform::SessionLockService> service;
        explicit ControlHarness(MainWindow& owner)
        {
            QString error;
            instance = passwall::platform::LinuxInstanceLock::acquireInDirectoryForTesting(runtime.path(), error);
            if (!bus.isValid() || !instance)
                return;
            client = std::make_unique<QDBusConnection>(bus.connect());
            const QPointer<MainWindow> guarded(&owner);
            service = std::make_unique<passwall::platform::SessionLockService>(*instance,
                [this, guarded](auto completion) {
                    ++received;
                    if (guarded)
                        guarded->requestExternalLock(std::move(completion));
                    else
                        completion(false);
                });
            service->start(bus.address());
        }
        bool ready() { return service && passwall::tests::waitFor([&] { return service->isAvailable(); }); }
        QDBusPendingReply<> request()
        {
            using Control = passwall::platform::SessionLockService;
            auto message = QDBusMessage::createMethodCall(QString::fromLatin1(Control::Service),
                QString::fromLatin1(Control::Path), QString::fromLatin1(Control::Interface), QStringLiteral("Lock"));
            message.setAutoStartService(false);
            return client->asyncCall(message, 2000);
        }
    };
    std::unique_ptr<passwall::platform::LinuxSessionMonitor> attachMonitor(
        passwall::tests::FakeLogin1Backend*& backend)
    {
        auto fake = std::make_unique<passwall::tests::FakeLogin1Backend>();
        backend = fake.get();
        auto monitor = std::make_unique<passwall::platform::LinuxSessionMonitor>(
            std::move(fake));
        const QPointer<passwall::platform::LinuxSessionMonitor> guarded(monitor.get());
        window->setLifecycleProtectionValidator(
            [guarded] { return guarded && guarded->protectionIsOperational(); },
            [guarded] { if (guarded) guarded->invalidateProtection(); });
        QObject::connect(monitor.get(),
            &passwall::platform::LinuxSessionMonitor::protectionChanged,
            window.get(), &MainWindow::setLifecycleProtectionAvailable,
            Qt::DirectConnection);
        QObject::connect(window.get(), &MainWindow::lifecycleSecretsCleared,
            monitor.get(), &passwall::platform::LinuxSessionMonitor::acknowledgeLocked,
            Qt::DirectConnection);
        monitor->start();
        return monitor;
    }

    void establishProtection(passwall::tests::FakeLogin1Backend& backend)
    {
        QElapsedTimer elapsed;
        elapsed.start();
        while (backend.inhibitors.empty() && elapsed.elapsed() < 500)
            QApplication::processEvents(QEventLoop::AllEvents, 5);
        ASSERT_FALSE(backend.inhibitors.empty());
        ASSERT_TRUE(backend.completeInhibit());
        ASSERT_TRUE(backend.completeState());
    }

    void expectNativeAccessDenied(const VaultLease& oldLease)
    {
        Credential loaded = makeCredential();
        const auto result = window->loadCredential(oldLease, entryId, loaded);
        EXPECT_TRUE(result != passwall::native::VaultAccessResult::Success);
        EXPECT_TRUE(loaded.password.empty());
        EXPECT_TRUE(loaded.notes.empty());
        wipeCredential(loaded);
        auto response = window->handleNativeRequest({
            {QStringLiteral("type"), QStringLiteral("get_credential")},
            {QStringLiteral("id"), QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(entryId.data()), entryId.size()).toHex())},
            {QStringLiteral("url"), QStringLiteral("https://example.test")}
        });
        const auto view = response.payloadView();
        const auto object = QJsonDocument::fromJson(QByteArray::fromRawData(
            reinterpret_cast<const char*>(view.data()), view.size())).object();
        EXPECT_FALSE(object.value(QStringLiteral("ok")).toBool());
        EXPECT_FALSE(object.contains(QStringLiteral("password")));
        EXPECT_FALSE(object.contains(QStringLiteral("notes")));
    }
#endif
};

#ifdef Q_OS_LINUX
TEST_F(MainWindowEditorLockTest,
    PublicConstructorSelectsGenerationalAndHidesHistoricalPreferences)
{
    window.reset();
    QApplication::processEvents();
    window = std::make_unique<MainWindow>();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();

    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    ASSERT_EQ(coordinator->triggerMode(),
        passwall::services::BackupTriggerMode::Generational);
    EXPECT_EQ(window->findChild<QAction*>(
        QStringLiteral("backupSettingsAction")), nullptr);
    EXPECT_NE(window->findChild<QAction*>(
        QStringLiteral("globalBackupPreferencesAction")), nullptr);
    EXPECT_NE(window->findChild<QAction*>(
        QStringLiteral("generationalBackupStatusAction")), nullptr);
    EXPECT_NE(window->findChild<QToolButton*>(
        QStringLiteral("generationalBackupStatusButton")), nullptr);
    EXPECT_NE(window->findChild<
        passwall::gui::GlobalBackupPreferencesController*>(), nullptr);
    EXPECT_NE(window->findChild<
        passwall::gui::GenerationalBackupStatusController*>(), nullptr);
}

TEST_F(MainWindowEditorLockTest,
    PublicGenerationalCommitDrainsAtCloseWithoutHistoricalPublication)
{
    using passwall::services::AutomaticBackupCoordinator;
    using passwall::services::MutationBackupOutcome;
    using passwall::services::MutationBackupResult;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("public-generational-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(passwall::services::GlobalBackupPreferencesStore().save(
        {backupRoot, 7}).valid());

    window.reset();
    QApplication::processEvents();
    window = std::make_unique<MainWindow>();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    auto* preferencesController = window->findChild<
        passwall::gui::GlobalBackupPreferencesController*>();
    ASSERT_NE(preferencesController, nullptr);
    int preferenceReads = 0;
    QObject observer;
    QObject::connect(preferencesController,
        &passwall::gui::GlobalBackupPreferencesController::readSettled,
        &observer, [&](passwall::services::GlobalBackupPreferencesStatus status) {
            EXPECT_EQ(status,
                passwall::services::GlobalBackupPreferencesStatus::Valid);
            ++preferenceReads;
        });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return preferenceReads == 1; },
        10000));
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);

    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious public generation before close";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    std::string error;
    ASSERT_TRUE(CredentialService::add(
        vaultPath.toStdString(), verificationKey, added, error,
        passwall::services::BackupTriggerMode::Generational)) << error;
    ASSERT_EQ(coordinator->triggerMode(),
        passwall::services::BackupTriggerMode::Generational);

    QVector<MutationBackupResult> outcomes;
    QObject::connect(coordinator, &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            outcomes.push_back(std::move(result));
        });

    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return outcomes.size() == 1; },
        10000));
    EXPECT_EQ(outcomes.front().outcome, MutationBackupOutcome::Published);
    EXPECT_EQ(outcomes.front().kind,
        passwall::services::GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_TRUE(outcomes.front().workerTerminated);
    ASSERT_TRUE(outcomes.front().publication.has_value());
    EXPECT_TRUE(QFileInfo::exists(outcomes.front().publication->destination));
    EXPECT_EQ(QFileInfo(outcomes.front().publication->destination).suffix(),
        QStringLiteral("pwdb"));
    QDirIterator historical(backupRoot, {QStringLiteral("*.db")},
        QDir::Files, QDirIterator::Subdirectories);
    EXPECT_FALSE(historical.hasNext());
    ASSERT_TRUE(passwall::tests::waitFor([&] { return !window->isVisible(); },
        10000));
}

#ifdef PASSWALL_GUI_TESTING
TEST_F(MainWindowEditorLockTest,
    GenerationalStatusKeepsPublicationRotationAndStaleTokensDistinct)
{
    using namespace passwall::services;
    AutomaticBackupCoordinator coordinator(VaultPreferencesStore(),
        QStringLiteral("unused-test-worker"), 100, 100,
        BackupTriggerMode::Generational);
    GenerationalBackupRotationController rotation(coordinator);
    passwall::gui::GenerationalBackupStatusController status(
        coordinator, rotation, window.get());
    VaultFileIdentity identity;
    QString error;
    ASSERT_TRUE(VaultPreferencesStore::inspectVault(
        vaultPath, identity, error)) << error.toStdString();
    status.setAuthenticatedVault(identity);
    status.preferencesReadSettled(GlobalBackupPreferencesStatus::ReadError);
    EXPECT_TRUE(status.configurationStatus().contains(
        QStringLiteral("Lecture sûre"), Qt::CaseInsensitive));
    status.preferencesWriteSettled(GlobalBackupPreferencesStatus::WriteError);
    EXPECT_TRUE(status.configurationStatus().contains(
        QStringLiteral("persistance"), Qt::CaseInsensitive));

    GenerationalBackupSuspensionState liveUnknown;
    liveUnknown.suspended = true;
    liveUnknown.reason = GenerationalBackupSuspensionReason::Unknown;
    liveUnknown.vaultPath = identity.path;
    liveUnknown.vaultId = identity.vaultId;
    liveUnknown.device = identity.device;
    liveUnknown.inode = identity.inode;
    liveUnknown.workerAlive = true;
    coordinator.generationalBackupSuspensionChanged(liveUnknown);
    EXPECT_FALSE(status.retryAvailable());
    liveUnknown.workerAlive = false;
    coordinator.generationalBackupSuspensionChanged(liveUnknown);
    EXPECT_TRUE(status.retryAvailable());
    status.invalidateAuthenticatedSession();
    EXPECT_FALSE(status.retryAvailable());
    status.setAuthenticatedVault(identity);
    GenerationalBackupSuspensionState cleared = liveUnknown;
    cleared.suspended = false;
    coordinator.generationalBackupSuspensionChanged(cleared);
    EXPECT_FALSE(status.retryAvailable());

    GenerationalBackupRequestOffer offer;
    offer.kind = GenerationalBackupRequestKind::CrudGeneration;
    offer.vaultPath = identity.path;
    offer.vault = identity;
    offer.vault.birthTime.clear(); // offerFor() carries the stable tuple only.
    offer.mutationGeneration = 8;
    offer.requestId = 41;
    coordinator.generationalBackupRequested(offer);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("attente"), Qt::CaseInsensitive))
        << vaultCorrelationDiagnostic(identity, offer.vault).toStdString();
    GenerationalOperationState active;
    active.phase = GenerationalOperationPhase::WorkerActive;
    active.vaultPath = identity.path;
    active.mutationGeneration = 8;
    active.requestId = 41;
    active.workerAlive = true;
    coordinator.generationalOperationStateChanged(active);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("en cours"), Qt::CaseInsensitive))
        << vaultCorrelationDiagnostic(identity, offer.vault).toStdString();
    EXPECT_FALSE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));

    MutationBackupResult published;
    published.vaultPath = identity.path;
    published.generation = 8;
    published.requestId = 41;
    published.outcome = MutationBackupOutcome::Published;
    published.workerOutcome = BackupOutcome::Published;
    published.publication = MutationBackupPublicationReceipt{};
    published.publication->vaultPath = identity.path;
    published.publication->destination =
        QStringLiteral("/tmp/fictitious-status-copy.pwdb");
    published.publication->generation = 8;
    published.publication->requestId = 41;
    published.publication->kind =
        GenerationalBackupRequestKind::CrudGeneration;
    BackupFileEvidence evidence;
    evidence.device = 1;
    evidence.inode = 2;
    evidence.size = 3;
    evidence.mount = 4;
    evidence.directoryDevice = 5;
    evidence.directoryInode = 6;
    evidence.directoryMount = 7;
    evidence.birth = QStringLiteral("1:0");
    evidence.modified = QStringLiteral("2:0");
    evidence.changed = QStringLiteral("3:0");
    evidence.directoryBirth = QStringLiteral("4:0");
    evidence.sha256 = QByteArray(32, '\x42');
    published.publication->evidence = evidence;
    published.confirmedPublicationResult = BackupResult{
        BackupOutcome::Published, QStringLiteral("publication-test"),
        evidence, published.publication->destination};
    published.workerTerminated = true;
    {
        // This test drives the presentation contract directly. Prevent the
        // real rotation consumer from first rejecting this intentionally
        // context-free publication and consuming the same presentation token.
        const QSignalBlocker blockRotation(&rotation);
        coordinator.mutationBatchSettled(published);
    }
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
    EXPECT_TRUE(status.lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));

    GenerationalBackupRotationResult uncertainRotation;
    uncertainRotation.requestId = 41;
    uncertainRotation.generation = 8;
    uncertainRotation.publishedPath = published.publication->destination;
    uncertainRotation.rotation.outcome =
        BackupSeriesRotationOutcome::DeletionDurabilityUnconfirmed;
    uncertainRotation.rotation.diagnostic =
        QStringLiteral("fsync [errno=5]");
    rotation.rotationSettled(uncertainRotation);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
    EXPECT_TRUE(status.rotationStatus().contains(
        QStringLiteral("durabilité non confirmée"), Qt::CaseInsensitive));
    EXPECT_TRUE(status.rotationDetail().contains(QStringLiteral("errno=5")));
    auto duplicateRotation = uncertainRotation;
    duplicateRotation.rotation.outcome = BackupSeriesRotationOutcome::Complete;
    duplicateRotation.rotation.diagnostic = QStringLiteral("duplicate-rotation");
    rotation.rotationSettled(duplicateRotation);
    EXPECT_TRUE(status.rotationStatus().contains(
        QStringLiteral("durabilité non confirmée"), Qt::CaseInsensitive));
    EXPECT_FALSE(status.rotationDetail().contains(
        QStringLiteral("duplicate-rotation")));

    MutationBackupResult stale = published;
    stale.outcome = MutationBackupOutcome::Failed;
    stale.workerOutcome = BackupOutcome::FailedBeforePublication;
    stale.diagnostic = QStringLiteral("stale-duplicate");
    stale.publication.reset();
    stale.confirmedPublicationResult.reset();
    coordinator.mutationBatchSettled(stale);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
    EXPECT_FALSE(status.backupDetail().contains(
        QStringLiteral("stale-duplicate")));

    offer.requestId = 42;
    offer.vault.inode += 1;
    coordinator.generationalBackupRequested(offer);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
    MutationBackupResult substituted = stale;
    substituted.requestId = 42;
    substituted.diagnostic = QStringLiteral("substituted-vault");
    coordinator.mutationBatchSettled(substituted);
    EXPECT_FALSE(status.backupDetail().contains(
        QStringLiteral("substituted-vault")));

    GenerationalOperationState latePending;
    latePending.phase = GenerationalOperationPhase::PendingRequest;
    latePending.vaultPath = identity.path;
    latePending.mutationGeneration = 9;
    coordinator.generationalOperationStateChanged(latePending);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));

    status.invalidateAuthenticatedSession();
    offer.requestId = 43;
    offer.vault = identity;
    offer.mutationGeneration = 9;
    coordinator.generationalBackupRequested(offer);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("attente"), Qt::CaseInsensitive));
    EXPECT_FALSE(status.retryAvailable());
    MutationBackupResult drained = published;
    drained.generation = 9;
    drained.requestId = 43;
    drained.publication->generation = 9;
    drained.publication->requestId = 43;
    drained.publication->destination =
        QStringLiteral("/tmp/fictitious-drained-status-copy.pwdb");
    drained.confirmedPublicationResult->publishedPath =
        drained.publication->destination;
    coordinator.mutationBatchSettled(drained);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
    EXPECT_FALSE(status.retryAvailable());

    offer.requestId = 44;
    offer.mutationGeneration = 10;
    coordinator.generationalBackupRequested(offer);
    MutationBackupResult wrongGeneration = drained;
    wrongGeneration.requestId = 44;
    wrongGeneration.generation = 11;
    wrongGeneration.publication->requestId = 44;
    wrongGeneration.publication->generation = 11;
    wrongGeneration.diagnostic = QStringLiteral("wrong-generation");
    coordinator.mutationBatchSettled(wrongGeneration);
    EXPECT_TRUE(status.backupStatus().contains(
        QStringLiteral("attente"), Qt::CaseInsensitive));
    EXPECT_FALSE(status.backupDetail().contains(
        QStringLiteral("wrong-generation")));
    EXPECT_TRUE(status.lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
}

TEST_F(MainWindowEditorLockTest,
    GenerationalMissingPreferencesAreProposedOnceWithoutBlockingVaultAccess)
{
    using namespace passwall::services;
    using passwall::gui::GlobalBackupPreferencesController;
    using passwall::gui::GlobalBackupPreferencesDialog;
    const QString preferencesFile =
        passwall::services::GlobalBackupPreferencesStore().fileName();
    ASSERT_FALSE(QFileInfo::exists(preferencesFile));
    const QString unchosenRoot =
        testDirectory->filePath(QStringLiteral("not-created-by-dialog"));

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    EXPECT_EQ(window->findChild<QAction*>(
        QStringLiteral("backupSettingsAction")), nullptr);
    auto* action = window->findChild<QAction*>(
        QStringLiteral("globalBackupPreferencesAction"));
    ASSERT_NE(action, nullptr);
    auto* statusAction = window->findChild<QAction*>(
        QStringLiteral("generationalBackupStatusAction"));
    ASSERT_NE(statusAction, nullptr);
    ASSERT_NE(window->findChild<QToolButton*>(
        QStringLiteral("generationalBackupStatusButton")), nullptr);
    auto* statusController = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(statusController, nullptr);
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    QVector<GenerationalBackupRequestOffer> offers;
    QVector<MutationBackupResult> terminalResults;
    QObject backupObserver;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &backupObserver, [&](GenerationalBackupRequestOffer offer) {
            offers.push_back(std::move(offer));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &backupObserver, [&](MutationBackupResult result) {
            terminalResults.push_back(std::move(result));
        });
    auto* controller = window->findChild<GlobalBackupPreferencesController*>();
    ASSERT_NE(controller, nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return window->findChild<GlobalBackupPreferencesDialog*>(
            QStringLiteral("globalBackupPreferencesDialog")) != nullptr;
    }));
    QPointer<GlobalBackupPreferencesDialog> dialog =
        window->findChild<GlobalBackupPreferencesDialog*>(
            QStringLiteral("globalBackupPreferencesDialog"));
    ASSERT_TRUE(dialog);
    EXPECT_FALSE(dialog->isModal());
    dialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRootEdit"))->setText(unchosenRoot);
    dialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRetentionEdit"))->setText(
            QStringLiteral("9"));
    dialog->findChild<QPushButton*>(
        QStringLiteral("globalBackupCloseButton"))->click();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return dialog.isNull(); }));
    EXPECT_FALSE(QFileInfo::exists(preferencesFile));
    EXPECT_FALSE(QFileInfo::exists(unchosenRoot));

    statusAction->trigger();
    auto* statusDialog = window->findChild<QDialog*>(
        QStringLiteral("generationalBackupStatusDialog"));
    ASSERT_NE(statusDialog, nullptr);
    EXPECT_FALSE(statusDialog->isModal());
    statusDialog->reject();

    runBounded([&] { unlock(); });
    EXPECT_TRUE(window->acquireLease().unlocked);
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_TRUE(statusController->backupStatus().contains(
        QStringLiteral("Aucune opération"), Qt::CaseInsensitive));
    EXPECT_TRUE(statusController->configurationStatus().contains(
        QStringLiteral("absentes"), Qt::CaseInsensitive));
    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious mutation while global preferences are absent";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    std::string mutationError;
    ASSERT_TRUE(CredentialService::add(
        vaultPath.toStdString(), verificationKey, added, mutationError,
        BackupTriggerMode::Generational))
        << mutationError;
    coordinator->requestPendingMutationsForLock(vaultPath);
    QCoreApplication::processEvents();
    EXPECT_TRUE(offers.isEmpty());
    EXPECT_TRUE(terminalResults.isEmpty());
    EXPECT_FALSE(coordinator->generationalBackupSuspension(vaultPath).suspended);
    EXPECT_EQ(window->findChild<GlobalBackupPreferencesDialog*>(
        QStringLiteral("globalBackupPreferencesDialog")), nullptr);

    int reopenedPreferenceReads = 0;
    GlobalBackupPreferencesStatus reopenedPreferenceStatus =
        GlobalBackupPreferencesStatus::ReadError;
    QObject::connect(controller,
        &GlobalBackupPreferencesController::readSettled,
        &backupObserver, [&](GlobalBackupPreferencesStatus status) {
            reopenedPreferenceStatus = status;
            ++reopenedPreferenceReads;
        });
    action->trigger();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        auto* reopened = window->findChild<GlobalBackupPreferencesDialog*>(
            QStringLiteral("globalBackupPreferencesDialog"));
        auto* save = reopened ? reopened->findChild<QPushButton*>(
            QStringLiteral("globalBackupSaveButton")) : nullptr;
        return reopenedPreferenceReads == 1 && save && save->isEnabled();
    }));
    EXPECT_EQ(reopenedPreferenceStatus,
        GlobalBackupPreferencesStatus::Absent);
    auto* configuredDialog = window->findChild<GlobalBackupPreferencesDialog*>(
        QStringLiteral("globalBackupPreferencesDialog"));
    ASSERT_NE(configuredDialog, nullptr);
    const QString configuredRoot =
        testDirectory->filePath(QStringLiteral("configured-after-first-crud"));
    ASSERT_TRUE(QDir().mkpath(configuredRoot));
    configuredDialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRootEdit"))->setText(configuredRoot);
    configuredDialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRetentionEdit"))->setText(
            QStringLiteral("7"));
    int preferenceWrites = 0;
    GlobalBackupPreferencesStatus preferenceWriteStatus =
        GlobalBackupPreferencesStatus::WriteError;
    QObject::connect(controller,
        &GlobalBackupPreferencesController::writeSettled,
        &backupObserver, [&](GlobalBackupPreferencesStatus status) {
            preferenceWriteStatus = status;
            ++preferenceWrites;
        });
    configuredDialog->findChild<QPushButton*>(
        QStringLiteral("globalBackupSaveButton"))->click();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return preferenceWrites == 1;
    }, 10000));
    ASSERT_EQ(preferenceWriteStatus,
        GlobalBackupPreferencesStatus::Valid);
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return terminalResults.size() == 1;
    }, 10000))
        << generationalStatusDiagnostic(coordinator, statusController,
               vaultPath, terminalResults.size(), 0).toStdString();
    ASSERT_EQ(offers.size(), 1)
        << generationalStatusDiagnostic(coordinator, statusController,
               vaultPath, terminalResults.size(), 0).toStdString();
    EXPECT_EQ(offers[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_GT(offers[0].mutationGeneration, 0U);
    ASSERT_EQ(terminalResults[0].outcome,
        MutationBackupOutcome::Published);
    EXPECT_EQ(terminalResults[0].requestId, offers[0].requestId);
    EXPECT_EQ(terminalResults[0].generation,
        offers[0].mutationGeneration);
    ASSERT_TRUE(terminalResults[0].publication.has_value());
    EXPECT_TRUE(QFileInfo::exists(
        terminalResults[0].publication->destination));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(offers.size(), 1);
    EXPECT_EQ(terminalResults.size(), 1);
}

TEST_F(MainWindowEditorLockTest,
    ConfirmedGlobalConfigurationWaitsForFirstCommitThenPublishesCrud)
{
    using namespace passwall::services;
    using passwall::gui::GlobalBackupPreferencesController;
    using passwall::gui::GlobalBackupPreferencesDialog;
    const QString preferencesFile = GlobalBackupPreferencesStore().fileName();
    ASSERT_FALSE(QFileInfo::exists(preferencesFile));
    const QString backupRoot =
        testDirectory->filePath(QStringLiteral("configured-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* controller = window->findChild<GlobalBackupPreferencesController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(controller, nullptr);
    QVector<GenerationalBackupRequestOffer> offers;
    QVector<MutationBackupResult> publications;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer offer) {
            offers.push_back(std::move(offer));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            publications.push_back(std::move(result));
        });
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return window->findChild<GlobalBackupPreferencesDialog*>(
            QStringLiteral("globalBackupPreferencesDialog")) != nullptr;
    }));
    auto* dialog = window->findChild<GlobalBackupPreferencesDialog*>(
        QStringLiteral("globalBackupPreferencesDialog"));
    ASSERT_NE(dialog, nullptr);

    QSettings historical(QStringLiteral("PassWall"), QStringLiteral("PassWall"));
    historical.sync();
    QFile historicalFile(historical.fileName());
    ASSERT_TRUE(historicalFile.open(QIODevice::ReadOnly));
    const QByteArray historicalBefore = historicalFile.readAll();
    historicalFile.close();

    GlobalBackupPreferencesStatus writeStatus =
        GlobalBackupPreferencesStatus::Absent;
    int writes = 0;
    QObject::connect(controller,
        &GlobalBackupPreferencesController::writeSettled,
        &observer, [&](GlobalBackupPreferencesStatus status) {
            writeStatus = status;
            ++writes;
        });
    dialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRootEdit"))->setText(backupRoot);
    dialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRetentionEdit"))->setText(
            QString::number(std::numeric_limits<quint64>::max()));
    dialog->findChild<QPushButton*>(
        QStringLiteral("globalBackupSaveButton"))->click();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return writes == 1 && writeStatus == GlobalBackupPreferencesStatus::Valid;
    }, 10000));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_TRUE(offers.isEmpty());
    EXPECT_TRUE(publications.isEmpty());
    EXPECT_FALSE(coordinator->isActive());

    commitGenerationalCredential(
        "Fictitious first committed generational entry");
    commitGenerationalCredential(
        "Fictitious nearby committed generational entry");
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return publications.size() == 1;
    }, 10000));
    ASSERT_EQ(publications[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_EQ(offers.size(), 1);
    EXPECT_EQ(offers[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(offers[0].mutationGeneration, 2U);
    EXPECT_EQ(publications[0].generation, 2U);
    ASSERT_EQ(publications[0].outcome, MutationBackupOutcome::Published);
    ASSERT_TRUE(publications[0].publication.has_value());
    EXPECT_TRUE(QFileInfo::exists(publications[0].publication->destination));
    EXPECT_EQ(GlobalBackupPreferencesStore().load().preferences.retainedVersions,
        std::numeric_limits<quint64>::max());

    ASSERT_TRUE(historicalFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(historicalFile.readAll(), historicalBefore);
    historicalFile.close();
    EXPECT_TRUE(window->acquireLease().unlocked);

    QPointer<GlobalBackupPreferencesDialog> oldDialog(dialog);
    dialog->reject();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return oldDialog.isNull(); }));
    window->findChild<QAction*>(
        QStringLiteral("globalBackupPreferencesAction"))->trigger();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        auto* reopened = window->findChild<GlobalBackupPreferencesDialog*>(
            QStringLiteral("globalBackupPreferencesDialog"));
        return reopened
            && reopened->findChild<QLineEdit*>(
                QStringLiteral("globalBackupRootEdit"))->text() == backupRoot
            && reopened->findChild<QLineEdit*>(
                QStringLiteral("globalBackupRetentionEdit"))->text()
                == QString::number(std::numeric_limits<quint64>::max());
    }));

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* restartedCoordinator =
        window->findChild<passwall::services::AutomaticBackupCoordinator*>(
            QStringLiteral("automaticBackupCoordinator"));
    auto* restartedPreferences =
        window->findChild<GlobalBackupPreferencesController*>();
    ASSERT_NE(restartedCoordinator, nullptr);
    ASSERT_NE(restartedPreferences, nullptr);
    int restartedOffers = 0;
    int restartedPreferenceReads = 0;
    QObject restartObserver;
    QObject::connect(restartedCoordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &restartObserver, [&](GenerationalBackupRequestOffer) {
            ++restartedOffers;
        });
    QObject::connect(restartedPreferences,
        &GlobalBackupPreferencesController::readSettled,
        &restartObserver, [&](GlobalBackupPreferencesStatus status) {
            EXPECT_EQ(status, GlobalBackupPreferencesStatus::Valid);
            ++restartedPreferenceReads;
        });
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return restartedPreferenceReads == 1;
    }));
    runBounded([&] { unlock(); });
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_FALSE(restartedCoordinator->isActive());
    EXPECT_EQ(restartedOffers, 0);
}

TEST_F(MainWindowEditorLockTest,
    LateGlobalPreferenceSaveAfterLockCannotStartAWorker)
{
    using namespace passwall::services;
    using passwall::gui::GlobalBackupPreferencesDialog;
    const QString backupRoot =
        testDirectory->filePath(QStringLiteral("late-settings-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    int publications = 0;
    bool preferenceChangeObserved = false;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult) { ++publications; });
    QObject::connect(&GlobalBackupPreferencesStore::events(),
        &GlobalBackupPreferencesEvents::changed,
        &observer, [&](const QString&, bool) {
            preferenceChangeObserved = true;
        });
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return window->findChild<GlobalBackupPreferencesDialog*>(
            QStringLiteral("globalBackupPreferencesDialog")) != nullptr;
    }));
    auto* dialog = window->findChild<GlobalBackupPreferencesDialog*>(
        QStringLiteral("globalBackupPreferencesDialog"));
    ASSERT_NE(dialog, nullptr);
    dialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRootEdit"))->setText(backupRoot);
    dialog->findChild<QLineEdit*>(
        QStringLiteral("globalBackupRetentionEdit"))->setText(
            QStringLiteral("7"));

    int heartbeatTicks = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout,
        [&] { ++heartbeatTicks; });
    heartbeat.start(0);
    passwall::tests::holdSettingsSync();
    const auto release = qScopeGuard([] {
        passwall::tests::releaseSettingsSync();
    });
    dialog->findChild<QPushButton*>(
        QStringLiteral("globalBackupSaveButton"))->click();
    ASSERT_TRUE(passwall::tests::waitFor(
        [] { return passwall::tests::settingsSyncEntered(); }, 10000));
    EXPECT_GT(heartbeatTicks, 0);

    lock();
    EXPECT_FALSE(window->acquireLease().unlocked);
    passwall::tests::releaseSettingsSync();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return preferenceChangeObserved
            && GlobalBackupPreferencesStore().load().valid();
    }, 10000));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_EQ(publications, 0);
    EXPECT_FALSE(coordinator->isActive());
}

TEST_F(MainWindowEditorLockTest,
    ValidGlobalPreferencesNeitherSearchClosedVaultsNorBackUpAnEmptyVault)
{
    using namespace passwall::services;
    const QString backupRoot =
        testDirectory->filePath(QStringLiteral("empty-vault-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    const QString emptyVault =
        testDirectory->filePath(QStringLiteral("empty.pwdb"));
    SecureBuffer emptyKey(0);
    std::string error;
    ASSERT_TRUE(VaultLifecycleService::createVault(emptyVault.toStdString(),
        "fictitious-master-password", emptyKey, error)) << error;
    emptyKey = SecureBuffer(0);
    vaultPath = emptyVault;

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* preferencesController = window->findChild<
        passwall::gui::GlobalBackupPreferencesController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(preferencesController, nullptr);
    int offers = 0;
    int publications = 0;
    int preferenceReads = 0;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer) { ++offers; });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult) { ++publications; });
    QObject::connect(preferencesController,
        &passwall::gui::GlobalBackupPreferencesController::readSettled,
        &observer, [&](GlobalBackupPreferencesStatus status) {
            EXPECT_EQ(status, GlobalBackupPreferencesStatus::Valid);
            ++preferenceReads;
        });
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return preferenceReads == 1;
    }));
    EXPECT_EQ(window->findChild<passwall::gui::GlobalBackupPreferencesDialog*>(
        QStringLiteral("globalBackupPreferencesDialog")), nullptr);
    EXPECT_EQ(offers, 0);
    EXPECT_EQ(publications, 0);

    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_FALSE(coordinator->isActive());
    EXPECT_EQ(offers, 0);
    EXPECT_EQ(publications, 0);
    EXPECT_TRUE(QDir(backupRoot).isEmpty());
}

TEST_F(MainWindowEditorLockTest,
    GenerationalProductionCompositionUsesSystemIdentityRealWorkerAndRealGrouping)
{
    using namespace passwall::services;
    const QString backupRoot =
        testDirectory->filePath(QStringLiteral("production-composition-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());

    // This vault intentionally starts empty.  A valid configuration and an
    // authenticated session must not manufacture a backup request.
    const QString emptyVault =
        testDirectory->filePath(QStringLiteral("production-composition.pwdb"));
    SecureBuffer emptyKey(0);
    std::string error;
    ASSERT_TRUE(VaultLifecycleService::createVault(emptyVault.toStdString(),
        "fictitious-master-password", emptyKey, error)) << error;
    vaultPath = emptyVault;

    BackupInstallationIdentity firstInstallation;
    BackupInstallationIdentity secondInstallation;
    QString identityError;
    ASSERT_TRUE(BackupSeriesIdentityService::currentInstallation(
        firstInstallation, identityError)) << identityError.toStdString();
    ASSERT_TRUE(BackupSeriesIdentityService::currentInstallation(
        secondInstallation, identityError)) << identityError.toStdString();
    EXPECT_EQ(firstInstallation, secondInstallation);
    EXPECT_EQ(firstInstallation.domain,
        BackupInstallationIdentityDomain::LinuxSystemdMachineAppSpecificV1);
    EXPECT_EQ(firstInstallation.value.size(),
        BackupSeriesIdentityService::InstallationIdentitySize);
    VaultFileIdentity inspectedVault;
    QString expectedSeries;
    ASSERT_TRUE(VaultPreferencesStore::inspectVault(emptyVault, inspectedVault,
        identityError)) << identityError.toStdString();
    ASSERT_TRUE(BackupSeriesIdentityService::deriveSeriesId(firstInstallation,
        inspectedVault.vaultId, expectedSeries, identityError))
        << identityError.toStdString();

    restartWithGenerationalProductionComposition();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* preferencesController = window->findChild<
        passwall::gui::GlobalBackupPreferencesController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(preferencesController, nullptr);
    ASSERT_EQ(coordinator->triggerMode(), BackupTriggerMode::Generational);
    EXPECT_EQ(QFileInfo(BackupJob::siblingWorkerPath()).fileName(),
        QStringLiteral("passwall_backup_worker"));

    int preferenceReads = 0;
    QVector<GenerationalBackupRequestOffer> offers;
    QVector<MutationBackupResult> results;
    QObject observer;
    QObject::connect(preferencesController,
        &passwall::gui::GlobalBackupPreferencesController::readSettled,
        &observer, [&](GlobalBackupPreferencesStatus status) {
            EXPECT_EQ(status, GlobalBackupPreferencesStatus::Valid);
            ++preferenceReads;
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer offer) {
            offers.push_back(std::move(offer));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return preferenceReads == 1; },
        10000));
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_TRUE(offers.isEmpty());
    EXPECT_TRUE(results.isEmpty());
    EXPECT_TRUE(QDir(backupRoot).isEmpty());

    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious production-composition commit";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    ASSERT_TRUE(CredentialService::add(emptyVault.toStdString(), emptyKey,
        added, error, BackupTriggerMode::Generational)) << error;

    // The production composition is intentionally not the 100 ms fixture.
    // It must retain the committed generation for the real 20-second window.
    QElapsedTimer groupingDelay;
    groupingDelay.start();
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return groupingDelay.elapsed() >= 750; }, 1500));
    EXPECT_TRUE(offers.isEmpty());
    EXPECT_TRUE(results.isEmpty());

    ASSERT_TRUE(passwall::tests::waitFor([&] { return results.size() == 1; },
        30000));
    EXPECT_GE(groupingDelay.elapsed(), 19000);
    ASSERT_EQ(offers.size(), 1);
    EXPECT_EQ(offers.front().kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_EQ(results.front().kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_EQ(results.front().outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results.front().workerTerminated);
    ASSERT_TRUE(results.front().publication.has_value());
    const QString published = results.front().publication->destination;
    EXPECT_TRUE(QFileInfo::exists(published));
    EXPECT_EQ(QFileInfo(published).suffix(), QStringLiteral("pwdb"));
    EXPECT_TRUE(published.startsWith(backupRoot + QLatin1Char('/')));
    EXPECT_EQ(QFileInfo(published).absoluteDir().dirName(), expectedSeries);

    // The result is a generation proof, not an historical .db publication.
    QDirIterator allFiles(backupRoot, QDir::Files, QDirIterator::Subdirectories);
    while (allFiles.hasNext())
        EXPECT_NE(QFileInfo(allFiles.next()).suffix(), QStringLiteral("db"));
    EXPECT_FALSE(coordinator->isActive());

    // Closing immediately after a later COMMIT must retain the request and
    // wait for the real worker/reservation rather than dropping the COMMIT.
    Credential second = makeCredential();
    second.id = {};
    second.title = "Fictitious production-composition close commit";
    const auto wipeSecond = qScopeGuard([&] { wipeCredential(second); });
    ASSERT_TRUE(CredentialService::add(emptyVault.toStdString(), emptyKey,
        second, error, BackupTriggerMode::Generational)) << error;
    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return results.size() == 2; },
        30000));
    EXPECT_EQ(results.back().outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results.back().workerTerminated);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return !window->isVisible(); },
        10000));
    emptyKey = SecureBuffer(0);
}

TEST_F(MainWindowEditorLockTest,
    GenerationalCloseWithoutMutationWipesImmediatelyAndClosesWithoutARequest)
{
    using passwall::services::AutomaticBackupCoordinator;
    restartWithGenerationalCoordinator();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    ASSERT_EQ(coordinator->triggerMode(),
        passwall::services::BackupTriggerMode::Generational);

    bool invalidated = false;
    int requests = 0;
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated,
        &observer, [&] { invalidated = true; });
    QObject::connect(coordinator, &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](passwall::services::GenerationalBackupRequestOffer) { ++requests; });

    EXPECT_FALSE(window->close());
    EXPECT_TRUE(invalidated);
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_TRUE(passwall::tests::waitFor([&] { return !window->isVisible(); }));
    EXPECT_EQ(requests, 0);
}

TEST_F(MainWindowEditorLockTest,
    GenerationalConsumerPublishesFirstCrudThenDrainsOnRepeatedClose)
{
    using passwall::services::AutomaticBackupCoordinator;
    using passwall::services::GenerationalBackupRequestOffer;
    using passwall::services::GenerationalOperationPhase;
    using passwall::services::GenerationalOperationState;
    using passwall::services::GenerationalShutdownDrainState;
    using passwall::services::MutationBackupOutcome;
    using passwall::services::MutationBackupResult;
    const QString backupRoot = testDirectory->filePath(QStringLiteral("automatic-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    const auto saved = passwall::services::GlobalBackupPreferencesStore().save({backupRoot, 7});
    ASSERT_TRUE(saved.valid()) << saved.diagnostic.toStdString();
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    QFile workerMode(vaultPath + QStringLiteral(".fake-mode"));
    ASSERT_TRUE(workerMode.open(
        QIODevice::WriteOnly | QIODevice::Truncate));
    const QByteArray gatedMode("gated-snapshot-published-file");
    ASSERT_EQ(workerMode.write(gatedMode), gatedMode.size());
    workerMode.close();

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    auto* rotationController = window->findChild<
        passwall::services::GenerationalBackupRotationController*>(
            QStringLiteral("generationalBackupRotationController"));
    ASSERT_NE(rotationController, nullptr);
    auto* statusController = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(statusController, nullptr);
    QVector<GenerationalBackupRequestOffer> offers;
    QVector<GenerationalOperationState> operationStates;
    QVector<GenerationalShutdownDrainState> drainStates;
    QVector<MutationBackupResult> results;
    QVector<passwall::services::GenerationalBackupRotationResult> rotations;
    bool invalidated = false;
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated,
        &observer, [&] { invalidated = true; });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer offer) {
            offers.push_back(std::move(offer));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalOperationStateChanged,
        &observer, [&](GenerationalOperationState state) {
            operationStates.push_back(std::move(state));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalShutdownDrainChanged,
        &observer, [&](GenerationalShutdownDrainState state) {
            drainStates.push_back(std::move(state));
        });
    QObject::connect(coordinator, &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });
    QObject::connect(rotationController,
        &passwall::services::GenerationalBackupRotationController::rotationSettled,
        &observer, [&](passwall::services::GenerationalBackupRotationResult result) {
            rotations.push_back(std::move(result));
        });
    const auto pipelineDiagnostic = [&] {
        QStringList offerDetails;
        for (const auto& offer : offers) {
            offerDetails.push_back(QStringLiteral(
                "{request=%1 kind=%2 mutation=%3 session=%4}")
                .arg(offer.requestId)
                .arg(static_cast<int>(offer.kind))
                .arg(offer.mutationGeneration)
                .arg(offer.sessionGeneration));
        }
        QStringList stateDetails;
        for (const auto& state : operationStates) {
            stateDetails.push_back(QStringLiteral(
                "{request=%1 phase=%2 kind=%3 mutation=%4 session=%5 "
                "workerAlive=%6 resultObserved=%7 outcome=%8}")
                .arg(state.requestId)
                .arg(static_cast<int>(state.phase))
                .arg(static_cast<int>(state.kind))
                .arg(state.mutationGeneration)
                .arg(state.sessionGeneration)
                .arg(state.workerAlive)
                .arg(state.resultObserved)
                .arg(static_cast<int>(state.workerOutcome)));
        }
        QStringList resultDetails;
        for (const auto& result : results) {
            resultDetails.push_back(QStringLiteral(
                "{request=%1 kind=%2 mutation=%3 session=%4 outcome=%5 "
                "workerOutcome=%6 terminated=%7 publication=%8 diagnostic='%9'}")
                .arg(result.requestId)
                .arg(static_cast<int>(result.kind))
                .arg(result.generation)
                .arg(result.sessionGeneration)
                .arg(static_cast<int>(result.outcome))
                .arg(static_cast<int>(result.workerOutcome))
                .arg(result.workerTerminated)
                .arg(result.publication.has_value())
                .arg(result.diagnostic));
        }
        QStringList drainDetails;
        for (const auto& state : drainStates) {
            drainDetails.push_back(QStringLiteral(
                "{status=%1 workerAlive=%2 pending=%3 latest=%4 diagnostic='%5'}")
                .arg(static_cast<int>(state.status))
                .arg(state.workerAlive)
                .arg(state.requestPending)
                .arg(state.latestMutationGeneration)
                .arg(state.diagnostic));
        }
        QStringList rotationDetails;
        for (const auto& rotation : rotations) {
            rotationDetails.push_back(QStringLiteral(
                "{request=%1 kind=%2 mutation=%3 session=%4 outcome=%5}")
                .arg(rotation.requestId)
                .arg(static_cast<int>(rotation.kind))
                .arg(rotation.generation)
                .arg(rotation.sessionGeneration)
                .arg(static_cast<int>(rotation.rotation.outcome)));
        }
        return QStringLiteral(
                   "fixture={pid=%1 vault='%2' settings='%3' "
                   "recoverySettings='%4' recoveryLock='%5' "
                   "xdgConfigHome='%6' backupRoot='%7'}; ")
                .arg(QCoreApplication::applicationPid())
                .arg(vaultPath)
                .arg(passwall::services::GlobalBackupPreferencesStore().fileName())
                .arg(QSettings(QStringLiteral("PassWall"),
                    QStringLiteral("PassWall")).fileName())
                .arg(QSettings(QStringLiteral("PassWall"),
                    QStringLiteral("PassWall")).fileName()
                    + QStringLiteral(".registry-lock"))
                .arg(qEnvironmentVariable("XDG_CONFIG_HOME"))
                .arg(backupRoot)
            + generationalStatusDiagnostic(coordinator, statusController,
                vaultPath, results.size(), rotations.size())
            + QStringLiteral("; offers=[%1]; states=[%2]; results=[%3]; "
                             "drain=[%4]; rotationResults=[%5]")
                  .arg(offerDetails.join(QStringLiteral(", ")),
                      stateDetails.join(QStringLiteral(", ")),
                      resultDetails.join(QStringLiteral(", ")),
                      drainDetails.join(QStringLiteral(", ")),
                      rotationDetails.join(QStringLiteral(", ")));
    };
    const auto reachedWorker = [&](quint64 requestId) {
        return std::any_of(operationStates.cbegin(), operationStates.cend(),
            [&](const GenerationalOperationState& state) {
                return state.requestId == requestId
                    && state.phase == GenerationalOperationPhase::WorkerActive;
            });
    };
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    QCoreApplication::sendPostedEvents();
    QCoreApplication::processEvents();
    EXPECT_TRUE(offers.isEmpty());
    EXPECT_TRUE(results.isEmpty());
    EXPECT_TRUE(rotations.isEmpty());
    EXPECT_FALSE(coordinator->isActive());

    auto commit = [&](const QString& title) {
        Credential added = makeCredential();
        added.id = {};
        added.title = title.toStdString();
        const auto wipe = qScopeGuard([&] { wipeCredential(added); });
        std::string error;
        EXPECT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
            added, error, passwall::services::BackupTriggerMode::Generational))
            << error;
    };

    commit(QStringLiteral("generation drained by close"));
    const quint64 closeGeneration = coordinator->mutationGeneration();
    ASSERT_GT(closeGeneration, 0U);
    QString firstWorkerReady;
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        QDirIterator markers(backupRoot, {QStringLiteral("*.ready")},
            QDir::Files, QDirIterator::Subdirectories);
        if (!markers.hasNext()) return false;
        firstWorkerReady = markers.next();
        const auto state = coordinator->generationalOperationState(vaultPath);
        return state.phase == GenerationalOperationPhase::WorkerActive
            && state.workerAlive;
    }, 10000)) << pipelineDiagnostic().toStdString();
    ASSERT_EQ(offers.size(), 1) << pipelineDiagnostic().toStdString();
    EXPECT_EQ(offers[0].mutationGeneration, closeGeneration);
    EXPECT_TRUE(results.isEmpty()) << pipelineDiagnostic().toStdString();
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        passwall::services::GenerationalShutdownDrainStatus::NotRequested);
    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->close()); // Reentrant close cannot start another drain.
    EXPECT_TRUE(invalidated);
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_EQ(coordinator->generationalShutdownDrainState().status,
        passwall::services::GenerationalShutdownDrainStatus::WorkerActive)
        << pipelineDiagnostic().toStdString();
    EXPECT_TRUE(coordinator->generationalShutdownDrainState().workerAlive)
        << pipelineDiagnostic().toStdString();
    // The session identity retained by the drain must still route a COMMIT
    // that completes after secret cleanup into its own generation.
    commit(QStringLiteral("late generation during close drain"));
    const quint64 lateGeneration = coordinator->mutationGeneration();
    ASSERT_GT(lateGeneration, closeGeneration);
    EXPECT_EQ(offers.size(), 1) << pipelineDiagnostic().toStdString();
    EXPECT_TRUE(results.isEmpty()) << pipelineDiagnostic().toStdString();
    ASSERT_TRUE(workerMode.open(
        QIODevice::WriteOnly | QIODevice::Truncate));
    const QByteArray ordinaryMode("snapshot-published-file");
    ASSERT_EQ(workerMode.write(ordinaryMode), ordinaryMode.size());
    workerMode.close();
    const QString readySuffix = QStringLiteral(".ready");
    ASSERT_TRUE(firstWorkerReady.endsWith(readySuffix));
    QFile release(firstWorkerReady.left(
        firstWorkerReady.size() - readySuffix.size())
        + QStringLiteral(".release"));
    ASSERT_TRUE(release.open(QIODevice::WriteOnly));
    const QByteArray releaseMarker("continue");
    ASSERT_EQ(release.write(releaseMarker), releaseMarker.size());
    release.close();

    // Each CRUD owns a distinct request and a distinct serialized worker.
    // One wall-clock budget cannot distinguish a lost result from two
    // serialized workers whose aggregate time exceeds that budget under load.
    // Observe every offer and terminal worker independently so a failure names
    // the exact request and phase that stopped progressing.
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return offers.size() >= 1; }, 10000))
        << pipelineDiagnostic().toStdString();
    ASSERT_EQ(offers[0].kind,
        passwall::services::GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return results.size() >= 1; }, 10000))
        << pipelineDiagnostic().toStdString();
    ASSERT_EQ(results[0].kind,
        passwall::services::GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(results[0].requestId, offers[0].requestId);
    EXPECT_EQ(results[0].generation, offers[0].mutationGeneration);
    ASSERT_EQ(results[0].outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results[0].workerTerminated);
    EXPECT_TRUE(reachedWorker(offers[0].requestId))
        << pipelineDiagnostic().toStdString();
    ASSERT_TRUE(results[0].confirmedPublicationResult.has_value());
    ASSERT_TRUE(results[0].publication.has_value());
    const QFileInfo firstCrudCopy(results[0].publication->destination);
    EXPECT_TRUE(firstCrudCopy.isFile());
    EXPECT_GT(firstCrudCopy.size(), 0);
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return offers.size() >= 2; }, 10000))
        << pipelineDiagnostic().toStdString();
    ASSERT_EQ(offers[1].kind,
        passwall::services::GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_GT(offers[1].mutationGeneration, offers[0].mutationGeneration);
    EXPECT_NE(offers[1].requestId, offers[0].requestId);
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return results.size() >= 2; }, 10000))
        << pipelineDiagnostic().toStdString();
    ASSERT_EQ(results[1].kind,
        passwall::services::GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(results[1].requestId, offers[1].requestId);
    EXPECT_EQ(results[1].generation, offers[1].mutationGeneration);
    ASSERT_EQ(results[1].outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results[1].workerTerminated);
    EXPECT_TRUE(reachedWorker(offers[1].requestId))
        << pipelineDiagnostic().toStdString();
    ASSERT_TRUE(results[1].confirmedPublicationResult.has_value());
    ASSERT_TRUE(results[1].publication.has_value());
    const QFileInfo lateCrudCopy(results[1].publication->destination);
    EXPECT_TRUE(lateCrudCopy.isFile());
    EXPECT_GT(lateCrudCopy.size(), 0);
    EXPECT_NE(lateCrudCopy.absoluteFilePath(),
        firstCrudCopy.absoluteFilePath());
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return rotations.size() >= 2; }, 10000))
        << pipelineDiagnostic().toStdString();
    EXPECT_TRUE(passwall::tests::waitFor([&] { return !window->isVisible(); },
        10000)) << pipelineDiagnostic().toStdString();
    EXPECT_EQ(offers.size(), 2) << pipelineDiagnostic().toStdString();
    EXPECT_EQ(results.size(), 2);
    ASSERT_EQ(rotations.size(), 2) << pipelineDiagnostic().toStdString();
    EXPECT_EQ(rotations[0].requestId, results[0].requestId);
    EXPECT_EQ(rotations[1].requestId, results[1].requestId);
    EXPECT_EQ(rotations[0].rotation.outcome,
        passwall::services::BackupSeriesRotationOutcome::NoRotationNecessary);
    EXPECT_EQ(rotations[1].rotation.outcome,
        passwall::services::BackupSeriesRotationOutcome::NoRotationNecessary);
    const auto presentationDiagnostic = generationalStatusDiagnostic(
        coordinator, statusController, vaultPath, results.size(),
        rotations.size());
    EXPECT_TRUE(statusController->backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << presentationDiagnostic.toStdString();
    EXPECT_TRUE(statusController->lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << presentationDiagnostic.toStdString();
    EXPECT_TRUE(statusController->rotationStatus().contains(
        QStringLiteral("Aucune rotation"), Qt::CaseInsensitive))
        << presentationDiagnostic.toStdString();
}

TEST_F(MainWindowEditorLockTest,
    GenerationalRealCrudPublicationRotatesEightVersionsWithoutBlockingGui)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("automatic-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* rotationController = window->findChild<
        GenerationalBackupRotationController*>(
            QStringLiteral("generationalBackupRotationController"));
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(rotationController, nullptr);
    QVector<MutationBackupResult> publications;
    QVector<GenerationalBackupRotationResult> rotations;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
        [&](MutationBackupResult result) {
            publications.push_back(std::move(result));
        });
    QObject::connect(rotationController,
        &GenerationalBackupRotationController::rotationSettled, &observer,
        [&](GenerationalBackupRotationResult result) {
            rotations.push_back(std::move(result));
        });
    int heartbeatTicks = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout,
        [&] { ++heartbeatTicks; });
    heartbeat.start(0);

    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious first published generation for rotation");
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return publications.size() == 1 && rotations.size() == 1;
    }, 10000));
    ASSERT_EQ(publications[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_EQ(publications[0].outcome, MutationBackupOutcome::Published);
    ASSERT_TRUE(publications[0].publication);
    const QString firstPublished = publications[0].publication->destination;
    const QString series = QFileInfo(firstPublished).absolutePath();
    const QString family = QFileInfo(series).absolutePath();
    QString otherSeriesId = QStringLiteral("a").repeated(
        BackupSeriesIdentityService::EncodedSeriesIdSize);
    if (QFileInfo(series).fileName() == otherSeriesId)
        otherSeriesId = QStringLiteral("b").repeated(
            BackupSeriesIdentityService::EncodedSeriesIdSize);
    const QString otherSeries = QDir(family).filePath(otherSeriesId);
    ASSERT_TRUE(QDir().mkpath(otherSeries));
    ASSERT_TRUE(QFile::setPermissions(otherSeries,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner
            | QFileDevice::ExeOwner));
    const QString otherSeriesSentinel = QDir(otherSeries).filePath(
        QStringLiteral("generation_1_2025-01-01_00-00-00.pwdb"));
    ASSERT_TRUE(QFile::copy(firstPublished, otherSeriesSentinel));
    ASSERT_TRUE(QFile::setPermissions(otherSeriesSentinel,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    QFile otherSeriesBeforeFile(otherSeriesSentinel);
    ASSERT_TRUE(otherSeriesBeforeFile.open(QIODevice::ReadOnly));
    const QByteArray otherSeriesBefore = otherSeriesBeforeFile.readAll();
    otherSeriesBeforeFile.close();
    for (int day = 1; day <= 6; ++day) {
        const QString copy = QDir(series).filePath(
            QStringLiteral("generation_%1_2026-01-01_00-00-00.pwdb").arg(day + 1));
        ASSERT_TRUE(QFile::copy(firstPublished, copy));
        ASSERT_TRUE(QFile::setPermissions(copy,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    }
    const QString oldest = firstPublished;
    ASSERT_EQ(QDir(series).entryList({QStringLiteral("*.pwdb")},
        QDir::Files).size(), 7);

    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious eighth published generation";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    std::string error;
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        added, error, BackupTriggerMode::Generational)) << error;
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return publications.size() == 2 && rotations.size() == 2;
    }, 10000));
    EXPECT_GT(heartbeatTicks, 1);
    ASSERT_EQ(publications[1].outcome, MutationBackupOutcome::Published);
    EXPECT_EQ(rotations[1].rotation.outcome,
        BackupSeriesRotationOutcome::Complete)
        << rotations[1].rotation.diagnostic.toStdString();
    ASSERT_EQ(rotations[1].rotation.deleted.size(), 1);
    EXPECT_EQ(rotations[1].rotation.deleted.front().path, oldest);
    EXPECT_FALSE(QFileInfo::exists(oldest));
    EXPECT_TRUE(QFileInfo::exists(
        publications[1].publication->destination));
    EXPECT_EQ(QDir(series).entryList({QStringLiteral("*.pwdb")},
        QDir::Files).size(), 7);

    for (int day = 1; day <= 3; ++day) {
        const QString copy = QDir(series).filePath(
            QStringLiteral("generation_%1_2026-02-01_00-00-00.pwdb").arg(day + 8));
        ASSERT_TRUE(QFile::copy(publications[1].publication->destination, copy));
        ASSERT_TRUE(QFile::setPermissions(copy,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    }
    Credential later = makeCredential();
    later.id = {};
    later.title = "Fictitious publication with several excess versions";
    const auto wipeLater = qScopeGuard([&] { wipeCredential(later); });
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        later, error, BackupTriggerMode::Generational)) << error;
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return publications.size() == 3 && rotations.size() == 3;
    }, 10000));
    EXPECT_EQ(rotations[2].rotation.outcome,
        BackupSeriesRotationOutcome::Complete)
        << rotations[2].rotation.diagnostic.toStdString();
    EXPECT_EQ(rotations[2].rotation.deleted.size(), 4);
    EXPECT_EQ(rotations[2].rotation.durableDeletions, 4U);
    ASSERT_TRUE(publications[2].publication);
    EXPECT_TRUE(QFileInfo::exists(
        publications[2].publication->destination));
    EXPECT_EQ(QDir(series).entryList({QStringLiteral("*.pwdb")},
        QDir::Files).size(), 7);
    QFile otherSeriesAfterFile(otherSeriesSentinel);
    ASSERT_TRUE(otherSeriesAfterFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(otherSeriesAfterFile.readAll(), otherSeriesBefore);
    EXPECT_EQ(QDir(otherSeries).entryList({QStringLiteral("*.pwdb")},
        QDir::Files), QStringList{QFileInfo(otherSeriesSentinel).fileName()});
}

TEST_F(MainWindowEditorLockTest,
    GenerationalPublicationsQueueBehindAnActiveRotation)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("queued-rotations"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* controller = window->findChild<
        GenerationalBackupRotationController*>(
            QStringLiteral("generationalBackupRotationController"));
    auto* statusController = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(controller, nullptr);
    ASSERT_NE(statusController, nullptr);
    QVector<GenerationalBackupRequestOffer> offers;
    QVector<GenerationalOperationState> operationStates;
    QVector<GenerationalShutdownDrainState> drainStates;
    QVector<MutationBackupResult> publications;
    QVector<GenerationalBackupRotationResult> rotations;
    QStringList mutationDiagnostics;
    QVector<bool> rotationBusyStates;
    RotationCheckpointPause pause;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested, &observer,
        [&](GenerationalBackupRequestOffer offer) {
            offers.push_back(std::move(offer));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalOperationStateChanged,
        &observer, [&](GenerationalOperationState state) {
            operationStates.push_back(std::move(state));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalShutdownDrainChanged,
        &observer, [&](GenerationalShutdownDrainState state) {
            drainStates.push_back(std::move(state));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchDiagnostic, &observer,
        [&](const QString& path, quint64 generation,
            const QString& diagnostic) {
            mutationDiagnostics.push_back(QStringLiteral(
                "{path='%1' generation=%2 diagnostic='%3'}")
                .arg(path).arg(generation).arg(diagnostic));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
        [&](MutationBackupResult result) {
            publications.push_back(std::move(result));
        });
    QObject::connect(controller,
        &GenerationalBackupRotationController::rotationSettled, &observer,
        [&](GenerationalBackupRotationResult result) {
            rotations.push_back(std::move(result));
        });
    QObject::connect(controller,
        &GenerationalBackupRotationController::busyChanged, &observer,
        [&](bool busy) { rotationBusyStates.push_back(busy); });
    const auto mutationOutcomeName = [](MutationBackupOutcome outcome) {
        switch (outcome) {
        case MutationBackupOutcome::Published:
            return QStringLiteral("Published");
        case MutationBackupOutcome::Failed:
            return QStringLiteral("Failed");
        case MutationBackupOutcome::Unknown:
            return QStringLiteral("Unknown");
        }
        return QStringLiteral("<invalid>");
    };
    const auto workerOutcomeName = [](BackupOutcome outcome) {
        switch (outcome) {
        case BackupOutcome::FailedBeforePublication:
            return QStringLiteral("FailedBeforePublication");
        case BackupOutcome::Published:
            return QStringLiteral("Published");
        case BackupOutcome::DurabilityUnconfirmed:
            return QStringLiteral("DurabilityUnconfirmed");
        case BackupOutcome::CancelledBeforePublication:
            return QStringLiteral("CancelledBeforePublication");
        case BackupOutcome::Unknown:
            return QStringLiteral("Unknown");
        }
        return QStringLiteral("<invalid>");
    };
    const auto progressDiagnostic = [&] {
        const auto state = coordinator->generationalOperationState(vaultPath);
        const auto suspension =
            coordinator->generationalBackupSuspension(vaultPath);
        const auto drain = coordinator->generationalShutdownDrainState();
        QStringList offerDetails;
        for (const auto& offer : offers) {
            offerDetails.push_back(QStringLiteral(
                "{request=%1 kind=%2 mutation=%3 session=%4 path='%5'}")
                .arg(offer.requestId)
                .arg(static_cast<int>(offer.kind))
                .arg(offer.mutationGeneration)
                .arg(offer.sessionGeneration)
                .arg(offer.vaultPath));
        }
        QStringList operationDetails;
        for (const auto& operation : operationStates) {
            operationDetails.push_back(QStringLiteral(
                "{request=%1 phase=%2 kind=%3 mutation=%4 session=%5 "
                "reservation=%6 workerAlive=%7 resultObserved=%8 "
                "workerOutcome=%9}")
                .arg(operation.requestId)
                .arg(static_cast<int>(operation.phase))
                .arg(static_cast<int>(operation.kind))
                .arg(operation.mutationGeneration)
                .arg(operation.sessionGeneration)
                .arg(operation.reservationHeld)
                .arg(operation.workerAlive)
                .arg(operation.resultObserved)
                .arg(workerOutcomeName(operation.workerOutcome)));
        }
        QStringList resultDetails;
        for (const auto& result : publications) {
            const bool coordinatorReceipt = result.publication.has_value();
            const bool confirmed =
                result.confirmedPublicationResult.has_value();
            const bool workerReceipt = confirmed
                && result.confirmedPublicationResult->receipt.has_value();
            const bool receiptValid = coordinatorReceipt && workerReceipt
                && result.publication->evidence
                    == *result.confirmedPublicationResult->receipt
                && result.publication->evidence.permitsDeletion();
            const QString destination = coordinatorReceipt
                ? result.publication->destination
                : QStringLiteral("<absente>");
            const QString publishedPath = confirmed
                ? result.confirmedPublicationResult->publishedPath
                : QStringLiteral("<absent>");
            const QString confirmedOutcome = confirmed
                ? workerOutcomeName(
                    result.confirmedPublicationResult->outcome)
                : QStringLiteral("<absent>");
            const QString workerDiagnostic = confirmed
                ? result.confirmedPublicationResult->diagnostic
                : QStringLiteral("<absent>");
            resultDetails.push_back(QStringLiteral(
                "{request=%1 kind=%2 mutation=%3 session=%4 outcome=%5 "
                "workerOutcome=%6 terminated=%7 diagnostic='%8' "
                "destination='%9' destinationExists=%10 confirmed=%11 "
                "confirmedOutcome=%12 workerDiagnostic='%13' "
                "publishedPath='%14' coordinatorReceipt=%15 "
                "workerReceipt=%16 receiptValid=%17}")
                .arg(result.requestId)
                .arg(static_cast<int>(result.kind))
                .arg(result.generation)
                .arg(result.sessionGeneration)
                .arg(mutationOutcomeName(result.outcome))
                .arg(workerOutcomeName(result.workerOutcome))
                .arg(result.workerTerminated)
                .arg(result.diagnostic)
                .arg(destination)
                .arg(coordinatorReceipt && QFileInfo::exists(destination))
                .arg(confirmed)
                .arg(confirmedOutcome)
                .arg(workerDiagnostic)
                .arg(publishedPath)
                .arg(coordinatorReceipt)
                .arg(workerReceipt)
                .arg(receiptValid));
        }
        QStringList rotationDetails;
        for (const auto& rotation : rotations) {
            rotationDetails.push_back(QStringLiteral(
                "{request=%1 kind=%2 mutation=%3 session=%4 outcome=%5 "
                "publishedPath='%6' deleted=%7 durable=%8 diagnostic='%9'}")
                .arg(rotation.requestId)
                .arg(static_cast<int>(rotation.kind))
                .arg(rotation.generation)
                .arg(rotation.sessionGeneration)
                .arg(static_cast<int>(rotation.rotation.outcome))
                .arg(rotation.publishedPath)
                .arg(rotation.rotation.deleted.size())
                .arg(rotation.rotation.durableDeletions)
                .arg(rotation.rotation.diagnostic));
        }
        QStringList busyDetails;
        for (bool busy : rotationBusyStates)
            busyDetails.push_back(busy ? QStringLiteral("busy")
                                       : QStringLiteral("idle"));
        QStringList drainDetails;
        for (const auto& observed : drainStates) {
            drainDetails.push_back(QStringLiteral(
                "{status=%1 workerAlive=%2 pending=%3 latest=%4 "
                "diagnostic='%5'}")
                .arg(static_cast<int>(observed.status))
                .arg(observed.workerAlive)
                .arg(observed.requestPending)
                .arg(observed.latestMutationGeneration)
                .arg(observed.diagnostic));
        }
        QStringList materialFiles;
        QDirIterator files(backupRoot, {QStringLiteral("*.pwdb")},
            QDir::Files, QDirIterator::Subdirectories);
        while (files.hasNext())
            materialFiles.push_back(files.next());
        return QStringLiteral(
            "fixture={pid=%1 vault='%2' settings='%3' recoverySettings='%4' "
            "recoveryLock='%5' xdgConfigHome='%6' root='%7'}; "
            "checkpoint=%8 idle=%9 current={phase=%10 request=%11 "
            "generation=%12 session=%13 reservation=%14 workerAlive=%15 "
            "resultObserved=%16}; suspension={active=%17 reason=%18 "
            "latest=%19 workerAlive=%20 diagnostic='%21'}; "
            "drainCurrent={status=%22 workerAlive=%23 pending=%24 latest=%25 "
            "diagnostic='%26'}; offers=[%27]; operations=[%28]; "
            "results=[%29]; mutationDiagnostics=[%30]; rotations=[%31]; "
            "rotationBusy=[%32]; drainHistory=[%33]; materialFiles=[%34]; "
            "status={%35}")
            .arg(QCoreApplication::applicationPid())
            .arg(vaultPath)
            .arg(GlobalBackupPreferencesStore().fileName())
            .arg(QSettings(QStringLiteral("PassWall"),
                QStringLiteral("PassWall")).fileName())
            .arg(QSettings(QStringLiteral("PassWall"),
                QStringLiteral("PassWall")).fileName()
                + QStringLiteral(".registry-lock"))
            .arg(qEnvironmentVariable("XDG_CONFIG_HOME"))
            .arg(backupRoot)
            .arg(pause.entered.load())
            .arg(controller->idle())
            .arg(static_cast<int>(state.phase))
            .arg(state.requestId)
            .arg(state.mutationGeneration)
            .arg(state.sessionGeneration)
            .arg(state.reservationHeld)
            .arg(state.workerAlive)
            .arg(state.resultObserved)
            .arg(suspension.suspended)
            .arg(static_cast<int>(suspension.reason))
            .arg(suspension.latestMutationGeneration)
            .arg(suspension.workerAlive)
            .arg(suspension.diagnostic)
            .arg(static_cast<int>(drain.status))
            .arg(drain.workerAlive)
            .arg(drain.requestPending)
            .arg(drain.latestMutationGeneration)
            .arg(drain.diagnostic)
            .arg(offerDetails.join(QStringLiteral(", ")))
            .arg(operationDetails.join(QStringLiteral(", ")))
            .arg(resultDetails.join(QStringLiteral(", ")))
            .arg(mutationDiagnostics.join(QStringLiteral(", ")))
            .arg(rotationDetails.join(QStringLiteral(", ")))
            .arg(busyDetails.join(QStringLiteral(", ")))
            .arg(drainDetails.join(QStringLiteral(", ")))
            .arg(materialFiles.join(QStringLiteral(", ")))
            .arg(generationalStatusDiagnostic(coordinator, statusController,
                vaultPath, publications.size(), rotations.size()))
            .toStdString();
    };
    const auto reachedWorker = [&](quint64 requestId) {
        return std::any_of(operationStates.cbegin(), operationStates.cend(),
            [&](const GenerationalOperationState& state) {
                return state.requestId == requestId
                    && state.phase == GenerationalOperationPhase::WorkerActive;
            });
    };

    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious first publication before queued rotations");
    const bool firstPublicationSettled = passwall::tests::waitFor([&] {
        return publications.size() == 1 && rotations.size() == 1;
    }, 10000);
    ASSERT_TRUE(firstPublicationSettled) << progressDiagnostic();
    ASSERT_EQ(publications[0].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_TRUE(publications[0].workerTerminated) << progressDiagnostic();
    ASSERT_EQ(publications[0].outcome, MutationBackupOutcome::Published)
        << progressDiagnostic();
    ASSERT_EQ(rotations[0].requestId, publications[0].requestId);
    ASSERT_EQ(rotations[0].rotation.outcome,
        BackupSeriesRotationOutcome::NoRotationNecessary);
    ASSERT_TRUE(controller->idle()) << progressDiagnostic();

    passwall::tests::setGenerationalRotationCheckpointHook(
        pauseGenerationalRotation, &pause);
    const auto release = qScopeGuard([&] {
        pause.released = true;
        pause.condition.notify_all();
        passwall::tests::setGenerationalRotationCheckpointHook(nullptr, nullptr);
    });
    Credential first = makeCredential();
    first.id = {};
    first.title = "Fictitious first queued rotation";
    const auto wipeFirst = qScopeGuard([&] { wipeCredential(first); });
    std::string error;
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        first, error, BackupTriggerMode::Generational)) << error;
    const bool firstRotationPaused = passwall::tests::waitFor([&] {
        return publications.size() == 2 && pause.entered.load();
    }, 10000);
    ASSERT_TRUE(firstRotationPaused) << progressDiagnostic();
    ASSERT_EQ(publications[1].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_TRUE(reachedWorker(publications[1].requestId))
        << progressDiagnostic();
    ASSERT_TRUE(publications[1].workerTerminated) << progressDiagnostic();
    ASSERT_EQ(publications[1].outcome, MutationBackupOutcome::Published)
        << progressDiagnostic();
    ASSERT_EQ(rotations.size(), 1) << progressDiagnostic();
    EXPECT_FALSE(controller->idle());

    Credential second = makeCredential();
    second.id = {};
    second.title = "Fictitious publication queued behind active rotation";
    const auto wipeSecond = qScopeGuard([&] { wipeCredential(second); });
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        second, error, BackupTriggerMode::Generational)) << error;
    const bool secondPublished = passwall::tests::waitFor(
        [&] { return publications.size() == 3; }, 10000);
    ASSERT_TRUE(secondPublished) << progressDiagnostic();
    ASSERT_EQ(offers.size(), 3) << progressDiagnostic();
    ASSERT_EQ(publications[2].kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(publications[2].requestId, offers[2].requestId)
        << progressDiagnostic();
    EXPECT_EQ(publications[2].generation, offers[2].mutationGeneration)
        << progressDiagnostic();
    ASSERT_TRUE(reachedWorker(publications[2].requestId))
        << progressDiagnostic();
    ASSERT_TRUE(publications[2].workerTerminated) << progressDiagnostic();
    ASSERT_EQ(publications[2].outcome, MutationBackupOutcome::Published)
        << progressDiagnostic();
    ASSERT_EQ(publications[2].workerOutcome, BackupOutcome::Published)
        << progressDiagnostic();
    ASSERT_TRUE(publications[2].publication) << progressDiagnostic();
    ASSERT_TRUE(publications[2].confirmedPublicationResult)
        << progressDiagnostic();
    ASSERT_TRUE(publications[2].confirmedPublicationResult->receipt)
        << progressDiagnostic();
    EXPECT_EQ(publications[2].publication->destination,
        publications[2].confirmedPublicationResult->publishedPath)
        << progressDiagnostic();
    EXPECT_EQ(publications[2].publication->evidence,
        *publications[2].confirmedPublicationResult->receipt)
        << progressDiagnostic();
    EXPECT_TRUE(publications[2].publication->evidence.permitsDeletion())
        << progressDiagnostic();
    EXPECT_TRUE(QFileInfo::exists(
        publications[2].publication->destination))
        << progressDiagnostic();
    ASSERT_EQ(rotations.size(), 1) << progressDiagnostic();
    EXPECT_FALSE(controller->idle());

    pause.released = true;
    pause.condition.notify_all();
    const bool queueDrained = passwall::tests::waitFor([&] {
        return rotations.size() == 3 && controller->idle();
    }, 10000);
    ASSERT_TRUE(queueDrained) << progressDiagnostic();
    EXPECT_EQ(rotations[1].requestId, publications[1].requestId);
    EXPECT_EQ(rotations[2].requestId, publications[2].requestId);
    EXPECT_NE(rotations[1].requestId, rotations[2].requestId);
    EXPECT_EQ(rotations[1].rotation.outcome,
        BackupSeriesRotationOutcome::NoRotationNecessary);
    EXPECT_EQ(rotations[2].rotation.outcome,
        BackupSeriesRotationOutcome::NoRotationNecessary);
}

TEST_F(MainWindowEditorLockTest,
    GenerationalFailedUnknownAndInvalidReceiptsNeverStartRotation)
{
    using namespace passwall::services;
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    const QVector<QByteArray> modes{
        "failed", "missing", "durability-file",
        "snapshot-published-without-receipt",
        "snapshot-insufficient-receipt",
        "snapshot-wrong-path-receipt"};
    for (qsizetype index = 0; index < modes.size(); ++index) {
        const QString backupRoot = testDirectory->filePath(
            QStringLiteral("refused-rotation-%1").arg(index));
        ASSERT_TRUE(QDir().mkpath(backupRoot));
        ASSERT_TRUE(GlobalBackupPreferencesStore().save(
            {backupRoot, 7}).valid());
        QFile selection(vaultPath + QStringLiteral(".fake-mode"));
        ASSERT_TRUE(selection.open(
            QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(selection.write(modes[index]), modes[index].size());
        selection.close();

        window.reset();
        QApplication::processEvents();
        window = MainWindow::createForGenerationalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
            QStringLiteral("automaticBackupCoordinator"));
        auto* controller = window->findChild<
            GenerationalBackupRotationController*>(
                QStringLiteral("generationalBackupRotationController"));
        auto* status = window->findChild<
            passwall::gui::GenerationalBackupStatusController*>();
        ASSERT_NE(coordinator, nullptr);
        ASSERT_NE(controller, nullptr);
        ASSERT_NE(status, nullptr);
        QVector<MutationBackupResult> publications;
        int rotations = 0;
        QObject observer;
        QObject::connect(coordinator,
            &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
            [&](MutationBackupResult result) {
                publications.push_back(std::move(result));
            });
        QObject::connect(controller,
            &GenerationalBackupRotationController::rotationSettled, &observer,
            [&](GenerationalBackupRotationResult) { ++rotations; });
        runBounded([&] { unlock(); });
        commitGenerationalCredential(
            "Fictitious generation with refused publication evidence");
        const bool terminalResultReceived = passwall::tests::waitFor(
            [&] { return publications.size() == 1; }, 10000);
        ASSERT_TRUE(terminalResultReceived)
            << generationalStatusDiagnostic(coordinator, status, vaultPath,
                   publications.size(), rotations).toStdString();
        EXPECT_NE(publications.front().outcome,
            MutationBackupOutcome::Published) << modes[index].constData();
        EXPECT_FALSE(status->backupStatus().contains(
            QStringLiteral("publiée"), Qt::CaseInsensitive));
        EXPECT_TRUE(status->backupStatus().contains(
            modes[index] == QByteArray("failed")
                ? QStringLiteral("échouée")
                : QStringLiteral("incertain"),
            Qt::CaseInsensitive))
            << generationalStatusDiagnostic(coordinator, status, vaultPath,
                   publications.size(), rotations).toStdString();
        EXPECT_TRUE(status->lastBackupResultStatus().contains(
            modes[index] == QByteArray("failed")
                ? QStringLiteral("échouée")
                : QStringLiteral("incertain"),
            Qt::CaseInsensitive))
            << generationalStatusDiagnostic(coordinator, status, vaultPath,
                   publications.size(), rotations).toStdString();
        EXPECT_TRUE(status->retryAvailable())
            << generationalStatusDiagnostic(coordinator, status, vaultPath,
                   publications.size(), rotations).toStdString();
        auto* statusButton = window->findChild<QToolButton*>(
            QStringLiteral("generationalBackupStatusButton"));
        ASSERT_NE(statusButton, nullptr);
        EXPECT_TRUE(statusButton->text().contains(
            QStringLiteral("intervention"), Qt::CaseInsensitive));
        QElapsedTimer grace;
        grace.start();
        ASSERT_TRUE(passwall::tests::waitFor(
            [&] { return grace.elapsed() >= 100; }, 1000));
        EXPECT_EQ(rotations, 0) << modes[index].constData();
    }
}

TEST_F(MainWindowEditorLockTest,
    GenerationalDuplicateTerminalCallbackCannotStartASecondRotation)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("duplicate-rotation"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* controller = window->findChild<
        GenerationalBackupRotationController*>(
            QStringLiteral("generationalBackupRotationController"));
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(controller, nullptr);
    std::optional<MutationBackupResult> publication;
    int rotations = 0;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
        [&](MutationBackupResult result) {
            if (!publication) publication = std::move(result);
        });
    QObject::connect(controller,
        &GenerationalBackupRotationController::rotationSettled, &observer,
        [&](GenerationalBackupRotationResult) { ++rotations; });
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious generation for duplicate terminal callback");
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return publication.has_value() && rotations == 1; }, 10000));
    coordinator->mutationBatchSettled(*publication);
    QElapsedTimer grace;
    grace.start();
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return grace.elapsed() >= 150; }, 1000));
    EXPECT_EQ(rotations, 1);
}

TEST_F(MainWindowEditorLockTest,
    GenerationalVoluntaryBackupButtonPublishesWithoutNewCommitAndLocks)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("voluntary-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    {
        QFile mode(vaultPath + QStringLiteral(".fake-mode"));
        ASSERT_TRUE(mode.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(mode.write("snapshot-published-file"), 23);
    }
    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* preferences = window->findChild<
        passwall::gui::GlobalBackupPreferencesController*>();
    auto* status = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(preferences, nullptr);
    ASSERT_NE(status, nullptr);
    QObject observer;
    int reads = 0;
    int offers = 0;
    QVector<MutationBackupResult> results;
    QObject::connect(preferences,
        &passwall::gui::GlobalBackupPreferencesController::readSettled,
        &observer, [&](GlobalBackupPreferencesStatus value) {
            EXPECT_EQ(value, GlobalBackupPreferencesStatus::Valid);
            ++reads;
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer) { ++offers; });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reads == 1; }, 10000));
    auto* action = window->findChild<QAction*>(
        QStringLiteral("generationalBackupStatusAction"));
    ASSERT_NE(action, nullptr);
    action->trigger();
    QPointer<QPushButton> button = window->findChild<QPushButton*>(
        QStringLiteral("generationalBackupManualButton"));
    ASSERT_TRUE(button);
    EXPECT_FALSE(button->isEnabled());
    button->click();
    EXPECT_EQ(offers, 0);
    QPointer<QDialog> dialog = window->findChild<QDialog*>(
        QStringLiteral("generationalBackupStatusDialog"));
    ASSERT_TRUE(dialog);
    dialog->reject();
    // The controller clears its pointer immediately, but deletes the dialog
    // later. Do not accidentally retrieve its disabled button on reopening.
    QCoreApplication::sendPostedEvents(dialog.data(), QEvent::DeferredDelete);
    ASSERT_TRUE(dialog.isNull());
    ASSERT_TRUE(button.isNull());
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    EXPECT_EQ(offers, 0);
    EXPECT_EQ(coordinator->mutationGeneration(), 0U);
    action->trigger();
    button = window->findChild<QPushButton*>(
        QStringLiteral("generationalBackupManualButton"));
    ASSERT_TRUE(button);
    ASSERT_TRUE(button->isEnabled());
    button->click();
    button->click(); // The common coordinator rejects duplicate admission.
    EXPECT_FALSE(coordinator->modificationGroupingPending());
    lock(); // The already admitted backup must remain eligible without a key.
    EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return results.size() == 1; }, 10000));
    EXPECT_EQ(offers, 1);
    EXPECT_EQ(results[0].outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results[0].workerTerminated);
    ASSERT_TRUE(results[0].publication.has_value());
    EXPECT_TRUE(QFileInfo::exists(results[0].publication->destination));
    EXPECT_TRUE(status->lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));
    action->trigger();
    button = window->findChild<QPushButton*>(
        QStringLiteral("generationalBackupManualButton"));
    ASSERT_TRUE(button);
    EXPECT_FALSE(button->isEnabled());
}

TEST_F(MainWindowEditorLockTest,
    GenerationalSuspensionOffersOneExplicitRevalidatedRetry)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("explicit-retry-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    auto setWorkerMode = [&](const QByteArray& mode) {
        QFile selection(vaultPath + QStringLiteral(".fake-mode"));
        ASSERT_TRUE(selection.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(selection.write(mode), mode.size());
    };
    setWorkerMode("enospc");

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* status = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(status, nullptr);
    int offers = 0;
    QVector<MutationBackupResult> results;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer) { ++offers; });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });

    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious generation for explicit retry");
    const bool failedResultReceived = passwall::tests::waitFor(
        [&] { return results.size() == 1; }, 10000);
    ASSERT_TRUE(failedResultReceived)
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    ASSERT_EQ(results.front().kind,
        GenerationalBackupRequestKind::CrudGeneration);
    ASSERT_EQ(results.front().outcome, MutationBackupOutcome::Failed);
    EXPECT_TRUE(status->backupStatus().contains(
        QStringLiteral("suspendues"), Qt::CaseInsensitive))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_TRUE(status->backupDetail().contains(QStringLiteral("errno=28")))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    ASSERT_TRUE(status->retryAvailable())
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_TRUE(status->lastBackupResultStatus().contains(
        QStringLiteral("échouée"), Qt::CaseInsensitive))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    ASSERT_EQ(offers, 1);

    lock();
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_FALSE(status->retryAvailable());
    EXPECT_EQ(offers, 1);
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    ASSERT_TRUE(status->retryAvailable())
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_EQ(offers, 1);

    auto* action = window->findChild<QAction*>(
        QStringLiteral("generationalBackupStatusAction"));
    ASSERT_NE(action, nullptr);
    action->trigger();
    auto* retry = window->findChild<QPushButton*>(
        QStringLiteral("generationalBackupRetryButton"));
    ASSERT_NE(retry, nullptr);
    ASSERT_TRUE(retry->isEnabled());
    setWorkerMode("snapshot-published-file");
    retry->click();
    EXPECT_FALSE(retry->isEnabled());
    retry->click();

    const bool retryResultReceived = passwall::tests::waitFor(
        [&] { return results.size() == 2; }, 10000);
    ASSERT_TRUE(retryResultReceived)
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_EQ(offers, 2);
    EXPECT_EQ(results.back().kind,
        GenerationalBackupRequestKind::CrudGeneration);
    EXPECT_EQ(results.back().generation, results.front().generation);
    EXPECT_EQ(results.back().outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results.back().workerTerminated);
    EXPECT_TRUE(status->backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_TRUE(status->lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_FALSE(status->retryAvailable());
    auto* statusButton = window->findChild<QToolButton*>(
        QStringLiteral("generationalBackupStatusButton"));
    ASSERT_NE(statusButton, nullptr);
    EXPECT_TRUE(statusButton->text().contains(
        QStringLiteral("état disponible"), Qt::CaseInsensitive));
}

TEST_F(MainWindowEditorLockTest,
    GenerationalCloseFailureStaysLockedUntilReauthenticationAndExplicitRetry)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("close-failure-stay"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    auto setWorkerMode = [&](const QByteArray& mode) {
        QFile selection(vaultPath + QStringLiteral(".fake-mode"));
        ASSERT_TRUE(selection.open(
            QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(selection.write(mode), mode.size());
    };
    setWorkerMode("gated-enospc");

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* status = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(status, nullptr);
    QVector<GenerationalBackupRequestOffer> offers;
    QVector<MutationBackupResult> results;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](GenerationalBackupRequestOffer offer) {
            offers.push_back(std::move(offer));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });

    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious generation failing during close");
    QString readyMarker;
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        QDirIterator markers(backupRoot, {QStringLiteral("*.ready")},
            QDir::Files, QDirIterator::Subdirectories);
        if (!markers.hasNext()) return false;
        readyMarker = markers.next();
        const auto operation = coordinator->generationalOperationState(
            vaultPath);
        return operation.phase == GenerationalOperationPhase::WorkerActive
            && operation.workerAlive;
    }, 10000));
    ASSERT_EQ(offers.size(), 1);
    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_TRUE(window->isVisible());

    const QString readySuffix = QStringLiteral(".ready");
    ASSERT_TRUE(readyMarker.endsWith(readySuffix));
    QFile release(readyMarker.left(
        readyMarker.size() - readySuffix.size())
        + QStringLiteral(".release"));
    ASSERT_TRUE(release.open(QIODevice::WriteOnly));
    ASSERT_EQ(release.write("continue", 8), 8);
    release.close();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return results.size() == 1
            && window->findChild<QMessageBox*>(
                QStringLiteral("generationalCloseFailureNotice"));
    }, 10000))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    ASSERT_EQ(results[0].outcome, MutationBackupOutcome::Failed);
    EXPECT_TRUE(results[0].workerTerminated);
    auto* notice = window->findChild<QMessageBox*>(
        QStringLiteral("generationalCloseFailureNotice"));
    ASSERT_NE(notice, nullptr);
    EXPECT_TRUE(notice->text().contains(
        QStringLiteral("verrouillé"), Qt::CaseInsensitive));
    EXPECT_TRUE(notice->text().contains(QStringLiteral("errno=28")));
    EXPECT_FALSE(status->retryAvailable());
    auto* stay = notice->findChild<QPushButton*>(
        QStringLiteral("generationalCloseFailureStayButton"));
    ASSERT_NE(stay, nullptr);
    stay->click();
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return coordinator->generationalShutdownDrainState().status
                == GenerationalShutdownDrainStatus::NotRequested
            && window->findChild<QMessageBox*>(
                QStringLiteral("generationalCloseFailureNotice")) == nullptr;
    }));
    EXPECT_TRUE(window->isVisible());
    EXPECT_FALSE(window->acquireLease().unlocked);
    auto* centralWidget = window->findChild<QWidget*>(
        QStringLiteral("centralwidget"));
    ASSERT_NE(centralWidget, nullptr);
    EXPECT_TRUE(centralWidget->isEnabled());
    EXPECT_TRUE(coordinator->generationalBackupSuspension(vaultPath).suspended);
    EXPECT_FALSE(status->retryAvailable());

    setWorkerMode("snapshot-published-file");
    runBounded([&] { unlock(); });
    ASSERT_TRUE(window->acquireLease().unlocked);
    ASSERT_TRUE(status->retryAvailable());
    auto* statusAction = window->findChild<QAction*>(
        QStringLiteral("generationalBackupStatusAction"));
    ASSERT_NE(statusAction, nullptr);
    statusAction->trigger();
    auto* retry = window->findChild<QPushButton*>(
        QStringLiteral("generationalBackupRetryButton"));
    ASSERT_NE(retry, nullptr);
    ASSERT_TRUE(retry->isEnabled());
    retry->click();
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return results.size() == 2; }, 10000))
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               results.size(), 0).toStdString();
    EXPECT_EQ(offers.size(), 2);
    EXPECT_EQ(results[1].outcome, MutationBackupOutcome::Published);
    EXPECT_TRUE(results[1].workerTerminated);
    EXPECT_FALSE(status->retryAvailable());
}

TEST_F(MainWindowEditorLockTest,
    GenerationalCloseAfterFailedBackupAllowsExplicitDeparture)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("close-failure-leave"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    QFile selection(vaultPath + QStringLiteral(".fake-mode"));
    ASSERT_TRUE(selection.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(selection.write("enospc", 6), 6);
    selection.close();

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    QVector<MutationBackupResult> results;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious failed generation before explicit departure");
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return results.size() == 1; }, 10000));
    ASSERT_EQ(results[0].outcome, MutationBackupOutcome::Failed);

    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->acquireLease().unlocked);
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return window->findChild<QMessageBox*>(
            QStringLiteral("generationalCloseFailureNotice")) != nullptr;
    }));
    auto* leave = window->findChild<QPushButton*>(
        QStringLiteral("generationalCloseFailureQuitButton"));
    ASSERT_NE(leave, nullptr);
    leave->click();
    EXPECT_TRUE(passwall::tests::waitFor(
        [&] { return !window->isVisible(); }, 10000));
    EXPECT_EQ(results.size(), 1);
    EXPECT_TRUE(coordinator->generationalBackupSuspension(vaultPath).suspended);
}

TEST_F(MainWindowEditorLockTest,
    GenerationalChangedOrUnreadablePreferencesDuringAdmissionRefuseDeletion)
{
    using namespace passwall::services;
    for (int change = 0; change < 3; ++change) {
        const bool changeRoot = change == 1;
        const QString backupRoot = testDirectory->filePath(
            changeRoot ? QStringLiteral("changing-root")
                       : change == 0
                ? QStringLiteral("changing-retention")
                : QStringLiteral("unreadable-preferences"));
        const QString replacementRoot = testDirectory->filePath(
            QStringLiteral("replacement-root"));
        ASSERT_TRUE(QDir().mkpath(backupRoot));
        ASSERT_TRUE(QDir().mkpath(replacementRoot));
        ASSERT_TRUE(GlobalBackupPreferencesStore().save(
            {backupRoot, 7}).valid());
        RotationCheckpointPause pause;
        passwall::tests::setGenerationalRotationCheckpointHook(
            pauseGenerationalRotation, &pause);
        const auto release = qScopeGuard([&] {
            pause.released = true;
            pause.condition.notify_all();
            passwall::tests::setGenerationalRotationCheckpointHook(
                nullptr, nullptr);
        });

        window.reset();
        QApplication::processEvents();
        window = MainWindow::createForGenerationalTests();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
            QStringLiteral("automaticBackupCoordinator"));
        auto* controller = window->findChild<
            GenerationalBackupRotationController*>(
                QStringLiteral("generationalBackupRotationController"));
        auto* status = window->findChild<
            passwall::gui::GenerationalBackupStatusController*>();
        ASSERT_NE(coordinator, nullptr);
        ASSERT_NE(controller, nullptr);
        ASSERT_NE(status, nullptr);
        std::optional<MutationBackupResult> publication;
        std::optional<GenerationalBackupRotationResult> rotation;
        QObject observer;
        QObject::connect(coordinator,
            &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
            [&](MutationBackupResult result) {
                publication = std::move(result);
            });
        QObject::connect(controller,
            &GenerationalBackupRotationController::rotationSettled, &observer,
            [&](GenerationalBackupRotationResult result) {
                rotation = std::move(result);
            });
        runBounded([&] { unlock(); });
        commitGenerationalCredential(
            "Fictitious generation before rotation preference change");
        const bool publicationEnteredRotation = passwall::tests::waitFor([&] {
            return publication.has_value() && pause.entered.load();
        }, 10000);
        ASSERT_TRUE(publicationEnteredRotation)
            << generationalStatusDiagnostic(coordinator, status, vaultPath,
                   publication.has_value() ? 1 : 0,
                   rotation.has_value() ? 1 : 0).toStdString();
        ASSERT_EQ(publication->outcome, MutationBackupOutcome::Published);
        if (change == 2) {
            ASSERT_TRUE(QFile::setPermissions(
                GlobalBackupPreferencesStore().fileName(),
                QFileDevice::ReadOwner | QFileDevice::WriteOwner
                    | QFileDevice::ReadGroup));
        } else {
            const auto changed = changeRoot
                ? GlobalBackupPreferences{replacementRoot, 7}
                : GlobalBackupPreferences{backupRoot, 8};
            ASSERT_TRUE(GlobalBackupPreferencesStore().save(changed).valid());
        }
        pause.released = true;
        pause.condition.notify_all();
        const bool rotationSettled = passwall::tests::waitFor(
            [&] { return rotation.has_value(); }, 10000);
        ASSERT_TRUE(rotationSettled)
            << generationalStatusDiagnostic(coordinator, status, vaultPath,
                   publication.has_value() ? 1 : 0,
                   rotation.has_value() ? 1 : 0).toStdString();
        EXPECT_EQ(rotation->rotation.outcome,
            BackupSeriesRotationOutcome::Refused);
        EXPECT_TRUE(rotation->rotation.deleted.isEmpty());
        ASSERT_TRUE(publication->publication);
        EXPECT_TRUE(QFileInfo::exists(
            publication->publication->destination));
        const auto presentationDiagnostic = generationalStatusDiagnostic(
            coordinator, status, vaultPath,
            publication.has_value() ? 1 : 0,
            rotation.has_value() ? 1 : 0);
        EXPECT_TRUE(status->lastBackupResultStatus().contains(
            QStringLiteral("publiée"), Qt::CaseInsensitive))
            << presentationDiagnostic.toStdString();
        EXPECT_TRUE(status->rotationStatus().contains(
            QStringLiteral("refusée"), Qt::CaseInsensitive))
            << presentationDiagnostic.toStdString();
        passwall::tests::setGenerationalRotationCheckpointHook(
            nullptr, nullptr);
        if (change == 2)
            ASSERT_TRUE(QFile::setPermissions(
                GlobalBackupPreferencesStore().fileName(),
                QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    }
}

TEST_F(MainWindowEditorLockTest,
    GenerationalPreferenceChangeAfterDeletionStopsWithoutChangingPublication)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("preference-change-after-deletion"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    auto* controller = window->findChild<
        GenerationalBackupRotationController*>(
            QStringLiteral("generationalBackupRotationController"));
    auto* status = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(coordinator, nullptr);
    ASSERT_NE(controller, nullptr);
    ASSERT_NE(status, nullptr);
    QVector<MutationBackupResult> publications;
    QVector<GenerationalBackupRotationResult> rotations;
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
        [&](MutationBackupResult result) {
            publications.push_back(std::move(result));
        });
    QObject::connect(controller,
        &GenerationalBackupRotationController::rotationSettled, &observer,
        [&](GenerationalBackupRotationResult result) {
            rotations.push_back(std::move(result));
        });
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious first generation before deletion checkpoint");
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return publications.size() == 1 && rotations.size() == 1;
    }, 10000));
    ASSERT_TRUE(publications[0].publication);
    const QString firstPublished = publications[0].publication->destination;
    const QString series = QFileInfo(firstPublished).absolutePath();
    for (int day = 1; day <= 7; ++day) {
        const QString copy = QDir(series).filePath(
            QStringLiteral("generation_%1_2026-03-01_00-00-00.pwdb").arg(day + 1));
        ASSERT_TRUE(QFile::copy(firstPublished, copy));
        ASSERT_TRUE(QFile::setPermissions(copy,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner));
    }

    RotationCheckpointPause pause;
    pause.checkpoint = BackupSeriesRotationCheckpoint::AfterDeletion;
    passwall::tests::setGenerationalRotationCheckpointHook(
        pauseGenerationalRotation, &pause);
    const auto release = qScopeGuard([&] {
        pause.released = true;
        pause.condition.notify_all();
        passwall::tests::setGenerationalRotationCheckpointHook(nullptr, nullptr);
    });
    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious publication during preference change";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    std::string error;
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        added, error, BackupTriggerMode::Generational)) << error;
    const bool publicationEnteredRotation = passwall::tests::waitFor([&] {
        return publications.size() == 2 && pause.entered.load();
    }, 10000);
    ASSERT_TRUE(publicationEnteredRotation)
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               publications.size(), rotations.size()).toStdString();
    ASSERT_EQ(publications[1].outcome, MutationBackupOutcome::Published);
    ASSERT_TRUE(publications[1].workerTerminated);
    ASSERT_TRUE(publications[1].publication);
    EXPECT_TRUE(QFileInfo::exists(publications[1].publication->destination));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 8}).valid());
    pause.released = true;
    pause.condition.notify_all();
    const bool rotationSettled = passwall::tests::waitFor(
        [&] { return rotations.size() == 2; }, 10000);
    ASSERT_TRUE(rotationSettled)
        << generationalStatusDiagnostic(coordinator, status, vaultPath,
               publications.size(), rotations.size()).toStdString();
    EXPECT_EQ(rotations[1].rotation.outcome,
        BackupSeriesRotationOutcome::Partial);
    EXPECT_EQ(rotations[1].rotation.deleted.size(), 1);
    EXPECT_EQ(rotations[1].rotation.durableDeletions, 1U);
    EXPECT_TRUE(QFileInfo::exists(publications[1].publication->destination));
    EXPECT_EQ(publications[1].outcome, MutationBackupOutcome::Published);
    const auto presentationDiagnostic = generationalStatusDiagnostic(
        coordinator, status, vaultPath, publications.size(), rotations.size());
    EXPECT_TRUE(status->lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << presentationDiagnostic.toStdString();
    EXPECT_TRUE(status->rotationStatus().contains(
        QStringLiteral("partielle"), Qt::CaseInsensitive))
        << presentationDiagnostic.toStdString();
    EXPECT_EQ(QDir(series).entryList({QStringLiteral("*.pwdb")},
        QDir::Files).size(), 8);
}

TEST_F(MainWindowEditorLockTest,
    GenerationalCloseSupervisesAnActiveRotationWithoutBlockingGui)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("close-during-rotation"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    RotationCheckpointPause pause;
    passwall::tests::setGenerationalRotationCheckpointHook(
        pauseGenerationalRotation, &pause);
    const auto release = qScopeGuard([&] {
        pause.released = true;
        pause.condition.notify_all();
        passwall::tests::setGenerationalRotationCheckpointHook(nullptr, nullptr);
    });

    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* controller = window->findChild<
        GenerationalBackupRotationController*>(
            QStringLiteral("generationalBackupRotationController"));
    ASSERT_NE(controller, nullptr);
    int rotations = 0;
    QObject observer;
    QObject::connect(controller,
        &GenerationalBackupRotationController::rotationSettled, &observer,
        [&](GenerationalBackupRotationResult) { ++rotations; });
    int heartbeatTicks = 0;
    QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout,
        [&] { ++heartbeatTicks; });
    heartbeat.start(0);
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious generation before close during rotation");
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return pause.entered.load(); }, 10000));

    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_TRUE(window->isVisible());
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return heartbeatTicks > 2; }, 1000));
    pause.released = true;
    pause.condition.notify_all();
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return rotations == 1 && !window->isVisible(); }, 10000));
}

TEST_F(MainWindowEditorLockTest,
    GenerationalOwnerDestructionRequestsControlledRotationCancellation)
{
    using namespace passwall::services;
    const QString backupRoot = testDirectory->filePath(
        QStringLiteral("destroy-during-rotation"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(GlobalBackupPreferencesStore().save({backupRoot, 7}).valid());
    RotationCheckpointPause pause;
    passwall::tests::setGenerationalRotationCheckpointHook(
        pauseGenerationalRotation, &pause);
    const auto release = qScopeGuard([&] {
        pause.released = true;
        pause.condition.notify_all();
        passwall::tests::setGenerationalRotationCheckpointHook(nullptr, nullptr);
    });
    window.reset();
    QApplication::processEvents();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    QString publishedPath;
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    QObject observer;
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::mutationBatchSettled, &observer,
        [&](MutationBackupResult result) {
            if (result.publication)
                publishedPath = result.publication->destination;
        });
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious generation before owner destruction");
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return !publishedPath.isEmpty() && pause.entered.load();
    }, 10000));
    QElapsedTimer destruction;
    destruction.start();
    window.reset();
    EXPECT_LT(destruction.elapsed(), 1000);
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
    pause.released = true;
    pause.condition.notify_all();
    QElapsedTimer grace;
    grace.start();
    ASSERT_TRUE(passwall::tests::waitFor(
        [&] { return grace.elapsed() >= 150; }, 1000));
    EXPECT_TRUE(QFileInfo::exists(publishedPath));
}

TEST_F(MainWindowEditorLockTest,
    GenerationalCloseDuringAWorkerDrainsTheConfirmedResultOnlyOnce)
{
    using passwall::services::AutomaticBackupCoordinator;
    using passwall::services::GenerationalOperationPhase;
    using passwall::services::MutationBackupOutcome;
    using passwall::services::MutationBackupResult;
    const QString backupRoot = testDirectory->filePath(QStringLiteral("automatic-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(passwall::services::GlobalBackupPreferencesStore().save(
        {backupRoot, 7}).valid());

    window.reset();
    QApplication::processEvents();
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    auto* statusController = window->findChild<
        passwall::gui::GenerationalBackupStatusController*>();
    ASSERT_NE(statusController, nullptr);
    QVector<MutationBackupResult> results;
    QObject observer;
    QObject::connect(coordinator, &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });
    auto setWorkerMode = [&](const QByteArray& mode) {
        QFile selection(vaultPath + QStringLiteral(".fake-mode"));
        ASSERT_TRUE(selection.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(selection.write(mode), mode.size());
    };
    setWorkerMode("snapshot-published-file");
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious first generation before active-worker close");
    ASSERT_TRUE(passwall::tests::waitFor([&] { return results.size() == 1; }, 10000));
    ASSERT_EQ(results[0].outcome, MutationBackupOutcome::Published);

    setWorkerMode("slow-snapshot-published-file");
    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious generation while worker is active";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    std::string error;
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        added, error, passwall::services::BackupTriggerMode::Generational))
        << error;
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        const auto state = coordinator->generationalOperationState(vaultPath);
        return state.phase == GenerationalOperationPhase::WorkerActive
            && state.workerAlive;
    }, 10000));
    EXPECT_TRUE(statusController->backupStatus().contains(
        QStringLiteral("en cours"), Qt::CaseInsensitive));
    EXPECT_FALSE(statusController->backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive));

    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->close());
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_TRUE(window->isVisible());
    const bool drainedResultReceived = passwall::tests::waitFor(
        [&] { return results.size() == 2; }, 10000);
    ASSERT_TRUE(drainedResultReceived)
        << generationalStatusDiagnostic(coordinator, statusController,
               vaultPath, results.size(), 0).toStdString();
    EXPECT_EQ(results[1].outcome, MutationBackupOutcome::Published);
    ASSERT_TRUE(results[1].publication.has_value());
    EXPECT_TRUE(QFileInfo(results[1].publication->destination).isFile());
    EXPECT_TRUE(passwall::tests::waitFor([&] { return !window->isVisible(); }));
    EXPECT_EQ(results.size(), 2);
    EXPECT_TRUE(statusController->backupStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << generationalStatusDiagnostic(coordinator, statusController,
               vaultPath, results.size(), 0).toStdString();
    EXPECT_TRUE(statusController->lastBackupResultStatus().contains(
        QStringLiteral("publiée"), Qt::CaseInsensitive))
        << generationalStatusDiagnostic(coordinator, statusController,
               vaultPath, results.size(), 0).toStdString();
}

TEST_F(MainWindowEditorLockTest,
    GenerationalPreferenceInvalidationConsumesNoLateCrudWorker)
{
    using passwall::services::AutomaticBackupCoordinator;
    using passwall::services::GenerationalOperationPhase;
    using passwall::services::GlobalBackupPreferencesResult;
    using passwall::services::GlobalBackupPreferencesStatus;
    using passwall::services::MutationBackupOutcome;
    using passwall::services::MutationBackupResult;
    const QString backupRoot = testDirectory->filePath(QStringLiteral("automatic-backups"));
    ASSERT_TRUE(QDir().mkpath(backupRoot));
    ASSERT_TRUE(passwall::services::GlobalBackupPreferencesStore().save(
        {backupRoot, 7}).valid());

    window.reset();
    QApplication::processEvents();
    passwall::tests::setBackupSettingsTestWorker(
        QString::fromLatin1(EXPORT_FAKE_WORKER));
    const auto resetWorker = qScopeGuard([] {
        passwall::tests::setBackupSettingsTestWorker({});
    });
    QFile selection(vaultPath + QStringLiteral(".fake-mode"));
    ASSERT_TRUE(selection.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(selection.write("snapshot-published-file"), 23);
    selection.close();
    window = MainWindow::createForGenerationalTests();
    window->setLifecycleProtectionValidator([] { return true; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    window->show();
    auto* coordinator = window->findChild<passwall::services::AutomaticBackupCoordinator*>(
        QStringLiteral("automaticBackupCoordinator"));
    ASSERT_NE(coordinator, nullptr);
    QVector<MutationBackupResult> results;
    QVector<quint64> invalidated;
    bool invalidateNextCrud = false;
    bool preferenceInvalidated = false;
    QObject observer;
    QObject::connect(coordinator, &AutomaticBackupCoordinator::mutationBatchSettled,
        &observer, [&](MutationBackupResult result) {
            results.push_back(std::move(result));
        });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequestInvalidated,
        &observer, [&](quint64 requestId) { invalidated.push_back(requestId); });
    QObject::connect(coordinator,
        &AutomaticBackupCoordinator::generationalBackupRequested,
        &observer, [&](passwall::services::GenerationalBackupRequestOffer offer) {
            if (!invalidateNextCrud || preferenceInvalidated
                || offer.kind != passwall::services::GenerationalBackupRequestKind::CrudGeneration)
                return;
            preferenceInvalidated = true;
            GlobalBackupPreferencesResult unavailable;
            unavailable.status = GlobalBackupPreferencesStatus::Absent;
            coordinator->applyGlobalBackupPreferences(std::move(unavailable));
        });
    runBounded([&] { unlock(); });
    commitGenerationalCredential(
        "Fictitious first generation before preference invalidation");
    ASSERT_TRUE(passwall::tests::waitFor([&] { return results.size() == 1; }, 10000));
    ASSERT_EQ(results[0].outcome, MutationBackupOutcome::Published);
    invalidateNextCrud = true;

    Credential added = makeCredential();
    added.id = {};
    added.title = "Fictitious invalidated generation";
    const auto wipe = qScopeGuard([&] { wipeCredential(added); });
    std::string error;
    ASSERT_TRUE(CredentialService::add(vaultPath.toStdString(), verificationKey,
        added, error, passwall::services::BackupTriggerMode::Generational))
        << error;
    ASSERT_TRUE(passwall::tests::waitFor([&] {
        return preferenceInvalidated && !invalidated.isEmpty();
    }, 10000));

    QElapsedTimer grace; grace.start();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return grace.elapsed() >= 300; }, 1000));
    const auto state = coordinator->generationalOperationState(vaultPath);
    EXPECT_NE(state.phase, GenerationalOperationPhase::WorkerActive);
    EXPECT_EQ(results.size(), 1);
}
#endif

TEST_F(MainWindowEditorLockTest, ReplacementPreparationDoesNotBlockGuiAndLateResultCannotAuthorizeAfterRepeatedLock)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error;
    ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    preparationSyncEntered = false; releasePreparationSync = false; pausePreparationSync = true;
    bool complete = false, authorized = true;
    const auto release = qScopeGuard([&] {
        releasePreparationSync = true; preparationSyncCondition.notify_all(); pausePreparationSync = false;
        passwall::tests::waitFor([&] { return complete; }, 10000);
    });
    int ticks = 0; QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; }); heartbeat.start(0);
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        authorized = a.valid(error); complete = true;
    });
    ASSERT_TRUE(passwall::tests::waitFor([] { return preparationSyncEntered.load(); }, 10000));
    EXPECT_FALSE(complete); EXPECT_GT(ticks, 0); EXPECT_FALSE(window->acquireLease().unlocked);
    bool cleaned = false;
    window->requestExternalLock([&](bool value) { cleaned = value; });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return cleaned; }));
    window->requestExternalLock([](bool) {}); // Already locked: still invalidates preparation generation.
    releasePreparationSync = true; preparationSyncCondition.notify_all();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }, 10000)); EXPECT_FALSE(authorized);
}
TEST_F(MainWindowEditorLockTest, RestoreRealWorkerUsesIssuedAuthorityAndCleansBeforePublication)
{
    using namespace passwall::services;
    const auto source = restoreSource(); const auto oldLease = window->acquireLease();
    const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    bool cleanBeforeCandidate = false; int ticks = 0; QTimer heartbeat;
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; }); heartbeat.start(0);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto phase) {
        if (phase == ReplacementCheckpoint::CandidateStaged) {
            cleanBeforeCandidate = o.cleanup == RestoreCleanup::ConfirmedByWorker;
            passwall::storage::VaultOperationGuard access; std::string error;
            EXPECT_FALSE(access.tryAccess(vaultPath.toStdString(), error));
        }
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    ASSERT_TRUE(o.finished); EXPECT_TRUE(o.received); EXPECT_GT(ticks, 1);
    ASSERT_EQ(o.result.outcome, RestoreOutcome::EngineResult) << o.result.diagnostic.toStdString();
    ASSERT_EQ(o.result.replacement.outcome, ReplacementOutcome::Replaced) << o.result.replacement.diagnostic.toStdString();
    EXPECT_TRUE(cleanBeforeCandidate); EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    EXPECT_TRUE(QFile::exists(o.result.replacement.recoveryArtifact));
    EXPECT_TRUE(encryptedBytes(o.result.replacement.recoveryArtifact) == before);
    EXPECT_TRUE(QFile::exists(testDirectory->filePath("exceptional-precaution.db")));
    expectEntryCount(1); runBounded([&] { unlock(); });
    EXPECT_TRUE(window->acquireLease().unlocked); EXPECT_FALSE(window->isLeaseCurrent(oldLease));
}
TEST_F(MainWindowEditorLockTest, ReplacementAsyncPersistenceErrorCannotIssueAuthorityOrKeepReservation)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    failPreparationSync = true;
    const auto reset = qScopeGuard([] { failPreparationSync = false; });
    bool complete = false, authorized = true;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString e) {
        authorized = a.valid(error); EXPECT_FALSE(e.isEmpty()); complete = true;
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }, 10000)); EXPECT_FALSE(authorized);
    EXPECT_FALSE(window->acquireLease().unlocked);
    passwall::storage::VaultOperationGuard reserve; std::string failure;
    EXPECT_TRUE(reserve.tryReserve(vaultPath.toStdString(), failure));
}
TEST_F(MainWindowEditorLockTest, ReplacementOwnerRefusesFileIdentityChangedDuringPreparationIo)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    preparationSyncEntered = false; releasePreparationSync = false; pausePreparationSync = true;
    bool complete = false, authorized = true;
    const auto release = qScopeGuard([&] {
        releasePreparationSync = true; preparationSyncCondition.notify_all(); pausePreparationSync = false;
        passwall::tests::waitFor([&] { return complete; }, 10000);
    });
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        authorized = a.valid(error); complete = true;
    });
    ASSERT_TRUE(passwall::tests::waitFor([] { return preparationSyncEntered.load(); }, 10000));
    const auto displaced = testDirectory->filePath("externally-moved-principal.db");
    ASSERT_TRUE(QFile::rename(vaultPath, displaced)); ASSERT_TRUE(QFile::copy(displaced, vaultPath));
    releasePreparationSync = true; preparationSyncCondition.notify_all();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }, 10000)); EXPECT_FALSE(authorized);
    EXPECT_TRUE(QFile::exists(displaced)); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, RestoreWrongPasswordDoesNotReplaceOrPublishSession)
{
    using namespace passwall::services;
    const auto source = restoreSource(); const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; ASSERT_NE(startRestore(o, source, true), nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.outcome, RestoreOutcome::SourceAuthenticationFailed);
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::NotReplaced);
    EXPECT_EQ(o.cleanup, RestoreCleanup::ConfirmedByWorker);
    EXPECT_TRUE(encryptedBytes(vaultPath) == before); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, RestoreSecurityLockWaitsForRemoteCleanupNotCancellationRequest)
{
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    bool ack = false, requested = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        requested = true; EXPECT_EQ(o.cleanup, RestoreCleanup::Pending);
        window->requestExternalLock([&](bool value) {
            EXPECT_NE(o.cleanup, RestoreCleanup::Pending); ack = value;
        });
        EXPECT_FALSE(ack); EXPECT_FALSE(window->acquireLease().unlocked);
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated && ack; }, 15000));
    EXPECT_TRUE(requested); EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::CancelledBeforeEngagement);
}
TEST_F(MainWindowEditorLockTest, RestoreLinuxProtectionLossDefersInhibitorAcknowledgementUntilCleanup)
{
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    bool ack = false, requested = false;
    QObject::connect(window.get(), &MainWindow::lifecycleSecretsCleared, window.get(), [&] {
        EXPECT_NE(o.cleanup, RestoreCleanup::Pending); ack = true;
    });
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        requested = true; window->setLifecycleProtectionAvailable(false); EXPECT_FALSE(ack);
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated && ack; }, 15000));
    EXPECT_TRUE(requested); EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::CancelledBeforeEngagement);
}
TEST_F(MainWindowEditorLockTest, RestoreSleepPreparationRetainsActualInhibitorUntilRemoteSecretProof)
{
    using namespace passwall::services;
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend); establishProtection(*backend);
    runBounded([&] { unlock(); });
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr); bool proof = false, requested = false;
    QObject::connect(job, &RestoreJob::secretsCleared, window.get(), [&](auto) {
        proof = true; EXPECT_TRUE(backend->inhibitorHeld(0));
    });
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        requested = true; emit backend->prepareForSleep(true);
        EXPECT_TRUE(backend->inhibitorHeld(0)); EXPECT_FALSE(proof); EXPECT_FALSE(monitor->protectionAvailable());
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated && proof && !backend->inhibitorHeld(0); }, 15000));
    EXPECT_TRUE(requested); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, RestoreControl1OverPrivateBusCannotReplyBeforeGlobalCleanup)
{
    using namespace passwall::services;
    ControlHarness control(*window); ASSERT_TRUE(control.ready());
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    std::optional<QDBusPendingReply<>> reply;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p == ReplacementCheckpoint::BeforeWork) reply.emplace(control.request());
    });
    bool premature = false; QTimer watch;
    QObject::connect(&watch, &QTimer::timeout, [&] {
        if (reply && reply->isFinished() && !reply->isError() && o.cleanup == RestoreCleanup::Pending) premature = true;
    });
    watch.start(0);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated && reply && reply->isFinished(); }, 15000));
    EXPECT_FALSE(reply->isError()); EXPECT_EQ(control.received, 1); EXPECT_FALSE(premature);
    EXPECT_NE(o.cleanup, RestoreCleanup::Pending); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, RestoreCancellationBeforeArmKeepsPreparedRecoveryAndPrincipal)
{
    using namespace passwall::services;
    const auto source = restoreSource(); const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [job](auto p) {
        if (p == ReplacementCheckpoint::BeforeArm) job->cancel();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::CancelledBeforeEngagement);
    EXPECT_TRUE(encryptedBytes(vaultPath) == before);
    QString error; EXPECT_EQ(VaultPreferencesStore().recoveryAccess(vaultPath, error), VaultRecoveryAccess::RecoveryRequired);
}
TEST_F(MainWindowEditorLockTest, RestoreCancellationAfterArmCannotClaimNoEngagement)
{
    using namespace passwall::services;
    const auto source = restoreSource(); const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [job](auto p) {
        if (p == ReplacementCheckpoint::Armed) job->cancel();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::EngagedRecoveryRequired);
    EXPECT_TRUE(encryptedBytes(vaultPath) == before); EXPECT_TRUE(QFile::exists(o.result.replacement.recoveryArtifact));
}
TEST_F(MainWindowEditorLockTest, RestoreCancellationAfterExchangePreservesActualReplacement)
{
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [job](auto p) {
        if (p == ReplacementCheckpoint::AfterExchange) job->cancel();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::ReplacedDurabilityUnconfirmed);
    EXPECT_TRUE(QFile::exists(o.result.replacement.recoveryArtifact)); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, RestoreSourceMutationAfterAuthenticationRefusesExchange)
{
    using namespace passwall::services;
    const auto source = restoreSource(); const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p == ReplacementCheckpoint::SourceAuthenticated) {
            QFile f(source); ASSERT_TRUE(f.open(QIODevice::WriteOnly | QIODevice::Append)); ASSERT_EQ(f.write("!", 1), 1);
        }
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::NotReplaced); EXPECT_TRUE(encryptedBytes(vaultPath) == before);
}
TEST_F(MainWindowEditorLockTest, RestoreCannotIssueASecondAuthorityOrReuseTheMovedOne)
{
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    bool refused = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
        window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
            refused = !a.valid(error);
        });
        job->cancel();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000)); EXPECT_TRUE(refused);
}
TEST_F(MainWindowEditorLockTest, RestorePartialWritesEintrAndEagainDoNotCopyPasswordIntoQt)
{
    using namespace passwall::services;
    const auto reset = qScopeGuard([] { restoreSendSlice = 0; restoreSendInterruptions = 0; });
    restoreSendSlice = 1; restoreSendInterruptions = 2;
    const auto source = restoreSource(); RestoreObservation o;
    ASSERT_NE(startRestore(o, source), nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 20000));
    EXPECT_EQ(o.result.outcome, RestoreOutcome::EngineResult);
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::Replaced);
    EXPECT_EQ(o.cleanup, RestoreCleanup::ConfirmedByWorker);
}
class RestoreDelegationRejectTest : public MainWindowEditorLockTest, public ::testing::WithParamInterface<const char*> {};
TEST_P(RestoreDelegationRejectTest, CorruptedDelegationNeverReceivesPasswordOrChangesPrincipal)
{
    using namespace passwall::services;
    const auto reset = qScopeGuard([] { restoreGrantFault.clear(); restorePasswordHeaderSent = false; });
    restoreGrantFault = QString::fromLatin1(GetParam()); restorePasswordHeaderSent = false;
    const auto source = restoreSource(); const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; ASSERT_NE(startRestore(o, source), nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 10000));
    EXPECT_FALSE(restorePasswordHeaderSent); EXPECT_TRUE(encryptedBytes(vaultPath) == before);
    EXPECT_TRUE(o.result.outcome == RestoreOutcome::Unknown || o.result.outcome == RestoreOutcome::Refused);
    EXPECT_FALSE(window->acquireLease().unlocked);
}
INSTANTIATE_TEST_SUITE_P(PrivateProtocol, RestoreDelegationRejectTest,
    ::testing::Values("uuid", "principal", "vault", "inode", "policy",
        "session", "protocol", "duplicate"));
class RestoreTerminalRejectTest : public MainWindowEditorLockTest, public ::testing::WithParamInterface<const char*> {};
TEST_P(RestoreTerminalRejectTest, DataAfterTerminalResultCannotBecomeFullSuccess)
{
    using namespace passwall::services;
    const auto reset = qScopeGuard([] { qunsetenv("PW_RESTORE_TRAILING_RESULT"); });
    qputenv("PW_RESTORE_TRAILING_RESULT", GetParam());
    const auto source = restoreSource(); RestoreObservation o;
    ASSERT_NE(startRestore(o, source), nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.outcome, RestoreOutcome::Unknown);
    EXPECT_TRUE(o.result.diagnostic.contains(QStringLiteral("protocole invalide")));
    EXPECT_TRUE(o.result.replacementStatusKnown); // The first valid business record is not retracted.
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::Replaced);
    EXPECT_TRUE(QFile::exists(o.result.replacement.recoveryArtifact));
}
INSTANTIATE_TEST_SUITE_P(TerminalProtocol, RestoreTerminalRejectTest, ::testing::Values("byte", "duplicate"));

TEST_F(MainWindowEditorLockTest, RestoreAdmissionRefusalIsNotReportedAsInvalidProtocol)
{
    using namespace passwall::services;
    const auto reset = qScopeGuard([] { qunsetenv("PW_RESTORE_TEST_ADMISSION_REFUSAL"); });
    qputenv("PW_RESTORE_TEST_ADMISSION_REFUSAL", "1");
    const auto source = restoreSource(); RestoreObservation observation;
    ASSERT_NE(startRestore(observation, source), nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return observation.terminated; }, 10000));
    EXPECT_EQ(observation.result.outcome, RestoreOutcome::Unknown);
    EXPECT_TRUE(observation.result.diagnostic.contains(QStringLiteral("Admission locale")));
    EXPECT_FALSE(observation.result.diagnostic.contains(QStringLiteral("protocole invalide")));
    EXPECT_FALSE(window->acquireLease().unlocked);
}

TEST_F(MainWindowEditorLockTest, RestoreResultDoesNotReleaseNewInodeReservationBeforeActualExit)
{
    using namespace passwall::services;
    const auto fifo = testDirectory->filePath("result-release.fifo");
    ASSERT_EQ(::mkfifo(QFile::encodeName(fifo), 0600), 0);
    const int releaseFd = ::open(QFile::encodeName(fifo), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    ASSERT_GE(releaseFd, 0);
    const auto release = qScopeGuard([&] {
        char byte = '!'; const auto sent = ::write(releaseFd, &byte, 1); EXPECT_EQ(sent, 1);
        ::close(releaseFd); qunsetenv("PW_RESTORE_HOLD_RESULT");
    });
    qputenv("PW_RESTORE_HOLD_RESULT", QFile::encodeName(fifo));
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.received; }, 15000));
    EXPECT_TRUE(job->isActive()); EXPECT_FALSE(o.finished); EXPECT_FALSE(o.terminated);
    EXPECT_EQ(o.cleanup, RestoreCleanup::ConfirmedByWorker);
    passwall::storage::VaultOperationGuard access; std::string error;
    EXPECT_FALSE(access.tryAccess(vaultPath.toStdString(), error));
    // A hard-link alias is rejected for a separate reason. Reserve the new
    // inode's recovery-name counterpart too: both participating names stay held.
    QVector<VaultRegistration> records; QString failure;
    ASSERT_TRUE(VaultPreferencesStore().list(records, failure)); ASSERT_TRUE(records[0].resolvedReplacement);
    const auto artifact = records[0].resolvedReplacement->recoveryArtifacts[0];
    EXPECT_FALSE(access.tryAccess(artifact.toStdString(), error));
    const auto alias = testDirectory->filePath("new-inode-alias.db");
    ASSERT_EQ(::link(QFile::encodeName(vaultPath), QFile::encodeName(alias)), 0);
    EXPECT_FALSE(access.tryAccess(alias.toStdString(), error)); EXPECT_TRUE(access.contended());
    ASSERT_TRUE(QFile::remove(alias));
    char byte = '!'; ASSERT_EQ(::write(releaseFd, &byte, 1), 1);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }));
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::Replaced);
    EXPECT_TRUE(access.tryAccess(vaultPath.toStdString(), error));
}
TEST_F(MainWindowEditorLockTest, RestoreUnknownWithLiveSensitiveWorkerCannotAcknowledgeCleanupOrReleaseLocks)
{
    using namespace passwall::services;
    const auto fifo = testDirectory->filePath("sensitive-release.fifo");
    ASSERT_EQ(::mkfifo(QFile::encodeName(fifo), 0600), 0);
    const int releaseFd = ::open(QFile::encodeName(fifo), O_RDWR | O_NONBLOCK | O_CLOEXEC); ASSERT_GE(releaseFd, 0);
    const auto release = qScopeGuard([&] {
        passwall::tests::releaseGuiRestoreStop();
        char byte = '!'; const auto sent = ::write(releaseFd, &byte, 1); EXPECT_EQ(sent, 1); ::close(releaseFd);
        qunsetenv("PW_RESTORE_HOLD_PHASE"); qunsetenv("PW_RESTORE_HOLD_FIFO");
    });
    qputenv("PW_RESTORE_HOLD_PHASE", "0"); qputenv("PW_RESTORE_HOLD_FIFO", QFile::encodeName(fifo));
    passwall::tests::suppressGuiStopsForRestore(true);
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr); bool ack = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto phase) {
        if (phase == ReplacementCheckpoint::BeforeWork) window->requestExternalLock([&](bool value) { ack = value; });
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.finished; }, 10000));
    EXPECT_EQ(o.result.outcome, RestoreOutcome::Unknown); EXPECT_TRUE(job->isActive()); EXPECT_FALSE(o.terminated);
    EXPECT_FALSE(o.result.replacementStatusKnown); // Default NotReplaced proves nothing.
    EXPECT_EQ(o.cleanup, RestoreCleanup::Pending); EXPECT_FALSE(ack); EXPECT_TRUE(passwall::tests::guiRestoreStopWasRequested());
    passwall::storage::VaultOperationGuard access; std::string error;
    EXPECT_FALSE(access.tryAccess(vaultPath.toStdString(), error));
    passwall::tests::releaseGuiRestoreStop();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated && ack; }));
    EXPECT_EQ(o.cleanup, RestoreCleanup::ConfirmedProcessTermination);
}
TEST_F(MainWindowEditorLockTest, RestoreAbnormalExitAfterResultPreservesKnownReplacementInsteadOfInventingNoReplacement)
{
    using namespace passwall::services;
    const auto fifo = testDirectory->filePath("terminal-release.fifo");
    ASSERT_EQ(::mkfifo(QFile::encodeName(fifo), 0600), 0);
    const int releaseFd = ::open(QFile::encodeName(fifo), O_RDWR | O_NONBLOCK | O_CLOEXEC); ASSERT_GE(releaseFd, 0);
    const auto release = qScopeGuard([&] {
        char byte = '!'; const auto n = ::write(releaseFd, &byte, 1); EXPECT_EQ(n, 1); ::close(releaseFd);
        qunsetenv("PW_RESTORE_HOLD_RESULT");
    });
    qputenv("PW_RESTORE_HOLD_RESULT", QFile::encodeName(fifo));
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.received; }, 15000));
    job->cancel();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 10000));
    EXPECT_EQ(o.result.outcome, RestoreOutcome::Unknown);
    EXPECT_TRUE(o.result.replacementStatusKnown);
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::Replaced);
    EXPECT_TRUE(QFile::exists(o.result.replacement.recoveryArtifact));
}

class RestoreCrashTest : public MainWindowEditorLockTest, public ::testing::WithParamInterface<int> {};
TEST_P(RestoreCrashTest, ActualWorkerExitPreservesFenceAndNeverRepeatsExchange)
{
    using namespace passwall::services;
    const int phase = GetParam();
    const auto reset = qScopeGuard([] { qunsetenv("PW_RESTORE_CRASH_PHASE"); qunsetenv("PW_RESTORE_LOSE_RESULT"); });
    if (phase < 0) qputenv("PW_RESTORE_LOSE_RESULT", "1");
    else qputenv("PW_RESTORE_CRASH_PHASE", QByteArray::number(phase));
    const auto source = restoreSource(); const auto before = encryptedBytes(vaultPath);
    RestoreObservation o; ASSERT_NE(startRestore(o, source), nullptr);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000));
    EXPECT_EQ(o.result.outcome, RestoreOutcome::Unknown); EXPECT_FALSE(window->acquireLease().unlocked);
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    ASSERT_EQ(records.size(), 1); const auto& record = records[0];
    const auto intent = record.replacement ? record.replacement : record.resolvedReplacement; ASSERT_TRUE(intent);
    const auto recovery = VaultReplacementAuthorization::recoverReplacement(VaultPreferencesStore(), record.localId,
        intent->operationId, ReplacementRecoveryAction::Inspect);
    if (phase == int(ReplacementCheckpoint::BeforeWork)) {
        EXPECT_EQ(recovery.layout, ReplacementLayout::PreparedIntact); EXPECT_TRUE(encryptedBytes(vaultPath) == before);
        EXPECT_EQ(o.cleanup, RestoreCleanup::ConfirmedProcessTermination);
    } else if (phase == int(ReplacementCheckpoint::Armed)) {
        EXPECT_EQ(recovery.layout, ReplacementLayout::ArmedBeforeExchange); EXPECT_TRUE(encryptedBytes(vaultPath) == before);
    } else if (phase == int(ReplacementCheckpoint::AfterExchange) || phase == int(ReplacementCheckpoint::AfterDirectorySync)) {
        EXPECT_EQ(recovery.layout, ReplacementLayout::ArmedAfterExchange);
        EXPECT_TRUE(encryptedBytes(intent->recoveryArtifacts[0]) == before);
    } else EXPECT_EQ(recovery.layout, ReplacementLayout::Resolved);
    // Inspection never substitutes/clears recovery or deletes the old principal.
    EXPECT_TRUE(QFile::exists(vaultPath));
}
INSTANTIATE_TEST_SUITE_P(WorkerInterruptions, RestoreCrashTest, ::testing::Values(
    int(passwall::services::ReplacementCheckpoint::BeforeWork),
    int(passwall::services::ReplacementCheckpoint::Armed),
    int(passwall::services::ReplacementCheckpoint::AfterExchange),
    int(passwall::services::ReplacementCheckpoint::AfterDirectorySync), -1));
TEST_F(MainWindowEditorLockTest, RestoreParentExitProbe)
{
    const auto root = qEnvironmentVariable("PW_RESTORE_PARENT_ROOT");
    if (root.isEmpty()) GTEST_SKIP() << "Subprocess helper only";
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr);
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::Armed) return;
        QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
        ASSERT_EQ(records.size(), 1); ASSERT_TRUE(records[0].replacement);
        const QJsonObject object{{"config", VaultPreferencesStore().fileName()}, {"local", records[0].localId},
            {"principal", vaultPath}, {"operation", records[0].replacement->operationId}};
        QFile metadata(root + "/probe.json"); ASSERT_TRUE(metadata.open(QIODevice::WriteOnly));
        const auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
        ASSERT_EQ(metadata.write(bytes), bytes.size()); metadata.close(); ::_exit(88);
    });
    passwall::tests::waitFor([&] { return o.terminated; }, 15000);
    FAIL() << "Parent crash checkpoint not reached";
}
TEST_F(MainWindowEditorLockTest, RestoreFacadeDestructionDoesNotLoseGlobalCleanupObservation)
{
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr); bool ack = false, destroyed = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        delete job; destroyed = true;
        window->requestExternalLock([&](bool value) { ack = value; }); EXPECT_FALSE(ack);
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return destroyed && ack; }, 10000));
    passwall::storage::VaultOperationGuard access; std::string error;
    ASSERT_TRUE(passwall::tests::waitFor([&] { return access.tryAccess(vaultPath.toStdString(), error); }));
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, RestoreWindowCloseRequestsCancellationWithoutWaitingInGui)
{
    using namespace passwall::services;
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr); bool closed = false, eventProcessed = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        closed = window->close(); EXPECT_FALSE(o.terminated);
        QTimer::singleShot(0, window.get(), [&] { eventProcessed = true; });
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated && eventProcessed; }, 15000));
    EXPECT_TRUE(closed); EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_EQ(o.result.replacement.outcome, ReplacementOutcome::CancelledBeforeEngagement);
}
TEST_F(MainWindowEditorLockTest, RestoreReservationDoesNotBlockBusinessOperationsOfAnotherVault)
{
    using namespace passwall::services;
    const auto other = testDirectory->filePath("independent.db"); SecureBuffer otherKey(0); std::string failure;
    ASSERT_TRUE(VaultLifecycleService::createVault(other.toStdString(), "fictitious-independent-master", otherKey, failure));
    const auto source = restoreSource(); RestoreObservation o;
    auto* job = startRestore(o, source); ASSERT_NE(job, nullptr); bool exercised = false;
    QObject::connect(job, &RestoreJob::phaseChanged, window.get(), [&](auto p) {
        if (p != ReplacementCheckpoint::BeforeWork) return;
        auto credential = makeCredential(); const auto wipe = qScopeGuard([&] { wipeCredential(credential); });
        EXPECT_TRUE(CredentialService::add(other.toStdString(), otherKey, credential, failure));
        EXPECT_TRUE(CredentialService::update(other.toStdString(), otherKey, credential, failure));
        EXPECT_TRUE(CredentialService::remove(other.toStdString(), otherKey, credential.id, failure));
        exercised = true; job->cancel();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return o.terminated; }, 15000)); EXPECT_TRUE(exercised);
}
// These cases exercise the production issuer and real accessible cleanup,
// unlike the isolated acknowledgement simulator in test_vault_replacement.cpp.
TEST_F(MainWindowEditorLockTest, ReplacementAuthorizationFollowsRealCleanupAndNativeInvalidation)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error;
    ASSERT_TRUE(VaultPreferencesStore().list(records, error)); ASSERT_EQ(records.size(), 1);
    const auto oldLease = window->acquireLease();
    std::optional<VaultReplacementAuthorization> authority;
    bool complete = false;
    window->requestReplacementAuthorization(records[0].localId,
        [&](VaultReplacementAuthorization value, QString failure) {
            error = failure;
            expectLockedAfterRefresh(); expectNativeAccessDenied(oldLease);
            EXPECT_TRUE(window->findChild<QLineEdit*>("unlockPasswordEdit")->text().isEmpty());
            authority.emplace(std::move(value)); complete = true;
        });
    EXPECT_FALSE(complete); // No early acknowledgement inside lockVault.
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }));
    ASSERT_TRUE(authority->valid(error)) << error.toStdString();
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    ASSERT_TRUE(authority->abandonPreparation(error));
    runBounded([&] { unlock(); });
    EXPECT_TRUE(window->acquireLease().unlocked); EXPECT_FALSE(window->isLeaseCurrent(oldLease));
}
TEST_F(MainWindowEditorLockTest, ReplacementRefusesOpenEditorWithoutDiscardingUnsavedFields)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    runEditor(false, [&](QDialog& editor) {
        bool refused = false;
        window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString e) {
            refused = !a.valid(error) && !e.isEmpty();
        });
        EXPECT_TRUE(refused); EXPECT_TRUE(window->acquireLease().unlocked);
        EXPECT_FALSE(editor.findChild<QLineEdit*>("credentialPasswordEdit")->text().isEmpty());
        editor.reject();
    });
    expectStoredEntry();
}
TEST_F(MainWindowEditorLockTest, ReplacementRefusesBusyReservationWithoutBlockingOrLockingSession)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    passwall::storage::VaultOperationGuard access; std::string failure;
    ASSERT_TRUE(access.tryAccess(vaultPath.toStdString(), failure));
    bool complete = false;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        complete = true; EXPECT_FALSE(a.valid(error));
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; })); EXPECT_TRUE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, ReplacementDoesNotLockAnUnrelatedActiveVault)
{
    using namespace passwall::services;
    const auto other = testDirectory->filePath("other-principal.pwdb");
    ASSERT_TRUE(QFile::copy(vaultPath, other));
    VaultRegistration record; QString error;
    ASSERT_EQ(VaultPreferencesStore().recognizeOrRegister(other, record, error), VaultRecognition::Registered);
    const auto lease = window->acquireLease(); bool complete = false;
    window->requestReplacementAuthorization(record.localId, [&](VaultReplacementAuthorization a, QString failure) {
        complete = true; EXPECT_FALSE(a.valid(error)); EXPECT_FALSE(failure.isEmpty());
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; })); EXPECT_TRUE(window->isLeaseCurrent(lease));
}
TEST_F(MainWindowEditorLockTest, ReplacementBlocksReentrantAuthenticationBeforeAcknowledgement)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    bool attempted = false, complete = false;
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &observer, [&] {
        if (attempted) return;
        attempted = true; unlock(); EXPECT_FALSE(window->acquireLease().unlocked);
    });
    std::optional<VaultReplacementAuthorization> authority;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        authority.emplace(std::move(a)); complete = true;
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }));
    EXPECT_TRUE(attempted); EXPECT_TRUE(authority->valid(error));
    runBounded([&] { unlock(); }); EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, ReplacementSecurityLockRevokesIssuedAuthorityWithoutRestoringSession)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    std::optional<VaultReplacementAuthorization> authority;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        authority.emplace(std::move(a));
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return authority.has_value(); }));
    ASSERT_TRUE(authority->valid(error)); bool cleaned = false;
    window->requestExternalLock([&](bool value) { cleaned = value; });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return cleaned; }));
    EXPECT_FALSE(authority->valid(error));
    EXPECT_EQ(VaultPreferencesStore().recoveryAccess(vaultPath, error), VaultRecoveryAccess::RecoveryRequired);
    EXPECT_FALSE(window->acquireLease().unlocked);
}
TEST_F(MainWindowEditorLockTest, ReplacementReentrantSecurityLockPreventsIssuance)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    QObject observer; bool requested = false, complete = false, valid = true;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &observer, [&] {
        if (requested) return; requested = true;
        window->requestExternalLock([](bool) {});
    });
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        valid = a.valid(error); complete = true;
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }));
    EXPECT_TRUE(requested); EXPECT_FALSE(valid);
}
TEST_F(MainWindowEditorLockTest, ReplacementFreshLifecycleFailureRevokesWithoutWaitingForTimer)
{
    using namespace passwall::services;
    auto healthy = std::make_shared<bool>(true);
    window->setLifecycleProtectionValidator([healthy] { return *healthy; }, [] {});
    window->setLifecycleProtectionAvailable(true);
    runBounded([&] { unlock(); });
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    std::optional<VaultReplacementAuthorization> authority;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        authority.emplace(std::move(a));
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return authority.has_value(); }));
    ASSERT_TRUE(authority->valid(error));
    *healthy = false; // No timer/event-loop turn between failure and validation.
    EXPECT_FALSE(authority->valid(error)); EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_EQ(VaultPreferencesStore().recoveryAccess(vaultPath, error), VaultRecoveryAccess::RecoveryRequired);
}
TEST_F(MainWindowEditorLockTest, ReplacementWindowDestructionCannotAcknowledgeOrKeepReservation)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    bool complete = false;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        complete = true; EXPECT_FALSE(a.valid(error));
    });
    window.reset(); ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; })); QApplication::processEvents();
    passwall::storage::VaultOperationGuard reserve; std::string failure;
    EXPECT_TRUE(reserve.tryReserve(vaultPath.toStdString(), failure));
}
TEST_F(MainWindowEditorLockTest, ReplacementRepeatedRequestCannotIssueSecondAuthority)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    bool first = false, second = false; std::optional<VaultReplacementAuthorization> authority;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        authority.emplace(std::move(a)); first = true;
    });
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        second = true; EXPECT_FALSE(a.valid(error));
    });
    EXPECT_TRUE(second); ASSERT_TRUE(passwall::tests::waitFor([&] { return first; }));
    EXPECT_TRUE(authority->valid(error));
}
TEST_F(MainWindowEditorLockTest, ReplacementInconsistentCleanupDoesNotIssueAuthority)
{
    using namespace passwall::services;
    QVector<VaultRegistration> records; QString error; ASSERT_TRUE(VaultPreferencesStore().list(records, error));
    QObject observer;
    QObject::connect(window->findChild<QStackedWidget*>("stackedWidget"), &QStackedWidget::currentChanged,
        &observer, [&] { window->findChild<QLineEdit*>("unlockPasswordEdit")->setText("fictitious-residual"); });
    bool complete = false;
    window->requestReplacementAuthorization(records[0].localId, [&](VaultReplacementAuthorization a, QString) {
        EXPECT_FALSE(a.valid(error)); complete = true;
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return complete; }));
    QVector<VaultRegistration> after; ASSERT_TRUE(VaultPreferencesStore().list(after, error));
    EXPECT_FALSE(after[0].replacement);
}
TEST_F(MainWindowEditorLockTest, ExternalLockDbusAcknowledgesCompleteCleanupAndInvalidatesOldLease)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    const auto oldLease = window->acquireLease();
    auto reply = control.request();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply.isFinished(); }));
    EXPECT_FALSE(reply.isError());
    EXPECT_TRUE(reply.reply().arguments().isEmpty());
    expectLockedAfterRefresh();
    expectNativeAccessDenied(oldLease);
}

TEST_F(MainWindowEditorLockTest, ExternalLockAllowsAnotherVaultOnlyWithItsOwnMasterPassword)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    const auto oldLease = window->acquireLease();
    const auto otherPath = testDirectory->filePath(QStringLiteral("other-vault.pwdb"));
    SecureBuffer otherKey(0);
    std::string error;
    const bool created = passwall::services::VaultLifecycleService::createVault(
        otherPath.toStdString(), "fictitious-other-master-password", otherKey, error);
    otherKey = SecureBuffer(0);
    ASSERT_TRUE(created);

    auto reply = control.request();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply.isFinished(); }));
    ASSERT_FALSE(reply.isError());
    expectLockedAfterRefresh();
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    EXPECT_TRUE(window->findChild<QPushButton*>(QStringLiteral("unlockVaultButton"))->isEnabled());

    // No obligation to reopen the last vault, and its password grants no
    // authority over a different vault. Close only this expected test warning.
    window->findChild<QPushButton*>(QStringLiteral("openPageButton"))->click();
    window->findChild<QLineEdit*>(QStringLiteral("unlockPathEdit"))->setText(otherPath);
    window->findChild<QLineEdit*>(QStringLiteral("unlockPasswordEdit"))->setText(
        QStringLiteral("fictitious-master-password"));
    bool authenticationRefused = false;
    QObject observer;
    QTimer::singleShot(0, &observer, [&] {
        auto* warning = window->findChild<QMessageBox*>();
        ASSERT_NE(warning, nullptr);
        authenticationRefused = true;
        EXPECT_FALSE(window->acquireLease().unlocked);
        warning->accept();
    });
    runBounded([&] {
        window->findChild<QPushButton*>(QStringLiteral("unlockVaultButton"))->click();
    });
    ASSERT_TRUE(authenticationRefused);
    expectLockedAfterRefresh("pageUnlock");
    expectNativeAccessDenied(oldLease);

    window->findChild<QLineEdit*>(QStringLiteral("unlockPasswordEdit"))->setText(
        QStringLiteral("fictitious-other-master-password"));
    runBounded([&] {
        window->findChild<QPushButton*>(QStringLiteral("unlockVaultButton"))->click();
    });
    ASSERT_TRUE(window->acquireLease().unlocked);
    EXPECT_NE(window->acquireLease().generation, oldLease.generation);
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    EXPECT_EQ(window->findChild<QListWidget*>(QStringLiteral("credentialsList"))->count(), 0);
    QSettings settings("PassWall", "PassWall");
    EXPECT_EQ(settings.value("vault/lastPath").toString(), otherPath);
    expectStoredEntry(false);
}

TEST_F(MainWindowEditorLockTest, ExternalLockBlocksNativeAccessUntilFreshAuthentication)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    const auto oldLease = window->acquireLease();
    std::optional<QDBusPendingReply<>> reply;
    bool checkedDuringCleanup = false;
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &observer, [&] {
        if (checkedDuringCleanup)
            return;
        checkedDuringCleanup = true;
        expectNativeAccessDenied(oldLease);
        // An actual attempt at fresh authentication is refused while the
        // outer cleanup and its acknowledgement are still pending.
        unlock();
        EXPECT_FALSE(window->acquireLease().unlocked);
        QCoreApplication::processEvents();
        ASSERT_TRUE(reply.has_value());
        EXPECT_FALSE(reply->isFinished());
    });
    reply = control.request();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply->isFinished(); }));
    ASSERT_FALSE(reply->isError());
    EXPECT_TRUE(checkedDuringCleanup);
    expectLockedAfterRefresh();
    expectNativeAccessDenied(oldLease);
    QCoreApplication::processEvents();
    EXPECT_FALSE(window->acquireLease().unlocked);

    runBounded([&] { unlock(); });
    const auto newLease = window->acquireLease();
    ASSERT_TRUE(newLease.unlocked);
    EXPECT_NE(newLease.generation, oldLease.generation);
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    Credential loaded;
    const auto result = window->loadCredential(newLease, entryId, loaded);
    const bool correctPassword = loaded.password == "fictitious-password-initial";
    const bool correctNotes = loaded.notes == "fictitious-notes-initial";
    wipeCredential(loaded);
    EXPECT_TRUE(result == passwall::native::VaultAccessResult::Success);
    EXPECT_TRUE(correctPassword);
    EXPECT_TRUE(correctNotes);
}

TEST_F(MainWindowEditorLockTest, ExternalLockAlreadyLockedStillClearsAccessiblePasswordFields)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    lock();
    auto* field = window->findChild<QLineEdit*>(QStringLiteral("unlockPasswordEdit"));
    field->setText(QStringLiteral("fictitious-unsaved-master-input"));
    auto reply = control.request();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply.isFinished(); }));
    EXPECT_FALSE(reply.isError());
    EXPECT_TRUE(field->text().isEmpty());
    EXPECT_FALSE(window->acquireLease().unlocked);
}

TEST_F(MainWindowEditorLockTest, ExternalLockEditorIsWipedBeforeAnySuccessfulDbusReply)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    std::optional<QDBusPendingReply<>> reply;
    bool rejected = false;
    QObject observer;
    runEditor(false, [&](QDialog& editor) {
        QObject::connect(&editor, &QDialog::rejected, &observer, [&] {
            rejected = true;
            expectFieldsEmpty(editor);
            EXPECT_FALSE(window->acquireLease().unlocked);
            QCoreApplication::processEvents();
            ASSERT_TRUE(reply.has_value());
            EXPECT_FALSE(reply->isFinished());
        });
        reply = control.request();
        EXPECT_TRUE(passwall::tests::waitFor([&] { return reply->isFinished(); }));
    });
    ASSERT_TRUE(reply.has_value());
    EXPECT_TRUE(rejected);
    EXPECT_FALSE(reply->isError());
    expectStoredEntry(false);
}

TEST_F(MainWindowEditorLockTest, ExternalLockDuringManualLockWaitsForTheOuterCleanup)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    std::optional<QDBusPendingReply<>> reply;
    bool nested = false;
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &observer, [&] {
        if (nested)
            return;
        nested = true;
        reply = control.request();
        ASSERT_TRUE(passwall::tests::waitFor([&] { return control.received == 1; }));
        QCoreApplication::processEvents();
        EXPECT_FALSE(reply->isFinished());
    });
    lock();
    ASSERT_TRUE(reply.has_value());
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply->isFinished(); }));
    EXPECT_FALSE(reply->isError());
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, ExternalLockQueuedCompletionCannotRunInsideAnotherLock)
{
    int acknowledgements = 0;
    window->requestExternalLock([&](bool cleaned) {
        EXPECT_TRUE(cleaned);
        ++acknowledgements;
    });
    EXPECT_EQ(acknowledgements, 0);
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &observer, [&] {
        QCoreApplication::processEvents();
        EXPECT_EQ(acknowledgements, 0);
    });
    lock();
    EXPECT_EQ(acknowledgements, 0);
    ASSERT_TRUE(passwall::tests::waitFor([&] { return acknowledgements == 1; }));
}

TEST_F(MainWindowEditorLockTest, ExternalLockConcurrentDbusRequestsAllCompleteWithoutReopening)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    auto first = control.request();
    auto second = control.request();
    auto third = control.request();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return first.isFinished() && second.isFinished() && third.isFinished(); }));
    EXPECT_FALSE(first.isError());
    EXPECT_FALSE(second.isError());
    EXPECT_FALSE(third.isError());
    EXPECT_EQ(control.received, 3);
    EXPECT_FALSE(window->acquireLease().unlocked);
}

TEST_F(MainWindowEditorLockTest, ExternalLockOldEditorCannotSaveAfterAcknowledgementAndReunlock)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    runEditor(false, [&](QDialog& editor) {
        const auto oldLease = window->acquireLease();
        auto reply = control.request();
        ASSERT_TRUE(passwall::tests::waitFor([&] { return reply.isFinished(); }));
        ASSERT_FALSE(reply.isError());
        expectFieldsEmpty(editor);
        unlock();
        ASSERT_TRUE(window->acquireLease().unlocked);
        EXPECT_NE(window->acquireLease().generation, oldLease.generation);
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-late-editor-value"));
        editor.accept();
    });
    expectStoredEntry(false);
}

TEST_F(MainWindowEditorLockTest, ExternalLockWindowDestructionDoesNotAcknowledgePendingCleanup)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    auto reply = control.request();
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &observer, [&] {
        control.service->stop();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply.isFinished(); }));
    EXPECT_TRUE(reply.isError());
    window.reset();
    QCoreApplication::processEvents();
    EXPECT_TRUE(reply.isError());
}

TEST_F(MainWindowEditorLockTest, ExternalLockDestructionCancelsQueuedLocalCompletion)
{
    int completions = 0;
    bool successful = false;
    window->requestExternalLock([&](bool cleaned) { ++completions; successful = cleaned; });
    EXPECT_EQ(completions, 0);
    window.reset();
    EXPECT_EQ(completions, 1);
    EXPECT_FALSE(successful);
    QCoreApplication::processEvents();
    EXPECT_EQ(completions, 1);
}

TEST_F(MainWindowEditorLockTest, ExternalLockInconsistentCleanupNeverReturnsSuccess)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
    QObject observer;
    QObject::connect(pages, &QStackedWidget::currentChanged, &observer, [&](int) {
        // Model an unexpected reentrant writer AFTER clearPasswordFields().
        window->findChild<QLineEdit*>(QStringLiteral("unlockPasswordEdit"))->setText(
            QStringLiteral("fictitious-inconsistent-field"));
    });
    auto reply = control.request();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return reply.isFinished(); }));
    EXPECT_TRUE(reply.isError());
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_FALSE(control.service->isAvailable());
}

TEST_F(MainWindowEditorLockTest, ExternalLockControlLossCannotBeOverriddenByLogindReadiness)
{
    ControlHarness control(*window);
    ASSERT_TRUE(control.ready());
    const bool logindReady = true;
    window->setLifecycleProtectionValidator(
        [&] { return logindReady && control.service->isAvailable(); }, [] {});
    QObject::connect(control.service.get(),
        &passwall::platform::SessionLockService::availabilityChanged, window.get(), [&](bool) {
            window->setLifecycleProtectionAvailable(logindReady && control.service->isAvailable());
        });
    window->setLifecycleProtectionAvailable(logindReady && control.service->isAvailable());
    unlock();
    ASSERT_TRUE(window->acquireLease().unlocked);
    const auto lease = window->acquireLease();
    control.bus.stop();
    ASSERT_TRUE(passwall::tests::waitFor([&] { return !control.service->isAvailable(); }));
    window->setLifecycleProtectionAvailable(logindReady && control.service->isAvailable());
    expectLockedAfterRefresh();
    expectNativeAccessDenied(lease);
    EXPECT_FALSE(window->findChild<QPushButton*>(QStringLiteral("unlockVaultButton"))->isEnabled());
    // The validator outlives the harness in the fixture's normal destruction.
    window->setLifecycleProtectionValidator([] { return false; }, [] {});
}

TEST_F(MainWindowEditorLockTest, ExternalLockCompletionMayDestroyTheWindowWithoutDanglingContinuation)
{
    int calls = 0;
    window->requestExternalLock([&](bool cleaned) {
        EXPECT_TRUE(cleaned);
        ++calls;
        window.reset();
    });
    ASSERT_TRUE(passwall::tests::waitFor([&] { return calls == 1; }));
    QCoreApplication::processEvents();
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(window, nullptr);
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleStartsFailClosed)
{
    window = MainWindow::createForHistoricalTests(); // no injected readiness
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_FALSE(window->findChild<QPushButton*>(
        QStringLiteral("unlockVaultButton"))->isEnabled());
    EXPECT_FALSE(window->findChild<QPushButton*>(
        QStringLiteral("createVaultButton"))->isEnabled());
    EXPECT_FALSE(inactivityTimer()->isActive());
    expectNativeAccessDenied({true, 1});
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleCachedReadyAloneCannotUnlock)
{
    window = MainWindow::createForHistoricalTests();
    window->setLifecycleProtectionAvailable(true); // deliberately no validator
    runBounded([&] { unlock(); });
    expectLockedAfterRefresh();
    EXPECT_FALSE(window->findChild<QPushButton*>(
        QStringLiteral("unlockVaultButton"))->isEnabled());
}

TEST_F(MainWindowEditorLockTest, LinuxLifecyclePeerBreakImmediatelyRefusesUnlock)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    ASSERT_TRUE(monitor->protectionIsOperational());
    ASSERT_TRUE(window->findChild<QPushButton*>(
        QStringLiteral("unlockVaultButton"))->isEnabled());
    backend->breakPeer(0);
    // No event dispatch between peer loss and the user's unlock attempt.
    runBounded([&] { unlock(); });
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_TRUE(window->findChild<QLineEdit*>(
        QStringLiteral("unlockPasswordEdit"))->text().isEmpty());
    expectLockedAfterRefresh();
    EXPECT_TRUE(window->findChildren<QMessageBox*>().isEmpty());
}

TEST_F(MainWindowEditorLockTest, LinuxLifecyclePeerBreakImmediatelyRefusesCreation)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    const QString newPath = testDirectory->filePath(QStringLiteral("must-not-exist.pwdb"));
    window->findChild<QPushButton*>(QStringLiteral("createPageButton"))->click();
    window->findChild<QLineEdit*>(QStringLiteral("createPathEdit"))->setText(newPath);
    window->findChild<QLineEdit*>(QStringLiteral("createPasswordEdit"))->setText(
        QStringLiteral("fictitious-master-password"));
    window->findChild<QLineEdit*>(QStringLiteral("confirmPasswordEdit"))->setText(
        QStringLiteral("fictitious-master-password"));
    backend->breakPeer(0);
    runBounded([&] {
        window->findChild<QPushButton*>(QStringLiteral("createVaultButton"))->click();
    });
    EXPECT_FALSE(QFile::exists(newPath));
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_TRUE(window->findChild<QLineEdit*>(
        QStringLiteral("createPasswordEdit"))->text().isEmpty());
    EXPECT_TRUE(window->findChild<QLineEdit*>(
        QStringLiteral("confirmPasswordEdit"))->text().isEmpty());
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecyclePeerBreakBeforeSessionPublicationCleansBeforeError)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    const auto checks = std::make_shared<int>(0);
    const QPointer<passwall::platform::LinuxSessionMonitor> guarded(monitor.get());
    window->setLifecycleProtectionValidator([checks, guarded, backend] {
        if (!guarded)
            return false;
        // Entry check succeeds; the post-KDF session initialization fails.
        if (++*checks == 2)
            backend->breakPeer(0);
        return guarded->protectionIsOperational();
    }, [guarded] { if (guarded) guarded->invalidateProtection(); });
    window->setLifecycleProtectionAvailable(monitor->protectionIsOperational());
    bool checked = false;
    QObject observer;
    duringRefreshError(observer, [&](QMessageBox& warning) {
        checked = true;
        expectLockedAfterRefresh();
        EXPECT_FALSE(monitor->protectionAvailable());
        EXPECT_TRUE(window->findChild<QLineEdit*>(
            QStringLiteral("unlockPasswordEdit"))->text().isEmpty());
        warning.accept();
    });
    runBounded([&] { unlock(); });
    EXPECT_TRUE(checked);
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecyclePeerBreakRefusesEditorCommitWithoutATimerTurn)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    window->findChild<QListWidget*>(QStringLiteral("credentialsList"))->setCurrentRow(0);
    const VaultLease old = window->acquireLease();
    ASSERT_TRUE(old.unlocked);
    runEditor(false, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-unsaved-password"));
        backend->breakPeer(0);
        editor.accept(); // operation must reject the commit and then clean up
    });
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(window->isLeaseCurrent(old));
    expectLockedAfterRefresh();
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecyclePeerBreakLocksEditorAndRecoveryCannotReviveIt)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    window->findChild<QListWidget*>(QStringLiteral("credentialsList"))->setCurrentRow(0);
    const VaultLease old = window->acquireLease();
    ASSERT_TRUE(old.unlocked);
    bool cleaned = false;
    runEditor(false, [&](QDialog& editor) {
        QObject observer;
        QObject::connect(window.get(), &MainWindow::lifecycleSecretsCleared,
                         &observer, [&] {
            cleaned = true;
            expectFieldsEmpty(editor);
            EXPECT_FALSE(window->isLeaseCurrent(old));
            EXPECT_FALSE(inactivityTimer()->isActive());
        });
        backend->breakPeer(0);
        // Fresh lease checks deny access even before the periodic lock runs.
        EXPECT_FALSE(window->acquireLease().unlocked);
        EXPECT_FALSE(window->isLeaseCurrent(old));
        expectNativeAccessDenied(old); // request boundary locks synchronously
        EXPECT_TRUE(cleaned);
        expectFieldsEmpty(editor);
        // A locked native request intentionally activates the unlock page.
        expectLockedAfterRefresh("pageUnlock");
        EXPECT_FALSE(monitor->protectionAvailable());
        emit backend->availabilityChanged(false);
        emit backend->availabilityChanged(true);
        establishProtection(*backend);
        EXPECT_TRUE(monitor->protectionIsOperational());
        EXPECT_FALSE(window->acquireLease().unlocked); // never automatic unlock
        unlock();
        EXPECT_TRUE(window->acquireLease().unlocked);
        EXPECT_FALSE(window->isLeaseCurrent(old));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-stale-password"));
        editor.accept();
    });
    EXPECT_TRUE(cleaned);
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecyclePeerBreakAtResponseBoundaryDiscardsSecret)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    struct CheckState { int checks = 0; int breakAt = 0; };
    const auto state = std::make_shared<CheckState>();
    const QPointer<passwall::platform::LinuxSessionMonitor> guarded(monitor.get());
    window->setLifecycleProtectionValidator([state, guarded, backend] {
        if (!guarded)
            return false;
        if (++state->checks == state->breakAt)
            backend->breakPeer(0);
        return guarded && guarded->protectionIsOperational();
    }, [guarded] { if (guarded) guarded->invalidateProtection(); });
    window->setLifecycleProtectionAvailable(monitor->protectionIsOperational());
    runBounded([&] { unlock(); });
    const VaultLease old = window->acquireLease();
    ASSERT_TRUE(old.unlocked);
    const QJsonObject request{
        {QStringLiteral("type"), QStringLiteral("get_credential")},
        {QStringLiteral("id"), QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(entryId.data()), entryId.size()).toHex())},
        {QStringLiteral("url"), QStringLiteral("https://example.test")}
    };
    state->checks = 0;
    auto baseline = window->handleNativeRequest(request);
    ASSERT_TRUE(baseline.hasPayload());
    const auto view = baseline.payloadView();
    const std::string_view bytes(reinterpret_cast<const char*>(view.data()), view.size());
    ASSERT_TRUE(bytes.find("\"password\":") != std::string_view::npos);
    baseline.wipePayload();
    ASSERT_GT(state->checks, 1);
    state->breakAt = state->checks; // final GUI check AFTER processor response
    state->checks = 0;
    auto rejected = window->handleNativeRequest(request);
    ASSERT_GE(state->checks, state->breakAt);
    EXPECT_FALSE(monitor->protectionAvailable());
    EXPECT_FALSE(window->isLeaseCurrent(old));
    EXPECT_FALSE(rejected.hasSessionGeneration());
    const auto rejectedView = rejected.payloadView();
    ASSERT_FALSE(rejectedView.empty());
    const auto object = QJsonDocument::fromJson(QByteArray::fromRawData(
        reinterpret_cast<const char*>(rejectedView.data()), rejectedView.size())).object();
    EXPECT_FALSE(object.value(QStringLiteral("ok")).toBool());
    EXPECT_FALSE(object.contains(QStringLiteral("password")));
    EXPECT_FALSE(object.contains(QStringLiteral("notes")));
    expectLockedAfterRefresh("pageUnlock");
    // Destroy callbacks capturing this test's locals before they leave scope.
    window->setLifecycleProtectionValidator([] { return false; }, [] {});
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleSleepCleansEditorBeforeInhibitorRelease)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    window->findChild<QListWidget*>(QStringLiteral("credentialsList"))->setCurrentRow(0);
    const VaultLease old = window->acquireLease();
    ASSERT_TRUE(old.unlocked);
    bool cleaned = false;
    runEditor(false, [&](QDialog& editor) {
        QObject observer;
        QObject::connect(window.get(), &MainWindow::lifecycleSecretsCleared,
                         &observer, [&] {
            cleaned = true;
            expectFieldsEmpty(editor);
            EXPECT_TRUE(backend->inhibitorHeld(0));
            EXPECT_FALSE(window->isLeaseCurrent(old));
            EXPECT_FALSE(inactivityTimer()->isActive());
            EXPECT_EQ(window->findChild<QListWidget*>(
                QStringLiteral("credentialsList"))->count(), 0);
        });
        emit backend->prepareForSleep(true);
        EXPECT_TRUE(cleaned);
        EXPECT_FALSE(backend->inhibitorHeld(0));
        expectNativeAccessDenied(old);
        EXPECT_TRUE(window->findChildren<QMessageBox*>().isEmpty());
    });
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleShutdownCleansUnsavedEditor)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    const VaultLease old = window->acquireLease();
    runEditor(true, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-unsaved-password"));
        editor.findChild<QTextEdit*>(QStringLiteral("credentialNotesEdit"))->setPlainText(
            QStringLiteral("fictitious-unsaved-notes"));
        emit backend->prepareForShutdown(true);
        expectFieldsEmpty(editor);
        EXPECT_FALSE(backend->inhibitorHeld(0));
        expectNativeAccessDenied(old);
    });
    expectEntryCount(1);
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleServiceLossBlocksAccessUntilRecovery)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    const VaultLease old = window->acquireLease();
    emit backend->availabilityChanged(false);
    expectNativeAccessDenied(old);
    EXPECT_FALSE(window->findChild<QPushButton*>(
        QStringLiteral("unlockVaultButton"))->isEnabled());
    emit backend->availabilityChanged(true);
    establishProtection(*backend);
    EXPECT_FALSE(window->acquireLease().unlocked);
    EXPECT_FALSE(inactivityTimer()->isActive());
    runBounded([&] { unlock(); });
    EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_FALSE(window->isLeaseCurrent(old));
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleOldEditorCannotSaveAfterResumeAndReunlock)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    window->findChild<QListWidget*>(QStringLiteral("credentialsList"))->setCurrentRow(0);
    const VaultLease old = window->acquireLease();
    runEditor(false, [&](QDialog& editor) {
        emit backend->prepareForSleep(true);
        expectFieldsEmpty(editor);
        emit backend->prepareForSleep(false);
        establishProtection(*backend);
        EXPECT_FALSE(window->acquireLease().unlocked);
        EXPECT_FALSE(inactivityTimer()->isActive());
        unlock();
        ASSERT_TRUE(window->acquireLease().unlocked);
        EXPECT_FALSE(window->isLeaseCurrent(old));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-stale-password"));
        editor.accept();
    });
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleReentrantEventWaitsForManualLockCleanup)
{
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    runBounded([&] { unlock(); });
    window->findChild<QListWidget*>(QStringLiteral("credentialsList"))->setCurrentRow(0);
    bool checked = false;
    runEditor(false, [&](QDialog& editor) {
        QObject observer;
        QObject::connect(&editor, &QDialog::rejected, &observer, [&] {
            emit backend->prepareForSleep(true);
            checked = true;
            // The outer lock has not finished clearing its summaries/UI yet.
            EXPECT_TRUE(backend->inhibitorHeld(0));
            expectFieldsEmpty(editor);
        });
        lock();
        EXPECT_TRUE(checked);
        EXPECT_FALSE(backend->inhibitorHeld(0));
    });
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, LinuxLifecycleLocksInsideRefreshErrorAfterDisabledPreferenceMigration)
{
    restartLockedWindow(0);
    QApplication::processEvents();
    ASSERT_NE(migrationNotice(), nullptr); migrationNotice()->accept();
    passwall::tests::FakeLogin1Backend* backend;
    auto monitor = attachMonitor(backend);
    establishProtection(*backend);
    corruptEntryCiphertext();
    bool checked = false;
    QObject observer;
    duringRefreshError(observer, [&](QMessageBox&) {
        checked = true;
        emit backend->prepareForShutdown(true);
        EXPECT_FALSE(backend->inhibitorHeld(0));
    });
    runBounded([&] { unlock(); });
    EXPECT_TRUE(checked);
    expectLockedAfterRefresh();
    EXPECT_FALSE(monitor->protectionAvailable());
}
#endif

TEST_F(MainWindowEditorLockTest, ManualLockClearsOpenEditorSynchronously)
{
    runEditor(false, [&](QDialog& editor) {
        const QPointer<QDialog> stillAlive(&editor);
        EXPECT_FALSE(editor.findChild<QLineEdit*>(
            QStringLiteral("credentialPasswordEdit"))->text().isEmpty());
        lock();
        ASSERT_FALSE(stillAlive.isNull());
        expectFieldsEmpty(editor);
        EXPECT_FALSE(window->acquireLease().unlocked);
        EXPECT_FALSE(editor.isEnabled());
        EXPECT_TRUE(window->findChildren<QMessageBox*>().isEmpty());
    });
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, AutomaticTimeoutClearsEditorWithoutModalNotification)
{
    bool checkedDuringInvalidation = false;
    runEditor(false, [&](QDialog& editor) {
        QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated,
                         &editor, [&]() {
            checkedDuringInvalidation = true;
            expectFieldsEmpty(editor);
            EXPECT_FALSE(window->acquireLease().unlocked);
            EXPECT_TRUE(window->findChildren<QMessageBox*>().isEmpty());
        });
        auto* timer = window->findChild<QTimer*>(QStringLiteral("vaultInactivityTimer"));
        ASSERT_NE(timer, nullptr);
        timer->start(1);
    });
    EXPECT_TRUE(checkedDuringInvalidation);
    EXPECT_TRUE(window->findChildren<QMessageBox*>().isEmpty());
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, ManualLockAlsoClearsUnsavedNewEntry)
{
    runEditor(true, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
            QStringLiteral("Nouvelle entree fictive"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-unsaved-password"));
        editor.findChild<QTextEdit*>(QStringLiteral("credentialNotesEdit"))->setPlainText(
            QStringLiteral("fictitious-unsaved-notes"));
        lock();
        expectFieldsEmpty(editor);
    });
    expectEntryCount(1);
}

TEST_F(MainWindowEditorLockTest, ReentrantAndRepeatedLocksKeepSessionInvalidated)
{
    const VaultLease original = window->acquireLease();
    runEditor(false, [&](QDialog& editor) {
        QObject::connect(&editor, &QDialog::rejected, window.get(), [&]() { lock(); });
        lock();
        expectFieldsEmpty(editor);
        lock();
        EXPECT_FALSE(window->isLeaseCurrent(original));
        EXPECT_FALSE(window->acquireLease().unlocked);
    });
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, OldEditorCannotSaveAfterANewUnlockedSession)
{
    const VaultLease original = window->acquireLease();
    runEditor(false, [&](QDialog& editor) {
        lock();
        expectFieldsEmpty(editor);
        unlock();
        ASSERT_TRUE(window->acquireLease().unlocked);
        EXPECT_NE(window->acquireLease().generation, original.generation);
        // Simuler un signal d'acceptation tardif, meme apres un nouveau coffre
        // deverrouille. Aucun contenu de cet ancien editeur ne doit etre stocke.
        editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
            QStringLiteral("Ancien editeur invalide"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-stale-password"));
        editor.accept();
    });
    expectStoredEntry();
    expectEntryCount(1);
}

TEST_F(MainWindowEditorLockTest, OldAddEditorCannotCreateAnEntryAfterReunlock)
{
    runEditor(true, [&](QDialog& editor) {
        lock();
        unlock();
        ASSERT_TRUE(window->acquireLease().unlocked);
        editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
            QStringLiteral("Ajout invalide"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-stale-add-password"));
        editor.accept();
    });
    expectEntryCount(1);
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, ReentrantUnlockCannotOpenASessionDuringLock)
{
    bool checked = false;
    runEditor(false, [&](QDialog& editor) {
        QObject::connect(&editor, &QDialog::rejected, window.get(), [&]() {
            checked = true;
            unlock();
            EXPECT_FALSE(window->acquireLease().unlocked);
        });
        lock();
        EXPECT_FALSE(window->acquireLease().unlocked);
        expectFieldsEmpty(editor);
    });
    EXPECT_TRUE(checked);
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, NestedEditorsAreAllWipedBeforeTheFirstRejects)
{
    bool checked = false;
    runEditor(false, [&](QDialog& first) {
        QTimer::singleShot(0, window.get(), [&]() {
            QDialog* second = nullptr;
            for (QDialog* dialog : window->findChildren<QDialog*>(
                     QStringLiteral("credentialEditorDialog"))) {
                if (dialog != &first) {
                    second = dialog;
                }
            }
            ASSERT_NE(second, nullptr);
            QObject::connect(&first, &QDialog::rejected, second, [&, second]() {
                checked = true;
                expectFieldsEmpty(first);
                expectFieldsEmpty(*second);
            });
            lock();
            expectFieldsEmpty(first);
            expectFieldsEmpty(*second);
        });
        window->findChild<QPushButton*>(QStringLiteral("editCredentialButton"))->click();
    });
    EXPECT_TRUE(checked);
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, ClipboardPublicationCannotOutliveAReentrantLock)
{
    bool lockTriggered = false;
    QClipboard* clipboard = QApplication::clipboard();
    runEditor(false, [&](QDialog& editor) {
        QObject::connect(clipboard, &QClipboard::dataChanged, window.get(), [&]() {
            if (lockTriggered)
                return;
            lockTriggered = true;
            lock();
            expectFieldsEmpty(editor);
        });
        auto* copy = editor.findChild<QPushButton*>(
            QStringLiteral("credentialCopyPasswordButton"));
        ASSERT_NE(copy, nullptr);
        copy->click();
        EXPECT_TRUE(lockTriggered);
        EXPECT_TRUE(clipboard->text().isEmpty());
        EXPECT_FALSE(window->acquireLease().unlocked);
    });
    EXPECT_TRUE(clipboard->text().isEmpty());
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, InvalidatedEditorIgnoresLateCopyAndGenerateSignals)
{
    runEditor(false, [&](QDialog& editor) {
        lock();
        unlock();
        ASSERT_TRUE(window->acquireLease().unlocked);
        for (const QString& name : {
                 QStringLiteral("credentialCopyPasswordButton"),
                 QStringLiteral("credentialGeneratePasswordButton")}) {
            auto* button = editor.findChild<QPushButton*>(name);
            ASSERT_NE(button, nullptr);
            EXPECT_TRUE(QMetaObject::invokeMethod(
                button, "clicked", Qt::DirectConnection, Q_ARG(bool, false)));
        }
        expectFieldsEmpty(editor);
    });
    expectStoredEntry();
}

TEST_F(MainWindowEditorLockTest, NormalEditingStillSavesPasswordAndNotes)
{
    runEditor(false, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-password-edited"));
        editor.findChild<QTextEdit*>(QStringLiteral("credentialNotesEdit"))->setPlainText(
            QStringLiteral("fictitious-notes-edited"));
        editor.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
    });
    expectStoredEntry(true);
    lock(); // Les connexions des anciens contextes doivent etre detachees.
}

TEST_F(MainWindowEditorLockTest, CancelledEditingDoesNotChangeStoredEntry)
{
    runEditor(false, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-cancelled-password"));
        editor.reject();
    });
    EXPECT_TRUE(window->acquireLease().unlocked);
    expectStoredEntry();
    lock();
}

TEST_F(MainWindowEditorLockTest, NormalAdditionStillSavesAnEntry)
{
    runEditor(true, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
            QStringLiteral("Nouvelle entree fictive"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialUsernameEdit"))->setText(
            QStringLiteral("autre-utilisateur-fictif"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-new-password"));
        editor.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
    });
    expectEntryCount(2);
}

TEST_F(MainWindowEditorLockTest, CancelledAdditionDoesNotCreateAnEntry)
{
    runEditor(true, [&](QDialog& editor) { editor.reject(); });
    EXPECT_TRUE(window->acquireLease().unlocked);
    expectEntryCount(1);
}

TEST_F(MainWindowEditorLockTest, RequiredFieldsRejectInvalidAdditionsAndAllowRetry)
{
    rejectInvalidRequiredFields(true);
    runEditor(true, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
            QStringLiteral("Nouveau compte fictif"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialUsernameEdit"))->setText(
            QStringLiteral("nouvel-utilisateur-fictif"));
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-new-password"));
        editor.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
    });
    expectEntryCount(2);
}

TEST_F(MainWindowEditorLockTest, RequiredFieldsRejectInvalidEditsAndAllowRetry)
{
    rejectInvalidRequiredFields(false);
    runEditor(false, [&](QDialog& editor) {
        editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
            QStringLiteral("fictitious-password-edited"));
        editor.findChild<QTextEdit*>(QStringLiteral("credentialNotesEdit"))->setPlainText(
            QStringLiteral("fictitious-notes-edited"));
        editor.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
    });
    expectEntryCount(1);
    expectStoredEntry(true);
}

TEST_F(MainWindowEditorLockTest, RequiredFieldsPreserveSpacesInPasswordsAndMetadata)
{
    for (bool adding : {false, true}) {
        runEditor(adding, [&](QDialog& editor) {
            editor.findChild<QLineEdit*>(QStringLiteral("credentialTitleEdit"))->setText(
                QStringLiteral("  Compte fictif exact  "));
            editor.findChild<QLineEdit*>(QStringLiteral("credentialUsernameEdit"))->setText(
                QStringLiteral("\u00a0utilisateur-fictif\u00a0"));
            editor.findChild<QLineEdit*>(QStringLiteral("credentialPasswordEdit"))->setText(
                QStringLiteral("   "));
            editor.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Save)->click();
        });
    }
    std::vector<passwall::models::CredentialSummary> summaries;
    std::string error;
    ASSERT_TRUE(CredentialService::listSummaries(
        vaultPath.toStdString(), verificationKey, summaries, error));
    ASSERT_EQ(summaries.size(), 2u);
    for (const auto& summary : summaries) {
        Credential loaded;
        ASSERT_TRUE(CredentialService::get(
            vaultPath.toStdString(), verificationKey, summary.id, loaded, error));
        EXPECT_TRUE(loaded.title == "  Compte fictif exact  ");
        EXPECT_TRUE(loaded.username == "\xC2\xA0utilisateur-fictif\xC2\xA0");
        EXPECT_TRUE(loaded.password == "   ");
        wipeCredential(loaded);
    }
}

TEST_F(MainWindowEditorLockTest, InactivityTimerIsArmedBeforeUnlockedPageAndRefresh)
{
    restartLockedWindow();
    ASSERT_NE(inactivityTimer(), nullptr);
    EXPECT_FALSE(inactivityTimer()->isActive());
    bool checked = false;
    QObject observer;
    auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
    QObject::connect(pages, &QStackedWidget::currentChanged, &observer, [&](int) {
        if (pages->currentWidget() == window->findChild<QWidget*>(QStringLiteral("pageVault"))) {
            checked = true;
            EXPECT_TRUE(window->acquireLease().unlocked);
            EXPECT_TRUE(inactivityTimer()->isActive());
            EXPECT_EQ(inactivityTimer()->interval(), 60'000);
        }
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_TRUE(inactivityTimer()->isActive());
    EXPECT_TRUE(window->acquireLease().unlocked);
}

TEST_F(MainWindowEditorLockTest, InactivityTimerIsAlsoArmedDuringVaultCreation)
{
    restartLockedWindow(5);
    bool checked = false;
    QObject observer;
    auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
    QObject::connect(pages, &QStackedWidget::currentChanged, &observer, [&](int) {
        if (pages->currentWidget() == window->findChild<QWidget*>(QStringLiteral("pageVault"))) {
            checked = true;
            EXPECT_TRUE(window->acquireLease().unlocked);
            EXPECT_TRUE(inactivityTimer()->isActive());
            EXPECT_EQ(inactivityTimer()->interval(), 300'000);
        }
    });
    window->findChild<QPushButton*>(QStringLiteral("createPageButton"))->click();
    window->findChild<QLineEdit*>(QStringLiteral("createPathEdit"))->setText(
        testDirectory->filePath(QStringLiteral("created.pwdb")));
    window->findChild<QLineEdit*>(QStringLiteral("createPasswordEdit"))->setText(
        QStringLiteral("fictitious-new-master-password"));
    window->findChild<QLineEdit*>(QStringLiteral("confirmPasswordEdit"))->setText(
        QStringLiteral("fictitious-new-master-password"));
    runBounded([&]() {
        window->findChild<QPushButton*>(QStringLiteral("createVaultButton"))->click();
    });
    EXPECT_TRUE(checked);
    EXPECT_TRUE(inactivityTimer()->isActive());
}

TEST_F(MainWindowEditorLockTest, InactivityTimerRemainsActiveInsideRefreshErrorNotification)
{
    restartLockedWindow();
    corruptEntryCiphertext();
    bool checked = false;
    int activeTimerId = -1;
    QObject observer;
    duringRefreshError(observer, [&](QMessageBox& warning) {
        checked = true;
        EXPECT_TRUE(window->acquireLease().unlocked);
        EXPECT_TRUE(inactivityTimer()->isActive());
        EXPECT_EQ(inactivityTimer()->interval(), 60'000);
        activeTimerId = inactivityTimer()->timerId();
        warning.accept();
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_TRUE(inactivityTimer()->isActive());
    // Le retour de refreshCredentials() ne doit pas réinitialiser le délai.
    EXPECT_EQ(inactivityTimer()->timerId(), activeTimerId);
}

TEST_F(MainWindowEditorLockTest, InactivityTimeoutInsideRefreshErrorDoesNotRearmAfterLock)
{
    restartLockedWindow();
    corruptEntryCiphertext();
    bool checked = false;
    int lockCount = 0;
    QObject observer;
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated,
                     &observer, [&]() { ++lockCount; });
    duringRefreshError(observer, [&](QMessageBox&) {
        checked = true;
        EXPECT_TRUE(inactivityTimer()->isActive());
        // Accélérer uniquement le QTimer du test, sans modifier la politique.
        inactivityTimer()->start(1);
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    expectLockedAfterRefresh();
    QEventLoop settle;
    QTimer::singleShot(20, &settle, &QEventLoop::quit);
    settle.exec();
    EXPECT_EQ(lockCount, 1);
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, InactivityManualLockInsideRefreshErrorDoesNotRearm)
{
    restartLockedWindow();
    corruptEntryCiphertext();
    bool checked = false;
    QObject observer;
    duringRefreshError(observer, [&](QMessageBox&) {
        checked = true;
        EXPECT_TRUE(inactivityTimer()->isActive());
        lock();
        expectLockedAfterRefresh();
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, InactivityLockDuringListPopulationDiscardsTheOldRefresh)
{
    restartLockedWindow();
    bool checked = false;
    VaultLease oldLease;
    QObject observer;
    auto* list = window->findChild<QListWidget*>(QStringLiteral("credentialsList"));
    QObject::connect(list->model(), &QAbstractItemModel::rowsInserted,
                     &observer, [&]() {
        if (checked)
            return;
        checked = true;
        oldLease = window->acquireLease();
        EXPECT_TRUE(inactivityTimer()->isActive());
        lock();
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    expectLockedAfterRefresh();
}

TEST_F(MainWindowEditorLockTest, InactivityNewSessionDuringRefreshIsNotOverwritten)
{
    restartLockedWindow();
    Credential second = makeCredential();
    second.title = "Seconde entree fictive";
    std::string error;
    const bool added = CredentialService::add(
        vaultPath.toStdString(), verificationKey, second, error);
    wipeCredential(second);
    ASSERT_TRUE(added);
    bool checked = false;
    VaultLease oldLease;
    QObject observer;
    auto* list = window->findChild<QListWidget*>(QStringLiteral("credentialsList"));
    QObject::connect(list->model(), &QAbstractItemModel::rowsInserted,
                     &observer, [&]() {
        if (checked)
            return;
        checked = true;
        oldLease = window->acquireLease();
        lock();
        Credential updated;
        const bool found = CredentialService::get(
            vaultPath.toStdString(), verificationKey, entryId, updated, error);
        EXPECT_TRUE(found);
        updated.title = "Compte de la nouvelle session";
        const bool saved = CredentialService::update(
            vaultPath.toStdString(), verificationKey, updated, error);
        wipeCredential(updated);
        EXPECT_TRUE(saved);
        unlock();
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    const VaultLease current = window->acquireLease();
    ASSERT_TRUE(current.unlocked);
    EXPECT_TRUE(inactivityTimer()->isActive());
    EXPECT_EQ(list->count(), 2);
    std::vector<passwall::models::CredentialSummary> summaries;
    EXPECT_EQ(window->copySummaries(current, summaries),
              passwall::native::VaultAccessResult::Success);
    EXPECT_EQ(summaries.size(), 2U);
    bool foundNewTitle = false;
    for (const auto& summary : summaries) {
        if (summary.id == entryId) {
            foundNewTitle = summary.title == "Compte de la nouvelle session";
        }
    }
    EXPECT_TRUE(foundNewTitle);
    auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
    EXPECT_TRUE(pages->currentWidget() ==
                window->findChild<QWidget*>(QStringLiteral("pageVault")));
}

TEST_F(MainWindowEditorLockTest, InactivityLockDuringPageChangeSkipsTheRefresh)
{
    restartLockedWindow();
    corruptEntryCiphertext();
    bool checked = false;
    QObject observer;
    auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
    QObject::connect(pages, &QStackedWidget::currentChanged, &observer, [&](int) {
        if (!checked && pages->currentWidget() ==
                window->findChild<QWidget*>(QStringLiteral("pageVault"))) {
            checked = true;
            EXPECT_TRUE(inactivityTimer()->isActive());
            lock();
        }
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    expectLockedAfterRefresh();
    EXPECT_TRUE(window->findChildren<QMessageBox*>().isEmpty());
}

TEST_F(MainWindowEditorLockTest, InactivityMandatoryChoicesPersistAndReloadWithoutMigrationNotice)
{
    QSettings("PassWall", "PassWall").setValue("unrelated/value", "keep");
    for (const int minutes : {1, 5, 15, 30, 60}) {
        SCOPED_TRACE(minutes);
        chooseInactivityDuration(minutes);
        EXPECT_TRUE(inactivityTimer()->isActive());
        EXPECT_EQ(inactivityTimer()->interval(), minutes * 60'000);
        EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), minutes);
        window.reset(); newLockedWindow(); QApplication::processEvents();
        EXPECT_EQ(migrationNotice(), nullptr);
        EXPECT_FALSE(inactivityTimer()->isActive());
        EXPECT_EQ(inactivityTimer()->interval(), minutes * 60'000);
        runBounded([&] { unlock(); });
        EXPECT_TRUE(inactivityTimer()->isActive());
        EXPECT_EQ(inactivityTimer()->interval(), minutes * 60'000);
        EXPECT_EQ(QSettings("PassWall", "PassWall").value("unrelated/value").toString(), "keep");
    }
}

TEST_F(MainWindowEditorLockTest, InactivityMissingPreferenceDefaultsToOneMinuteWithoutNotification)
{
    window.reset();
    { QSettings settings("PassWall", "PassWall"); settings.remove("security/autoLockMinutes"); settings.sync(); }
    newLockedWindow(); QApplication::processEvents();
    EXPECT_EQ(migrationNotice(), nullptr); EXPECT_EQ(inactivityTimer()->interval(), 60'000);
    runBounded([&] { unlock(); });
    EXPECT_TRUE(inactivityTimer()->isActive()); EXPECT_EQ(inactivityTimer()->interval(), 60'000);
}

TEST_F(MainWindowEditorLockTest, InactivityInvalidPreferencesMigrateUniformlyWithoutDisablingProtection)
{
    const QList<QVariant> invalid{0, 10, -1, 2, 61, std::numeric_limits<int>::max(),
        QStringLiteral("disabled"), QStringLiteral("1.5"), QStringLiteral("999999999999999999999"),
        QString{}, 1.5, true};
    for (const auto& value : invalid) {
        SCOPED_TRACE(value.toString().toStdString());
        window.reset();
        { QSettings settings("PassWall", "PassWall"); settings.setValue("security/autoLockMinutes", value); settings.sync(); }
        newLockedWindow(); QApplication::processEvents();
        ASSERT_NE(migrationNotice(), nullptr);
        EXPECT_FALSE(migrationNotice()->isModal());
        EXPECT_EQ(QApplication::activeModalWidget(), nullptr);
        EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 1);
        migrationNotice()->accept(); QApplication::processEvents();
        runBounded([&] { unlock(); });
        ASSERT_TRUE(window->acquireLease().unlocked);
        EXPECT_TRUE(inactivityTimer()->isActive()); EXPECT_EQ(inactivityTimer()->interval(), 60'000);
        window.reset(); newLockedWindow(); QApplication::processEvents();
        EXPECT_EQ(migrationNotice(), nullptr); // The durable migration is not announced again.
    }
}

TEST_F(MainWindowEditorLockTest, InactivityMigrationPersistenceFailureStillUsesOneMinuteAndCanRetry)
{
    window.reset();
    QSettings settings("PassWall", "PassWall");
    settings.setValue("security/autoLockMinutes", 0); settings.sync();
    QLockFile writer(settings.fileName() + ".registry-lock"); ASSERT_TRUE(writer.tryLock(0));
    newLockedWindow(); QApplication::processEvents();
    ASSERT_NE(migrationNotice(), nullptr); EXPECT_FALSE(migrationNotice()->isModal());
    EXPECT_TRUE(migrationNotice()->text().contains("Enregistrement impossible"));
    EXPECT_EQ(inactivityTimer()->interval(), 60'000);
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 0);
    writer.unlock(); migrationNotice()->accept();
    runBounded([&] { unlock(); });
    EXPECT_TRUE(inactivityTimer()->isActive()); EXPECT_EQ(inactivityTimer()->interval(), 60'000);
    window.reset(); newLockedWindow(); QApplication::processEvents();
    ASSERT_NE(migrationNotice(), nullptr);
    EXPECT_FALSE(migrationNotice()->text().contains("Enregistrement impossible"));
    EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 1);
}

TEST_F(MainWindowEditorLockTest, InactivityMigrationNeverRewritesAnInvalidVaultRegistry)
{
    window.reset();
    { QSettings settings("PassWall", "PassWall");
      settings.setValue("security/autoLockMinutes", 0);
      settings.setValue("vaultRegistry/data", "invalid-registry"); settings.sync(); }
    const auto path = QSettings("PassWall", "PassWall").fileName();
    QFile file(path); ASSERT_TRUE(file.open(QIODevice::ReadOnly)); const auto before = file.readAll(); file.close();
    newLockedWindow(); QApplication::processEvents();
    EXPECT_EQ(inactivityTimer()->interval(), 60'000);
    ASSERT_NE(migrationNotice(), nullptr);
    EXPECT_TRUE(migrationNotice()->text().contains("Enregistrement impossible"));
    ASSERT_TRUE(file.open(QIODevice::ReadOnly)); EXPECT_EQ(file.readAll(), before);
    EXPECT_FALSE(window->acquireLease().unlocked);
}

TEST_F(MainWindowEditorLockTest, InactivityFailedGuiPreferenceSaveFallsBackToOneMinuteInMemory)
{
    QLockFile writer(QSettings("PassWall", "PassWall").fileName() + ".registry-lock");
    ASSERT_TRUE(writer.tryLock(0)); chooseInactivityDuration(60);
    EXPECT_TRUE(inactivityTimer()->isActive()); EXPECT_EQ(inactivityTimer()->interval(), 60'000);
    EXPECT_TRUE(window->statusBar()->currentMessage().contains("non enregistrées"));
    writer.unlock(); EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 1);
}

TEST_F(MainWindowEditorLockTest, InactivityCancelledSettingPreservesPolicyAndTimer)
{
    restartLockedWindow(5); runBounded([&] { unlock(); });
    const auto id = inactivityTimer()->timerId(); chooseInactivityDuration(60, false);
    EXPECT_EQ(inactivityTimer()->interval(), 300'000); EXPECT_TRUE(inactivityTimer()->isActive());
    EXPECT_EQ(inactivityTimer()->timerId(), id);
    EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 5);
}

TEST_F(MainWindowEditorLockTest, InactivityExpirationRejectsSettingDialogAndCannotRearmVault)
{
    const auto lease = window->acquireLease();
    QTimer::singleShot(0, window.get(), [&] {
        auto* dialog = window->findChild<QInputDialog*>("autoLockDurationDialog"); ASSERT_NE(dialog, nullptr);
        dialog->findChild<QComboBox*>()->setCurrentIndex(4);
        inactivityTimer()->start(1); // The actual timeout rejects the modal setting, not an accept.
    });
    runBounded([&] { window->findChild<QAction*>("autoLockDurationAction")->trigger(); });
    EXPECT_FALSE(window->isLeaseCurrent(lease)); expectLockedAfterRefresh();
    EXPECT_EQ(QSettings("PassWall", "PassWall").value("security/autoLockMinutes").toInt(), 1);
    runBounded([&] { unlock(); });
    EXPECT_TRUE(inactivityTimer()->isActive()); EXPECT_EQ(inactivityTimer()->interval(), 60'000);
}

TEST_F(MainWindowEditorLockTest, InactivityUserInputRestartsOnlyAnActiveTimer)
{
    const auto original = inactivityTimer()->timerId();
    auto* target = window->findChild<QLineEdit*>("credentialSearchEdit");
    QKeyEvent key(QEvent::KeyPress, Qt::Key_Shift, Qt::ShiftModifier);
    QApplication::sendEvent(target, &key);
    EXPECT_TRUE(inactivityTimer()->isActive()); EXPECT_NE(inactivityTimer()->timerId(), original);
    EXPECT_EQ(inactivityTimer()->interval(), 60'000);
    lock(); QApplication::sendEvent(target, &key);
    EXPECT_FALSE(inactivityTimer()->isActive()); EXPECT_FALSE(window->acquireLease().unlocked);
}

TEST_F(MainWindowEditorLockTest, InactivityOneRealMinuteExpiresWithoutSyntheticTimeoutOrIntervalChange)
{
    const auto lease = window->acquireLease();
    ASSERT_TRUE(lease.unlocked); ASSERT_EQ(inactivityTimer()->interval(), 60'000);
    ASSERT_GE(inactivityTimer()->remainingTime(), 59'000);
    bool invalidated = false; QEventLoop idle; QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, &idle, &QEventLoop::quit);
    QObject::connect(window.get(), &MainWindow::vaultSessionInvalidated, &idle, [&] { invalidated = true; idle.quit(); });
    QElapsedTimer elapsed; elapsed.start();
    watchdog.start(75'000); idle.exec();
    ASSERT_TRUE(invalidated);
    EXPECT_GE(elapsed.elapsed(), 59'000); // No accelerated clock or direct timeout signal in this case.
    EXPECT_FALSE(window->isLeaseCurrent(lease)); expectLockedAfterRefresh();
    std::vector<passwall::models::CredentialSummary> output;
    EXPECT_NE(window->copySummaries(lease, output), passwall::native::VaultAccessResult::Success);
    EXPECT_TRUE(output.empty());
}

TEST_F(MainWindowEditorLockTest, InactivityDisabledPreferenceMigratesAndArmsBeforePagePublication)
{
    restartLockedWindow(0);
    ASSERT_NE(inactivityTimer(), nullptr);
    bool checked = false;
    QObject observer;
    auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
    QObject::connect(pages, &QStackedWidget::currentChanged, &observer, [&](int) {
        if (pages->currentWidget() == window->findChild<QWidget*>(QStringLiteral("pageVault"))) {
            checked = true;
            EXPECT_TRUE(window->acquireLease().unlocked);
            EXPECT_TRUE(inactivityTimer()->isActive());
            EXPECT_EQ(inactivityTimer()->interval(), 60'000);
        }
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_TRUE(inactivityTimer()->isActive());
    QSettings settings("PassWall", "PassWall");
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 1);
}

TEST_F(MainWindowEditorLockTest, InactivityMigratedPreferenceStillExpiresInsideRefreshError)
{
    restartLockedWindow(0);
    QApplication::processEvents();
    ASSERT_NE(migrationNotice(), nullptr); migrationNotice()->accept();
    corruptEntryCiphertext();
    bool checked = false;
    QObject observer;
    duringRefreshError(observer, [&](QMessageBox& warning) {
        checked = true;
        EXPECT_TRUE(window->acquireLease().unlocked);
        EXPECT_TRUE(inactivityTimer()->isActive());
        inactivityTimer()->start(1); // Real timeout, accelerated only in this test.
        (void)warning;
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    expectLockedAfterRefresh();
    QSettings settings("PassWall", "PassWall");
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 1);
}

} // namespace

int main(int argc, char** argv)
{
    // Explicit organization/application constructors use NativeFormat in Qt
    // 6.8.2, regardless of setDefaultFormat(). Isolate that format too, BEFORE
    // any fixture/window can read or write the user's personal configuration.
    const auto probeRoot = qEnvironmentVariable("PW_RESTORE_PARENT_ROOT");
    QTemporaryDir nativeSettings(probeRoot.isEmpty() ? QDir::tempPath() + "/pw-native-XXXXXX" : probeRoot + "/native-XXXXXX");
    if (!nativeSettings.isValid())
        return 1;
    // QSettings::setPath() is process-local. Backup workers are separate
    // processes and otherwise fall back to the user's shared native settings
    // root, including PassWall.conf.registry-lock. Export the already-private
    // root before any worker can start so every child resolves the same
    // per-CTest-process recovery registry as its parent.
    if (!qputenv("XDG_CONFIG_HOME", QFile::encodeName(nativeSettings.path())))
        return 1;
    QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, nativeSettings.path());
    QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, nativeSettings.path());
    // Some CTest cases exercise SecureBuffer directly, without first going
    // through a vault service that initializes libsodium for them.
    if (sodium_init() < 0)
        return 1;
    // Les tests ne lancent ni passwall_app ni Firefox et n'utilisent pas le
    // bureau utilisateur. Ce choix permet aussi la decouverte CTest sans ecran.
    qputenv("QT_QPA_PLATFORM", QByteArrayLiteral("offscreen"));
    qunsetenv("QT_QPA_PLATFORMTHEME");
    qputenv("QT_STYLE_OVERRIDE", QByteArrayLiteral("Fusion"));
    QApplication application(argc, argv);
    application.setQuitOnLastWindowClosed(false);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
