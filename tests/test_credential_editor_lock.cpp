#include "gui/credential_editor_context.hpp"
#include "gui/main_window.hpp"
#include "services/credential_service.hpp"
#include "services/restore_protocol.hpp"
#include "storage/vault_operation_guard.hpp"
#include "services/vault_lifecycle_service.hpp"
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
#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QLineEdit>
#include <QJsonDocument>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QTextEdit>
#include <QTimer>
#include <QScopeGuard>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#ifdef Q_OS_LINUX
extern "C" QString wrappedRestoreWorkerPath() asm("__wrap__ZN8passwall8services10RestoreJob17siblingWorkerPathEv");
extern "C" QString wrappedRestoreWorkerPath() { return QString::fromUtf8(RESTORE_TEST_WORKER); }
namespace {
std::atomic<bool> pausePreparationSync{false}, preparationSyncEntered{false}, releasePreparationSync{false};
std::atomic<bool> failPreparationSync{false};
std::mutex preparationSyncMutex;
std::condition_variable preparationSyncCondition;
const auto guiTestThread = std::this_thread::get_id();
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd) {
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
void suppressGuiStopsForRestore(bool);
bool guiRestoreStopWasRequested();
void releaseGuiRestoreStop();
}
#endif

#include <functional>
#include <array>
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
        window = std::make_unique<MainWindow>();
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
        window = std::make_unique<MainWindow>();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        EXPECT_FALSE(window->acquireLease().unlocked);
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
    ::testing::Values("uuid", "principal", "vault", "inode", "session", "protocol", "duplicate"));
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
    window = std::make_unique<MainWindow>(); // no injected readiness
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
    window = std::make_unique<MainWindow>();
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

TEST_F(MainWindowEditorLockTest, LinuxLifecycleLocksInsideRefreshErrorWithInactivityDisabled)
{
    restartLockedWindow(0);
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

TEST_F(MainWindowEditorLockTest, InactivityDisabledPolicyDoesNotArmTheTimer)
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
            EXPECT_FALSE(inactivityTimer()->isActive());
        }
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_FALSE(inactivityTimer()->isActive());
    QSettings settings("PassWall", "PassWall");
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 0);
}

TEST_F(MainWindowEditorLockTest, InactivityDisabledPolicyIsRespectedInsideRefreshError)
{
    restartLockedWindow(0);
    corruptEntryCiphertext();
    bool checked = false;
    bool checkedAfterWait = false;
    QObject observer;
    duringRefreshError(observer, [&](QMessageBox& warning) {
        checked = true;
        EXPECT_TRUE(window->acquireLease().unlocked);
        EXPECT_FALSE(inactivityTimer()->isActive());
        QTimer::singleShot(20, &warning, [&]() {
            checkedAfterWait = true;
            EXPECT_TRUE(window->acquireLease().unlocked);
            EXPECT_FALSE(inactivityTimer()->isActive());
            warning.accept();
        });
    });
    runBounded([&]() { unlock(); });
    EXPECT_TRUE(checked);
    EXPECT_TRUE(checkedAfterWait);
    EXPECT_TRUE(window->acquireLease().unlocked);
    EXPECT_FALSE(inactivityTimer()->isActive());
    QSettings settings("PassWall", "PassWall");
    EXPECT_EQ(settings.value("security/autoLockMinutes").toInt(), 0);
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
    QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope, nativeSettings.path());
    QSettings::setPath(QSettings::NativeFormat, QSettings::SystemScope, nativeSettings.path());
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
