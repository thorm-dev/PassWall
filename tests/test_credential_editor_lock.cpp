#include "gui/credential_editor_context.hpp"
#include "gui/main_window.hpp"
#include "services/credential_service.hpp"
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
        suiteDirectory = std::make_unique<QTemporaryDir>(
            QStringLiteral("/tmp/passwall-editor-lock-suite-XXXXXX"));
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
        testDirectory = std::make_unique<QTemporaryDir>(
            QStringLiteral("/tmp/passwall-editor-lock-case-XXXXXX"));
        ASSERT_TRUE(testDirectory->isValid());
        vaultPath = testDirectory->filePath(QStringLiteral("vault.pwdb"));
        ASSERT_TRUE(QFile::copy(
            suiteDirectory->filePath(QStringLiteral("template.pwdb")), vaultPath));
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
