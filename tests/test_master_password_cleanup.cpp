#include "gui/main_window.hpp"
#include "services/vault_lifecycle_service.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <QApplication>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QTimer>

#include <algorithm>
#include <exception>
#include <functional>
#include <memory>
#include <string>

namespace {
using passwall::core::SecureBuffer;
using passwall::gui::MainWindow;
using passwall::services::VaultLifecycleService;

enum class ServiceBehavior { RealService, ThrowWithPartialKey, FailWithPartialKey };
struct ServiceFailure {};

struct CleanupProbe {
    ServiceBehavior behavior = ServiceBehavior::RealService;
    unsigned calls = 0;
    const void* passwordMemory = nullptr;
    std::size_t passwordSize = 0;
    const void* keyMemory = nullptr;
    std::size_t keySize = 0;
    bool passwordZeroed = false;
    bool passwordZeroedWhileUnwinding = false;
    bool partialKeyZeroed = false;
};

// Emprunts d'adresses, jamais de copie du secret ni de lecture après libération.
// Les wrappers sont limités à cet exécutable Linux et passent normalement
// au vrai service, y compris pour les autres suites GUI existantes.
thread_local CleanupProbe* activeProbe = nullptr;

using LifecycleCall = bool (*)(const std::string&, const std::string&,
                               SecureBuffer&, std::string&);

bool callWithProbe(LifecycleCall realCall, const std::string& path,
                   const std::string& password, SecureBuffer& key, std::string& error)
{
    if (activeProbe == nullptr)
        return realCall(path, password, key, error);

    auto& probe = *activeProbe;
    ++probe.calls;
    probe.passwordMemory = password.data();
    probe.passwordSize = password.size();
    if (probe.behavior == ServiceBehavior::RealService)
        return realCall(path, password, key, error);

    // Éprouver aussi le nettoyage d'une sortie partiellement construite.
    key = SecureBuffer(passwall::core::KeySize);
    std::fill_n(key.data(), key.size(), 0x5a);
    probe.keyMemory = key.data();
    probe.keySize = key.size();
    if (probe.behavior == ServiceBehavior::ThrowWithPartialKey)
        throw ServiceFailure{};
    error = "Échec simulé du service.";
    return false;
}

bool allZero(const void* memory, std::size_t size) noexcept
{
    const auto* bytes = static_cast<const unsigned char*>(memory);
    for (std::size_t index = 0; index < size; ++index)
        if (bytes[index] != 0)
            return false;
    return true;
}
} // namespace

extern "C" void __real_sodium_memzero(void*, std::size_t);
extern "C" void __wrap_sodium_memzero(void* memory, std::size_t size)
{
    __real_sodium_memzero(memory, size);
    if (activeProbe == nullptr)
        return;
    auto& probe = *activeProbe;
    if (memory == probe.passwordMemory && size == probe.passwordSize) {
        probe.passwordZeroed = allZero(memory, size);
        probe.passwordZeroedWhileUnwinding = std::uncaught_exceptions() > 0;
        probe.passwordMemory = nullptr;
    }
    if (memory == probe.keyMemory && size == probe.keySize) {
        probe.partialKeyZeroed = allZero(memory, size);
        probe.keyMemory = nullptr;
    }
}

extern "C" bool realCreateVault(const std::string&, const std::string&,
                                 SecureBuffer&, std::string&)
    asm("__real__ZN8passwall8services21VaultLifecycleService11createVaultERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES9_RNS_4core12SecureBufferERS7_");
extern "C" bool wrappedCreateVault(const std::string&, const std::string&,
                                    SecureBuffer&, std::string&)
    asm("__wrap__ZN8passwall8services21VaultLifecycleService11createVaultERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES9_RNS_4core12SecureBufferERS7_");
extern "C" bool wrappedCreateVault(const std::string& path, const std::string& password,
                                    SecureBuffer& key, std::string& error)
{
    return callWithProbe(realCreateVault, path, password, key, error);
}

extern "C" bool realUnlockVault(const std::string&, const std::string&,
                                 SecureBuffer&, std::string&)
    asm("__real__ZN8passwall8services21VaultLifecycleService11unlockVaultERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES9_RNS_4core12SecureBufferERS7_");
extern "C" bool wrappedUnlockVault(const std::string&, const std::string&,
                                    SecureBuffer&, std::string&)
    asm("__wrap__ZN8passwall8services21VaultLifecycleService11unlockVaultERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES9_RNS_4core12SecureBufferERS7_");
extern "C" bool wrappedUnlockVault(const std::string& path, const std::string& password,
                                    SecureBuffer& key, std::string& error)
{
    return callWithProbe(realUnlockVault, path, password, key, error);
}

namespace {
class MasterPasswordCleanupTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<QTemporaryDir> suiteDirectory;
    std::unique_ptr<QTemporaryDir> directory;
    std::unique_ptr<MainWindow> window;
    CleanupProbe probe;
    bool sessionPublished = false;
    bool cleanedBeforePublication = false;

    static void SetUpTestSuite()
    {
        ASSERT_GE(sodium_init(), 0);
        suiteDirectory = std::make_unique<QTemporaryDir>(
            QStringLiteral("/tmp/passwall-master-cleanup-suite-XXXXXX"));
        ASSERT_TRUE(suiteDirectory->isValid());
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                           suiteDirectory->path());
        QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope,
                           suiteDirectory->path());
        SecureBuffer key(0);
        std::string error;
        ASSERT_TRUE(VaultLifecycleService::createVault(
            templatePath().toStdString(), "fictitious-master-password", key, error));
    }

    static void TearDownTestSuite() { suiteDirectory.reset(); }
    static QString templatePath()
    {
        return suiteDirectory->filePath(QStringLiteral("template.pwdb"));
    }

    void SetUp() override
    {
        directory = std::make_unique<QTemporaryDir>(
            QStringLiteral("/tmp/passwall-master-cleanup-case-XXXXXX"));
        ASSERT_TRUE(directory->isValid());
        QSettings settings("PassWall", "PassWall");
        settings.clear();
        settings.setValue("security/autoLockMinutes", 1);
        window = std::make_unique<MainWindow>();
        window->setLifecycleProtectionValidator([] { return true; }, [] {});
        window->setLifecycleProtectionAvailable(true);
        window->show();
        auto* pages = window->findChild<QStackedWidget*>(QStringLiteral("stackedWidget"));
        ASSERT_NE(pages, nullptr);
        QObject::connect(pages, &QStackedWidget::currentChanged, window.get(), [this, pages](int) {
            if (pages->currentWidget()->objectName() == QStringLiteral("pageVault")) {
                sessionPublished = true;
                cleanedBeforePublication = probe.passwordZeroed && passwordFieldsEmpty();
            }
        });
        activeProbe = &probe;
    }

    void TearDown() override
    {
        activeProbe = nullptr;
        window.reset();
        directory.reset();
        QApplication::processEvents();
    }

    void click(const char* name)
    {
        auto* button = window->findChild<QPushButton*>(QString::fromLatin1(name));
        ASSERT_NE(button, nullptr);
        button->click();
    }

    void setField(const char* name, const QString& value)
    {
        auto* field = window->findChild<QLineEdit*>(QString::fromLatin1(name));
        ASSERT_NE(field, nullptr);
        field->setText(value);
    }

    bool passwordFieldsEmpty() const
    {
        for (const auto* name : {"createPasswordEdit", "confirmPasswordEdit", "unlockPasswordEdit"}) {
            auto* field = window->findChild<QLineEdit*>(QString::fromLatin1(name));
            if (field == nullptr || !field->text().isEmpty())
                return false;
        }
        return true;
    }

    void prepareCreation(const QString& password = QStringLiteral("fictitious-master-password"))
    {
        click("createPageButton");
        setField("createPathEdit", directory->filePath(QStringLiteral("created.pwdb")));
        setField("createPasswordEdit", password);
        setField("confirmPasswordEdit", password);
    }

    void prepareUnlock(const QString& password = QStringLiteral("fictitious-master-password"))
    {
        click("openPageButton");
        setField("unlockPathEdit", templatePath());
        setField("unlockPasswordEdit", password);
    }

    void expectError(const char* button, bool serviceCalled = true)
    {
        bool observed = false;
        QTimer inspect;
        inspect.setInterval(1);
        QObject::connect(&inspect, &QTimer::timeout, window.get(), [&]() {
            auto* warning = window->findChild<QMessageBox*>();
            if (warning == nullptr || !warning->isVisible())
                return;
            observed = true;
            // Vérification PENDANT la notification, avant sa fermeture.
            EXPECT_TRUE(passwordFieldsEmpty());
            EXPECT_FALSE(window->acquireLease().unlocked);
            EXPECT_FALSE(sessionPublished);
            auto* timer = window->findChild<QTimer*>(QStringLiteral("vaultInactivityTimer"));
            ASSERT_NE(timer, nullptr);
            EXPECT_FALSE(timer->isActive());
            if (serviceCalled)
                EXPECT_TRUE(probe.passwordZeroed);
            if (probe.behavior != ServiceBehavior::RealService)
                EXPECT_TRUE(probe.partialKeyZeroed);
            warning->accept();
            inspect.stop();
        });
        QTimer watchdog;
        watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, window.get(), [&]() {
            ADD_FAILURE() << "La notification attendue n'a pas été traitée dans le délai de test.";
            for (auto* dialog : window->findChildren<QMessageBox*>())
                dialog->reject();
        });
        inspect.start();
        watchdog.start(10'000);
        click(button);
        watchdog.stop();
        inspect.stop();
        EXPECT_TRUE(observed);
        EXPECT_FALSE(window->acquireLease().unlocked);
        EXPECT_EQ(probe.calls, serviceCalled ? 1u : 0u);
    }

    void expectSuccess(const char* button)
    {
        QTimer watchdog;
        watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, window.get(), [&]() {
            ADD_FAILURE() << "Une notification inattendue empêche la fin de l'opération.";
            for (auto* dialog : window->findChildren<QMessageBox*>())
                dialog->reject();
        });
        watchdog.start(10'000);
        click(button);
        watchdog.stop();
        EXPECT_EQ(probe.calls, 1u);
        EXPECT_TRUE(probe.passwordZeroed);
        EXPECT_FALSE(probe.passwordZeroedWhileUnwinding);
        EXPECT_TRUE(passwordFieldsEmpty());
        EXPECT_TRUE(sessionPublished);
        EXPECT_TRUE(cleanedBeforePublication);
        EXPECT_TRUE(window->acquireLease().unlocked);
    }
};

TEST_F(MasterPasswordCleanupTest, CreationSuccessWipesBeforeSessionPublication)
{
    prepareCreation();
    expectSuccess("createVaultButton");
}

TEST_F(MasterPasswordCleanupTest, CreationFailureWipesBeforeErrorNotification)
{
    prepareCreation();
    setField("createPathEdit", directory->filePath(QStringLiteral("missing/created.pwdb")));
    expectError("createVaultButton");
}

TEST_F(MasterPasswordCleanupTest, UnlockSuccessWipesBeforeSessionPublication)
{
    prepareUnlock();
    expectSuccess("unlockVaultButton");
}

TEST_F(MasterPasswordCleanupTest, WrongMasterPasswordWipesWithoutPublishingSession)
{
    prepareUnlock(QStringLiteral("fictitious-wrong-master-password"));
    expectError("unlockVaultButton");
}

TEST_F(MasterPasswordCleanupTest, CreationServiceExceptionWipesDuringUnwinding)
{
    probe.behavior = ServiceBehavior::ThrowWithPartialKey;
    prepareCreation();
    expectError("createVaultButton");
    EXPECT_TRUE(probe.passwordZeroedWhileUnwinding);
}

TEST_F(MasterPasswordCleanupTest, UnlockServiceExceptionWipesDuringUnwinding)
{
    probe.behavior = ServiceBehavior::ThrowWithPartialKey;
    prepareUnlock();
    expectError("unlockVaultButton");
    EXPECT_TRUE(probe.passwordZeroedWhileUnwinding);
}

TEST_F(MasterPasswordCleanupTest, ExceptionAlsoWipesShortStringStorage)
{
    probe.behavior = ServiceBehavior::ThrowWithPartialKey;
    prepareUnlock(QStringLiteral("fake"));
    expectError("unlockVaultButton");
    EXPECT_TRUE(probe.passwordZeroedWhileUnwinding);
}

TEST_F(MasterPasswordCleanupTest, CreationFalseReturnAlsoDropsPartialKey)
{
    probe.behavior = ServiceBehavior::FailWithPartialKey;
    prepareCreation();
    expectError("createVaultButton");
}

TEST_F(MasterPasswordCleanupTest, UnlockFalseReturnAlsoDropsPartialKey)
{
    probe.behavior = ServiceBehavior::FailWithPartialKey;
    prepareUnlock();
    expectError("unlockVaultButton");
}

TEST_F(MasterPasswordCleanupTest, MismatchedConfirmationNeverCallsService)
{
    prepareCreation();
    setField("confirmPasswordEdit", QStringLiteral("fictitious-other-confirmation"));
    expectError("createVaultButton", false);
}

TEST_F(MasterPasswordCleanupTest, EmptyCreationPasswordNeverCallsService)
{
    prepareCreation(QString());
    expectError("createVaultButton", false);
}

TEST_F(MasterPasswordCleanupTest, EmptyUnlockPasswordNeverCallsService)
{
    prepareUnlock(QString());
    expectError("unlockVaultButton", false);
}

TEST_F(MasterPasswordCleanupTest, Utf8MasterPasswordStillCreatesAndUnlocks)
{
    const QString password = QStringLiteral("fictif-é-漢-🔑");
    prepareCreation(password);
    expectSuccess("createVaultButton");
    const auto oldLease = window->acquireLease();
    click("lockVaultButton");
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
    probe = CleanupProbe{};
    sessionPublished = false;
    cleanedBeforePublication = false;
    prepareUnlock(password);
    setField("unlockPathEdit", directory->filePath(QStringLiteral("created.pwdb")));
    expectSuccess("unlockVaultButton");
    EXPECT_FALSE(window->isLeaseCurrent(oldLease));
}
} // namespace
