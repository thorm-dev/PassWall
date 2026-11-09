#include "main_window.hpp"
#include "core/password_generator.hpp"
#include "gui/credential_editor_context.hpp"
#include "native/native_bridge_server.hpp"
#include "services/credential_service.hpp"
#include "services/vault_lifecycle_service.hpp"
#include "services/vault_preferences_store.hpp"
#ifdef Q_OS_LINUX
#include "services/automatic_backup_coordinator.hpp"
#endif
#include "storage/vault_operation_guard.hpp"
#include "ui_main_window.h"
#ifdef Q_OS_LINUX
#include "gui/vault_export_dialog.hpp"
#include "services/backup_job.hpp"
#endif
#include <sodium.h>

#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QScopedValueRollback>
#include <QScopeGuard>
#include <QSettings>
#include <QSpinBox>
#include <QStatusBar>
#include <QStringList>
#include <QTextEdit>
#include <QTextDocument>
#include <QTimer>
#include <QThread>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
namespace passwall::gui
{
    namespace
    {
        using detail::wipeCredential;
        using detail::wipeString;
        void wipeQString(QString &value);
        std::uint64_t clipboardCopyGeneration = 0;
        QString lastPassWallClipboardText;
        void takePassword(QLineEdit *field, std::string &password)
        {
            // Le destinataire a déjà son nettoyeur. Ne pas retourner une
            // string par valeur : un déplacement peut recopier son stockage SSO.
            QString text;
            const auto textCleanup = qScopeGuard([&]() noexcept {
                // Ne jamais détacher/allouer pendant un déroulement de pile.
                // Les allocations Qt encore partagées ne sont pas effaçables
                // ici sans modifier les autres propriétaires.
                if (text.isDetached() && !text.isEmpty())
                    sodium_memzero(text.data(),
                        static_cast<std::size_t>(text.size()) * sizeof(QChar));
                text.clear();
            });
            QByteArray utf8;
            const auto utf8Cleanup = qScopeGuard([&]() noexcept {
                if (utf8.isDetached() && !utf8.isEmpty())
                    sodium_memzero(utf8.data(),
                        static_cast<std::size_t>(utf8.size()));
                utf8.clear();
            });

            text = field->text();
            field->clear();
            // Si ce détachement échoue, les gardes restent actives, sans
            // prétendre effacer les anciennes copies internes de QLineEdit.
            text.detach();
            utf8 = text.toUtf8();
            password.assign(utf8.constData(),
                static_cast<std::size_t>(utf8.size()));
        }
        class CredentialWiper final
        {
        public:
            explicit CredentialWiper(models::Credential &credential) noexcept
                : credential_(credential)
            {
            }

            ~CredentialWiper()
            {
                wipeCredential(credential_);
            }

            CredentialWiper(const CredentialWiper &) = delete;
            CredentialWiper &operator=(const CredentialWiper &) = delete;

        private:
            models::Credential &credential_;
        };
        void wipeCredentialSummary(models::CredentialSummary &summary)
        {
            wipeString(summary.title);
            wipeString(summary.url);
            wipeString(summary.username);
            sodium_memzero(summary.id.data(), summary.id.size());
            summary.version = 0;
        }
        QString fromUtf8(const std::string &value)
        {
            return QString::fromUtf8(
                value.data(),
                static_cast<qsizetype>(value.size()));
        }
        void setEditText(QLineEdit *edit, const std::string &value)
        {
            edit->setText(fromUtf8(value));
        }
        void assignEditText(QLineEdit *edit, std::string &destination)
        {
            QString text = edit->text();
            QByteArray utf8 = text.toUtf8();

            destination.assign(
                utf8.constData(),
                static_cast<std::size_t>(utf8.size()));

            if (!utf8.isEmpty())
            {
                sodium_memzero(
                    utf8.data(),
                    static_cast<std::size_t>(utf8.size()));
            }

            utf8.clear();
            wipeQString(text);
        }
        void wipeQString(QString &value)
        {
            // Détacher la chaîne pour ne pas modifier une autre copie partagée.
            value.detach();
            if (!value.isEmpty())
            {
                sodium_memzero(
                    value.data(),
                    static_cast<std::size_t>(value.size() * sizeof(QChar)));
            }
            value.clear();
        }
        bool clipboardMatchesLastPassWallText(QClipboard *clipboard)
        {
            if (clipboard == nullptr ||
                lastPassWallClipboardText.isEmpty())
            {
                return false;
            }

            QString clipboardText =
                clipboard->text(QClipboard::Clipboard);

            const bool matches =
                clipboardText == lastPassWallClipboardText;

            wipeQString(clipboardText);

            return matches;
        }
        // Efface les champs du formulaire avant la destruction de la boîte de dialogue.
        // Cela réduit leur durée de présence dans les widgets Qt, sans garantir
        // l'effacement physique de toutes les copies internes de Qt.
        struct DialogFieldCleanup final
        {
            QPointer<QLineEdit> title;
            QPointer<QLineEdit> url;
            QPointer<QLineEdit> username;
            QPointer<QLineEdit> password;
            QPointer<QTextEdit> notes;

            ~DialogFieldCleanup()
            {
                if (title != nullptr)
                    title->clear();
                if (url != nullptr)
                    url->clear();
                if (username != nullptr)
                    username->clear();
                if (password != nullptr)
                    password->clear();
                if (notes != nullptr)
                    notes->clear();
            }
        };
        void clearPassWallClipboardIfUnchanged()
        {
            QClipboard *clipboard = QGuiApplication::clipboard();
            // Ne jamais effacer un contenu que l'utilisateur a remplacé.
            if (clipboardMatchesLastPassWallText(clipboard))
            {
                clipboard->clear(QClipboard::Clipboard);
            }
            // Invalider le délai en cours et effacer notre copie temporaire.
            ++clipboardCopyGeneration;
            wipeQString(lastPassWallClipboardText);
        }
        void copyTextToClipboard(const QString &text, QWidget *parent)
        {
            if (text.isEmpty())
            {
                QMessageBox::information(
                    parent,
                    QObject::tr("Presse-papiers"),
                    QObject::tr("Il n'y a aucun texte à copier."));
                return;
            }
            QClipboard *clipboard = QGuiApplication::clipboard();
            if (clipboard == nullptr)
            {
                QMessageBox::warning(
                    parent,
                    QObject::tr("Presse-papiers"),
                    QObject::tr("Le presse-papiers est indisponible."));
                return;
            }
            // Enregistrer avant publication : setText() peut émettre
            // dataChanged et provoquer un verrouillage réentrant.
            wipeQString(lastPassWallClipboardText);
            lastPassWallClipboardText = text;
            const std::uint64_t generation = ++clipboardCopyGeneration;
            clipboard->setText(text, QClipboard::Clipboard);
            if (generation != clipboardCopyGeneration)
            {
                return;
            }
            QTimer::singleShot(
                30'000,
                QCoreApplication::instance(),
                [clipboard, generation]()
                {
                    // N'agir que si aucun autre contenu n'a été copié via PassWall.
                    if (generation != clipboardCopyGeneration)
                    {
                        return;
                    }
                if (clipboardMatchesLastPassWallText(clipboard))
                    {
                        clipboard->clear(QClipboard::Clipboard);
                    }
                    // Même si l'utilisateur a remplacé le contenu, effacer notre copie.
                    wipeQString(lastPassWallClipboardText);
                });
        }
        bool editCredentialDialog(
            QWidget *parent,
            models::Credential &credential,
            CredentialEditorContext &editorContext)
        {
            QDialog dialog(parent);
            dialog.setObjectName(QStringLiteral("credentialEditorDialog"));
            dialog.setWindowTitle(
                credential.title.empty()
                    ? QObject::tr("Nouvel identifiant")
                    : QObject::tr("Modifier l'identifiant"));
            dialog.setMinimumWidth(650);
            auto *layout = new QVBoxLayout(&dialog);
            auto *form = new QFormLayout();
            auto *titleEdit = new QLineEdit(&dialog);
            auto *urlEdit = new QLineEdit(&dialog);
            auto *usernameEdit = new QLineEdit(&dialog);
            auto *passwordEdit = new QLineEdit(&dialog);
            auto *notesEdit = new QTextEdit(&dialog);
            titleEdit->setObjectName(QStringLiteral("credentialTitleEdit"));
            urlEdit->setObjectName(QStringLiteral("credentialUrlEdit"));
            usernameEdit->setObjectName(QStringLiteral("credentialUsernameEdit"));
            passwordEdit->setObjectName(QStringLiteral("credentialPasswordEdit"));
            notesEdit->setObjectName(QStringLiteral("credentialNotesEdit"));
            // Déclaré après les widgets : le nettoyeur s'exécute avant que
            // la boîte de dialogue et ses champs ne soient détruits.
            DialogFieldCleanup fieldCleanup{
                titleEdit, urlEdit, usernameEdit, passwordEdit, notesEdit};
            editorContext.bindDialog(
                dialog, *titleEdit, *urlEdit, *usernameEdit, *passwordEdit, *notesEdit);
            passwordEdit->setEchoMode(QLineEdit::Password);
            passwordEdit->setPlaceholderText(
                QObject::tr("Mot de passe"));
            notesEdit->setMinimumHeight(90);
            setEditText(titleEdit, credential.title);
            setEditText(urlEdit, credential.url);
            setEditText(usernameEdit, credential.username);
            setEditText(passwordEdit, credential.password);
            notesEdit->setPlainText(fromUtf8(credential.notes));
            // Ligne du nom d'utilisateur et bouton de copie.
            auto *usernameRow = new QWidget(&dialog);
            auto *usernameRowLayout = new QHBoxLayout(usernameRow);
            usernameRowLayout->setContentsMargins(0, 0, 0, 0);
            usernameRowLayout->setSpacing(6);
            auto *copyUsernameButton =
                new QPushButton(QObject::tr("Copier"), usernameRow);
            usernameRowLayout->addWidget(usernameEdit, 1);
            usernameRowLayout->addWidget(copyUsernameButton);
            QObject::connect(
                copyUsernameButton,
                &QPushButton::clicked,
                &dialog,
                [&dialog, &editorContext, usernameEdit]()
                {
                    if (editorContext.isInvalidated())
                        return;
                    copyTextToClipboard(usernameEdit->text(), &dialog);
                });
            // Ligne du mot de passe.
            auto *passwordRow = new QWidget(&dialog);
            auto *passwordRowLayout = new QHBoxLayout(passwordRow);
            passwordRowLayout->setContentsMargins(0, 0, 0, 0);
            passwordRowLayout->setSpacing(6);
            auto *visibilityButton =
                new QPushButton(QObject::tr("Afficher"), passwordRow);
            auto *copyPasswordButton =
                new QPushButton(QObject::tr("Copier"), passwordRow);
            copyPasswordButton->setObjectName(
                QStringLiteral("credentialCopyPasswordButton"));
            passwordRowLayout->addWidget(passwordEdit, 1);
            passwordRowLayout->addWidget(visibilityButton);
            passwordRowLayout->addWidget(copyPasswordButton);
            QObject::connect(
                visibilityButton,
                &QPushButton::clicked,
                &dialog,
                [&editorContext, passwordEdit, visibilityButton]()
                {
                    if (editorContext.isInvalidated())
                        return;
                    const bool isHidden =
                        passwordEdit->echoMode() == QLineEdit::Password;
                    passwordEdit->setEchoMode(
                        isHidden ? QLineEdit::Normal : QLineEdit::Password);
                    visibilityButton->setText(
                        isHidden
                            ? QObject::tr("Masquer")
                            : QObject::tr("Afficher"));
                });
            QObject::connect(
                copyPasswordButton,
                &QPushButton::clicked,
                &dialog,
                [&dialog, &editorContext, passwordEdit]()
                {
                    if (editorContext.isInvalidated())
                        return;
                    copyTextToClipboard(passwordEdit->text(), &dialog);
                });
            // Options du générateur de mots de passe.
            auto *lengthSpin = new QSpinBox(&dialog);
            lengthSpin->setRange(8, 128);
            lengthSpin->setValue(20);
            auto *lowercaseCheck =
                new QCheckBox(QObject::tr("Minuscules"), &dialog);
            auto *uppercaseCheck =
                new QCheckBox(QObject::tr("Majuscules"), &dialog);
            auto *digitsCheck =
                new QCheckBox(QObject::tr("Chiffres"), &dialog);
            auto *symbolsCheck =
                new QCheckBox(QObject::tr("Symboles"), &dialog);
            lowercaseCheck->setChecked(true);
            uppercaseCheck->setChecked(true);
            digitsCheck->setChecked(true);
            symbolsCheck->setChecked(true);
            auto *characterTypes = new QHBoxLayout();
            characterTypes->addWidget(lowercaseCheck);
            characterTypes->addWidget(uppercaseCheck);
            characterTypes->addWidget(digitsCheck);
            characterTypes->addWidget(symbolsCheck);
            auto *generateButton =
                new QPushButton(QObject::tr("Générer"), &dialog);
            generateButton->setObjectName(
                QStringLiteral("credentialGeneratePasswordButton"));
            QObject::connect(
                generateButton,
                &QPushButton::clicked,
                &dialog,
                [&dialog,
                 &editorContext,
                 lengthSpin,
                 lowercaseCheck,
                 uppercaseCheck,
                 digitsCheck,
                 symbolsCheck,
                 passwordEdit]()
                {
                    if (editorContext.isInvalidated())
                        return;
                    core::PasswordOptions options;
                    options.length =
                        static_cast<std::size_t>(lengthSpin->value());
                    options.lowercase = lowercaseCheck->isChecked();
                    options.uppercase = uppercaseCheck->isChecked();
                    options.digits = digitsCheck->isChecked();
                    options.symbols = symbolsCheck->isChecked();
                    std::string generatedPassword;
                    std::string error;
                    const bool success =
                        core::PasswordGenerator::generate(
                            options,
                            generatedPassword,
                            error);
                    if (!success)
                    {
                        QMessageBox::warning(
                            &dialog,
                            QObject::tr("Générateur de mots de passe"),
                            QString::fromStdString(error));
                        return;
                    }
                    QString generatedText = QString::fromLatin1(
                        generatedPassword.data(),
                        static_cast<qsizetype>(generatedPassword.size()));

                    passwordEdit->setText(generatedText);

                    wipeQString(generatedText);
                    wipeString(generatedPassword);
                });
            // Construction du formulaire.
            form->addRow(QObject::tr("Titre"), titleEdit);
            form->addRow(QObject::tr("URL"), urlEdit);
            form->addRow(QObject::tr("Nom d'utilisateur"), usernameRow);
            form->addRow(QObject::tr("Mot de passe"), passwordRow);
            form->addRow(QObject::tr("Longueur du mot de passe"), lengthSpin);
            form->addRow(QObject::tr("Types de caractères"), characterTypes);
            form->addRow(QString(), generateButton);
            form->addRow(QObject::tr("Notes"), notesEdit);
            layout->addLayout(form);
            auto *buttons = new QDialogButtonBox(
                QDialogButtonBox::Save | QDialogButtonBox::Cancel,
                &dialog);
            QObject::connect(
                buttons,
                &QDialogButtonBox::accepted,
                &dialog,
                [&dialog, &editorContext]()
                {
                    if (!editorContext.isInvalidated())
                        dialog.accept();
                });
            QObject::connect(
                buttons,
                &QDialogButtonBox::rejected,
                &dialog,
                &QDialog::reject);
            layout->addWidget(buttons);
            if (editorContext.isInvalidated() ||
                dialog.exec() != QDialog::Accepted ||
                editorContext.isInvalidated())
            {
                return false;
            }
            assignEditText(titleEdit, credential.title);
            assignEditText(urlEdit, credential.url);
            assignEditText(usernameEdit, credential.username);
            assignEditText(passwordEdit, credential.password);
            QString notesText = notesEdit->toPlainText();
            QByteArray notesUtf8 = notesText.toUtf8();

            credential.notes.assign(
                notesUtf8.constData(),
                static_cast<std::size_t>(notesUtf8.size()));

            if (!notesUtf8.isEmpty())
            {
                sodium_memzero(
                    notesUtf8.data(),
                    static_cast<std::size_t>(notesUtf8.size()));
            }

            notesUtf8.clear();
            wipeQString(notesText);
            std::string error;
            if (!services::CredentialService::validate(credential, error))
            {
                // Ne pas conserver les champs ni le credential pendant la
                // notification modale. Les nettoyeurs RAII restent actifs.
                editorContext.invalidate();
                QMessageBox::warning(parent, QObject::tr("PassWall"),
                    QString::fromStdString(error));
                return false;
            }
            return true;
        }
    } // namespace
    MainWindow::MainWindow(QWidget *parent)
        : QMainWindow(parent),
          inactivityTimer_(this),
          ui_(new Ui::MainWindow)
    {
        ui_->setupUi(this);
#ifdef Q_OS_LINUX
        automaticBackup_ = new services::AutomaticBackupCoordinator(this);
        automaticBackup_->setPaused(true);
        connect(automaticBackup_, &services::AutomaticBackupCoordinator::notification, this,
            [this](const QString&, const QString& message) {
                auto* notice = new QMessageBox(QMessageBox::Warning, tr("Sauvegarde automatique"),
                    message, QMessageBox::Ok, this);
                notice->setObjectName(QStringLiteral("automaticBackupWarning"));
                notice->setTextFormat(Qt::PlainText);
                notice->setAttribute(Qt::WA_DeleteOnClose);
                notice->setModal(false); notice->show();
            });
        connect(automaticBackup_, &services::AutomaticBackupCoordinator::closeReady,
            this, &MainWindow::queueExportClose);
        connect(automaticBackup_, &services::AutomaticBackupCoordinator::activityChanged,
            this, [this](bool) { updateExportAction(); });
#endif
        inactivityTimer_.setObjectName(QStringLiteral("vaultInactivityTimer"));
        // Charger le délai de verrouillage automatique.
        QSettings settings("PassWall", "PassWall");
        autoLockMinutes_ =
            settings.value("security/autoLockMinutes", 5).toInt();
        const QList<int> allowedMinutes = {0, 1, 5, 10, 15, 30};
        if (!allowedMinutes.contains(autoLockMinutes_))
        {
            autoLockMinutes_ = 5;
        }
        if (autoLockMinutes_ > 0)
        {
            inactivityTimer_.setInterval(autoLockMinutes_ * 60 * 1000);
        }
        connect(
            &inactivityTimer_,
            &QTimer::timeout,
            this,
            [this]()
            {
                // Le verrouillage nettoie les éditeurs synchroniquement.
                // Aucune notification modale ne retarde ensuite leur dépilement.
                lockVault();
            });
        // Observer l'activité clavier et souris dans l'application.
        qApp->installEventFilter(this);
        // Ajouter le réglage au menu de l'application.
        QMenu *securityMenu = menuBar()->addMenu(tr("Sécurité"));
        QAction *autoLockAction =
            securityMenu->addAction(
                tr("Délai de verrouillage automatique..."));
        connect(
            autoLockAction,
            &QAction::triggered,
            this,
            [this]()
            {
                const QStringList options = {
                    tr("Désactivé"),
                    tr("1 minute"),
                    tr("5 minutes"),
                    tr("10 minutes"),
                    tr("15 minutes"),
                    tr("30 minutes")};
                QString currentOption = tr("Désactivé");
                if (autoLockMinutes_ > 0)
                {
                    currentOption = tr("%1 minute%2")
                                        .arg(autoLockMinutes_)
                                        .arg(autoLockMinutes_ == 1 ? "" : "s");
                }
                const int currentIndex =
                    options.indexOf(currentOption);
                bool accepted = false;
                const QString selected = QInputDialog::getItem(
                    this,
                    tr("Verrouillage automatique"),
                    tr("Verrouiller le coffre après :"),
                    options,
                    currentIndex >= 0 ? currentIndex : 2,
                    false,
                    &accepted);
                if (!accepted)
                {
                    return;
                }
                int minutes = 0;
                if (selected != tr("Désactivé"))
                {
                    minutes = selected.section(' ', 0, 0).toInt();
                }
                autoLockMinutes_ = minutes;
                updateInactivityTimer();
                persistUiPreference(
                    "security/autoLockMinutes",
                    autoLockMinutes_);
            });
        ui_->stackedWidget->setCurrentWidget(ui_->pageWelcome);
        // Restaurer le dernier chemin de coffre utilisé.
        ui_->unlockPathEdit->setText(settings.value("vault/lastPath").toString());
        connect(ui_->createPageButton, &QPushButton::clicked,
                this, [this]
                { ui_->stackedWidget->setCurrentWidget(ui_->pageCreate); });
        connect(ui_->openPageButton, &QPushButton::clicked,
                this, [this]
                { ui_->stackedWidget->setCurrentWidget(ui_->pageUnlock); });
        connect(ui_->createBackButton, &QPushButton::clicked,
                this, [this]
                {
        clearPasswordFields();
        ui_->stackedWidget->setCurrentWidget(ui_->pageWelcome); });
        connect(ui_->unlockBackButton, &QPushButton::clicked,
                this, [this]
                {
        clearPasswordFields();
        ui_->stackedWidget->setCurrentWidget(ui_->pageWelcome); });
        connect(ui_->createBrowseButton, &QPushButton::clicked,
                this, &MainWindow::chooseCreatePath);
        connect(ui_->unlockBrowseButton, &QPushButton::clicked,
                this, &MainWindow::chooseUnlockPath);
        connect(ui_->createVaultButton, &QPushButton::clicked,
                this, &MainWindow::createVault);
        connect(ui_->unlockVaultButton, &QPushButton::clicked,
                this, &MainWindow::unlockVault);
        connect(ui_->lockVaultButton, &QPushButton::clicked,
                this, [this] { lockVault(); });
#ifdef Q_OS_LINUX
        connect(ui_->exportVaultButton, &QPushButton::clicked,
                this, &MainWindow::exportVault);
#else
        ui_->exportVaultButton->hide(); // Snapshot backend currently Linux only.
#endif
        connect(ui_->credentialSearchEdit, &QLineEdit::textChanged,
                this, &MainWindow::filterCredentials);
        connect(ui_->addCredentialButton, &QPushButton::clicked,
                this, &MainWindow::addCredential);
        connect(ui_->editCredentialButton, &QPushButton::clicked,
                this, &MainWindow::editCredential);
        connect(ui_->deleteCredentialButton, &QPushButton::clicked,
                this, &MainWindow::deleteCredential);
        connect(ui_->credentialsList, &QListWidget::itemDoubleClicked,
                this, [this](QListWidgetItem *)
                { editCredential(); });
        setLifecycleProtectionAvailable(lifecycleProtectionAvailable_);
    }
    MainWindow::~MainWindow()
    {
        services::VaultReplacementAuthorization::revoke(replacement_.lock());
#ifdef Q_OS_LINUX
        if (automaticBackup_) automaticBackup_->shutdown();
        exportCloseRequested_ = true;
        if (backupJob_)
        {
            disconnect(backupJob_, nullptr, this, nullptr);
            backupJob_->cancel(); // No wait, even outside a normal closeEvent.
        }
        delete exportDialog_.data();
#endif
        externalLockClosing_ = true;
        const auto pending = std::exchange(externalLockRequests_, {});
        for (const auto& completion : pending)
        {
            try { completion(false); }
            catch (...) { /* No successful acknowledgement while closing. */ }
        }
        lockVault();
        delete ui_;
    }
    bool MainWindow::externalLockBlocksAccess() const noexcept
    {
#ifdef Q_OS_LINUX
        if (exportCloseRequested_)
            return true;
#endif
        return replacementTransition_ || services::VaultReplacementAuthorization::active(replacement_.lock()) ||
            externalLockClosing_ || externalLockFailed_ ||
            externalLockReplyInProgress_ || !externalLockRequests_.empty();
    }
    void MainWindow::requestExternalLock(std::function<void(bool)> completion)
    {
        requestLock(std::move(completion), LockReason::Security);
    }
    void MainWindow::requestLock(std::function<void(bool)> completion, LockReason reason)
    {
        if (!isSessionThread())
            qFatal("External locking must run on the vault owner's thread");
        // Reentry must revoke BEFORE joining an already-running cleanup.
        if (reason == LockReason::Security)
            services::VaultReplacementAuthorization::revoke(replacement_.lock());
        if (!completion)
            return;
        if (externalLockClosing_ || externalLockFailed_)
        {
            completion(false);
            return;
        }
        externalLockRequests_.push_back(std::move(completion));
        if (vaultLockInProgress_ || externalLockReplyInProgress_)
            return; // The outer operation schedules completion, never this reentry.
        try { lockVault(reason); }
        catch (...)
        {
            externalLockFailed_ = true;
            scheduleExternalLockCompletion();
        }
    }
    void MainWindow::scheduleExternalLockCompletion()
    {
        if (externalLockRequests_.empty() || externalLockCompletionQueued_ || externalLockClosing_)
            return;
        externalLockCompletionQueued_ = true;
        QMetaObject::invokeMethod(this, [this] { completeExternalLockRequests(); }, Qt::QueuedConnection);
    }
    bool MainWindow::isFullyLocked() const
    {
        if (vaultLockInProgress_ || !dataKey_.empty() || !vaultPath_.isEmpty() ||
            !credentialSummaries_.empty() || inactivityTimer_.isActive() || !ui_ ||
            !ui_->createPasswordEdit->text().isEmpty() ||
            !ui_->confirmPasswordEdit->text().isEmpty() ||
            !ui_->unlockPasswordEdit->text().isEmpty() ||
            !ui_->credentialSearchEdit->text().isEmpty() ||
            ui_->credentialsList->count() != 0 || !lastPassWallClipboardText.isEmpty())
            return false;
        for (auto* field : findChildren<QLineEdit*>())
        {
            if (field->objectName().startsWith(QStringLiteral("credential")) &&
                !field->text().isEmpty())
                return false;
        }
        for (auto* field : findChildren<QTextEdit*>())
        {
            if (field->objectName() == QStringLiteral("credentialNotesEdit") &&
                !field->document()->isEmpty())
                return false;
        }
        return true;
    }
    void MainWindow::completeExternalLockRequests()
    {
        externalLockCompletionQueued_ = false;
        if (vaultLockInProgress_ || externalLockReplyInProgress_)
            return; // A nested event loop must wait for its outer operation.
        const QPointer<MainWindow> guarded(this);
        externalLockReplyInProgress_ = true;
        const auto replying = qScopeGuard([guarded] {
            if (guarded)
            {
                guarded->externalLockReplyInProgress_ = false;
                guarded->scheduleExternalLockCompletion();
#ifdef Q_OS_LINUX
                guarded->updateExportAction();
#endif
            }
        });
        const auto pending = std::exchange(externalLockRequests_, {});
        for (const auto& completion : pending)
        {
            bool cleaned = false;
            if (guarded)
            {
                try { cleaned = !guarded->externalLockFailed_ && !guarded->externalLockClosing_ && guarded->isFullyLocked(); }
                catch (...) { guarded->externalLockFailed_ = true; }
                if (!cleaned)
                    guarded->externalLockFailed_ = true;
            }
            try { completion(cleaned); }
            catch (...) { /* Never escape into the Qt event dispatcher. */ }
        }
    }
    bool MainWindow::isSessionThread() const noexcept
    {
        return QThread::currentThread() == thread();
    }
    void MainWindow::setLifecycleProtectionValidator(
        std::function<bool()> check, std::function<void()> invalidate)
    {
        if (!isSessionThread())
            qFatal("Lifecycle validation must run on the vault owner's thread");
        setLifecycleProtectionAvailable(false);
        lifecycleValidator_ = std::make_shared<const LifecycleProtectionValidator>(
            LifecycleProtectionValidator{std::move(check), std::move(invalidate)});
    }
    bool MainWindow::hasLifecycleProtection() const noexcept
    {
        if (!isSessionThread() || !lifecycleProtectionAvailable_)
            return false;
        const auto validator = lifecycleValidator_;
        if (!validator)
        {
#ifdef Q_OS_LINUX
            return false;
#else
            return true;
#endif
        }
        try
        {
            return validator->check && validator->invalidate && validator->check() &&
                lifecycleProtectionAvailable_ && lifecycleValidator_ == validator;
        }
        catch (...)
        {
            return false;
        }
    }
    bool MainWindow::ensureLifecycleProtection()
    {
        if (hasLifecycleProtection())
            return true;
        const auto validator = lifecycleValidator_;
        if (lifecycleProtectionAvailable_ && validator && validator->invalidate)
        {
            try { validator->invalidate(); }
            catch (...) { /* Local fail-closed cleanup is still required. */ }
        }
        if (lifecycleProtectionAvailable_ || !vaultPath_.isEmpty() || !dataKey_.empty())
            setLifecycleProtectionAvailable(false);
        return false;
    }
    void MainWindow::setLifecycleProtectionAvailable(bool available)
    {
        // The monitor must not receive an acknowledgement before cleanup on
        // this object's thread. A queued cross-thread lock would be unsafe.
        if (!isSessionThread())
            qFatal("Lifecycle protection must run on the vault owner's thread");
        lifecycleProtectionAvailable_ = available;
        if (!available)
        {
            lifecycleLockPending_ = true;
            lockVault();
        }
        updateSessionAccessUi();
    }
    void MainWindow::updateSessionAccessUi()
    {
        const bool available = lifecycleProtectionAvailable_;
        ui_->createPageButton->setEnabled(available);
        ui_->openPageButton->setEnabled(available);
        ui_->createVaultButton->setEnabled(available);
        ui_->unlockVaultButton->setEnabled(available);
        ui_->createPasswordEdit->setEnabled(available);
        ui_->confirmPasswordEdit->setEnabled(available);
        ui_->unlockPasswordEdit->setEnabled(available);
        if (available)
            statusBar()->clearMessage();
        else
            statusBar()->showMessage(tr("Coffre verrouillé : protection système indisponible ou transition en cours."));
#ifdef Q_OS_LINUX
        updateExportAction();
#endif
    }
    bool MainWindow::advanceSessionGeneration() noexcept
    {
        if (sessionGenerationExhausted_ ||
            sessionGeneration_ ==
            std::numeric_limits<std::uint64_t>::max())
        {
            // Ne jamais réutiliser une génération après débordement : la
            // valeur invalide force toutes les opérations Native à échouer.
            sessionGenerationExhausted_ = true;
            sessionGeneration_ = 0;
            return false;
        }

        ++sessionGeneration_;
        return sessionGeneration_ != 0;
    }
    void MainWindow::updateInactivityTimer()
    {
        if (!ensureLifecycleProtection() || autoLockMinutes_ <= 0 || vaultLockInProgress_ ||
            vaultPath_.isEmpty() || dataKey_.empty() || sessionGeneration_ == 0)
        {
            inactivityTimer_.stop();
            return;
        }
        inactivityTimer_.start(autoLockMinutes_ * 60 * 1000);
        // Échec fermé si Qt refuse d'enregistrer le timer demandé.
        if (!inactivityTimer_.isActive())
            lockVault();
    }
    bool MainWindow::beginUnlockedSession() noexcept
    {
        if (externalLockBlocksAccess())
        {
            lockVault();
            return false;
        }
        if (vaultLockInProgress_ || !ensureLifecycleProtection())
        {
            lockVault();
            return false;
        }
        if (advanceSessionGeneration())
        {
            const native::VaultLease lease{true, sessionGeneration_};
            // Armer avant tout callback Native ou changement de page Qt :
            // une boucle modale ne doit pas publier une session sans protection.
            // Le choix explicite « Désactivé » reste toutefois respecté.
            updateInactivityTimer();
            if (!isLeaseCurrent(lease))
            {
                (void)ensureLifecycleProtection();
                return false;
            }
            native::NativeBridgeServer::invalidateCurrentSession(
                lease.generation);
            if (!isLeaseCurrent(lease))
            {
                (void)ensureLifecycleProtection();
                return false;
            }
            return true;
        }

        // Échec fermé : une nouvelle session ne doit pas exister si nous ne
        // pouvons plus lui attribuer une génération unique.
        lockVault();
        return false;
    }
    void MainWindow::clearSummaryOutput(
        std::vector<models::CredentialSummary> &output) noexcept
    {
        for (auto &summary : output)
        {
            wipeCredentialSummary(summary);
        }
        output.clear();
    }
    native::VaultAccessResult MainWindow::leaseFailureResult(
        const native::VaultLease &lease) const noexcept
    {
        if (!isSessionThread())
        {
            return native::VaultAccessResult::Failed;
        }

        if (!hasLifecycleProtection() || vaultLockInProgress_ || externalLockBlocksAccess() || vaultPath_.isEmpty() || dataKey_.empty() ||
            !recoveryAllowsCurrentSession() ||
            sessionGeneration_ == 0)
        {
            return native::VaultAccessResult::Locked;
        }

        if (!lease.unlocked || lease.generation == 0 ||
            lease.generation != sessionGeneration_)
        {
            return native::VaultAccessResult::SessionChanged;
        }

        return native::VaultAccessResult::Success;
    }
    native::VaultLease MainWindow::acquireLease() const noexcept
    {
        if (!hasLifecycleProtection() || vaultLockInProgress_ || externalLockBlocksAccess() ||
            vaultPath_.isEmpty() || dataKey_.empty() ||
            !recoveryAllowsCurrentSession() ||
            sessionGeneration_ == 0)
        {
            return {};
        }

        return {true, sessionGeneration_};
    }
    bool MainWindow::isLeaseCurrent(
        const native::VaultLease &lease) const noexcept
    {
        return leaseFailureResult(lease) ==
            native::VaultAccessResult::Success;
    }
    native::VaultAccessResult MainWindow::copySummaries(
        const native::VaultLease &lease,
        std::vector<models::CredentialSummary> &output)
    {
        clearSummaryOutput(output);

        const native::VaultAccessResult initialStatus =
            leaseFailureResult(lease);
        if (initialStatus != native::VaultAccessResult::Success)
        {
            return initialStatus;
        }

        try
        {
            output = credentialSummaries_;
        }
        catch (...)
        {
            clearSummaryOutput(output);
            return native::VaultAccessResult::Failed;
        }

        const native::VaultAccessResult finalStatus =
            leaseFailureResult(lease);
        if (finalStatus != native::VaultAccessResult::Success)
        {
            clearSummaryOutput(output);
            return finalStatus;
        }

        return native::VaultAccessResult::Success;
    }
    native::VaultAccessResult MainWindow::loadCredential(
        const native::VaultLease &lease,
        const models::EntryId &entryId,
        models::Credential &output)
    {
        wipeCredential(output);

        const native::VaultAccessResult initialStatus =
            leaseFailureResult(lease);
        if (initialStatus != native::VaultAccessResult::Success)
        {
            return initialStatus;
        }

        const std::string vaultPath = vaultPath_.toStdString();
        std::string error;
        if (!services::CredentialService::get(
                vaultPath, dataKey_, entryId, output, error))
        {
            wipeCredential(output);
            return native::VaultAccessResult::Failed;
        }

        const native::VaultAccessResult finalStatus =
            leaseFailureResult(lease);
        if (finalStatus != native::VaultAccessResult::Success)
        {
            wipeCredential(output);
            return finalStatus;
        }

        return native::VaultAccessResult::Success;
    }
    void MainWindow::chooseCreatePath()
    {
        const QString path = QFileDialog::getSaveFileName(
            this,
            tr("Créer un coffre PassWall"),
            QStringLiteral("PassWall.pwdb"),
            tr("Coffres PassWall (*.pwdb);;Tous les fichiers (*)"));
        if (!path.isEmpty())
        {
            ui_->createPathEdit->setText(path);
        }
    }
    void MainWindow::chooseUnlockPath()
    {
        const QString previousPath =
            ui_->unlockPathEdit->text().trimmed();
        const QString path = QFileDialog::getOpenFileName(
            this,
            tr("Ouvrir un coffre PassWall"),
            previousPath,
            tr("Coffres PassWall (*.pwdb);;Tous les fichiers (*)"));
        if (!path.isEmpty())
        {
            ui_->unlockPathEdit->setText(path);
            // Mémoriser le chemin choisi.
            persistUiPreference("vault/lastPath", path);
        }
    }
    void MainWindow::createVault()
    {
        if (externalLockBlocksAccess())
            return;
        if (vaultLockInProgress_ || !ensureLifecycleProtection())
            return;
        const QString path = ui_->createPathEdit->text().trimmed();
        if (path.isEmpty())
        {
            showError(tr("Choisis un emplacement pour le coffre."));
            return;
        }

        bool success = false;
        QString failureMessage;
        try
        {
            std::string password;
            const auto passwordCleanup = qScopeGuard([&]() noexcept {
                wipeString(password);
            });
            std::string confirmation;
            const auto confirmationCleanup = qScopeGuard([&]() noexcept {
                wipeString(confirmation);
            });
            takePassword(ui_->createPasswordEdit, password);
            takePassword(ui_->confirmPasswordEdit, confirmation);

            if (password.empty())
                failureMessage = tr("Le mot de passe maître est obligatoire.");
            else if (password != confirmation)
                failureMessage = tr("Les deux mots de passe ne correspondent pas.");
            else
            {
                wipeString(confirmation);
                std::string error;
                const auto failedKeyCleanup = qScopeGuard([&]() noexcept {
                    if (!success)
                        dataKey_ = core::SecureBuffer(0);
                });
                success = services::VaultLifecycleService::createVault(
                    path.toStdString(), password, dataKey_, error);
                wipeString(password);
                if (!success)
                    failureMessage = QString::fromStdString(error);
            }
        }
        catch (...)
        {
            // Les buffers locaux ont déjà été nettoyés par déroulement de
            // pile. Ne pas exposer what(), ni conserver une clé partielle.
            success = false;
            dataKey_ = core::SecureBuffer(0);
            clearPasswordFields();
            failureMessage = tr("Impossible de créer le coffre : erreur inattendue.");
        }
        if (!success)
        {
            // Aucun mot de passe local vivant pendant cette boucle modale.
            showError(failureMessage);
            return;
        }
        vaultPath_ = path;
        if (!beginUnlockedSession())
        {
            showError(tr("Impossible d'initialiser une nouvelle session de coffre."));
            return;
        }
        registerAuthenticatedVault(path);
        showUnlockedVault();
    }
    void MainWindow::unlockVault()
    {
        if (externalLockBlocksAccess())
            return;
        if (vaultLockInProgress_ || !ensureLifecycleProtection())
            return;
        const QString path = ui_->unlockPathEdit->text().trimmed();
        if (path.isEmpty())
        {
            showError(tr("Choisis le fichier du coffre à ouvrir."));
            return;
        }
        bool success = false;
        QString failureMessage;
        try
        {
            std::string password;
            const auto passwordCleanup = qScopeGuard([&]() noexcept {
                wipeString(password);
            });
            takePassword(ui_->unlockPasswordEdit, password);

            if (password.empty())
                failureMessage = tr("Saisis le mot de passe maître.");
            else
            {
                std::string error;
                const auto failedKeyCleanup = qScopeGuard([&]() noexcept {
                    if (!success)
                        dataKey_ = core::SecureBuffer(0);
                });
                success = services::VaultLifecycleService::unlockVault(
                    path.toStdString(), password, dataKey_, error);
                wipeString(password);
                if (!success)
                    failureMessage = QString::fromStdString(error);
            }
        }
        catch (...)
        {
            success = false;
            dataKey_ = core::SecureBuffer(0);
            clearPasswordFields();
            failureMessage = tr("Impossible d'ouvrir le coffre : erreur inattendue.");
        }
        if (!success)
        {
            showError(failureMessage);
            return;
        }
        vaultPath_ = path;
        if (!beginUnlockedSession())
        {
            showError(tr("Impossible d'initialiser une nouvelle session de coffre."));
            return;
        }
        registerAuthenticatedVault(path);
        showUnlockedVault();
    }
    void MainWindow::registerAuthenticatedVault(const QString& path)
    {
        // Called only after successful authentication, password cleanup and
        // beginUnlockedSession() (which already arms the inactivity timer).
        // Configuration and SQLite publication are NOT one transaction.
        QString error;
        try
        {
            services::VaultPreferencesStore store;
            services::VaultRegistration registration;
            const auto result = store.recognizeOrRegister(
                QFileInfo(path).absoluteFilePath(), registration, error);
            if (result == services::VaultRecognition::Registered
                || result == services::VaultRecognition::Recognized)
            {
#ifdef Q_OS_LINUX
                automaticBackup_->trackVault(registration);
#endif
                persistUiPreference("vault/lastPath", path);
                return;
            }
        }
        catch (...)
        {
            error = tr("Erreur inattendue pendant l'enregistrement local du coffre.");
        }
        // No modal loop and no rollback/deletion of a successfully created vault.
        // No preferences are applied when recognition/persistence failed.
        auto* notice = new QMessageBox(QMessageBox::Warning,
            tr("Configuration du coffre non enregistrée"),
            tr("Le coffre reste utilisable, mais son enregistrement local n'est pas confirmé.\n%1")
                .arg(error), QMessageBox::Ok, this);
        notice->setObjectName(QStringLiteral("vaultRegistrationWarning"));
        notice->setAttribute(Qt::WA_DeleteOnClose);
        notice->setModal(false);
        notice->show();
    }
    void MainWindow::persistUiPreference(const QString& key, const QVariant& value)
    {
        // Legacy UI settings share the registry's file. A pending setValue()
        // must not silently rewrite a malformed INI before registry validation.
        try
        {
            services::VaultPreferencesStore store;
            QVector<services::VaultRegistration> records;
            QString error;
            if (store.list(records, error))
            {
                QSettings settings("PassWall", "PassWall");
                settings.setFallbacksEnabled(false);
                settings.setAtomicSyncRequired(true);
                settings.sync();
                (void)settings.allKeys();
                if (settings.status() == QSettings::NoError)
                {
                    settings.setValue(key, value);
                    settings.sync();
                    if (settings.status() == QSettings::NoError)
                        return;
                }
            }
        }
        catch (...) {}
        // Nonmodal; runtime inactivity policy still applies even if saving it
        // fails. Do not include values/paths in diagnostics.
        statusBar()->showMessage(tr("Préférences non enregistrées : configuration illisible, occupée ou inaccessible."));
    }
    void MainWindow::showUnlockedVault()
    {
        const auto protectionCleanup = qScopeGuard([this]() {
            (void)ensureLifecycleProtection();
        });
        const native::VaultLease lease = acquireLease();
        if (!lease.unlocked)
            return;
        ui_->stackedWidget->setCurrentWidget(ui_->pageVault);
        // setCurrentWidget() peut déclencher du code réentrant. Ne pas
        // rafraîchir une autre session, ni réarmer un timer arrêté au verrouillage.
        if (!isLeaseCurrent(lease))
            return;
#ifdef Q_OS_LINUX
        updateExportAction();
#endif
        refreshCredentials();
    }
    void MainWindow::activateFromNativeRequest()
    {
        // Si le coffre est verrouillé, afficher l'écran de déverrouillage.
        if (vaultPath_.isEmpty() || dataKey_.empty())
        {
            ui_->stackedWidget->setCurrentWidget(ui_->pageUnlock);
            ui_->unlockPasswordEdit->setFocus();
        }
        // Restaurer la fenêtre si elle était minimisée.
        showNormal();
        raise();
        activateWindow();
    }
    native::NativeRequestResponse MainWindow::handleNativeRequest(
        const QJsonObject &request)
    {
        (void)ensureLifecycleProtection();
        native::NativeRequestProcessor processor(*this);
        native::NativeRequestResponse response = processor.handle(request);
        if (!hasLifecycleProtection())
        {
            // Processor locals are already wiped. Wipe its response BEFORE
            // revocation can acknowledge cleanup and release the inhibitor.
            response.wipePayload();
            (void)ensureLifecycleProtection();
            response = processor.handle(request); // now a locked-vault response
        }

        // Le processeur ne dépend pas des widgets. L'activation reste donc
        // ici et est réalisée avant que le bridge prenne possession du buffer.
        if (response.requestVaultActivation)
        {
            activateFromNativeRequest();
            // MainWindow owns the activation workflow. Do not ask the bridge
            // to activate the window a second time after returning.
            response.requestVaultActivation = false;
        }

        return response;
    }
    bool MainWindow::eventFilter(QObject *watched, QEvent *event)
    {
        if (inactivityTimer_.isActive())
        {
            switch (event->type())
            {
            case QEvent::MouseMove:
            case QEvent::MouseButtonPress:
            case QEvent::KeyPress:
            case QEvent::Wheel:
            case QEvent::TouchBegin:
            case QEvent::TabletPress:
                inactivityTimer_.start();
                break;
            default:
                break;
            }
        }
        return QMainWindow::eventFilter(watched, event);
    }
    bool MainWindow::refreshCredentials()
    {
        const auto protectionCleanup = qScopeGuard([this]() {
            (void)ensureLifecycleProtection();
        });
        const native::VaultLease lease = acquireLease();
        if (!lease.unlocked)
            return false;
        std::vector<models::CredentialSummary> loaded;
        const auto cleanup = qScopeGuard([&loaded]() { clearSummaryOutput(loaded); });
        std::string error;
        const bool success = services::CredentialService::listSummaries(
            vaultPath_.toStdString(), dataKey_, loaded, error);
        if (!isLeaseCurrent(lease))
            return false;
        if (!success)
        {
            clearSummaryOutput(loaded);
            clearCredentials();
            if (ui_ != nullptr)
            {
                ui_->credentialsList->clear();
            }
            if (isLeaseCurrent(lease))
                showError(QString::fromStdString(error));
            return false;
        }
        clearCredentials();
        ui_->credentialsList->clear();
        if (!isLeaseCurrent(lease))
            return false;
        // Conserver le lot local jusqu'à la fin de l'affichage : les signaux
        // du modèle Qt peuvent vider les membres ou ouvrir une nouvelle session.
        for (const auto &summary : loaded)
        {
            QString title = fromUtf8(summary.title);
            if (title.isEmpty())
            {
                title = tr("(Sans titre)");
            }
            QString display = title;
            if (!summary.url.empty())
            {
                display += QStringLiteral("\n") + fromUtf8(summary.url);
            }
            if (!summary.username.empty())
            {
                display += QStringLiteral("\n") +
                           tr("Utilisateur : ") +
                           fromUtf8(summary.username);
            }
            auto *item = new QListWidgetItem(display);
            const QByteArray idBytes(
                reinterpret_cast<const char *>(summary.id.data()),
                static_cast<int>(summary.id.size()));
            item->setData(Qt::UserRole, idBytes);
            const QString searchable =
                title + QStringLiteral(" ") +
                fromUtf8(summary.url) + QStringLiteral(" ") +
                fromUtf8(summary.username);
            item->setData(Qt::UserRole + 1, searchable);
            ui_->credentialsList->addItem(item);
            if (!isLeaseCurrent(lease))
                return false;
        }
        credentialSummaries_ = std::move(loaded);
        filterCredentials(ui_->credentialSearchEdit->text());
        return isLeaseCurrent(lease);
    }
    void MainWindow::filterCredentials(const QString &text)
    {
        const auto protectionCleanup = qScopeGuard([this]() {
            (void)ensureLifecycleProtection();
        });
        const native::VaultLease lease = acquireLease();
        if (!lease.unlocked)
            return;
        for (int i = 0; i < ui_->credentialsList->count(); ++i)
        {
            if (!isLeaseCurrent(lease))
                return;
            auto *item = ui_->credentialsList->item(i);
            const QString searchable =
                item->data(Qt::UserRole + 1).toString();
            item->setHidden(
                !searchable.contains(text, Qt::CaseInsensitive));
        }
    }
    void MainWindow::addCredential()
    {
#ifdef Q_OS_LINUX
        const QPointer<MainWindow> autoRetryOwner(this);
        const auto retryAutomatic = qScopeGuard([autoRetryOwner] {
            if (autoRetryOwner) QTimer::singleShot(0, autoRetryOwner, [autoRetryOwner] {
                if (autoRetryOwner) { autoRetryOwner->updateExportAction(); autoRetryOwner->automaticBackup_->retryPending(); }
            });
        });
#endif
        const auto protectionCleanup = qScopeGuard([this]() {
            (void)ensureLifecycleProtection();
        });
        if (!ensureLifecycleProtection())
            return;
        storage::VaultOperationGuard editing;
        std::string accessError;
        if (!editing.tryAccess(vaultPath_.toStdString(), accessError)) {
            showError(QString::fromStdString(accessError));
            return;
        }
        models::Credential credential;
        CredentialWiper credentialWiper(credential);
        CredentialEditorContext editorContext(credential, acquireLease());
        connect(this, &MainWindow::vaultSessionInvalidated,
                &editorContext, &CredentialEditorContext::invalidate);
        connect(this, &MainWindow::vaultEditorsMustClose,
                &editorContext, &CredentialEditorContext::rejectDialog);
        if (!editorContext.canCommit(acquireLease()) ||
            !editCredentialDialog(this, credential, editorContext) ||
            !editorContext.canCommit(acquireLease()))
        {
            return;
        }
        std::string error;
        const bool success = services::CredentialService::add(
            vaultPath_.toStdString(), dataKey_, credential, error);
        wipeCredential(credential);
        if (!ensureLifecycleProtection())
            return;
        if (!success)
        {
            showError(QString::fromStdString(error));
            return;
        }
        refreshCredentials();
    }
    void MainWindow::editCredential()
    {
#ifdef Q_OS_LINUX
        const QPointer<MainWindow> autoRetryOwner(this);
        const auto retryAutomatic = qScopeGuard([autoRetryOwner] {
            if (autoRetryOwner) QTimer::singleShot(0, autoRetryOwner, [autoRetryOwner] {
                if (autoRetryOwner) { autoRetryOwner->updateExportAction(); autoRetryOwner->automaticBackup_->retryPending(); }
            });
        });
#endif
        const auto protectionCleanup = qScopeGuard([this]() {
            (void)ensureLifecycleProtection();
        });
        if (!ensureLifecycleProtection())
            return;
        storage::VaultOperationGuard editing;
        std::string accessError;
        if (!editing.tryAccess(vaultPath_.toStdString(), accessError)) {
            showError(QString::fromStdString(accessError));
            return;
        }
        auto *item = ui_->credentialsList->currentItem();
        if (item == nullptr)
        {
            showError(tr("Sélectionne d'abord un identifiant."));
            return;
        }
        const QByteArray selectedId =
            item->data(Qt::UserRole).toByteArray();
        auto it = std::find_if(
            credentialSummaries_.begin(), credentialSummaries_.end(),
            [&selectedId](const models::CredentialSummary &summary)
            {
                const QByteArray idBytes(
                    reinterpret_cast<const char *>(summary.id.data()),
                    static_cast<int>(summary.id.size()));
                return idBytes == selectedId;
            });
        if (it == credentialSummaries_.end())
        {
            showError(tr("L'identifiant sélectionné est introuvable."));
            return;
        }
        const models::EntryId entryId = it->id;
        models::Credential updated;
        CredentialWiper updatedWiper(updated);
        CredentialEditorContext editorContext(updated, acquireLease());
        connect(this, &MainWindow::vaultSessionInvalidated,
                &editorContext, &CredentialEditorContext::invalidate);
        connect(this, &MainWindow::vaultEditorsMustClose,
                &editorContext, &CredentialEditorContext::rejectDialog);
        if (!editorContext.canCommit(acquireLease()))
            return;
        std::string error;
        if (!services::CredentialService::get(
                vaultPath_.toStdString(), dataKey_, entryId, updated, error))
        {
            showError(QString::fromStdString(error));
            return;
        }
        if (!editorContext.canCommit(acquireLease()) ||
            !editCredentialDialog(this, updated, editorContext))
        {
            return;
        }
        if (!editorContext.canCommit(acquireLease()))
        {
            return;
        }
        const bool success = services::CredentialService::update(
            vaultPath_.toStdString(), dataKey_, updated, error);
        wipeCredential(updated);
        if (!ensureLifecycleProtection())
            return;
        if (!success)
        {
            showError(QString::fromStdString(error));
            return;
        }
        refreshCredentials();
    }
    void MainWindow::deleteCredential()
    {
        if (!ensureLifecycleProtection())
            return;
        auto *item = ui_->credentialsList->currentItem();
        if (item == nullptr)
        {
            showError(tr("Sélectionne d'abord un identifiant."));
            return;
        }
        const QByteArray selectedId =
            item->data(Qt::UserRole).toByteArray();
        auto it = std::find_if(
            credentialSummaries_.begin(), credentialSummaries_.end(),
            [&selectedId](const models::CredentialSummary &summary)
            {
                const QByteArray idBytes(
                    reinterpret_cast<const char *>(summary.id.data()),
                    static_cast<int>(summary.id.size()));
                return idBytes == selectedId;
            });
        if (it == credentialSummaries_.end())
        {
            showError(tr("L'identifiant sélectionné est introuvable."));
            return;
        }
        const models::EntryId entryId = it->id;
        QString title = fromUtf8(it->title);
        const auto answer = QMessageBox::question(
            this,
            tr("Supprimer l'identifiant"),
            tr("Supprimer définitivement « %1 » ?").arg(title),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        wipeQString(title);
        if (!ensureLifecycleProtection())
            return;
        if (answer != QMessageBox::Yes)
        {
            return;
        }
        if (vaultPath_.isEmpty() || dataKey_.empty())
        {
            showError(tr("Le coffre a été verrouillé."));
            return;
        }
        std::string error;
        const bool success = services::CredentialService::remove(
            vaultPath_.toStdString(), dataKey_, entryId, error);
        if (!success)
        {
            showError(QString::fromStdString(error));
            return;
        }
        refreshCredentials();
    }
    void MainWindow::lockVault(LockReason reason)
    {
        // Even a repeated/reentrant security lock revokes a pending operation.
        // The deliberate preparation lock is the only exception, never a
        // change in Control1.Lock() or system/manual/idle locking semantics.
        if (reason == LockReason::Security)
            services::VaultReplacementAuthorization::revoke(replacement_.lock());
        if (vaultLockInProgress_)
            return;
#ifdef Q_OS_LINUX
        const QString lockedSource = vaultPath_; // Non-secret, before session cleanup.
#endif
        const QScopedValueRollback<bool> locking(vaultLockInProgress_, true);
#ifdef Q_OS_LINUX
        if (automaticBackup_) automaticBackup_->setPaused(true);
#endif
        inactivityTimer_.stop();
        if (!vaultPath_.isEmpty() || !dataKey_.empty())
        {
            // Invalider les leases avant tout effacement afin qu'aucune
            // requête Native en cours ne puisse réutiliser cette session.
            static_cast<void>(advanceSessionGeneration());
            // Le bridge efface immédiatement les portions de réponses encore
            // détenues par l'application et ferme leurs connexions. Les octets
            // déjà acceptés par Qt ou le noyau ne sont pas récupérables.
            native::NativeBridgeServer::invalidateCurrentSession(
                sessionGeneration_);
        }
        vaultPath_.clear();
        dataKey_ = core::SecureBuffer(0);
        emit vaultSessionInvalidated();
        emit vaultEditorsMustClose();
        // Conserver aussi l'annulation des confirmations et réglages modaux.
        // Les QPointer protègent le parcours si un rejet détruit un autre UI.
        std::vector<QPointer<QDialog>> dialogs;
        for (QDialog *dialog : findChildren<QDialog *>())
            dialogs.emplace_back(dialog);
        for (const auto &dialog : dialogs)
        {
            if (!dialog.isNull() && dialog->isVisible())
                dialog->reject();
        }
        clearPassWallClipboardIfUnchanged();
        clearCredentials();
        clearPasswordFields();
        if (ui_ != nullptr)
        {
            ui_->credentialsList->clear();
            QString searchText = ui_->credentialSearchEdit->text();
            ui_->credentialSearchEdit->clear();
            wipeQString(searchText);
            ui_->stackedWidget->setCurrentWidget(ui_->pageWelcome);
        }
        if (lifecycleLockPending_)
        {
            lifecycleLockPending_ = false;
            emit lifecycleSecretsCleared();
        }
#ifdef Q_OS_LINUX
        updateExportAction();
#endif
        // Posting is safe while the guard is still set: even a nested loop in
        // a callback cannot acknowledge until the outer operation has returned.
        scheduleExternalLockCompletion();
#ifdef Q_OS_LINUX
        if (reason != LockReason::ReplacementPreparation && !lockedSource.isEmpty()
            && !externalLockClosing_ && !exportCloseRequested_)
            QTimer::singleShot(0, this, [this, lockedSource] {
                // This event follows external-lock completion. Coordinator I/O
                // is deferred once more; never part of the cleanup/ack stack.
                updateExportAction();
                automaticBackup_->requestForLockedVault(lockedSource);
            });
#endif
    }
    void MainWindow::clearCredentials()
    {
        for (auto &summary : credentialSummaries_)
        {
            wipeCredentialSummary(summary);
        }
        credentialSummaries_.clear();
    }
    void MainWindow::clearPasswordFields()
    {
        ui_->createPasswordEdit->clear();
        ui_->confirmPasswordEdit->clear();
        ui_->unlockPasswordEdit->clear();
    }
    void MainWindow::showError(const QString &message)
    {
        QMessageBox::warning(this, tr("PassWall"), message);
    }
} // namespace passwall::gui
