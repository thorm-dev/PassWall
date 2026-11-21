#include "services/global_backup_preferences_store.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLockFile>
#include <QSettings>
#include <QTemporaryFile>

#include <utility>

#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace passwall::services {
namespace {

constexpr auto Organization = "PassWall";
constexpr auto Application = "BackupPreferences";
constexpr auto VersionKey = "format/version";
constexpr auto RootDirectoryKey = "backup/rootDirectory";
constexpr auto RetainedVersionsKey = "backup/retainedVersions";
constexpr int FormatVersion = 1;
constexpr qint64 MaximumSettingsBytes = 64 * 1024;

GlobalBackupPreferencesResult result(
    GlobalBackupPreferencesStatus status,
    QString diagnostic = {},
    GlobalBackupPreferences preferences = {})
{
    return {status, std::move(preferences), std::move(diagnostic)};
}

bool validRootDirectory(const QString& path)
{
    if (path.isEmpty() || path.contains(QChar{}) || !QDir::isAbsolutePath(path)
        || QDir::cleanPath(path) != path || QFileInfo(path).isRoot())
        return false;

    const QFileInfo existing(path);
    return !existing.exists() || (!existing.isSymLink() && existing.isDir());
}

bool validPreferences(const GlobalBackupPreferences& preferences)
{
    return validRootDirectory(preferences.rootDirectory)
        && preferences.retainedVersions
            >= GlobalBackupPreferencesStore::MinimumRetainedVersions;
}

bool canonicalUnsigned(const QVariant& value, quint64& output)
{
    if (!value.isValid()) return false;
    const QString text = value.toString();
    bool converted = false;
    output = text.toULongLong(&converted);
    return converted && QString::number(output) == text;
}

GlobalBackupPreferencesResult parseSettings(const QByteArray& bytes)
{
    QTemporaryFile snapshot(
        QDir::temp().filePath(QStringLiteral("passwall-backup-preferences-XXXXXX.ini")));
    if (!snapshot.open()
        || snapshot.write(bytes) != bytes.size()
        || !snapshot.flush())
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Impossible de valider les préférences sans les modifier."));
    snapshot.close();

    QSettings settings(snapshot.fileName(), QSettings::IniFormat);
    settings.setFallbacksEnabled(false);
    (void)settings.allKeys();
    if (settings.status() == QSettings::AccessError)
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Lecture des préférences globales impossible."));
    if (settings.status() != QSettings::NoError)
        return result(GlobalBackupPreferencesStatus::Invalid,
            QStringLiteral("Fichier de préférences globales corrompu."));

    if (!settings.contains(VersionKey)
        || !settings.contains(RootDirectoryKey)
        || !settings.contains(RetainedVersionsKey))
        return result(GlobalBackupPreferencesStatus::Invalid,
            QStringLiteral("Configuration globale incomplète."));

    bool versionOk = false;
    const int version = settings.value(VersionKey).toString().toInt(&versionOk);
    GlobalBackupPreferences preferences;
    preferences.rootDirectory = settings.value(RootDirectoryKey).toString();
    if (!versionOk || version != FormatVersion
        || !canonicalUnsigned(settings.value(RetainedVersionsKey),
            preferences.retainedVersions)
        || !validPreferences(preferences))
        return result(GlobalBackupPreferencesStatus::Invalid,
            QStringLiteral("Configuration globale invalide."));

    return result(GlobalBackupPreferencesStatus::Valid, {}, std::move(preferences));
}

GlobalBackupPreferencesResult readPhysicalFile(const QString& path)
{
    const QFileInfo information(path);
    if (!information.exists() && information.isSymLink())
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Fichier de préférences globales non sûr."));
    if (!information.exists())
        return result(GlobalBackupPreferencesStatus::Absent);

#ifdef Q_OS_UNIX
    const QByteArray encoded = QFile::encodeName(path);
    const int descriptor = ::open(encoded.constData(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Fichier de préférences globales inaccessible."));
    struct Descriptor {
        int value;
        ~Descriptor() noexcept { if (value >= 0) (void)::close(value); }
    } owner{descriptor};
    struct stat before {};
    if (::fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != ::geteuid() || before.st_nlink != 1
        || (before.st_mode & 0077) || before.st_size < 0
        || before.st_size > MaximumSettingsBytes)
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Fichier de préférences globales non sûr ou trop volumineux."));
    QFile file;
    if (!file.open(descriptor, QIODevice::ReadOnly, QFileDevice::DontCloseHandle))
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Lecture des préférences globales impossible."));
    const QByteArray bytes = file.read(MaximumSettingsBytes + 1);
    struct stat after {};
    if (file.error() != QFile::NoError || bytes.size() > MaximumSettingsBytes
        || !file.atEnd() || ::fstat(descriptor, &after) != 0
        || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec)
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Lecture stable des préférences globales impossible."));
    return parseSettings(bytes);
#else
    if (information.isSymLink() || !information.isFile()
        || information.size() < 0 || information.size() > MaximumSettingsBytes)
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Fichier de préférences globales non sûr ou trop volumineux."));
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Lecture des préférences globales impossible."));
    const QByteArray bytes = file.read(MaximumSettingsBytes + 1);
    if (file.error() != QFile::NoError || bytes.size() > MaximumSettingsBytes
        || !file.atEnd())
        return result(GlobalBackupPreferencesStatus::ReadError,
            QStringLiteral("Lecture des préférences globales impossible."));
    return parseSettings(bytes);
#endif
}

bool prepareParentDirectory(const QString& path, QString& diagnostic)
{
    const QFileInfo information(path);
    const QString parent = information.absolutePath();
    if (!QDir::isAbsolutePath(path) || parent.isEmpty() || parent == QStringLiteral("/")) {
        diagnostic = QStringLiteral("Emplacement des préférences globales invalide.");
        return false;
    }
    if (!QDir().mkpath(parent)) {
        diagnostic = QStringLiteral("Création du répertoire de configuration impossible.");
        return false;
    }
#ifdef Q_OS_UNIX
    const QByteArray encoded = QFile::encodeName(parent);
    const int descriptor = ::open(encoded.constData(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat status {};
    const bool safe = descriptor >= 0 && ::fstat(descriptor, &status) == 0
        && S_ISDIR(status.st_mode) && status.st_uid == ::geteuid()
        && ::fchmod(descriptor, 0700) == 0;
    if (descriptor >= 0) (void)::close(descriptor);
    if (!safe) {
        diagnostic = QStringLiteral("Répertoire de configuration non sûr ou inaccessible.");
        return false;
    }
#endif
    return true;
}

bool safeExistingTarget(const QString& path, QString& diagnostic)
{
    if (!QFileInfo::exists(path)) return true;
#ifdef Q_OS_UNIX
    const QByteArray encoded = QFile::encodeName(path);
    const int descriptor = ::open(encoded.constData(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat status {};
    const bool safe = descriptor >= 0 && ::fstat(descriptor, &status) == 0
        && S_ISREG(status.st_mode) && status.st_uid == ::geteuid()
        && status.st_nlink == 1 && !(status.st_mode & 0077);
    if (descriptor >= 0) (void)::close(descriptor);
    if (!safe) {
        diagnostic = QStringLiteral("Fichier de préférences globales non sûr.");
        return false;
    }
#else
    const QFileInfo information(path);
    if (information.isSymLink() || !information.isFile()) {
        diagnostic = QStringLiteral("Fichier de préférences globales non sûr.");
        return false;
    }
#endif
    return true;
}

bool confirmPersistence(const QString& path, QString& diagnostic)
{
    if (!QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        diagnostic = QStringLiteral("Permissions des préférences globales non confirmées.");
        return false;
    }
#ifdef Q_OS_UNIX
    const QFileInfo information(path);
    const QByteArray parent = QFile::encodeName(information.absolutePath());
    const QByteArray fileName = QFile::encodeName(information.fileName());
    const int directory = ::open(parent.constData(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const int file = directory < 0 ? -1 : ::openat(directory, fileName.constData(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat status {};
    const bool safe = file >= 0 && ::fstat(file, &status) == 0
        && S_ISREG(status.st_mode) && status.st_uid == ::geteuid()
        && status.st_nlink == 1 && !(status.st_mode & 0077)
        && ::fsync(file) == 0 && ::fsync(directory) == 0;
    if (file >= 0) (void)::close(file);
    if (directory >= 0) (void)::close(directory);
    if (!safe) {
        diagnostic = QStringLiteral(
            "Préférences publiées, mais persistance non confirmée.");
        return false;
    }
#endif
    return true;
}

} // namespace

GlobalBackupPreferencesStore::GlobalBackupPreferencesStore()
    : settingsFile_(QSettings(QSettings::IniFormat, QSettings::UserScope,
          Organization, Application).fileName())
{
}

GlobalBackupPreferencesStore::GlobalBackupPreferencesStore(QString settingsFile)
    : settingsFile_(std::move(settingsFile))
{
}

GlobalBackupPreferencesResult GlobalBackupPreferencesStore::load() const
{
    auto loaded = readPhysicalFile(settingsFile_);
    loaded.sourceFile = settingsFile_;
    return loaded;
}

GlobalBackupPreferencesResult GlobalBackupPreferencesStore::save(
    const GlobalBackupPreferences& preferences) const
{
    const auto sourced = [this](GlobalBackupPreferencesResult value) {
        value.sourceFile = settingsFile_;
        return value;
    };
    if (!validPreferences(preferences))
        return sourced(result(GlobalBackupPreferencesStatus::Invalid,
            QStringLiteral("Préférences globales invalides."), preferences));

    QString diagnostic;
    if (!prepareParentDirectory(settingsFile_, diagnostic)
        || !safeExistingTarget(settingsFile_, diagnostic))
        return sourced(result(GlobalBackupPreferencesStatus::WriteError,
            std::move(diagnostic), preferences));

    QLockFile lock(settingsFile_ + QStringLiteral(".passwall.lock"));
    lock.setStaleLockTime(0);
    if (!lock.tryLock(0))
        return sourced(result(GlobalBackupPreferencesStatus::WriteError,
            QStringLiteral("Préférences globales occupées ; réessayer explicitement."),
            preferences));

#ifdef Q_OS_UNIX
    if (!QFileInfo::exists(settingsFile_)) {
        const QByteArray encoded = QFile::encodeName(settingsFile_);
        const int created = ::open(encoded.constData(),
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (created < 0 || ::close(created) != 0)
            return sourced(result(GlobalBackupPreferencesStatus::WriteError,
                QStringLiteral("Création privée des préférences globales impossible."),
                preferences));
    }
#endif

    QSettings settings(settingsFile_, QSettings::IniFormat);
    settings.setFallbacksEnabled(false);
    settings.setAtomicSyncRequired(true);
    settings.setValue(VersionKey, FormatVersion);
    settings.setValue(RootDirectoryKey, preferences.rootDirectory);
    settings.setValue(RetainedVersionsKey,
        QString::number(preferences.retainedVersions));
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return sourced(result(GlobalBackupPreferencesStatus::WriteError,
            QStringLiteral("Écriture atomique des préférences globales impossible."),
            preferences));

    // The file is already visible at this point. Notify even if the following
    // durability confirmation fails: retaining a preparation made from the
    // previous contents would be unsafe. The current process must however
    // remain fail-closed rather than reloading the visible file as confirmed.
    if (!confirmPersistence(settingsFile_, diagnostic)) {
        emit events().changed(settingsFile_, false);
        return sourced(result(GlobalBackupPreferencesStatus::WriteError,
            std::move(diagnostic), preferences));
    }

    emit events().changed(settingsFile_, true);
    return sourced(result(GlobalBackupPreferencesStatus::Valid, {}, preferences));
}

GlobalBackupPreferencesEvents& GlobalBackupPreferencesStore::events()
{
    static GlobalBackupPreferencesEvents instance;
    return instance;
}

} // namespace passwall::services
