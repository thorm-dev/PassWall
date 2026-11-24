#pragma once

#include <QObject>
#include <QString>
#include <QtGlobal>

#include <optional>

namespace passwall::services {

struct GlobalBackupPreferences {
    QString rootDirectory;
    quint64 retainedVersions = 7;

    bool operator==(const GlobalBackupPreferences&) const = default;
};

// Transient provenance of the exact preferences file read from disk.  It is
// never persisted and is only used to reject a preparation/rotation after the
// configuration file has been replaced or modified concurrently.
struct GlobalBackupPreferencesFileIdentity {
    quint64 device = 0;
    quint64 inode = 0;
    quint64 size = 0;
    qint64 modifiedSeconds = 0;
    quint32 modifiedNanoseconds = 0;
    qint64 changedSeconds = 0;
    quint32 changedNanoseconds = 0;
    bool operator==(const GlobalBackupPreferencesFileIdentity&) const = default;
};

enum class GlobalBackupPreferencesStatus {
    Absent,
    Valid,
    Invalid,
    ReadError,
    WriteError
};

struct GlobalBackupPreferencesResult {
    GlobalBackupPreferencesStatus status = GlobalBackupPreferencesStatus::Absent;
    GlobalBackupPreferences preferences;
    QString diagnostic;
    // Provenance of the snapshot read from disk. It is not persisted in the
    // INI file; prepared operations retain it solely for final revalidation.
    QString sourceFile;
    std::optional<GlobalBackupPreferencesFileIdentity> sourceIdentity;

    [[nodiscard]] bool valid() const noexcept
    {
        return status == GlobalBackupPreferencesStatus::Valid;
    }
};

class GlobalBackupPreferencesEvents final : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
signals:
    // Emitted only after the on-disk contents may have changed. Consumers must
    // reload the file and must not treat this notification as trusted data.
    void changed(QString settingsFile, bool persistenceConfirmed);
};

// Ordinary installation-wide backup preferences only. This file contains no
// vault identity, recovery proof, mutation, attempt or secret. Its validity is
// necessary but never sufficient to authorize an automatic backup: destination
// admission and publication checks remain separate responsibilities.
class GlobalBackupPreferencesStore final {
public:
    static constexpr quint64 MinimumRetainedVersions = 7;

    GlobalBackupPreferencesStore();
    explicit GlobalBackupPreferencesStore(QString settingsFile);

    [[nodiscard]] QString fileName() const { return settingsFile_; }
    [[nodiscard]] GlobalBackupPreferencesResult load() const;
    // Syntax and local path-shape validation only. A Valid result is not proof
    // that the destination is mounted, writable or otherwise operational.
    [[nodiscard]] static GlobalBackupPreferencesResult validate(
        const GlobalBackupPreferences& preferences);
    [[nodiscard]] GlobalBackupPreferencesResult save(
        const GlobalBackupPreferences& preferences) const;
    static GlobalBackupPreferencesEvents& events();

private:
    QString settingsFile_;
};

} // namespace passwall::services
