#pragma once

#include "services/backup_publication_verifier.hpp"
#include <sys/stat.h>
#include <unistd.h>

// Shared implementation with the historical rotation during its removal.
// Not a public authorization or deletion API.
namespace passwall::services::backup_publication_detail {
struct Fd {
    int value = -1;
    Fd() = default;
    explicit Fd(int v) : value(v) {}
    ~Fd() noexcept { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
struct Opened {
    Fd directory, file;
    QByteArray name;
    struct stat stable {};
    BackupFileEvidence evidence;
};
bool fail(QString& error, const char* operation);
bool systemFailure(QString& error, const char* operation);
bool cancelled(SnapshotCancellation cancellation);
bool openDirectory(const QString& path, Fd& dir, QString& error);
void extendedIdentity(int fd, quint64& mount, QString& birth);
bool sameStat(const struct stat& a, const struct stat& b);
bool inspect(const QString& path, Opened& file, QString& error,
    SnapshotCancellation cancellation);
} // namespace passwall::services::backup_publication_detail
