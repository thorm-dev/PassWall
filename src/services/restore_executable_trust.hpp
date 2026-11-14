#pragma once

#include <QString>
#include <sys/types.h>

namespace passwall::services::restore_executable_trust {

enum class Failure {
    None,
    Missing,
    NotRegular,
    WrongOwner,
    WritableByOthers,
    NotOwnerExecutable,
    ProcessUnavailable,
    IdentityMismatch
};

// Local executable provenance only. No path or diagnostic produced here may
// contain restoration data or secrets.
Failure executable(const QString& path) noexcept;
Failure processExecutable(pid_t process, const QString& expected) noexcept;
QString diagnostic(Failure failure, const QString& subject);

} // namespace passwall::services::restore_executable_trust
