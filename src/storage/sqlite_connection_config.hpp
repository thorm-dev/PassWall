#pragma once

#include <string>

struct sqlite3;

namespace passwall::storage {

// Configure a caller-owned connection, before transactions or business SQL.
// newlyCreated may only be true after exclusive creation of our own file.
// Existing files are inspected, never converted to another journal mode.
// NO_CKPT_ON_CLOSE is verified before inspection and retained on this connection
// until close. It inhibits only the automatic WAL checkpoint at close (no effect
// in accepted DELETE mode), not recovery, SHM maintenance, explicit checkpoints
// or checkpoints/writes by other connections. If it cannot be confirmed, no
// PRAGMA is inspected. On false or exception, the caller's RAII owner must close
// the connection; the function never assumes ownership or deletes any file.
[[nodiscard]] bool configureSqliteConnection(
    sqlite3* database, std::string& error, bool newlyCreated = false);

} // namespace passwall::storage
