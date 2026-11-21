#pragma once

namespace passwall::services {

// Immutable process-component policy selected by the owner at construction or
// call admission. Production currently selects Historical exclusively.
enum class BackupTriggerMode {
    Historical,
    Generational
};

} // namespace passwall::services
