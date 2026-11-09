
cmake_minimum_required(VERSION 3.25)

project(PassWall VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/src/gui/forms")

find_package(Qt6 REQUIRED COMPONENTS Widgets Network)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Qt6 REQUIRED COMPONENTS DBus)
    add_library(passwall_linux_session STATIC
        src/platform/linux_session_monitor.hpp
        src/platform/linux_session_monitor.cpp
        src/platform/logind_dbus_backend.cpp
        src/platform/linux_instance_lock.hpp
        src/platform/linux_instance_lock.cpp
        src/platform/session_lock_service.hpp
        src/platform/session_lock_service.cpp
    )
    target_include_directories(passwall_linux_session PUBLIC src)
    target_link_libraries(passwall_linux_session PUBLIC Qt6::DBus)
endif()
find_package(SQLite3 REQUIRED)
find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# Cooperative exclusion shared by ALL vault connections and keyless workers.
add_library(passwall_vault_operations STATIC src/storage/vault_operation_guard.cpp)
target_include_directories(passwall_vault_operations PUBLIC src)
target_link_libraries(passwall_vault_operations PUBLIC Qt6::Core)

# Verification de l'environnement
add_executable(passwall_env_check
    src/core/environment_check.cpp
)
target_link_libraries(passwall_env_check PRIVATE
    PkgConfig::SODIUM
    SQLite::SQLite3
)

# Tests automatises
enable_testing()

add_executable(passwall_tests
    tests/isolated_vault_settings.cpp
    tests/test_environment.cpp
    tests/test_credential_service.cpp
    tests/test_vault_operation_guard.cpp
    tests/test_password_generator.cpp
    tests/test_site_matcher.cpp
    src/core/site_matcher.cpp
    src/core/crypto_engine.cpp
    src/storage/vault_storage.cpp
    src/storage/sqlite_connection_config.cpp
    src/services/vault_key_service.cpp
    src/services/vault_lifecycle_service.cpp
    src/services/credential_service.cpp
    src/native/entry_id_parser.cpp
    tests/test_entry_id_parser.cpp
    tests/test_native_request_processor.cpp
    src/native/native_request_processor.cpp
    tests/test_native_bridge_server.cpp
    src/native/native_bridge_server.cpp
)

target_include_directories(passwall_tests PRIVATE src)

target_link_libraries(passwall_tests PRIVATE
    passwall_vault_operations
    GTest::gtest_main
    Qt6::Core
    Qt6::Network
    PkgConfig::SODIUM
    SQLite::SQLite3
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Injection locale aux tests : panne d'allocation pendant une copie,
    # observation des effacements et interruption avant COMMIT SQLite.
    target_sources(passwall_tests PRIVATE tests/test_credential_service_memory.cpp)
    target_link_options(passwall_tests PRIVATE
        -Wl,--wrap=_Znwm
        -Wl,--wrap=sodium_malloc
        -Wl,--wrap=sodium_memzero
        -Wl,--wrap=sqlite3_exec
        -Wl,--wrap=sqlite3_extended_errcode
        -Wl,--wrap=sqlite3_txn_state
        -Wl,--wrap=sqlite3_step
        -Wl,--wrap=sqlite3_close_v2)
endif()

include(GoogleTest)
gtest_discover_tests(passwall_tests)

# Local metadata/preferences only: no keys or credentials in QSettings.
add_library(passwall_vault_preferences STATIC src/services/vault_preferences_store.cpp
    src/services/vault_replacement_authorization.cpp)
target_include_directories(passwall_vault_preferences PUBLIC src)
target_link_libraries(passwall_vault_preferences PUBLIC Qt6::Core SQLite::SQLite3 passwall_vault_operations)
target_link_libraries(passwall_tests PRIVATE passwall_vault_preferences)
add_executable(passwall_preferences_tests
    tests/isolated_vault_settings.cpp
    tests/test_vault_preferences_store.cpp
    src/storage/vault_storage.cpp
    src/storage/sqlite_connection_config.cpp)
target_link_libraries(passwall_preferences_tests PRIVATE
    passwall_vault_preferences GTest::gtest_main)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(passwall_preferences_tests PRIVATE
        -Wl,--wrap=_ZNK9QSettings6statusEv -Wl,--wrap=fsync)
endif()
gtest_discover_tests(passwall_preferences_tests)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Isolated SQLite resource faults: reuse linker injection without changing
    # production APIs or the existing credential-memory test wrappers.
    add_executable(passwall_storage_tests
        tests/test_vault_storage_resources.cpp
        src/storage/vault_storage.cpp
        src/storage/sqlite_connection_config.cpp
        src/services/credential_service.cpp
        src/services/vault_lifecycle_service.cpp
        src/services/vault_key_service.cpp
        src/core/crypto_engine.cpp)
    target_include_directories(passwall_storage_tests PRIVATE src)
    target_link_libraries(passwall_storage_tests PRIVATE
        GTest::gtest_main Qt6::Core SQLite::SQLite3 PkgConfig::SODIUM passwall_vault_preferences)
    target_link_options(passwall_storage_tests PRIVATE
        -Wl,--wrap=_Znwm
        -Wl,--wrap=sqlite3_open_v2
        -Wl,--wrap=sqlite3_db_config
        -Wl,--wrap=sqlite3_busy_timeout
        -Wl,--wrap=sqlite3_close_v2
        -Wl,--wrap=sqlite3_prepare_v2
        -Wl,--wrap=sqlite3_step
        -Wl,--wrap=sqlite3_finalize
        -Wl,--wrap=sqlite3_exec
        -Wl,--wrap=sqlite3_errmsg
        -Wl,--wrap=sqlite3_free
        -Wl,--wrap=fsync
        -Wl,--wrap=unlink)
    gtest_discover_tests(passwall_storage_tests)

    # Keyless snapshot engine: no Widgets, vault keys or application integration.
    add_library(passwall_vault_snapshot STATIC
        src/services/vault_snapshot_service.cpp
        src/storage/sqlite_connection_config.cpp
        src/storage/vault_storage.cpp)
    target_include_directories(passwall_vault_snapshot PUBLIC src)
    target_link_libraries(passwall_vault_snapshot PUBLIC SQLite::SQLite3 passwall_vault_operations)
    target_link_libraries(passwall_vault_preferences PUBLIC passwall_vault_snapshot)
    # Recovery gate before every storage/snapshot SQL open. Static libraries
    # form a small strongly-connected component; CMake repeats it for linking.
    target_link_libraries(passwall_vault_snapshot PUBLIC passwall_vault_preferences)
    add_executable(passwall_snapshot_tests
        tests/test_vault_snapshot_service.cpp
        src/core/crypto_engine.cpp
        src/services/vault_key_service.cpp
        src/services/vault_lifecycle_service.cpp
        src/services/credential_service.cpp)
    target_link_libraries(passwall_snapshot_tests PRIVATE
        passwall_vault_snapshot passwall_vault_preferences GTest::gtest_main Qt6::Core PkgConfig::SODIUM)
    target_link_options(passwall_snapshot_tests PRIVATE
        -Wl,--wrap=_Znwm
        -Wl,--wrap=_ZNSt6chrono3_V212steady_clock3nowEv
        -Wl,--wrap=sqlite3_open_v2
        -Wl,--wrap=sqlite3_close
        -Wl,--wrap=sqlite3_close_v2
        -Wl,--wrap=sqlite3_prepare_v2
        -Wl,--wrap=sqlite3_finalize
        -Wl,--wrap=sqlite3_exec
        -Wl,--wrap=sqlite3_step
        -Wl,--wrap=sqlite3_backup_init
        -Wl,--wrap=sqlite3_backup_step
        -Wl,--wrap=sqlite3_backup_finish
        -Wl,--wrap=fstatfs
        -Wl,--wrap=fsync
        -Wl,--wrap=linkat
        -Wl,--wrap=unlinkat)
    gtest_discover_tests(passwall_snapshot_tests)

    # Independent authenticated restoration; never linked to the keyless worker.
    add_library(passwall_vault_restore STATIC
        src/services/vault_restore_service.cpp src/services/credential_service.cpp
        src/services/vault_key_service.cpp src/core/crypto_engine.cpp)
    target_include_directories(passwall_vault_restore PUBLIC src)
    target_link_libraries(passwall_vault_restore PUBLIC passwall_vault_snapshot
        passwall_vault_preferences PkgConfig::SODIUM)
    add_executable(passwall_restore_tests tests/test_vault_restore_service.cpp
        src/services/vault_lifecycle_service.cpp)
    target_link_libraries(passwall_restore_tests PRIVATE
        passwall_vault_restore GTest::gtest_main Qt6::Core)
    target_link_options(passwall_restore_tests PRIVATE
        -Wl,--wrap=_Znwm -Wl,--wrap=sodium_malloc -Wl,--wrap=sodium_free
        -Wl,--wrap=sodium_memzero -Wl,--wrap=crypto_pwhash
        -Wl,--wrap=sqlite3_open_v2 -Wl,--wrap=sqlite3_close -Wl,--wrap=sqlite3_close_v2
        -Wl,--wrap=sqlite3_prepare_v2 -Wl,--wrap=sqlite3_finalize -Wl,--wrap=sqlite3_step
        -Wl,--wrap=sqlite3_backup_step -Wl,--wrap=fsync -Wl,--wrap=linkat -Wl,--wrap=unlinkat)
    gtest_discover_tests(passwall_restore_tests)

    # Synchronous capability-scoped principal replacement, no GUI/worker API.
    # Deliberately separate from the keyless snapshot/backup binaries.
    add_library(passwall_vault_replacement STATIC src/services/vault_replacement_service.cpp)
    target_include_directories(passwall_vault_replacement PUBLIC src)
    target_link_libraries(passwall_vault_replacement PUBLIC passwall_vault_restore)

    # Isolated contract issuer, compiled only into this executable. Production
    # authorization has no public factory or boolean cleanup assertion.
    add_executable(passwall_replacement_tests tests/test_vault_replacement.cpp
        tests/test_vault_replacement_engine.cpp
        tests/isolated_vault_settings.cpp
        src/services/vault_preferences_store.cpp
        src/services/vault_replacement_authorization.cpp
        src/services/vault_replacement_service.cpp
        src/services/vault_lifecycle_service.cpp
        src/services/credential_service.cpp
        src/services/vault_key_service.cpp src/core/crypto_engine.cpp)
    target_compile_definitions(passwall_replacement_tests PRIVATE PASSWALL_REPLACEMENT_TESTING)
    target_link_libraries(passwall_replacement_tests PRIVATE passwall_vault_snapshot
        GTest::gtest Qt6::Core PkgConfig::SODIUM)
    target_link_options(passwall_replacement_tests PRIVATE -Wl,--wrap=fsync -Wl,--wrap=openat
        -Wl,--wrap=_ZN9QSettings4syncEv -Wl,--wrap=renameat2
        -Wl,--wrap=sodium_malloc -Wl,--wrap=sodium_free -Wl,--wrap=sqlite3_step
        -Wl,--wrap=crypto_aead_xchacha20poly1305_ietf_decrypt -Wl,--wrap=fstatfs
        -Wl,--wrap=sqlite3_backup_step -Wl,--wrap=linkat)
    gtest_discover_tests(passwall_replacement_tests)

    # Short-lived keyless backup process and standalone asynchronous Qt driver.
    # Two keyless modes (snapshot / optional automatic-version rotation).
    add_library(passwall_backup_rotation STATIC src/services/backup_rotation_service.cpp)
    target_include_directories(passwall_backup_rotation PUBLIC src)
    target_link_libraries(passwall_backup_rotation PUBLIC passwall_vault_preferences Qt6::Core)
    add_executable(passwall_backup_worker src/services/backup_worker_main.cpp)
    target_link_libraries(passwall_backup_worker PRIVATE passwall_backup_rotation)
    add_library(passwall_backup_driver STATIC
        src/services/backup_job.hpp src/services/backup_job.cpp)
    target_include_directories(passwall_backup_driver PUBLIC src)
    target_link_libraries(passwall_backup_driver PUBLIC Qt6::Core passwall_vault_operations)
    add_library(passwall_automatic_backup STATIC
        src/services/automatic_backup_coordinator.hpp src/services/automatic_backup_coordinator.cpp)
    target_include_directories(passwall_automatic_backup PUBLIC src)
    target_link_libraries(passwall_automatic_backup PUBLIC passwall_backup_driver passwall_vault_preferences)
    add_executable(passwall_automatic_backup_tests tests/test_automatic_backup.cpp
        src/services/credential_service.cpp src/services/vault_key_service.cpp src/core/crypto_engine.cpp)
    target_link_libraries(passwall_automatic_backup_tests PRIVATE
        passwall_automatic_backup GTest::gtest PkgConfig::SODIUM)
    target_link_options(passwall_automatic_backup_tests PRIVATE
        -Wl,--wrap=fsync -Wl,--wrap=fstatfs
        -Wl,--wrap=_ZN8QProcess4killEv -Wl,--wrap=_ZN8QProcess9terminateEv
        -Wl,--wrap=_ZN9QDateTime15currentDateTimeEv)
    target_compile_definitions(passwall_automatic_backup_tests PRIVATE
        AUTO_REAL_WORKER="$<TARGET_FILE:passwall_backup_worker>"
        AUTO_FAKE_WORKER="$<TARGET_FILE:passwall_fake_backup_worker>"
        AUTO_PROBE_WORKER="$<TARGET_FILE:passwall_backup_worker_probe>")
    add_dependencies(passwall_automatic_backup_tests passwall_backup_worker
        passwall_fake_backup_worker passwall_backup_worker_probe)
    gtest_discover_tests(passwall_automatic_backup_tests)

    add_executable(passwall_fake_backup_worker tests/fake_backup_worker.cpp)
    target_include_directories(passwall_fake_backup_worker PRIVATE src)
    target_link_libraries(passwall_fake_backup_worker PRIVATE passwall_backup_rotation)
    add_executable(passwall_backup_worker_probe
        src/services/backup_worker_main.cpp tests/backup_worker_faults.cpp)
    target_link_libraries(passwall_backup_worker_probe PRIVATE passwall_backup_rotation)
    target_link_options(passwall_backup_worker_probe PRIVATE
        -Wl,--wrap=sqlite3_open_v2 -Wl,--wrap=sqlite3_backup_step
        -Wl,--wrap=linkat -Wl,--wrap=fsync -Wl,--wrap=fstatat -Wl,--wrap=unlinkat
        -Wl,--wrap=read)
    add_executable(passwall_backup_tests tests/test_backup_job.cpp
        src/core/crypto_engine.cpp src/services/vault_key_service.cpp
        src/services/vault_lifecycle_service.cpp src/services/credential_service.cpp)
    target_link_libraries(passwall_backup_tests PRIVATE passwall_backup_driver
        passwall_vault_snapshot passwall_vault_preferences GTest::gtest PkgConfig::SODIUM)
    target_link_options(passwall_backup_tests PRIVATE
        -Wl,--wrap=_ZN8QProcess4killEv -Wl,--wrap=_ZN8QProcess9terminateEv)
    target_compile_definitions(passwall_backup_tests PRIVATE
        REAL_BACKUP_WORKER="$<TARGET_FILE:passwall_backup_worker>"
        FAKE_BACKUP_WORKER="$<TARGET_FILE:passwall_fake_backup_worker>"
        PROBE_BACKUP_WORKER="$<TARGET_FILE:passwall_backup_worker_probe>")
    add_dependencies(passwall_backup_tests passwall_backup_worker
        passwall_fake_backup_worker passwall_backup_worker_probe)
    gtest_discover_tests(passwall_backup_tests PROPERTIES TIMEOUT 20)

    # Deterministic intent-before-SQL/crash tests; hooks stay in this binary.
    add_executable(passwall_dirty_tracking_tests tests/test_vault_dirty_tracking.cpp
        src/services/credential_service.cpp src/services/vault_key_service.cpp
        src/storage/vault_storage.cpp src/storage/sqlite_connection_config.cpp
        src/core/crypto_engine.cpp)
    target_include_directories(passwall_dirty_tracking_tests PRIVATE src)
    target_link_libraries(passwall_dirty_tracking_tests PRIVATE
        passwall_vault_preferences GTest::gtest PkgConfig::SODIUM)
    target_link_options(passwall_dirty_tracking_tests PRIVATE
        -Wl,--wrap=sqlite3_open_v2 -Wl,--wrap=sqlite3_exec
        -Wl,--wrap=fsync -Wl,--wrap=_ZNK9QSettings6statusEv)
    gtest_discover_tests(passwall_dirty_tracking_tests)
    foreach(regression_target passwall_storage_tests passwall_snapshot_tests
            passwall_restore_tests passwall_backup_tests)
        target_sources(${regression_target} PRIVATE tests/isolated_vault_settings.cpp)
    endforeach()
endif()

# Mesure des performances Argon2id
add_executable(passwall_argon2_benchmark
    src/core/argon2_benchmark.cpp
)
target_link_libraries(passwall_argon2_benchmark PRIVATE
    PkgConfig::SODIUM
)

# Application graphique PassWall
add_executable(passwall_app
    src/gui/main.cpp
    src/gui/main_window.hpp
    src/gui/main_window.cpp
    src/gui/main_window_replacement.cpp
    src/gui/credential_editor_context.cpp
    src/gui/forms/main_window.ui
    src/core/site_matcher.cpp
    src/core/crypto_engine.cpp
    src/storage/vault_storage.cpp
    src/storage/sqlite_connection_config.cpp
    src/services/vault_key_service.cpp
    src/services/vault_lifecycle_service.cpp
    src/services/credential_service.cpp
    src/native/entry_id_parser.cpp
    src/native/native_request_processor.cpp
    src/native/native_bridge_server.hpp
    src/native/native_bridge_server.cpp
)

target_include_directories(passwall_app PRIVATE src)

target_link_libraries(passwall_app PRIVATE
    passwall_vault_preferences
    Qt6::Widgets
    Qt6::Network
    PkgConfig::SODIUM
    SQLite::SQLite3
)

# Tests GUI isoles : memes implementations que l'application, donnees fictives
# et configuration QSettings redirigee vers un repertoire temporaire.
add_executable(passwall_gui_tests
    tests/test_credential_editor_lock.cpp
    tests/test_vault_preferences_gui.cpp
    src/gui/main_window.hpp
    src/gui/main_window.cpp
    src/gui/main_window_replacement.cpp
    src/gui/credential_editor_context.cpp
    src/gui/forms/main_window.ui
    src/core/site_matcher.cpp
    src/core/crypto_engine.cpp
    src/storage/vault_storage.cpp
    src/storage/sqlite_connection_config.cpp
    src/services/vault_key_service.cpp
    src/services/vault_lifecycle_service.cpp
    src/services/credential_service.cpp
    src/native/entry_id_parser.cpp
    src/native/native_request_processor.cpp
    src/native/native_bridge_server.hpp
    src/native/native_bridge_server.cpp
)
target_include_directories(passwall_gui_tests PRIVATE src)
target_link_libraries(passwall_gui_tests PRIVATE
    passwall_vault_preferences
    GTest::gtest
    Qt6::Widgets
    Qt6::Network
    PkgConfig::SODIUM
    SQLite::SQLite3
)
gtest_discover_tests(passwall_gui_tests)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(passwall_app PRIVATE passwall_linux_session)
    target_link_libraries(passwall_gui_tests PRIVATE passwall_linux_session)
    foreach(gui_target passwall_app passwall_gui_tests)
        target_sources(${gui_target} PRIVATE src/gui/main_window_export.cpp
            src/gui/vault_export_dialog.hpp src/gui/vault_export_dialog.cpp)
        target_link_libraries(${gui_target} PRIVATE passwall_backup_driver passwall_automatic_backup)
        add_dependencies(${gui_target} passwall_backup_worker)
    endforeach()
    target_sources(passwall_gui_tests PRIVATE
        tests/test_manual_vault_export.cpp
        tests/test_master_password_cleanup.cpp
        tests/test_linux_session_monitor.cpp
        tests/test_logind_dbus_backend.cpp
        tests/test_linux_instance_lock.cpp
        tests/test_session_lock_service.cpp
    )
    add_dependencies(passwall_gui_tests passwall_fake_backup_worker)
    target_compile_definitions(passwall_gui_tests PRIVATE
        EXPORT_FAKE_WORKER="$<TARGET_FILE:passwall_fake_backup_worker>")
    target_link_options(passwall_gui_tests PRIVATE
        -Wl,--wrap=_ZN8passwall8services9BackupJob17siblingWorkerPathEv
        -Wl,--wrap=_ZN8passwall8services9BackupJob5startERK7QStringS4_
        -Wl,--wrap=_ZN8QProcess4killEv -Wl,--wrap=_ZN8QProcess9terminateEv)
    add_executable(passwall_instance_probe tests/linux_instance_probe.cpp)
    target_link_libraries(passwall_instance_probe PRIVATE passwall_linux_session Qt6::Network)
    add_dependencies(passwall_gui_tests passwall_instance_probe)
    # Inject poll() failures only in isolated tests, never in production.
    target_link_options(passwall_gui_tests PRIVATE -Wl,--wrap=poll)
    # Observe real Qt subscriptions and pause ONLY a private test bus.
    target_link_options(passwall_gui_tests PRIVATE
        -Wl,--wrap=_ZN15QDBusConnection7connectERK7QStringS2_S2_S2_P7QObjectPKc
        -Wl,--wrap=_ZNK15QDBusConnection9asyncCallERK12QDBusMessagei)
    # Exceptions et observation des effacements uniquement dans les tests,
    # sans point d'injection dans l'interface du service de production.
    target_link_options(passwall_gui_tests PRIVATE
        -Wl,--wrap=sodium_memzero
        -Wl,--wrap=_ZN8passwall8services21VaultLifecycleService11createVaultERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES9_RNS_4core12SecureBufferERS7_
        -Wl,--wrap=_ZN8passwall8services21VaultLifecycleService11unlockVaultERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES9_RNS_4core12SecureBufferERS7_)
endif()

# Hôte natif de communication avec Firefox
add_executable(passwall_native_host
    src/native/native_host.cpp
    src/core/crypto_engine.cpp
)

target_include_directories(passwall_native_host PRIVATE src)

target_link_libraries(passwall_native_host PRIVATE
    nlohmann_json::nlohmann_json
    PkgConfig::SODIUM
)

# Tests isoles du demarrage natif avec injection des erreurs POSIX a l'edition
# de liens, sans executer l'application graphique.
add_executable(passwall_native_host_tests
    tests/test_native_host_startup.cpp
    src/core/crypto_engine.cpp
)
target_include_directories(passwall_native_host_tests PRIVATE src)
target_link_libraries(passwall_native_host_tests PRIVATE
    GTest::gtest_main
    nlohmann_json::nlohmann_json
    PkgConfig::SODIUM
)
target_link_options(passwall_native_host_tests PRIVATE
    -Wl,--wrap=open
    -Wl,--wrap=dup2
    -Wl,--wrap=access
    -Wl,--wrap=fork
    -Wl,--wrap=execl
)
gtest_discover_tests(passwall_native_host_tests)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # The instance test starts hosts with stdin held open and sends no request.
    add_dependencies(passwall_gui_tests passwall_native_host)

    # Isolated screen-lock coordinator: no Widgets, vault code or system changes.
    add_executable(passwall_session_lock src/platform/session_lock_main.cpp)
    set_target_properties(passwall_session_lock PROPERTIES OUTPUT_NAME passwall-session-lock)
    target_link_libraries(passwall_session_lock PRIVATE Qt6::Core Qt6::DBus)

    add_executable(passwall_fake_session_locker tests/fake_session_locker.cpp)
    target_link_libraries(passwall_fake_session_locker PRIVATE Qt6::Core)
    add_executable(passwall_session_lock_test_driver src/platform/session_lock_main.cpp)
    target_link_libraries(passwall_session_lock_test_driver PRIVATE Qt6::Core Qt6::DBus)
    target_compile_definitions(passwall_session_lock_test_driver PRIVATE PASSWALL_SESSION_LOCK_TESTING)
    add_dependencies(passwall_session_lock_test_driver passwall_fake_session_locker)

    add_executable(passwall_session_lock_tests tests/test_session_lock_coordinator.cpp)
    target_include_directories(passwall_session_lock_tests PRIVATE tests)
    target_link_libraries(passwall_session_lock_tests PRIVATE GTest::gtest Qt6::Core Qt6::DBus Qt6::Network)
    target_compile_definitions(passwall_session_lock_tests PRIVATE
        PASSWALL_COORDINATOR_TEST_PROGRAM="$<TARGET_FILE:passwall_session_lock_test_driver>"
        PASSWALL_COORDINATOR_PROGRAM="$<TARGET_FILE:passwall_session_lock>"
        PASSWALL_FAKE_LOCKER_PROGRAM="$<TARGET_FILE:passwall_fake_session_locker>")
    add_dependencies(passwall_session_lock_tests passwall_session_lock_test_driver passwall_session_lock)
    gtest_discover_tests(passwall_session_lock_tests PROPERTIES TIMEOUT 15)
endif()
