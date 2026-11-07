
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
    tests/test_environment.cpp
    tests/test_credential_service.cpp
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
        GTest::gtest_main Qt6::Core SQLite::SQLite3 PkgConfig::SODIUM)
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
    Qt6::Widgets
    Qt6::Network
    PkgConfig::SODIUM
    SQLite::SQLite3
)

# Tests GUI isoles : memes implementations que l'application, donnees fictives
# et configuration QSettings redirigee vers un repertoire temporaire.
add_executable(passwall_gui_tests
    tests/test_credential_editor_lock.cpp
    src/gui/main_window.hpp
    src/gui/main_window.cpp
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
    target_sources(passwall_gui_tests PRIVATE
        tests/test_master_password_cleanup.cpp
        tests/test_linux_session_monitor.cpp
        tests/test_logind_dbus_backend.cpp
        tests/test_linux_instance_lock.cpp
        tests/test_session_lock_service.cpp
    )
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
