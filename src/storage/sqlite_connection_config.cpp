#include "storage/sqlite_connection_config.hpp"

#include <sqlite3.h>

#include <cstring>

namespace passwall::storage {
namespace {

struct Statement {
    sqlite3_stmt* handle = nullptr;
    Statement() = default;
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    ~Statement() noexcept
    {
        if (handle != nullptr)
            sqlite3_finalize(handle);
    }
};

bool fail(std::string& error, const char* parameter, const char* reason)
{
    // Parameter names and reasons are constants, never database/user contents.
    error = std::string("Configuration SQLite : ") + parameter + " : " + reason + ".";
    return false;
}

bool prepare(sqlite3* database, const char* sql, const char* parameter,
             Statement& statement, std::string& error)
{
    if (sqlite3_prepare_v2(database, sql, -1, &statement.handle, nullptr) != SQLITE_OK)
        return fail(error, parameter, "préparation impossible");
    return true;
}

bool finish(Statement& statement, const char* parameter, std::string& error)
{
    if (sqlite3_step(statement.handle) != SQLITE_DONE)
        return fail(error, parameter, "fin du résultat non vérifiable");
    auto* handle = statement.handle;
    statement.handle = nullptr;
    if (sqlite3_finalize(handle) != SQLITE_OK)
        return fail(error, parameter, "finalisation impossible");
    return true;
}

bool checkInteger(sqlite3* database, const char* sql, const char* parameter,
                  int expected, std::string& error)
{
    Statement statement;
    if (!prepare(database, sql, parameter, statement, error))
        return false;
    if (sqlite3_step(statement.handle) != SQLITE_ROW
        || sqlite3_column_count(statement.handle) != 1
        || sqlite3_column_type(statement.handle, 0) != SQLITE_INTEGER
        || sqlite3_column_int64(statement.handle, 0) != expected)
        return fail(error, parameter, "valeur effective absente ou inattendue");
    return finish(statement, parameter, error);
}

bool setAndCheck(sqlite3* database, const char* setting, const char* query,
                 const char* parameter, int expected, std::string& error)
{
    if (sqlite3_exec(database, setting, nullptr, nullptr, nullptr) != SQLITE_OK)
        return fail(error, parameter, "application impossible");
    return checkInteger(database, query, parameter, expected, error);
}

bool checkJournal(sqlite3* database, bool newlyCreated, std::string& error)
{
    Statement statement;
    if (!prepare(database, newlyCreated ? "PRAGMA main.journal_mode=DELETE;"
                                        : "PRAGMA main.journal_mode;",
                 "journal_mode", statement, error))
        return false;
    if (sqlite3_step(statement.handle) != SQLITE_ROW
        || sqlite3_column_count(statement.handle) != 1
        || sqlite3_column_type(statement.handle, 0) != SQLITE_TEXT)
        return fail(error, "journal_mode", "mode effectif non vérifiable");
    const auto* value = sqlite3_column_text(statement.handle, 0);
    if (value == nullptr || sqlite3_column_bytes(statement.handle, 0) != 6
        || std::memcmp(value, "delete", 6) != 0)
        return fail(error, "journal_mode", "DELETE requis, aucune conversion autorisée");
    return finish(statement, "journal_mode", error);
}

bool checkTempStoreBuild(sqlite3* database, std::string& error)
{
    Statement statement;
    if (!prepare(database, "PRAGMA compile_options;", "temp_store", statement, error))
        return false;
    bool found = false;
    int result;
    while ((result = sqlite3_step(statement.handle)) == SQLITE_ROW) {
        if (sqlite3_column_count(statement.handle) != 1
            || sqlite3_column_type(statement.handle, 0) != SQLITE_TEXT)
            return fail(error, "temp_store", "options de compilation non vérifiables");
        const auto* value = sqlite3_column_text(statement.handle, 0);
        if (value == nullptr)
            return fail(error, "temp_store", "option de compilation illisible");
        const int size = sqlite3_column_bytes(statement.handle, 0);
        if (size >= 11 && std::memcmp(value, "TEMP_STORE=", 11) == 0) {
            if (found || size != 12 || value[11] < '1' || value[11] > '3')
                return fail(error, "temp_store", "option TEMP_STORE incompatible avec MEMORY");
            found = true;
        }
    }
    if (result != SQLITE_DONE || !found)
        return fail(error, "temp_store", "option TEMP_STORE absente ou non vérifiable");
    auto* handle = statement.handle;
    statement.handle = nullptr;
    if (sqlite3_finalize(handle) != SQLITE_OK)
        return fail(error, "temp_store", "finalisation impossible");
    return true;
}

} // namespace

bool configureSqliteConnection(sqlite3* database, std::string& error, bool newlyCreated)
{
    error.clear();
    if (database == nullptr)
        return fail(error, "connexion", "connexion absente");

    // Connection-local only. Establish this before any PRAGMA can initialize
    // a WAL pager; refusing WAL must not cause a close-time checkpoint.
    int enabled = 0;
    if (sqlite3_db_config(database, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, &enabled) != SQLITE_OK
        || enabled != 1)
        return fail(error, "NO_CKPT_ON_CLOSE", "activation impossible ou non confirmée");
    enabled = 0;
    if (sqlite3_db_config(database, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, -1, &enabled) != SQLITE_OK
        || enabled != 1)
        return fail(error, "NO_CKPT_ON_CLOSE", "protection effective non vérifiable");

    if (sqlite3_get_autocommit(database) == 0)
        return fail(error, "connexion", "configuration interdite pendant une transaction");
    if (!checkJournal(database, newlyCreated, error) || !checkTempStoreBuild(database, error))
        return false;

    if (sqlite3_busy_timeout(database, 3000) != SQLITE_OK)
        return fail(error, "busy_timeout", "application impossible");
    return checkInteger(database, "PRAGMA busy_timeout;", "busy_timeout", 3000, error)
        && setAndCheck(database, "PRAGMA main.synchronous=EXTRA;", "PRAGMA main.synchronous;",
                       "synchronous", 3, error)
        && setAndCheck(database, "PRAGMA main.secure_delete=ON;", "PRAGMA main.secure_delete;",
                       "secure_delete", 1, error)
        && setAndCheck(database, "PRAGMA temp_store=MEMORY;", "PRAGMA temp_store;",
                       "temp_store", 2, error);
}

} // namespace passwall::storage
