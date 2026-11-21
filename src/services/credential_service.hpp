#pragma once

#include "core/crypto_engine.hpp"
#include "models/credential.hpp"
#include "services/backup_trigger_mode.hpp"

#include <QObject>
#include <QMetaType>
#include <QString>
#include <QtGlobal>
#include <string>
#include <vector>

namespace passwall::services {

enum class CredentialMutation {
    Added,
    Updated,
    Removed
};

// In-process observation boundary for confirmed business mutations. The signal
// carries no entry content and is emitted only after SQLite has confirmed the
// end of the corresponding COMMIT. It does not itself schedule a backup.
class CredentialEvents final : public QObject {
    Q_OBJECT
signals:
    void committed(QString databasePath, passwall::services::CredentialMutation mutation,
        quint64 generation);
};

class CredentialService {
public:
    static CredentialEvents& events();
    [[nodiscard]] static quint64 currentCommitGeneration() noexcept;

    // Validation sans mutation ni accès au stockage. Titre et utilisateur
    // doivent contenir autre chose que des blancs Unicode. Le mot de passe
    // est une donnée exacte : seule sa vacuité est interdite, sans trim.
    [[nodiscard]] static bool validate(
        const models::Credential& credential,
        std::string& error);

    [[nodiscard]] static bool add(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        models::Credential& credential,
        std::string& error,
        BackupTriggerMode triggerMode = BackupTriggerMode::Historical);

    [[nodiscard]] static bool list(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        std::vector<models::Credential>& credentials,
        std::string& error);

    [[nodiscard]] static bool listSummaries(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        std::vector<models::CredentialSummary>& summaries,
        std::string& error);

    // No output, cache, session or vector of entries/summaries. Authenticate,
    // deserialize and validate each record with the existing read path, then
    // wipe it before advancing. Caller supplies a stable private database (the
    // restore engine validates its structure first). No business SQL writes.
    [[nodiscard]] static bool authenticateAll(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        std::string& error);
    [[nodiscard]] static bool authenticateAll(
        const std::string& databasePath, const core::SecureBuffer& dataKey,
        std::string& error, bool (*cancelled)(void*) noexcept, void* context);

    [[nodiscard]] static bool get(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        const models::EntryId& entryId,
        models::Credential& credential,
        std::string& error);

    [[nodiscard]] static bool update(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        const models::Credential& credential,
        std::string& error,
        BackupTriggerMode triggerMode = BackupTriggerMode::Historical);

    [[nodiscard]] static bool remove(
        const std::string& databasePath,
        const core::SecureBuffer& dataKey,
        const models::EntryId& entryId,
        std::string& error,
        BackupTriggerMode triggerMode = BackupTriggerMode::Historical);
};

} // namespace passwall::services

Q_DECLARE_METATYPE(passwall::services::CredentialMutation)
