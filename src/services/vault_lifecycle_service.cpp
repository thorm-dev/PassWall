
#include "services/vault_lifecycle_service.hpp"

#include "services/vault_key_service.hpp"
#include "services/vault_preferences_store.hpp"
#include "storage/vault_storage.hpp"
#include "storage/vault_operation_guard.hpp"

#include <sodium.h>

#include <array>
#include <cerrno>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <fcntl.h>
#include <cstring>

#include <unistd.h>

namespace passwall::services {
namespace {

std::string makeTemporaryPath(const std::filesystem::path& finalPath)
{
    std::array<unsigned char, 16> randomBytes{};
    randombytes_buf(randomBytes.data(), randomBytes.size());

    char hexadecimal[crypto_generichash_BYTES * 2 + 1]{};
    sodium_bin2hex(
        hexadecimal,
        sizeof(hexadecimal),
        randomBytes.data(),
        randomBytes.size());

    sodium_memzero(randomBytes.data(), randomBytes.size());

    const std::string temporaryName =
        "." + finalPath.filename().string() +
        ".tmp-" + hexadecimal;

    return (finalPath.parent_path() / temporaryName).string();
}

struct TemporaryFiles {
    // Allocate paths before acquiring any file. Cleanup must not allocate,
    // including when an error message itself throws std::bad_alloc.
    const std::array<std::string, 4> paths;
    bool active = false;

    explicit TemporaryFiles(const std::string& path)
        : paths{path, path + "-journal", path + "-wal", path + "-shm"} {}
    TemporaryFiles(const TemporaryFiles&) = delete;
    TemporaryFiles& operator=(const TemporaryFiles&) = delete;
    ~TemporaryFiles() noexcept
    {
        if (active)
            for (const auto& path : paths)
                ::unlink(path.c_str());
    }
};


bool syncFile(const std::string& path, std::string& error)
{
    const int fd = ::open(
        path.c_str(),
        O_RDWR | O_CLOEXEC | O_NOFOLLOW);

    if (fd == -1) {
        error = "Impossible d'ouvrir le coffre pour synchronisation : ";
        error += std::strerror(errno);
        return false;
    }

    if (::fsync(fd) != 0) {
        const int savedErrno = errno;
        ::close(fd);

        error = "Impossible de synchroniser le fichier du coffre : ";
        error += std::strerror(savedErrno);
        return false;
    }

    if (::close(fd) != 0) {
        error = "Impossible de fermer le fichier après synchronisation.";
        return false;
    }

    return true;
}

bool syncDirectory(
    const std::filesystem::path& path,
    std::string& error)
{
    const int fd = ::open(
        path.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC);

    if (fd == -1) {
        error = "Impossible d'ouvrir le dossier du coffre : ";
        error += std::strerror(errno);
        return false;
    }

    if (::fsync(fd) != 0) {
        const int savedErrno = errno;
        ::close(fd);

        error = "Impossible de synchroniser le dossier du coffre : ";
        error += std::strerror(savedErrno);
        return false;
    }

    if (::close(fd) != 0) {
        error = "Impossible de fermer le dossier après synchronisation.";
        return false;
    }

    return true;
}


} // namespace

bool VaultLifecycleService::createVault(
    const std::string& databasePath,
    const std::string& masterPassword,
    core::SecureBuffer& dataKey,
    std::string& error)
{
    error.clear();
    dataKey = core::SecureBuffer(0);

    if (databasePath.empty() || masterPassword.empty()) {
        error = "Le chemin du coffre et le mot de passe maître sont obligatoires.";
        return false;
    }

    storage::VaultOperationGuard access;
    if (!access.tryAccess(databasePath, error)) return false;
    if (!VaultPreferencesStore::checkRecoveryAccess(databasePath, error)) return false;
    if (!core::CryptoEngine::initialize()) {
        error = "Impossible d'initialiser le moteur cryptographique.";
        return false;
    }

    const std::filesystem::path finalPath(databasePath);
    const std::filesystem::path parentPath =
        finalPath.parent_path().empty()
            ? std::filesystem::path(".")
            : finalPath.parent_path();

    if (finalPath.filename().empty()) {
        error = "Le chemin du coffre doit désigner un fichier.";
        return false;
    }

    std::error_code filesystemError;

    if (!std::filesystem::is_directory(parentPath, filesystemError) ||
        filesystemError) {
        error = "Le dossier de destination n'existe pas ou est inaccessible.";
        return false;
    }

    const std::string temporaryPath = makeTemporaryPath(
        std::filesystem::path(
            parentPath / finalPath.filename()));

    const auto* passwordBytes =
        reinterpret_cast<const unsigned char*>(masterPassword.data());

    const auto password = std::span<const unsigned char>(
        passwordBytes, masterPassword.size());

    VaultKeyMetadata metadata;
    core::SecureBuffer candidateKey(0);

    const core::CryptoError cryptoResult =
        VaultKeyService::create(password, metadata, candidateKey);

    if (cryptoResult != core::CryptoError::None) {
        error = "Impossible de générer les clés du coffre.";
        return false;
    }

    TemporaryFiles temporaryFiles(temporaryPath);
    if (!storage::VaultStorage::createSchema(temporaryPath, error)) {
        return false;
    }
    // createSchema owns cleanup until it has successfully created the file.
    // In particular, a failed exclusive creation must not remove another file.
    temporaryFiles.active = true;

    if (!storage::VaultStorage::writeMetadata(
            temporaryPath, metadata, error)) {
        return false;
    }


    if (!syncFile(temporaryPath, error)) {
        return false;
    }

    // link() échoue si la destination existe : aucun écrasement.
    if (::link(temporaryPath.c_str(), databasePath.c_str()) != 0) {
        error = errno == EEXIST
            ? "Un fichier existe déjà à cet emplacement."
            : "Impossible de publier le coffre à son emplacement final.";

        return false;
    }

    // Publication is irreversible here: retain the existing post-publication
    // diagnostics, and never remove the final vault on a later failure.
    temporaryFiles.active = false;
    const bool temporaryRemoved =
        (::unlink(temporaryPath.c_str()) == 0);

    std::string syncError;

    if (!syncDirectory(parentPath, syncError)) {
        error =
            "Le coffre a été publié, mais la synchronisation du dossier "
            "a échoué. La durabilité après une panne n'est pas garantie. "
            + syncError;
        return false;
    }

    // Le coffre final est publié et le dossier a été synchronisé.
    dataKey = std::move(candidateKey);

    if (!temporaryRemoved) {
        error =
            "Le coffre a été créé, mais son nom temporaire n'a pas pu "
            "être supprimé. Le coffre final est disponible.";
    }

    return true;

}

bool VaultLifecycleService::unlockVault(
    const std::string& databasePath,
    const std::string& masterPassword,
    core::SecureBuffer& dataKey,
    std::string& error)
{
    error.clear();
    dataKey = core::SecureBuffer(0);

    if (databasePath.empty() || masterPassword.empty()) {
        error = "Le chemin du coffre et le mot de passe maître sont obligatoires.";
        return false;
    }

    storage::VaultOperationGuard access;
    if (!access.tryAccess(databasePath, error)) return false;
    if (!VaultPreferencesStore::checkRecoveryAccess(databasePath, error)) return false;
    services::VaultKeyMetadata metadata;

    if (!storage::VaultStorage::readMetadata(
            databasePath, metadata, error)) {
        return false;
    }

    const auto* passwordBytes =
        reinterpret_cast<const unsigned char*>(masterPassword.data());

    const auto password = std::span<const unsigned char>(
        passwordBytes, masterPassword.size());

    const core::CryptoError result =
        VaultKeyService::unlock(password, metadata, dataKey);

    if (result == core::CryptoError::None) {
        return true;
    }

    if (result == core::CryptoError::AuthenticationFailed) {
        error = "Mot de passe maître incorrect ou données cryptographiques altérées.";
    } else if (result == core::CryptoError::InvalidInput) {
        error = "Le format du coffre ou ses paramètres sont incompatibles ou invalides.";
    } else {
        error = "Impossible de déverrouiller le coffre.";
    }

    return false;
}

} // namespace passwall::services
