#include "services/vault_replacement_service.hpp"
#include "services/credential_service.hpp"
#include "services/vault_key_service.hpp"
#include "storage/vault_storage.hpp"

#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QUuid>
#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace passwall::services {
namespace {
struct Fd {
    int value = -1;
    Fd() = default;
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() noexcept { if (value >= 0) ::close(value); }
    void replace(int fd) noexcept { if (value >= 0) ::close(value); value = fd; }
};
bool fail(QString& error, const char* text) { error = QString::fromUtf8(text); return false; }
bool systemFailure(QString& error, const char* text) {
    const int code = errno;
    error = QString::fromUtf8(text) + " [errno=" + QString::number(code) + "].";
    return false;
}
bool safeParent(const QString& path, Fd& parent, QByteArray& leaf, QString& error) {
    const auto encoded = QFile::encodeName(path);
    if (encoded.contains('\0')) return fail(error, "Chemin de restauration invalide.");
    const std::filesystem::path parsed(encoded.constData());
    if (!parsed.is_absolute() || parsed.filename().empty()) return fail(error, "Chemin absolu requis.");
    for (const auto& part : parsed) if (part == "." || part == "..")
        return fail(error, "Composante de chemin ambiguë.");
    leaf = QByteArray(parsed.filename().c_str());
    parent.replace(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (parent.value < 0) return systemFailure(error, "Ouverture du dossier impossible");
    for (const auto& part : parsed.parent_path().relative_path()) {
        const int next = ::openat(parent.value, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) return systemFailure(error, "Dossier absent ou lien refusé");
        parent.replace(next);
        struct stat info {};
        if (::fstat(parent.value, &info) != 0 || !S_ISDIR(info.st_mode)
            || (info.st_uid != 0 && info.st_uid != ::geteuid())
            || ((info.st_mode & 0022) && !(info.st_uid == 0 && (info.st_mode & S_ISVTX))))
            return fail(error, "Dossier de restauration non protégé.");
    }
    return true;
}
bool sameRevision(const struct stat& a, const struct stat& b) noexcept {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size
        && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
        && a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec
        && S_ISREG(b.st_mode) && b.st_nlink == 1 && b.st_uid == ::geteuid() && !(b.st_mode & 0022);
}
// Retain the descriptor, name, parent identity and byte digest of the source.
// SQLite's coherent backup alone deliberately permits concurrent source writes;
// this stricter restoration path rejects changes we can observe instead.
struct StableSource {
    Fd parent, file;
    QByteArray leaf, hash;
    QString path;
    struct stat original {}, parentIdentity {};
    bool named(QString& error) const {
        Fd currentParent; QByteArray currentLeaf;
        struct stat p {}, current {}, opened {};
        if (!safeParent(path, currentParent, currentLeaf, error)
            || ::fstat(currentParent.value, &p) != 0
            || p.st_dev != parentIdentity.st_dev || p.st_ino != parentIdentity.st_ino
            || ::fstatat(currentParent.value, currentLeaf.constData(), &current, AT_SYMLINK_NOFOLLOW) != 0
            || ::fstat(file.value, &opened) != 0 || !sameRevision(original, current)
            || !sameRevision(original, opened)) return fail(error, "La sauvegarde source a changé.");
        return true;
    }
    bool digest(QByteArray& output, QString& error) const {
        if (!named(error)) return false;
        QCryptographicHash value(QCryptographicHash::Sha256);
        std::array<char, 65536> bytes {};
        off_t offset = 0;
        for (;;) {
            const auto count = ::pread(file.value, bytes.data(), bytes.size(), offset);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return systemFailure(error, "Lecture de la sauvegarde impossible");
            if (count == 0) break;
            value.addData(QByteArrayView(bytes.data(), count));
            offset += count; // bounded by the regular file's representable size
        }
        if (!named(error)) return false;
        output = value.result(); return true;
    }
    bool open(const QString& source, const VaultFileIdentity& principal, QString& error) {
        path = source;
        if (!safeParent(path, parent, leaf, error)) return false;
        file.value = ::openat(parent.value, leaf.constData(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (file.value < 0) return systemFailure(error, "Ouverture de la sauvegarde impossible");
        if (::fstat(parent.value, &parentIdentity) != 0 || ::fstat(file.value, &original) != 0
            || !sameRevision(original, original)) return fail(error, "Sauvegarde ambiguë ou non protégée.");
        if (quint64(original.st_dev) == principal.device && quint64(original.st_ino) == principal.inode)
            return fail(error, "La source est un alias du principal.");
        return digest(hash, error);
    }
    bool unchanged(QString& error) const {
        QByteArray current;
        return digest(current, error) && (current == hash || fail(error, "Contenu source modifié."));
    }
};
struct CandidateDirectory {
    const int parent;
    const QByteArray name;
    Fd directory;
    bool owned = false, retained = false;
    dev_t fileDevice = 0;
    ino_t fileInode = 0;
    CandidateDirectory(int parent, QByteArray name) : parent(parent), name(std::move(name)) {}
    ~CandidateDirectory() noexcept {
        // Only our unpublished, unreferenced private directory is reclaimed.
        // Once registry publication is attempted, retain it even on an error.
        if (!owned || retained) return;
        struct stat current {};
        if (directory.value >= 0 && fileInode
            && ::fstatat(directory.value, "candidate.db", &current, AT_SYMLINK_NOFOLLOW) == 0
            && current.st_dev == fileDevice && current.st_ino == fileInode)
            ::unlinkat(directory.value, "candidate.db", 0);
        ::unlinkat(parent, name.constData(), AT_REMOVEDIR);
    }
    bool create(QString& error) {
        if (::mkdirat(parent, name.constData(), 0700) != 0)
            return systemFailure(error, "Création du dossier candidat impossible");
        owned = true;
        directory.value = ::openat(parent, name.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat info {};
        if (directory.value < 0 || ::fstat(directory.value, &info) != 0
            || info.st_uid != ::geteuid() || (info.st_mode & 0777) != 0700)
            return fail(error, "Dossier candidat privé non confirmé.");
        return true;
    }
};
struct Authentication {
    VaultReplacementAuthorization& authority;
    core::SecureBuffer& password;
    const StableSource& source;
    const QByteArray& expectedVaultId;
    QByteArray authenticatedDigest;
    static bool check(void* value, SnapshotCheckpoint) noexcept {
        auto& context = *static_cast<Authentication*>(value);
        try {
            QString error;
            if (!context.authority.valid(error) || !context.source.named(error)) return true;
        } catch (...) { return true; }
        return false;
    }
    static bool verify(void* value, const std::string& path, std::string& error) {
        auto& context = *static_cast<Authentication*>(value);
        struct WipePassword {
            core::SecureBuffer& value;
            ~WipePassword() noexcept { value = core::SecureBuffer(0); }
        } wipe{context.password};
        VaultKeyMetadata metadata;
        if (!storage::VaultStorage::readMetadata(path, metadata, error)) return false;
        if (QByteArray(reinterpret_cast<const char*>(metadata.vaultId.data()), metadata.vaultId.size())
            != context.expectedVaultId) { error = "La sauvegarde appartient à une autre lignée de coffre."; return false; }
        core::SecureBuffer key(0);
        const auto code = VaultKeyService::unlock({context.password.data(), context.password.size()}, metadata, key);
        if (code != core::CryptoError::None) {
            error = "Mot de passe maître incorrect ou authentification du coffre impossible."; return false;
        }
        if (!CredentialService::authenticateAll(path, key, error)) return false;
        QString failure;
        if (!context.authority.valid(failure) || !context.source.unchanged(failure)) {
            error = "Source ou autorisation modifiée pendant l'authentification."; return false;
        }
        QFile encrypted(QString::fromStdString(path));
        if (!encrypted.open(QIODevice::ReadOnly)) { error = "Lecture du candidat authentifié impossible."; return false; }
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (!hash.addData(&encrypted) || encrypted.error() != QFile::NoError) {
            error = "Empreinte du candidat authentifié non confirmée."; return false;
        }
        context.authenticatedDigest = hash.result();
        // No DEK/credential/password survives this hook, before private candidate
        // publication by the snapshot engine, let alone the principal exchange.
        return true;
    }
};
} // namespace

bool VaultReplacementAuthorization::replacePrincipal(const QString& requestedPrincipal, const QString& selectedSource,
    core::SecureBuffer password, const QString& selectedPrecautionDestination,
    ReplacementResult& result, ReplacementControl control) noexcept
{
    bool armed = false;
    // Before engagement retain the caller's scoped authority for an explicit,
    // verified abandon. Afterwards release it, NEVER its persistent fence.
    struct Consume {
        VaultReplacementAuthorization& value;
        const bool& armed;
        ~Consume() noexcept { if (armed) value.reset(); }
    } consume{*this, armed};
    result.outcome = ReplacementOutcome::NotReplaced;
    result.diagnostic.clear();
    auto& error = result.diagnostic;
    const auto checkpoint = [&](ReplacementCheckpoint point) {
        if (!control.requested || !control.requested(control.context, point)) return false;
        if (!armed) result.outcome = ReplacementOutcome::CancelledBeforeEngagement;
        return true;
    };
    try {
        // A synchronous control callback may modify the caller's Qt state.
        // Pin metadata values before the first callback: never re-read aliased
        // path references to decide which names renameat2 will exchange.
        const QString principal = requestedPrincipal;
        const QString source = selectedSource;
        const QString precautionDestination = selectedPrecautionDestination;
        result = {};
        VaultRegistration registration; VaultReplacementIntent intent;
        if (!replacementContext(registration, intent, error) || intent.phase != "prepared" || intent.candidate)
            return fail(error, "Autorisation préparée sans candidat requise.");
        result.operationId = intent.operationId;
        if (principal != registration.file.path || password.empty())
            return fail(error, "Principal lié et mot de passe maître propriétaire requis.");
        if (checkpoint(ReplacementCheckpoint::BeforeWork)) return false;
        StableSource stable;
        if (!stable.open(source, registration.file, error)) return false;
        if (!registration.backup.automatic && precautionDestination.isEmpty())
            return fail(error, "Une destination de copie de précaution est obligatoire.");
        // No-existing-file semantics also reject all physical aliases. Never
        // defer this check until after an expensive authentication.
        if (!registration.backup.automatic) {
            Fd parent; QByteArray name; struct stat existing {};
            if (!safeParent(precautionDestination, parent, name, error)) return false;
            if (::fstatat(parent.value, name.constData(), &existing, AT_SYMLINK_NOFOLLOW) == 0
                || errno != ENOENT) return fail(error, "La destination de précaution existe ou est ambiguë.");
        }
        const QString parentPath = QFileInfo(principal).absolutePath();
        SnapshotDirectoryIdentity parentIdentity; std::string failure;
        if (!VaultSnapshotService::inspectDestinationDirectory(parentPath.toStdString(), parentIdentity, failure))
            return fail(error, failure.c_str());
        Fd principalParent; QByteArray principalName;
        if (!safeParent(principal, principalParent, principalName, error)) return false;
        CandidateDirectory candidate(principalParent.value,
            (".passwall-restore-" + intent.operationId).toUtf8());
        const QString candidatePath = parentPath + '/' + QString::fromUtf8(candidate.name) + "/candidate.db";
        if (!candidate.create(error)) return false;
        Authentication authentication{*this, password, stable, registration.file.vaultId, {}};
        SnapshotResult snapshot;
        const bool copied = VaultSnapshotService::createSnapshot(source.toStdString(), candidatePath.toStdString(),
            snapshot, {&Authentication::check, &authentication}, {&Authentication::verify, &authentication});
        password = core::SecureBuffer(0); // also when a pre-authentication snapshot check failed
        struct stat candidateFile {};
        if (::fstatat(candidate.directory.value, "candidate.db", &candidateFile, AT_SYMLINK_NOFOLLOW) == 0) {
            candidate.fileDevice = candidateFile.st_dev; candidate.fileInode = candidateFile.st_ino;
        }
        if (!copied || snapshot.publication != SnapshotPublication::Published)
            return fail(error, snapshot.diagnostic.empty() ? "Copie privée non confirmée." : snapshot.diagnostic.c_str());
        if (checkpoint(ReplacementCheckpoint::SourceAuthenticated)) return false;
        if (!valid(error) || !stable.unchanged(error)) return false;
        if (!registration.backup.automatic) {
            if (!snapshotPrincipal(precautionDestination.toStdString(), result.precaution)
                || result.precaution.publication != SnapshotPublication::Published)
                return fail(error, "Copie de précaution non confirmée ; remplacement interdit.");
        }
        if (checkpoint(ReplacementCheckpoint::PrecautionCreated)) return false;
        // The private candidate name will become the recovery name of the OLD
        // principal. Sync its new directory and its parent before recording it.
        if (::fsync(candidate.directory.value) != 0 || ::fsync(principalParent.value) != 0)
            return systemFailure(error, "Durabilité du dossier candidat non confirmée");
        result.recoveryArtifact = candidatePath; // allocate before any exchange
        candidate.retained = true; // a failed QSettings write may already be visible
        if (!stageCandidate(candidatePath, error, authentication.authenticatedDigest)) return false;
        if (checkpoint(ReplacementCheckpoint::CandidateStaged)) return false;
        if (!verifyBeforeExchange(error) || !stable.unchanged(error)) return false;
        if (checkpoint(ReplacementCheckpoint::BeforeArm)) return false;
        // Even a failed arm persistence may be visible. Conservatively retain
        // every artifact and never call abandonPreparation from this engine.
        result.outcome = ReplacementOutcome::EngagedRecoveryRequired;
        armed = true;
        if (!armPublication(error)) return false;
        if (checkpoint(ReplacementCheckpoint::Armed) || checkpoint(ReplacementCheckpoint::BeforeExchange)) return false;
        if (!verifyBeforeExchange(error) || !stable.unchanged(error)) return false;
        SnapshotDirectoryIdentity currentParent;
        if (!VaultSnapshotService::inspectDestinationDirectory(parentPath.toStdString(), currentParent, failure)
            || currentParent != parentIdentity) return fail(error, "Dossier principal remplacé avant substitution.");
        struct stat pinnedParent {}, namedCandidate {}, pinnedCandidate {};
        Fd candidateParent; QByteArray candidateName;
        if (!safeParent(candidatePath, candidateParent, candidateName, error)
            || ::fstat(principalParent.value, &pinnedParent) != 0
            || quint64(pinnedParent.st_dev) != parentIdentity.device || quint64(pinnedParent.st_ino) != parentIdentity.inode
            || ::fstat(candidate.directory.value, &pinnedCandidate) != 0
            || ::fstat(candidateParent.value, &namedCandidate) != 0
            || pinnedCandidate.st_dev != namedCandidate.st_dev || pinnedCandidate.st_ino != namedCandidate.st_ino)
            return fail(error, "Répertoires de substitution non confirmés.");
        if (!valid(error)) return false;
        if (::renameat2(principalParent.value, principalName.constData(), candidate.directory.value,
                        "candidate.db", RENAME_EXCHANGE) != 0)
            return systemFailure(error, "Échange atomique refusé ; récupération requise");
        // No allocation or callback before remembering irreversible substitution.
        result.outcome = ReplacementOutcome::ReplacedDurabilityUnconfirmed;
        if (checkpoint(ReplacementCheckpoint::AfterExchange)) return false;
        if (::fsync(candidate.directory.value) != 0 || ::fsync(principalParent.value) != 0)
            return systemFailure(error, "Échange effectué ; durabilité des répertoires non confirmée");
        if (checkpoint(ReplacementCheckpoint::AfterDirectorySync)) return false;
        result.outcome = ReplacementOutcome::ReplacedFinalizationPending;
        result.finalization = finalizePublication();
        if (result.finalization.state != ReplacementFinalizationState::Resolved) {
            error = result.finalization.diagnostic; return false;
        }
        result.outcome = ReplacementOutcome::Replaced;
        return true;
    } catch (...) {
        try { error = "Restauration interrompue ; consulter l'état et les éléments de récupération."; }
        catch (...) { error.clear(); }
        return false;
    }
}
} // namespace passwall::services
