#include "services/vault_replacement_authorization.hpp"
#include "services/vault_replacement_service.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QUuid>
#include <utility>
#include <atomic>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace passwall::services {
namespace {
bool fail(QString& error, const char* text) { error = QString::fromUtf8(text); return false; }
bool digest(const VaultFileIdentity& expected, QByteArray& output, QString& error)
{
    output.clear();
    const auto name = QFile::encodeName(expected.path);
    struct Fd { int value; ~Fd() noexcept { if (value >= 0) ::close(value); } };
    Fd owned{::open(name.constData(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
    const int fd = owned.value;
    if (fd < 0) return fail(error, "Lecture de l'empreinte du coffre impossible.");
    QFile file;
    if (!file.open(fd, QIODevice::ReadOnly, QFileDevice::DontCloseHandle)) {
        return fail(error, "Lecture de l'empreinte du coffre impossible.");
    }
    struct stat before {}, after {}, named {};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_uid != ::geteuid()
        || before.st_nlink != 1 || (before.st_mode & 0022)
        || quint64(before.st_dev) != expected.device || quint64(before.st_ino) != expected.inode)
        return fail(error, "Identité du coffre changée avant préparation.");
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file) || file.error() != QFile::NoError
        || ::fstat(fd, &after) != 0 || ::lstat(name.constData(), &named) != 0
        || named.st_dev != before.st_dev || named.st_ino != before.st_ino
        || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec
        || before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        return fail(error, "Empreinte du coffre non confirmée.");
    output = hash.result();
    return true;
}

bool syncIdentity(const VaultFileIdentity& expected, QString& error)
{
    // No followed parent components, no new SQLite connection, no allocation
    // in descriptor destructors. This does not promise a hardware flush beyond fsync.
    struct Fd { int value; ~Fd() noexcept { if (value >= 0) ::close(value); } };
    Fd parent{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    for (const auto& part : QFileInfo(expected.path).absolutePath().split('/', Qt::SkipEmptyParts)) {
        const auto name = QFile::encodeName(part);
        const int next = parent.value < 0 ? -1 : ::openat(parent.value, name.constData(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent.value >= 0) ::close(parent.value);
        parent.value = next;
    }
    const auto name = QFile::encodeName(QFileInfo(expected.path).fileName());
    Fd file{parent.value < 0 ? -1 : ::openat(parent.value, name.constData(),
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
    struct stat information {};
    if (file.value < 0 || ::fstat(file.value, &information) != 0
        || !S_ISREG(information.st_mode) || information.st_uid != ::geteuid()
        || information.st_nlink != 1 || (information.st_mode & 0022)
        || quint64(information.st_dev) != expected.device || quint64(information.st_ino) != expected.inode
        || ::fsync(file.value) != 0 || ::fsync(parent.value) != 0)
        return fail(error, "Identité ou synchronisation du coffre non confirmée ; récupération requise.");
    return true;
}

bool matchesCandidate(const VaultReplacementIntent& intent, const VaultFileIdentity& current)
{
    if (!intent.candidate) return false;
    auto expected = *intent.candidate;
    expected.path = intent.previous.path;
    return expected == current;
}
}
struct VaultReplacementAuthorization::State {
    VaultPreferencesStore store;
    VaultRegistration registration;
    VaultReplacementIntent intent;
    storage::VaultOperationGuard reservation, candidateReservation;
    std::function<bool()> cleanupStillValid;
    std::atomic<bool> live{true};
    bool preparing = false, delegated = false, acknowledged = false, persisted = false;
    explicit State(VaultPreferencesStore value) : store(std::move(value)) {}
};

VaultReplacementAuthorization::VaultReplacementAuthorization(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}
VaultReplacementAuthorization::~VaultReplacementAuthorization() noexcept { reset(); }
VaultReplacementAuthorization::VaultReplacementAuthorization(VaultReplacementAuthorization&& other) noexcept
    : state_(std::move(other.state_)) {}
VaultReplacementAuthorization& VaultReplacementAuthorization::operator=(VaultReplacementAuthorization&& other) noexcept
{
    if (this != &other) { reset(); state_ = std::move(other.state_); }
    return *this;
}
void VaultReplacementAuthorization::revoke(const std::shared_ptr<State>& state) noexcept
{
    if (!state) return;
    state->live = false;
    // The owner can revoke during secretless I/O, but must not close descriptors
    // underneath that I/O. The task retains the state until finishPreparation.
    if (state->preparing || state->delegated) return;
    state->reservation.reset();
    state->candidateReservation.reset();
}
void VaultReplacementAuthorization::reset() noexcept { revoke(state_); state_.reset(); }
bool VaultReplacementAuthorization::active(const std::shared_ptr<State>& state) noexcept
{ return state && state->live; }
bool VaultReplacementAuthorization::targetsSession(const std::shared_ptr<State>& state, const QString& path)
{
    return state && (path.isEmpty()
        || QDir::cleanPath(QFileInfo(path).absoluteFilePath()) == state->registration.file.path);
}
QString VaultReplacementAuthorization::operationId() const
{ return state_ ? state_->intent.operationId : QString{}; }
QString VaultReplacementAuthorization::localId() const
{ return state_ ? state_->registration.localId : QString{}; }

bool VaultReplacementAuthorization::delegationCurrent() const noexcept
{
    try {
        return active(state_) && state_->acknowledged && state_->persisted
            && state_->cleanupStillValid && state_->cleanupStillValid() && active(state_);
    } catch (...) { return false; }
}
std::array<int, 2> VaultReplacementAuthorization::delegationHandles() const noexcept
{ return state_ ? state_->reservation.inheritedHandles() : std::array<int, 2>{-1, -1}; }
QJsonObject VaultReplacementAuthorization::delegate(QString& error)
{
    if (!delegationCurrent() || state_->delegated || state_->intent.phase != "prepared"
        || state_->intent.candidate) {
        fail(error, "Autorisation non délégable ou déjà consommée."); return {};
    }
    const auto& f = state_->registration.file;
    QJsonObject result{{"config", state_->store.fileName()}, {"local", localId()}, {"operation", operationId()},
        {"principal", f.path}, {"device", QString::number(f.device)}, {"inode", QString::number(f.inode)},
        {"vault", QString::fromLatin1(f.vaultId.toHex())},
        {"digest", QString::fromLatin1(state_->intent.previousDigest.toHex())}};
    state_->delegated = true; // Only this session may now consume the grant.
    return result;
}
VaultReplacementAuthorization VaultReplacementAuthorization::receiveDelegation(
    const QJsonObject& message, std::array<int, 2> handles, std::function<bool()> check, QString& error)
{
    // Called only AFTER RestoreWorker verifies its OS parent/channel provenance.
    // A registry record, FD or JSON object alone never reaches this private API.
    const VaultPreferencesStore store(message["config"].toString());
    QVector<VaultRegistration> records;
    if (!check || !check() || !store.list(records, error)) return {};
    for (const auto& r : records) {
        if (r.localId != message["local"].toString()) continue;
        if (!r.replacement || r.replacement->phase != "prepared" || r.replacement->candidate
            || r.replacement->operationId != message["operation"].toString()
            || r.file.path != message["principal"].toString()
            || QString::number(r.file.device) != message["device"].toString()
            || QString::number(r.file.inode) != message["inode"].toString()
            || QString::fromLatin1(r.file.vaultId.toHex()) != message["vault"].toString()
            || QString::fromLatin1(r.replacement->previousDigest.toHex()) != message["digest"].toString()) break;
        auto state = std::make_shared<State>(store);
        state->registration = r; state->intent = *r.replacement;
        state->cleanupStillValid = std::move(check);
        std::string failure;
        if (!state->reservation.adoptReservation(r.file.path.toStdString(), handles, failure)) {
            error = QString::fromStdString(failure); return {};
        }
        state->acknowledged = state->persisted = state->delegated = true;
        VaultReplacementAuthorization authority(std::move(state));
        if (authority.valid(error)) return authority;
        return {};
    }
    fail(error, "Délégation et intention persistante incompatibles."); return {};
}

std::shared_ptr<VaultReplacementAuthorization::State> VaultReplacementAuthorization::reserve(
    const VaultPreferencesStore& store, const QString& localId,
    std::function<bool()> cleanupStillValid, QString& error)
{
    QVector<VaultRegistration> records;
    if (!store.list(records, error)) return {};
    auto state = std::make_shared<State>(store);
    state->cleanupStillValid = std::move(cleanupStillValid);
    bool found = false;
    for (const auto& record : records) if (record.localId == localId) {
        if (record.replacement) { fail(error, "Une récupération est déjà requise pour ce coffre."); return {}; }
        state->registration = record; found = true; break;
    }
    if (!found) { fail(error, "Coffre principal non enregistré."); return {}; }
    std::string failure;
    const auto& expected = state->registration.file;
    if (!state->reservation.tryReserve(expected.path.toStdString(), failure)) {
        error = QString::fromStdString(failure); return {};
    }
    state->intent.operationId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    state->intent.previous = expected;
    state->intent.phase = "prepared";
    return state;
}
VaultReplacementAuthorization VaultReplacementAuthorization::acknowledge(
    std::shared_ptr<State> state, QString& error)
{
    if (!beginPreparation(state, error)) return {};
    try { prepare(state, error); }
    catch (...) { state->preparing = false; revoke(state); throw; }
    return finishPreparation(std::move(state), error);
}
bool VaultReplacementAuthorization::beginPreparation(const std::shared_ptr<State>& state, QString& error)
{
    if (!active(state) || state->preparing || state->acknowledged || state->persisted
        || !state->cleanupStillValid || !state->cleanupStillValid()) {
        revoke(state); return fail(error, "Préparation de remplacement invalidée.");
    }
    state->preparing = true;
    return true;
}
bool VaultReplacementAuthorization::prepare(const std::shared_ptr<State>& state, QString& error)
{
    if (!active(state)) return fail(error, "Préparation de remplacement révoquée.");
    VaultFileIdentity current;
    if (!VaultPreferencesStore::inspectReserved(state->registration.file.path,
        state->reservation, current, error) || current != state->registration.file) {
        return false;
    }
    // Potentially slow SQL/hash I/O happens only AFTER the real cleanup ack,
    // never while an old GUI session still owns its data key.
    if (!digest(current, state->intent.previousDigest, error)) return false;
    // Only MainWindow can reach this boundary after real cleanup. Persist before
    // issuing anything that could later authorize publication. Failure (even
    // after an uncertain QSettings publication) never yields a capability.
    if (!active(state)) return fail(error, "Préparation de remplacement révoquée.");
    if (!state->store.writeReplacementIntent(state->registration.localId,
        state->registration.file, state->intent, error)) return false;
    state->persisted = true;
    return true;
}
VaultReplacementAuthorization VaultReplacementAuthorization::finishPreparation(
    std::shared_ptr<State> state, QString& error)
{
    if (!state) return {};
    state->preparing = false;
    // Last owner-thread physical check, no SQL/hash/fsync. Full persistent
    // proofs are checked again by the execution context before using them.
    struct stat identity {};
    const auto named = QFile::encodeName(state->registration.file.path);
    const bool sameFile = ::lstat(named.constData(), &identity) == 0 && S_ISREG(identity.st_mode)
        && identity.st_nlink == 1 && identity.st_uid == ::geteuid() && !(identity.st_mode & 0022)
        && quint64(identity.st_dev) == state->registration.file.device
        && quint64(identity.st_ino) == state->registration.file.inode;
    if (!sameFile || !active(state) || !state->persisted || !state->cleanupStillValid || !state->cleanupStillValid()) {
        revoke(state);
        if (error.isEmpty()) fail(error, "Protection ou nettoyage devenus invalides ; récupération requise.");
        return {};
    }
    state->acknowledged = true;
    return VaultReplacementAuthorization(std::move(state));
}
bool VaultReplacementAuthorization::valid(QString& error) const
{
    if (!active(state_) || !state_->acknowledged || !state_->persisted)
        return fail(error, "Autorisation de remplacement absente ou révoquée.");
    bool cleaned = false;
    try { cleaned = state_->cleanupStillValid && state_->cleanupStillValid(); } catch (...) {}
    if (!cleaned) { revoke(state_); return fail(error, "Protection ou nettoyage non confirmés."); }
    std::string failure;
    const bool reserved = state_->intent.phase == "armed" || state_->intent.phase == "identity-confirmed"
        ? ((state_->intent.candidate
            && state_->reservation.matchesReservation(state_->registration.file.path.toStdString(), failure)
            && state_->candidateReservation.matchesReservation(state_->intent.candidate->path.toStdString(), failure))
            || state_->reservation.matchesReplacement(state_->registration.file.path.toStdString(),
                state_->candidateReservation, failure))
        : state_->reservation.matchesReservation(state_->registration.file.path.toStdString(), failure);
    if (!reserved) { revoke(state_); return fail(error, "Réservation de remplacement non confirmée."); }
    QVector<VaultRegistration> records;
    if (!state_->store.list(records, error)) { revoke(state_); return false; }
    for (const auto& record : records)
        if (record.localId == localId() && record.file == (state_->intent.confirmed
                ? *state_->intent.confirmed : state_->registration.file)
            && record.replacement && *record.replacement == state_->intent) {
            // Registry/descriptor inspection can take time. Revalidate live
            // owner protection AFTER it too, especially immediately before an
            // exchange in the delegated execution context. The final permit is
            // an admission, not a promise to recall a syscall already admitted.
            try {
                if (active(state_) && state_->cleanupStillValid && state_->cleanupStillValid() && active(state_)) return true;
            } catch (...) {}
            break;
        }
    revoke(state_);
    return fail(error, "Intention de remplacement non confirmée.");
}
bool VaultReplacementAuthorization::abandonPreparation(QString& error)
{
    if (!valid(error)) return false;
    if (state_->intent.phase != "prepared")
        return fail(error, "Substitution potentielle : abandon automatique interdit.");
    VaultFileIdentity current;
    QByteArray currentDigest;
    if (!VaultPreferencesStore::inspectReserved(state_->registration.file.path,
        state_->reservation, current, error) || current != state_->intent.previous
        || !digest(current, currentDigest, error) || currentDigest != state_->intent.previousDigest)
        return fail(error, "Intégrité initiale non démontrée ; récupération requise.");
    if (!state_->store.resolveReplacement(localId(), state_->intent, current, false, error)) {
        reset(); return false;
    }
    reset(); return true;
}
bool VaultReplacementAuthorization::stageCandidate(const QString& path, QString& error,
    const QByteArray& authenticatedDigest)
{
    if (!valid(error) || state_->intent.phase != "prepared" || state_->intent.candidate) return false;
    if (path == state_->registration.file.path)
        return fail(error, "Le candidat ne peut pas être le coffre principal.");
    storage::VaultOperationGuard reserved;
    std::string failure;
    if (!reserved.tryReserve(path.toStdString(), failure)) {
        error = QString::fromStdString(failure); return false;
    }
    VaultFileIdentity candidate;
    if (!VaultPreferencesStore::inspectReserved(path, reserved, candidate, error)) return false;
    QVector<VaultRegistration> records;
    if (!state_->store.list(records, error)) return false;
    for (const auto& record : records)
        if (record.file.path == path || (record.file.device == candidate.device && record.file.inode == candidate.inode))
            return fail(error, "Le candidat appartient déjà à un coffre enregistré.");
    auto next = state_->intent;
    next.candidate = candidate;
    if (!digest(candidate, next.candidateDigest, error)) return false;
    if (!authenticatedDigest.isEmpty() && next.candidateDigest != authenticatedDigest)
        return fail(error, "Le candidat diffère de la copie intégralement authentifiée.");
    next.recoveryArtifacts = {path};
    if (!state_->store.writeReplacementIntent(localId(), state_->registration.file, next, error)) {
        reset(); return false;
    }
    state_->intent = std::move(next);
    state_->candidateReservation = std::move(reserved);
    return true;
}
bool VaultReplacementAuthorization::replacementContext(VaultRegistration& record,
    VaultReplacementIntent& intent, QString& error) const
{
    if (!valid(error)) return false;
    record = state_->registration;
    intent = state_->intent;
    return true;
}
bool VaultReplacementAuthorization::verifyBeforeExchange(QString& error) const
{
    if (!valid(error) || !state_->intent.candidate || state_->intent.candidateDigest.size() != 32)
        return fail(error, "Preuves de publication incomplètes.");
    VaultFileIdentity old, candidate;
    QByteArray oldHash, candidateHash;
    if (!VaultPreferencesStore::inspectReserved(state_->intent.previous.path,
            state_->reservation, old, error) || old != state_->intent.previous
        || !VaultPreferencesStore::inspectReserved(state_->intent.candidate->path,
            state_->candidateReservation, candidate, error) || candidate != *state_->intent.candidate
        || !digest(old, oldHash, error) || oldHash != state_->intent.previousDigest
        || !digest(candidate, candidateHash, error) || candidateHash != state_->intent.candidateDigest
        || !syncIdentity(old, error) || !syncIdentity(candidate, error))
        return fail(error, "Identité, contenu ou durabilité modifiés avant substitution ; récupération requise.");
    return valid(error);
}
bool VaultReplacementAuthorization::armPublication(QString& error)
{
    if (!valid(error) || state_->intent.phase != "prepared" || !state_->intent.candidate)
        return fail(error, "Candidat de remplacement non préparé.");
    std::string failure;
    if (!state_->candidateReservation.matchesReservation(state_->intent.candidate->path.toStdString(), failure))
        return fail(error, "Réservation du candidat non confirmée.");
    auto next = state_->intent;
    next.phase = "armed";
    if (!state_->store.writeReplacementIntent(localId(), state_->registration.file, next, error)) {
        reset(); return false;
    }
    state_->intent = std::move(next);
    return true;
}
ReplacementFinalizationResult VaultReplacementAuthorization::finalizePublication()
{
    ReplacementFinalizationResult result;
    auto& error = result.diagnostic;
    try {
        if (!state_) { fail(error, "Autorisation de finalisation absente."); return result; }
        result.state = ReplacementFinalizationState::RecoveryRequired;
        if (!valid(error) || (state_->intent.phase != "armed" && state_->intent.phase != "identity-confirmed")
            || !state_->intent.candidate) {
            if (error.isEmpty()) fail(error, "Phase de publication non autorisée.");
            return result;
        }
        std::string failure;
        if (!state_->reservation.matchesReplacement(state_->registration.file.path.toStdString(),
            state_->candidateReservation, failure)) {
            fail(error, "Identité publiée non confirmée ; récupération requise."); return result;
        }
        VaultFileIdentity current;
        if (!VaultPreferencesStore::inspect(state_->registration.file.path, &state_->reservation, current, error)
            || !matchesCandidate(state_->intent, current)) {
            if (error.isEmpty()) fail(error, "Identité publiée étrangère au candidat autorisé.");
            return result;
        }
        // Future 6B exchange must retain the OLD inode at the candidate name.
        // Never infer it from the disappearance of an artifact.
        auto previous = state_->intent.previous;
        previous.path = state_->intent.candidate->path;
        VaultFileIdentity oldCurrent;
        QByteArray previousDigest, candidateDigest;
        if (!VaultPreferencesStore::inspect(previous.path, &state_->reservation, oldCurrent, error)
            || oldCurrent != previous || !digest(previous, previousDigest, error)
            || previousDigest != state_->intent.previousDigest
            || (!state_->intent.candidateDigest.isEmpty()
                && (!digest(current, candidateDigest, error) || candidateDigest != state_->intent.candidateDigest))
            || !syncIdentity(current, error) || !syncIdentity(previous, error)) {
            if (error.isEmpty()) fail(error, "Identité ou empreinte de l'ancien principal non confirmée.");
            return result;
        }
        if (!valid(error)) return result;
        result.state = ReplacementFinalizationState::IdentityUnconfirmed;
        if (!state_->store.confirmReplacementIdentity(localId(), state_->intent, current, error)) return result;
        result.state = ReplacementFinalizationState::IdentityConfirmedResolutionPending;
        state_->intent.phase = "identity-confirmed";
        state_->intent.confirmed = current;
        if (!valid(error)) return result;
        // From here both possible on-disk states are safe: protected confirmed
        // identity, or a resolved receipt referring to that SAME identity.
        result.state = ReplacementFinalizationState::SafeResolutionUnconfirmed;
        RegistryPersistence persistence;
        if (!state_->store.resolveReplacement(localId(), state_->intent, current, true, error, &persistence)) {
            if (persistence == RegistryPersistence::NotAttempted)
                result.state = ReplacementFinalizationState::IdentityConfirmedResolutionPending;
            return result;
        }
        result.state = ReplacementFinalizationState::Resolved;
        reset();
    } catch (...) {
        try { error = "Finalisation interrompue ; consulter son état et les preuves de récupération."; }
        catch (...) { error.clear(); }
    }
    return result;
}

ReplacementFinalizationResult VaultReplacementAuthorization::resumeFinalization(
    const VaultPreferencesStore& store, const QString& localId, const QString& operationId)
{
    ReplacementFinalizationResult result{ReplacementFinalizationState::RecoveryRequired, {}};
    auto& error = result.diagnostic;
    try {
        QVector<VaultRegistration> records;
        if (!store.list(records, error)) return result;
        for (const auto& record : records) {
            if (record.localId != localId) continue;
            const auto intent = record.replacement ? record.replacement : record.resolvedReplacement;
            if (!intent || intent->operationId != operationId || !intent->confirmed
                || (intent->phase != "identity-confirmed" && intent->phase != "resolved")) {
                fail(error, "Opération non confirmée ou UUID de récupération différent."); return result;
            }
            storage::VaultOperationGuard principal, oldArtifact;
            std::string failure;
            if (!principal.tryReserve(record.file.path.toStdString(), failure)) {
                error = QString::fromStdString(failure); return result;
            }
            VaultFileIdentity current;
            if (!VaultPreferencesStore::inspectReserved(record.file.path, principal, current, error)
                || current != *intent->confirmed || !matchesCandidate(*intent, current)) {
                fail(error, "Identité de récupération inattendue ; blocage conservé."); return result;
            }
            if (intent->phase == "identity-confirmed") {
                auto previous = intent->previous;
                previous.path = intent->candidate->path;
                if (!oldArtifact.tryReserve(previous.path.toStdString(), failure)) {
                    error = QString::fromStdString(failure); return result;
                }
                VaultFileIdentity oldCurrent;
                QByteArray originalDigest, candidateDigest;
                if (!VaultPreferencesStore::inspectReserved(previous.path, oldArtifact, oldCurrent, error)
                    || oldCurrent != previous || !digest(previous, originalDigest, error)
                    || originalDigest != intent->previousDigest
                    || (!intent->candidateDigest.isEmpty()
                        && (!digest(current, candidateDigest, error) || candidateDigest != intent->candidateDigest))
                    || !syncIdentity(current, error) || !syncIdentity(previous, error)) {
                    if (error.isEmpty()) fail(error, "Identité ou empreinte de récupération non confirmée.");
                    return result;
                }
                result.state = ReplacementFinalizationState::IdentityUnconfirmed;
                // Re-confirm even a visible phase from a failed previous fsync.
                if (!store.confirmReplacementIdentity(localId, *intent, current, error)) return result;
            }
            // This path never issues an authority and never swaps/deletes files.
            result.state = ReplacementFinalizationState::SafeResolutionUnconfirmed;
            RegistryPersistence persistence;
            if (!store.resolveReplacement(localId, *intent, current, true, error, &persistence)) {
                if (persistence == RegistryPersistence::NotAttempted)
                    result.state = ReplacementFinalizationState::IdentityConfirmedResolutionPending;
                return result;
            }
            result.state = ReplacementFinalizationState::Resolved;
            return result;
        }
        fail(error, "Coffre de récupération inconnu.");
    } catch (...) {
        try { error = "Reprise interrompue ; aucune substitution ni suppression effectuée."; }
        catch (...) { error.clear(); }
    }
    return result;
}

ReplacementRecoveryResult VaultReplacementAuthorization::recoverReplacement(
    const VaultPreferencesStore& store, const QString& localId, const QString& operationId,
    ReplacementRecoveryAction action)
{
    ReplacementRecoveryResult result;
    auto& error = result.diagnostic;
    try {
        QVector<VaultRegistration> records;
        if (!store.list(records, error)) return result;
        for (const auto& record : records) {
            if (record.localId != localId) continue;
            const auto intent = record.replacement ? record.replacement : record.resolvedReplacement;
            if (!intent || intent->operationId != operationId)
                { fail(error, "UUID ou intention de récupération non confirmé."); return result; }
            if (intent->phase == "identity-confirmed" || intent->phase == "resolved") {
                if (action == ReplacementRecoveryAction::FinalizeExchanged) {
                    result.finalization = resumeFinalization(store, localId, operationId);
                    if (result.finalization.state == ReplacementFinalizationState::Resolved)
                        result.layout = ReplacementLayout::Resolved;
                    error = result.finalization.diagnostic;
                } else {
                    storage::VaultOperationGuard guard;
                    std::string failure;
                    VaultFileIdentity current;
                    if (!guard.tryReserve(record.file.path.toStdString(), failure)
                        || !VaultPreferencesStore::inspectReserved(record.file.path, guard, current, error)
                        || !intent->confirmed || current != *intent->confirmed) {
                        fail(error, "Identité confirmée introuvable ou réservée."); return result;
                    }
                    result.layout = intent->phase == "resolved" ? ReplacementLayout::Resolved
                        : ReplacementLayout::IdentityConfirmed;
                }
                return result;
            }
            storage::VaultOperationGuard principal, artifact;
            std::string failure;
            if (!principal.tryReserve(intent->previous.path.toStdString(), failure))
                { error = QString::fromStdString(failure); return result; }
            VaultFileIdentity current;
            QByteArray currentHash;
            if (!VaultPreferencesStore::inspectReserved(intent->previous.path, principal, current, error)
                || !digest(current, currentHash, error)) return result;
            if (intent->phase == "prepared") {
                if (current == intent->previous && currentHash == intent->previousDigest)
                    result.layout = ReplacementLayout::PreparedIntact;
                else fail(error, "Principal préparé inattendu ; récupération requise.");
                // No cleanup acknowledgement after restart: never abandon or
                // authorize publication from a record alone.
                return result;
            }
            if (intent->phase != "armed" || !intent->candidate || intent->candidateDigest.size() != 32
                || !intent->recoveryArtifacts.contains(intent->candidate->path)) {
                fail(error, "Preuves persistantes de substitution insuffisantes."); return result;
            }
            if (!artifact.tryReserve(intent->candidate->path.toStdString(), failure))
                { error = QString::fromStdString(failure); return result; }
            VaultFileIdentity other;
            QByteArray otherHash;
            if (!VaultPreferencesStore::inspectReserved(intent->candidate->path, artifact, other, error)
                || !digest(other, otherHash, error)) return result;
            if (current == intent->previous && other == *intent->candidate
                && currentHash == intent->previousDigest && otherHash == intent->candidateDigest) {
                result.layout = ReplacementLayout::ArmedBeforeExchange;
                // Deliberately no second exchange, no release of the fence.
                return result;
            }
            auto expectedNew = *intent->candidate; expectedNew.path = intent->previous.path;
            auto expectedOld = intent->previous; expectedOld.path = intent->candidate->path;
            if (current != expectedNew || other != expectedOld
                || currentHash != intent->candidateDigest || otherHash != intent->previousDigest) {
                fail(error, "Disposition ou contenu de récupération inattendus ; blocage conservé."); return result;
            }
            result.layout = ReplacementLayout::ArmedAfterExchange;
            if (action == ReplacementRecoveryAction::Inspect) return result;
            result.finalization.state = ReplacementFinalizationState::RecoveryRequired;
            if (!syncIdentity(current, error) || !syncIdentity(other, error)) return result;
            result.finalization.state = ReplacementFinalizationState::IdentityUnconfirmed;
            // Same two protected CAS/durability transitions as live finalization,
            // under both fresh exclusive reservations. No new phase or journal.
            if (!store.confirmReplacementIdentity(localId, *intent, current, error)) return result;
            result.finalization.state = ReplacementFinalizationState::IdentityConfirmedResolutionPending;
            auto confirmed = *intent; confirmed.phase = "identity-confirmed"; confirmed.confirmed = current;
            result.finalization.state = ReplacementFinalizationState::SafeResolutionUnconfirmed;
            RegistryPersistence persistence;
            if (!store.resolveReplacement(localId, confirmed, current, true, error, &persistence)) {
                if (persistence == RegistryPersistence::NotAttempted)
                    result.finalization.state = ReplacementFinalizationState::IdentityConfirmedResolutionPending;
                return result;
            }
            result.finalization.state = ReplacementFinalizationState::Resolved;
            result.layout = ReplacementLayout::Resolved;
            return result;
        }
        fail(error, "Coffre de récupération inconnu.");
    } catch (...) {
        try { error = "Inspection interrompue ; aucun échange ni effacement effectué."; }
        catch (...) { error.clear(); }
    }
    return result;
}

bool VaultReplacementAuthorization::permitsSnapshot(const std::string& source,
    const storage::VaultOperationGuard& reservation, SnapshotCheckpoint checkpoint, std::string& error) const
{
    QString failure;
    if (!valid(failure) || !state_ || state_->intent.phase != "prepared"
        || &reservation != &state_->reservation || source != state_->intent.previous.path.toStdString()) {
        error = "Lecture du principal non autorisée par l'opération de restauration."; return false;
    }
    if (checkpoint == SnapshotCheckpoint::BeforeWork || checkpoint == SnapshotCheckpoint::BeforePublication) {
        VaultFileIdentity current;
        QByteArray originalDigest;
        if (!VaultPreferencesStore::inspectReserved(state_->intent.previous.path, reservation, current, failure)
            || current != state_->intent.previous || !digest(current, originalDigest, failure)
            || originalDigest != state_->intent.previousDigest) {
            error = "Identité ou contenu initial du principal modifiés ; lecture refusée."; return false;
        }
    }
    return true;
}

bool VaultReplacementAuthorization::snapshotPrincipal(const std::string& destination,
    SnapshotResult& result, SnapshotCancellation cancellation) const
{
    result = {};
    // A cancellation callback can revoke this authority. Keep its State alive
    // so the borrowed reservation object never becomes a dangling reference.
    const auto retained = state_;
    if (!retained) { result.diagnostic = "Autorisation de lecture absente."; return false; }
    const auto source = retained->intent.previous.path.toStdString();
    struct Context {
        const VaultReplacementAuthorization& authority;
        const storage::VaultOperationGuard& reservation;
        const std::string& source;
    } context{*this, retained->reservation, source};
    const VaultSnapshotService::ReplacementReadCheck permission{
        [](void* value, SnapshotCheckpoint point, std::string& error) {
            const auto& c = *static_cast<Context*>(value);
            return c.authority.permitsSnapshot(c.source, c.reservation, point, error);
        }, &context};
    return VaultSnapshotService::createReplacementSnapshot(source,
        destination, result, cancellation, retained->reservation, permission);
}
} // namespace passwall::services
