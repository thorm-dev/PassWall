#include "services/vault_preferences_store.hpp"
#include "storage/sqlite_connection_config.hpp"
#include "storage/vault_operation_guard.hpp"

#include <QDir>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QScopeGuard>
#include <QSettings>
#include <QTemporaryFile>
#include <QUuid>

#include <sqlite3.h>
#include <algorithm>
#include <cerrno>
#include <memory>
#include <utility>
#include <limits>
#ifdef Q_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace passwall::services {
namespace {
constexpr auto RegistryKey = "vaultRegistry/data";
constexpr qint64 MaxConfigBytes = 16 * 1024 * 1024;

bool fail(QString& error, const char* message)
{
    error = QString::fromUtf8(message);
    return false;
}

bool absolutePath(const QString& path)
{
    return !path.isEmpty() && !path.contains(QChar::Null)
        && QFileInfo(path).isAbsolute() && QDir::cleanPath(path) == path;
}

#ifdef Q_OS_UNIX
struct Fd {
    int value = -1;
    ~Fd() { if (value >= 0) ::close(value); }
};

// Walk every component without following symlinks, not just the leaf.
int openDirectory(const QString& path)
{
    Fd current{::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (current.value < 0)
        return -1;
    for (const auto& part : path.split('/', Qt::SkipEmptyParts)) {
        const auto name = QFile::encodeName(part);
        const int next = ::openat(current.value, name.constData(),
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
            return -1;
        ::close(current.value);
        current.value = next;
    }
    return std::exchange(current.value, -1);
}

QString birthTime(int fd)
{
#ifdef Q_OS_LINUX
    struct statx information {};
    if (::statx(fd, "", AT_EMPTY_PATH, STATX_BTIME, &information) == 0
        && (information.stx_mask & STATX_BTIME))
        return QString::number(information.stx_btime.tv_sec) + ':'
            + QString::number(information.stx_btime.tv_nsec);
#else
    Q_UNUSED(fd);
#endif
    return {};
}
#endif

bool prepareSettings(const QString& path, QString& error)
{
    if (!absolutePath(path))
        return fail(error, "Chemin de configuration invalide.");
    const QFileInfo file(path);
    const QString parent = file.absolutePath();
    if (parent == "/" || parent == QDir::homePath() || parent == QDir::tempPath())
        return fail(error, "La configuration exige un répertoire applicatif dédié.");
    if (!QDir().mkpath(parent))
        return fail(error, "Impossible de créer le répertoire de configuration.");
#ifdef Q_OS_UNIX
    Fd directory{openDirectory(parent)};
    struct stat info {};
    if (directory.value < 0 || ::fstat(directory.value, &info) != 0
        || info.st_uid != ::geteuid() || ::fchmod(directory.value, 0700) != 0)
        return fail(error, "Répertoire de configuration non sûr ou inaccessible.");
    const auto name = QFile::encodeName(file.fileName());
    Fd descriptor{::openat(directory.value, name.constData(),
                          O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
    if (descriptor.value < 0) {
        if (errno != ENOENT)
            return fail(error, "Fichier de configuration inaccessible ou non sûr.");
    } else if (::fstat(descriptor.value, &info) != 0 || !S_ISREG(info.st_mode)
               || info.st_uid != ::geteuid() || info.st_nlink != 1
               || info.st_size > MaxConfigBytes || ::fchmod(descriptor.value, 0600) != 0) {
        return fail(error, "Fichier de configuration non sûr ou trop volumineux.");
    }
#else
    if (file.isSymLink() || (file.exists() && (!file.isFile() || file.size() > MaxConfigBytes)))
        return fail(error, "Fichier de configuration invalide.");
#endif
    return true;
}

bool validPreferences(const VaultBackupPreferences& value)
{
    return value.retainedVersions > 0
        && (value.directory.isEmpty() || absolutePath(value.directory))
        && (!value.automatic || !value.directory.isEmpty());
}

bool readRegistryOnDisk(const QString& path, QVariant& registry, QString& error)
{
    registry = {};
    QFile source(path);
    if (!source.exists())
        return true;
    if (!source.open(QIODevice::ReadOnly) || source.size() > MaxConfigBytes)
        return fail(error, "Lecture du fichier de configuration impossible.");
    const QByteArray bytes = source.readAll();
    if (source.error() != QFile::NoError)
        return fail(error, "Lecture du fichier de configuration incomplète.");
    // QSettings shares a filename-based cache, but a parse error belongs to the
    // instance that first read the file. A new instance can lose that error and
    // silently normalize malformed INI. Validate physical bytes under a unique
    // temporary name (0600, inside the private parent), before ANY sync/write.
    // This also avoids reading stale registry authorizations from Qt's cache.
    QTemporaryFile snapshot(path + ".validate-XXXXXX");
    if (!snapshot.open() || snapshot.write(bytes) != bytes.size() || !snapshot.flush())
        return fail(error, "Impossible de valider la configuration sans la modifier.");
    snapshot.close();
    QSettings fresh(snapshot.fileName(), QSettings::IniFormat);
    fresh.setFallbacksEnabled(false);
    (void)fresh.allKeys();
    if (fresh.status() != QSettings::NoError)
        return fail(error, "Configuration INI corrompue ; aucune réinitialisation effectuée.");
    registry = fresh.value(RegistryKey);
    return true;
}

QJsonObject encodeIdentity(const VaultFileIdentity& file)
{
    return {{"path", file.path}, {"vaultId", QString::fromLatin1(file.vaultId.toHex())},
            {"device", QString::number(file.device)}, {"inode", QString::number(file.inode)},
            {"birthTime", file.birthTime}};
}

bool unsignedNumber(const QJsonValue& value, quint64& output)
{
    if (!value.isString())
        return false;
    const auto string = value.toString();
    bool ok = false;
    output = string.toULongLong(&ok);
    return ok && QString::number(output) == string;
}

bool decodeIdentity(const QJsonObject& object, VaultFileIdentity& file)
{
    file.path = object["path"].toString();
    const auto hex = object["vaultId"].toString();
    file.vaultId = QByteArray::fromHex(hex.toLatin1());
    file.birthTime = object["birthTime"].toString();
    return absolutePath(file.path) && file.vaultId.size() == 16
        && QString::fromLatin1(file.vaultId.toHex()) == hex
        && object["birthTime"].isString()
        && unsignedNumber(object["device"], file.device)
        && unsignedNumber(object["inode"], file.inode) && file.inode != 0;
}

bool recoveryAllowed(const QVector<VaultRegistration>& records, const QString& path, QString& error)
{
    const auto normalized = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    quint64 device = 0, inode = 0;
#ifdef Q_OS_UNIX
    struct stat info {};
    const auto encoded = QFile::encodeName(path);
    if (::lstat(encoded.constData(), &info) == 0) { device = info.st_dev; inode = info.st_ino; }
#endif
    for (const auto& record : records) {
        if (record.resolvedReplacement && !record.replacement) {
            const auto& receipt = *record.resolvedReplacement;
            const bool principal = normalized == record.file.path
                || (inode && device == record.file.device && inode == record.file.inode);
            if (principal) {
#ifdef Q_OS_UNIX
                // No SQL/shared flock here: callers may already own either a
                // shared business guard or an exclusive policy reservation.
                Fd parent{openDirectory(QFileInfo(path).absolutePath())};
                const auto name = QFile::encodeName(QFileInfo(path).fileName());
                Fd fd{parent.value < 0 ? -1 : ::openat(parent.value, name.constData(),
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
                struct stat current {};
                if (fd.value < 0 || ::fstat(fd.value, &current) != 0
                    || !S_ISREG(current.st_mode) || current.st_uid != ::geteuid()
                    || current.st_nlink != 1 || (current.st_mode & 0022)
                    || quint64(current.st_dev) != record.file.device
                    || quint64(current.st_ino) != record.file.inode
                    || birthTime(fd.value) != record.file.birthTime)
                    return fail(error, "Identité résolue remplacée ou ambiguë ; récupération requise.");
#else
                return fail(error, "Identité résolue invérifiable sur cette plateforme.");
#endif
            } else if ((inode && device == receipt.previous.device && inode == receipt.previous.inode)
                || (receipt.candidate && normalized == receipt.candidate->path)) {
                return fail(error, "Artefact technique de récupération ; accès ordinaire refusé.");
            }
        }
        if (!record.replacement) continue;
        const auto matches = [&](const VaultFileIdentity& identity) {
            return identity.path == normalized
                || (inode && identity.device == device && identity.inode == inode);
        };
        if (matches(record.file) || matches(record.replacement->previous)
            || (record.replacement->candidate && matches(*record.replacement->candidate)))
            return fail(error, "Restauration en préparation ou interrompue : récupération contrôlée requise.");
    }
    return true;
}

bool decodeReplacement(const QJsonObject& r, VaultReplacementIntent& intent, QString& error)
{
    intent.operationId = r["operation"].toString();
    intent.phase = r["phase"].toString();
    const auto digest = r["previousDigest"].toString();
    intent.previousDigest = QByteArray::fromHex(digest.toLatin1());
    if (r["version"] != 1 || QUuid(intent.operationId).isNull()
        || QUuid(intent.operationId).toString(QUuid::WithoutBraces) != intent.operationId
        || (intent.phase != "prepared" && intent.phase != "armed"
            && intent.phase != "identity-confirmed" && intent.phase != "resolved")
        || !decodeIdentity(r["previous"].toObject(), intent.previous)
        || intent.previousDigest.size() != 32
        || QString::fromLatin1(intent.previousDigest.toHex()) != digest || !r["artifacts"].isArray())
        return fail(error, "Intention de restauration invalide ; récupération indéterminée.");
    if (r.contains("candidate")) {
        VaultFileIdentity candidate;
        if (!decodeIdentity(r["candidate"].toObject(), candidate)
            || candidate.path == intent.previous.path
            || (candidate.device == intent.previous.device && candidate.inode == intent.previous.inode))
            return fail(error, "Candidat de restauration ambigu.");
        intent.candidate = std::move(candidate);
    }
    if (r.contains("candidateDigest")) {
        const auto hex = r["candidateDigest"].toString();
        intent.candidateDigest = QByteArray::fromHex(hex.toLatin1());
        if (!intent.candidate || intent.candidateDigest.size() != 32
            || QString::fromLatin1(intent.candidateDigest.toHex()) != hex)
            return fail(error, "Empreinte du candidat de restauration invalide.");
    }
    for (const auto& artifact : r["artifacts"].toArray()) {
        if (!artifact.isString() || !absolutePath(artifact.toString())
            || artifact.toString() == intent.previous.path)
            return fail(error, "Référence de récupération invalide.");
        intent.recoveryArtifacts.append(artifact.toString());
    }
    if (intent.phase != "prepared" && !intent.candidate)
        return fail(error, "Intention de substitution incomplète.");
    if (r.contains("confirmed")) {
        VaultFileIdentity confirmed;
        if (!decodeIdentity(r["confirmed"].toObject(), confirmed) || !intent.candidate)
            return fail(error, "Identité confirmée incomplète.");
        auto expected = *intent.candidate;
        expected.path = intent.previous.path;
        if (confirmed != expected)
            return fail(error, "Identité confirmée étrangère au candidat.");
        intent.confirmed = std::move(confirmed);
    }
    if ((intent.phase == "identity-confirmed" || intent.phase == "resolved") != intent.confirmed.has_value())
        return fail(error, "Phase de confirmation incohérente.");
    if (intent.confirmed && !intent.recoveryArtifacts.contains(intent.candidate->path))
        return fail(error, "Référence de récupération confirmée manquante.");
    return true;
}

QJsonObject encodeReplacement(const VaultReplacementIntent& r)
{
    QJsonArray artifacts;
    for (const auto& path : r.recoveryArtifacts) artifacts.append(path);
    QJsonObject intent{{"version", 1}, {"operation", r.operationId},
        {"previous", encodeIdentity(r.previous)},
        {"previousDigest", QString::fromLatin1(r.previousDigest.toHex())},
        {"phase", r.phase}, {"artifacts", artifacts}};
    if (r.candidate) intent.insert("candidate", encodeIdentity(*r.candidate));
    if (!r.candidateDigest.isEmpty())
        intent.insert("candidateDigest", QString::fromLatin1(r.candidateDigest.toHex()));
    if (r.confirmed) intent.insert("confirmed", encodeIdentity(*r.confirmed));
    return intent;
}

bool decode(const QJsonObject& root, QVector<VaultRegistration>& records, QString& error)
{
    if (root.value("version") != QJsonValue(1) || !root.value("vaults").isArray())
        return fail(error, "Version ou structure du registre invalide.");
    for (const auto& value : root.value("vaults").toArray()) {
        const auto object = value.toObject();
        VaultRegistration record;
        record.localId = object.value("localId").toString();
        const QUuid id(record.localId);
        const auto file = object.value("file").toObject();
        record.file.path = file.value("path").toString();
        const QString hex = file.value("vaultId").toString();
        record.file.vaultId = QByteArray::fromHex(hex.toLatin1());
        record.file.birthTime = file.value("birthTime").toString();
        if (object.contains("replacement")) {
            VaultReplacementIntent intent;
            if (!decodeReplacement(object["replacement"].toObject(), intent, error)
                || intent.phase == "resolved")
                return fail(error, "Intention active de restauration invalide.");
            record.replacement = std::move(intent);
        }
        if (object.contains("resolvedReplacement")) {
            VaultReplacementIntent receipt;
            if (!decodeReplacement(object["resolvedReplacement"].toObject(), receipt, error)
                || receipt.phase != "resolved")
                return fail(error, "Reçu de restauration invalide.");
            record.resolvedReplacement = std::move(receipt);
        }
        const auto backup = object.value("backup").toObject();
        record.backup.automatic = backup.value("automatic").toBool();
        record.backup.directory = backup.value("directory").toString();
        record.backup.retainedVersions = backup.value("retainedVersions").toInt(0);
        const auto required = object.value("backupRequired");
        record.backupRequired = required.toBool();
        const auto state = object.value("automaticState");
        if (!state.isUndefined()) {
            const auto automatic = state.toObject();
            const auto device = automatic["device"], inode = automatic["inode"];
            quint64 a = 0, b = 0;
            record.automaticSuspended = automatic["suspended"].toBool();
            record.backupAttempt = automatic["attempt"].toString();
            record.backupAttemptDestination = automatic["destination"].toString();
            if (!state.isObject() || !automatic["suspended"].isBool()
                || !automatic["attempt"].isString() || !automatic["destination"].isString()
                || !unsignedNumber(device, a) || !unsignedNumber(inode, b)
                || (!record.backupAttempt.isEmpty() && QUuid(record.backupAttempt).isNull())
                || (!record.backupAttemptDestination.isEmpty() && !absolutePath(record.backupAttemptDestination)))
                return fail(error, "État de sauvegarde automatique invalide.");
            record.backupDirectory = {a, b};
        }
        const auto versions = object.value("automaticVersions");
        if (object.contains("automaticOrder") && !unsignedNumber(object["automaticOrder"], record.automaticOrder))
            return fail(error, "Ordre des sauvegardes invalide.");
        record.backupEpoch = object.value("backupEpoch").toString();
        if (object.contains("backupEpoch") && (!object["backupEpoch"].isString()
            || (!record.backupEpoch.isEmpty() && QUuid(record.backupEpoch).isNull())))
            return fail(error, "Génération de destination invalide.");
        const auto rotation = object.value("rotation");
        if (!rotation.isUndefined()) {
            const auto r = rotation.toObject();
            record.rotationAttempt = r["attempt"].toString();
            record.rotationState = r["state"].toString();
            record.rotationCandidate = r["candidate"].toString();
            if (!rotation.isObject() || r.size() != 3 || !r["attempt"].isString()
                || !r["state"].isString() || !r["candidate"].isString()
                || (record.rotationState != "" && record.rotationState != "prepared" && record.rotationState != "running")
                || (record.rotationState.isEmpty() != record.rotationAttempt.isEmpty())
                || (!record.rotationAttempt.isEmpty() && QUuid(record.rotationAttempt).isNull())
                || (!record.rotationCandidate.isEmpty() && (QUuid(record.rotationCandidate).isNull()
                    || record.rotationState != "running")))
                return fail(error, "État de rotation invalide ; suppression interdite.");
        }
        if (!versions.isUndefined() && !versions.isArray()) return fail(error, "Suivi des sauvegardes invalide.");
        for (const auto& version : versions.toArray()) {
            const auto entry = version.toObject();
            AutomaticBackupVersion saved;
            saved.attemptId = entry["attempt"].toString(); saved.path = entry["path"].toString();
            saved.createdUtc = entry["createdUtc"].toString(); saved.birthTime = entry["birthTime"].toString();
            saved.durable = entry["durable"].toBool();
            if (entry.contains("evidence") || entry.contains("order") || entry.contains("destinationEpoch")) {
                BackupFileEvidence evidence;
                saved.destinationEpoch = entry["destinationEpoch"].toString();
                if (!decodeBackupEvidence(entry["evidence"], evidence)
                    || !unsignedNumber(entry["order"], saved.order) || !saved.order
                    || saved.order > record.automaticOrder || QUuid(saved.destinationEpoch).isNull()
                    || !entry["destinationEpoch"].isString())
                    return fail(error, "Preuves de sauvegarde incomplètes ou invalides.");
                saved.evidence = std::move(evidence);
            }
            if (entry["kind"] != "automatic" || entry["publication"] != "published"
                || QUuid(saved.attemptId).isNull() || !absolutePath(saved.path)
                || !entry["durable"].isBool() || !entry["birthTime"].isString()
                || !QDateTime::fromString(saved.createdUtc, Qt::ISODateWithMs).isValid()
                || !unsignedNumber(entry["device"], saved.device) || !unsignedNumber(entry["inode"], saved.inode)
                || !unsignedNumber(entry["size"], saved.size) || saved.inode == 0)
                return fail(error, "Version de sauvegarde automatique invalide.");
            for (const auto& prior : record.automaticVersions)
                if (prior.attemptId == saved.attemptId || prior.path == saved.path
                    || (saved.order && prior.order >= saved.order))
                    return fail(error, "Versions de sauvegarde ambiguës.");
            if (saved.evidence && (saved.evidence->device != saved.device || saved.evidence->inode != saved.inode
                || saved.evidence->size != saved.size || saved.evidence->birth != saved.birthTime))
                return fail(error, "Identité et reçu de sauvegarde incohérents.");
            record.automaticVersions.push_back(std::move(saved));
        }
        if (id.isNull() || id.toString(QUuid::WithoutBraces) != record.localId
            || !absolutePath(record.file.path) || record.file.vaultId.size() != 16
            || QString::fromLatin1(record.file.vaultId.toHex()) != hex
            || !unsignedNumber(file.value("device"), record.file.device)
            || !unsignedNumber(file.value("inode"), record.file.inode)
            || !file.value("birthTime").isString()
            || !backup.value("automatic").isBool() || !backup.value("directory").isString()
            || backup.value("retainedVersions") != QJsonValue(record.backup.retainedVersions)
            || (!required.isUndefined() && !required.isBool())
            || !validPreferences(record.backup))
            return fail(error, "Enregistrement de coffre invalide ; aucune réinitialisation effectuée.");
        if (record.replacement && record.file != (record.replacement->confirmed
            ? *record.replacement->confirmed : record.replacement->previous))
            return fail(error, "Identité de restauration incohérente.");
        if (record.resolvedReplacement && (record.replacement
            || record.file != *record.resolvedReplacement->confirmed))
            return fail(error, "Reçu résolu incohérent avec le coffre enregistré.");
        for (const auto& existing : records)
            if (existing.localId == record.localId || existing.file.path == record.file.path
                || (existing.file.device == record.file.device && existing.file.inode == record.file.inode))
                return fail(error, "Identités ambiguës dans le registre.");
        records.push_back(std::move(record));
    }
    return true;
}

// Preserve unknown root/record fields for future version-1 extensions.
void encode(QJsonObject& root, const QVector<VaultRegistration>& records)
{
    const auto oldRecords = root.value("vaults").toArray();
    QJsonArray array;
    for (const auto& record : records) {
        QJsonObject object;
        for (const auto& old : oldRecords)
            if (old.toObject().value("localId").toString() == record.localId)
                object = old.toObject();
        object.insert("localId", record.localId);
        object.insert("file", encodeIdentity(record.file));
        if (record.replacement) {
            object.insert("replacement", encodeReplacement(*record.replacement));
        } else object.remove("replacement");
        if (record.resolvedReplacement)
            object.insert("resolvedReplacement", encodeReplacement(*record.resolvedReplacement));
        else object.remove("resolvedReplacement");
        object.insert("backup", QJsonObject{{"automatic", record.backup.automatic},
            {"directory", record.backup.directory}, {"retainedVersions", record.backup.retainedVersions}});
        object.insert("backupRequired", record.backupRequired);
        object.insert("automaticState", QJsonObject{{"suspended", record.automaticSuspended},
            {"attempt", record.backupAttempt}, {"destination", record.backupAttemptDestination},
            {"device", QString::number(record.backupDirectory.device)},
            {"inode", QString::number(record.backupDirectory.inode)}});
        QJsonArray versions;
        for (const auto& saved : record.automaticVersions) {
            QJsonObject version{{"kind", "automatic"}, {"publication", "published"},
                {"attempt", saved.attemptId}, {"path", saved.path}, {"createdUtc", saved.createdUtc},
                {"birthTime", saved.birthTime}, {"durable", saved.durable},
                {"device", QString::number(saved.device)}, {"inode", QString::number(saved.inode)},
                {"size", QString::number(saved.size)}};
            if (saved.evidence) {
                version.insert("evidence", encodeBackupEvidence(*saved.evidence));
                version.insert("order", QString::number(saved.order));
                version.insert("destinationEpoch", saved.destinationEpoch);
            }
            versions.append(version);
        }
        object.insert("automaticVersions", versions);
        // Additive version-1 extension. Missing fields in old records do not
        // authorize deletion and are not reconstructed from today's files.
        object.insert("automaticOrder", QString::number(record.automaticOrder));
        object.insert("backupEpoch", record.backupEpoch);
        object.insert("rotation", QJsonObject{{"attempt", record.rotationAttempt},
            {"state", record.rotationState}, {"candidate", record.rotationCandidate}});
        array.push_back(object);
    }
    root.insert("version", 1);
    root.insert("vaults", array);
}

bool confirmSettingsDurability(const QString& path, QString& error)
{
    if (!QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner))
        return fail(error, "Configuration publiée mais permissions non confirmées.");
#ifdef Q_OS_UNIX
    Fd directory{openDirectory(QFileInfo(path).absolutePath())};
    const auto name = QFile::encodeName(QFileInfo(path).fileName());
    Fd published{directory.value < 0 ? -1 : ::openat(directory.value, name.constData(),
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)};
    if (published.value < 0 || ::fsync(published.value) != 0 || ::fsync(directory.value) != 0)
        return fail(error, "Configuration publiée, mais durabilité non confirmée.");
#endif
    return true;
}

template<class Operation>
bool accessRegistry(const QString& path, QString& error, Operation operation,
    RegistryPersistence* persistence = nullptr)
{
    if (persistence) *persistence = RegistryPersistence::NotAttempted;
    error.clear();
    if (!prepareSettings(path, error))
        return false;
    // Different from Qt's .lock: do not deadlock QSettings::sync(). This lock
    // serializes registry read-modify-write; Qt merges unrelated settings keys.
    QLockFile lock(path + ".registry-lock");
    lock.setStaleLockTime(0); // Never steal from a live slow writer based on age.
    if (!lock.tryLock(0))
        return fail(error, "Configuration occupée ; réessayer explicitement.");
    QVariant previous;
    if (!readRegistryOnDisk(path, previous, error))
        return false;
    QSettings settings(path, QSettings::IniFormat);
    settings.setFallbacksEnabled(false);
    settings.setAtomicSyncRequired(true);
    settings.sync();
    (void)settings.allKeys(); // Force lazy INI parsing before changing anything.
    if (settings.status() != QSettings::NoError)
        return fail(error, "Lecture de configuration impossible ou fichier corrompu.");
    QJsonObject root{{"version", 1}, {"vaults", QJsonArray{}}};
    if (previous.isValid()) {
        QJsonParseError parseError;
        const auto document = QJsonDocument::fromJson(previous.toByteArray(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
            return fail(error, "Registre corrompu ; aucune réinitialisation effectuée.");
        root = document.object();
    }
    QVector<VaultRegistration> records;
    if (!decode(root, records, error))
        return false;
    bool changed = false;
    if (!operation(records, changed))
        return false;
    if (!changed)
        return true;
    encode(root, records);
    const QByteArray serialized = QJsonDocument(root).toJson(QJsonDocument::Compact);
    if (serialized.size() > MaxConfigBytes / 2)
        return fail(error, "Registre trop volumineux.");
    // QSettings has a shared cache. Restore its previous value on error, before
    // destruction can retry pending changes. Never leave failed authorizations
    // in that cache. This is not a transaction with a vault's SQLite file.
    bool published = false;
    const auto restoreCache = qScopeGuard([&]() noexcept {
        if (!published) {
            // QVariant/QSettings can allocate. Never throw during unwinding.
            // An allocation failure here cannot provide a persistence guarantee.
            try {
                if (previous.isValid()) settings.setValue(RegistryKey, previous);
                else settings.remove(RegistryKey);
            } catch (...) {}
        }
    });
    settings.setValue(RegistryKey, serialized);
    // An error/exception from sync does NOT prove no bytes became visible.
    if (persistence) *persistence = RegistryPersistence::Unconfirmed;
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return fail(error, "Échec de synchronisation atomique de la configuration.");
    published = true; // Visibility only, never a durability certificate.
    // Qt preserves an existing file's permissions; first creation is protected
    // by the 0700 parent, then explicitly restricted to owner-only access.
    if (!confirmSettingsDurability(path, error)) return false;
    if (persistence) *persistence = RegistryPersistence::Durable;
    return true;
}

bool sameFile(const VaultFileIdentity& left, const VaultFileIdentity& right)
{
    return left.device == right.device && left.inode == right.inode;
}
} // namespace

VaultPreferencesStore::VaultPreferencesStore()
    : settingsFile_(QSettings("PassWall", "PassWall").fileName()) {}
VaultPreferencesStore::VaultPreferencesStore(QString settingsFile)
    : settingsFile_(std::move(settingsFile)) {}
VaultPreferencesEvents& VaultPreferencesStore::events()
{
    static VaultPreferencesEvents value;
    return value;
}

bool VaultPreferencesStore::inspectVault(const QString& path, VaultFileIdentity& output, QString& error)
{
    storage::VaultOperationGuard access;
    std::string failure;
    if (!access.tryAccess(path.toStdString(), failure)) {
        output = {};
        error = QString::fromStdString(failure);
        return false;
    }
    if (VaultPreferencesStore().recoveryAccess(path, error) != VaultRecoveryAccess::Allowed) {
        output = {};
        return false;
    }
    return inspect(path, &access, output, error);
}
bool VaultPreferencesStore::inspectReserved(const QString& path,
    const storage::VaultOperationGuard& reservation, VaultFileIdentity& output, QString& error)
{
    std::string failure;
    if (!reservation.matchesReservation(path.toStdString(), failure))
        return fail(error, "Réservation exclusive du coffre non confirmée.");
    return inspect(path, &reservation, output, error);
}
bool VaultPreferencesStore::inspect(const QString& path,
    const storage::VaultOperationGuard* reservation, VaultFileIdentity& output, QString& error)
{
    output = {};
    error.clear();
    if (!absolutePath(path))
        return fail(error, "Chemin de coffre non canonique ; réassociation nécessaire.");
    VaultFileIdentity identity;
    identity.path = path;
#ifdef Q_OS_UNIX
    Fd directory{openDirectory(QFileInfo(path).absolutePath())};
    const auto name = QFile::encodeName(QFileInfo(path).fileName());
    Fd descriptor{directory.value < 0 ? -1 : ::openat(directory.value, name.constData(),
        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
    struct stat before {};
    if (descriptor.value < 0 || ::fstat(descriptor.value, &before) != 0
        || !S_ISREG(before.st_mode) || before.st_uid != ::geteuid()
        || before.st_nlink != 1 || (before.st_mode & 0022))
        return fail(error, "Identité du coffre non sûre ou ambiguë ; réassociation nécessaire.");
    identity.device = before.st_dev;
    identity.inode = before.st_ino;
    identity.birthTime = birthTime(descriptor.value);
#else
    // Do not invent a persistent file identity on unsupported platforms.
    return fail(error, "Identification locale des coffres non disponible sur cette plateforme.");
#endif
    sqlite3* raw = nullptr;
    storage::VaultOperationGuard access;
    std::string accessError;
    if (!reservation && !access.tryAccess(path.toStdString(), accessError))
        return fail(error, "Coffre réservé ou synchronisation indisponible.");
    const auto encodedPath = QFile::encodeName(path);
    const int opened = sqlite3_open_v2(encodedPath.constData(), &raw,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nullptr);
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> database(raw, sqlite3_close_v2);
    std::string sqlError;
    if (opened != SQLITE_OK || !storage::configureSqliteConnection(raw, sqlError))
        return fail(error, "Impossible de lire l'identité du coffre (SQLite).");
    sqlite3_stmt* statement = nullptr;
    const int prepared = sqlite3_prepare_v2(raw,
        "SELECT vault_id FROM vault_metadata WHERE id = 1", -1, &statement, nullptr);
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(statement, sqlite3_finalize);
    if (prepared != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW
        || sqlite3_column_type(statement, 0) != SQLITE_BLOB || sqlite3_column_bytes(statement, 0) != 16)
        return fail(error, "Identifiant cryptographique du coffre invalide.");
    identity.vaultId = QByteArray(static_cast<const char*>(sqlite3_column_blob(statement, 0)), 16);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return fail(error, "Lecture de l'identité du coffre incomplète.");
#ifdef Q_OS_UNIX
    struct stat after {}, named {};
    if (::fstat(descriptor.value, &after) != 0
        || ::fstatat(directory.value, name.constData(), &named, AT_SYMLINK_NOFOLLOW) != 0
        || named.st_dev != before.st_dev || named.st_ino != before.st_ino
        || before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec
        || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec)
        return fail(error, "Le coffre a changé pendant son identification.");
#endif
    output = std::move(identity);
    return true;
}

bool VaultPreferencesStore::listForDisplay(QVector<VaultRegistration>& output, QString& error) const
{
    output.clear(); error.clear();
    if (!prepareSettings(settingsFile_, error)) return false;
    QVariant published;
    if (!readRegistryOnDisk(settingsFile_, published, error)) return false;
    if (!published.isValid()) return true;
    QJsonParseError parse;
    const auto document = QJsonDocument::fromJson(published.toByteArray(), &parse);
    if (parse.error != QJsonParseError::NoError || !document.isObject())
        return fail(error, "Registre corrompu ; aucune réinitialisation effectuée.");
    QVector<VaultRegistration> snapshot;
    if (!decode(document.object(), snapshot, error)) return false;
    output = std::move(snapshot);
    return true;
}
bool VaultPreferencesStore::list(QVector<VaultRegistration>& output, QString& error) const
{
    output.clear();
    QVector<VaultRegistration> result;
    if (!accessRegistry(settingsFile_, error, [&](auto& records, bool&) {
            result = records; return true;
        }))
        return false;
    output = std::move(result);
    return true;
}

VaultRecognition VaultPreferencesStore::recognizeOrRegister(
    const QString& path, VaultRegistration& output, QString& error) const
{
    output = {};
    VaultRecognition status = VaultRecognition::Error;
    VaultRegistration result;
    if (!accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        if (!recoveryAllowed(records, path, error)) return false;
        VaultFileIdentity identity;
        if (!inspect(path, nullptr, identity, error)) {
            status = VaultRecognition::ReassociationRequired;
            return false;
        }
        for (const auto& record : records) {
            if (record.file == identity) {
                result = record;
                status = VaultRecognition::Recognized;
                return true;
            }
            if (record.file.path == identity.path || sameFile(record.file, identity)
                || (record.file.vaultId == identity.vaultId && !QFileInfo::exists(record.file.path))) {
                status = VaultRecognition::ReassociationRequired;
                return fail(error, "Coffre déplacé, remplacé ou ambigu : réassociation explicite nécessaire.");
            }
        }
        result.file = std::move(identity);
        do { result.localId = QUuid::createUuid().toString(QUuid::WithoutBraces); }
        while (std::any_of(records.cbegin(), records.cend(), [&](const auto& record) {
            return record.localId == result.localId;
        }));
        records.push_back(result);
        changed = true;
        status = VaultRecognition::Registered;
        return true;
    }))
        return status == VaultRecognition::ReassociationRequired ? status : VaultRecognition::Error;
    output = std::move(result);
    return status;
}

bool VaultPreferencesStore::updatePreferences(const QString& localId,
    const VaultBackupPreferences& preferences, QString& error) const
{
    return updatePreferencesImpl(localId, nullptr, preferences, error);
}
bool VaultPreferencesStore::updatePreferencesIfCurrent(const VaultRegistration& expected,
    const VaultBackupPreferences& preferences, QString& error) const
{
    return updatePreferencesImpl(expected.localId, &expected, preferences, error);
}
bool VaultPreferencesStore::updatePreferencesImpl(const QString& localId,
    const VaultRegistration* expected, const VaultBackupPreferences& preferences, QString& error) const
{
    if (!validPreferences(preferences))
        return fail(error, "Préférences invalides : nombre positif et chemin absolu requis.");
    // Keep policy changes outside ongoing mutations: otherwise enabling backups
    // could race just after a CRUD observed 'disabled'. Retain through fsync.
    // Existing registry->vault inspection and this reservation are nonblocking;
    // a CRUD holding vault access never waits for this registry lock either.
    storage::VaultOperationGuard policyChange;
    QString source;
    const bool saved = accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) {
            if (record.localId != localId) continue;
            if (expected && (record.file != expected->file || record.backup != expected->backup))
                return fail(error, "Préférences ou identité modifiées depuis l'affichage ; actualisez avant d'enregistrer.");
            if (record.replacement)
                return fail(error, "Préférences bloquées pendant une récupération.");
            VaultFileIdentity current;
            if (!inspect(record.file.path, nullptr, current, error) || current != record.file)
                return fail(error, "L'identité du coffre a changé ; préférences non modifiées.");
            std::string failure;
            if (!policyChange.tryReserve(current.path.toStdString(), failure)) {
                error = QString::fromStdString(failure);
                return false;
            }
#ifdef Q_OS_UNIX
            // No second SQLite open under our exclusive reservation. Recheck
            // filesystem evidence across the preceding read/reserve boundary.
            const auto name = QFile::encodeName(current.path);
            Fd file{::open(name.constData(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
            struct stat information {};
            if (file.value < 0 || ::fstat(file.value, &information) != 0
                || quint64(information.st_dev) != current.device
                || quint64(information.st_ino) != current.inode || birthTime(file.value) != current.birthTime)
                return fail(error, "Identité du coffre modifiée pendant le changement de préférences.");
#endif
            if (!record.backup.automatic && preferences.automatic) record.backupRequired = true;
            if (record.backup.directory != preferences.directory) {
                record.backupDirectory = {};
                record.backupEpoch = QUuid::createUuid().toString(QUuid::WithoutBraces);
            }
            record.backup = preferences;
            source = record.file.path;
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement local inconnu.");
    });
    policyChange.reset(); // Receivers may attempt a reservation, never under this lease.
    if (saved) emit events().changed(settingsFile_, localId, source, preferences.automatic);
    return saved;
}

bool VaultPreferencesStore::prepareMutation(const QString& path,
    storage::VaultOperationGuard& access, QString& error) const
{
    error.clear();
    storage::VaultOperationGuard candidate;
    std::string accessError;
    if (!candidate.tryAccess(path.toStdString(), accessError)) {
        error = QString::fromStdString(accessError);
        return false;
    }
    const QString normalized = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    // Lock order: business guard -> nonblocking registry lock -> persistence;
    // caller opens SQLite only AFTER this method succeeds. No registry lock
    // is kept across SQLite work. No SQL inspection before recording intent.
    if (!accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        if (!recoveryAllowed(records, path, error)) return false;
#ifdef Q_OS_UNIX
        Fd directory{openDirectory(QFileInfo(normalized).absolutePath())};
        const auto name = QFile::encodeName(QFileInfo(normalized).fileName());
        Fd descriptor{directory.value < 0 ? -1 : ::openat(directory.value, name.constData(),
            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
        struct stat info {};
        if (descriptor.value < 0 || ::fstat(descriptor.value, &info) != 0
            || !S_ISREG(info.st_mode) || info.st_uid != ::geteuid())
            return fail(error, "Identité du coffre impossible à confirmer avant modification.");
        const auto birth = birthTime(descriptor.value);
        for (auto& record : records) {
            const bool same = record.file.device == quint64(info.st_dev)
                && record.file.inode == quint64(info.st_ino);
            if (record.file.path != normalized && !same) continue;
            if (record.file.path != normalized || !same || record.file.birthTime != birth
                || info.st_nlink != 1 || (info.st_mode & 0022))
                return fail(error, "Identité du coffre modifiée ou ambiguë ; modification refusée.");
            if (!record.backup.automatic) return true;
            if (record.backupRequired) {
                // A prior attempt may have published true but failed its fsync.
                // Physical visibility alone is NOT a durability confirmation.
                // Reconfirm without rewriting the registry on every CRUD.
                return confirmSettingsDurability(settingsFile_, error);
            }
            record.backupRequired = true;
            changed = true;
            return true;
        }
        // A distinct copy does not inherit the original's local authorization.
        // Recognition/registration is a separate existing lifecycle operation.
        return true;
#else
        return fail(error, "Suivi local des modifications indisponible sur cette plateforme.");
#endif
    })) return false;
    access = std::move(candidate);
    return true;
}

bool VaultPreferencesStore::suspendAutomaticBackup(const QString& localId, QString& error) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == localId) {
            record.backupRequired = true;
            record.automaticSuspended = true;
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement local inconnu.");
    });
}

bool VaultPreferencesStore::beginAutomaticBackup(const VaultRegistration& expected,
    const SnapshotDirectoryIdentity& directory, const QString& destination, const QString& attempt,
    const storage::VaultOperationGuard& reservation, QString& error, bool explicitResume) const
{
    std::string failure;
    if (QUuid(attempt).isNull() || !absolutePath(destination)
        || !reservation.matchesReservation(expected.file.path.toStdString(), failure))
        return fail(error, "Réservation ou tentative de sauvegarde non confirmée.");
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == expected.localId) {
            if (record.replacement || record.file != expected.file || record.backup != expected.backup
                || QFileInfo(destination).absolutePath() != record.backup.directory
                || (record.backupDirectory.inode && record.backupDirectory != directory)
                || !record.backup.automatic || !record.backupRequired
                || (record.automaticSuspended && !explicitResume) || directory.inode == 0)
                return fail(error, "Autorisation ou support de sauvegarde modifié.");
            for (const auto& prior : record.automaticVersions)
                if (prior.attemptId == attempt) return fail(error, "Identifiant de tentative déjà utilisé.");
#ifdef Q_OS_UNIX
            const auto name = QFile::encodeName(record.file.path);
            Fd file{::open(name.constData(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)};
            struct stat info {};
            if (file.value < 0 || ::fstat(file.value, &info) != 0 || !S_ISREG(info.st_mode)
                || quint64(info.st_dev) != record.file.device || quint64(info.st_ino) != record.file.inode
                || birthTime(file.value) != record.file.birthTime || info.st_nlink != 1)
                return fail(error, "Le coffre enregistré a été remplacé ou son identité est ambiguë.");
#endif
            record.backupDirectory = directory;
            if (record.backupEpoch.isEmpty()) record.backupEpoch = QUuid::createUuid().toString(QUuid::WithoutBraces);
            record.backupAttempt = attempt;
            record.backupAttemptDestination = destination;
            record.automaticSuspended = true; // Durable crash latch BEFORE launch.
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement local inconnu.");
    });
}

bool VaultPreferencesStore::finishAutomaticBackup(const QString& localId, const QString& attempt,
    BackupResult result, bool normalInterruption, const storage::VaultOperationGuard& reservation,
    QString& error) const
{
    const bool published = result.outcome == BackupOutcome::Published
        || result.outcome == BackupOutcome::DurabilityUnconfirmed;
    const bool durable = result.outcome == BackupOutcome::Published;
    const bool interrupted = normalInterruption && result.outcome == BackupOutcome::CancelledBeforePublication;
    // First persist the catalogue WITH intent/latch still set. A catalogue
    // failure can therefore never clear intent, even after atomic publication.
    if (!accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == localId) {
            std::string failure;
            if (record.backupAttempt != attempt || attempt.isEmpty()
                || !reservation.matchesReservation(record.file.path.toStdString(), failure))
                return fail(error, "Confirmation de sauvegarde obsolète ou non réservée.");
            if (published) {
#ifdef Q_OS_LINUX
                AutomaticBackupVersion version;
                version.attemptId = attempt; version.path = record.backupAttemptDestination;
                version.createdUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                version.durable = durable;
                if (result.receipt) {
                    // Full-content verification took place in the worker,
                    // bound to its PRIVATE staging inode before publication.
                    // Never hash a vault on the GUI thread.
                    const auto& e = *result.receipt;
                    if (e.directoryDevice != record.backupDirectory.device
                        || e.directoryInode != record.backupDirectory.inode || !e.inode || !e.size
                        || e.sha256.size() != 32 || version.path == record.file.path
                        || (e.device == record.file.device && e.inode == record.file.inode)
                        || record.automaticOrder == std::numeric_limits<quint64>::max())
                        return fail(error, "Reçu de publication incompatible avec la tentative.");
                    version.device = e.device; version.inode = e.inode; version.size = e.size;
                    version.birthTime = e.birth; version.evidence = e;
                    version.order = ++record.automaticOrder;
                    version.destinationEpoch = record.backupEpoch;
                } else {
                // Compatibility with step-4 records/peers: tracked, but NEVER
                // eligible for deletion without a worker publication receipt.
                SnapshotDirectoryIdentity current;
                if (!VaultSnapshotService::inspectDestinationDirectory(
                        QFileInfo(record.backupAttemptDestination).absolutePath().toStdString(), current, failure)
                    || current != record.backupDirectory)
                    return fail(error, "Support de publication non confirmé ; intention conservée.");
                const auto path = QFile::encodeName(record.backupAttemptDestination);
                Fd file{::open(path.constData(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
                struct stat info {};
                if (file.value < 0 || ::fstat(file.value, &info) != 0 || !S_ISREG(info.st_mode)
                    || info.st_uid != ::geteuid() || (info.st_mode & 0777) != 0600 || info.st_nlink != 1
                    || info.st_size <= 0)
                    return fail(error, "Identité de la sauvegarde publiée non confirmée.");
                version.device = info.st_dev; version.inode = info.st_ino; version.size = info.st_size;
                version.birthTime = birthTime(file.value); version.durable = durable;
                }
                record.automaticVersions.push_back(std::move(version));
#else
                return fail(error, "Suivi de publication indisponible.");
#endif
            }
            record.backupRequired = true;
            record.automaticSuspended = true;
            if (!durable && !interrupted) { record.backupAttempt.clear(); record.backupAttemptDestination.clear(); }
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement local inconnu.");
    })) return false;
    if (!durable && !interrupted) return true;
    const bool cleared = accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == localId) {
            std::string failure;
            if (record.backupAttempt != attempt || (durable && (record.automaticVersions.isEmpty()
                || record.automaticVersions.last().attemptId != attempt || !record.automaticVersions.last().durable))
                || !reservation.matchesReservation(record.file.path.toStdString(), failure))
                return fail(error, "Confirmation de sauvegarde obsolète refusée.");
            record.backupRequired = !durable;
            record.automaticSuspended = false;
            record.backupAttempt.clear(); record.backupAttemptDestination.clear();
            if (durable && result.receipt && record.rotationAttempt.isEmpty()) {
                record.rotationAttempt = attempt;
                record.rotationState = "prepared";
                record.rotationCandidate.clear();
            }
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement local inconnu.");
    });
    if (!cleared) {
        const auto original = error;
        QString secondary;
        // No final file is removed. If this repair also fails, the earlier
        // durable catalogue still describes the exact reserved source snapshot.
        const bool rearmed = suspendAutomaticBackup(localId, secondary);
        error = original + (rearmed ? QStringLiteral(" Intention réarmée.")
            : QStringLiteral(" Réarmement non confirmé ; vérifier la configuration."));
    }
    return cleared;
}

bool VaultPreferencesStore::claimRotation(const QString& localId, const QString& attempt,
    const storage::VaultOperationGuard& reservation, VaultRegistration& output, QString& error) const
{
    output = {};
    VaultRegistration candidate;
    const bool saved = accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& r : records) if (r.localId == localId) {
            std::string failure;
            if (r.replacement || attempt.isEmpty() || r.rotationAttempt != attempt || r.rotationState != "prepared"
                || !r.rotationCandidate.isEmpty() || !r.backup.automatic || r.backupRequired
                || r.automaticVersions.isEmpty() || r.automaticVersions.last().attemptId != attempt
                || !r.automaticVersions.last().durable || !r.automaticVersions.last().evidence
                || !reservation.matchesReservation(r.file.path.toStdString(), failure))
                return fail(error, "Rotation non autorisée, obsolète ou précédente rotation non confirmée.");
            r.rotationState = "running";
            candidate = r;
            changed = true;
            return true;
        }
        return fail(error, "Coffre de rotation inconnu.");
    });
    if (saved) output = std::move(candidate);
    return saved;
}

bool VaultPreferencesStore::markRotationDeletion(const QString& localId, const QString& attempt,
    const AutomaticBackupVersion& candidate, const storage::VaultOperationGuard& reservation, QString& error) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& r : records) if (r.localId == localId) {
            std::string failure;
            const auto found = std::find(r.automaticVersions.begin(), r.automaticVersions.end(), candidate);
            if (r.rotationState != "running" || r.rotationAttempt != attempt || !r.rotationCandidate.isEmpty()
                || candidate.attemptId == attempt || found == r.automaticVersions.end() || !candidate.evidence
                || !candidate.durable || candidate.destinationEpoch != r.backupEpoch
                || QFileInfo(candidate.path).absolutePath() != r.backup.directory
                || !reservation.matchesReservation(r.file.path.toStdString(), failure))
                return fail(error, "Intention de suppression non autorisée.");
            // Also exclude ALL registered principal identities, not just ours.
            for (const auto& principal : records)
                if (principal.file.path == candidate.path || (principal.file.device == candidate.device
                    && principal.file.inode == candidate.inode))
                    return fail(error, "Une sauvegarde utilisée comme coffre principal ne peut pas être supprimée.");
            r.rotationCandidate = candidate.attemptId;
            changed = true; return true;
        }
        return fail(error, "Coffre de rotation inconnu.");
    });
}

bool VaultPreferencesStore::confirmRotationDeletion(const QString& localId, const QString& attempt,
    const QString& candidate, const storage::VaultOperationGuard& reservation, QString& error) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& r : records) if (r.localId == localId) {
            std::string failure;
            if (r.rotationState != "running" || r.rotationAttempt != attempt || r.rotationCandidate != candidate
                || candidate.isEmpty() || !reservation.matchesReservation(r.file.path.toStdString(), failure))
                return fail(error, "Confirmation de suppression obsolète.");
            const auto found = std::find_if(r.automaticVersions.begin(), r.automaticVersions.end(),
                [&](const auto& v) { return v.attemptId == candidate; });
            if (found == r.automaticVersions.end()) return fail(error, "Version supprimée introuvable au catalogue.");
            r.automaticVersions.erase(found);
            r.rotationCandidate.clear();
            changed = true; return true;
        }
        return fail(error, "Coffre de rotation inconnu.");
    });
}

bool VaultPreferencesStore::completeRotation(const QString& localId, const QString& attempt,
    const storage::VaultOperationGuard& reservation, QString& error) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& r : records) if (r.localId == localId) {
            std::string failure;
            if (r.rotationState != "running" || r.rotationAttempt != attempt || !r.rotationCandidate.isEmpty()
                || !reservation.matchesReservation(r.file.path.toStdString(), failure))
                return fail(error, "Fin de rotation non confirmée.");
            r.rotationAttempt.clear(); r.rotationState.clear();
            changed = true; return true;
        }
        return fail(error, "Coffre de rotation inconnu.");
    });
}

bool VaultPreferencesStore::updateIdentityAfterReplacement(const QString& localId,
    const VaultFileIdentity& previous, const VaultFileIdentity& replacement, QString& error) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        if (!recoveryAllowed(records, previous.path, error)) return false;
        VaultFileIdentity current;
        if (previous.path != replacement.path || !inspect(replacement.path, nullptr, current, error)
            || current != replacement)
            return fail(error, "Identité de remplacement non confirmée.");
        for (auto& record : records) {
            if (record.localId != localId && sameFile(record.file, replacement))
                return fail(error, "Le fichier appartient déjà à un autre enregistrement.");
        }
        for (auto& record : records) {
            if (record.localId != localId) continue;
            if (record.file != previous)
                return fail(error, "Réassociation obsolète refusée.");
            record.file = replacement;
            record.resolvedReplacement.reset(); // Explicit CAS, never an active recovery bypass.
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement local inconnu.");
    });
}

VaultRecoveryAccess VaultPreferencesStore::recoveryAccess(const QString& path, QString& error) const
{
    bool allowed = false;
    const bool read = accessRegistry(settingsFile_, error, [&](auto& records, bool&) {
        allowed = recoveryAllowed(records, path, error);
        return true; // A readable pending fence differs from an unreadable registry.
    });
    if (!read) return VaultRecoveryAccess::Unavailable;
    return allowed ? VaultRecoveryAccess::Allowed : VaultRecoveryAccess::RecoveryRequired;
}
bool VaultPreferencesStore::checkRecoveryAccess(const std::string& path, std::string& error)
{
    QString failure;
    if (VaultPreferencesStore().recoveryAccess(QString::fromStdString(path), failure)
        == VaultRecoveryAccess::Allowed) return true;
    error = failure.toStdString();
    return false;
}
bool VaultPreferencesStore::writeReplacementIntent(const QString& localId,
    const VaultFileIdentity& expected, const VaultReplacementIntent& intent, QString& error) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == localId) {
            if (record.file != expected || intent.previous != expected
                || (record.replacement && (record.replacement->operationId != intent.operationId
                    || record.replacement->phase != "prepared")))
                return fail(error, "Préparation de remplacement obsolète ou déjà engagée.");
            record.replacement = intent;
            record.resolvedReplacement.reset(); // Bounded receipt; never removes an artifact.
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement de remplacement inconnu.");
    });
}
bool VaultPreferencesStore::resolveReplacement(const QString& localId,
    const VaultReplacementIntent& expected, const VaultFileIdentity& observed,
    bool completed, QString& error, RegistryPersistence* persistence) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == localId) {
            if (completed) {
                if (!expected.confirmed || observed != *expected.confirmed || record.file != observed)
                    return fail(error, "Identité finale de remplacement non confirmée.");
                if (expected.phase == "resolved" && !record.replacement
                    && record.resolvedReplacement == expected) {
                    changed = true; // Idempotent re-confirmation of the same receipt, including fsync.
                    return true;
                }
                if (expected.phase != "identity-confirmed" || record.replacement != expected)
                    return fail(error, "Résolution sans confirmation préalable interdite.");
                auto receipt = expected;
                receipt.phase = "resolved";
                record.resolvedReplacement = std::move(receipt);
                if (record.backup.automatic) record.backupRequired = true;
            } else if (expected.phase != "prepared" || observed != expected.previous
                || record.file != expected.previous || record.replacement != expected) {
                return fail(error, "Abandon non démontré avant substitution ; blocage conservé.");
            }
            // completed is reachable only after the protected identity write
            // was confirmed durable by the trusted caller. Both the old active
            // intent and the new resolved receipt retain every recovery reference.
            record.replacement.reset();
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement de récupération inconnu.");
    }, persistence);
}

bool VaultPreferencesStore::confirmReplacementIdentity(const QString& localId,
    const VaultReplacementIntent& expected, const VaultFileIdentity& observed,
    QString& error, RegistryPersistence* persistence) const
{
    return accessRegistry(settingsFile_, error, [&](auto& records, bool& changed) {
        for (auto& record : records) if (record.localId == localId) {
            if (record.replacement != expected || !expected.candidate
                || (expected.phase != "armed" && expected.phase != "identity-confirmed")
                || record.file != (expected.confirmed ? *expected.confirmed : expected.previous))
                return fail(error, "Confirmation de remplacement obsolète ; blocage conservé.");
            auto candidate = *expected.candidate;
            candidate.path = expected.previous.path;
            if (observed != candidate)
                return fail(error, "Identité observée étrangère au candidat autorisé.");
            for (const auto& other : records)
                if (other.localId != localId && sameFile(other.file, observed))
                    return fail(error, "Candidat déjà associé à un autre coffre.");
            record.file = observed;
            record.replacement->confirmed = observed;
            record.replacement->phase = "identity-confirmed";
            // Keep preferences, dirty state, catalogue, suspension AND fence.
            changed = true;
            return true;
        }
        return fail(error, "Enregistrement de récupération inconnu.");
    }, persistence);
}
} // namespace passwall::services
