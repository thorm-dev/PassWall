#include "services/generational_backup_rotation_controller.hpp"

#include "services/backup_series_identity.hpp"
#include "services/global_backup_preferences_store.hpp"

#include <QDir>
#include <QFileInfo>
#include <QPointer>
#include <QThread>
#include <QTimer>

#include <atomic>
#include <mutex>
#include <utility>

#ifdef PASSWALL_GUI_TESTING
namespace {
std::atomic<passwall::tests::GenerationalRotationCheckpointHook>
    rotationCheckpointHook{nullptr};
std::atomic<void*> rotationCheckpointContext{nullptr};
}
namespace passwall::tests {
void setGenerationalRotationCheckpointHook(
    GenerationalRotationCheckpointHook hook, void* context) noexcept
{
    if (hook == nullptr) {
        rotationCheckpointHook.store(nullptr, std::memory_order_release);
        rotationCheckpointContext.store(nullptr, std::memory_order_release);
        return;
    }
    rotationCheckpointContext.store(context, std::memory_order_release);
    rotationCheckpointHook.store(hook, std::memory_order_release);
}
}
#endif

namespace passwall::services {
namespace {

bool inMemoryPublicationValid(const MutationBackupResult& result)
{
    if (result.outcome != MutationBackupOutcome::Published
        || result.workerOutcome != BackupOutcome::Published
        || !result.workerTerminated
        || result.requestId == 0 || !result.publication
        || !result.confirmedPublicationResult)
        return false;
    const auto& receipt = *result.publication;
    const auto& publication = *result.confirmedPublicationResult;
    return receipt.requestId == result.requestId
        && receipt.generation == result.generation
        && receipt.kind == result.kind
        && receipt.sessionGeneration == result.sessionGeneration
        && receipt.vaultPath == result.vaultPath
        && publication.outcome == BackupOutcome::Published
        && publication.receipt
        && publication.receipt->permitsDeletion()
        && publication.publishedPath == receipt.destination
        && *publication.receipt == receipt.evidence
        && receipt.evidence.permitsDeletion();
}

bool configurationMatches(const GenerationalBackupRotationContext& context,
    const QString& publishedPath, QString& diagnostic)
{
    diagnostic.clear();
    if (context.preferencesSourceFile.isEmpty()
        || !context.preferencesSourceIdentity
        || context.vaultId.size() != BackupSeriesIdentityService::VaultIdSize
        || context.preparedPreferences.retainedVersions
            < GlobalBackupPreferencesStore::MinimumRetainedVersions
        || context.preparedPreferences.rootDirectory != context.rootDirectory) {
        diagnostic = QStringLiteral(
            "Contexte de préférences ou de série insuffisant pour la rotation.");
        return false;
    }
    const auto current = GlobalBackupPreferencesStore(
        context.preferencesSourceFile).load();
    if (!current.valid()
        || current.sourceFile != context.preferencesSourceFile
        || current.preferences != context.preparedPreferences
        || current.sourceIdentity != context.preferencesSourceIdentity) {
        diagnostic = QStringLiteral(
            "Les préférences globales ont changé ou ne sont plus lisibles.");
        return false;
    }
    const QString family = QDir(context.rootDirectory).filePath(
        QString::fromLatin1(context.vaultId.toHex()));
    const QString series = QDir(family).filePath(context.seriesId);
    if (QFileInfo(publishedPath).absolutePath() != series) {
        diagnostic = QStringLiteral(
            "La publication ne correspond pas à la série préparée.");
        return false;
    }
    return true;
}

} // namespace

struct GenerationalBackupRotationController::Work {
    MutationBackupResult publication;
    std::atomic_bool cancellationRequested{false};
    std::atomic_bool configurationInvalidated{false};
    std::atomic_bool ownerDestroyed{false};
    std::mutex mutex;
    BackupSeriesRotationResult result;

    static bool stop(void* raw, BackupSeriesRotationCheckpoint checkpoint,
        const QString&) noexcept
    {
        auto& work = *static_cast<Work*>(raw);
#ifdef PASSWALL_GUI_TESTING
        void* hookContext = rotationCheckpointContext.load(
            std::memory_order_acquire);
        if (const auto hook = rotationCheckpointHook.load(
                std::memory_order_acquire))
            hook(hookContext, checkpoint);
#endif
        if (work.cancellationRequested.load(std::memory_order_acquire))
            return true;
        try {
            QString diagnostic;
            const auto& receipt = *work.publication.publication;
            if (!receipt.rotationContext
                || !configurationMatches(*receipt.rotationContext,
                    receipt.destination, diagnostic)) {
                work.configurationInvalidated.store(
                    true, std::memory_order_release);
                return true;
            }
        } catch (...) {
            work.configurationInvalidated.store(true, std::memory_order_release);
            return true;
        }
        return false;
    }
};

GenerationalBackupRotationController::GenerationalBackupRotationController(
    AutomaticBackupCoordinator& coordinator, QObject* parent)
    : QObject(parent), coordinator_(&coordinator)
{
    setObjectName(QStringLiteral("generationalBackupRotationController"));
    connect(&coordinator, &AutomaticBackupCoordinator::mutationBatchSettled,
        this, &GenerationalBackupRotationController::consumePublication);
    connect(&GlobalBackupPreferencesStore::events(),
        &GlobalBackupPreferencesEvents::changed, this,
        [this](const QString& settingsFile, bool) {
            preferencesChanged(settingsFile);
        });
}

GenerationalBackupRotationController::~GenerationalBackupRotationController()
{
    pending_.clear();
    if (active_) {
        active_->ownerDestroyed.store(true, std::memory_order_release);
        active_->cancellationRequested.store(true, std::memory_order_release);
    }
}

bool GenerationalBackupRotationController::idle() const noexcept
{
    return !active_ && pending_.isEmpty();
}

void GenerationalBackupRotationController::beginShutdownDrain() noexcept
{
    shutdownDrainRequested_ = true;
    if (idle()) emit shutdownDrainCompleted();
}

bool GenerationalBackupRotationController::continueAfterShutdownDrain() noexcept
{
    if (!shutdownDrainRequested_ || !idle()) return false;
    shutdownDrainRequested_ = false;
    return true;
}

void GenerationalBackupRotationController::consumePublication(
    MutationBackupResult result)
{
    if (QThread::currentThread() != thread() || !coordinator_
        || coordinator_->triggerMode() != BackupTriggerMode::Generational
        || !inMemoryPublicationValid(result))
        return;
    if (acceptedRequestIds_.contains(result.requestId))
        return;
    try {
        acceptedRequestIds_.insert(result.requestId);
    } catch (...) {
        reject(result, QStringLiteral(
            "Mémorisation du jeton de rotation impossible."));
        return;
    }
    if (!result.publication->rotationContext) {
        reject(result, QStringLiteral(
            "Publication confirmée sans contexte de rotation préparé."));
        return;
    }
    const bool wasIdle = idle();
    try {
        pending_.push_back(std::move(result));
    } catch (...) {
        reject(result, QStringLiteral(
            "Mise en file de la rotation impossible."));
        return;
    }
    const QPointer<GenerationalBackupRotationController> owner(this);
    if (wasIdle) emit busyChanged(true);
    if (!owner) return;
    startNext();
}

void GenerationalBackupRotationController::reject(
    const MutationBackupResult& publication, QString diagnostic)
{
    GenerationalBackupRotationResult result;
    result.requestId = publication.requestId;
    result.generation = publication.generation;
    result.sessionGeneration = publication.sessionGeneration;
    result.kind = publication.kind;
    if (publication.publication)
        result.publishedPath = publication.publication->destination;
    result.rotation.outcome = BackupSeriesRotationOutcome::Refused;
    result.rotation.diagnostic = std::move(diagnostic);
    const QPointer<GenerationalBackupRotationController> owner(this);
    emit rotationSettled(std::move(result));
    if (!owner) return;
    if (shutdownDrainRequested_ && idle())
        emit shutdownDrainCompleted();
}

void GenerationalBackupRotationController::startNext()
{
    if (active_ || pending_.isEmpty()) return;
    auto publication = std::move(pending_.front());
    pending_.removeFirst();
    std::shared_ptr<Work> work;
    try {
        work = std::make_shared<Work>();
        work->publication = std::move(publication);
    } catch (...) {
        const QPointer<GenerationalBackupRotationController> owner(this);
        reject(publication, QStringLiteral(
            "Allocation du travail de rotation impossible."));
        if (!owner) return;
        if (idle()) emit busyChanged(false);
        if (!owner) return;
        QTimer::singleShot(0, this, [this] { startNext(); });
        return;
    }
    active_ = work;
    const QPointer<GenerationalBackupRotationController> owner(this);
    QObject* delivery = nullptr;
    QThread* thread = nullptr;
    try {
        delivery = new QObject;
        thread = QThread::create([work] {
            BackupSeriesRotationResult result;
            try {
                const auto& receipt = *work->publication.publication;
                QString diagnostic;
                if (!receipt.rotationContext
                    || !configurationMatches(*receipt.rotationContext,
                        receipt.destination, diagnostic)) {
                    result.outcome = BackupSeriesRotationOutcome::Refused;
                    result.diagnostic = std::move(diagnostic);
                } else {
                    const auto& context = *receipt.rotationContext;
                    BackupSeriesRotationRequest request;
                    request.rootDirectory = context.rootDirectory;
                    request.vaultId = context.vaultId;
                    request.seriesId = context.seriesId;
                    request.retainedVersions =
                        context.preparedPreferences.retainedVersions;
                    request.expectedRoot = context.rootIdentity;
                    request.expectedFamily = context.familyIdentity;
                    request.expectedSeries = context.seriesIdentity;
                    request.publication =
                        *work->publication.confirmedPublicationResult;
                    request.control = {Work::stop, work.get()};
                    result = BackupSeriesRotationService::rotate(request);
                    if (work->configurationInvalidated.load(
                            std::memory_order_acquire))
                        result.diagnostic = QStringLiteral(
                            "Rotation arrêtée : les préférences globales ont changé ou sont devenues illisibles.");
                    else if (work->ownerDestroyed.load(
                            std::memory_order_acquire))
                        result.diagnostic = QStringLiteral(
                            "Rotation arrêtée après destruction de son propriétaire.");
                }
            } catch (...) {
                result.outcome = BackupSeriesRotationOutcome::Unknown;
                result.diagnostic = QStringLiteral(
                    "Travail asynchrone de rotation interrompu.");
            }
            std::lock_guard lock(work->mutex);
            work->result = std::move(result);
        });
    } catch (...) {
        delete delivery;
        active_.reset();
        const QPointer<GenerationalBackupRotationController> owner(this);
        reject(work->publication, QStringLiteral(
            "Création du travail asynchrone de rotation impossible."));
        if (!owner) return;
        if (idle()) emit busyChanged(false);
        if (!owner) return;
        QTimer::singleShot(0, this, [this] { startNext(); });
        return;
    }
    connect(thread, &QThread::finished, delivery,
        [thread, delivery, owner, work] {
            if (owner) owner->finishWork(work);
            thread->deleteLater();
            delivery->deleteLater();
        }, Qt::QueuedConnection);
    thread->start();
}

void GenerationalBackupRotationController::finishWork(
    const std::shared_ptr<Work>& work)
{
    if (!work || active_ != work) return;
    GenerationalBackupRotationResult result;
    result.requestId = work->publication.requestId;
    result.generation = work->publication.generation;
    result.sessionGeneration = work->publication.sessionGeneration;
    result.kind = work->publication.kind;
    result.publishedPath = work->publication.publication->destination;
    {
        std::lock_guard lock(work->mutex);
        result.rotation = std::move(work->result);
    }
    active_.reset();
    const QPointer<GenerationalBackupRotationController> owner(this);
    emit rotationSettled(std::move(result));
    if (!owner) return;
    startNext();
    if (!owner) return;
    if (idle()) {
        emit busyChanged(false);
        if (!owner) return;
        if (shutdownDrainRequested_) emit shutdownDrainCompleted();
    }
}

void GenerationalBackupRotationController::preferencesChanged(
    const QString& settingsFile)
{
    if (!active_ || !active_->publication.publication
        || !active_->publication.publication->rotationContext)
        return;
    if (active_->publication.publication->rotationContext
            ->preferencesSourceFile == settingsFile) {
        active_->configurationInvalidated.store(true,
            std::memory_order_release);
        active_->cancellationRequested.store(true,
            std::memory_order_release);
    }
}

} // namespace passwall::services
