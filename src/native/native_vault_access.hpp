#pragma once

#include "models/credential.hpp"

#include <cstdint>
#include <vector>

namespace passwall::native {

// Capture l'état d'une session de coffre à un instant donné. La génération
// doit changer avant le verrouillage, lors de l'ouverture d'une nouvelle
// session, et lors de toute transition qui invalide une requête en cours.
struct VaultLease final {
    bool unlocked = false;
    std::uint64_t generation = 0;
};

enum class VaultAccessResult {
    Success,
    Locked,
    SessionChanged,
    NotFound,
    Failed
};

// Frontière étroite entre le traitement Native Messaging et la session du
// coffre. Cette interface n'expose ni le chemin SQLite ni la clé de données.
//
// Contrats de sortie :
// - copySummaries() ne retourne que des CredentialSummary. Si le résultat
//   n'est pas Success, output doit être vide.
// - loadCredential() ne retourne un Credential complet que pour Success. Si
//   le résultat n'est pas Success, output doit être nettoyé et vide.
// - Les objets placés dans les sorties sont détenus par l'appelant. Ils ne
//   doivent pas référencer un cache interne de l'implémentation.
// - L'implémentation ne doit pas conserver durablement de Credential complet
//   et doit nettoyer ses temporaires avant de retourner.
//
// Contrat de concurrence : dans l'architecture actuelle, toutes les méthodes
// sont appelées sur le thread propriétaire de la session Qt. L'implémentation
// ne doit donc ni accéder concurremment à la génération, à la clé ou à l'état
// du coffre, ni modifier l'état pendant un appel. Une future implémentation
// multi-thread devra sérialiser ces opérations et conserver le lease valide
// jusqu'à la mise en file de la réponse par le transport. Le processeur
// vérifie le lease une dernière fois après avoir construit une réponse secrète;
// le futur adaptateur et le transport devront étendre cette garantie jusqu'à
// l'écriture effective sur le socket.
//
// Les erreurs opérationnelles attendues sont retournées par VaultAccessResult.
// Le processeur contient néanmoins les exceptions afin qu'elles ne traversent
// pas la frontière Native Messaging.
class NativeVaultAccess {
public:
    virtual ~NativeVaultAccess() = default;

    [[nodiscard]] virtual VaultLease acquireLease() const noexcept = 0;

    [[nodiscard]] virtual bool isLeaseCurrent(
        const VaultLease& lease) const noexcept = 0;

    [[nodiscard]] virtual VaultAccessResult copySummaries(
        const VaultLease& lease,
        std::vector<models::CredentialSummary>& output) = 0;

    [[nodiscard]] virtual VaultAccessResult loadCredential(
        const VaultLease& lease,
        const models::EntryId& entryId,
        models::Credential& output) = 0;
};

} // namespace passwall::native
