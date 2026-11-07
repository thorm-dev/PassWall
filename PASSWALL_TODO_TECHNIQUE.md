# PassWall — Plan technique des travaux restants

**Version :** 1.4
**Date :** 7 novembre 2026
**Statut :** feuille de route actualisée avec la clôture fonctionnelle locale du verrouillage Linux rapportée par l'utilisateur. Les essais manuels sont distingués des validations automatisées ; les limites de sécurité et les travaux non réalisés restent explicites.

## 1. Objet et méthode

Cette feuille de route synthétise les travaux restant à réaliser ou à vérifier. Elle distingue les décisions validées, les composants développés et les points dont l'achèvement n'est pas confirmé. Elle ne constitue pas une certification de sécurité.

- **À faire** : travail identifié, non confirmé comme réalisé.
- **À vérifier** : une implémentation existe ou a été évoquée, mais doit être contrôlée.
- **Conditionnel** : dépend d'une décision préalable.
- **Réalisé** : étape implémentée ou observation rapportée, dans le seul périmètre explicitement indiqué ; cela ne vaut pas certification de sécurité.

### Faits vérifiés dans l'implémentation

- Le coffre local, le chiffrement des entrées, l'interface Qt, le pont Firefox, `SiteMatcher` et le générateur de mots de passe sont implémentés.
- Le générateur est intégré à la boîte d'édition et couvert par des tests C++.
- Le chemin de production Firefox est Firefox → Extension PassWall → `passwall_native_host` → `NativeBridgeServer` → `MainWindow::handleNativeRequest()` → `NativeRequestProcessor` → `NativeVaultAccess` → Coffre PassWall. `MainWindow` implémente `NativeVaultAccess` ; `NativeRequestProcessor` est l'unique implémentation métier Native Messaging, compilée à la fois par l'application et les tests.
- La migration de `MainWindow` vers `CredentialSummary` et `CredentialService::listSummaries()` est réalisée ; l'interface ne conserve plus une collection durable de credentials complets.
- TOTP, passkeys, audit de mots de passe, synchronisation, sauvegarde, restauration et migration ne sont pas implémentés.
- Le verrouillage manuel et par inactivité, le nettoyage immédiat des éditeurs et l'armement précoce du timer sont implémentés. `LinuxSessionMonitor` traite les préparations de suspension/hibernation et d'arrêt/redémarrage de logind, avec inhibiteur `delay`, vérification effective du descripteur et politique fail-closed.
- L'instance unique, `Control1.Lock()` acquitté après nettoyage et `passwall-session-lock` sont implémentés. Le coordinateur est installé et raccordé à `Ctrl+Alt+L` et au pilote conservé `Ctrl+Super+L`. Le parcours labwc/PassWall/Firefox est fonctionnellement validé manuellement sur Raspberry Pi 5 / Debian 13, dans le périmètre de la section 3.4.
- `SessionGuard1` est définitivement supprimé. Il n'existe ni garde persistante globale ni authentification globale supplémentaire : chaque coffre reste indépendant, avec son propre mot de passe maître et sans restauration automatique d'une ancienne session.

## 2. Ordre des priorités

| Priorité | Domaine | Objectif |
|---|---|---|
| P0 | Mémoire sensible | Réduire la présence des secrets et les copies |
| P0 | Flux Firefox/natif | Contrôler le parcours complet du mot de passe |
| P0 | Verrouillage | Préserver le nettoyage acquis et compléter la couverture des défaillances et événements Linux |
| P1 | Stockage | Fiabiliser erreurs, migrations et sauvegardes |
| P1 | Tests | Ajouter des scénarios de sécurité et d'échec |
| P1 | Spécification des entrées | Imposer les champs obligatoires prévus |
| P1 | Installation Firefox | Rendre reproductible l'installation du Native Host et de l'extension |
| P1 | Synchronisation | Finaliser conflits, appareils et révocation |
| P2 | Produit | Finaliser TOTP, passkeys, audit et ergonomie |
| P3 | Plateformes | Linux, puis Windows ; iOS différé |

## 3. P0 — Réduction de l'exposition mémoire

### 3.1 Ne plus conserver tous les credentials complets dans MainWindow

**Réalisé :** l'ancienne collection `MainWindow::credentials_` de credentials complets a été remplacée par des `CredentialSummary` contenant l'identifiant, la version, le titre, l'URL et le nom d'utilisateur, sans mot de passe ni notes. L'interface utilise ces résumés ; l'édition et une demande Firefox ciblée chargent temporairement l'entrée nécessaire, avec nettoyage RAII.

`CredentialService::listSummaries()` déchiffre les entrées une par une, extrait les métadonnées puis nettoie chaque credential temporaire, sans vecteur intermédiaire de credentials complets.

**Travaux restants :** vérifier qu'aucun autre composant GUI ne conserve de copie complète, auditer la durée de vie des objets temporaires sur les chemins d'erreur et réduire les copies encore évitables. La migration ne garantit pas l'effacement de toutes les anciennes allocations des chaînes et des types Qt.

**Acceptation :** aucun conteneur durable de l'interface ne conserve les mots de passe ou notes de toutes les entrées.

### 3.2 Nettoyage RAII des objets temporaires dans CredentialService

**État vérifié :** `CredentialService` utilise déjà des nettoyeurs RAII pour des credentials temporaires et des vecteurs de credentials, et nettoie la sortie de `get()` et `list()` avant remplacement. Cela réduit certains chemins d'erreur, sans éliminer les copies internes de `std::string`, SQLite ou Qt.

Les chemins à examiner dans `credential_service.cpp` :
- copies locales dans `add()` ;
- credential existant et candidat dans `update()` ;
- credential chargé dans `remove()` ;
- candidat de désérialisation ;
- vecteurs temporaires dans `list()` ;
- sortie de `get()` avant remplacement.

**Travaux :**
1. Auditer les nettoyeurs existants sur chaque retour anticipé et chaque exception.
2. Réduire les copies complètes encore évitables.
3. Ajouter des tests ciblant succès, erreur et exception.

**Limite importante :** nettoyer la zone actuellement utilisée par un `std::string` ne garantit pas l'effacement de toutes ses anciennes allocations, copies ou données SSO. Il ne faut pas présenter `sodium_memzero()` sur `string.data()` comme une garantie absolue.

### 3.3 Consolider le flux natif Firefox de bout en bout

**Architecture effective :** le chemin complet figure en section 1. `popup.js` contacte `org.passwall.native` ; `passwall_native_host` (`native_host.cpp`) rejoint `NativeBridgeServer` par socket Unix. `MainWindow` implémente `NativeVaultAccess`, qui fournit au processeur l'état du coffre, les résumés et le chargement ciblé. La consolidation autour de l'unique implémentation métier `NativeRequestProcessor` est réalisée ; il ne reste pas de second handler métier à maintenir.

**Installation locale réalisée :** application `/home/thormster/.local/bin/passwall_app`, Host `/home/thormster/.local/bin/passwall_native_host`, manifeste `/home/thormster/.mozilla/native-messaging-hosts/org.passwall.native.json`. Le manifeste pointe vers ce Host ; les deux exécutables ont les permissions `0755` et leurs SHA-256 correspondent aux versions compilées et testées selon les vérifications rapportées. Cette installation est manuelle, pas une procédure reproductible intégrée au projet.

**Première campagne Firefox réelle, le 6 novembre 2026 :** l'utilisateur rapporte le chargement de l'extension temporaire, l'ouverture du popup, le démarrage automatique, la communication, la détection du coffre verrouillé, la recherche, le remplissage, le blocage après verrouillage et l'isolation entre domaines réussis. La fermeture puis le redémarrage automatique réussissent et le coffre reste verrouillé. Tous les essais utilisent uniquement des données fictives. Le changement de session pendant une requête a été déclaré fonctionnel lors d'un essai manuel, sans reproduction déterministe de l'instant d'invalidation. Le détail figure en section 6.5 de la documentation technique ; il ne s'agit pas de tests automatisés de bout en bout.

Composants à consolider :
- `native_host.cpp` ;
- `NativeBridgeServer` ;
- `MainWindow::handleNativeRequest()` ;
- `NativeRequestProcessor` et `NativeVaultAccess` ;
- extension Firefox (`popup`, `fill_script` et tests associés).

**Contrôles :**
1. Conserver `NativeRequestProcessor` comme implémentation unique de traitement des requêtes et vérifier que les tests continuent d'exercer ce même composant.
2. Vérifier que le chargement par `NativeVaultAccess` reste ciblé lors de `get_credential`, sans réintroduire de cache durable de credentials complets.
3. Compter les conversions/copies (`std::string`, `QByteArray`, `QString`, `QJsonObject`).
4. Préserver et tester la validation de l'origine avant et après le chargement ciblé du secret.
5. Ne jamais journaliser mot de passe, réponse JSON ou données sensibles.
6. Nettoyer les buffers de réponse après transmission, dans la mesure permise par les types.
7. Vérifier messages tronqués, invalides, trop grands et déconnexions.
8. Vérifier que l'extension ne conserve le secret que le temps nécessaire au remplissage.
9. Versionner un modèle de manifeste Native Messaging `org.passwall.native` et fournir une installation reproductible du Native Host et de l'extension, au-delà de l'installation manuelle locale déjà réalisée. `passwall-native-test@passwall.local` provient de `browser_specific_settings.gecko.id` dans `firefox-extension/manifest.json`, pour l'extension temporaire « PassWall - Test natif » ; le packaging et l'identifiant d'une future diffusion restent à définir.

**À faire :** automatiser les tests de bout en bout avec Firefox, ajouter des scénarios déterministes d'invalidation de session pendant une réponse en cours, et poursuivre les vérifications de sécurité et de robustesse. Les succès manuels ne clôturent pas ces travaux.

**Acceptation :** une demande ne charge qu'une entrée ciblée après validation ; pas de secret dans les logs ; buffers temporaires nettoyés au mieux.

### 3.4 Verrouillage

**Réalisé :** nettoyage immédiat des éditeurs sans attente d'une notification modale, protection contre les anciens éditeurs et réentrances, minuterie active avant le rafraîchissement d'une session utilisable et respect de « Désactivé ». `lockVault()` invalide la session Native Messaging et les transmissions encore détenues par l'application avant de détruire la clé. `LinuxSessionMonitor` surveille les préparations logind de suspension/hibernation et d'arrêt/redémarrage, avec nettoyage sur le thread Qt propriétaire avant libération de l'inhibiteur ; une protection indisponible interdit l'accès aux secrets.

**Coordination de session réalisée :** `passwall-session-lock` appelle `org.passwall.PassWall.Control1.Lock()` sans activer PassWall, consacre un budget de 1 500 ms à l'attente D-Bus, puis tente `/usr/bin/swaylock -p`. Ce budget inclut le démarrage de l'auxiliaire mais ne constitue pas une garantie temps réel globale. Absence, refus ou non-réponse de PassWall n'empêchent pas la tentative de verrouillage de l'écran et ne valent pas acquittement de nettoyage.

**Installation et utilisation locales réalisées :** application `/home/thormster/.local/bin/passwall_app`, coordinateur `/home/thormster/.local/bin/passwall-session-lock`, Native Host inchangé `/home/thormster/.local/bin/passwall_native_host`. Le fichier utilisateur labwc définit `C-A-l` et conserve `C-W-l` ; le mode `--merge-config` remplace l'action système de `C-A-l`, sans cumul des deux verrouilleurs. Le thème, la souris, le fichier système et Firefox sont préservés. Les sauvegardes datées vérifiées et les commandes de retour arrière figurent dans [le guide du coordinateur](docs/linux-session-lock.md).

**Décisions closes :** `SessionGuard1` est supprimé, sans remplacement par une garde persistante globale. Aucun mot de passe maître global ni obligation de rouvrir le dernier coffre. Après le verrouillage, chaque coffre peut être ouvert par une nouvelle authentification avec son propre mot de passe maître, si les protections système sont disponibles. Le déverrouillage de Linux ne restaure jamais de session. Aucune modification du code de swaylock/labwc ni preuve de déverrouillage Wayland n'est requise pour cette nouvelle authentification.

**Validation manuelle rapportée, bilan du 7 novembre 2026 :** `Ctrl+Alt+L` déclenche le coordinateur ; PassWall se verrouille avant le verrouillage Linux visible ; la session Linux se verrouille et se déverrouille normalement ; le coffre reste verrouillé ; Firefox refuse le remplissage jusqu'à une nouvelle authentification ; le remplissage reprend ensuite ; `Ctrl+Super+L` reste disponible. Le verrouillage avec PassWall absent avait également été essayé avec succès. Ces observations clôturent la validation fonctionnelle de cette intégration locale, pas un audit exhaustif de la mémoire ou de tous les scénarios d'échec.

**Propriétés à préserver et à vérifier au-delà du changement d'écran :**

- arrêt du timer ;
- effacement conditionnel du presse-papiers ;
- nettoyage des credentials et données de recherche ;
- destruction de la clé (`SecureBuffer`) ;
- nettoyage des champs de saisie ;
- invalidation des états des services et du pont natif ;
- traitement des requêtes natives en cours ;
- maintien des protections logind déjà implémentées, sans les assimiler à une interception garantie des fermetures de session, crashs ou arrêts forcés.

**Travaux restant ouverts :** compléter les scénarios pendant une opération SQLite et une requête Firefox, maintenir les régressions GUI déjà présentes et poursuivre les tests déterministes de transmission. Valider séparément les transitions réelles de suspension/hibernation/arrêt : les tests simulés et les essais du raccourci ne les démontrent pas. Recenser les déclencheurs directs de swaylock et autres mécanismes de fermeture de session, qui peuvent contourner le coordinateur. Documenter le cas de PassWall bloqué, sans nettoyage confirmé, et les limites d'un thread principal ou de logind indisponible.

L'état réel de déverrouillage Wayland n'est pas surveillé ; le code de sortie de swaylock ne constitue pas une preuve de déverrouillage. La disparition éventuelle de l'indication du raccourci dans `pishutdown` reste un point ergonomique à vérifier, sans modifier le programme système. Le pilote `Ctrl+Super+L` peut être conservé ou retiré ultérieurement sur décision explicite. L'installation reproductible du coordinateur reste à formaliser au-delà de cette installation locale.

Le verrouillage visible ne prouve pas l'effacement de toutes les allocations historiques de Qt. Distinguer les données encore détenues par l'application, qui doivent être annulées et nettoyées, des octets déjà acceptés par Qt ou le système, qui ne peuvent pas être rappelés.

### 3.5 Qt et presse-papiers

Vérifier les conversions `std::string`/`QByteArray`/`QString`, les propriétés Qt, `UserRole`, messages d'erreur et logs. Qt peut conserver des copies internes ; leur effacement physique ne peut pas être garanti simplement par l'application. Vérifier aussi le délai d'effacement du presse-papiers et le cas où l'utilisateur copie autre chose entre-temps.

### 3.6 Imposer les champs obligatoires de PassWall V1

**Décision fonctionnelle V1 :** titre, nom d'utilisateur et mot de passe sont obligatoires. **État vérifié :** l'interface ne refuse actuellement que le titre vide et `CredentialService` accepte des chaînes vides pour les trois champs.

**Travaux :**
1. Imposer les trois champs dans l'interface graphique, à l'ajout comme à la modification.
2. Imposer les trois champs dans `CredentialService`, afin que les appels non-GUI ne contournent pas l'invariant.
3. Ajouter les tests d'ajout et de mise à jour vérifiant qu'aucun de ces champs ne peut être vide.

## 4. P0/P1 — Cryptographie et stockage

### 4.1 Moteur cryptographique

Le moteur utilise libsodium, Argon2id et XChaCha20-Poly1305. Les paramètres actuels sont 3 itérations et 256 Mio (`VaultArgon2Operations=3`, `VaultArgon2Memory=256 MiB`), avec une plage acceptée de 3 à 4 itérations et de 256 à 512 Mio à l'ouverture. À vérifier :
- justification documentée de ces paramètres au regard du matériel cible ;
- génération et stockage du sel ;
- unicité des nonces ;
- AAD ;
- version et format des données chiffrées ;
- ciphertext tronqué ou altéré ;
- nettoyage des clés et buffers sur tous les chemins d'erreur ;
- comportement si libsodium ne s'initialise pas.

Documenter les paramètres et ajouter des tests de corruption, troncature et incompatibilité de format.

### 4.2 SQLite

**État vérifié :** chaque coffre utilise sa propre base SQLite, qui stocke les notes chiffrées avec le reste de l'entrée. À la création, le coffre applique `PRAGMA journal_mode=DELETE`, `PRAGMA synchronous=FULL`, `PRAGMA secure_delete=ON` et `PRAGMA temp_store=MEMORY`; `CredentialService` réapplique `secure_delete=ON` à ses connexions.

À vérifier :
- persistance effective du mode `journal_mode=DELETE` et de ses fichiers associés après création/réouverture ;
- WAL, journaux, fichiers temporaires et sauvegardes ;
- permissions du coffre et du répertoire ;
- arrêt brutal, disque plein et corruption ;
- transactions d'ajout, modification et suppression ;
- absence de données en clair dans colonnes, tables auxiliaires et logs.

Le mode `DELETE` évite le WAL persistant, mais ses propriétés de confidentialité et de durabilité après incident restent à valider expérimentalement.

### 4.3 Migrations

Décision validée : bloquer l'ouverture normale lorsqu'une migration est nécessaire et proposer une migration contrôlée après sauvegarde. **État vérifié :** le coffre et les entrées portent une version de format, mais aucun mécanisme de migration n'est implémenté.

À faire : versionner le format, décrire les migrations, créer et vérifier une sauvegarde préalable, rendre l'opération atomique ou récupérable, vérifier le résultat, tester interruption/échec/restauration et refuser les formats non pris en charge.

### 4.4 Sauvegardes

La sauvegarde chiffrée du coffre et la rétention de 7 jours ont été discutées, mais aucune fonction de sauvegarde/restauration du coffre n'est implémentée. La sauvegarde automatique locale avait été différée. Les copies manuelles des exécutables et de la configuration labwc ne remplissent pas cet objectif.

À faire : préciser le format (copie du coffre chiffré ou export), métadonnées, destination et permissions ; tester sauvegarde/restauration réelle ; vérifier l'intégrité après restauration ; documenter la sauvegarde manuelle vers un autre ordinateur ou NAS local.

## 5. P1 — Synchronisation et appareils

### 5.1 Conflits

Ne pas écraser silencieusement une modification concurrente. Détecter les versions divergentes, conserver les deux versions, présenter les différences et demander une résolution explicite. Tester des reconnexions dans des ordres différents.

### 5.2 Autorisation et révocation

La règle de référence dans les notes est : ajout d'un appareil approuvé par un appareil déjà autorisé ; mot de passe maître toujours requis pour déchiffrer le coffre. Une révocation d'urgence avec évaluation du risque, rotation de clés et identification des secrets externes à renouveler a été privilégiée.

À consolider dans une spécification unique : rôle du mot de passe maître à l'enrôlement, clés par appareil, preuve de possession, révocation, rotation et conséquences pour les appareils restants.

### 5.3 Récupération et serveur

Décision validée : pas de récupération si tous les appareils autorisés sont perdus ; pas de contournement en cas de perte du mot de passe maître.

Préférences : fonctionnement hors ligne obligatoire ; serveur distant ne nécessitant pas d'exposer le Raspberry Pi à Internet ; Europe privilégiée, Norvège/Suisse possibles si garanties adéquates ; budget de quelques euros par mois.

À faire : définir le modèle de menace, protocole, chiffrement de bout en bout, données visibles du serveur, juridiction, sauvegardes, suppression et disponibilité hors ligne.

## 6. P1 — Tests

Compléter la couverture automatisée et les scénarios d'échec :

1. mémoire : nettoyage succès/échec/exception, sortie déjà remplie, vecteur partiellement rempli ;
2. service : désérialisation invalide, entrée corrompue au milieu d'une liste, échec update/remove ;
3. GUI : maintenir les régressions existantes des éditeurs, du minuteur, du contrôle D-Bus et des générations natives ; compléter les scénarios avec liste ou requête active et les contrôles d'absence de mot de passe dans les données de recherche ;
4. Firefox : tests automatisés de bout en bout avec site autorisé, domaine ressemblant, redirection, entrée modifiée/supprimée, coffre verrouillé, message invalide et invalidation déterministe pendant une réponse ;
5. stockage : arrêt brutal, corruption, disque plein, restauration et migration interrompue ;
6. synchronisation : conflit, appareil révoqué, hors ligne, perte de tous les appareils.
7. JavaScript : exécution explicite des cinq tests existants avec `node --test tests/extension/*.test.cjs`, puis ajout d'une commande de projet et d'une version Node minimale documentée.
8. Firefox : rendre reproductibles l'installation et les essais avec le manifeste et l'hôte installés ; la première campagne réelle a été effectuée manuellement le 6 novembre, mais son automatisation reste à faire.
9. Linux : maintenir les tests du coordinateur, de `Control1.Lock()`, de logind et de l'instance unique ; compléter la couverture des déclencheurs et transitions système sans assimiler les services simulés à une transition réelle.

**Validations automatisées ciblées rapportées au 6 novembre :** `EntryIdParserTest` 9/9, `NativeRequestProcessorTest` 27/27, `NativeRequestResponseTest` 1/1, `SiteMatcherTest` 12/12, `NativeBridgeServerTest` 21/21 avec sockets Unix réels dans l'environnement Debian habituel, et `passwall_native_host_tests` 6/6, concernant notamment les échecs de redirection des flux. Ces résultats ne prouvent pas une nouvelle exécution complète de tous les tests du projet et sont distincts des essais manuels Firefox.

**Validations du verrouillage rapportées avant installation :** `SessionLockCoordinatorTest` 21/21 (cible `passwall_session_lock_tests`, bus privé et faux verrouilleur) et `SessionLockServiceTest` 10/10. Les régressions GUI de nettoyage des éditeurs, de minuterie et de générations natives, ainsi que celles du moniteur logind, de son backend D-Bus et de l'instance unique, ont été rapportées comme réussies au fil des interventions. Un jalon antérieur de campagne complète 225/225 a été rapporté avant les évolutions ultérieures ; il ne représente pas le total actuel de tous ces tests. Les essais réels du raccourci et de Firefox de la section 3.4 restent des observations manuelles distinctes. Aucune compilation ni suite de tests n'a été relancée lors de cette clôture documentaire.

Le journal CTest de 69/69 tests réussis le 5 novembre est un jalon historique, pas le nombre actuel établi de tous les tests. Les cinq tests JavaScript existants ne sont actuellement ni intégrés à CTest ni déclarés par un `package.json` ; aucune nouvelle exécution JavaScript n'est établie par le compte rendu du 6 novembre.

Pour chaque changement technique : point Git initial, modification ciblée, compilation et tests adaptés au périmètre, inspection du diff et consignation du résultat. Préciser si la validation est ciblée ou complète, et ne pas assimiler des essais manuels à une suite automatisée.

## 7. P2/P3 — Fonctionnalités et plateformes

Le générateur de mots de passe est implémenté, intégré à l'interface et testé. TOTP, passkeys, audit des mots de passe et synchronisation restent à développer. Les paramètres, l'ergonomie, la recherche et la gestion des erreurs doivent être repris selon les besoins produit.

L'intégration aux applications locales a été reportée après stabilisation du coffre et de Firefox.

Ordre des plateformes : Linux d'abord ; Windows via VM pour les tests ; iOS différé.

La campagne Firefox manuelle du 6 novembre et le bilan du verrouillage Linux du 7 novembre concernent l'installation locale Raspberry Pi 5 / Debian 13 / labwc uniquement. Les validations Windows et des autres plateformes prévues restent à réaliser.

## 8. Ordre de travail recommandé

1. Poursuivre la réduction de l'exposition des secrets après la migration réalisée vers `CredentialSummary` : auditer les nettoyeurs RAII et réduire les copies évitables, sans réintroduire de credentials complets dans l'état durable de `MainWindow`.
2. Compléter la validation du flux Firefox désormais unifié autour de `NativeRequestProcessor` : tests déterministes d'invalidation pendant une réponse, tests automatisés de bout en bout et vérifications supplémentaires de sécurité et de robustesse.
3. Préserver le verrouillage Linux fonctionnellement validé et ses protections internes ; compléter la couverture des défaillances, des déclencheurs non coordonnés et des événements système, sans rouvrir les décisions de garde globale abandonnées.
4. Poursuivre les travaux P1 de stockage et de tests : valider SQLite face aux incidents, compléter les scénarios de sécurité, puis mettre en place migrations, sauvegardes et restauration testées.
5. Appliquer les champs obligatoires dans l'interface et `CredentialService`, rendre reproductible l'installation du Native Host et de l'extension au-delà de l'installation locale manuelle, puis documenter la commande de tests JavaScript.
6. Finaliser la spécification de synchronisation, d'enrôlement et de révocation.
7. Développer les fonctionnalités produit restantes : TOTP, passkeys, audit et ergonomie.
8. Étendre et tester les plateformes dans l'ordre Linux, Windows, puis iOS.

Une étape doit être validée avant de passer à la suivante.

## 9. Incertitudes à lever dans le dépôt

- versions actuelles exactes de tous les fichiers ;
- nombre et nature des copies du mot de passe dans le flux natif ;
- détails de conception des futures sauvegardes, migrations et synchronisation, aujourd'hui absentes ;
- couverture globale au-delà des suites ciblées rapportées, automatisation Firefox et scénarios déterministes d'invalidation de session.

Les points suivants sont connus et ne doivent plus être traités comme incertains : le chemin Firefox de production (section 1, avec `MainWindow` comme `NativeVaultAccess`), l'installation locale manuelle et la première campagne réelle rapportée le 6 novembre (section 3.3), la configuration SQLite de création (`DELETE`, `FULL`, `secure_delete=ON`, `temp_store=MEMORY`), les paramètres Argon2id (3 itérations, 256 Mio), l'absence de sauvegarde/migration/synchronisation et l'absence de TOTP, passkeys et audit.

L'installation du coordinateur, la surcharge utilisateur de `Ctrl+Alt+L`, le maintien du pilote et les succès fonctionnels rapportés de la section 3.4 sont également établis dans ce périmètre local. `SessionGuard1` est définitivement supprimé ; une garde globale persistante, une authentification globale ou une modification de swaylock/labwc ne sont pas des travaux en attente. Les limites de mémoire, de couverture des déclencheurs et de comportement sous défaillance restent ouvertes.

Ne pas résoudre ces incertitudes par supposition : inspecter le dépôt et consigner les observations.

## 10. Critères de candidature à une première version

Avant une première diffusion : chiffrement et formats documentés ; tests du cycle de vie et de la corruption ; exposition mémoire réduite et vérifiée ; flux Firefox de production consolidé, installation reproductible et validation automatisée de bout en bout, au-delà des essais manuels déjà réalisés ; invalidation de session testée de manière déterministe pendant une réponse ; couverture du verrouillage système étendue au-delà des raccourcis Linux déjà validés localement, avec limites documentées ; sauvegarde/restauration et migration testées ; absence de secrets dans les logs ; plateformes annoncées testées ; limites et absence de récupération clairement documentées.
