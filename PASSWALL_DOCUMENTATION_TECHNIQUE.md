# PassWall — Référence technique unique

**Révision documentaire :** 22 novembre 2026 — vidange générationnelle et fermeture GUI de test (2I-4F-4A/4B), validations ciblées

**Version applicative actuelle :** 1.29.0

**Plateforme prioritaire :** Linux ARM64, Raspberry Pi 5, Debian 13, Qt 6

**Portée :** état réel du code, architecture cible validée, garanties, limites et travaux restants

## 1. Objet et statuts

Ce fichier est l'unique référence technique de PassWall. Il remplace la séparation historique entre documentation et TODO. Le code actuel reste la source de vérité pour les comportements présents ; les décisions validées ci-dessous définissent la cible sans présumer qu'elle est déjà implémentée.

Les statuts employés sont :

- **VALIDÉ** : décision approuvée pour l'architecture cible ;
- **IMPLÉMENTÉ** : comportement réellement présent dans le code ;
- **TESTÉ** : comportement vérifié dans le périmètre explicitement indiqué ;
- **À FAIRE** : modification, validation ou fonctionnalité encore nécessaire ;
- **À DÉFINIR** : choix technique ou fonctionnel non résolu.

Une fonctionnalité peut donc être **VALIDÉE** mais non **IMPLÉMENTÉE**. Un résultat **TESTÉ** sur un composant, un bus privé ou un coffre fictif ne constitue pas une certification générale ni une validation sur toutes les plateformes.

## 2. Périmètre du produit

### 2.1 Fonctions présentes

- **IMPLÉMENTÉ** — coffres SQLite chiffrés, autonomes et portables ;
- **IMPLÉMENTÉ** — création, ouverture, verrouillage et opérations CRUD sur les identifiants ;
- **IMPLÉMENTÉ** — interface Qt 6 Widgets, générateur de mots de passe et validation des champs obligatoires ;
- **IMPLÉMENTÉ** — intégration Firefox par Native Messaging ;
- **IMPLÉMENTÉ** — verrouillage automatique obligatoire, protection Linux par logind et coordination avec swaylock ;
- **IMPLÉMENTÉ** — instantanés SQLite, export manuel, sauvegardes automatiques, rotation et processus auxiliaire ;
- **IMPLÉMENTÉ** — restauration par remplacement complet, worker asynchrone, supervision et récupération contrôlée fondée sur des preuves persistantes historiques ;
- **VALIDÉ** — la cible simplifie cette restauration sans journal permanent PassWall ni reprise automatique ou semi-automatique après interruption ;
- **IMPLÉMENTÉ** — version applicative issue de CMake et options `--version` / `-v` ;
- **À FAIRE** — refonte des préférences et sauvegardes selon la cible de la section 5 ;
- **À FAIRE** — TOTP, passkeys et audit des mots de passe ;
- **À FAIRE** — installation et distribution reproductibles ;
- **À FAIRE** — validation Windows ; iOS reste ultérieur.

### 2.2 Hors périmètre actuel

- **VALIDÉ** — aucun serveur de référence, synchronisation automatique ou fusion entre copies ;
- **VALIDÉ** — aucun mécanisme d'autorisation ou de révocation des appareils ;
- **VALIDÉ** — aucune récupération cryptographique possible sans le mot de passe maître ;
- **VALIDÉ** — les copies d'un même coffre évoluent indépendamment et leurs divergences relèvent de l'utilisateur.

## 3. Environnement et construction

### 3.1 Environnement de développement connu

| Élément | Version ou environnement relevé |
|---|---|
| Matériel prioritaire | Raspberry Pi 5, 8 Go |
| Système | Debian 13.7 Trixie, ARM64 |
| Bureau | labwc / wlroots / Wayland |
| Compilateur | GCC/G++ 14.2.0 |
| CMake | 3.31.6 |
| Ninja | 1.12.1 |
| Qt | 6.8.2 |
| libsodium | 1.0.18 |
| SQLite | 3.46.1 |
| Git | 2.47.3 |

Ces valeurs sont des relevés de développement et doivent être revérifiées avant une diffusion.

### 3.2 CMake et exécutables

- **IMPLÉMENTÉ** — `project(PassWall VERSION 1.29.0 ...)` est la source unique de version.
- **IMPLÉMENTÉ** — `passwall_app --version` et `passwall_app -v` écrivent `PassWall 1.29.0` puis quittent avant l'initialisation de Qt et des services.
- **IMPLÉMENTÉ** — une compilation sans cible explicite construit les cinq exécutables Linux de production et leurs dépendances : `passwall_app`, `passwall_backup_worker`, `passwall_restore_worker`, `passwall_native_host` et `passwall-session-lock`.
- **IMPLÉMENTÉ** — tests, probes, `passwall_env_check` et `passwall_argon2_benchmark` sont exclus du build courant mais restent compilables explicitement.
- **IMPLÉMENTÉ** — la cible `passwall_all_tests` construit les binaires enregistrés auprès de CTest.
- **IMPLÉMENTÉ** — la cible CMake canonique est `SQLite3::SQLite3`, avec alias de compatibilité local si la version de CMake ne la fournit pas ; aucun hook `CMAKE_PROJECT_INCLUDE` externe n'est requis.

Commandes de référence :

```bash
cmake -S . -B build -G Ninja
cmake --build build --parallel 1

# Suite ciblée
cmake --build build --target passwall_snapshot_tests --parallel 1
ctest --test-dir build --output-on-failure -R '^VaultSnapshotServiceTest\.' -j1

# Ensemble des cibles de test, puis CTest
cmake --build build --target passwall_all_tests --parallel 1
ctest --test-dir build --output-on-failure --no-tests=error -j1

# Tests JavaScript indépendants de CTest
node --test tests/extension/*.test.cjs
```

### 3.3 Intégration continue

- **IMPLÉMENTÉ** — le workflow Linux ARM64 compile la production puis `passwall_all_tests` et exécute CTest avec Qt offscreen, séquentiellement et avec `--no-tests=error`.
- **TESTÉ** — la version 1.26 a produit 887 réussites CTest, aucun échec et un auxiliaire volontairement ignoré sur 888 cas enregistrés.
- **IMPLÉMENTÉ** — une étape séparée exécute les cinq tests JavaScript avec le lanceur natif Node.js et Node.js 24.
- **TESTÉ localement** — les cinq cas JavaScript réussissent avec Node.js 20.19.2.
- **À FAIRE** — confirmer sur GitHub ARM64 les évolutions 1.27 à 1.29 et maintenir la distinction entre tests offscreen/simulés et essais Firefox, Wayland, logind et swaylock réels.

### 3.4 Installation locale connue

L'installation pilote Linux rapportée utilise :

| Élément | Chemin |
|---|---|
| Application | `$HOME/.local/bin/passwall_app` |
| Native Host | `$HOME/.local/bin/passwall_native_host` |
| Coordinateur de session | `$HOME/.local/bin/passwall-session-lock` |
| Manifeste Firefox | `$HOME/.mozilla/native-messaging-hosts/org.passwall.native.json` |

- **TESTÉ historiquement** — l'application et le Native Host installés ont été comparés aux candidats validés par SHA-256 et contrôlés en `0755` lors des interventions correspondantes.
- **IMPLÉMENTÉ** — le manifeste local pointe vers le Native Host de `$HOME/.local/bin`.
- **À FAIRE** — l'état actuel de ces fichiers doit être revérifié avant toute nouvelle installation ; les sources présentes dans le dépôt ne prouvent pas que les binaires installés sont à jour.
- **À FAIRE** — fournir une installation reproductible incluant les deux workers, leurs permissions attendues, l'application, le Host, le coordinateur et l'extension. L'installation pilote manuelle n'est pas un mécanisme de distribution.

## 4. Coffre, cryptographie et stockage

### 4.1 Format et portabilité

- **IMPLÉMENTÉ** — un coffre est un fichier SQLite autonome contenant ses métadonnées cryptographiques, dont un `vault_id` de 16 octets.
- **VALIDÉ** — le coffre n'est lié cryptographiquement ni à la machine, ni au registre QSettings, ni à une autorisation d'appareil.
- **VALIDÉ** — une copie cohérente peut être ouverte sur une installation compatible avec son propre mot de passe maître.
- **VALIDÉ** — `vault_id` identifie une famille de copies ; ce n'est ni une preuve d'authenticité, ni une autorisation de remplacement ou de suppression.
- **IMPLÉMENTÉ** — le format est indépendant de l'extension du fichier.
- **VALIDÉ** — les anciens fichiers `.db` compatibles restent pris en charge ; `.pwdb` devient la convention nominale des nouveaux coffres et sauvegardes, sans migration ou renommage automatique imposé.

Une copie prise pendant une transaction ou une opération de remplacement n'est pas nécessairement cohérente. Il faut utiliser les mécanismes d'instantané ou attendre la fin effective de toutes les opérations, pas seulement un verrouillage visuel.

### 4.2 Cryptographie

- **IMPLÉMENTÉ** — libsodium est initialisée avant l'usage des buffers protégés.
- **IMPLÉMENTÉ** — Argon2id dérive la clé depuis le mot de passe maître ; les paramètres de production actuels sont trois opérations et 256 Mio.
- **IMPLÉMENTÉ** — XChaCha20-Poly1305 assure le chiffrement authentifié.
- **IMPLÉMENTÉ** — les entrées sont chiffrées individuellement ; les notes sont protégées avec les autres champs.
- **IMPLÉMENTÉ** — la clé de données est enveloppée et n'est rendue disponible qu'après authentification du maître.
- **IMPLÉMENTÉ** — `SecureBuffer` est non copiable, nettoie sa zone contrôlée et protège les clés et certains secrets temporaires.
- **À FAIRE** — audit cryptographique global V1 : sels, nonces, AAD, versionnement du format, paramètres Argon2id sur le matériel annoncé et chemins d'erreur.

Le nettoyage d'une zone contrôlée ne prouve pas l'effacement de toutes les copies historiques produites par `std::string`, Qt, SQLite, le noyau, le swap ou le support physique.

### 4.3 Politique SQLite V1

Chaque connexion de production pertinente applique puis relit :

| Paramètre | Valeur imposée |
|---|---|
| `journal_mode` | `DELETE` |
| `synchronous` | `EXTRA` (`3`) |
| `secure_delete` | `ON` (`1`) |
| `temp_store` | `MEMORY` (`2`) |
| `busy_timeout` | `3000` ms |
| `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` | activé et vérifié avant inspection |

- **IMPLÉMENTÉ** — `configureSqliteConnection()` centralise ces contrôles pour `VaultStorage` et `CredentialService`.
- **IMPLÉMENTÉ** — un journal WAL ou tout mode inattendu est refusé sans conversion, checkpoint volontaire ni suppression des fichiers auxiliaires.
- **IMPLÉMENTÉ** — connexions, statements, messages SQLite et temporaires de création disposent de protections RAII.
- **IMPLÉMENTÉ** — les CRUD utilisent `BEGIN IMMEDIATE` et ne publient leur résultat qu'après `COMMIT` confirmé.
- **IMPLÉMENTÉ** — les diagnostics distinguent cause initiale, rollback explicite réussi ou échoué, rollback automatique et état transactionnel incertain.
- **À FAIRE** — aucun moteur de migration de schéma ou de format n'existe. Une version incompatible doit rester refusée jusqu'à définition d'une migration sauvegardée et testée.

`synchronous=EXTRA` et les `fsync` renforcent les garanties demandées à l'OS ; ils ne prouvent pas la durabilité physique face à une panne d'alimentation, un contrôleur défaillant ou un support retiré.

### 4.4 Modèle métier et mémoire sensible

- **IMPLÉMENTÉ** — titre, nom d'utilisateur et mot de passe sont obligatoires à l'ajout et à la modification.
- **IMPLÉMENTÉ** — titre et nom d'utilisateur vides ou uniquement composés d'espaces Unicode sont refusés.
- **IMPLÉMENTÉ** — le mot de passe vide est refusé, mais sa valeur exacte n'est jamais normalisée ; un mot de passe composé d'espaces est accepté.
- **IMPLÉMENTÉ** — `CredentialService::validate()` porte la règle métier commune à la GUI et au service.
- **IMPLÉMENTÉ** — `CredentialSummary` et `listSummaries()` évitent de conserver durablement tous les mots de passe et notes dans `MainWindow`.
- **IMPLÉMENTÉ** — les temporaires sensibles ciblés de création, ouverture, ajout et modification sont associés à leurs nettoyeurs avant les appels susceptibles d'échouer.
- **À FAIRE** — maintenir un audit continu des conversions `QString` / `QByteArray` / `std::string`, du presse-papiers, des messages, propriétés Qt et nouvelles tâches asynchrones.

### 4.5 Responsabilités des composants

| Composant | Responsabilité actuelle |
|---|---|
| `CryptoEngine` / `SecureBuffer` | initialisation libsodium, dérivation, chiffrement authentifié et mémoire protégée |
| `VaultStorage` | schéma, métadonnées, création/publication du fichier et accès SQLite de cycle de vie |
| `VaultKeyService` | enveloppe et récupération de la clé de données après authentification |
| `VaultLifecycleService` | création et ouverture d'un coffre, sans publier de session après échec |
| `CredentialService` | validation, chiffrement, CRUD, résumés, authentification de toutes les entrées et notification en mémoire des mutations confirmées |
| `MainWindow` | session GUI, clé active, verrouillage, adaptateurs natifs et admissions sensibles |
| `VaultOperationGuard` | exclusion coopérative intra/interprocessus |
| `VaultSnapshotService` | copie SQLite cohérente et publication sécurisée |
| `BackupJob` / `passwall_backup_worker` | exécution et supervision asynchrones sans clé de déchiffrement |
| `AutomaticBackupCoordinator` | coordination automatique historique et frontière préparée, mais non activée en production, entre générations en mémoire et worker d'instantané |
| `VaultReplacementAuthorization` | autorité opaque issue du véritable propriétaire GUI |
| `VaultReplacementService` | moteur unique actuel de remplacement et récupération |
| `RestoreJob` / `passwall_restore_worker` | délégation, transport privé du maître et supervision du remplacement |
| `NativeRequestProcessor` | unique traitement métier des requêtes Firefox |
| `LinuxSessionMonitor` / `SessionLockService` | protection logind et verrouillage externe acquitté |

### 4.6 Utilitaires métier

- **IMPLÉMENTÉ** — `SiteMatcher` accepte HTTP/HTTPS, compare schéma, hôte et port effectif, rejette URL malformées et informations utilisateur, et interprète une URL sans schéma comme HTTPS.
- **IMPLÉMENTÉ** — `PasswordGenerator` produit de 8 à 128 caractères avec `randombytes_uniform`, garantit chaque catégorie choisie et mélange sans biais modulo.
- **TESTÉ** — ces deux composants possèdent leurs suites unitaires et sont intégrés aux parcours GUI/Firefox concernés.

## 5. Architecture cible des préférences et sauvegardes

Cette section décrit la cible approuvée. La section 6 décrit séparément l'implémentation historique encore présente.

### 5.1 Préférences globales

- **VALIDÉ** — un seul dossier racine global de sauvegardes est configuré pour l'installation.
- **VALIDÉ** — une politique globale de rétention s'applique à chaque famille : sept versions par défaut, minimum configurable de sept et aucune limite supérieure arbitraire imposée par la spécification.
- **VALIDÉ** — la configuration initiale demande clairement la racine et la rétention ; elle ne présente pas de case d'activation.
- **VALIDÉ** — les sauvegardes automatiques commencent après une configuration initiale valide.
- **VALIDÉ** — les préférences sont locales et ne sont jamais embarquées dans le coffre.
- **VALIDÉ** — une configuration globale absente, corrompue ou incomplète ne doit pas empêcher l'ouverture d'un coffre sain. PassWall doit permettre sa reconfiguration et signaler que les sauvegardes automatiques ne sont pas opérationnelles tant qu'une destination valide n'est pas définie.
- **VALIDÉ** — aucune sauvegarde ne doit être présentée comme active ou réussie sans configuration globale valide.
- **VALIDÉ** — la reconfiguration des préférences ordinaires ne contourne jamais les protections historiques de restauration encore actives pendant leur transition. La cible n'introduit toutefois aucun journal permanent de remplacement.
- **VALIDÉ** — changer la racine ne déplace ni ne supprime les anciennes sauvegardes.
- **VALIDÉ** — PassWall ne modifie pas automatiquement les permissions du dossier choisi par l'utilisateur.
- **VALIDÉ** — les sous-dossiers gérés et les fichiers créés par PassWall reçoivent des permissions privées appropriées.
- **À DÉFINIR** — possibilité de désactiver ultérieurement les sauvegardes depuis les paramètres globaux.
- **IMPLÉMENTÉ — fondation 2I-3A** : `GlobalBackupPreferencesStore` utilise un fichier INI utilisateur distinct, obtenu par `QSettings::IniFormat` avec l'organisation `PassWall` et l'application `BackupPreferences`. Sous Linux, l'emplacement nominal est `~/.config/PassWall/BackupPreferences.ini`; il n'est pas codé en dur et suit les emplacements utilisateur de QSettings sur les futures plateformes.
- **IMPLÉMENTÉ — schéma 2I-3A** : le fichier versionné contient uniquement `backup/rootDirectory` et `backup/retainedVersions`. La rétention vaut sept par défaut, refuse toute valeur inférieure à sept et utilise un entier non signé sans plafond produit arbitraire. Aucun coffre, `localId`, `vault_id`, secret, état de mutation, tentative ou preuve de récupération n'y est enregistré.
- **IMPLÉMENTÉ — états 2I-3A** : l'API distingue `Absent`, `Valid`, `Invalid`, `ReadError` et `WriteError`. Une absence ne crée pas le fichier et expose seulement la valeur par défaut de sept ; fichier incomplet, version inconnue, chemin non absolu/non normalisé et rétention invalide restent séparés des erreurs d'accès ou de publication.
- **IMPLÉMENTÉ — persistance 2I-3A** : QSettings exige une synchronisation atomique, le fichier est limité, relu depuis ses octets physiques, privé pour le propriétaire et synchronisé avec son répertoire. Une publication visible dont la synchronisation finale échoue reste un `WriteError`, jamais une réussite inventée. Le dossier racine choisi n'est ni créé, ni chmodé, ni autrement modifié par ce stockage.
- **À FAIRE — intégration** : aucun consommateur de production n'utilise encore ces préférences. Le futur chemin générationnel devra exiger l'état `Valid`, puis effectuer séparément ses contrôles opérationnels de destination ; une préférence syntaxiquement valide ne constitue ni une capacité d'écriture ni une preuve que le support est disponible.
- **À DÉFINIR** — export éventuel du nouveau fichier de préférences ; l'import n'est pas spécifié.

### 5.2 Familles et disposition des fichiers

- **VALIDÉ** — chaque `vault_id` complet correspond à une famille et à un sous-dossier de la racine globale. Le nom de ce sous-dossier est l'encodage du `vault_id` en 32 caractères hexadécimaux minuscules, sans séparateur.
- **VALIDÉ** — une sauvegarde est une copie SQLite cohérente, autonome et directement ouvrable, conservant le `vault_id` de sa source.
- **VALIDÉ** — les nouvelles sauvegardes utilisent l'extension nominale `.pwdb`.
- **VALIDÉ** — le nom nominal est l'horodatage UTC `YYYY-MM-DD_HH-MM-SS.pwdb`.
- **VALIDÉ** — en cas de collision dans la même seconde, le suffixe `_2`, puis `_3`, `_4`, etc. est ajouté avant `.pwdb`, uniquement lorsque nécessaire.
- **VALIDÉ** — deux fichiers de travail partageant un `vault_id` alimentent la même famille. PassWall ne fusionne pas leurs divergences et ne choisit pas une branche canonique.
- **À DÉFINIR** — présentation à l'utilisateur de plusieurs principaux divergents appartenant à la même famille.
- **À DÉFINIR avant la rotation sans catalogue** — politique de protection de l'historique lorsque des principaux divergents partagent le même dossier familial : une version admissible d'une copie A peut suffire à écarter la première copie de B, et une rétention commune peut évincer les anciennes versions de A au profit de B. Cette conséquence possible de la politique familiale n'autorise ni une nouvelle règle de sauvegarde ni une exclusion de suppression sans décision explicite.

Le `vault_id` et la conformité du nom servent au routage et à l'organisation de la famille. Ils ne suffisent jamais, seuls, à authentifier une sauvegarde, autoriser une restauration ou justifier une suppression.

- **IMPLÉMENTÉ — fondation 2I-3B** : `BackupDestinationPreparer` exige un `vault_id` réel de 16 octets relu depuis le coffre sous une capacité d'instantané liée au périphérique et à l'inode attendus. Il forme le dossier familial avec les 32 caractères hexadécimaux minuscules et conserve en mémoire le coffre, la génération et les identités physiques de la racine et de la famille.
- **IMPLÉMENTÉ — création privée** : la racine configurée est seulement inspectée ; ses permissions ne sont jamais modifiées. Le sous-dossier familial est créé par `mkdirat` en `0700`, ouvert sans suivre de lien et recoupé avec son entrée nommée. Un dossier existant n'est accepté que s'il appartient à l'utilisateur, reste le même inode et possède déjà les permissions privées attendues.
- **IMPLÉMENTÉ — nommage préparatoire** : le nom UTC nominal et les suffixes `_2`, `_3`, etc. sont choisis par inspection sans suivi de liens. Aucun fichier de réservation n'est créé : le nom préparé n'est donc ni une publication ni une promesse d'exclusivité. La publication future devra encore utiliser le mécanisme sans écrasement de `VaultSnapshotService`.
- **IMPLÉMENTÉ — revalidation et transfert** : l'admission 2I-4B recontrôle la source et son `vault_id`, la racine, le dossier familial et l'absence de la destination, puis déplace sans réacquisition la capacité et l'identité familiale vers le moteur d'instantané. Une collision ou substitution postérieure reste refusée par les contrôles du pilote, du worker et de la publication sans écrasement.
- **IMPLÉMENTÉ — liaison 2I-3C** : une inspection préalable peut désormais imposer au préparateur les identités de racine et de famille qu'elle a observées. Une substitution entre la découverte d'une famille et la préparation de la destination est ainsi refusée au lieu d'être acceptée comme un nouvel emplacement équivalent.
- **IMPLÉMENTÉ — arbitrage 2I-4C inactif** : le coordinateur accepte désormais sur son thread propriétaire une préparation 2I-4B sous le type transitoire explicite `InitialCopy`. Une génération CRUD et une génération de session restent deux liaisons distinctes ; aucune valeur zéro ou conversion implicite ne transforme la première copie en mutation fictive.
- **À FAIRE — intégration** : aucun consommateur de production ne démarre encore les offres typées du coordinateur. Le futur consommateur devra utiliser l'admission à usage unique 2I-4B après l'arbitrage 2I-4C, sans traiter l'objet comme une autorisation de restauration ou de suppression.

### 5.3 Déclenchement automatique

- **VALIDÉ** — seuls les coffres effectivement ouverts sont concernés par la gestion automatique. PassWall ne recherche pas les coffres fermés et ne maintient aucune liste permanente des coffres connus à cette fin.
- **VALIDÉ** — PassWall suit uniquement en mémoire, pour la session du coffre, les modifications métier confirmées. Aucun nouveau registre persistant de modifications n'est créé.
- **VALIDÉ** — l'indicateur de modification n'est activé qu'après confirmation du `COMMIT` SQLite. Une préparation, une écriture tentée ou une transaction annulée ne le déclenchent pas.
- **VALIDÉ** — après chaque `COMMIT` métier réussi, une sauvegarde automatique est demandée avec un délai de regroupement de vingt secondes ; chaque nouveau `COMMIT` réussi remet ce délai à zéro.
- **VALIDÉ** — si le verrouillage intervient avant l'expiration, la demande devient immédiate après le nettoyage des secrets ; le verrouillage ne doit jamais attendre la copie.
- **VALIDÉ — fermeture normale générationnelle** : une demande de fermeture rend immédiatement éligibles les générations CRUD confirmées, invalide sans attente la session et efface les secrets, puis laisse la vidange se terminer de manière asynchrone. Aucune boîte de dialogue « attendre ou quitter » ni confirmation répétée n'est demandée : la fenêtre se ferme automatiquement lorsque les workers concernés ont effectivement terminé et que la vidange est terminale, y compris en cas d'échec ou de suspension dûment distingué d'une réussite. Une nouvelle demande de fermeture ne doit ni recommencer le nettoyage, ni perdre les générations déjà confirmées ou celles qui se terminent pendant la vidange.
- **VALIDÉ** — une sauvegarde peut s'exécuter pendant que le coffre reste déverrouillé. Plusieurs modifications regroupées ne produisent qu'une seule copie lorsqu'un même instantané peut les couvrir ; une modification postérieure au lancement reste une demande distincte tant que sa présence dans l'instantané n'est pas démontrée.
- **VALIDÉ** — un coffre ouvert et peuplé qui ne possède aucune sauvegarde admissible dans la racine actuelle doit recevoir une première sauvegarde, sous réserve d'une configuration globale valide et des règles de déclenchement ci-dessus.
- **VALIDÉ** — ouvrir puis verrouiller sans modification confirmée un coffre qui possède déjà une sauvegarde admissible ne crée pas de sauvegarde supplémentaire.
- **VALIDÉ** — pour un nouveau coffre, le premier `COMMIT` d'une entrée déclenche la demande de première sauvegarde selon le délai de regroupement, avec accélération au verrouillage.
- **VALIDÉ** — après la configuration initiale ou un changement de racine, les coffres déjà peuplés sont progressivement pris en charge lorsqu'ils sont ouverts puis verrouillés. Les coffres fermés ne sont ni recherchés ni sauvegardés en arrière-plan.
- **IMPLÉMENTÉ — fondation 2I-3C inactive** : `InitialBackupPreparer` reçoit uniquement le contexte transitoire d'une session que son futur propriétaire déclare réellement authentifiée. Sous une capacité d'instantané liée au chemin, au périphérique et à l'inode, il relit la structure, le `vault_id` et la présence d'au moins une entrée. Coffre vide, configuration globale indisponible ou identité divergente ne produisent aucune demande.
- **IMPLÉMENTÉ — découverte 2I-3C** : pour le seul besoin de décider d'une première copie, une version est provisoirement admissible si elle se trouve dans la famille attendue, porte exactement un nom UTC géré et passe les contrôles complets de structure SQLite/PassWall, de propriétaire, de permissions, de stabilité physique et de `vault_id`. Ce contrôle sans clé n'authentifie pas le contenu chiffré, n'autorise ni restauration ni suppression et ne fixe pas les critères définitifs de rotation encore ouverts.
- **IMPLÉMENTÉ — demande distincte 2I-3C** : un coffre peuplé sans version admissible produit un `InitialBackupRequest` transitoire lié à la génération de session et à une `PreparedBackupDestination`. Si une génération CRUD est déjà en attente, elle couvre l'obligation de première copie et aucune seconde demande n'est créée. Aucun état de cette décision n'est écrit sur disque.
- **IMPLÉMENTÉ — cycle de session 2I-3C** : les points d'annulation permettent au futur propriétaire asynchrone de rejeter une session fermée ou remplacée avant le retour. L'inspection est volontairement synchrone au niveau du service et son contrat interdit son exécution sur le thread GUI ; aucun raccordement à `MainWindow`, au coordinateur ou au worker n'est encore actif.
- **IMPLÉMENTÉ — admission 2I-4B inactive** : `InitialBackupRequest` est désormais un objet mobile à usage unique. Son contexte final distingue explicitement génération de session et génération de mutation, exige le mode `Generational`, une session courante, l'absence de fermeture et l'admissibilité de l'opération, puis revalide source, `vault_id`, racine, famille et nom encore libre sur le thread propriétaire.
- **IMPLÉMENTÉ — transfert 2I-4B** : après admission, la capacité d'instantané déjà détenue est déplacée directement vers `BackupJob::startSnapshotReserved()` sans nouvel appel à `trySnapshotAccess()` ni exposition publique de la garde. Toute tentative, y compris refus ou échec synchrone de démarrage, consomme la préparation ; RAII libère la réservation si le worker n'en devient pas propriétaire. Le raccordement production reste absent.
- **IMPLÉMENTÉ — fusion 2I-4C inactive** : l'admission propriétaire relit l'identité du coffre et revalide la préparation avant de l'insérer dans la même file à jetons que les générations CRUD. Une génération CRUD déjà planifiée, offerte, en attente ou active pour le même fichier physique couvre l'obligation de première copie ; la préparation redondante est alors libérée par RAII sans second worker.
- **IMPLÉMENTÉ — courses 2I-4C** : une mutation confirmée pendant l'inspection, entre préparation et admission, ou après une offre `InitialCopy` gagne l'arbitrage. Une offre initiale non démarrée est invalidée, son jeton devient inutilisable, sa capacité est libérée et le délai CRUD repart du dernier `COMMIT`. Les générations CRUD restent monotones dans leur propre session et une offre remplacée n'est jamais présentée comme publiée.
- **VALIDÉ** — une sauvegarde automatique n'abandonne jamais silencieusement une édition non enregistrée.
- **IMPLÉMENTÉ — production historique** : un échec suspend actuellement les tentatives automatiques du coffre dans le registre historique jusqu'à une reprise explicite, sans conserver d'instantané interrompu à reprendre. Ce mécanisme persistant reste actif uniquement avec le moteur `Historical`.
- **VALIDÉ** — une sauvegarde demandée ou simplement lancée n'est pas une sauvegarde réussie. Tout échec doit être signalé sans annoncer une réussite sur la seule base d'une demande, d'un fichier visible ou de la fin d'un processus.
- **VALIDÉ — cible** : après `Failed` ou `Unknown`, le moteur générationnel signale l'incident et suspend en mémoire les nouvelles tentatives du coffre jusqu'à une reprise explicite. Les `COMMIT` ultérieurs restent suivis comme non couverts, mais ne déclenchent aucune tentative pendant cette suspension. Il n'existe ni suspension persistante, ni historique d'erreurs, ni boucle de tentatives automatiques, ni journal de reprise ou mécanisme de réparation automatique ; un redémarrage peut donc oublier la suspension.
- **VALIDÉ — reprise générationnelle** : une reprise explicite n'est admise qu'après terminaison effective de tout ancien worker susceptible d'agir. Elle autorise une seule nouvelle tentative couvrant le dernier besoin connu ; les demandes répétées, anciens jetons et résultats tardifs ne peuvent ni créer un doublon ni lever une suspension plus récente. Une sauvegarde de résultat incertain n'est jamais supprimée pour permettre cette reprise.
- **IMPLÉMENTÉ — lot 2I-4F-1 inactif** : le coordinateur générationnel conserve une suspension volatile liée au chemin, au `vault_id`, au périphérique et à l'inode, distincte de la session authentifiée et de toute autorisation cryptographique. `Failed` et `Unknown` absorbent les besoins non démarrés du même coffre ; les commits suivants actualisent la génération non couverte sans réarmer le délai. La reprise propriétaire revalide l'identité physique, refuse un worker encore vivant et produit au plus une nouvelle offre. Pour `InitialCopy`, elle demande une nouvelle inspection explicitement forcée afin qu'un fichier incertain mais structurellement lisible ne supprime pas le besoin de copie fraîche. Une époque transitoire empêche un ancien résultat de lever une suspension récente.
- **TESTÉ — lot 2I-4F-1** : les 138/138 tests ciblés du coordinateur rapportés par l'utilisateur réussissent. Ils couvrent l'échec, le résultat incertain, les commits et verrouillages suspendus, la reprise unique, le worker encore vivant, le résultat obsolète, l'isolation physique, l'absence de persistance et la neutralité historique.
- **VALIDÉ** — pendant la vie du processus, une première copie échouée reste soumise à la même suspension et exige une reprise explicite avec une nouvelle inspection sécurisée. Après redémarrage, la suspension peut être oubliée et une nouvelle inspection d'un coffre toujours dépourvu de version admissible peut de nouveau proposer une première copie.
- **VALIDÉ** — aucune durée maximale globale n'est imposée à une sauvegarde saine ; contention SQLite, annulation et erreurs d'E/S restent traitées séparément.
- **VALIDÉ — conséquence acceptée** : après une interruption brutale avant l'expiration du délai ou avant la publication confirmée, les modifications déjà validées restent protégées par les transactions SQLite, mais l'indicateur en mémoire est perdu. PassWall ne garantit pas le rattrapage automatique de la sauvegarde manquée au redémarrage.
- **VALIDÉ — conséquence acceptée** : après un plantage, aucun état d'échec ou de modification non sauvegardée n'est restauré depuis un registre. L'utilisateur relance PassWall et peut vérifier ses données ; les sauvegardes déjà publiées restent indépendantes.

Le choix d'un suivi en mémoire ne modifie ni l'atomicité des transactions et journaux internes SQLite, ni les garanties de copie cohérente et de publication sûre. Il accepte en revanche qu'une interruption avant une publication confirmée puisse laisser l'historique de sauvegardes en retard sur l'état durable du coffre.

### 5.4 Publication et rotation

- **VALIDÉ** — la validation d'intégrité de la source et les garanties actuelles de copie cohérente, publication sans écrasement et confirmation de durabilité doivent être préservées.
- **VALIDÉ** — la rotation ne commence qu'après la publication réussie et suffisamment confirmée de la nouvelle sauvegarde.
- **VALIDÉ** — la rétention conserve sept sauvegardes par famille par défaut, ne peut être configurée sous sept et ne possède pas de plafond arbitraire dans la spécification.
- **VALIDÉ** — l'historique correspond aux dernières sauvegardes effectivement publiées, pas nécessairement aux dernières modifications SQLite. Une famille peut contenir moins de sept versions tant que cet historique n'a pas encore été constitué.
- **VALIDÉ** — aucun catalogue persistant individuel des versions n'est requis dans la cible.
- **VALIDÉ** — une sauvegarde peut être considérée comme gérée lorsqu'elle se trouve dans le sous-dossier de famille attendu, respecte la convention de nommage et satisfait les contrôles techniques nécessaires.
- **VALIDÉ** — la rotation n'exige pas une preuve historique individuelle de création ou de publication pour chaque ancienne version. Un fichier déposé manuellement peut donc être pris en compte s'il satisfait les mêmes conditions de dossier, de nommage, d'identité et de sécurité.
- **VALIDÉ** — elle ne réauthentifie pas cryptographiquement et exhaustivement toutes les anciennes versions avant chaque suppression.
- **VALIDÉ** — les fichiers ambigus, hors convention, hors sous-dossier familial ou ne satisfaisant pas les contrôles techniques ne sont pas supprimés. Les liens symboliques, substitutions concurrentes et suppressions hors périmètre restent refusés.
- **VALIDÉ** — un export manuel n'est pas intégré automatiquement à la rotation ; s'il est ensuite placé manuellement dans le dossier géré et rendu conforme à toutes les conditions, il peut devenir une version gérée comme tout autre fichier admissible.
- **À DÉFINIR** — critères techniques précis d'admission à la suppression : fichier ordinaire, parcours sans lien, identité stable, nom géré, métadonnées minimales, `vault_id` concordant et conduite en cas d'ambiguïté ou de changement concurrent.

La séquence cible est simple et sans état persistant propre à la rotation :

1. créer et vérifier la nouvelle sauvegarde ;
2. confirmer suffisamment sa publication ;
3. compter les versions admissibles du dossier familial ;
4. si leur nombre dépasse la rétention, identifier les plus anciennes ;
5. supprimer seulement les versions admissibles les plus anciennes jusqu'au nombre configuré.

- **VALIDÉ** — aucun catalogue, reçu de rotation, historique de suppression ou système persistant de reprise n'est créé.
- **VALIDÉ** — une erreur de suppression est un échec de rotation distinct : elle n'efface ni n'invalide la nouvelle sauvegarde déjà publiée.

La présence d'un fichier, un code de sortie nul ou le début d'une copie ne prouvent pas une publication réussie. Une erreur postérieure ne doit pas provoquer la suppression d'une publication déjà valide.

### 5.5 Résultats et diagnostics

- **VALIDÉ** — chaque tentative produit un résultat borné et une notification indiquant l'opération concernée.
- **VALIDÉ** — lorsque la cause est identifiable, le diagnostic présente la raison et les informations système réellement disponibles, notamment l'`errno` ou le code SQLite pertinent. Aucun code d'erreur n'est inventé.
- **VALIDÉ** — les diagnostics techniques nécessaires restent attachés au résultat d'exécution, sans historique persistant des erreurs.
- **VALIDÉ** — un échec de création, un résultat de publication ou de synchronisation non confirmé et un échec de rotation sont distingués. Une sauvegarde publiée avec une suppression ancienne impossible reste une sauvegarde réussie accompagnée d'une erreur de rotation.
- **VALIDÉ** — lorsqu'une publication est visible mais que sa durabilité n'est pas confirmée, PassWall avertit qu'il ne peut pas garantir la réussite ; il ne transforme pas l'incertitude en succès.
- **À DÉFINIR** — conduite ultérieure exacte pour une publication visible mais de durabilité non confirmée, sans journal de reprise ni nouvelle suppression risquée.

Les diagnostics ne contiennent aucun secret. Des formulations compréhensibles peuvent accompagner, sans les remplacer ni les fabriquer, des causes telles que `ENOSPC` (28), `EACCES` (13) ou un code SQLite effectivement retourné.

### 5.6 Consultation et copie de travail

- **VALIDÉ** — les versions situées sous la racine gérée sont consultables en lecture seule.
- **VALIDÉ** — leur modification exige la création d'une copie de travail hors du dossier géré.
- **VALIDÉ** — cette copie de travail conserve le `vault_id` ; elle appartient donc à la même famille si elle est ensuite modifiée et sauvegardée.
- **À FAIRE** — définir et implémenter une vraie session de lecture seule empêchant CRUD, Native Messaging d'écriture, suivi de modification et opérations incompatibles ; désactiver seulement les boutons serait insuffisant.
- **À FAIRE** — implémenter la copie de travail par le moteur d'instantané, sans écrasement ni ouverture automatique.
- **À DÉFINIR** — manière de retrouver et consulter les sauvegardes laissées dans une ancienne racine.

## 6. Implémentation actuelle des sauvegardes et écarts

### 6.1 Registre monolithique actuel

`VaultPreferencesStore` conserve dans `vaultRegistry/data`, au sein du fichier QSettings global existant, un tableau JSON de `VaultRegistration`.

- **IMPLÉMENTÉ** — chaque principal reconnu possède un `localId` distinct du `vault_id`, une identité physique et son chemin.
- **IMPLÉMENTÉ** — une copie reconnue comme nouveau fichier reçoit un nouvel enregistrement et n'hérite pas automatiquement des préférences.
- **IMPLÉMENTÉ** — les préférences sont actuellement par coffre : automatique désactivé par défaut, destination vide et rétention de sept versions.
- **IMPLÉMENTÉ** — le même enregistrement contient `backupRequired`, suspension, tentative, destination, époque, catalogue des versions et état de rotation.
- **IMPLÉMENTÉ** — le registre contient aussi les intentions et reçus de restauration/récupération.
- **À FAIRE — écart actuel** : ces responsabilités sont incompatibles avec les préférences globales et la rotation sans catalogue de la cible.
- **À FAIRE — écart actuel** : les états persistants de modification, d'échec, de suspension, de tentative et de rotation ne font pas partie de la politique cible 0C.
- **À FAIRE — risque de transition** : supprimer simplement le registre supprimerait aussi des preuves historiques encore indispensables aux opérations inachevées. Elles doivent rester lisibles et opposables jusqu'à leur résolution contrôlée ; elles ne seront pas transférées dans un nouveau journal permanent.

`GlobalBackupPreferencesStore` constitue désormais une fondation distincte, sans remplacer ce registre :

- **IMPLÉMENTÉ — lot 2I-3A** : `BackupPreferences.ini` conserve seulement la racine globale et la rétention cible ; il ne lit ni n'écrit `PassWall.conf` ou `vaultRegistry/data` ;
- **IMPLÉMENTÉ — indépendance métier** : son absence, son invalidité ou une erreur d'accès n'interviennent dans aucun chemin d'ouverture ou CRUD. Les preuves historiques de récupération restent consultées par leurs mécanismes actuels ;
- **IMPLÉMENTÉ — production inchangée** : le coordinateur construit par `MainWindow` reste `Historical`. Les préférences par coffre, la destination, le catalogue et la rotation historiques restent donc temporairement actifs jusqu'aux lots de basculement ;
- **TESTÉ — lot 2I-3A** : les dix tests ciblés rapportés après correction du conflit entre le verrou applicatif et celui de QSettings couvrent états, valeurs, erreurs, persistance, permissions et indépendance de `PassWall.conf`.

### 6.2 Exclusion et suivi des mutations

- **IMPLÉMENTÉ** — `VaultOperationGuard` distingue les accès métier partagés, les accès d'instantané partagés et les réservations exclusives de remplacement.
- **IMPLÉMENTÉ — préparation 2I-3B inactive** : la nouvelle préparation acquiert explicitement l'accès d'instantané existant, vérifie son identité physique avec `matchesSnapshotIdentity()`, relit le `vault_id` avec les contrôles de récupération encore actifs et conserve la capacité jusqu'à sa consommation ou sa destruction. Une restauration exclusive ne peut donc pas franchir cette préparation ; les accès métier compatibles restent possibles.
- **IMPLÉMENTÉ — destination 2I-3B** : `VaultSnapshotService::inspectDestinationDirectory()` reste la politique d'admission des systèmes de fichiers et chemins. La création familiale ajoute une ouverture composante par composante sans liens, une identité racine/famille stable, des permissions `0700`, une synchronisation du dossier créé et une revalidation avant usage. Ces contrôles n'affaiblissent ni la publication sans écrasement ni la vérification finale du worker.
- **TESTÉ — lot 2I-3B** : les onze tests ciblés rapportés sont réussis ; ils couvrent familles partagées ou distinctes, UTC et collisions, chemins, liens, permissions, identités, substitutions, absence d'écrasement et durée de vie de la réservation.
- **IMPLÉMENTÉ — inspection 2I-3C** : `VaultSnapshotService::prevalidateVaultSource()` peut restituer, après validation structurelle et contrôle de stabilité, le `vault_id` et l'existence d'entrées sans clé de déchiffrement. Le préparateur de première copie garde simultanément l'accès d'instantané du principal et revalide racine et famille avant de remettre sa demande transitoire.
- **TESTÉ — lots 2I-3B/2I-3C** : les 21 tests ciblés rapportés sont réussis, ainsi que les deux tests directement concernés de prévalidation de restauration. Ils couvrent destination, réservation unique, coffre vide ou peuplé, version existante, changement de racine, famille partagée, configuration indisponible, génération CRUD en attente, substitutions et fermeture de session.
- **IMPLÉMENTÉ — lot 2I-4B inactif** : la préparation conserve un identifiant de liaison opaque ; la demande initiale l'interprète exclusivement comme génération de session. L'admission finale est exécutée sur le thread propriétaire du `BackupJob`, consomme définitivement la demande et transfère la même capacité après revalidation complète. Aucun constructeur de production n'active ce chemin.
- **TESTÉ — lot 2I-4B, validation ciblée** : 29/29 tests de `passwall_backup_destination_tests` (11 destinations et 18 premières copies/admissions), 2/2 tests de sélection du mode du coordinateur et 2/2 tests de réservation `BackupJob` ont été exécutés avec succès dans le terminal utilisateur, soit 33/33 tests ciblés. Ils couvrent notamment consommation unique, transfert sans réacquisition, admissions refusées, substitutions, annulation, échec synchrone et libération RAII. Aucun CTest complet ni essai de production générationnelle n'est déduit de ces résultats.
- **IMPLÉMENTÉ — lot 2I-4C inactif** : `AutomaticBackupCoordinator` porte une seule file d'arbitrage et émet une offre transitoire typée `CrudGeneration` ou `InitialCopy`. L'admission d'une première copie vérifie le mode, le thread, la session, le coffre physique et la destination préparée. Une mutation concurrente remplace seulement une offre initiale non démarrée et invalide son jeton ; une tentative CRUD active et ses résultats restent régis par les contrats 2D–2H.
- **TESTÉ — lot 2I-4C** : les tests ciblés rapportés réussissent ; ils couvrent première copie seule, génération déjà en attente, commit injecté pendant l'inspection, commit entre préparation et admission, remplacement d'une offre, regroupement de plusieurs mutations, fermeture ou session obsolète, libération RAII et neutralité du mode historique.
- **IMPLÉMENTÉ — coordination 2I-4D inactive** : le coordinateur expose en mémoire des phases distinctes pour l'inspection initiale, la préparation détenant une capacité, la demande en attente ou offerte, la contention, la tentative et le worker réellement vivant. Une activité d'inspection porte un identifiant éphémère lié au coffre physique et à la génération de session ; le coordinateur conserve lui-même la demande préparée et sa capacité jusqu'à admission, annulation ou invalidation, de sorte qu'une réponse tardive ne peut ni être admise ni libérer deux fois la réservation.
- **IMPLÉMENTÉ — préadmission 2I-4D** : l'export manuel et l'émission d'une autorisation de restauration consultent cette activité avant de détruire une session ou de créer une intention persistante. Une incompatibilité produit un diagnostic et n'annule jamais implicitement la sauvegarde automatique. Ce contrôle de présentation reste anticipé et ne constitue jamais une réservation ni une autorisation de remplacement.
- **IMPLÉMENTÉ — arbitrage 2I-4F-2 inactif** : après les dialogues et confirmations, mais avant le verrouillage volontaire, `AutomaticBackupCoordinator::acquireUserOperation()` délivre sur son thread propriétaire une capacité RAII mobile, liée au type d'opération et au chemin concerné. Une sauvegarde déjà inspectée, préparée, en attente, offerte, en contention, tentée ou encore supervisée a priorité et refuse cette capacité. Une opération manuelle admise en premier empêche inversement l'offre d'une demande automatique ultérieure du même coffre jusqu'à l'acquisition exclusive finale ; les demandes CRUD restent conservées en mémoire et sont réordonnancées à la libération.
- **IMPLÉMENTÉ — transfert 2I-4F-2 inactif** : l'export acquiert la capacité avant le verrouillage, puis la consomme seulement après nettoyage du coffre ; il acquiert alors la réservation exclusive historique et la transfère directement à `BackupJob::startReserved()`. La restauration acquiert également l'admission avant le verrouillage, la marque à usage unique après le nettoyage, puis acquiert hors du thread GUI la réservation exclusive du principal sélectionné ; `VaultReplacementAuthorization::reserve()` vérifie cette garde contre l'enregistrement avant d'en devenir propriétaire. L'admission logique reste vivante jusqu'à cette acquisition ou son refus, puis RAII la libère : il n'existe donc pas d'intervalle coopératif sans admission logique ni réservation physique. Cette capacité ne crée aucune intention, n'est ni sérialisable ni persistante et ne remplace jamais `VaultOperationGuard` ou l'autorisation opaque 6A. En mode `Historical`, les deux parcours conservent leurs appels historiques à `BackupJob::start()` et à la réservation interne de l'autorisation.
- **IMPLÉMENTÉ — isolation 2I-4F-2 inactive** : les admissions sont indexées par coffre ; un worker `Unknown` encore vivant reste bloquant, tandis qu'un `Failed` ou `Unknown` dont le worker a réellement terminé ne bloque plus les opérations manuelles une fois ses verrous libérés. Deux chemins indépendants ne se bloquent pas par ce seul arbitrage. Une nouvelle session authentifiée révoque les admissions non consommées de l'ancienne session ; une réponse tardive ne peut donc pas acquérir ensuite une réservation.
- **IMPLÉMENTÉ — corrections 2I-4F-2** : l'admission finale de remplacement inspecte le registre avec `VaultPreferencesStore::inspectReserved()` sous la réservation exclusive déjà acquise, sans perdre la porte de récupération. `ManualBackupOperationAdmission` reste une amie de l'autorisation de remplacement dans tous les builds, et non uniquement sous `PASSWALL_REPLACEMENT_TESTING`.
- **TESTÉ — lot 2I-4F-2** : l'utilisateur rapporte 146/146 tests de sauvegarde automatique, 165/165 tests de remplacement et 5/5 tests GUI ciblés réussis après les deux corrections précédentes.
- **IMPLÉMENTÉ — invalidation 2I-4F-3 inactive** : chaque lecture de `BackupPreferences.ini` transporte désormais sa provenance transitoire. Une destination préparée conserve la racine, la rétention et le fichier de configuration exacts ayant servi à sa préparation. Une publication confirmée des préférences notifie le coordinateur, y compris lorsque la synchronisation finale reste incertaine, car l'ancien contenu ne peut alors plus être présumé courant.
- **IMPLÉMENTÉ — cohérence 2I-4F-3 inactive** : sur son thread propriétaire, le coordinateur annule sans attente l'inspection initiale, libère par RAII les premières copies préparées et invalide les jetons non lancés. Les générations CRUD correspondantes sont conservées et réoffertes seulement sous une configuration de nouveau valide ; elles ne deviennent ni `Published`, ni `Failed`, ni `Unknown` du seul fait de la reconfiguration. Une nouvelle inspection est demandée pour une première copie devenue obsolète.
- **IMPLÉMENTÉ — admission finale 2I-4F-3 inactive** : avant de consommer un jeton, le coordinateur compare l'instantané courant aux préférences de préparation. La frontière `BackupDestinationPreparer` relit en plus le fichier physique lorsque sa provenance est disponible ; changement de racine, de rétention, état absent/invalide ou fichier différent refusent ainsi l'ancienne destination. Un worker déjà lancé n'est jamais interrompu par ce changement et conserve son résultat réel ainsi que sa suspension éventuelle.
- **À FAIRE — consommateur 2I-4F-3** : le futur consommateur de production devra détruire immédiatement toute `PreparedBackupDestination` CRUD qu'il détient lorsqu'il reçoit `generationalBackupRequestInvalidated`. La revalidation finale empêche déjà son utilisation, mais seul le propriétaire de cet objet mobile peut libérer sans délai sa capacité RAII avant qu'elle ne soit remise au coordinateur.
- **TESTÉ — lot 2I-4F-3** : l'utilisateur rapporte 11/11 tests des préférences globales, 29/29 tests de préparation des destinations, 150/150 tests du coordinateur et 5/5 tests GUI ciblés réussis. Ils couvrent notamment la modification pendant l'inspection, après préparation, l'indisponibilité de configuration avec générations conservées, la rétention modifiée et le worker déjà actif.
- **IMPLÉMENTÉ — vidange 2I-4F-4A inactive** : `beginGenerationalShutdownDrain()` constitue une frontière propriétaire, asynchrone et idempotente distincte de `shutdown()`. Elle annule sans attente une inspection initiale non achevée, supprime le délai de regroupement d'une génération CRUD effectivement confirmée et laisse la file générationnelle, ses jetons et le consommateur existant terminer le travail. Une mutation confirmée pendant la vidange devient immédiatement une demande distincte ; aucune génération n'est inventée en l'absence de `COMMIT`.
- **IMPLÉMENTÉ — résultat de vidange 2I-4F-4A inactif** : l'état transitoire distingue demande en cours, worker encore vivant, vidange confirmée et vidange achevée avec échec ou suspension. Un worker actif n'est ni annulé ni préempté ; sa réservation et sa supervision restent effectives jusqu'à sa terminaison réelle, puis une génération postérieure est offerte si nécessaire. `Failed`, `Unknown`, configuration devenue inadmissible ou inspection initiale à reprendre ne sont jamais transformés en succès et ne déclenchent aucun retry.
- **IMPLÉMENTÉ — priorité et arrêt 2I-4F-4A** : une opération manuelle déjà admise garde sa place et la demande automatique attend sa libération ; une nouvelle opération manuelle est refusée pendant la vidange. L'arrêt immédiat `shutdown()` conserve sa sémantique historique d'annulation/règlement et demeure séparé de cette frontière progressive.
- **TESTÉ — lot 2I-4F-4A** : les huit tests ciblés de vidange rapportés par l'utilisateur réussissent. Ils couvrent absence de mutation, accélération et regroupement, idempotence, worker réel avec génération postérieure, absence de copie redondante, `Failed`/`Unknown` et enfant encore vivant, admission manuelle antérieure, inspection annulée et configuration obsolète. Ces scénarios font également partie de la suite du coordinateur exécutée après 2I-4F-4B (158/158 réussis).
- **IMPLÉMENTÉ — raccordement GUI 2I-4F-4B, inactif en production** : `MainWindow::closeEvent()` utilise la vidange générationnelle uniquement lorsque le coordinateur a été explicitement construit en mode `Generational`. Une fabrique dédiée aux tests GUI sous `PASSWALL_GUI_TESTING` permet ce parcours ; les constructeurs de production restent en mode `Historical`. À la première demande de fermeture, la fenêtre refuse provisoirement l'événement, engage la vidange, invalide l'accès au coffre et appelle `lockVault()` pour effacer immédiatement les secrets, sans attendre l'inspection ni le worker et sans dialogue modal.
- **IMPLÉMENTÉ — fermeture répétée 2I-4F-4B** : les nouvelles demandes de fermeture pendant une vidange non terminale restent refusées mais ne rappellent plus `lockVault()`. Elles conservent ainsi l'identité physique non secrète et les compteurs du coordinateur nécessaires à la reconnaissance d'un `COMMIT` tardif. Une génération confirmée après le démarrage d'un instantané demeure une demande distincte. Lorsque la vidange devient `Completed` ou `CompletedWithFailureOrSuspension`, une fermeture est programmée automatiquement ; aucun résultat `Failed` ou `Unknown` n'est inventé comme `Published`, aucun nouvel essai n'est lancé et un worker encore vivant ne provoque pas une fermeture anticipée.
- **TESTÉ — lot 2I-4F-4B** : l'utilisateur rapporte 4/4 tests GUI de fermeture et de neutralité du mode production, 5/5 régressions GUI d'export/restauration, puis 158/158 tests du coordinateur réussis. La fixture GUI générationnelle exige une configuration globale valide ; le test de double fermeture vérifie une première génération, un second `COMMIT` pendant la vidange et la terminaison avec échec sans retry. Un test d'inspection asynchrone, intermittent lors d'une campagne précédente, a été stabilisé par une attente bornée de l'offre sans abaisser l'exigence de résultat ; sa cause précise n'est pas démontrée. Ces résultats ne constituent ni une campagne CTest complète ni une activation du moteur générationnel en production.
- **À DÉFINIR — désactivation explicite** : le schéma global actuel ne possède toujours pas de booléen d'activation. L'état non valide/absent suspend déjà les nouvelles offres observées et la future désactivation explicite devra emprunter la même invalidation, mais son stockage et son interface ne sont pas inventés par 2I-4F-3.
- **IMPLÉMENTÉ — supervision 2I-4D** : une offre sans consommateur n'est jamais présentée comme un worker ; inversement, un résultat `Unknown` observé alors que l'enfant vit encore reste exposé comme `WorkerActive`, avec réservation conservée, jusqu'au signal de terminaison effective. Les phases terminales sont notifiées après libération RAII des capacités détenues par le coordinateur.
- **TESTÉ — lot 2I-4D** : les validations ciblées rapportées réussissent pour l'inspection, la préparation réservée, les préadmissions export/restauration, la course avec la réservation exclusive, l'offre sans worker, le résultat `Unknown` avec enfant vivant, l'annulation, le changement de session et la neutralité historique.
- **IMPLÉMENTÉ — inspection asynchrone 2I-4E-1 inactive** : le coordinateur peut lancer `InitialBackupPreparer` sur un thread court sans secret, avec une identité de coffre, une génération de session et une empreinte de configuration transitoires. Un jeton atomique compose l'annulation de cycle de vie avec les points de contrôle du préparateur. La réponse move-only est synchronisée puis remise au thread propriétaire, où seulement ont lieu la revalidation et l'arbitrage 2I-4C.
- **IMPLÉMENTÉ — cycle de vie 2I-4E-1 inactif** : verrouillage, fermeture, changement de session/coffre ou invalidation de configuration demandent l'annulation sans attendre le thread. Une activité annulée reste bloquante jusqu'à la fin réelle si sa capacité peut encore être détenue ; le point de contrôle suivant l'acquisition rend cet état consultable. La destruction du propriétaire n'attend pas le thread : la réponse tardive détruit seulement ses objets RAII et ne peut plus être admise.
- **IMPLÉMENTÉ — raccordement conditionnel 2I-4E-1** : après l'enregistrement d'une session réellement authentifiée, `MainWindow` prépare le contexte sans clé et ne demande l'inspection que si son coordinateur immuable est déjà `Generational`. Le constructeur de production reste `Historical`, donc ce raccordement ne s'exécute pas actuellement. Une même session/configuration ne lance pas deux inspections et une mutation concurrente est arbitrée sur le thread propriétaire.
- **TESTÉ — lot 2I-4E-1** : les 129 tests ciblés du coordinateur rapportés par l'utilisateur réussissent. Ils couvrent notamment la réussite asynchrone, la réactivité du propriétaire, les invalidations de verrouillage/destruction/coffre/configuration, les réponses tardives, les doublons, la libération RAII, une mutation concurrente et la neutralité historique.
- **IMPLÉMENTÉ — consommation 2I-4E-2 inactive** : un coordinateur explicitement construit en mode `Generational` peut désormais consommer une offre `InitialCopy` ou une génération CRUD dotée d'une `PreparedBackupDestination`. Les deux voies convergent vers un unique `BackupJob`, réutilisent sans réacquisition la capacité d'instantané préparée et effectuent l'admission finale sur le thread propriétaire. Le jeton, la session, l'identité physique, le `vault_id`, la racine, la famille et la destination sont revalidés avant le transfert à `startSnapshotReserved()`.
- **IMPLÉMENTÉ — résultats 2I-4E-2 inactifs** : le superviseur commun sérialise les workers, conserve les générations plus récentes et ne publie le résultat complet qu'après terminaison effective. `Published` exige le reçu 2H-1 cohérent avec le type de demande, le jeton, la génération ou session et la destination ; `Failed` et `Unknown` conservent le résultat détaillé et son diagnostic. Un enfant encore vivant après un résultat incertain conserve sa réservation sous le superviseur existant.
- **TESTÉ — lot 2I-4E-2** : les 137/137 tests ciblés du coordinateur rapportés par l'utilisateur réussissent après raccordement des publications réelles `InitialCopy`/CRUD, de l'usage unique du jeton, du changement de session avant admission, des mutations pendant le worker, des échecs de lancement, des preuves insuffisantes et de la survie supervisée d'un worker inconnu.
- **IMPLÉMENTÉ** — un accès d'instantané partage les verrous de nom et d'inode avec les accès métier, mais détient en plus un verrou exclusif de sérialisation : deux instantanés du même fichier physique ne peuvent donc pas agir simultanément.
- **IMPLÉMENTÉ** — sous Linux, les réservations interprocessus utilisent `flock` et des descripteurs explicitement transmis aux workers ; les capacités d'instantané et de remplacement possèdent des méthodes distinctes de vérification, d'export et d'adoption.
- **IMPLÉMENTÉ** — le contrôle porte sur le nom et l'identité physique pour résister aux changements d'inode et substitutions concurrentes.
- **IMPLÉMENTÉ — production historique** : les CRUD préparent le suivi persistant avant l'écriture SQL ; un commit réussi conserve l'obligation de sauvegarde. Ce comportement reste celui de tous les appels qui ne sélectionnent pas explicitement un autre moteur.
- **IMPLÉMENTÉ — fondation 2A** : `CredentialService::events()` émet en mémoire un événement typé `Added`, `Updated` ou `Removed`, avec le seul chemin du coffre, après confirmation de la fin du `COMMIT`. Validation refusée, erreur SQL, rollback et état de commit incertain n'émettent rien.
- **IMPLÉMENTÉ — lot 2B/2I-1** : lorsqu'il est construit explicitement en mode `Generational`, `AutomaticBackupCoordinator` observe ces événements pour la seule session authentifiée courante, redémarre un `QTimer` mono-coup de 20 000 ms et incrémente une génération de mutation en mémoire. L'expiration prépare une demande unique pour la période regroupée. Le mode de production `Historical` ne s'abonne pas à ces événements.
- **IMPLÉMENTÉ — isolation 2B** : le chemin normalisé, la génération de session et la génération monotone du `COMMIT` excluent les événements d'un autre coffre, les événements retardés antérieurs à l'ouverture courante et les délais d'une session terminée. Un arrêt explicite du regroupement annule le délai sans persistance.
- **IMPLÉMENTÉ — lot 2C** : lors d'un verrouillage ordinaire, une génération encore planifiée est capturée avec le chemin normalisé du coffre, le délai et la session de regroupement sont invalidés immédiatement, puis la demande est offerte au tour de boucle Qt suivant. Une génération déjà offerte n'est pas redemandée. Les préparations de remplacement, fermetures externes et exports conservent leurs exclusions historiques.
- **IMPLÉMENTÉ — lots 2D/2I-4C** : chaque `GenerationalBackupRequestOffer` porte un type explicite et un jeton monotone à usage unique. Le coordinateur distingue l'offre non encore prise en charge, la tentative active et les demandes prêtes mais différées. Une seule tentative peut être active ; une génération apparue après son démarrage reste en attente, même si l'instantané réel pouvait matériellement la contenir.
- **IMPLÉMENTÉ — résultats 2D/2I-4F-1** : seul le jeton actif exact peut produire `Published`, `Failed` ou `Unknown`. Seul `Published` représente une publication confirmée ; `Failed` et `Unknown` installent désormais une suspension générationnelle volatile. Une mutation ultérieure met à jour le besoin non couvert mais reste inadmissible jusqu'à une reprise explicite, et un résultat obsolète ne peut ni acquitter ce besoin ni lever la suspension.
- **IMPLÉMENTÉ — fondation 2E** : `startMutationBackupSnapshot()` vérifie une capacité d'instantané déjà acquise, marque le jeton et la génération comme tentés avant tout lancement, puis délègue à `BackupJob::startSnapshotReserved()`. Le même `BackupJob` reste partagé avec le chemin historique : aucun second worker ne peut être lancé simultanément par le coordinateur.
- **IMPLÉMENTÉ — résultats 2E/2H-1** : le résultat du worker reste attaché au jeton actif et n'acquitte la génération qu'après terminaison effective du processus. Seul `Published` accompagné de la preuve transitoire complète devient `Published` ; un échec ou une annulation confirmés avant publication deviennent `Failed`, tandis que preuve absente ou incohérente, durabilité non confirmée, résultat absent, crash ou protocole non confirmé deviennent `Unknown`. Une génération postérieure reste différée jusqu'à cette terminaison.
- **IMPLÉMENTÉ — séparation publication/rotation 2E** : ce chemin appelle le worker sans contexte de rotation historique. Une publication confirmée peut donc acquitter sa génération sans qu'un échec futur de rotation soit confondu avec un échec de copie ; le raccordement à la future rotation sans catalogue reste à réaliser.
- **IMPLÉMENTÉ — preuve de publication 2H-1** : le chemin d'instantané partagé demande désormais explicitement au worker un reçu transitoire. Le résultat lie l'identité stable du fichier publié et de son répertoire, son empreinte SHA-256 et le chemin de destination effectivement contrôlé. `BackupJob` refuse de conserver `Published` si cette preuve manque, vise une autre destination ou ne satisfait pas les critères techniques déjà requis pour une suppression sûre ; comme une publication a pu avoir lieu, ce refus devient `Unknown`, jamais un échec fictivement antérieur à la publication.
- **IMPLÉMENTÉ — liaison au jeton 2H-1/2H-2** : `AutomaticBackupCoordinator` conserve le reçu uniquement en mémoire jusqu'à la terminaison effective du worker, puis vérifie le worker supervisé, le jeton actif, la génération, le chemin du coffre et la destination attendue. Le résultat transitoire unique `MutationBackupResult` transporte cette preuve avec `BackupFileEvidence` et le règlement exact de la génération. Une preuve absente, incomplète, incohérente ou attachée à un résultat tardif ne peut pas acquitter la génération.
- **IMPLÉMENTÉ — séparation rotation 2H-1** : le reçu n'est écrit ni dans QSettings ni dans un catalogue et ce lot ne lance aucune rotation. Il fournit seulement au futur consommateur la preuve nécessaire pour commencer cette étape séparée après une publication confirmée.
- **IMPLÉMENTÉ — diagnostics 2H-2** : `MutationBackupResult` associe atomiquement le chemin du coffre, la génération, le jeton à usage unique, l'état de coordination `Published`/`Failed`/`Unknown`, le `BackupOutcome` détaillé du worker, son diagnostic borné et le reçu de publication éventuel. Une annulation confirmée reste ainsi distincte d'un échec avant publication ; une durabilité non confirmée reste distincte d'un résultat absent ou invalide. Les diagnostics réellement transmis par le worker, notamment les codes POSIX ou SQLite disponibles, ne sont plus perdus lors de la réduction en état de coordination.
- **IMPLÉMENTÉ — absence d'invention 2H-2** : les échecs locaux antérieurs au worker portent uniquement la cause effectivement connue. L'absence d'un résultat terminal produit un diagnostic explicite d'absence, jamais une cause système fabriquée. Aucun résultat, diagnostic ni reçu générationnel n'est persisté.
- **IMPLÉMENTÉ — sélecteur 2I-1** : `BackupTriggerMode` est fixé à la construction du coordinateur et ne possède aucun mutateur. Tous les constructeurs utilisés par la production sélectionnent `Historical`; `Generational` exige le constructeur explicite employé par les tests. Le coordinateur ne connecte que la source d'événements du moteur choisi et chaque frontière d'entrée refuse défensivement les appels de l'autre moteur.
- **IMPLÉMENTÉ — exclusivité 2I-1** : en mode `Historical`, commits, délais et demandes générationnelles sont neutralisés ; en mode `Generational`, changements de préférences, reprise historique par `localId`, demande historique au verrouillage et dispatch historique sont neutralisés. La reprise volatile 2I-4F-1 appartient exclusivement au moteur générationnel. Les rappels Qt différés revérifient leur moteur avant tout dispatch. Il n'existe ni basculement à chaud, ni repli automatique vers l'historique après un échec générationnel.
- **IMPLÉMENTÉ — admission 2I-2** : la politique immuable `BackupTriggerMode` est partagée entre le coordinateur et `CredentialService`. `MainWindow` transmet à `add()`, `update()` et `remove()` le mode du coordinateur propriétaire de la session ; les appels directs conservent `Historical` par défaut. En mode historique, `prepareMutation()` et toutes ses écritures de `backupRequired` restent inchangés. En mode générationnel, `admitGenerationalMutation()` conserve la réservation métier, les contrôles de fichier et d'identité physique ainsi que la porte de récupération historique, mais n'écrit ni `backupRequired`, ni tentative, ni suspension dans QSettings.
- **IMPLÉMENTÉ — indépendance des préférences 2I-2** : l'admission générationnelle lit sous verrou uniquement l'identité locale et les intentions ou reçus historiques nécessaires à la sécurité. L'absence du fichier de préférences, l'absence des champs ordinaires de sauvegarde ou leur contenu invalide ne bloquent donc pas à eux seuls un CRUD sur un coffre sain et ne créent pas le fichier de configuration. Une configuration INI globalement illisible, une structure ne permettant plus de décider si une preuve de récupération existe, une preuve malformée ou une restauration active restent refusées par prudence.
- **IMPLÉMENTÉ — capacité d'admission 2I-2** : la capacité d'accès métier obtenue pendant l'admission reste vivante jusqu'à la fin du CRUD. La lecture des métadonnées qui suit ne peut éviter le second contrôle des préférences ordinaires qu'en présentant cette capacité exacte, encore valide pour le même chemin et la même identité coopérative. L'ouverture SQLite conserve sa propre garde partagée ; aucune API publique ne transforme un booléen en autorisation.
- **IMPLÉMENTÉ — notifications 2I-2** : les événements `Added`, `Updated` et `Removed` restent émis exclusivement après un `COMMIT` confirmé, indépendamment du mode. Un refus d'admission, une erreur SQLite ou un rollback ne produit aucune notification.
- **TESTÉ — lot 2I-2** : 40 tests ciblés réussis couvrent le mode historique explicite, l'absence ou l'invalidité des préférences ordinaires, l'absence de fichier de configuration, le refus des preuves de récupération actives ou malformées, l'exigence d'une capacité exacte et la notification après `COMMIT`.
- **IMPLÉMENTÉ — identité 2G-1** : chaque génération conserve en mémoire le périphérique et l'inode vérifiés lors de l'enregistrement de la session authentifiée. Cette identité suit la demande lorsqu'un verrouillage ordinaire détruit la session et n'est ni sérialisée ni transformée en autorisation persistante.
- **IMPLÉMENTÉ — admission 2G-1** : juste avant le lancement, `startMutationBackupSnapshot()` exige d'abord une capacité d'instantané valide pour le chemin courant, puis confirme que cette capacité protège le périphérique et l'inode attendus. L'absence d'une tentative d'acquisition est une erreur d'appel qui ne vaut pas résultat métier ; une acquisition effectivement tentée mais définitivement refusée ou une capacité devenue invalide soldent la génération `Failed`. Une capacité valide sur un fichier physiquement différent prouve également que l'ancienne génération est obsolète et ne lance aucun worker.
- **IMPLÉMENTÉ — concurrence 2G-1** : la réservation partagée et sa revalidation empêchent la préparation exclusive et l'instantané de franchir simultanément leur frontière. Si un remplacement gagne la réservation, l'ancienne demande reste bloquée puis est invalidée par la nouvelle identité ; si l'instantané gagne, la restauration exclusive attend ou échoue sans contourner ses contrôles. Une substitution extérieure qui ignore les verrous coopératifs est encore détectée lors de la revalidation ou de l'adoption des descripteurs par le worker.
- **IMPLÉMENTÉ — reprise 2G-2** : une acquisition effectivement tentée et refusée pour contention place la demande dans un état d'attente en mémoire distinct d'un échec. La libération effective d'un `VaultOperationGuard` détenu dans le processus produit un indice noyau local ; le coordinateur réémet alors la demande avec un nouveau jeton à usage unique. Cet indice ne constitue ni une preuve de disponibilité ni une capacité : chaque réveil exige une nouvelle acquisition et les contrôles complets de chemin, périphérique et inode.
- **IMPLÉMENTÉ — borne 2G-2** : la première contention démarre une unique échéance de pré-lancement de 3 000 ms, cohérente avec la fenêtre de contention SQLite V1. Les réveils et jetons successifs ne la réarment pas. À l'échéance, la génération est soldée `Failed` avec un diagnostic explicite, sans worker et sans réussite fictive ; une génération postérieure conservée en mémoire reste ensuite admissible. Cette borne ne limite jamais la durée d'une sauvegarde saine déjà lancée.
- **IMPLÉMENTÉ — échecs 2G-2** : une annulation confirmée avant lancement solde la seule demande correspondante ; un refus définitif, une identité divergente, un échec réel du worker et un résultat `Unknown` ne déclenchent aucune reprise automatique. Un résultat ou un jeton ancien ne peut pas terminer une offre réémise. Le déclenchement reste limité à un worker actif dans le coordinateur.
- **IMPLÉMENTÉ — limite de notification 2G-2** : le réveil est local au processus et couvre les gardes détenus par PassWall, y compris ceux conservés par les superviseurs jusqu'à la terminaison effective des workers. Une réservation détenue par un processus indépendant ou un composant ignorant ce mécanisme peut ne produire aucun réveil local ; l'échéance transforme alors l'attente en échec explicite plutôt qu'en attente infinie ou polling.
- **IMPLÉMENTÉ — fermeture 2G-3** : avant l'arrêt du coordinateur lors d'une fermeture normale, `MainWindow` capture synchroniquement la génération encore planifiée avec son identité physique, sans lancer de worker et sans retarder le nettoyage du coffre. Le verrouillage invalide ensuite la session Firefox et détruit les secrets selon le chemin existant. Le destructeur possède la même capture de dernier recours si aucun `closeEvent()` normal n'a abouti.
- **IMPLÉMENTÉ — résultats de fermeture 2G-3** : une génération capturée, prête, offerte ou en attente de contention mais jamais lancée est soldée `Failed` avec un diagnostic de fermeture ; une tentative simulée dont aucun processus supervisé ne peut encore répondre est soldée `Unknown`. Une génération déjà soldée `Failed` ou `Unknown` n'est ni recréée ni réessayée. Aucune de ces transitions n'est présentée comme une sauvegarde publiée.
- **IMPLÉMENTÉ — worker actif 2G-3** : un véritable `BackupJob` déjà lancé reçoit une demande d'annulation. Un résultat confirmé avant publication devient `Failed`; une publication confirmée reste `Published`; un résultat incertain devient `Unknown`. La fermeture de la façade Qt ne libère pas les réservations d'un enfant encore vivant : le superviseur indépendant les conserve jusqu'à sa terminaison effective. Aucune durée maximale globale n'est imposée à une sauvegarde saine ; les délais d'escalade après annulation restent distincts.
- **IMPLÉMENTÉ — limite volontaire 2G-3** : puisque le consommateur générationnel de production est encore désactivé, une fermeture normale ne lance pas artificiellement un nouveau worker. Elle rend la perte de la demande explicite par `Failed` au lieu de l'effacer silencieusement. Cette fondation ne constitue donc pas une garantie de sauvegarde à la fermeture.
- **IMPLÉMENTÉ — limite volontaire 2I-4E-2** : le coordinateur générationnel injectable possède maintenant ses voies de consommation réelles pour `InitialCopy` et `CrudGeneration`, mais aucun composant de production ne consomme encore `generationalBackupRequested`. Le déclenchement automatique historique demeure le seul chemin actif dans `MainWindow`, ce qui évite un double déclenchement pendant la transition.
- **TESTÉ — lot 2A** : les trois mutations réussies émettent exactement une notification typée ; un refus de validation et les échecs de commit avec rollback des trois opérations n'en émettent aucune. Les 27 tests ciblés des services métier et transactions passent.
- **TESTÉ — lot 2B** : délai démarré et réarmé, trois commits regroupés en une demande, nouvelle période après expiration, isolation entre coffres et sessions, arrêt sans demande résiduelle et absence de sauvegarde réelle. Les tests utilisent un délai injecté court ; la valeur de production reste 20 000 ms.
- **TESTÉ — lot 2C avant 2I-1** : verrouillage avant échéance, absence de demande sans mutation, regroupement de plusieurs mutations, ordonnancements des deux côtés de l'échéance sans perte ni doublon, conservation du chemin et de la génération après changement de session. L'ancien parcours mixte `MainWindow` avait également vérifié que la session et ses secrets étaient invalidés avant que la demande différée soit observable ; la production est désormais explicitement `Historical` et une future intégration GUI générationnelle devra être revalidée lors du basculement.
- **TESTÉ — lot 2D** : regroupement avant démarrage, mutation et expiration pendant une tentative active, accélération au verrouillage, sérialisation des offres, conservation des générations non couvertes, résultats publié/échoué/inconnu, absence de reprise en boucle après échec, nouvelle tentative après nouveau commit, et refus des démarrages ou résultats portant un jeton, un chemin, une génération ou une session obsolète.
- **TESTÉ — lot 2E** : lancement d'un véritable `BackupJob`/`QProcess` avec capacité d'instantané et jeton exact, publication d'un fichier par l'auxiliaire de test, échec confirmé sans reprise, résultat absent et crash classés `Unknown`, mutation pendant un worker actif conservée comme génération suivante, refus d'une capacité absente pendant une réservation de remplacement, absence de rotation et absence d'appel du chemin automatique historique.
- **TESTÉ — lot 2G-1** : identité inchangée admise, remplacement physique avant lancement refusé sans fichier publié, capacité acquise avant une substitution extérieure devenue inutilisable, ancienne génération soldée sans reprise contre le nouveau principal, et demande issue d'un verrouillage ordinaire encore admise après une nouvelle session du même fichier physique. Les trois régressions d'exclusivité de l'export manuel restent vertes.
- **TESTÉ — lot 2G-2** : reprise après libération, contention persistante soldée une seule fois, conservation d'une génération plus récente, nouvelle réservation concurrente après réveil, annulation pendant l'attente, substitution physique pendant l'attente, rejet des jetons tardifs et absence de reprise après échec ou résultat inconnu. Les régressions d'export manuel exclusif et les contrôles de réservation de restauration directement concernés restent verts. Une fixture historique de précaution placée sous `/tmp` reste refusée par la politique de permissions des ancêtres et n'a pas été assouplie.
- **TESTÉ — lot 2G-3** : absence de résultat sans mutation, fermeture avant échéance, après offre, pendant contention et pendant tentative réelle, conservation puis règlement distinct d'une génération plus récente, absence de reprise après `Failed` ou `Unknown`, nettoyage de session `MainWindow` et quatre régressions de fermeture de l'export manuel. Les résultats globaux de la campagne demandée sont consignés en section 12.
- **TESTÉ — lot 2H-1** : les huit tests ciblés exécutés après correction locale de la portée du reçu dans `backup_worker_main.cpp` couvrent le reçu produit par le worker réel, sa liaison exacte à la destination, sa transmission avec le jeton et la génération, ainsi que le refus fail-closed d'un résultat publié sans reçu, avec reçu incomplet ou avec chemin incohérent.
- **TESTÉ — lot 2H-2, validation ciblée** : 11/11 tests ciblés rapportés réussis dans le terminal utilisateur après implémentation. Ils vérifient notamment l'association atomique du reçu au résultat publié, la conservation d'un diagnostic `errno=28`, la distinction d'une annulation confirmée, la conservation de `DurabilityUnconfirmed` et les diagnostics de résultat absent ou de crash. Cela ne constitue pas une validation exhaustive des parcours de production.
- **TESTÉ — lot 2I-1** : 41 tests ciblés réussis couvrent la sélection explicite de la fixture `Generational`, le refus croisé des entrées de l'autre moteur, l'absence de double lancement ou de repli et le maintien strict de `MainWindow` en mode historique.
- **VALIDÉ** — les réservations et contrôles d'identité doivent être préservés dans la cible.
- **À FAIRE — écart actuel** : activer le consommateur de production des demandes générationnelles, puis remplacer `backupRequired` et le suivi persistant des mutations sans créer une fenêtre où un CRUD, un worker ou une restauration deviennent concurrents.
- **VALIDÉ — fermeture cible** : toute génération CRUD confirmée et encore en attente devient immédiatement éligible à la fermeture, sans délai de regroupement ni boîte de dialogue. Les secrets sont nettoyés sans attendre les sauvegardes ; la fenêtre attend de façon asynchrone la terminaison effective des workers et des générations postérieures, puis se ferme automatiquement sur un état terminal, y compris si le résultat doit rester signalé comme échec ou suspension. Les demandes de fermeture répétées n'effacent pas l'identité transitoire nécessaire aux `COMMIT` déjà engagés. Les lots 2I-4F-4A/4B implémentent et testent ce comportement uniquement dans la voie générationnelle injectable.
- **À FAIRE — après 2I-4F-4B** : raccorder un consommateur unique de production et les préférences globales, puis sélectionner explicitement `Generational` sans maintenir simultanément le déclenchement historique. Conserver les contrôles d'admission, la protection du coffre principal et la distinction entre vidange progressive et `shutdown()` immédiat. `Failed` et `Unknown` exigent toujours une reprise explicite pendant la vie du processus.

### 6.3 Instantané, worker et export manuel

- **IMPLÉMENTÉ** — `VaultSnapshotService` utilise l'API de sauvegarde SQLite pour produire une copie cohérente sans clé de déchiffrement.
- **IMPLÉMENTÉ** — la source et la destination sont ouvertes de manière conservatrice ; les chemins ambigus, liens et types interdits sont refusés.
- **IMPLÉMENTÉ** — la copie est validée structurellement avant publication.
- **IMPLÉMENTÉ** — la publication est sans écrasement, avec fichier temporaire privé, synchronisation du fichier et du répertoire, puis distinction entre publié, durabilité incertaine, annulé et échec.
- **IMPLÉMENTÉ** — les échecs POSIX et SQLite pertinents conservent dans leur diagnostic les codes réellement observés ; le protocole transmet ce diagnostic sans contenu du coffre.
- **IMPLÉMENTÉ — transport 2H-2** : le coordinateur générationnel conserve ce `BackupResult` jusqu'à la terminaison effective du worker au lieu de le réduire immédiatement à trois états. Son signal de résultat expose simultanément le diagnostic borné, le résultat détaillé et la preuve 2H-1, toujours sans contenu du coffre, clé ou mot de passe.
- **IMPLÉMENTÉ** — `passwall_backup_worker` exécute la copie hors du thread GUI et ne contient aucun moteur de déchiffrement.
- **IMPLÉMENTÉ** — `BackupJob` distingue résultat métier et terminaison effective ; la réservation n'est pas libérée tant que l'enfant peut encore agir.
- **IMPLÉMENTÉ — protocole 2H-1** : lorsqu'un reçu est demandé, le protocole borné associe obligatoirement `BackupFileEvidence` au chemin canonique publié. Le worker construit cette preuve par inspection protégée de la destination après publication et la recoupe avec l'identité vérifiée avant publication ; un chemin seul, un fichier visible ou un code de sortie nul ne suffisent pas.
- **IMPLÉMENTÉ — lot 2F** : l'entrée `BackupJob::start()` utilisée par l'export manuel acquiert une réservation exclusive et utilise le protocole worker historique `--protocol-v1`. Accès métier, restauration et autre instantané du même coffre restent refusés jusqu'à la terminaison effective du worker, y compris après un résultat `Unknown` ou la destruction de la façade Qt.
- **IMPLÉMENTÉ** — seul le chemin explicite `BackupJob::startSnapshotReserved()` et le protocole worker `--snapshot-v1` utilisent l'accès d'instantané partagé : les accès métier restent possibles, tandis qu'une restauration exclusive et un second instantané restent refusés jusqu'à la terminaison effective.
- **IMPLÉMENTÉ — compatibilité temporaire** : le chemin automatique actif de `AutomaticBackupCoordinator` et sa rotation utilisent encore l'ancien chemin exclusif `startReserved()`. La frontière générationnelle peut appeler le chemin partagé `startSnapshotReserved()`, mais elle n'est volontairement reliée à aucun signal de production ; le basculement attend le routage global, le nommage cible et la rotation sans catalogue.
- **IMPLÉMENTÉ** — l'export manuel verrouille et nettoie le coffre avant de lancer le worker ; il n'impose aucune durée globale arbitraire.
- **TESTÉ — lot 2F** : les trois régressions d'exclusivité de l'export manuel, les 25 cas `BackupJob`, les fondations 2B–2E et la campagne CTest complète séquentielle passent. La campagne compte 928 cas sans échec ; `RestoreParentExitProbe` reste l'unique auxiliaire volontairement ignoré.
- **VALIDÉ** — ces moteurs sont réutilisables par la cible.

Le contrôle actuel des chemins refuse notamment des ancêtres modifiables par un autre utilisateur ou groupe selon sa politique POSIX. PassWall ne doit pas corriger automatiquement les permissions d'un dossier choisi. L'ouverture future à NAS/NFS/CIFS/FUSE/FAT/exFAT ou l'assouplissement de cette politique nécessitent une décision et des contrôles adaptés.

### 6.4 Coordinateur automatique et rotation actuelle

- **IMPLÉMENTÉ** — `AutomaticBackupCoordinator` résout actuellement un chemin principal vers un `localId`, relit les préférences par coffre et lance une sauvegarde au verrouillage si `backupRequired` est actif.
- **IMPLÉMENTÉ — lot 2I-1** : le coordinateur possède un sélecteur immuable `Historical`/`Generational`. `MainWindow` utilise le constructeur par défaut, exclusivement `Historical`. Le mode `Generational` demeure une frontière injectable par les tests : aucun consommateur de production de `generationalBackupRequested` n'est connecté.
- **IMPLÉMENTÉ** — les noms automatiques utilisent actuellement l'heure locale et l'extension `.db`, avec un suffixe d'opération en cas de collision.
- **IMPLÉMENTÉ** — `BackupRotationService` charge le catalogue, trie les versions par ordre persistant, vérifie leurs preuves puis marque et confirme chaque suppression.
- **IMPLÉMENTÉ** — une suppression incertaine bloque la rotation sans rétracter la nouvelle sauvegarde publiée.
- **À FAIRE — écart actuel** : le nommage, le routage, les préférences par coffre, les époques de destination et le catalogue doivent être remplacés.
- **À FAIRE** — remplacer les reçus et états persistants de rotation par le traitement simple décrit en 5.4, tout en réutilisant les contrôles de chemin, les identités et la supervision sans conserver deux moteurs à long terme.

### 6.5 Interface actuelle des préférences

- **IMPLÉMENTÉ** — `VaultBackupSettingsDialog` et `VaultBackupSettingsController` permettent de choisir un principal enregistré, une activation, une destination et une rétention.
- **IMPLÉMENTÉ** — l'enregistrement compare l'identité et les préférences affichées avant la mise à jour atomique du registre.
- **IMPLÉMENTÉ** — la reprise après suspension est explicite et ne vaut pas réussite de sauvegarde.
- **À FAIRE — écart actuel** : l'interface doit devenir une configuration globale initiale puis des paramètres globaux ; elle ne doit plus présenter les trois réglages par coffre.
- **À FAIRE — écart actuel** : retirer avec le moteur historique la suspension persistante et sa reprise par `localId`, puis exposer dans la future interface la suspension générationnelle uniquement volatile et sa reprise explicite.
- **À FAIRE** — conserver les diagnostics de destination sans modifier automatiquement les permissions du dossier utilisateur.

## 7. Restauration et récupération

### 7.1 Cible validée sans journal permanent

- **VALIDÉ** — restaurer signifie remplacer intégralement le coffre principal par une sauvegarde authentifiée ; aucune fusion entrée par entrée.
- **VALIDÉ** — PassWall ne doit conserver, dans l'architecture cible, aucun journal permanent d'intentions, de phases ou de reçus de restauration. Il n'existe aucune reprise automatique ou semi-automatique d'un échange interrompu.
- **VALIDÉ** — le moteur de remplacement, ses réservations, l'authentification complète de la source et la protection des secrets sont préservés autant que possible.
- **VALIDÉ** — une autorisation transitoire opaque n'est délivrée qu'après confirmation explicite, verrouillage et nettoyage réels du coffre ; elle reste limitée à l'opération autorisée.
- **VALIDÉ** — le candidat complet est préparé sur le système de fichiers du principal, sous contrôles des chemins, types, propriétaires, liens symboliques, identités physiques et substitutions concurrentes.
- **VALIDÉ** — l'intégrité et les identités sont revalidées avant publication ; les synchronisations nécessaires distinguent remplacement confirmé, durabilité incertaine et résultat inconnu.
- **VALIDÉ** — la sauvegarde source et son emplacement ne sont pas modifiés par la restauration ; l'ancien principal est conservé par l'échange au lieu d'être écrasé directement.
- **VALIDÉ** — le coffre reste verrouillé après un remplacement et exige une nouvelle authentification manuelle.
- **VALIDÉ** — une interruption ne provoque jamais automatiquement un nouvel échange. Après redémarrage, PassWall examine et authentifie le fichier effectivement présent au chemin principal ; une nouvelle restauration exige une demande et une autorisation explicites.
- **VALIDÉ** — un principal sain et authentifié peut être rouvert, sous réserve des protections historiques encore applicables pendant la transition décrite en 7.6.
- **VALIDÉ** — la restauration manuelle doit rester possible lorsque le principal est corrompu, même si ses métadonnées SQLite ou son `vault_id` sont illisibles.
- **VALIDÉ** — la disparition des préférences ordinaires ne bloque pas à elle seule l'ouverture d'un coffre sain et n'est pas utilisée comme preuve de l'issue d'une ancienne restauration.

La suppression du journal PassWall ne supprime ni les transactions et journaux internes nécessaires à SQLite, ni les états transitoires gardés en mémoire pendant une opération supervisée. Elle renonce seulement à déduire ou reprendre automatiquement, après redémarrage, le déroulement passé d'un remplacement.

### 7.2 Autorisation et moteur actuels

- **IMPLÉMENTÉ** — `MainWindow` ne délivre une `VaultReplacementAuthorization` opaque qu'après verrouillage et nettoyage réels, revalidation de la génération, de l'identité, de l'autorisation et des protections Linux.
- **IMPLÉMENTÉ** — l'autorisation est non copiable, limitée au coffre et à l'UUID d'opération, et possède une réservation exclusive.
- **IMPLÉMENTÉ** — un UUID, chemin, booléen ou message JSON ne suffit pas à fabriquer l'autorisation.
- **IMPLÉMENTÉ** — `VaultReplacementService` authentifie le maître et toutes les entrées de la source avant l'engagement.
- **IMPLÉMENTÉ Linux** — le principal et le candidat sont échangés avec `renameat2(RENAME_EXCHANGE)` après préparation privée ; l'ancien principal est conservé dans un emplacement de récupération.
- **IMPLÉMENTÉ — mécanisme historique à retirer** : les intentions et phases persistantes comprennent `prepared`, `armed`, `identity-confirmed`, `resolved`, `abandon-confirmed` et `abandoned`, avec reçus et preuves associées dans `vaultRegistry/data`.
- **IMPLÉMENTÉ — mécanisme historique à retirer** : une porte permanente de récupération utilise notamment `localId`, le chemin, l'identité physique, des empreintes et les preuves persistantes pour autoriser ou refuser l'ouverture.
- **IMPLÉMENTÉ** — `recoverReplacement()` ne répète jamais automatiquement l'échange ; `resumeFinalization()` reprend seulement une finalisation démontrée.
- **IMPLÉMENTÉ** — aucun rollback destructeur ni nettoyage automatique de l'ancien principal.

Ces mécanismes décrivent le code actuel, pas la cible. Leur retrait ne pourra intervenir qu'après la transition contrôlée de 7.6. L'autorisation opaque délivrée après nettoyage, l'engagement transitoire de l'opération, les contrôles avant publication et les résultats conservateurs restent nécessaires sans persistance permanente de leurs phases.

### 7.3 Worker, secrets et supervision

- **IMPLÉMENTÉ** — `passwall_restore_worker` est séparé du worker de sauvegarde.
- **IMPLÉMENTÉ** — sa délégation à usage unique provient de l'autorisation 6A et exige les ressources héritées, l'identité du parent, l'opération et les réservations attendues.
- **IMPLÉMENTÉ** — le maître passe par un canal Unix privé, entre buffers propriétaires, jamais par arguments, environnement, JSON, QSettings ou fichier temporaire.
- **IMPLÉMENTÉ** — le worker valide la délégation avant de recevoir le secret ; tailles, version, ordre, messages partiels, doublons, EOF et déconnexions sont contrôlés.
- **IMPLÉMENTÉ** — `RestoreJob` distingue demande d'annulation, acquittement, nettoyage sensible, résultat métier et terminaison effective.
- **IMPLÉMENTÉ** — `Control1.Lock()` et le nettoyage attendu par logind n'acquittent positivement le nettoyage global qu'après confirmation de la phase sensible ou terminaison effective.
Limite connue : le délai maximal de l'inhibiteur logind ne permet pas de garantir que tout worker ou appel noyau bloqué sera nettoyé avant une transition système.

### 7.4 Prévalidation et interface

- **IMPLÉMENTÉ** — la GUI prévalide sans mot de passe les sources absentes, inaccessibles, non ordinaires, manifestement non SQLite, structurellement incompatibles ou corrompues avant le verrouillage et la création de `prepared`.
- **IMPLÉMENTÉ** — cette prévalidation n'est ni une authentification ni une autorisation ; la source est revalidée après préparation pour résister aux changements TOCTOU.
- **IMPLÉMENTÉ** — le sélecteur propose les sauvegardes par extension mais permet une sélection libre ; l'extension n'est pas un critère de sécurité.
- **IMPLÉMENTÉ** — annulation avant worker, mauvais maître et autres refus structurés certainement non engagés peuvent utiliser l'abandon contrôlé après terminaison, nettoyage et preuves confirmés.
- **IMPLÉMENTÉ** — résultat `Unknown`, worker vivant, divergence, engagement possible ou persistance non confirmée imposent la récupération manuelle.
- **IMPLÉMENTÉ** — aucune issue ne réouvre automatiquement le coffre.

### 7.5 Récupération utilisateur

| État prouvé | Comportement actuel |
|---|---|
| `prepared`, principal intact, aucune opération active | abandon contrôlé possible après confirmation |
| `abandon-confirmed` | reprise idempotente de la résolution d'abandon |
| `armed` avant échange | blocage conservé ; ni abandon ni second échange |
| `armed` après échange démontré | reprise de finalisation uniquement |
| `identity-confirmed` | finalisation idempotente sous réservations |
| reçu `resolved` ou `abandoned` | revalidation de la persistance et de l'identité avant admission |
| preuves insuffisantes ou divergentes | aucun déblocage automatique |

- **IMPLÉMENTÉ** — la GUI de récupération ne contient aucun secret et ne duplique pas les contrôles des services.
- **IMPLÉMENTÉ** — les opérations longues et synchronisations s'exécutent hors du thread GUI ; les retours sont liés à la génération, au coffre et à l'UUID.
- **IMPLÉMENTÉ** — un reçu visible après échec de `fsync` ne suffit pas à autoriser l'ouverture ; l'admission reconfirme actuellement le fichier de registre et son répertoire.
- **À FAIRE — transition historique** : conserver ces garanties pour les opérations déjà enregistrées, sans extraire les preuves vers un nouveau journal permanent.
- **À FAIRE** — définir le nettoyage contrôlé des anciens principaux, candidats et artefacts ; leur suppression automatique reste interdite.
- **À FAIRE** — traiter ou documenter durablement les états `armed` avant échange et les preuves irrémédiablement divergentes.

### 7.6 Interruption, artefacts et transition historique

L'architecture cible distingue trois catégories d'interruption :

- une interruption du processus peut laisser le principal ancien ou nouveau au chemin principal et un ancien principal ou candidat à l'emplacement de travail ;
- un arrêt système ordonné peut permettre certaines synchronisations, sans constituer une preuve universelle de durabilité ;
- une panne électrique ou matérielle peut rendre le résultat indémontrable malgré l'atomicité de l'échange et les appels à `fsync`.

- **TESTÉ — lot 0A** : sept interruptions réelles du processus enfant, injectées de l'authentification de la source jusqu'à la synchronisation suivant l'échange, caractérisent l'implémentation historique. Avant l'échange, le principal reste identique ; après l'échange, le nouveau principal et l'ancien principal restent observables ; la source sélectionnée reste octet pour octet inchangée à chaque point. Ces tests ne simulent pas une panne électrique.

- **VALIDÉ** — après redémarrage, PassWall vérifie l'état actuel des fichiers et authentifie le coffre au chemin principal ; il ne prétend pas nécessairement déterminer si l'échange précédent a eu lieu.
- **VALIDÉ** — les fichiers de récupération inconnus, anciens principaux et candidats ne sont jamais supprimés automatiquement.
- **VALIDÉ** — l'emplacement des artefacts connus doit pouvoir être communiqué à l'utilisateur ; un futur nettoyage reste volontaire et contrôlé.
- **VALIDÉ** — l'échange atomique conserve l'ancien principal à l'emplacement du candidat. Aucune seconde copie de précaution systématique n'est prévue dans la cible.
- **VALIDÉ** — l'atomicité de `RENAME_EXCHANGE` ne constitue pas une garantie absolue de durabilité après coupure électrique.
- **À DÉFINIR** — convention d'emplacement et de nommage des artefacts, diagnostic utilisateur et critères précis d'un nettoyage volontaire.

La transition depuis l'implémentation actuelle suit les règles suivantes :

1. **À FAIRE** — arrêter la création de nouvelles intentions persistantes une fois le remplacement transitoire prêt et caractérisé ;
2. **À FAIRE** — conserver temporairement la lecture des preuves historiques présentes dans `vaultRegistry/data` ;
3. **À FAIRE** — maintenir leur porte d'admission et résoudre les opérations historiques inachevées avec les mécanismes actuels ;
4. **À FAIRE** — ne supprimer automatiquement ni preuve incertaine ni artefact associé ;
5. **À FAIRE** — retirer les structures, la GUI et les services historiques seulement après validation des conditions de transition et des tests correspondants ;
6. **À DÉFINIR** — comportement face à une ancienne version de PassWall encore capable de recréer des intentions dans le registre historique.

Aucun nouveau journal permanent ne doit être introduit pour réaliser cette transition. La délégation au worker reste liée à une autorisation transitoire opaque et à des ressources vivantes ; un UUID, un chemin ou un message sérialisé ne constitue jamais à lui seul une autorisation de remplacement.

### 7.7 Principal corrompu

- **VALIDÉ** — l'utilisateur sélectionne et confirme explicitement la destination lorsque le principal ne peut plus fournir de métadonnées fiables.
- **VALIDÉ** — la sauvegarde source est intégralement authentifiée, y compris ses entrées chiffrées, avant tout remplacement.
- **VALIDÉ** — chemin, propriétaire, type de fichier, identité physique et opérations concurrentes font l'objet de contrôles stricts ; les liens symboliques et substitutions restent refusés.
- **VALIDÉ** — le candidat complet est préparé sur le système de fichiers du principal, puis l'ancien fichier est conservé par l'échange.
- **À DÉFINIR** — politique exacte de confirmation renforcée et preuve suffisante que la destination choisie est bien celle voulue lorsque son contenu est inexploitable.

## 8. Interface, verrouillage et préférences locales

### 8.1 Cycle de vie de la session

- **IMPLÉMENTÉ** — `MainWindow::lockVault()` invalide les sessions Native Messaging avant de détruire la clé.
- **IMPLÉMENTÉ** — les éditeurs ouverts sont nettoyés immédiatement et leurs générations sont révoquées ; un ancien éditeur ne peut pas republier dans une nouvelle session.
- **IMPLÉMENTÉ** — les nettoyeurs RAII restent une protection supplémentaire sans être l'unique mécanisme.
- **IMPLÉMENTÉ** — le chemin critique n'affiche pas de notification modale bloquante.
- **IMPLÉMENTÉ** — le timer est armé dès qu'une session avec clé devient utilisable, avant les rafraîchissements susceptibles d'ouvrir une boucle Qt imbriquée.
- **IMPLÉMENTÉ — lot 2I-4F-4B, uniquement en test générationnel** : `closeEvent()` amorce une vidange asynchrone et un verrouillage sensible immédiat lors de la première fermeture. Les fermetures répétées ne relancent pas le nettoyage et la fenêtre se ferme automatiquement à l'état terminal ; le parcours de production `Historical` reste inchangé.

### 8.2 Verrouillage automatique obligatoire

- **IMPLÉMENTÉ** — seules les valeurs 1, 5, 15, 30 et 60 minutes sont autorisées ; la valeur par défaut est une minute.
- **IMPLÉMENTÉ** — aucune désactivation n'est disponible.
- **IMPLÉMENTÉ** — anciennes valeurs 0, 10 ou invalides migrées vers une minute avec notification non modale.
- **IMPLÉMENTÉ** — si la persistance échoue, une minute reste appliquée en mémoire et la désactivation ne réapparaît pas.
- **TESTÉ** — 64 cas ciblés couvrent valeurs, défaut, migration, échec de persistance, expiration réelle, éditeurs, Native Messaging, logind et opérations asynchrones.
- **À FAIRE** — essais manuels Wayland des cinq choix et maintien des régressions lors des évolutions GUI.

Le timer mesure l'activité dans PassWall, pas l'inactivité globale du bureau. Aucun délai temps réel n'est garanti si le thread GUI ou le système est bloqué.

### 8.3 Dernier coffre ouvert

- **IMPLÉMENTÉ dans l'état local actuel** — `vault/lastPath` n'est publié qu'après création ou ouverture authentifiée et enregistrement confirmé, jamais à la simple sélection du fichier.
- **IMPLÉMENTÉ dans l'état local actuel** — au démarrage, seuls les chemins absolus vers un fichier ordinaire lisible et non ambigu préremplissent le champ, sans ouvrir SQLite ni authentifier le coffre.
- **IMPLÉMENTÉ dans l'état local actuel** — une valeur absente, vide, relative, supprimée, inaccessible ou symbolique laisse le champ vide sans effacer la préférence ; un support temporairement absent peut revenir.
- **TESTÉ dans l'état local actuel** — 15 cas ciblés couvrent préférence, sélection, authentification, conservation du registre, session et timer.

`lastPath` est une commodité locale, jamais une preuve d'identité, une autorisation ou un substitut aux protections historiques de récupération encore actives.

## 9. Firefox et Native Messaging

### 9.1 Architecture

Le chemin de production est :

```text
Firefox
  → Extension PassWall
  → passwall_native_host
  → NativeBridgeServer
  → MainWindow::handleNativeRequest()
  → NativeRequestProcessor
  → NativeVaultAccess (implémenté par MainWindow)
  → Coffre PassWall
```

- **IMPLÉMENTÉ** — `NativeRequestProcessor` est l'unique implémentation métier Native Messaging.
- **IMPLÉMENTÉ** — les identifiants d'entrée sont des chaînes hexadécimales canoniques de 32 caractères.
- **IMPLÉMENTÉ** — la taille commune maximale des messages est de 1 Mio hors préfixe.
- **IMPLÉMENTÉ** — l'origine est vérifiée avant le chargement ciblé du secret puis de nouveau côté extension avant remplissage.
- **IMPLÉMENTÉ** — les générations de session invalident les réponses en attente après verrouillage ou changement de session.
- **IMPLÉMENTÉ** — `NativeRequestResponse` possède son buffer et n'est pas copiable.
- **IMPLÉMENTÉ** — aucun cache durable de tous les credentials complets n'est nécessaire au traitement natif.

### 9.2 Validation et travaux restants

- **TESTÉ automatiquement** — `EntryIdParserTest` 9/9, `NativeRequestProcessorTest` 27/27, `NativeRequestResponseTest` 1/1, `SiteMatcherTest` 12/12, `NativeBridgeServerTest` 21/21 avec sockets Unix réels, `passwall_native_host_tests` 6/6.
- **TESTÉ manuellement le 6 novembre 2026** — chargement temporaire Firefox, démarrage automatique, communication, détection du coffre verrouillé, recherche, remplissage, isolation des domaines, refus après verrouillage et redémarrage verrouillé, avec données fictives.
- **À FAIRE** — tests Firefox automatisés de bout en bout, invalidation déterministe pendant la transmission réelle, packaging et installation reproductible du Host et de l'extension.
- **À DÉFINIR** — identifiant et canal de diffusion définitifs de l'extension.

Les tests JavaScript et du bridge ne prouvent pas à eux seuls le parcours complet dans Firefox. Les buffers Qt, système et JavaScript peuvent conserver des copies hors du contrôle direct de PassWall.

## 10. Protection Linux

### 10.1 Instance unique et service de contrôle

- **IMPLÉMENTÉ** — une seule instance applicative Linux est admise.
- **IMPLÉMENTÉ** — `org.passwall.PassWall.Control1.Lock()` acquitte le verrouillage après nettoyage local attendu.
- **IMPLÉMENTÉ** — l'ancienne interface `SessionGuard1` est supprimée ; aucune garde globale persistante ou authentification maître globale n'existe.

### 10.2 logind

- **IMPLÉMENTÉ** — `LinuxSessionMonitor`, indépendant des widgets, surveille `PrepareForSleep` et `PrepareForShutdown` avec Qt DBus.
- **IMPLÉMENTÉ** — un inhibiteur `delay` pour sleep/shutdown est conservé tant que la protection est requise.
- **IMPLÉMENTÉ** — le descripteur est contrôlé par `poll()` ; une simple valeur numérique ou `fcntl(F_GETFD)` n'est pas considérée comme une preuve de pair vivant.
- **IMPLÉMENTÉ** — résolution asynchrone du propriétaire unique de logind, réabonnement par génération et politique fail-closed lors des incohérences.
Limite connue : thread principal bloqué, logind indisponible, crash, arrêt forcé ou délai d'inhibiteur expiré peuvent empêcher un nettoyage avant la transition physique.

### 10.3 Verrouillage de session Wayland

- **IMPLÉMENTÉ** — `passwall-session-lock` tente `Control1.Lock()` pendant un budget D-Bus de 1 500 ms, puis lance `/usr/bin/swaylock -p` même si PassWall est absent ou ne répond pas.
- **IMPLÉMENTÉ** — une réservation `flock` empêche plusieurs verrouilleurs concurrents pour la même invocation.
- **IMPLÉMENTÉ** — aucun shell ni argument non fiable n'est utilisé.
- **TESTÉ automatiquement** — 21 cas du coordinateur et 10 cas du service de verrouillage sur bus privés et faux verrouilleur.
- **TESTÉ manuellement le 7 novembre 2026** — `Ctrl+Alt+L`, verrouillage préalable du coffre, verrouillage/déverrouillage Linux, coffre restant fermé, refus Firefox puis nouvelle authentification, avec maintien de `Ctrl+Super+L`.
Limite connue : lancer directement swaylock contourne le coordinateur ; l'absence d'acquittement de PassWall ne prouve pas le nettoyage du coffre.

Limite connue : `LockedHint`, le code de sortie de swaylock et son simple affichage ne prouvent ni un déverrouillage normal, ni l'effacement de toutes les allocations historiques.
- **À FAIRE** — installation reproductible et essais contrôlés des véritables transitions suspension, hibernation et arrêt ; vérifier les autres déclencheurs de session et l'ergonomie `pishutdown`.

## 11. Garanties et limites de sécurité

### 11.1 Garanties à préserver

- authentification cryptographique avant accès aux secrets ;
- aucune clé ou mot de passe dans les journaux, arguments, environnement ou fichiers temporaires ;
- validation métier commune et transactions atomiques ;
- invalidation Native Messaging avant destruction de la clé ;
- nettoyage immédiat des champs contrôlés et RAII en protection supplémentaire ;
- aucune session ancienne restaurée après verrouillage, récupération ou remplacement ;
- réservations maintenues jusqu'à la terminaison effective des workers ;
- distinction entre réussite, échec avant publication, publication à durabilité incertaine, annulation confirmée et résultat inconnu ;
- aucune suppression ou nouvelle substitution en cas de preuve insuffisante ;
- aucun nouvel échange automatique après une restauration interrompue ;
- authentification complète de la source, préparation d'un candidat complet, revalidation des identités et remplacement atomique sous réservation ;
- conservation de la sauvegarde source et de l'ancien principal après échange ;
- après redémarrage, ouverture seulement du fichier actuellement présent au chemin principal s'il est sain et authentifié, sans restauration automatique d'une ancienne session ;
- aucune modification automatique des permissions d'un dossier utilisateur choisi ;
- aucune ouverture rendue impossible par la seule perte des futures préférences ordinaires.

### 11.2 Limites inhérentes

- un processus malveillant déjà exécuté sous le même compte utilisateur dépasse le modèle de protection locale des permissions et descripteurs ;
- Qt, la bibliothèque C++, SQLite et le noyau peuvent conserver des copies historiques de secrets ;
- une E/S ou un appel noyau peut rester bloqué malgré une annulation ;
- une demande d'annulation envoyée ne prouve ni sa réception ni la terminaison du worker ;
- `fsync` et les résultats système ne garantissent pas la conservation physique après retrait ou panne du support ;
- `renameat2(RENAME_EXCHANGE)` garantit l'atomicité attendue de l'échange sur les systèmes pris en charge, pas sa durabilité physique absolue après une coupure ;
- sans journal permanent, PassWall ne peut pas toujours déterminer après redémarrage si un échange antérieur a eu lieu ; il authentifie l'état présent et exige une nouvelle demande explicite pour restaurer ;
- les réservations sont coopératives et ne contraignent pas un processus tiers qui les ignore ;
- les systèmes réseau, amovibles ou synchronisés n'ont pas les mêmes propriétés que les systèmes de fichiers locaux testés ;
- une copie cohérente n'empêche pas deux copies de la même famille de diverger ensuite ;
- les tests injectés ne simulent pas intégralement une panne électrique ou matérielle.

## 12. Validation connue

Les nombres ci-dessous correspondent à des campagnes distinctes et ne doivent pas être additionnés.

| Jalon | Résultat rapporté | Portée principale |
|---|---:|---|
| Campagne complète historique | 225/225 | État antérieur du projet |
| Restauration 6B | 449 cas ciblés | échange réel sur coffres fictifs, finalisation, reprise |
| Worker et supervision 7 | 737 cas ciblés | délégation, canal secret, processus, réservations |
| GUI de restauration 8A | 713 cas ciblés | parcours widgets/6A/worker/6B |
| Préférences GUI 8B | 772 cas ciblés | registre, coordinateur, worker, reprise |
| Verrouillage obligatoire 8C-2 | 64/64 | valeurs, migration, expirations et régressions |
| Prévalidation/restauration 1.29 | 157 cas ciblés | sources invalides, TOCTOU, abandon contrôlé |
| `vault/lastPath` local | 15/15 | préremplissage et publication après authentification |
| Caractérisation lot 0A | 320/320 ciblés | transactions/interruption SQLite, publication, réservations, worker, remplacement et preuves historiques |
| Réservations partagées d'instantané | 135/135 ciblés | garde typée, copie SQLite concurrente, worker, supervision, coordinateur historique exclusif et remplacement |
| Correction export manuel 2F | 928 sans échec, 1 auxiliaire ignoré | export exclusif, chemin d'instantané partagé explicite, annulation, résultat inconnu et terminaison effective |
| Identité générationnelle 2G-1 | 12 cas ciblés verts ; campagne CTest 930 réussis, 1 échec GUI non reproductible isolément, 1 auxiliaire ignoré | liaison périphérique/inode, substitution, verrouillage ordinaire, réservation de remplacement et export exclusif |
| Reprise de contention 2G-2 | 28 cas ciblés distincts réussis ; 1 fixture historique sous `/tmp` refusée par la politique de permissions | réveil local, borne de pré-lancement, générations, concurrence, identité, résultats tardifs, export exclusif et réservations de restauration |
| Fermeture normale 2G-3 | 8 nouveaux cas ciblés réussis ; 4 régressions d'export réussies ; CTest : 944 réussis, 1 échec GUI intermittent réussi en relance isolée, 1 auxiliaire ignoré | capture avant arrêt, règlement explicite, worker réel, contention, générations récentes, nettoyage de session, export et restauration |
| Preuve de publication 2H-1 | 8 tests ciblés réussis | reçu worker, destination exacte, jeton/génération et refus fail-closed des preuves absentes ou incohérentes |
| Diagnostics générationnels 2H-2 | 11/11 tests ciblés rapportés réussis après implémentation | résultat détaillé, `errno`, annulation, durabilité incertaine, résultat absent/crash et reçu atomique |
| Sélecteur exclusif 2I-1 | 41 tests ciblés réussis | mode immuable, production historique, injection générationnelle et neutralisation croisée sans double déclenchement |
| Admission CRUD 2I-2 | 40 tests ciblés réussis | production historique inchangée, admission générationnelle sans suivi persistant et barrières de récupération conservées |
| Préférences globales 2I-3A | 10 tests ciblés réussis après correction du verrou QSettings | états explicites, schéma global, persistance, erreurs et indépendance de `PassWall.conf` |
| Familles et destinations 2I-3B | 11 tests ciblés réussis | familles `vault_id`, nommage UTC, permissions privées, identités, collisions et substitutions |
| Première sauvegarde 2I-3B/2I-3C | 21 tests ciblés rapportés réussis | destination, réservation unique, peuplement, version admissible, nouvelle racine, familles partagées, configuration, sessions et substitutions |
| Admission préparée 2I-4B | 33/33 tests ciblés réussis (29 préparation/destination, 2 coordinateur, 2 BackupJob) | usage unique, admission propriétaire, revalidation complète, transfert au worker, annulation et libération RAII |
| Arbitrage initial/CRUD 2I-4C | tests ciblés rapportés réussis | type `InitialCopy`, admission propriétaire, courses de commit, fusion, invalidation de jeton et libération RAII |
| Coordination utilisateur 2I-4D | validations ciblées rapportées réussies | états transitoires, préadmission export/restauration, course avec l'exclusivité, worker inconnu encore vivant, annulation et session obsolète |
| Inspection asynchrone 2I-4E-1 | 129 tests ciblés du coordinateur rapportés réussis | thread de travail, cycle de session, annulation non bloquante, réponse tardive, configuration, doublons et arbitrage CRUD |
| Consommation générationnelle 2I-4E-2 | 137/137 tests ciblés du coordinateur rapportés réussis | publication réelle initiale/CRUD, jeton et session, sérialisation, échecs, preuve de publication et worker inconnu |
| Suspension générationnelle 2I-4F-1 | 138/138 tests ciblés du coordinateur rapportés réussis | suspension volatile `Failed`/`Unknown`, commits non couverts, reprise unique, worker vivant, résultat obsolète, isolation et absence de persistance |
| Arbitrage manuel 2I-4F-2 | 146/146 sauvegarde automatique, 165/165 remplacement, 5/5 GUI ciblés rapportés réussis | admission RAII, priorité automatique, transfert vers l'exclusivité, inspection réservée, annulation, substitution, sessions et isolation |
| Invalidation des préférences 2I-4F-3 | 11/11 préférences, 29/29 destinations, 150/150 coordinateur, 5/5 GUI ciblés rapportés réussis | provenance INI, annulation non bloquante, jetons invalidés, CRUD conservés, revalidation finale et worker actif préservé |
| Vidange du coordinateur 2I-4F-4A | 8/8 tests ciblés réussis ; inclus dans les 158/158 du coordinateur après 4B | générations immédiates, worker actif et génération postérieure, absence de doublon, suspension, admission manuelle et inspection annulée |
| Fermeture GUI générationnelle 2I-4F-4B | 4/4 tests GUI de fermeture, 5/5 GUI export/restauration, 158/158 coordinateur rapportés réussis | premier verrouillage et secrets nettoyés, fermetures répétées, `COMMIT` tardif, clôture automatique et compatibilité production `Historical` |
| GitHub ARM64 1.26 | 887 réussis, 1 ignoré | ensemble CTest enregistré |
| JavaScript extension | 5/5 localement | tests unitaires Node.js, pas Firefox réel |

Principes d'interprétation :

- **TESTÉ** ne signifie pas certifié ni validé sous panne électrique.
- Les sélections ciblées se recouvrent ; leurs totaux ne mesurent pas le nombre global de tests uniques du dépôt.
- Les bus D-Bus privés, faux logind, faux verrouilleurs et Qt offscreen ne remplacent pas une transition système réelle.
- Les essais Firefox et Wayland sont des observations manuelles avec données fictives, séparées des tests automatisés.
- Les anciens échecs `EPERM` de sockets ou identités artificielles dans un sandbox ne sont pas des défauts applicatifs lorsqu'ils disparaissent dans l'environnement POSIX autorisé sans relâcher les protections.

### 12.1 Principales suites existantes

- cryptographie, environnement, stockage et ressources SQLite ;
- `CredentialService`, nettoyage maître et mémoire CRUD ;
- parsing d'identifiants, traitement natif, bridge et démarrage du Host ;
- SiteMatcher et générateur de mots de passe ;
- instance unique, logind, service et coordinateur de session ;
- préférences, suivi des mutations et réservations ;
- instantané, worker, sauvegarde automatique et rotation ;
- autorisation, moteur de remplacement, worker de restauration et supervision ;
- GUI d'export, préférences, restauration, récupération, éditeurs et timer ;
- JavaScript de remplissage et sécurité de navigation.

## 13. Plan de refonte des sauvegardes

L'ordre ci-dessous peut être ajusté si l'analyse des dépendances l'impose, sans retirer une garantie au seul motif qu'elle appartient au code historique.

### Lot 0 — spécification, décisions et caractérisation

- **VALIDÉ — lot 0B** — le suivi des modifications métier est limité à la mémoire de la session et commence seulement après `COMMIT` ; l'interruption avant publication confirmée peut donc laisser une sauvegarde non rattrapée automatiquement ;
- **VALIDÉ — lot 0B** — le dossier familial, le nom UTC, les collisions, la première copie et les bornes de rétention sont spécifiés par les sections 5.2 à 5.4 ;
- **VALIDÉ — lots 0C/2I-4F-1** — seuls les coffres ouverts sont pris en charge, chaque tentative produit un résultat et une notification sans suspension persistante ; `Failed` et `Unknown` suspendent seulement en mémoire jusqu'à reprise explicite, et la rotation suit une publication suffisamment confirmée sans catalogue ni reçu persistant ;
- **TESTÉ — lot 0A** — 320 cas ciblés caractérisent les transactions, interruptions injectées, publications, réservations, workers, remplacement et preuves historiques de l'implémentation actuelle ;
- **À FAIRE** — trancher les points restant ouverts de la section 14 ;
- **Critère de sortie** — règles explicites pour les artefacts, la destination corrompue, l'admission à la rotation, les préférences, les échecs de sauvegarde et la compatibilité historique.

### Lot 1 — découplage des préférences et transition historique

- **À FAIRE** — séparer les préférences ordinaires des contrôles de sécurité encore utilisés par les opérations historiques ;
- **À FAIRE** — préparer l'arrêt des nouvelles intentions persistantes sans supprimer ni déplacer aveuglément les preuves existantes ;
- **À FAIRE** — caractériser la coexistence temporaire avec les versions anciennes de PassWall ;
- **Critère de sortie** — perdre les préférences ordinaires ne bloque pas un coffre sain, tandis qu'une opération historique inachevée conserve ses protections actuelles.

### Lot 2 — préférences globales et familles `vault_id`

- **IMPLÉMENTÉ et TESTÉ — fondation 2I-3A** : un fichier INI utilisateur distinct stocke la racine, la rétention minimale de sept et un état explicite d'absence, validité, invalidité ou erreur, sans modifier le registre historique. Les dix tests ciblés rapportés sont réussis ;
- **IMPLÉMENTÉ et TESTÉ — fondation 2I-3B** : le préparateur inactif route une identité de coffre vérifiée vers sa famille `vault_id`, crée le sous-dossier privé, choisit un nom UTC sans réserver ni publier de fichier et conserve la capacité d'instantané ainsi que les identités nécessaires à une revalidation. Les onze tests ciblés rapportés sont réussis ;
- **À FAIRE** — raccorder la configuration initiale et le futur consommateur générationnel à cette fondation, sans présenter l'état `Valid` comme une autorisation suffisante d'écrire dans la destination ;
- **À FAIRE** — retirer la liste permanente des coffres comme condition de la gestion automatique ; un coffre est pris en charge lorsqu'il est effectivement ouvert ;
- **À FAIRE** — remplacer la GUI par une configuration initiale puis des paramètres globaux ;
- **Critère de sortie** — deux copies de même famille alimentent le même dossier sans que `vault_id` devienne une autorisation.

### Lot 3 — sauvegarde automatique et rotation sans catalogue

- **IMPLÉMENTÉ — fondation** : le garde, le moteur d'instantané et le worker possèdent un accès partagé typé, transmissible et sérialisé par coffre ; le coordinateur automatique historique reste provisoirement exclusif.
- **IMPLÉMENTÉ — fondation 2A** : les ajouts, modifications et suppressions confirmés exposent un événement en mémoire après `COMMIT` ;
- **IMPLÉMENTÉ — fondation 2B** : le coordinateur regroupe ces événements par session avec un délai mono-coup de vingt secondes et des générations en mémoire, puis émet une demande interne sans lancer de copie ;
- **IMPLÉMENTÉ — fondation 2C** : le verrouillage ordinaire transforme une génération encore planifiée en demande différée unique après l'invalidation synchrone de la session ; le nettoyage des secrets n'attend aucun consommateur ni aucune copie ;
- **IMPLÉMENTÉ — fondation 2D** : offres, tentative active et générations différées sont sérialisées en mémoire par des jetons à usage unique ; seul un résultat correspondant à la tentative active peut la terminer, sans acquitter les générations postérieures ;
- **IMPLÉMENTÉ — fondation 2E** : la frontière peut lancer `BackupJob::startSnapshotReserved()` avec une capacité partagée contrôlée, marque la tentative avant le lancement, lie le résultat au jeton et attend la terminaison effective avant de publier `Published`, `Failed` ou `Unknown`. Elle n'exécute aucune rotation et n'est pas encore consommée en production ;
- **IMPLÉMENTÉ — fondation 2G-1** : une demande transporte l'identité physique en mémoire de sa session d'origine et la frontière refuse définitivement toute génération dont une capacité d'instantané valide révèle que le fichier au chemin attendu a été remplacé ; un verrouillage ordinaire du même fichier conserve la demande ;
- **IMPLÉMENTÉ — fondation 2G-2** : une contention de pré-lancement attend en mémoire un indice local de libération et réémet un jeton neuf sous une échéance unique de trois secondes ; la disponibilité et l'identité sont toujours réacquises, tandis qu'une contention persistante, une annulation, un refus définitif ou un résultat incertain se terminent explicitement sans boucle automatique ;
- **IMPLÉMENTÉ — fondation 2G-3** : la fermeture normale capture la génération planifiée avant d'arrêter le coordinateur, nettoie la session sans attendre une copie, solde explicitement les demandes non lancées et conserve la supervision/réservation d'un worker réel jusqu'à sa terminaison ou son transfert au superviseur indépendant ; elle ne lance aucun nouveau worker tant que le consommateur de production reste désactivé ;
- **IMPLÉMENTÉ — fondations 2H-1/2H-2** : une publication générationnelle exige un reçu transitoire lié à la destination et au jeton actifs ; le même résultat transitoire conserve ce reçu, le `BackupOutcome` détaillé et le diagnostic effectivement disponible sans créer de catalogue ni d'historique persistant ;
- **IMPLÉMENTÉ — fondation 2I-1** : les deux sources de déclenchement sont mutuellement exclusives dès la construction ; les événements et rappels du moteur inactif ne peuvent pas lancer une sauvegarde, et aucun échec ne provoque de repli vers l'autre moteur ;
- **IMPLÉMENTÉ et TESTÉ — fondation 2I-2** : l'admission des CRUD est maintenant sélectionnée par la même politique immuable. Le mode historique conserve son intention persistante avant SQL ; le mode générationnel conserve les barrières de récupération et d'identité sans écrire le suivi historique des sauvegardes. Les 40 tests ciblés rapportés sont réussis ;
- **IMPLÉMENTÉ — préparation 2I-3B** : la destination peut être sélectionnée et liée au coffre, à sa famille et à sa génération sous capacité d'instantané, mais aucun consommateur de production ne l'appelle encore ;
- **IMPLÉMENTÉ — préparation 2I-3C inactive** : un service sans état persistant détecte, sous identité physique et contrôles structurels, un coffre authentifié et peuplé sans version admissible dans la racine courante. Il produit une demande de première copie distincte ou la fusionne avec une génération CRUD déjà en attente, sans créer de fichier ni lancer de worker ;
- **TESTÉ — préparation 2I-3B/2I-3C** : les 21 tests ciblés rapportés réussissent, ainsi que les deux régressions de prévalidation de restauration directement concernées ;
- **IMPLÉMENTÉ et TESTÉ — admission 2I-4B inactive** : une frontière propriétaire à usage unique revalide la préparation et transfère sans réacquisition la capacité au pilote existant ; les 33 tests ciblés rapportés réussissent (29 préparateur/destination, 2 coordinateur, 2 `BackupJob`), sans activation en production ;
- **IMPLÉMENTÉ et TESTÉ — arbitrage 2I-4C inactif** : `InitialCopy` et `CrudGeneration` partagent la file, la sérialisation et les jetons du coordinateur sans confondre génération de session et génération métier. Une mutation arrivée avant démarrage remplace la première copie préparée et conserve son propre délai ; les tests ciblés sont rapportés réussis ;
- **IMPLÉMENTÉ et TESTÉ — coordination 2I-4D inactive** : l'activité préparatoire, la capacité détenue, les offres, la contention et les workers vivants sont distingués en mémoire. L'export et la restauration disposent d'un refus anticipé diagnostiqué, sans annulation implicite et sans remplacer leurs réservations exclusives finales. Les validations ciblées sont rapportées réussies ;
- **IMPLÉMENTÉ et TESTÉ — inspection 2I-4E-1 inactive** : l'inspection 2I-3C est exécutable hors du thread GUI, liée au véritable cycle de session et remise à l'arbitrage propriétaire sans attendre lors du verrouillage. Les 129 tests ciblés du coordinateur rapportés par l'utilisateur réussissent ;
- **IMPLÉMENTÉ et TESTÉ — consommation 2I-4E-2 inactive** : les demandes préparées initiales et CRUD utilisent un superviseur et un worker communs avec admission finale, transfert unique de capacité et résultat complet après terminaison. Les 137/137 tests ciblés du coordinateur rapportés par l'utilisateur réussissent ;
- **IMPLÉMENTÉ et TESTÉ — suspension 2I-4F-1 inactive** : `Failed` et `Unknown` créent une suspension exclusivement en mémoire, tout commit ultérieur reste non couvert sans nouvelle tentative, et seule une reprise explicite revalidée peut offrir une tentative unique. Un worker encore vivant interdit cette reprise et les sauvegardes incertaines sont conservées ; les 138/138 tests ciblés rapportés réussissent ;
- **IMPLÉMENTÉ et TESTÉ — arbitrage 2I-4F-2 inactif** : une capacité RAII propriétaire ferme la course entre précontrôle et réservation exclusive des exports/restaurations. Une demande automatique antérieure gagne ; une opération manuelle admise en premier termine son transfert sans être préemptée ; la garde physique reste l'autorité finale et aucun état persistant n'est ajouté. Les validations rapportées sont 146/146, 165/165 et 5/5 selon les suites ciblées ;
- **IMPLÉMENTÉ et TESTÉ — invalidation 2I-4F-3 inactive** : provenance et contenu des préférences lient chaque préparation ; les changements annulent les travaux non lancés, conservent les générations CRUD et sont revalidés au dernier point de consommation. Aucun worker actif n'est interrompu et aucun état persistant n'est ajouté. Les validations ciblées rapportées réussissent (11/11, 29/29, 150/150 et 5/5 selon les suites) ;
- **IMPLÉMENTÉ et TESTÉ — vidange 2I-4F-4A inactive** : la fermeture rend immédiatement éligibles les générations confirmées, conserve un worker actif et traite séparément les générations postérieures sans retry ; les huit tests ciblés de vidange réussissent ;
- **IMPLÉMENTÉ et TESTÉ — GUI 2I-4F-4B inactive en production** : la première fermeture verrouille et nettoie immédiatement, les fermetures répétées n'effacent pas la session non secrète nécessaire aux derniers `COMMIT`, et la fermeture finale est automatique après vidange terminale, sans dialogue utilisateur. Une fabrique sous `PASSWALL_GUI_TESTING` rend ce parcours testable sans sélectionner `Generational` en production. Les validations rapportées réussissent : 4/4 GUI de fermeture, 5/5 régressions export/restauration et 158/158 coordinateur ;
- **À FAIRE** — raccorder le consommateur unique de production et les préférences globales, construire explicitement le coordinateur de production en mode `Generational`, puis retirer le suivi historique persistant après validation de la transition, sans réintroduire de dialogue de fermeture « attendre ou quitter » ;
- **À FAIRE** — appliquer une rétention globale de sept par défaut, configurable à partir de sept sans plafond arbitraire de produit ;
- **À FAIRE** — après publication suffisamment confirmée, découvrir, filtrer et trier les versions admissibles puis supprimer les plus anciennes jusqu'à la rétention, sans catalogue, reçu ou reprise persistante ;
- **À FAIRE** — raccorder le résultat générationnel détaillé au futur consommateur et à sa notification, puis distinguer la publication confirmée de la rotation sans perdre les diagnostics système réellement disponibles ;
- **À FAIRE** — supprimer la suspension persistante et les boucles historiques lors du retrait du moteur `Historical`, tout en raccordant à la future interface la reprise explicite de la suspension générationnelle volatile ;
- **Critère de sortie** — aucune rotation n'exige de catalogue individuel, aucun fichier ambigu, hors périmètre ou modifié concurremment n'est supprimé, une erreur de rotation ne rétracte pas la nouvelle sauvegarde et une interruption n'est pas présentée comme automatiquement rattrapée.

### Lot 4 — restauration atomique sans journal et autorisation transitoire

- **À FAIRE** — conserver un moteur unique, l'authentification complète, le canal secret, les réservations, les revalidations et l'échange atomique ;
- **À FAIRE** — remplacer les intentions et reçus permanents par un engagement supervisé uniquement pendant l'opération ;
- **À FAIRE** — après interruption, authentifier l'état présent sans nouvel échange automatique ni prétention de reconstituer un historique indémontrable ;
- **Critère de sortie** — aucune donnée sérialisée ne permet de forger une autorisation et les résultats incertains restent présentés comme tels.

### Lot 5 — principal corrompu, consultation et copies de travail

- **À FAIRE** — admettre une destination corrompue sous sélection explicite, confirmation renforcée et contrôles stricts ;
- **À FAIRE** — exposer une lecture seule réelle des sauvegardes gérées ;
- **À FAIRE** — créer une copie de travail hors racine sans changer le `vault_id` ;
- **Critère de sortie** — l'ancien principal est conservé, aucune ouverture automatique ne suit le remplacement et aucune écriture n'est possible depuis la consultation en lecture seule.

### Lot 6 — retrait des mécanismes historiques et audit final

- **À FAIRE** — résoudre ou maintenir bloqués les états historiques encore actifs avant de retirer leur porte d'admission ;
- **À FAIRE** — supprimer intentions, phases, reçus, catalogue, préférences par coffre et ancien code uniquement après disparition de leur dernier appelant et transfert des garanties pertinentes ;
- **À FAIRE** — retirer ou réécrire les tests devenus purement historiques sans perdre les scénarios de sécurité réutilisables ;
- **Critère de sortie** — une seule architecture de préférences, sauvegarde, rotation et restauration demeure, sans nouveau journal permanent PassWall.

## 14. Décisions techniques encore ouvertes

1. **À DÉFINIR** — possibilité de désactiver les sauvegardes après la configuration initiale.
2. **À DÉFINIR** — comportement exact d'une nouvelle ouverture sans sauvegarde admissible après un échec précédent : distinguer une nouvelle tentative liée à une nouvelle utilisation d'une boucle automatique répétée.
3. **À DÉFINIR** — critères techniques détaillés de suppression sans catalogue et traitement des fichiers ambigus ou modifiés concurremment ; une preuve historique individuelle n'est pas requise pour une version autrement admissible.
4. **À DÉFINIR** — conduite après une publication visible dont la synchronisation ou la durabilité n'est pas confirmée, sans inventer un succès, une suppression ou un journal de reprise.
5. **À DÉFINIR** — conditions précises permettant d'arrêter la création des intentions historiques, de résoudre les états restants puis de retirer leur porte d'admission sans période contradictoire.
6. **À DÉFINIR** — compatibilité et politique de retour à une ancienne version de PassWall capable de recréer des intentions dans `vaultRegistry/data`.
7. **À DÉFINIR** — emplacement, nommage, signalement et nettoyage volontaire des anciens principaux et autres artefacts ; aucune seconde copie de précaution systématique n'est prévue.
8. **À DÉFINIR** — confirmation renforcée et identification suffisante pour remplacer une destination corrompue dont le `vault_id` et les métadonnées sont illisibles.
9. **À DÉFINIR** — comportement détaillé après interruption lorsque plusieurs fichiers sont sains ou lorsqu'aucun ne peut être authentifié, sans reprise automatique de l'échange.
10. **À DÉFINIR** — politique sur les plateformes ou systèmes de fichiers dépourvus d'un échange atomique équivalent à `RENAME_EXCHANGE` ; aucun remplacement non atomique silencieux ne doit être introduit.
11. **À DÉFINIR** — accès aux anciennes racines après changement de destination.
12. **À DÉFINIR** — politique d'acceptation des chemins ayant un ancêtre modifiable par le groupe, systèmes de fichiers non pris en charge et supports NAS/amovibles indisponibles ou déconnectés.
13. **À DÉFINIR** — comportement produit lorsque plusieurs principaux de travail de la même famille divergent, y compris la première copie de B lorsqu'une version de A est admissible et la protection d'historiques distincts sous une rétention commune avant toute rotation destructive.

## 15. Travaux transversaux restants

### 15.1 Sécurité et qualité V1

- **À FAIRE** — audit global des copies sensibles, du presse-papiers, des logs, messages et nouvelles tâches asynchrones ;
- **À FAIRE** — revue cryptographique V1 documentée ;
- **À FAIRE** — tests supplémentaires de corruption, fichier inaccessible, espace insuffisant et E/S, sans les présenter comme des pannes matérielles réelles ;
- **À FAIRE** — conserver les tests des champs obligatoires, transactions, RAII, timer, éditeurs, Native Messaging, récupérations historiques pendant la transition et interruptions de la restauration cible ;
- **À FAIRE** — campagne complète actuelle après les lots de refonte, sans masquer les tests instables ou ignorés ;
- **À FAIRE** — essais contrôlés de panne/interruption sur supports fictifs et documentation des résultats incertains.

### 15.2 Firefox

- **À FAIRE** — automatisation de bout en bout avec Firefox réel ;
- **À FAIRE** — installation versionnée du manifeste, du Native Host et de l'extension ;
- **À FAIRE** — scénarios d'invalidation pendant une réponse réellement transmise ;
- **À FAIRE** — revue de la durée de vie des secrets dans l'extension.

### 15.3 Produit

- **À FAIRE** — TOTP ;
- **À FAIRE** — passkeys ;
- **À FAIRE** — audit des mots de passe ;
- **À FAIRE** — export de la configuration globale, sans inventer un import non spécifié ;
- **À FAIRE** — ergonomie et diagnostics des supports indisponibles, destinations invalides et résultats incertains.

### 15.4 Plateformes et distribution

- **À FAIRE** — installation Linux reproductible de l'application, des deux workers, du Native Host, du coordinateur et de l'extension ;
- **À FAIRE** — vérifier les incompatibilités de versions et auxiliaires absents ;
- **À FAIRE** — validation Windows en machine virtuelle, puis conception iOS après stabilisation Linux/Windows ;
- **À FAIRE** — fournir un `README.md`, un `SECURITY.md` et un `CHANGELOG.md` adaptés à la diffusion ;
- **À FAIRE** — documenter les plateformes et systèmes de fichiers effectivement supportés.

## 16. Critères de candidature à une V1

Avant une première diffusion :

- architecture de préférences/sauvegardes unique, sans ancien catalogue concurrent ;
- restauration atomique sans nouveau journal permanent PassWall, avec autorisation transitoire non forgeable et supervision testées ;
- arrêt des nouvelles intentions persistantes et traitement contrôlé de toutes les preuves historiques avant retrait de leur porte d'admission ;
- restauration manuelle d'un principal corrompu sous confirmation renforcée et conservation de l'ancien fichier ;
- chiffrement, format et paramètres documentés et audités ;
- sauvegardes, rotation et restauration sans anomalie non qualifiée ;
- traitement explicite des résultats incertains, des interruptions, des artefacts et des limites de durabilité ;
- absence de secret dans les logs et maintien des nettoyages contrôlés ;
- tests actuels du cycle de vie, corruption, mémoire, Firefox et verrouillages ;
- installation Linux et Firefox reproductible ;
- supports et plateformes annoncés réellement validés ;
- risques résiduels, limites physiques et absence de récupération du maître clairement documentés.

TOTP, passkeys et audit des mots de passe doivent être positionnés explicitement dans le périmètre de la diffusion retenue ; ils ne sont pas implicitement livrés par les fondations existantes.

## 17. Règles de maintenance de cette référence

Après chaque changement :

1. mettre à jour le statut concerné sans présenter une décision cible comme déjà implémentée ;
2. indiquer les composants modifiés, les tests réellement exécutés et leurs limites ;
3. conserver les garanties historiques encore actives, même si leur implémentation change ;
4. retirer les descriptions et composants obsolètes dès que leur dernière dépendance est migrée et testée ;
5. ne pas recréer un TODO ou un document architectural parallèle sans décision explicite.

Les comptes rendus de développement doivent distinguer essais automatisés, observations manuelles, injections de fautes et transitions système réelles. Cette référence ne constitue pas une certification de sécurité.
