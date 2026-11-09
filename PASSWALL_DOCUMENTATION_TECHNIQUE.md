# PassWall — Documentation technique du projet et état des réalisations

**Version :** 1.9
**Date :** 9 novembre 2026
**Statut :** moteur synchrone 6B de remplacement du principal développé sur les fondations 6A/6A-bis, sans auxiliaire ni GUI de restauration. Les validations historiques et la campagne ciblée 6B du 9 novembre 2026 sont distinguées en section 6.2 ; les contrats, fonctionnalités incomplètes et limites restent explicites.

## 1. Présentation

PassWall est un gestionnaire de mots de passe dont le développement vise d'abord Linux sur Raspberry Pi 5. L'arbre courant contient un coffre chiffré local, une interface graphique indépendante du moteur et une intégration Firefox par Native Messaging. Le fichier de coffre chiffré est autonome : une copie cohérente peut être ouverte avec son mot de passe maître sur une installation compatible, sans autorisation de la machine d'origine. Les copies évoluent indépendamment, sans propagation automatique ; l'utilisateur assure leurs transferts et leur cohérence.

La priorité est la sécurité : chiffrement au repos, protection des clés, réduction de la durée de présence des secrets en mémoire, verrouillage du coffre et contrôles locaux des opérations et de récupération.

Ce document distingue décisions validées, composants implémentés et travaux non implémentés. « Implémenté et testé » désigne du code présent, des tests correspondants et une validation antérieure rapportée dans le périmètre indiqué ; la présence d'un fichier ou d'un contrat ne suffit pas. Il ne constitue pas une certification de sécurité. Le TODO décrit les prochains travaux sans répéter tous les contrats détaillés ici.

## 2. Environnement connu

| Élément | Valeur relevée |
|---|---|
| Matériel | Raspberry Pi 5, 8 Go |
| OS | Debian 13.7 Trixie |
| Bureau | labwc / wlroots |
| Navigateur | Firefox |
| Éditeur | Visual Studio Code |
| Compilateur | GCC/G++ 14.2.0 |
| CMake | 3.31.6 |
| Ninja | 1.12.1 |
| Qt | 6.8.2 |
| libsodium | 1.0.18 |
| SQLite | 3.46.1 |
| Git | 2.47.3 |
| GoogleTest | installé et détecté par CMake |

Ces versions proviennent des relevés communiqués pendant le développement et doivent être revérifiées sur la machine actuelle.

## 3. Technologies et périmètre fonctionnel

Technologies : C++20, Qt 6 Widgets/Core/Network/DBus, Qt Designer, QSS, libsodium, SQLite, JavaScript, CMake et GoogleTest. Le générateur CMake peut être Ninja ou Make selon le répertoire de compilation.

Périmètre v1 défini :
- coffre chiffré et gestion des identifiants — implémentés ;
- extension Firefox pour rechercher un compte et remplir les champs — implémentée et essayée manuellement avec Firefox le 6 novembre 2026 ; installation locale manuelle, non empaquetée dans le dépôt ;
- générateur de mots de passe — implémenté et testé ;
- registre local, exclusion métier, suivi des modifications, moteur d'instantané, auxiliaire de sauvegarde, export manuel Qt, sauvegardes automatiques et rotation — implémentés et couverts par des tests ciblés ; l'interface de réglage et de reprise des sauvegardes reste absente ;
- restauration authentifiée vers un nouveau fichier — moteur existant testé ; remplacement d'un principal existant — moteur synchrone 6B, sans auxiliaire ni parcours GUI ;
- TOTP — à développer ;
- portabilité du fichier sans lien cryptographique à une machine — présente dans le format et le chemin d'ouverture ; contrôles locaux et limites de validation détaillés en sections 4.3 et 5.10 ;
- passkeys — à développer ;
- audit des mots de passe — à développer.

L'intégration aux applications locales du système a été reportée après stabilisation du coffre et de Firefox.

La synchronisation automatique, la résolution de conflits entre copies et un serveur de référence ne font pas partie du périmètre actuel. Ce sont d'éventuelles évolutions nécessitant une nouvelle décision, pas des fonctionnalités déjà planifiées.

## 4. Décisions de conception validées

### 4.1 Stockage et modèle

- Une base SQLite locale par coffre ; les coffres sont cryptographiquement indépendants.
- Notes chiffrées avec le reste de l'entrée.
- Titre, nom d'utilisateur et mot de passe sont obligatoires, à l'ajout comme à la modification. La GUI et les services réutilisent `CredentialService::validate()`. Un titre ou nom d'utilisateur vide ou uniquement composé d'espaces Unicode est refusé, sans normaliser les valeurs acceptées. Le mot de passe est une donnée exacte : chaîne vide refusée, espaces conservés, y compris un mot de passe uniquement composé d'espaces. Les limites de taille restent appliquées.
- La politique SQLite V1 est appliquée et relue par connexion : `journal_mode=DELETE`, `synchronous=EXTRA` (3), `secure_delete=ON` (1), `temp_store=MEMORY` (2), `busy_timeout=3000` ms, avec `NO_CKPT_ON_CLOSE` établi avant l'inspection du journal. `FULL` correspond à l'ancien état, remplacé après étude et mesures sur le Raspberry Pi. Détails et limites en section 5.2.
- Si une migration est nécessaire, l'ouverture normale doit être bloquée et une migration contrôlée proposée après sauvegarde. Aucun moteur de migration n'est implémenté ; les versions incompatibles sont refusées. Les moteurs de sauvegarde et de restauration existants ne constituent pas une migration.

### 4.2 Cryptographie

Choix techniques documentés :
- libsodium ;
- Argon2id pour dériver une clé depuis le mot de passe maître, avec 3 itérations et 256 Mio de mémoire (`VaultArgon2Operations=3`, `VaultArgon2Memory=256 MiB`) ;
- XChaCha20-Poly1305 pour le chiffrement authentifié ;
- chiffrement individuel des entrées ;
- `SecureBuffer` pour les clés et certains buffers sensibles.

Le mot de passe maître est nécessaire pour déverrouiller le coffre. Aucun mécanisme de récupération n'est prévu si ce mot de passe est perdu.

### 4.3 Portabilité des coffres et récupération

- Aucun système d'appareils autorisés n'existe : ni enrôlement, approbation, liste de confiance, clé d'autorisation par appareil ou révocation. Ce modèle est abandonné, pas en attente d'implémentation.
- Le fichier contient les métadonnées cryptographiques nécessaires au déchiffrement par son mot de passe maître. Le registre QSettings d'origine n'est pas requis et ne doit pas être transféré pour autoriser son ouverture.
- Chaque copie est indépendante : modifier `password.db` copié de A vers B ne change pas le fichier resté sur A. L'utilisateur est responsable des transferts et de la cohérence ; aucune fusion ou résolution automatique des conflits n'est réalisée.
- La récupération dépend de copies ou sauvegardes utilisables et du mot de passe maître. Aucune récupération centralisée ni contournement de la perte du mot de passe n'est prévu.

« Autonome » décrit le fichier cryptographique, pas une dispense des protections de l'installation destinataire : version compatible, accès au stockage, politique SQLite, exclusion métier, surveillance Linux et porte de récupération restent applicables. Le registre local associe des préférences de sauvegarde à un fichier, pas un droit d'utilisation à une machine. L'inspection du chemin d'ouverture et ses limites sont détaillées en section 5.10 ; Windows et iOS ne sont pas validés par ce constat.

### 4.4 Copies, sauvegardes et migrations

- Fonctionnement local hors ligne, sans serveur ni infrastructure de confiance entre machines.
- Pour transférer un coffre, privilégier un export/instantané confirmé par le mécanisme existant. Une copie directe n'est acceptable qu'une fois toutes les connexions et opérations d'écriture sur la source terminées ; être verrouillé visuellement ne prouve pas à lui seul cette quiescence, notamment si un auxiliaire est actif. Ne pas copier isolément le fichier principal pendant une transaction ou une restauration. Après incident, ne pas supprimer un journal/WAL/SHM pour fabriquer artificiellement un fichier autonome : faire établir un état cohérent par les chemins pris en charge.
- Les préférences de sauvegarde sont locales, dans un seul fichier global QSettings, jamais dans le coffre SQLite. Chaque enregistrement possède trois réglages : automatique désactivé, destination non définie, sept versions conservées par défaut. L'ancienne piste de rétention de sept jours est remplacée par un nombre de versions.
- Une activation demande une première copie ; les mutations marquent ensuite le coffre à sauvegarder et une demande est faite au verrouillage. Pas de copie supplémentaire si aucune modification n'est en attente. Un échec suspend les nouvelles tentatives jusqu'à une reprise explicite ; ni boucle de répétition automatique, ni destination de secours, ni reprise de fichier interrompu.
- Aucune durée maximale globale pour une sauvegarde saine. Les limites de contention SQLite et les délais d'escalade après annulation sont distincts.
- Export manuel : autorisation depuis une session déverrouillée, verrouillage et nettoyage effectifs avant démarrage. Les modifications non enregistrées d'un éditeur ne sont pas abandonnées pour lancer une sauvegarde.
- Sauvegardes automatiques : `NomDuCoffre_JJ-MM-AAAA_HH-MM-SS.db`, suffixe d'opération en cas de collision. Rotation seulement des versions automatiques suffisamment identifiées, après nouvelle copie confirmée ; jamais des exports manuels, fichiers inconnus ou copies exceptionnelles de précaution.
- Nouvelle restauration V1 décidée : remplacer intégralement un coffre principal existant, sans fusion, en conservant son association locale et ses anciennes sauvegardes ; le laisser verrouillé. Le fichier source est choisi librement, indépendamment du dossier automatique. Si les sauvegardes automatiques sont désactivées, une copie préalable obligatoire du principal, à l'emplacement choisi par l'utilisateur, doit réussir. Si elles sont activées, aucune copie supplémentaire ni condition de sauvegarde récente/disponibilité du dossier habituel n'est imposée. Le parcours complet n'est pas implémenté.
- Pendant une sauvegarde ou restauration, interdire les écritures métier incompatibles sur le coffre concerné tout en gardant l'interface réactive. Une annulation demandée ne prouve pas qu'une publication a été empêchée. Un verrouillage de sécurité pendant la future phase sensible de restauration demandera son annulation (option A), à distinguer du verrouillage volontaire de préparation.
- Exporter la configuration globale est une fonction distincte encore à développer ; son import n'est pas défini et n'est pas à inventer.

Les sauvegardes locales ont donc été développées, mais le support NAS/systèmes de fichiers réseau n'est pas acquis : les destinations non prises en charge sont refusées sans repli. Aucun moteur de migration n'existe. La synchronisation entre copies n'est ni implémentée ni engagée dans le périmètre actuel. Les sauvegardes d'exécutables et de configuration labwc de la section 5.9 restent distinctes des sauvegardes de coffres.

### 4.5 Interface et verrouillage

- Interface Qt indépendante du moteur.
- Interface modifiable sans modifier le moteur.
- Qt Designer et QSS prévus.
- Verrouillage manuel et par inactivité implémenté dans `MainWindow`, avec un timer configuré par défaut à cinq minutes et les choix actuels « Désactivé », 1, 5, 10, 15 ou 30 minutes ; il invalide la session native et nettoie la clé, les résumés en mémoire, les champs de saisie et le presse-papiers PassWall lorsqu'il est inchangé. C'est l'état du code, pas la future politique obligatoire décrite au TODO, section 3.4.
- Sous Linux, `LinuxSessionMonitor` traite les préparations de suspension/hibernation (`PrepareForSleep`) et d'arrêt/redémarrage (`PrepareForShutdown`) de logind, avec un inhibiteur de délai et une politique fail-closed. Cela ne constitue pas une interception garantie de toute fermeture de session, de tout crash ou arrêt forcé.
- Le verrouillage d'écran par les raccourcis labwc configurés passe par `passwall-session-lock`, qui demande `Control1.Lock()` et attend son acquittement de nettoyage avant de tenter `/usr/bin/swaylock -p`, dans la limite du budget D-Bus de 1 500 ms. L'absence de réponse ne bloque pas la tentative de verrouillage de l'écran.
- Décision définitive : `SessionGuard1` est supprimé ; aucune garde persistante globale, authentification globale supplémentaire ou modification du code de swaylock/labwc n'est retenue. Chaque coffre reste cryptographiquement indépendant et s'ouvre avec son propre mot de passe maître, sans obligation de rouvrir le dernier coffre. Le déverrouillage Linux ne restaure aucune ancienne session PassWall.

## 5. Architecture logicielle connue

| Domaine | Responsabilité |
|---|---|
| `core` | cryptographie, buffers sensibles, générateur de mots de passe et rapprochement d'origines Web |
| `storage` | schéma et métadonnées SQLite, configuration vérifiée des connexions et exclusion coopérative |
| `services` | credentials, cycle de vie, registre local, instantanés, pilotage des sauvegardes, catalogue/rotation et moteurs de restauration |
| `models` | structures métier |
| `gui` | interface Qt |
| `native` | hôte Native Messaging Firefox, socket Unix local et traitement métier commun des requêtes |
| `platform` | intégration Linux : logind, instance unique, service D-Bus de verrouillage et coordinateur d'écran |
| `tests` | tests unitaires et d'intégration |

Ce découpage est confirmé dans les sources inspectées. Les composants nouveaux et leurs limites sont détaillés en sections 5.10 à 5.16.

### 5.1 Moteur cryptographique

Fichiers attestés : `crypto_engine.hpp` et `crypto_engine.cpp`.

Fonctions connues : initialisation libsodium, génération de clés, dérivation Argon2id, chiffrement/déchiffrement XChaCha20-Poly1305 et gestion de `SecureBuffer`.

`SecureBuffer` utilise `sodium_malloc`, initialise son buffer, interdit la copie, autorise le déplacement et nettoie/libère sa mémoire dans son destructeur. L'affectation par déplacement nettoie et libère la mémoire précédemment détenue par la destination.

### 5.2 Stockage et cycle de vie

Composants implémentés :
- `vault_storage` ;
- `vault_key_service` ;
- `vault_lifecycle_service`.

Ils participent à la création et à l'ouverture du coffre. La création utilise un fichier temporaire, des permissions `0600`, une synchronisation `fsync`, puis une publication qui refuse tout écrasement de destination existante. Le coffre stocke les métadonnées de clé et les entrées chiffrées, sans colonnes de credentials en clair.

`VaultStorage` protège par RAII connexions, statements, messages SQLite et fichiers temporaires de création. Les statements sont finalisés avant la fermeture effective de leur connexion. Les nettoyeurs ne construisent pas de diagnostics allouants. Une exception avant publication nettoie le temporaire détenu ; une erreur ultérieure de synchronisation ou de suppression du nom temporaire ne doit jamais effacer le coffre final déjà publié.

`storage::configureSqliteConnection()` (`sqlite_connection_config.hpp/.cpp`) est commun aux ouvertures de `VaultStorage`, de `CredentialService` et aux inspections/copies qui l'utilisent. Les réglages sont vérifiés avant les opérations métier, hors transaction :

| Réglage | Contrôle effectif |
|---|---|
| `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` | Activation puis interrogation, valeur 1 exigée avant tout PRAGMA |
| `main.journal_mode` | Nouveau fichier : demande explicite DELETE et vérification ; existant : lecture seulement, `delete` exigé |
| `main.synchronous` | EXTRA, valeur 3 relue |
| `main.secure_delete` | ON, valeur 1 relue |
| `temp_store` | MEMORY, valeur 2 relue, options de compilation `TEMP_STORE` compatibles et vérifiables exigées |
| `busy_timeout` | API `sqlite3_busy_timeout(3000)` contrôlée puis valeur 3000 relue |

La configuration n'est pas supposée héritée d'une connexion précédente : le mode de journal est aussi inspecté à la réouverture et les autres réglages sont réappliqués. Toute valeur obligatoire absente ou invérifiable refuse l'opération. Un coffre WAL ou dans un autre mode inattendu est refusé sans conversion et sans suppression manuelle de WAL/SHM. `NO_CKPT_ON_CLOSE` empêche le checkpoint automatique à la fermeture de cette connexion, pas une récupération SQLite ni l'action d'autres connexions ; l'index `-shm` peut changer. Ce n'est pas une garantie d'immuabilité de tous les fichiers.

EXTRA a été retenu pour renforcer la synchronisation liée à la suppression du journal DELETE. Les mesures FULL/EXTRA rapportées ne sont pas une expérience de coupure électrique et ne prouvent pas la durabilité physique d'un matériel donné. `secure_delete` et `temp_store` ne garantissent pas l'effacement de l'historique d'un SSD, d'un système de fichiers à snapshots, du swap ou des copies externes.

### 5.3 Modèle Credential

Le fichier communiqué `src/models/credential.hpp` définit :
- `EntryId`, identifiant de 16 octets ;
- version ;
- titre ;
- URL ;
- nom d'utilisateur ;
- mot de passe ;
- notes.

Les champs textuels sont des `std::string`. Le type reste une structure simple ; l'invariant V1 et les limites de taille sont imposés par `CredentialService::validate()`, réutilisé par la GUI. Le modèle ne garantit pas à lui seul l'effacement sécurisé de ses champs à la destruction.

`CredentialSummary` contient uniquement l'identifiant, la version, le titre, l'URL et le nom d'utilisateur. Il ne contient ni mot de passe ni notes et sert à l'affichage et à la recherche sans collection durable de credentials complets dans `MainWindow`.

### 5.4 CredentialService

`CredentialService` gère l'ajout, la lecture, la liste, la modification et la suppression des entrées.

Le fichier `src/services/credential_service.cpp` a été communiqué et examiné. Les champs d'une entrée sont sérialisés, chiffrés puis stockés dans SQLite ; la désérialisation reconstruit un objet `Credential`.

`listSummaries()` traite les entrées une par une : déchiffrement temporaire, extraction des métadonnées et nettoyage du credential avant de poursuivre, sans vecteur intermédiaire de credentials complets. `get()` permet le chargement ciblé d'une entrée.

`add()` construit d'abord un candidat vide et arme son `CredentialWiper` avant l'affectation des champs. Une exception pendant une copie partielle déclenche ainsi le nettoyage de l'objet déjà construit. `update()` évite la copie complète entrante, authentifie l'ancienne entrée puis l'efface avant de chiffrer la nouvelle ; l'entrée appartenant à l'appelant n'est pas effacée. Les tests d'injection d'allocation et de panne SQL couvrent ces chemins. Le chantier ciblé de durcissement mémoire est terminé, sans prétendre effacer toutes les anciennes allocations C++/Qt/SQLite.

Les mutations gardent `BEGIN IMMEDIATE`, écriture puis `COMMIT`. L'ajout ne publie l'`EntryId` et la version qu'après commit réussi et état de fin confirmé. Les diagnostics sauvegardent le code primaire/étendu initial avant nettoyage et consultent `sqlite3_get_autocommit()` / `sqlite3_txn_state()` : annulation automatique avant commit, transaction active puis rollback confirmé, rollback échoué, état inconnu, ou absence de transaction après erreur de commit sont distingués. Autocommit actif après erreur ne prouve ni un rollback ni une réussite durable ; aucune reprise aveugle n'est tentée. Une erreur peut donc décrire une écriture déjà effectuée avec résultat non confirmé. Les diagnostics transactionnels n'incluent pas les valeurs des entrées ou le SQL lié.

`authenticateAll()` parcourt et authentifie toutes les entrées, une à une avec nettoyeur armé avant lecture, sans collection complète durable. Il est utilisé par le moteur de restauration existant. L'exclusion et le suivi persistant avant mutation sont décrits en section 5.11.

### 5.5 Interface graphique

Fichiers attestés : `src/gui/main_window.hpp` et `src/gui/main_window.cpp`, ainsi qu'une interface Qt Designer associée.

Fonctions présentes dans la version examinée : création/déverrouillage du coffre, affichage/filtrage, ajout, modification, suppression et verrouillage.

La version examinée comporte un timer d'inactivité, le nettoyage de champs de saisie, le nettoyage de la liste au verrouillage et un mécanisme d'effacement conditionnel du presse-papiers. Des fonctions utilitaires de nettoyage de `QString`, `std::string` et `Credential` sont présentes. Le timer est armé avant le rafraîchissement d'une session utilisable ; le réglage « Désactivé » reste respecté.

`MainWindow::lockVault()` invalide la génération Native Messaging et les transmissions encore détenues par l'application avant de détruire la clé. Les éditeurs nettoient immédiatement leurs champs et credentials temporaires avant leur rejet, sans dépendre de la fermeture d'une notification modale ; les nettoyeurs RAII restent une protection supplémentaire. Le nettoyage et l'acquittement externe restent sur le thread Qt propriétaire, avec protection contre les réentrances. Les événements logind et le coordinateur utilisent ce même verrouillage (section 5.9).

**Migration mémoire réalisée :** l'ancienne collection `MainWindow::credentials_` de credentials complets a été remplacée par des `CredentialSummary`. L'édition et la récupération native utilisent un chargement ciblé et temporaire ; les credentials locaux disposent de nettoyeurs RAII. Cela réduit l'exposition durable sans garantir l'effacement de toutes les copies créées par les chaînes, les dialogues ou Qt.

`createVault()` et `unlockVault()` arment les nettoyeurs du mot de passe maître avant remplissage. `takePassword()` limite les conversions, protège aussi les temporaires `QString`/UTF-8 et n'alloue pas volontairement dans les nettoyeurs de déroulement de pile ; seules les allocations Qt effectivement détachées sont effaçables sans copie supplémentaire. Les mots de passe locaux sont nettoyés avant les notifications ; erreur, mauvais mot de passe et exception ne publient pas de session. `addCredential()` nettoie son credential dès le retour du service, avant notification ou rafraîchissement, avec RAII conservé.

La fenêtre enregistre/reconnaît le coffre après authentification, raccorde les demandes automatiques après nettoyage du verrouillage, et fournit l'export manuel via `main_window_export.cpp` / `VaultExportDialog`. Il n'existe pas encore de GUI de restauration, de gestion des trois préférences de sauvegarde, de bouton de reprise ni d'export de configuration. `main_window_replacement.cpp` fournit uniquement l'entrée interne de préparation 6A, pas une action de restauration accessible à l'utilisateur.

### 5.6 Extension Firefox et pont natif

Le parcours de production effectivement utilisé est :

Firefox → Extension PassWall → `passwall_native_host` → `NativeBridgeServer` → `MainWindow::handleNativeRequest()` → `NativeRequestProcessor` → `NativeVaultAccess` → Coffre PassWall.

L'extension contient `popup` et `fill_script`. `popup.js` contacte l'hôte Native Messaging `org.passwall.native` ; `passwall_native_host` (`native_host.cpp`) communique avec `NativeBridgeServer` par socket Unix local. La réponse repart par le bridge et l'hôte vers l'extension.

`NativeRequestProcessor` constitue l'unique implémentation métier du traitement Native Messaging. `MainWindow::handleNativeRequest()` est l'adaptateur lié à l'interface ; il délègue le traitement au processeur, tandis que `MainWindow` implémente `NativeVaultAccess` pour fournir l'état de session, les résumés et le chargement ciblé d'une entrée. Le processeur est compilé par `passwall_app` et par la cible de tests.

Le popup revalide l'origine avant la récupération, et le script injecté la revalide avant de remplir les champs. Le mot de passe n'est récupéré qu'après la sélection d'un credential. `parseCanonicalEntryId()` exige exactement 32 caractères hexadécimaux minuscules pour les 16 octets ; le paramètre JSON doit être une chaîne. Le processeur vérifie origine et lease avant/après chargement et refuse les entrées disparues ou dont l'origine a changé. L'URL fournie par un client local n'est pas une preuve cryptographique du site visité ; les processus sous le même compte restent une hypothèse de confiance.

`NativeRequestResponse` possède un `SecureBuffer` non copiable, transféré par déplacement au bridge, sans `QByteArray` propriétaire ni second buffer `framed` contenant le secret. Le JSON sensible est construit avec contrôle UTF-8/échappement sans placer le mot de passe dans un `QString`/`QJsonValue`. La limite commune est de 1 048 576 octets JSON après échappement, hors préfixe de quatre octets. Le bridge envoie préfixe puis payload par segments d'au plus 64 Kio, contrôle la génération avant les écritures et annule les réponses anciennes lors du verrouillage. Des tests déterministes de cette invalidation existent au niveau composant ; ils ne prouvent pas tous les entrelacements réels avec Firefox. L'hôte protège également sa réponse par `SecureBuffer`, gère les écritures partielles/EINTR et SIGPIPE, et refuse le lancement automatique si `open()`/`dup2()` ne permettent pas une redirection correcte des flux. Les copies internes Qt/noyau restent hors d'un effacement exhaustif garanti.

Le fichier `firefox-extension/manifest.json` confirme l'identifiant `passwall-native-test@passwall.local` dans `browser_specific_settings.gecko.id`. Il s'agit de l'extension de test actuellement versionnée, nommée « PassWall - Test natif », utilisée temporairement pour la campagne manuelle. Cela ne constitue pas une validation du packaging ou de l'identifiant d'une future diffusion.

**Installation locale Linux, actualisée au 7 novembre 2026 :**

| Élément | Chemin installé |
|---|---|
| Application | `$HOME/.local/bin/passwall_app` |
| Native Host | `$HOME/.local/bin/passwall_native_host` |
| Manifeste Firefox | `$HOME/.mozilla/native-messaging-hosts/org.passwall.native.json` |

Le champ `path` du manifeste pointe vers `$HOME/.local/bin/passwall_native_host`. Les deux exécutables sont installés avec les permissions `0755` ; leurs empreintes SHA-256 ont été comparées et correspondent aux versions compilées et testées, selon les vérifications d'installation rapportées. Le Host retrouve `passwall_app` dans son propre répertoire. L'application a été actualisée pour exposer `Control1.Lock()` ; le Native Host, déjà identique au candidat récent, n'a pas été remplacé. Le manifeste Firefox est resté inchangé.

Cette installation est locale et manuelle. Le manifeste installé hors du dépôt ne doit pas être confondu avec un modèle versionné : le projet ne fournit toujours pas de procédure reproductible intégrée pour installer le Native Host et l'extension sur une nouvelle machine. Les essais réels sont détaillés en section 6.5.

### 5.7 SiteMatcher

`SiteMatcher` est implémenté et testé. Il accepte HTTP/HTTPS, compare schéma, hôte et port effectif, rejette les URL malformées et les informations d'utilisateur, et interprète une URL enregistrée sans schéma comme HTTPS. Les chemins et redirections ne participent pas à la comparaison d'origine.

### 5.8 Générateur de mots de passe

`PasswordGenerator` est implémenté sous forme d'en-tête, utilisé dans la boîte d'édition et testé. Il produit des mots de passe de 8 à 128 caractères avec `randombytes_uniform`, garantit la présence de chaque catégorie sélectionnée et mélange le résultat sans biais modulo.

### 5.9 Verrouillage de session Linux

Le parcours nominal configuré sur Raspberry Pi 5 / Debian 13 / labwc 0.20.2 est :

`Ctrl+Alt+L` ou `Ctrl+Super+L` → `$HOME/.local/bin/passwall-session-lock` → bus D-Bus utilisateur → `org.passwall.PassWall.Control1.Lock()` → `MainWindow::requestExternalLock()` → `lockVault()` → acquittement après nettoyage → tentative de `/usr/bin/swaylock -p`.

- `SessionLockService` expose `Lock() -> ()` sur le nom `org.passwall.PassWall`, chemin `/org/passwall/PassWall`. Il n'expose ni déverrouillage ni accès aux secrets. Une réponse positive sans argument acquitte le nettoyage applicatif vérifié ; une erreur ne l'acquitte pas.
- Le coordinateur utilise un auxiliaire D-Bus sans activation automatique de PassWall. Son budget d'attente D-Bus est de 1 500 ms, démarrage de l'auxiliaire compris, et non une garantie temps réel globale. À l'expiration, il demande l'arrêt de l'auxiliaire sans attendre sa terminaison avant la tentative de lancement du verrouilleur.
- PassWall absent, indisponible, refus ou délai expiré : le verrouillage de l'écran est tout de même tenté, sans annoncer un nettoyage du coffre confirmé. Le coordinateur déduplique ses invocations concurrentes par `flock`, sous réserve d'un répertoire d'exécution sûr ; les lancements directs de swaylock restent hors de cette coordination.
- `LinuxSessionMonitor` et son backend Qt DBus restent indépendants du coordinateur. L'inhibiteur `delay` de logind pour `sleep:shutdown` est conservé jusqu'à l'acquittement du nettoyage sur le thread propriétaire. Sa validité effective est contrôlée par `poll()`, notamment avant d'autoriser une nouvelle session. Une perte de protection refuse l'accès aux secrets ; la récupération ne déverrouille jamais le coffre automatiquement. Un thread bloqué, un événement manqué ou l'expiration du délai accordé par logind restent des limites.
- `LinuxInstanceLock` assure l'instance unique. `Control1.Lock()` est ponctuel : après son acquittement, une nouvelle authentification manuelle du coffre choisi est permise si les protections système et la porte de récupération de ce coffre l'autorisent. Il n'existe plus de `SessionGuard1`, de jeton de garde à libérer ni de registre de garde globale Wayland. Le registre local de préférences et les intentions de récupération par coffre sont des mécanismes distincts (sections 5.10 et 5.16).

Le coordinateur est installé dans `$HOME/.local/bin/passwall-session-lock`, mode `0755`, propriétaire. Le fichier utilisateur `$HOME/.config/labwc/rc.xml` définit `C-A-l` vers ce chemin et conserve `C-W-l` avec `onRelease="yes"`. Labwc est lancé avec `--merge-config` (`-m`) : les définitions utilisateur identiques remplacent les définitions système, actions comprises, sans lancer les deux commandes. Le fichier `/etc/xdg/labwc/rc.xml` conserve sa définition originale `C-A-l` vers `swaylock -p`, désormais surchargée, et n'a pas été modifié.

L'installation reste locale et manuelle. Aucun code de swaylock ou labwc n'a été modifié. Le verrouillage Wayland et son déverrouillage restent entièrement assurés par le système officiel, sans surveillance de leur état réel par PassWall.

La déduplication utilise un fichier régulier privé `0600` dans `XDG_RUNTIME_DIR` (répertoire appartenant à l'utilisateur, mode `0700`), jamais supprimé au fil des invocations. Chaque invocation demande le nettoyage de PassWall, même si un coordinateur est déjà actif ; elle ne lance pas un deuxième verrouilleur si l'autre reste actif. Si l'exclusion ne peut pas être établie, un avertissement est émis et l'écran reste prioritaire, sans garantie de déduplication. Un crash du coordinateur ou une daemonisation du verrouilleur peut aussi interrompre ce suivi. L'indication du raccourci dans `pishutdown` peut disparaître, sa recherche de la commande directe `swaylock -p` ne reconnaissant pas nécessairement le coordinateur ; ce point reste ergonomique et ne justifie pas de modifier le paquet système.

**Sauvegardes d'installation et retour arrière :** les relevés du 7 novembre situent les copies suivantes sous `$HOME/.local/share/passwall/backups/`, dans des répertoires privés `0700`, avec empreintes vérifiées lors des interventions :

1. `pre-linux-pilot-20261107T030441Z-d0_ttewl/` : ancienne application, Host de précaution, métadonnées, empreintes, manifeste et configurations labwc avant le pilote.
2. `labwc-pilot-shortcut-20261107T031234Z-IYlDvm6L/rc.xml` : configuration utilisateur avant ajout de `C-W-l`.
3. `labwc-ctrl-alt-l-20261107T185614+0100-umwOy0vK/rc.xml` : avant surcharge de `C-A-l`, avec `C-W-l` déjà présent ; SHA-256 `f4651e422e179b0aeb52f05f65922bf2a9296664c36a2ac894fa2a3350e38408`. `SHA256SUMS` et `original-metadata.txt` sont dans le même répertoire.

Pour revenir au seul raccourci habituel direct, sauvegarder d'abord la configuration courante et réconcilier les éventuels réglages ajoutés depuis. Le bloc suivant est une procédure de recours, non exécutée lors de cette mise à jour :

```sh
(
set -eu
passwall_backup="$HOME/.local/share/passwall/backups/labwc-ctrl-alt-l-20261107T185614+0100-umwOy0vK"
(cd "$passwall_backup" && sha256sum --check SHA256SUMS)
passwall_temp=$(mktemp "$HOME/.config/labwc/.rc.xml.retour.XXXXXX")
cp --preserve=all "$passwall_backup/rc.xml" "$passwall_temp"
mv -fT "$passwall_temp" "$HOME/.config/labwc/rc.xml"
/usr/bin/labwc --reconfigure
)
```

`Ctrl+Alt+L` retrouve alors l'action système directe, sans acquittement PassWall ; `Ctrl+Super+L` conserve le coordinateur. La deuxième sauvegarde permet aussi de retirer le pilote, avec les mêmes précautions. Un retour d'exécutables exige l'arrêt normal des processus, la vérification des empreintes/permissions et de la compatibilité application/Host. L'ancienne application ne possède pas `Control1.Lock()` : adapter les raccourcis si elle est restaurée. Le Host étant resté identique, son remplacement n'est pas nécessaire. Ne supprimer aucune sauvegarde ni restaurer de fichier système pour ce retour arrière. Ces copies ne sont pas des sauvegardes de coffres SQLite.

Les chemins et validations d'installation ci-dessus sont des relevés historiques, pas une vérification des empreintes installées au 9 novembre. Les nouvelles fonctions de sauvegarde/restauration présentes dans les sources ne sont pas, pour autant, attestées dans les exécutables de `~/.local/bin`. Le futur déploiement doit aussi fournir l'auxiliaire de sauvegarde à côté de l'application.

### 5.10 Registre local et préférences — étape 1

`VaultPreferencesStore` utilise le fichier de `QSettings("PassWall", "PassWall").fileName()`, clé `vaultRegistry/data` contenant un registre JSON version 1. Ce fichier global conserve aussi les autres réglages de l'application. Il ne contient ni mot de passe maître, ni clé, ni credential déchiffré ; les chemins et métadonnées qu'il contient restent privés.

Chaque `VaultRegistration` possède un UUID local indépendant du `vault_id` cryptographique. L'identification combine chemin, périphérique/inode et date de naissance lorsque disponible, avec lecture du `vault_id`. Les liens et identités ambiguës sont refusés. Une copie distincte ne reçoit pas les préférences ni les autorisations locales de sauvegarde du principal : elle peut obtenir un nouvel enregistrement par défaut lorsque l'original est identifiable ; un déplacement, remplacement inattendu ou original manquant peut imposer une réassociation explicite. Ni `vault_id` ni l'identité physique ne constituent seuls une preuve cryptographique ou une continuité garantie après toutes les copies/déplacements. Ce sont des contrôles de gestion locale, pas des autorisations d'appareil.

Les trois préférences sont `automatic=false`, `directory` vide et `retainedVersions=7`. La GUI tente l'enregistrement après création/ouverture authentifiée ; création du coffre et publication du registre ne sont pas une transaction unique. Les appels directs au cycle de vie n'enregistrent pas automatiquement un coffre. Un échec tardif d'enregistrement ne doit donc pas être présenté comme une preuve que le fichier de coffre n'a pas été créé.

Les mises à jour contrôlent les octets réellement présents, la structure du registre, l'identité attendue et la concurrence par un verrou de registre non bloquant. La synchronisation atomique QSettings est suivie de contrôles de permissions et de `fsync` du fichier/répertoire : parent privé `0700`, fichier `0600` sous Unix. Une configuration corrompue n'est pas réinitialisée silencieusement. Une erreur après publication peut laisser une modification visible sans durabilité confirmée.

Un incident ordinaire d'association, avec registre lisible sans intention de restauration, peut laisser une session authentifiée utilisable avec avertissement non modal. Depuis 6A, un registre illisible/ambigu ne permet pas d'écarter une récupération en cours et refuse les accès concernés (section 5.16). La GUI de préférences, la réassociation utilisateur, l'export global sans écrasement et l'import restent respectivement à développer ou, pour l'import, à définir.

**Portabilité vérifiée par lecture du code :**

| Niveau | Comportement présent |
|---|---|
| Ouverture cryptographique | `VaultLifecycleService::unlockVault()` lit les métadonnées puis appelle `VaultKeyService::unlock()` ; la dérivation/désencapsulation utilise mot de passe, sel, paramètres et AAD du coffre, sans identité de machine ni clé QSettings |
| Registre absent sur l'installation destinataire | `readRegistryOnDisk()` accepte l'absence du fichier ; `accessRegistry()` part d'un registre vide et `recoveryAccess()` autorise le fichier non enregistré si la configuration locale est accessible/sûre et aucun autre contrôle ne le refuse |
| Enregistrement après ouverture GUI | `registerAuthenticatedVault()` appelle `recognizeOrRegister()` après authentification ; dans un registre neuf, nouvel UUID local et préférences désactivé/dossier vide/sept versions, sans héritage de la source |
| Sécurité et ambiguïtés locales | Registre occupé, illisible ou corrompu : accès refusé faute d'état fiable ; intention 6A correspondant au chemin/inode : récupération requise. Une association ordinaire ambiguë est distincte d'un échec cryptographique et n'applique pas de préférences non confirmées |

Aucune incompatibilité liée à la seule absence du registre d'origine n'a été identifiée dans ces chemins. Des tests existants couvrent registre absent, copies à préférences indépendantes et refus de récupération (`test_vault_preferences_store.cpp`, `test_vault_preferences_gui.cpp`, `test_vault_replacement.cpp`). Ils ne constituent pas un essai complet de transfert entre deux machines ; ce contrôle ciblé n'a exécuté aucun test. Supprimer un registre local contenant une intention 6A ou déplacer ses artefacts n'est pas une procédure de portabilité/récupération : cette information locale ne voyage pas automatiquement dans la copie et son absence ne prouve pas qu'une restauration d'origine était terminée.

### 5.11 Exclusion métier et suivi persistant — étapes 2 et 3

`VaultOperationGuard` utilise des `flock` coopératifs Linux : accès partagés conservés pendant toute la connexion métier, réservations exclusives non bloquantes pour les copies et opérations incompatibles. Deux identités sont protégées : répertoire parent + nom, et périphérique/inode du fichier. Cela couvre les alias physiques et conserve la réservation du nom lors d'un remplacement. Les fichiers de verrouillage privés sous `/tmp/.passwall-vault-operations-UID` ne sont pas supprimés au fil des opérations, pour éviter des espaces de verrouillage divergents.

Les connexions de `VaultStorage`, `CredentialService` et les opérations de cycle de vie utilisent ces protections. Les descripteurs exclusifs sont transmis explicitement à l'auxiliaire, validés et conservés jusqu'à sa terminaison effective, même si son résultat est déjà `Unknown` ou si sa façade Qt a disparu. Une session déverrouillée de `MainWindow` ne conserve pas de garde partagé permanent : une réservation ne prouve donc pas l'effacement de la clé ; l'autorisation 6A traite précisément ce point.

Avant le premier accès SQLite d'une mutation, `prepareMutation()` vérifie l'identité locale et persiste `backupRequired=true` si l'automatique est activé. Si cette persistance/durabilité échoue, le CRUD est refusé avant SQL. Le marqueur peut rester vrai après rollback ou exception : ce faux positif conservateur est accepté. Seule une sauvegarde confirmée peut le lever. Registre et SQLite ne partagent pas de transaction ; aucun événement GUI seul ne sert de preuve de modification sauvegardée.

Cette exclusion n'est pas un verrou système imposé aux programmes tiers : elle suppose des participants coopératifs, le même espace `/tmp` et l'absence de suppression administrative de ses fichiers. Elle ne protège pas contre tous les processus malveillants du même UID, ni contre des espaces de montage isolés. Le support interprocessus hors Linux n'est pas validé.

### 5.12 Moteur d'instantané SQLite

`VaultSnapshotService::createSnapshot()` est un moteur synchrone sans clé. Il utilise l'API SQLite backup pour produire une copie cohérente des octets chiffrés, vérifie la structure, travaille dans un staging privé puis publie sans écrasement par `linkat`, après synchronisation du fichier. La synchronisation du répertoire confirme ensuite la durabilité demandée ; une erreur après le lien ne supprime jamais le fichier final. Une source nécessitant une récupération en écriture est refusée, sans ouverture de secours en lecture-écriture et sans `immutable=1`.

Le moteur n'authentifie pas cryptographiquement les entrées par lui-même ; un hook interne de vérification de la copie privée est utilisé par la restauration. Les protections de chemins, permissions et identité sont maintenues au-delà des vérifications préalables.

`createSnapshot()` conserve la porte de récupération, même avec une réservation exclusive fournie. L'exception préparée pour une copie de précaution est uniquement `VaultReplacementAuthorization::snapshotPrincipal()` (section 5.16) : elle ne transforme pas une réservation ordinaire en autorisation de restauration.

Il n'existe plus de budget global de cinq secondes : une copie saine peut continuer et redémarrer selon SQLite sans plafond arbitraire. Trois résultats consécutifs `BUSY`/`LOCKED` arrêtent une tentative ; une progression `SQLITE_OK` remet ce compteur à zéro. Le timeout SQLite V1 reste distinct. L'annulation coopérative est contrôlée entre étapes et immédiatement avant publication ; une publication déjà engagée peut gagner la course et ne doit pas être rétractée.

Les destinations admises sont locales et explicitement limitées : ext2/3/4, tmpfs, XFS, Btrfs, F2FS et overlayfs, avec support effectif de lien/synchronisation contrôlé. Les chemins ambigus, liens symboliques, destinations existantes et répertoires non sûrs sont refusés. NAS, systèmes réseau, FAT/exFAT et dossiers synchronisés ne constituent pas des supports validés ; aucune destination de repli n'est créée. Les appels système bloqués ne sont pas bornés par un timeout global.

### 5.13 Auxiliaire de sauvegarde et pilotage asynchrone

`passwall_backup_worker` et `BackupJob` séparent copie/rotation du thread GUI. L'auxiliaire est recherché par chemin explicite à côté de l'application, jamais dans `PATH`. Il ne reçoit aucune clé de déchiffrement. Le protocole privé de sauvegarde est un JSON versionné délimité par ligne, distinct du framing Native Messaging ; il transporte chemins, contexte et résultats bornés, pas des secrets.

Les résultats distinguent réussite publiée, échec avant publication, durabilité non confirmée, annulation confirmée avant publication et `Unknown`. Un enregistrement terminal valide et une terminaison normale sont nécessaires après lancement : une sortie de processus seule ne vaut pas réussite. `copyConfirmed`, `finished` et `processTerminated` ont des sens différents ; une erreur de rotation ne transforme pas une copie confirmée en échec de copie.

Après demande d'annulation, les délais d'escalade sont de 1 s coopérative, puis 1 s après SIGTERM, puis 1 s avant signalement d'arrêt non confirmé après SIGKILL. Ce ne sont ni des limites de durée de sauvegarde, ni une promesse qu'un enfant bloqué dans le noyau termine immédiatement. Un superviseur indépendant évite de détruire un `QProcess` actif et d'attendre dans son destructeur ; il conserve les réservations jusqu'à terminaison réelle. Fermeture du canal parent, signal de mort du parent et fermeture de l'application demandent l'arrêt, sans effacer une publication finale. Un arrêt forcé peut laisser du staging privé. Le processus auxiliaire n'est pas un sandbox complet.

### 5.14 Export manuel et sauvegardes automatiques — étape 4

L'export Qt (`main_window_export.cpp`, `VaultExportDialog`) est implémenté : sélection/confirmation autorisées par le lease initial, refus d'un éditeur ouvert, véritable acquittement de nettoyage avant lancement, affichage modeless du progrès/résultat et annulation. Les boucles modales de sélection ne permettent pas de réutiliser une ancienne session. Le coffre reste verrouillé ; le résultat ne sélectionne ni n'ouvre automatiquement un autre coffre.

`AutomaticBackupCoordinator`, sans clé, est raccordé à `MainWindow`. Il traite l'activation des préférences, les demandes après verrouillage et la reprise explicite. Les contrôles de destination n'inventent pas de diagnostic : une erreur identifiable est expliquée, sinon le message reste générique. Un échec arme une suspension persistante et ne notifie pas à chaque nouvelle mutation. La reprise crée une nouvelle copie de l'état courant, sans conserver d'instantané ni de transfert à reprendre.

Un accès occupé ou un éditeur fait différer la demande, sans jeter une saisie ni suspendre les sauvegardes pour une fausse panne. Les traitements sont reportés hors de la pile critique du verrouillage/acquittement. Les transitions système, l'export et la fermeture suspendent le dispatch approprié ; le nettoyage de sécurité demeure prioritaire. Une intention de restauration fait différer la demande sans armer de nouvelle tentative ou rotation, sans modifier sa suspension ; un prochain verrouillage normal ou une reprise explicite pourra redemander une copie.

**Limite produit :** le moteur, ses API et son raccordement sont présents ; les réglages par coffre et le bouton « Reprendre la sauvegarde » ne sont pas encore proposés dans la GUI. L'export manuel, lui, possède un parcours utilisateur testé et des essais Wayland rapportés.

### 5.15 Catalogue et rotation sécurisée — étape 5

Le catalogue est conservé dans le même registre QSettings : opération, chemin, ordre de publication, génération de destination, durabilité et preuves du fichier chiffré. La rétention par défaut porte sur sept versions, pas sept jours. Un changement de dossier crée une nouvelle génération de destination ; revenir vers un ancien dossier ne réautorise pas silencieusement la suppression de ses anciennes versions.

L'auxiliaire réalise la rotation après copie et association au catalogue confirmées, sous réservation continue du principal. `BackupRotationService` vérifie aussi la nouvelle copie, réserve les candidats et contrôle identités, répertoire/support, dates disponibles et SHA-256 des octets chiffrés avant suppression. Un nom ressemblant à une sauvegarde ne suffit jamais. Exports manuels, fichiers inconnus, versions anciennes sans preuves suffisantes, fichiers modifiés, liens et fichiers enregistrés comme principaux restent protégés. Des preuves de naissance/montage manquantes interdisent la suppression automatique plutôt que d'être inventées.

Une intention persistante de rotation `prepared`/`running`, avec candidat de suppression, empêche de rejouer aveuglément une suppression après résultat inconnu. Échec de suppression, de synchronisation ou de catalogue conserve les preuves et ne provoque pas de suppression compensatrice d'autres fichiers. Une rotation échouée ne réarme pas à elle seule `backupRequired` et ne suspend pas une copie déjà réussie. Elle peut rester bloquée sans outil de résolution utilisateur actuel.

Les preuves et empreintes ne sont pas des MAC ni une défense absolue contre un processus malveillant du même UID. La vérification finale du nom et `unlinkat` restent deux appels distincts. L'annulation est coopérative : sa demande n'acquitte ni sa réception ni l'arrêt des suppressions. Le diagnostic et les deux ordres déterministes de régression sont détaillés en section 6.3 ; le moteur et le protocole de production sont inchangés.

### 5.16 Restauration existante et remplacement — étapes 6A, 6A-bis et 6B

**Moteur existant implémenté et testé :** `VaultRestoreService::restoreBackup()` restaure vers une destination nouvelle et inexistante. Il vérifie la structure, authentifie le mot de passe de la sauvegarde puis toutes les entrées via `CredentialService::authenticateAll()`, et détruit la DEK et les credentials temporaires avant publication. Il ne renvoie ni clé ni session, préserve les octets chiffrés/liaisons AEAD et n'hérite pas des préférences du principal. Son `std::span` de mot de passe reste emprunté : le propriétaire appelant doit préserver et nettoyer ce buffer, qui n'est pas effacé par le moteur. Une sauvegarde authentique ne prouve pas sa fraîcheur ou son exhaustivité historique.

Ce moteur n'est pas la nouvelle fonction V1 de remplacement et n'est pas raccordé à une GUI. Il n'effectue ni écrasement ni fusion. Son API reste disponible, distincte du nouveau moteur.

**Fondations 6A conservées par le moteur 6B :** `VaultReplacementAuthorization` est une autorisation opaque, non copiable, déplaçable, non reconstructible depuis un booléen ou un UUID. Elle lie identifiant local, identité initiale, opération et réservation exclusive. Seul `MainWindow::requestReplacementAuthorization()` l'émet en production, sur le thread propriétaire, après son vrai acquittement de nettoyage. L'émetteur simulé n'est compilé que dans `passwall_replacement_tests`.

La fenêtre barre les nouvelles ouvertures pendant la transition, refuse les opérations incompatibles/éditeurs sans attendre leur fermeture et réserve le principal avant son verrouillage. Le verrouillage volontaire de préparation se distingue d'un verrouillage de sécurité, qui révoque l'autorisation, même réentrant. Les inspections SQLite et l'empreinte sont réalisées après nettoyage. La validité du nettoyage, de la protection Linux et des réservations est recontrôlée ; aucune session ancienne n'est restaurée. Une réservation exclusive seule n'est jamais assimilée à une preuve d'effacement.

Une intention versionnée dans le registre contient opération, identité précédente/empreinte, candidat éventuel et références de récupération, sans secret. Sa persistance doit réussir avant publication. Les chemins privés assurent la finalisation sous réservation du nom et de l'inode candidat, sans affaiblir `matchesReservation()` des sauvegardes. En 6B, `candidateDigest` lie les octets chiffrés intégralement authentifiés au candidat et à la reprise. Les anciens contrats sans cette empreinte restent lisibles, mais leur état `armed` n'autorise pas la nouvelle reprise spécialisée. Une empreinte n'est pas une authentification : celle-ci précède son enregistrement par le moteur vivant.

**Durcissement 6A-bis :** l'ancien chemin supprimait l'intention avant la confirmation de durabilité du registre. Une publication QSettings suivie d'une erreur d'ouverture/`fsync` pouvait donc retourner un échec tout en laissant disparaître la porte de récupération. La finalisation comporte désormais deux écritures distinctes, sérialisées par le verrou du registre et sous réservation continue du coffre :

| État observable | Informations conservées et accès |
|---|---|
| `replacement.phase=prepared` | Identité/empreinte initiales ; nettoyage acquitté ; aucune substitution autorisée ; accès ordinaires bloqués |
| `replacement.phase=armed` | Candidat et références conservés ; une substitution future pourrait avoir eu lieu ; accès bloqués, jamais de déduction depuis un fichier absent |
| `replacement.phase=identity-confirmed` | Nouvelle identité dans l'enregistrement et dans `confirmed`, ancienne identité/empreinte et références toujours présentes ; accès **encore bloqués**, même si cette écriture est visible |
| `resolvedReplacement.phase=resolved` | Reçu de la dernière opération, nouvelle identité et références conservées ; l'intention active est retirée seulement après confirmation durable de l'écriture protégée précédente ; accès au principal conditionné à l'identité physique attendue |

La première écriture enregistre la nouvelle identité **sans lever la protection**, puis vérifie permissions et `fsync` du fichier QSettings et de son répertoire. La résolution n'est tentée qu'après son succès. Sa propre publication peut aussi échouer à la confirmation : l'ancien état possible reste `identity-confirmed` et bloqué ; le nouveau reçu visible repose déjà sur une identité durablement établie. Il n'existe donc pas de suppression finale d'un marqueur indispensable dont on supposerait implicitement la durabilité. Un seul reçu résolu est conservé par coffre dans le registre existant ; une nouvelle préparation autorisée peut le remplacer. Aucun fichier de récupération n'est supprimé. La visibilité (`published`) n'est pas une preuve de durabilité ; `RegistryPersistence` distingue absence de tentative, tentative non confirmée et confirmation durable. Le comportement des autres mises à jour de préférences/sauvegardes n'est pas transformé en un nouveau gestionnaire transactionnel.

Préférences, catalogue, suspensions et états de rotation sont conservés. La règle existante reste inchangée : la résolution positionne `backupRequired=true` si l'automatique est activé, sans effacer un état déjà vrai ; lorsqu'il est désactivé, cet état n'est pas modifié. Aucune sauvegarde ou rotation n'est déclenchée par la finalisation.

Le contrat privé `finalizePublication()` retourne `ReplacementFinalizationResult`, pas un booléen ambigu : `NotStarted`, `RecoveryRequired`, `IdentityUnconfirmed`, `IdentityConfirmedResolutionPending`, `SafeResolutionUnconfirmed` ou `Resolved`. Seul `Resolved` confirme complètement la résolution. `SafeResolutionUnconfirmed` ne signifie ni remplacement annulé ni réussite complète : une variante encore bloquée ou un reçu sûr peut être observable. L'identité finale doit correspondre au candidat ; l'ancien inode doit être retrouvé au nom technique du candidat, avec métadonnées/empreinte initiales intactes. Les fichiers et répertoires concernés sont synchronisés avant confirmation du registre. La réservation reste détenue pendant ces vérifications et écritures ; l'erreur laisse une preuve persistante, pas seulement un verrou en mémoire.

`VaultReplacementAuthorization::resumeFinalization(store, localId, operationId)` prépare une reprise spécialisée après interruption. Elle n'émet aucune autorisation, ne substitue aucun fichier et ne déverrouille rien. Elle refuse `prepared`, `armed`, un autre UUID, les identités ambiguës, un principal inattendu et, pour `identity-confirmed`, l'absence ou l'altération de l'ancien artefact. Elle réserve principal et ancien artefact, vérifie les identités et l'empreinte, reconfirme la durabilité protégée puis résout. Un reçu `resolved` du même UUID peut être reconfirmé de manière idempotente, sans nouvelle substitution. La porte refuse aussi les anciens artefacts techniques et un reçu ne correspondant plus au principal physique ; elle n'impose pas une empreinte immuable au principal après résolution, pour préserver les CRUD légitimes.

**Lecture exceptionnelle limitée :** `snapshotPrincipal(destination, result, cancellation)` ne reçoit aucun chemin source ni booléen de contournement. Elle exige une autorisation vivante liée au même principal, à sa réservation, à son intention et à la phase `prepared`. Identité et empreinte de l'ancien principal sont vérifiées au début et avant publication ; l'autorisation est revalidée aux points de contrôle de copie/validation/publication, notamment après les callbacks d'annulation. Le moteur partage l'implémentation SQLite/staging/publication existante, sans garde partagé incompatible sur la source. Un maintien local de l'état évite une référence pendante si le callback révoque l'autorisation. Une réservation seule, un ancien UUID, la phase `armed` ou une révocation ne permettent pas cette lecture. CRUD, export et sauvegarde ordinaire conservent leurs portes habituelles. Le moteur 6B utilise ce chemin avant armement pour la copie de précaution obligatoire.

La porte de récupération est appliquée aux services, pas seulement aux boutons : reconnaissance, cycle de vie, CRUD, ouvertures SQLite/instantanés et accès natifs concernés sont refusés si une intention l'exige ou si le registre n'est pas interprétable. Un autre coffre indépendant reste utilisable lorsque le registre le permet. Aucune réassociation ou authentification ne lève implicitement cette porte. L'abandon par l'autorisation vivante n'est permis qu'avant engagement, après vérification de l'identité et de l'empreinte initiales ; destruction de l'autorisation ou absence du candidat ne suffit jamais à lever une intention ambiguë. Aucun rollback destructeur ni nettoyage automatique des artefacts de récupération n'est implémenté.

Il s'agit d'une protection de récupération **par coffre**, pas du retour de `SessionGuard1` ni d'une garde globale de session Wayland. La suppression externe du registre ne peut pas être distinguée dans tous les cas d'une première configuration absente ; les protections restent conditionnées à sa conservation et aux participants coopératifs. Les confirmations `fsync` ne constituent ni une simulation de panne électrique ni une garantie physique absolue du support. Les transitions d'identité des tests historiques 6A-bis sont modélisées ; les nouveaux tests 6B exercent réellement la substitution et des interruptions de processus sur fichiers fictifs.

**Moteur 6B :** `VaultReplacementAuthorization::replacePrincipal(principal, source, SecureBuffer, precautionDestination, result, control)`, implémenté dans `vault_replacement_service.cpp`, exige l'autorisation existante et le chemin exact auquel elle est liée. Il n'ajoute ni émetteur ni booléen de preuve. Les trois chemins sont figés dans des copies locales avant tout callback de contrôle : modifier l'état Qt de l'appelant ne peut pas rediriger la substitution. Le mot de passe est transféré par déplacement, sans copie supplémentaire. L'ancienne API `VaultRestoreService::restoreBackup()` reste inchangée. La bibliothèque `passwall_vault_replacement` reste séparée du worker de sauvegarde sans clé.

1. Ouvrir la source sans suivre de lien, refuser alias physiques/liens durs et chemins ambigus ; retenir descripteur, identité du parent, taille, dates de modification/changement et empreinte. Les contrôles de stabilité entourent la copie et l'authentification ; une mutation détectable interdit la substitution.
2. Réutiliser l'instantané SQLite avec validation structurelle et un hook privé : même `vault_id`, mot de passe, paramètres bornés, déchiffrement de la DEK et `authenticateAll()` entrée par entrée. Mot de passe propriétaire, DEK et credentials temporaires sont nettoyés avant publication du candidat privé, a fortiori avant échange. Les anciennes allocations Qt/C++/SQLite n'ont pas de garantie exhaustive d'effacement.
3. Automatique désactivé : exiger une destination explicite inexistante, sans alias du principal/source ; créer la copie supplémentaire via `snapshotPrincipal()` pendant `prepared`. Seul `SnapshotPublication::Published` permet de poursuivre ; une copie publiée à durabilité non confirmée est conservée mais insuffisante. Cette copie n'entre pas au catalogue. Automatique activé : aucune copie supplémentaire, sauvegarde récente ou disponibilité du dossier habituel n'est imposée.
4. Préparer le candidat chiffré `répertoire-du-principal/.passwall-restore-UUID/candidate.db` (dossier 0700, fichier 0600, même système de fichiers local pris en charge). Vérifier son empreinte authentifiée, synchroniser fichier et répertoires, enregistrer candidat/empreinte/références puis `armed` durablement. Ne jamais revenir à `prepared`.
5. Revalider autorisation, identités, contenus et répertoires ; effectuer `renameat2(..., RENAME_EXCHANGE)` ([contrat Linux de l'échange atomique](https://man7.org/linux/man-pages/man2/rename.2.html)). Le chemin du principal reçoit le candidat complet et **l'ancien inode reste à `candidate.db`**. Aucun effacement préalable, copie en place, fenêtre volontaire d'absence ou rollback supposé. Si l'échange est indisponible, refuser sans repli non atomique. Les réservations du nom et des deux inodes restent détenues.
6. Enregistrer immédiatement le fait de substitution, synchroniser les deux répertoires puis utiliser la finalisation 6A-bis : nouvelle identité, ancien inode/empreinte et empreinte du candidat vérifiés, fichiers/répertoires synchronisés, écriture protégée `identity-confirmed`, puis reçu `resolvedReplacement`. Préférences, identifiant local, catalogue, suspensions et états de rotation restent conservés ; `backupRequired` est positionné si automatique activé, sans copie/rotation immédiate ni ouverture de session.

`ReplacementOutcome` distingue `NotReplaced`, `CancelledBeforeEngagement`, `EngagedRecoveryRequired`, `ReplacedDurabilityUnconfirmed`, `ReplacedFinalizationPending` et `Replaced`, en conservant le résultat détaillé de finalisation et celui de précaution. Seul `Replaced` confirme complètement l'opération. Une annulation avant armement ne supprime pas implicitement l'intention ; tant que l'autorisation reste valide, l'appelant peut demander `abandonPreparation()` avec preuves initiales intactes. Après tentative d'armement, l'autorisation est consommée et une annulation/erreur laisse les éléments persistants ; aucune annulation tardive ne prétend défaire un échange. Pas de délai global ni suppression d'une copie déjà publiée.

**Reprise contrôlée 6B :** `recoverReplacement(store, localId, operationId, Inspect|FinalizeExchanged)` n'émet aucune autorisation et ne fait jamais de substitution. Elle acquiert de nouvelles réservations et compare identités/empreintes des fichiers réellement présents avec l'intention. `prepared` intact est inspectable mais non libéré automatiquement ; `armed` avant échange reste bloqué, sans seconde substitution ; `armed` après échange n'est finalisable qu'avec le candidat authentifié au nom principal et l'ancien contenu exact au nom technique. Les identités déjà confirmées/reçus résolus utilisent la reprise 6A-bis. Fichier absent, empreinte/identité inattendue, UUID obsolète ou registre illisible conservent le blocage. Aucun nettoyage automatique de l'ancien inode n'est proposé ; il reste conservé avec ses références même après réussite. Un crash avant enregistrement du candidat peut laisser un dossier privé orphelin, jamais interprété comme une autorisation ni supprimé à l'aveugle.

**Frontière des étapes :** 6B est synchrone et indépendant des widgets, sans boucle événementielle ni action utilisateur. Le contrat de thread propriétaire de l'autorisation reste applicable ; ce moteur ne doit pas être branché directement sur la GUI pour de longues E/S, ni déplacé arbitrairement sur un autre thread. L'étape 7 devra définir une délégation interprocessus limitée, sans transformer cette autorisation non sérialisable en jeton fabricable, puis `passwall_restore_worker`, canal privé du mot de passe, supervision/annulation/fermeture et articulation avec les acquittements de nettoyage. L'étape 8 garde les interfaces et la récupération utilisateur, notamment la résolution des préparations interrompues. Aucun worker de restauration ni GUI n'est disponible.

## 6. État des réalisations

### 6.1 Développement attesté

- projet C++ configuré avec CMake/Ninja ;
- environnement Qt 6 et libsodium installé ;
- moteur cryptographique et `SecureBuffer` ;
- stockage SQLite ;
- services de gestion de clé et cycle de vie ;
- `CredentialService` ;
- modèles `Credential` et `CredentialSummary`, avec `CredentialService::listSummaries()` ;
- interface Qt ;
- extension Firefox et scripts de remplissage ;
- hôte natif / communication extension, avec `NativeRequestProcessor` comme unique traitement métier ;
- nettoyage immédiat des éditeurs, armement précoce du timer, protection logind, instance unique, `Control1.Lock()` acquitté et coordinateur Linux installé ;
- `SiteMatcher` ;
- générateur de mots de passe, intégré à l'interface ;
- validation commune des trois champs obligatoires et durcissement mémoire ciblé de création/ouverture et CRUD ;
- configuration SQLite V1 vérifiée, RAII des ressources et diagnostics transactionnels ;
- registre local, exclusion métier, suivi persistant, sauvegardes par auxiliaire, export Qt, coordination automatique et rotation ;
- moteur de restauration authentifiée vers un nouveau fichier et moteur synchrone 6B de remplacement récupérable, sans worker ni GUI de restauration ;
- tests C++ et JavaScript.

### 6.2 Résultats de tests communiqués

Jalons historiques rapportés :

- 5 tests initiaux réussis (initialisation/libsodium, versions libsodium/SQLite, XChaCha20) ;
- jalon antérieur : 60/60 tests C++ et 5/5 tests JavaScript ;
- jalon du 5 novembre 2026 : 69/69 tests réussis après correction d'une erreur de syntaxe dans `crypto_engine.cpp`.

Un journal CTest antérieurement consulté enregistrait 69/69 tests C++ réussis le 5 novembre 2026 à 15:20 CET. Il s'agit d'une observation historique, pas d'une nouvelle vérification du journal ni du nombre actuel de tests.

**Validations automatisées ciblées rapportées pour l'état du 6 novembre 2026 :**

| Suite ou cible | Résultat rapporté | Périmètre |
|---|---|---|
| `EntryIdParserTest` | 9/9 | Conversion canonique des identifiants |
| `NativeRequestProcessorTest` | 27/27 | Traitement métier commun à l'application et aux tests |
| `NativeRequestResponseTest` | 1/1 | API et propriété du buffer de réponse |
| `SiteMatcherTest` | 12/12 | Correspondance des origines |
| `NativeBridgeServerTest` | 21/21 | Transport avec sockets Unix réels dans l'environnement Debian habituel |
| `passwall_native_host_tests` | 6/6 | Notamment les échecs de redirection des flux au démarrage automatique |

Ces résultats concernent les suites ciblées indiquées, pas une nouvelle exécution complète de tous les tests du projet. Ils sont distincts des observations manuelles avec Firefox (section 6.5). Les échecs historiques `EPERM` lors de `bind(AF_UNIX)` dans le sandbox restreint ne décrivent pas ces exécutions Debian avec sockets réels et ne doivent pas être contournés par une désactivation des tests.

**Validations automatisées du verrouillage Linux rapportées avant l'installation locale :**

| Suite ou cible | Résultat rapporté | Périmètre |
|---|---|---|
| `passwall_session_lock_tests` / `SessionLockCoordinatorTest` | 21/21 | Bus privé et faux verrouilleur : ordre de l'acquittement, absence/refus/délai, réponses tardives, concurrence et erreurs de lancement |
| `SessionLockServiceTest` | 10/10 | Acquittement après nettoyage, paramètres, pertes du bus et rejet de l'ancienne interface de garde |

Les protections internes disposent aussi de tests GUI dans `passwall_gui_tests` : éditeurs, minuteur d'inactivité, invalidation des générations natives et intégration à `MainWindow`. Les tests de `LinuxSessionMonitor`, du backend logind et de l'instance unique utilisent des abstractions simulées, des bus D-Bus privés et des descripteurs réels de test ; ils ne réalisent aucune transition système réelle. Leurs régressions ciblées ont été rapportées comme réussies pendant le développement. Le jalon antérieur de campagne complète 225/225 précède les évolutions ultérieures de l'instance unique, du service de contrôle et du coordinateur : ce n'est pas un décompte de la suite actuelle. Le test isolé de handshake D-Bus bloqué a de nouveau réussi lors de la préparation de l'installation, avec un faux verrouilleur.

**Validations ultérieures rapportées, non additionnables comme une campagne unique :** durcissement des mots de passe maîtres 46 tests ciblés ; champs obligatoires 70 ; RAII stockage 44 ; politique SQLite V1 56 ; export manuel 139 et six vérifications manuelles Wayland ; moteur de restauration existant 153 ; registre local (étape 1) 115 ; exclusion métier (étape 2) 356 ; jalon avant 6A 382. Ces nombres décrivent des sélections de régressions à différents états, pas les seuls tests nouveaux d'un composant. Les sources et cas de test correspondants sont présents ; leur lecture ne reproduit pas ces exécutions.

**Bilan ciblé 6A historique rapporté : 426 cas distincts validés, dont 44 nouveaux**, avec une réserve d'intermittence alors ouverte, traitée ensuite en section 6.3. Répartition de ce jalon, à ne pas confondre avec la nouvelle campagne :

| Cible / périmètre | Résultat rapporté |
|---|---|
| `passwall_replacement_tests` — contrats simulés d'autorisation/registre | 32/32 |
| `passwall_gui_tests` — sélection éditeurs, mots de passe, timer, préférences, export et autorisation réelle | 123 cas distincts validés : passage de 122 puis 11 tests finaux dont 10 communs |
| `passwall_automatic_backup_tests` — passage historique 6A | 65/65, sans résolution de l'intermittence à ce jalon |
| `passwall_preferences_tests` | 27/27 |
| `passwall_dirty_tracking_tests` | 29/29 |
| `passwall_storage_tests` | 24/24 |
| `passwall_snapshot_tests` | 19/19 |
| `passwall_restore_tests` | 23/23 |
| `passwall_backup_tests` | 23/23 |
| `passwall_tests` — sélection stockage, cycle de vie, CRUD, mémoire, transactions et gardes | 61/61 |

Les tests 6A de contrats ne prouvent pas un nettoyage réel s'ils simulent l'acquittement ; les tests GUI exercent séparément l'émetteur et le verrouillage réels avec données fictives. Les simulations d'identité finale ne sont pas des tests de remplacement atomique. `VaultOperationGuard`, les défauts SQLite réels (`FULL`, contention), les fautes injectées (`IOERR`, allocation, commit/rollback) et les arrêts de processus sur fichiers isolés disposent de tests distincts. Une injection n'est pas une panne matérielle réelle.

Les seules actualisations documentaires jusqu'à la version 1.6 n'ont exécuté aucun test ni compilation. L'intervention suivante de stabilisation a reconfiguré le répertoire `/tmp/passwall-credential-summary-verification` absent, puis compilé uniquement `passwall_automatic_backup_tests`, `passwall_backup_tests` et `passwall_tests` avec leurs dépendances nécessaires.

**Campagne ciblée de stabilisation de rotation exécutée le 9 novembre 2026, hors sandbox :**

| Sélection | Résultat exécuté |
|---|---|
| `AutomaticBackupTest.*` | 66/66, dont le test stabilisé et un nouveau contre-ordre déterministe |
| `BackupJobTest.*` | 23/23 |
| `VaultOperationGuardTest.*` | 13/13 |
| Total distinct de cette sélection séquentielle | 102/102, aucun échec ni test ignoré, 44,04 s |

Les deux tests de la section 6.3 ont aussi réussi chacun 30 passages isolés via `ctest --repeat until-fail:30`, soit 60 exécutions en 5,58 s, sans relance jusqu'à réussite. Ce sont deux cas déjà inclus dans les 102, pas 60 cas distincts supplémentaires. Avant correction, dix passages diagnostiques hors sandbox avaient réussi : cette absence de reproduction naturelle ne démontre pas la cause ; le contre-ordre instrumenté la rend déterministe.

Les premières tentatives sous sandbox refusaient la destination avant rotation : `/tmp` y apparaissait appartenir à `nobody`, contrairement aux exigences de chemin sûr. Elles ne validaient pas le scénario et l'ancien test poursuivait après un échec de préparation jusqu'à une assertion Qt sur une liste vide. Le test corrigé vérifie fatalement sa préparation avant tout accès à cette liste. Les validations ci-dessus ont été exécutées dans l'environnement autorisé, sans affaiblir les contrôles de destination.

Il ne s'agit pas d'une campagne CTest complète. Aucune installation ni transition système n'a été effectuée. Les observations réelles des sections 6.5/6.6 et les six essais Wayland d'export rapportés restent distincts de ces validations automatisées.

**Validation 6A-bis exécutée le 9 novembre 2026 :** compilation ciblée dans `/tmp/passwall-credential-summary-verification`, dont `passwall_app` et les cibles de tests concernées avec leurs dépendances. Tests séquentiels hors sandbox, configurations et coffres fictifs isolés, GUI offscreen. Au terme des sélections et corrections du harnais : **472 cas distincts validés, aucun échec restant ni test ignoré**, pas une exécution unique de toute la suite CTest.

| Périmètre | Dernier résultat validé pendant 6A-bis |
|---|---|
| `VaultReplacementTest` | 73/73 : 32 cas existants et 41 nouveaux |
| `VaultPreferencesStoreTest` | 27/27 |
| `VaultOperationGuardTest` | 13/13 |
| `VaultSnapshotServiceTest` | 19/19 |
| `VaultRestoreServiceTest` | 23/23 |
| `VaultStorageResourcesTest` | 24/24 |
| `AutomaticBackupTest` | 66/66 |
| `BackupJobTest` | 23/23 |
| Suivi persistant (`VaultDirtyTrackingTest` et `DirectServices/DirtyCrudTest`) | 29/29 |
| GUI ciblée : contexte éditeurs, `MainWindowEditorLockTest`, préférences, export et mot de passe maître | 123/123, dont l'émetteur 6A et le nettoyage réels |
| Stockage/clé/cycle de vie, validation/CRUD, mémoire et erreurs transactionnelles, hors gardes déjà comptés | 52/52 |

La sélection initiale de fondations (155 cas, 81,08 s) avait 154 succès et un nouveau test incorrect : il employait `writeMetadata()` comme une mise à jour, alors que cette API insère les métadonnées initiales. Le test vérifie désormais ajout/modification/suppression via `CredentialService`, sans modification de production. La sélection initiale sauvegardes/suivi/ressources (142 cas, 62,31 s) avait 140 succès et deux arrêts de tests SQLite isolés. Les traces GDB ont établi `sodium_malloc → sodium_misuse → SIGABRT` : les deux cas construisaient un `SecureBuffer` sans initialisation de libsodium dans leur processus neuf. La fixture `VaultStorageResourcesTest::SetUp()` initialise explicitement le moteur ; aucune assertion de sécurité ni primitive n'est affaiblie.

Après correction, le cas CRUD a réussi isolément, puis les deux cas SQLite ont réussi isolément (2/2, 0,11 s). La sélection finale `VaultReplacementTest` + `VaultStorageResourcesTest` a réussi 97/97 en 15,18 s. La GUI a réussi 123/123 en 299,60 s, et la dernière sélection métier 52/52 en 66,02 s. Un premier passage de développement 66/66 précédait les sept derniers cas ajoutés. Ces reprises, les vérifications isolées et les sous-processus de diagnostic ne sont pas des cas distincts supplémentaires.

Les nouveaux tests reproduisent notamment une configuration publiée/lisible suivie d'un échec d'ouverture, de `fsync` fichier ou répertoire, des erreurs réelles de `QSettings::sync()` sous permissions restreintes de test, et des exceptions avant/après publication. Ils vérifient un nouveau lecteur et un processus exécuté à neuf, la reprise/UUID/identités, les références conservées, les accès refusés et le snapshot réel sous autorisation, y compris sa révocation pendant la copie et avant publication. Les états post-publication du principal sont **modélisés dans le registre sans substituer les fichiers** ; les snapshots utilisent réellement le moteur sur fichiers fictifs. Cela ne démontre ni remplacement 6B, ni résistance à une coupure électrique, ni nettoyage exhaustif de toutes les allocations historiques. `git diff --check` ne signale aucune erreur ; les fichiers non suivis modifiés ont aussi été contrôlés.

**Validation 6B exécutée le 9 novembre 2026 :** compilation ciblée de `passwall_vault_replacement`, `passwall_replacement_tests`, `passwall_app`, des tests GUI et des cibles de régression concernées dans `/tmp/passwall-credential-summary-verification`. Les sélections finales séquentielles, hors sandbox et exclusivement sur registres/coffres fictifs isolés, valident **449 cas distincts, aucun échec restant ni test ignoré**, dont **62 nouveaux cas** (55 moteur et 7 interruptions). Ce total n'ajoute ni les 472 cas historiques ni les réexécutions, et ne représente pas une campagne CTest complète.

| Périmètre | Résultat pendant 6B |
|---|---|
| Contrats `VaultReplacementTest` 6A/6A-bis | 73/73 |
| Nouveau moteur `VaultReplacementEngineTest` | 55/55 |
| `RealFiles/VaultReplacementCrashTest` | 7/7 |
| `VaultPreferencesStoreTest` | 27/27 |
| `VaultOperationGuardTest` | 13/13 |
| `VaultSnapshotServiceTest` | 19/19 |
| Ancienne API `VaultRestoreServiceTest` | 23/23 |
| `VaultStorageResourcesTest` | 24/24 |
| `AutomaticBackupTest` / `BackupJobTest` | 66/66 et 23/23 |
| Suivi persistant (dont trois cas CRUD paramétrés) | 29/29 |
| Cycle de vie, clés, stockage, validation, CRUD, mémoire et défaillances SQL | 52/52 |
| Sélection `MainWindowEditorLockTest` (émetteur 6A, verrous, éditeurs, timer, génération native, logind simulé) | 38/38 |

Dernières sélections : remplacement **135/135 en 122,89 s** ; métier/stockage/sauvegardes **276/276 en 221,77 s** ; GUI offscreen **38/38 en 120,15 s**. Le nouveau harnais a d'abord mal ciblé l'injection de synchronisation du registre (ancienne fixture), puis continué après une assertion non bloquante sur un état absent, interrompant la sélection provisoire. Le ciblage et l'assertion ont été corrigés ; les sélections finales ci-dessus passent. Les essais intermédiaires ne sont pas comptés comme nouveaux cas.

Les tests 6B authentifient réellement le mot de passe et toutes les entrées (dont corruption volontaire de la deuxième entrée après une première valide), contrôlent les buffers `SecureBuffer` effacés avant publication privée/échange, les mutations de source/candidat/principal, les alias, la copie conditionnelle et ses échecs de publication/durabilité. Ils vérifient un catalogue non vide et ses fichiers conservés, les réservations avant/après échange, les phases persistantes et les erreurs finales. Sept sous-processus s'interrompent sans destruction normale à différentes frontières, sur de vrais fichiers fictifs ; un processus exécuté à neuf inspecte/reprend ensuite les preuves. Des cas séparés refusent fichiers absents, identités/empreintes inattendues, registre corrompu et UUID obsolète. Le callback qui change le chemin principal de l'appelant ne peut pas rediriger l'échange. Les tests n'exercent ni GUI de restauration ni délégation à un worker ; ils ne simulent pas une panne électrique ou un noyau bloqué. Les vérifications de symboles n'exposent pas l'émetteur de test en production et n'introduisent pas le déchiffrement dans le worker de sauvegarde. `git diff --check` et les contrôles des fichiers non suivis sont sans diagnostic.

Cinq tests JavaScript sont présents, avec le module standard `node:test` : deux dans `fill-script.test.cjs` et trois dans `navigation-security.test.cjs`. Ils ne sont pas intégrés à CTest et le dépôt ne contient pas de `package.json` ni de commande de test JavaScript. La commande à documenter et exécuter explicitement est `node --test tests/extension/*.test.cjs`, après avoir défini et vérifié une version minimale de Node.js.

Aucune nouvelle exécution des tests JavaScript n'est établie par le compte rendu du 6 novembre.

### 6.3 Incidents corrigés et diagnostic de l'annulation de rotation

Une erreur de compilation dans `tests/test_environment.cpp` signalait que `std::all_of` n'était pas reconnu. Une erreur de syntaxe dans des blocs `catch` de `crypto_engine.cpp` a ensuite été corrigée par l'utilisateur. Le résultat historique communiqué après cette correction était 69/69 tests réussis le 5 novembre 2026 ; les validations ciblées ultérieures figurent en section 6.2.

Le bridge a aussi reçu une correction de destruction des états de connexion avant disparition du suivi `connections_`, et les erreurs de redirection du démarrage natif ont des tests dédiés. Les deux P1 logind (validation fraîche de l'inhibiteur et attentes de résolution/abonnement D-Bus sur le thread GUI) ont été traités : contrôles `poll()`, résolution asynchrone du propriétaire unique et générations de connexion. Les tests privés/simulés ne démontrent pas toutes les transitions physiques du système.

**Intermittence de test résolue le 9 novembre 2026 :** `AutomaticBackupTest.RotationCancellationAfterCopyNeverRetractsPublishedBackup` avait échoué lors d'un passage 6A, puis une fois sur dix répétitions isolées, malgré un dernier passage 65/65 réussi. Le défaut est une relation d'ordre absente dans le test : `cancel()` mettait l'octet `!` en tampon Qt, puis le test libérait le worker sans garantir sa réception avant le dernier contrôle précédant `unlinkat()`. La [mise en tampon Unix de Qt 6.8.2](https://github.com/qt/qtbase/blob/v6.8.2/src/corelib/io/qprocess_unix.cpp#L956-L995) n'est pas un acquittement de lecture.

La séquence de production reste `copie → catalogue durable → confirmation → rotation → terminaison → libération`. Dans la rotation, `ParentChannel::check()` lit le canal non bloquant ; un retour `EAGAIN` signifie qu'aucune demande n'est encore reçue et permet de poursuivre. Le service recontrôle l'annulation après les vérifications finales d'identité, avant suppression. Une demande encore en transit peut donc arriver après une suppression déjà appliquée : elle ne restaure pas l'ancienne version et ne rétracte jamais la nouvelle copie confirmée.

La correction est limitée aux tests et au linkage de leur probe réel :

- Le test initial attend la disponibilité du message (`poll`), puis l'acquittement de sa lecture réelle par un wrapper `read` qui conserve exactement le retour/`errno`. Un second point de contrôle permet d'observer le worker vivant, avant que le résultat `Cancelled` confirme la prise en compte. Attentes conditionnelles bornées, sans délai supposé suffisant ni changement des temporisations de production.
- `RotationQueuedCancellationCannotUndoAnAlreadyAppliedDeletion` reproduit l'autre ordre : même demande avant libération du point d'arrêt, mais sans dispatcher Qt dans cette portion du test seulement. La lecture réelle retourne `EAGAIN`, puis le véritable `unlinkat` est constaté avant livraison du message. Qt est ensuite relancé, la réception acquittée et l'annulation acceptée. Aucun faux retour de lecture/suppression n'est injecté.
- Résultats fixes et distincts : annulation reçue à temps → `Cancelled`, zéro suppression, ancienne version intacte ; réception tardive après suppression → `Cancelled`, une suppression, pas de restauration rétroactive. Dans les deux cas, octets de la nouvelle sauvegarde inchangés, copie `Published`, `backupRequired` non réarmé et absence de suspension de copie.
- Les deux scénarios vérifient la réservation durant la réception et le signal de résultat, puis son relâchement uniquement après terminaison effective. Les régressions existantes couvrent aussi `Unknown` avec enfant encore actif, disparition du parent et conservation des descripteurs hérités.

Les marqueurs d'acquittement sont privés au harnais `passwall_backup_worker_probe` ; ni `BackupJob`, ni le coordinateur, ni les moteurs, ni le protocole `--protocol-v1` / `--rotation-v1` ne sont modifiés. Les 30 répétitions par ordre complètent les preuves de synchronisation, sans constituer une garantie générale contre tous les incidents d'E/S ou d'ordonnancement. Aucune nouvelle anomalie de production n'a été identifiée dans ce périmètre.

### 6.4 Fonctionnalités incomplètes et absentes

Les étapes de sauvegarde 1 à 5 et l'export manuel sont implémentés, avec les limites décrites ci-dessus. La restauration vers un nouveau fichier et le moteur synchrone 6B de remplacement sont développés ; ce dernier n'est pas une fonction GUI disponible. Restent absents : worker/transport secret/supervision de restauration 7 ; interfaces de restauration, préférences, reprise et récupération ainsi qu'export de configuration 8 ; migrations, TOTP, passkeys, audit de mots de passe et validation Windows/iOS. L'import de configuration n'est pas défini, et ne constitue pas une fonction V1 implicitement promise. Le générateur n'est pas un travail restant. Synchronisation, résolution de conflits entre copies et serveur de référence ne sont pas des fonctions engagées dans le périmètre actuel.

### 6.5 Première campagne manuelle Firefox — 6 novembre 2026

Les résultats ci-dessous sont **rapportés par l'utilisateur**, avec Firefox réel et un coffre contenant uniquement des données fictives. Ce sont des observations manuelles, distinctes des tests automatisés de la section 6.2 ; elles n'ont pas été réexécutées lors de cette mise à jour documentaire.

| Essai manuel | Résultat rapporté |
|---|---|
| Chargement de l'extension temporaire dans Firefox | Réussi |
| Ouverture du popup | Réussi |
| Démarrage automatique de PassWall | Réussi |
| Communication Native Messaging | Réussie |
| Détection du coffre verrouillé | Réussie |
| Recherche d'identifiants | Réussie |
| Récupération et remplissage d'un formulaire web | Réussis |
| Blocage de récupération après verrouillage | Réussi |
| Isolation des identifiants entre domaines | Réussie |
| Fermeture puis redémarrage automatique de PassWall | Réussi ; le coffre reste verrouillé |
| Changement de session pendant une requête | Déclaré fonctionnel lors d'un essai manuel, sans reproduction déterministe de l'instant d'invalidation |

Cette campagne établit un premier fonctionnement de bout en bout observé manuellement sur l'installation locale Linux. Elle ne prouve ni tous les entrelacements possibles du verrouillage et de la transmission, ni la sécurité générale de l'intégration.

Restent à réaliser : installation reproductible du Native Host et de l'extension, tests automatisés de bout en bout avec Firefox, extension des scénarios d'invalidation déterministe à l'intégration réelle, vérifications supplémentaires de sécurité et de robustesse, puis validation sur Windows et les autres plateformes prévues. Des tests déterministes de composant du bridge existent déjà ; ils ne doivent pas être présentés comme absents ni comme preuve du parcours Firefox complet.

### 6.6 Validation manuelle du verrouillage Linux — bilan du 7 novembre 2026

L'utilisateur rapporte les succès suivants sur Raspberry Pi 5 / Debian 13 / labwc, après installation et reconfiguration locales :

1. `Ctrl+Alt+L` déclenche le coordinateur.
2. PassWall se verrouille avant le verrouillage visible de Linux.
3. La session Linux se verrouille et se déverrouille normalement.
4. Le coffre reste verrouillé après le déverrouillage Linux.
5. Firefox refuse le remplissage tant que le coffre est fermé.
6. Une nouvelle authentification permet de retrouver le remplissage.
7. Le raccourci pilote `Ctrl+Super+L` reste disponible.

Un essai réel antérieur avec PassWall absent a également été rapporté comme réussi. L'intégration locale de ces raccourcis est donc fonctionnellement validée ; elle n'est plus une installation ou un premier essai à réaliser. Ces observations manuelles n'ont pas été reproduites pendant la mise à jour documentaire et ne constituent ni des tests automatisés de bout en bout, ni une preuve exhaustive d'effacement mémoire. Le verrouillage visible ne mesure pas les allocations historiques de Qt, les buffers système ou tous les entrelacements de requêtes. Les essais ne démontrent pas la couverture de tous les déclencheurs ni une garantie de nettoyage en cas de blocage/crash ; aucune validation réelle de suspension/hibernation/arrêt n'est déduite de ces essais.

## 7. Sécurité : constats

### Points positifs connus

- libsodium ;
- Argon2id ;
- XChaCha20-Poly1305 ;
- `SecureBuffer` non copiable et nettoyé à la destruction ;
- chiffrement des entrées avant stockage SQLite ;
- notes chiffrées avec les autres champs ;
- coffre cryptographiquement autonome, sans clé d'autorisation liée à une machine ; préférences locales distinctes du déchiffrement ;
- absence attendue de mots de passe en clair dans la base ;
- validation de l'origine avant récupération du secret par `NativeRequestProcessor`, appelé par `MainWindow::handleNativeRequest()`, puis de nouveau dans l'extension ;
- nettoyage explicite de certains champs et buffers de l'interface ;
- nettoyeurs armés avant remplissage/copie sur les chemins mémoire ciblés, validation métier commune et tests d'exception ;
- vérification des paramètres SQLite par connexion, diagnostics conservant l'erreur initiale, publication sans écrasement et distinction des résultats incertains ;
- exclusion coopérative jusqu'à terminaison réelle des auxiliaires, catalogue conservateur et porte de récupération par coffre.

### Points de vigilance

- `std::string` et les types Qt peuvent créer des copies ;
- nettoyer la zone courante d'une chaîne ne garantit pas l'effacement de toutes les anciennes allocations ;
- `QByteArray`, `QString` et `QJsonObject` peuvent conserver des copies/références partagées ;
- la migration vers `CredentialSummary` supprime la collection durable de credentials complets dans la fenêtre, mais pas toutes les copies temporaires ;
- les chemins ciblés de `CredentialService` ont été durcis, mais la revue globale des temporaires et des nouvelles tâches asynchrones reste nécessaire ;
- les buffers applicatifs de réponse sont protégés/nettoyés ; leurs copies internes Qt, système et JavaScript restent des limites de durée de vie à auditer ;
- logs et messages d'erreur à inspecter ;
- le verrouillage doit couvrir les requêtes natives et les états des services, pas seulement l'écran ; l'essai manuel de changement de session ne remplace pas une validation déterministe pendant la transmission ;
- les octets déjà acceptés par Qt ou le système ne peuvent pas être rappelés : distinguer cette limite du nettoyage et de l'annulation des données encore détenues par l'application ;
- un lancement direct de swaylock peut contourner le coordinateur ; en l'absence d'acquittement de PassWall, la tentative de verrouillage d'écran ne prouve pas le nettoyage du coffre ;
- PassWall ne surveille ni `LockedHint` ni l'état réel de déverrouillage Wayland ; le code de sortie de swaylock n'en constitue pas une preuve. La nouvelle authentification manuelle ne restaure jamais l'ancienne session et ne sert pas de preuve indépendante de cet état ;
- un support retiré ou une E/S bloquée ne permet pas de promettre une terminaison immédiate ou une durabilité physique ; ne jamais supprimer une publication valide à cause d'une erreur ultérieure ;
- configuration et SQLite ne sont pas une transaction unique ; changement de fichier, registre corrompu, résultat perdu ou interruption de restauration nécessitent une interprétation conservatrice ;
- finalisation réelle et interruption de substitution 6B sont exercées sur fichiers fictifs, pas sous coupure électrique. Supervision des secrets (7), délégation de l'autorisation et parcours utilisateur de récupération (8) restent à développer ; la correction ciblée du test de rotation ne certifie pas ces futurs chemins ;
- l'autonomie cryptographique ne garantit ni la cohérence d'une copie prise en pleine écriture, ni le transport de l'état de récupération local, ni l'application des protections d'une autre plateforme non validée.

Ces constats définissent des surfaces à examiner ; ils ne signifient pas qu'une fuite exploitable a été démontrée.

## 8. Construction et tests

Le répertoire de compilation récent communiqué est `/tmp/passwall-credential-summary-verification/`. Il sert aux vérifications de développement, pas à une installation durable. Les exécutables utilisés par Firefox et les raccourcis de verrouillage sont ceux installés dans `~/.local/bin` (sections 5.6 et 5.9).

Exemples de commandes générales de construction et de tests :

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Ces commandes sont des instructions, pas le compte rendu d'une exécution pendant cette actualisation. Les résultats ciblés rapportés figurent en section 6.2 ; les options CMake restent à adapter à l'environnement et un répertoire déjà configuré conserve son générateur. Les tests du bridge nécessitent un environnement autorisant `bind(AF_UNIX)`.

Les nouvelles cibles comprennent `passwall_preferences_tests`, `passwall_dirty_tracking_tests`, `passwall_storage_tests`, `passwall_snapshot_tests`, `passwall_backup_tests`, `passwall_automatic_backup_tests`, `passwall_restore_tests` et `passwall_replacement_tests`. `passwall_gui_tests` réutilise les sources de la fenêtre, de l'export et de l'autorisation. Les configurations QSettings et coffres des tests sont isolés ; les faux workers, injections d'allocation/appels système et émetteur 6A de test ne doivent pas être activés dans l'application de production. Le worker de sauvegarde reste sans moteur de déchiffrement ; aucun `passwall_restore_worker` n'existe.

Les tests JavaScript sont indépendants de CTest :

```bash
node --test tests/extension/*.test.cjs
```

Cette commande suppose une installation de Node.js compatible, qui n'est pas déclarée par un manifeste de projet. L'installation Firefox locale dispose désormais d'un manifeste Native Messaging pour `org.passwall.native` et a été essayée manuellement (sections 5.6 et 6.5). Aucun modèle de manifeste Native Messaging ni automatisation d'installation n'est versionné ; la procédure reproductible pour une nouvelle machine et l'identifiant d'une future diffusion restent à définir.

## 9. Plateformes

Ordre de priorité :
1. Linux sur Raspberry Pi 5 / Debian ;
2. Windows via machine virtuelle pour les tests ;
3. iOS après stabilisation Linux/Windows.

Le fonctionnement hors ligne est requis sur chaque plateforme. Le transfert de copies reste manuel et leur cohérence relève de l'utilisateur ; aucun serveur de synchronisation ou mécanisme de confiance entre machines n'est requis. Les contrôles Linux actuels ne sont pas une validation des chemins d'ouverture sur Windows/iOS.

La campagne Firefox du 6 novembre et le bilan du verrouillage de session du 7 novembre concernent uniquement l'installation locale Linux ; ils ne valent pas validation Windows, iOS ou des autres plateformes prévues.

## 10. Documents et artefacts manquants

Les deux documents suivants sont présents à la racine :
- `PASSWALL_DOCUMENTATION_TECHNIQUE.md` — architecture et état réalisé ;
- `PASSWALL_TODO_TECHNIQUE.md` — feuille de route ;

Ces deux documents constituent la référence technique du projet ; l'installation locale du coordinateur et son retour arrière sont décrits en section 5.9.

Les documents suivants sont recommandés mais absents de l'arbre courant :
- `README.md` — installation, compilation et lancement ;
- `SECURITY.md` — modèle de menace, choix cryptographiques, limites et signalement ;
- `CHANGELOG.md` — historique des changements.

Le répertoire `docs/decisions/` et les ADR associés sont également absents. Un modèle versionné de manifeste Native Messaging, une procédure reproductible d'installation du Native Host et de l'extension, ainsi que la procédure de test JavaScript doivent compléter cette documentation. Le manifeste déjà installé localement ne remplit pas ces objectifs de reproductibilité.

## 11. Mise à jour

Après chaque étape validée : noter les fichiers modifiés, le comportement avant/après, les commandes et résultats de tests, les limites connues, puis mettre à jour les deux documents racine. Distinguer les faits vérifiés des hypothèses.

Cette version confronte l'historique aux sources, interfaces, intégrations CMake et tests présents au 9 novembre. Les résultats 6B sont distingués de 6A-bis et des campagnes antérieures en section 6.2 ; aucune nouvelle vérification d'installation ni transition système n'est déduite de ces tests.
