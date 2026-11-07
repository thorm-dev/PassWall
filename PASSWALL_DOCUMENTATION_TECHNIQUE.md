# PassWall — Documentation technique du projet et état des réalisations

**Version :** 1.4
**Date :** 7 novembre 2026
**Statut :** état issu des inspections et validations précédentes, actualisé avec la clôture fonctionnelle locale de l'intégration du verrouillage Linux rapportée par l'utilisateur. Ce document distingue les faits vérifiés dans le code, les observations manuelles, les résultats de tests automatisés, les décisions de conception et les travaux restant à réaliser.

## 1. Présentation

PassWall est un gestionnaire de mots de passe dont le développement vise d'abord Linux sur Raspberry Pi 5. L'arbre courant contient un coffre chiffré local, une interface graphique indépendante du moteur et une intégration Firefox par Native Messaging. La synchronisation sécurisée entre appareils reste à développer.

La priorité est la sécurité : chiffrement au repos, protection des clés, réduction de la durée de présence des secrets en mémoire, verrouillage du coffre et contrôle de l'autorisation des appareils.

Ce document distingue décisions validées, composants implémentés et travaux non implémentés. Il ne constitue pas une certification de sécurité.

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

Technologies : C++, Qt 6 Widgets, Qt Designer, QSS, libsodium, SQLite, JavaScript, CMake, Ninja et GoogleTest.

Périmètre v1 défini :
- coffre chiffré et gestion des identifiants — implémentés ;
- extension Firefox pour rechercher un compte et remplir les champs — implémentée et essayée manuellement avec Firefox le 6 novembre 2026 ; installation locale manuelle, non empaquetée dans le dépôt ;
- générateur de mots de passe — implémenté et testé ;
- TOTP — à développer ;
- synchronisation Linux/Windows/iOS — à développer ;
- passkeys — à développer ;
- audit des mots de passe — à développer.

L'intégration aux applications locales du système a été reportée après stabilisation du coffre et de Firefox.

## 4. Décisions de conception validées

### 4.1 Stockage et modèle

- Une base SQLite locale par coffre ; les coffres sont cryptographiquement indépendants.
- Notes chiffrées avec le reste de l'entrée.
- La décision fonctionnelle de PassWall V1 impose un titre, un nom d'utilisateur et un mot de passe obligatoires. Cet invariant n'est pas encore entièrement appliqué : l'interface exige le titre seulement, et `CredentialService` accepte des chaînes vides pour les trois champs. La règle doit être imposée dans ces deux couches.
- La création du coffre configure SQLite avec `PRAGMA journal_mode=DELETE`, `PRAGMA synchronous=FULL`, `PRAGMA secure_delete=ON` et `PRAGMA temp_store=MEMORY`. Les connexions du service réactivent `secure_delete=ON`. Cette configuration est celle appliquée à la création ; son comportement après incident doit encore être validé expérimentalement.
- Si une migration est nécessaire, l'ouverture normale doit être bloquée et une migration contrôlée proposée après sauvegarde. Cette décision n'est pas implémentée : il n'existe ni migration ni sauvegarde/restauration dans l'arbre courant.

### 4.2 Cryptographie

Choix techniques documentés :
- libsodium ;
- Argon2id pour dériver une clé depuis le mot de passe maître, avec 3 itérations et 256 Mio de mémoire (`VaultArgon2Operations=3`, `VaultArgon2Memory=256 MiB`) ;
- XChaCha20-Poly1305 pour le chiffrement authentifié ;
- chiffrement individuel des entrées ;
- `SecureBuffer` pour les clés et certains buffers sensibles.

Le mot de passe maître est nécessaire pour déverrouiller le coffre. Aucun mécanisme de récupération n'est prévu si ce mot de passe est perdu.

### 4.3 Appareils et récupération

- L'ajout d'un appareil doit être approuvé par un appareil déjà autorisé.
- Le mot de passe maître reste nécessaire pour déchiffrer le coffre.
- Une procédure d'urgence de révocation d'appareil perdu a été privilégiée, avec évaluation du risque, rotation de clés et identification des secrets externes à renouveler.
- Si tous les appareils autorisés sont perdus, il n'y a pas de récupération.

Les détails cryptographiques du protocole d'enrôlement et de révocation doivent être consolidés dans une spécification unique.

### 4.4 Synchronisation, sauvegardes et migrations

- Fonctionnement hors ligne obligatoire sur chaque appareil.
- Synchronisation souhaitée Linux, Windows et iOS.
- Préférence pour un stockage distant sans exposer directement le Raspberry Pi à Internet.
- Juridiction européenne privilégiée ; Norvège et Suisse envisageables si garanties adaptées.
- Budget cible : quelques euros par mois.
- Sauvegarde manuelle vers un autre ordinateur ou un NAS local souhaitée.
- Rétention de 7 jours discutée.
- Sauvegarde automatique locale différée.

Ces choix sont des décisions de produit à finaliser. Aucune fonction de sauvegarde/restauration du coffre, migration ou synchronisation n'est actuellement implémentée. Les copies manuelles des exécutables et de la configuration labwc documentées en section 5.9 ne sont pas une fonction de sauvegarde des coffres SQLite.

### 4.5 Interface et verrouillage

- Interface Qt indépendante du moteur.
- Interface modifiable sans modifier le moteur.
- Qt Designer et QSS prévus.
- Verrouillage manuel et par inactivité implémenté dans `MainWindow`, avec un timer configuré par défaut à cinq minutes ; il invalide la session native et nettoie la clé, les résumés en mémoire, les champs de saisie et le presse-papiers PassWall lorsqu'il est inchangé.
- Sous Linux, `LinuxSessionMonitor` traite les préparations de suspension/hibernation (`PrepareForSleep`) et d'arrêt/redémarrage (`PrepareForShutdown`) de logind, avec un inhibiteur de délai et une politique fail-closed. Cela ne constitue pas une interception garantie de toute fermeture de session, de tout crash ou arrêt forcé.
- Le verrouillage d'écran par les raccourcis labwc configurés passe par `passwall-session-lock`, qui demande `Control1.Lock()` et attend son acquittement de nettoyage avant de tenter `/usr/bin/swaylock -p`, dans la limite du budget D-Bus de 1 500 ms. L'absence de réponse ne bloque pas la tentative de verrouillage de l'écran.
- Décision définitive : `SessionGuard1` est supprimé ; aucune garde persistante globale, authentification globale supplémentaire ou modification du code de swaylock/labwc n'est retenue. Chaque coffre reste cryptographiquement indépendant et s'ouvre avec son propre mot de passe maître, sans obligation de rouvrir le dernier coffre. Le déverrouillage Linux ne restaure aucune ancienne session PassWall.

## 5. Architecture logicielle connue

| Domaine | Responsabilité |
|---|---|
| `core` | cryptographie, buffers sensibles, générateur de mots de passe et rapprochement d'origines Web |
| `storage` | schéma et métadonnées SQLite |
| `services` | logique métier et credentials |
| `models` | structures métier |
| `gui` | interface Qt |
| `native` | hôte Native Messaging Firefox, socket Unix local et traitement métier commun des requêtes |
| `platform` | intégration Linux : logind, instance unique, service D-Bus de verrouillage et coordinateur d'écran |
| `tests` | tests unitaires et d'intégration |

Ce découpage est l'architecture connue ; l'arborescence exacte doit être confirmée dans le dépôt courant.

### 5.1 Moteur cryptographique

Fichiers attestés : `crypto_engine.hpp` et `crypto_engine.cpp`.

Fonctions connues : initialisation libsodium, génération de clés, dérivation Argon2id, chiffrement/déchiffrement XChaCha20-Poly1305 et gestion de `SecureBuffer`.

`SecureBuffer` utilise `sodium_malloc`, initialise son buffer, interdit la copie, autorise le déplacement et nettoie/libère sa mémoire dans son destructeur. L'affectation par déplacement nettoie et libère la mémoire précédemment détenue par la destination.

### 5.2 Stockage et cycle de vie

Composants mentionnés comme développés :
- `vault_storage` ;
- `vault_key_service` ;
- `vault_lifecycle_service`.

Ils participent à la création et à l'ouverture du coffre. La création utilise un fichier temporaire, des permissions `0600`, une synchronisation `fsync`, puis une publication qui refuse tout écrasement de destination existante. Le coffre stocke les métadonnées de clé et les entrées chiffrées, sans colonnes de credentials en clair.

### 5.3 Modèle Credential

Le fichier communiqué `src/models/credential.hpp` définit :
- `EntryId`, identifiant de 16 octets ;
- version ;
- titre ;
- URL ;
- nom d'utilisateur ;
- mot de passe ;
- notes.

Les champs textuels sont des `std::string`. La décision fonctionnelle V1 impose titre, nom d'utilisateur et mot de passe ; ce type, ainsi que le service, n'imposent actuellement que des limites de taille. Le modèle simple ne garantit pas à lui seul l'effacement sécurisé de ses champs à la destruction.

`CredentialSummary` contient uniquement l'identifiant, la version, le titre, l'URL et le nom d'utilisateur. Il ne contient ni mot de passe ni notes et sert à l'affichage et à la recherche sans collection durable de credentials complets dans `MainWindow`.

### 5.4 CredentialService

`CredentialService` gère l'ajout, la lecture, la liste, la modification et la suppression des entrées.

Le fichier `src/services/credential_service.cpp` a été communiqué et examiné. Les champs d'une entrée sont sérialisés, chiffrés puis stockés dans SQLite ; la désérialisation reconstruit un objet `Credential`.

`listSummaries()` traite les entrées une par une : déchiffrement temporaire, extraction des métadonnées et nettoyage du credential avant de poursuivre, sans vecteur intermédiaire de credentials complets. `get()` permet le chargement ciblé d'une entrée.

La création du coffre applique `journal_mode=DELETE`, `synchronous=FULL`, `secure_delete=ON` et `temp_store=MEMORY`; le service réapplique `secure_delete=ON` à ses connexions. Des nettoyeurs RAII sont présents pour certains credentials temporaires, mais les copies créées par `std::string`, SQLite et Qt restent un sujet d'audit.

### 5.5 Interface graphique

Fichiers attestés : `src/gui/main_window.hpp` et `src/gui/main_window.cpp`, ainsi qu'une interface Qt Designer associée.

Fonctions présentes dans la version examinée : création/déverrouillage du coffre, affichage/filtrage, ajout, modification, suppression et verrouillage.

La version examinée comporte un timer d'inactivité, le nettoyage de champs de saisie, le nettoyage de la liste au verrouillage et un mécanisme d'effacement conditionnel du presse-papiers. Des fonctions utilitaires de nettoyage de `QString`, `std::string` et `Credential` sont présentes. Le timer est armé avant le rafraîchissement d'une session utilisable ; le réglage « Désactivé » reste respecté.

`MainWindow::lockVault()` invalide la génération Native Messaging et les transmissions encore détenues par l'application avant de détruire la clé. Les éditeurs nettoient immédiatement leurs champs et credentials temporaires avant leur rejet, sans dépendre de la fermeture d'une notification modale ; les nettoyeurs RAII restent une protection supplémentaire. Le nettoyage et l'acquittement externe restent sur le thread Qt propriétaire, avec protection contre les réentrances. Les événements logind et le coordinateur utilisent ce même verrouillage (section 5.9).

**Migration mémoire réalisée :** l'ancienne collection `MainWindow::credentials_` de credentials complets a été remplacée par des `CredentialSummary`. L'édition et la récupération native utilisent un chargement ciblé et temporaire ; les credentials locaux disposent de nettoyeurs RAII. Cela réduit l'exposition durable sans garantir l'effacement de toutes les copies créées par les chaînes, les dialogues ou Qt.

### 5.6 Extension Firefox et pont natif

Le parcours de production effectivement utilisé est :

Firefox → Extension PassWall → `passwall_native_host` → `NativeBridgeServer` → `MainWindow::handleNativeRequest()` → `NativeRequestProcessor` → `NativeVaultAccess` → Coffre PassWall.

L'extension contient `popup` et `fill_script`. `popup.js` contacte l'hôte Native Messaging `org.passwall.native` ; `passwall_native_host` (`native_host.cpp`) communique avec `NativeBridgeServer` par socket Unix local. La réponse repart par le bridge et l'hôte vers l'extension.

`NativeRequestProcessor` constitue l'unique implémentation métier du traitement Native Messaging. `MainWindow::handleNativeRequest()` est l'adaptateur lié à l'interface ; il délègue le traitement au processeur, tandis que `MainWindow` implémente `NativeVaultAccess` pour fournir l'état de session, les résumés et le chargement ciblé d'une entrée. Le processeur est compilé par `passwall_app` et par la cible de tests.

Le popup revalide l'origine avant la récupération, et le script injecté la revalide avant de remplir les champs. Le mot de passe n'est récupéré qu'après la sélection d'un credential. Des copies temporaires restent néanmoins possibles dans les types C++ et Qt.

Le fichier `firefox-extension/manifest.json` confirme l'identifiant `passwall-native-test@passwall.local` dans `browser_specific_settings.gecko.id`. Il s'agit de l'extension de test actuellement versionnée, nommée « PassWall - Test natif », utilisée temporairement pour la campagne manuelle. Cela ne constitue pas une validation du packaging ou de l'identifiant d'une future diffusion.

**Installation locale Linux, actualisée au 7 novembre 2026 :**

| Élément | Chemin installé |
|---|---|
| Application | `/home/thormster/.local/bin/passwall_app` |
| Native Host | `/home/thormster/.local/bin/passwall_native_host` |
| Manifeste Firefox | `/home/thormster/.mozilla/native-messaging-hosts/org.passwall.native.json` |

Le champ `path` du manifeste pointe vers `/home/thormster/.local/bin/passwall_native_host`. Les deux exécutables sont installés avec les permissions `0755` ; leurs empreintes SHA-256 ont été comparées et correspondent aux versions compilées et testées, selon les vérifications d'installation rapportées. Le Host retrouve `passwall_app` dans son propre répertoire. L'application a été actualisée pour exposer `Control1.Lock()` ; le Native Host, déjà identique au candidat récent, n'a pas été remplacé. Le manifeste Firefox est resté inchangé.

Cette installation est locale et manuelle. Le manifeste installé hors du dépôt ne doit pas être confondu avec un modèle versionné : le projet ne fournit toujours pas de procédure reproductible intégrée pour installer le Native Host et l'extension sur une nouvelle machine. Les essais réels sont détaillés en section 6.5.

### 5.7 SiteMatcher

`SiteMatcher` est implémenté et testé. Il accepte HTTP/HTTPS, compare schéma, hôte et port effectif, rejette les URL malformées et les informations d'utilisateur, et interprète une URL enregistrée sans schéma comme HTTPS. Les chemins et redirections ne participent pas à la comparaison d'origine.

### 5.8 Générateur de mots de passe

`PasswordGenerator` est implémenté sous forme d'en-tête, utilisé dans la boîte d'édition et testé. Il produit des mots de passe de 8 à 128 caractères avec `randombytes_uniform`, garantit la présence de chaque catégorie sélectionnée et mélange le résultat sans biais modulo.

### 5.9 Verrouillage de session Linux

Le parcours nominal configuré sur Raspberry Pi 5 / Debian 13 / labwc 0.20.2 est :

`Ctrl+Alt+L` ou `Ctrl+Super+L` → `/home/thormster/.local/bin/passwall-session-lock` → bus D-Bus utilisateur → `org.passwall.PassWall.Control1.Lock()` → `MainWindow::requestExternalLock()` → `lockVault()` → acquittement après nettoyage → tentative de `/usr/bin/swaylock -p`.

- `SessionLockService` expose `Lock() -> ()` sur le nom `org.passwall.PassWall`, chemin `/org/passwall/PassWall`. Il n'expose ni déverrouillage ni accès aux secrets. Une réponse positive sans argument acquitte le nettoyage applicatif vérifié ; une erreur ne l'acquitte pas.
- Le coordinateur utilise un auxiliaire D-Bus sans activation automatique de PassWall. Son budget d'attente D-Bus est de 1 500 ms, démarrage de l'auxiliaire compris, et non une garantie temps réel globale. À l'expiration, il demande l'arrêt de l'auxiliaire sans attendre sa terminaison avant la tentative de lancement du verrouilleur.
- PassWall absent, indisponible, refus ou délai expiré : le verrouillage de l'écran est tout de même tenté, sans annoncer un nettoyage du coffre confirmé. Le coordinateur déduplique ses invocations concurrentes par `flock`, sous réserve d'un répertoire d'exécution sûr ; les lancements directs de swaylock restent hors de cette coordination.
- `LinuxSessionMonitor` et son backend Qt DBus restent indépendants du coordinateur. L'inhibiteur `delay` de logind pour `sleep:shutdown` est conservé jusqu'à l'acquittement du nettoyage sur le thread propriétaire. Sa validité effective est contrôlée par `poll()`, notamment avant d'autoriser une nouvelle session. Une perte de protection refuse l'accès aux secrets ; la récupération ne déverrouille jamais le coffre automatiquement. Un thread bloqué, un événement manqué ou l'expiration du délai accordé par logind restent des limites.
- `LinuxInstanceLock` assure l'instance unique. `Control1.Lock()` est ponctuel : après son acquittement, une nouvelle authentification manuelle du coffre choisi est permise si les protections système sont opérationnelles. Il n'existe plus de `SessionGuard1`, de jeton de garde à libérer ni de registre persistant global.

Le coordinateur est installé dans `/home/thormster/.local/bin/passwall-session-lock`, mode `0755`, propriétaire `thormster:thormster`. Le fichier utilisateur `/home/thormster/.config/labwc/rc.xml` définit `C-A-l` vers ce chemin et conserve `C-W-l` avec `onRelease="yes"`. Labwc est lancé avec `--merge-config` (`-m`) : les définitions utilisateur identiques remplacent les définitions système, actions comprises, sans lancer les deux commandes. Le fichier `/etc/xdg/labwc/rc.xml` conserve sa définition originale `C-A-l` vers `swaylock -p`, désormais surchargée, et n'a pas été modifié.

L'installation reste locale et manuelle. Les chemins exacts des sauvegardes, les commandes de retour arrière, les limites de déduplication et l'impact ergonomique possible sur `pishutdown` sont consignés dans [le guide du coordinateur](docs/linux-session-lock.md). Aucun code de swaylock ou labwc n'a été modifié. Le verrouillage Wayland et son déverrouillage restent entièrement assurés par le système officiel, sans surveillance de leur état réel par PassWall.

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
- tests C++ et JavaScript.

### 6.2 Résultats de tests communiqués

Jalons historiques rapportés :

- 5 tests initiaux réussis (initialisation/libsodium, versions libsodium/SQLite, XChaCha20) ;
- jalon antérieur : 60/60 tests C++ et 5/5 tests JavaScript ;
- jalon du 5 novembre 2026 : 69/69 tests réussis après correction d'une erreur de syntaxe dans `crypto_engine.cpp`.

Le journal CTest du répertoire de build enregistre 69/69 tests C++ réussis le 5 novembre 2026 à 15:20 CET. Cette observation ne remplace pas une nouvelle exécution après changement.

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

Aucun test ni compilation n'a été relancé pour cette clôture documentaire. Les observations réelles de la section 6.6 sont distinctes de ces validations automatisées.

Cinq tests JavaScript sont présents, avec le module standard `node:test` : deux dans `fill-script.test.cjs` et trois dans `navigation-security.test.cjs`. Ils ne sont pas intégrés à CTest et le dépôt ne contient pas de `package.json` ni de commande de test JavaScript. La commande à documenter et exécuter explicitement est `node --test tests/extension/*.test.cjs`, après avoir défini et vérifié une version minimale de Node.js.

Aucune nouvelle exécution des tests JavaScript n'est établie par le compte rendu du 6 novembre.

### 6.3 Incidents corrigés

Une erreur de compilation dans `tests/test_environment.cpp` signalait que `std::all_of` n'était pas reconnu. Une erreur de syntaxe dans des blocs `catch` de `crypto_engine.cpp` a ensuite été corrigée par l'utilisateur. Le résultat historique communiqué après cette correction était 69/69 tests réussis le 5 novembre 2026 ; les validations ciblées ultérieures figurent en section 6.2.

### 6.4 Achèvement non confirmé

Le générateur de mots de passe est implémenté et testé. TOTP, passkeys, audit de mots de passe et synchronisation ne sont pas implémentés. Il en va de même des sauvegardes, de la restauration, des migrations, de l'enrôlement/révocation complète et des tests Windows/iOS.

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

Restent à réaliser : installation reproductible du Native Host et de l'extension, tests automatisés de bout en bout avec Firefox, tests déterministes d'invalidation de session pendant une réponse en cours, vérifications supplémentaires de sécurité et de robustesse, puis validation sur Windows et les autres plateformes prévues.

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
- absence attendue de mots de passe en clair dans la base ;
- validation de l'origine avant récupération du secret par `NativeRequestProcessor`, appelé par `MainWindow::handleNativeRequest()`, puis de nouveau dans l'extension ;
- nettoyage explicite de certains champs et buffers de l'interface.

### Points de vigilance

- `std::string` et les types Qt peuvent créer des copies ;
- nettoyer la zone courante d'une chaîne ne garantit pas l'effacement de toutes les anciennes allocations ;
- `QByteArray`, `QString` et `QJsonObject` peuvent conserver des copies/références partagées ;
- la migration vers `CredentialSummary` supprime la collection durable de credentials complets dans la fenêtre, mais pas toutes les copies temporaires ;
- le service crée des objets temporaires à auditer ;
- les buffers de réponse contenant un mot de passe doivent être nettoyés après transmission ;
- logs et messages d'erreur à inspecter ;
- le verrouillage doit couvrir les requêtes natives et les états des services, pas seulement l'écran ; l'essai manuel de changement de session ne remplace pas une validation déterministe pendant la transmission ;
- les octets déjà acceptés par Qt ou le système ne peuvent pas être rappelés : distinguer cette limite du nettoyage et de l'annulation des données encore détenues par l'application ;
- un lancement direct de swaylock peut contourner le coordinateur ; en l'absence d'acquittement de PassWall, la tentative de verrouillage d'écran ne prouve pas le nettoyage du coffre ;
- PassWall ne surveille ni `LockedHint` ni l'état réel de déverrouillage Wayland ; le code de sortie de swaylock n'en constitue pas une preuve. La nouvelle authentification manuelle ne restaure jamais l'ancienne session et ne sert pas de preuve indépendante de cet état.

Ces constats définissent des surfaces à examiner ; ils ne signifient pas qu'une fuite exploitable a été démontrée.

## 8. Construction et tests

Le répertoire de compilation récent communiqué est `/tmp/passwall-credential-summary-verification/`. Il sert aux vérifications de développement, pas à une installation durable. Les exécutables utilisés par Firefox et les raccourcis de verrouillage sont ceux installés dans `~/.local/bin` (sections 5.6 et 5.9).

Exemples de commandes générales de construction et de tests :

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Ces commandes sont des instructions, pas le compte rendu d'une exécution complète le 6 novembre. Les résultats ciblés rapportés figurent en section 6.2 ; les options CMake restent à adapter à l'environnement. Les tests du bridge nécessitent un environnement autorisant `bind(AF_UNIX)`.

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

Le fonctionnement hors ligne est requis sur chaque appareil. Le serveur de synchronisation ne doit pas nécessiter l'exposition directe du Raspberry Pi à Internet.

La campagne Firefox du 6 novembre et le bilan du verrouillage de session du 7 novembre concernent uniquement l'installation locale Linux ; ils ne valent pas validation Windows, iOS ou des autres plateformes prévues.

## 10. Documents et artefacts manquants

Les deux documents suivants sont présents à la racine :
- `PASSWALL_DOCUMENTATION_TECHNIQUE.md` — architecture et état réalisé ;
- `PASSWALL_TODO_TECHNIQUE.md` — feuille de route ;

Le guide `docs/linux-session-lock.md` documente également l'installation locale effective du coordinateur, les raccourcis, les validations, les sauvegardes et les retours arrière.

Les documents suivants sont recommandés mais absents de l'arbre courant :
- `README.md` — installation, compilation et lancement ;
- `SECURITY.md` — modèle de menace, choix cryptographiques, limites et signalement ;
- `CHANGELOG.md` — historique des changements.

Le répertoire `docs/decisions/` et les ADR associés sont également absents. Un modèle versionné de manifeste Native Messaging, une procédure reproductible d'installation du Native Host et de l'extension, ainsi que la procédure de test JavaScript doivent compléter cette documentation. Le manifeste déjà installé localement ne remplit pas ces objectifs de reproductibilité.

## 11. Mise à jour

Après chaque étape validée : noter les fichiers modifiés, le comportement avant/après, les commandes et résultats de tests, les limites connues, puis mettre à jour les deux documents racine et les guides concernés. Distinguer les faits vérifiés des hypothèses.

Cette synthèse repose sur l'historique de travail disponible ; elle ne remplace pas une inspection automatique du dépôt actuel.
