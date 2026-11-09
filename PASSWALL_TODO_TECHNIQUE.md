# PassWall — Plan technique des travaux restants

**Version :** 1.9
**Date :** 9 novembre 2026
**Statut :** moteur synchrone 6B de remplacement développé sur 6A/6A-bis, avec inspection/reprise contrôlée et conservation de l'ancien principal. Les campagnes ciblées sont distinguées en section 6 ; aucune campagne complète n'est revendiquée. Prochain chantier : étape 7, délégation limitée et auxiliaire de restauration, sans GUI.

## 1. Objet et méthode

Cette feuille de route synthétise les travaux restant à réaliser ou à vérifier. Elle distingue les décisions validées, les composants développés et les points dont l'achèvement n'est pas confirmé. Elle ne constitue pas une certification de sécurité.

- **À faire** : travail identifié, non confirmé comme réalisé.
- **À vérifier** : une implémentation existe ou a été évoquée, mais doit être contrôlée.
- **Conditionnel** : dépend d'une décision préalable.
- **Réalisé** : étape implémentée ou observation rapportée, dans le seul périmètre explicitement indiqué ; cela ne vaut pas certification de sécurité.
- **Fondation** : contrat ou mécanisme préparatoire implémenté/testé, sans parcours fonctionnel complet.
- **Partiel** : certains composants sont opérationnels, mais l'ensemble du besoin n'est pas livré.
- **Anomalie ouverte** : incident constaté ou rapporté qui n'est pas résolu par la seule réussite d'un passage ultérieur.

La documentation technique décrit les contrats et limites des composants ; ce TODO privilégie les actions restantes et leurs critères d'acceptation. Les résultats historiques de tests ne sont ni additionnables comme une campagne unique, ni une preuve d'exécution de l'état actuel complet.

### Faits vérifiés dans l'implémentation

- Coffre local, GUI, Firefox à traitement unique `NativeRequestProcessor`, générateur, validation des champs, durcissement mémoire et SQLite V1 sont développés. Leur architecture et leurs validations figurent dans la documentation technique, sections 5 et 6.
- Les étapes de sauvegarde 1 à 5 et l'export manuel existent ; préférences/reprise GUI restent absentes. L'intermittence du test de rotation est résolue par synchronisation déterministe, sans changement de production (section 4.4). L'ancien moteur restaure vers un nouveau fichier ; le moteur 6B remplace réellement le principal sous autorisation 6A/6A-bis, sans auxiliaire ni GUI.
- Les protections Linux, des éditeurs et des générations natives sont présentes. `SessionGuard1` est supprimé, sans garde globale ni authentification globale supplémentaire ; l'intention de récupération 6A reste propre à une opération sur un coffre.
- Le coffre est cryptographiquement autonome ; ses copies sont indépendantes et l'utilisateur assure leurs transferts/cohérence. Aucun modèle d'autorisation d'appareil ni développement de synchronisation automatique ou de serveur de référence n'est retenu dans le périmètre actuel. Les contrôles locaux de récupération restent applicables (section 5).
- TOTP, passkeys, audit de mots de passe, migrations et export de configuration restent absents ; l'import de configuration n'est pas défini.

## 2. Ordre des priorités

| Priorité | Domaine | Objectif |
|---|---|---|
| P0 | Mémoire sensible | Préserver le durcissement réalisé ; contrôler les nouveaux chemins sensibles, surtout la restauration asynchrone |
| P0 | Flux Firefox/natif | Préserver le traitement unique, les origines et l'invalidation ; étendre la validation de l'intégration réelle |
| P0 | Verrouillage | Préserver le nettoyage acquis et vérifier son articulation avec les opérations longues et les défaillances Linux |
| P1 | Restauration — 7 | Déléguer étroitement l'autorisation 6A au futur auxiliaire, superviser les secrets et l'annulation ; préserver le moteur 6B sans GUI à l'étape 7 |
| P1 | Interfaces et finalisation — 8 | Préférences/reprise, GUI de restauration/récupération, export de configuration et politique de verrouillage automatique obligatoire |
| P1 | Tests et distribution | Compléter les scénarios manquants, établir une campagne actuelle et rendre l'installation Linux/Firefox reproductible |
| P1 | Migrations | Préparer lorsqu'une évolution de format le nécessitera, après stabilisation locale |
| P2 | Produit | Finaliser TOTP, passkeys, audit et ergonomie |
| P3 | Plateformes | Linux, puis Windows ; iOS différé |

Les P0 restent des invariants de maintenance, non une demande de recommencer les chantiers clos. Après validation du moteur 6B, **7 est le prochain chantier**, sous réserve d'une nouvelle vulnérabilité prioritaire. L'ordre détaillé de la section 8 suit ce tableau.

## 3. P0 — Réduction de l'exposition mémoire

### 3.1 Ne plus conserver tous les credentials complets dans MainWindow

**Réalisé :** `CredentialSummary` / `listSummaries()` remplacent la collection durable de credentials complets dans `MainWindow` ; voir documentation technique, sections 5.3 à 5.5.

**Travaux restants :** préserver cette propriété dans les nouvelles fonctions, notamment restauration et annulation ; compléter l'audit global V1 des copies résiduelles. La migration et le durcissement ciblé ne garantissent pas l'effacement de toutes les anciennes allocations des chaînes et des types Qt.

**Acceptation :** aucun conteneur durable de l'interface ne conserve les mots de passe ou notes de toutes les entrées.

### 3.2 Nettoyage RAII des objets temporaires

**Réalisé :** nettoyage des mots de passe maîtres, temporaires CRUD et authentification entrée par entrée, avec tests d'erreur/exception (documentation technique, sections 5.4 et 5.5). Le chantier ciblé est clos ; ne pas le rouvrir sans défaut démontré.

**Travaux restants :** conserver ces régressions et appliquer les mêmes règles aux futurs buffers de restauration asynchrone. Documenter dans l'audit global V1 les limites des historiques d'allocations, des copies Qt, SQLite et du système, sans créer un nouveau framework mémoire par principe.

**Limite importante :** nettoyer la zone actuellement utilisée par un `std::string` ne garantit pas l'effacement de toutes ses anciennes allocations, copies ou données SSO. Il ne faut pas présenter `sodium_memzero()` sur `string.data()` comme une garantie absolue.

### 3.3 Consolider le flux natif Firefox de bout en bout

**Réalisé :** traitement métier unique `NativeRequestProcessor`, adaptateur `MainWindow` / `NativeVaultAccess` et pont Host/socket. Installation manuelle et essais réels du 6 novembre rapportés : documentation technique, sections 5.6 et 6.5. Cela ne prouve ni la présence de toutes les sources récentes dans les exécutables installés, ni une automatisation Firefox de bout en bout.

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

**Réalisé aussi :** validation canonique partagée des `EntryId` (32 caractères hexadécimaux minuscules et type JSON chaîne), `NativeRequestResponse` non copiable à buffer propriétaire, limite commune de 1 Mio hors préfixe, transmission segmentée et invalidation des réponses en attente. Des tests déterministes de composant couvrent l'invalidation entre segments ; les erreurs de redirection du Host sont également testées.

**À faire :** automatiser les tests de bout en bout avec Firefox, étendre les scénarios d'invalidation déterministe à cette intégration réelle et poursuivre les vérifications de robustesse. Les succès manuels et les tests du bridge ne clôturent pas ces travaux. Aucun second handler métier n'est à recréer.

**Acceptation :** une demande ne charge qu'une entrée ciblée après validation ; pas de secret dans les logs ; buffers temporaires nettoyés au mieux.

### 3.4 Verrouillage

**État actuel :** nettoyage immédiat/réentrant des éditeurs et des réponses natives, minuterie armée avant rafraîchissement, protections logind et coordinateur `Control1.Lock()` sont implémentés. Installation, budget D-Bus de 1 500 ms, limites et retour arrière : documentation technique, sections 4.5, 5.5 et 5.9.

**À faire — politique obligatoire validée, étape 8 :** remplacer les choix actuels (désactivation possible, défaut cinq minutes, 10 minutes présent et 60 absent) par **1 minute par défaut, 5, 15, 30 et 60 minutes maximum**. Supprimer « Désactivé » ; convertir les anciennes configurations `security/autoLockMinutes=0` vers 1 minute. Retirer aussi le choix 10 minutes, hors de la nouvelle liste. La règle de conversion des anciennes valeurs 10 ou invalides devra être explicitée avant sa mise en œuvre ; ne pas conserver de valeur non autorisée ni inventer une nouvelle option. Aucun changement du code du minuteur n'est réalisé ici.

**Acceptation et tests nécessaires :**

- Installation sans préférence : 1 minute ; liste GUI et validation de configuration limitées exactement à 1/5/15/30/60, sans désactivation.
- Ancienne valeur 0 : conversion vers 1, armement effectif et persistance contrôlée ; vérifier le rechargement. Définir/tester le traitement des anciennes valeurs 10 et des configurations invalides, sans laisser le coffre sans protection si la sauvegarde de préférence échoue.
- Vérifier chaque durée, le plafond 60, l'expiration en boucle Qt imbriquée et l'armement avant tout rafraîchissement/notification ; aucune réactivation après verrouillage et aucune ancienne session restaurée.
- Adapter les tests qui valident aujourd'hui la désactivation, tout en préservant les régressions des éditeurs, générations Native Messaging, logind et `Control1.Lock()`. Ne pas supprimer ces protections pour modifier la politique du timer.

**Décisions closes :** `SessionGuard1` est supprimé, sans remplacement par une garde persistante globale. Aucun mot de passe maître global ni obligation de rouvrir le dernier coffre. Après le verrouillage, chaque coffre peut être ouvert par une nouvelle authentification avec son propre mot de passe maître, si les protections système et la porte de récupération de ce coffre l'autorisent. Le déverrouillage de Linux ne restaure jamais de session. Aucune modification du code de swaylock/labwc ni preuve de déverrouillage Wayland n'est requise pour cette nouvelle authentification.

**Jalon acquis :** le parcours local des raccourcis et du remplissage après nouvelle authentification a été validé manuellement le 7 novembre ; voir documentation technique, section 6.6. Il ne démontre pas tous les scénarios d'échec ni un effacement mémoire exhaustif.

**Propriétés à préserver et à vérifier au-delà du changement d'écran :**

- arrêt du timer ;
- effacement conditionnel du presse-papiers ;
- nettoyage des credentials et données de recherche ;
- destruction de la clé (`SecureBuffer`) ;
- nettoyage des champs de saisie ;
- invalidation des états des services et du pont natif ;
- traitement des requêtes natives en cours ;
- maintien des protections logind déjà implémentées, sans les assimiler à une interception garantie des fermetures de session, crashs ou arrêts forcés.

**Travaux restant ouverts :** maintenir les régressions GUI, logind et de transmission ; compléter les entrelacements avec les nouvelles opérations longues. La préparation 6A distingue déjà son verrouillage volontaire du verrouillage de sécurité, qui révoque l'autorisation ; l'annulation et le nettoyage d'un futur worker de restauration restent à réaliser. Valider séparément les transitions réelles de suspension/hibernation/arrêt : les tests simulés et les essais du raccourci ne les démontrent pas. Recenser les déclencheurs directs de swaylock et autres mécanismes de fermeture de session, qui peuvent contourner le coordinateur. Documenter le cas de PassWall bloqué, sans nettoyage confirmé, et les limites d'un thread principal ou de logind indisponible.

L'état réel de déverrouillage Wayland n'est pas surveillé ; le code de sortie de swaylock ne constitue pas une preuve de déverrouillage. La disparition éventuelle de l'indication du raccourci dans `pishutdown` reste un point ergonomique à vérifier, sans modifier le programme système. Le pilote `Ctrl+Super+L` peut être conservé ou retiré ultérieurement sur décision explicite. L'installation reproductible du coordinateur reste à formaliser au-delà de cette installation locale.

Le verrouillage visible ne prouve pas l'effacement de toutes les allocations historiques de Qt. Distinguer les données encore détenues par l'application, qui doivent être annulées et nettoyées, des octets déjà acceptés par Qt ou le système, qui ne peuvent pas être rappelés.

### 3.5 Qt et presse-papiers

Vérifier les conversions `std::string`/`QByteArray`/`QString`, les propriétés Qt, `UserRole`, messages d'erreur et logs. Qt peut conserver des copies internes ; leur effacement physique ne peut pas être garanti simplement par l'application. Vérifier aussi le délai d'effacement du presse-papiers et le cas où l'utilisateur copie autre chose entre-temps.

### 3.6 Champs obligatoires de PassWall V1 — réalisé

Titre, nom d'utilisateur et mot de passe sont imposés à l'ajout et à la modification par `CredentialService::validate()`, réutilisé dans les dialogues Qt. Titre et nom d'utilisateur vides ou uniquement composés d'espaces Unicode sont refusés. Un mot de passe vide est refusé, mais ses espaces sont conservés exactement, y compris s'il ne contient que des espaces. Aucune normalisation silencieuse n'est appliquée ; les limites de taille restent en vigueur.

Les tests couvrent champs manquants, valeurs Unicode/blanches, cohérence GUI/service, préservation de l'entrée source, absence d'écriture après refus et nouvelle opération valide. **Reste à faire :** maintenir ces tests dans les évolutions des formulaires et futurs chemins d'écriture, pas redécider les obligations ni ajouter une migration des anciens coffres de test.

## 4. P0/P1 — Cryptographie et stockage

### 4.1 Moteur cryptographique

Le moteur utilise libsodium, Argon2id et XChaCha20-Poly1305. Les paramètres actuels sont 3 itérations et 256 Mio (`VaultArgon2Operations=3`, `VaultArgon2Memory=256 MiB`), avec une plage acceptée de 3 à 4 itérations et de 256 à 512 Mio à l'ouverture. Des tests de chiffrement, altération, troncature et authentification existent ; ils ne remplacent pas une revue cryptographique globale V1. Points à examiner dans cette revue :
- justification documentée de ces paramètres au regard du matériel cible ;
- génération et stockage du sel ;
- unicité des nonces ;
- AAD ;
- version et format des données chiffrées ;
- ciphertext tronqué ou altéré ;
- nettoyage des clés et buffers sur tous les chemins d'erreur ;
- comportement si libsodium ne s'initialise pas.

Conserver les tests existants et compléter seulement les scénarios réellement manquants. Justifier les paramètres sur le matériel cible sans modifier la cryptographie à l'occasion d'un chantier de sauvegarde.

### 4.2 SQLite

**Réalisé :** chaque connexion concernée utilise `configureSqliteConnection()` et vérifie `DELETE`, `EXTRA=3`, `secure_delete=1`, `temp_store=2`, les options de compilation compatibles et `busy_timeout=3000`. `NO_CKPT_ON_CLOSE=1` est établi et relu avant inspection. Un journal incompatible est refusé sans conversion ni nettoyage manuel ; les modifications normales du SHM restent possibles. Le passage FULL → EXTRA est une décision validée, pas une comparaison encore à refaire.

Connexions, statements, erreurs SQLite et temporaires de création disposent de protections RAII, y compris sur exception. Les transactions CRUD restent `BEGIN IMMEDIATE` / `COMMIT` : codes initiaux préservés, état transactionnel consulté, rollback confirmé/échoué/automatique et résultat incertain distingués. Ni autocommit après erreur ni terminaison d'un processus ne prouvent un succès durable.

Les tests existants traitent déjà refus WAL, vérification des PRAGMA, exceptions d'allocation, échecs BEGIN/COMMIT/ROLLBACK, contention réelle, `FULL`, `IOERR` injecté et interruption de processus. **Travaux restants :** maintenir ces régressions, compléter l'audit de corruption et les essais sur matériels/supports annoncés ; ne pas présenter les injections comme des pannes électriques. L'effacement physique sur SSD, snapshots ou swap et les garanties d'un stockage distant ne sont pas démontrés par SQLite.

### 4.3 Migrations

Décision validée : bloquer l'ouverture normale lorsqu'une migration est nécessaire et proposer une migration contrôlée après sauvegarde. **État vérifié :** le coffre et les entrées portent une version de format, les versions incompatibles sont refusées, mais aucun moteur de migration n'est implémenté.

Lorsqu'une évolution de format le nécessitera : spécifier les transitions supportées, créer et vérifier une sauvegarde préalable, rendre la migration atomique ou récupérable, puis tester interruption/échec/restauration. Réutiliser les fondations d'exclusion et de publication sans les confondre avec un moteur de migration déjà livré. Aucune reprise des anciens coffres fictifs n'est exigée pour les chantiers courants.

### 4.4 Sauvegardes — moteurs réalisés et finitions restantes

**Fondations réalisées :** étapes 1 à 5 (registre, exclusion, suivi persistant, sauvegarde/worker/coordination et catalogue/rotation) et export manuel Qt. Les contrats détaillés figurent dans la documentation technique, sections 5.10 à 5.15 ; ils ne sont pas à reconstruire. `Unknown` ne prouve pas la terminaison d'un auxiliaire, et les réservations restent détenues jusqu'à sa fin effective.

**Résolu le 9 novembre 2026 :** le test `AutomaticBackupTest.RotationCancellationAfterCopyNeverRetractsPublishedBackup` supposait reçue une annulation seulement mise en tampon Qt. Il acquitte désormais la lecture réelle avant poursuite ; un nouveau test `RotationQueuedCancellationCannotUndoAnAlreadyAppliedDeletion` démontre l'autre ordre, avec `EAGAIN` puis suppression réelle avant livraison. Chacun a réussi 30 passages isolés ; les 102 régressions ciblées ont réussi. Moteur, protocole et temporisations de production sont inchangés. Maintenir ces deux scénarios et la distinction entre demande, réception, acceptation et terminaison ; le diagnostic détaillé est conservé dans la documentation technique, section 6.3. Cette anomalie n'est plus une priorité immédiate.

**Travaux restants :**

1. Fournir les réglages GUI par coffre et « Reprendre la sauvegarde » (section 4.6), sans réintroduire de répétitions automatiques après échec.
2. Proposer une résolution explicite des intentions de rotation interrompues, sans suppression aveugle, réutilisation d'une ancienne preuve ni effacement d'un fichier inconnu.
3. Compléter la validation sur supports locaux annoncés, changements de destination, retrait de support et fermeture ; distinguer les erreurs réellement retournées des diagnostics supposés.
4. Distribuer le worker à côté de l'application et tester son absence/incompatibilité dans une installation reproductible.

**Décisions closes :** automatique désactivé, dossier vide, sept versions par défaut ; nomenclature `NomDuCoffre_JJ-MM-AAAA_HH-MM-SS.db` avec protection contre collisions ; nouvelle copie à l'activation puis sur modifications au verrouillage ; reprise explicite avec une copie fraîche après erreur, sans destination de secours. Rotation seulement après copie et association confirmées. NAS et systèmes de fichiers réseau ne sont pas actuellement des destinations validées : étudier leur prise en charge avant de les annoncer, sans affaiblir les refus existants.

### 4.5 Restauration par remplacement — moteur 6B, auxiliaire encore absent

Le moteur existant `VaultRestoreService` authentifie le mot de passe maître et toutes les entrées avant publication vers un nouveau fichier. Il est testé, mais ne remplace pas le principal et n'a pas de parcours GUI. Son mot de passe est un `std::span` emprunté : sa durée de vie et son nettoyage restent à la charge de l'appelant.

**Étape 6A — fondations de sécurité, implémentée :** autorisation opaque émise par `MainWindow` après nettoyage réel, réservation exclusive, barrière aux nouvelles sessions, intention persistante et porte de récupération (documentation technique, section 5.16). Ces fondations seules ne substituaient aucun fichier ; elles sont maintenant utilisées par 6B. Les tests simulés ne remplacent pas ceux de l'émetteur GUI réel.

**Étape 6A-bis — durcissement implémenté et validé :** la nouvelle identité est persistée en phase `identity-confirmed` avec blocage encore actif ; une confirmation durable est exigée avant résolution. La résolution conserve un reçu `resolvedReplacement` borné à la dernière opération, avec identités et références, sans second registre ni effacement d'artefact. Une erreur de confirmation finale peut laisser l'ancien état protégé ou un reçu sûr, jamais supprimer les seules preuves en prétendant que rien n'a eu lieu. Résultats explicites, reprise idempotente limitée au même UUID déjà confirmé et contrôles physiques sont décrits en section 5.16 de la documentation. `snapshotPrincipal()` permet uniquement la lecture du principal initial en phase `prepared`, sous l'autorisation 6A vivante ; une réservation seule ne contourne pas la porte. 6B y raccorde le remplacement et la copie conditionnelle ; worker et GUI restent absents.

**À conserver après 6B :** phases sans court-circuit, double identité et empreintes, ancien inode et réservations continues. La reprise 6B ne répète jamais une substitution : elle reconnaît les dispositions réelles et ne finalise que l'échange déjà prouvé. Seule une autorisation encore vivante peut abandonner `prepared` avec preuves intactes ; après perte de celle-ci, la préparation reste bloquée. `armed` avant échange ne bénéficie d'aucun abandon automatique, même avec autorisation vivante. Leur parcours utilisateur contrôlé relève de 8, pas d'une authentification levant implicitement le blocage. Perte externe du registre, participants non coopératifs, supports non validés et limites physiques de `fsync` restent explicites.

**Étape 6B — moteur de remplacement récupérable, implémenté et validé dans son périmètre synchrone :**

1. `replacePrincipal()` exige l'autorisation opaque et son principal exact ; copie privée stable, validation structurelle, même `vault_id`, authentification réelle de toutes les entrées et nettoyage du `SecureBuffer` propriétaire/DEK/credentials avant publication. L'ancienne API de restauration vers un nouveau fichier reste inchangée.
2. Copie de précaution par `snapshotPrincipal()` en `prepared` obligatoire lorsque automatique désactivé : destination explicite inexistante, échec ou durabilité incertaine bloquants, exclusion du catalogue. Si activé : ni copie récente ni disponibilité du dossier habituel exigée.
3. Candidat privé 0600 dans un dossier 0700 du système de fichiers du principal, empreinte authentifiée et durabilité établies avant `armed`. Échange réel `RENAME_EXCHANGE`, sans copie en place : l'ancien inode reste au nom technique du candidat, avec références persistantes et réservations continues.
4. Finalisation 6A-bis réutilisée, résultats détaillés, conservation de l'identifiant local/préférences/catalogue/suspensions, `backupRequired` conservateur si automatique activé. Aucune ouverture, sauvegarde ou rotation déclenchée par le moteur.
5. Inspection/reprise explicite par UUID : reconnaître `armed` avant/après échange avec les deux identités et empreintes ; finaliser seulement l'échange démontré, jamais le répéter. États manquants/incohérents restent bloqués. Tests de vrais fichiers et interruptions de sous-processus, sans panne électrique réelle.

**Limites maintenues :** aucun auxiliaire, délégation ou parcours GUI. Le moteur synchrone respecte encore le thread propriétaire de l'autorisation ; ne pas le déplacer arbitrairement pour éviter de bloquer la GUI. Ne pas nettoyer automatiquement les anciens inodes ni les dossiers privés orphelins après crash ; définir en 8 une récupération/éventuelle suppression avec preuves, pas un effacement aveugle. Registre et SQLite ne forment pas une transaction atomique ; visibilité et confirmation de durabilité restent distinctes.

**Étape 7 — processus auxiliaire de restauration, à développer :**

- Ajouter `passwall_restore_worker`, distinct du worker de sauvegarde sans clé, puis exécuter le moteur 6B hors du thread GUI.
- Définir la délégation interprocessus limitée depuis l'émetteur 6A, qui conserve son autorité et l'exclusion jusqu'à terminaison réelle ; aucune reconstruction de l'autorisation depuis un UUID ou un booléen, aucun accès aux méthodes d'émission pour l'auxiliaire.
- Transmettre le mot de passe par canal privé et propriété explicite d'un `SecureBuffer` ; aucun secret dans arguments, environnement, fichiers ou logs. Démontrer nettoyage du mot de passe, DEK et credentials avant publication.
- Coordonner annulation coopérative, verrouillages de sécurité et acquittements réels de nettoyage, sans confondre le verrouillage volontaire de préparation avec une annulation inattendue.
- Superviser résultats, réponses tardives, fermeture et terminaison réelle ; conserver les protections nécessaires tant que l'auxiliaire peut encore agir. Ne pas attendre dans un destructeur Qt ni considérer un processus bloqué dans le noyau comme immédiatement interrompu.

**Acceptation 7 :** tests ciblés du canal secret, des générations obsolètes, annulation avant/après engagement, verrouillage, perte de résultat et enfant non coopératif. Une sortie seule ne prouve pas publication/nettoyage, et `Unknown` ne prouve pas terminaison. Aucune GUI de restauration n'est incluse dans cette étape.

### 4.6 Étape 8 — Interface utilisateur et finalisation, à développer

- Ajouter la GUI des trois seuls réglages de sauvegarde : activation, dossier, nombre de versions. L'activation initiale doit demander la première copie ; aucune option de cadence, délai global ou répétition automatique n'est à inventer.
- Exposer la reprise manuelle après erreur avec revalidation de la destination, nouveau snapshot, notification unique et maintien de la suspension en cas de nouvel échec.
- Ajouter la GUI de restauration après 6B et 7 : sélection du principal et de la sauvegarde librement choisie, saisie protégée du mot de passe, choix de copie de précaution obligatoire selon configuration et confirmation explicite du remplacement. Résultat/cancel restent réactifs ; aucun coffre n'est automatiquement ouvert ou sélectionné après réussite.
- Exporter le fichier global de configuration sans altérer l'original ni écraser sans autorisation ; protéger les chemins privés qu'il contient. **Import non défini :** ne pas l'ajouter par déduction.
- Proposer une réassociation conservatrice et des parcours de récupération de restauration/rotation interrompues ; ne pas réinitialiser un registre corrompu ni lever un blocage par simple confirmation.
- Finaliser la politique de verrouillage automatique obligatoire et ses tests décrits en section 3.4, sans affaiblir les autres verrouillages.
- Documenter les changements d'identité après déplacement/copie/remplacement et l'absence de transaction unique entre QSettings et SQLite. Un registre supprimé extérieurement ne peut pas toujours être distingué d'une première configuration.

**Acceptation 8 :** tests GUI d'intégration des réglages, reprise, restauration/confirmation, copie préalable, récupération, export de configuration et minuteur obligatoire. Une copie ne reçoit pas automatiquement les préférences/autorisations locales de sauvegarde du principal ; un registre illisible/ambigu refuse les accès lorsque la récupération ne peut pas être exclue ; une récupération n'active jamais une ancienne session. Les opérations sur un coffre indépendant restent possibles lorsque son état peut être établi.

## 5. P1 — Portabilité des fichiers et contrôles locaux

### 5.1 Périmètre et vérification du code

Le coffre est autonome et les copies sont indépendantes ; les transferts et leur cohérence relèvent de l'utilisateur. Aucun système d'autorisation d'appareil, serveur de référence, synchronisation automatique ou résolution de conflits entre copies n'est planifié dans le périmètre actuel. Une éventuelle évolution demanderait une nouvelle décision.

La lecture de `VaultLifecycleService`, `VaultKeyService` et `VaultPreferencesStore` ne révèle pas de dépendance au registre d'origine pour ouvrir une copie cohérente. Un registre destinataire absent est accepté ; l'enregistrement local après authentification utilise les trois préférences par défaut, sans héritage de la source. La documentation technique, section 5.10, distingue déchiffrement, association locale, protections d'installation et récupération. Il ne s'agit pas d'un essai exécuté entre machines.

### 5.2 Tests et limites à traiter

- Ajouter un scénario complet de transfert sur installation/configuration isolée neuve : ouverture et lecture au mot de passe, nouvel UUID/préférences par défaut, mutation de la copie sans changement de l'original. Les tests actuels de copie sur un même registre et de porte de récupération avec registre absent ne démontrent pas seuls ce parcours complet.
- Maintenir les refus sur registre local occupé/corrompu/illisible ou intention 6A correspondante. Ne pas supprimer le registre, réassocier arbitrairement ou contourner les contrôles d'identité pour prétendre rendre la copie portable.
- Tester séparément les associations ambiguës dans un registre déjà utilisé (déplacement, original manquant, remplacement inattendu). Elles peuvent empêcher les préférences de sauvegarde sans constituer une autorisation de machine manquante.
- Documenter le transfert d'un export/instantané confirmé ou d'un fichier dont toutes les écritures/connexions sont terminées ; ne pas recommander une copie brute en cours d'écriture ni la suppression des journaux SQLite.
- Le registre supprimé reste indistinguable dans certains cas d'une première configuration ; les intentions de récupération ne voyagent pas automatiquement avec une copie. Préserver cette limite et prévoir la récupération contrôlée 6B/8, pas un contournement automatique.
- Valider chaque future plateforme : le garde d'opérations interprocessus refuse actuellement l'accès hors Linux. C'est une limite de portage, pas une dépendance à l'ancienne machine.

**Acceptation :** sur une installation Linux compatible et sûre, l'absence du seul QSettings d'origine ne bloque pas la copie ; aucune préférence de sauvegarde source n'est héritée. Pas d'incompatibilité de ce type identifiée par inspection ; les validations complètes de transfert et Windows/iOS restent à faire.

### 5.3 Récupération

La récupération repose sur des copies/sauvegardes utilisables et le mot de passe maître. Aucun mécanisme ne contourne sa perte et aucune récupération centralisée n'est prévue. Distinguer cette récupération de données de la résolution locale d'une opération 6A interrompue ; les protections `VaultReplacementAuthorization`, `VaultOperationGuard`, Firefox et Linux restent requises.

## 6. P1 — Tests

**Couverture déjà présente à conserver :** mémoire succès/erreur/exception, listes partiellement lues et corruption, validation des champs, nettoyage des éditeurs, minuterie, contrôle D-Bus et générations natives ; configuration/ressources SQLite et diagnostics transactionnels ; exclusion réelle entre processus, suivi persistant, snapshots, worker, export GUI, catalogue/rotation ; restauration vers un nouveau fichier ; contrats et émetteur réel d'autorisation 6A. Ne pas redemander ces suites comme si elles étaient absentes.

**Scénarios manquants ou à consolider :**

1. Maintenir les deux ordres déterministes d'annulation de rotation désormais validés (section 4.4), sans remplacer les acquittements par des délais ni confondre `Unknown` et terminaison. Le développement prioritaire après validation de 6B est l'étape 7.
2. Maintenir les tests 6B de remplacement réel sur principal fictif, interruptions, résultats incertains, copie préalable conditionnelle et récupération ; préserver aussi les contrats 6A-bis de visibilité/durabilité, UUID et lecture autorisée. En 7, démontrer les mêmes protections sous délégation réelle, supervision des secrets et verrouillage de sécurité, pas seulement dans un appel synchrone de test.
3. Auxiliaire 7 et secrets asynchrones : propriétés/durée de vie du canal et du `SecureBuffer`, erreur, fermeture, verrouillage de sécurité, terminaison réelle de l'enfant non coopératif et callback tardif. Une exception injectée ou un acquittement simulé ne prouve pas un nettoyage réel.
4. GUI/finalisation 8 : préférences, reprise, restauration/confirmation, copie de précaution, export de configuration et récupération contrôlée. Appliquer les tests de la politique de minuteur obligatoire (section 3.4) et maintenir les régressions existantes : réentrances, ancienne session, éditeur ouvert.
5. Firefox : automatisation de bout en bout et entrelacements déterministes avec navigateur réel. Les scénarios métier de refus d'origine, entrée absente/modifiée et les tests d'invalidation du bridge existent déjà ; ils ne prouvent pas l'intégration Firefox complète.
6. Stockage/supports : étendre aux supports effectivement annoncés, retraits et erreurs remontées ; ne pas confondre interruption de processus et perte d'alimentation. Évaluer NAS/réseau avant support, sans relâcher les protections existantes par simple nom de système de fichiers.
7. Linux : maintenir les tests du coordinateur, de `Control1.Lock()`, de logind et de l'instance unique ; compléter la couverture des déclencheurs et transitions système sans assimiler les services simulés à une transition réelle.
8. JavaScript : exécution explicite des cinq tests existants avec `node --test tests/extension/*.test.cjs`, puis commande de projet et version minimale de Node documentées. Les tests restent hors CTest.
9. Distribution : rendre reproductibles l'installation et les essais avec application, workers, manifeste et extension ; tester les versions incompatibles ou auxiliaires manquants. Les premières campagnes Firefox/Linux locales ne remplacent pas cette validation.
10. Portabilité : vérifier le transfert complet avec registre neuf et l'indépendance des copies (section 5). Lorsque nécessaire, tester les migrations interrompues ; ne pas ajouter des tests de confiance entre machines pour un modèle abandonné.

**Jalons et réserves :** l'historique chiffré reste dans la documentation technique, section 6.2 : bilan 6A rapporté de 426 cas, dont passage 65/65 alors insuffisant pour clôturer l'intermittence. L'intervention suivante l'a diagnostiquée et corrigée dans les tests : 66/66 `AutomaticBackupTest`, 23/23 `BackupJobTest`, 13/13 `VaultOperationGuardTest`, soit 102 cas distincts réussis en 44,04 s, plus 30 répétitions isolées de chacun des deux ordres (60 exécutions en 5,58 s, pas 60 cas distincts supplémentaires). Ces validations sont ciblées, hors sandbox ; elles ne prouvent ni une campagne complète actuelle ni une nouvelle exécution JavaScript.

**Validation 6A-bis clôturée le 9 novembre :** 41 nouveaux cas, `VaultReplacementTest` 73/73 ; au terme des sélections, 472 cas distincts validés, sans échec restant ni test ignoré. La documentation technique, section 6.2, donne les résultats par périmètre et les trois échecs initiaux de harnais corrigés : usage incorrect de l'insertion de métadonnées dans un nouveau test, puis absence d'initialisation de libsodium dans deux tests SQLite lancés en processus isolés (confirmée par GDB). La sélection finale remplacement/ressources a réussi 97/97 ; GUI 123/123 ; les autres régressions ciblées ont réussi. Ne pas additionner les reprises aux cas distincts ni présenter les transitions de registre modélisées comme un remplacement atomique réel. Maintenir ces tests en 6B ; le défaut initial de suppression prématurée de l'intention est corrigé dans ce périmètre, pas une certification globale de stockage.

**Validation 6B clôturée le 9 novembre :** **62 nouveaux cas** (55 moteur, 7 interruptions de sous-processus), ajoutés aux 73 contrats 6A/6A-bis : dernière sélection remplacement 135/135. Les régressions métier/stockage/sauvegardes passent 276/276 et la sélection GUI pertinente 38/38, soit **449 cas ciblés distincts validés, sans échec restant ni test ignoré**. Les détails et les défauts initiaux de harnais corrigés sont dans la documentation technique, section 6.2. Les tests utilisent des fichiers fictifs réellement échangés et une reprise dans un processus neuf, pas seulement des transitions modélisées. Ils couvrent notamment la précaution non confirmée, les deux dispositions `armed`, les erreurs de finalisation, les identités/empreintes et les chemins de l'appelant figés avant callback. Les réexécutions et résultats historiques ne sont pas additionnés ; aucune suite CTest complète, panne électrique, nouvelle transition Linux réelle ou validation du futur worker n'est revendiquée. `git diff --check` est sans erreur ; étape 7 prochaine, étape 8 ouverte.

Pour chaque changement technique : point Git initial, modification ciblée, compilation et tests adaptés au périmètre, inspection du diff et consignation du résultat. Préciser si la validation est ciblée ou complète, et ne pas assimiler des essais manuels à une suite automatisée.

Les anciens échecs `EPERM` de sockets dans le sandbox ne sont pas une preuve de régression applicative. Lors de cette intervention, la présentation de `/tmp` comme propriété de `nobody` y empêchait aussi l'initialisation sûre des sauvegardes ; ne pas contourner les contrôles de chemins pour faire passer les tests. Les régressions ont été exécutées dans l'environnement autorisé. L'intermittence de rotation est un incident distinct, désormais résolu dans son harnais.

## 7. P2/P3 — Fonctionnalités et plateformes

Le générateur de mots de passe est implémenté, intégré à l'interface et testé. TOTP, passkeys et audit des mots de passe restent à développer. Les paramètres, l'ergonomie, la recherche et la gestion des erreurs doivent être repris selon les besoins produit, sans masquer les interfaces de l'étape 8 encore absentes. Aucune synchronisation entre copies n'est engagée dans cette feuille de route.

L'intégration aux applications locales a été reportée après stabilisation du coffre et de Firefox.

Ordre des plateformes : Linux d'abord ; Windows via VM pour les tests ; iOS différé.

La campagne Firefox manuelle du 6 novembre et le bilan du verrouillage Linux du 7 novembre concernent l'installation locale Raspberry Pi 5 / Debian 13 / labwc uniquement. Les validations Windows et des autres plateformes prévues restent à réaliser.

La reproductibilité Linux doit également couvrir `passwall_backup_worker` à côté de l'application ; une future restauration asynchrone ajoutera son propre auxiliaire. Vérifier les versions réellement installées avant toute mise à jour, sans considérer les sources récentes comme automatiquement déployées.

## 8. Ordre de travail recommandé

1. **P0 — Mémoire :** maintenir le durcissement clos et `CredentialSummary` ; vérifier les nouveaux chemins sensibles au fur et à mesure, sans recommencer les corrections validées.
2. **P0 — Firefox :** maintenir l'implémentation unique et l'invalidation ; préparer l'extension de validation déterministe au parcours réel et l'automatisation de bout en bout.
3. **P0 — Verrouillage :** conserver les protections Linux/éditeurs/minuteur ; assurer leur articulation avec les opérations longues, sans réintroduire de garde globale abandonnée.
4. **P1 — Maintien de 6B :** conserver le moteur synchrone, les preuves de remplacement réel, la copie préalable conditionnelle, l'ancien inode et la reprise sans seconde substitution ; ne pas élargir son usage à la GUI ou à un worker sans le contrat de délégation suivant.
5. **P1 — Étape 7, prochain chantier :** délégation limitée de l'autorisation, auxiliaire de restauration, canal secret, `SecureBuffer`, annulation/verrouillage de sécurité, supervision et terminaison réelle ; aucune GUI dans cette étape.
6. **P1 — Étape 8 :** préférences/reprise, GUI de restauration et confirmation, choix de copie de précaution, récupération contrôlée, export de configuration et verrouillage automatique obligatoire. Les interfaces indépendantes peuvent avancer séparément ; le parcours de restauration dépend de 6B et 7.
7. **P1 — Validation et distribution :** campagne adaptée aux changements, audit global V1, portabilité des copies et déploiement Linux/Firefox/auxiliaires reproductible, avec tests JavaScript. Ne pas annoncer les supports réseau ou autres plateformes avant validation.
8. **P1 — Évolutions de données :** développer les migrations lorsqu'une transition de format le nécessitera. Aucun chantier de synchronisation, serveur de référence ou autorisation d'appareil n'est décidé.
9. **P2/P3 — Produit et plateformes :** TOTP, passkeys, audit et ergonomie ; étendre les plateformes dans l'ordre Linux, Windows, puis iOS.

Chaque étape fonctionnelle doit disposer de ses critères d'acceptation et tests ciblés. Les invariants P0 s'appliquent à toutes les étapes ; ils ne retardent pas artificiellement les P1 en l'absence de nouveau défaut.

## 9. Incertitudes à lever dans le dépôt

- délégation de l'autorisation et auxiliaire asynchrone 7 ; interfaces/finalisation utilisateur 8, dont récupération des états `prepared`/`armed` avant échange et nettoyage éventuel des anciens artefacts avec preuves ;
- conversion des anciennes valeurs de minuteur 10 ou invalides lors du passage obligatoire à 1/5/15/30/60 ; la conversion de « Désactivé » vers 1 et le nouveau défaut 1 sont déjà décidés ;
- validation complète d'une copie transférée sur configuration neuve et sur les futures plateformes, sans affaiblir la récupération 6A ;
- limites de nettoyage des nouvelles tâches sensibles et comportement sous E/S durablement bloquée ;
- comportement/durabilité sur chaque support annoncé, notamment avant une éventuelle ouverture aux NAS ;
- couverture globale au-delà des suites ciblées rapportées, automatisation Firefox et validation réelle des transitions logind ;
- correspondance des exécutables installés avec les sources récentes et procédure reproductible complète ;
- spécification détaillée des migrations lorsqu'une évolution de format l'exigera ; aucun moteur n'existe.

Les composants déjà vérifiés ne sont pas des incertitudes à rouvrir : voir le bilan de la documentation technique, sections 5 et 6. L'autonomie cryptographique et l'absence de dépendance au registre d'origine ressortent de la lecture du code ; cela ne dispense pas des protections de l'installation destinataire ni des tests complets de transfert. Synchronisation automatique, autorisation d'appareil et serveur de référence ne sont pas des travaux différés déjà décidés.

L'installation locale manuelle et les campagnes réelles Firefox/Linux sont des jalons rapportés, non réexécutés ici. L'installation du coordinateur, la surcharge utilisateur de `Ctrl+Alt+L`, le maintien du pilote et les succès de la section 3.4 sont établis dans ce périmètre historique local. `SessionGuard1` est définitivement supprimé ; une garde globale persistante, une authentification globale ou une modification de swaylock/labwc ne sont pas des travaux en attente. La porte de récupération par coffre de 6A ne contredit pas cette décision. Les limites de mémoire, de couverture des déclencheurs et de comportement sous défaillance restent ouvertes.

Ne pas résoudre ces incertitudes par supposition : inspecter le dépôt et consigner les observations.

## 10. Critères de candidature à une première version

Avant une première diffusion : chiffrement et formats documentés ; maintien des tests du cycle de vie, de corruption et de mémoire ; audit global V1 avec risques résiduels explicites ; flux Firefox unique préservé, installation reproductible et validation automatisée de bout en bout au-delà des essais manuels ; invalidation composant existante conservée et entrelacements d'intégration vérifiés ; couverture du verrouillage système étendue au-delà des raccourcis déjà validés localement, avec limites documentées ; sauvegardes exposées et rétention sans anomalie non qualifiée ; restauration V1 complète avec récupération et résultats incertains correctement traités ; politique de refus des formats incompatibles et migrations testées si une transition est nécessaire ; absence de secrets dans les logs ; plateformes et supports annoncés testés.

Les fonctionnalités déjà réalisées ne sont pas à reconstruire. Les lacunes produit (étapes 7 et 8, dont minuteur obligatoire, puis distribution) et l'absence de campagne complète récente empêchent de confondre l'état courant avec une V1 prête à diffuser. Le moteur 6B et la correction ciblée du test de rotation ne valent pas certification exhaustive du stockage. La perte du mot de passe maître n'a pas de mécanisme de contournement ; une sauvegarde ne crée pas une récupération cryptographique sans ce mot de passe. Aucun mécanisme de confiance entre machines n'est un critère de cette V1.
