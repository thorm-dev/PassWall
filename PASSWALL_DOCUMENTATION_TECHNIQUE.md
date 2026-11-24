# PassWall — Référence technique unique

**Révision documentaire :** 24 novembre 2026 — consolidation de l'audit et clôture R1a / R1b / R1c / R1d (déclencheurs unifiés, numérotation générationnelle et rotation sans lecture des anciennes copies).

**Version applicative relevée dans CMake :** 1.29.0. **Format de coffre actuellement implémenté :** V1. **Format cible validé :** V2 (non implémenté dans les sources auditées).

**Plateforme prioritaire :** Linux ARM64, Raspberry Pi 5, Debian 13, Qt 6. **Périmètre :** état du code fourni, décisions cible et plan de développement proposé.

## 1. Lecture de la référence et statuts

Les sections 1 à 12 ci-dessous constituent la référence normative actualisée. L'annexe historique H conserve intégralement le contenu technique antérieur et les résultats de validation rapportés, pour ne pas perdre les détails utiles à la refonte. Les décisions de l'annexe H sont datées du 23 novembre 2026 : lorsqu'elles contredisent les sections actuelles, elles sont **supplantées**. Les mentions de production, de cible, de travaux restants et les renvois numérotés internes de cette annexe décrivent uniquement cette révision ancienne. Ne pas s'en servir pour réintroduire un comportement abandonné.

- **VALIDÉ** : approuvé par l'utilisateur ; ne signifie pas implémenté.
- **IMPLÉMENTÉ** : présent dans les sources examinées, sans préjuger du résultat d'un essai.
- **TESTÉ** : résultats effectivement exécutés et rapportés, dans le périmètre indiqué.
- **À FAIRE** : développement ou validation restant.
- **À DÉFINIR** : détail non arbitré ; ne pas inventer une décision ni traiter une piste comme une exigence définitive.

Audit statique des archives `passwall_src.zip`, `tests_passwall.zip`, `firefox_extension_passwall.zip`, de `CMakeLists.txt`, de l'arborescence et des deux documents du projet. Aucun fichier source n'a été modifié ni compilé, aucun test exécuté pendant cet audit. Les résultats historiques restent rattachés aux états du code auxquels ils se rapportent. Les binaires effectivement installés sur la machine n'ont pas été vérifiés. Depuis cet audit, R1a à R1d ont été réalisés (voir §12.1–12.3). Les résultats postérieurs à l’audit sont identifiés séparément. Avant chaque intervention, vérifier la correspondance des sources et préserver les modifications locales, y compris non suivies.

## 2. Produit, environnement et frontières

**VALIDÉ.** Gestionnaire personnel de mots de passe, C++20 / Qt 6 Widgets / libsodium / SQLite, utilisable hors ligne sur chaque appareil. Aucun serveur, aucune synchronisation ni fusion interappareils, aucun enrôlement ou révocation d'appareil. Un fichier de coffre autonome peut être déplacé entre machines compatibles ; ses copies peuvent diverger. Pas de récupération cryptographique sans maître. Linux d'abord, Windows après stabilisation, iOS ultérieurement. Firefox reste le navigateur cible. TOTP, passkeys et audit des mots de passe restent à développer ; intégrations applicatives supplémentaires reportées. Ne pas les considérer livrés par les fondations actuelles.

**IMPLÉMENTÉ.** Création/ouverture/verrouillage, CRUD, générateur, Firefox Native Messaging, logind, sauvegarde/export/rotation et restauration par worker. Le constructeur Linux de `MainWindow` utilise `BackupTriggerMode::Generational` (`src/gui/main_window.cpp`, vers 564–567). CMake relie `passwall_app` aux services de rotation, préférences globales et contrôleur de statut (vers 497–519). L'ancienne voie `Historical`, le registre et leurs dépendances existent encore. L'activation de production constatée statiquement ne signifie ni installation effective ni validation complète.

Environnement relevé : Raspberry Pi 5 8 Go, Debian 13.7 ARM64, labwc/wlroots/Wayland, GCC 14.2.0, CMake 3.31.6, Ninja 1.12.1, Qt 6.8.2, libsodium 1.0.18, SQLite 3.46.1, Git 2.47.3. Les versions sont des relevés, pas des exigences universelles. CMake est source de la version applicative ; le numéro de format de coffre en est indépendant.

**VALIDÉ — transition de développement.** Tous les coffres actuels sont des coffres de test jetables. Aucune migration ni compatibilité avec ces données de test n'est requise lors du basculement. Ne pas détruire automatiquement de fichiers utilisateur. Refuser explicitement les formats incompatibles. Pour les futures versions réelles, toute migration doit faire l'objet d'une spécification et d'une validation distinctes (sauvegarde, compatibilité, erreurs, absence d'ouverture normale d'un format non supporté).

## 3. Sauvegardes et préférences (A01, A02, A04–A07, A09, B01–B05, L04)

### 3.1 Architecture unique et identité

**VALIDÉ.** Préserver le moteur générationnel et retirer le moteur historique, catalogue, préférences par coffre et registre permanent. Aucun nouveau registre de coffres, de mutations, de sauvegardes ou de récupération. Préférences globales ordinaires, non indispensables à l'ouverture d'un coffre sain ; racine choisie et rétention de sept versions par défaut, minimum sept, sans plafond de produit arbitraire. Configuration absente/invalide : avertir, permettre reconfiguration, ne pas annoncer de sauvegarde opérationnelle. Les anciens supports/racines ne sont ni déplacés ni nettoyés automatiquement. Ne pas modifier les permissions de la racine choisie.

Conserver `vault_id` (16 octets) comme identifiant de famille et `series_id` stable par installation/famille pour isoler les séries, sans liaison cryptographique à la machine. Le chemin, inode et périphérique ne servent qu'aux contrôles physiques transitoires. Déplacer/renommer un coffre fermé sur la même installation ne change pas sa série. L'absence d'un enregistrement permanent ne doit pas empêcher son usage. La série n'est pas une preuve d'authenticité. Copies divergentes sur même installation et clones d'identité peuvent partager une série : limites connues ; pas de synchronisation ou mécanisme spécial de fusion. Les détails d'identité de plateforme sont à vérifier lors du portage Windows.

**À FAIRE.** Découpler stockage/préférences ; éliminer les dépendances historiques après transfert des protections utiles (dont fonctions partagées de `BackupRotationService`). Conserver des préférences ordinaires nécessaires, par exemple `lastPath` en tant que commodité, jamais autorisation. L'absence de `lastPath` n'empêche pas l'ouverture.

### 3.2 Déclenchement — B02 annule la première copie sur inspection

**VALIDÉ.** Un seul moteur d'instantané et de supervision pour trois déclencheurs : modification métier confirmée, demande manuelle de nouvelle sauvegarde, relance manuelle après incident. L'export indépendant (emplacement choisi) reste distinct et ne déclenche pas la rotation de la série gérée.

- Seuls les `COMMIT` métier confirmés alimentent le suivi volatile des modifications. Un brouillon, un échec/rollback ou une simple lecture ne déclenche pas de sauvegarde automatique. Chaque nouveau commit repousse l'échéance de regroupement de 20 secondes. Une mutation postérieure à la couverture effective de l'instantané reste en attente jusqu'à couverture confirmée.
- Nouveau coffre vide : aucune sauvegarde automatique à la création, configuration, ouverture ou verrouillage. Les premières entrées enregistrées déclenchent le mécanisme habituel. Un coffre peuplé ouvert sans modification ne déclenche pas de copie, même si aucune sauvegarde n'existe, si la racine a changé ou si l'utilisateur a supprimé toutes les anciennes copies. Il peut demander une sauvegarde manuelle. Cette règle remplace explicitement l'ancienne exception de première copie sur inspection initiale.
- Si verrouillage ou fermeture intervient avant les 20 secondes et qu'un besoin confirmé reste en attente, rendre ce besoin immédiatement éligible, sans créer de doublon. Le verrouillage n'attend pas la copie ni la rotation. Une session déjà verrouillée ne lance pas de sauvegardes périodiques : seuls les besoins déjà admis/en attente peuvent se poursuivre.
- Aucune inspection d'intégrité ou comparaison rétrospective des sauvegardes, ni au démarrage, ni au déverrouillage, ni après plantage. **IMPLÉMENTÉ et TESTÉ dans le périmètre R1b** : retrait de `InitialBackupPreparer`, `InitialCopy`, de leurs relances et états GUI associés ; les contrôles utiles de préparation de destination et d'instantané restent en place. Voir §12.1. La suppression des lectures du contenu des anciennes générations pendant la rotation générationnelle est également **IMPLÉMENTÉE et TESTÉE (R1d-2, §12.3)** ; ne pas confondre ces lectures supprimées avec les contrôles de noms et métadonnées physiques nécessaires à la rotation. Après crash, l'utilisateur vérifie le principal et peut demander une nouvelle sauvegarde. Aucun rattrapage automatique et aucun historique persistant de besoins perdus.
- Après `Failed` ou `Unknown`, signaler l'incident ; suspension volatile des nouvelles tentatives automatiques pendant la vie du processus, suivi des commits non couverts. Aucune boucle de retry. Relance exclusivement explicite, après terminaison effective du worker précédent, avec revalidation des conditions et nouveau travail complet, pas de reprise d'un instantané interrompu. Afficher réussite seulement après publication confirmée. Une nouvelle modification après redémarrage est un nouveau déclencheur normal, non un rattrapage d'une erreur ancienne.
- **IMPLÉMENTÉ et TESTÉ (R1c, §12.2).** Sauvegarde manuelle volontaire accessible par « Sauvegarder maintenant » dans la fenêtre d’état des sauvegardes, sans échec ni modification préalable, depuis une session authentifiée et une configuration valide. Une demande explicite peut viser un coffre vide ; aucune sauvegarde automatique de coffre vide. Si le regroupement de commits est en attente, la demande l’accélère sans doublon ; une opération de sauvegarde déjà en attente d’admission ou active empêche une nouvelle demande. Après incident, utiliser la relance explicite existante. Les trois déclencheurs empruntent le même circuit générationnel, sans faux COMMIT ; l’export indépendant reste distinct. Les besoins déjà admis peuvent finir après verrouillage sans clé secrète. **À DÉFINIR pour V2** : disponibilité et durée de confiance de la clé publique de vérification.

### 3.3 Verrouillage et fermeture — A02 / L04

**VALIDÉ.** Distinguer verrouillage du coffre et fermeture de l'application. Sur demande de verrouillage, empêcher immédiatement de nouvelles opérations sensibles, terminer proprement les transactions engagées (commit ou rollback, sans attente indéfinie), invalider session, fermer et nettoyer les brouillons non validés, effacer les secrets. Sauvegardes et rotations sans secret peuvent poursuivre leur travail. Le coffre n'attend pas la fin de la rotation.

Sur demande de fermeture avec besoin de sauvegarde, accélérer ce besoin et attendre asynchronement la fin effective de la publication/rotation. Ne pas provoquer un verrouillage prématuré du seul fait de la demande de fermeture : le délai normal d'inactivité, les transitions de sécurité Linux et le verrouillage manuel restent applicables, sans extension artificielle du délai. Une fermeture normale sans incident se termine après la vidange. Sur échec/incertitude, maintenir l'application ouverte, expliquer le problème (support indisponible, disque plein, etc.) et permettre une relance manuelle. Pas de réauthentification si le coffre est toujours normalement déverrouillé ; sinon nouvelle authentification. Après réussite de cette relance, l'utilisateur décide de verrouiller ou quitter ; pas de fermeture automatique liée à la relance. Ne pas effacer la mémoire des besoins confirmés par une fermeture répétée. **À DÉFINIR** : ergonomie exacte de la fermeture après incident persistant et possibilité de quitter sans nouvelle sauvegarde ; aucune contrainte bloquante indéfinie.

**IMPLÉMENTÉ à corriger.** `main_window_export.cpp::closeEvent()` verrouille actuellement immédiatement au premier drain générationnel et désactive la GUI. Ce comportement n'est plus la cible.

### 3.4 Publication et contrôles — B03/B04

**VALIDÉ.** Copies SQLite cohérentes et autonomes conservant `vault_id`, sans transmettre la clé de déchiffrement ni le maître au worker de sauvegarde. Contrôler la nouvelle copie (cohérence SQLite, format attendu, identité, preuve de publication et durabilité demandée à l'OS). En V2 étudier et spécifier Ed25519 pour vérifier cryptographiquement la copie nouvellement créée, sans clé secrète dans le worker ; voir §5. Le contrôle structurel actuel ne prouve pas l'authenticité. Contrôler l'intégrité d'une sauvegarde existante uniquement lorsque l'utilisateur demande sa restauration (ou ouvre explicitement cette copie comme coffre : authentification normale de son contenu, pas audit automatique de la série). Aucun examen structurel/cryptographique systématique des anciennes générations durant la rotation. **IMPLÉMENTÉ et TESTÉ (R1d-2, §12.3)** sur le chemin générationnel : `BackupSeriesInspector` liste les noms et relève les métadonnées physiques, sans lire SQLite, le `vault_id` ni les empreintes des anciennes copies ; la rotation utilise notamment `O_PATH` pour maintenir une référence physique sans accès en lecture au contenu. La nouvelle publication reste contrôlée par sa preuve et un contrôle structurel ciblé avant rotation. La présence de compagnons SQLite (`-journal`, `-wal`, `-shm`) entraîne un refus de rotation sans lecture de leur contenu. Les chemins historiques restent à retirer (R1e).

La rotation ne commence qu'après publication confirmée (`Published` et preuve transitoire adéquate). Un fichier visible, une tentative ou la fin d'un processus ne suffit pas ; `Failed`/`Unknown` n'autorisent aucune suppression. Les résultats publication et rotation restent distincts ; échec de rotation n'annule pas la publication réussie. Préserver réservations, revalidations physiques, supervision jusqu'à terminaison, diagnostics et synchronisations nécessaires. Aucun ancien fichier ambigu, hors série ou dont l'identité attendue a changé ne doit être supprimé. Ne jamais modifier le principal pour pallier un échec de sauvegarde.

**VALIDÉ B03.** Favoriser compatibilité des clés USB et systèmes de fichiers courants, nomenclature unique et protection native sans écrasement lorsqu'elle est disponible ; aucune complexité disproportionnée pour les interventions extérieures marginales. Conserver les garanties contre le chevauchement de nos propres opérations (instance Linux unique, un worker de sauvegarde à la fois). Étudier une publication native équivalente à `linkat()` sur des systèmes sans liens physiques (piste `renameat2(RENAME_NOREPLACE)` sous Linux, à tester). Ne pas prétendre à des garanties indisponibles sur un support ni dégrader silencieusement la sécurité. **À DÉFINIR** : liste de systèmes supportés, permissions appropriées et garanties réelles de publication/durabilité, traitement explicite en l'absence d'une primitive native équivalente. Aucun nouveau coordinateur complexe ; les manipulations externes du répertoire relèvent de l'utilisateur.

### 3.5 Ordre des générations — B05

**VALIDÉ.** Dans `racine/vault_id/series_id/`, le numéro de génération croissant détermine l'ordre, pas la date UTC. La date peut rester informative. Au moment de créer une nouvelle copie, déterminer le plus grand numéro valide à partir des noms des fichiers présents dans la série, puis ajouter un ; première génération 1 si série vide. Les trous dus à des suppressions ne changent pas la règle ; si toutes les copies sont retirées, repartir de 1. Aucun compteur persistant, appel NTP, réseau, ouverture du contenu des anciennes copies ou surveillance du répertoire. Lors de la rotation, identifier les fichiers gérés, classer les numéros, calculer les excédents, protéger la nouvelle copie et revalider l'identité physique des cibles de suppression. En cas d'ordre ambigu, débordement, incohérence détectable ou preuve insuffisante, ne pas supprimer. Préserver les fichiers non reconnus, y compris les anciennes nomenclatures ; aucune migration automatique des copies de test n'est nécessaire. **IMPLÉMENTÉ et TESTÉ (R1d-1, §12.3)** : nomenclature `generation_<numéro>_<yyyy-MM-dd_HH-mm-ss>.pwdb` (UTC), parseur strict commun dans `backup_generation_name.hpp`, numéro positif `quint64`, refus de produire un numéro supérieur au maximum représentable. Le préparateur calcule le maximum des noms valides ; la rotation refuse les doublons et les noms invalides revendiquant la convention `generation_*.pwdb`. Les noms anciens et objets hors convention sont préservés et exclus de la rétention générationnelle ; les fichiers auxiliaires hors convention ne rendent pas à eux seuls le classement ambigu (sauf compagnons SQLite, voir §3.4). Les noms ne sont pas une preuve cryptographique de l’ordre réel : un fichier étranger placé dans la série sous un nom valide et satisfaisant les contrôles physiques peut être compté et supprimé comme une génération ; une copie altérée après publication peut compter dans la rétention. Le renommage externe, les manipulations manuelles du répertoire et le remplacement intégral authentique restent hors garantie. La détection cryptographique lors de la restauration relève notamment du futur V2.

### 3.6 Consultation et copies indépendantes

Décisions antérieures conservées : consultation d'une sauvegarde gérée en lecture seule (avec authentification normale si l'utilisateur la sélectionne), modification uniquement sur copie de travail hors zone gérée. Copie indépendante et export conservent `vault_id`. Aucun CRUD ni suivi de mutation sur sauvegarde gérée en lecture seule ; désactiver seulement les boutons n'est pas suffisant. Aucune ouverture automatique après export ou restauration. **À FAIRE** : confirmer le parcours réellement implémenté et développer les protections manquantes. **À DÉFINIR** : ergonomie de la consultation depuis une ancienne racine sans inspection automatique.

## 4. Restauration et suppression du registre (A03, A04, A06, B06)

**VALIDÉ.** Restauration explicite = remplacement intégral, aucune fusion. Aucun journal permanent d'intentions/phases/reçus, ni procédure persistante de reprise après interruption, ni copie de précaution supplémentaire obligatoire ou facultative. Ne pas supprimer les journaux transactionnels internes de SQLite. Préserver la sauvegarde source et l'ancien principal par l'échange atomique ; l'export indépendant n'est pas une étape imposée de restauration.

Conserver le moteur unique de remplacement, authentification complète du fichier source (MAC V2 compris), réservation et autorisation opaque transitoire liée à la confirmation explicite et à la session, verrouillage et nettoyage du principal avant l'autorisation de remplacement, canal privé pour le maître, supervision des secrets et revalidation des identités. Préparer un candidat complet sur le système de fichiers du principal, échanger atomiquement (sur Linux, primitive appropriée prise en charge), demander les synchronisations nécessaires. Distinguer succès confirmé, durabilité incertaine, annulation et résultat inconnu ; pas de réparation destructive, nouvel échange automatique ni reconstitution d'un historique indémontrable. Après interruption, examiner le fichier principal présent lors de l'ouverture explicite, authentifier normalement et demander une nouvelle confirmation pour toute nouvelle restauration. Conserver l'ancien principal et la source ; rester verrouillé après remplacement. La restauration manuelle d'un principal corrompu dont le `vault_id` est illisible reste possible avec confirmation renforcée et vérification de la source/destination.

Le registre actuel mêle préférences, état historique et autorisation de récupération. Retirer seulement après remplacement cohérent de ses responsabilités et protection du passage de l'ancien état au nouveau. Les données actuelles sont jetables, mais aucune suppression automatique d'artefact utilisateur n'est autorisée. La perte des préférences ordinaires ne doit jamais rendre un coffre sain inutilisable dans la cible. **À DÉFINIR** : emplacement/nom/diagnostic de l'ancien principal, traitement explicite des anciens états résiduels, confirmation du principal corrompu, plateformes sans échange atomique, conduite exacte sur interruption et durabilité inconnue. Ne pas introduire un repli non atomique silencieux.

## 5. Cryptographie et format V2 (C01–C04, B04)

### 5.1 Fondations V1 constatées

**IMPLÉMENTÉ.** Argon2id (`crypto_pwhash_ALG_ARGON2ID13`, production 3 opérations, 256 Mio), XChaCha20-Poly1305 par entrée, nonce aléatoire, clé de données DEK enveloppée sous une clé dérivée du maître, sel et paramètres publics nécessaires à la dérivation. `vault_metadata` expose notamment version, `vault_id`, sel, paramètres, nonce et DEK enveloppée ; `entries` expose identifiants, version, nonce et ciphertext. Un lecteur SQLite externe peut lire la structure, pas déchiffrer les secrets sans clé. Les tags par entrée ne détectent pas nécessairement la suppression d'une ligne ou le rejeu d'une ancienne ligne authentique. Préserver ces primitives et paramètres sauf justification et décision explicite. Le fichier peut être copié/modifié/détruit par quiconque dispose des droits OS ; le chiffrement n'empêche pas matériellement ces actions.

### 5.2 Maître et résistance aux essais — C01

**VALIDÉ.** Minimum de 15 caractères pour le maître ; maximum proposé et retenu lors de l'audit de 256 caractères, traitement exact des espaces et Unicode, pas de composition artificielle, pas de changement périodique forcé. Contrôle local de robustesse et liste locale de mots de passe courants/faibles/compromis, sans envoyer le maître ni son empreinte à un service. Bulle d'aide « ? » : recommander notamment des mots tirés au hasard, uniques, mémorisables, absence de récupération ; ne pas présenter une phrase humaine prévisible comme équivalente à un tirage aléatoire. Générateur local de phrases de passe de six mots aléatoires par défaut, en complément du générateur existant (8–128 caractères). Utiliser un générateur cryptographiquement sûr. **À DÉFINIR** : liste de mots et licence, méthode de contrôle local, règles Unicode exactes, messages et parcours concernés (création/changement du maître, pas de blocage de lecture d'un format autorisé par simple modification des règles de création).

Délai progressif après échecs consécutifs : 1, 2, 4, 8, 16 puis 30 secondes, plafonné à 30 ; compteur visible, UI non bloquée, réinitialisation après authentification réussie. Pas d'effacement ni blocage définitif. Cette protection ne ralentit que les tentatives effectuées via PassWall, pas un attaquant possédant une copie du fichier. **À DÉFINIR** : portée du compteur et cohérence entre parcours d'authentification, gestion des erreurs non liées au mot de passe. Aucun nouveau registre persistant implicite. La protection hors ligne repose surtout sur Argon2id et le maître.

### 5.3 Authentification du contenu — C02

**VALIDÉ.** MAC global 256 bits stocké à l'intérieur du même fichier SQLite. Clé dédiée dérivée de la DEK avec séparation de domaines, jamais enregistrée en clair. Couvrir une représentation canonique non ambiguë des métadonnées logiques pertinentes et de l'ensemble des entrées, y compris identifiants, valeurs et leur présence/absence ; pas seulement les ciphertexts isolés. Vérifier avant admission de la session et avant toute opération qui pourrait accepter/re-signer un contenu altéré ; contrôle et mutation sous une frontière transactionnelle/physique cohérente, mise à jour du MAC dans la même transaction que le CRUD. Échec d'authentification : refuser accès et modifications, diagnostic sûr ; ne jamais recalculer une preuve sur un état non authentifié pour le rendre acceptable. Le MAC reste dans le coffre, sans liaison machine ni fichier annexe. Un ancien coffre complet et authentique peut être rejoué sans référence externe de confiance ; limite acceptée. La destruction physique et la disponibilité du fichier ne sont pas garanties par le MAC.

**À DÉFINIR avant codage V2** : primitive MAC, KDF/domaines de sous-clés, encodage canonique versionné, données exactement couvertes, initialisation du coffre vide, vérification avant lectures/écritures/restauration, gestion des accès concurrents, erreurs, performances sur Pi, compatibilité et tests de vecteurs. Ne pas introduire une construction cryptographique improvisée.

### 5.4 Vérification publique des nouvelles sauvegardes — B04

**VALIDÉ POUR ÉTUDE ET INTÉGRATION SI SÛRE.** Ed25519/libsodium : piste de signature du contenu logique chiffré, mise à jour atomique avec la mutation ; clé privée de signature dédiée dérivée de la DEK (séparation de domaines) et conservée en mémoire protégée seulement quand nécessaire. Le worker de sauvegarde reçoit au plus une clé publique fiable provenant d'un déverrouillage authentifié, pas la DEK, le maître ou la clé privée. Une clé publique lue aveuglément dans le fichier à vérifier n'est pas une ancre de confiance. Rejeter substitution simultanée clé/signature et lier la preuve à la bonne famille/source ; disposer d'un contexte public fiable jusqu'à la terminaison d'une sauvegarde admise après verrouillage. Pas de registre permanent ni de réseau. Lors d'une restauration, authentifier le coffre source par son maître et le format V2. Pas de vérification crypto des générations anciennes pour la rotation (B02), une altération ultérieure sera détectée à l'usage explicite ; elle peut réduire la rétention effectivement récupérable. Le MAC global C02 reste validé ; ne pas le remplacer par la signature sans décision explicite. **À DÉFINIR** : construction exacte, provenance/durée de vie et transport de la clé publique, comportement si absente, portée de la signature, intégration transactionnelle, coût, cas manuel verrouillé. Ne pas annoncer de vérification crypto réussie si non effectuée. Limite du rejeu intégral authentique acceptée.

### 5.5 Confidentialité des métadonnées — C04

**VALIDÉ.** Conserver SQLite et le moteur d'instantané sans clé. Chiffrer les métadonnées non indispensables avant authentification, limiter les informations publiques au strict nécessaire, ajouter du padding par paliers avant chiffrement pour masquer la taille exacte des entrées. Le sel, paramètres de dérivation, nonces et identité nécessaire au rangement ne deviennent pas secrets par simple convention. Taille globale, nombre d'entrées et certains paliers restent observables. Ni fausses entrées ni basculement SQLCipher à ce stade. **À DÉFINIR** : paliers, longueur encodée et vérifiée à l'intérieur du contenu authentifié, traitement des valeurs malformées, bornes avant allocation, impact sur sauvegardes et schéma V2. Regrouper les modifications de format dans V2 ; aucun nouveau format concurrent provisoire durable.

## 6. Secrets en mémoire (C03, M01–M05)

**VALIDÉ — C03/M02/M03.** Protection maximale proportionnée de toutes les informations sensibles : clés de dérivation/enveloppe/DEK/sous-clés, maîtres, identifiants, mots de passe, notes, futurs secrets TOTP et clés privées passkeys. Utiliser `SecureBuffer` comme infrastructure unique, notamment pour les maîtres de création/ouverture et clés encore en tableaux ordinaires. Étendre le nettoyage RAII aux exceptions, sorties anticipées, conversions et temporaires, réduire copies et durée de vie. Vérifier le verrouillage mémoire, étudier `sodium_mlock`, protection anti-swap, `sodium_mprotect_noaccess` hors utilisation et lecture seule si possible, effacement sécurisé, protection contre dumps et inspections (`PR_SET_DUMPABLE`, `MADV_DONTDUMP`/équivalents selon plateforme). Ne pas mettre en clair dans logs, arguments, environnement ou fichiers temporaires ; transport privé des secrets de restauration, buffers à durée limitée pour Native Messaging. **À DÉFINIR** : politique si l'OS refuse une protection, sans dégradation silencieuse ni gêne disproportionnée, interfaces de prêt mémoire et tests portables. Ne pas affirmer que RAII s'exécute après arrêt brutal ni que l'OS efface physiquement toute mémoire ; prévention et effacement maximal dans les limites du système et du matériel.

**VALIDÉ — M01.** Copie facile des mots de passe maintenue. Marquer systématiquement les copies sensibles avec le type MIME `x-kde-passwordManagerHint` pour gestionnaires compatibles. Effacement automatique après 30 secondes, sans conserver une seconde copie du secret pour comparaison ni surveillance permanente du presse-papiers. Ne jamais effacer un contenu ultérieur de l'utilisateur ; un jeton non secret propre à la copie est une piste, à vérifier sous Qt/Wayland, avec refus de l'effacement si appartenance incertaine. Préserver le nettoyage au verrouillage lorsqu'une copie PassWall est encore identifiable (comportement actuel à préserver sans comparaison de secrets). Centraliser les chemins de copie sensibles, y compris raccourcis si autorisés. Le marqueur ne contraint pas tous les logiciels ; un historique externe peut conserver le secret, PassWall ne peut pas le purger de manière garantie. **À FAIRE** : caractériser les copies natives Qt et tester les comportements. La commande de recherche des processus connus sur le Pi n'a renvoyé aucun résultat ; indice, pas preuve d'absence d'historique.

**VALIDÉ — M04.** Durcir les composants Qt : limiter historique/annulation, suggestions, prédiction, glisser-déposer, copies et durée de présence des secrets ; remasquage après délai à spécifier. Pas d'enregistrement implicite du brouillon. Les widgets masqués ne constituent pas une mémoire cryptographiquement protégée.

**M05** : audit Firefox réalisé séparément, voir §9. JavaScript et page web hors contrôle direct : ne pas promettre effacement garanti d'un secret déjà transmis.

## 7. SQLite et protection des fichiers (S01–S04)

**IMPLÉMENTÉ — fondations à conserver.** `journal_mode=DELETE`, `synchronous=EXTRA`, `secure_delete=ON`, `temp_store=MEMORY`, `busy_timeout=3000 ms`, `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` vérifié avant inspection, refus d'un mode WAL inattendu sans conversion/checkpoint volontaire, `BEGIN IMMEDIATE` pour mutations, diagnostics de commit/rollback et RAII. Création privée 0600 sous Linux. Ne pas supprimer les journaux transactionnels nécessaires ni promettre d'effacement physique sur SSD.

**VALIDÉ — S01.** Durcir chaque connexion concernée, y compris ouverture, CRUD, snapshot et restauration : mode défensif SQLite, `trusted_schema` désactivé, triggers/vues désactivés lorsque non nécessaires, chargement d'extensions désactivé explicitement, `ATTACH` interdit, schéma attendu strictement validé et vérification des résultats. Les contrôles de schéma doivent fonctionner avant usage d'un fichier potentiellement malveillant, sans les appliquer aux anciennes copies pendant une rotation. **À DÉFINIR** : ordre/configuration exacte compatible avec SQLite 3.46.1 et opérations légitimes ; vérifier que les primitives employées fournissent réellement la protection demandée.

**VALIDÉ — S02.** Contrôles homogènes des fichiers ordinaires, propriétaire, permissions privées, absence de liens symboliques et de liens physiques multiples hors opérations internes contrôlées, détection de substitutions, identités physiques transitoires ; aucun changement automatique des permissions utilisateur. Adapter aux plateformes/systèmes de fichiers avec garanties vérifiées. Pas de registre nécessaire. Alerter et refuser selon risque, sans prétendre que ces contrôles protègent absolument contre un processus du même UID.

**VALIDÉ — S03.** Réutiliser les mécanismes existants d'écriture/rollback, améliorer le résultat métier structuré et le traitement par la GUI. Disque plein, contention temporaire ou échec avec annulation confirmée sans indice de corruption : diagnostic et maintien de l'usage normal, nouvelle tentative possible. Résultat de transaction incertain : suspendre les écritures et vérifier l'état réel du coffre avant reprise, informer de l'incertitude. Corruption confirmée : interdire modifications et proposer restauration manuelle ; authentification cryptographique invalide : refuser utilisation du coffre. Pas de verrouillage systématique à chaque erreur, réparation destructive ou restauration automatique. Récupération transactionnelle SQLite normale autorisée. **À DÉFINIR** : codes d'état, frontière de vérification/reprise, contrôle d'intégrité structurelle à l'ouverture, traitement d'une transaction bloquée et interaction avec verrouillage. Les tests existants couvrant `SQLITE_FULL`, commit/rollback et interruption doivent rester.

**VALIDÉ — S04.** Réduire les anciennes limites (1 Mio par champ, 5 Mio sérialisés), sans troncature silencieuse. Limites fonctionnelles en caractères :

| Champ | Maximum |
|---|---:|
| Titre | 50 |
| Identifiant | 256 |
| Mot de passe | 256 |
| URL | 2 048 |
| Notes | 1 024 |

Titre, identifiant et mot de passe obligatoires. Préserver valeur exacte du mot de passe. Appliquer les mêmes règles à la GUI, service, sérialisation/désérialisation et entrées natives pertinentes ; limites techniques en octets UTF-8, sérialisation, padding V2 et messages calculées séparément. `sqlite3_limit()` et bornes appropriées avant allocations importantes, sans plafond arbitraire du coffre entier. **À DÉFINIR** : unité Unicode exacte, nombre maximal d'URL multiples par compte (limite de 2 048 par URL), budgets totaux de l'entrée et des réponses, SQLite, cas limites et futures fonctionnalités. Toute valeur proposée doit être compatible avec le générateur et les données légitimes.

## 8. Verrouillage et sessions (L01–L04, A08)

**IMPLÉMENTÉ.** Verrouillage manuel et automatique obligatoire, délais 1/5/15/30/60 minutes, défaut 1 minute, `QTimer` précis. Compteur de session volatile, invalidation du bridge et des éditeurs, nettoyage de la DEK, logind et coordinateur swaylock actuellement présents. Conserver les protections utiles.

**VALIDÉ — L01.** Une seule échéance monotone faisant autorité, pas deux chronomètres autonomes en concurrence. `QTimer` sert à réveiller et vérifier cette échéance (piste `QDeadlineTimer` ou équivalent natif Qt). Vérifier la même échéance avant toute opération sensible et avant réinitialisation pour empêcher une activité tardive de réouvrir implicitement une session expirée. Une interaction réelle dans PassWall (clic, frappe) repousse le délai, aucune activité externe au logiciel ni callback de travail de fond ne l'allonge artificiellement. Ne pas modifier les valeurs autorisées. Un thread complètement bloqué ne peut pas exécuter immédiatement son nettoyage.

**VALIDÉ — L02.** Conserver le compteur de génération d'autorisation en mémoire : nouveau lors du déverrouillage, inchangé pendant l'activité, invalidé au verrouillage ; aucune ancienne opération ne peut reprendre sur une nouvelle session. L'appliquer aux suppressions, confirmations, opérations asynchrones et accès sensibles. Ne pas imposer de durée supplémentaire ni de contrainte utilisateur ; tester la transparence d'usage et les cas de réentrance. Ce numéro n'est ni identifiant de compte, ni jeton persistant, ni mécanisme de synchronisation.

**VALIDÉ — L03/A08.** Retirer `passwall-session-lock` et ses dépendances devenues inutiles après essai du verrouillage du coffre au terme du délai normal lorsque swaylock est lancé directement et que le Pi reste éveillé. Le verrouillage du bureau n'est pas une responsabilité de PassWall. Conserver l'instance unique, logind et protections indépendantes suspension/hibernation/arrêt, y compris gestion de perte de service. Adapter l'admission au démarrage (`main.cpp`) avant retrait ; ne pas supprimer un service de contrôle encore nécessaire à d'autres consommateurs. Ne modifier aucun raccourci ni configuration système utilisateur sans autorisation. Si test réel non concluant, signaler et définir correction avant retrait. Pas d'obligation de détecter immédiatement le verrouillage direct du bureau dès lors que le verrouillage automatique continue normalement.

**VALIDÉ — L04.** Voir §3.3 : figer les nouvelles actions dès demande de verrouillage, terminer proprement transactions, ne pas enregistrer les brouillons, invalider/effacer les secrets. Sauvegardes/rotations sans secret continuent sans retarder le verrouillage ; fermeture attend les travaux nécessaires. Protéger les secrets de restauration même lorsque le coffre principal est déjà verrouillé ; révoquer/nettoyer lors d'une transition de sécurité, sans compromettre l'atomicité d'un échange déjà engagé. Secrets déjà transmis à Firefox hors contrôle direct (§9).

## 9. Extension Firefox (F01–F07)

**IMPLÉMENTÉ.** Firefox → extension → `passwall_native_host` → `NativeBridgeServer` → `NativeRequestProcessor`/GUI → coffre. Permissions `nativeMessaging`, `activeTab`, `scripting`, pas de script permanent ni stockage durable des secrets, pas de soumission automatique, déchiffrement ciblé et comparaison de l'origine. Le socket local est limité à l'utilisateur Linux, ce qui ne distingue pas suffisamment deux processus du même compte. Le code actuel utilise HTTP/HTTPS, limite messages à 1 Mio et force XWayland au lancement du logiciel. Le manifeste Native Messaging effectivement installé n'a pas été fourni pour inspection.

**VALIDÉ — F01/F02.** Conserver les permissions minimales ; toutes décisions sensibles appartiennent à PassWall. Étudier authentification du canal local, identité de l'interlocuteur, autorisations limitées et refus des requêtes non autorisées ; ne pas introduire un secret permanent dans l'extension. Ne pas considérer le seul UID, nom de programme ou identifiant d'extension comme une preuve absolue face à une compromission du même compte. **À DÉFINIR avant codage** : modèle de menace local, méthode d'admission, liaison à un échange autorisé, prévention du rejeu, vérification des processus et limites OS réelles, sans architecture disproportionnée. L'hôte natif est indispensable à l'architecture Firefox actuelle, mais sa surface d'attaque n'est pas nulle : intermédiaire minimal, sans clé du coffre, sans cache durable et sans décisions métier.

**VALIDÉ — F03.** HTTPS par défaut ; origine exacte (protocole/hôte/port). Éventuelle exception explicite pour services HTTP locaux à définir. Plusieurs URL par compte ; domaines tiers ajoutés manuellement uniquement, pas d'extension implicite de confiance aux sous-domaines/redirections. **À DÉFINIR** : représentation, validation, interface et plafonds des URL multiples.

**VALIDÉ — F04/F05.** Rechercher les champs standard d'identifiant et de mot de passe (formulaire ou groupe cohérent), vérifier destination déclarée si applicable, refuser si ambigu, ne pas essayer de couvrir toutes les méthodes exotiques. Vérifier un formulaire compatible avant de demander le secret ; ensuite récupération ciblée, dernier contrôle de l'origine, document, autorisation/session et champs juste avant injection ; aucun remplissage si les conditions ne sont plus valides. Minimiser copies/temps en JavaScript et connexions simultanées, aucun cache permanent. Pas de soumission automatique. PassWall ne peut pas reprendre ou effacer avec certitude un secret déjà accepté par le navigateur, le noyau ou le site. Les futures captures de nouveaux mots de passe et de changements devront avoir leur propre spécification de sécurité avant développement.

**VALIDÉ — F06.** Aucun indice d'existence d'un compte lorsque le coffre est verrouillé. Ni index de domaines accessible verrouillé, ni résultat de recherche révélateur, ni contournement de l'authentification. Déverrouillage via parcours autorisé possible, sans exposer de secret à l'extension. Cette décision annule toute ancienne exigence de détection des comptes lorsque verrouillé.

**VALIDÉ — F07.** Identifiant Firefox définitif (à choisir) et installation native reproductible avec liste d'extensions autorisées correcte ; garder le forçage XWayland pour le moment (problème d'affichage antérieur, ne pas retirer dans ce chantier). Adapter plafonds des messages variables aux limites S04, JSON/encodage et listes de comptes. Une seule connexion/requête active traitée à la fois, échanges ponctuels `sendNativeMessage()`, fermeture après réponse, durée maximale bornée et refus occupé ; pas de connexion permanente. **À DÉFINIR** : valeurs de taille/durée, gestion des réponses trop longues et du démarrage normal, installation/identifiant définitif. Ne pas introduire de nouvelle dépendance sans nécessité.

## 10. Architecture, construction et responsabilité (A05–A11, T01–T06)

**VALIDÉ.** Ne pas réécrire globalement PassWall. Garder séparation UI, services métier, crypto, stockage et workers de sauvegarde/restauration. Supprimer les branches historiques et la dépendance circulaire stockage/préférences après migration des responsabilités. Supprimer uniquement le code dont les dépendances directes et indirectes, CMake, tests et responsabilités ont été vérifiées. Aucune nouvelle architecture concurrente permanente. Les tests anciens spécifiques aux fonctions supprimées peuvent disparaître, jamais uniquement parce qu'ils échouent. Les tests mixtes sont adaptés pour conserver les garanties pertinentes.

**VALIDÉ A10/A11.** Rendre GTest nécessaire pour les tests seulement, pas une compilation de production seule ; conserver Qt DBus (logind), libsodium, SQLite, libsystemd tant que nécessaire à l'identité de série ; réexaminer nlohmann_json avec le Host sans imposer un remplacement. Corriger installation CMake incomplète (worker de sauvegarde et autres exécutables indispensables), puis installation reproductible de l'application, des workers et de Native Messaging/extension. Le coordinateur bureau est retiré après L03. Vérifier les exécutables réellement requis, versions et permissions. Supprimer les résidus `*~` après contrôle et ignorer ces fichiers dans Git si nécessaire. Les quatre résidus relevés sont `backup_destination_preparer.cpp~`, `backup_destination_preparer.hpp~`, `global_backup_preferences_store.cpp~`, `initial_backup_preparer.cpp~`. Ne pas supprimer de fichier non suivi sans vérifier qu'il ne contient pas de travail utilisateur.

**Responsabilités.** PassWall doit assurer chiffrement/authentification, transactions et vérification des résultats, permissions et contrôles disponibles, copie cohérente, signalement des erreurs, nettoyage des secrets sous son contrôle, refus des accès non autorisés et des suppressions incertaines. SQLite assure sa récupération transactionnelle selon son contrat ; OS et support assurent l'exécution des primitives de synchronisation, la protection du processus et le stockage physique. Utilisateur responsable de disponibilité/choix du support, sauvegardes indépendantes, manipulation manuelle des fichiers, sécurité de son environnement et maître choisi (encadré par l'application), vérification et sauvegarde manuelle après crash si nécessaire. Pas de garantie absolue contre compromission noyau/même UID, matériel défaillant, coupure, suppression volontaire, historique externe, rejeu intégral authentique ou copies déjà remises au navigateur. Ne jamais présenter une limite comme une réussite ni utiliser cette séparation pour omettre un contrôle raisonnable relevant de PassWall.

## 11. Stratégie de tests et critères de sortie (T01–T06)

**VALIDÉ — T01.** Préserver les essais de défaillances réelles et de sécurité (SQLite FULL, interruption avant/après commit, corruption/altération, substitution fichier, erreurs fsync, nettoyage après exception, verrouillage et autorisations expirées, snapshot cohérent sous écritures concurrentes, changement de source en restauration). **T02** : adapter les tests aux nouvelles frontières, supprimer les tests devenus purement historiques au retrait effectif de la fonctionnalité. **T03** : écrire les nouveaux tests dans chaque lot, avec échec, annulation, interruption, limites et transitions. Ne pas masquer avertissements/échecs.

Inventaire statique rapporté : 37 fichiers de tests C++, 1 134 déclarations GoogleTest, 5 cas JavaScript ; pas une mesure de couverture ni une garantie du nombre de cas CTest exécutables. **T04** : les tests JS de navigation reproduisant la logique doivent exécuter le véritable code, conserver/compléter les tests du script de remplissage et ajouter intégration Firefox–Host–PassWall. Les résultats historiques restent dans H ; une campagne réussie ancienne ne valide pas l'état courant.

| Domaine | Cas nouveaux ou à adapter |
|---|---|
| Sauvegarde | COMMIT/20 s/verrouillage, coffre vide et simple lecture, absence d'inspection, manuel sans erreur, échec/Unknown/reprise, fermeture, numérotation et ambiguïté, rotation seulement sur publication confirmée |
| Restauration | source authentifiée, principal corrompu, échange atomique, source/ancien principal préservés, interruption sans reprise automatique, secrets |
| SQLite | schéma hostile, triggers/vues/ATTACH/extensions, tailles avant allocation, permissions/liens, états récupérables/incertains/corruption |
| Mémoire | buffers et accès protégés, refus OS, exceptions, maître, copies, marqueur MIME, expiration et remplacement du presse-papiers |
| V2 | MAC invalidé par suppression/ajout/rejeu partiel, canonisation et séparation de clés, atomicité preuve/CRUD, paramètres, padding malformé, signature et substitution clé publique, copie authentique/rejeu total documenté |
| Sessions | délai unique, interaction légitime, expiration retardée, ancienne session, transaction en cours, veille/arrêt et opérations asynchrones |
| Firefox | accès local non autorisé, HTTPS et origine exacte, ambiguïté, navigation avant injection, verrouillage, aucune indication verrouillée, limites messages/connexion et code JS réel |
| Installation | production seule sans GTest, exécutables et manifeste complets, chemins hors build, permissions et erreurs |

**T05 — Essais réels nécessaires** sur Pi avec coffres et secrets fictifs exclusivement : swaylock direct et délai, veille/reprise, hibernation si disponible, arrêt ; presse-papiers Wayland ; clé USB sur formats annoncés, déconnexion pendant sauvegarde, déplacement/renommage du coffre fermé ; restauration complète et interruption contrôlée ; Firefox réel, installation hors build. Vérifier les conditions de sécurité avant ces essais, ne pas déclencher de transition réelle sans autorisation. Plateformes non testées non annoncées comme supportées.

**T06 — Méthode quota** : Codex écrit les tests et propose commandes exactes, l'utilisateur compile et exécute. Build CMake/Ninja isolé et persistant sous `$HOME/Developpement/tmp_passwall_test`, parallélisme maximum 2. Suites directement concernées et régressions utiles après chaque lot ; campagnes complètes aux jalons (stabilisation V2 et avant diffusion), sur demande explicite. `git diff --check` autorisé comme contrôle textuel, pas comme validation fonctionnelle. Pas de compilation ni test par Codex sans autorisation explicite. Mettre à jour cette référence et AGENTS uniquement via l'utilisateur/ChatGPT sauf demande contraire. Consigner l'état réel, résultats communiqués et limites après chaque lot.

**Critères avant candidature V1 du produit** (distincte du format V2) : architecture unique, coffre autonome, restauration simplifiée sûre, crypto V2 spécifiée et testée, protections mémoire et SQLite validées, sauvegardes/rotation/relances vérifiées, sessions et Firefox durcis, essais réels et installation réussis, limites documentées. Positionner explicitement TOTP/passkeys/audit des mots de passe dans le périmètre de diffusion ; pas de certification générale sur la base de cet audit.

## 12. Plan de développement proposé et spécifications à fermer

Le découpage ci-dessous est une **PROPOSITION D'ORGANISATION**, pas un ordre imposé par l'utilisateur. Les décisions fonctionnelles des sections précédentes sont validées ; les choix marqués À DÉFINIR doivent être résolus avant le sous-lot concerné. Les identifiants `R1`–`R9` sont nouveaux et n'écrasent pas les anciens numéros 2I. Chaque chantier peut être subdivisé en petits lots ciblés, avec état de départ, périmètre, tests, critères de sortie et compte rendu. Ne pas soumettre l'ensemble de l'audit à Codex comme un prompt monolithique.

| Chantier | Sous-lots envisagés (ordre à confirmer selon dépendances) | Critère de sortie |
|---|---|---|
| R1 — Sauvegardes | R1a état réel et dépendances partagées ; R1b supprimer inspection initiale/InitialCopy ; R1c unifier automatique/manuelle/relance ; R1d numérotation/rotation sans ouverture des anciennes ; R1e retirer mode historique et catalogues dont dernier appelant a disparu ; R1f fermeture après incident et publication USB | Une voie générationnelle, déclencheurs validés, pas d'inspection rétrospective, protection et diagnostic conservés |
| R2 — Restauration | R2a découpler autorisations et registre ; R2b supprimer copie de précaution et reprise persistante en conservant échange ; R2c principal corrompu, lecture seule/copie de travail ; R2d retirer dernière dépendance registre et corriger CMake | Aucun registre historique requis ; restauration atomique supervisée, ancien principal/source conservés |
| R3 — SQLite | R3a connexion et schéma ; R3b contrôle des fichiers commun ; R3c états d'écriture ; R3d limites fonctionnelles et techniques | Défenses vérifiées, diagnostics différenciés, transactions et protections conservées |
| R4 — Mémoire | R4a spécifier SecureBuffer/refus OS ; R4b clés et maîtres ; R4c conversions/RAII et Qt ; R4d presse-papiers | Pas de nouvelle copie persistante sensible, protections et nettoyage démontrés dans le périmètre contrôlable |
| R5 — Format V2 | R5a spécification écrite (MAC, signature, canonicalisation, KDF, padding, limites, création/ouverture) et vecteurs ; R5b implémentation atomique du format, CRUD et contrôle ; R5c intégration sauvegarde/restauration/keyless ; R5d politique du maître et générateur/délai | Format unique de production V2, preuves fiables, aucun secret worker de sauvegarde, refus des incompatibilités et tests de régression |
| R6 — Verrouillage/UI | R6a échéance unique et autorisations ; R6b transactions/verrouillage/fermeture et secrets de restauration ; R6c essai swaylock direct puis retrait du coordinateur | Politique de session cohérente et tests Linux ciblés, aucune dépendance bureau superflue |
| R7 — Firefox | R7a spécification de l'admission locale ; R7b Host/bridge/limites ; R7c origine/URL et formulaire avant secret ; R7d contrôles document/session, tests JS réels et intégration | Extension minimaliste, aucune indication verrouillée, aucun accès non autorisé dans le modèle spécifié |
| R8 — Construction | R8a GTest optionnel pour production, dépendances et résidus ; R8b packaging app/workers/Host/extension, identifiant définitif | Installation Linux reproductible hors build, dépendances nécessaires seulement |
| R9 — Validation | R9a campagne ciblée finale puis complète sur autorisation ; R9b essais réels Pi ; R9c bilan/documentation et critères de diffusion | Résultats réels et limites documentés ; pas d'affirmation de validation non exécutée |

R1 et R2 peuvent se chevaucher au niveau des dépendances : ne retirer le registre, fonctions partagées ou preuves historiques qu'après remplacement de leurs derniers consommateurs. Une protection commune à une future fonction ne doit pas disparaître pour satisfaire artificiellement un critère de fin de R1. R3/R4 préparent V2 ; les protections nécessaires à V2 ne doivent pas attendre R6 si elles constituent un prérequis. Les essais du délai de verrouillage réel doivent précéder R6c. Les sujets ouverts (primitive/clé publique de confiance, limites Unicode, publication USB, erreurs/fermeture, compatibilité et installation) ne sont pas des tâches à improviser.

**Méthode de reprise** : R1a à R1d sont clôturés dans le périmètre ci-dessous. Prochain sous-lot proposé : R1e, retrait du moteur historique et de ses dépendances dont les derniers consommateurs ont disparu, après vérification et préservation des fonctions communes encore utilisées (dont preuve de publication dans `BackupRotationService`). Préciser ses prérequis avant intervention ; aucun autre changement n'est autorisé implicitement. ChatGPT peut préparer un patch Git sur une copie des sources ; l'utilisateur l'applique après `git apply --check`, compile et exécute les tests sur son Pi. Préserver les modifications locales non enregistrées dans Git. L'usage de Codex reste possible selon les règles existantes.

### 12.1 Avancement réel — R1a et R1b (24 novembre 2026)

- **R1a — TERMINÉ** : caractérisation des dépendances ; correspondance des 156 fichiers couverts par le manifeste `passwall_R1a.sha256` confirmée par l'utilisateur. Le dépôt local comportait des modifications suivies et des fichiers non suivis ; les patchs sont appliqués au-dessus de cet état, sans reset ni effacement du travail existant. Les documents actualisés n'étaient pas inclus dans ce manifeste.
- **R1b-1 — IMPLÉMENTÉ, TESTÉ (ciblé)** : suppression du lancement asynchrone de l'inspection initiale, de ses relances et de ses états. Adaptation des tests mixtes et test de non-déclenchement lors d'une ouverture sans mutation. Patch `passwall_R1b-1.patch` ; correction de qualification `passwall::services::AutomaticBackupCoordinator` dans `tests/test_credential_editor_lock.cpp` après le premier échec de compilation. Compilation des deux cibles concernées réussie sur le Pi. CTest : coordinateur 153/153 (26,19 s), interface 21/21 (115,17 s), total 174/174.
- **R1b-2 — IMPLÉMENTÉ, TESTÉ (ciblé)** : suppression résiduelle d'`InitialCopy` et d'`InitialBackupPreparer`, retrait de leurs sources et tests dédiés de CMake, nettoyage des branches et états associés dans le coordinateur et le contrôleur de statut. Adaptation des tests de réservation, de publication incertaine et de relance au parcours des mutations. Patch `passwall_R1b-2.patch` ; correction d'édition de liens : déplacement du point d'entrée `main()` avec `QCoreApplication` dans `tests/test_backup_destination_preparer.cpp`. Compilation des trois cibles concernées réussie sur le Pi. L'utilisateur rapporte que les trois campagnes CTest ci-dessous sont passées sans problème ; les nombres exacts de tests et durées de R1b-2 ne sont pas communiqués. Ne pas réutiliser les nombres de R1b-1 pour R1b-2.

Commandes des campagnes R1b-2 exécutées par l'utilisateur (build isolé existant) :

```bash
cmake --build "$HOME/Developpement/tmp_passwall_test/build-R1b" --target passwall_automatic_backup_tests passwall_gui_tests passwall_backup_destination_tests -j 2
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^(AutomaticBackupTest|GenerationalAutomaticBackupTest)\.' --output-on-failure
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^MainWindowEditorLockTest\..*(Generational|Backup|Shutdown|PublicConstructor)' --output-on-failure
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^(BackupDestinationPreparerTest|BackupSeriesIdentityTest|BackupSeriesInspectorTest)\.' --output-on-failure
```

**Contrôles statiques post-correction sur la copie de travail ChatGPT :** aucune référence à `InitialCopy` ou `InitialBackupPreparer` dans les sources/tests recherchés (hors résidus d'éditeur `*~`) ni dans CMake ; `git diff HEAD --check` réussi. Aucune compilation ni exécution des tests par ChatGPT ou Codex. Les corrections de compilation sont incluses dans la copie de travail utilisée pour préparer la suite.

**Limites et suite :** R1b ne valide pas l'ensemble du moteur ni l'installation de production. À la clôture de R1b, les inspections des anciennes sauvegardes lors de la rotation et la demande manuelle volontaire restaient à traiter (réalisées depuis en R1d, §12.3, et R1c, §12.2). Le mode historique, le registre et la politique de fermeture restent à traiter. Le format V2, la restauration simplifiée, les nouvelles protections mémoire/SQLite et Firefox restent des chantiers distincts. Aucune campagne CTest complète ni aucun essai réel supplémentaire n'a été rapporté pour R1b. La clôture de ce lot ne vaut pas certification générale.

### 12.2 Avancement réel — R1c (24 novembre 2026)

- **R1c — IMPLÉMENTÉ, TESTÉ (ciblé)** : `passwall_R1c.patch` raccorde `requestGenerationalBackup()` et le bouton « Sauvegarder maintenant » au moteur générationnel commun. Le coordinateur réutilise les réservations, l'identité physique authentifiée et la préparation existantes ; une demande manuelle ne simule pas un commit. Elle peut avancer le regroupement en attente, refuse les demandes concurrentes ou sans session authentifiée et conserve la relance dédiée en cas de suspension. Six nouveaux tests : cinq du coordinateur et un graphique. Aucun changement de format, aucune dépendance ni registre ajouté.
- **Compilation initiale** : réussie sur le Pi pour `passwall_automatic_backup_tests` et `passwall_gui_tests`. Première campagne graphique : 21/22, échec de `GenerationalVoluntaryBackupButtonPublishesWithoutNewCommitAndLocks` (bouton désactivé retrouvé après réouverture du dialogue).
- **R1c-fix1** : modification du seul fichier `tests/test_credential_editor_lock.cpp` pour traiter la destruction différée du dialogue Qt et vérifier la disparition des anciennes références (`QPointer`). Aucune assertion de sécurité retirée, aucun code de production modifié. `git apply --check`, application, `git diff --check` et recompilation graphique réussis selon le retour utilisateur. Test isolé réussi : 1/1, 3,65 s au total.
- **Validation finale** : l'utilisateur confirme 100 % de réussite des deux campagnes ci-dessous après correctif. Suite graphique : 22 tests dans la campagne initiale, filtre inchangé ; aucun échec final rapporté. Décompte exact de la campagne finale du coordinateur et durées finales non communiqués. Ne pas déduire un total de tests à partir des anciens lots.

```bash
cmake --build "$HOME/Developpement/tmp_passwall_test/build-R1b" --target passwall_automatic_backup_tests passwall_gui_tests -j 2
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^(AutomaticBackupTest|GenerationalAutomaticBackupTest)\.' --output-on-failure
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^MainWindowEditorLockTest\..*(Generational|Backup|Shutdown|PublicConstructor)' --output-on-failure
```

**Limites et suite :** validation ciblée sur les deux suites, pas de campagne globale ni de nouvel essai réel rapporté. À la clôture de R1c, R1d restait à faire (réalisé depuis, §12.3). R1e (moteur historique) et R1f (fermeture après incident et compatibilité USB) restent à faire. La génération volatile interne des demandes/commits ne doit pas être confondue avec les numéros des fichiers de sauvegarde. Le format V2 et les autres chantiers restent inchangés. Aucun recours à Codex ni exécution de compilation/tests par ChatGPT dans ce lot.

### 12.3 Avancement réel — R1d (24 novembre 2026)

- **R1d-1 — IMPLÉMENTÉ, TESTÉ (ciblé)** : `passwall_R1d-1.patch` introduit le parseur/formateur commun `backup_generation_name.hpp`, le calcul du numéro suivant à partir des noms présents, le classement numérique et le refus de rotation en cas d'ambiguïté. Les fichiers d'ancienne nomenclature restent intacts et ne comptent pas dans la rétention des nouvelles générations. Aucun registre, compteur permanent ou accès réseau. Compilation des quatre cibles ci-dessous réussie sur le Pi. Campagne graphique initiale : 21/22, un échec de `GenerationalConsumerPublishesFirstCrudThenDrainsOnRepeatedClose` ; rotation refusée à tort car les fichiers auxiliaires `.pwdb.ready` et `.pwdb.release` du worker de test étaient considérés comme des noms invalides.
- **R1d-1-fix1** : `passwall_R1d-1-fix1.patch` limite les candidats revendiquant la convention aux noms commençant par `generation_` et se terminant par `.pwdb`, avec test de régression. Correctif du code de production, pas de retrait d'assertion de sécurité. Compilation, test graphique isolé et campagne inspection/rotation réussis selon l'utilisateur ; puis coordinateur, destinations/identité et campagne graphique à 100 %. Décomptes finaux non communiqués.
- **R1d-2 — IMPLÉMENTÉ, TESTÉ (ciblé)** : `passwall_R1d-2.patch` retire du chemin de rotation générationnelle la lecture SQLite, la comparaison du `vault_id` et le calcul d'empreinte des anciennes générations. Le service d'identification ne consulte que les noms et métadonnées physiques ; les références `O_PATH`, réservations, contrôles de substitution, permissions, revalidation et preuve de la nouvelle publication restent en place. Le contrôle structurel ciblé est réservé à la nouvelle publication. Refus en présence de compagnons SQLite, détectés par noms. Tests ajoutés/adaptés pour anciennes copies altérées ou de famille différente (contenu non lu), compagnons SQLite et refus de suppression en cas de nouvelle publication invalide. Les tests ne font pas de l'admissibilité physique une preuve d'intégrité cryptographique.
- **Validation finale R1d-2** : l'utilisateur a confirmé la compilation et la réussite de toutes les quatre campagnes ci-dessous. Aucun nombre exact ni durée finale communiqués ; ne pas déduire un total des campagnes précédentes. Les vérifications de patch et `git diff --check` sur la copie de travail ont été rapportées réussies lors de la livraison. Aucune compilation ni test exécuté par ChatGPT ; aucun recours à Codex dans ce lot.

```bash
umask 077
export PW_RESTORE_PARENT_ROOT="$HOME/Developpement/tmp_passwall_test"
export QT_QPA_PLATFORM=offscreen
cmake --build "$HOME/Developpement/tmp_passwall_test/build-R1b" --target passwall_automatic_backup_tests passwall_gui_tests passwall_backup_destination_tests passwall_backup_series_rotation_tests -j 2
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^(AutomaticBackupTest|GenerationalAutomaticBackupTest)\.' --output-on-failure
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^(BackupDestinationPreparerTest|BackupSeriesIdentityTest|BackupSeriesInspectorTest)\.' --output-on-failure
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^BackupSeriesRotationServiceTest\.' --output-on-failure
ctest --test-dir "$HOME/Developpement/tmp_passwall_test/build-R1b" -R '^MainWindowEditorLockTest\..*(Generational|Backup|Shutdown|PublicConstructor)' --output-on-failure
```

**Limites et suite :** validation ciblée, aucune campagne complète ni nouvel essai réel rapporté. L'ordre des fichiers dépend de leurs noms, non de leur authenticité ; la rétention n'est pas une garantie que toutes les copies anciennes soient restaurables. Les fichiers de l'ancienne nomenclature ne sont pas automatiquement renommés ni supprimés. R1e doit supprimer les chemins historiques après caractérisation de leurs consommateurs et migration des protections communes, notamment la vérification de la preuve de la publication récente. R1f, le registre et la restauration simplifiée, le format V2 et les autres chantiers ne sont pas validés par R1d.

---

## Annexe H — Révision historique intégrale du 23 novembre 2026 (non normative)

**ARCHIVE HISTORIQUE.** Ce qui suit est conservé pour les références de composants, preuves et résultats de tests anciens, et les détails de transition qui peuvent être réutilisés. Les déclarations VALIDÉ, IMPLÉMENTÉ, TESTÉ, À FAIRE et À DÉFINIR ci-dessous sont celles de cette révision passée, pas les statuts du 24 novembre. En particulier, les déclarations « production Historical » / « voie de test uniquement », les inspections initiales ou rétrospectives, le verrouillage immédiat à la fermeture, la rotation fondée sur UTC, la conservation de la compatibilité des coffres de test, et les exigences de reprise persistante/coordinateur bureau ne sont plus des prescriptions actuelles. Pour tout développement, lire en priorité les sections actuelles 1–12 ; consulter cette annexe uniquement pour les détails historiques utiles. Les titres et numéros internes de l'archive conservent leur sens d'origine.

### PassWall — Référence technique unique

**Révision documentaire :** 23 novembre 2026 — interface générationnelle de suivi des sauvegardes/rotations et reprise explicite (2I-4H-2), correctifs 2A à 2E et validations GUI parallèles ciblées

**Version applicative actuelle :** 1.29.0

**Plateforme prioritaire :** Linux ARM64, Raspberry Pi 5, Debian 13, Qt 6

**Portée :** état réel du code, architecture cible validée, garanties, limites et travaux restants

#### 1. Objet et statuts

Ce fichier est l'unique référence technique de PassWall. Il remplace la séparation historique entre documentation et TODO. Le code actuel reste la source de vérité pour les comportements présents ; les décisions validées ci-dessous définissent la cible sans présumer qu'elle est déjà implémentée.

Les statuts employés sont :

- **VALIDÉ** : décision approuvée pour l'architecture cible ;
- **IMPLÉMENTÉ** : comportement réellement présent dans le code ;
- **TESTÉ** : comportement vérifié dans le périmètre explicitement indiqué ;
- **À FAIRE** : modification, validation ou fonctionnalité encore nécessaire ;
- **À DÉFINIR** : choix technique ou fonctionnel non résolu.

Une fonctionnalité peut donc être **VALIDÉE** mais non **IMPLÉMENTÉE**. Un résultat **TESTÉ** sur un composant, un bus privé ou un coffre fictif ne constitue pas une certification générale ni une validation sur toutes les plateformes.

#### 2. Périmètre du produit

##### 2.1 Fonctions présentes

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

##### 2.2 Hors périmètre actuel

- **VALIDÉ** — aucun serveur de référence, synchronisation automatique ou fusion entre copies ;
- **VALIDÉ** — aucun mécanisme d'autorisation ou de révocation des appareils ;
- **VALIDÉ** — aucune récupération cryptographique possible sans le mot de passe maître ;
- **VALIDÉ** — les copies d'un même coffre évoluent indépendamment et leurs divergences relèvent de l'utilisateur.

#### 3. Environnement et construction

##### 3.1 Environnement de développement connu

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

Ces valeurs sont des relevés de développement et doivent être revérifiées avant une diffusion. Pour 2I-4G-1, le build Linux local détecte `libsystemd` 257 via pkg-config après installation des en-têtes `libsystemd-dev` ; cette dépendance de développement sert à compiler, tandis que la bibliothèque d’exécution doit être prise en charge par le paquet de distribution.

##### 3.2 CMake et exécutables

- **IMPLÉMENTÉ** — `project(PassWall VERSION 1.29.0 ...)` est la source unique de version.
- **IMPLÉMENTÉ** — `passwall_app --version` et `passwall_app -v` écrivent `PassWall 1.29.0` puis quittent avant l'initialisation de Qt et des services.
- **IMPLÉMENTÉ** — une compilation sans cible explicite construit les cinq exécutables Linux de production et leurs dépendances : `passwall_app`, `passwall_backup_worker`, `passwall_restore_worker`, `passwall_native_host` et `passwall-session-lock`.
- **IMPLÉMENTÉ** — tests, probes, `passwall_env_check` et `passwall_argon2_benchmark` sont exclus du build courant mais restent compilables explicitement.
- **IMPLÉMENTÉ** — la cible `passwall_all_tests` construit les binaires enregistrés auprès de CTest.
- **TESTÉ localement — diagnostic CTest 2I-4F-5A** : huit cibles de tests exclues du build général ont été construites explicitement ; les entrées `NOT_BUILT` qui les représentaient ont alors été remplacées par 333 tests découverts et exécutables. `RestoreParentExitProbe`, auxiliaire provoquant volontairement une sortie de processus, est désormais exclu de la découverte CTest ordinaire par `TEST_FILTER`, sans être supprimé ni rendu inaccessible aux tests parents. Une campagne CTest exige toujours que ses exécutables soient construits avant exécution.
- **IMPLÉMENTÉ** — la cible CMake canonique est `SQLite3::SQLite3`, avec alias de compatibilité local si la version de CMake ne la fournit pas ; aucun hook `CMAKE_PROJECT_INCLUDE` externe n'est requis.
- **IMPLÉMENTÉ — isolation CMake 2I-4G-4/2I-4H-1/2I-4H-2** : le contrôleur de rotation, la GUI des préférences globales et le contrôleur de statut générationnel sont reliés uniquement aux parcours explicitement construits pour les tests (`passwall_gui_tests`, fabrique `MainWindow::createForGenerationalTests()` sous `PASSWALL_GUI_TESTING`). `passwall_app` ne lie ni `passwall_backup_series_rotation` ni `passwall_global_backup_preferences_gui` ni le contrôleur de statut générationnel. Ses constructeurs de production restent en mode `Historical`.

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

##### 3.3 Intégration continue

- **IMPLÉMENTÉ** — le workflow Linux ARM64 compile la production puis `passwall_all_tests` et exécute CTest avec Qt offscreen, séquentiellement et avec `--no-tests=error`.
- **TESTÉ** — la version 1.26 a produit 887 réussites CTest, aucun échec et un auxiliaire volontairement ignoré sur 888 cas enregistrés.
- **IMPLÉMENTÉ** — une étape séparée exécute les cinq tests JavaScript avec le lanceur natif Node.js et Node.js 24.
- **TESTÉ localement** — les cinq cas JavaScript réussissent avec Node.js 20.19.2.
- **À FAIRE** — confirmer sur GitHub ARM64 les évolutions 1.27 à 1.29 et maintenir la distinction entre tests offscreen/simulés et essais Firefox, Wayland, logind et swaylock réels.

##### 3.4 Installation locale connue

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

#### 4. Coffre, cryptographie et stockage

##### 4.1 Format et portabilité

- **IMPLÉMENTÉ** — un coffre est un fichier SQLite autonome contenant ses métadonnées cryptographiques, dont un `vault_id` de 16 octets.
- **VALIDÉ** — le coffre n'est lié cryptographiquement ni à la machine, ni au registre QSettings, ni à une autorisation d'appareil.
- **VALIDÉ** — une copie cohérente peut être ouverte sur une installation compatible avec son propre mot de passe maître.
- **VALIDÉ** — `vault_id` identifie une famille de copies ; ce n'est ni une preuve d'authenticité, ni une autorisation de remplacement ou de suppression.
- **IMPLÉMENTÉ** — le format est indépendant de l'extension du fichier.
- **VALIDÉ** — les anciens fichiers `.db` compatibles restent pris en charge ; `.pwdb` devient la convention nominale des nouveaux coffres et sauvegardes, sans migration ou renommage automatique imposé.

Une copie prise pendant une transaction ou une opération de remplacement n'est pas nécessairement cohérente. Il faut utiliser les mécanismes d'instantané ou attendre la fin effective de toutes les opérations, pas seulement un verrouillage visuel.

##### 4.2 Cryptographie

- **IMPLÉMENTÉ** — libsodium est initialisée avant l'usage des buffers protégés.
- **IMPLÉMENTÉ** — Argon2id dérive la clé depuis le mot de passe maître ; les paramètres de production actuels sont trois opérations et 256 Mio.
- **IMPLÉMENTÉ** — XChaCha20-Poly1305 assure le chiffrement authentifié.
- **IMPLÉMENTÉ** — les entrées sont chiffrées individuellement ; les notes sont protégées avec les autres champs.
- **IMPLÉMENTÉ** — la clé de données est enveloppée et n'est rendue disponible qu'après authentification du maître.
- **IMPLÉMENTÉ** — `SecureBuffer` est non copiable, nettoie sa zone contrôlée et protège les clés et certains secrets temporaires.
- **À FAIRE** — audit cryptographique global V1 : sels, nonces, AAD, versionnement du format, paramètres Argon2id sur le matériel annoncé et chemins d'erreur.

Le nettoyage d'une zone contrôlée ne prouve pas l'effacement de toutes les copies historiques produites par `std::string`, Qt, SQLite, le noyau, le swap ou le support physique.

##### 4.3 Politique SQLite V1

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

##### 4.4 Modèle métier et mémoire sensible

- **IMPLÉMENTÉ** — titre, nom d'utilisateur et mot de passe sont obligatoires à l'ajout et à la modification.
- **IMPLÉMENTÉ** — titre et nom d'utilisateur vides ou uniquement composés d'espaces Unicode sont refusés.
- **IMPLÉMENTÉ** — le mot de passe vide est refusé, mais sa valeur exacte n'est jamais normalisée ; un mot de passe composé d'espaces est accepté.
- **IMPLÉMENTÉ** — `CredentialService::validate()` porte la règle métier commune à la GUI et au service.
- **IMPLÉMENTÉ** — `CredentialSummary` et `listSummaries()` évitent de conserver durablement tous les mots de passe et notes dans `MainWindow`.
- **IMPLÉMENTÉ** — les temporaires sensibles ciblés de création, ouverture, ajout et modification sont associés à leurs nettoyeurs avant les appels susceptibles d'échouer.
- **À FAIRE** — maintenir un audit continu des conversions `QString` / `QByteArray` / `std::string`, du presse-papiers, des messages, propriétés Qt et nouvelles tâches asynchrones.

##### 4.5 Responsabilités des composants

| Composant | Responsabilité actuelle |
|---|---|
| `CryptoEngine` / `SecureBuffer` | initialisation libsodium, dérivation, chiffrement authentifié et mémoire protégée |
| `VaultStorage` | schéma, métadonnées, création/publication du fichier et accès SQLite de cycle de vie |
| `VaultKeyService` | enveloppe et récupération de la clé de données après authentification |
| `VaultLifecycleService` | création et ouverture d'un coffre, sans publier de session après échec |
| `CredentialService` | validation, chiffrement, CRUD, résumés, authentification de toutes les entrées et notification en mémoire des mutations confirmées |
| `MainWindow` | session GUI, clé active, verrouillage, adaptateurs natifs et admissions sensibles ; dans la seule fabrique générationnelle de test, accès non modal à la configuration globale et relance conditionnelle de l’inspection initiale |
| `VaultOperationGuard` | exclusion coopérative intra/interprocessus |
| `VaultSnapshotService` | copie SQLite cohérente et publication sécurisée |
| `BackupSeriesIdentity` | dérivation versionnée d’un identifiant de série par installation et famille `vault_id`, sans dépendre du chemin ni de l’inode du coffre |
| `BackupSeriesInspector` | inspection légère et non destructive des versions d’une série, classement UTC et sélection transitoire des excédents ; aucune autorisation de suppression |
| `BackupSeriesRotationService` | rotation destructive explicite d’une seule série après publication démontrée ; réinspection et revalidation avant chaque `unlinkat`, `fsync` du répertoire et résultat de rotation distinct du résultat de sauvegarde ; non raccordé en production |
| `GenerationalBackupRotationController` | orchestration asynchrone volatile de la rotation dans la seule fabrique GUI de test : preuve terminale exacte, relecture physique des préférences, file FIFO, thread de rotation, résultats autonomes et fermeture supervisée |
| `GlobalBackupPreferencesDialog` / `GlobalBackupPreferencesController` | validation et lecture/écriture asynchrones des préférences globales ; proposition initiale non modale et action de paramètres accessibles seulement depuis la fabrique GUI générationnelle de test 2I-4H-1 |
| `GenerationalBackupStatusController` | présentation volatile et non modale, uniquement dans la GUI générationnelle de test 2I-4H-2, des opérations de sauvegarde, résultats terminaux, rotations, inspections et suspensions ; reprise explicite par le coordinateur sans autorité de sauvegarde, de rotation ou de session propre |
| `BackupDestinationPreparer` / `InitialBackupPreparer` | préparation privée des familles et séries, contrôle de première copie dans la série courante et transfert de capacité d’instantané |
| `BackupJob` / `passwall_backup_worker` | exécution et supervision asynchrones sans clé de déchiffrement |
| `AutomaticBackupCoordinator` | coordination automatique historique en production ; préparation, inspection asynchrone, relances bornées et consommation des générations initiales/CRUD dans la voie générationnelle injectable pour les tests |
| `VaultReplacementAuthorization` | autorité opaque issue du véritable propriétaire GUI |
| `VaultReplacementService` | moteur unique actuel de remplacement et récupération |
| `RestoreJob` / `passwall_restore_worker` | délégation, transport privé du maître et supervision du remplacement |
| `NativeRequestProcessor` | unique traitement métier des requêtes Firefox |
| `LinuxSessionMonitor` / `SessionLockService` | protection logind et verrouillage externe acquitté |

##### 4.6 Utilitaires métier

- **IMPLÉMENTÉ** — `SiteMatcher` accepte HTTP/HTTPS, compare schéma, hôte et port effectif, rejette URL malformées et informations utilisateur, et interprète une URL sans schéma comme HTTPS.
- **IMPLÉMENTÉ** — `PasswordGenerator` produit de 8 à 128 caractères avec `randombytes_uniform`, garantit chaque catégorie choisie et mélange sans biais modulo.
- **TESTÉ** — ces deux composants possèdent leurs suites unitaires et sont intégrés aux parcours GUI/Firefox concernés.

#### 5. Architecture cible des préférences et sauvegardes

Cette section décrit la cible approuvée. La section 6 décrit séparément l'implémentation historique encore présente.

##### 5.1 Préférences globales

- **VALIDÉ** — un seul dossier racine global de sauvegardes est configuré pour l'installation.
- **VALIDÉ** — une politique globale de rétention s'applique à chaque série de sauvegardes : sept versions par défaut, minimum configurable de sept et aucune limite supérieure arbitraire imposée par la spécification.
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
- **À FAIRE — intégration de production** : aucun consommateur de production n’utilise encore ces préférences. La voie GUI générationnelle de test les charge depuis 2I-4F-5A, puis expose leur configuration initiale et leur modification par 2I-4H-1. Le futur basculement de production devra toujours exiger l’état `Valid` puis des contrôles opérationnels distincts de destination. Une préférence syntaxiquement valide ne constitue ni une capacité d’écriture ni une preuve que le support est disponible.
- **IMPLÉMENTÉ — interface globale 2I-4H-1, accessible seulement dans la GUI générationnelle de test** : `GlobalBackupPreferencesDialog` et `GlobalBackupPreferencesController`, précédemment isolés, sont raccordés à l’action `globalBackupPreferencesAction` créée exclusivement par `MainWindow::createForGenerationalTests()`. `passwall_app` ne lie pas `passwall_global_backup_preferences_gui` ; l’action historique `backupSettingsAction`, son contrôleur par coffre et le moteur `Historical` restent seuls utilisés en production.
- **IMPLÉMENTÉ — validation et saisie isolées** : la rétention est saisie avec un `QLineEdit` numérique pour couvrir le domaine `quint64`, sans plafond d'interface artificiel ; le minimum reste sept. `GlobalBackupPreferencesStore::validate()` centralise les contrôles non persistants et `save()` les réutilise. Aucun bouton d'activation n'est ajouté. Un chemin absolu inexistant peut être enregistré sans être créé ni présenté comme opérationnel.
- **IMPLÉMENTÉ — contrôleur asynchrone, intégré seulement en test depuis 2I-4H-1** : lecture, écriture et relectures du coordinateur s’exécutent hors du thread GUI ; les états `Absent`, `Valid`, `Invalid`, `ReadError` et `WriteError` restent distingués. La fermeture sans confirmation ne persiste rien ; seul le stockage global assure la publication. Le dialogue ne crée ni ne chmod le dossier choisi et ne modifie ni `PassWall.conf` ni `vaultRegistry/data` ; la rotation et les sauvegardes ne sont déclenchées qu’au travers des composants de coordination, jamais directement par le dialogue.
- **TESTÉ — interface globale isolée** : 11/11 tests de `GlobalBackupPreferencesStore`, 9/9 tests Qt offscreen de `GlobalBackupPreferencesGuiTest` et 2/2 tests ciblés de neutralité `Historical` ont réussi dans le terminal de l'utilisateur (22/22 dans ces sélections distinctes). Aucune revue indépendante du code ni campagne CTest complète n'est déduite de ces résultats.
- **IMPLÉMENTÉ — provenance physique 2I-4G-4, hors production** : la lecture globale ajoute une identité physique transitoire du fichier `BackupPreferences.ini`, recoupée avec la provenance déjà conservée lors de la préparation. Le contrôleur de rotation refuse une configuration absente, illisible, remplacée même par un fichier au contenu identique, ou changée en racine/rétention ; une modification détectée après une suppression confirmée interrompt les suppressions suivantes et laisse un résultat partiel. Aucune donnée de rotation n’est persistée.
- **IMPLÉMENTÉ — configuration initiale 2I-4H-1, uniquement sous `PASSWALL_GUI_TESTING`** : une lecture asynchrone au démarrage du parcours générationnel propose une seule fois par session GUI un dialogue non modal si les préférences sont `Absent`, `Invalid` ou `ReadError`. L’état `Valid` ne provoque aucune proposition ; un refus n’est retenu qu’en mémoire et l’action dédiée permet de rouvrir les paramètres. Annuler ne crée ni fichier de préférences ni dossier racine, sans empêcher l’ouverture ou les CRUD d’un coffre sain.
- **IMPLÉMENTÉ — reconfiguration et première copie 2I-4H-1, uniquement en test** : une écriture confirmée utilise l’invalidation déjà présente du coordinateur : offres et préparations obsolètes sont invalidées, capacités RAII libérées, générations CRUD confirmées conservées, worker actif non interrompu et rotation toujours soumise à la revalidation de la provenance et du contenu. Seule une session de coffre encore authentifiée peut lancer une nouvelle inspection initiale après configuration ; les coffres fermés ne sont jamais recherchés et un coffre vide ne produit pas de copie fictive. Une configuration absente/invalide maintient un besoin volatil de réinspection, sans déclenchement prématuré ni nouvelle persistance. Les réponses tardives après verrouillage, fermeture, changement de session ou destruction sont ignorées.
- **TESTÉ — lot 2I-4H-1, validations ciblées Qt offscreen** : l’utilisateur rapporte **8/8** nouveaux tests, **11/11** tests de régression de configuration/sauvegarde et **9/9** tests de neutralité `Historical`, tous réussis sous CTest `--parallel 2`. Ces sélections peuvent se recouper : 28 exécutions réussies ne signifient pas 28 tests distincts. Les résultats couvrent la proposition initiale, l’annulation sans écriture, la première copie après configuration, la rétention `UINT64_MAX`, la relecture, l’ignorance des retours tardifs, la neutralité des coffres fermés/vides et les parcours historiques. Ni audit indépendant ni campagne CTest complète ne sont déduits.
- **À DÉFINIR** — export éventuel du nouveau fichier de préférences ; l'import n'est pas spécifié.

##### 5.2 Familles et disposition des fichiers

- **VALIDÉ** — chaque `vault_id` complet correspond à une famille et à un sous-dossier de la racine globale. Le nom de ce sous-dossier est l'encodage du `vault_id` en 32 caractères hexadécimaux minuscules, sans séparateur.
- **VALIDÉ** — une sauvegarde est une copie SQLite cohérente, autonome et directement ouvrable, conservant le `vault_id` de sa source.
- **VALIDÉ** — les nouvelles sauvegardes utilisent l'extension nominale `.pwdb`.
- **VALIDÉ** — le nom nominal est l'horodatage UTC `YYYY-MM-DD_HH-MM-SS.pwdb`.
- **VALIDÉ** — en cas de collision dans la même seconde, le suffixe `_2`, puis `_3`, `_4`, etc. est ajouté avant `.pwdb`, uniquement lorsque nécessaire.
- **VALIDÉ** — deux fichiers de travail partageant un `vault_id` appartiennent à la même famille, sans fusion de leurs divergences ni branche canonique. Chaque installation distinctement identifiée alimente sa propre série, avec sa propre rétention globale appliquée indépendamment.
- **À DÉFINIR** — présentation à l'utilisateur de plusieurs principaux divergents appartenant à la même famille.
- **VALIDÉ — séparation des séries** : une sauvegarde de la série A ne dispense jamais B de sa première sauvegarde dans sa propre série ; la rotation de A ne doit jamais supprimer une version de B. Une restauration manuelle d’une sauvegarde de A dans le coffre de B ne modifie pas l’identité de série de B.
- **VALIDÉ — limites acceptées** : une réinstallation susceptible de changer l’identité d’installation crée une nouvelle série sans rattacher ou effacer automatiquement les précédentes ; plusieurs copies indépendantes d’une même famille sur une installation ne bénéficient pas d’une séparation garantie. Des systèmes clonés partageant le même identifiant peuvent partager involontairement une série sur une destination commune ; documenter ce risque pour l’utilisateur, sans mécanisme spécial de résolution dans cette fondation.

La disposition cible est `racine/vault_id/series_id/YYYY-MM-DD_HH-MM-SS[_N].pwdb`. Les sous-dossiers de série isolent les historiques ; `vault_id`, `series_id` et la conformité du nom n’authentifient pas une sauvegarde et n’autorisent ni restauration ni suppression. Le format historique `racine/vault_id/fichier.pwdb` reste conservé sans migration ni rattachement implicite à une nouvelle série.

- **IMPLÉMENTÉ — fondation 2I-3B** : `BackupDestinationPreparer` exige un `vault_id` réel de 16 octets relu depuis le coffre sous une capacité d'instantané liée au périphérique et à l'inode attendus. Il forme le dossier familial avec les 32 caractères hexadécimaux minuscules et conserve en mémoire le coffre, la génération et les identités physiques de la racine et de la famille.
- **IMPLÉMENTÉ — création privée** : la racine configurée est seulement inspectée ; ses permissions ne sont jamais modifiées. Le sous-dossier familial est créé par `mkdirat` en `0700`, ouvert sans suivre de lien et recoupé avec son entrée nommée. Un dossier existant n'est accepté que s'il appartient à l'utilisateur, reste le même inode et possède déjà les permissions privées attendues.
- **IMPLÉMENTÉ — nommage préparatoire** : le nom UTC nominal et les suffixes `_2`, `_3`, etc. sont choisis par inspection sans suivi de liens, désormais dans la série courante. Aucun fichier de réservation n’est créé : le nom préparé n’est donc ni une publication ni une promesse d’exclusivité. La publication future devra encore utiliser le mécanisme sans écrasement de `VaultSnapshotService`.
- **IMPLÉMENTÉ — revalidation et transfert** : l’admission 2I-4B, adaptée en 2I-4G-1, recontrôle la source et son `vault_id`, la racine, le dossier familial, le dossier de série et l’absence de la destination, puis transfère sans réacquisition la capacité et les identités physiques nécessaires au moteur d’instantané. Le worker reçoit l’identité physique du dossier de série ; collisions et substitutions restent refusées par les contrôles du pilote, du worker et de la publication sans écrasement.
- **IMPLÉMENTÉ — liaison 2I-3C/2I-4G-1** : une inspection préalable peut imposer au préparateur les identités de racine, de famille et de série observées. La substitution de l’un de ces dossiers entre découverte, préparation et admission est refusée plutôt qu’acceptée comme un nouvel emplacement équivalent.
- **IMPLÉMENTÉ — identité des séries 2I-4G-1, inactive en production** : `BackupSeriesIdentity` dérive un `series_id` SHA-256 hexadécimal d’un encodage canonique versionné comprenant un domaine de plateforme, une identité d’installation propre à PassWall et le `vault_id`. Il ne dépend ni du chemin, ni de l’inode, ni du contenu du coffre. Sous Linux, `sd_id128_get_machine_app_specific()` fournit l’identité spécifique à l’application à partir d’un identifiant PassWall fixe, sans publier le `machine-id` brut. L’identité manquante ou un domaine Windows non implémenté sont refusés sans repli aléatoire silencieux ; les identifiants restent des clés de rangement, jamais des autorisations.
- **IMPLÉMENTÉ — préparation par série 2I-4G-1, inactive en production** : `BackupDestinationPreparer` prépare `racine/vault_id/series_id/nom-UTC.pwdb`, crée et inspecte les sous-dossiers familiaux et de série en `0700` sans suivre les liens et conserve leurs identités physiques. La racine choisie reste inchangée. Les fichiers de l’ancien agencement directement sous la famille ne sont ni déplacés, ni supprimés, ni attribués implicitement à une série.
- **IMPLÉMENTÉ — première copie par série 2I-4G-1** : `InitialBackupPreparer` recherche une sauvegarde admissible dans la seule série courante. Une version de A ne bloque pas la première copie de B ; l’empreinte d’inspection du coordinateur tient compte de l’identité d’installation. Les tests GUI emploient une identité fictive uniquement sous `PASSWALL_GUI_TESTING`.
- **TESTÉ — lot 2I-4G-1** : 41/41 tests de série, destination et première copie, 101/101 tests de coordination générationnelle et neutralité `Historical`, puis 4/4 tests GUI générationnels réussis dans le terminal de l’utilisateur, soit 146/146 tests ciblés répartis sur trois sélections. CMake a détecté `libsystemd` 257 (`SYSTEMD_ID128_FOUND=1`) après installation de `libsystemd-dev`. Les tests d’identité utilisent des valeurs fictives ; aucune validation Windows ni campagne CTest complète n’est déduite de ces résultats.
- **IMPLÉMENTÉ — arbitrage 2I-4C inactif** : le coordinateur accepte désormais sur son thread propriétaire une préparation 2I-4B sous le type transitoire explicite `InitialCopy`. Une génération CRUD et une génération de session restent deux liaisons distinctes ; aucune valeur zéro ou conversion implicite ne transforme la première copie en mutation fictive.
- **À FAIRE — intégration de production** : le consommateur GUI injecté sous `PASSWALL_GUI_TESTING` démarre désormais les offres typées `InitialCopy` et `CrudGeneration` avec les admissions 2I-4B/2I-4C. Aucun consommateur de production ne le fait encore ; le futur basculement devra conserver les admissions à usage unique et ne jamais traiter la préparation comme une autorisation de restauration ou de suppression.

##### 5.3 Déclenchement automatique

- **VALIDÉ** — seuls les coffres effectivement ouverts sont concernés par la gestion automatique. PassWall ne recherche pas les coffres fermés et ne maintient aucune liste permanente des coffres connus à cette fin.
- **VALIDÉ** — PassWall suit uniquement en mémoire, pour la session du coffre, les modifications métier confirmées. Aucun nouveau registre persistant de modifications n'est créé.
- **VALIDÉ** — l'indicateur de modification n'est activé qu'après confirmation du `COMMIT` SQLite. Une préparation, une écriture tentée ou une transaction annulée ne le déclenchent pas.
- **VALIDÉ** — après chaque `COMMIT` métier réussi, une sauvegarde automatique est demandée avec un délai de regroupement de vingt secondes ; chaque nouveau `COMMIT` réussi remet ce délai à zéro.
- **VALIDÉ** — si le verrouillage intervient avant l'expiration, la demande devient immédiate après le nettoyage des secrets ; le verrouillage ne doit jamais attendre la copie.
- **VALIDÉ — fermeture normale générationnelle** : une demande de fermeture rend immédiatement éligibles les générations CRUD confirmées, invalide sans attente la session et efface les secrets, puis laisse la vidange se terminer de manière asynchrone. Aucune boîte de dialogue « attendre ou quitter » ni confirmation répétée n'est demandée : la fenêtre se ferme automatiquement lorsque les workers concernés ont effectivement terminé et que la vidange est terminale, y compris en cas d'échec ou de suspension dûment distingué d'une réussite. Une nouvelle demande de fermeture ne doit ni recommencer le nettoyage, ni perdre les générations déjà confirmées ou celles qui se terminent pendant la vidange.
- **VALIDÉ** — une sauvegarde peut s'exécuter pendant que le coffre reste déverrouillé. Plusieurs modifications regroupées ne produisent qu'une seule copie lorsqu'un même instantané peut les couvrir ; une modification postérieure au lancement reste une demande distincte tant que sa présence dans l'instantané n'est pas démontrée.
- **VALIDÉ** — un coffre ouvert et peuplé qui ne possède aucune sauvegarde admissible dans sa série de la racine actuelle doit recevoir une première sauvegarde, même si une autre série de la famille possède déjà des versions, sous réserve d’une configuration globale valide et des règles de déclenchement ci-dessus.
- **VALIDÉ** — ouvrir puis verrouiller sans modification confirmée un coffre qui possède déjà une sauvegarde admissible ne crée pas de sauvegarde supplémentaire.
- **VALIDÉ** — pour un nouveau coffre, le premier `COMMIT` d'une entrée déclenche la demande de première sauvegarde selon le délai de regroupement, avec accélération au verrouillage.
- **VALIDÉ** — après la configuration initiale ou un changement de racine, les coffres déjà peuplés sont progressivement pris en charge lorsqu'ils sont ouverts puis verrouillés. Les coffres fermés ne sont ni recherchés ni sauvegardés en arrière-plan.
- **IMPLÉMENTÉ — fondation 2I-3C inactive** : `InitialBackupPreparer` reçoit uniquement le contexte transitoire d'une session que son futur propriétaire déclare réellement authentifiée. Sous une capacité d'instantané liée au chemin, au périphérique et à l'inode, il relit la structure, le `vault_id` et la présence d'au moins une entrée. Coffre vide, configuration globale indisponible ou identité divergente ne produisent aucune demande.
- **IMPLÉMENTÉ — découverte 2I-3C/2I-4G-1** : pour décider d’une première copie, une version est provisoirement admissible si elle se trouve dans la série courante de la famille attendue, porte un nom UTC géré et passe les contrôles structurels SQLite/PassWall, de propriétaire, de permissions, de stabilité physique et de `vault_id`. Un ancien fichier directement dans la famille ou une version d’une autre série ne couvre pas ce besoin. Ce contrôle sans clé n’authentifie pas le contenu chiffré, n’autorise ni restauration ni suppression et ne fixe pas les critères définitifs de rotation.
- **IMPLÉMENTÉ — demande distincte 2I-3C** : un coffre peuplé sans version admissible produit un `InitialBackupRequest` transitoire lié à la génération de session et à une `PreparedBackupDestination`. Si une génération CRUD est déjà en attente, elle couvre l'obligation de première copie et aucune seconde demande n'est créée. Aucun état de cette décision n'est écrit sur disque.
- **IMPLÉMENTÉ — cycle de session 2I-3C/2I-4E-1/2I-4F-5A** : les points d'annulation rejettent une session fermée ou remplacée. `InitialBackupPreparer::prepare()` reste synchrone au niveau du service, mais le coordinateur générationnel l'exécute sur un thread de travail ; `MainWindow` n'active ce raccordement que dans le parcours de test explicitement `Generational`. Le mode de production `Historical` n'effectue pas cette inspection.
- **IMPLÉMENTÉ — admission 2I-4B inactive** : `InitialBackupRequest` est désormais un objet mobile à usage unique. Son contexte final distingue explicitement génération de session et génération de mutation, exige le mode `Generational`, une session courante, l'absence de fermeture et l'admissibilité de l'opération, puis revalide source, `vault_id`, racine, famille et nom encore libre sur le thread propriétaire.
- **IMPLÉMENTÉ — transfert 2I-4B** : après admission, la capacité d'instantané déjà détenue est déplacée directement vers `BackupJob::startSnapshotReserved()` sans nouvel appel à `trySnapshotAccess()` ni exposition publique de la garde. Toute tentative, y compris refus ou échec synchrone de démarrage, consomme la préparation ; RAII libère la réservation si le worker n'en devient pas propriétaire. Le raccordement production reste absent.
- **IMPLÉMENTÉ — fusion 2I-4C inactive** : l'admission propriétaire relit l'identité du coffre et revalide la préparation avant de l'insérer dans la même file à jetons que les générations CRUD. Une génération CRUD déjà planifiée, offerte, en attente ou active pour le même fichier physique couvre l'obligation de première copie ; la préparation redondante est alors libérée par RAII sans second worker.
- **IMPLÉMENTÉ — courses 2I-4C** : une mutation confirmée pendant l'inspection, entre préparation et admission, ou après une offre `InitialCopy` gagne l'arbitrage. Une offre initiale non démarrée est invalidée, son jeton devient inutilisable, sa capacité est libérée et le délai CRUD repart du dernier `COMMIT`. Les générations CRUD restent monotones dans leur propre session et une offre remplacée n'est jamais présentée comme publiée.
- **IMPLÉMENTÉ — consommateur GUI 2I-4F-5A, exclusivement en test** : une session authentifiée lance de manière différée l’inspection initiale ; `MainWindow` consomme les offres typées `InitialCopy` et `CrudGeneration`, revalide identité physique, jeton et configuration, puis utilise le worker commun et son reçu de publication. Depuis 2I-4H-1, une sauvegarde initiale peut aussi être inspectée après configuration globale confirmée, mais uniquement pour la session courante authentifiée et sans création de `COMMIT` fictif. La fermeture générationnelle conserve des générations CRUD distinctes, y compris un `COMMIT` tardif pendant la vidange. La production demeure `Historical`.
- **IMPLÉMENTÉ — contention d'inspection initiale 2I-4F-5A** : seule une contention coopérative classée par `VaultOperationGuard::contended()` produit `RetryableContention`, avec au maximum deux relances différées ou réveillées par libération locale. Identité divergente, permissions, chemins, stabilité et erreurs d'E/S restent des refus terminaux. L'attente est observable (`WaitingForRetry`) et annulable ; les résultats intermédiaires portent `terminal == false`, tandis que les annulations et l'épuisement des relances sont terminaux.
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

##### 5.4 Publication et rotation

- **VALIDÉ** — la validation d'intégrité de la source et les garanties actuelles de copie cohérente, publication sans écrasement et confirmation de durabilité doivent être préservées.
- **VALIDÉ** — la rotation ne commence qu'après la publication réussie et suffisamment confirmée de la nouvelle sauvegarde.
- **VALIDÉ** — la rétention conserve sept sauvegardes par série par défaut, ne peut être configurée sous sept et ne possède pas de plafond arbitraire dans la spécification. Chaque série utilise la même valeur globale, mais la rotation est indépendante des autres séries de la famille.
- **VALIDÉ** — l’historique d’une série correspond à ses dernières sauvegardes effectivement publiées, pas nécessairement aux dernières modifications SQLite. Une série peut contenir moins de sept versions tant que cet historique n’a pas encore été constitué.
- **VALIDÉ** — aucun catalogue persistant individuel des versions n'est requis dans la cible.
- **VALIDÉ** — une sauvegarde peut être considérée comme gérée pour sa série lorsqu’elle se trouve dans le sous-dossier de série attendu, respecte la convention de nommage et satisfait les contrôles techniques nécessaires.
- **VALIDÉ** — la rotation n'exige pas une preuve historique individuelle de création ou de publication pour chaque ancienne version. Un fichier déposé manuellement peut donc être pris en compte s'il satisfait les mêmes conditions de dossier, de nommage, d'identité et de sécurité.
- **VALIDÉ** — elle ne réauthentifie pas cryptographiquement et exhaustivement toutes les anciennes versions avant chaque suppression.
- **VALIDÉ** — les fichiers ambigus, hors convention, hors sous-dossier de série courant ou ne satisfaisant pas les contrôles techniques ne sont pas supprimés. Les liens symboliques, substitutions concurrentes et suppressions hors périmètre restent refusés ; les anciennes versions à la racine de la famille restent hors rotation.
- **VALIDÉ** — un export manuel n'est pas intégré automatiquement à la rotation ; s'il est ensuite placé manuellement dans le dossier géré et rendu conforme à toutes les conditions, il peut devenir une version gérée comme tout autre fichier admissible.
- **IMPLÉMENTÉ — inspection 2I-4G-2, non destructive et inactive en production** : `BackupSeriesInspector` inspecte exclusivement `racine/vault_id/series_id`, sans créer, modifier ou supprimer de fichiers. Il vérifie les dossiers et fichiers attendus (parcours sans liens symboliques, type ordinaire, propriétaire, permissions, identité physique stable), les noms UTC canoniques et une structure SQLite/PassWall légère avec concordance du `vault_id` interne. La nouvelle prévalidation légère de `VaultSnapshotService` n’exécute ni `integrity_check` systématique ni authentification exhaustive des entrées ; les contrôles complets déjà utilisés ailleurs ne sont pas modifiés.
- **IMPLÉMENTÉ — classement et rétention 2I-4G-2** : les versions admissibles d’une seule série sont triées selon la date UTC nominale du nom et la valeur numérique du suffixe (`_2`, `_3`, `_10`), sans utiliser `mtime`, `ctime` ni l’ordre de parcours. Le calcul de l’excédent pour une rétention `quint64` d’au moins sept versions prend en charge `UINT64_MAX` sans conversion dangereuse. Les anciennes versions directement sous `vault_id/` et les autres séries restent hors calcul. Une horloge système incorrecte peut fausser l’ancienneté nominale.
- **IMPLÉMENTÉ — prudence 2I-4G-2** : le service distingue versions admissibles, objets hors convention et ambiguïtés ; toute ambiguïté neutralise la liste des excédents. Une erreur de lecture, une disparition ou une substitution concurrente n’est pas assimilée à une absence sûre. Le résultat transitoire peut conserver les identités physiques observées, mais sa liste d’excédents ne constitue jamais une autorisation de suppression. L’inspection est synchrone et potentiellement bloquante : tout futur appel depuis la GUI devra s’exécuter hors de son thread.
- **TESTÉ — lot 2I-4G-2** : l’utilisateur rapporte 17/17 tests ciblés de `BackupSeriesInspectorTest` et 7/7 régressions ciblées de prévalidation, première copie et neutralité `Historical`, soit 24/24 dans deux sélections distinctes. Aucun test destructif, campagne CTest complète ou essai de production générationnelle n’en est déduit.
- **IMPLÉMENTÉ — frontière destructive 2I-4G-3, isolée de la production** : `BackupSeriesRotationService::rotate()` reçoit explicitement racine, `vault_id`, `series_id`, rétention, identités physiques attendues facultatives, `BackupResult` terminal de la nouvelle publication et contrôle synchrone facultatif d’interruption/tests. Seuls `BackupOutcome::Published`, une destination cohérente et un `BackupFileEvidence::permitsDeletion()` conforme au fichier physique permettent d’envisager la rotation. Un chemin seul, un fichier visible ou une publication de durabilité incertaine ne suffisent pas. Le service ne crée ni nouveau protocole de publication, ni catalogue, ni état persistant.
- **IMPLÉMENTÉ — revalidation et suppression 2I-4G-3** : avant chaque suppression, le service relance `BackupSeriesInspector`, recalcule l’excédent, vérifie la racine, la famille et la série ainsi que leurs identités, refuse l’ambiguïté et une rétention inférieure à sept. Il maintient une réservation exclusive sur la nouvelle sauvegarde et réserve individuellement chaque candidat. Les contrôles incluent fichier ordinaire, propriétaire, permissions `0600`, lien unique, identité/stabilité physiques, structure PassWall légère, `vault_id` et empreinte du fichier. Une dernière réinspection et une réouverture sans suivre les liens précèdent `unlinkat()` relatif au dossier de série vérifié, puis `fsync` du répertoire. La nouvelle sauvegarde ne peut jamais être supprimée : si son horodatage nominal reculé la rend excédentaire, la rotation est refusée sans choisir arbitrairement une autre ancienne version.
- **IMPLÉMENTÉ — résultat indépendant 2I-4G-3** : le service distingue absence de rotation nécessaire, rotation complète, refus avant suppression, rotation partielle, suppression accomplie mais synchronisation non confirmée et résultat inconnu. Il expose séparément les suppressions réellement effectuées et celles dont la synchronisation a été confirmée. Une erreur arrête les suppressions suivantes sans annuler la sauvegarde déjà `Published` ni inventer de restauration, de reprise automatique ou de succès de durabilité.
- **TESTÉ — lot 2I-4G-3** : l’utilisateur rapporte 23/23 tests ciblés de `BackupSeriesRotationServiceTest` et 21/21 régressions `BackupSeriesInspectorTest`/neutralité `Historical`, soit 44/44 dans deux sélections distinctes. Ils couvrent rétention, séries isolées, ancien agencement, publication protégée, horloge reculée, refus conservateurs, substitutions, interruptions, erreurs `unlinkat` et `fsync`, et absence d’écriture des préférences. Ces tests utilisent des sauvegardes fictives et des injections de fautes ; ils ne valent ni campagne CTest complète, ni audit indépendant, ni essai réel de panne matérielle.
- **IMPLÉMENTÉ — raccordement 2I-4G-4 exclusivement dans la GUI de test** : après `BackupJob::processTerminated`, le coordinateur accepte seulement le véritable résultat terminal `BackupResult::Published` après vérification du reçu, de la destination, du jeton, de la génération/session et de la fin effective du worker. `GenerationalBackupRotationController` rejette les résultats synthétiques, incomplets, obsolètes ou dupliqués ; `InitialCopy` et `CrudGeneration` empruntent le même chemin. Aucune publication `Failed`, `Unknown`, annulée ou de durabilité non confirmée ne déclenche la rotation. Le moteur de production ne lie pas ce contrôleur.
- **IMPLÉMENTÉ — asynchronisme et sérialisation 2I-4G-4** : le contrôleur relit les préférences globales, contrôle leur provenance physique ainsi que la racine, la rétention et la série de la publication, puis délègue `BackupSeriesRotationService::rotate()` à un thread dédié, sans accès inter-thread à un `QObject` GUI ni transmission de clé ou de secret. Une file FIFO en mémoire sérialise les publications rapprochées dans le contrôleur ; les doublons terminaux sont refusés, sans retry, journal ou catalogue. Le résultat revient séparément sur le thread propriétaire ; un échec de rotation ne révoque jamais la publication `Published` et ne provoque pas de suspension des sauvegardes.
- **IMPLÉMENTÉ — cycle de vie 2I-4G-4** : la fermeture générationnelle de test attend de façon asynchrone le résultat terminal de la rotation tout en nettoyant immédiatement les secrets. Une destruction directe demande une annulation coopérative ; le travail possède ses ressources et ses contrôles d’arrêt sans dépendre de la survie de la fenêtre. Une suppression déjà effectuée ne peut pas être annulée rétroactivement. L’absence du consommateur après destruction interdit la remise du résultat à celui-ci.
- **IMPLÉMENTÉ — visibilité GUI 2I-4H-2, uniquement en test** : le résultat d’une sauvegarde publiée et celui de sa rotation sont consultables séparément ; un refus, une rotation partielle ou une synchronisation de suppression incertaine ne rétrograde pas la publication confirmée. Le contrôleur d’affichage n’émet aucune nouvelle autorisation de suppression.
- **TESTÉ — 2I-4G-4/4A, portée ciblée** : huit régressions des composants, puis 23/23 tests de rotation et 14/14 tests GUI générationnels exécutés séquentiellement ont réussi. Les premières campagnes parallèles ont échoué (6/23 tests de rotation et 1/14 GUI) ; 2I-4G-4A a isolé le registre QSettings de chaque processus de rotation avec `tests/isolated_vault_settings.cpp` et décomposé les attentes du test GUI de deux publications en étapes observables. Après correctif, 24/24 tests ciblés réussissent sous `--parallel 2`, puis chacun réussit sur vingt répétitions à ordre aléatoire (480 exécutions réussies). Ces sélections se recouvrent, sans constituer une campagne CTest complète ni prouver l’absence de toute course.
- **LIMITE — concurrence** : les réservations sont coopératives et POSIX ne permet pas de supprimer directement un inode ouvert ; une substitution hostile du même utilisateur peut encore intervenir entre la dernière vérification de l’entrée nommée et `unlinkat()`. Les identités `st_dev`/`st_ino` ne garantissent pas une atomicité absolue. Les propriétés des supports réseau ou amovibles doivent être validées séparément.

La séquence cible est simple et sans état persistant propre à la rotation :

1. créer et vérifier la nouvelle sauvegarde ;
2. confirmer suffisamment sa publication ;
3. compter les versions admissibles du seul dossier de série courant ;
4. si leur nombre dépasse la rétention, identifier les plus anciennes ;
5. supprimer seulement les versions admissibles les plus anciennes jusqu'au nombre configuré.

- **VALIDÉ** — aucun catalogue, reçu de rotation, historique de suppression ou système persistant de reprise n'est créé.
- **VALIDÉ ; IMPLÉMENTÉ dans le service 2I-4G-3 et le raccordement de test 2I-4G-4** — une erreur de suppression est un échec de rotation distinct : elle n'efface ni n'invalide la nouvelle sauvegarde déjà publiée. Une suppression visible mais non confirmée par `fsync` conserve un statut incertain propre à la rotation.

La présence d'un fichier, un code de sortie nul ou le début d'une copie ne prouvent pas une publication réussie. Une erreur postérieure ne doit pas provoquer la suppression d'une publication déjà valide.

##### 5.5 Résultats et diagnostics

- **VALIDÉ** — chaque tentative produit un résultat borné et une notification indiquant l’opération concernée.
- **IMPLÉMENTÉ — présentation 2I-4H-2, seulement dans la GUI générationnelle de test** : `GenerationalBackupStatusController` est accessible par l’action de menu « État des sauvegardes… » et par un accès discret dans la barre d’état. Un dialogue non modal présente séparément la sauvegarde, la rotation, la configuration et la suspension ; aucun de ces points d’entrée n’est raccordé à `passwall_app` en production. Le dialogue global de préférences 2I-4H-1 reste distinct.
- **IMPLÉMENTÉ — états distincts** : le contrôleur conserve séparément la progression de l’opération courante, le dernier résultat terminal établi et son diagnostic, et la suspension volatile actuelle. Une nouvelle opération peut afficher son attente ou sa progression sans effacer le dernier résultat consultable ; une progression tardive ou dépourvue de jeton n’efface pas un état terminal. `Published`, `Failed` et `Unknown` restent distincts, de même que les états indépendants de rotation (sans rotation nécessaire, complète, refusée, partielle, synchronisation non confirmée et inconnu).
- **IMPLÉMENTÉ — corrélation et preuves 2I-4H-2/2A/2B** : une offre réellement observée est associée transitoirement à son type (`InitialCopy`/CRUD), son chemin, son `vault_id` de 16 octets, ses identifiants physiques (périphérique et inode non nuls), son jeton et ses générations pertinentes. La date de création (`birthTime`) est facultative et ne devient pas un champ d’autorité : les offres réelles ne la transportent pas toujours. Un statut `Published` exige le résultat terminal authentique, un worker effectivement terminé, une preuve de publication concordante et le chemin publié exact ; résultats anciens, dupliqués, substitués ou liés à une autre génération restent refusés.
- **IMPLÉMENTÉ — cycle de session et reprise explicite** : les offres engagées et résultats authentiques drainés après verrouillage peuvent encore être affichés sans réactiver une session ni relancer de worker. Les inspections distinguent étapes intermédiaires et terminales. L’action « Réessayer la sauvegarde » n’est offerte que pour une suspension réellement admissible du coffre et de la session authentifiée courants, après revalidation et constat de terminaison du worker ; elle appelle uniquement `AutomaticBackupCoordinator::resumeGenerationalBackup()`. Aucun retry automatique, nouveau catalogue ou historique permanent d’erreurs n’est ajouté.
- **TESTÉ — 2I-4H-2 et correctifs 2A à 2E, périmètre GUI** : après les corrections et l’isolation des workers de test, deux scénarios concurrents passent 2/2, puis 40/40 exécutions sous vingt répétitions parallèles aléatoires ; la suite `MainWindowEditorLockTest` passe 119/119 sous `--parallel 2`. Ces campagnes ne sont pas une exécution CTest complète du dépôt ni un audit indépendant. L’intégration et les notifications de production restent **À FAIRE**.
- **VALIDÉ** — lorsque la cause est identifiable, le diagnostic présente la raison et les informations système réellement disponibles, notamment l'`errno` ou le code SQLite pertinent. Aucun code d'erreur n'est inventé.
- **VALIDÉ** — les diagnostics techniques nécessaires restent attachés au résultat d'exécution, sans historique persistant des erreurs.
- **VALIDÉ ; IMPLÉMENTÉ en service 2I-4G-3 et dans la voie GUI de test 2I-4G-4** — un échec de création, un résultat de publication ou de synchronisation non confirmé et un échec de rotation sont distingués. Une sauvegarde publiée avec une suppression ancienne impossible reste une sauvegarde réussie accompagnée d'une erreur de rotation ; la rotation distingue également suppressions confirmées, partielles et non durablement synchronisées. Les diagnostics sont exposés par le contrôleur de test, mais ne sont pas encore affichés dans la GUI de production.
- **VALIDÉ** — lorsqu'une publication est visible mais que sa durabilité n'est pas confirmée, PassWall avertit qu'il ne peut pas garantir la réussite ; il ne transforme pas l'incertitude en succès.
- **À DÉFINIR** — conduite ultérieure exacte pour une publication visible mais de durabilité non confirmée, sans journal de reprise ni nouvelle suppression risquée.

Les diagnostics ne contiennent aucun secret. Des formulations compréhensibles peuvent accompagner, sans les remplacer ni les fabriquer, des causes telles que `ENOSPC` (28), `EACCES` (13) ou un code SQLite effectivement retourné.

##### 5.6 Consultation et copie de travail

- **VALIDÉ** — les versions situées sous la racine gérée sont consultables en lecture seule.
- **VALIDÉ** — leur modification exige la création d'une copie de travail hors du dossier géré.
- **VALIDÉ** — cette copie de travail conserve le `vault_id` ; elle appartient donc à la même famille si elle est ensuite modifiée et sauvegardée.
- **À FAIRE** — définir et implémenter une vraie session de lecture seule empêchant CRUD, Native Messaging d'écriture, suivi de modification et opérations incompatibles ; désactiver seulement les boutons serait insuffisant.
- **À FAIRE** — implémenter la copie de travail par le moteur d'instantané, sans écrasement ni ouverture automatique.
- **À DÉFINIR** — manière de retrouver et consulter les sauvegardes laissées dans une ancienne racine.

#### 6. Implémentation actuelle des sauvegardes et écarts

##### 6.1 Registre monolithique actuel

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

##### 6.2 Exclusion et suivi des mutations

- **IMPLÉMENTÉ** — `VaultOperationGuard` distingue les accès métier partagés, les accès d'instantané partagés et les réservations exclusives de remplacement.
- **IMPLÉMENTÉ — préparation 2I-3B inactive** : la nouvelle préparation acquiert explicitement l'accès d'instantané existant, vérifie son identité physique avec `matchesSnapshotIdentity()`, relit le `vault_id` avec les contrôles de récupération encore actifs et conserve la capacité jusqu'à sa consommation ou sa destruction. Une restauration exclusive ne peut donc pas franchir cette préparation ; les accès métier compatibles restent possibles.
- **IMPLÉMENTÉ — destination 2I-3B/2I-4G-1** : `VaultSnapshotService::inspectDestinationDirectory()` reste la politique d’admission des systèmes de fichiers et chemins. La création familiale et du sous-dossier de série ajoute une ouverture composante par composante sans liens, des identités racine/famille/série stables, des permissions `0700`, une synchronisation des dossiers créés et une revalidation avant usage. Ces contrôles n’affaiblissent ni la publication sans écrasement ni la vérification finale du worker.
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
- **À FAIRE — consommateur de production 2I-4F-3** : le consommateur GUI de test 2I-4F-5A traite l'invalidation des offres non lancées. Lors du futur raccordement en production, le propriétaire de toute `PreparedBackupDestination` CRUD devra également la détruire immédiatement à `generationalBackupRequestInvalidated` ; la revalidation finale interdit sa réutilisation, mais seule cette destruction libère sans délai sa capacité RAII.
- **TESTÉ — lot 2I-4F-3** : l'utilisateur rapporte 11/11 tests des préférences globales, 29/29 tests de préparation des destinations, 150/150 tests du coordinateur et 5/5 tests GUI ciblés réussis. Ils couvrent notamment la modification pendant l'inspection, après préparation, l'indisponibilité de configuration avec générations conservées, la rétention modifiée et le worker déjà actif.
- **IMPLÉMENTÉ — vidange 2I-4F-4A inactive** : `beginGenerationalShutdownDrain()` constitue une frontière propriétaire, asynchrone et idempotente distincte de `shutdown()`. Elle annule sans attente une inspection initiale non achevée, supprime le délai de regroupement d'une génération CRUD effectivement confirmée et laisse la file générationnelle, ses jetons et le consommateur existant terminer le travail. Une mutation confirmée pendant la vidange devient immédiatement une demande distincte ; aucune génération n'est inventée en l'absence de `COMMIT`.
- **IMPLÉMENTÉ — résultat de vidange 2I-4F-4A inactif** : l'état transitoire distingue demande en cours, worker encore vivant, vidange confirmée et vidange achevée avec échec ou suspension. Un worker actif n'est ni annulé ni préempté ; sa réservation et sa supervision restent effectives jusqu'à sa terminaison réelle, puis une génération postérieure est offerte si nécessaire. `Failed`, `Unknown`, configuration devenue inadmissible ou inspection initiale à reprendre ne sont jamais transformés en succès et ne déclenchent aucun retry.
- **IMPLÉMENTÉ — priorité et arrêt 2I-4F-4A** : une opération manuelle déjà admise garde sa place et la demande automatique attend sa libération ; une nouvelle opération manuelle est refusée pendant la vidange. L'arrêt immédiat `shutdown()` conserve sa sémantique historique d'annulation/règlement et demeure séparé de cette frontière progressive.
- **TESTÉ — lot 2I-4F-4A** : les huit tests ciblés de vidange rapportés par l'utilisateur réussissent. Ils couvrent absence de mutation, accélération et regroupement, idempotence, worker réel avec génération postérieure, absence de copie redondante, `Failed`/`Unknown` et enfant encore vivant, admission manuelle antérieure, inspection annulée et configuration obsolète. Ces scénarios font également partie de la suite du coordinateur exécutée après 2I-4F-4B (158/158 réussis).
- **IMPLÉMENTÉ — raccordement GUI 2I-4F-4B, inactif en production** : `MainWindow::closeEvent()` utilise la vidange générationnelle uniquement lorsque le coordinateur a été explicitement construit en mode `Generational`. Une fabrique dédiée aux tests GUI sous `PASSWALL_GUI_TESTING` permet ce parcours ; les constructeurs de production restent en mode `Historical`. À la première demande de fermeture, la fenêtre refuse provisoirement l'événement, engage la vidange, invalide l'accès au coffre et appelle `lockVault()` pour effacer immédiatement les secrets, sans attendre l'inspection ni le worker et sans dialogue modal.
- **IMPLÉMENTÉ — fermeture répétée 2I-4F-4B** : les nouvelles demandes de fermeture pendant une vidange non terminale restent refusées mais ne rappellent plus `lockVault()`. Elles conservent ainsi l'identité physique non secrète et les compteurs du coordinateur nécessaires à la reconnaissance d'un `COMMIT` tardif. Une génération confirmée après le démarrage d'un instantané demeure une demande distincte. Lorsque la vidange devient `Completed` ou `CompletedWithFailureOrSuspension`, une fermeture est programmée automatiquement ; aucun résultat `Failed` ou `Unknown` n'est inventé comme `Published`, aucun nouvel essai n'est lancé et un worker encore vivant ne provoque pas une fermeture anticipée.
- **TESTÉ — lot 2I-4F-4B** : l'utilisateur rapporte 4/4 tests GUI de fermeture et de neutralité du mode production, 5/5 régressions GUI d'export/restauration, puis 158/158 tests du coordinateur réussis. La fixture GUI générationnelle exige une configuration globale valide ; le test de double fermeture vérifie une première génération, un second `COMMIT` pendant la vidange et la terminaison avec échec sans retry. Un test d'inspection asynchrone, intermittent lors d'une campagne précédente, a été stabilisé par une attente bornée de l'offre sans abaisser l'exigence de résultat ; sa cause précise n'est pas démontrée. Ces résultats ne constituent ni une campagne CTest complète ni une activation du moteur générationnel en production.
- **IMPLÉMENTÉ — consommateur GUI 2I-4F-5A, inactif en production** : la fabrique `MainWindow::createForGenerationalTests()` raccorde les offres `InitialCopy`/CRUD au coordinateur, aux destinations préparées et au `BackupJob` réel. L'inspection initiale est reportée au tour de boucle Qt suivant l'enregistrement authentifié et vérifie alors le chemin et la génération de session ; `vault/lastPath` reste persisté après l'enregistrement. En test, le regroupement est ramené à 100 ms sous `PASSWALL_GUI_TESTING`, sans modifier la valeur normale de 20 000 ms. Une mutation validée durant la vidange crée sa propre demande CRUD plutôt que d'être fusionnée avec une génération déjà en attente.
- **IMPLÉMENTÉ — reprise d'inspection 2I-4F-5A** : `InitialBackupPreparer` distingue la contention coopérative (`RetryableContention`) d'un refus de sécurité terminal. Le coordinateur conserve sans secret le contexte de la même inspection logique (préférences, identité physique et session), autorise au plus deux relances, interdit une seconde inspection concurrente et abandonne sur verrouillage, fermeture, changement de session ou de configuration. L'attente `WaitingForRetry` bloque les opérations manuelles incompatibles ; `initialBackupInspectionActive()` reste vrai pendant cette attente, `AlreadyRunning` désigne une activité encore annulable et `AlreadySettled` uniquement une empreinte terminale.
- **IMPLÉMENTÉ — annulation et notifications 2I-4F-5A** : l'annulation d'une attente accepte exclusivement l'identifiant courant, rejette un ancien identifiant et publie un résultat terminal `Cancelled`. Les annulations de cycle de vie sont notifiées au tour de boucle Qt suivant, après révocation des droits correspondants ; un observateur direct de `WaitingForRetry` peut annuler sans armer le minuteur ni recevoir ensuite de résultat intermédiaire obsolète. L'observateur externe optionnel est conservé à travers les relances, avec contexte non propriétaire devant rester valide jusqu'au résultat terminal. Une contention intermédiaire a `terminal == false` ; après épuisement, le résultat est terminal avec diagnostic, sans boucle infinie.
- **TESTÉ — lot 2I-4F-5A, validations ciblées** : après le premier correctif, 117/117 tests de préparation, de coordination et de GUI générationnelle ont réussi ; après clarification des annulations, 103/103 ; après correction de la réentrée et de l’observateur, 105/105 dans le répertoire de build local dédié. Les tests couvrent notamment première copie et CRUD publiées, `COMMIT` tardif, fermeture répétée, contention libérée ou persistante, refus de sécurité, annulations de session/configuration/vidange, ancien identifiant, observateur externe, réentrée dans `WaitingForRetry` et notification tardive. Ces campagnes se recouvrent ; aucune campagne CTest complète n’a été relancée après le dernier correctif.
- **IMPLÉMENTÉ et TESTÉ — réinspection après configuration 2I-4H-1, réservée aux tests** : le contrôleur des préférences globales notifie la sauvegarde confirmée de la configuration, puis la voie GUI générationnelle réinterroge uniquement le coffre toujours authentifié. L’état invalide/absent conserve un besoin volatil de réinspection ; les réponses tardives ne redémarrent pas de worker après perte de session. Les invalidations des demandes non lancées et les protections du worker et de la rotation demeurent celles des lots 2I-4F-3 et 2I-4G-4. Huit nouveaux cas, onze régressions générationnelles et neuf vérifications historiques ont réussi dans les trois sélections rapportées.
- **IMPLÉMENTÉ — information utilisateur 2I-4H-2, seulement en test ; À FAIRE — production** : le contrôleur de statut de la GUI générationnelle de test observe les étapes d’inspection initiale et leurs résultats, sans confondre un état intermédiaire ou une inspection refusée/épuisée avec une sauvegarde publiée. Le parcours de production `Historical` ne possède pas encore cet affichage générationnel ; son intégration lors du basculement demeure nécessaire.
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
- **IMPLÉMENTÉ — séparation publication/rotation 2E, raccordée en test par 2I-4G-4** : ce chemin appelle le worker sans contexte de rotation historique. Une publication confirmée acquitte sa génération indépendamment du résultat de la rotation sans catalogue ; le contrôleur 2I-4G-4 n’est relié que dans la fabrique GUI générationnelle de test, sans activation de production.
- **IMPLÉMENTÉ — preuve de publication 2H-1** : le chemin d'instantané partagé demande désormais explicitement au worker un reçu transitoire. Le résultat lie l'identité stable du fichier publié et de son répertoire, son empreinte SHA-256 et le chemin de destination effectivement contrôlé. `BackupJob` refuse de conserver `Published` si cette preuve manque, vise une autre destination ou ne satisfait pas les critères techniques déjà requis pour une suppression sûre ; comme une publication a pu avoir lieu, ce refus devient `Unknown`, jamais un échec fictivement antérieur à la publication.
- **IMPLÉMENTÉ — liaison au jeton 2H-1/2H-2** : `AutomaticBackupCoordinator` conserve le reçu uniquement en mémoire jusqu'à la terminaison effective du worker, puis vérifie le worker supervisé, le jeton actif, la génération, le chemin du coffre et la destination attendue. Le résultat transitoire unique `MutationBackupResult` transporte cette preuve avec `BackupFileEvidence` et le règlement exact de la génération. Une preuve absente, incomplète, incohérente ou attachée à un résultat tardif ne peut pas acquitter la génération.
- **IMPLÉMENTÉ — séparation rotation 2H-1, consommée en test depuis 2I-4G-4** : le reçu n'est écrit ni dans QSettings ni dans un catalogue ; le lot 2H-1 ne lançait lui-même aucune rotation. Cette preuve transitoire est désormais consommée par le contrôleur générationnel de test après une publication confirmée, sans rattachement au moteur historique.
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
- **À FAIRE — après 2I-4F-5A** : raccorder le consommateur et les préférences globales à la production, puis sélectionner explicitement `Generational` sans maintenir simultanément le déclenchement historique. Conserver les contrôles d'admission, la protection du coffre principal, les diagnostics d'échec et la distinction entre vidange progressive et `shutdown()` immédiat. `Failed` et `Unknown` exigent toujours une reprise explicite pendant la vie du processus.

##### 6.3 Instantané, worker et export manuel

- **IMPLÉMENTÉ** — `VaultSnapshotService` utilise l'API de sauvegarde SQLite pour produire une copie cohérente sans clé de déchiffrement.
- **IMPLÉMENTÉ** — la source et la destination sont ouvertes de manière conservatrice ; les chemins ambigus, liens et types interdits sont refusés.
- **IMPLÉMENTÉ** — la copie est validée structurellement avant publication.
- **IMPLÉMENTÉ — prévalidation légère 2I-4G-2, hors production générationnelle** : `VaultSnapshotService` propose en complément un contrôle structurel léger destiné à l’inspection des anciennes versions, sans `integrity_check` ni parcours exhaustif des entrées. La prévalidation exhaustive utilisée par les parcours existants conserve ses garanties et son comportement.
- **IMPLÉMENTÉ** — la publication est sans écrasement, avec fichier temporaire privé, synchronisation du fichier et du répertoire, puis distinction entre publié, durabilité incertaine, annulé et échec.
- **IMPLÉMENTÉ** — les échecs POSIX et SQLite pertinents conservent dans leur diagnostic les codes réellement observés ; le protocole transmet ce diagnostic sans contenu du coffre.
- **IMPLÉMENTÉ — transport 2H-2** : le coordinateur générationnel conserve ce `BackupResult` jusqu'à la terminaison effective du worker au lieu de le réduire immédiatement à trois états. Son signal de résultat expose simultanément le diagnostic borné, le résultat détaillé et la preuve 2H-1, toujours sans contenu du coffre, clé ou mot de passe.
- **IMPLÉMENTÉ** — `passwall_backup_worker` exécute la copie hors du thread GUI et ne contient aucun moteur de déchiffrement.
- **IMPLÉMENTÉ** — `BackupJob` distingue résultat métier et terminaison effective ; la réservation n'est pas libérée tant que l'enfant peut encore agir.
- **IMPLÉMENTÉ — protocole 2H-1** : lorsqu'un reçu est demandé, le protocole borné associe obligatoirement `BackupFileEvidence` au chemin canonique publié. Le worker construit cette preuve par inspection protégée de la destination après publication et la recoupe avec l'identité vérifiée avant publication ; un chemin seul, un fichier visible ou un code de sortie nul ne suffisent pas.
- **IMPLÉMENTÉ — lot 2F** : l'entrée `BackupJob::start()` utilisée par l'export manuel acquiert une réservation exclusive et utilise le protocole worker historique `--protocol-v1`. Accès métier, restauration et autre instantané du même coffre restent refusés jusqu'à la terminaison effective du worker, y compris après un résultat `Unknown` ou la destruction de la façade Qt.
- **IMPLÉMENTÉ** — seul le chemin explicite `BackupJob::startSnapshotReserved()` et le protocole worker `--snapshot-v1` utilisent l'accès d'instantané partagé : les accès métier restent possibles, tandis qu'une restauration exclusive et un second instantané restent refusés jusqu'à la terminaison effective.
- **IMPLÉMENTÉ — compatibilité temporaire** : le chemin automatique actif de `AutomaticBackupCoordinator` et sa rotation utilisent encore l'ancien chemin exclusif `startReserved()`. La frontière générationnelle appelle le chemin partagé `startSnapshotReserved()` uniquement dans les tests et peut désormais déclencher la rotation sans catalogue par son contrôleur de test 2I-4G-4. Aucun de ces raccordements n'est relié à un signal de production ; le basculement attend l'intégration applicative contrôlée des préférences globales, du nommage cible, de la rotation et des diagnostics.
- **IMPLÉMENTÉ** — l'export manuel verrouille et nettoie le coffre avant de lancer le worker ; il n'impose aucune durée globale arbitraire.
- **TESTÉ — lot 2F** : les trois régressions d'exclusivité de l'export manuel, les 25 cas `BackupJob`, les fondations 2B–2E et la campagne CTest complète séquentielle passent. La campagne compte 928 cas sans échec ; `RestoreParentExitProbe` reste l'unique auxiliaire volontairement ignoré.
- **VALIDÉ** — ces moteurs sont réutilisables par la cible.

Le contrôle actuel des chemins refuse notamment des ancêtres modifiables par un autre utilisateur ou groupe selon sa politique POSIX. PassWall ne doit pas corriger automatiquement les permissions d'un dossier choisi. L'ouverture future à NAS/NFS/CIFS/FUSE/FAT/exFAT ou l'assouplissement de cette politique nécessitent une décision et des contrôles adaptés.

##### 6.4 Coordinateur automatique et rotation actuelle

- **IMPLÉMENTÉ** — `AutomaticBackupCoordinator` résout actuellement un chemin principal vers un `localId`, relit les préférences par coffre et lance une sauvegarde au verrouillage si `backupRequired` est actif.
- **IMPLÉMENTÉ — lots 2I-1/2I-4F-5A/2I-4H-1/2I-4H-2** : le coordinateur possède un sélecteur immuable `Historical`/`Generational`. Les constructeurs de production de `MainWindow` restent exclusivement `Historical` ; la fabrique `PASSWALL_GUI_TESTING` raccorde les offres générationnelles à un consommateur GUI réel et fournit le dialogue global (2I-4H-1) puis la consultation des statuts et la reprise explicite conditionnelle (2I-4H-2). Aucun consommateur de production de `generationalBackupRequested` n’est connecté.
- **IMPLÉMENTÉ** — les noms automatiques utilisent actuellement l'heure locale et l'extension `.db`, avec un suffixe d'opération en cas de collision.
- **IMPLÉMENTÉ** — `BackupRotationService` charge le catalogue, trie les versions par ordre persistant, vérifie leurs preuves puis marque et confirme chaque suppression.
- **IMPLÉMENTÉ** — une suppression incertaine bloque la rotation sans rétracter la nouvelle sauvegarde publiée.
- **IMPLÉMENTÉ — fondation 2I-4G-2** : `BackupSeriesInspector` sélectionne les excédents d’une série sans catalogue ni mutation ; il est réutilisé et relancé par `BackupSeriesRotationService` dans le parcours générationnel de test, mais pas par le coordinateur historique ou le worker de production.
- **IMPLÉMENTÉ et TESTÉ — rotation 2I-4G-3, raccordée exclusivement en test depuis 2I-4G-4** : `BackupSeriesRotationService` supprime les versions admissibles de la seule série courante sous preuve terminale, réservations, réinspections et revalidations répétées ; son résultat reste distinct de la publication. Les 23 tests spécifiques et 21 régressions initialement rapportés réussissent. La bibliothèque demeure hors des dépendances de `passwall_app` ; `BackupRotationService` historique est inchangé et seul `Historical` fonctionne en production.
- **IMPLÉMENTÉ et TESTÉ — contrôleur 2I-4G-4 et correction 2I-4G-4A** : `GenerationalBackupRotationController` est raccordé aux résultats terminaux confirmés du coordinateur dans `MainWindow::createForGenerationalTests()` uniquement, avec FIFO volatile, contrôle de provenance des préférences, rotation hors GUI, résultats et diagnostics indépendants et vidange supervisée. Le correctif 4A ne modifie que CMake et le test GUI : la fixture de rotation réutilise l’isolement QSettings existant pour chaque processus, et l’ordonnancement du test GUI suit distinctement la première copie, la première rotation CRUD bloquée et la seconde publication. La campagne parallèle 24/24 puis vingt répétitions aléatoires (480 exécutions réussies) ne remplace pas une campagne complète.
- **À FAIRE — écart actuel** : le routage générationnel par famille/série est préparé par 2I-4G-1, mais le nommage, les préférences par coffre, les époques de destination et le catalogue du chemin historique de production restent à remplacer.
- **À FAIRE** — remplacer les reçus et états persistants de rotation par le traitement simple décrit en 5.4, tout en réutilisant les contrôles de chemin, les identités et la supervision sans conserver deux moteurs à long terme.

##### 6.5 Interface actuelle des préférences

- **IMPLÉMENTÉ** — `VaultBackupSettingsDialog` et `VaultBackupSettingsController` permettent de choisir un principal enregistré, une activation, une destination et une rétention.
- **IMPLÉMENTÉ** — l'enregistrement compare l'identité et les préférences affichées avant la mise à jour atomique du registre.
- **IMPLÉMENTÉ** — la reprise après suspension est explicite et ne vaut pas réussite de sauvegarde.
- **IMPLÉMENTÉ et TESTÉ — raccordement GUI global 2I-4H-1, exclusivement en test** : `GlobalBackupPreferencesDialog` et son contrôleur asynchrone sont reliés à `MainWindow::createForGenerationalTests()` par l’action `globalBackupPreferencesAction`. Une vérification initiale non bloquante propose le dialogue une fois par session GUI pour `Absent`/`Invalid`/`ReadError` ; la validation et la persistance restent sous `GlobalBackupPreferencesStore`. Le dialogue historique par coffre et `backupSettingsAction` demeurent les seuls points d’entrée de production.
- **IMPLÉMENTÉ — reconfiguration GUI de test 2I-4H-1** : une configuration confirmée peut déclencher, pour le seul coffre encore authentifié, une nouvelle inspection initiale ; l’annulation ne persiste rien, la racine n’est ni créée ni modifiée et les anciens emplacements ne sont ni déplacés ni nettoyés. Fermeture, verrouillage, changement de session ou destruction rendent les réponses tardives inoffensives. Le mode `Historical`, l’export manuel et la restauration de production restent inchangés.
- **IMPLÉMENTÉ et TESTÉ — suivi GUI de test 2I-4H-2/2A–2E** : une action « État des sauvegardes… » et un accès de barre d’état ouvrent un dialogue non modal de résultats et diagnostics. Le dernier résultat terminal est conservé distinctement de l’opération courante et de la suspension ; les statuts de rotation restent autonomes. Une reprise explicite est proposée uniquement pour une suspension réellement courante et admissible, via le coordinateur. La corrélation des offres ne requiert pas `birthTime`, absent de certaines offres réelles, mais continue d’exiger chemin, `vault_id`, périphérique/inode, type, jeton, génération et preuve terminale cohérente. Production inchangée.
- **À FAIRE — écart de production** : promouvoir après validation le dialogue initial et les paramètres globaux déjà accessibles en test, puis retirer l’interface des réglages par coffre avec le moteur historique, sans activer simultanément deux déclenchements.
- **À FAIRE — production uniquement** : retirer avec le moteur historique la suspension persistante et sa reprise par `localId`, puis promouvoir dans l’interface ordinaire le suivi générationnel volatile et la reprise explicite déjà implémentés dans la seule fabrique de test.
- **À FAIRE** — conserver les diagnostics de destination sans modifier automatiquement les permissions du dossier utilisateur.

#### 7. Restauration et récupération

##### 7.1 Cible validée sans journal permanent

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

##### 7.2 Autorisation et moteur actuels

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

##### 7.3 Worker, secrets et supervision

- **IMPLÉMENTÉ** — `passwall_restore_worker` est séparé du worker de sauvegarde.
- **IMPLÉMENTÉ** — sa délégation à usage unique provient de l'autorisation 6A et exige les ressources héritées, l'identité du parent, l'opération et les réservations attendues.
- **IMPLÉMENTÉ** — le maître passe par un canal Unix privé, entre buffers propriétaires, jamais par arguments, environnement, JSON, QSettings ou fichier temporaire.
- **IMPLÉMENTÉ** — le worker valide la délégation avant de recevoir le secret ; tailles, version, ordre, messages partiels, doublons, EOF et déconnexions sont contrôlés.
- **IMPLÉMENTÉ** — `RestoreJob` distingue demande d'annulation, acquittement, nettoyage sensible, résultat métier et terminaison effective.
- **IMPLÉMENTÉ** — `Control1.Lock()` et le nettoyage attendu par logind n'acquittent positivement le nettoyage global qu'après confirmation de la phase sensible ou terminaison effective.
Limite connue : le délai maximal de l'inhibiteur logind ne permet pas de garantir que tout worker ou appel noyau bloqué sera nettoyé avant une transition système.

##### 7.4 Prévalidation et interface

- **IMPLÉMENTÉ** — la GUI prévalide sans mot de passe les sources absentes, inaccessibles, non ordinaires, manifestement non SQLite, structurellement incompatibles ou corrompues avant le verrouillage et la création de `prepared`.
- **IMPLÉMENTÉ** — cette prévalidation n'est ni une authentification ni une autorisation ; la source est revalidée après préparation pour résister aux changements TOCTOU.
- **IMPLÉMENTÉ** — le sélecteur propose les sauvegardes par extension mais permet une sélection libre ; l'extension n'est pas un critère de sécurité.
- **IMPLÉMENTÉ** — annulation avant worker, mauvais maître et autres refus structurés certainement non engagés peuvent utiliser l'abandon contrôlé après terminaison, nettoyage et preuves confirmés.
- **IMPLÉMENTÉ** — résultat `Unknown`, worker vivant, divergence, engagement possible ou persistance non confirmée imposent la récupération manuelle.
- **IMPLÉMENTÉ** — aucune issue ne réouvre automatiquement le coffre.

##### 7.5 Récupération utilisateur

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

##### 7.6 Interruption, artefacts et transition historique

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

##### 7.7 Principal corrompu

- **VALIDÉ** — l'utilisateur sélectionne et confirme explicitement la destination lorsque le principal ne peut plus fournir de métadonnées fiables.
- **VALIDÉ** — la sauvegarde source est intégralement authentifiée, y compris ses entrées chiffrées, avant tout remplacement.
- **VALIDÉ** — chemin, propriétaire, type de fichier, identité physique et opérations concurrentes font l'objet de contrôles stricts ; les liens symboliques et substitutions restent refusés.
- **VALIDÉ** — le candidat complet est préparé sur le système de fichiers du principal, puis l'ancien fichier est conservé par l'échange.
- **À DÉFINIR** — politique exacte de confirmation renforcée et preuve suffisante que la destination choisie est bien celle voulue lorsque son contenu est inexploitable.

#### 8. Interface, verrouillage et préférences locales

##### 8.1 Cycle de vie de la session

- **IMPLÉMENTÉ** — `MainWindow::lockVault()` invalide les sessions Native Messaging avant de détruire la clé.
- **IMPLÉMENTÉ** — les éditeurs ouverts sont nettoyés immédiatement et leurs générations sont révoquées ; un ancien éditeur ne peut pas republier dans une nouvelle session.
- **IMPLÉMENTÉ** — les nettoyeurs RAII restent une protection supplémentaire sans être l'unique mécanisme.
- **IMPLÉMENTÉ** — le chemin critique n'affiche pas de notification modale bloquante.
- **IMPLÉMENTÉ** — le timer est armé dès qu'une session avec clé devient utilisable, avant les rafraîchissements susceptibles d'ouvrir une boucle Qt imbriquée.
- **IMPLÉMENTÉ — lot 2I-4F-4B, uniquement en test générationnel** : `closeEvent()` amorce une vidange asynchrone et un verrouillage sensible immédiat lors de la première fermeture. Les fermetures répétées ne relancent pas le nettoyage et la fenêtre se ferme automatiquement à l'état terminal ; le parcours de production `Historical` reste inchangé.
- **IMPLÉMENTÉ — lot 2I-4F-5A, uniquement en test générationnel** : le consommateur GUI reçoit les offres initiales et CRUD, les invalide lorsqu'elles deviennent obsolètes et délègue les copies au worker commun. L'inspection initiale est déclenchée au tour de boucle Qt suivant l'authentification afin d'éviter la contention immédiate du registre observée lors des tests ; cette temporisation seule ne garantit pas l'absence de contention, traitée par la reprise bornée du coordinateur.
- **IMPLÉMENTÉ — lot 2I-4G-4, uniquement en test générationnel** : une publication réelle peut lancer une rotation asynchrone ; `closeEvent()` attend également la fin de cette rotation dans sa vidange, sans bloquer le nettoyage immédiat des secrets. Une destruction directe demande une annulation coopérative et laisse le travail autonome libérer ses ressources ; la production `Historical` ne lie pas le contrôleur et sa fermeture ne change pas.
- **IMPLÉMENTÉ — lot 2I-4H-1, uniquement en test générationnel** : le dialogue global est accessible depuis une action dédiée, avec proposition initiale non modale unique pour les préférences absentes, invalides ou illisibles. Ses opérations sont asynchrones ; la configuration enregistrée permet une nouvelle inspection uniquement si la session de coffre est encore authentifiée. Les callbacks obsolètes après verrouillage, fermeture ou destruction ne peuvent plus lancer d’activité. Le menu et le contrôleur historiques de production restent inchangés.
- **IMPLÉMENTÉ — lot 2I-4H-2/2A–2E, uniquement en test générationnel** : les états de sauvegarde, rotation, inspection, configuration et suspension sont consultables dans un dialogue non modal, accessible depuis le menu et la barre d’état. Le contrôleur accepte les résultats exactement corrélés d’une opération déjà engagée après fermeture/verrouillage pour les afficher seulement ; il ne restaure jamais l’ancienne session et n’effectue pas de reprise sans action explicite et revalidation. Les corrections de tests isolent également le registre natif `PassWall.conf` des workers `QProcess` par `XDG_CONFIG_HOME` propre à chaque processus CTest ; ce réglage n’est pas une modification du comportement de production.

##### 8.2 Verrouillage automatique obligatoire

- **IMPLÉMENTÉ** — seules les valeurs 1, 5, 15, 30 et 60 minutes sont autorisées ; la valeur par défaut est une minute.
- **IMPLÉMENTÉ** — aucune désactivation n'est disponible.
- **IMPLÉMENTÉ** — anciennes valeurs 0, 10 ou invalides migrées vers une minute avec notification non modale.
- **IMPLÉMENTÉ** — si la persistance échoue, une minute reste appliquée en mémoire et la désactivation ne réapparaît pas.
- **TESTÉ** — 64 cas ciblés couvrent valeurs, défaut, migration, échec de persistance, expiration réelle, éditeurs, Native Messaging, logind et opérations asynchrones.
- **À FAIRE** — essais manuels Wayland des cinq choix et maintien des régressions lors des évolutions GUI.

Le timer mesure l'activité dans PassWall, pas l'inactivité globale du bureau. Aucun délai temps réel n'est garanti si le thread GUI ou le système est bloqué.

##### 8.3 Dernier coffre ouvert

- **IMPLÉMENTÉ dans l'état local actuel** — `vault/lastPath` n'est publié qu'après création ou ouverture authentifiée et enregistrement confirmé, jamais à la simple sélection du fichier.
- **IMPLÉMENTÉ dans l'état local actuel** — au démarrage, seuls les chemins absolus vers un fichier ordinaire lisible et non ambigu préremplissent le champ, sans ouvrir SQLite ni authentifier le coffre.
- **IMPLÉMENTÉ dans l'état local actuel** — une valeur absente, vide, relative, supprimée, inaccessible ou symbolique laisse le champ vide sans effacer la préférence ; un support temporairement absent peut revenir.
- **TESTÉ dans l'état local actuel** — 15 cas ciblés couvrent préférence, sélection, authentification, conservation du registre, session et timer.

`lastPath` est une commodité locale, jamais une preuve d'identité, une autorisation ou un substitut aux protections historiques de récupération encore actives.

#### 9. Firefox et Native Messaging

##### 9.1 Architecture

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

##### 9.2 Validation et travaux restants

- **TESTÉ automatiquement** — `EntryIdParserTest` 9/9, `NativeRequestProcessorTest` 27/27, `NativeRequestResponseTest` 1/1, `SiteMatcherTest` 12/12, `NativeBridgeServerTest` 21/21 avec sockets Unix réels, `passwall_native_host_tests` 6/6.
- **TESTÉ manuellement le 6 novembre 2026** — chargement temporaire Firefox, démarrage automatique, communication, détection du coffre verrouillé, recherche, remplissage, isolation des domaines, refus après verrouillage et redémarrage verrouillé, avec données fictives.
- **À FAIRE** — tests Firefox automatisés de bout en bout, invalidation déterministe pendant la transmission réelle, packaging et installation reproductible du Host et de l'extension.
- **À DÉFINIR** — identifiant et canal de diffusion définitifs de l'extension.

Les tests JavaScript et du bridge ne prouvent pas à eux seuls le parcours complet dans Firefox. Les buffers Qt, système et JavaScript peuvent conserver des copies hors du contrôle direct de PassWall.

#### 10. Protection Linux

##### 10.1 Instance unique et service de contrôle

- **IMPLÉMENTÉ** — une seule instance applicative Linux est admise.
- **IMPLÉMENTÉ** — `org.passwall.PassWall.Control1.Lock()` acquitte le verrouillage après nettoyage local attendu.
- **IMPLÉMENTÉ** — l'ancienne interface `SessionGuard1` est supprimée ; aucune garde globale persistante ou authentification maître globale n'existe.

##### 10.2 logind

- **IMPLÉMENTÉ** — `LinuxSessionMonitor`, indépendant des widgets, surveille `PrepareForSleep` et `PrepareForShutdown` avec Qt DBus.
- **IMPLÉMENTÉ** — un inhibiteur `delay` pour sleep/shutdown est conservé tant que la protection est requise.
- **IMPLÉMENTÉ** — le descripteur est contrôlé par `poll()` ; une simple valeur numérique ou `fcntl(F_GETFD)` n'est pas considérée comme une preuve de pair vivant.
- **IMPLÉMENTÉ** — résolution asynchrone du propriétaire unique de logind, réabonnement par génération et politique fail-closed lors des incohérences.
Limite connue : thread principal bloqué, logind indisponible, crash, arrêt forcé ou délai d'inhibiteur expiré peuvent empêcher un nettoyage avant la transition physique.

##### 10.3 Verrouillage de session Wayland

- **IMPLÉMENTÉ** — `passwall-session-lock` tente `Control1.Lock()` pendant un budget D-Bus de 1 500 ms, puis lance `/usr/bin/swaylock -p` même si PassWall est absent ou ne répond pas.
- **IMPLÉMENTÉ** — une réservation `flock` empêche plusieurs verrouilleurs concurrents pour la même invocation.
- **IMPLÉMENTÉ** — aucun shell ni argument non fiable n'est utilisé.
- **TESTÉ automatiquement** — 21 cas du coordinateur et 10 cas du service de verrouillage sur bus privés et faux verrouilleur.
- **TESTÉ manuellement le 7 novembre 2026** — `Ctrl+Alt+L`, verrouillage préalable du coffre, verrouillage/déverrouillage Linux, coffre restant fermé, refus Firefox puis nouvelle authentification, avec maintien de `Ctrl+Super+L`.
Limite connue : lancer directement swaylock contourne le coordinateur ; l'absence d'acquittement de PassWall ne prouve pas le nettoyage du coffre.

Limite connue : `LockedHint`, le code de sortie de swaylock et son simple affichage ne prouvent ni un déverrouillage normal, ni l'effacement de toutes les allocations historiques.
- **À FAIRE** — installation reproductible et essais contrôlés des véritables transitions suspension, hibernation et arrêt ; vérifier les autres déclencheurs de session et l'ergonomie `pishutdown`.

#### 11. Garanties et limites de sécurité

##### 11.1 Garanties à préserver

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

##### 11.2 Limites inhérentes

- un processus malveillant déjà exécuté sous le même compte utilisateur dépasse le modèle de protection locale des permissions et descripteurs ;
- Qt, la bibliothèque C++, SQLite et le noyau peuvent conserver des copies historiques de secrets ;
- une E/S ou un appel noyau peut rester bloqué malgré une annulation ;
- une demande d'annulation envoyée ne prouve ni sa réception ni la terminaison du worker ;
- `fsync` et les résultats système ne garantissent pas la conservation physique après retrait ou panne du support ;
- `renameat2(RENAME_EXCHANGE)` garantit l'atomicité attendue de l'échange sur les systèmes pris en charge, pas sa durabilité physique absolue après une coupure ;
- sans journal permanent, PassWall ne peut pas toujours déterminer après redémarrage si un échange antérieur a eu lieu ; il authentifie l'état présent et exige une nouvelle demande explicite pour restaurer ;
- les réservations sont coopératives et ne contraignent pas un processus tiers qui les ignore ;
- pour la rotation 2I-4G-3, utilisée seulement dans le parcours générationnel de test 2I-4G-4, POSIX ne permet pas de supprimer atomiquement par inode ouvert : même avec réouverture et contrôle final, un adversaire du même UID peut remplacer l’entrée nommée juste avant `unlinkat()` ;
- le contrôleur de rotation 2I-4G-4 ne sérialise que les tâches de son instance en mémoire ; il n’ajoute pas de verrou interprocessus ni de journal. Après destruction du propriétaire, le résultat final peut ne plus être remis à un observateur supprimé, même si le travail termine ou s’arrête proprement ;
- le suivi GUI générationnel 2I-4H-2 est volontairement volatil et n’est activé que dans la fabrique de test : il ne constitue pas un historique persistant des opérations, ne reconstitue pas les résultats perdus après redémarrage et n’autorise pas la suppression ou la restauration ;
- les systèmes réseau, amovibles ou synchronisés n'ont pas les mêmes propriétés que les systèmes de fichiers locaux testés ;
- une copie cohérente n'empêche pas deux copies de la même famille de diverger ensuite ;
- les tests injectés ne simulent pas intégralement une panne électrique ou matérielle.

#### 12. Validation connue

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
| Requalification locale CTest avant correctifs finaux 2I-4F-5A | 727 tests réussis dans la campagne initiale, 8 entrées `NOT_BUILT`, 1 auxiliaire exécuté directement ; puis 333/333 tests supplémentaires réussis après construction explicite | cibles `EXCLUDE_FROM_ALL`, découverte Google Test, exclusion CTest de `RestoreParentExitProbe` sans suppression du processus auxiliaire ; résultats antérieurs au dernier correctif |
| Consommateur GUI et reprises 2I-4F-5A | 117/117 après premier correctif ; 103/103 après clarification des états ; **105/105 après correction finale** | première copie, CRUD, fermeture et `COMMIT` tardif, contention et deux relances bornées, refus terminaux, annulations, observateur externe et réentrée Qt ; tests ciblés, non suite complète |
| Interface des préférences globales isolée, après 2I-4F-5A | 11/11 stockage, 9/9 GUI Qt offscreen et 2/2 neutralité `Historical` : **22/22 ciblés réussis** | validation `quint64`, états et erreurs de configuration, absence d’écriture à l’annulation, non-création de destination, indépendance exacte de `PassWall.conf` ; aucun raccordement de production, ni campagne complète |
| Séries par installation 2I-4G-1 | **41/41** identité/destination/première copie, **101/101** coordinateur et neutralité historique, **4/4** GUI : **146/146 ciblés réussis** | dérivation déterministe, séries distinctes, sous-dossiers privés, ancien agencement préservé, première copie de B malgré A, réservations RAII, Qt test-only ; `libsystemd` 257 détectée, Windows non implémenté et aucune campagne complète |
| Inspection non destructive 2I-4G-2 | **17/17** inspection des séries et **7/7** régressions : **24/24 ciblés réussis** | sélection et tri UTC numérique, rétention `quint64`, isolation A/B, validation légère SQLite/PassWall, ambiguïtés, substitutions, absence de mutation et neutralité historique ; tests réalisés avant 2I-4G-3 |
| Rotation destructive isolée 2I-4G-3 | **23/23** service de rotation et **21/21** régressions : **44/44 ciblés réussis** | réservations et suppressions contrôlées, revalidation avant chaque `unlinkat`, synchronisation et résultats partiels/incertains, publication protégée même avec horloge reculée, isolation des séries, neutralité `Historical` ; aucun raccordement de production ni campagne complète |
| Raccordement générationnel 2I-4G-4, premières campagnes | **8/8** régressions des composants ; **23/23** rotation et **14/14** GUI en séquentiel ; campagne parallèle initiale : **17/23** rotation et **13/14** GUI | publication réelle `InitialCopy`/CRUD, rotation asynchrone et FIFO, préférences revalidées, diagnostics séparés, fermeture/destruction et neutralité `Historical` ; échecs parallèles initialement observés, ensuite analysés dans 4A |
| Stabilisation parallèle 2I-4G-4A | Après correctif : **24/24** tests en parallèle, puis **24 × 20 = 480 exécutions réussies** avec `--schedule-random --repeat until-fail:20` | isolement QSettings des fixtures de rotation par processus via `tests/isolated_vault_settings.cpp`, synchronisation GUI en trois phases et diagnostics de checkpoint ; 504 exécutions réussies sur ces deux campagnes, pas 504 tests distincts ; aucune campagne complète |
| Intégration GUI des préférences globales 2I-4H-1 | **8/8** nouveaux tests, **11/11** régressions générationnelles, **9/9** vérifications `Historical`, sous Qt offscreen et `--parallel 2` | proposition initiale non modale, action réservée aux tests, annulation sans création, première copie après configuration confirmée, rétention `UINT64_MAX`, coffre vide/fermé, réponse tardive, invalidation et neutralité production ; 28 exécutions dans des sélections potentiellement recoupées, aucune campagne complète |
| Présentation et corrélation GUI 2I-4H-2/2A/2B | Après 2B : **7/7** scénarios ciblés et **119/119** GUI en séquentiel ; une répétition parallèle a encore échoué | menu et barre d’état, dialogue non modal, résultat terminal distinct de la progression et de la suspension, preuve `Published` et rotation indépendantes ; correction d’une comparaison trop stricte sur `VaultFileIdentity::birthTime` et fixture synthétique de rotation ; la stabilité parallèle n’était pas acquise à ce stade |
| Diagnostics et synchronisation GUI 2I-4H-2C/2D | Test 320 initialement intermittent ; puis échec du test 322 sous concurrence, classé `FailedBeforePublication` | attentes distinctes par offre, worker, résultat et rotation, jetons/générations vérifiés ; instrumentation sans correction métier spéculative révélant « Configuration occupée ; réessayer explicitement. » dès `InitialCopy` dans un cas |
| Isolation native des workers 2I-4H-2E, validation finale ciblée | **2/2** tests 320/322 parallèles ; **40/40** répétitions parallèles aléatoires ; **119/119** `MainWindowEditorLockTest` sous `--parallel 2` | `QSettings::setPath()` n’était pas hérité par les workers `QProcess`, qui concurrençaient le même `PassWall.conf.registry-lock` via `tryLock(0)` ; la fixture exporte un `XDG_CONFIG_HOME` natif privé par processus avant lancement du worker, sans contourner le verrou. **161 exécutions réussies** dans ces trois campagnes ; pas 161 cas distincts ni une campagne CTest complète |
| GitHub ARM64 1.26 | 887 réussis, 1 ignoré | ensemble CTest enregistré |
| JavaScript extension | 5/5 localement | tests unitaires Node.js, pas Firefox réel |

Principes d'interprétation :

- **TESTÉ** ne signifie pas certifié ni validé sous panne électrique.
- Les sélections ciblées se recouvrent ; leurs totaux ne mesurent pas le nombre global de tests uniques du dépôt.
- Les bus D-Bus privés, faux logind, faux verrouilleurs et Qt offscreen ne remplacent pas une transition système réelle.
- Les essais Firefox et Wayland sont des observations manuelles avec données fictives, séparées des tests automatisés.
- Les anciens échecs `EPERM` de sockets ou identités artificielles dans un sandbox ne sont pas des défauts applicatifs lorsqu'ils disparaissent dans l'environnement POSIX autorisé sans relâcher les protections.

##### 12.1 Principales suites existantes

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

#### 13. Plan de refonte des sauvegardes

L'ordre ci-dessous peut être ajusté si l'analyse des dépendances l'impose, sans retirer une garantie au seul motif qu'elle appartient au code historique.

##### Lot 0 — spécification, décisions et caractérisation

- **VALIDÉ — lot 0B** — le suivi des modifications métier est limité à la mémoire de la session et commence seulement après `COMMIT` ; l'interruption avant publication confirmée peut donc laisser une sauvegarde non rattrapée automatiquement ;
- **VALIDÉ — lot 0B** — le dossier familial, le nom UTC, les collisions, la première copie et les bornes de rétention sont spécifiés par les sections 5.2 à 5.4 ;
- **VALIDÉ — lots 0C/2I-4F-1** — seuls les coffres ouverts sont pris en charge, chaque tentative produit un résultat et une notification sans suspension persistante ; `Failed` et `Unknown` suspendent seulement en mémoire jusqu'à reprise explicite, et la rotation suit une publication suffisamment confirmée sans catalogue ni reçu persistant ;
- **TESTÉ — lot 0A** — 320 cas ciblés caractérisent les transactions, interruptions injectées, publications, réservations, workers, remplacement et preuves historiques de l'implémentation actuelle ;
- **À FAIRE** — trancher les points restant ouverts de la section 14 ;
- **Critère de sortie** — règles explicites pour les artefacts, la destination corrompue, l'admission à la rotation, les préférences, les échecs de sauvegarde et la compatibilité historique.

##### Lot 1 — découplage des préférences et transition historique

- **À FAIRE** — séparer les préférences ordinaires des contrôles de sécurité encore utilisés par les opérations historiques ;
- **À FAIRE** — préparer l'arrêt des nouvelles intentions persistantes sans supprimer ni déplacer aveuglément les preuves existantes ;
- **À FAIRE** — caractériser la coexistence temporaire avec les versions anciennes de PassWall ;
- **Critère de sortie** — perdre les préférences ordinaires ne bloque pas un coffre sain, tandis qu'une opération historique inachevée conserve ses protections actuelles.

##### Lot 2 — préférences globales et familles `vault_id`

- **IMPLÉMENTÉ et TESTÉ — fondation 2I-3A** : un fichier INI utilisateur distinct stocke la racine, la rétention minimale de sept et un état explicite d'absence, validité, invalidité ou erreur, sans modifier le registre historique. Les dix tests ciblés rapportés sont réussis ;
- **IMPLÉMENTÉ et TESTÉ — fondation 2I-3B** : le préparateur inactif route une identité de coffre vérifiée vers sa famille `vault_id`, crée le sous-dossier privé, choisit un nom UTC sans réserver ni publier de fichier et conserve la capacité d'instantané ainsi que les identités nécessaires à une revalidation. Les onze tests ciblés rapportés sont réussis ;
- **IMPLÉMENTÉ et TESTÉ — GUI globale isolée après 2I-4F-5A** : dialogue Qt et contrôleur hors thread GUI, validation `GlobalBackupPreferencesStore::validate()`, rétention de sept à `quint64::max()`, annulation sans persistance et erreurs explicites. La bibliothèque dédiée est exclue du build par défaut et n’est pas liée à `passwall_app` ; 11/11 tests de stockage, 9/9 GUI et 2/2 régressions `Historical` ciblées réussissent ;
- **IMPLÉMENTÉ et TESTÉ — séries 2I-4G-1, inactives en production** : dérivation stable par installation et `vault_id`, sous-dossier de série privé, coexistence non destructive du format historique et décision de première copie limitée à la série courante. Les 146/146 tests ciblés rapportés réussissent ; l’inspection et la rotation générationnelles 2I-4G-2/3 sont désormais raccordées seulement à la fabrique GUI de test par 2I-4G-4 ;
- **IMPLÉMENTÉ et TESTÉ — intégration de test 2I-4H-1** : l’action GUI globale, la proposition initiale, les sauvegardes de paramètres et la réinspection conditionnelle du coffre authentifié sont raccordées à la fabrique générationnelle de test. Les campagnes ciblées rapportées réussissent (8/8 nouveaux tests, 11/11 régressions, 9/9 tests historiques) ; l’état `Valid` ne constitue toujours pas à lui seul une autorisation d’écrire dans la destination ;
- **À FAIRE** — retirer la liste permanente des coffres comme condition de la gestion automatique ; un coffre est pris en charge lorsqu'il est effectivement ouvert ;
- **À FAIRE — production uniquement** : intégrer le dialogue global initial et les paramètres dans le parcours ordinaire à la place des réglages par coffre, après contrôle des dépendances historiques et sans activer prématurément ou simultanément les moteurs `Historical` et `Generational` ;
- **Critère de sortie** — deux copies de même famille alimentent le même dossier sans que `vault_id` devienne une autorisation.

##### Lot 3 — sauvegarde automatique et rotation sans catalogue

- **IMPLÉMENTÉ — fondation** : le garde, le moteur d'instantané et le worker possèdent un accès partagé typé, transmissible et sérialisé par coffre ; le coordinateur automatique historique reste provisoirement exclusif.
- **IMPLÉMENTÉ — fondation 2A** : les ajouts, modifications et suppressions confirmés exposent un événement en mémoire après `COMMIT` ;
- **IMPLÉMENTÉ — fondation 2B** : le coordinateur regroupe ces événements par session avec un délai mono-coup de vingt secondes et des générations en mémoire, puis émet une demande interne sans lancer de copie ;
- **IMPLÉMENTÉ — fondation 2C** : le verrouillage ordinaire transforme une génération encore planifiée en demande différée unique après l'invalidation synchrone de la session ; le nettoyage des secrets n'attend aucun consommateur ni aucune copie ;
- **IMPLÉMENTÉ — fondation 2D** : offres, tentative active et générations différées sont sérialisées en mémoire par des jetons à usage unique ; seul un résultat correspondant à la tentative active peut la terminer, sans acquitter les générations postérieures ;
- **IMPLÉMENTÉ — fondation 2E** : la frontière peut lancer `BackupJob::startSnapshotReserved()` avec une capacité partagée contrôlée, marque la tentative avant le lancement, lie le résultat au jeton et attend la terminaison effective avant de publier `Published`, `Failed` ou `Unknown`. Elle n'exécute pas elle-même de rotation ; le contrôleur de test 2I-4G-4 réalise cette étape séparée, et aucun de ces chemins n'est encore consommé en production ;
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
- **IMPLÉMENTÉ et TESTÉ — consommateur et inspection 2I-4F-5A, inactifs en production** : la GUI injectée consomme les offres `InitialCopy`/CRUD avec le worker réel, maintient distinctes les générations confirmées pendant la vidange et diffère l’inspection initiale après l’enregistrement authentifié. La contention coopérative seule provoque au plus deux relances ; les contrôles de sécurité restent terminaux, l’attente est annulable et observable, et une réentrée pendant `WaitingForRetry` ne publie pas de résultat intermédiaire périmé. Les validations ciblées rapportées sont 117/117, puis 103/103, puis 105/105 après la dernière correction ; aucune campagne CTest complète postérieure ne doit en être déduite ;
- **IMPLÉMENTÉ et TESTÉ — identité de série 2I-4G-1, inactive en production** : `BackupSeriesIdentity` dérive un identifiant versionné de la machine et du `vault_id`, distinct du contenu du coffre ; les préparateurs, l’inspection et les capacités physiques sont adaptés à `racine/vault_id/series_id/`. Les sauvegardes sous l’ancien emplacement sont préservées et ne couvrent pas la première copie d’une nouvelle série. Les validations ciblées rapportées sont 41/41, 101/101 et 4/4 ; Windows et l’intégration de production de la rotation restent à réaliser ;
- **IMPLÉMENTÉ et TESTÉ — inspection 2I-4G-2, non destructive et inactive en production** : `BackupSeriesInspector` filtre les versions d’une série, contrôle leur admissibilité technique par prévalidation SQLite/PassWall légère, trie les noms UTC et leurs suffixes numériques, puis calcule les excédents sans catalogue ni mutation. Toute ambiguïté interdit une sélection destructive ; la rotation 2I-4G-3 revalide indépendamment les cibles. Les 17/17 tests de l’inspecteur et 7/7 régressions concernées réussissent ; son usage par le contrôleur reste limité au parcours générationnel de test ;
- **IMPLÉMENTÉ et TESTÉ — rotation destructive 2I-4G-3, isolée de la production** : après un `BackupResult` terminal `Published` et un `BackupFileEvidence` cohérent, `BackupSeriesRotationService::rotate()` réinspecte la seule série, protège la nouvelle publication, revalide chaque excédent sous réservations et réalise `unlinkat()` puis `fsync`. Les résultats distinguent aucune rotation, réussite, refus, partialité, durabilité non confirmée et inconnu ; ils n’altèrent jamais le résultat de la sauvegarde publiée. Les 23/23 tests du service et 21/21 régressions ciblées rapportés réussissent. Limites : suppression par nom non atomique face à un adversaire du même UID, réservations coopératives, service lui-même synchrone mais utilisé depuis un thread dans le parcours de test, aucune activation générationnelle en production ;
- **À FAIRE** — raccorder le consommateur unique de production et les préférences globales, construire explicitement le coordinateur de production en mode `Generational`, puis retirer le suivi historique persistant après validation de la transition, sans réintroduire de dialogue de fermeture « attendre ou quitter » ;
- **À FAIRE** — appliquer une rétention globale de sept par défaut, configurable à partir de sept sans plafond arbitraire de produit ;
- **IMPLÉMENTÉ et TESTÉ — raccordement asynchrone 2I-4G-4, fabrique GUI de test uniquement** : après terminaison réelle du worker et confirmation de `Published`, le coordinateur remet un résultat complet authentique à `GenerationalBackupRotationController`. Celui-ci revalide préférences et identité physique de leur fichier, sérialise les rotations en FIFO volatile, exécute le service hors GUI, protège publication et anciennes séries, expose un résultat indépendant et supervise l’arrêt sans tâche orpheline. Les 8/8 régressions des composants, puis 23/23 rotations et 14/14 GUI en séquentiel passent, mais le premier lancement parallèle a révélé des fixtures insuffisamment isolées ;
- **IMPLÉMENTÉ et TESTÉ — correctif 2I-4G-4A, sans changement applicatif** : la fixture de rotation isole QSettings par processus via l’environnement `isolated_vault_settings.cpp` ; le test GUI des publications rapprochées observe séparément l’achèvement de `InitialCopy`, le blocage de la première rotation CRUD et la seconde publication mise en file, sans élargir les délais de dix secondes. Les 24/24 tests parallèles réussissent, puis leurs vingt répétitions avec ordonnancement aléatoire (480 exécutions) réussissent ; ces résultats n’équivalent pas à une campagne CTest générale ;
- **IMPLÉMENTÉ et TESTÉ — accès aux préférences globales 2I-4H-1, test seulement** : lecture initiale et dialogue non modal proposés une fois en l’absence de configuration valide, action globale explicite, lecture/écriture hors GUI, persistance sans créer le dossier choisi, relecture et nouvelle inspection uniquement pour la session encore authentifiée. Les réponses tardives sont neutralisées et la reconfiguration utilise les invalidations déjà sécurisées. Les trois campagnes ciblées rapportées réussissent : 8/8, 11/11 et 9/9 ;
- **IMPLÉMENTÉ et TESTÉ — état des sauvegardes 2I-4H-2 et correctifs 2A–2E, fabrique GUI de test uniquement** : menu et barre d’état donnent accès à la consultation non modale des sauvegardes, rotations, inspections, configurations et suspensions ; progression, dernier terminal et suspension sont indépendants. Une reprise explicitement sollicitée n’est possible que dans la session courante et après revalidation ; seules les publications réelles, terminées et prouvées apparaissent comme `Published`, sans prétendre qu’une rotation refusée invalide la copie. 2A/2B corrigent la corrélation des offres et l’identité physique (`birthTime` facultatif), 2C synchronise les attentes des tests CRUD, 2D instrumente un échec non expliqué et 2E isole le registre natif hérité par les workers sous `XDG_CONFIG_HOME` privé. Validation finale : 2/2 en parallèle, 40/40 en vingt répétitions et 119/119 GUI en parallèle, sans campagne CTest globale ni activation en production ;
- **À FAIRE — future intégration de production** : promouvoir les préférences globales déjà raccordées en test, la rotation, les résultats et notifications utilisateur au parcours applicatif en supprimant le mode de sauvegarde historique de façon contrôlée ; conserver l’indépendance `Published`/rotation, les admissions et les garanties de fermeture. Aucun catalogue, reçu de rotation persistant ou mécanisme de reprise automatique ne doit apparaître ;
- **À FAIRE — production** : promouvoir le résultat générationnel détaillé et sa notification utilisateur déjà testés en 2I-4H-2 (y compris l’inspection initiale et la reprise explicite), en conservant la séparation entre publication confirmée, rotation, progression et suspension ainsi que les diagnostics système réellement disponibles ;
- **À FAIRE** — supprimer la suspension persistante et les boucles historiques lors du retrait du moteur `Historical`, tout en raccordant à la future interface la reprise explicite de la suspension générationnelle volatile ;
- **Critère de sortie** — aucune rotation n'exige de catalogue individuel, aucun fichier ambigu, hors périmètre ou modifié concurremment n'est supprimé, une erreur de rotation ne rétracte pas la nouvelle sauvegarde et une interruption n'est pas présentée comme automatiquement rattrapée.

##### Lot 4 — restauration atomique sans journal et autorisation transitoire

- **À FAIRE** — conserver un moteur unique, l'authentification complète, le canal secret, les réservations, les revalidations et l'échange atomique ;
- **À FAIRE** — remplacer les intentions et reçus permanents par un engagement supervisé uniquement pendant l'opération ;
- **À FAIRE** — après interruption, authentifier l'état présent sans nouvel échange automatique ni prétention de reconstituer un historique indémontrable ;
- **Critère de sortie** — aucune donnée sérialisée ne permet de forger une autorisation et les résultats incertains restent présentés comme tels.

##### Lot 5 — principal corrompu, consultation et copies de travail

- **À FAIRE** — admettre une destination corrompue sous sélection explicite, confirmation renforcée et contrôles stricts ;
- **À FAIRE** — exposer une lecture seule réelle des sauvegardes gérées ;
- **À FAIRE** — créer une copie de travail hors racine sans changer le `vault_id` ;
- **Critère de sortie** — l'ancien principal est conservé, aucune ouverture automatique ne suit le remplacement et aucune écriture n'est possible depuis la consultation en lecture seule.

##### Lot 6 — retrait des mécanismes historiques et audit final

- **À FAIRE** — résoudre ou maintenir bloqués les états historiques encore actifs avant de retirer leur porte d'admission ;
- **À FAIRE** — supprimer intentions, phases, reçus, catalogue, préférences par coffre et ancien code uniquement après disparition de leur dernier appelant et transfert des garanties pertinentes ;
- **À FAIRE** — retirer ou réécrire les tests devenus purement historiques sans perdre les scénarios de sécurité réutilisables ;
- **Critère de sortie** — une seule architecture de préférences, sauvegarde, rotation et restauration demeure, sans nouveau journal permanent PassWall.

#### 14. Décisions techniques encore ouvertes

1. **À DÉFINIR** — possibilité de désactiver les sauvegardes après la configuration initiale.
2. **À DÉFINIR** — comportement exact d'une nouvelle ouverture sans sauvegarde admissible après un échec précédent : distinguer une nouvelle tentative liée à une nouvelle utilisation d'une boucle automatique répétée.
3. **IMPLÉMENTÉ et TESTÉ — 2I-4G-3/4/4A et présentation 2I-4H-2 exclusivement dans la voie générationnelle de test ; À FAIRE — production** : l’admission destructive est conditionnée à `Published` et à une preuve transitoire de publication valide ; les excédents sont recalculés et revalidés avant chaque `unlinkat`, suivi de `fsync`. Le contrôleur de test relit les préférences, vérifie la provenance physique du fichier, exécute la rotation hors GUI et distingue son résultat de la publication, désormais consultable dans le dialogue de statut de test. Une preuve historique individuelle n’est pas exigée pour les anciennes versions admissibles. Restent l’intégration de production, la validation complète et les limites de sérialisation seulement locale et de course hostile du même UID avant suppression nommée.
4. **À DÉFINIR** — conduite après une publication visible dont la synchronisation ou la durabilité n'est pas confirmée, sans inventer un succès, une suppression ou un journal de reprise.
5. **À DÉFINIR** — conditions précises permettant d'arrêter la création des intentions historiques, de résoudre les états restants puis de retirer leur porte d'admission sans période contradictoire.
6. **À DÉFINIR** — compatibilité et politique de retour à une ancienne version de PassWall capable de recréer des intentions dans `vaultRegistry/data`.
7. **À DÉFINIR** — emplacement, nommage, signalement et nettoyage volontaire des anciens principaux et autres artefacts ; aucune seconde copie de précaution systématique n'est prévue.
8. **À DÉFINIR** — confirmation renforcée et identification suffisante pour remplacer une destination corrompue dont le `vault_id` et les métadonnées sont illisibles.
9. **À DÉFINIR** — comportement détaillé après interruption lorsque plusieurs fichiers sont sains ou lorsqu'aucun ne peut être authentifié, sans reprise automatique de l'échange.
10. **À DÉFINIR** — politique sur les plateformes ou systèmes de fichiers dépourvus d'un échange atomique équivalent à `RENAME_EXCHANGE` ; aucun remplacement non atomique silencieux ne doit être introduit.
11. **À DÉFINIR** — accès aux anciennes racines après changement de destination.
12. **À DÉFINIR** — politique d'acceptation des chemins ayant un ancêtre modifiable par le groupe, systèmes de fichiers non pris en charge et supports NAS/amovibles indisponibles ou déconnectés.
13. **VALIDÉ — principe ; IMPLÉMENTÉ et TESTÉ dans la voie générationnelle de test ; À FAIRE — intégration de production** : chaque installation identifiée conserve sa série au sein de la même famille `vault_id`, avec rétention indépendante ; la première copie de B n’est pas bloquée par A. Les clones partageant leur identité d’installation et plusieurs principaux indépendants sur la même installation constituent des limites acceptées à documenter. L’inspection, la suppression et le raccordement automatique de test sont couverts par 2I-4G-2/3/4/4A ; aucun parcours automatique de production n’utilise encore cette rotation.

#### 15. Travaux transversaux restants

##### 15.1 Sécurité et qualité V1

- **À FAIRE** — audit global des copies sensibles, du presse-papiers, des logs, messages et nouvelles tâches asynchrones ;
- **À FAIRE** — revue cryptographique V1 documentée ;
- **À FAIRE** — tests supplémentaires de corruption, fichier inaccessible, espace insuffisant et E/S, sans les présenter comme des pannes matérielles réelles ;
- **À FAIRE** — conserver les tests des champs obligatoires, transactions, RAII, timer, éditeurs, Native Messaging, récupérations historiques pendant la transition et interruptions de la restauration cible ;
- **À FAIRE** — campagne complète actuelle après les lots de refonte, sans masquer les tests instables ou ignorés ;
- **À FAIRE** — essais contrôlés de panne/interruption sur supports fictifs et documentation des résultats incertains.

##### 15.2 Firefox

- **À FAIRE** — automatisation de bout en bout avec Firefox réel ;
- **À FAIRE** — installation versionnée du manifeste, du Native Host et de l'extension ;
- **À FAIRE** — scénarios d'invalidation pendant une réponse réellement transmise ;
- **À FAIRE** — revue de la durée de vie des secrets dans l'extension.

##### 15.3 Produit

- **À FAIRE** — TOTP ;
- **À FAIRE** — passkeys ;
- **À FAIRE** — audit des mots de passe ;
- **À FAIRE** — export de la configuration globale, sans inventer un import non spécifié ;
- **À FAIRE** — ergonomie et diagnostics des supports indisponibles, destinations invalides et résultats incertains.

##### 15.4 Plateformes et distribution

- **À FAIRE** — installation Linux reproductible de l'application, des deux workers, du Native Host, du coordinateur et de l'extension ;
- **À FAIRE** — vérifier les incompatibilités de versions et auxiliaires absents ;
- **À FAIRE** — validation Windows en machine virtuelle, notamment choix et vérification d’une identité d’installation stable adaptée aux applications Win32 avant toute dérivation de `series_id` ; `SystemIdentification.GetSystemIdForPublisher()` reste une piste, non implémentée. La conception iOS viendra après stabilisation Linux/Windows ;
- **À FAIRE** — fournir un `README.md`, un `SECURITY.md` et un `CHANGELOG.md` adaptés à la diffusion ;
- **À FAIRE** — documenter les plateformes et systèmes de fichiers effectivement supportés.

#### 16. Critères de candidature à une V1

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

#### 17. Règles de maintenance de cette référence

Après chaque changement :

1. mettre à jour le statut concerné sans présenter une décision cible comme déjà implémentée ;
2. indiquer les composants modifiés, les tests réellement exécutés et leurs limites ;
3. conserver les garanties historiques encore actives, même si leur implémentation change ;
4. retirer les descriptions et composants obsolètes dès que leur dernière dépendance est migrée et testée ;
5. ne pas recréer un TODO ou un document architectural parallèle sans décision explicite.

Les comptes rendus de développement doivent distinguer essais automatisés, observations manuelles, injections de fautes et transitions système réelles. Cette référence ne constitue pas une certification de sécurité.
