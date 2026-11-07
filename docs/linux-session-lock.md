# Coordinateur Linux de verrouillage — intégration locale validée

État documentaire du 7 novembre 2026 : installation locale et parcours des
raccourcis fonctionnellement validés par l'utilisateur sur Raspberry Pi 5 /
Debian 13 / labwc 0.20.2. Les résultats automatisés, les observations réelles et
les limites sont distingués ci-dessous. Aucune compilation, exécution de tests,
modification de configuration ou transition système n'est effectuée pour cette
mise à jour documentaire.

## Contrat

`passwall-session-lock` est une commande Linux sans argument public. Elle tente
un seul appel `org.passwall.PassWall.Control1.Lock()`, sur le bus utilisateur,
sans activation de PassWall ni autorisation interactive. Seule une réponse
D-Bus positive sans argument confirme le nettoyage ; absence, erreur, réponse
mal formée et expiration ne sont jamais assimilées à cet acquittement. Aucun
contenu de réponse ou message d'erreur distant n'est journalisé.

Le service `SessionLockService` de l'instance PassWall expose `Lock() -> ()` sur
le nom `org.passwall.PassWall`, chemin `/org/passwall/PassWall`. Il délègue à
`MainWindow::requestExternalLock()` et à `lockVault()` sur le thread Qt
propriétaire. L'acquittement n'est envoyé qu'après la fin du verrouillage et la
vérification du nettoyage applicatif : invalidation des générations Native
Messaging et des portions de réponse encore détenues par l'application avant
destruction de la clé, nettoyage immédiat des éditeurs, des résumés, des champs
et du suivi du presse-papiers. Aucun dialogue modal de notification ne retarde
ce nettoyage ; les protections RAII et contre les réentrances sont conservées.
Cet acquittement ne prouve pas l'effacement physique de toutes les allocations
historiques de Qt ou des buffers du système.

Le budget de cette étape est de **1 500 ms**, démarrage de l'auxiliaire compris.
Ce compromis laisse une courte possibilité de nettoyer le coffre sans retarder
longuement le verrouillage de l'écran. L'appel se déroule dans un auxiliaire du
même exécutable (`--dbus-lock-worker`, usage interne). Ainsi, même une attente
synchrone interne de `connectToBus()` ne bloque pas la minuterie du coordinateur.
À l'expiration, l'arrêt de l'auxiliaire est demandé sans attendre sa terminaison
avant le lancement du verrouilleur. Sa destruction peut attendre sa terminaison,
mais intervient après la tentative de lancement, pas dans l'attente préalable
de PassWall. Ce budget
D-Bus n'est pas une garantie temps réel globale si le coordinateur lui-même
est suspendu, si l'ordonnanceur tarde ou si le système manque de ressources.

Dans tous ces cas, le coordinateur tente ensuite de lancer exactement
`/usr/bin/swaylock -p`, sans shell et sans option de substitution à l'exécution.
Une réponse tardive ne peut pas provoquer un second lancement. Les erreurs de
lancement, les sorties non nulles et les crashs du verrouilleur sont signalés
sur stderr avec un code de sortie 1. stdout reste inutilisé. Le code 0 n'est
**pas** une preuve de verrouillage effectif ni de déverrouillage de Wayland.
Une option publique inconnue est refusée avec le code 64.

Le coordinateur reste vivant pendant le processus de verrouillage uniquement
pour dédupliquer les demandes : il ne maintient aucune interdiction d'accès au
coffre. Une authentification manuelle dans le coffre choisi est autorisée après
l'acquittement, sous réserve des protections logind et Control1 existantes.
Aucune clé ni ancienne session n'est restaurée, y compris après le déverrouillage
de Linux. Chaque coffre conserve son indépendance cryptographique et son propre
mot de passe maître ; il n'est pas nécessaire de rouvrir le dernier coffre.

**Décision définitive :** `SessionGuard1` a été supprimé. Il n'existe ni jeton de
garde à acquérir/libérer, ni garde persistante globale, ni authentification globale
supplémentaire. PassWall ne modifie pas le code de swaylock, labwc ou Wayland.
Il ne surveille pas l'état réel de déverrouillage, ne synchronise pas `LockedHint`
et n'utilise pas `--ready-fd`. L'authentification d'un coffre n'est pas une preuve
indépendante de déverrouillage Wayland ; cette preuve n'est pas une condition de
la nouvelle politique d'authentification manuelle.

## Demandes concurrentes et limites

Un `flock(LOCK_EX | LOCK_NB)` protège
`/run/user/<uid>/passwall-session-lock.lock`. Le répertoire doit être celui de
`XDG_RUNTIME_DIR`, appartenir à l'utilisateur et être de mode 0700 ; le fichier
est ouvert sans suivre de lien symbolique et contrôlé (fichier régulier, un
seul lien, propriétaire courant, mode 0600). Le fichier vide n'est jamais
supprimé : son existence n'est pas une garde persistante, seul le descripteur
verrouillé compte. Chaque invocation demande néanmoins le nettoyage de PassWall,
même si elle est répétée : une authentification récente ne doit pas être ignorée.
Après cette étape bornée, elle se termine sans second verrouilleur si l'autre
invocation est toujours active, avec un diagnostic « demande déjà en cours ».
Si l'autre invocation s'est terminée pendant l'attente, le verrou est repris et
un verrouilleur est lancé. La déduplication ne confirme pas le résultat de
la première invocation.

Si cette exclusion ne peut pas être établie sûrement, le verrouillage de l'écran
reste prioritaire : un avertissement est émis et la tentative continue sans
déduplication. Il faut alors corriger le problème de répertoire d'exécution
avant un usage régulier. Les lancements directs de swaylock contournent aussi
cette exclusion. Un crash du coordinateur, ou une éventuelle daemonisation de
swaylock par sa configuration, peut terminer la déduplication avant le processus
de verrouillage réel : aucune continuité de suivi n'est revendiquée dans ces cas.

Un PassWall bloqué peut ne pas nettoyer son coffre avant le verrouillage de
l'écran. L'absence d'acquittement est donc explicitement indiquée, mais n'empêche
jamais la tentative de verrouillage. Les protections indépendantes de PassWall
(inactivité, logind, nettoyage des éditeurs, générations Native Messaging et
instance unique) ne sont pas modifiées par ce composant.

## Tests isolés

La cible `passwall_session_lock_tests` utilise un bus D-Bus privé, une copie de
`passwall_session_lock_test_driver` et un faux verrouilleur dans un répertoire
temporaire propre à chaque test. Seul ce frontend compilé pour les tests utilise
un faux programme voisin et accepte un répertoire d'exécution temporaire.
La commande de production n'est jamais lancée sans argument pendant les tests.
Le test de blocage d'authentification D-Bus utilise un socket muet, pas logind ni
le bus réel. Aucun test ne lance swaylock ou ne provoque de transition système.

Résultats rapportés avant l'installation :

- `SessionLockCoordinatorTest` : **21/21**. Acquittement avant lancement,
  absence de PassWall sans activation automatique, refus, expiration, réponse
  tardive, demandes simultanées/répétées, bus indisponible, erreurs et crash du
  faux verrouilleur sont couverts. Le test de handshake D-Bus bloqué a été
  réexécuté lors de la préparation de l'installation : **1/1**, en 1,527 s ;
  ce résultat n'est pas une borne temps réel générale.
- `SessionLockServiceTest` : **10/10**. Acquittement différé jusqu'au nettoyage,
  erreurs, concurrence, perte du bus, callbacks obsolètes et rejet de l'interface
  de garde supprimée ; ces tests utilisent un bus privé et un nettoyage simulé.
- Les tests GUI de `MainWindow` dans `passwall_gui_tests` exercent le nettoyage
  effectif des objets applicatifs avec données fictives : éditeur ouvert,
  verrouillages répétés/réentrants, ancien éditeur, timer, ancien lease natif et
  nouvelle authentification, y compris dans un autre coffre. Ils sont distincts
  des faux objets du service et ont été rapportés comme réussis lors des
  régressions ciblées. Les tests du moniteur logind, de son backend et de
  l'instance unique ne constituent pas des transitions système réelles.

Ces validations ne sont pas une nouvelle campagne CTest complète de l'état final.
Le jalon antérieur 225/225 précède les évolutions ultérieures du service de
contrôle et du coordinateur. Aucun test n'a été relancé pour cette documentation.

Commandes de référence pour les tests isolés, à exécuter uniquement lors d'une
validation technique autorisée, pas pour cette clôture documentaire :

```sh
cmake --build /tmp/passwall-credential-summary-verification --target passwall_session_lock passwall_session_lock_tests -j2
/tmp/passwall-credential-summary-verification/passwall_session_lock_tests
```

L'exécution nécessite un environnement autorisant les sockets Unix privés.
Les binaires de harnais et le faux verrouilleur ne doivent pas être installés.

## Essais réels rapportés — bilan du 7 novembre 2026

L'utilisateur confirme les observations manuelles suivantes :

1. `Ctrl+Alt+L` déclenche le coordinateur.
2. PassWall se verrouille avant le verrouillage visible de Linux.
3. La session Linux se verrouille et se déverrouille normalement.
4. Le coffre reste verrouillé après le déverrouillage Linux.
5. Firefox refuse le remplissage tant que le coffre est fermé.
6. Une nouvelle authentification permet de retrouver le remplissage.
7. Le raccourci pilote `Ctrl+Super+L` reste disponible.

Le verrouillage réel avec PassWall absent avait également été rapporté comme
réussi. L'installation et ce parcours local sont fonctionnellement validés ;
ces essais ne sont plus présentés comme un premier pilote encore à réaliser.

Ces observations ne sont pas des tests automatisés de bout en bout. Le changement
visible d'écran ne démontre pas l'effacement de toutes les copies mémoire,
l'absence de données déjà acceptées par Qt/le noyau, tous les entrelacements
Native Messaging ou la couverture des autres déclencheurs. Elles ne prouvent
pas non plus le nettoyage si PassWall est bloqué, si le coordinateur crashe ou
lors d'une véritable suspension/hibernation/extinction non essayée ici. Le code
de sortie et la terminaison de swaylock ne constituent pas une preuve de
déverrouillage Wayland.

## Configuration constatée et points à vérifier

État après installation locale et reconfiguration contrôlée du 7 novembre 2026 :

- Le processus `/usr/bin/labwc -m` utilise les chemins XDG par défaut.
- `/etc/xdg/labwc/rc.xml`, lignes 92–93 : la définition système de `C-A-l` lance
  toujours `swaylock -p` ; ce fichier n'a pas été modifié.
- Le fichier utilisateur `/home/thormster/.config/labwc/rc.xml` définit `C-A-l`
  vers `/home/thormster/.local/bin/passwall-session-lock` et conserve le pilote
  `C-W-l`, avec `onRelease="yes"`. Les réglages de thème et de souris sont inchangés.
- En mode `--merge-config`, labwc lit le système puis l'utilisateur et supprime
  les anciennes définitions de raccourcis identiques, actions comprises. Le
  `C-A-l` utilisateur **remplace**, et ne cumule pas, l'action système. Cette
  règle a été vérifiée dans le [code de labwc 0.20.2](https://github.com/labwc/labwc/blob/0.20.2/src/config/rcxml.c)
  (`rcxml_read()`, `post_processing()`, `deduplicate_key_bindings()`) et dans
  `keybind_the_same()` : comparaison des modificateurs et des keysyms.
- Le XML a été validé avant et après publication atomique ; la reconfiguration
  a retourné 0 et labwc est resté actif. Le journal a signalé trois dépréciations
  de la configuration système inchangée (`snapping.range` et deux attributs de
  `windowSwitcher`), sans erreur XML ni de raccourci. Aucun réglage système n'a
  été corrigé à cette occasion.
- `C-A-Delete` appelle `pishutdown`, et `XF86PowerOff` appelle `pwrkey`.
- `swayidle` est installé, mais aucun processus de ce nom ni lancement dans les
  fichiers autostart labwc inspectés n'a été trouvé. Cela n'exclut pas d'autres
  scripts ou une configuration ajoutée ultérieurement.
- Les lancements directs de swaylock, d'autres raccourcis ou des scripts d'inactivité
  ne passent pas automatiquement par le coordinateur.

`pishutdown` installé est en version 0.43. Ses chaînes et son
[code amont](https://github.com/raspberrypi-ui/pishutdown/blob/master/src/pishutdown.c)
indiquent une recherche exacte de `swaylock -p` dans les raccourcis XML pour
afficher l'indication « Press ... to lock screen ». La surcharge utilisateur de
`C-A-l` peut donc masquer cette indication. Ce point ergonomique reste à vérifier
visuellement ; il ne faut pas modifier ce paquet pour la rétablir. Le code amont
consulté n'est pas une preuve d'identité avec le binaire installé. Le pilote
`Ctrl+Super+L` reste disponible et pourra être conservé ou retiré ultérieurement
sur décision explicite.

## Installation locale, sauvegardes et retour arrière

| Élément | Chemin installé | État |
|---|---|---|
| Application | `/home/thormster/.local/bin/passwall_app` | Actualisée pour exposer `Control1.Lock()` |
| Coordinateur | `/home/thormster/.local/bin/passwall-session-lock` | Installé, appelé par les deux raccourcis |
| Native Host Firefox | `/home/thormster/.local/bin/passwall_native_host` | Déjà à jour, non remplacé lors de cette installation |
| Manifeste Firefox | `/home/thormster/.mozilla/native-messaging-hosts/org.passwall.native.json` | Inchangé, pointe vers le Host installé |

Les trois exécutables sont de mode `0755`, propriétaire `thormster:thormster`.
L'application et le coordinateur ont été installés par fichiers temporaires dans
`~/.local/bin` puis renommages atomiques ; leurs SHA-256 ont été comparés aux
candidats validés. Le Host retrouve l'application dans son propre répertoire.
L'introspection D-Bus a confirmé `Control1.Lock()` sans l'appeler à cette étape.
Les essais réels ultérieurs confirment la compatibilité avec Firefox : refus du
remplissage après verrouillage, rétablissement après nouvelle authentification.

Il s'agit d'une installation locale manuelle, pas d'une procédure reproductible
intégrée au projet. Aucun paquet système, fichier sous `/etc`, code de labwc ou
de swaylock n'a été modifié ; `/usr/bin/swaylock -p` reste la commande officielle,
sans wrapper de substitution. La configuration utilisateur est restée de mode
`0664`, propriétaire `thormster:thormster`.

Les sauvegardes suivantes sont distinctes, dans le répertoire privé
`/home/thormster/.local/share/passwall/backups/` ; leurs répertoires sont de mode
`0700` et leurs empreintes ont été vérifiées lors des interventions :

1. `pre-linux-pilot-20261107T030441Z-d0_ttewl/` : ancienne application, Native
   Host à titre de précaution, métadonnées, empreintes, manifeste et configurations
   labwc utilisateur/système avant raccordement du pilote. Cette sauvegarde
   préparatoire n'a pas été modifiée par les ajouts de raccourcis.
2. `labwc-pilot-shortcut-20261107T031234Z-IYlDvm6L/rc.xml` : fichier utilisateur
   avant ajout de `C-W-l`.
3. `labwc-ctrl-alt-l-20261107T185614+0100-umwOy0vK/rc.xml` : fichier utilisateur
   avant surcharge de `C-A-l`, contenant déjà `C-W-l`. Son SHA-256 est
   `f4651e422e179b0aeb52f05f65922bf2a9296664c36a2ac894fa2a3350e38408` ;
   `SHA256SUMS` et `original-metadata.txt` sont conservés dans le même répertoire.

Ces copies d'installation et de configuration ne constituent pas une fonction
de sauvegarde/restauration des coffres SQLite, toujours absente de PassWall.

**Retour arrière du seul raccourci habituel :** le bloc suivant restaure la
troisième sauvegarde, puis recharge labwc depuis un terminal de la session.
`Ctrl+Alt+L` retrouve alors l'action système directe `swaylock -p`, qui ne passe
plus par PassWall ; `Ctrl+Super+L` conserve le coordinateur. Si des réglages ont
été ajoutés depuis, sauvegarder d'abord l'état courant et réconcilier ces ajouts
pour ne pas les écraser. Ces commandes sont une procédure de recours, **non
exécutée** lors de cette mise à jour documentaire.

```sh
(
set -eu
passwall_backup=/home/thormster/.local/share/passwall/backups/labwc-ctrl-alt-l-20261107T185614+0100-umwOy0vK
(cd "$passwall_backup" && sha256sum --check SHA256SUMS)
passwall_temp=$(mktemp /home/thormster/.config/labwc/.rc.xml.retour.XXXXXX)
cp --preserve=all "$passwall_backup/rc.xml" "$passwall_temp"
mv -fT "$passwall_temp" /home/thormster/.config/labwc/rc.xml
/usr/bin/labwc --reconfigure
)
```

Pour retirer aussi le pilote, utiliser la deuxième sauvegarde après les mêmes
précautions. Un retour des exécutables exige l'arrêt normal des processus concernés
et une restauration contrôlée depuis la sauvegarde préparatoire, avec contrôle
des empreintes, permissions et compatibilité de la paire application/Host.
L'ancienne application ne possède pas `Control1.Lock()` : restaurer cette version
sans adapter les raccourcis ferait perdre l'acquittement de nettoyage. Le Host
étant resté identique, son remplacement n'est pas nécessaire. Ne supprimer ni
écraser aucune sauvegarde et ne restaurer aucun fichier système pour ce seul
retour arrière.

Restent ouverts : installation reproductible sur une autre machine, inventaire
des déclencheurs non coordonnés, comportement sous défaillance et tests des
transitions système réelles, vérifications mémoire complémentaires et ergonomie
de `pishutdown`. La preuve de déverrouillage Wayland, une garde globale et des
modifications de swaylock/labwc ne sont pas des prérequis en attente : ces options
ne font pas partie de l'architecture retenue.
