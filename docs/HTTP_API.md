# Référence API HTTP

> [Sommaire](README.md) · Voir aussi : [Référence CLI](CLI.md) · [Configuration](CONFIGURATION.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md)

La console (`forge`) expose l'API et le SPA sur `FORGE_CONSOLE_ADDR` (défaut
`127.0.0.1:7100`). **Toutes** les routes passent sous **`host_guard`** (anti-DNS-rebinding : `Host`
hors allowlist ⇒ **421**). La plupart passent aussi sous **`auth_guard`** (gate d'auth engagée dès
qu'un hash env est posé OU qu'un compte activé existe en base).

## Niveaux d'authentification

| Niveau | Preuve acceptée |
|---|---|
| **public** | hors `auth_guard` (mais sous `host_guard`) — accessible sans session. |
| **viewer** | toute identité authentifiée : session (`cookie forge_session` / `Bearer <session>`), **Basic** viewer (`FORGE_CONSOLE_PASS_HASH`), ou **Bearer** = token d'ingestion. En mode dev-open (gate désengagée), passe sans preuve. |
| **token** | **Bearer** = token d'ingestion (`FORGE_CONSOLE_TOKEN`). Canal machine (moteur→console). |
| **operator** | session **operator\|admin**, ou en-tête `X-Forge-Operator` (hash env) — **+** contrainte source-CIDR si `operator_policy.source_cidrs` est configurée. Un viewer ne passe jamais. |
| **admin** | **session admin uniquement** (aucun repli env-hash — attribution individuelle stricte). |

Détail du modèle : [Modèle de sécurité](SECURITY_MODEL.md).

---

## Routes publiques (hors `auth_guard`)

| Méthode & route | Auth | Objet |
|---|---|---|
| `GET /health` | public | Liveness. `{status:"ok", version}`. Sonde du healthcheck Docker/compose (attend 200). |
| `POST /api/login` | public | Ouvre une **session individuelle** (compte). Corps `{login, password}` → cookie `forge_session` (HttpOnly, SameSite=Strict) + token. |
| `GET /api/setup/state` | public | État du 1er déploiement : `{provisioned, needs_setup, capabilities:{sqlcipher}}`. Sondé par le SPA au boot. |
| `POST /api/setup` | public, **auto-désactivante** | Wizard : crée le 1er admin (+ `operator_policy`/`detection_source`/`session_ttl` optionnels). **409** dès qu'un admin activé existe. Ledger `console.setup.provision`. Voir [Premier déploiement](FIRST_DEPLOYMENT.md). |
| `POST /api/setup/migrate` | public, **pré-provision** | Migration pilotée depuis le wizard (chemins serveur). **403** sans `FORGE_ALLOW_API_MIGRATE` ; **409** une fois provisionné. UX primaire = CLI `forge migrate`. |

---

## Lecture (viewer)

| Méthode & route | Objet |
|---|---|
| `GET /` | Le SPA (console opérateur dark). |
| `GET /api/whoami` | Identité effective de l'appelant (`authenticated`, `login`, `role`, `is_operator`). Pilote l'affichage/masquage des actions C2 dans l'UI. |
| `GET /api/findings` | Liste des findings (store rouge). |
| `GET /api/findings/:id` | Détail d'un finding (evidence, PoC, CWE, CVSS, fix, mitre, status). |
| `GET /api/runrecords` | Run-records ATT&CK (techniques tirées). |
| `GET /api/coverage` | Rollup de **couverture ATT&CK** : par technique, nb de runs tentés vs tirés. |
| `GET /api/detection/coverage` (alias `GET /api/purple/coverage`) | Matrice **purple** : JOIN run-records `fired` (red) ↔ détections de la source (blue), tags multi-techniques éclatés des deux côtés → **trois** états `detected` (exact) / `parent_approx` (sous-technique tirée, seule la parente couverte) / `missed`, + **MTTD**. `detection_rate` et le MTTD ne comptent QUE l'exact. Fail-open : `source_reachable:false` + `error` si aucune source. |
| `GET /api/campaigns` | Liste des campagnes. |
| `GET /api/roe` | Décisions ROE tracées (verdict par action — anti-masquage). |
| `GET /api/modules` | Catalogue de modules (kind, exploit, mitre, disponibilité, gouvernance). |
| `GET /api/ledger` | Entrées du ledger (depuis le JSONL disque), paginé (`limit`/`offset`). |
| `GET /api/ledger/verify` | Vérif de la chaîne SHA-256 **côté console** (sans clé privée : `sig_checked:false`). Pour la vérif de signature, voir `forge ledger verify`. |
| `GET /api/query` · `POST /api/query` | **GXQL** (type-SPL) → SQL **read-only** (champs allowlistés, params liés, un seul SELECT, LIMIT plafonné, connexion RO). POST pour les requêtes longues. Champ hors allowlist ⇒ **400**. |
| `GET /api/dashboards` | Liste des dashboards (ordre `position`). |
| `GET /api/panels` | Liste des panels GXQL. |
| `GET /api/panels/:id/data?from=&to=` | Exécute la requête GXQL du panel (viz table/bar/stat). |
| `GET /api/runs` | Liste des runs C2-light (récents d'abord). |
| `GET /api/runs/:id` | Détail d'un run. |
| `GET /api/runs/:id/report[?format=md\|html\|pdf]` | **Rapport d'engagement**. `md` (défaut), `html` (livrable brandé, CSS print), `pdf` (si moteur PDF présent, sinon `pdf_unavailable`). **Mène par le verdict** — voir ci-dessous. |
| `GET /api/runs/:id/logs?after=<ID>` | Lignes de log d'un run (fallback polling de SSE). |
| `GET /api/runs/:id/events` | Flux **SSE** : lignes de log + transitions de statut du run. |
| `POST /api/scope-check` | Verdict d'appartenance d'une cible au scope serveur (lecture/gouvernance). |

### `GET /api/runs/:id/report` — structure du rapport (parité avec `forge.report.build_report`)

Le rapport **mène par le verdict**, pas par la liste. Ordre des sections (`md` et `html`) :

1. **bannière de partialité** — *seulement* si `run_job.status ∈ {timeout, cancelled, failed, running}*.
   Un run coupé le DIT en tête : une absence de finding n'y vaut pas une absence de vulnérabilité.
   La console ne reçoit pas les compteurs de plan du moteur (`forge/console_client.py` ne les
   transmet pas) — elle dit donc qu'elle **ignore** le ratio « exécutées / planifiées » au lieu d'en
   fabriquer un ;
2. **Résumé exécutif** (console uniquement — prose du livrable client) ;
3. **Verdict** — une ligne (« N actionnable(s) » ou « rien d'actionnable trouvé ») + les comptes des
   quatre seaux : actionnable (≥ MEDIUM **ou** statut prouvé) · à qualifier (LOW / signalé par un
   outil) · **couverture NON vérifiée** (`skipped`) · bruit de reconnaissance (INFO) ;
4. **Actionnable — à reporter** puis **Signal à qualifier** — un bloc par gabarit (1 vuln × N
   endpoints) à la forme attendue par un triager : sévérité, CWE, CVSS, cible, requête déduite du
   PoC, reproduction numérotée, **commande rejouable**, observation, correctif ;
5. **Couverture NON vérifiée (trous de couverture)** — les `skipped`, groupés par module, **avant**
   toute annexe : c'est ce qui BORNE ce que l'absence de finding permet de conclure ;
6. **Synthèse** par sévérité ;
7. **Findings — annexe complète** — précédée d'une ligne de **comptabilité** : `rendus + repliés =
   émis`. En vue `pentest` (défaut) rien n'est replié ; en vue `bounty` les répétitions de gabarit
   sont repliées, **comptées, nommées**, avec le moyen de les récupérer ;
8. **Couverture & transparence (ROE)**, **Couverture détection (purple)**, **Annexe — chaîne de custody**.

**Vue** : `FORGE_REPORT_VIEW=pentest|bounty` (même variable que le moteur, pour que replier soit la
même décision des deux côtés). Défaut `pentest` = exhaustif.

**Sections du rapport CLI non mirroitées ici, et pourquoi** — le triage à score-bruit
(`forge/triage.py`) n'est pas porté côté console (elle ne prétend pas à un triage qu'elle n'a pas
exécuté) ; les techniques ATT&CK exercées sont rendues **dans** « Couverture détection (purple) », où
elles sont en plus jointes aux détections du SOC ; l'en-tête d'engagement et le ledger du moteur ont
pour équivalents l'en-tête console et l'annexe chaîne-de-custody. Cette correspondance est **vérifiée
par un test** (`report_view_parity_python_vs_rust_same_corpus`) qui rougit si le moteur ajoute une
section que personne n'a ni mirroitée ni déclarée.

> **Les routes qui spawnent le moteur** lancent **un process par requête**. Inventaire complet, par gate :
>
> | Gate (plafond) | Routes | Budget de temps |
> |---|---|---|
> | `FORGE_ENGINE_MAX_CONCURRENT` (défaut 4) — lecture, ouverte au viewer | `GET /api/techniques`, `GET /api/workflows`, `GET /api/detection/coverage` (collecteur Python), `GET /api/engagements/:id/report?format=docx\|pdf`, `GET /api/runs/:id/report?format=pdf`, `GET /api/compliance/evidence?format=pdf` (enterprise, flag-gated) | `FORGE_ENGINE_TIMEOUT` (120 s) |
> | `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT` (défaut 2) — opérateur | `POST /api/import`, `POST /api/modules/refresh`, `POST`/`DELETE /api/tools`, et la sonde du registre au BOOT | `FORGE_IMPORT_TIMEOUT` (600 s) pour l'import, `FORGE_ENGINE_TIMEOUT` sinon |
> | `FORGE_PLAN_MAX_CONCURRENT` (défaut 2) — opérateur | `POST /api/plan` | `FORGE_PLAN_TIMEOUT` (300 s) |
>
> Le total de process moteur simultanés est la **somme** des trois plafonds, pas l'un d'eux. Un slot est tenu par la
> **vie du process ET de ses descendants**, pas par la vie de la requête HTTP : abandonner la requête ne rend donc pas
> le slot, et le slot n'est rendu qu'après la mort du spawn. `POST /api/run` n'est pas dans ce tableau : c'est un run
> supervisé, avec son propre cycle de vie (`FORGE_RUN_TIMEOUT`, FIFO par engagement).
>
> **Ce que « la mort du spawn » couvre, et ce qu'elle ne couvre pas.** Le kill de groupe (`setsid`+`killpg`) est le
> chemin rapide, mais un descendant peut QUITTER le groupe (`setsid`, double-fork) — mesuré avant correctif :
> `FORGE_ENGINE_MAX_CONCURRENT=4`, 40 requêtes abandonnées → **40 descendants vivants**, plafond jamais atteint, aucun
> refus. Le balayage s'appuie donc sur deux propriétés dont un descendant n'hérite pas par choix : un **marqueur
> d'environnement** unique par spawn (recopié par fork/exec, `setsid` n'y change rien) et la **chaîne de parenté**,
> fermée par `PR_SET_CHILD_SUBREAPER` sur le leader (un orphelin est réadopté par le leader, pas par `init`). Après
> correctif, même mesure : **0 descendant vivant** après 40 abandons, et la borne refuse (rafale de 20 requêtes
> tenues : 16 × `429`, pic de process = 4 = le plafond).
>
> **Limites mesurées, pas contournées** : (1) un descendant qui SE PRIVE DU MARQUEUR ET dont le leader est déjà sorti
> — c'est le cas du chemin nominal — n'est rattachable par aucune des deux propriétés : mesuré, il survit. Attention à
> ce que ça coûte VRAIMENT à l'évadé : **il n'a pas à jeter son environnement**, il lui suffit d'en retirer UNE
> variable, dont le nom est une constante publique de ce dépôt. Mesuré côte à côte (5 requêtes servies, moteur bouchon
> qui lance 1 descendant détaché par spawn) : `env -i` → **7 survivants**, `env -u FORGE_ENGINE_SPAWN` → **7
> survivants** (identique) ; contrôle avec le marqueur conservé → **0 survivant**. L'héritage est PASSIF : un acte
> délibéré le défait, et le prix de cet acte est d'une seule variable. Sur les chemins abandon/budget, où le leader vit
> encore, la chaîne de parenté rattrape l'évadé et il est bien tué (0 survivant).
> (1-bis) **LA DÉLÉGATION À UN NON-DESCENDANT sort du domaine de la propriété** — c'est une limite de même classe
> pratique que la précédente, et elle n'est refermée par rien aujourd'hui. Le contrat porte sur ce qu'un DESCENDANT
> hérite ; un travail confié au gestionnaire de services de l'utilisateur (`systemd-run --user`) n'est le descendant de
> personne, n'hérite ni du marqueur ni de la parenté, et le slot est rendu tout de suite. Mesuré (moteur bouchon
> `systemd-run --user --collect --unit=… sleep N ; exec sleep 300`, `FORGE_ENGINE_MAX_CONCURRENT=4`, 4 requêtes
> ABANDONNÉES par un client anonyme) : **5 survivants** (les 4 délégations + la sonde du registre au boot), et la
> requête suivante est **servie** (le plafond n'est jamais atteint). Le coût client est nul, le coût machine ne l'est
> pas : c'est le levier de dégradation qui reste ouvert sur une machine où `systemd --user` est disponible.
> (2) Hors Linux il n'y a pas de
> `/proc` : le balayage rend une liste vide et la garde retombe sur le kill de groupe seul (cf. `docs/PLATFORMS.md`).
> (3) Le balayage coûte une passe `/proc` par spawn : mesuré sur cette machine (594 process), `GET /api/techniques`
> passe d'une médiane de **0,198 s à 0,221 s** (3 rondes entrelacées de 15 mesures, moteur `python3` réel, build debug).
> (4) **Le contrat a un coût sur le chemin NOMINAL, pas seulement sur l'abandon** — et ce coût DÉPEND DE LA FORME DU
> DESCENDANT. Le lot précédent n'avait mesuré qu'UNE forme (descendant qui REDIRIGE ses fd) et avait généralisé son
> chiffre à toutes : **c'était faux de deux ordres de grandeur** pour la forme la plus courante, celle d'un
> `fork`/`Popen` **sans redirection**, qui HÉRITE du pipe stdout du spawn. La collecte s'arrêtait à l'EOF des pipes ;
> un descendant qui tient le pipe le repousse indéfiniment, si bien qu'une requête **RÉUSSIE** était facturée le
> **BUDGET MOTEUR ENTIER** et que la sortie valide du moteur était **JETÉE** (corps `techniques_unavailable` alors que
> le moteur était sorti en 0). Mesuré sur le binaire, `GET /api/techniques`, 3 mesures par forme, moteur bouchon
> rendant une sortie valide puis sortant tout de suite :
>
> | forme du descendant | AVANT | APRÈS |
> |---|---|---|
> | aucun descendant | **0,030–0,040 s** | **0,030–0,040 s** |
> | redirige ses fd, MEURT au SIGTERM | **0,133–0,146 s** | **0,133–0,146 s** |
> | redirige ses fd, IGNORE SIGTERM | **5,17–5,24 s** (SIGKILL de `CANCEL_GRACE_SECS`) | **inchangé** |
> | **hérite du pipe stdout**, meurt au SIGTERM, `FORGE_ENGINE_TIMEOUT=5` | **5,127–5,136 s**, sortie JETÉE | **0,380–0,396 s**, sortie RENDUE |
> | idem, `FORGE_ENGINE_TIMEOUT=9` | **9,130–9,140 s** (donc indexé sur le BUDGET) | **0,380–0,396 s** |
> | idem, **défaut livré** (`FORGE_ENGINE_TIMEOUT` non posé = 120 s) | **120,061 s** | **0,386 s** |
> | idem au BOOT (sonde du registre de modules) | **120,66 s** avant le `listen` | **1,31 s** |
>
> La cause est traitée, pas le symptôme : **on n'attend plus la fermeture d'un pipe hérité par un descendant pour
> rendre la réponse**. Le travail se termine quand le PROCESS MOTEUR sort ; ce qu'il a écrit est ensuite drainé
> pendant une fenêtre courte (`PIPE_DRAIN_AFTER_EXIT` = 250 ms), puis la lecture est **coupée**. Le levier nommé
> auparavant (`CANCEL_GRACE_SECS`) n'était pas le bon : c'était `FORGE_ENGINE_TIMEOUT`.
> **Rien n'est tronqué** : contrôle mesuré avec 5 MiB de sortie valide ET un descendant qui hérite du pipe — corps
> rendu **5 243 025 octets** (`pad` = 5 242 880 exact), JSON valide, **0,79 s** ; le même contrôle AVANT rendait
> **351 octets** d'erreur en **5,13 s**, les 5 MiB jetés.
> **Ce que ce choix coûte ailleurs, dit et mesuré** : un moteur qui FERME ses deux pipes puis se BLOQUE n'est plus
> borné par « EOF + `CANCEL_GRACE_SECS` » mais par le budget — `FORGE_ENGINE_TIMEOUT=9` : **9,128–9,141 s** contre
> **5,130–5,145 s** avant. L'issue est identique (`504`, groupe tué, aucune sortie partielle) ; seule l'attente
> change, et elle ne dépasse jamais le budget annoncé. **Ce qui n'est plus capturé** : une sortie écrite par un
> DESCENDANT APRÈS la mort du moteur (elle l'était, au prix ci-dessus). Ça compte parce que des daemons détachés
> EXISTENT dans ce produit (`forge/modules/_daemon_reap.py`).
>
> Toute borne franchie est **explicite** et NOMME la variable qui la règle : dégradation documentée de la route
> (`techniques_unavailable` / `builtins_unavailable`), `429` `*_busy` (plafond), `504` `*_timeout` (budget), `502`
> (plafond d'octets) — jamais une attente silencieuse, et jamais une cause inventée. En particulier, `501`
> `docx_unavailable` / `pdf_unavailable` est **réservé** au cas où le générateur est réellement absent ou a échoué :
> une saturation rend `429 docx_engine_busy`, un budget dépassé `504 docx_engine_timeout`.
>
> **Mur-à-mur mesuré** : le temps de réponse d'une requête coupée à sa borne vaut le budget **plus** le temps de mort
> effective du spawn (SIGTERM, puis SIGKILL après `CANCEL_GRACE_SECS` = 5 s si un membre ignore SIGTERM). Mesuré avec
> `FORGE_ENGINE_TIMEOUT=5` sur un moteur qui sort au SIGTERM : `GET /api/techniques` répond en **5,02–5,06 s**
> (9 mesures consécutives sur le binaire de ce lot ; avant l'ajout du balayage des descendants détachés : **5,00–5,03 s**).
> C'est CE chiffre que doivent porter les trois fichiers qui l'énoncent (ici, `docs/CONFIGURATION.md`, `.env.example`) :
> une valeur rétractée avait survécu dans `.env.example` parce que la recherche de nettoyage portait sur la
> FORMULATION et pas sur le CHIFFRE.

---

## Écriture machine (token d'ingestion)

| Méthode & route | Objet |
|---|---|
| `POST /api/ingest` | **Point de jonction** moteur→console : reçoit findings + run-records + couverture + décisions ROE d'une campagne. Dedup au store (`UNIQUE(campaign,target,title)`). |
| `POST /api/dashboards` · `POST /api/dashboards/:id` · `DELETE /api/dashboards/:id` | CRUD des dashboards. |
| `POST /api/panels` · `POST /api/panels/:id` · `DELETE /api/panels/:id` | CRUD des panels GXQL. |

---

## C2-light (operator)

| Méthode & route | Objet |
|---|---|
| `POST /api/run` | **Lance une campagne gouvernée et auditée** (spawn `python3 -m forge.cli campaign`). Corps `{campaign, targets[], modules?, mode?, budget?, exhaustive?, reason?, arm?, allow_high_impact?, module_params?}`. Fail-closed : cibles ⊆ scope serveur, **plancher exploit** (exploit/destructif refusés sauf opt-in haut-impact = operator + `arm=true` + `reason`), **FIFO par engagement** (un run vivant *par engagement* ; 2e run sur le même engagement → **409** avec `engagement_id` ; autres engagements en parallèle). `engagement_id` optionnel dans le corps (défaut = engagement actif). Voir [Architecture §3.3](ARCHITECTURE.md#33-le-run-flow--c2-light--gouverné). |
| `POST /api/runs/:id/cancel` | Annule le run courant. |
| `POST /api/plan` | **Dry-plan INERTE** (allow_high_impact=false par construction) : montre les verdicts ROE sans rien tirer. **Operator** : il spawne quand même un process moteur, donc même gate que `/api/run` (viewer → **403**), budget de temps borné (`FORGE_PLAN_TIMEOUT`, défaut 300 s → **504** `plan_timeout`, groupe moteur tué), concurrence bornée (`FORGE_PLAN_MAX_CONCURRENT`, défaut 2 → **429** `plan_busy`) et sortie moteur plafonnée en octets (→ **502** `plan_output_too_large`). |
| `POST /api/modules/refresh` | Re-peuple le catalogue `module` depuis `forge.cli modules`. Spawn **borné** (plafond `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT`, budget `FORGE_ENGINE_TIMEOUT`) : si la sonde n'a pas eu lieu, la réponse porte `probe_error` (et **429** quand c'est le plafond) — le catalogue rendu est alors celui de la base, non re-sondé. |
| `POST /api/import` | Importe une sortie de scanner (parse par le moteur). Spawn **borné** : plafond `FORGE_ENGINE_OPERATOR_MAX_CONCURRENT` (→ **429** `import_busy`), budget `FORGE_IMPORT_TIMEOUT` (défaut 600 s → **504** `import_timeout`, groupe tué, **aucun** finding partiel inséré), plafond d'octets (→ **502**). |

---

## Administration (admin — session admin stricte)

| Méthode & route | Objet |
|---|---|
| `GET /api/users` | Liste des comptes (**jamais** `pass_hash`). |
| `POST /api/users` | Crée un compte (`{login, role, password}` ; `role ∈ viewer\|operator\|admin`). |
| `POST /api/users/:login` | Met à jour un compte (rôle, mot de passe, `disabled`). Le **dernier admin activé** est protégé. |
| `DELETE /api/users/:login` | Supprime/désactive un compte. |
| `GET /api/detection/source` | Config de la source de détection — **secret RETIRÉ** (`secret_set` seul). |
| `POST /api/detection/source` | Enregistre `settings.detection_source` (secret **write-only**), recharge la source à chaud. Ledger `console.detection.source.set`. |
| `POST /api/detection/test` | Teste une config de source (fournie ou stockée) : `{reachable, count, sample_mitres, error?}` — **jamais** le secret. `keep_secret:true` pour tester sans re-saisir. |
| `POST /api/modules/:kind` | **Gouvernance des connecteurs** : `{enabled?, web_allowed?, available_override?}`. Désactiver ⇒ SKIP au spawn même si le binaire est présent. Ledger. |
| `GET /api/tools/runtime` | **Cycle de vie des outils** : état par outil du manifeste (version cible, version installée lue dans le reçu, provenance, pin). N'exécute aucun outil. |
| `POST /api/tools/runtime` | `{action, name}` **et rien d'autre** — `install\|update\|remove` d'un outil **du manifeste**. Un champ `url`/`sha256`/`digest`/`version` fait **échouer** la requête (400) : la source vient de `forge/tools.json`, il n'existe aucun paramètre de source. `name` inconnu du manifeste, ou manifeste illisible ⇒ refus. Ledger `console.tools.*` + `tools.install` (digest vérifié) côté installeur. Cf. [`TOOLS_LIFECYCLE.md`](TOOLS_LIFECYCLE.md). |
| `GET /api/notify/channel` | **Canal de notification sortant** : config **sans le jeton** (`secret_set` seul) + `enabled`. |
| `POST /api/notify/channel` | Enregistre `settings.notify_channel` (jeton **write-only**, `keep_secret:true` pour ne pas le retaper). **OFF par défaut** : sans config, aucun octet ne sort. Ledger `console.notify.channel.set` (destinataire **rédigé**, jamais le jeton ni l'URL complète). |
| `POST /api/notify/channel/test` | Envoie un message de vérification avec la config **stockée** — l'endpoint n'est **jamais** un paramètre de requête (sinon la route serait un proxy SSRF pour admin). Ledger `console.notify.dispatch`. |
| `GET /api/notify/sla` | **SLA de triage** : politique (budgets par sévérité) + `enabled` + `overdue_now` — un **aperçu en lecture seule** du nombre de findings actuellement en retard (il **ne notifie personne**). `capped` dit si l'aperçu a buté sur `max_sweep_rows` (fenêtre tronquée ≠ base saine). |
| `POST /api/notify/sla` | Enregistre `settings.sla_policy` `{enabled, budgets:{SEVERITY:heures}, escalate_to}`. **OFF par défaut** ; `enabled` sans budget positif reste **inerte**. Champ inconnu / sévérité hors jeu fermé / budget non entier ⇒ **400**. Ledger `console.notify.sla.set`. Le balayage lui-même est **leader-only** sous HA et ledgerise `console.notify.sla.sweep` (**compteurs seuls**). |
| `POST /api/backup` | Crée l'archive **chiffrée** et la renvoie en téléchargement. Corps `{passphrase}`. Ledger `console.backup` (taille + sha256, jamais la passphrase). |
| `POST /api/restore` | Corps `{archive_b64, passphrase, apply?, confirm?}`. **Par défaut** : valide + vérifie + rapporte (aucune écriture). `apply:true` **exige** `confirm:true` ⇒ swap en place (**redémarrage requis**). |
| `GET /api/backup/policy` | Politique de sauvegarde **rédigée** (secrets `***REDACTED***` ; `passphrase_env` = un NOM d'ENV, conservé). |
| `POST /api/backup/policy` | Enregistre la politique (schedule/rétention/offsite). Tout `passphrase` en clair est retiré avant persistance. Ledger. |

Sauvegarde/restauration : [`BACKUP.md`](BACKUP.md). Source de détection : [`DETECTION.md`](DETECTION.md).

---

## Conventions

- **Erreurs** : JSON `{"error": "<code>", "why": "<message lisible>"}` + code HTTP approprié
  (`400` entrée invalide, `401` auth requise, `403` admin/operator requis, `404`, `409` conflit
  d'état, `421` host non autorisé).
- **Secrets** : jamais renvoyés par un GET, jamais journalisés, jamais ledgerisés (traités comme des
  secrets de session, rédigés en profondeur).
- **Ledger** : chaque mutation d'administration/C2 est scellée (`console.*`) avec **métadonnées
  seules** (acteur, horodatage, kind), jamais le contenu secret.
- **Bind & exposition** : loopback par défaut. N'exposer qu'à travers un reverse-proxy + auth +
  `FORGE_CONSOLE_HOST`. Voir [Modèle de sécurité](SECURITY_MODEL.md).
