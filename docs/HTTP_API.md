# Référence API HTTP

> [Sommaire](README.md) · Voir aussi : [Référence CLI](CLI.md) · [Configuration](CONFIGURATION.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md)

La console (`forge-console`) expose l'API et le SPA sur `FORGE_CONSOLE_ADDR` (défaut
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
| `POST /api/setup/migrate` | public, **pré-provision** | Migration pilotée depuis le wizard (chemins serveur). **403** sans `FORGE_ALLOW_API_MIGRATE` ; **409** une fois provisionné. UX primaire = CLI `forge-console migrate`. |

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
| `GET /api/detection/coverage` (alias `GET /api/purple/coverage`) | Matrice **purple** : JOIN run-records `fired` (red) ↔ détections de la source (blue) → detected / missed / **MTTD**. Fail-open : `source_reachable:false` + `error` si aucune source. |
| `GET /api/campaigns` | Liste des campagnes. |
| `GET /api/roe` | Décisions ROE tracées (verdict par action — anti-masquage). |
| `GET /api/modules` | Catalogue de modules (kind, exploit, mitre, disponibilité, gouvernance). |
| `GET /api/ledger` | Entrées du ledger (depuis le JSONL disque), paginé (`limit`/`offset`). |
| `GET /api/ledger/verify` | Vérif de la chaîne SHA-256 **côté console** (sans clé privée : `sig_checked:false`). Pour la vérif de signature, voir `forge ledger verify`. |
| `GET /api/query` · `POST /api/query` | **soql** (type-SPL) → SQL **read-only** (champs allowlistés, params liés, un seul SELECT, LIMIT plafonné, connexion RO). POST pour les requêtes longues. Champ hors allowlist ⇒ **400**. |
| `GET /api/dashboards` | Liste des dashboards (ordre `position`). |
| `GET /api/panels` | Liste des panels soql. |
| `GET /api/panels/:id/data?from=&to=` | Exécute la requête soql du panel (viz table/bar/stat). |
| `GET /api/runs` | Liste des runs C2-light (récents d'abord). |
| `GET /api/runs/:id` | Détail d'un run. |
| `GET /api/runs/:id/report[?format=md\|html\|pdf]` | **Rapport d'engagement**. `md` (défaut), `html` (livrable brandé, CSS print), `pdf` (si moteur PDF présent, sinon `pdf_unavailable`). |
| `GET /api/runs/:id/logs?after=<ID>` | Lignes de log d'un run (fallback polling de SSE). |
| `GET /api/runs/:id/events` | Flux **SSE** : lignes de log + transitions de statut du run. |
| `POST /api/scope-check` | Verdict d'appartenance d'une cible au scope serveur (lecture/gouvernance). |
| `POST /api/plan` | **Dry-plan INERTE** (allow_high_impact=false par construction) : montre les verdicts ROE sans rien tirer. |

---

## Écriture machine (token d'ingestion)

| Méthode & route | Objet |
|---|---|
| `POST /api/ingest` | **Point de jonction** moteur→console : reçoit findings + run-records + couverture + décisions ROE d'une campagne. Dedup au store (`UNIQUE(campaign,target,title)`). |
| `POST /api/dashboards` · `POST /api/dashboards/:id` · `DELETE /api/dashboards/:id` | CRUD des dashboards. |
| `POST /api/panels` · `POST /api/panels/:id` · `DELETE /api/panels/:id` | CRUD des panels soql. |

---

## C2-light (operator)

| Méthode & route | Objet |
|---|---|
| `POST /api/run` | **Lance une campagne gouvernée et auditée** (spawn `python3 -m forge.cli campaign`). Corps `{campaign, targets[], modules?, mode?, budget?, exhaustive?, reason?, arm?, allow_high_impact?, module_params?}`. Fail-closed : cibles ⊆ scope serveur, **plancher exploit** (exploit/destructif refusés sauf opt-in haut-impact = operator + `arm=true` + `reason`), FIFO (un seul run vivant → **409**). Voir [Architecture §3.3](ARCHITECTURE.md#33-le-run-flow--c2-light--gouverné). |
| `POST /api/runs/:id/cancel` | Annule le run courant. |
| `POST /api/modules/refresh` | Re-peuple le catalogue `module` depuis `forge.cli modules`. |

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
