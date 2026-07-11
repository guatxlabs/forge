# Forge — Audit qualité (pratiques d'ingénierie senior)

> Audit lecture-seule (4 agents) + campagne de corrections gouvernée. Périmètre : **tout Forge** —
> console Rust (`console/src`), moteur Python (`forge/`), front web (`console/web`). `../core` et
> `../soc` (Plume) **jamais touchés**. Chaque correction : review adverse + tests complets + commit
> behavior-neutral, build communautaire **byte-identical** et **openssl-free** préservés.
>
> **Date** : 2026-07-11 · **HEAD à la clôture** : `bc0244b` · **Verdict** : Rust *strong /
> production-leaning*, Python *A−/B+*, Web *A−* → après corrections, plus de god-file majeur ni de
> fuite de secret.

## 1. Note globale par zone

| Zone | Note | Forces vérifiées | Ce qui a été corrigé |
|------|------|------------------|----------------------|
| **Rust** (`console/src`) | Strong | Seam Store (aucun type DB ne fuit), lock discipline (`await_holding_lock`/`significant_drop_tightening` activés), erreurs typées, isolation tenant fail-closed, ~256 tests | god-files scindés, `main()` scindé, tests redistribués, swallowed-writes fermés, valeurs SQL bindées |
| **Python** (`forge/`) | A−/B+ | ROE fail-closed (4 couches), ledger anti-downgrade Ed25519, 0 `shell=True`/`eval`/`pickle`, base-class oracle→preuve, 1001 tests | **fuite de secrets fermée**, typage mypy du cœur, codec msgpack extrait, dedup |
| **Web** (`console/web`) | A− | Router + `core/`/`views/`, CSP stricte, hygiène XSS (`esc`/`safeHtml`/`textContent`), a11y (focus-trap, aria), 0 TODO | 2 god-files scindés en packages, import circulaire cassé, `esc()` durci |

## 2. Correction de perception du census

Le classement par **lignes totales** trompe : `main.rs` 5788 = ~1000 code réel + ~4747 **tests**, et
ces tests testaient d'**autres** modules (d'où l'illusion « backup/cli non testés »). Vrai classement
par **code réel** : `runs.rs` 1618 > `backup.rs` 1431 > `store.rs` 1401 > `cli.rs` 1368 > `compliance.rs` 1314.
Cohésifs (gros mais **une** responsabilité, **non** scindés) : `store.rs`, `scim.rs`, `tenancy.rs`,
`explore.js`, `index.html`, `style.css`, `report_engagement.py`, `recon_*`, `techniques_data.py` (data).

## 3. Corrections livrées (commits)

### Sûreté / correctness
- **`adbf6de`** — **Fuite de secrets fermée** : la rédaction était forkée en 3 versions divergentes
  (`report_engagement` = superset ; `importers/_base` et `exposure` rataient les tokens cloud
  `ghp_`/`sk-`/Slack/JWT → **fuite** via ingest importer + evidence). Canonicalisée dans
  `forge/redact.py` (surface unique auditée), les 3 sites délèguent. Bonus : regex PEM corrigée
  (`[A-Z0-9 ]*`, masque `EC2 PRIVATE KEY`) + regex URL-cred rendue linéaire (était O(n²)).
- **`ee001c5`** — false-200/divergence ledger sur 3 handlers community (match `Result` → 500 avant
  ledger) + `ledger.py` Python **flock + fsync** (plus de fork de chaîne multi-writer console+engine).
- **`6216c70`** — ~12 swallowed-writes **enterprise** → 500 fail-closed avant ledger + ~25 valeurs SQL
  dynamiques bindées en `Param` (fin des `format!`-into-SQL sur des valeurs).

### Structure / anti-monolithe (behavior-neutral)
- **`92759d1`** — `launch.js` 1028 → package `launch/` (8 modules) ; `admin.js` 727 → `admin/` +
  `components/detection-source-form.js` (**casse l'import circulaire** `auth⇄admin`) ; `esc()` durci
  (`'`→`&#39;`) ; CSS inline `index.html` → `style.css`. + `533e1ce` (fix `include_str!` du test webui).
- **`ac568bd`** — `runs.rs` 1618 → `runs_proc` + `runs_ha` + `runs_validate` (CONC-1 RAII intact).
- **`73eaea6`** — `cli.rs` → `cli/` (6 sous-modules) ; `compliance.rs` → `compliance_policy` +
  `compliance_evidence` (garde E3 purge global-scope + `parse_ts_epoch` is_ascii verbatim).
- **`bc0244b`** — `main()` 484 l. → `dispatch_cli` + `serve` ; 22 tests redistribués (backup +16,
  dbmigrate +5, cli/ledger +1) + helpers hoistés dans `testutil` ; `main.rs` 5788→4832.
- **`66ae602`** — `state.rs` 2276→730 (+ `schema.rs` + `detection.rs`) ; token ingest fingerprint-only ;
  `/tmp`→`temp_dir()`. **`ab06a3a`** — codec msgpack extrait de `msf.py` (`_msgpack.py`) + dedup
  `access_control._fetch`. **`41c44b4`** — typage mypy `roe/ledger/planner/engine` + fix oracle test.

### Capacités (issues de l'audit d'extensibilité)
- **`71dafa4`** — **drop-in plugins** : auto-discovery des modules (0 edit `__init__.py`) + `FORGE_PLUGINS`
  + loader `ToolSpec` **JSON/YAML** (`--toolspec`), gouvernance ROE préservée, exemples `contrib/`.
- **`f5025ff`** — intégrations `ToolSpec` gouvernées : masscan, gobuster-dns, theHarvester, wfuzz,
  ZAP-baseline (crackers/C2 **exclus** = choix de politique proof-oriented).

## 4. Backlog priorisé (ce qui reste — documenté, non fait)

| Pri | Item | Où | Note |
|-----|------|-----|------|
| P1 | ~4 swallowed-writes restants | `runs.rs claim_and_spawn`, `scim add_member`, `auth create_session` | Un 500 naïf orphelinerait un process déjà lancé / ripplerait les signatures auth → fix ciblé requis, pas mécanique |
| P1 | Redistribuer le cluster tenancy (~30 tests) hors `main.rs` | `main.rs` tests | Tests d'intégration handler via helpers partagés (`seed_two_tenants`…) → move non-trivial ; candidats à un `tests/` d'intégration |
| P2 | Scinder `backup.rs` 1431 | `backup_crypto` + `backup_sched` | Layering déjà cohérent ; crypto pur mérite un module testé isolé |
| P2 | Dedup `rand_hex`/`err`/`gate` | `scim`/`sso`/`compliance`/`tenancy` → `common.rs` | Consolidation behavior-neutral |
| P2 | Dedup chemins SQLite/PG | `cli/*`, `backup.rs` (`_store` variants) | Collapser sur le seam `store.rs` (effort moyen) |
| P3 | `report_engagement.py` → package | `forge/report_engagement/` | Optionnel, déjà cohésif ; seulement s'il grossit |
| P3 | Driver KMS/HSM concret | `signing.py`/`compliance_signer.py` | Seam `CallableComplianceSigner` prêt ; besoin choix backend (AWS-KMS/PKCS#11) |
| P3 | bulk-assign findings | `console/src/findings.rs` | Nécessite un modèle d'assignation/propriétaire |

## 5. Invariants tenus (vérifiés à la clôture, `bc0244b`)

- `cargo test` défaut **239 passed / 0 failed** · store-postgres **255 passed** (docker PG throwaway)
- `pytest forge tests` **1001 passed** · tous les JS `node --check` OK
- `cargo tree -e no-dev | grep -iE 'openssl|native-tls'` = **vide** (défaut + `store-postgres` + `object-store`)
- clippy propre (1 warning doc préexistant `presence.rs:11`) · 0 `TODO/FIXME` ajouté
- `../core` / `../soc` (Plume) jamais touchés · `git add -A` jamais utilisé · pushes fast-forward, jamais `--force`
