# Forge — Roadmap

> État : `vps/main` — build par défaut **communautaire byte-identical + openssl-free** (rustls/ring), `../core`/`../soc` (Plume) jamais touchés.
> Validation à jour : `cargo test` défaut + `--features store-postgres` verts, `pytest` vert, `kubeconform` OK.
> Docs détail : [`docs/AUDIT.md`](docs/AUDIT.md) · [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md) · [`docs/READINESS_MATRIX.md`](docs/READINESS_MATRIX.md) · [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) · [`docs/QUICKSTART.md`](docs/QUICKSTART.md) · [`docs/UPGRADE.md`](docs/UPGRADE.md) · [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md) · [`docs/TECHNIQUE_COVERAGE.md`](docs/TECHNIQUE_COVERAGE.md) · [`docs/TOOLS.md`](docs/TOOLS.md)

## En cours
- Rien mid-flight. Working tree propre. Reste **2 items planifiés** (expérience opérateur P5/P6, voir §D) + des choix **accepted-as-is** — aucun item readiness / audit / sécurité non résolu.

---

# ✅ FAIT — par thème

## A. Readiness équipe / entreprise (dossier `fc2a18ca` — cf. `docs/READINESS_MATRIX.md`)
Les 11 écarts §03 + les 7 contrôles §07 sont **tous livrés et vérifiés sur le code**.
- **Postgres 0→4** — seam Store backend-neutre, dialect normalisé, backend PG feature-gated (`store-postgres`, OFF par défaut), boot/seed routés backend-actif, **pool de connexions + `RETURNING`** (writers concurrents), migrator gouverné `forge migrate-store` (FK-order, dry-run, verify, checkpoint ledger signé). `9e10c67 d48ab4b 1118f3b e188e2b`
- **HA / multi-instance** — `FORGE_HA` opt-in, leader-lease, run-leader (exécution leader-only, one-run-per-engagement **fencé DB**), ledger single-writer (verrou advisory unique, jamais de fork), cache-invalidation cross-instance, présence partagée, object-store S3/MinIO, manifests **k8s** + NetworkPolicies deny-by-default, HWM anti-troncature. `7ce53f7 c07231e 5a1fb4f b85ce1e 0c6fb99 3b74963 0ff4591 0abff20 0d127ee`
- **Multi-tenant** — `tenant_id` row-level, filtre grant fail-closed (sentinelle `NO_ENGAGEMENT`).
- **RBAC par-engagement** — grants `(user,tenant,engagement,role)`, most-specific-wins, intersecté fail-closed.
- **SSO / SCIM** — OIDC générique (PKCE/RS256/JWKS/discovery, **agnostique IdP** : Keycloak/Okta/Azure/Authentik/…), SCIM 2.0 ; SAML via bridge OIDC.
- **Matrice ATT&CK par-engagement** (exercé×détecté×MTTD) — `/api/attack-matrix` + vue grille. `613cd8d`
- **Vues sauvegardées + bulk-ops** + **pagination keyset/curseur**. `05a64ef`
- **Ownership + triage findings** — `assignee` grant-scopé + bulk-assign (`6723dab`) ; **workflow de triage gouverné** `new→triaging→{confirmed|false_positive|duplicate}→resolved` + `reopened`, transitions fail-closed, ledgerisé, **SSE live**. `b5257ba`
- **Export par-engagement** (HTML/PDF/CSV/JSON) + bulk-export.

## B. Qualité de code (cf. `docs/AUDIT.md`)
- **God-files scindés** behavior-neutral : `launch.js`/`admin.js`→packages `92759d1`, `runs.rs`→proc/ha/validate `ac568bd`, `cli.rs`→`cli/` + `compliance.rs`→policy/evidence `73eaea6`, `state.rs`→schema/detection `66ae602`, `backup.rs`→crypto/sched `bcfbf39`, `main()`→dispatch/serve `bc0244b`, `msf.py`→`_msgpack` `ab06a3a`.
- **Typage mypy** du cœur Python (`roe/ledger/planner/engine`) `41c44b4` · **dedup** `rand_hex`/`err`→`common.rs` `a52e117`.
- Grades : Rust *strong/production-leaning*, Python *A−*, Web *A−*.

## C. Sécurité (audit pentest / purple / DevSecOps — cf. `docs/SECURITY_AUDIT.md`)
Tous les findings **HIGH/MEDIUM/LOW exploitables corrigés** :
- **HIGH** : bypass scope-guard via redirect + exfil secrets session `a9678d3` ; IDOR cross-tenant run-endpoints `5504f5d` ; ATO SSO email-collision `40ff5dd`.
- **MEDIUM** : oracles non scope-gardés + discipline de preuve schéma-contrainte `a9678d3` ; SSO state/discovery/downgrade + SCIM `40ff5dd` ; k8s securityContext/PSA/MinIO-pin `855c3d1`.
- **LOW** : SSRF deny-list intégrations + reap process + drops audit observables + login lockout `e1b649e` ; canonical secret-redaction (fuite token fermée) `adbf6de` ; enterprise swallowed-writes + SQL value-binding `6216c70`.
- **Hygiène des clés** : création atomique `O_EXCL 0600` fail-closed `6f587b8` ; clé ledger hors volume RWX partagé (`FORGE_LEDGER_KEY` + signeur off-host) `3418d31`.
- **Portabilité vérifiée** : **0 couplage Authentik, 0 dépendance Vault** — secrets par env/fichier/k8s-Secret/PKCS#11.
- **KMS/HSM** : signeur **PKCS#11** Ed25519 opt-in (`docs/KEY_CUSTODY.md`) `d7fb893`.

## D. Expérience opérateur / UI-first
- **Onboarding zéro-étape** `55b5d03` — `docker compose up` sans aucun fichier → **wizard 5 étapes** (admin + **scope/ROE dans l'UI** + détection + opérateur). Plus de scope.json, plus de `useradd`.
- **Rename `forge-console` → `forge`** `cb55511` — l'app EST la console/UI (binaire+service+image+k8s+docs, DB `forge.db`).
- **Args custom par-outil dans l'UI** `0d19512 5c15dfd` — **26 kinds** avec `params_schema` typé + `flag_allowlist` conservatrice (nmap custom + nuclei + 20 ToolSpec + ffuf/sqlmap/httpx/subfinder), rendu dynamique, `extra_args` allowlisté no-shell.
- **Rate-limit** `3034616` — throttle moteur (token-bucket `Oracle._http`) + flags rate par outil + back-off 429/`Retry-After`/WAF + signal « throttled ». Défaut byte-identical.
- **Ajout d'outils par l'UI** `b6b8ee8` — `POST /api/tools` admin+ledgered, **ToolSpec gouverné** `custom.*` (no-shell, allowlist, traversal-safe, jamais built-in/`vulnerable`), hot-reload, form `admin/addtool.js`, `docs/TOOLS.md`.
- **CLI `--param KIND.KEY=VALUE` + curl/dig gouvernés** `f6a5281` — args par-run en CLL (précédence sur scope.json/workflow) ; `recon.curl` (fetch benin, pas d'exfil) + `recon.dig` (DNS) configurables UI+CLI.
- **Outils sans rebuild** `a237e11` — `dnsutils`(dig) dans l'image + `/opt/tools` sur `PATH` + **3 montages opt-in** (`./tools` binaires/scripts, `./plugins` FORGE_PLUGINS, `./toolspecs` FORGE_TOOLSPECS). « 3 façons » dans `docs/TOOLS.md` : image full / image custom `FROM forge` / **mount sans rebuild**. Binaire absent → `skipped` (jamais de faux résultat).
- **Secrets sans `.env` en clair** `83d47cc` — indirection **`*_FILE`** (Docker/k8s secrets) sur TOUS les secrets (token, passphrase backup, `FORGE_DB_KEY`, creds connecteurs MSF/Burp/Plume, PIN PKCS#11) : l'env porte un **chemin**, le secret vit dans un fichier monté root-owned. Détection & SSO déjà write-only UI. `docs/SECRETS.md`. Défaut byte-identical.
- **Console `forge` gouvernée DANS l'UI** `b4096bd` — panneau admin « Console Forge » : runner à **allowlist** (`status`/`ledger verify`/`read`/`backup`/`upgrade`), **argv fixe, jamais de shell**, args schéma-validés, `upgrade` exige `confirm`, destructifs (`restore`/`migrate-store`) exclus, secrets jamais échoués, ledgerisé, sortie **streamée SSE**. Supprime `docker compose exec` pour les ops courantes. `docs/CONSOLE.md`.
- **Notifications in-app** `6b6d518` — l'assigné est notifié sur assign/triage (cloche+badge+panneau, **grant-scopé**, own-only, live SSE). Complète ownership+triage.
- **Revue sécu de la nouvelle surface** `50c458a` — audit adverse post-features (console-exec/add-tools/args-custom/rate/secrets/wizard) : **0 Critical/High**, contrôles tiennent ; 3 notes Info (frontière admin) fermées : `dangerous_flag` élargi (exfil `-T`/`-K`/`-F`/`--upload-file`), **parité de validation** du loader Python (spec `FORGE_TOOLSPECS` = mêmes checks que l'API), note port-avant-provision.

## E. Déploiement & cycle de vie
- **Upgrade sûr une-commande** `131ee7d` — snapshot chiffré pré-upgrade → migrate → verify → **rollback auto** si échec ; `schema_version` + `forge status` ; `docs/UPGRADE.md`.
- **Re-déploiement idempotent** `fcc0be1` — seeding/`migrate()` idempotents, `upgrade` no-op = 0 écriture, pruning des snapshots ; aucun résidu ne ship (gitignore/dockerignore).
- **Backup chiffré + migrate vérifié** (argon2id + XChaCha20, chaîne vérifiée, offsite S3/MinIO).
- **Quickstart UI-first** `docs/QUICKSTART.md`.

## F. Couverture technique (cf. `docs/TECHNIQUE_COVERAGE.md`)
- **100 % des techniques web** des 439 findings FAISS → oracle natif Forge ; scanners → ToolSpec ; long tail → drop-in plugin. Hors-couverture = exclusions **par design** (DoS/cred-cracking/memory-safety native/LAN-spoofing/forensics), pas des lacunes.

---

# 🔜 RESTE À FAIRE

## Planifié — expérience opérateur
- **Rien de planifié — les items UX sont livrés** (onboarding zéro-étape, rename `forge`, args custom tous outils, rate-limit, ajout d'outils UI, secrets `*_FILE`, console `forge` dans l'UI). Voir §D.

## Décisions produit (actées)
- **Triage enrichi** → **notifications in-app LIVRÉES** (`6b6d518`). SLA / email / webhook **différés** : nécessitent une config de canaux (SMTP/webhook) — à construire sur demande, pas une dette.
- **Native in-process SAML** → **DÉCISION : ne pas construire.** Garder le **bridge OIDC** (Dex/Keycloak/oauth2-proxy) — SAML natif tirerait openssl+libxmlsec1 (casse openssl-free) et XML-DSig maison = foot-gun XSW. Feature `saml` optionnelle reste différée, uniquement si un contrat l'exige. (`docs/DEPLOYMENT.md §3ter`.)
- **KMS cloud** → **DÉCISION : pas de driver bespoke.** L'**exec-signer générique couvre déjà GCP-KMS Ed25519** — recette concrète dans `docs/KEY_CUSTODY.md` (`50c458a`). PKCS#11 couvre HSM/CloudHSM. AWS-KMS **impossible** (pas d'Ed25519).

## Résiduels sécurité — ASSUMÉS et documentés (cf. `docs/SECURITY_AUDIT.md §4`)
- **F4** — intégrité d'audit vs compromission **host-root** : **fermable en opt-in** (signeur off-host PKCS#11 + `WitnessAnchor`). Par défaut local + `NullAnchor` (byte-identique).
- **F6** — collecteurs de détection **fail-open by design** : alimentent le reporting/couverture, **jamais** une décision de FIRE (scope/ROE/ledger restent fail-closed).

## Accepted as-is (délibéré, pas du backlog caché)
- **~25 tests d'intégration router dans `main.rs`** — de vrais tests `build_router` end-to-end via un réseau de helpers partagés (pas des unit-tests mal rangés).
- **Sites `let _ = store.execute(...)` best-effort** (présence/GC/heartbeat/membership SCIM/cancel background) — fail-soft intentionnel sans attestation d'audit ; les swallowed-writes **porteurs d'audit** ont tous été corrigés.
- **Duplication chemins SQLite/PG** (quelques variants `_pg`/`_store`) — collapse sans gain de correctness, basse priorité.

---

# Annexes (détail conservé)

## Postgres — programme étagé (DONE)
- **Stage 0** seam DB-access + conversion modules · **Stage 1** normalisation dialecte (`?`/`$N`, `ON CONFLICT`, `->>`) · **Stage 2** backend PG feature-gated · **Stage 2b** (`9e10c67`) tout `db()` + seeding routés backend-actif, pool + `RETURNING` (`e188e2b`) · **Stage 3** (`d48ab4b`) migrator gouverné `forge migrate-store` · **Stage 4** (`1118f3b`) HA/ops (pool+timeouts, `/health` DB ping, `pg_dump`, docker-compose profile).
> Le ledger tamper-evident est un fichier (`jsonl`), pas en DB — Postgres n'affecte pas l'intégrité d'audit ; sous HA sérialisé par un verrou advisory unique (`0abff20`).

## SSO
- **OIDC** natif (`FORGE_ENTERPRISE_SSO` : Auth-Code+PKCE, RS256/JWKS, redirect-allowlist, groups→role) ; SAML-only via bridge externe (Dex/Keycloak/oauth2-proxy). SAML in-process **différé** derrière feature `saml` optionnelle (défaut openssl-free préservé). Détail `docs/DEPLOYMENT.md §3ter`.

## Deferred engineering — RÉSOLU
- `significant_drop_tightening` clippy **activé** (`3c7a5c4`) · `last_insert_id()` session-scoping **résolu** via `Store::execute_returning_id` (`e188e2b`).
