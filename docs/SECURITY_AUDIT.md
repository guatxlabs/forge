# Forge — Audit de sécurité (lens pentest / purple / DevSecOps)

> Audit sécurité adversarial (4 agents : appsec/authz, injection/crypto, DevSecOps, purple/audit-intégrité)
> + campagne de remédiation gouvernée (review adverse, tests, commits behavior-neutral, forge-only).
> `../core`/`../soc` (Plume) jamais touchés. Build communautaire **byte-identical** et **openssl-free** préservés.
>
> **Date** : 2026-07-11 · **HEAD** : `e1b649e` · **Périmètre** : console Rust, moteur Python, front web, k8s/CI/compose.

## Verdict

Codebase **inhabituellement bien durcie** pour sa classe (plateforme red-team gouvernée). L'audit a trouvé
**1 bypass de contrôle confirmé (crown-jewel), 2 IDOR cross-tenant HIGH, 1 ATO SSO HIGH conditionnel**, plus
un lot de MEDIUM/LOW — **tous corrigés**. Aucune SQLi, command-injection, path-traversal, ni mauvais usage
crypto trouvé. Deux risques résiduels **assumés et documentés** (voir §4).

## 1. Findings HIGH — corrigés

| ID | Finding | Fix | Commit |
|----|---------|-----|--------|
| **F1** | **Bypass scope-guard + exfiltration de secrets de session via redirections HTTP.** `oracle._http` suivait les 3xx vers un hôte arbitraire en réémettant Cookie/Authorization → un hôte in-scope redirigeant vers l'interne faisait fuiter le secret (**reproduit empiriquement**, contredisait une garantie écrite). | Fetch oracle par défaut **no-follow** ; opt-in via un suiveur qui **re-valide chaque hop** contre le scope et **strippe les secrets** sur tout saut cross-origin. Invariant `session.py` corrigé. | `a9678d3` |
| **IDOR-1** | **Lecture cross-tenant** : `run_detail`/`run_report`/`run_logs`/`run_sse` résolvaient par `run_id` global **sans** filtre engagement/tenant → n'importe quel user lisait le rapport/logs/stdout d'un autre tenant (protégé par un run_id 32-bit seulement). | Tous les handlers clés-par-run gated par `tenancy::engagement_visible` (404 sans oracle d'existence). | `5504f5d` |
| **IDOR-2** | **Écriture cross-tenant** : `run_cancel` gated seulement par operator console-global → kill du run d'un autre tenant (DoS). | Gate `can_operate_engagement` sur l'engagement propriétaire (403). | `5504f5d` |
| **SSO-F1** | **ATO par collision d'email** : pas de check `email_verified`, email utilisé comme clé de login → collision avec un compte privilégié. | `email_verified==true` requis (défaut, fail-closed) ; `sub` préféré. | `40ff5dd` |

## 2. Findings MEDIUM — corrigés

| ID | Finding | Fix | Commit |
|----|---------|-----|--------|
| **F2** | Oracles IDOR/auth/cors fetchaient des URLs **non scope-gardées** (extends `Oracle`, kinds hors `_SCOPE_INJECT_KINDS`). | Passés à `ScopeGuardedOracle` + kinds injectés + re-check par URL fail-closed. | `a9678d3` |
| **F3** | **Discipline de preuve non contrainte** : un module/plugin pouvait appeler `finding(status="vulnerable")` directement → fausse attestation « prouvée » dans le ledger signé. | `Finding.__post_init__` valide le statut ; `Module.finding` clampe `vulnerable`→`tested` sauf marqueur de preuve (`Oracle.proof`). Sites légitimes marqués `_proven`. | `a9678d3` |
| **SSO-F2** | OAuth `state` non lié au navigateur (login-CSRF / fixation). | Cookie `forge_sso_state` (HttpOnly/SameSite=Lax/Secure) vérifié == state avant consommation. | `40ff5dd` |
| **SSO-F5** | SSRF + exfil `client_secret` via endpoints de discovery non contraints. | `token/jwks/authorization_endpoint` **pinnés à l'origine de l'issuer**. | `40ff5dd` |
| **SSO-F6** | Pas de downgrade sur retrait de groupe IdP (admin périmé). | Table `sso_managed` ; downgrade au rôle par défaut si aucun groupe mappé (jamais les admins locaux). | `40ff5dd` |
| **SCIM-F7** | `group-members` divulguait les logins de comptes locaux non-SCIM. | Membres scopés aux users `scim_user` (+ JOIN défense-en-profondeur). | `40ff5dd` |
| **k8s-1** | Containers sans securityContext durci. | `allowPrivilegeEscalation:false` + `drop:[ALL]` + `seccompProfile:RuntimeDefault` sur les 3 workloads ; console `readOnlyRootFilesystem` + emptyDirs ; postgres uid 999 ; minio non-root. | `855c3d1` |
| **k8s-2/3** | Pas de PSA ; MinIO `:latest`. | Namespace `enforce=baseline/warn=restricted` ; MinIO pinné (tag + digest en commentaire). | `855c3d1` |

## 3. Findings LOW / defense-in-depth — corrigés

| ID | Finding | Fix | Commit |
|----|---------|-----|--------|
| **L1** | Pas de deny-list SSRF sur les fetches d'intégration du console (detection source, OIDC). | `guard_integration_addr` bloque loopback/link-local(169.254.169.254)/RFC1918/ULA/unspecified sur les fetches **console** (pas les cibles scope-gardées du moteur) ; escape-hatch `FORGE_ALLOW_INTERNAL_INTEGRATIONS`. | `e1b649e` |
| **L2** | ToolSpec argv sans garde `--` (option smuggling si target commence par `-`). | Refus fail-closed d'un positionnel `{target}` commençant par `-`. | `a9678d3` |
| **L3** | `_msgpack` levait des exceptions non catchées sur frames msfrpcd malformées. | `IndexError/struct.error/RecursionError`→`ValueError` + cap récursion 32. | `a9678d3` |
| **SCIM-F8** | `add_member` sans garde super-admin + writes avalés puis ledgerisés. | Garde super-admin + `Result` propagé avant ledger. | `40ff5dd` |
| **swallow** | `claim_and_spawn` (orphelin process), `create_session` (session non persistée), appends ledger fire-and-forget silencieux. | Reap du groupe process sur échec ; session persistée avant succès ; **drops d'audit loggés en erreur** (observables). | `e1b649e` |
| **cookie** | Cookie de session sans `Secure`. | `Secure` par défaut (escape-hatch `FORGE_COOKIE_INSECURE` pour dev localhost). | `40ff5dd` |
| **lockout** | Pas de rate-limit/lockout login. | Lockout par-login (5 échecs/300s), **sans énumération** (locked known == locked unknown). | `e1b649e` |
| **F4-dib** | Troncature du ledger indétectable en déploiement par défaut. | **High-water-mark** `{seq,hash}` fsync'd sous le même flock ; `verify()` détecte `tail.seq < hwm`. | `0d127ee` |
| **CI** | Actions non SHA-pinnées, pas de scan sécu. | Actions pinnées par SHA + job `cargo audit --deny warnings` + gitleaks. | `855c3d1` |
| **ingress** | Pas de headers sécu. | ssl-redirect + HSTS + X-Frame-Options + nosniff + Referrer-Policy. | `855c3d1` |

## 4. Risques résiduels — ASSUMÉS et documentés

- **F4 — intégrité d'audit vs compromission host-root (par défaut).** La clé Ed25519 est co-localisée avec
  l'écrivain (`LocalFileSigner`) et l'anchor par défaut est `NullAnchor`. Un attaquant **root sur l'hôte** lit
  la clé, réécrit/re-signe/re-chaîne l'historique (et le HWM) → `verify` local passe. Le HWM ferme la
  **troncature accidentelle** et un tampering **non-root/naïf**.
  **➜ Résiduel désormais FERMABLE (opt-in, livré).** La custody off-host est disponible et se ferme en
  activant **deux** contrôles opt-in :
  1. **Clé hors-host** — soit le **signeur PKCS#11** (`FORGE_LEDGER_SIGNER=pkcs11`, Ed25519/`CKM_EDDSA` sur
     SoftHSM2 dev/CI, HSM / AWS CloudHSM / KMS-via-PKCS#11 prod ; `forge/signing_pkcs11.py::Pkcs11Signer`,
     sous-classe de `RemoteSigner` → même re-vérification fail-closed, jamais de repli local), soit le signeur
     **exec** générique vers un KMS Ed25519 (GCP-KMS via `gcloud kms asymmetric-sign`). La clé privée vit sur
     le token : host-root ne peut plus l'**exfiltrer**. Dépendance **optionnelle** (`pip install 'forge[pkcs11]'`) ;
     le moteur par défaut reste stdlib-only, `LocalFileSigner` byte-identique.
  2. **Ancre off-host** — `WitnessAnchor`/`reconcile` (checkpoint contre-signé par une clé que le host ne détient
     pas → détecte une réécriture même re-signée).

  **Les deux sont nécessaires** : la clé hors-host stoppe l'exfiltration, le témoin détecte une réécriture
  future re-signée ; ensemble, forger l'audit exige de compromettre l'hôte Forge **ET** le témoin **ET** le HSM.
  Reste **opt-in par design** (open-core : défaut local + `NullAnchor`, byte-identique et sans dépendance) —
  à **activer** explicitement. Détails + setup : `docs/KEY_CUSTODY.md` ; threat model : `anchor.py`.
- **F6 — collecteurs de détection fail-open (par design).** L'entrée collector (SIEM/logs) est de confiance et
  fail-open ; elle alimente **le reporting/la mesure de couverture uniquement**, jamais une décision de FIRE
  (scope/ROE/ledger restent fail-closed). Une entrée empoisonnée peut au pire fabriquer de la couverture /
  masquer un gap dans un rapport — risque accepté, commenté dans le code.
- **DNS-rebinding** sur les fetches d'intégration : le guard vérifie l'IP de connexion effective sur une
  connexion unique sans suivi de redirection → pas de fenêtre TOCTOU pour ce modèle. Résiduel : nul pour ce chemin.
- **login lockout** : locked-vs-unlocked distinguable par timing, mais ne révèle que l'état de verrou
  (induit par l'attaquant), **jamais l'existence d'un compte**.

## 5. Contrôles qui tiennent (crédit — vérifié, pas supposé)

- **Pas de SQLi** : toute valeur dynamique bindée en `Param` ; identifiants = littéraux/allowlist ; curseur keyset strict-parsé.
- **No-shell partout** : argv tokenisé (`shell=False`), pas d'`eval`/`exec`/`pickle`/`os.system`.
- **Path-traversal fermé** : `blob.safe_join` (anti `..`/absolu/NUL), backup restore sans zip-slip (in-memory, noms fixes).
- **Backup crypto sain** : XChaCha20-Poly1305, nonce+salt CSPRNG **par archive** (pas de réuse), argon2id, header en AAD, clé zeroizée/0600.
- **Ledger anti-downgrade** : liaison alg↔kind bloque downgrade ET relabel, dans `verify` et `verify_external` ; `RemoteSigner`/`Pkcs11Signer` fail-closed re-vérifient leur signature contre la clé publique (jamais de repli local).
- **AuthN/Z** : compares constant-time (`subtle`), CSPRNG panic-on-failure, tenant sentinel `NO_ENGAGEMENT=-1` deny-by-default, RBAC par-engagement most-specific-wins, host-guard fail-closed anti-rebinding, admin sans fallback env-hash, accès super-admin ledgerisé.
- **OIDC** : RS256 hard-pinné (rejette `none`/HS*), `kid` fail-closed, iss/aud/exp + nonce constant-time, PKCE-S256, redirect_uri allowlist exacte.
- **Supply-chain / infra** : openssl-free (rustls/ring), moteur Python **zéro dép runtime**, Dockerfile multi-stage non-root (uid 10001) + tools SHA256-vérifiés, `.dockerignore` couvre secrets/clés, compose bind `127.0.0.1`, NetworkPolicies deny-by-default, aucun secret commité.

## 6. Validation à la clôture (`e1b649e`)

- `cargo test` défaut **255 passed / 0 failed** · `--features store-postgres` **271 passed**
- `pytest forge tests` **1027 passed** (+~45 tests sécu ajoutés cette campagne)
- `cargo tree -e no-dev | grep -iE 'openssl|native-tls'` = **vide** (défaut + features)
- `kubectl kustomize k8s/` rend ; kubeconform **17/17 valid** ; actionlint clean
- clippy propre (1 warning doc préexistant) · community build byte-identical · `../core`/`../soc` jamais touchés
