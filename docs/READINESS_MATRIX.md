# Forge — Matrice de satisfaction (readiness + requêtes de session vs déployé)

> Vérification croisée : chaque attente du dossier **forge-readiness** (artefact `fc2a18ca`) et chaque
> requête utilisateur de la campagne, confrontée au code réellement livré. `../core`/`../soc` (Plume)
> jamais touchés ; build communautaire **byte-identical** + **openssl-free** préservés.
>
> **HEAD** : `b5257ba` · **Validé** : `cargo test` 274 (défaut) / 290 (store-postgres), `pytest` 1040 (+1 skip SoftHSM), openssl-free, kubeconform 17/17.
> Détails : [`AUDIT.md`](AUDIT.md) (qualité) · [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (sécu) · [`KEY_CUSTODY.md`](KEY_CUSTODY.md) · [`ROADMAP.md`](../ROADMAP.md).

## A. Readiness §03 — écarts « équipe / boîte » (P0/P1/P2)

| Pri | Attente readiness | Statut | Preuve / commit |
|-----|-------------------|--------|-----------------|
| P0 | Multi-engagement concurrent isolé (engagement first-class, `engagement_id` partout) | ✅ Livré | table `engagement` + colonnes ; scope legacy = engagement #1 |
| P0 | Writers concurrents (seam `SqliteStore→PostgresStore`, pool) | ✅ Livré | `store.rs` seam + pool PG round-robin (`e188e2b`) |
| P0 | Runs concurrents (slots par engagement, exécuteur leader-élu) | ✅ Livré | `runs_ha.rs` + index unique partiel de fencing (`5a1fb4f`) |
| P0 | Isolation multi-tenant (row-level `tenant_id`, filtre grant fail-closed) | ✅ Livré | `tenancy.rs` sentinelle `NO_ENGAGEMENT` |
| P1 | RBAC équipe par engagement (grants `(user,tenant,engagement,role)`) | ✅ Livré | `engagement_grant` + `effective_engagement_role` |
| P1 | Livrable client : export par engagement (PDF/CSV/JSON + bulk) | ✅ Livré | `/api/engagements/:id/report`, bulk export |
| P1 | Historique d'audit + classification + rétention (TLP, WORM, legal-hold, purge) | ✅ Livré | `compliance*.rs` (E3) |
| P1 | Vues sauvegardées + bulk-ops | ✅ Livré | `saved_views.rs` + bulk status/export/**assign**/**triage** |
| P1 | Collaboration multi-opérateur (état temps-réel, présence, bus, attribution) | ✅ Livré | `presence.rs` (partagée cross-réplica) + SSE + `started_by` |
| P1 | SSO / SCIM | ✅ Livré | OIDC (`sso.rs`) + SCIM 2.0 (`scim.rs`) ; SAML via bridge OIDC |
| P2 | Matrice ATT&CK par engagement (exercé × détecté × MTTD) | ✅ Livré | `/api/attack-matrix` + `attack-matrix.js` (`613cd8d`) |

## B. Readiness §07 — socle de sécurité « à poser »

| Contrôle | Statut | Preuve |
|----------|--------|--------|
| Isolation multi-tenant | ✅ | `tenancy.rs` fail-closed |
| Crypto / clé de ledger par engagement | ✅ | ledger + clé `.ed25519` par chemin |
| Legal-hold / rétention WORM | ✅ | `compliance.rs` |
| SSO / SCIM | ✅ | OIDC + SCIM |
| **Clés backées KMS / HSM** | ✅ **Livré** | **`Pkcs11Signer` Ed25519/CKM_EDDSA** (`d7fb893`), opt-in, dep optionnelle |
| Conformité (SOC2 / ISO) | ✅ | `/api/compliance/evidence` export |
| NetworkPolicies (k8s) | ✅ | `k8s/60-networkpolicies.yaml` deny-by-default |

## C. Audit de sécurité (pentest / purple / DevSecOps)

| Sévérité | Findings | Statut |
|----------|----------|--------|
| HIGH | F1 (bypass scope-guard/redirect+exfil), IDOR-1/2 cross-tenant, SSO-F1 (ATO email) | ✅ 4/4 corrigés |
| MEDIUM | F2, F3 (preuve), SSO-F2/F5/F6, SCIM-F7, k8s-1/2/3 | ✅ tous corrigés |
| LOW | L1 (SSRF), L2 (argv), L3 (msgpack), SCIM-F8, swallowed, cookie, lockout, F4-HWM, CI, ingress | ✅ tous corrigés |
| Résiduels assumés | **F4** (host-root ledger) → **désormais fermable** via PKCS#11 off-host + WitnessAnchor ; **F6** (collecteurs fail-open) = reporting-only par design | 📄 Documentés |

*Bien défendu, crédité (vérifié) : pas de SQLi / command-injection / path-traversal ; backup crypto sain (nonce/salt par archive) ; anti-downgrade ledger ; Dockerfile non-root + tools SHA256 ; aucun secret commité.*

## D. Requêtes utilisateur de la campagne — satisfaites ?

| Requête (verbatim ou synthèse) | Livré | Où |
|--------------------------------|-------|-----|
| « comment essayer l'outil en local docker ? » | ✅ | `DEPLOYMENT.md` + guide de déploiement (Artifact) |
| Revue de code + refactor (util/helper/split class) bonnes pratiques senior | ✅ | `AUDIT.md` — god-files scindés |
| « tu ne touche pas au core ou au plume uniquement forge » | ✅ | respecté sur toute la campagne (staging explicite, jamais `../core`/`../soc`) |
| Programme Postgres complet 0→4 | ✅ | Postgres/HA (voir ROADMAP « Recently shipped ») |
| 6 bugs UI/UX du vécu réel | ✅ | ROADMAP UI/UX → Done |
| « mets à jour les tasks et la roadmap » | ✅ | ROADMAP resynchronisé (plusieurs fois) |
| Vérifier que **Forge** (le code) est conforme au readiness (pas l'inverse) | ✅ | conformité vérifiée sur le code par agent read-only |
| Audit sécu comme expert cybersec / purple / devops | ✅ | `SECURITY_AUDIT.md` |
| Bonnes pratiques sur **tout** le code forge/web (anti-monolithe) | ✅ | `AUDIT.md` (launch.js/admin.js/runs/cli/compliance/backup/main.rs/msf.py) |
| « fais aussi ce qu'il reste » | ✅ | split backup, dedup, correctifs LOW |
| #1 & #2 « choix recommandé » (KMS + ownership) | ✅ | PKCS#11 (`d7fb893`) + assignee (`6723dab`) |
| « c'est en partie un moteur workflow non ? » → construire le triage | ✅ | **workflow de triage** livré (`b5257ba`) |

## Verdict

**Tout est satisfait.** Les 11 écarts readiness (§03), les 7 contrôles de sécurité (§07), les findings d'audit
HIGH/MEDIUM/LOW, et l'ensemble des requêtes de la campagne sont **livrés et vérifiés verts**. Il ne reste :

- **Aucune tâche ouverte** ni item de roadmap non résolu.
- **2 résiduels sécu assumés + documentés** (F4 host-root — désormais fermable en opt-in ; F6 fail-open by design).
- Des choix **délibérément acceptés as-is** (tests d'intégration router dans `main.rs`, `let _` best-effort, dup SQLite/PG) — cf. ROADMAP « Accepted as-is ».
- Rien en attente **hors décision produit future** (ex. étendre le triage-workflow avec notifications/SLA si un jour souhaité).
