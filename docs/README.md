# Documentation Forge

**Forge** — plateforme d'évaluation red-team **gouvernée** : chaque action offensive passe par une
gate ROE *fail-closed* et est scellée dans un **ledger d'engagement** tamper-evident, tandis que la
boucle **purple** mesure ce que la défense a réellement détecté. Forge tourne **en standalone**
(l'intégration au SOC Plume est optionnelle).

> ⚠️ **Cadre autorisé uniquement** — bug bounty in-scope, pentest sous contrat, CTF, infra propre.
> La gate ROE + le scope-guard + le ledger sont là pour **imposer ET prouver** l'autorisation.
> Forge est **INERTE par défaut** : rien ne tire tant que l'opérateur n'a pas armé chaque couche.

Version documentée : **0.0.1**. Cette page est le sommaire. Chaque lien pointe vers une page dédiée.

---

## Par où commencer

| Vous êtes… | Commencez par |
|---|---|
| **Nouvel opérateur** qui découvre le produit | [Vue d'ensemble](OVERVIEW.md) → [Démarrage hors-ligne](GETTING_STARTED.md) |
| **Admin/DevOps** qui déploie une console | [Installation](INSTALLATION.md) → [Premier déploiement (wizard)](FIRST_DEPLOYMENT.md) |
| **Architecte / RSSI** qui évalue | [Vue d'ensemble](OVERVIEW.md) → [Architecture](ARCHITECTURE.md) → [Modèle de sécurité](SECURITY_MODEL.md) |
| **Intégrateur** qui câble une source de détection | [Concepts : boucle purple](CONCEPTS.md#5-la-boucle-purple) → [Sources de détection](DETECTION.md) |
| **Développeur / scripteur** | [Référence CLI](CLI.md) → [Référence API HTTP](HTTP_API.md) → [Configuration](CONFIGURATION.md) |

---

## Sommaire complet

### 1. Comprendre Forge

- **[Vue d'ensemble](OVERVIEW.md)** — ce qu'est Forge, la proposition de valeur, le fonctionnement
  standalone (Plume/purple est optionnel), ce que Forge n'est pas.
- **[Architecture](ARCHITECTURE.md)** — comment c'est construit : le moteur Python (scope-guard ROE,
  planner coverage-safe, cerveau, oracles à preuve, catalogue de techniques, chaînage,
  découverte par évasion, ledger Ed25519, collecteurs), la console Rust/axum (RBAC, C2-light, DB,
  settings), le SPA, le registre de modules, le modèle de gouvernance. *(Le document de rationale
  historique reste [`../ARCHITECTURE.md`](../ARCHITECTURE.md).)*
- **[Concepts](CONCEPTS.md)** — ROE/scope-guard, ledger tamper-evident, oracles à preuve
  (*tested-unless-proven*), catalogue de modules + techniques (mapping ATT&CK), boucle purple,
  chaînage, découverte backée par évasion.
- **[Catalogue de modules](MODULES.md)** — les 31 modules livrés : `kind`, capacité (exploit/destructif),
  technique ATT&CK, description, dépendance.
- **[Ajouter votre propre outil (depuis l'UI)](TOOLS.md)** — déclarer un outil CLI gouverné (ToolSpec
  déclaratif : binaire + argv no-shell + allowlist + params) sans éditer de fichier ni recompiler.

### 2. Déployer & exploiter

- **[Installation](INSTALLATION.md)** — Docker (profils `mini`/`full`), docker-compose (profils
  optionnels), natif/systemd, venv/dev, image `encryption` (SQLCipher au repos). Commandes exactes.
- **[Premier déploiement](FIRST_DEPLOYMENT.md)** — le wizard web de 1er boot (admin, crypto, source
  de détection, politique opérateur — rien de codé en dur).
- **[Démarrage bout-en-bout hors-ligne](GETTING_STARTED.md)** — parcours opérateur 100 % offline
  (seed + mock-Plume) : install → scope → console → purple → rapport → intégrité.
- **[Runbook de déploiement self-service](DEPLOYMENT.md)** — le runbook détaillé (empreinte mesurée,
  matrice Docker/k8s/host/venv, contexte de build = racine du dépôt + git-dep `guatx-core`, liveness
  `/health`, export PDF).
- **[Utiliser Forge en standalone (sans Plume)](STANDALONE.md)** — page dédiée : tout fonctionne
  sans SOC.

### 3. Administrer

- **[Administration](ADMINISTRATION.md)** — comptes & rôles (admin/opérateur/viewer), gouvernance
  des connecteurs (activer/désactiver = « installer/désinstaller »), configuration de la source de
  détection, politique opérateur + source-CIDR, sauvegarde/restauration + programmation/offsite,
  migration.
- **[Sources de détection](DETECTION.md)** — brancher n'importe quelle infra BLUE **sans code**
  (Plume/CrowdSec/FortiGate/pfSense/OPNsense/Elastic/OpenSearch/fichier/exec) : modèle
  `DetectionSource`, préréglages, mapping MITRE.
- **[Prérequis Plume](PURPLE_PREREQS.md)** — le préréglage `kind=plume` de la boucle purple.
- **[Migration de données](MIGRATION.md)** — reprendre un install existant (DB + ledger + clé
  `.ed25519`), option chiffrement au repos SQLCipher.
- **[Sauvegarde & restauration](BACKUP.md)** — archives **toujours chiffrées** (argon2id +
  XChaCha20-Poly1305), programmation + offsite.
- **[Console in-UI](CONSOLE.md)** — runner **gouverné** de sous-commandes `forge` depuis l'UI (allowlist
  stricte, **sans shell**, admin-only, ledgerisé, streamé) : supprime le `docker compose exec forge forge …`
  pour les ops courantes (`status`, `ledger verify`, `read`, `backup`, `upgrade`).

### 4. Références

- **[Configuration](CONFIGURATION.md)** — table COMPLÈTE de **toutes** les variables d'environnement
  (`FORGE_CONSOLE_*`, `PLUME_URL`/`PLUME_TOKEN`, `FORGE_DB_KEY`, `FORGE_ALLOW_API_MIGRATE`,
  `FORGE_TOOLS_PROFILE`, knobs opérateur/détection/backup) **et** de toutes les clés de la table
  `settings` (nom, sens, défaut, exemple, configurable au déploiement vs dans l'UI).
- **[Référence CLI](CLI.md)** — toutes les sous-commandes `forge` (`python -m forge.cli`) et
  `forge`, avec leurs flags.
- **[Référence API HTTP](HTTP_API.md)** — toutes les routes de la console (méthode, auth requise,
  objet).

### 5. Sécurité, dépannage, désinstallation

- **[Modèle de sécurité](SECURITY_MODEL.md)** — authz, gates fail-closed, intégrité du ledger,
  chiffrement au repos, gestion des secrets, host-guard, plancher exploit.
- **[Plateformes supportées](PLATFORMS.md)** — matrice OS (Linux primaire, macOS pleinement
  supporté, Windows best-effort) : composants qui marchent partout vs la seule capacité Unix-only
  (kill de sous-arbre `setsid`/`killpg` du run C2 gouverné), résolution config/données/temp par OS,
  et le filet anti-régression `tests/test_portability_guard.py`.
- **[Dépannage & FAQ](TROUBLESHOOTING.md)** — symptômes courants, diagnostics, questions fréquentes.
- **[Désinstallation & suppression des données](UNINSTALL.md)** — arrêter, supprimer
  image/conteneur/volumes, purger DB/ledger/clés, désinstaller les outils.

### 6. Go-to-market & référence purple *(contexte produit)*

- **[Positionnement](POSITIONING.md)** — segment cible, les trois piliers, teardown concurrentiel.
- **[Pricing](PRICING.md)** *(proposition)* — logique de prix, tiers Red/Purple/Enterprise.
- **[Plan & roadmap](PLAN.md)** — statut des blockers, roadmap séquencée.
- **[MTTD — ce que la métrique mesure](MTTD.md)** — time-to-ALERT vs time-to-event, interprétation.
- **[Runbook campagne purple](PURPLE_CAMPAIGN.md)** — campagne recon-large (à lancer sur « go »).
- **[Template d'engagement de référence](REFERENCE_ENGAGEMENT_TEMPLATE.md)** — squelette du livrable.

---

## Carte des concepts (en 30 secondes)

```
  cerveau (HeuristicBrain / orchestrateur Claude)
        │  propose des Actions (kind, target, exploit?, destructive?)
        ▼
  Engine ──► gate ROE ──► VETO | DRY_RUN | FIRE ──► Ledger (append-time, hash-chain + Ed25519)
        │                                  │
        │                                  ▼ (FIRE seulement)
        └──► module.fire() ──► Findings ──► report + console (findings / coverage / purple / runs)
                  ▲
        modules = OUTILS AUTONOMES orchestrés (recon, oracles à preuve, évasion, connecteurs MSF/Burp)
```

- **Gate ROE à 4 couches** (`forge/roe.py`) : *armé → in-scope → capacité autorisée → approuvé*.
  Hors scope ⇒ `VETO` (jamais simulé, jamais tiré). Voir [Concepts](CONCEPTS.md#1-roe--scope-guard).
- **Ledger tamper-evident** (`forge/ledger.py`) : chaîne SHA-256 + signature Ed25519 par-entrée,
  vérifiable par un tiers avec la seule clé publique. Voir [Concepts](CONCEPTS.md#2-le-ledger-dengagement).
- **Boucle purple** : chaque finding porte un `mitre` (ATT&CK) — clé de jointure avec les détections
  du SOC. Source de détection = **plugin configurable**. Voir [Concepts](CONCEPTS.md#5-la-boucle-purple).

---

*Forge est un produit **[GuatX](https://guatx.com)** — l'antithèse offensive gouvernée du SOC
blue-team [Plume](../../plume). Usage autorisé / éthique uniquement (voir [`../LICENSE`](../LICENSE)).*
