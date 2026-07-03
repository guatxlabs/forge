# Utiliser Forge en standalone (sans Plume)

> [Sommaire](README.md) · Voir aussi : [Vue d'ensemble](OVERVIEW.md) · [Démarrage](GETTING_STARTED.md) ·
> [Concepts : boucle purple](CONCEPTS.md#5-la-boucle-purple)

**Plume (le SOC) et la boucle purple sont OPTIONNELS.** Forge est un produit complet sans eux. Cette
page décrit ce que vous obtenez en standalone et comment brancher une source de détection **plus
tard**, sans rien casser.

## Ce que Forge fait sans aucune source de détection

| Capacité | Standalone |
|---|---|
| Scope-guard ROE + armement par couche (inerte par défaut) | ✅ |
| Ledger d'engagement signé Ed25519 + vérif externe par clé publique | ✅ |
| Recon passif/actif, oracles à preuve, connecteurs MSF/Burp (gatés ROE) | ✅ |
| Console : Findings / Coverage ATT&CK / Runs / Ledger | ✅ |
| soql (recherche type-SPL) + dashboards (panels sauvegardés) | ✅ |
| Rapports d'engagement (md / html / pdf) + section anti-masquage | ✅ |
| C2-light gouverné (lancement de campagne depuis le web) | ✅ |
| **Couverture purple (detected / missed / MTTD)** | ⏸️ **inerte — fail-open lisible** |

La **couverture ATT&CK** (`GET /api/coverage`) — *quelles techniques ai-je tirées, combien ont fait
`FIRE`* — est **native** et ne dépend d'aucun SOC : c'est la moitié « red » de la matrice. Seule la
moitié « blue » (a-t-on été détecté ?) exige une source de détection.

## Le comportement fail-open (honnête)

Sans source configurée, l'endpoint de couverture purple (`GET /api/detection/coverage`, alias
`/api/purple/coverage`) répond **`source_reachable:false`** avec une raison lisible — il **n'invente
jamais** `detected`/`missed`/`MTTD`. C'est un choix de conception : mieux vaut « mesure impossible »
qu'un chiffre faux. Le diagnostic `forge doctor --purple` affiche « boucle purple INCOMPLÈTE » avec
la ligne exacte qui manque, sans rien tirer.

## Parcours standalone recommandé

1. **Installer** — [Installation](INSTALLATION.md) (Docker `mini` suffit pour du recon/oracles ;
   `full` si vous voulez httpx/nuclei/subfinder embarqués + export PDF clé-en-main).
2. **Provisionner** — [Premier déploiement](FIRST_DEPLOYMENT.md), **en sautant l'étape 3** (source
   de détection). Ne renseignez que l'admin (+ éventuellement la politique opérateur).
3. **Définir le scope** — `cp scope.example.json scope.json` et renseigner `in_scope` **avec
   autorisation écrite**. Vérifier : `forge scope-check <cible> --scope scope.json`.
4. **Chasser** — soit en CLI (`forge campaign …`, voir [CLI](CLI.md)), soit via le C2-light de la
   console (opérateur). Les findings/coverage/runs peuplent la console.
5. **Livrer** — `GET /api/runs/:id/report?format=html` (livrable brandé, impression → PDF), la
   couverture ATT&CK, et la chaîne de custody : `forge ledger verify --pubkey <clé publique>` prouve
   à un tiers que rien n'est sorti du périmètre autorisé.

Un parcours **100 % hors-ligne** de bout en bout (avec un stub mock-Plume pour *voir* la matrice
purple sans SOC réel) est détaillé dans [`GETTING_STARTED.md`](GETTING_STARTED.md).

## Activer la boucle purple plus tard

Aucune migration : brancher une source **à chaud** suffit.

- **Dans l'UI** : *Administration → Source de détection* → choisir le `kind`, l'endpoint, l'auth
  (write-only), le mapping MITRE, **Tester la connexion**, **Enregistrer**. La source est rechargée
  immédiatement. Modèle et préréglages : [`DETECTION.md`](DETECTION.md).
- **Par env** (rétro-compat/headless) : `PLUME_URL` + `PLUME_TOKEN` (préréglage `kind=plume`), ou
  `FORGE_DETECTION_SOURCE` (JSON pour les kinds riches). Voir [Configuration §1.7](CONFIGURATION.md#17-boucle-purple--source-de-détection-legacy--collecteur).

Dès qu'une source répond, la matrice `detected/missed/MTTD` apparaît sur les techniques déjà tirées —
la moitié « red » était déjà là.

## Standalone hors programme (own-infra / CTF / pentest autorisé)

Forge n'exige aucun « programme » : créez un dossier de scope pour n'importe quelle cible **autorisée**
(own-infra, lab, CTF, mission sous contrat). Le seul prérequis est l'**autorisation** — la gate ROE
et le ledger sont là pour l'imposer et la prouver, pas pour la contourner. Voir la charte dans
[`../LICENSE`](../LICENSE) et le template d'engagement [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md).
