# Forge — Démarrage (parcours opérateur bout-en-bout, 100 % hors-ligne)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Vue d'ensemble](OVERVIEW.md) ·
> [Installation](INSTALLATION.md) · [Référence CLI](CLI.md)

> Ce guide se fait **entièrement hors-ligne**, avec l'**engagement de référence synthétique** fourni
> ([`examples/reference-engagement/`](../examples/reference-engagement/)) et le **stub mock-Plume**
> stdlib ([`tools/mock_plume.py`](../tools/mock_plume.py)). **Aucun service externe, aucune cible
> réelle, aucun SOC réel** n'est requis. Chaque étape a un point de contrôle **« Ce que tu dois
> voir »** : si ça ne correspond pas, arrête-toi là avant de continuer.
>
> ⚠️ Cadre **autorisé uniquement** (bug bounty in-scope, pentest sous contrat, CTF, infra propre).
> Passer un WAF/Cloudflare ≠ une faille : la gate ROE + le scope-guard + le ledger sont là pour
> **imposer ET prouver** l'autorisation. Voir [`../README.md`](../README.md).

Toutes les commandes se lancent depuis la racine du dépôt (`GUATX/forge/`).

---

## (a) Installer / construire

Le cœur Python est **pur-stdlib** (`deps=[]`) ; la console est un binaire Rust unique.

```bash
# 1) moteur Python (met l'exécutable `forge` sur le PATH)
pip install -e .            # sans install : préfixer les commandes par `python3 -m forge.cli`

# 2) console Rust (compile offline depuis le cache cargo)
cd console && cargo build --release && cd ..

# 3) suite de tests complète (stdlib côté Python + cargo côté console, zéro réseau)
make test                  # = python3 -m unittest discover -s tests -t .  +  (cd console && cargo test)
python3 -m unittest discover -s tests -t .   # Python seul (260 tests)
```

> **Ce que tu dois voir** : `pip install -e .` termine sans erreur et `forge --version` répond
> (version dérivée du fichier [`../VERSION`](../VERSION)). `cargo build --release` produit
> `console/target/release/forge`. `make test` finit sur **`OK`** (260 tests Python verts +
> cargo test de la console). L'empreinte et la matrice de déploiement (Docker / k8s / host / venv)
> sont détaillées dans [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## (b) Mettre en place le scope (ROE)

Forge est **INERTE par défaut** : `in_scope` vide ⇒ tout est refusé (fail-closed). Pour un vrai
engagement, on copie l'exemple puis on renseigne `in_scope` **avec autorisation écrite** :

```bash
cp scope.example.json scope.json     # scope.json est gitignored ; scope.example.json (INERTE) est committé
```

> ⚠️ **Garde compose** — en déploiement Docker, **créer `scope.json` AVANT `docker compose up`**.
> Le bind-mount attend un **fichier** : si `./scope.json` est absent, Docker crée un **répertoire**
> vide à sa place. Le point d'entrée compose **échoue bruyamment** dans ce cas, et **bascule sur le
> `scope.example.json` embarqué (INERTE)** si `scope.json` manque ou est vide (cf.
> [`../docker-compose.yml`](../docker-compose.yml)). Rien ne tire tant que le scope n'autorise pas.

Pour ce guide hors-ligne, **on n'édite rien** : on réutilise le scope déjà fourni avec l'engagement
de référence — [`examples/reference-engagement/scope.json`](../examples/reference-engagement/scope.json)
(grey-box, `allow_exploit=false`, `allow_destructive=false`, hôtes `.example` réservés).

```bash
forge scope-check api.lab.example --scope examples/reference-engagement/scope.json   # IN SCOPE ✅
forge scope-check evil.example    --scope examples/reference-engagement/scope.json   # HORS SCOPE ⛔
```

> **Ce que tu dois voir** : la 1re commande imprime `IN SCOPE ✅`, la 2de `HORS SCOPE ⛔`
> (code de sortie `1`). Le scope-guard tranche l'appartenance **avant** tout test.

---

## (c) Peupler la console (campagne gatée, ou `make demo`)

Deux chemins, tous deux hors-ligne :

**Chemin rapide — `make demo`** ingère les fixtures de l'engagement de référence directement dans
SQLite (idempotent, sans réseau, ne touche que la campagne démo `acme-lab`, run `seed-demo-acme-lab`) :

```bash
make demo          # amorce la base démo + lance la console peuplée -> http://127.0.0.1:7100
```

**Chemin CLI — lancer une campagne gatée** contre le seed (démontre plan → ROE → dry/fire → ledger →
rapport). Le scope de référence est INERTE côté capacités (`allow_exploit=false`) : sans `--arm`, tout
reste en `DRY_RUN`/`VETO` (aucun effet), ce qui est le comportement voulu — Forge ne tire jamais à
l'aveugle.

```bash
python3 -m forge.cli campaign \
    --scope   examples/reference-engagement/scope.json \
    --targets examples/reference-engagement/targets.json \
    --campaign getting-started --ledger engagements/gs.jsonl --report /tmp/gs_report.md
```

> **Ce que tu dois voir** : après `make demo`, la console écoute sur `http://127.0.0.1:7100` et ses
> onglets **Findings / Couverture ATT&CK / Runs** sont peuplés (6 findings, 8 run-records, campagne
> `acme-lab`). Après la campagne CLI : une ligne `Tirées=… Simulées=… Refusées=…` puis
> `Rapport -> /tmp/gs_report.md`, et la liste des **lacunes de couverture** (classes jamais tentées) —
> zéro lacune silencieuse.

---

## (d) Voir findings + preuves + couverture ATT&CK dans la console

Console peuplée par `make demo`, à `http://127.0.0.1:7100` :

| Onglet | URL | Contenu |
|---|---|---|
| Findings | <http://127.0.0.1:7100/#findings> | 6 findings avec sévérité, CWE, statut, **evidence** et **PoC** |
| Couverture ATT&CK | <http://127.0.0.1:7100/#coverage> | par technique MITRE : nb de runs tentés et combien ont **tiré** |
| Détection purple | <http://127.0.0.1:7100/#purple-coverage> | matrice détecté/raté (peuplée à l'étape (e)) |
| Ledger | <http://127.0.0.1:7100/#ledger> | intégrité de la chaîne d'engagement |

En API (mêmes données, lecture) : `GET /api/findings`, `GET /api/coverage`, `GET /api/runrecords`.

> **Ce que tu dois voir** : l'onglet **Findings** liste l'IDOR cross-tenant, le SSRF OOB, le CORS
> credential, le token de reset prédictible, l'exposition d'origine et les en-têtes manquants —
> chacun avec son **evidence** et sa **PoC**. L'onglet **Couverture ATT&CK** montre les techniques
> tirées (T1595, T1046, T1190, T1212, T1590.005, T1595.002, T1539).

---

## (e) Boucle purple : matrice détecté / raté / MTTD (stub mock-Plume)

```bash
make demo-purple   # démarre tools/mock_plume.py (DEMO FIXTURE) + la console avec PLUME_URL réglé
```

`make demo-purple` lance le **stub mock-Plume** sur `127.0.0.1:8899`, qui sert un jeu **fixe et
synthétique** de détections MITRE ([`examples/reference-engagement/detections.jsonl`](../examples/reference-engagement/detections.jsonl)),
puis démarre la console avec `PLUME_URL` pointé dessus. La console fait la **jointure**
red-tiré ↔ blue-détecté et affiche la matrice.

> ⚠️ **Ceci est une fixture de démonstration, PAS un vrai SOC.** Le stub étiquette chaque réponse
> `DEMO FIXTURE` (`_demo:true`, `_warning`, en-tête `X-Demo-Fixture`). **Ne jamais** pointer un
> engagement réel dessus.

> **Ce que tu dois voir** : sur <http://127.0.0.1:7100/#purple-coverage>, la matrice affiche
> **7 techniques tirées · 4 détectées · 3 ratées** (taux de détection 57 %, MTTD moyen ≈ 3,9 min,
> max 6 min). Les lignes ratées (T1590.005, T1595.002, T1539) sont volontairement absentes du seed
> de détections — c'est ce qui rend la matrice utile (détecté **ET** raté).

---

## (f) Générer un rapport

**CLI** — le rapport d'engagement markdown, écrit par
[`forge/report.py`](../forge/report.py) `build_report` (déjà produit à l'étape (c) via `--report`) :

```bash
python3 -m forge.cli campaign --scope examples/reference-engagement/scope.json \
    --targets examples/reference-engagement/targets.json \
    --campaign gs --ledger engagements/gs.jsonl --report rapport.md
```

Le rapport CLI porte : **en-tête d'engagement** (périmètre du scope + empreinte du ledger : head +
clé publique Ed25519 quand disponible), synthèse par sévérité, findings détaillés, section
**Techniques ATT&CK exercées** (les MITRE réellement tirés), transparence ROE (anti-masquage :
simulé / refusé / déféré / jamais tenté), et un **pointeur** vers le rapport console.

**Console** — le livrable **complet** est servi par la console. Comme la jointure des détections
Plume est **côté console**, c'est **lui seul** qui porte la **matrice détecté/raté + MTTD** et
l'**annexe chaîne-de-custody** :

```
GET http://127.0.0.1:7100/api/runs/seed-demo-acme-lab/report            # markdown (défaut)
GET http://127.0.0.1:7100/api/runs/seed-demo-acme-lab/report?format=html  # livrable client brandé
```

> **Ce que tu dois voir** : `rapport.md` s'ouvre sur `## Engagement` (périmètre) puis `## Synthèse`,
> et se termine par `## Techniques ATT&CK exercées` + un renvoi explicite vers
> `GET /api/runs/<id>/report`. Le lien console `?format=html` rend un document autonome imprimable
> (Imprimer → « Enregistrer en PDF » ; voir [`DEPLOYMENT.md`](DEPLOYMENT.md) § Rapports & export PDF)
> avec la matrice purple **et** l'annexe custody.

---

## (g) Vérifier l'intégrité (ledger) et le préflight (doctor)

Le ledger d'engagement est **append-time, tamper-evident** : chaque acte est chaîné (SHA-256) et
signé (Ed25519 par défaut ; repli HMAC si `cryptography` absent).

```bash
# intégrité : recalcule la chaîne + vérifie chaque signature
forge ledger verify --ledger engagements/gs.jsonl

# clé publique Ed25519 (hex) — un tiers vérifie SANS aucun secret
forge ledger pubkey --ledger engagements/gs.jsonl
forge ledger verify --ledger engagements/gs.jsonl --pubkey <hex_ci-dessus>   # vérif externe
```

**Préflight de la boucle purple** (lecture seule — ne tire rien, ne touche ni scope ni ledger) :

```bash
forge doctor --purple      # état des modules + prérequis de la jointure purple
```

> **Ce que tu dois voir** : `ledger verify` répond `{"ok": true, "entries": N, ...}` ; `ledger
> pubkey` imprime 64 caractères hex (ou une note claire si le ledger est signé en HMAC) ; la vérif
> externe `--pubkey` répond `ok: true` sans aucun secret. `forge doctor --purple` liste les modules
> opérationnels et signale ce qui manquerait pour brancher un vrai Plume — **sans rien tirer**.

---

## Aller plus loin

Tout ce guide tourne **sans Plume réel** (seed + stub mock-Plume). Pour brancher un **vrai Plume**,
voir [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) (`PLUME_URL` / `PLUME_TOKEN`) — **non requis ici**.

- [`../README.md`](../README.md) — vue d'ensemble, gate ROE à 4 couches, catalogue des 14 modules.
- [`../examples/reference-engagement/README.md`](../examples/reference-engagement/README.md) — détail du seed synthétique + la matrice purple attendue.
- [`ARCHITECTURE.md`](../ARCHITECTURE.md) — cœur (roe/ledger/engine/schema) + boucle purple.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — empreinte, matrice Docker/k8s/host/venv, export PDF.
- [`PURPLE_CAMPAIGN.md`](PURPLE_CAMPAIGN.md) · [`MTTD.md`](MTTD.md) — la boucle purple en profondeur.
- [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) — prérequis pour câbler un vrai Plume (le moat).
</content>
</invoke>
