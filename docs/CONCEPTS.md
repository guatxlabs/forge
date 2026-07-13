# Concepts

> [Sommaire](README.md) · Voir aussi : [Architecture](ARCHITECTURE.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md) · [Catalogue de modules](MODULES.md)

Cette page explique les idées centrales de Forge. Chaque section renvoie au code et aux références.

- [1. ROE & scope-guard](#1-roe--scope-guard)
- [2. Le ledger d'engagement](#2-le-ledger-dengagement)
- [3. Oracles à preuve (*tested-unless-proven*)](#3-oracles-à-preuve)
- [4. Catalogue de modules & techniques (ATT&CK)](#4-catalogue-de-modules--techniques)
- [5. La boucle purple](#5-la-boucle-purple)
- [6. Chaînage (engine itératif)](#6-chaînage)
- [7. Découverte backée par évasion](#7-découverte-backée-par-évasion)

---

## 1. ROE & scope-guard

Le **ROE (Rules of Engagement)** est le cœur de sûreté (`forge/roe.py`). Il combine le scope-guard
*fail-closed* de secpipe et le modèle d'armement par couche de Plume. **Quatre couches** doivent
TOUTES être franchies pour qu'une action LIVE parte :

| Couche | Question | Portée | Échec → |
|---|---|---|---|
| 1 — armé ? | l'engagement est-il explicitement armé (`--arm`) ? | global | `DRY_RUN` |
| 2 — scope ? | cible ∈ `in_scope` **et** ∉ `out_scope` ? (fail-closed : `in_scope` vide = rien) | par cible | `VETO` |
| 3 — capacité ? | exploit/destructif ⇒ `allow_exploit`/`allow_destructive` explicites ? | par action | `VETO` |
| 4 — approuvé ? | action approuvée (`--approve`), ou mode `auto` ? | par action | `DRY_RUN` |

**Verdicts** :
- **`FIRE`** — 1+2+3+4 OK → action live autorisée (seul cas où `module.fire()` est appelé).
- **`DRY_RUN`** — in-scope + capacité OK mais non armé/non approuvé → simulation sûre (`module.dry()`
  génère le PoC, aucun effet de bord).
- **`VETO`** — couche 2 ou 3 échoue → refus DUR, **jamais** simulé, **jamais** tiré.

**Fail-closed intégral** : toute exception, champ inconnu ou ambiguïté d'évaluation ⇒ `VETO`.
L'appartenance au scope canonise l'hôte (retire scheme/port/path, casefold) et gère les globs **et**
les CIDR/IP — une IP `out_scope` ne peut pas être contournée via une URL ou un `host:port`.

Le `Scope` (`scope.json`) porte : `mode` (white/grey/black), `in_scope`/`out_scope`, `rate`,
`allow_exploit`, `allow_destructive`, `known_creds`, `idor_targets`, `module_params`,
`disabled_modules`, et le matériel de `session`/`sessions` (SECRET). Modèle de fichier :
[`../scope.example.json`](../scope.example.json).

> **Note trust-boundary** : franchir un WAF/Cloudflare n'est **pas** une faille — c'est un enabler
> d'accès. La gate ROE + le ledger existent pour **imposer ET prouver** l'autorisation, pas pour la
> contourner.

---

## 2. Le ledger d'engagement

Chaque acte (décision ROE, armement, approbation, finding, run-record, action console) est **chaîné
et signé à l'append** (`forge/ledger.py` + `signing.py`) :

```
hash_n = SHA256( hash_{n-1} || seq || ts || kind || canonical_json(detail) )
sig_n  = sign(hash_n)                     # Ed25519 par défaut ; HMAC en repli si cryptography absent
```

Propriétés :
- **Couverture totale** : TOUTES les entrées sont chaînées (corrige la faiblesse « ~8 types admin
  seulement » du ledger d'origine).
- **Signature par-entrée** (pas seulement au checkpoint) : altérer un octet casse `verify()`.
- **Non-répudiation** (Ed25519) : `verify_external(pubkey_hex)` laisse un **tiers** vérifier
  l'intégrité **et** l'appartenance au périmètre avec la **seule clé publique**, sans pouvoir forger.
- **Alg-aware / anti-downgrade** : un même ledger mélange les entrées moteur (`ed25519`/`hmac`) et
  les entrées console (`sha256-console`, chaîne non signée). Une garde structurelle lie l'algo au
  `kind` : `sha256-console` n'est légitime que sur un `kind` `console.*`, et inversement — ce qui
  ferme le downgrade (réécrire une entrée moteur en non-signée) **et** le relabel.

**Custody (honnêteté)** : la clé privée `.ed25519` (0600) est aujourd'hui **locale**. L'ancrage
hors-host (`forge/anchor.py` : témoin co-signataire distant + `reconcile` qui détecte une réécriture
re-signée localement) est la dernière étape ; l'architecture asymétrique le permet déjà.

Commandes : `forge ledger verify|pubkey|keygen` ([CLI](CLI.md)) · `forge ledger verify`
(chaîne seule, rapide) · `GET /api/ledger/verify` (côté console, sans clé privée).

---

## 3. Oracles à preuve

Principe ***tested-unless-proven*** : un finding **ne monte PAS** en `vulnerable` sans **preuve
concrète d'impact**. La machine d'état des findings (`schema.py`) :

`tested → reported_by_tool → vulnerable` (+ `not_vulnerable`, `informative`, `skipped`, …).

- **`reported_by_tool`** — un outil tiers (nuclei, Burp) a signalé un hit **sur sa propre
  sévérité auto-déclarée**. Ce n'est PAS une vuln confirmée par Forge : pas de sur-classement.
- **`vulnerable`** — réservé aux **oracles à preuve** qui apportent une preuve différentielle ou
  d'exploitabilité, **liée au compte de l'opérateur** (jamais un tiers). Exemples :

| Oracle | Preuve exigée pour `vulnerable` |
|---|---|
| `access_control.idor` | Le compte B obtient le **même corps normalisé** que l'objet du compte A (anon refusé). |
| `ssrf.callback` | Un **callback unique** est reçu côté collecteur. |
| `auth.takeover` | Après le flux de bypass, le `whoami` renvoie l'**identité de la victime**. |
| `cors.credentials` | ACAO reflète l'origine attaquante (pas `*`) **ET** ACAC=true sur un endpoint authentifié. |
| `jwt.weakness` | Un **jeton forgé est accepté pour le compte de l'opérateur** (self_marker). |
| `path.traversal` / `ssti.eval` | Un **marqueur bénin** (canari) revient — jamais de fichier système ni de RCE. |
| `csrf.state_change` | Action **critique** + anti-CSRF absent **ET** SameSite confirmé absent (détection seule, aucune mutation cross-site). |

Cette discipline reflète le « Gate Impact » : *quelle donnée d'un autre user puis-je voir ? quelle
action au nom d'un autre user ? quel asset détourner ?* Si les trois sont non → pas de promotion.

---

## 4. Catalogue de modules & techniques

`forge/techniques.py` est la **source de vérité unique** de la taxonomie : une table
`kind`/classe/CWE → `Technique` (ATT&CK id, CWE, qualifiant, remédiation, tactique/phase/capability).
Les autres fichiers **dérivent** leurs vues (le planner son ensemble `QUALIFYING`, le brain les
`cls`/`exploit` par kind, le schema le mapping de remédiation, purple le repli ATT&CK par kind) —
plus aucune recopie qui dériverait.

Chaque module porte un **identifiant MITRE ATT&CK** (le badge dans la console et la clé de jointure
purple). Le catalogue livré compte **31 modules** couvrant :

- **Recon passif** : `recon.subdomains` (crt.sh), `recon.dns`, `recon.urls` (Wayback), `recon.tech`,
  `recon.waf`, `recon.js_endpoints`.
- **Recon actif gouverné** : `recon.httpx`, `recon.nmap`, `web.nuclei`, `recon.content` (ffuf,
  rate-limité), `recon.secrets` (trufflehog/gitleaks), `origin.find` (IP d'origine derrière CDN).
- **Oracles à preuve** : `access_control.idor`, `ssrf.callback`, `auth.takeover`, `cors.credentials`,
  `ssti.eval`, `path.traversal`, `sqli.probe`, `xss.reflected`, `redirect.open`, `csrf.state_change`,
  `jwt.weakness`, `graphql.access`.
- **Évasion** (browser-automation) : `evasion.xhr`, `evasion.turnstile`, `evasion.idor_intercept`,
  `evasion.discover`.
- **Connecteurs** : `msf.module` (msfrpcd), `burp.scan` (REST API Burp).
- **Démo** : `demo.fingerprint` (no-op, zéro I/O).

La **table complète générée** (`kind`, exploit, destructif, ATT&CK, description, dépendance,
disponibilité) est dans **[MODULES.md](MODULES.md)**. La disponibilité réelle sur une machine se
sonde avec `forge doctor` (un module dont l'outil manque est **auto-neutralisé**, jamais tiré).

---

## 5. La boucle purple

La boucle **purple** corrèle les techniques **tirées** en red (run-records taggés `mitre`) aux
techniques **détectées** par la défense — par **égalité d'identifiant MITRE** — et en déduit
`detected` / `missed` / **MTTD**.

```
Forge tire la technique T ─► run-record {mitre: T} ─► console (store rouge)
                                                          │  JOIN lecture seule
Source de détection (Plume/SIEM/IDS) détecte T ? ─────────┘  sur égalité `mitre`
   ─►  matrice de couverture ATT&CK : detected / missed / MTTD(T) = first_detection − last_fire
```

Deux invariants :
- **La corrélation ne change jamais** ; seule la **SOURCE** de détection est spécifique au client.
  C'est un **plugin configurable** : Plume n'est qu'un préréglage (`kind=plume`). Modèle
  `DetectionSource`, préréglages (CrowdSec/FortiGate/pfSense/OPNsense/Elastic/fichier/exec) et mapping
  MITRE : [`DETECTION.md`](DETECTION.md). Prérequis du préréglage Plume : [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).
- **Fail-open lisible** : source absente/injoignable ⇒ `source_reachable:false`, la mesure est
  déclarée **impossible** — jamais de `detected`/`missed`/`MTTD` inventé. Source joignable mais vide
  (SOC frais) = état **valide**.

Le **MTTD** est un **time-to-ALERT** (il englobe l'ingest + la cadence d'évaluation des règles), pas
un time-to-event — à ne pas surinterpréter. Explication détaillée : [`MTTD.md`](MTTD.md).

Endpoint : `GET /api/detection/coverage` (alias rétro-compat `/api/purple/coverage`). Préflight
lecture seule : `forge doctor --purple`.

---

## 6. Chaînage

`engine.campaign()` est **itératif** : `plan → observe → replan`, jusqu'à un critère d'arrêt.

À chaque **vague**, le cerveau (`brain.propose(graph)`) lit le **world-model enrichi** par la vague
précédente (pas seulement les cibles), le planner ordonne (coverage-safe), l'engine tire (gaté), et
les findings **enrichissent le graphe** — ce qui permet au cerveau de **chaîner** :

- une **origine hors-CDN** découverte (`origin.find`) → `nuclei`/oracles sur l'IP ;
- un **fingerprint** → les oracles à preuve adaptés à la techno ;
- un **endpoint découvert** (JS, WAF-bypass) → un oracle IDOR/injection sur cet endpoint.

Critères d'arrêt : point fixe (plus de nouvelle action), `max_waves` (garde anti-boucle), ou budget
épuisé pour le travail non-qualifiant. Le **ROE/gouvernance est réappliqué à chaque vague** — rien ne
tire sans `FIRE`. La **session gouvernée** est héritée le long de la chaîne : une cible dérivée
in-scope hérite du matériel d'auth de sa source (no-op scope-guardé si hors-scope), pour que les
oracles chaînés soient authentifiés — sans que le secret n'entre jamais dans le finding/ledger/graphe.

Les cibles dérivées à runtime sont **re-validées fail-closed** contre le périmètre injecté
(`in_scope`/`out_scope`) avant toute émission — un module de découverte ne peut pas élargir le scope.

---

## 7. Découverte backée par évasion

`evasion.discover` (T1594) navigue **derrière un challenge WAF managé** via le service
browser-automation (Camoufox + vision-click-os pour un Turnstile interactif), puis **extrait des
endpoints** (DOM/JS/XHR) **in-scope** et les émet avec le marqueur de découverte — qui alimente
ensuite la chaîne d'oracles (§6). Les modules d'évasion :

| Module | Rôle | ATT&CK |
|---|---|---|
| `evasion.turnstile` | Franchit le Cloudflare Turnstile interactif (détection template + clic OS X11) — **enabler d'accès** | T1556 |
| `evasion.xhr` | Observe les requêtes XHR via la session browser (contournement WAF/DataDome) | T1190 |
| `evasion.idor_intercept` | Arme l'interception IDOR en vol (browser intercept-modify) — preuve via `/intercept-dump` | T1190 |
| `evasion.discover` | Découverte d'endpoints derrière WAF, scope-locké, non destructif, borné, session redigée | T1594 |

Garanties : **scope-locked** (chaque endpoint découvert re-validé), **non-destructif**, **borné**,
**session redigée** (le matériel d'auth ne fuit pas). Le service browser-automation est **optionnel**
(`FORGE_BROWSER_URL`) : injoignable ⇒ le module s'auto-neutralise (`available:false`), jamais tiré.

> Rappel : franchir un WAF **≠ une faille**. C'est un enabler d'accès à combiner avec un oracle à
> preuve. Le ledger et le scope-guard restent durs.
