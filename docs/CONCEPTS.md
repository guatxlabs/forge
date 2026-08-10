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
*fail-closed* du prototype interne d'origine et le modèle d'armement par couche de Plume.
**Quatre couches** doivent
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
| `framework.exposure` | Signature de **CORPS propre à l'endpoint** (`/beans` → JSON `"beans"`, `/httptrace` → `"traces"`, `/heapdump` → magic `JAVA PROFILE`). Jamais un code 200, **jamais** une réponse HTML. |
| `race.condition` | Strictement **plus de succès que le quota**, le succès étant attesté par un `success_marker` de **corps** — ou par le statut *sur une cible dont on a vérifié qu'elle discrimine ses routes*. |

Cette discipline reflète le « Gate Impact » : *quelle donnée d'un autre user puis-je voir ? quelle
action au nom d'un autre user ? quel asset détourner ?* Si les trois sont non → pas de promotion.

### 3.1 Un code 200 n'est pas une preuve — la sonde de contrôle *catch-all*

**MESURÉ (campagne `kong`, 2026-08-10, ledger signé).** Première campagne contre une cible tierce à
surface anonyme réelle. Résultat : **16 findings, 8 distincts, tous `[HIGH] vulnerable`, tous FAUX** —
`/actuator/beans`, `/actuator/heapdump`, `/actuator/threaddump`, `/actuator/httptrace`, plus les
variantes Spring Boot 1.x `/beans`, `/heapdump`, `/threaddump`, `/trace`. La cible est une **SPA qui
rend son `index.html` — 3 427 octets identiques, HTTP 200 — pour n'importe quel chemin** (`/wp-admin`,
`/.git/config`, `/zzz-chemin-inexistant-12345`). Il n'y a **aucun** Actuator dessus.

La cause tenait en une disjonction : `if is_sensitive and (leaks or path.endswith((...)))` — pour ces
cinq chemins `path.endswith(...)` est **vrai inconditionnellement**, donc `leaks` (le seul terme qui
lisait le corps) n'était **jamais exigé**. Le verdict tombait sur le seul `st == 200`.

**Pourquoi le « 0 faux positif » du dépôt ne l'avait pas vu.** Il était mesuré sur 2 410 puis 5 318
puis 2 771 findings — mais uniquement contre des cibles **murées** (Cloudflare, UAT qui rend 404
partout). Aucune ne répondait 200 avec du contenu. **Le défaut se révèle à la première cible
réellement atteignable.**

**Les deux remèdes, et leurs bornes.**

1. **Preuve positive par CORPS, endpoint par endpoint** (`exposure._actuator_leak`) : chaque surface a
   une signature propre, et une réponse `text/html` n'est un actuator dans **aucun** cas.
2. **Sonde de contrôle générique** (`Oracle.path_discrimination`) : *toute* découverte de chemin est
   non concluante sur une cible qui ne discrimine pas ses routes. On demande **deux chemins qui ne
   peuvent pas exister** (dérivés de l'origine par SHA-256, donc rejouables) ; s'ils répondent tous
   deux en 2xx, la cible est **catch-all** et le module rend **`skipped`** — « je n'ai pas pu
   vérifier » — jamais `tested` ni `vulnerable`. Vocabulaire et témoin réutilisés de
   [`blindness`](CONCEPTS.md#3-oracles-à-preuve) / `Oracle.degraded()`.

Comme pour `blindness`, deux bornes empêchent l'**excès inverse** :

- la sonde **ne promeut jamais** : son seul pouvoir est de *taire* un verdict. Le 2xx y est lu sur un
  chemin **fabriqué par l'appelant**, donc c'est une preuve *positive* de non-discrimination — pas une
  déduction depuis une absence ;
- **deux** contrôles, pas un : un seul 2xx pourrait être une collision. Preuve partielle (une sonde
  muette) → **indéterminé**, le module garde son comportement historique.

**Mesuré en lab loopback** (`AVANT` = code de `git HEAD`, `APRÈS` = arbre corrigé, mêmes serveurs) :

| Cible loopback | AVANT | APRÈS |
|---|---|---|
| SPA catch-all (corps réel de la campagne) | **8 `vulnerable` HIGH** | 0 `vulnerable`, 1 `skipped` |
| Cible qui discrimine, mais HTML sur `/actuator/*` | **8 `vulnerable` HIGH** | 0 `vulnerable`, 1 `tested` |
| **Actuator Spring réellement exposé** | 5 `vulnerable` + 1 `tested` | **5 `vulnerable` + 1 `tested`** (intact) |

La dernière ligne est la moitié qui compte autant que la première : **un actuator réellement exposé
reste détecté**. Verrouillé par `tests/test_catchall_body_proof.py` (les deux sens) et prouvé par
mutation (11 mutants, 11 tués).

---

## 4. Catalogue de modules & techniques

`forge/techniques.py` est la **source de vérité unique** de la taxonomie : une table
`kind`/classe/CWE → `Technique` (ATT&CK id, CWE, qualifiant, remédiation, tactique/phase/capability).
Les autres fichiers **dérivent** leurs vues (le planner son ensemble `QUALIFYING`, le brain les
`cls`/`exploit` par kind, le schema le mapping de remédiation, purple le repli ATT&CK par kind) —
plus aucune recopie qui dériverait.

Chaque module porte un **identifiant MITRE ATT&CK** (le badge dans la console et la clé de jointure
purple). Le catalogue livré compte **77 modules** (compte MESURÉ : `forge modules --json`) couvrant :

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
techniques **détectées** par la défense — par **égalité d'identifiant de TECHNIQUE** — et en déduit
**trois états** + le **MTTD**.

```
Forge tire la technique T ─► run-record {mitre: T} ─► console (store rouge)
                                                          │  JOIN lecture seule
Source de détection (Plume/SIEM/IDS) détecte T ? ─────────┘  sur la TECHNIQUE
   ─►  matrice de couverture ATT&CK, TROIS états :
         detected-exact         → la source alerte sur EXACTEMENT T   (compte dans le taux + MTTD)
         detected-parent-approx → T est une SOUS-technique et la source n'a que la PARENTE
         missed                 → ni l'un ni l'autre
       MTTD(T) = first_detection − last_fire, sur les detected-exact UNIQUEMENT
```

**Pourquoi trois états et pas deux.** Un tag multi-techniques (`"T1595.002 T1046"` — la norme chez
SigmaHQ : plusieurs `attack.` par règle) est **éclaté des deux côtés** de la jointure, sinon le corpus
Sigma fabrique de faux `missed`. Et une règle taguée de la technique **parente** n'est **pas** une
preuve de détection de la sous-technique tirée : elle est comptée à part (`parent_approx`), **hors du
taux vitrine et hors du MTTD**. La jointure voit un **identifiant**, pas une requête de détection :
elle ne peut donc pas *prouver* que le vecteur tiré est couvert. Exemple mesuré : Forge tire
`T1110.001` (devinette de mot de passe SSH) ; trois des règles `T1110` livrées avec Plume sont bornées
au mail, bornées au web, ou exigent une dispersion d'IP — aucune de ces trois n'attrape un brute-force
SSH mono-source ; d'autres règles `T1110` seedées le pourraient, **selon la télémétrie branchée et les
règles activées**. C'est précisément pour ça qu'on ne tranche pas : le doute est **nommé** plutôt
qu'arbitré en faveur du vendeur. Le parent-approx n'est pas du déchet pour autant : c'est un **angle
mort nommé** (« vous avez tiré `T1110.001`, vous n'avez que des règles `T1110` génériques »), rendu
dans sa propre liste. Pour passer au vert : taguer une règle **de cette sous-technique**.

Deux invariants :
- **La corrélation ne change jamais** ; seule la **SOURCE** de détection est spécifique au client.
  C'est un **plugin configurable** : Plume n'est qu'un préréglage (`kind=plume`). Modèle
  `DetectionSource`, préréglages (CrowdSec/FortiGate/pfSense/OPNsense/Elastic/fichier/exec) et mapping
  MITRE : [`DETECTION.md`](DETECTION.md). Prérequis du préréglage Plume : [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).
- **Fail-open lisible** : source absente/injoignable ⇒ `source_reachable:false`, la mesure est
  déclarée **impossible** — jamais de `detected`/`parent_approx`/`missed`/`MTTD` inventé. Source
  joignable mais vide (SOC frais) = état **valide**.

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

### 6.1 La découverte d'abord (`stage`)

Le chaînage ne vaut que si la **découverte a eu lieu** : un scanner qui tourne avant `katana`/`gau`/
`subfinder` travaille sur trois URLs au lieu de cinquante. Deux mécanismes le garantissent, tous deux
**structurels** (ils s'appliquent à toute action, quelle que soit la voie qui l'a proposée — y compris
le **balayage auto-pentest**, qui contournait l'intention d'ordre portée par le cerveau) :

1. **L'étage de tri.** `planner.order()` trie par `(étage, -EV)`. L'étage vaut `STAGE_SURFACE` pour les
   kinds qui **produisent** de la surface — dérivé du `ToolSpec` (`asset_hits`/`emit_*_discovery` :
   katana, gau, subfinder, amass, feroxbuster, naabu, dnsx, gobuster) et d'une liste de kinds natifs
   *vérifiée contre le source des modules* (httpx, js_endpoints, urls, subdomains, nmap,
   evasion.discover) — `STAGE_VERIFY` pour tout le reste. Un producteur **sur un endpoint déjà dérivé**
   n'est pas un producteur (il n'élargit rien) ; `origin.find` non plus (il publie une **route
   alternative** vers la surface connue, pas de la surface nouvelle).
2. **La frontière de replanification.** À la **première vague seulement**, les consommateurs sont
   reportés d'une vague : la découverte est donc **replanifiée** avant que le premier scanner lent
   n'engage le budget. Reportés ≠ supprimés — ils restent au dénominateur (`planned_total`) et, s'ils
   ne tournent pas, sortent en « planifiées jamais tentées ».

Coverage-safe **inchangé** : c'est un ré-ordonnancement, rien n'est retiré, le plancher qualifiant et
`skipped_budget` sont intacts. Mesuré sur le harnais qui rejoue une campagne réelle
(`tests/bench_wave_reach.py`, 3 cibles, durées observées injectées, budget égal) : **225 → 1 292
actions**, **0 → 32 URLs distinctes atteintes**, **0 → 1 vague complétée**, et **aucun kind ne cesse de
tourner** (58 → 58) — les scanners lents tournent toujours, mais sur une surface découverte.

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
