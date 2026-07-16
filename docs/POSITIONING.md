# Forge — Positionnement (GTM)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Vue d'ensemble](OVERVIEW.md) · [Pricing](PRICING.md) · [Plan](PLAN.md)

> **Slogan**
> *« Forge n'est pas un remplaçant de Metasploit — c'est la couche **gouvernance + preuve + mesure
> purple** par-dessus les outils que vous avez déjà (il pilote MSF / Burp / nuclei). »*

Forge ne se vend PAS sur le nombre d'exploits. Il se vend sur trois choses qu'aucun arsenal offensif
n'a jamais offertes ensemble : **prouver l'autorisation**, **mesurer ce que le SOC a vu**, et **ne
rien casser par défaut**. C'est une couche de **gouvernance offensive**, pas un nouvel arsenal.

---

## 1. Le segment cible (et qui on N'adresse PAS)

| | Acheteur visé | Pourquoi |
|---|---|---|
| ✅ | **RSSI / Direction sécurité** | Veut une preuve auditable que le red-team est resté in-scope, et un chiffre de couverture défensive à présenter au COMEX / au régulateur. |
| ✅ | **Lead purple-team / responsable détection** | Veut savoir, technique ATT&CK par technique, ce que le SOC **a détecté / raté** et en combien de temps (MTTD). |
| ✅ | **Juridique / conformité / DPO** | Veut une chaîne de custody signée et vérifiable par un tiers : qui a autorisé quoi, quand, sur quel périmètre. |
| ❌ | **Le pentester chasseur d'exploits** | Cherche la capacité brute (0-days, post-exploit, evasion EDR). Forge ne joue PAS sur ce terrain — il **pilote** ses outils, il ne les remplace pas. |

**La phrase qui qualifie un prospect** : *« Après une campagne offensive, pouvez-vous prouver
à un auditeur que vous êtes resté in-scope, ET chiffrer ce que votre SOC a réellement détecté ? »*
Si la réponse est « non / pas facilement », c'est un prospect Forge.

---

## 2. Les trois piliers

### Pilier (a) — Preuve d'autorisation signée

Le différenciateur que **personne** dans l'offensif n'industrialise : l'autorisation n'est pas une
intention, c'est un artefact cryptographique.

- **Gate ROE fail-closed à 4 couches** (`forge/roe.py`) : une action LIVE ne part QUE si elle a
  franchi *armé → in-scope (allowlist, jamais deny-list) → capacité autorisée → approuvée*. Toute
  ambiguïté ou erreur d'évaluation ⇒ `VETO` (refus dur). Hors scope ⇒ jamais simulé, jamais tiré.
- **Ledger d'engagement append-time, tamper-evident** (`forge/ledger.py` + `signing.py`) :
  chaîne de hash SHA-256 + signature **Ed25519** par-entrée. Un tiers (auditeur, client, juridique)
  vérifie l'intégrité avec la **seule clé publique** (`verify_external(pubkey)`) — sans jamais
  pouvoir forger une entrée.
- **Custody — honnêteté** : la clé privée est encore locale ; l'**ancrage hors-host** (témoin
  co-signataire distant, `forge/anchor.py`) est l'étape finale, et l'architecture asymétrique le
  permet déjà (seule la clé publique circule). Documenté, pas caché.

**Valeur vendue** : « Vous signez chaque action de l'engagement. Votre auditeur la vérifie sans vous
faire confiance. »

### Pilier (b) — Boucle PURPLE même-vendeur

Forge (rouge) et **Plume** (bleu, le SOC `../plume`) sont du **même éditeur** et se corrèlent par
champ **MITRE ATT&CK**. « Purple » n'est pas un 3ᵉ produit : c'est la boucle.

```
Forge tire la technique T ─► run-record {mitre: T} ─► Plume ingère
                                                          │
                       Plume détecte ? alerte {mitre: T} ─┘
   corrélation = égalité du champ `mitre`  ─►  matrice de couverture ATT&CK
   (Forge mesure le VRAI MTTD + le VRAI % de couverture du SOC)
```

Sortie : par technique → **detected / missed / MTTD réel**. Pas un score marketing — un join
lecture-seule entre ce que le rouge a tiré et ce que le bleu a vu.

**Valeur vendue** : « Voici, technique par technique, ce que votre SOC a raté, et en combien de
temps il a vu le reste. Voici comment combler. »

### Pilier (c) — Safe-by-default

- **Non-exploit forcé** : par défaut Forge est **INERTE**. `allow_exploit` / `allow_destructive`
  sont des opt-in explicites par engagement. Un module marqué `exploit=True` (ex. `msf.module`) est
  vétoé tant que la capacité n'est pas armée.
- **Gouverne opt-in** : armement par couche (`--arm`), approbation par action (`--approve`), ou mode
  `auto` documenté. Rien ne « part tout seul ».
- **Scope-guard dur** : `in_scope` vide ⇒ rien ne tire (fail-closed). Le connecteur `burp.scan`
  émet `reported_by_tool`, jamais `vulnerable`, tant qu'il n'y a pas de preuve d'exploitabilité —
  pas de sur-classement.

**Valeur vendue** : « L'outil le plus difficile à utiliser pour faire une bêtise. Par construction. »

---

## 3. Teardown concurrentiel (honnête)

Où Forge **GAGNE** et où il **PERD**. Vendre la vérité construit la confiance d'un acheteur RSSI.

| Dimension | Forge | Metasploit (Pro) | Cobalt Strike | Maltego | Splunk (ES) |
|---|---|---|---|---|---|
| **Gouvernance / preuve d'autorisation** | 🟢 **Gate ROE + ledger Ed25519 tiers-vérifiable** | 🔴 quasi nul | 🔴 nul | ⚪ N/A | ⚪ N/A |
| **Audit / chaîne de custody** | 🟢 **append-time, signé** | 🟡 logs locaux | 🟡 logs C2 | 🔴 | 🟡 logs |
| **Boucle purple intégrée (même vendeur)** | 🟢 **Forge×Plume, corrélation ATT&CK, MTTD** | 🔴 | 🟡 via intégrations tierces | 🔴 | 🟡 côté bleu seul |
| **UI opérateur / dashboards** | 🟢 console + soql + panels | 🟡 | 🟡 | 🟢 | 🟢 |
| **Safe-by-default** | 🟢 **inerte, opt-in, fail-closed** | 🔴 conçu pour tirer | 🔴 | ⚪ | ⚪ |
| **Empreinte / déployabilité** | 🟢 cœur ~5 MB, stdlib pur | 🟡 | 🟡 | 🟡 | 🔴 lourd |
| | | | | | |
| **Capacité offensive brute** | 🔴 **faible — pilote, ne fournit pas** | 🟢 énorme | 🟢 élite (C2/post-ex) | 🟡 OSINT | ⚪ |
| **Maturité / track record** | 🔴 **v0.0.1** | 🟢 20+ ans | 🟢 standard red-team | 🟢 | 🟢 |
| **Écosystème / modules / communauté** | 🔴 **11 modules** | 🟢 2000+ | 🟢 | 🟢 | 🟢 |
| **Post-exploitation / C2 / pivot** | 🔴 **aucun (hors-charte)** | 🟢 | 🟢 | ⚪ | ⚪ |

**Lecture** : Forge est **complémentaire**, pas substituable. Il ne cherche PAS à battre MSF sur la
capacité (perdu d'avance, hors-charte). Il s'achète **par-dessus** MSF/Burp/nuclei pour les gouverner
et mesurer leur impact défensif. Le moat = *rouge + bleu, même vendeur, corrélés ATT&CK, autorisation
signée* — ce qu'aucune ligne de cette table n'a en colonne unique.

---

## 3bis. Face à l'OSS / AGPL (honnête)

La vérité qui désarme l'objection « c'est juste reNgine avec une autre UI » : comme **orchestrateur
d'outils piloté depuis une interface**, Forge n'est **PAS unique** — l'OSS mature couvre déjà bien cet
axe. Le différenciateur de Forge n'est pas l'orchestration : c'est la couche
**gouvernance + preuve + non-répudiation** qu'aucun projet OSS n'industrialise.

| Outil | Licence | Ce qu'il fait aussi bien (ou mieux) | Ce qui manque vs Forge |
|---|---|---|---|
| **reNgine** | GPL-3.0 | Orchestration recon/scan via UI web, scan-engines paramétrables, findings. Le plus proche sur « piloter des outils depuis une UI ». | Pas de scope-guard fail-closed, pas de ledger, pas de discipline de preuve, pas de purple. Orienté recon web. |
| **Faraday** (Community) | GPL-3.0 | Plateforme collaborative multi-pentest : workspaces (≈ engagements), 80+ outils intégrés, findings, reporting, RBAC. | Il agrège, il ne tire pas sous contrainte ; pas de ledger signé, pas de planner coverage-safe, pas de purple. |
| **Osmedeus** | MIT | Framework d'automatisation recon/scan par workflows, rapide, CLI-first. | CLI, pas de gouvernance UI, pas de preuve/ledger/purple. |
| **DefectDojo** (OWASP) | BSD-2 | Vuln management / ASPM : import de scans, dédup, triage, métriques, rapport. | DevSecOps, pas d'orchestration active, pas de scope-guard offensif, pas de ledger d'autorisation. |
| **Nuclei / ProjectDiscovery** | MIT | Le moteur de scan que Forge pilote. | Une brique, pas un orchestrateur gouverné. |
| **Metasploit / Sliver / Havoc / Mythic** | BSD/Apache/GPL | Vrais frameworks d'exploitation & C2 (post-ex). | Niche opposée : ils exploitent ; Forge exclut l'exploit et se veut prouvable/auditable — il les pilote. |

**Lecture** : comme orchestrateur-UI, Forge n'est **pas unique** (reNgine / Faraday sont matures). Le
trou que personne ne remplit = **prouver l'autorisation** (scope-guard fail-closed), **prouver
l'impact** (oracle → preuve), et le rendre **non-répudiable** (ledger Ed25519 chaîné) + la **boucle
purple**. C'est là, pas sur « une UI par-dessus des outils », que se joue le moat.

---

## 4. Ce que Forge N'EST PAS (anti-confusion)

- **PAS un beacon / un C2** : aucun implant, aucun callback persistant, aucune post-exploitation.
  Forge orchestre des outils à fire-time puis trace ; il ne maintient pas d'accès.
- **PAS de l'OSINT / Maltego** : il ne cartographie pas des personnes, des graphes sociaux, des
  fuites. Son `origin.find` retrouve une IP d'origine derrière un CDN — c'est de la recon technique
  scopée, pas du renseignement.
- **PAS du forensics / Cellebrite** : aucune acquisition disque/mobile, aucune analyse post-mortem.
  Le ledger est une preuve **d'autorisation d'engagement**, pas une preuve forensique de terminal.
- **PAS un scanner de vulnérabilités** : nuclei/Burp font le scan ; Forge les **gouverne et corrèle**.
- **PAS un remplaçant de Metasploit** : il le **pilote** (`msf.module` → msfrpcd).

---

## 5. Le pitch en une page (pour un RSSI)

> Vos pentesters ont déjà Metasploit, Burp, nuclei. Ce qui vous manque, c'est : (1) **prouver** à
> votre auditeur que la campagne est restée dans le périmètre autorisé — signé, vérifiable sans vous
> faire confiance ; (2) **chiffrer** ce que votre SOC a réellement détecté, technique ATT&CK par
> technique, avec le vrai temps de détection ; (3) un outil **incapable de déraper** par défaut.
> Forge est cette couche. Il ne remplace pas vos outils — il les rend gouvernables et mesurables.

---

*Voir aussi : [`PRICING.md`](PRICING.md) · [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md) ·
[`PLAN.md`](PLAN.md) (roadmap) · [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) (câblage Plume).*
