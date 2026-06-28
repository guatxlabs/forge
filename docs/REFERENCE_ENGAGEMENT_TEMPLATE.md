# Forge — Write-up d'engagement de référence (TEMPLATE)

> **But** : ce squelette devient la **preuve commerciale** de Forge. À remplir **après la 1ʳᵉ
> campagne purple live** (cf. [`PLAN.md`](PLAN.md) Étape 1 + [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md)).
> Le message final qui vend : *« Votre SOC a raté N techniques. Voici lesquelles, et comment combler. »*
>
> ⚠️ **Cadre autorisé uniquement.** Ne remplir qu'à partir d'un engagement réellement scopé et
> autorisé par écrit. Aucune cible non autorisée, jamais. (Reprend la charte de la LICENSE Forge.)

---

## 0. En-tête

| Champ | Valeur |
|---|---|
| Client / programme | `<nom>` |
| Type d'engagement | `<bug bounty in-scope · pentest sous contrat · own-infra lab>` |
| Période | `<début> → <fin>` |
| Opérateur(s) Forge | `<identité / siège>` |
| Référence autorisation | `<n° contrat / accord écrit>` |
| Empreinte ledger (hash racine) | `<sha256 de la dernière entrée — vérifiable>` |
| Clé publique de vérification | `<pubkey Ed25519 pour verify_external>` |

---

## 1. Contexte & scope autorisé

- **Objectif métier** de l'engagement : `<ce que le client voulait valider>`.
- **Périmètre `in_scope`** (verbatim depuis `scope.json`) : `<hôtes / domaines / apps>`.
- **`out_scope`** (exclusions explicites) : `<...>`.
- **Capacités armées** : `allow_exploit = <true/false>` · `allow_destructive = <true/false>` ·
  `mode = <grey/black/white>` · `rate = <n>`.
- **Fenêtre & contraintes** : `<horaires, NTP synchronisé pour MTTD, hôte surveillé par Plume>`.

> Renseigner à partir du `scope.json` réel de l'engagement (ne jamais coller de secret/clé privée ici).

---

## 2. Techniques tirées (timeline)

Une ligne par action ayant abouti à un verdict `FIRE` (les `DRY_RUN` / `VETO` figurent dans la
section anti-masquage §6). Source = run-records de la campagne + ledger.

| # | Horodatage (`ts_fired`) | Module (kind) | ATT&CK | Cible | Verdict ROE | Réf. ledger |
|---|---|---|---|---|---|---|
| 1 | `<epoch/ISO>` | `recon.httpx` | T1595 | `<host>` | FIRE | `<entry hash>` |
| 2 | `<...>` | `recon.nmap` | T1046 | `<...>` | FIRE | `<...>` |
| 3 | `<...>` | `web.nuclei` | T1595.002 | `<...>` | FIRE | `<...>` |
| 4 | `<...>` | `access_control.idor` | T1190 | `<...>` | FIRE | `<...>` |
| … | | | | | | |

---

## 3. Matrice de couverture PURPLE (le cœur du livrable)

JOIN lecture-seule entre les run-records Forge (`{mitre: T}`) et les détections Plume
(`GET {PLUME_URL}/api/coverage/detections`). MTTD = `first_ts (alerte Plume) − ts_fired (Forge)`.

| Technique ATT&CK | Tirée par Forge | Détectée par le SOC (Plume) | MTTD | Statut |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ | `<X min>` | 🟢 detected |
| T1046 — Network Service Discovery | ✅ | ✅ | `<X min>` | 🟢 detected |
| T1595.002 — Vuln Scanning | ✅ | ❌ | — | 🔴 **missed** |
| T1190 — Exploit Public-Facing App | ✅ | ✅ | `<X min>` | 🟢 detected |
| T1210 — Exploit Remote Services | ✅ | ❌ | — | 🔴 **missed** |
| … | | | | |

**Synthèse de couverture** :
- Techniques tirées : **`<M>`**
- Détectées : **`<D>`** → **couverture = `<D/M %>`**
- Ratées : **`<N>`** → *(voir §7 « comment combler »)*
- **MTTD médian** (sur les détectées) : **`<X min>`**

> Cette table est la sortie native de la boucle purple (`/api/purple/coverage`). C'est l'argument
> qu'aucun outil offensif seul ne produit : le **vrai** taux de détection du SOC, mesuré, pas estimé.

---

## 4. Findings avec preuve

Pour chaque finding remonté (store rouge de la console). Pas de sur-classement : un `reported_by_tool`
reste `reported_by_tool` tant qu'il n'y a pas de preuve d'exploitabilité.

### Finding `<#>` — `<titre>`
- **Sévérité** : `<LOW/MEDIUM/HIGH/CRITICAL>` · **ATT&CK** : `<Txxxx>` · **Module** : `<kind>`
- **Cible** : `<host/endpoint>`
- **Statut** : `<reported_by_tool · vulnerable (preuve) >`
- **Preuve** : `<sortie outil / PoC vérifié / capture>` (réf. ledger : `<entry hash>`)
- **Détecté par le SOC ?** : `<oui (MTTD X) / non — voir §3>`
- **Remédiation suggérée** : `<fix technique>`

*(Répéter par finding.)*

---

## 5. Chaîne de custody — le ledger signé

La crédibilité de tout ce write-up repose sur ceci : **chaque action est dans un ledger signé,
vérifiable par un tiers sans confiance dans l'opérateur**.

- **Intégrité interne** : `forge ledger verify --ledger <engagement>.jsonl` → `<OK / hash racine>`.
- **Vérification tiers** : `verify_external(<pubkey>)` → l'auditeur valide la chaîne Ed25519 avec la
  **seule clé publique** (il ne peut ni forger ni altérer). Résultat : `<OK>`.
- **Couverture du ledger** : `<n>` entrées chaînées = **toutes** les décisions ROE (FIRE, DRY_RUN,
  VETO), MAC par-entrée (pas seulement aux checkpoints).
- **Custody — note honnête** : clé privée locale sur cet engagement ; ancrage hors-host (témoin
  co-signataire distant, `anchor.py`) = `<activé / non activé>`.

> **Argument** : « Vous n'avez pas à nous croire. Voici la clé publique. Vérifiez vous-même que
> rien n'a été tiré hors du périmètre que vous avez autorisé, et que le journal n'a pas été réécrit. »

---

## 6. Anti-masquage — ce qui N'a PAS été tiré

Section de transparence (portée de `report.py`). Un rapport honnête liste aussi les lacunes : zéro
trou silencieux.

- **`DRY_RUN`** (simulé, jamais exécuté — capacité non armée ou non approuvé) : `<liste>`.
- **`VETO`** (refusé par la gate — hors scope, capacité interdite, erreur d'éval fail-closed) :
  `<liste + raison>`.
- **Classes jamais tentées** (budget / hors périmètre / hors-charte) : `<liste>`.
- **Non testé (budget temps)** : `<liste>`.

---

## 7. Valeur livrée — « voici comment combler »

La conclusion qui transforme la matrice en décision d'achat.

1. **Trous de détection** : « Votre SOC a raté **`<N>`** techniques : `<T1595.002, T1210, …>`. »
   Pour chacune → **règle / source de log manquante** côté Plume (cf. checklist
   [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) : `rule.mitre` à taguer, sources de logs à brancher).
2. **MTTD à réduire** : techniques détectées mais lentes (`MTTD > <seuil>`) → `<priorisation des
   règles / corrélation>`.
3. **Posture après remédiation** : projection de couverture si les `<N>` trous sont comblés →
   « passez de **`<D/M %>`** à **`<cible %>`** ».
4. **Prochaine campagne** : re-tirer les techniques ratées après correction → **prouver** le
   comblement (boucle purple en amélioration continue).

> **Le pitch de clôture** : *« Cet engagement vous a coûté un périmètre signé et vérifiable, et vous
> a rendu un chiffre que vous n'aviez pas : votre SOC voit `<D/M %>` des techniques, en `<MTTD>` min.
> Voici les `<N>` règles à ajouter. On re-tire au prochain run pour prouver que c'est comblé. »*

---

*Voir aussi : [`POSITIONING.md`](POSITIONING.md) · [`PRICING.md`](PRICING.md) (le livrable de §3+§7
porte le premium Purple) · [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) (prérequis Plume pour §3).*
