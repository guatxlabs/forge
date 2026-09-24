# Forge — Compte rendu d'engagement de référence (labo ACME Retail)

> **Ceci est un exemple REMPLI, CAVIARDÉ, FAÇON LABO** de
> [`docs/REFERENCE_ENGAGEMENT_TEMPLATE.md`](../../docs/REFERENCE_ENGAGEMENT_TEMPLATE.md).
> C'est l'artefact commercial/onboarding : « voici à quoi ressemble un livrable Forge ». Toutes les données sont
> **100 % synthétiques** (hôtes `.example` RFC 2606, IP de documentation RFC 5737). Aucun système réel n'a été
> touché. C'est le pendant lisible par un humain des fixtures machine de ce dossier, que
> `make demo` / `make demo-purple` chargent dans la console.
>
> La phrase qui vend le tout : *« Votre SOC a vu 4 des 7 techniques que nous avons tirées. Une de plus, il ne la voit
> qu'à travers une règle parente générique. Les voici, et voici comment les fermer. »*

---

## 0. En-tête

| Champ | Valeur |
|---|---|
| Client / programme | ACME Retail — **labo interne** (synthétique) |
| Type d'engagement | labo sur infra maison (autorisé, auto-autorisation écrite) |
| Période | 2026-06-26 12:00 → 12:30 UTC |
| Opérateur(s) Forge | `lab-operator` (démo) |
| Réf. d'autorisation | `LAB-SELF-AUTH-2026-06` (infrastructure maison) |
| Hash racine du ledger | `<calculé à l'exécution — vérifiable via forge ledger verify>` |
| Clé publique de vérification | `<clé publique Ed25519 pour verify_external — caviardée dans cet échantillon>` |

---

## 1. Contexte & scope autorisé

- **Objectif métier** : mesurer quelle part d'une chaîne web red-team réaliste le SOC du labo détecte
  réellement, et à quelle vitesse — avant de la lancer pour de vrai contre la production.
- **`in_scope`** (verbatim depuis `scope.json`) : `shop.lab.example`, `api.lab.example`, `lab.example`.
- **`out_scope`** (exclusions explicites) : `corp.internal.example`, `*.prod.example`.
- **Capacités armées** : `allow_exploit = false` · `allow_destructive = false` · `mode = grey` ·
  `rate = 5`.
- **Fenêtre & contraintes** : fenêtre de 30 minutes, hôtes monitorés par le SOC Plume du labo, synchronisés NTP pour
  le MTTD. Findings obtenus par **vérification en lecture seule uniquement** (aucune exploitation, aucune destruction de données).

---

## 2. Techniques tirées (timeline)

Une ligne par action ayant atteint un verdict `FIRE`. Source = run-records + décisions ROE (voir
`runrecords.jsonl` / `roe_decisions.jsonl`). `VETO` / `DRY_RUN` sont en §6 (anti-masquage).

| # | Timestamp (UTC) | Module (kind) | ATT&CK | Cible | Verdict ROE |
|---|---|---|---|---|---|
| 1 | 12:00:00 | `recon.httpx` | T1595 | shop.lab.example | FIRE |
| 2 | 12:01:00 | `origin.find` | T1590.005 | lab.example | FIRE |
| 3 | 12:03:00 | `recon.nmap` | T1046 | shop.lab.example | FIRE |
| 4 | 12:07:00 | `web.nuclei` | T1595.002 | shop.lab.example | FIRE |
| 5 | 12:12:00 | `access_control.idor` | T1190 | api.lab.example | FIRE |
| 6 | 12:15:00 | `ssrf.callback` | T1190 | api.lab.example | FIRE |
| 7 | 12:18:00 | `cors.credentials` | T1539 | shop.lab.example | FIRE |
| 8 | 12:20:00 | `auth.takeover` | T1212 | shop.lab.example | FIRE |

---

## 3. Matrice de coverage PURPLE (le livrable central)

JOIN en lecture seule entre les run-records Forge (`{mitre}`, `fired=1`) et les détections Plume
(`GET {PLUME_URL}/api/coverage/detections`), sur les **techniques** (tags multi-techniques éclatés des deux
côtés). MTTD = `first_ts (alerte Plume) − ts_fired (Forge)`, calculé contre le tir **le plus récent**
de chaque technique, et échantillonné sur les détections **exactes** uniquement.

| Technique ATT&CK | Tirée | Détectée (SOC) | MTTD | Statut |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ exact | 4 min | 🟢 detected-exact |
| T1046 — Network Service Discovery | ✅ | ✅ exact | 2.5 min | 🟢 detected-exact |
| T1190 — Exploit Public-Facing App | ✅ | ✅ exact | 3 min | 🟢 detected-exact |
| T1212 — Exploitation for Credential Access | ✅ | ✅ exact | 6 min | 🟢 detected-exact |
| T1595.002 — Vulnerability Scanning | ✅ | ⚠️ parent `T1595` seul (3 alertes) | — | 🟠 **detected-parent-approx** |
| T1590.005 — Gather Victim Network Info: IP Addresses | ✅ | ❌ | — | 🔴 **missed** |
| T1539 — Steal Web Session Cookie | ✅ | ❌ | — | 🔴 **missed** |

**Résumé de coverage** (correspond à la sortie live de `/api/purple/coverage` pour ce seed) :
- Techniques tirées : **7**
- Détectées **exactement** : **4** → **coverage = 57 %**
- **Parent-approx** : **1** (T1595.002) → *non* compté dans le taux, aucun MTTD inventé — un **angle
  mort nommé**, voir §7
- Manquées : **2** → *(voir §7 « comment fermer »)*
- **MTTD** : moy. **232,5 s (3,9 min)**, max **360 s (6 min)** sur les techniques détectées **exactement**.

> Cette table est la sortie native de la boucle purple (`/api/purple/coverage`). C'est l'argument qu'aucun
> outil offensif seul ne produit : le taux de détection SOC **réel, mesuré** — pas une estimation.
>
> **Pourquoi T1595.002 est en orange et pas en vert.** Le SOC alerte bien sur `T1595`, et Forge a tiré la
> sous-technique `T1595.002`. Appeler cela « détecté » serait une affirmation que nous ne pouvons pas étayer : une règle parente
> ne dit rien du **vecteur** qu'elle couvre, et le MTTD daterait le tir de vuln-scan contre une
> alerte sans rapport. Elle reste donc hors du taux et hors du MTTD. Elle n'est pas non plus silencieusement écartée
> — un simple `missed` aurait masqué le fait utile qu'une règle voisine existe déjà et n'a besoin que d'être
> resserrée. Trois états, parce que deux devraient mentir dans un sens ou dans l'autre.

---

## 4. Findings avec preuve

Source = le store red (`findings.jsonl`). Pas de sur-classification : un SSRF n'ayant produit qu'un
callback out-of-band reste `reported_by_tool` tant que l'exploitabilité n'est pas prouvée.

### Finding 1 — IDOR : factures de commande lisibles entre tenants
- **Sévérité** : HIGH · **ATT&CK** : T1190 · **CWE-639** · **Module** : `access_control.idor`
- **Cible** : `api.lab.example` — `/api/orders/{id}/invoice`
- **Statut** : `vulnerable` (lecture cross-tenant prouvée)
- **Preuve** : le tenant de test B (uid=1042) a récupéré le PDF de facture du tenant A (commande 5581), HTTP 200 — aucun
  contrôle de propriété sur l'id de l'objet.
- **Détecté par le SOC ?** : oui, en tant que T1190 (MTTD 3 min — voir §3).
- **Correctif** : contrôle de propriété côté serveur sur chaque référence d'objet (deny-by-default).

### Finding 2 — SSRF : le proxy d'image récupère l'URL de l'attaquant
- **Sévérité** : HIGH · **ATT&CK** : T1190 · **CWE-918** · **Module** : `ssrf.callback`
- **Cible** : `api.lab.example` — `/api/proxy?url=`
- **Statut** : `reported_by_tool` (callback OOB seulement ; les métadonnées cloud ont renvoyé 403 — non escaladé)
- **Preuve** : callback out-of-band depuis l'egress en moins de 1,2 s ; `169.254.169.254` bloqué (403).
- **Détecté par le SOC ?** : oui, replié dans la détection T1190.
- **Correctif** : allowlist stricte d'hôtes/schémas ; bloquer les IP internes et les endpoints de métadonnées.

### Finding 3 — CORS permissif avec identifiants
- **Sévérité** : MEDIUM · **ATT&CK** : T1539 · **CWE-942** · **Module** : `cors.credentials`
- **Cible** : `shop.lab.example` — `/api/account`
- **Statut** : `vulnerable`
- **Preuve** : `Access-Control-Allow-Origin` reflète une Origin arbitraire **et**
  `Access-Control-Allow-Credentials: true` — lecture cross-origin avec identifiants du profil de session.
- **Détecté par le SOC ?** : **non** — 🔴 missed (voir §7).
- **Correctif** : ne jamais refléter une Origin arbitraire avec identifiants ; allowlist exacte uniquement.

### Finding 4 — Token de réinitialisation de mot de passe prévisible
- **Sévérité** : CRITICAL · **ATT&CK** : T1212 · **CWE-287** · **Module** : `auth.takeover`
- **Cible** : `shop.lab.example`
- **Statut** : `reported_by_tool` (token d'une victime de test deviné ; aucun compte réel affecté)
- **Preuve** : les tokens de reset sont des compteurs zero-paddés ; devinés en ~300 essais, sans rate limit, sans
  expiration → prise de contrôle complète du compte.
- **Détecté par le SOC ?** : oui, en tant que T1212 (MTTD 6 min — la détection la plus lente).
- **Correctif** : tokens à usage unique CSPRNG avec expiration courte + rate limiting sur l'endpoint de reset.

### Finding 5 — IP d'origine exposée derrière le CDN
- **Sévérité** : LOW · **ATT&CK** : T1590.005 · **CWE-200** · **Module** : `origin.find`
- **Cible** : `lab.example`
- **Statut** : `tested` (divulgation d'information seulement)
- **Preuve** : un enregistrement A historique + un SAN de certificat partagé révèlent l'origine `203.0.113.24`, contournant le
  WAF du CDN.
- **Détecté par le SOC ?** : **non** — 🔴 missed (passif, donc attendu — voir §7).
- **Correctif** : faire tourner l'IP d'origine, restreindre l'origine aux plages d'egress du CDN, nettoyer l'historique DNS/certificats.

### Finding 6 — En-têtes de sécurité manquants + jQuery obsolète
- **Sévérité** : LOW · **ATT&CK** : T1595.002 · **CWE-693** · **Module** : `web.nuclei`
- **Cible** : `shop.lab.example`
- **Statut** : `tested`
- **Preuve** : pas de CSP/HSTS ; jQuery 1.12.4 servi (sinks DOM-XSS connus).
- **Détecté par le SOC ?** : **pas sur cette sous-technique** — 🟠 parent-approx : le SOC alerte sur le parent
  `T1595` (Active Scanning, 3 alertes) mais n'a aucune règle pour `T1595.002` (Vulnerability Scanning). Non
  compté comme détecté (voir §3, §7).
- **Correctif** : ajouter CSP + HSTS, mettre à jour les bibliothèques front-end.

---

## 5. Chaîne de custody — le ledger signé

La crédibilité de ce compte rendu repose là-dessus : **chaque action est dans un ledger signé et chaîné,
vérifiable par un tiers qui ne fait pas confiance à l'opérateur**.

- **Intégrité interne** : `forge ledger verify --ledger acme-lab.jsonl` → `<OK / hash racine>`.
- **Vérification par un tiers** : `verify_external(<pubkey>)` — l'auditeur valide la chaîne Ed25519
  avec la **clé publique seule** (ne peut ni forger ni altérer). Résultat : `<OK>`.
- **Couverture du ledger** : `<n>` entrées chaînées = **toutes** les décisions ROE (8 FIRE, 1 DRY_RUN, 2 VETO),
  MAC par entrée (pas seulement aux checkpoints).
- **Note de custody (honnête)** : clé privée locale pour ce labo ; ancrage off-host (témoin de co-signature
  distant, `anchor.py`) = *non activé* dans cet échantillon.

> **L'argument** : « Vous n'avez pas à nous faire confiance. Voici la clé publique. Vérifiez vous-même que rien
> n'a été tiré hors du scope que vous avez autorisé, et que le log n'a pas été réécrit. »

---

## 6. Anti-masquage — ce qui n'a PAS été tiré

Un reporting honnête liste aussi les manques — zéro trou silencieux. Source = `roe_decisions.jsonl` + les
`coverage_gaps` / `skipped_budget` du run_job.

- **`DRY_RUN`** (simulé, jamais exécuté) : `web.sqli` sur `shop.lab.example` — non approuvé par
  l'opérateur.
- **`VETO`** (refusé par la gate) : `access_control.idor` sur `corp.internal.example` (out of scope,
  scope-guard fail-closed) ; `msf.module` sur `api.lab.example` (`allow_exploit=false` — l'exploit
  exige un opt-in écrit à fort impact).
- **Classes jamais tentées** : injection SQL (`injection.sqli`) sur `shop.lab.example` — reportée.
- **Non testé (budget temps)** : XSS stocké (`web.xss`) sur `shop.lab.example` — reporté, pas supprimé.

---

## 7. Valeur délivrée — « voici comment fermer »

La conclusion qui transforme la matrice en décision.

1. **Gaps de détection** : « Votre SOC a manqué **2** techniques purement et simplement (**T1590.005, T1539**) et en couvre une
   troisième (**T1595.002**) uniquement par sa règle parente générique. »
   - **T1539 (CORS permissif / vol de cookie)** — priorité la plus haute : mappe sur un finding MEDIUM avec
     un vrai impact cross-origin et aucune détection. Ajouter une règle sur les réponses à `Origin` reflétée
     anormale / CORS avec identifiants sur `/api/*`.
   - **T1595.002 (vuln scanning)** — 🟠 *parent-approx*, le gain le moins cher du tableau : votre règle `T1595`
     tire déjà sur ce trafic, elle n'est simplement pas spécifique au template scanning. Resserrez-la/dupliquez-la
     en une règle `T1595.002` (signatures de template-scan, rafales de 4xx) et la ligne passe au vert — aucune
     nouvelle télémétrie requise.
   - **T1590.005 (collecte d'IP passive)** — angle mort attendu (aucun trafic à détecter) ; mitiger au
     niveau de l'asset (faire tourner l'origine, nettoyer l'historique DNS/certificats) plutôt que via une règle SOC.
2. **MTTD à réduire** : T1212 (brute force de token de reset) détecté mais le plus lent à **6 min** — ajouter une
   règle dédiée de rate/vélocité sur l'endpoint de reset pour le ramener sous la cible.
3. **Posture après remédiation** : fermer T1539 + resserrer la règle parente en une vraie règle `T1595.002`
   fait passer le coverage mesuré de **57 %** (4/7) à **≈ 86 %** (6/7) — et la ligne parent-approx
   disparaît, car elle devient une détection prouvée au lieu d'une détection supposée.
4. **Prochaine campagne** : re-tirer les techniques manquées après le déploiement des règles → **prouver** que le gap est
   fermé (boucle purple d'amélioration continue).

> **Pitch de clôture** : *« Cet engagement vous a coûté un scope signé et vérifiable, et vous a remis un chiffre
> que vous n'aviez pas : votre SOC voit *de façon prouvée* 57 % des techniques que nous avons tirées, en ~4 minutes — plus une
> de plus qu'il ne couvre que par une règle parente générique, que nous ne comptons pas pour vous. Voici les 3 règles
> à ajouter. On re-tire au run suivant pour prouver que c'est fermé. »*

---

*Voir aussi : [`docs/POSITIONING.md`](../../docs/POSITIONING.md) · [`docs/PRICING.md`](../../docs/PRICING.md) ·
[`docs/PURPLE_PREREQS.md`](../../docs/PURPLE_PREREQS.md) · [`docs/MTTD.md`](../../docs/MTTD.md).*
