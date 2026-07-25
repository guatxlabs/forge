# Vue d'ensemble

> [Sommaire](README.md) · Suivant : [Architecture](ARCHITECTURE.md) · [Concepts](CONCEPTS.md) ·
> [Démarrage hors-ligne](GETTING_STARTED.md)

## Qu'est-ce que Forge ?

**Forge est une plateforme d'évaluation red-team gouvernée.** Elle orchestre des modules d'attaque
(recon → énumération → oracles à preuve → connecteurs d'exploitation), mais son cœur n'est pas
l'arsenal : c'est la **couche de gouvernance, de preuve et de mesure** posée par-dessus.

Trois invariants la définissent :

1. **Gouvernance fail-closed** — chaque action passe par une **gate ROE (Rules of Engagement) à
   quatre couches**. Par défaut, Forge est **INERTE** : rien ne peut tirer tant que l'opérateur n'a
   pas armé chaque couche consciemment. Hors périmètre autorisé ⇒ refus dur (`VETO`), jamais simulé.
2. **Preuve d'autorisation** — chaque décision (armement, approbation, tir, finding) est scellée
   dans un **ledger d'engagement append-time, tamper-evident**, signé **Ed25519**. Un tiers
   (auditeur, client, juridique) vérifie l'intégrité et l'appartenance au périmètre avec la **seule
   clé publique**, sans jamais pouvoir forger une entrée.
3. **Mesure purple** — chaque technique tirée porte un identifiant **MITRE ATT&CK**. En joignant les
   techniques *tirées* (red) aux techniques *détectées* par la défense (blue), Forge calcule la
   **couverture de détection réelle** et le **MTTD** — technique par technique.

Forge est écrit en **Python pur-stdlib** (le moteur) + **Rust/axum** (la console) + **vanilla-JS**
(le SPA). Le cœur livrable pèse ~5 MB ; les moteurs offensifs lourds (nmap, nuclei, Metasploit, Burp,
browser-automation) sont **orchestrés en option**, jamais embarqués, et **s'auto-neutralisent** s'ils
sont absents.

## Le problème que Forge résout

Après une campagne offensive, deux questions restent souvent sans réponse démontrable :

- **« Pouvez-vous prouver à un auditeur que le red-team est resté dans le périmètre autorisé ? »**
  → Forge répond avec un ledger signé, vérifiable sans confiance dans l'opérateur.
- **« Combien de ces techniques votre SOC a-t-il réellement détecté, et en combien de temps ? »**
  → Forge répond avec une matrice de couverture ATT&CK et un MTTD mesuré (pas estimé).

Forge n'essaie **pas** de battre Metasploit ou Cobalt Strike sur la capacité offensive brute. Il les
**pilote** et **mesure leur impact défensif**. Le différenciateur n'est aucune ligne prise isolément,
mais leur combinaison : *rouge + bleu, même éditeur, corrélés ATT&CK, autorisation signée*.

Le positionnement commercial complet est dans [`POSITIONING.md`](POSITIONING.md) ; la logique de
prix dans [`PRICING.md`](PRICING.md).

## La proposition de valeur en trois piliers

### Pilier A — Preuve d'autorisation signée
- **Gate ROE fail-closed à 4 couches** (`forge/roe.py`) : une action LIVE ne part QUE si elle a
  franchi *armé → in-scope (allowlist, jamais deny-list) → capacité autorisée → approuvée*. Toute
  ambiguïté ou erreur d'évaluation ⇒ `VETO`.
- **Ledger d'engagement** (`forge/ledger.py` + `signing.py`) : chaîne SHA-256 + signature Ed25519
  **par-entrée**, vérification externe par clé publique seule (`verify_external`).

### Pilier B — Boucle purple même-éditeur
- Forge (rouge) et Plume (bleu, le SOC) se corrèlent par champ **MITRE**. « Purple » n'est pas un 3ᵉ
  produit : c'est la boucle. Sortie : par technique → **detected / missed / MTTD**.
- La **source de détection est un plugin configurable** : Plume n'est qu'un préréglage
  (`kind=plume`). CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, un fichier ou une
  commande se câblent **sans code** — voir [`DETECTION.md`](DETECTION.md).

### Pilier C — Safe-by-default
- **Non-exploit forcé** : `allow_exploit` / `allow_destructive` sont des opt-in explicites par
  engagement. Un module `exploit=True` (ex. `msf.module`) est vétoé tant que la capacité n'est pas
  armée.
- **Scope-guard dur** : `in_scope` vide ⇒ rien ne tire (fail-closed).
- **Pas de sur-classement** : un connecteur tiers (nuclei, Burp) émet `reported_by_tool`, jamais
  `vulnerable`, tant qu'il n'y a pas de preuve d'exploitabilité.

## Forge fonctionne en STANDALONE

**Plume (le SOC) et la boucle purple sont OPTIONNELS.** Forge est un produit complet sans eux :

| Sans aucune source de détection | Forge fait quand même… |
|---|---|
| Scope-guard ROE + armement par couche | ✅ tout le cycle de gouvernance |
| Ledger d'engagement signé + vérif externe | ✅ preuve d'autorisation |
| Recon, oracles à preuve, connecteurs MSF/Burp | ✅ tout le red-team gouverné |
| Console (findings / coverage ATT&CK / runs), soql, dashboards, rapports | ✅ tout le store + livrables |
| Boucle purple (detected/missed/MTTD) | ⏸️ inerte — **fail-open lisible** : `source_reachable:false`, aucune métrique inventée |

Quand aucune source de détection n'est configurée, l'endpoint de couverture purple répond
honnêtement « mesure impossible » plutôt que d'inventer un chiffre. Brancher une source **plus tard**
active la boucle sans rien changer d'autre. Voir la page dédiée
**[Utiliser Forge en standalone](STANDALONE.md)**.

## Ce que Forge N'EST PAS

- **PAS un C2 / un beacon** : aucun implant, aucun callback persistant, aucune post-exploitation.
  Forge orchestre des outils à *fire-time* puis trace ; il ne maintient pas d'accès. Le run-flow
  « C2-light » de la console est un **lanceur de campagne gouverné et audité**, pas un canal de
  commande persistant.
- **PAS un scanner de vulnérabilités** : nuclei/Burp font le scan ; Forge les **gouverne et corrèle**.
- **PAS un remplaçant de Metasploit** : il le **pilote** (`msf.module` → msfrpcd).
- **PAS de l'OSINT / du forensics** : `origin.find` retrouve une IP d'origine derrière un CDN (recon
  technique scopée) ; le ledger prouve une **autorisation d'engagement**, pas une preuve forensique
  de terminal.

Détail anti-confusion : [`POSITIONING.md`](POSITIONING.md) §4.

## Maturité & contraintes (honnêteté)

- **Version 0.0.1** — les premiers clients sont des design partners.
- **Stateful single-replica** : SQLite + ledger sur un volume `ReadWriteOnce` → profil idéal
  **mono-opérateur / petit MSSP**. Le multi-tenant scale-out est une évolution (ledger hors-host +
  store partagé), pas un acquis. Voir [`DEPLOYMENT.md`](DEPLOYMENT.md) § Contrainte d'archi.
- **Custody** : la clé privée de signature est aujourd'hui **locale** ; l'ancrage hors-host (témoin
  co-signataire distant, `forge/anchor.py`) est la dernière étape, et l'architecture asymétrique le
  permet déjà (seule la clé publique circule). Documenté, pas caché.

## Prochaines étapes

- Voir Forge tourner en 10 minutes, 100 % hors-ligne → **[Démarrage](GETTING_STARTED.md)**.
- Comprendre comment c'est construit → **[Architecture](ARCHITECTURE.md)** et **[Concepts](CONCEPTS.md)**.
- Déployer une console → **[Installation](INSTALLATION.md)** puis **[Premier déploiement](FIRST_DEPLOYMENT.md)**.
