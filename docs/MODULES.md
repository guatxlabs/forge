# Catalogue de modules

> [Sommaire](README.md) · Voir aussi : [Concepts §4](CONCEPTS.md#4-catalogue-de-modules--techniques) ·
> [Référence CLI](CLI.md) (`forge modules`, `forge doctor`)

Un **module** est un outil d'attaque autonome orchestré par l'engine derrière la gate ROE. Il ne
tire jamais sans verdict `FIRE`, s'auto-neutralise si son outil sous-jacent est absent
(`available:false`), et ne produit aucun effet de bord en `dry-run`. Le contrat et le modèle de
gouvernance sont décrits dans [Architecture §2.3](ARCHITECTURE.md#23-le-registre-de-modules-forgemodules).

> Cette table est **générée** depuis `forge modules --json` (source de vérité : le registre). Pour la
> régénérer : `python3 -m forge.cli modules --json`. Pour connaître la disponibilité **sur votre
> machine** (outil présent ou non) : `python3 -m forge.cli doctor`.

## Colonnes

- **exploit** — le module exploite (⇒ exige `allow_exploit` dans le scope, sinon `VETO`).
- **destructif** — le module est destructif (⇒ exige `allow_destructive`).
- **ATT&CK** — technique MITRE (badge console + clé de jointure purple).
- **dépendance** — outil/service attendu (`stdlib` = toujours disponible, pur Python ; sinon
  auto-neutralisé si absent).

## Les 31 modules

| kind | exploit | destructif | ATT&CK | dépendance | description |
|---|:---:|:---:|---|---|---|
| `access_control.idor` | oui | — | T1190 | stdlib (params.accounts+urls) | Oracle différentiel IDOR/BOLA à PREUVE sur 2 comptes : A possède l'objet, B obtient-il le MÊME corps normalisé (anon refusé) ? Énumère aussi des IDs. CWE-639. |
| `auth.takeover` | oui | oui | T1212 | stdlib | Oracle ATO/auth-bypass à PREUVE : après le flux de bypass, le whoami renvoie-t-il l'identité de la VICTIME ? Sinon tested. CWE-287/640. |
| `burp.scan` | — | — | T1595.002 | REST API Burp | Pilote la REST API de Burp Suite : scan actif (authentifié via la session gouvernée, scope-locké), sonde l'état, rapatrie les issues → Finding(s). |
| `cors.credentials` | oui | — | T1539 | stdlib | Oracle CORS-credentials à PREUVE : ACAO reflète l'origine attaquante (pas `*`) ET ACAC=true sur un endpoint authentifié. Sinon tested. CWE-942. |
| `csrf.state_change` | — | — | T1204 | stdlib | Oracle CSRF à PREUVE CIBLÉE (non destructif) : `vulnerable` UNIQUEMENT pour une action CRITIQUE sans anti-CSRF ET SameSite confirmé absent. Détection seule. CWE-352. |
| `demo.fingerprint` | — | — | T1595 | aucune | Module de démonstration — illustre le pipeline (plan→ROE→dry/fire→finding→ledger) sans aucun I/O réseau. |
| `evasion.discover` | — | — | T1594 | browser-automation:8080 | Découverte d'endpoints derrière WAF via browser-automation : franchit le challenge managé puis extrait DOM/JS/XHR in-scope, émis avec le marqueur de découverte. |
| `evasion.idor_intercept` | oui | — | T1190 | browser-automation:8080 | Arme l'interception IDOR en vol via browser intercept-modify (substitution d'identifiant) — preuve via `/intercept-dump`. CWE-639. |
| `evasion.turnstile` | — | — | T1556 | browser-automation:8080 | Franchit le Cloudflare Turnstile interactif via vision-click-os (détection template + clic OS X11) — enabler d'accès. |
| `evasion.xhr` | — | — | T1190 | browser-automation:8080 | Observation des requêtes XHR via la session browser-automation (capture-start/dump) — contournement WAF/DataDome. |
| `graphql.access` | — | — | T1190 | stdlib | Oracle GraphQL à PREUVE DEUX-COMPTES-OPÉRATEUR : introspection (informatif) + BOLA objet/champ (A lit l'objet de B, tous deux détenus par l'opérateur ; anon refusé). Sinon tested. CWE-639. |
| `jwt.weakness` | — | — | T1606 | stdlib | Oracle JWT à PREUVE COMPTE-OPÉRATEUR : alg=none, confusion RS256→HS256, secret HMAC faible (liste bornée), injection kid. PREUVE = jeton forgé accepté POUR LE COMPTE OPÉRATEUR. Sinon tested. CWE-347. |
| `msf.module` | oui | — | T1210 | msfrpcd | Pilote msfrpcd (RPC msgpack) : lance le module MSF choisi par l'opérateur, PROUVE la réussite (session ouverte / CheckCode confirmée), promeut `vulnerable` QU'AVEC preuve — sinon reported_by_tool. Scope-guard + plancher exploit. |
| `origin.find` | — | — | T1590.005 | subfinder+httpx | Trouve l'IP d'origine derrière un CDN/WAF (subfinder + préfixes passifs → DNS → drop-CF → vérif Host-header) — bypass WAF si l'origine est joignable. |
| `path.traversal` | — | — | T1190 | stdlib | Oracle path-traversal à PREUVE BÉNIGNE : lit un CANARI non sensible via traversal (jamais de fichier système). PREUVE = le marqueur bénin revient. Sinon tested. CWE-22. |
| `recon.content` | — | — | T1595.003 | ffuf (local) | Découverte ACTIVE de contenu/routes web via ffuf — scope-locked, rate-limité, lecture seule. ffuf absent → skipped. |
| `recon.dns` | — | — | T1590.002 | stdlib socket (dnspython/dig opt.) | Résolution DNS (A/AAAA/CNAME/MX/TXT/NS) des hôtes in-scope. Backend dnspython > dig > socket ; impossible → skipped. |
| `recon.httpx` | — | — | T1595 | httpx (bin/docker) | Fingerprint HTTP (httpx) : status, titre, techno détectées. |
| `recon.js_endpoints` | — | — | T1594 | stdlib | Récupère les pages in-scope et extrait routes/URLs d'API référencées dans leur JavaScript. Endpoints jamais appelés. |
| `recon.nmap` | — | — | T1046 | nmap (bin/docker) | Découverte des services exposés (`nmap -sV`) sur le top 1000 ports. |
| `recon.secrets` | — | — | T1552.001 | trufflehog/gitleaks | Détecte les SECRETS EXPOSÉS dans les assets in-scope joignables (bundles JS, config) via trufflehog OU gitleaks. Secret redacté. Absent/KO → skipped. |
| `recon.subdomains` | — | — | T1590 | stdlib (crt.sh) | Énumération PASSIVE de sous-domaines (crt.sh CT + passive DNS optionnel), verrouillée aux racines in-scope. |
| `recon.tech` | — | — | T1592.002 | stdlib (httpx opt.) | Fingerprint techno depuis les réponses HTTP (Server/X-Powered-By/cookies/meta) ; enrichi par httpx si dispo. Passif, in-scope. |
| `recon.urls` | — | — | T1596 | stdlib (Wayback) | Découverte PASSIVE d'URLs historiques (Wayback CDX / CommonCrawl), filtrée aux racines déclarées. Aucune URL requêtée. |
| `recon.waf` | — | — | T1590 | stdlib (wafw00f opt.) | Identifie le WAF/CDN devant un hôte in-scope (heuristique passive + wafw00f si présent). Fingerprint INFORMATIF. |
| `redirect.open` | — | — | T1204.001 | stdlib | Oracle open-redirect à PREUVE IMPACTANTE : `vulnerable` UNIQUEMENT si cible attaquant-contrôlée ET chaînable à un sink sensible (OAuth/token/email). Redirections non suivies. Sinon tested. CWE-601. |
| `sqli.probe` | — | — | T1190 | stdlib | Oracle SQLi à PREUVE : différentiel BOOLÉEN fiable et/ou version SGBD error-based UNIQUEMENT (jamais de dump). sqlmap optionnel. Sinon tested. CWE-89. |
| `ssrf.callback` | oui | — | T1190 | stdlib + collecteur callback | Oracle SSRF à PREUVE : injecte une URL de callback unique et confirme la réception côté collecteur. Pas de callback → tested (jamais vuln aveugle). CWE-918. |
| `ssti.eval` | — | — | T1190 | stdlib | Oracle SSTI à PREUVE BÉNIGNE : injecte un produit arithmétique unique ; PREUVE = le produit ÉVALUÉ est réfléchi. Aucune exécution de code. Sinon tested. CWE-1336. |
| `web.nuclei` | — | — | T1595.002 | nuclei (bin/docker) | Scan de vulnérabilités par templates nuclei (medium/high/critical). |
| `xss.reflected` | — | — | T1059 | stdlib | Oracle Reflected XSS à PREUVE BÉNIGNE : marqueur unique réfléchi NON échappé en contexte JS-exécutable. L'exécution réelle + la chaînabilité exigent le module navigateur/évasion. Sinon tested. CWE-79. |

## Gouvernance des connecteurs

Un administrateur peut **désactiver** (« désinstaller ») un connecteur depuis la console — il est
alors SKIP au tir **même si son binaire/service est présent**, y compris quand c'est le planner (et
non `--modules`) qui l'a choisi. Voir [Administration → Gouvernance des connecteurs](ADMINISTRATION.md#3-gouvernance-des-connecteurs-installerdésinstaller)
et `POST /api/modules/:kind` dans la [Référence API](HTTP_API.md).

## Connecteurs opérateur (outils standards pilotés)

Forge n'ajoute aucune capacité offensive propre : deux connecteurs **pilotent** des outils que
l'opérateur exécute déjà, et **mappent** leurs résultats en Findings derrière la même gate ROE. Tous
deux sondent leur service **à fire-time** (jamais au catalogue) et s'auto-neutralisent si le service
est injoignable.

| Module | Outil piloté | Variables d'env (défauts) |
|---|---|---|
| `msf.module` | **msfrpcd** (RPC msgpack) — lance le module MSF choisi par l'opérateur ; aucun payload généré par Forge | `MSF_RPC_HOST` (127.0.0.1) · `MSF_RPC_PORT` (55553) · `MSF_RPC_USER` (msf) · `MSF_RPC_PASS` · `MSF_RPC_SSL` (true) · `MSF_RPC_TOKEN` |
| `burp.scan` | **REST API Burp Suite** Pro/Enterprise — lance un scan in-scope, rapatrie les issues | `BURP_API_URL` (http://127.0.0.1:1337) · `BURP_API_KEY` |

Gouvernance : `msf.module` déclare `exploit=True` (fail-safe → l'engine exige `allow_exploit`) ;
`burp.scan` reste `exploit=False` mais émet `reported_by_tool` (jamais `vulnerable` sans preuve
d'exploitabilité — comme nuclei). `forge doctor` indique lesquels sont joignables. Configuration :
[Configuration §1.9](CONFIGURATION.md#19-connecteurs-opérateur-optionnels).
