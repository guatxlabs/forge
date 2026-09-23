# Catalogue de modules

> [Sommaire](README.md) · Voir aussi : [Concepts §4](CONCEPTS.md#4-catalogue-de-modules--techniques) ·
> [Référence CLI](CLI.md) (`forge modules`, `forge doctor`)

Un **module** est un outil d'attaque autonome orchestré par l'engine derrière la gate ROE. Il ne
tire jamais sans verdict `FIRE`, s'auto-neutralise si son outil sous-jacent est absent
(`available:false`), et ne produit aucun effet de bord en `dry-run`. Le contrat et le modèle de
gouvernance sont décrits dans [Architecture §2.3](ARCHITECTURE.md#23-le-registre-de-modules-forgemodules).

> La source de vérité est le **registre**, pas cette page : `python3 -m forge.cli modules --json`. Pour
> connaître la disponibilité **sur votre machine** (outil présent ou non) : `python3 -m forge.cli doctor`.
>
> ⚠️ **Cette table est un EXTRAIT, pas le catalogue complet.** Mesuré sur cet arbre
> (`python3 -m forge.cli modules --json | python3 -c "import json,sys;print(len(json.load(sys.stdin)))"`) :
> le registre compte **88 modules**, dont **43 sont décrits ci-dessous** — les 45 autres existent et sont
> tirables, mais n'ont pas encore leur ligne ici. Aucun module listé ci-dessous n'est absent du registre
> (vérifié : 0 entrée fantôme). En cas de doute, croyez la commande, pas la page.

> **Outils embarqués dans l'image `full` (défaut).** Depuis l'ajout de la suite de scanners au
> `Dockerfile`, le profil `full` livre — en plus de `nmap`/`curl`/`dig`/`httpx`/`nuclei`/`subfinder` —
> les binaires `dnsx`, `naabu`, `katana`, `amass`, `gau`, `feroxbuster`, `ffuf`,
> `gobuster`, `whatweb`, `wafw00f`, `wfuzz`, `nikto`, `testssl.sh`, `dalfox`, `sqlmap`. Les modules du
> **catalogue OSS** (`recon.dnsx`, `recon.amass`, `web.nikto`, `web.testssl`, `xss.dalfox`, `sqli.sqlmap`…)
> ainsi que les modules natifs à **outil optionnel** (`recon.content` → ffuf, `recon.waf` → wafw00f,
> `sqli.probe` → sqlmap) sont donc `available:true` **d'office** en `full`. En `mini` ils dégradent en
> `available:false`. Non embarqués (par design) : `wpscan`/`zap-baseline` (repli `docker_image`), **Burp** &
> **Metasploit** (services externes ENV) — cf.
> [TOOLS.md §4(a)](TOOLS.md#a-il-est-déjà-dans-limage-full).

## Colonnes

- **exploit** — le module exploite (⇒ exige `allow_exploit` dans le scope, sinon `VETO`).
- **destructif** — le module est destructif (⇒ exige `allow_destructive`).
- **ATT&CK** — technique MITRE (badge console + clé de jointure purple).
- **dépendance** — outil/service attendu (`stdlib` = toujours disponible, pur Python ; sinon
  auto-neutralisé si absent).

## 43 des 88 modules du registre

| kind | exploit | destructif | ATT&CK | dépendance | description |
|---|:---:|:---:|---|---|---|
| `access_control.idor` | oui | — | T1190 | stdlib (params.accounts+urls) | Oracle différentiel IDOR/BOLA à PREUVE sur 2 comptes : A possède l'objet, B obtient-il le MÊME corps normalisé (anon refusé) ? Énumère aussi des IDs. CWE-639. |
| `auth.takeover` | oui | oui | T1212 | stdlib | Oracle ATO/auth-bypass à PREUVE : après le flux de bypass, le whoami renvoie-t-il l'identité de la VICTIME ? Sinon tested. CWE-287/640. |
| `burp.scan` | — | — | T1595.002 | REST API Burp | Pilote la REST API de Burp Suite : scan actif (authentifié via la session gouvernée, scope-locké), sonde l'état, rapatrie les issues → Finding(s). |
| `business_logic.invariants` | — | — | T1190 | stdlib | DERIVE les invariants arithmetiques d'un objet metier (negatifs, bornes entre champs, sommes, valeurs hors grille) puis tente de les violer avec des valeurs que le serveur DOIT rejeter. Complete `business_logic.scan`, dont les trois verifications de commerce en ligne, redigees en texte libre, ne pouvaient rien tester d'elles-memes et ne decrivaient qu'un seul metier. |
| `cors.credentials` | oui | — | T1539 | stdlib | Oracle CORS-credentials à PREUVE : ACAO reflète l'origine attaquante (pas `*`) ET ACAC=true sur un endpoint authentifié. Sinon tested. CWE-942. |
| `cspt.redirect` | oui | — | T1190 | stdlib | PROUVE un Client-Side Path Traversal par DIFFERENTIEL DE PROFONDEUR : le meme canari est envoye avec et sans `../`, et l'on compare les chemins REELLEMENT emis par le navigateur. Preuve = le chemin de la sonde traversal porte strictement moins de segments — la normalisation a bien eu lieu et la requete authentifiee est partie ailleurs. |
| `csrf.state_change` | — | — | T1204 | stdlib | Oracle CSRF à PREUVE CIBLÉE (non destructif) : `vulnerable` UNIQUEMENT pour une action CRITIQUE sans anti-CSRF ET SameSite confirmé absent. Détection seule. CWE-352. |
| `demo.fingerprint` | — | — | T1595 | aucune | Module de démonstration — illustre le pipeline (plan→ROE→dry/fire→finding→ledger) sans aucun I/O réseau. |
| `evasion.discover` | — | — | T1594 | browser-automation:8080 | Découverte d'endpoints derrière WAF via browser-automation : franchit le challenge managé puis extrait DOM/JS/XHR in-scope, émis avec le marqueur de découverte. |
| `evasion.idor_intercept` | oui | — | T1190 | browser-automation:8080 | Arme l'interception IDOR en vol via browser intercept-modify (substitution d'identifiant) — preuve via `/intercept-dump`. CWE-639. |
| `evasion.turnstile` | — | — | T1556 | browser-automation:8080 | Franchit le Cloudflare Turnstile interactif via vision-click-os (détection template + clic OS X11) — enabler d'accès. |
| `evasion.xhr` | — | — | T1190 | browser-automation:8080 | Observation des requêtes XHR via la session browser-automation (capture-start/dump) — contournement WAF/DataDome. |
| `graphql.access` | — | — | T1190 | stdlib | Oracle GraphQL à PREUVE DEUX-COMPTES-OPÉRATEUR : introspection (informatif) + BOLA objet/champ (A lit l'objet de B, tous deux détenus par l'opérateur ; anon refusé). Sinon tested. CWE-639. |
| `jwt.weakness` | — | — | T1606 | stdlib | Oracle JWT à PREUVE COMPTE-OPÉRATEUR : alg=none, confusion RS256→HS256, secret HMAC faible (liste bornée), injection kid. PREUVE = jeton forgé accepté POUR LE COMPTE OPÉRATEUR. Sinon tested. CWE-347. |
| `llm.prompt_injection` | — | — | T1059 | stdlib | Eprouve la frontiere de confiance entre les instructions systeme d'une application a modele de langage et l'entree utilisateur. Quatre familles : sortie non assainie (un XSS dont la charge transite par le modele), injection directe, confusion de delimiteur, fuite d'instructions. Les canaris sont INERTES — ce n'est pas un outil de jailbreak et il ne demande jamais de contenu nuisible. |
| `massassign.params` | — | — | T1078 | stdlib | PROUVE qu'une API desserialise en bloc en acceptant un champ privilegie que le formulaire n'expose pas. Trois points : etat de reference lu AVANT, injection d'un CANARI inerte, persistance verifiee a la relecture. La valeur injectee n'a aucun pouvoir — prouver que `role` est assignable n'exige pas d'ecrire `admin`. |
| `msf.module` | oui | — | T1210 | msfrpcd | Pilote msfrpcd (RPC msgpack) : lance le module MSF choisi par l'opérateur, PROUVE la réussite (session ouverte / CheckCode confirmée), promeut `vulnerable` QU'AVEC preuve — sinon reported_by_tool. Scope-guard + plancher exploit. |
| `origin.find` | — | — | T1590.005 | subfinder+httpx | Trouve l'IP d'origine derrière un CDN/WAF (subfinder + préfixes passifs → DNS → drop-CF → vérif Host-header) — bypass WAF si l'origine est joignable. Tir **borné à 600 s** (`origin.MAX_RUNTIME`, annoncée au moteur via `max_runtime`, rabotée au budget restant) : ce que la borne coupe sort en `skipped` compté, jamais en « rien trouvé ». |
| `ormleak.filter` | — | — | T1190 | stdlib | PROUVE qu'une API de recherche laisse filtrer sur un champ qu'elle n'expose pas, ce qui en fait un oracle booleen sur son contenu. Trois points : le discriminant existe sur un champ connu, un champ sensible est ACCEPTE comme critere, et il discrimine lui aussi. S'arrete la — prouver qu'on peut lire n'exige pas de lire. |
| `parserdiff.unicode` | — | — | T1027 | stdlib | PROUVE un ecart de normalisation Unicode entre le filtre en amont (WAF) et l'application. Differentiel a trois points : le marqueur nu passe, sa variante ASCII sensible est refusee, sa variante CONFUSABLE passe ET revient normalisee en ASCII. C'est la conjonction des trois qui prouve — l'ecart ENTRE les deux lectures est la vulnerabilite, pas l'un des deux resultats pris seul. |
| `path.traversal` | — | — | T1190 | stdlib | Oracle path-traversal à PREUVE BÉNIGNE : lit un CANARI non sensible via traversal (jamais de fichier système). PREUVE = le marqueur bénin revient. Sinon tested. CWE-22. |
| `recon.client_sinks` | — | — | T1595 | stdlib | Lit le JavaScript de MEME ORIGINE et en extrait les couples source -> puits (XSS DOM) et les chemins d'API a segment construit (Client-Side Path Traversal). Aucun oracle ne LISAIT le code client : les deux classes qui paient le mieux sont precisement celles qui se trouvent en lisant, pas en arrosant des parametres devines. |
| `recon.content` | — | — | T1595.003 | ffuf (local) | Découverte ACTIVE de contenu/routes web via ffuf — scope-locked, rate-limité, lecture seule. **Producteur de surface** : les routes in-scope portent `DISCOVERY_ENDPOINT_MARKER` et sont chaînées vers les oracles (sélection partagée : interrogeables d'abord, non-cibles d'infra écartées, cap `crawl_max_endpoints`). ffuf absent → skipped. |
| `recon.dns` | — | — | T1590.002 | stdlib socket (dnspython/dig opt.) | Résolution DNS (A/AAAA/CNAME/MX/TXT/NS) des hôtes in-scope. Backend dnspython > dig > socket ; impossible → skipped. |
| `recon.httpx` | — | — | T1595 | httpx (bin/docker) | Fingerprint HTTP (httpx) : status, titre, techno détectées. |
| `recon.js_endpoints` | — | — | T1594 | stdlib | Récupère les pages in-scope et extrait routes/URLs d'API référencées dans leur JavaScript. Endpoints jamais appelés. |
| `recon.nmap` | — | — | T1046 | nmap (bin/docker) | Découverte des services exposés (`nmap -sV`) sur le top 1000 ports par défaut. Param opt-in `full_ports` → `-p-` (scan complet 1-65535, prime sur `ports`/`top_ports`). |
| `recon.secrets` | — | — | T1552.001 | trufflehog/gitleaks | Détecte les SECRETS EXPOSÉS dans les assets in-scope joignables (bundles JS, config) via trufflehog OU gitleaks. Secret redacté. Absent/KO → skipped. |
| `recon.subdomains` | — | — | T1590 | stdlib (crt.sh) | Énumération PASSIVE de sous-domaines (crt.sh CT + passive DNS optionnel), verrouillée aux racines in-scope. |
| `recon.tech` | — | — | T1592.002 | stdlib (httpx opt.) | Fingerprint techno depuis les réponses HTTP (Server/X-Powered-By/cookies/meta) ; enrichi par httpx si dispo. Passif, in-scope. |
| `recon.urls` | — | — | T1596 | stdlib (Wayback) | Découverte PASSIVE d'URLs historiques (Wayback CDX / CommonCrawl), filtrée aux racines déclarées. Aucune URL requêtée. |
| `recon.waf` | — | — | T1590 | stdlib (wafw00f opt.) | Identifie le WAF/CDN devant un hôte in-scope (heuristique passive + wafw00f si présent). Fingerprint INFORMATIF. |
| `redirect.open` | — | — | T1204.001 | stdlib | Oracle open-redirect à PREUVE IMPACTANTE : `vulnerable` UNIQUEMENT si cible attaquant-contrôlée ET chaînable à un sink sensible (OAuth/token/email). Redirections non suivies. Sinon tested. CWE-601. |
| `sidechannel.shape` | — | — | T1592 | stdlib | Oracle de CANAL AUXILIAIRE par forme de réponse (XS-Leak / length-leak) : PREUVE = la forme (statut/ETag/longueur) du PRÉSENT est stable ET diffère de l'ABSENT, révélant un oracle d'existence sur l'état d'un tiers. Read-only, bénin. Sinon tested. CWE-203. |
| `sqli.probe` | — | — | T1190 | stdlib | Oracle SQLi à PREUVE : différentiel BOOLÉEN fiable et/ou version SGBD error-based UNIQUEMENT (jamais de dump). sqlmap optionnel. Sinon tested. CWE-89. |
| `ssrf.callback` | oui | — | T1190 | stdlib + collecteur callback | Oracle SSRF à PREUVE : injecte une URL de callback unique et confirme la réception côté collecteur. Pas de callback → tested (jamais vuln aveugle). CWE-918. |
| `ssrf.redirect_loop` | — | — | T1190 | stdlib | Rend VISIBLE un SSRF aveugle par une boucle de redirection a codes incrementaux (302, 303, … 311), qui pousse le client HTTP de la cible hors des codes qu'il sait traiter : il entre en erreur et divulgue la chaine, reponse interne comprise. Preuve a trois points — atteinte, aveuglement de la sonde directe, visibilite par la boucle — et evidence MASQUEE. |
| `ssti.errors` | — | — | T1190 | stdlib | Oracle SSTI AVEUGLE par le canal d'erreur (« Successful Errors ») : preuve par conjonction — une erreur ARITHMÉTIQUE apparaît sur N*M/0 (test) mais pas sur le marqueur inerte (contrôle) ni le témoin. HIGH si le produit fuite dans l'erreur, sinon MEDIUM. Aucune exécution de code. Sinon tested. CWE-1336. |
| `ssti.eval` | — | — | T1190 | stdlib | Oracle SSTI à PREUVE BÉNIGNE : injecte un produit arithmétique unique ; PREUVE = le produit ÉVALUÉ est réfléchi. Aucune exécution de code. Sinon tested. CWE-1336. |
| `upload.unrestricted` | — | — | T1190 | stdlib | Oracle FILE UPLOAD à PREUVE BÉNIGNE : téléverse un fichier INERTE (marqueur texte, aucun code) sous des noms qui contournent les filtres d'extension/MIME ; PREUVE = le marqueur est RESSERVI, avec extension dangereuse préservée ou Content-Type rendant. Aucun webshell n'est jamais construit. Sinon tested. CWE-434. |
| `web.nuclei` | — | — | T1595.002 | nuclei (bin/docker) | Scan de vulnérabilités par templates nuclei (medium/high/critical). |
| `web.security_headers` | — | — | T1595.002 | stdlib | Audit des en-têtes HTTP de sécurité (CSP/X-Frame-Options/nosniff/Referrer-Policy/HSTS sur https/Permissions-Policy) + cookies non sécurisés (Secure/HttpOnly/SameSite). Un finding INFO/LOW par écart, status=tested (jamais vulnerable). CWE-693. |
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
