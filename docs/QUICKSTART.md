# Forge — Quickstart : déployer + tester en local sur un programme bug bounty

> Cible : lancer Forge en **Docker** et tester un **nouveau programme bug bounty**, **entièrement via l'UI web**.
> Aucun fichier à créer, aucune commande avant d'accéder à l'interface.
> Rappel de sûreté : Forge est **fail-closed** — périmètre vide = tout refusé. Le scope EST ton autorisation (ROE).

## 0. Prérequis
- Docker + Docker Compose. Un clone standalone de ce dépôt (la console récupère `guatx-core` via une git-dep publique au build — aucun contexte parent requis).
- Rien d'autre. Pas de scope.json, pas de compte à pré-créer.

## 1. Déployer — une seule commande
```bash
# depuis la racine du dépôt
docker compose up -d --build
```
- Service **`forge`** ; console web sur **http://127.0.0.1:7100** (loopback uniquement).
- Données dans les volumes nommés `forge-db` / `forge-ledger` (re-`up` idempotent, aucune accumulation).
- Image `full` par défaut (httpx/nuclei/subfinder vérifiés SHA256 + PDF). `mini` : `FORGE_TOOLS_PROFILE=mini docker compose build`.

## 2. Ouvrir l'UI → le wizard fait tout
Ouvre **http://127.0.0.1:7100**. Au 1er lancement, l'**assistant de déploiement** (5 étapes) crée TOUT, dans le navigateur :
1. **Admin** — ton compte administrateur (argon2id). Pas de CLI `useradd`.
2. **Chiffrement** — crypto au repos (SQLCipher optionnel selon l'image).
3. **Détection** — source blue (SIEM/IDS) pour la boucle purple, optionnelle.
4. **Opérateur** — politique C2 (source-CIDR, fail-closed).
5. **Périmètre (ROE)** — **le scope de ton programme, saisi ici** : `mode` (grey/white/black), hôtes **in-scope** (globs/CIDR), **out-scope**. C'est ton autorisation.

L'assistant s'auto-désactive une fois provisionné. Tu es connecté, prêt à tester. **Zéro fichier, zéro commande.**

> ⚠️ **Provisionne AVANT d'exposer le port.** Le wizard est public jusqu'à ce que l'admin existe — quiconque atteint l'hôte en premier peut le réclamer. Garde le bind sur **loopback `127.0.0.1`** (le défaut) et **ne passe PAS à `0.0.0.0`** tant que tu n'as pas claim l'admin (cf. `docs/DEPLOYMENT.md §2`).

> Le périmètre saisi devient l'**Engagement #1**. `allow_exploit`/`allow_destructive` restent `false` en bug bounty (techniques destructrices/DoS/brute-force bannies et refusées par le scope-guard de toute façon). Le test authentifié (IDOR/ATO : creds/session/idor_targets) se règle dans l'éditeur d'engagement (secret, jamais journalisé).

## 3. Un 2e programme = un nouvel Engagement (dans l'UI)
Administration → **Engagements** → créer un engagement avec son propre scope/ROE/ledger. Chaque programme reste **isolé** (findings/runs/ledger/RBAC/rapport par-engagement). Bascule d'un engagement à l'autre dans l'UI. Rien à éditer sur disque.

## 4. Tester (lancer une campagne) — vue **Launch**
1. Choisis les **modules** (ou laisse le **planner** ordonner par valeur avec planchers de couverture).
2. Saisis/valide les **cibles in-scope** et lance. Le **scope-guard** garantit : rien hors-scope, jamais tiré ni simulé.
3. **Logs live (SSE)** ; les **findings** apparaissent avec **discipline de preuve** (`tested` tant qu'un oracle ne prouve pas `vulnerable`).
4. **Triage** (`new → triaging → confirmed / false_positive / duplicate → resolved`) + **assigne** (ownership), transitions gouvernées + événement live.
5. **Exporte** le rapport **par engagement** (HTML/PDF/CSV/JSON) + bulk-export.

Techniques natives : IDOR, SSRF, XSS, SQLi, JWT/auth, CORS, XXE, race, CSRF, open-redirect, SSTI, cmdi,
proto-pollution, GraphQL, NoSQL, cache-poison, smuggling, takeover, secrets… (cf. `docs/TECHNIQUE_COVERAGE.md`).

## 5. Outils (piloter nmap/nuclei/httpx/sqlmap/ffuf…) — TOUT depuis l'UI
Forge **pilote** des outils, il n'embarque pas d'arsenal offensif. Les scanners standards sont dans l'image `full`.
Pour Metasploit/Burp : pointe les env `MSF_RPC_*` / `BURP_API_*` vers tes services (profils `--profile msf|burp`).
- **Paramétrer un outil** : chaque outil (26 kinds — nmap, nuclei, ffuf, sqlmap, subfinder, naabu, feroxbuster, dalfox…) expose ses **arguments dans l'UI** (ports/scripts/timing/wordlist/threads/rate…), plus un champ `extra_args` allowlisté. Ex. nmap entièrement custom `-sV -p- --script http-* -T2`.
- **Rate-limit** : règle le débit (req/s) dans la vue Launch → propagé à chaque outil (`--max-rate`/`-rl`/`--rate`/`--delay`) + throttle moteur + back-off automatique sur 429/WAF.
- **Ajouter TON outil** : Administration → **Ajouter un outil** → déclare un ToolSpec gouverné (binaire/docker, argv, params, allowlist) → il apparaît dans Launch, configurable, scope-guardé. Aucun fichier, aucun rebuild (cf. `docs/TOOLS.md`). *(Le binaire doit être présent dans l'image ou fourni par un script — sinon l'outil est `skipped`.)*
- **Ajout LIVE, sans redémarrage** : dépose un exécutable dans **`forge/tools/`** (utilisable au run suivant, rien à cliquer) **ou** ajoute un ToolSpec via l'UI / **`forge/toolspecs/`** → clique **« Rafraîchir modules »**. Les deux montages sont **ON par défaut** — jamais de `docker build`/`down`/`up` en plein pentest.
- **Rendre le binaire dispo — 3 voies** (détail `docs/TOOLS.md §5`) : (a) **déjà dans l'image `full`** (nmap/curl/dig/httpx/nuclei/subfinder) ; (b) **image custom mince** `FROM forge:0.0.1` + `apt install`/`COPY` (jeu figé, prod) ; (c) **monter SANS rebuild** — dossiers hôte `:ro` : `./tools`→`/opt/tools` (binaires/scripts exécutables, **déjà sur le PATH**) et `./toolspecs` (`FORGE_TOOLSPECS`, ToolSpecs déclaratifs gouvernés) sont **ON par défaut** ; `./plugins` (`FORGE_PLUGINS`, modules Python `@register` — code, haute confiance) reste **OPT-IN** (décommenter le bind + l'env → un `up` de recréation one-shot). Ex. : `cp myfuzzer forge/tools/ && chmod +x` → utilisable au run suivant. ⚠️ `./tools`/`./plugins` = **opérateur-de-confiance** (arbitraire) ; la gouvernance ToolSpec borne l'invocation, pas l'interne du binaire.

## 6. Cycle de vie (sûr) — depuis l'UI
Administration → **Console Forge** : un panneau qui lance les commandes gouvernées (`status`, `ledger verify`,
`backup`, `upgrade`…) **sans quitter le navigateur** (allowlist, pas de shell, `upgrade` demande confirmation,
sortie streamée). En CLI (optionnel, pour les habitués) :
```bash
docker compose exec forge forge status
# upgrade sûr : snapshot chiffré -> migrate -> verify -> rollback auto si échec (no-op = 0 écriture)
docker compose exec forge forge upgrade --passphrase-env FORGE_BACKUP_PASSPHRASE
```
Arrêt : `docker compose down` (volumes persistent ; `down -v` pour tout effacer).

## Alternatives
- **Host natif** : `cd console && cargo build --release && ./target/release/forge` (puis wizard dans le navigateur).
- **Postgres (équipe)** : `--profile postgres` + `FORGE_ENTERPRISE_STORE=postgres` (voir `docs/DEPLOYMENT.md §3bis`).
- **HA / k3s** : `kubectl apply -k k8s/` (voir `docs/DEPLOYMENT.md §3bis.6`, `docs/UPGRADE.md`, `docs/KEY_CUSTODY.md`).

## Règle d'or
Le **scope est l'autorisation**. N'y mets que ce que le programme t'autorise ; `allow_exploit`/`allow_destructive`
restent `false` sauf ROE écrit. Les secrets ne traînent pas en clair : détection/SSO se règlent write-only dans
l'UI ; les secrets d'env (token, passphrase, creds connecteurs) passent par Docker/k8s secrets (`*_FILE`), pas un
`.env` en clair à côté de l'app (cf. [`docs/SECRETS.md`](SECRETS.md)). Forge refuse tout hors-scope, c'est sa raison d'être.
