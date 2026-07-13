# Forge — Quickstart : déployer + tester en local sur un programme bug bounty

> Cible : lancer Forge en **Docker** sur ta machine et tester un **nouveau programme bug bounty**, de A à Z.
> Rappel de sûreté : Forge est **fail-closed** — `in_scope` vide = tout refusé. Le scope EST ton autorisation (ROE).

## 0. Prérequis
- Docker + Docker Compose. Le repo `GUATX/` (Forge a besoin du contexte parent pour `core/`).
- (Optionnel) un `forge/.env` pour les secrets (token, hashes rôles, connecteurs). Absent = boot OK, token auto-généré, C2 fermé.

## 1. Définir le SCOPE = ton autorisation (l'étape qui compte)
Le scope/ROE est un fichier `forge/scope.json` monté **read-only**. Il faut le créer AVANT le `up`
(sinon Docker crée un répertoire à sa place → l'entrypoint échoue bruyamment exprès).

```bash
cd GUATX/forge
cp scope.example.json scope.json      # scope.json est git-ignoré (*.json local n'est pas commité)
```

Édite `scope.json` avec les cibles **autorisées par le programme** (globs hostname ou CIDR) :

```json
{
  "mode": "grey",
  "in_scope": ["*.target-program.com", "api.target-program.com", "203.0.113.0/24"],
  "out_scope": ["admin.target-program.com", "*.corp.internal"],
  "rate": 5,
  "allow_exploit": false,
  "allow_destructive": false,
  "idor_targets": [],
  "known_creds": []
}
```

- **`mode`** : `grey` (défaut bug bounty), `white` (source dispo) ou `black`.
- **`allow_exploit`/`allow_destructive`** : laisse `false` en bug bounty (les techniques destructrices/DoS/brute-force sont bannies et refusées par le scope-guard de toute façon).
- **Test authentifié** (IDOR/ATO) : ajoute `idor_targets`, `known_creds`, et une `session`/`sessions` (cookies/bearer/headers). ⚠️ SECRET : le matériel de session n'est **attaché qu'aux hôtes in-scope**, **jamais** journalisé dans le ledger ni dans un finding/rapport. Garde ce scope local (git-ignoré).

## 2. Déployer
```bash
# depuis GUATX/  (ou ajoute -f forge/docker-compose.yml)
docker compose -f forge/docker-compose.yml up -d --build
```
- Console web sur **http://127.0.0.1:7100** (loopback uniquement ; jamais 0.0.0.0 sans reverse-proxy).
- Données persistées dans les volumes nommés `forge-db` / `forge-ledger` (re-`up` = idempotent, aucune accumulation).
- Image `full` par défaut (httpx/nuclei/subfinder vérifiés SHA256 + moteur PDF). `mini` : `FORGE_TOOLS_PROFILE=mini docker compose -f forge/docker-compose.yml build`.

## 3. Créer le 1er admin
- **Le plus simple** : ouvre http://127.0.0.1:7100 → le **wizard de 1er déploiement** crée l'admin, choisit la crypto (argon2id, SQLCipher optionnel) et la source de détection. Il s'auto-désactive une fois provisionné (409).
- **Ou en CLI** :
```bash
docker compose -f forge/docker-compose.yml exec forge forge useradd <toi> admin
# (mot de passe demandé)
```
Vérifier l'état : `docker compose -f forge/docker-compose.yml exec forge forge status`

## 4. Ton programme = l'Engagement #1
Au 1er boot, le scope monté devient **l'Engagement #1** (migration zéro-perte). Tout ce que tu testes
(findings/runs/ledger) est isolé sous cet engagement. Pour un **2e programme** : crée un **nouvel Engagement**
dans la console (Administration/Engagements) avec son propre scope/ROE/ledger — chaque programme reste isolé
(RBAC + rapport + ledger par-engagement), plutôt que d'écraser `scope.json`.

## 5. Tester (lancer une campagne)
Dans la console web → vue **Launch** :
1. Choisis les **modules** (ou laisse le **planner** ordonner par valeur avec planchers de couverture).
2. Lance le run **contre les cibles in-scope**. Le **scope-guard** garantit : rien hors-scope, jamais tiré ni simulé.
3. **Logs live (SSE)** en temps réel ; les **findings** apparaissent avec **discipline de preuve** — un finding reste `tested` tant qu'un oracle concret ne prouve pas `vulnerable` (fini les « en théorie »).
4. **Triage** le finding (`new → triaging → confirmed / false_positive / duplicate → resolved`) + **assigne**-le (ownership), transitions gouvernées + événement live.
5. **Exporte** le rapport **par engagement** (HTML/PDF/CSV/JSON) + bulk-export des findings.

Techniques couvertes nativement : IDOR, SSRF, XSS, SQLi, JWT/auth, CORS, XXE, race, CSRF, open-redirect,
SSTI, cmdi, proto-pollution, GraphQL, NoSQL, cache-poison, smuggling, takeover, secrets… (cf. `docs/TECHNIQUE_COVERAGE.md`).

## 6. Bring-your-own outils (optionnel)
Forge **pilote** des outils, il n'embarque pas d'arsenal. nmap/nuclei/httpx/sqlmap/ffuf… sont dans l'image `full`.
Pour Metasploit/Burp : pointe les env `MSF_RPC_*` / `BURP_API_*` vers tes services (profils `--profile msf|burp`, BYO images).
Ajouter un outil CLI = **une ligne ToolSpec** (`toolcatalog.py`) ou un fichier JSON (`FORGE_TOOLSPECS`), ou déposer
un module `@register` / un `FORGE_PLUGINS` (drop-in, gouverné). cf. `contrib/`.

## 7. Cycle de vie (sûr, une commande)
```bash
# état
docker compose -f forge/docker-compose.yml exec forge forge status
# upgrade sûr : snapshot chiffré pré-upgrade -> migrate -> verify -> rollback auto si échec (no-op = 0 écriture)
docker compose -f forge/docker-compose.yml exec forge forge upgrade --passphrase-env FORGE_BACKUP_PASSPHRASE
# backup / restore chiffrés
docker compose -f forge/docker-compose.yml exec forge forge backup   --passphrase-env FORGE_BACKUP_PASSPHRASE --out /data/db/backup.forge
docker compose -f forge/docker-compose.yml exec forge forge restore  <archive> --passphrase-env FORGE_BACKUP_PASSPHRASE
```
Arrêt / purge : `docker compose -f forge/docker-compose.yml down` (les volumes persistent ; `down -v` pour tout effacer).

## Alternatives (mêmes concepts, autres cibles)
- **Host natif** : `cd console && cargo build --release && FORGE_CONSOLE_SCOPE=../scope.json ./target/release/forge` (puis `useradd`). Le scope/engagement/campagne sont identiques.
- **Postgres (équipe)** : `--profile postgres` + `FORGE_ENTERPRISE_STORE=postgres` (voir `docs/DEPLOYMENT.md §3bis`).
- **HA / k3s** : `kubectl apply -k k8s/` (voir `docs/DEPLOYMENT.md §3bis.6` + `docs/UPGRADE.md` pour le rolling-upgrade drain-leader ; `docs/KEY_CUSTODY.md` pour la clé de signature hors volume partagé).

## Règle d'or
Le **scope est l'autorisation**. Renseigne uniquement des cibles que le programme t'autorise à tester ;
`allow_exploit`/`allow_destructive` restent `false` sauf ROE écrit ; les secrets vont dans `forge/.env` /
un scope local git-ignoré, jamais commités. Forge refuse tout ce qui sort du scope — c'est sa raison d'être.
