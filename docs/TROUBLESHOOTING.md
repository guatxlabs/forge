# Dépannage & FAQ

> [Sommaire](README.md) · Voir aussi : [Configuration](CONFIGURATION.md) · [API HTTP](HTTP_API.md) ·
> [Modèle de sécurité](SECURITY_MODEL.md) · [Installation](INSTALLATION.md)

La plupart des « problèmes » de Forge sont des **comportements fail-closed voulus** : le produit
refuse plutôt que d'agir sur une configuration ambiguë. Cette page aide à distinguer un vrai blocage
d'un garde-fou qui fait son travail.

## Premier réflexe : les diagnostics lecture seule

```sh
python3 -m forge.cli doctor            # quels modules sont opérationnels + source de détection
python3 -m forge.cli doctor --purple   # préflight boucle purple (console /health + source)
curl -s http://127.0.0.1:7100/health   # liveness -> {"status":"ok","version":"0.0.1"}
forge ledger verify --ledger <L>       # intégrité de la chaîne d'engagement
```

Aucun ne tire quoi que ce soit ni ne touche le scope/ledger.

---

## Symptômes courants

### HTTP 421 « host non autorisé (anti-rebinding) »
Le `Host` de la requête n'est pas dans l'allowlist du **host-guard**. Ajouter le nom d'hôte public à
`FORGE_CONSOLE_HOST` (CSV). `localhost`/`127.0.0.1`/`::1` sont toujours acceptés — c'est pourquoi le
healthcheck (qui vise `127.0.0.1`) reste vert même derrière un host-guard restreint. Voir
[Configuration §1.1](CONFIGURATION.md#11-console--bind-chemins-détat-session).

### HTTP 401 « auth requise » (le SPA affiche le portail de login)
La gate d'auth est **engagée** (un hash env est posé **ou** un compte activé existe) et aucune preuve
valide n'est présentée. Se connecter via `POST /api/login`, ou présenter Basic (viewer) / Bearer
(token d'ingestion). Sur un fresh install, c'est le comportement attendu après le wizard. Voir
[Modèle de sécurité §2](SECURITY_MODEL.md#2-autorisation-authz--rbac--gates).

### HTTP 403 « operator_required » sur `/api/run`
Le rôle **opérateur** n'est pas provisionné (C2 fermé, fail-closed) **ou** la preuve/le source-CIDR
échoue. Provisionner : `forge useradd <login> operator` (ou `FORGE_CONSOLE_OPERATOR_HASH` +
en-tête `X-Forge-Operator`). Si `operator_policy.source_cidrs` est configuré, vérifier que l'IP
client (ou le dernier hop XFF, si `trusted_proxy` est correct) tombe dans un CIDR.

### HTTP 403 « admin_required »
L'administration exige une **session admin** (aucun repli par secret partagé). Se connecter avec un
compte admin. Créer le premier : le [wizard](FIRST_DEPLOYMENT.md) ou `forge useradd <login> admin`.

### HTTP 400 « out_of_scope » au lancement d'un run
La cible n'est pas dans le **scope serveur** (`FORGE_CONSOLE_SCOPE`). Le C2-light refuse **avant** le
spawn toute cible hors `in_scope`. Vérifier : `forge scope-check <cible> --scope <scope.json>`.

### HTTP 400 sur `/api/run` avec un module exploit/destructif
**Plancher exploit** : les modules `exploit`/`destructive` sont refusés sauf **opt-in haut-impact
gouverné** — poser `arm:true` + `reason` (non vide) **et** être opérateur. Sinon, retirer ces modules
du run. Voir [Architecture §3.3](ARCHITECTURE.md#33-le-run-flow--c2-light--gouverné).

### HTTP 409 « run_in_progress »
**FIFO PAR ENGAGEMENT** : au plus un run vivant *par engagement* (le corps du 409 porte
l'`engagement_id` occupé). Attendre la fin de CE run ou `POST /api/runs/:id/cancel`. Un autre
engagement peut, lui, lancer un run **en parallèle** sans 409 — la concurrence est inter-engagement.

### `forge scope-check` dit HORS SCOPE / rien ne tire (tout DRY_RUN ou VETO)
Forge est **INERTE par défaut** : `in_scope` vide ⇒ tout est refusé (fail-closed). Renseigner
`in_scope` dans `scope.json` **avec autorisation écrite**. Pour tirer, il faut aussi **armer**
(`--arm`) et **approuver** (`--approve` ou `--mode auto`), et — pour un exploit — `allow_exploit:true`
dans le scope. Voir [Concepts §1](CONCEPTS.md#1-roe--scope-guard).

### Un module apparaît `INDISPONIBLE ⛔` dans `forge doctor`
Son outil sous-jacent manque (auto-neutralisation) — ce **n'est pas une erreur**, le module est
simplement SKIP au tir. `forge doctor` imprime l'outil attendu + l'astuce d'install. En image `mini`,
httpx/nuclei/subfinder/weasyprint sont volontairement absents (passer `full` pour les embarquer). Un
module de recon injoignable émet un finding `status=skipped` (offline-safe), pas un crash.

### Un connecteur activé ne tire pas
Vérifier qu'il n'a pas été **désactivé** en gouvernance (`GET /api/modules` → `enabled`). Un
connecteur désactivé est SKIP **même si son binaire est présent**. Voir
[Administration §3](ADMINISTRATION.md#3-gouvernance-des-connecteurs-installerdésinstaller).

### La couverture purple répond `source_reachable:false`
La source de détection est **absente / injoignable / mal configurée** — Forge déclare la mesure
**impossible** (fail-open lisible) et **n'invente jamais** `detected`/`missed`/`MTTD`. C'est valide en
standalone. Pour l'activer : *Administration → Source de détection* (ou `PLUME_URL`/`PLUME_TOKEN`),
puis `forge doctor --purple` pour le préflight. Source **joignable mais vide** (SOC frais) =
`reachable:true, detections:[]` — également valide. Voir [`DETECTION.md`](DETECTION.md).

### Le MTTD paraît anormalement élevé (plusieurs centaines de secondes)
Le MTTD de Forge est un **time-to-ALERT**, pas un time-to-event : il englobe la latence d'ingest + la
**cadence d'évaluation des règles** (`interval_s`) du SIEM. Un MTTD dominé par l'intervalle des règles
n'indique **pas** un SOC lent. Explication complète : [`MTTD.md`](MTTD.md).

### Le conteneur est `unhealthy`
Le healthcheck fait un vrai `GET /health` attendant 200. Vérifier les logs
(`docker logs forge`) — souvent un **scope monté comme répertoire** (voir ci-dessous) ou un
bind qui a échoué. `docker inspect --format '{{.State.Health.Status}}' forge`.

### « FATAL: /data/scope/scope.json est un REPERTOIRE, pas un fichier »
La **pré-étape scope a été oubliée** : Docker crée un répertoire vide quand `./scope.json` est absent
sur l'hôte. Faire `cp scope.example.json scope.json` dans `forge/` **avant** `docker compose up`.
L'entrypoint échoue **bruyamment** exprès (plutôt que de démarrer sur un scope illisible), et bascule
sur `scope.example.json` (INERTE) si le fichier manque/est vide sans être un répertoire. Voir
[Installation](INSTALLATION.md#pré-étape-obligatoire--le-fichier-scope-fail-loud).

### La base chiffrée ne s'ouvre pas / la console ne démarre pas (build `encryption`)
`FORGE_DB_KEY` est absente ou incorrecte ⇒ base **illisible** (fail-closed, comportement attendu).
Fournir la bonne clé par l'ENV (jamais en argv). Sur un build **par défaut** (non chiffré),
`FORGE_DB_KEY` est simplement ignorée et `capabilities.sqlcipher:false`. Voir
[`MIGRATION.md`](MIGRATION.md) Runbook B.

### `forge ledger verify` échoue après une migration
La clé `.ed25519` **n'a pas voyagé** avec le ledger. Les signatures Ed25519 ne sont vérifiables que
par leur clé de signature sibling. Refaire la migration en s'assurant que
`engagement.jsonl.ed25519` est présent côté source ; `forge migrate` la copie
automatiquement en `0600`. `GET /api/ledger/verify` (chaîne, `sig_checked:false`) peut être OK côté
console alors que la **signature** échoue côté moteur — c'est le symptôme. Voir
[`MIGRATION.md`](MIGRATION.md).

### `ledger verify` rapporte « algo interdit pour kind (downgrade refusé) »
Garde anti-downgrade : une entrée non-console porte `sha256-console`, ou une entrée console porte un
algo signé. Cela signale une **altération** (réécriture/relabel). Le ledger est cassé — investiguer
(l'entrée `broken` est rapportée). Voir [Modèle de sécurité §4](SECURITY_MODEL.md#4-intégrité-du-ledger).

### Le build Docker échoue « pin SHA256 absent / non-correspondance »
Supply-chain durcie : les archives ProjectDiscovery sont **épinglées par digest** ; toute
non-correspondance fait échouer le build. Lors d'un bump de version, rafraîchir **version ET digest**
(depuis les `*_checksums.txt` officiels). Alternative : build `mini` puis bind-monter les binaires.

### Le build Docker échoue « core hors contexte »
Le **contexte de build doit être le parent `GUATX/`** (la console dépend du sibling `guatx-core`).
Lancer `docker build -f forge/Dockerfile .` **depuis `GUATX/`**, ou utiliser le compose qui fixe déjà
`context: ..`. Voir [`DEPLOYMENT.md`](DEPLOYMENT.md) §4.

### `?format=pdf` renvoie `pdf_unavailable`
Aucun moteur PDF sur le PATH (image `mini`, ou install sans weasyprint). Utiliser
`?format=html` + « Imprimer → Enregistrer au format PDF » du navigateur (feuille de style d'impression
fournie), ou installer `weasyprint` (pip, pur-Python) / passer à l'image `full`. Voir
[`DEPLOYMENT.md`](DEPLOYMENT.md) § Rapports & export PDF.

---

## FAQ

**Forge remplace-t-il Metasploit / Burp / nuclei ?**
Non — il les **pilote** et **gouverne**, et **mesure** leur impact défensif. C'est une couche de
gouvernance + preuve + mesure, pas un arsenal. Voir [Vue d'ensemble](OVERVIEW.md) et
[`POSITIONING.md`](POSITIONING.md).

**Ai-je besoin de Plume / d'un SOC pour utiliser Forge ?**
Non. Forge est complet en **standalone** ; la boucle purple est optionnelle et se branche plus tard
sans migration. Voir [Utiliser Forge en standalone](STANDALONE.md).

**Est-ce un C2 / un beacon ?**
Non — aucun implant, aucun accès persistant, aucune post-exploitation. Le run-flow « C2-light » est
un **lanceur de campagne gouverné et audité**, pas un canal de commande persistant. Voir
[Architecture §3.3](ARCHITECTURE.md#33-le-run-flow--c2-light--gouverné).

**Forge peut-il tirer tout seul par accident ?**
Non par construction : INERTE par défaut, `in_scope` vide = rien, armement + approbation explicites,
plancher exploit opt-in, `VETO` jamais tiré. Voir [Concepts §1](CONCEPTS.md#1-roe--scope-guard).

**Le ledger prouve-t-il quelque chose à un tiers ?**
Oui : `forge ledger verify --pubkey <clé publique>` laisse un auditeur vérifier intégrité **et**
appartenance au périmètre avec la **seule clé publique**, sans pouvoir forger. La clé privée reste
locale aujourd'hui (custody documentée). Voir [Concepts §2](CONCEPTS.md#2-le-ledger-dengagement).

**Puis-je exposer la console sur Internet ?**
Seulement derrière un reverse-proxy + auth + `FORGE_CONSOLE_HOST` + hashes/comptes activés (+
`trusted_proxy` si proxy). Ne jamais exposer le mode dev localhost-ouvert. Voir
[Modèle de sécurité §7](SECURITY_MODEL.md#7-durcissement-de-surface).

**Forge scale-t-il horizontalement ?**
Pas encore : **stateful single-replica** (SQLite + ledger sur PVC RWO). Profil idéal
mono-opérateur / petit MSSP. Voir [`DEPLOYMENT.md`](DEPLOYMENT.md) § Contrainte d'archi.

**Combien de modules et quelles techniques ?**
31 modules livrés (recon, oracles à preuve, évasion, connecteurs), chacun taggé MITRE ATT&CK.
Table complète : [MODULES.md](MODULES.md) (générée depuis `forge modules --json`).

**Comment sauvegarder / migrer sans perdre l'audit ?**
Les trois artefacts couplés (DB + ledger + clé `.ed25519`) voyagent ensemble. Sauvegarde toujours
chiffrée : [`BACKUP.md`](BACKUP.md). Migration : [`MIGRATION.md`](MIGRATION.md).

**Où sont les valeurs de configuration ?**
Table complète des variables d'environnement et des clés `settings` : [Configuration](CONFIGURATION.md).
