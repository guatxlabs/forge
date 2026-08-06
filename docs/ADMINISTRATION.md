# Administration

> [Sommaire](README.md) · Prérequis : [Premier déploiement](FIRST_DEPLOYMENT.md) · Références :
> [Configuration](CONFIGURATION.md) · [API HTTP](HTTP_API.md) · [Modèle de sécurité](SECURITY_MODEL.md)

Toute l'administration se fait dans l'onglet **Administration** du SPA ou via l'API — **session admin
requise** (aucun repli par secret partagé : les mutations d'administration sont **imputables à un
compte individuel nommé** et **ledgerisées**).

- [1. Comptes & rôles](#1-comptes--rôles)
- [2. Source de détection](#2-source-de-détection)
- [3. Gouvernance des connecteurs (installer/désinstaller)](#3-gouvernance-des-connecteurs-installerdésinstaller)
- [4. Politique opérateur & source-CIDR](#4-politique-opérateur--source-cidr)
- [5. Sauvegarde & restauration](#5-sauvegarde--restauration)
- [6. Migration de données](#6-migration-de-données)

---

## 1. Comptes & rôles

Trois rôles (contrainte applicative ; la table `users` stocke un TEXT) :

| Rôle | Peut | Ne peut pas |
|---|---|---|
| **viewer** | Lecture : findings, coverage ATT&CK, purple, runs, ledger, GXQL, dashboards. | Lancer un run, administrer. |
| **operator** | Tout viewer **+** lancer/annuler un run C2-light (`/api/run*`), rafraîchir les modules. | Administrer (comptes/settings/gouvernance). |
| **admin** | Tout **+** administration : comptes, settings, source de détection, gouvernance des connecteurs, backup/restore, setup. | — (superset). |

### Gérer les comptes

- **UI** : *Administration → Comptes* — créer, changer le rôle/mot de passe, désactiver.
- **API** (admin) : `GET /api/users` (jamais `pass_hash`), `POST /api/users` (`{login, role,
  password}`), `POST /api/users/:login` (update), `DELETE /api/users/:login`.
- **CLI** : `forge useradd <login> <role>` (mot de passe sur STDIN). Idempotent par login.

Garde-fous :
- Le **dernier admin activé** est protégé (impossible de se verrouiller dehors).
- Un rôle changé/désactivé prend effet **immédiatement**, même sur une session déjà émise (le compte
  est relu à chaque lookup).
- Chaque mutation est **ledgerisée** (attribution = l'admin acteur) ; `GET` ne renvoie jamais le hash.

### Comment on se connecte

- **Session individuelle** : `POST /api/login {login, password}` → cookie `forge_session`
  (HttpOnly, SameSite=Strict) + token. TTL = `FORGE_CONSOLE_SESSION_TTL` (défaut 3600 s).
- **Amorçage headless** (rétro-compat) : Basic viewer (`FORGE_CONSOLE_PASS_HASH`) ; opérateur via
  en-tête `X-Forge-Operator` (`FORGE_CONSOLE_OPERATOR_HASH`). **L'administration n'accepte PAS** ce
  repli — elle exige une session admin nommée.

---

## 2. Source de détection

La boucle purple joint les techniques **tirées** (red) aux techniques **détectées** (blue). La
**source** de détection est un **plugin configurable** — Plume n'est qu'un préréglage. Configuration
complète, préréglages par infra (FortiGate/pfSense/OPNsense/CrowdSec/Elastic/OpenSearch/fichier/exec)
et mapping MITRE : **[`DETECTION.md`](DETECTION.md)**.

En bref (*Administration → Source de détection*, ou l'étape 3 du wizard) :

| Action | Route (admin) | Note |
|---|---|---|
| Voir la config | `GET /api/detection/source` | **secret RETIRÉ** (`secret_set` seul). |
| Enregistrer | `POST /api/detection/source` | Persiste `settings.detection_source` (secret **write-only**), recharge à chaud. Ledger `console.detection.source.set`. |
| Tester la connexion | `POST /api/detection/test` | Collecte unique : `{reachable, count, sample_mitres, error?}` — **jamais** le secret. `keep_secret:true` pour tester sans re-saisir. |

Diagnostic hors-ligne : `forge doctor --purple` (préflight lecture seule) et `forge detections
--source <spec> --since N`. Voir [CLI](CLI.md).

**Fail-open lisible** : source absente/injoignable ⇒ `source_reachable:false`, la mesure est déclarée
impossible — jamais inventée. Prérequis du préréglage Plume : [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).

---

## 3. Gouvernance des connecteurs (installer/désinstaller)

Un connecteur peut être **activé/désactivé** par l'admin — c'est l'équivalent d'un
« installer/désinstaller » gouverné. **Désactiver un connecteur l'empêche RÉELLEMENT de tirer** : il
est SKIP au spawn **même si son binaire/service est présent**, y compris quand c'est le planner (et
non `--modules`) qui l'a choisi.

- **UI** : *Administration → Connecteurs* (état activé, disponibilité, web_allowed).
- **API** (admin) : `POST /api/modules/:kind` avec un corps typé strict :

| Champ | Type | Effet |
|---|---|---|
| `enabled` | bool | `false` ⇒ le module est SKIP au tir (comme un outil absent). |
| `web_allowed` | bool | Autorise/interdit le lancement du module depuis le web (C2-light). |
| `available_override` | bool \| null | Force (true/false) ou efface (null) l'état de disponibilité affiché. |

Chaque changement est **ledgerisé** (acteur + état effectif). Le catalogue (`GET /api/modules`) est
la source de vérité des kinds ; `POST /api/modules/refresh` (operator) le re-peuple depuis
`forge.cli modules`. Catalogue complet : [MODULES.md](MODULES.md).

> Le connecteur doit exister dans le catalogue (sinon **404**). Cela couvre aussi bien les
> connecteurs opérateur (msf/burp) que n'importe quel module de recon/oracle.

---

## 4. Politique opérateur & source-CIDR

Le rôle **opérateur** (C2-light) est **fail-closed** : non provisionné = `/api/run*` renvoie **403**.
La politique `settings.operator_policy` le gouverne :

| Champ | Sens | Défaut |
|---|---|---|
| `source_cidrs` | Allowlist d'IP client autorisées à lancer un run. | *(absente/vide = aucune restriction)* |

Quand `source_cidrs` est configuré, l'IP client effective **DOIT** tomber dans l'un des CIDR, sinon
l'action opérateur est refusée. Politique active mais IP indéterminée ⇒ refus (fail-closed). La
contrainte ne s'applique **qu'au C2 opérateur** — jamais admin/viewer.

**Derrière un proxy** : configurer `settings.trusted_proxy` (CIDR du/des proxy amont). Un
`X-Forwarded-For` n'est honoré que si le pair TCP tombe dans un CIDR de confiance ; sinon repli
**fail-closed** sur le pair TCP. Une valeur non-CIDR ⇒ XFF ignoré (la console alerte au boot). Voir
[Modèle de sécurité](SECURITY_MODEL.md).

Le **plancher exploit** du C2 : les modules `exploit`/`destructive` sont refusés (400) sauf **opt-in
haut-impact gouverné** — honoré **uniquement** si `operator + arm=true + reason non vide`. Voir
[Architecture §3.3](ARCHITECTURE.md#33-le-run-flow--c2-light--gouverné).

---

## 5. Sauvegarde & restauration

L'archive est **TOUJOURS chiffrée** (argon2id + XChaCha20-Poly1305) et embarque **la clé de
signature ET la base** — il n'existe aucun chemin en clair. Runbook complet, format, offsite :
**[`BACKUP.md`](BACKUP.md)**.

En bref (*Administration → Sauvegarde*, admin, ledgerisé) :

| Action | Route / CLI |
|---|---|
| Créer une sauvegarde (téléchargement) | `POST /api/backup {passphrase}` · ou `forge backup --out … --passphrase-env …` |
| Restaurer (valide par défaut ; swap = `apply:true`+`confirm:true`, **redémarrage requis**) | `POST /api/restore {archive_b64, passphrase, apply?, confirm?}` · ou `forge restore --in … --force` |
| Politique programmée/offsite (rédigée au GET) | `GET`/`POST /api/backup/policy` |

Scheduler en-console **fail-open** (un échec est loggé + ledgerisé, ne crashe jamais). Deux knobs
d'environnement : `FORGE_BACKUP_TICK_SECS` (défaut 60 s), `FORGE_BACKUP_PASSPHRASE` (le **nom** d'ENV
est référencé par `backup_policy.passphrase_env` ; la passphrase n'est jamais en DB). Offsite ∈
`{none, local_dir, exec}` (argv fixe, aucun shell).

---

## 5bis. Canal de notification sortant (webhook)

Les notifications **in-app** (assignation / triage) ne quittent jamais le processus. Ce canal en fait
un miroir vers un endpoint HTTP. C'est de l'**egress depuis un outil offensif** — un finding porte des
preuves — donc il est gouverné exactement comme l'egress LLM du moteur.

*Administration → canal de notification* (admin, ledgerisé) · `GET`/`POST /api/notify/channel`,
`POST /api/notify/channel/test`.

| Garantie | Mise en œuvre | En cas d'écart |
|---|---|---|
| **OFF par défaut** | aucune clé `settings.notify_channel` ⇒ canal inerte | aucun octet ne sort ; un déploiement qui ne touche à rien est inchangé |
| **Rédaction du corps** | `redact::redact_secrets` (**le rédacteur des rapports**, pas une 2e copie) **puis** neutralisation des URL absolues | un JWT / une clef cloud / une URL de cible ne peut pas partir |
| **Anti-SSRF** | deny-list d'intégration **partagée** sur l'IP **résolue** (anti-rebinding) | loopback / RFC1918 / link-local / métadonnées / ULA refusés, sauf `FORGE_ALLOW_INTERNAL_INTEGRATIONS=1` |
| **Jeton write-only** | jamais re-servi par `GET` (`secret_set` seul), jamais loggé, jamais ledgerisé | `keep_secret:true` pour éditer l'endpoint sans le retaper |
| **Transport `https://` vérifié** | seam TLS unique (`console/src/tls.rs`) — chaîne (racines Mozilla) **et** nom d'hôte vérifiés, handshake abouti **avant** le premier octet | Slack / Teams / PagerDuty sont joignables ; **aucune** option n'accepte un certificat non fiable |
| **Pas de credential en clair sur un réseau public** | un jeton + une cible **publique** en `http://` = **refus** ; en `https://` = autorisé (le jeton est protégé) ; en `http://` vers un collecteur **interne** autorisé = inchangé | passer en `https://`, viser un collecteur interne (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`), ou retirer le jeton |
| **Journalisation de l'ENVOI, pas du contenu** | ledger `console.notify.dispatch` : canal, **destinataire rédigé** (`scheme://authority` — le chemin d'un webhook Slack/Teams **est** un credential), événement, issue | le texte du message n'apparaît nulle part |
| **Best-effort** | tâche détachée et bornée | un échec d'envoi n'affecte ni la notification in-app ni la mutation qui l'a déclenchée |

**Pourquoi il n'y a toujours pas de SMTP** — et le seam TLS n'y change rien. STARTTLS est une élévation
**négociée** : la session débute en clair et se hisse sur une commande échangée en clair, ce qui est une
classe d'**injection de commandes en clair** (CVE-2011-0411 et sa descendance). Et le SMTP réel se pratique
en TLS **opportuniste** contre des relais à certificat auto-signé : le servir honnêtement demanderait soit
d'accepter des certificats non fiables — l'échappatoire de vérification que ce socle refuse par principe —,
soit d'imposer aux relais de mail une PKI qu'ils n'ont pas. Débuter un client TLS par le protocole aux pires
sémantiques d'élévation serait le mauvais ordre. Le cas restant — un relais on-prem sans authentification —
est déjà couvert, mieux, par un webhook vers un collecteur interne ; un vrai besoin SMTP se délègue au
moteur Python (`smtplib` + `ssl`), qui est une autre couche.

---

## 5ter. SLA de triage

Un **ordonnanceur**, pas un canal : un balayage périodique signale les findings dont le **cycle de
triage** est resté ouvert au-delà du budget de leur sévérité. Il **n'ouvre aucune sortie** — ce qu'il
trouve remonte par la **porte des notifications**, et hérite donc du canal ci-dessus et de **ses**
rédactions. Même discipline que le scheduler de sauvegarde (politique déclarative, fail-open, ledger).

*Administration → SLA de triage* (admin, ledgerisé) · `GET`/`POST /api/notify/sla`.

**Ce que « en retard » veut dire** — dérivé des **seuls champs que le modèle porte déjà**, aucune
colonne nouvelle : un finding dont `triage` ∈ {`new`, `triaging`, `reopened`} (le cycle attend encore
une décision) et dont l'âge depuis `finding.ts` dépasse le budget configuré pour **sa sévérité**.
`confirmed` n'est pas en retard : la décision est prise, ce qui reste est la remédiation — une autre
horloge, qui exigerait un propriétaire de correctif que ce modèle n'a pas.

| Garantie | Mise en œuvre | En cas d'écart |
|---|---|---|
| **OFF par défaut** | aucune clé `settings.sla_policy` ⇒ balayage **no-op total** ; `enabled` sans budget positif reste **inerte** | aucune notification, aucune ligne de ledger |
| **Aucun egress nouveau** | remontée via `notifications::emit` ⇒ mêmes rédactions (secrets **puis** URL de cible) que le canal | le SLA n'a ni socket, ni URL, ni secret à lui |
| **Leader-only sous HA** | `ha::is_leader` lu à chaque tick | N réplicas enverraient N notifications identiques |
| **Une notification par finding** | dédup **dans la requête** (`NOT EXISTS … kind='finding.sla'`) | pas de rappel toutes les 15 min ; le plafond de balayage n'est pas consommé par du déjà-traité |
| **Grant-scopé** | hérité de l'émission : un destinataire sans grant sur l'engagement ne reçoit rien | l'isolation multi-tenant n'est pas contournée par une tâche de fond |
| **Non assigné ⇒ jamais diffusé** | escalade vers **un** login nommé (`escalate_to`) ou personne | un SLA qui écrit à tout le monde est un SLA qu'on désactive |
| **Ne casse jamais rien** | `spawn_blocking` + fail-open ; toute erreur capturée dans le rapport et ledgerisée `console.notify.sla.error` | un balayage ne peut ni bloquer ni faire échouer un run |
| **Ledger sans contenu** | `console.notify.sla.sweep` : compteurs seuls | ni titre de finding, ni cible |

L'horloge part de la **date de création** parce que c'est la seule date que la ligne porte : il n'y a pas
de `triage_updated`, et en inventer une pour un SLA reviendrait à faire porter au schéma une fonction
périphérique. Conséquence assumée : **pas de ré-armement** après réouverture (une notification par
finding, à vie) — le compromis privilégie l'absence de spam.

Le `GET` porte aussi `overdue_now` : un **aperçu en lecture seule** (il ne notifie personne) du nombre de
findings actuellement en retard selon la politique **enregistrée** — de quoi calibrer des budgets sans
armer la politique et regarder qui se fait spammer.

---

## 6. Migration de données

Reprendre un install existant (systemd/bare-metal) vers Docker/autre cible **sans perdre l'audit**.
Trois artefacts **couplés** voyagent ensemble : la base SQLite, le ledger `engagement.jsonl`, **et sa
clé de signature `.ed25519`** (sinon la chaîne signée devient invérifiable). Runbook complet +
garde-fous + option chiffrement au repos : **[`MIGRATION.md`](MIGRATION.md)**.

```sh
# UX primaire : conteneur one-shot (source ouverte READ-ONLY, jamais mutée)
docker run --rm \
  -v /ancien/forge:/import:ro -v forge-db:/data/db -v forge-ledger:/data/ledger \
  forge:0.0.1 \
  forge migrate --from /import --to /data/db/forge.db \
    --ledger /data/ledger/engagement.jsonl --verify
```

La voie API (`POST /api/setup/migrate`) est **pré-provision uniquement** et **désactivée par défaut**
(`FORGE_ALLOW_API_MIGRATE` + `FORGE_CONSOLE_IMPORT_DIR`) — la CLI reste l'UX documentée.

Post-migration : `GET /api/ledger/verify` (chaîne intègre côté console) **et** `forge ledger verify`
(signatures OK ⇒ la clé `.ed25519` a voyagé, en `0600`).
