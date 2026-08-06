# Modèle de sécurité

> [Sommaire](README.md) · Voir aussi : [Architecture](ARCHITECTURE.md) · [Concepts](CONCEPTS.md) ·
> [Configuration](CONFIGURATION.md) · [API HTTP](HTTP_API.md)

Le modèle de sécurité de Forge repose sur un principe : **fail-closed par construction**. L'absence
de configuration, une erreur d'évaluation ou un secret manquant produisent un **refus**, jamais une
capacité par défaut. Cette page consolide toutes les garanties.

## 1. Frontière de confiance

- **L'attaquant modélisé** est le monde extérieur au périmètre autorisé. Forge est l'outil du **red
  team autorisé** : sa charte est *bug bounty in-scope, pentest sous contrat, CTF, infra propre*.
- **Franchir un WAF/Cloudflare n'est PAS une faille** : c'est un enabler d'accès. La gate ROE + le
  scope-guard + le ledger existent pour **imposer ET prouver** l'autorisation, pas pour la contourner.
- La console bind **loopback** par défaut ; l'exposition publique exige un reverse-proxy + auth +
  host-allowlist (§4).

## 2. Autorisation (AuthZ) — RBAC & gates

### 2.1 Les deux gardes middleware

Toutes les routes sauf `/health`, `/api/login`, `/api/setup*` passent par :

1. **`host_guard`** (anti-DNS-rebinding) — le `Host` (port retiré) doit être **non vide** et dans
   l'allowlist (`localhost`/`127.0.0.1`/`::1` + `FORGE_CONSOLE_HOST`). Sinon **421**. Fail-closed sur
   `Host` absent.
2. **`auth_guard`** — la gate s'engage sur `auth_required` = *un hash env posé OU un compte activé en
   base*. Engagée sans preuve ⇒ **401**. Ceci **ferme le trou dev-open historique** : un fresh
   install avec des comptes en base mais sans hash env est désormais gaté.

### 2.2 Les rôles et leurs preuves

| Rôle | Preuve | Repli env-hash ? |
|---|---|---|
| **viewer** | session (cookie/Bearer) · ou Basic (`FORGE_CONSOLE_PASS_HASH`) · ou Bearer = token d'ingestion | oui (Basic) |
| **operator** | session operator\|admin · ou en-tête `X-Forge-Operator` (`FORGE_CONSOLE_OPERATOR_HASH`) **+ source-CIDR** | oui (bootstrap) |
| **admin** | **session admin uniquement** | **NON** (attribution individuelle stricte) |
| **token** (machine) | Bearer = token d'ingestion (`FORGE_CONSOLE_TOKEN`), comparé en temps constant | — |

Points clés :
- **`check_admin` n'a aucun repli env-hash** : une mutation d'administration DOIT être imputable à un
  compte individuel nommé, jamais à un secret partagé « bootstrap ».
- Une session porte le rôle **relu au moment du lookup** : un rôle changé/désactivé prend effet
  **immédiatement**, même sur une session déjà émise. Compte désactivé ⇒ fail-closed.
- **`check_operator`** exige AuthN operator|admin **ET** la contrainte source-CIDR (opt-in). Un
  viewer en session ne passe jamais le C2.

### 2.3 Le plancher exploit (C2-light)

`POST /api/run` refuse les modules `exploit`/`destructive` (**400**) **sauf** opt-in haut-impact
**gouverné** — honoré uniquement si `operator + arm=true + reason non vide` (`high_impact_gate`).
Sinon le scope écrit pour le run **force** `allow_exploit=false`. Les cibles doivent être ⊆ scope
serveur (**400 out_of_scope** avant tout spawn). **FIFO par engagement** : au plus un run vivant *par
engagement* (**409** sur le même engagement ; les autres engagements tournent en parallèle). Chaque run
applique le scope-guard et écrit le ledger **de SON engagement** — jamais ceux d'un autre (isolation
fail-closed par construction).

## 3. La gate ROE (moteur)

Quatre couches fail-closed (`forge/roe.py`) : *armé → in-scope → capacité → approuvé*. Hors scope ou
capacité non autorisée ⇒ **VETO** (jamais simulé, jamais tiré). Toute exception ⇒ VETO. Détail :
[Concepts §1](CONCEPTS.md#1-roe--scope-guard). L'appartenance canonise l'hôte et gère globs **et**
CIDR/IP — une IP `out_scope` ne se contourne pas via une URL ou un `host:port`.

## 4. Intégrité du ledger

- **Hash-chain SHA-256 + signature par-entrée** (Ed25519 par défaut, HMAC en repli). Altérer un octet
  casse `verify()`.
- **Non-répudiation** : `verify_external(pubkey)` — un tiers vérifie intégrité + périmètre avec la
  **seule clé publique**, sans pouvoir forger.
- **Anti-downgrade / anti-relabel** : liaison structurelle alg↔kind. `sha256-console` (chaîne non
  signée) n'est légitime **que** sur un `kind` `console.*` ; les algos signés sont interdits sur un
  kind console. Cela ferme la réécriture d'une entrée moteur en non-signée **et** le relabel d'une
  entrée signée en console. `verify` refuse ces cas **avant** toute vérification de signature.
- **Custody** : la clé privée `.ed25519` (`0600`) est aujourd'hui **locale**. L'ancrage hors-host
  (`forge/anchor.py` : témoin co-signataire + `reconcile` qui détecte une réécriture re-signée
  localement) est la dernière étape ; l'architecture asymétrique le permet déjà (seule la clé
  publique circule). Documenté, pas caché.

## 5. Chiffrement au repos

- **En transit / stockage par défaut** : la base SQLite est **en clair** (build par défaut). Le
  ledger est **tamper-evident par sa chaîne**, pas confidentiel.
- **Opt-in SQLCipher** : build `--features encryption` + `FORGE_DB_KEY` → la console émet `PRAGMA
  key` **avant toute requête**. Sans clé correcte, la base est **illisible** (fail-closed) — la
  console ne démarre pas sur des données exploitables. Voir [Installation §6](INSTALLATION.md#6-image-encryption-chiffrement-au-repos--sqlcipher-opt-in)
  et [`MIGRATION.md`](MIGRATION.md) Runbook B.
- **Sauvegardes** : **toujours chiffrées** (argon2id + XChaCha20-Poly1305), l'archive embarque la clé
  de signature ET la base. AEAD authentifie corps **et** en-tête ; une passphrase absente/mauvaise ⇒
  refus, rien écrit. Voir [`BACKUP.md`](BACKUP.md).
- **Magasin de durées** (`<ledger>.durations`, sidecar du ledger) : agrégat **par kind de module**
  (`web.testssl` → n observations + anneau de durées), **jamais par cible**. Une agrégation par cible
  aurait été un **journal de reconnaissance persistant après l'engagement** (quels hôtes existaient,
  lesquels étaient lents, lesquels filtraient) ; c'est pour cela qu'elle n'existe pas. La garde est
  **structurelle**, pas déclarative : `DurationStore.record()` refuse toute clé qui n'est pas un
  identifiant de module (une IP littérale, un `host:port`, une URL ou un chemin sont rejetés), à
  l'écriture **comme à la relecture** d'un fichier trafiqué. Portée **par engagement** (il suit le
  ledger dédié) et désactivable (`FORGE_DURATIONS=0`). Il ne pilote **que** l'ordre de soumission du
  préchauffage — aucune décision de tir n'en dépend.

### 5.1 Péremption du matériel d'authentification — « rien trouvé » n'est pas « pas testé »

Le bloc `auth` d'un engagement (comptes de test `attacker`/`victim`) **arme** les oracles de contrôle
d'accès : `access_control.idor`, `auth.takeover`, `access_control.privesc`. Quand la session qu'il
porte n'authentifie plus, ces oracles **ne plantent pas** — toutes leurs conjonctions de preuve
s'effondrent à `False`, et le run rend un **rapport propre et vide** qui ressemble à « la cible est
saine ». C'est un faux négatif **silencieux**, et il coûte une campagne entière.

**Ce qui se passe désormais.** Un oracle désarmé rend `status='skipped'` (« je n'ai pas pu tester »),
jamais `tested` (« testé, rien trouvé ». Deux signaux, **aucun n'émet de requête supplémentaire** :

| Signal | Détection | Effet |
|---|---|---|
| **Péremption lisible** | le jeton porte un claim `exp` dépassé (`session.jwt_expiry`) | finding `skipped` **avant** tout réseau — aucune requête émise |
| **Matériel inerte** | la cible répond au compte authentifié **exactement** comme à la sonde anonyme (même statut de **barrière** 401/403/3xx, même corps) | finding `skipped`, verdict refusé |

Trois surfaces le disent, du plus tôt au plus tard : l'**éditeur d'engagement** (`expires_at` /
`expired` par compte), le **lancement** (`warnings` de la réponse + `console.run.start.auth_expired`
au ledger), puis le **run** (`engine.auth_expired` + ligne d'avancement `[AUTH]` en direct, et un
finding `skipped` par cible).

**Ce que ces signaux ne prouvent pas** (nommé, pas passé sous silence) :
- *Barrière uniquement* — 404/5xx identiques des deux côtés disent l'**objet** ou le **serveur**, pas
  la session ; un 2xx dit que le compte a **obtenu** de l'accès. Ni l'un ni l'autre ne déclenche.
- *Garde anti-faux-positif* — si un compte du même jeu de sondes **entre** (2xx) sur la même URL, la
  cible discrimine démontrablement et aucun verdict d'inertie n'est rendu (sinon un privesc
  correctement bloqué deviendrait « non testé »).
- *Ambiguïté résiduelle assumée* — « 403 identique pour l'authentifié et l'anonyme » peut aussi être
  une cible **durcie qui ne discrimine pas ses refus**. Les deux lectures sont indistinguables depuis
  la réponse : c'est précisément pourquoi le verdict honnête est « je n'ai pas pu tester ».
- *Hors de portée* — un **seul** compte mort parmi plusieurs, dont le matériel n'est **pas** un JWT
  (cookie opaque), reste indétectable au tir ; une page de login rendue en **200** pour tout le monde
  aussi (indistinguable d'une ressource publique). Un `exp` inconnu n'est **jamais** présenté comme
  une validité.

**Tampon `exp` au repos.** Une fois scellé, le matériel est illisible par la console — donc ni
l'éditeur ni le lanceur ne peuvent voir qu'un jeton est mort. L'échéance est donc lue **au
scellement** (dernier instant où le clair est visible) et rangée à côté du `label`. C'est un
**horodatage, pas un credential** : il ne rejoue rien, ne signe rien, ne s'authentifie nulle part —
l'invariant « aucun nouveau champ de **matériel** persisté en clair » est tenu. Aucune vérification
de signature n'est faite : on **lit** une date auto-déclarée, on ne valide pas un jeton.

### 5.2 Renouvellement automatique de session — REFUSÉ, et pourquoi

« Faire tourner les sessions expirées sans ressaisie » **n'est pas implémenté, délibérément**. Les
deux voies possibles dégradent la posture qu'on vient de durcir :

1. **Rejouer un login** exigerait de persister un **mot de passe** — on troquerait un secret court et
   révocable contre un secret **permanent** qui ouvre bien plus que la session qu'il remplace.
   Refusé, sans condition.
2. **Rafraîchir via un `refresh_token`** fourni par l'exploitant évite le mot de passe, mais :
   - le `refresh_token` est **plus durable** que le jeton d'accès qu'il régénère — on stockerait le
     credential le plus fort pour préserver le plus faible ;
   - les `refresh_token` **rotatifs** sont à usage unique : un échec de persistance après
     consommation **détruit** le compte de test de l'opérateur. L'outil casserait ce qu'il protège ;
   - l'endpoint de jeton (IdP) est **presque toujours hors du périmètre** de l'engagement. Le
     rafraîchir obligerait à émettre du trafic authentifié **hors scope-guard** — exactement
     l'invariant fail-closed que rien ne doit assouplir.

**Ce qui reste acquis sans ressaisie** : à l'édition d'un engagement, le matériel **non ressaisi est
repris par compte** (`keep_existing`, cf. anti-effacement silencieux) — seul le compte réellement mort
doit être re-collé. Le renouvellement pourra être reconsidéré si, et seulement si, l'endpoint de jeton
entre dans le périmètre déclaré et que la rotation est traitée transactionnellement.

## 6. Gestion des secrets

- **Jamais renvoyés** par un GET, **jamais journalisés**, **jamais ledgerisés**. Traités comme des
  secrets de session, **rédigés en profondeur** :
  - Secret d'auth de la source de détection : **write-only** (GET renvoie `secret_set` seul).
  - Passphrases de backup : transitoires (corps de requête), abandonnées après dérivation.
  - Matériel de **session gouvernée** (`forge/session.py`) : attaché **uniquement** aux requêtes
    in-scope, jamais dans un finding / le ledger / le graphe / `action.params`.
  - Token d'ingestion : le log n'imprime qu'une **empreinte sha8**, jamais le token (sauf token
    auto-généré, imprimé une fois pour être utilisable).
- **Jamais en argv** : la config de source (avec secret) est passée au collecteur **par ENV**
  (`FORGE_DETECTION_SOURCE`) ; les passphrases de backup/migration par `--passphrase-env`/`--key-env`
  (jamais `--flag`) — pas de fuite via `ps`/historique shell.
- **Hashes de mots de passe** : **argon2id** (jamais en clair), sel aléatoire, comparaison en temps
  constant. `forge hashpw`/`hashpw-operator`.
- **CSPRNG** : tokens de session (256 bits via `getrandom`, panic si l'entropie manque plutôt que
  générer un token faible) ; sels/nonces de backup via le CSPRNG de l'OS.

## 7. Durcissement de surface

- **Validation stricte des entrées** : login/campagne `[A-Za-z0-9._-]{1,64}` (pas de `-` en tête) ;
  hôtes rejetant NUL, whitespace, métacaractères shell et `-` en tête (anti-injection d'option CLI).
  Les cibles sont écrites dans un **fichier** puis passées par chemin, jamais concaténées à un shell.
- **GXQL** : compilé en **SQL read-only** (champs allowlistés, valeurs en params liés, un seul
  SELECT, LIMIT plafonné, connexion `SQLITE_OPEN_READ_ONLY`). Un champ hors allowlist ⇒ 400.
- **Migration API** : opt-in (`FORGE_ALLOW_API_MIGRATE`, off par défaut) + validation de chemin
  allowlistée (`FORGE_CONSOLE_IMPORT_DIR`, anti path-traversal) + pré-provision uniquement.
- **X-Forwarded-For** : honoré **uniquement** si le pair TCP appartient à un CIDR de
  `settings.trusted_proxy` ; sinon repli **fail-closed** sur le pair TCP (anti-spoofing de source-IP).
- **systemd** : unité durcie (`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`,
  seccomp `@system-service`). **Docker** : non-root uid 10001, tini PID1, volumes séparés
  (db/ledger/scope), supply-chain **pinnée SHA256** (les binaires ProjectDiscovery échouent le build
  en cas de non-correspondance).

### 7.1 Dashboards et panels partagés — caveat opérateur multi-tenant

Les **données** rendues par un panel sont filtrées **par ligne** selon les engagements accordés à
l'appelant : le filtre est injecté par le compilateur GXQL à chaque feuille lisant des données
scopables, il est AND-joint à chaque profondeur, il est **fail-closed** (grant vide ⇒ aucune ligne) et
la requête de l'utilisateur ne peut pas l'élargir. Un panel partagé affiché par un tenant ne renvoie
donc que les lignes de ce tenant.

En revanche la **définition** d'un panel (son nom et le **texte** de sa requête GXQL) est une
configuration de console **globale** : les tables `panel`/`dashboard` ne portent pas de colonne
propriétaire/tenant, donc tout appelant authentifié disposant d'un grant voit la liste des
définitions.

> ⚠️ **Recommandation** : en déploiement multi-tenant, **ne pas embarquer d'identifiant
> tenant-sensible en clair dans le texte GXQL d'un panel partagé** (p.ex. le nom de code d'une
> campagne client). C'est une visibilité de **métadonnée** inhérente au modèle « dashboards
> partagés », pas une fuite de données. Des dashboards privés par propriétaire/tenant sont une
> évolution possible du modèle.

## 8. Garanties de gouvernance (rappel)

- **Fail-closed** : `in_scope` vide = rien ne tire ; opérateur non provisionné = C2 fermé (403) ;
  source de détection absente = mesure impossible (jamais inventée).
- **Proof-oriented** : pas de sur-classement en `vulnerable` sans preuve concrète
  ([Concepts §3](CONCEPTS.md#3-oracles-à-preuve)).
- **Plancher exploit opt-in** : `exploit`/`destructive` exigent un opt-in explicite.
- **Tout est tracé** : chaque décision/action au ledger + section anti-masquage du rapport (ce qui a
  été simulé/refusé/jamais tenté). Zéro trou silencieux.
