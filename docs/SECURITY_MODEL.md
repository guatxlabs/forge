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
  constant. `forge-console hashpw`/`hashpw-operator`.
- **CSPRNG** : tokens de session (256 bits via `getrandom`, panic si l'entropie manque plutôt que
  générer un token faible) ; sels/nonces de backup via le CSPRNG de l'OS.

## 7. Durcissement de surface

- **Validation stricte des entrées** : login/campagne `[A-Za-z0-9._-]{1,64}` (pas de `-` en tête) ;
  hôtes rejetant NUL, whitespace, métacaractères shell et `-` en tête (anti-injection d'option CLI).
  Les cibles sont écrites dans un **fichier** puis passées par chemin, jamais concaténées à un shell.
- **soql** : compilé en **SQL read-only** (champs allowlistés, valeurs en params liés, un seul
  SELECT, LIMIT plafonné, connexion `SQLITE_OPEN_READ_ONLY`). Un champ hors allowlist ⇒ 400.
- **Migration API** : opt-in (`FORGE_ALLOW_API_MIGRATE`, off par défaut) + validation de chemin
  allowlistée (`FORGE_CONSOLE_IMPORT_DIR`, anti path-traversal) + pré-provision uniquement.
- **X-Forwarded-For** : honoré **uniquement** si le pair TCP appartient à un CIDR de
  `settings.trusted_proxy` ; sinon repli **fail-closed** sur le pair TCP (anti-spoofing de source-IP).
- **systemd** : unité durcie (`NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet=`,
  seccomp `@system-service`). **Docker** : non-root uid 10001, tini PID1, volumes séparés
  (db/ledger/scope), supply-chain **pinnée SHA256** (les binaires ProjectDiscovery échouent le build
  en cas de non-correspondance).

## 8. Garanties de gouvernance (rappel)

- **Fail-closed** : `in_scope` vide = rien ne tire ; opérateur non provisionné = C2 fermé (403) ;
  source de détection absente = mesure impossible (jamais inventée).
- **Proof-oriented** : pas de sur-classement en `vulnerable` sans preuve concrète
  ([Concepts §3](CONCEPTS.md#3-oracles-à-preuve)).
- **Plancher exploit opt-in** : `exploit`/`destructive` exigent un opt-in explicite.
- **Tout est tracé** : chaque décision/action au ledger + section anti-masquage du rapport (ce qui a
  été simulé/refusé/jamais tenté). Zéro trou silencieux.
