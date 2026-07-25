# Premier déploiement — le wizard web

> [Sommaire](README.md) · Prérequis : [Installation](INSTALLATION.md) · Suivant :
> [Administration](ADMINISTRATION.md) · Voir aussi : [Configuration](CONFIGURATION.md)

**Rien n'est codé en dur.** Une install fraîche n'a **aucun admin, aucun scope réel, aucune source de
détection** : tout se provisionne **depuis le navigateur** au premier accès, via un wizard
**auto-désactivant**.

## Le flux

1. Ouvrir **`http://127.0.0.1:7100`** (ou l'URL du reverse-proxy). Le SPA appelle
   `GET /api/setup/state` :
   - `needs_setup:true` ⇒ le **wizard** s'affiche ;
   - `capabilities.sqlcipher` ⇒ l'UI sait si le chiffrement au repos est disponible (image
     `encryption`).
2. **Le wizard `POST /api/setup`** (route **PUBLIQUE mais auto-désactivante** : **409** dès qu'un
   admin activé existe). Seul l'admin est requis ; **le reste n'est persisté que s'il est fourni**.
3. La gate d'auth **s'engage** dès qu'un admin activé existe (l'état DB fait autorité). `/api/setup`
   se ferme définitivement. Le navigateur **atterrit connecté** (cookie `forge_session`,
   HttpOnly/SameSite=Strict).

## Les quatre volets du wizard

### 1. Créer l'admin *(requis)*
`admin_login` + `admin_password` → hash **argon2id**, rôle `admin`. Le mot de passe/hash n'est
**jamais** journalisé ni ledgerisé. C'est un **compte individuel nommé** : l'administration exige
ensuite une session admin (aucun repli par secret partagé).

### 2. Crypto *(automatique + capacité)*
- Le **ledger** est déjà signé **Ed25519** automatiquement — aucune action.
- Le **chiffrement au repos** dépend de l'**image** (`encryption`, cf.
  [Installation §6](INSTALLATION.md#6-image-encryption-chiffrement-au-repos--sqlcipher-opt-in)),
  surfacé via `capabilities.sqlcipher`. L'UI reflète honnêtement s'il est disponible.

### 3. Source de détection = **VOTRE infra** *(optionnel)*
`detection_source` — plugin **configurable, sans code** : FortiGate / pfSense / OPNsense / CrowdSec /
Elastic / OpenSearch / fichier / exec / Plume… Modèle, préréglages et mapping MITRE :
**[`DETECTION.md`](DETECTION.md)**. Réglable aussi plus tard dans *Administration → Source de
détection*. Le **secret d'auth est write-only** (jamais renvoyé/loggé). Laisser vide = boucle purple
inerte (fail-open lisible) — voir [Utiliser Forge en standalone](STANDALONE.md).

### 4. Politique opérateur *(optionnel)*
`operator_policy` — gouverne le rôle **opérateur/C2** (RBAC). Vide = C2 **fermé** (fail-closed).
Champ clé : `source_cidrs` (allowlist d'IP client autorisées à lancer un run). `session_ttl`
optionnel (substrat de config ; la TTL effective est pilotée par `FORGE_CONSOLE_SESSION_TTL`).

## Ce que le wizard persiste

| Champ | Où | Condition |
|---|---|---|
| Admin (login + hash argon2id, rôle admin) | table `users` | **toujours** |
| `operator_policy` | `settings.operator_policy` | si fourni (objet JSON) |
| `detection_source` | `settings.detection_source` (secret write-only) | si fourni (objet JSON) |
| `session_ttl` | `settings.session_ttl` | si entier positif fourni |

Ledger : `console.setup.provision` (attribution = le login admin ; **jamais** le mot de passe/hash).
La source de détection est **rechargée à chaud** si fournie.

## Provisioning headless (sans navigateur)

Pour un déploiement automatisé, poser dans `.env` / l'EnvironmentFile :

- `FORGE_CONSOLE_PASS_HASH` (hash argon2id viewer via `forge hashpw`),
- `FORGE_CONSOLE_OPERATOR_HASH` (hash argon2id opérateur via `forge hashpw-operator`),
- `FORGE_CONSOLE_TOKEN` (bearer d'ingestion).

L'état bascule alors `provisioned:true` sans wizard. Pour un **compte admin individuel** en headless :
`forge useradd <login> admin` (mot de passe sur STDIN). Voir [Configuration §1.2](CONFIGURATION.md#12-console--secrets-dauthentification--rbac).

## Après le wizard — RBAC

- **Comptes** : `/api/users` (admin) ou *Administration → Comptes*. Rôles `viewer` / `operator` /
  `admin` — voir [Administration](ADMINISTRATION.md).
- **Toutes les routes** (sauf `/health`, `/api/login`, `/api/setup*`) sont derrière **host-guard**
  (anti-rebinding) + **auth-guard**. Détail : [Modèle de sécurité](SECURITY_MODEL.md).

## Sécuriser l'exposition

La console bind `127.0.0.1:7100` par défaut. Pour l'exposer :
1. `FORGE_CONSOLE_ADDR=0.0.0.0:7100` (dans un réseau isolé) + mapping loopback + reverse-proxy ;
2. ajouter le nom d'hôte public au host-guard via `FORGE_CONSOLE_HOST` ;
3. **et** définir `FORGE_CONSOLE_PASS_HASH` (ou un compte activé) — ne jamais exposer le mode
   dev localhost-ouvert hors de la machine.

Si vous êtes derrière un proxy amont, configurer `settings.trusted_proxy` (CIDR du proxy) pour que
`X-Forwarded-For` soit honoré (sinon la politique source-CIDR verrait l'IP du proxy). Voir
[Configuration §2](CONFIGURATION.md#2-table-settings-configurée-dans-lui-ledgerisée).
