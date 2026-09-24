# Forge — Modules avancés (tous open, séparables, flag-gated)

Forge est **entièrement open source** sous **[AGPL-3.0-or-later](../LICENSE)** — le **produit entier**, **sans
édition payante ni fonctionnalité retenue derrière un paywall**. Le moteur complet de gouvernance et
d'audit cryptographique est open, et chaque capacité avancée ci-dessous l'est aussi.

**Ici, open source signifie le copyleft fort d'AGPL-3.0 — pas l'absence de règles.** Si vous exploitez un
Forge (modifié) comme service réseau, vous devez offrir sa **source correspondante** aux utilisateurs de ce
service (AGPL §13) ; toute **œuvre dérivée reste sous AGPL-3.0-or-later** ; et le **texte de la licence
ainsi que les mentions de copyright/attribution doivent être préservés**. La liberté de lire, exécuter,
modifier et partager vient **avec** les obligations qui la maintiennent — voir [`LICENSE`](../LICENSE) pour
les termes contraignants.

Ce que ce document décrit est une **stratification à l'intérieur de la base de code open**, pas une frontière commerciale :

> **Le cœur gouvernance + audit cryptographique est toujours actif.** Les capacités de **passage à
> l'échelle / équipe / conformité** sont livrées comme des **modules séparables, flag-gated** qui sont **OFF
> par défaut** — un point d'extension propre sur le cœur, jamais un fork de celui-ci, et jamais une gate qui
> affaiblit ou masque la surface open de gouvernance/audit. Activez-les quand vous en avez besoin ;
> laissez-les désactivées et le build est byte-identique au cœur.

Parce que tout est AGPL-3.0, quiconque peut exécuter Forge en solo ou sur de nombreux tenants, lire chaque
ligne de la machinerie de sécurité et d'audit, et vérifier que le ledger, le scope-guard et les oracles font
exactement ce qu'ils affirment. Cette transparence est l'enjeu : on ne peut pas faire confiance à un outil de
gouvernance red-team qu'on ne peut pas lire. (L'offre commerciale de GuatX, ce sont des **services** autour de
l'outil — engagements de référence, accompagnement purple, support/SLA, hébergement managé — jamais une
licence sur le code ; voir [`docs/PRICING.md`](PRICING.md).)

---

## Le cœur — toujours actif, aucun flag

Tout ce dont vous avez besoin pour exécuter Forge **en solo ou en petite équipe**, sur votre propre
infrastructure, sans coût et sans rien de désactivé :

- **Cœur de gouvernance**
  - **Scope-guard ROE** fail-closed (inerte par défaut ; in-scope vide = rien ne se déclenche ; `VETO` sur
    toute erreur d'évaluation).
  - **Ledger d'autorisation Ed25519 tamper-evident** (au moment de l'append, chaîné par hash, vérifiable
    publiquement à partir de la seule clé publique).
  - **Oracles orientés preuve** — les findings sont adossés à des preuves, pas affirmés.
- **Techniques**
  - Le **registre de techniques extensible** (declare-once → derive-everywhere) et **toutes les classes de
    techniques** livrées avec le cœur.
- **Exécution**
  - Le **flux de run gouverné C2-light** (arm → scope → capability → approve, chaque action gated et
    ledgerisée).
  - La **boucle purple** (findings + run-records ATT&CK alimentés côté détection et corrélés).
- **Console & accès**
  - L'**UI de la console + wizard de premier boot + RBAC** avec les trois rôles intégrés : **admin / operator /
    viewer**.
- **Intégration & infra**
  - **Connecteurs / orchestration** : nuclei, Metasploit (msf), Burp, et les autres intégrations d'outils
    embarquées.
  - **Détection infra-agnostique** (brancher n'importe quelle source BLUE — Plume, CrowdSec, FortiGate,
    pfSense/OPNsense, Elastic, file, exec — sans code).
  - **Sauvegarde / restauration chiffrée** (argon2id + XChaCha20-Poly1305, vérifiée par le ledger).
- **Échelle**
  - **Usage single-scope + petite équipe** — store SQLite mono-nœud, politique opérateur locale.

Si Forge tient sur un nœud et une petite équipe, le cœur est le produit entier. Rien de l'histoire de
sécurité ou d'audit n'est retenu — ni rien de ce qui suit.

---

## Les modules avancés — séparables, flag-gated, OFF par défaut

Ces capacités sont destinées aux organisations qui exploitent Forge à **l'échelle**, sur **de nombreuses
équipes / tenants**, ou sous **conformité formelle**. Ce sont des **modules séparables** construits par-dessus
le cœur ; le cœur n'en dépend jamais, et chacun n'est engagé que par un flag explicite. **Dans le build par
défaut, chaque flag est OFF ⇒ le comportement est byte-identique au cœur** (tous les tests existants verts).

- **Multi-tenant / MSSP** — de nombreux engagements/clients isolés sur un seul déploiement, avec **isolation
  cryptographique par tenant** (clés et ledgers séparés par tenant).
  - **Multi-tenance au niveau ligne** *(implémenté — `console/src/tenancy.rs`, flag-gated)* : une hiérarchie
    `TENANT ──< ENGAGEMENT ──< findings/runs` plus une map `tenant_grant(user_id, tenant_id, role)`. Un
    **filtre de tenant fail-closed** (deny-by-default, calqué sur le ROE) est appliqué par-dessus l'isolation
    d'engagement + RBAC existante : un utilisateur du tenant A ne peut **jamais** lister, lire, ou agir sur
    les engagements / findings / runs / roe / ledger / coverage / reports du tenant B — pas de grant ⇒ zéro
    ligne / 403. Il n'est engagé que par le flag **`FORGE_ENTERPRISE_TENANCY=1`** (ou la clé de config DB
    `enterprise.tenancy=on`). **Build par DÉFAUT : flag OFF ⇒ un unique tenant implicite #1, tous les
    utilisateurs y accèdent, comportement byte-identique** à l'avant-tenance (tous les tests existants
    verts). Le module est séparable — le cœur n'en dépend jamais.
  - **Super-admin audité (opérateur plateforme/MSSP)** *(implémenté — `console/src/tenancy.rs`)* : une
    capacité **NON-DÉSACTIVABLE**, **désignée au provisioning** (env `FORGE_SUPERADMIN` et/ou la clé de
    provisioning DB `enterprise.superadmin` — jamais une route UI normale) qui peut **LIRE à travers TOUS les
    tenants**. Elle est fail-closed (aucune désignation ⇒ personne n'est super-admin ; exige une session
    `admin` individuelle valide), le compte **ne peut être ni désactivé / supprimé / rétrogradé** via le CRUD
    de compte, et **chaque lecture cross-tenant est ledgerisée `console.superadmin.access`** (tenant + quoi).
    Elle accorde le cross-tenant **EN LECTURE SEULE** — l'écriture/le run cross-tenant reste lié aux grants
    natifs (un `tenant_admin` normal ne peut jamais franchir les tenants). Reflète le super-admin audité
    non-désactivable de Plume.
  - **CRUD tenant + gestion des grants** *(implémenté — `console/src/tenancy.rs`)* : créer / renommer /
    archiver des tenants et lister / ajouter / retirer le `tenant_grant` d'un utilisateur, gaté à un
    **platform-admin** (une session `admin` de console ou un super-admin) et ledgerisé **`console.tenant.*`**.
    Gardes fail-closed : ne jamais archiver le **dernier tenant actif**, ne jamais retirer le **dernier grant
    `tenant_admin`** d'un tenant. Dans le build par défaut, la surface est fermée (`403 enterprise_disabled`).
  - **Ledger cryptographique par tenant** *(implémenté — `console/src/tenancy.rs`)* : les ledgers
    d'engagement de chaque tenant sont regroupés sous un sous-répertoire clé-par-tenant
    (`tenant-<tid>/engagement-<eid>.jsonl`), gardant la **signature Ed25519 par-ledger inchangée** — juste
    scopée par tenant. Le build par défaut (flag OFF) conserve le chemin plat historique (byte-identique).
  - **UI tenant flag-gated** *(implémenté — SPA + `console/src/tenancy.rs`)* : le SPA de la console expose la
    surface tenant **uniquement quand le flag est ON**. Une sonde en lecture seule `GET /api/tenancy` (servie
    par le module séparable) renvoie `{"enabled": false}` dans le build par défaut → le SPA n'affiche **aucun
    sélecteur de tenant, aucune vue admin `#tenants`, aucun lien de nav** (shell single-tenant,
    byte-identique). Une fois activée, elle renvoie les tenants accessibles à l'appelant (super-admin ⇒ tous)
    et pilote : un **sélecteur de tenant** dans l'en-tête **au-dessus du sélecteur d'engagement** (hiérarchie
    tenant → engagement, filtrant la liste des engagements au tenant actif), et une **vue admin `#tenants`**
    (créer / renommer / archiver des tenants, gérer les grants utilisateur) montrée uniquement à un
    **platform-admin**. Le serveur reste l'autorité (filtre fail-closed + gates `403`) ; le gating de l'UI est
    de la défense en profondeur.

**Comment activer.** Poser le flag **`FORGE_ENTERPRISE_TENANCY=1`** (env) *ou* la clé de config par-DB
**`enterprise.tenancy=on`** ; désigner le(s) opérateur(s) de plateforme via **`FORGE_SUPERADMIN`** (env) ou la
clé de provisioning **`enterprise.superadmin`** (logins séparés par virgule/espace — jamais une route UI
normale). Avec le flag OFF (le **défaut**), Forge est un **unique tenant implicite #1** où tous les
utilisateurs ont un accès complet et un comportement **byte-identique** à l'avant-tenance (tous les tests
existants verts). La fonctionnalité entière est un **module séparable** — `console/src/tenancy.rs` (+ un
câblage minimal `mod tenancy;` dans `main.rs`) ; le cœur n'en dépend jamais.
- **Identité à l'échelle** — **SSO / SCIM** (login SAML/OIDC, provisioning/déprovisioning automatisé des utilisateurs).
  - **Login SSO OIDC** *(implémenté — `console/src/sso.rs`, flag-gated)* : un flux de login **Authorization-Code + PKCE**
    contre n'importe quel provider OIDC. `GET /api/sso/login` redirige vers l'endpoint `authorize` de l'IdP
    avec un **state + nonce + challenge PKCE `S256`** côté serveur (persisté par pending-auth) ; `GET
    /api/sso/callback` valide le state, échange le code (+ `code_verifier`) contre des tokens, et **valide
    entièrement l'ID token** — **signature RS256 via la JWKS de l'IdP** (`jsonwebtoken`/`ring` pur-Rust, **pas
    d'openssl**), **issuer**, **audience == `client_id`**, **exp**, et le **nonce**. En cas de succès, il mappe
    le `sub`/`email` OIDC vers un utilisateur Forge (**appariement d'un existant** ou **auto-provisioning**
    avec un rôle par défaut configuré et un mot de passe local inutilisable) et émet **le même cookie
    `forge_session`** que le login local (HttpOnly / SameSite=Strict). La config du provider (`GET/POST
    /api/sso/config`) est **admin-gated**, supporte la **discovery OIDC**
    (`{issuer}/.well-known/openid-configuration`), et le **`client_secret` est write-only** (rédigé au GET).
    **Fail-closed** : toute divergence de state / nonce / issuer / audience / signature / exp est rejetée
    (403) ; le navigateur n'est jamais redirigé que vers une cible de retour **allowlistée** (reflète la
    discipline anti-open-redirect `oauth.flow` / `redirect.open`) ; le `client_secret` et les tokens ID/access
    ne sont **jamais loggés, ledgerisés, ni renvoyés** ; chaque login est ledgerisé `console.sso.login`
    (acteur + sujet seulement). Il n'est engagé que par **`FORGE_ENTERPRISE_SSO=1`** (ou la clé de config DB
    `enterprise.sso=on`). **Build par DÉFAUT : flag OFF ⇒ `/api/sso/*` est désactivé (404) et les comptes
    LOCAUX se comportent de façon byte-identique** à aujourd'hui (tous les tests existants verts). Le module
    est séparable — `console/src/sso.rs` (+ une ligne `mod sso;` et un merge de route dans `main.rs`) ; le
    cœur n'en dépend jamais.
  - **Provisioning SCIM 2.0** *(implémenté — `console/src/scim.rs`, flag-gated)* : provisioning +
    déprovisioning automatisé des utilisateurs/groupes depuis un IdP (Okta / Azure AD). `GET/POST /scim/v2/Users`,
    `GET/PUT/PATCH/DELETE /scim/v2/Users/:id`, et `/scim/v2/Groups` implémentent le schéma core SCIM 2.0
    (`userName`, `active`, `emails`, `name`, `externalId`). Il est authentifié par un **bearer token SCIM**
    — un long token aléatoire qu'un admin génère via `GET/POST /api/scim/config` (admin-gated) — qui est un
    **secret** : stocké **haché** (SHA-256, comme un token de session — jamais le token brut), comparé en
    **temps constant**, et renvoyé **une seule fois** à la rotation (rédigé ensuite). Ce n'est **pas** une
    session normale (un IdP n'a pas de `forge_session`) ; **fail-closed** : token absent/invalide/non-configuré ⇒ **401**.
    Mapping vers Forge : créer / activer un utilisateur SCIM **crée / active** un utilisateur Forge (avec un
    **rôle par défaut scopé** — viewer, **jamais** admin, **jamais** super-admin — et un mot de passe local
    inutilisable) ; **désactiver** (`active=false`) ou **DELETE** **désactive l'utilisateur et purge ses sessions**
    (révocation immédiate) ; l'appartenance à un groupe mappe vers un rôle scopé / tenant-grant (lié au RBAC
    avancé, borné à viewer|operator). Un **login super-admin désigné est protégé** — SCIM refuse de le créer /
    désactiver / supprimer (403). Chaque mutation est ledgerisée `console.scim.*` (métadonnées seulement —
    login / externalId / active / booléens, **jamais le token**). Il n'est engagé que par **`FORGE_ENTERPRISE_SCIM=1`**
    (ou la clé de config DB `enterprise.scim=on`, ou le flag SSO). **Build par DÉFAUT : flag OFF ⇒ `/scim/*` et
    `/api/scim/config` sont désactivés (404) et les comptes LOCAUX se comportent de façon byte-identique** à
    aujourd'hui (tous les tests existants verts). Le module est séparable — `console/src/scim.rs` (+ une ligne
    `mod scim;` et un merge de route dans `main.rs`) ; le cœur n'en dépend jamais.
  - **RBAC avancé — mapping groupe-IdP → {rôle, tenant grant}** *(implémenté — `console/src/rbac.rs`,
    flag-gated)* : un mapping CONFIGURABLE d'un nom de groupe IdP vers un résultat d'autorisation Forge —
    `idp_group → { role: viewer|operator|admin, tenant_id?, tenant_role? }`. **À la fois** le chemin de login
    SSO OIDC (le claim `groups` de l'ID-token) **et** le chemin d'appartenance de groupe SCIM consultent cette
    UNIQUE table, si bien qu'un admin configure groupe → accès en un seul endroit (`GET/POST /api/rbac/group-map`,
    `DELETE /api/rbac/group-map/:group` — **admin-gated**, ledgerisé `console.rbac.*`). Il remplace l'ancienne
    heuristique best-effort sur `displayName` ; quand aucun mapping n'est configuré, le comportement est
    byte-identique à avant. **FAIL-CLOSED / least-privilege** (en affaiblir un fait passer un test au ROUGE) :
    une identité SSO/SCIM n'obtient **QUE** ce que son mapping de groupe confère — aucun groupe correspondant ⇒
    `role: None` ⇒ l'identité conserve son propre défaut least-privilege (`viewer` au plus), jamais davantage.
    **JAMAIS super-admin via SSO/SCIM** — le super-admin est une désignation *au provisioning uniquement* (voir
    `tenancy.rs`), n'est pas une valeur `users.role`, et ne peut pas être exprimé dans la table ; un login
    super-admin désigné n'est en outre jamais re-rôlé/re-granté par SSO/SCIM. Les rôles sont validés à
    `viewer|operator|admin` et les rôles de tenant à `tenant_admin|tenant_operator|tenant_viewer` (tout le
    reste — y compris `super_admin` — est rejeté au moment de la config). Quand plusieurs groupes mappés
    correspondent, le **rôle le plus élevé l'emporte** (plafonné à admin) ; **SCIM clampe en plus admin → operator**
    (le provisioning de masse automatisé ne confère jamais automatiquement l'admin de console). Les tenant
    grants ne sont posés que lorsque la **multi-tenance** est également engagée. Il est engagé dès que
    **SSO ou SCIM** est engagé (`rbac::enabled()` = `sso::enabled() || scim::enabled()`).
    **Build par DÉFAUT : les deux flags OFF ⇒ `/api/rbac/*` est désactivé (404), la table de mapping n'est
    jamais créée, et l'assignation de rôle reste admin-only exactement comme aujourd'hui** (tous les tests
    existants verts). Le module est séparable — `console/src/rbac.rs` (+ une ligne `mod rbac;` et un merge de
    route dans `main.rs`) ; le cœur n'en dépend jamais.
  - Le login **SAML** est encore sur la roadmap (un suivi FUTUR documenté — **OIDC couvre le cas commun** ;
    SAML réutiliserait le même mapping groupe → rôle/tenant dans `rbac.rs`).
- **Autorisation avancée (pour aller plus loin)** — les **rôles composables/personnalisés** au-delà
  d'admin/operator/viewer, et les **grants par-engagement à durée limitée**, s'appuient sur le mapping
  `rbac.rs` ci-dessus (roadmap).
- **Haute disponibilité & échelle** — **HA / clustering / store distribué** (Postgres au lieu de SQLite
  mono-nœud), scale-out horizontal.
- **Conformité — legal-hold / rétention WORM** *(implémenté — `console/src/compliance.rs` +
  `forge/compliance_signer.py`, flag-gated)* : une **politique de rétention** (une durée de rétention
  configurable pour l'audit trail + findings/runs) réglable **par global / par tenant / par engagement** (le
  plus spécifique l'emporte), et un flag **legal-hold** (par global/tenant/engagement) qui **bloque toute
  suppression/purge indépendamment de la rétention** — **le hold l'emporte toujours** (fail-closed).
  **Enforcement WORM** : tant qu'un enregistrement de ledger est sous rétention *ou* sous legal-hold, il **ne
  peut être ni supprimé, ni altéré, ni purgé**. Une **purge gouvernée** (`POST /api/compliance/purge`, admin)
  n'est autorisée **que** lorsque la rétention a **expiré** **et** qu'il n'y a **aucun hold**, et elle **ne
  supprime jamais en silence** : elle (a) **archive d'abord le segment expiré — chiffré**, en réutilisant la
  discipline de backup (`backup_encrypt`, XChaCha20-Poly1305 + argon2id), puis (b) **ré-ancre** le ledger et
  enregistre un **événement de ledger checkpoint signé `console.compliance.purge`** (comptes, SHA-256 du
  segment, SHA-256 de l'archive chiffrée, head purgé, heure, acteur). La **chaîne restante demeure vérifiable**
  sous le vérifieur **existant** (`crate::verify_ledger_chain`) *et* le `Ledger.verify` Python — le contenu
  audité des entrées survivantes est préservé byte-pour-byte (seuls leurs `prev`/`hash` sont re-liés), de
  sorte que **le tamper-evidence et la vérification Ed25519 sont intacts**. **Coin fail-closed** : une purge
  **refuse** (409 `signed_survivor`) si une entrée *survivante* est signée Ed25519/HMAC (la re-hacher
  casserait sa signature) et **refuse** (400) si aucune clé d'archive n'est configurée (jamais de suppression
  irrécupérable). Le **signeur de checkpoint pluggable** (`forge/compliance_signer.py`) garde la **vérification
  byte-identique** à `signing.verify_with_pubkey` et expose un **seam KMS/HSM** (`CallableComplianceSigner`)
  pour qu'un signeur ancré matériellement se branche sans changer le chemin de vérification. Il n'est engagé
  que par **`FORGE_ENTERPRISE_COMPLIANCE=1`** (ou la clé de config DB `enterprise.compliance=on`). **Build par
  DÉFAUT : flag OFF ⇒ chaque route `/api/compliance/*` est désactivée (404), WORM/rétention/hold sont inertes,
  et le ledger + les données d'engagement sont byte-identiques** (tous les tests existants verts). Le module
  est séparable — `console/src/compliance.rs` (+ une ligne `mod compliance;`, un merge de route, un flag SPA,
  et un garde WORM de suppression/archivage flag-gated dans `main.rs`) ; le cœur n'en dépend jamais.
- **Conformité — signeur de ledger pluggable (KMS/HSM/clé distante)** *(implémenté — `forge/signing.py`,
  flag-gated)* : la **clé privée Ed25519** du ledger d'audit **peut vivre OFF-HOST** — dans un KMS/HSM, un
  endpoint de signeur distant, ou un **helper `exec` no-shell** — de sorte que la clé privée **n'atterrit
  jamais sur disque**. Sélectionné par config (`FORGE_LEDGER_SIGNER` = `local` | `kms` | `hsm` | `http` |
  `remote` | `exec`, plus `FORGE_LEDGER_SIGNER_{ENDPOINT,CREDENTIAL,PUBKEY,ARGV,TIMEOUT}`) et gaté par
  **`FORGE_ENTERPRISE_COMPLIANCE=1`**. Un `RemoteSigner` produit une **signature Ed25519 standard sur les
  mêmes octets**, de sorte que **la vérification est INCHANGÉE** — `Ledger.verify` /
  `Ledger.verify_external(pubkey)` / `signing.verify_with_pubkey` l'acceptent avec la **seule clé publique**,
  byte-identique quel que soit le signataire. **Fail-closed & sans repli** : un signeur distant
  injoignable/mal configuré/qui ne vérifie pas **lève `RemoteSignerError`** et l'append avorte — Forge
  **n'écrit jamais** d'entrée non signée ou non sûre et **ne se rabat jamais** en silence sur la clé locale
  (un signeur distant demandé sans le flag est refusé). **Secrets** : l'endpoint/credential/argv sont
  **rédigés** (`redact_signer_config`) et jamais loggés/ledgerisés/fuités (pas même dans les messages
  d'erreur ou `repr`) ; le signeur `exec` est **no-shell** (argv fixe, configuré par l'admin — une chaîne
  shell est rejetée). **Build par DÉFAUT** : rien de configuré ⇒ `make_ledger_signer` renvoie le
  **`LocalFileSigner`** (la clé sur disque `<ledger>.ed25519`) — **byte-identique à avant** (tous les tests de
  ledger existants verts). Séparable — le seam entier est additif dans `forge/signing.py` (`LocalFileSigner`,
  `RemoteSigner`, `make_ledger_signer`) ; le chemin par défaut du cœur est inchangé.
- **Conformité — export d'évidence SOC 2 / ISO 27001** *(implémenté — `console/src/compliance.rs`,
  flag-gated)* : un bundle d'évidence en **lecture seule** pour un **tenant / engagement / intervalle de
  temps**, assemblé à partir de l'état **existant** ledger + RBAC + backup (il **ne mute jamais** aucune
  donnée). Il contient l'**audit trail d'autorisation** (qui a autorisé quoi, quand, sur quel scope — extrait
  du ledger tamper-evident), l'**état RBAC / grant** (comptes de console, tenant grants, mappings groupe
  IdP→rôle pour *ce* tenant), le **log d'accès / de mutation**, l'**attestation de backup** (restauration-**prouvée**,
  depuis le ledger de la console), et l'**attestation d'intégrité du ledger** — **hash du head + clé publique
  Ed25519 + résultat de la vérification de chaîne + une commande externe `forge ledger verify`** (la
  vérification n'a besoin que de la **seule clé publique** ; aucun secret n'est inclus).
  `GET /api/compliance/evidence?engagement_id=&format=json|html|pdf&from=&to=` (admin) renvoie du **JSON** ou un
  **HTML lisible par un humain** (le HTML **dégrade vers `?format=html` + impression-vers-PDF** quand aucun
  moteur PDF n'est présent sur l'hôte — même seam `render_pdf_from_html` que le rapport brandé). Le bundle est
  **isolé par tenant/engagement** (seulement le ledger + les comptes de cet engagement, seulement les grants de
  ce tenant) et **secret-rédigé** de bout en bout (passphrases / tokens / credentials / `client_secret` / clés
  privées → `[REDACTED]` ; **les clés publiques sont préservées**). L'**acte d'exporter est lui-même ledgerisé**
  (`console.compliance.evidence.export` — acteur, scope, format, head du ledger, chain-ok). Engagé uniquement
  par **`FORGE_ENTERPRISE_COMPLIANCE=1`** (ou la config DB `enterprise.compliance=on`) ; **build par défaut
  (flag OFF) ⇒ la route renvoie 404 et rien ne change**.
- **Conformité (pour aller plus loin)** — les **clés adossées à un KMS/HSM** sont désormais disponibles à la
  fois pour le **signeur de ledger d'audit** (`forge/signing.py` `RemoteSigner`, ci-dessus) et le **signeur de
  checkpoint de conformité** (`forge/compliance_signer.py` `CallableComplianceSigner`) ; le **chiffrement**
  ancré matériellement (backup/archive au repos) est le seam restant.

---

## Principe de conception pour les contributeurs

En ajoutant une capacité, demandez-vous **à quelle couche elle appartient** — les deux couches sont open
AGPL ; la question est de savoir si c'est du cœur toujours-actif ou un module séparable flag-gated :

- Rend-elle la **gouvernance ou l'audit trail cryptographique** plus fort, plus vérifiable, ou utilisable par
  un opérateur solo / une petite équipe ? → **elle appartient au cœur toujours-actif.**
- Est-elle fondamentalement une affaire de **passage à l'échelle, multi-tenance, identité-à-l'échelle, HA, ou
  conformité formelle** ? → c'est un **module avancé**, et il doit être construit **séparable** — un point
  d'extension propre sur le cœur, OFF par défaut, jamais un fork de celui-ci, et jamais une gate qui affaiblit
  ou masque la surface open de gouvernance/audit.

La règle de pouce : **la crédibilité (gouvernance + audit crypto) est toujours active ; l'échelle/équipe/conformité
est un interrupteur qu'on bascule.** Rien n'est jamais payant ni caché — l'offre commerciale, ce sont des
**services**, pas le code (voir [`docs/PRICING.md`](PRICING.md)).
