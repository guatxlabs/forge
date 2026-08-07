# Changelog

All notable changes to Forge are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Forge aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first tagged release.

> Forge is pre-1.0: the public API, module kinds, and config surface may still change between
> minor versions. Breaking changes will be called out here.

## [Unreleased]

### Added
- **Une CA privée d'entreprise devient vérifiable — sans lire le magasin système, et sans relâcher un
  seul contrôle** (`FORGE_EXTRA_CA_PEM` / `FORGE_EXTRA_CA_PEM_FILE`). Le seam TLS livré juste avant
  vérifie contre les racines **Mozilla compilées** ; le magasin de CA du **système n'est pas lu**, et
  c'est exactement ce qui évite `schannel`, `security-framework` et `openssl`. Cette posture avait un
  prix documenté : un déploiement dont l'IdP OIDC ou le collecteur est signé par **sa propre AC**
  n'avait que de **mauvaises** issues — dont le **retour au clair**, précisément ce que « pas de clair »
  refuse.

  **La distinction est tout le sujet.** Ce knob **AJOUTE une ancre** que l'opérateur **fournit
  explicitement** ; il ne **retire aucun contrôle**. La chaîne est toujours validée jusqu'à une ancre, le
  **nom d'hôte** toujours vérifié, l'**expiration** toujours honorée. `with_root_certificates` accepte des
  ancres supplémentaires **sans jamais toucher** à l'API `dangerous` de rustls — la garde de **source**
  qui interdit au crate de l'ouvrir reste **verte**, inchangée.

  **Prouvé par un COUPLE, pas par une affirmation.** Le test de rejet existant (fixture AC non fiable +
  feuille signée) reste rouge-quand-muté, et **quatre** tests l'encadrent : la **même** AC fournie en PEM
  fait **ABOUTIR** le handshake (le knob opère) ; une **AUTRE** AC le laisse **ÉCHOUER** (il vérifie, il
  ne gobe pas) ; le **nom d'hôte** hors SAN est refusé **ancre en place** ; une feuille **EXPIRÉE** signée
  par l'ancre fournie est refusée **ancre en place**, avec pour contre-exemple la **même** ancre + le
  **même** sujet + le **même** SAN sur une feuille **non expirée**, qui aboutit — la seule variable entre
  les deux moitiés étant la fenêtre de validité.

  **Fail-closed au boot** : un PEM configuré mais illisible, vide ou invalide **tue le démarrage**
  (`[forge] FATAL`, code 2), il ne dégrade **jamais** vers « pas d'ancre » — sinon l'opérateur croirait sa
  CA installée et découvrirait le contraire au premier handshake, sous un « émetteur inconnu » qui ne
  désigne pas la cause. C'est la **seule** différence assumée avec le motif maison `secret_env`, qui est
  fail-**soft** par contrat. Rien de configuré ⇒ **aucune** ligne au boot. **Zéro nouvelle dépendance**
  (le parseur PEM est déjà dans `rustls-pki-types`) ; openssl-freedom du build PAR DÉFAUT vérifiée par commande (**0** hit).

- **Les trois derniers secrets en clair au repos sont scellés — mais la faillibilité d'abord.** Le jeton
  de **source de détection**, le jeton de **canal de notification** et le **`client_secret` SSO** vivaient
  en clair dans `settings`. Ils avaient été écartés du premier lot de chiffrement de champ pour une raison
  technique **réelle**, consignée : les sceller **exige** de rendre faillibles `ds_secret`, `ch_secret` et
  `sso::load_config` — or ce dernier rendait un **`Option`**, où un déchiffrement raté serait devenu
  « **SSO non configuré** », soit la **dégradation silencieuse** que tout ce travail interdit.

  L'ordre imposé a été suivi. **(1) Faillibilité, avec un échec LISIBLE** : `sso::load_config` rend
  désormais `Result<Option<SsoConfig>, String>` — **trois** issues distinctes : `Ok(None)` = non configuré
  (**403** `sso_unconfigured`), `Ok(Some)` = utilisable, `Err` = **configuré mais illisible** (**503**
  `sso_secret_unreadable`). Les deux autres secrets sont ouverts à leur **point d'usage unique**
  (`collect_detections_with`, `deliver_blocking`) : sans clé, l'intégration **refuse de partir** avec une
  raison nommée, au lieu de se présenter **sans authentification** — un 401 que l'admin diagnostiquerait
  comme une panne de SIEM. **(2) Scellement** : `field_crypto` réutilisé tel quel — **même** clé
  (`FORGE_FIELD_KEY`), **même** enveloppe `forge:fenc1:`, **aucune** ré-implémentation d'AEAD.

  **Illisibilité prouvée SUR LES OCTETS DU DISQUE** (fichier `.db` + `-wal` + `-shm`), avec son
  contre-exemple : la **même** sonde, sur la **même** base, **trouve** les canaris quand les mêmes valeurs
  sont écrites sans scellement — sans quoi « absent » pourrait l'être pour la mauvaise raison. Une base
  existante est **convertie au boot**, en place et idempotemment ; sans clé, rien n'est converti mais le
  clair restant est **compté et annoncé** — jamais tu. Périmètre **mesuré** : seule la **valeur** du
  secret est scellée ; `kind`, `endpoint`, `auth.type`, `issuer`, `client_id` restent lisibles (l'admin
  doit pouvoir ré-éditer sa config sans la clé, et ce ne sont pas des credentials).
- **Le préchauffage intra-vague sait enfin ce qu'est une action LENTE — il la MESURE.** L'ordonnancement
  des soumissions (`engine._preheat_order`) estimait la lenteur avec `action.cost`, parce que c'était le
  seul porteur EXISTANT. Or `cost` est une donnée de **gouvernance** (le prix qu'on accepte de payer),
  pas une mesure de **durée** : les deux corrèlent souvent, rien ne le garantit — et le cerveau ne
  renseigne un coût explicite que pour les kinds de sa table, **tout le reste part au défaut 1.0**, y
  compris des modules réellement lents. Le résidu était consigné avec son bloqueur : « ni le ledger ni
  les run-records n'horodatent à mieux que la seconde ». C'est ce bloqueur qui est levé.

  **Instrumentation** : `engine._decide_blocking` chronomètre le **tir** à l'horloge **monotone**
  (`time.monotonic`, jamais l'heure murale). Le **dry-run n'est PAS chronométré**, délibérément :
  `dry()` est sans effet de bord par contrat, donc quasi instantané — mesurer une campagne non armée
  apprendrait que `web.testssl` prend 3 ms et **empoisonnerait** le magasin. **Prix mesuré, pas
  affirmé** : `1,23 µs` par observation en boucle serrée, et un écart **sous le bruit** (`-0,1 ms` sur
  24 tirs) en mur-à-mur — à comparer à des **secondes** pour un vrai outil.

  **Stockage — l'agrégat est PAR KIND, JAMAIS PAR CIBLE** (`forge/durations.py`). Ce n'est pas une
  contrainte subie : un magasin de durées par-cible serait un **journal de reconnaissance persistant
  après l'engagement** (« combien de temps l'hôte X a mis à répondre »), et le préchauffage n'a de toute
  façon besoin que du kind. La garde est **structurelle** — `record()` refuse toute clé qui n'est pas un
  identifiant de module, à l'écriture comme à la relecture d'un fichier trafiqué — et **prouvée sur les
  octets écrits**, pas sur l'API. Taille **bornée** : ≤ 256 kinds (éviction déterministe), agrégat de
  **taille fixe** par kind (compteur + anneau de 8 durées) — 10 000 tirs n'écrivent pas un octet de plus
  que 10.

  **Confiance sans modèle** : sous 3 observations, le kind n'a **pas** d'estimation (n=1 est du bruit) ;
  au-delà, c'est la **médiane** de l'anneau (un tir qui échoue en 3 ms ne fait pas passer un kind lent
  pour rapide), **quantifiée** à un chiffre significatif pour que deux kinds de lenteur comparable
  restent dans le **même palier** — sans quoi la règle « palier complet ou rien » scinderait le groupe
  d'actions lentes qu'elle existe pour protéger. Pas d'apprentissage, pas de seuil réglable.

  **Repli EXACT** : sans magasin, ou avec un magasin sans aucune observation, `_preheat_key` rend
  `action.cost` pour toute action — **mêmes paliers, même ordre, comportement d'avant à l'identique**.
  C'est la première propriété testée, et sa mutation (casser le repli) rougit.

  **Gain mesuré, et dit honnêtement** (`tests/bench_engine_parallel_order.py`, pool=4, 5 répétitions,
  deux invocations indépendantes, dispersion intra-série ≤ 1,3 %) : sur les formes où `cost` **dit
  vrai**, la durée observée ne rapporte **RIEN** — `straggler` 1,84 s → 1,83/1,84 s (dans le bruit),
  `queue-large` et `uniform` inchangés. Elle ne rapporte **que** là où
  `cost` **ment** — nouvelle forme `cost-lies` (un module lent resté au coût par défaut, un module
  rapide sur-annoté) : `index` 1,88 s, `cost` **1,92 s** (le préchauffage par coût est alors **pire que
  ne rien faire**), **observed 1,60 s** — soit **-16,8 %** contre le coût et **1,05x** le plancher
  travail/pool au lieu de 1,26x. Le gain réel de ce chantier n'est donc pas « c'est plus rapide », c'est
  « l'ordonnancement ne dépend plus d'une donnée qui n'a jamais promis d'être une durée ».

  **Invariants intacts** : l'ordre d'**APPLICATION** ne bouge pas (ledger/findings/décisions identiques
  au sériel, chaîne vérifiée des deux côtés), seul l'ordre de **SOUMISSION** change ; scope, ROE et
  ledger restent fail-closed ; **zéro nouvelle dépendance**. Le magasin est **gelé** pour la durée d'un
  run : deux runs sur le même magasin préchauffent à l'identique (le prix assumé : c'est le run
  **suivant** qui profite des mesures, pas les vagues suivantes du même run).
- **Chiffrement au repos du matériel d'authentification — dans le build PAR DÉFAUT, sans OpenSSL.** Le
  volet réseau venait d'être fermé (seam TLS) ; restait le repos. `docs/DEPLOYMENT.md` §1.5 le concédait :
  le build par défaut stocke la base **en clair**, et cette base porte désormais le **contexte auth
  par-engagement** — bearers, cookies et valeurs d'en-tête des **comptes de test** de l'opérateur,
  c'est-à-dire des **sessions authentifiées sur l'estate d'un client**. Le chiffrement intégral existait
  (feature `encryption`) mais exige un **backend crypto système/openssl à la compilation** : l'activer par
  défaut aurait cassé l'openssl-freedom.

  **Chiffrement de CHAMP** (`console/src/field_crypto.rs`) avec la pile AEAD **pur Rust déjà embarquée**
  (`chacha20poly1305` + `argon2`, deps non optionnelles — celles des sauvegardes) : **ZÉRO nouvelle
  dépendance**, openssl-freedom du build PAR DÉFAUT **vérifiée à 0 occurrence** après coup. La KDF argon2id et le cœur AEAD
  ont été **EXTRAITS** de `backup_crypto.rs` (`aead_seal`/`aead_open`) plutôt que réécrits — il n'existe
  qu'**une** implémentation de crypto symétrique dans la console, et elle a maintenant un test de contrat
  sur le **lien AAD** (la preuve par mutation a montré qu'aucun test n'en dépendait).

  **Un seul goulot d'écriture** : `validate_engagement_scope` produit la chaîne `scope_json` persistée,
  donc sceller là rend structurellement impossible d'écrire un credential en clair par un chemin oublié.
  **Un seul point d'ouverture** : le `scope.json` **0600** du run. Entre les deux, le matériel reste
  chiffré — y compris dans le blob `run_job.spawn_spec` du chemin HA *pending*, qui devient donc chiffré
  au repos lui aussi, en plus d'être purgé au claim.

  **Périmètre MESURÉ** : scellés `bearer` / `cookies` / **valeurs** d'en-tête. Laissés en clair, à dessein,
  les `label`, les **noms** d'en-têtes et les `idor_targets` — l'API les re-sert **déjà** en clair à
  l'éditeur, donc les sceller rendrait l'éditeur illisible sans la clé **sans protéger un seul credential**.
  `users.pass_hash` (argon2id) et `session.token_sha` (SHA-256) ne sont **pas** chiffrés : ce sont des
  empreintes à sens unique, pas du matériel rejouable.

  **FAIL-CLOSED, sans dégradation silencieuse** — on venait de corriger un bug où le contexte auth
  s'effaçait en silence, et ça a coûté une campagne : (1) **aucun contexte auth ⇒ aucune clé requise**
  (no-op strict, payloads inchangés) ; (2) **écrire du matériel sans clé ⇒ `503 field_key_missing`**
  nommant la variable — jamais de credential persisté en clair « en attendant » ; (3) **matériel scellé
  illisible ⇒ le run REFUSE de démarrer** (`auth_context_sealed`) plutôt que de partir avec un `auth`
  vide qui désarmerait les oracles de contrôle d'accès sans le dire.

  **Migration traitée, pas ignorée** : les bases existantes sont **scellées en place au boot**
  (idempotent, rejouable, compté). Sans clé, rien n'est converti et le boot le **crie** — donner
  l'illusion du chiffrement serait pire que le clair assumé. L'état est aussi lisible **dans le produit**
  (`auth.at_rest` ∈ `sealed|plaintext|mixed|none`).

  **Clé** : `FORGE_FIELD_KEY`, via le motif maison `<VAR>_FILE` déjà supporté. **Custody** : c'est un
  secret à conserver **avec** la passphrase de sauvegarde — une base restaurée sans lui est intacte mais
  son matériel reste scellé (round-trip sauvegarde vérifié). Perdre la clé ne perd **aucune autre donnée** :
  il suffit de ressaisir le matériel. Les deux couches **composent** (`--features encryption` par-dessus
  reste valide). Docs : `DEPLOYMENT.md` §1.6, `CONFIGURATION.md` §1.4, `KEY_CUSTODY.md`.
- **Seam TLS sortant — la console parle `https://`, et le vérifie.** La console avait exactement trois
  sorties TCP, toutes en socket brut, donc **en clair** : l'échange de jeton OIDC (`sso/mod.rs`), le
  webhook de notification (`notify_channels.rs`) et le fetcher de source de détection (`net.rs`). La plus
  grave était la première : le POST au token endpoint porte le **`client_secret`**
  (`Authorization: Basic`) **et** le **`code`** d'autorisation — `docs/DEPLOYMENT.md` le concédait et
  prescrivait un **proxy TLS d'egress** en contournement.

  **Un seul point de sortie** (`console/src/tls.rs`), partagé par les trois : clair (**gouverné**) ou TLS
  avec **vérification complète du certificat** — chaîne jusqu'aux racines Mozilla (`webpki-roots`) **et**
  nom d'hôte —, le **handshake aboutissant avant le premier octet applicatif**. Face à un pair non prouvé,
  l'appelant n'obtient aucun flux, donc n'écrit aucun secret. **Aucune échappatoire de vérification** n'est
  livrée : ni option, ni ENV, ni feature ; une garde de source interdit au crate d'ouvrir l'API dangereuse
  de rustls. Le contournement par proxy TLS est **caduc** ; Slack / Teams / PagerDuty deviennent joignables
  ; une source de détection `https` est servie **en Rust**, sans spawn Python sur une route de lecture.

  **Les gardes existantes restent.** La deny-list SSRF s'applique à l'IP **résolue**, en `http://` comme en
  `https://` (chiffrer un fetch vers `169.254.169.254` n'en fait pas une cible légitime). Le refus
  « secret + cible publique en clair » s'**assouplit exactement** : autorisé en `https://`, toujours refusé
  en `http://`. Le clair vers un collecteur **interne** explicitement autorisé est inchangé.

  **Pas de SMTP** — refusé indépendamment du TLS : STARTTLS est une élévation **négociée** (classe
  d'injection de commandes en clair, CVE-2011-0411 et sa descendance) et le SMTP réel se pratique en TLS
  opportuniste contre des relais auto-signés. **Pas de lecture du magasin d'AC système** — une AC
  d'entreprise n'est donc pas reprise AUTOMATIQUEMENT ; elle se fournit explicitement (cf. plus bas,
  `FORGE_EXTRA_CA_PEM`). Le **mTLS**, annoncé absent dans une version antérieure de cette entrée, est
  livré plus bas dans cette même release non publiée.

  **Coût : 6 crates nets** (`ring`, `rustls`, `rustls-pki-types`, `rustls-webpki`, `untrusted`,
  `webpki-roots`), ≈ +20 s CPU à froid, **aucun nouveau prérequis machine** (`ring` compile de l'asm/C via
  `cc`, déjà exigé par `rusqlite/bundled`). **openssl-freedom préservée et vérifiée par commande** : aucun
  `openssl-sys` / `native-tls` / `aws-lc-rs` / `schannel` / `security-framework` dans la fermeture, build
  par défaut comme sous `store-postgres` (qui partage la même pile, une seule version de `rustls`).
- **Cycle de vie des outils — un manifeste unique, et une surcouche runtime qui n'ouvre aucune porte.**
  Les versions et les empreintes SHA256 des douze binaires de sécurité téléchargés (httpx, nuclei,
  subfinder, dnsx, naabu, katana, amass, gau, gospider, dalfox, feroxbuster, ffuf) étaient des `ARG`
  codés en dur **dupliqués** entre `Dockerfile` et `docker-compose.yml`. Deux copies d'un pin, c'est
  une divergence silencieuse qui attend son heure — et il n'existait aucun moyen d'installer un outil
  omis, ni d'en mettre un à jour, sans reconstruire l'image.

  **Source unique : `forge/tools.json`.** Version, gabarit d'URL, format d'archive, membre à extraire,
  nom posé sur le `PATH`, et un digest **par architecture**. Le `Dockerfile` le lit au build (via
  `forge/toolsmanifest.py`, script autonome stdlib) et l'installeur runtime lit le même fichier.
  Le compose ne propage plus aucun pin. Bumper une version = éditer ce seul fichier. Une garde statique
  échoue si une version, un digest ou une URL d'outil réapparaît dans le `Dockerfile` ou le compose.

  **La baseline du build ne change pas** : mêmes binaires, mêmes versions, mêmes digests, même
  `sha256sum -c` qui fait échouer le build en cas d'écart. Deux garde-fous s'ajoutent : un outil sans
  pin pour l'architecture cible est **écarté du plan** (jamais téléchargé non vérifié) et signalé, et
  le groupe socle passe par `--require-complete core` — un pin manquant sur httpx/nuclei/subfinder fait
  échouer le build plutôt que produire une image amputée. Comme un `docker build` n'est pas jouable en
  CI, la boucle d'installation du `Dockerfile` est **extraite et réellement exécutée** par la suite de
  tests, avec `curl`/`sha256sum`/`unzip`/`tar` doublés : on vérifie l'URL téléchargée, le digest
  présenté, le membre extrait, la profondeur de `--strip-components` et le nom du binaire posé — et
  qu'un digest non concordant fait tout échouer sans rien installer.

  **Surcouche runtime : `forge tools list|install|update|remove`.** Le binaire atterrit dans
  `/data/tools/bin` — volume persistant, propriété de l'utilisateur `forge`, en tête du `PATH` devant le
  `/usr/local/bin` baké : mettre à jour un outil ne demande plus de rebuild, et l'install survit à un
  *recreate* du conteneur. Installer un binaire au runtime dans un outil offensif est précisément la
  capacité qui annule une gouvernance si elle est mal posée, donc : SHA256 épinglé **calculé sur le
  flux** et comparé avant que quoi que ce soit n'atteigne le `PATH` (écart ⇒ refus, temporaire détruit,
  refus **journalisé**) ; source **allowlistée** par le manifeste — il n'existe ni `--url` ni
  `--sha256`, et un nom hors manifeste ne déclenche aucune requête ; HTTPS strict, redirection quittant
  HTTPS refusée ; **aucun shell ni sous-processus** (`urllib` + `zipfile`/`tarfile`, un seul membre
  extrait vers une destination que nous calculons — un membre nommé `../../evil` ne sort pas du
  répertoire outils) ; **ledger obligatoire** (`tools.install`/`.update`/`.remove`/`.refused`, chaînés
  et signés) — sans ledger résoluble, l'action est refusée : pas de changement de capacité sans trace.

  Aucune élévation : l'outil installé reste soumis au scope-guard ROE fail-closed, au plancher exploit
  et au même contrat `Module`. Et **le défaut est un no-op** : rien n'est créé ni sondé à l'import,
  aucun module du moteur n'importe l'installeur, le volume est vide tant qu'aucune action opérateur
  n'a eu lieu — la résolution `PATH` est alors identique à la baseline.

  Volontairement **non construit** : l'installation d'une version *hors* manifeste (elle supposerait
  d'accepter un digest saisi à la main — tant qu'elle n'existe pas, il n'y a aucun chemin vers un
  téléchargement non épinglé), l'API admin et le panneau UI de la console, et la sonde de version par
  exécution du binaire. Documentation : `docs/TOOLS_LIFECYCLE.md`.

### Changed
- **Un secret de source de détection ne part plus en clair vers une cible PUBLIQUE** (installs existantes
  — rupture **NOMMÉE**). Le fetcher de source n'avait **aucune** garde de ce genre : une source
  `plume`/`generic_http` en **`http://`** vers une adresse **publique**, portant un `auth.secret`, mettait
  son en-tête `Authorization:` **sur le fil**. Le canal de notification, lui, refusait déjà ce cas — la
  règle existait donc, en **copie inline** dans un seul des deux egress. Elle est désormais **partagée**
  (`net::reject_cleartext_secret`, une implémentation, vérifiée une fois) et **appliquée aux deux**. Le
  refus tombe **avant la connexion** et **aucune** variable d'environnement ne l'ouvre. Correctifs :
  passer la source en **`https://`** (une AC privée se fournit via `FORGE_EXTRA_CA_PEM`), ou retirer le
  secret.

  **Ce qui N'A PAS été resserré, et pourquoi — mesuré, pas supposé.** L'option envisagée était d'exiger
  `https` **dès qu'un secret est configuré**, l'échappatoire ne couvrant plus que le cas *sans* secret.
  Mesure faite : cela casse le déploiement **on-prem de référence** — un collecteur interne authentifié
  qui n'expose **aucun écouteur TLS** (`PLUME_URL`/`PLUME_TOKEN` sur un segment privé, encodé par deux
  tests existants). La CA d'entreprise n'aide pas ici : elle fournit une **ancre**, pas un **écouteur**.
  Le resserrement aurait donc **tué** l'usage au lieu de le déplacer. `http://` + secret vers une cible
  **interne** explicitement autorisée (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`) reste donc **servi** — c'est
  le clair **gouverné**, et il est nommé comme tel.

- **Les secrets d'intégration ne sont plus persistés verbatim** (installs existantes — rupture
  **NOMMÉE**). `settings.detection_source → auth.secret`, `settings.notify_channel → auth.secret` et
  `settings.sso.config → client_secret` étaient stockés **en clair** ; ils sont désormais **scellés**
  (`FORGE_FIELD_KEY`). Conséquences pratiques : (a) sans clé de champ, **poser** l'un de ces secrets par
  l'API renvoie **503** `field_key_missing` au lieu de l'écrire en clair ; (b) un outil externe qui lisait
  ces valeurs directement dans la base n'y trouvera plus qu'une enveloppe ; (c) `FORGE_FIELD_KEY` devient
  un secret à **conserver** pour ces intégrations aussi — la perdre les rend illisibles, et l'intégration
  **refuse de partir** plutôt que de se présenter sans authentification. Le chemin `keep_secret` (éditer
  l'endpoint sans retaper le jeton) fonctionne **sans clé** : il recopie l'enveloppe telle quelle.
- **Un nouveau fichier apparaît à côté du ledger d'un engagement : `<ledger>.durations`** (installs
  existantes — rupture NOMMÉE). Sidecar au même titre que `<ledger>.hwm` et `<ledger>.ed25519`, créé au
  premier `forge run`/`forge campaign` qui reçoit `--ledger` **et** tire au moins une action. Il porte
  **uniquement** des durées agrégées **par kind de module** (aucune cible, aucun hôte, aucune URL), pèse
  quelques Kio au plus, n'est **pas** un secret, et n'est **pas** dans la chaîne d'auditabilité (le
  perdre ne casse rien : le préchauffage retombe sur `action.cost`). Conséquences pratiques : les
  scripts de purge doivent l'inclure (`docs/UNINSTALL.md` mis à jour), et une exploitation qui n'en veut
  pas pose `FORGE_DURATIONS=0` (aucun fichier créé, comportement d'avant à l'identique). Sans
  `--ledger`, rien ne change : aucun fichier n'a jamais été écrit.
- **The purple join now has THREE states, not two — and the headline rate got stricter.** The join
  between fired techniques (red) and SOC detections (blue) was a plain **string equality** on the
  `mitre` tag, which produced two measured defects.

  **(a) Parent vs sub-technique.** Forge fires `T1110.001` (module `network.ssh`, SSH password
  guessing); a SOC that only has a `T1110` rule scored a flat `missed`. Naively normalising to the
  parent would have scored `detected` — and that would have been an **unmeasured** claim: the join sees
  an *identifier*, not a detection query, so it cannot prove the fired vector is covered. Read one by
  one, three of the shipped `T1110` rules are `ca-cred-mail-bruteforce` (`search source=mail
  action=failure …`, mail only), `ca-cred-web-login-bruteforce` (`search source=web status=401 …`, web
  only) and `ca-cred-distributed-bruteforce` (`search category=auth action=failure | stats
  dc(src_ip)`, needs IP spread) — none of those three catches a single-source SSH brute force. Other
  seeded `T1110` rules might, depending on which rules are enabled and which telemetry is wired. That
  ambiguity is the point: the join does not arbitrate it in the vendor's favour, it **names** it. So a
  parent match is now its own state,
  `detected-parent-approx`: it is **excluded from `detection_rate`** and **excluded from MTTD**
  sampling (a MTTD computed between an SSH fire and an unrelated alert is an invented number), and it
  is surfaced in its own `parent_approx` list with the parent named and an explicit reason — a *named
  blind spot*, which is the product, not waste.

  **(b) Multi-technique tags.** A `mitre` tag may carry several techniques separated by space, comma
  or semicolon — the norm at SigmaHQ (several `attack.` per rule). A tag `"T1595.002 T1046"` matched
  **neither** key, so a Sigma corpus manufactured false `missed`. Tags are now **split on both sides**
  of the join (fired records and detections), sub-technique preserved. A tag that parses to no
  technique at all is still joined verbatim — a fired technique must never silently vanish.

  New/renamed contract on `GET /api/detection/coverage` (alias `/api/purple/coverage`):
  `techniques_parent_approx` and `parent_approx[]` added; every row carries its `state`
  (`detected-exact` / `detected-parent-approx` / `missed`); `techniques_detected` and
  `detection_rate` now count **exact matches only**. Invariant: `detected + parent_approx + missed ==
  techniques_fired`. Report (markdown/HTML/JSON/`forge/report_engagement.py`), console UI and the
  bundled reference engagement all render the third state.
- **`GET /api/attack-matrix`: cell field `detected` renamed to `fired`, and the fire count `fired` to
  `fires`.** That boolean never measured detection — it was `runrecord.fired > 0`, i.e. *the red side
  actually shot*, as opposed to proposed/vetoed/dry-run. It sat next to the genuinely blue `detected`
  of the purple coverage under the same name, and the UI rendered it as « détectée ». Two distinct
  notions must not share one name in an API. The matrix stays a **red** view; MTTD and the
  parent-approx marker come from `/api/purple/coverage` as an enrichment, matched on the **exact**
  technique id (the previous « T1595.003 measured under its base T1595 » fallback is gone — it was
  precisely a parent-approx displayed as the sub-technique's MTTD). Read `missed` as the list it is: in **fail-open** (`purple_fail_open`) `techniques_fired` is `N` while all three counters are `0` — deriving `missed = fired - detected - parent_approx` there manufactures the very false "missed" that fail-open exists to prevent.

### Fixed
- **Detection-source fetch never completed its HTTP request.** The console's built-in fetcher
  (`console/src/net.rs::http_get_blocking`, used by `kind=plume` / `generic_http` over http) wrote its
  request headers without the terminating blank line, so an RFC-compliant server kept waiting for more
  headers, the console hit its read timeout, and `GET /api/detection/coverage` reported the source as
  unreachable (`source_reachable:false`, `error: "lecture réponse échouée: Resource temporarily
  unavailable (os error 11)"`) even though the SOC was up and answering. Measured byte for byte by
  replaying the emitted request against `tools/mock_plume.py`: without the blank line, no response in
  4 s; with it, `HTTP/1.1 200 OK` immediately. Now covered end to end by the `purple-e2e` CI job.

  **Blast radius — larger than the detection source.** `http_get_blocking` has three production
  callers, and all three were affected: `detection.rs:531` (detection source) **and `sso.rs:935`
  (OIDC discovery, `.well-known/openid-configuration`) and `sso.rs:1001` (JWKS)**. OIDC login over
  plain http therefore could not complete either. Only the token exchange was safe, because it goes
  through the *POST* helper (`sso.rs::http_post_form_blocking`), which did send the blank line — the
  omission was an oversight in the GET path, not a convention. An earlier wording of this entry
  mentioned only the detection source and cited the healthy POST sibling, which wrongly implied SSO
  was unaffected.

  **Why no test caught it, in either path.** The fetcher's tests only ever targeted
  `http://127.0.0.1:1/x` — an unreachable port — so they asserted that failure fails; a *successful*
  fetch was never exercised. And the 18 SSO tests still pass with the bug reintroduced, because their
  mock IdP does a single `read()` and answers immediately instead of waiting for the end of headers.
  A green suite proved nothing here; only an end-to-end exchange with an RFC-compliant server did.

### Added
- **End-to-end CI for the purple loop** (`purple-e2e` job + `scripts/purple_loop_e2e.py`,
  `make test-purple`): fires the engine, ingests the run-records into a real console binary, serves
  detections from the loopback demo stub `tools/mock_plume.py`, and asserts the computed coverage
  (`detected`/`parent_approx`/`missed`, `detection_rate`, per-technique MTTD, `since` windowing)
  against expectations derived from the actual shots — including the two guards of the three-state
  join: a fired sub-technique whose parent alone is covered must not move the rate, and its apparent
  MTTD must not be sampled; a multi-technique SOC tag must match every technique it carries. No offensive network I/O: loopback only, synthetic module, loopback IP
  literals (no DNS lookup).

### Notes for open-source builds
- The Rust console depends on `guatx-core` via a **pinned public git dependency**
  (`git = "https://github.com/guatxlabs/core", tag = "v0.2.1", features = ["forge"]`; see
  `console/Cargo.toml`). A standalone clone of this repo builds the console directly — the core is
  fetched from GitHub at build time, no sibling crate required. In a monorepo dev checkout,
  `console/.cargo/config.toml` (gitignored) carries a `[patch]` that overrides the git dep to a local
  `../../core` for speed; it is absent from public clones.

## [0.0.1] — initial release

First public cut of Forge — a governed, proof-oriented red-team engine.

### Core safety model
- **4-layer ROE gate** (`forge/roe.py`): armed → in-scope → capability → approved. Inert by
  default; any evaluation error is a hard `VETO`. Scope-guard is fail-closed (empty scope fires
  nothing).
- **Tamper-evident engagement ledger**: append-only, hash-chained, Ed25519-signed (HMAC fallback),
  with high-water-mark truncation detection and alg-aware verification.
- **Coverage-safe planner**: qualifying vuln classes are never silently starved; deferrals are
  reported.
- **Central secret redaction**: session credentials, API keys, and signing keys are redacted at
  the finding boundary — never reaching the ledger, reports, logs, or API responses.

### Engine & modules
- Recon arsenal (subfinder, amass, dnsx, httpx, nmap, masscan, katana, gau, gospider, whatweb,
  theHarvester, …) chained into proof-oriented oracles.
- Vuln oracles across the payable classes (IDOR/access-control, auth/ATO, SQLi, XSS, SSTI, SSRF,
  XXE, RFI, command injection, CSRF, CORS, JWT, GraphQL BOLA, request smuggling, cache poisoning,
  and more), each scope-guarded and requiring genuine proof to promote.
- Governed **ToolSpec** wrapper (wrap any CLI tool, no-shell, ROE-gated) + drop-in plugin loader.
- Importers for nmap/nuclei/burp/httpx/ffuf output.
- Per-engagement **authenticated context** for cross-account testing (IDOR/ATO), scope-guarded and
  credential-redacted.

### Operations
- **Unified resource profile** (`FORGE_RESOURCE_PROFILE=low|balanced|full`) — one knob sets sane
  resource defaults for constrained or beefy machines, with strict override > profile > default
  precedence and zero governance impact.
- **Governed console** (Rust/axum): findings, ATT&CK coverage, GXQL explore, dashboards, runs,
  ROE, ledger, admin — session-authenticated, RBAC, loopback-strict by default.
- **Optional LLM assist** (OpenAI-compatible, off by default, egress-gated, advisory-only).
- Postgres backend + HA topology, object-store artifacts, and Kubernetes manifests
  (deny-by-default NetworkPolicies) for enterprise deployments.

### Licensing
- **AGPL-3.0-or-later**, open-core. Enterprise features are documented in
  [`COMMUNITY_VS_ENTERPRISE.md`](COMMUNITY_VS_ENTERPRISE.md).

[Unreleased]: https://github.com/guatxlabs/forge/commits/main
[0.0.1]: https://github.com/guatxlabs/forge/commits/main
