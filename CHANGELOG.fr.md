# Journal des modifications

[English](CHANGELOG.md) | [Français](CHANGELOG.fr.md)

Tous les changements notables de Forge sont consignés ici. Le format s'appuie sur
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), et Forge entend suivre
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) à partir de sa première version étiquetée.

> Forge est pré-1.0 : l'API publique, les kinds de modules et la surface de configuration peuvent encore changer entre
> versions mineures. Les ruptures seront signalées ici.

## [Unreleased]

### Modifié — la console compile contre `guatx-core` v0.2.6 (au lieu de v0.2.2)

Le compilateur de requêtes partagé avec Plume refuse désormais des formes qu'il jetait ou lisait de
travers sans rien dire. Une requête qui compilait et rendait un résultat peut désormais être refusée,
avec un message qui dit quoi écrire. Sans aucune de ces formes, le SQL émis est inchangé.

- `stats`, `eventstats`, `timechart`, `sort`, `head`, `top`, `rare`, `join`, `append`… refusent tout
  jeton qu'ils ne lisent pas (`sort ts desc` triait en ordre croissant ; `stats count dc(user)` ne
  rendait que le compte) ; une clé de `stats … by` qui ne nomme aucun champ en portée est refusée au
  lieu de devenir un libellé.
- `search` refuse un `OR`, `AND` ou `NOT` nu et une parenthèse non appariée (aucune grammaire
  booléenne n'existe ; ils devenaient un terme libre). Un `|` ou un `]` entre guillemets doubles ne
  coupe plus le pipeline ; un guillemet double non fermé est refusé.
- Sous un masque de champ, le sac JSON n'est jamais lu brut : prédicats et clés de jointure sur le
  sac sont refusés, les clés de groupe lisent la projection caviardée.

### Ajouté — couverture du Top 10 des techniques web 2025 : onze oracles à preuve

Onze modules de vérification à preuve bénigne (exploit=False, destructive=False sauf mention),
et la `DEFAULT_CHECKLIST` recalée sur les taux d'acceptation mesurés (traversal et XSS en tête) —
l'ordre précédent omettait ces classes et les rendait invisibles à `coverage_gaps()`.

- `upload.unrestricted` (CWE-434) : file upload dangereux, marqueur inerte resservi.
- `cspt.redirect` + `recon.client_sinks` : Client-Side Path Traversal, différentiel de profondeur
  de chemin observé au navigateur ; lecture des couples source vers puits du JavaScript de même origine.
- `parserdiff.unicode` (CWE-176) : différentiel de normalisation Unicode entre WAF et backend.
- `ormleak.filter` : oracle booléen par filtre ORM, deux sondes par champ, aucun balayage.
- `ssrf.redirect_loop` : rend visible un SSRF aveugle via une boucle de redirection à codes incrémentaux.
- `massassign.params` : mass assignment prouvé par un canari inerte, jamais une valeur privilégiée réelle.
- `business_logic.invariants` : invariants dérivés de l'objet métier (négatif, borne, somme).
- `llm.prompt_injection` : injection de prompt, canaris inertes, hors `DEFAULT_CHECKLIST` par défaut.
- `ssti.errors` (CWE-1336) : SSTI aveugle par le canal d'erreur (« Successful Errors »).
- `sidechannel.shape` (CWE-203) : oracle d'existence par forme de réponse (XS-Leak / length-leak).

Support : garde anti-réflexion sur `cmdi.probe` (un token contenu dans la charge ne prouve pas
l'exécution), filtre d'assets statiques dans `recon.urls` (constat compté, jamais silencieux),
synchronisation à dernier octet pour `race`.

Registre : 88 modules, 42 bug_bounty_eligible.

### Corrigé — les verdicts disaient plus que ce qu'ils avaient vérifié

Ce lot vient d'une **campagne réelle** contre une infra de production autorisée, entièrement derrière
un tunnel Cloudflare. Aucun de ces défauts ne cassait quoi que ce soit : ils **rassuraient**.

- **`Oracle.skip()` émettait `status='tested'`.** La méthode LITTÉRALEMENT NOMMÉE `skip`, documentée
  « non testé / config manquante », affirmait donc « **j'ai vérifié, rien trouvé** » — sur
  **1 750 findings** mesurés, 25 kinds, **aucun octet émis pour aucun d'eux**. Un rapport listant
  « access_control.idor : tested » sur une cible pour laquelle aucun compte de test n'est configuré se
  lit comme une **absence de vulnérabilité** ; c'est le mode d'échec qui a déjà coûté une campagne.
  Corrigé en `skipped` — le vocabulaire qui existait déjà pour « je n'ai pas pu vérifier », et que la
  vue de rapport promeut en section « Couverture NON vérifiée ». **Rupture** : 8 tests figeaient le
  mensonge (dont un nommé `test_no_session_jwt_is_skip` qui assertait `"tested"`), et le snapshot
  d'équivalence l'avait figé aussi — cinq entrées corrigées, les quatre `*_negative` laissées en
  `tested` car elles ont bel et bien tiré.

- **Un mur produisait des verdicts.** `Oracle._http` JETTE le corps sur `HTTPError` — or l'interstitiel
  Cloudflare vit exactement là. La garde d'abstention était déjà câblée dans 6 modules et rendait
  **zéro** abstention. Le corps d'erreur est désormais prélevé (8 Kio, **pour juger seulement** : le
  contrat public de `_http` reste byte-identique) et `__init_subclass__` enveloppe le `fire()` de
  chaque oracle. **117 `tested` convertis sur les 256 réellement atteignables, 0 verdict légitime
  détruit** (contrôle négatif sur cible saine : identique avant/après). La borne reste étroite et
  testée — un **403 NU reste un verdict applicatif**, sinon forge deviendrait aveugle aux contrôles
  d'accès, sa classe la plus payante.

- **Deux verdicts FABRIQUÉS.** (1) Un lot `web.nuclei` tué à son mur rend une sortie **partielle**,
  donc la branche « outil en échec » n'était jamais atteinte : chaque cible jamais scannée sortait en
  `tested` « aucun hit » — **15 sur 17** en reproduction. (2) La comptabilité anti-lacune vivait
  **après** la boucle du moteur : un arrêt gracieux la sautait, et le rapport annonçait « aucune
  lacune, aucun module non planifié » alors qu'il y en avait **78**.

- **La console perdait 9,4 % des findings en silence** — 499 sur 5 318, `UNIQUE(campaign, target,
  title) ON CONFLICT IGNORE` (ni `run_id`, ni `tool`, ni `severity`), dont **8 `skipped`**, c'est-à-dire
  des trous de couverture évaporés. Le symptôme réel est pire qu'un écrasement : c'est le **second**
  run qui est refusé, et comme le rapport filtre par `run_id`, **son rapport est VIDE** — ce qui se lit
  « rien trouvé ». Élargir la clef ne récupérait que **8 findings sur 499** et cassait l'idempotence de
  rejeu que `IncrementalIngest` documente : on **compte et on annonce** (`findings_dropped`,
  `findings_write_errors`, loi de conservation testée), le stockage ne bouge pas.

- **Fuite de secret dans deux livrables.** L'annexe markdown **et** le livrable client HTML rendaient
  un `Authorization: Bearer <jwt>` **en clair** — `html_escape` n'est pas une rédaction. Trouvée par
  le garde-fou de parité **dès sa première exécution**.

### Ajouté

- **Budget de temps in-process** (`--run-timeout` / `FORGE_RUN_TIMEOUT`, levier `run_timeout_secs`
  existant qui n'avait qu'une exécution EXTERNE au SIGKILL) + arrêt gracieux hors console. **Le
  rapport et le sidecar `.durations` sont désormais garantis dans les trois cas d'arrêt** — échéance,
  SIGTERM, exception — là où deux campagnes réelles avaient perdu leur livrable alors que tout le
  travail était fait. Un rapport partiel **s'annonce partiel** : cause, X/Y actions, non-tentées
  listées. Une porte refuse en outre de DÉMARRER un tir dont la borne dépasse le budget restant :
  dépassement **+26 % → −0,8 %**, avec plus d'actions terminées qu'avant.
- **`web.nuclei` mutualisé par hôte** (`-u a,b,c` — `-list` est inutilisable, `docker run` est
  construit sans `-v`) : **60 → 10 invocations**, couverture par URL prouvée identique, scope-guard
  appliqué par cible via quatre portes indépendantes.
- **Le rapport de la console mène par un verdict**, comme le CLI : sections « Actionnable »,
  « Signal à qualifier », « Couverture NON vérifiée » (les `skipped` PROMUS), annexe derrière une
  comptabilité. Le garde-fou de parité qui le surveille compare des **structures** — l'ancien
  n'assertait que cinq sous-chaînes et restait vert quand la parité cassait.
- **`make check-supply-chain`** — les trois gardes (openssl-freedom, licences, octets NUL) tournaient
  en CI sans qu'aucune cible ne les expose : on ne pouvait les découvrir qu'en les cassant dans une PR.
- **`docs/UPSTREAM_REPORTS.md`** — reproduction minimale du défaut `cargo-deny`/`krates` (une
  dépendance OPTIONNELLE dont le nom de paquet diffère du nom de `[lib]` disparaît du graphe, et
  l'outil répond **`licenses ok`**). Il n'est pas propre à forge : le taire laisserait les autres
  projets avec le même angle mort.
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

### Modifié
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
- **La jointure purple a désormais TROIS états, pas deux — et le taux affiché est devenu plus strict.** La
  jointure entre techniques tirées (rouge) et détections du SOC (bleu) était une simple **égalité de chaînes**
  sur l'étiquette `mitre`, ce qui produisait deux défauts mesurés.

  **(a) Parent contre sous-technique.** Forge tire `T1110.001` (module `network.ssh`, devinette de mot de
  passe SSH) ; un SOC qui n'a qu'une règle `T1110` obtenait un `missed` sec. Normaliser naïvement vers le
  parent aurait donné `detected` — et cela aurait été une affirmation **non mesurée** : la jointure voit
  un *identifiant*, pas une requête de détection, elle ne peut donc pas prouver que le vecteur tiré est couvert. Lues une
  à une, trois des règles `T1110` livrées sont `ca-cred-mail-bruteforce` (`search source=mail
  action=failure …`, mail seulement), `ca-cred-web-login-bruteforce` (`search source=web status=401 …`, web
  seulement) et `ca-cred-distributed-bruteforce` (`search category=auth action=failure | stats
  dc(src_ip)`, exige une dispersion d'IP) — aucune de ces trois n'attrape une force brute SSH à source unique. D'autres
  règles `T1110` amorcées le pourraient, selon les règles activées et la télémétrie câblée. Cette
  ambiguïté est le cœur du sujet : la jointure ne la tranche pas en faveur du fournisseur, elle la **nomme**. Une
  correspondance au parent est donc désormais un état à part entière,
  `detected-parent-approx` : elle est **exclue de `detection_rate`** et **exclue de l'échantillonnage du
  MTTD** (un MTTD calculé entre un tir SSH et une alerte sans rapport est un nombre inventé), et elle
  apparaît dans sa propre liste `parent_approx`, le parent nommé et une raison explicite — un *angle mort
  nommé*, qui est le produit, pas un déchet.

  **(b) Étiquettes multi-techniques.** Une étiquette `mitre` peut porter plusieurs techniques séparées par espace, virgule
  ou point-virgule — la norme chez SigmaHQ (plusieurs `attack.` par règle). Une étiquette `"T1595.002 T1046"` ne correspondait
  à **aucune** clé, si bien qu'un corpus Sigma fabriquait de faux `missed`. Les étiquettes sont désormais **découpées des deux côtés**
  de la jointure (enregistrements tirés et détections), sous-technique préservée. Une étiquette qui ne se lit comme aucune
  technique est toujours jointe telle quelle — une technique tirée ne doit jamais disparaître en silence.

  Contrat nouveau/renommé sur `GET /api/detection/coverage` (alias `/api/purple/coverage`) :
  `techniques_parent_approx` et `parent_approx[]` ajoutés ; chaque ligne porte son `state`
  (`detected-exact` / `detected-parent-approx` / `missed`) ; `techniques_detected` et
  `detection_rate` ne comptent plus que les **correspondances exactes**. Invariant : `detected + parent_approx + missed ==
  techniques_fired`. Le rapport (markdown/HTML/JSON/`forge/report_engagement.py`), l'UI de la console et
  l'engagement de référence embarqué rendent tous le troisième état.
- **`GET /api/attack-matrix` : le champ de cellule `detected` renommé en `fired`, et le compte de tirs `fired` en
  `fires`.** Ce booléen n'a jamais mesuré la détection — c'était `runrecord.fired > 0`, c'est-à-dire *le côté rouge
  a réellement tiré*, par opposition à proposé/veto/dry-run. Il voisinait sous le même nom avec le `detected`
  réellement bleu de la couverture purple, et l'UI l'affichait comme « détectée ». Deux notions
  distinctes ne doivent pas partager un nom dans une API. La matrice reste une vue **rouge** ; le MTTD et le
  marqueur parent-approx viennent de `/api/purple/coverage` comme enrichissement, appariés sur l'identifiant de technique
  **exact** (l'ancien repli « T1595.003 mesurée sous sa base T1595 » a disparu — c'était
  précisément un parent-approx affiché comme MTTD de la sous-technique). Lire `missed` comme la liste qu'il est : en **fail-open** (`purple_fail_open`), `techniques_fired` vaut `N` alors que les trois compteurs valent `0` — y dériver `missed = fired - detected - parent_approx` fabrique exactement le faux « raté » que le fail-open existe pour empêcher.

### Corrigé
- **La récupération de la source de détection n'achevait jamais sa requête HTTP.** Le fetcher intégré de la console
  (`console/src/net.rs::http_get_blocking`, utilisé par `kind=plume` / `generic_http` sur http) écrivait les
  en-têtes de sa requête sans la ligne vide finale, si bien qu'un serveur conforme à la RFC attendait d'autres
  en-têtes, que la console atteignait son délai de lecture, et que `GET /api/detection/coverage` déclarait la source
  injoignable (`source_reachable:false`, `error: "lecture réponse échouée: Resource temporarily
  unavailable (os error 11)"`) alors que le SOC était en ligne et répondait. Mesuré octet par octet en
  rejouant la requête émise contre `tools/mock_plume.py` : sans la ligne vide, aucune réponse en
  4 s ; avec elle, `HTTP/1.1 200 OK` immédiatement. Désormais couvert de bout en bout par le job CI `purple-e2e`.

  **Rayon d'impact — plus large que la source de détection.** `http_get_blocking` a trois appelants
  en production, et tous trois étaient touchés : `detection.rs:531` (source de détection) **et `sso.rs:935`
  (découverte OIDC, `.well-known/openid-configuration`) et `sso.rs:1001` (JWKS)**. La connexion OIDC sur
  http en clair ne pouvait donc pas aboutir non plus. Seul l'échange de jeton était sûr, parce qu'il passe
  par l'assistant *POST* (`sso.rs::http_post_form_blocking`), qui envoyait bien la ligne vide — l'omission
  était un oubli dans le chemin GET, pas une convention. Une formulation antérieure de cette entrée
  ne mentionnait que la source de détection et citait le voisin POST sain, ce qui laissait entendre à tort que le SSO
  n'était pas touché.

  **Pourquoi aucun test ne l'a vu, dans aucun des deux chemins.** Les tests du fetcher ne visaient jamais que
  `http://127.0.0.1:1/x` — un port injoignable — ils affirmaient donc que l'échec échoue ; une récupération
  *réussie* n'était jamais exercée. Et les 18 tests SSO passent toujours avec le bug réintroduit, parce que leur
  IdP simulé fait un seul `read()` et répond aussitôt au lieu d'attendre la fin des en-têtes.
  Une suite verte ne prouvait rien ici ; seul un échange de bout en bout avec un serveur conforme à la RFC l'a fait.

### Ajouté
- **CI de bout en bout pour la boucle purple** (job `purple-e2e` + `scripts/purple_loop_e2e.py`,
  `make test-purple`) : tire le moteur, ingère les run-records dans un vrai binaire de console, sert des
  détections depuis le stub de démo en loopback `tools/mock_plume.py`, et vérifie la couverture calculée
  (`detected`/`parent_approx`/`missed`, `detection_rate`, MTTD par technique, fenêtrage `since`)
  contre des attentes dérivées des tirs réels — y compris les deux gardes de la jointure à trois états :
  une sous-technique tirée dont seul le parent est couvert ne doit pas faire bouger le taux, et son MTTD
  apparent ne doit pas être échantillonné ; une étiquette SOC multi-techniques doit correspondre à chaque technique qu'elle porte. Aucune E/S réseau offensive : loopback seulement, module synthétique, IP loopback
  littérales (aucune résolution DNS).

### Notes pour les builds open source
- La console Rust dépend de `guatx-core` via une **dépendance git publique épinglée**
  (`git = "https://github.com/guatxlabs/core", tag = "v0.2.6", features = ["forge"]` ; voir
  `console/Cargo.toml`). Un clone autonome de ce dépôt compile directement la console — le core est
  récupéré depuis GitHub au moment du build, aucun crate voisin requis. Dans un checkout de dev en monorepo,
  `console/.cargo/config.toml` (gitignoré) porte un `[patch]` qui remplace la dépendance git par un
  `../../core` local pour la vitesse ; il est absent des clones publics.

## [0.0.1] — première version

Première version publique de Forge — un moteur red-team gouverné, orienté preuve.

### Modèle de sûreté du cœur
- **Gate ROE à 4 couches** (`forge/roe.py`) : armé → dans le scope → capacité → approuvé. Inerte par
  défaut ; toute erreur d'évaluation est un `VETO` dur. Le scope-guard est fail-closed (un scope vide ne tire
  rien).
- **Ledger d'engagement tamper-evident** : append-only, chaîné par hachage, signé Ed25519 (repli HMAC),
  avec détection de troncature par high-water-mark et vérification consciente de l'algorithme.
- **Planner qui préserve la couverture** : les classes de vulnérabilités éligibles ne sont jamais affamées en silence ; les reports sont
  signalés.
- **Rédaction centrale des secrets** : identifiants de session, clés d'API et clés de signature sont rédigés à
  la frontière du finding — ils n'atteignent jamais le ledger, les rapports, les journaux ni les réponses de l'API.

### Moteur & modules
- Arsenal de recon (subfinder, amass, dnsx, httpx, nmap, masscan, katana, gau, gospider, whatweb,
  theHarvester, …) enchaîné vers des oracles orientés preuve.
- Oracles de vulnérabilités sur les classes payantes (IDOR/contrôle d'accès, auth/ATO, SQLi, XSS, SSTI, SSRF,
  XXE, RFI, injection de commandes, CSRF, CORS, JWT, GraphQL BOLA, request smuggling, cache poisoning,
  et d'autres), chacun gardé par le scope et exigeant une preuve réelle pour être promu.
- Enveloppe **ToolSpec** gouvernée (envelopper n'importe quel outil CLI, sans shell, gatée par les ROE) + chargeur de plugins drop-in.
- Importeurs pour les sorties nmap/nuclei/burp/httpx/ffuf.
- **Contexte authentifié** par engagement pour les tests inter-comptes (IDOR/ATO), gardé par le scope et
  avec identifiants rédigés.

### Exploitation
- **Profil de ressources unifié** (`FORGE_RESOURCE_PROFILE=low|balanced|full`) — un seul réglage fixe des
  défauts de ressources raisonnables pour des machines contraintes ou costaudes, avec une précédence stricte surcharge > profil > défaut
  et zéro impact sur la gouvernance.
- **Console gouvernée** (Rust/axum) : findings, couverture ATT&CK, exploration GXQL, tableaux de bord, runs,
  ROE, ledger, admin — authentifiée par session, RBAC, strictement en loopback par défaut.
- **Assistance LLM optionnelle** (compatible OpenAI, désactivée par défaut, sortie gatée, consultative seulement).
- Backend Postgres + topologie HA, artefacts en object-store, et manifestes Kubernetes
  (NetworkPolicies en refus par défaut) pour les déploiements d'entreprise.

### Licence
- **AGPL-3.0-or-later** — tout le produit est open source, sans édition payante. Les modules avancés
  séparables (multi-tenant, SSO/SCIM, conformité) sont flag-gated et OFF par défaut ; ils sont
  documentés dans [`ADVANCED_MODULES.md`](docs/ADVANCED_MODULES.fr.md).

[Unreleased]: https://github.com/guatxlabs/forge/commits/main
[0.0.1]: https://github.com/guatxlabs/forge/commits/main
