<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Banc de détection multi-applications — méthode et résultats

> [Sommaire](README.md) · Code du banc : [`../bench/detection/`](../bench/README.md) ·
> Mesure historique mono-cible : `ROADMAP.md` § « Pouvoir de détection — mesuré, pas supposé »
>
> **DEUX campagnes, gardées côte à côte.** `2026-08-10` (mesure initiale, 13 défauts consignés) et
> `2026-08-11` (banc **rejoué en entier** après remédiation, pour mesurer les 13 correctifs ENSEMBLE
> et non plus isolément). Les chiffres d'avant sont **conservés visibles** partout où ils ont bougé :
> un rapport de banc qui réécrit ses erreurs ne vaut plus rien comme référence. Le rejeu a fermé
> 10 défauts sur 13, en a laissé 3 partiellement ouverts, et en a mis **6 nouveaux** au jour (§6bis).

## 1. Pourquoi ce banc existe

La seule mesure de pouvoir de détection du dépôt portait sur **une** application (OWASP Juice Shop) :
2 vulnérabilités confirmées, vérité terrain fournie par l'app elle-même. C'est une mesure honnête,
mais un **échantillon de 1** : il ne dit pas si le moteur GÉNÉRALISE ou s'il a été ajusté à cette
cible. Tout le reste des confrontations avait buté sur l'**accès** (mur Cloudflare, UAT en 404),
jamais sur la détection — sauf une cible réelle où le moteur a produit **8 HIGH faux**.

Ce banc répond à une question et une seule : **au-delà de Juice Shop, forge trouve-t-il quelque
chose, et affirme-t-il des choses fausses ?**

## 2. Ce qui est mesuré, et comment

Quatre applications volontairement vulnérables, **stacks délibérément différentes**, chacune
fournissant sa PROPRE vérité terrain — jamais forge :

| app | stack | vérité terrain |
|---|---|---|
| Juice Shop (contrôle) | Node/Express/Angular/SQLite | `GET /api/Challenges` : son registre de challenges |
| DVWA | PHP 7/Apache/MariaDB | `/var/www/html/vulnerabilities/` : sa liste de modules |
| VAmPI | Python/Flask/connexion/OpenAPI3 | `README.md` § *List of Vulnerabilities* + branches `if vuln:` |
| DVGA | Python/Flask/Graphene | `templates/partials/solutions/*.html` : ses pages de solutions |

Juice Shop est **rejouée** pour vérifier que le banc REPRODUIT la mesure connue du dépôt : sans ce
contrôle, un écart sur les trois autres serait indiscernable d'un défaut du banc.

### Deux pistes, jamais confondues

Une campagne autonome mesure **deux** capacités à la fois — DÉCOUVRIR la surface, et JUGER une fois
dessus. Quand elle ne trouve rien, on ignore laquelle a échoué. Le banc les sépare :

- **piste A — jugement.** Chaque oracle est amorcé à la main sur l'URL et le paramètre EXACTS de la
  vuln connue. La découverte est neutralisée ; il ne reste que le verdict.
- **piste B — chaîne complète.** Campagne `--auto-pentest` sur la racine de l'app. C'est là que se
  comptent les **faux positifs**, parce que c'est là qu'il y a du volume.

### Trois métriques, la troisième d'abord

Vrais positifs **par classe** · faux négatifs **avec leur cause** (oracle absent ? amorçage ?
navigateur ? budget ?) · et **faux positifs** : chaque finding ≥ MEDIUM est rejoué à la main contre
l'application. Un banc qui ne compterait que les trouvailles ne prouverait rien.

Une classe qu'**aucun** oracle du dépôt ne revendique n'est PAS comptée en faux négatif : c'est une
lacune de couverture, comptée à part. Les classes bannies du périmètre (DoS, brute force, absence de
rate-limit) sont exclues du dénominateur.

## 3. Ce qui a été amorcé — déclaré par application

« forge trouve X avec 2 comptes fournis » et « forge trouve X sans rien » sont deux affirmations
différentes. Le banc rend les deux lisibles ; l'amorçage exact vit dans `manifest.json`
(`apps.<app>.primed`) et est recopié tel quel dans le rapport.

| app | amorcé |
|---|---|
| Juice Shop | 2 comptes à nous (self-signup) + le panier de la victime comme cible IDOR marquée |
| DVWA | 1 session authentifiée (compte natif `admin`), niveau natif `low`, 1 **canari bénin** dans la racine web |
| VAmPI | 2 comptes à nous + 1 ressource possédée par la victime, décrite par son marqueur |
| DVGA | **rien** — l'application est entièrement anonyme |

Le canari de DVWA n'est pas une facilité : `path.traversal` REFUSE par conception de cibler
`/etc/passwd` et exige un marqueur bénin fourni par l'opérateur. Sans lui il ne peut structurellement
rien confirmer.

## 4. Sûreté du banc

- **Loopback strict.** Chaque conteneur est publié sur `127.0.0.1` uniquement.
  `provision.verify_loopback_only()` lit `ss -ltn` et **refuse d'armer** si un socket du banc écoute
  ailleurs. Ces applications sont délibérément vulnérables : elles ne doivent jamais être exposées.
- **Périmètre borné au port** : `in_scope: ["127.0.0.1:<port>"]`, plus `allow_private: true` (le ROE
  refuse les adresses privées par défaut). Vérifié par `forge scope-check` avant chaque armement,
  avec **contre-épreuve** sur une cible hors périmètre (attendu : exit 1).
- **`allow_exploit: true`** — assumé et déclaré : les oracles de contrôle d'accès en dépendent. Ces
  applications nous appartiennent. `allow_destructive` reste `false`.
- **Modules interrogeant un tiers exclus** (`provision.THIRD_PARTY_MODULES`) : crt.sh, Wayback,
  résolveurs DNS publics, dépôts de templates amont, collecteurs de callback hors hôte. La liste
  retenue/exclue est écrite à chaque exécution dans `modules_loopback_safe.json`.
  ⚠️ **CETTE GARANTIE EST INCOMPLÈTE, mesuré le 2026-08-11** : l'exclusion porte sur l'INTENTION
  déclarée d'un module, pas sur son egress observé. `recon.httpx` — retenu comme sûr — a téléchargé
  92,6 Mio depuis `huggingface.co` à chacun de ses 4 tirs. Détail et preuve en **D17** (§6bis).
  Le reste du run est resté en boucle locale ; aucune requête n'est sortie vers une cible tierce.
- **Limite assumée** : le service navigateur gouverné tourne dans son propre espace réseau ; il ne
  peut pas atteindre un `127.0.0.1:<port>` de l'hôte. Les oracles adossés au navigateur
  (`xss.execution`, le rendu DOM de `xss.stored`) sont donc **non mesurables** sur ce banc — ils sont
  comptés `skipped`, jamais `manqués`. Les rendre mesurables exigerait de lier les applications à
  l'adresse du pont docker, ce que la règle « loopback uniquement » interdit.

## 5. Résultats — AVANT (2026-08-10) / APRÈS (2026-08-11)

> **Les deux campagnes sont conservées côte à côte, colonne par colonne.** Les 13 défauts consignés
> en §6 ont été fermés entre les deux, mais **ils n'avaient été mesurés qu'ISOLÉMENT** ; le banc a été
> rejoué EN ENTIER pour les mesurer ENSEMBLE. Sorties brutes : [`RESULTS_2026-08-10.md`](../bench/detection/RESULTS_2026-08-10.md)
> et [`RESULTS_2026-08-11.md`](../bench/detection/RESULTS_2026-08-11.md).
>
> **Méthode IDENTIQUE** — même vérité terrain (fournie par les applications), même amorçage déclaré,
> même budget `--budget 900`, mêmes modules retenus, mêmes deux pistes.
> **UN SEUL paramètre a changé, et il est déclaré** : l'action `cmdi.probe`/`rce.probe` de la piste A
> de DVWA vise désormais `/vulnerabilities/exec/?Submit=Submit` au lieu de `/vulnerabilities/exec/`
> (`bench/detection/seeded.py`). Raison : DVWA teste `isset($_POST['Submit'])` — sans ce co-paramètre
> la RCE est **hors d'atteinte par construction**, quelle que soit la charge. C'est le défaut D6 vu
> depuis l'amorçage : l'action ne déclarait le co-paramètre nulle part, donc rien ne pouvait le
> porter. Le correctif D6 (préservation des autres paramètres) et cette correction d'amorçage sont
> **indissociables** : ni l'un ni l'autre seul ne rend la RCE atteignable.

### 5.1 Synthèse

| app | piste | opposables | **vrais positifs** | **faux négatifs** | **faux positifs** | findings émis | ≥ MEDIUM revendiqués |
|---|---|---|---|---|---|---|---|
| | | | AVANT → **APRÈS** | AVANT → **APRÈS** | AVANT → **APRÈS** | AVANT → **APRÈS** | AVANT → **APRÈS** |
| Juice Shop | A | 3 | 2 → **2** | 1 → **1** | 0 → **0** | 6 → **6** | 2 → **2** |
| Juice Shop | B | 3 | 0 → **0** | 3 → **3** | 0 → **0** | 873 → **45** | 0 → **0** |
| DVWA | A | 9 | 3 → **5** | 6 → **4** | 0 → **0** | 15 → **15** | 3 → **5** |
| DVWA | B | 9 | 0 → **0** | 9 → **9** | **4 → 4** | 1806 → **1558** | 4 → **4** |
| VAmPI | A | 4 | 1 → **2** | 3 → **2** | 0 → **0** | 8 → **8** | 1 → **2** |
| VAmPI | B | 4 | 1 → **1** | 3 → **3** | 4 → **0** | 1175 → **319** | 5 → **1** |
| DVGA | A | 7 | 0 → **0** | 7 → **7** | 0 → **0** | 15 → **15** | 0 → **0** |
| DVGA | B | 7 | 0 → **0** | 7 → **7** | 0 → **0** | 1849 → **2940** | 0 → **0** |
| **TOTAL** | | | **6 → 9** ¹ | | **8 → 4** | **5747 → 4906** ² | **15 → 14** |

¹ vrais positifs comptés en paires (app, classe) distinctes, sans double compte entre les pistes.
² A+B confondues. Sur la seule piste autonome : **5703 → 4862**.

- **Ce qui a bougé en bien** : DVWA gagne `cmdi.probe` **HIGH** et `rce.probe` **CRITICAL** (la RCE,
  vérifiée à la main : `uid=33(www-data)`) ; VAmPI gagne `jwt.weakness` **HIGH** ; les 4 faux positifs
  de VAmPI ont disparu ; le volume de la piste B tombe de 1806 à 1558 sur DVWA et de 1175 à 319 sur
  VAmPI.
- **Ce qui n'a PAS bougé** : les **4 `header_injection.probe` HIGH de DVWA sont toujours là** (§5.2) ;
  la piste B reste à **1 seul vrai positif** sur les 4 applications ; DVGA reste à **0 sur 7** dans les
  deux pistes, et son volume **AUGMENTE** (1849 → 2940).
- **Colonne « run partiel » retirée du tableau** : elle était fausse pour 3 lignes sur 4. Voir §6bis,
  défaut **D15**.

### 5.2 Faux positifs — chaque ≥ MEDIUM rejoué à la main, dans les DEUX campagnes

**AVANT — 15 revendications ≥ MEDIUM : 7 vrais positifs, 8 FAUX POSITIFS, 0 non vérifié.**
**APRÈS — 14 revendications ≥ MEDIUM : 10 vrais positifs, 4 FAUX POSITIFS, 0 non vérifié.**

| verdict | AVANT | APRÈS | qui | pourquoi (vérifié à la main contre l'application) |
|---|---|---|---|---|
| **TP** | 3 | **3** | `access_control.idor` (Juice Shop, VAmPI A+B) | marqueur de la victime lu depuis la session de l'attaquant, absent en anonyme (401) ; Juice Shop **certifié par l'app** (« View Basket » `solved`) |
| **TP** | 3 | **3** | `sqli.probe` (DVWA ×2, Juice Shop) | erreur MariaDB / différentiel booléen / bypass d'auth `' OR 1=1--` → `admin@juice-sh.op` (témoin sans injection : 401) |
| **TP** | 1 | **1** | `path.traversal` (DVWA) | canari lu ; LFI prouvée **indépendamment** du canari (`?page=/etc/passwd` → `root:x:0:0`) |
| **TP** | 0 | **2** | `cmdi.probe` + `rce.probe` (DVWA) | **NOUVEAU (D6)** — POST `ip=127.0.0.1;id&Submit=Submit` → `uid=33(www-data)`, rejoué hors forge |
| **TP** | 0 | **1** | `jwt.weakness` (VAmPI) | **NOUVEAU (D12)** — jeton HS256 forgé hors forge avec le secret `random` (`/vampi/config.py:13`) → `PUT /users/v1/attacker1/email` accepté (**204**) |
| **FP** | 5 | **4** | `header_injection.probe` | ~~redirection de répertoire : `Location` construit depuis `Host`~~ **cette forme-là est éteinte** ; les 4 qui restent passent par une **AUTRE porte** — voir §5.2bis |
| **FP** | 3 | **0** | `ssrf.xspa` (VAmPI) | éteints — mais **pas par la voie qu'on croit** : voir §5.2ter |

Taux de faux positifs sur les revendications actionnables : ~~**8/15 ≈ 53 %**~~ → **4/14 ≈ 29 %**.
Inchangé en revanche : **la totalité des faux positifs vient du mode autonome** (piste B). La piste A,
amorcée à la main, n'a produit **aucun** faux positif sur les 4 applications, dans les deux campagnes.

### 5.2bis Les 4 `header_injection.probe` HIGH de DVWA — le correctif a déplacé la porte, pas fermé la pièce

C'était le point d'attention explicite du mandat. Verdict : **ils n'ont PAS disparu, et le correctif
D4 ne couvre pas cette forme.** Le compte est resté rigoureusement identique — seules les cibles ont
glissé d'un caractère :

| | AVANT (2026-08-10) | APRÈS (2026-08-11) |
|---|---|---|
| cibles | `/docs` · `/config` · `/external` · `/external/phpids/0.6` | `/docs/` · `/config/` · `/external/` · `/external/phpids/0.6/` |
| réponse | **301** avec `Location: http://<marqueur>/docs/` | **200**, **aucun `Location`** |
| voie du reflet | en-tête `Location` | **corps** |
| verdict forge | HIGH `vulnerable` ×4 | HIGH `vulnerable` ×4 |

Sur les cibles SANS slash final, le correctif D4 fonctionne et le dit — evidence rendue :

> « canonicalisation d'URL ÉCARTÉE (en-tête Host) : la cible a répondu une REDIRECTION vers le MÊME
> chemin sur l'hôte injecté […] aucun reflet RÉSIDUEL hors l'écho du Location. »

Mais la découverte propose AUSSI les variantes AVEC slash final, où Apache ne redirige plus : il sert
l'index de répertoire, et son pied de page recopie l'en-tête `Host`. Reproduit à la main sur les
quatre :

```
curl -H 'Host: evil.forge-hh.test' http://127.0.0.1:8081/docs/
  -> HTTP/1.1 200 OK      (aucun Location)
  -> <address>Apache/2.4.25 (Debian) Server at evil.forge-hh.test Port 80</address>
     occurrences de l'hôte injecté dans le corps : 1
     href portant l'hôte injecté                 : 0
```

C'est `ServerSignature On`, le **réglage par défaut de Debian**, et il apparaît sur **toute** page
auto-générée par Apache — index de répertoire **et page 404**. Le reflet est du **texte inerte** :
aucun lien ne le porte, aucun cache ne le sert, aucune réinitialisation de mot de passe ne l'utilise.
La vérité terrain de DVWA (`/var/www/html/vulnerabilities/`) ne déclare aucune classe « host header ».
**Quatre faux HIGH, à nouveau.**

Cause exacte, lue dans le code : `_host_reflection` (`forge/modules/httpflow.py:520`) ne discrimine
que la voie `Location`, par le chemin de destination. Dès que le marqueur est dans le CORPS,
`_reflected_in` rend `"corps"` sans autre examen, et la seule garde restante est
`control_reflects_host` — la garde que D4 a elle-même qualifiée de structurellement incapable :
la requête de contrôle part **sans** l'en-tête injecté, donc le marqueur ne peut par construction
jamais y apparaître, et elle rend **toujours** `False`. Le correctif a fermé la porte du `Location` et
laissé la porte du corps **exactement dans l'état que le banc dénonçait**. Consigné en **D14** (§6bis).

### 5.2ter Les 3 `ssrf.xspa` de VAmPI — éteints, mais la campagne ne le prouve pas

Sur la piste B, `ssrf.xspa` rend désormais `skipped — Requiert params.param` sur les 9 cibles de
VAmPI : l'URL paramétrée `/console?__debugger__=yes&cmd=resource&f=console.png` **n'est plus
découverte du tout**. Les 3 faux positifs ont donc disparu **de la campagne** sans que l'oracle ait
eu à juger — c'est le correctif de découverte (D8) qui les a fait disparaître, pas le correctif de
jugement (D5).

Le correctif D5 a donc été vérifié **séparément**, en rejouant l'oracle sur la cible EXACTE des 3 faux
positifs du 2026-08-10 :

```
forge run --actions  {kind: ssrf.xspa,
                      target: http://127.0.0.1:5001/console?__debugger__=yes&cmd=resource&f=console.png,
                      params: {param: __debugger__}}

AVANT  -> MEDIUM · vulnerable · « XSPA CONFIRMÉ — joignabilité de ports internes »
          ports JOIGNABLES = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]   (9 sur 10 FERMÉS)
APRÈS  -> INFO   · skipped    · « XSPA non testé — la réponse ne VARIE PAS selon l'URL injectée »
          « les 12 réponses (2 baselines fermées + 10 port(s)) sont IDENTIQUES octet pour octet
            (HTTP 200, 1563 o) »
```

Les 1 563 octets sont exactement ceux que le banc avait mesurés à la main en §D5. Le correctif tient
sur sa propre mesure ; **c'est la disparition en campagne qui ne prouve rien**, et le distinguer était
nécessaire.

### 5.3 Faux négatifs — expliqués, un par un (AVANT → APRÈS)

| classe manquée | app | cause établie AVANT | APRÈS (2026-08-11) |
|---|---|---|---|
| injection de commande / RCE | DVWA | **D6** — la sonde POST ne porte QUE le paramètre injecté ; DVWA exige le co-paramètre `Submit` | ✅ **TROUVÉE** — `cmdi.probe` HIGH + `rce.probe` CRITICAL, vérifiées à la main (`uid=33(www-data)`) |
| XSS réfléchi | DVWA | conception : `xss.reflected` exige un contexte JS-exécutable ; DVWA réfléchit en contenu HTML — l'oracle VOIT `réfléchi=True, non_échappé=True` et refuse de promouvoir | inchangé — toujours `tested`, abstention de conception |
| XSS stocké | DVWA, DVGA | **D7** — verdict fabriqué à partir d'une erreur du service navigateur | ✅ **abstention honnête** — `skipped · « rendu navigateur indisponible (dégradation gracieuse) »`. Toujours un faux négatif, mais il ne se déguise plus en verdict |
| XSS DOM | DVWA, Juice Shop | non mesurable ici (navigateur hors espace réseau) — `skipped`, correctement | inchangé |
| CSRF | DVWA | le détecteur d'anti-CSRF cherche `"csrf"` dans **tout le corps** ; la page DVWA « CSRF » contient le mot dans ses liens et titres | inchangé — toujours `tested`, non promu |
| SQLi | VAmPI | point d'injection = **segment de chemin** (`/users/v1/{username}`) ; les oracles n'écrivent que dans un paramètre de query ou un corps de formulaire | **inchangé** — le correctif D6 préserve les autres paramètres, il n'apprend pas à écrire dans un segment de chemin |
| BFLA (mot de passe d'autrui) | VAmPI | abstention **correcte** (`PUT` mute l'objet d'un tiers, refusé tant que `allow_destructive` est faux) | ✅ abstention désormais **nommée** : « Privesc write PUT non tiré — capacité destructive non autorisée » (au lieu de « config manquante ») |
| JWT à clé faible | VAmPI | **D12** — la liste HMAC par défaut (16 entrées) ne contient pas `random` | ✅ **TROUVÉE** — HIGH `vulnerable`, secret craqué hors ligne (candidat #16 de la liste étendue) |
| introspection GraphQL | DVGA | détectée mais rendue **INFO** par conception ; le chemin exige `b_marker` + `query` | inchangé |
| cmdi / SQLi / traversal / XSS / SSRF GraphQL | DVGA | points d'injection = **arguments dans un corps JSON GraphQL** ; aucun oracle ne sait écrire dedans | **inchangé — 0 sur 7** |
| toutes (piste B, DVWA/DVGA) | — | la découverte n'a produit **aucune URL portant un paramètre de query** | **inchangé** : 22 cibles sur DVWA, 25 sur DVGA, **aucune avec un paramètre de query** |
| toutes (piste B, Juice Shop) | — | **D13** — l'application est morte pendant la campagne | **l'application est morte À NOUVEAU** — mais cette fois la cause est mesurée (§6bis, D13-bis) et les oracles ne tirent plus sur le cadavre |

### 5.4 Le contrôle a bien reproduit la mesure de référence — deux fois

Juice Shop, piste A, dans les DEUX campagnes : `access_control.idor` → **IDOR CONFIRMÉ**,
`sqli.probe` → **SQLi CONFIRMÉ**, 6 findings, 2 revendications ≥ MEDIUM, **aucun écart**. L'app
l'atteste elle-même (`GET /api/Challenges` : `basketAccessChallenge` et `loginAdminChallenge` passés
à `solved`). Le banc n'introduit donc pas de biais, et le rejeu n'a pas dérivé : les écarts observés
sur DVWA/VAmPI/DVGA sont bien ceux du moteur.

*Nuance consignée* : en 2026-08-11 c'est le **rejeu manuel** (`' OR 1=1--` → `admin@juice-sh.op`) qui a
fait basculer `loginAdminChallenge`, alors qu'en 2026-08-10 la sonde de forge l'avait fait elle-même.
Forge a prouvé la SQLi par différentiel d'AUTORISATION (`' OR '1'='1'-- -`, 401 → 200) sans viser le
compte administrateur. La revendication reste un vrai positif — la vuln est à l'endroit annoncé — mais
la certification par l'app vient d'ailleurs.

### 5.5 Verdict honnête sur la généralisation — le chiffre a bougé, la frontière non

**Forge généralise un peu plus largement, toujours étroitement, et toujours seulement quand on
l'amorce.**

- **Ce qui tient sur plusieurs stacks** : ~~`sqli.probe`, `access_control.idor` et `path.traversal` —
  **3 classes d'oracle sur 25 opposables**~~ → désormais **6 classes d'oracle sur les 13 opposables**
  du banc : `sqli.probe`, `access_control.idor`, `path.traversal`, **`cmdi.probe`**, **`rce.probe`**,
  **`jwt.weakness`**. En paires (app, classe) : **6 → 9 sur 23**.
- **La frontière, elle, s'est déplacée d'un cran seulement.** L'ancien constat disait « rien hors
  paramètre de query sur une URL connue ». Ce n'est plus exact : le correctif D6 fait entrer le
  **formulaire POST multi-champs** (DVWA `exec`, qui exige le co-paramètre `Submit`) — et c'est la
  RCE, la trouvaille la plus lourde du banc. Mais les deux autres formes n'ont **pas** bougé :
  **segment de chemin** (VAmPI SQLi) et **corps JSON GraphQL** (DVGA) restent à **0 détection**.
- **GraphQL : le chiffre n'a PAS bougé — 0 sur 7**, dans les deux pistes, dans les deux campagnes.
  Une stack entière reste hors de portée, et son volume de bruit a même **augmenté** (1849 → 2940).
- **Le mode autonome ne trouve toujours presque rien, et se trompe encore plus souvent qu'il ne
  trouve.** ~~5703 findings, 1 vrai positif, 8 faux positifs~~ → **4862 findings sur les 4 campagnes,
  toujours 1 SEUL vrai positif** (la BOLA de VAmPI, et uniquement parce que l'opérateur avait déclaré
  la cible IDOR dans le scope), contre **4 faux positifs**. Le rapport faux/vrai s'améliore de 8:1 à
  **4:1** — il reste **défavorable**.
- **Répondre à la question posée** : *forge a-t-il été ajusté à Juice Shop ?* Non, et c'est encore
  plus net qu'avant — les classes qui marchent sur Juice Shop marchent ailleurs, et DVWA en trouve
  désormais **plus** que la cible de référence. *Mais* l'échantillon de 1 masquait toujours la même
  chose : hors des formes de requête que les oracles savent écrire, la couverture tombe à zéro, et le
  mode autonome produit encore plus de faux HIGH que de vrais.

**Recommandation de publication — NON RENVERSÉE.** Publier le mode `--auto-pentest` comme un scanner
resterait **indéfendable** :

1. **Plus de faux que de vrais** : 4 HIGH faux contre 1 vrai positif. Un opérateur qui suivrait ce
   rapport enverrait 4 rapports « host header poisoning » sur une signature Apache par défaut.
2. **La cible meurt toujours**, et cette fois la cause est établie (§6bis, D13-bis) : idle 34 minutes
   → mémoire stable ; campagne lancée → 4,9 Gio et `Exited(139)` en **90 secondes**.
3. **13 nmap sur 13 rapportent « j'ai vérifié » après avoir scanné 0 hôte** (§6bis, D16). Le compte a
   chuté (72 → 13), la cécité est restée à **100 %**.
4. La découverte ne produit **toujours aucune URL portant un paramètre de query** : les oracles qui
   paient n'ont rien à mordre en mode autonome.

En revanche les **oracles amorcés** (piste A) sont défendables, et le sont **davantage** qu'avant :
**0 faux positif** sur les 4 applications dans les deux campagnes, **9 vrais positifs au lieu de 6**,
dont une **RCE CRITICAL prouvée**, et des abstentions nommées au lieu de verdicts fabriqués.
Le chemin de publication reste « forge = un vérificateur d'hypothèses amorcé par l'opérateur », pas
« forge = un scanner autonome » — désormais jusqu'à ce que **D14, D16 et la cause de D13** soient
traités.

## 6. Les 13 défauts du 2026-08-10 — **texte d'origine conservé**, statut mesuré en campagne complète

> Les descriptions ci-dessous sont celles du jour où le banc les a trouvés, **inchangées**. Les 13 ont
> été fermés depuis (`ROADMAP.md` § « Remédiation des 13 défauts »), mais ils n'avaient été mesurés
> qu'**isolément**. Le tableau qui suit dit ce que la campagne COMPLÈTE du 2026-08-11 a constaté —
> et pour trois d'entre eux, le constat n'est pas celui qu'on attendait.

| # | ce que le correctif promettait | **constaté en campagne complète** |
|---|---|---|
| D1 | l'IDOR à 2 comptes n'est plus éteint par `scope.session` | ✅ evidence VAmPI : `anon=401 · anon_refusé=True · « sonde anonyme tirée SANS matériel de session gouverné »` |
| D2 | l'evidence du chemin à marqueur ne ment plus | ✅ idem — l'ancien `anon=200 / anon_refusé=False` a disparu |
| D3 | plus de HIGH sur une ressource publique | ✅ véto de publicité visible dans l'evidence (`marqueur_lisible_anonymement=False`) ; aucun HIGH sur ressource publique dans les 4 campagnes |
| D4 | les 5 `header_injection` faux sont éteints | ⚠️ **PARTIEL — 1 sur 5 éteint pour de bon.** VAmPI `/ui` : oui, avec l'abstention nommée. DVWA : les 4 HIGH **reviennent** par une autre porte → **D14** |
| D5 | `ssrf.xspa` n'invente plus de ports joignables | ✅ vérifié **séparément** sur la cible exacte (§5.2ter) — en campagne, la cible avait déjà disparu de la découverte |
| D6 | la RCE de DVWA devient atteignable | ✅ **HIGH + CRITICAL**, `uid=33(www-data)` vérifié à la main. La plus grosse trouvaille du rejeu |
| D7 | `xss.stored` ne fabrique plus de verdict négatif | ✅ `skipped — rendu navigateur indisponible (dégradation gracieuse)` sur DVWA **et** DVGA |
| D8 | plus de 404 ingérés en endpoints | ✅ 22 cibles sur DVWA (toutes réelles), 9 sur VAmPI ; **aucune URL fantôme** du type `/modern%20mom` |
| D9 | plus de nmap sur un endpoint | ⚠️ **PARTIEL** — 72 → 13, mais **13 sur 13 scannent 0 hôte et rendent `tested`** → **D16** |
| D10 | `forge run --actions` injecte le contexte d'auth | ✅ (le banc passe toujours les valeurs dans l'action ; l'injection est désormais idempotente) |
| D11 | `rc=1` sur vuln prouvée | ✅ **5 runs sur 8 rendent `rc=1`**, exactement ceux qui portent un `vulnerable` (DVWA A/B, VAmPI A/B, Juice Shop A) |
| D12 | `jwt.weakness` craque le secret de VAmPI | ✅ **HIGH `vulnerable`**, confirmé hors forge (jeton forgé avec `random` → 204) |
| D13 | plus de tir sur cadavre | ✅ pour le **symptôme** (8 tirs, **0 verdict d'oracle qualifiant** post-mortem) · ❌ pour la **cause**, qui est maintenant établie → **D13-bis** |

Le texte d'origine des 13 entrées suit. Chaque entrée porte sa preuve : une commande, une sortie, ou
un extrait de code à la ligne près. L'ordre est celui de la gravité pour un opérateur **au moment où
elles ont été écrites**.

### D1 — Une session gouvernée DÉSACTIVE l'oracle IDOR à 2 comptes (faux négatif silencieux)

`access_control.idor` juge par `vuln = same and anon_denied` (`access_control.py:390`), où
`anon_denied` vient de `ru = self._fetch(url, {})` (`access_control.py:363`). Mais `Oracle._http`
**fusionne la session gouvernée** (`scope.session`) sur toute URL in-scope : la sonde dite « anonyme »
part donc AUTHENTIFIÉE dès qu'un `scope.session` est configuré — ce que `scope.example.json`
recommande explicitement pour attacher du matériel d'auth.

Mesuré sur la BOLA réelle de VAmPI (`GET /books/v1/victimbook`, vérité terrain : README de l'app),
mêmes comptes, même cible, seul `scope.session` diffère :

| scope | evidence rendue par l'oracle | verdict |
|---|---|---|
| **avec** `session` | `A=200 B=200 anon=200 même_objet=True anon_refusé=False` | `IDOR non confirmé` — **INFO** |
| **sans** `session` | `A=200 B=200 anon=401 même_objet=True anon_refusé=True` | `IDOR CONFIRMÉ` — **HIGH** |

Vérification indépendante : `curl http://127.0.0.1:5001/books/v1/victimbook` (sans en-tête) → **401**.
Et directement sur le chokepoint :

```
Oracle._http(url, headers={})                       -> 401     (vraiment anonyme)
with session.using(store): Oracle._http(url, {})    -> 200 + corps du panier
```

**Conséquence** : la classe #1 du bug bounty est éteinte par une configuration légitime — et sans
aucun signal, puisque le finding rendu est un « non confirmé » d'apparence normale.

### D2 — La même sonde fausse l'evidence du chemin à marqueur

Sur le chemin `_fire_auth_targets`, `anon_denied` ne promeut pas, mais il est **imprimé** :
sur Juice Shop, `GET /rest/basket/1` répond **401** à un anonyme réel, et l'evidence du finding dit
`anon=200 ; anon_refusé=False`. Un relecteur y lit « ressource publique » et écarte un vrai positif.

### D3 — `access_control.idor` promeut un HIGH sur une ressource PUBLIQUE

`proven = marker_hit` seul (`access_control.py:227`). Un marqueur présent dans une ressource
publique ne prouve aucune appartenance, et la sonde anonyme — cassée par D1 — ne peut pas véto.

Contre-épreuve exécutée : `GET /users/v1` de VAmPI est **public par conception** (anon → 200, liste
tous les utilisateurs), déclaré `idor_target {owner: victim, marker: "victim1"}`. Verdict rendu :

> **HIGH · vulnerable · « IDOR CONFIRMÉ — l'attaquant lit la ressource de la victime (accès
> cross-compte) »**, evidence `anon=200 … anon_refusé=False`.

Un test porte pourtant ce nom — `tests/test_auth_context.py::test_no_false_positive_on_public_200`.
Il passe, et il ne peut pas échouer : son `idor_target` n'a **pas de `marker`**
(`{"url": …, "owner": "victim"}`), or `marker_hit = bool(marker) and …`. Le test couvre donc la
branche NON promouvante et laisse intacte celle qui promeut — celle que `scope.example.json` décrit
comme « le chemin PRÉFÉRÉ ».

### D4 — `header_injection.probe` : un HIGH par répertoire, sur du comportement de serveur par défaut

Un `Host:` reflété dans `Location:` promeut `HIGH / vulnerable / CWE-644 (host header poisoning)`
(`httpflow.py:515`). Or **toute** redirection de répertoire construit son `Location` à partir du
`Host` de la requête. Reproduit sur DEUX stacks :

```
curl -H 'Host: evil.example' http://127.0.0.1:8081/docs   -> 301  Location: http://evil.example/docs/   (Apache 2.4)
curl -H 'Host: evil.example' http://127.0.0.1:5001/ui     -> 308  Location: http://evil.example/ui/     (Werkzeug 2.2)
```

Ni DVWA ni VAmPI ne déclarent cette classe dans leur vérité terrain. Récolte : **4 HIGH sur DVWA**
(un par répertoire découvert) + **1 HIGH sur VAmPI**. Le contrôle interne ne peut pas rattraper : il
compare avec le **vrai** `Host`, où le marqueur ne peut par construction pas apparaître.

### D5 — `ssrf.xspa` déclare JOIGNABLES des ports qui n'écoutent nulle part

Sur VAmPI (Flask `debug=True`, donc console Werkzeug exposée), la campagne autonome a promu **3
findings MEDIUM `vulnerable`** :

> « XSPA CONFIRMÉ — joignabilité de ports internes via SSRF » ·
> `ports JOIGNABLES (différentiel)=[22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]`

Vérification par connexion TCP directe sur le même hôte : **9 de ces 10 ports sont FERMÉS**
(seul `8080` écoute). Et la cible — `/console?__debugger__=yes&cmd=resource&f=console.png`, le
servant de ressources statiques du débogueur — n'est pas SSRF-able du tout :

```
__debugger__=yes                        -> 200,  507 o
__debugger__=http://127.0.0.1:1/        -> 200, 1563 o     <- « baseline port fermé »
__debugger__=http://127.0.0.1:3306/     -> 200, 1563 o     <- corps IDENTIQUE
```

⚠️ **CETTE CAUSE ÉTAIT FAUSSE, corrigée le 2026-08-11** — elle est laissée ici parce qu'un rapport
de banc qui réécrit ses erreurs ne vaut plus rien comme référence. Version initiale : « le
différentiel repose sur des écarts de timing de l'ordre de 20 ms (`0.036s` vs `0.056s`) ». **Le
timing est mesuré et imprimé mais n'entre dans AUCUN verdict** — seul `sig != closed_sig` promeut.

**La vraie cause** : la neutralisation du reflet était appliquée de façon **ASYMÉTRIQUE**. La
baseline était le port **1**, et le corps était scrubé du numéro de port de la requête courante :

    re.sub(r"(?<!\d)1(?!\d)",    "<PORT>", body)   # baseline : mange TOUS les « 1 » isolés
    re.sub(r"(?<!\d)3306(?!\d)", "<PORT>", body)   # port     : no-op

Sur n'importe quel corps HTML (`HTTP/1.1`, `version 1.0.1`), la baseline est mutilée et les corps de
ports ne le sont pas. Reproduit : corps IDENTIQUES en entrée -> signatures différentes -> les 10
ports déclarés « diff », 10 sur 10. **Le mécanisme censé supprimer le faux signal le fabriquait**,
inconditionnellement — et le module émettait `status=vulnerable` en MEDIUM là-dessus.

La leçon vaut au-delà de D5 : la cause « évidente » (le timing, visible dans l'evidence) n'était pas
la cause. C'est le neuvième diagnostic de cette série à tomber devant la mesure.

### D6 — Les oracles d'injection perdent les autres paramètres de la requête

Quatre implémentations indépendantes (`injection.py::_send`, `clientflow.py::_send_h`, `rce.py`,
`ssrf.py`) construisent la requête ainsi :

```python
sep = "&" if "?" in action.target else "?"
url = f"{action.target}{sep}{urllib.parse.urlencode({param: payload})}"   # GET : AJOUTE
...
data=urllib.parse.urlencode({param: payload})                             # POST : REMPLACE tout le corps
```

- **POST** — le corps ne contient QUE le paramètre injecté. L'injection de commande de DVWA exige le
  co-paramètre `Submit` : `ip=127.0.0.1;echo FORGEMARK123` seul → **0 occurrence** ; le même payload
  avec `&Submit=Submit` → **1 occurrence** (commande exécutée). D'où `cmdi.probe` et `rce.probe` en
  « non confirmée » sur une RCE bien vivante (`uid=33(www-data)` vérifié à la main).
- **GET** — le paramètre est AJOUTÉ, pas substitué : `?id=1&Submit=Submit&id=<payload>`. En PHP le
  dernier gagne (mesuré : `ID: 2`) donc ça marche ; en **Flask/Werkzeug le premier gagne**
  (`MultiDict(parse_qsl("id=1&Submit=Submit&id=INJECTION")).get("id")` → **`1`**). Sur tout parseur
  premier-gagnant, la charge n'atteint jamais le sink et l'oracle rend malgré tout « non confirmé ».

Ce défaut est **invisible sur une seule cible** : il dépend du parseur de la stack.

### D7 — `xss.stored` rend un verdict NÉGATIF à partir d'une page d'erreur du navigateur

Garde de `clientflow.py:620` : `if rst is None or not dom:` — le **succès** de la navigation n'est jamais
vérifié. Un 500 du service navigateur renvoie `(500, "Internal Server Error")` : `dom` est non vide,
la garde passe, et l'oracle conclut. Reproduction déterministe (seams stubés) :

```
xss.stored     -> tested  · « XSS stored non confirmé — pas de reflet exécutable non échappé
                            dans le DOM rendu » ; evidence : « réfléchi=False … module NAVIGATEUR
                            utilisé pour le rendu DOM »
xss.execution  -> skipped · « sonde navigateur non aboutie (dégradation gracieuse) »   <- correct
```

L'oracle frère fait le bon choix (`if not _ok(gst): return False`). C'est un verdict fabriqué.

### D8 — La découverte ingère des 404 comme endpoints, sans sonde de confirmation

Le spec `recon.feroxbuster` (`toolcatalog.py:366`) invoque `--silent` et parse `https?://\S+`.
`--silent` **supprime la colonne de statut** : forge ne peut pas la voir. Mesuré :

```
docker run --rm --network host epi052/feroxbuster -u http://127.0.0.1:8081 --no-recursion
  404  ... 285c http://127.0.0.1:8081/modern%20mom
  404  ... 287c http://127.0.0.1:8081/Reports%20List
```

(l'auto-filtre de feroxbuster manque ces 404 : leur taille varie avec la longueur du chemin.)
Ces URLs deviennent des **nœuds du graphe** et reçoivent tout le balayage d'oracles. `_discovery.py`
applique pourtant exactement cette discipline aux PORTS (« un vrai GET obtient un STATUS HTTP ») —
elle n'est pas appliquée aux URLs. C'est l'origine du gros du volume : 1806 findings sur DVWA.

### D9 — `--auto-pentest` contourne la discrimination hôte/endpoint

`brain.py:175` dit explicitement qu'un endpoint ne doit pas recevoir « recon/nmap/origin sur une
URL », et `_base_actions` l'applique. Mais `AutoPentestBrain.propose` balaie **chaque technique sur
chaque cible touchée**, endpoints compris, sans ce garde. Résultat mesuré dans le ledger :

```
poc      : docker run --rm --network host instrumentisto/nmap -sV -Pn --top-ports 1000 \
           http://127.0.0.1:8081/Planned%20Giving
evidence : Nmap done: 0 IP addresses (0 hosts up) scanned in 0.35 seconds
status   : tested        title : « Services exposés (nmap -sV) »
```

**22 findings `recon.nmap` sur 22** sont dans ce cas. nmap sort `rc=0` (« Unable to split netmask
from target expression »), donc la borne `rc != 0` de `blindness.tool_did_not_run` ne peut pas le
voir : un outil qui n'a rien scanné est rendu en « j'ai vérifié ».

### D10 — `forge run --actions` n'injecte pas le contexte d'auth par-engagement

L'injection des `accounts`/`idor_targets` depuis `scope.auth` vit dans `Engine._prepare`
(`engine.py:1184-1209`), appelé UNIQUEMENT par `campaign()`. `Engine.run()` (`engine.py:839`) ne
l'appelle pas. Conséquence : avec un `scope.auth` complet, `forge run --actions` rend « IDOR non
testé — config manquante ». Le banc contourne en passant les valeurs dans l'action ; la CLI, elle,
ne le documente nulle part.

### D11 — Le code de sortie documenté « 1 = vuln trouvée » n'est jamais produit

`docs/CLI.md:16` annonce « `0` OK, `1` échec/vuln trouvée ». `cmd_run` (`cli/engine.py:277`) et
`cmd_campaign` (`cli/engine.py:466`) font `return 0` inconditionnellement. Mesuré : tous les runs du
banc qui ont produit des findings `HIGH/vulnerable` sortent en **`rc=0`**. Une CI qui gate sur le
code de sortie ne verrait jamais une vulnérabilité.

### D12 — La liste HMAC par défaut de `jwt.weakness` est très courte

16 secrets (`tokenapi.py:108`). Le secret de VAmPI est `'random'` (`config.py`) et n'y figure pas →
faux négatif. Avec `hmac_wordlist=["secret","password","random","changeme"]`, le même oracle rend
**HIGH · vulnerable · « secret HMAC faible craqué hors-ligne »**. Le mécanisme est bon, la liste est
le facteur limitant.

### D13 — Le mode autonome TUE la cible, et les oracles qualifiants tirent sur un cadavre

Deux campagnes `--auto-pentest` sur OWASP Juice Shop, deux **crashs de l'application** :

```
docker ps -a  ->  forge-bench-juice     Exited (139)
                  forge-bench-juiceshop Exited (139)
docker logs   ->  FATAL ERROR: Ineffective mark-compacts near heap limit
                  Allocation failed - JavaScript heap out of memory
```

Conséquence mesurable : `access_control.idor` — la classe #1 — a rendu, aux DEUX runs,
« IDOR non testé — cible injoignable (aucune réponse) … attaquant=None, anonyme=None ». L'oracle
s'abstient correctement (c'est la bonne discipline), mais le résultat net est **zéro mesure** : la
tempête de découverte de contenu passe AVANT les oracles qualifiants et emporte la cible. Le
plancher anti-famine du planner protège leur *sélection*, pas leur *ordre d'exécution*.

C'est aussi un problème de politique : le workspace bannit les techniques DoS, et le mode autonome
en produit une par accident.

## 6bis. Défauts mis au jour par le REJEU (2026-08-11) — CONSIGNÉS, NON CORRIGÉS

Aucun fichier de `forge/**` n'a été modifié par ce rejeu. Comme au premier tour, chaque entrée porte
sa preuve : une commande, une sortie, ou un extrait de code à la ligne près.

### D13-bis — La cause de la mort de Juice Shop est établie, et ce n'est PAS celle qui a été retenue

Le correctif D13 (gate de liveness) a été livré avec une conclusion explicite : *« la campagne n'était
pas la CAUSE de la mort »*, appuyée sur une mesure d'un agent (conteneur seul, zéro paquet, 121 Mio →
4,79 Gio, mort à 222 s). La ROADMAP note que l'orchestrateur **n'a pas reproduit ce renversement** et
laisse la question ouverte. **Le rejeu la tranche.**

Le banc lance Juice Shop **en même temps que les trois autres applications** puis la teste **en
dernier**. Elle est donc restée en vie, sans être ciblée, pendant 34 minutes — un contrôle négatif
gratuit. Échantillonnage `docker stats --no-stream`, une mesure par minute :

```
12:38:47  102.6 MiB      <- conteneur levé à 12:34:39, AUCUNE campagne ne le vise
12:45:55   57.1 MiB
12:55:05   48.1 MiB
13:05:16   63.8 MiB
13:11:22   24.4 MiB
13:12:23   21.2 MiB      <- 34 minutes plus tard : mémoire STABLE, tendance à la BAISSE

13:12:42                 <- la phase juiceshop commence (piste A, puis `--auto-pentest`)
13:13:24    3.782 GiB    <- ~40 s après
13:14:25    4.905 GiB
13:14:47                 <- Exited (139) · FATAL ERROR: Ineffective mark-compacts near heap limit
```

`docker inspect` : `StartedAt 10:34:39Z → FinishedAt 11:14:47Z`, `ExitCode 139`, `OOMKilled false`
(c'est le heap V8 qui sature, pas le cgroup). **34 minutes au repos : rien. 90 secondes sous
campagne : 0,02 → 4,9 Gio, puis mort.** La prémisse « elle s'autodétruit toute seule » est donc
**contredite par la mesure**, et le constat d'origine du banc — *le mode autonome tue la cible* — est
**rétabli**. La décision produit « aucun throttle n'est justifié » repose sur une prémisse fausse.

Ce qui tient, en revanche, c'est le correctif lui-même : `Tirées=8` sur le cadavre (contre 1107
avant), chaque abstention nommée (« la cible a répondu pendant ce run puis a CESSÉ de répondre »), et
**aucun oracle qualifiant n'a émis de verdict post-mortem** — les 22 findings postérieurs à la mort
sont tous des enregistrements `feroxbuster` de l'outil qui était en vol au moment du crash.

### D14 — `header_injection.probe` : la garde D4 ne couvre QUE la voie `Location` ; la voie du CORPS est intacte

Décrit en détail en §5.2bis. En résumé : **4 HIGH faux sur DVWA, exactement autant qu'avant**, sur les
mêmes répertoires, à un caractère près.

```
curl -H 'Host: evil.forge-hh.test' http://127.0.0.1:8081/docs/      -> 200, AUCUN Location
  corps : <address>Apache/2.4.25 (Debian) Server at evil.forge-hh.test Port 80</address>
  occurrences de l'hôte injecté dans le corps : 1        href porteur : 0
  (identique sur /config/, /external/, /external/phpids/0.6/ — et sur toute page 404)
```

`ServerSignature On` est le défaut Debian d'Apache : **toute** page auto-générée recopie l'en-tête
`Host`. Le reflet est du texte inerte dans un `<address>` — aucun lien, aucun cache, aucun lien de
réinitialisation. Aucune des quatre applications ne déclare cette classe dans sa vérité terrain.

Mécanique, à la ligne : `_host_reflection` (`httpflow.py:520`) n'appelle `_is_canonical_redirect` que
pour discriminer le `Location`. Dès que le marqueur est dans le corps, `_reflected_in`
(`httpflow.py:286`) rend `"corps"` sans autre examen, et la seule garde restante est
`control_reflects_host` — **la garde que D4 a elle-même démontrée incapable** : la requête de contrôle
part sans l'en-tête injecté, donc le marqueur ne peut par construction jamais y apparaître, et elle
rend toujours `False`. Le correctif D4 a donc traité **le symptôme observé** (la redirection de
répertoire), pas **le mécanisme** (une garde de contrôle qui ne peut rien garder).

### D15 — Le drapeau `partial` du BANC est vrai pour toute campagne, interrompue ou non

Défaut **du banc**, pas du moteur, et il touche une colonne publiée : `harness.py:108` décide
`partial = hard_kill or ("PARTIEL" in text.upper()) or ("interrompu" in text.lower())`, où `text` est
la sortie standard de forge **plus** le rapport. Or `forge/cli/engine.py:177` émet, **au lancement**
de toute campagne pourvue d'un `--run-timeout` :

> `# Budget de temps : 900s — à l'échéance le run S'ARRÊTE proprement (frontière d'action) et rend un
> rapport annoncé PARTIEL.`

Contre-épreuve exécutée — une campagne d'**une seule action**, terminée en quelques secondes,
`Déférées(budget)=0`, `rc=0`, rapport **sans** bannière d'interruption :

```
banniere de LANCEMENT contient « PARTIEL »  -> OUI (ligne 1)
rapport annonce « RAPPORT PARTIEL »          -> NON (0 occurrence)
ce que le harnais en déduit                  -> partial = True
```

Conséquence : les quatre lignes `OUI (budget)` de la colonne « run partiel » du tableau §5.1 **du
2026-08-10 ne portaient aucune information**. Le vrai décompte, lu dans le rapport du moteur (qui, lui,
dit vrai) : **une seule** campagne sur quatre a réellement été interrompue par le budget — VAmPI B
(909,3 s pour 900 s demandées, bannière « RAPPORT PARTIEL » présente). DVWA B (617 s) et DVGA B
(718 s) sont allées au bout, avec des actions **non démarrées** par la gate de budget et nommées comme
telles (`web.testssl`, `web.zap_baseline`, `xss.dalfox` : « borne d'exécution déclarée 600s > budget
de temps restant 299s »). Juice Shop B s'est arrêtée sur la mort de la cible, pas sur le budget.
La colonne a été retirée du tableau et remplacée par ce paragraphe.

### D16 — 13 nmap sur 13 rendent « j'ai vérifié » après avoir scanné **0 hôte**

Le correctif D9 a bien fait chuter le **nombre** de tirs nmap (72 → 13) en appliquant au balayage
autonome la règle que `brain.py:175` énonçait déjà. Mais le défaut que D9 nommait — *« un outil qui
n'a rien scanné est rendu en “j'ai vérifié” »* — est **intact**, et sa fréquence est passée de 22/72
à **13/13**.

```
poc      : docker run --rm --network host instrumentisto/nmap -sV -Pn --top-ports 1000 127.0.0.1:8081
evidence : Nmap done: 0 IP addresses (0 hosts up) scanned in 1.10 seconds
statut   : tested      titre : « Services exposés (nmap -sV) »
```

Les 13 tirs (DVWA ×5, DVGA ×4, VAmPI ×3, Juice Shop ×1) scannent tous **0 hôte** et rendent tous
`tested`. Deux causes distinctes, aucune couverte :

- **forme URL** — `http://127.0.0.1:8081`, `http://127.0.0.1:8081/`, `https://127.0.0.1:8081` sont
  encore proposées à nmap. Le garde de D9 discrimine « endpoint » et « hôte » ; une URL de RACINE
  passe pour un hôte ;
- **forme `host:port`** — `127.0.0.1:8081` est traité par nmap comme un **nom d'hôte** à résoudre, qui
  n'existe pas → `0 IP addresses`. Même la forme « correcte » est donc inscannable telle quelle.

nmap sort `rc=0` dans les deux cas, donc la borne `rc != 0` de `blindness.tool_did_not_run` ne peut
toujours pas le voir. Un opérateur lit « Services exposés — vérifié » là où rien n'a été regardé.

### D17 — Le banc a émis du trafic vers un TIERS, et sa liste d'exclusion ne pouvait pas le voir

Défaut **du banc**, et il touche sa garantie de sûreté la plus forte (§4 : « aucun trafic vers un
tiers »). `provision.THIRD_PARTY_MODULES` exclut les modules dont **l'intention déclarée** est
d'interroger un tiers (crt.sh, Wayback, résolveurs DNS publics, dépôts de templates, collecteurs de
callback). `recon.httpx` n'en fait pas partie — il ne parle qu'à la cible… sauf au premier
démarrage :

```
finding « Fingerprint HTTP (httpx) », evidence :
  2026/08/11 10:43:40 INFO Model not found, downloading
      url=https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/model.json
      dest=/root/.dit/model.json
  2026/08/11 10:43:42 INFO Model downloaded size=92.6MB
```

Constaté **4 fois** (DVWA ×2, DVGA, Juice Shop ; le conteneur tourne en `--rm`, donc rien n'est mis en
cache d'un tir à l'autre) : soit ≈ **370 Mio téléchargés depuis huggingface.co** pendant un run dont
la propriété annoncée est le loopback strict. Aucune requête n'est sortie **vers les cibles**, et le
`verify_loopback_only()` a bien fait son travail — mais il vérifie les sockets d'**écoute**, pas
l'**egress**. Balayage des 4 906 findings : c'est le **seul** egress prouvé ; toutes les autres
occurrences d'hôtes tiers sont du contenu de page cité en evidence (`github.com` dans le HTML de
DVGA), des bannières d'outil (`nmap.org`), ou des marqueurs synthétiques jamais résolus
(`attacker.example`, `forge-redirect.example`).

**La leçon est la même que celle de D5** : une garde formulée sur l'INTENTION d'un module ne peut pas
attraper un comportement de son outil sous-jacent. Il faudrait mesurer l'egress (réseau du conteneur
d'outil coupé, ou observation) plutôt que de le déclarer.

### D18 — L'amorçage du banc mute la cible, et le banc ne le dit pas

Mineur, mais il fausse toute reprise manuelle. L'action `csrf.state_change` de la piste A vise
`/vulnerabilities/csrf/?password_new=a&password_conf=a&Change=Change` : elle **change réellement le
mot de passe** du compte `admin` de DVWA en `a`. Constaté après coup — la reconnexion manuelle avec
`admin/password` échoue, `admin/a` réussit. Un nouveau run du banc n'en souffre pas
(`provision.prime_dvwa` réinitialise la base via `setup.php` avant de se connecter), mais toute
vérification manuelle faite APRÈS un run doit le savoir. L'`AuthMaterial.declared` de DVWA ne
mentionne pas cet effet de bord.

## 7. Ce qui a bien tenu (à ne pas perdre)

- **L'anti-masquage est réel.** ~~Le run DVWA a été coupé par le budget et le rapport l'annonce en
  tête : « RAPPORT PARTIEL — RUN INTERROMPU », « 1751 action(s) exécutée(s) sur 2700 planifiée(s),
  949 jamais tentée(s) »~~ — **exemple corrigé le 2026-08-11, il n'était pas le bon** : le drapeau qui
  l'avait désigné venait du banc, pas du moteur (défaut **D15**). Le mécanisme, lui, tient et se
  vérifie sur la campagne qui a VRAIMENT été interrompue, **VAmPI B** (909,3 s pour 900 s demandées) :
  son rapport porte bien la bannière « RAPPORT PARTIEL — RUN INTERROMPU » en tête, et forge le répète
  jusque dans le résumé de sortie — « 1 finding(s) PROUVÉ(S) vulnerable (run INTERROMPU : ce total ne
  couvre que la partie exécutée) ». Sur les campagnes NON interrompues, la même discipline s'applique
  aux actions non démarrées par la gate de budget, nommées une par une : « borne d'exécution déclarée
  600s > budget de temps restant 299s — la démarrer dépasserait l'échéance ; AUCUN verdict n'est émis
  pour cette action (non testée, pas “rien trouvé”) ».
- **La discipline de preuve tient sur les négatifs**, et elle a tenu deux fois : ~~1770 des 1806
  findings DVWA~~ → **1476 des 1558** sont des `INFO` `tested`/`skipped` explicites (le reste : 78 LOW
  et les 4 HIGH faux) ; aucun verdict aveugle, chaque abstention est nommée. Mieux qu'avant : les abstentions qui étaient auparavant des
  verdicts fabriqués (`xss.stored`) ou muettes (`privesc`) sont désormais motivées en clair.
- **La gate de liveness tient sur sa propre mesure.** Juice Shop est morte pendant la campagne, comme
  la première fois — mais **`Tirées=8`** sur le cadavre, chaque `SKIP` nommé (« la cible a répondu
  pendant ce run puis a CESSÉ de répondre »), et **aucun oracle qualifiant n'a émis de verdict
  post-mortem** (contre 221 « j'ai vérifié, rien trouvé » avant).
- **Une revendication d'outil tiers reste cantonnée.** `dalfox` a signalé un XSS réfléchi sur
  `/docs?any=…` ; vérification manuelle : la charge revient **URL-encodée** dans le `href`, donc
  inerte. Forge l'a classé `reported_by_tool` / LOW, sous « Signal à qualifier (exploitabilité NON
  démontrée) » — jamais promu. C'est le bon comportement, et il n'a pas régressé : les 70
  `reported_by_tool` du rejeu sont tous en LOW, aucun promu.
- **Le scope-guard fait ce qu'il dit.** `scope-check` in-scope → `rc=0`, hors périmètre
  (`http://example.com`) → `rc=1`, sur les **quatre** engagements des **deux** campagnes ; aucune
  requête n'est sortie de la boucle locale **vers une cible**. Réserve nommée : un outil, lui, est
  sorti — voir **D17**.
- **Le contrat de code de sortie est désormais honoré** (D11) : 5 des 8 runs rendent `rc=1`, et ce
  sont exactement les 5 qui portent un finding `vulnerable`.

## 8. Reproduire

```bash
python3 -m bench.detection.run_bench --workdir /tmp/bench --track both --budget 900
python3 -m bench.detection.report   --workdir /tmp/bench --verdicts bench/detection/verdicts.json
python3 -c "from bench.detection import provision; provision.teardown()"
```

`run_bench` écrit `manifest.json` (amorçage, scope rédigé, durées, drapeau `partial` par piste —
**attention : ce drapeau est faux, cf. D15 ; lire la bannière du rapport du moteur**), un store
`--memory` JSONL par piste et par application (les findings bruts), le rapport markdown du moteur et
son ledger signé.

Sorties brutes conservées, une par campagne — **jamais écrasées** :
[`RESULTS_2026-08-10.md`](../bench/detection/RESULTS_2026-08-10.md) ·
[`RESULTS_2026-08-11.md`](../bench/detection/RESULTS_2026-08-11.md).
Les verdicts manuels des deux campagnes cohabitent dans
[`verdicts.json`](../bench/detection/verdicts.json) : les cibles ont changé de forme entre les deux
runs (correctif D6), donc les clés ne se recouvrent pas, et `report.py` n'apparie que celles du run
qu'on lui donne.
