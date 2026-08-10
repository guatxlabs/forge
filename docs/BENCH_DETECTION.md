<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Banc de détection multi-applications — méthode et résultats

> [Sommaire](README.md) · Code du banc : [`../bench/detection/`](../bench/README.md) ·
> Mesure historique mono-cible : `ROADMAP.md` § « Pouvoir de détection — mesuré, pas supposé »

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
- **Limite assumée** : le service navigateur gouverné tourne dans son propre espace réseau ; il ne
  peut pas atteindre un `127.0.0.1:<port>` de l'hôte. Les oracles adossés au navigateur
  (`xss.execution`, le rendu DOM de `xss.stored`) sont donc **non mesurables** sur ce banc — ils sont
  comptés `skipped`, jamais `manqués`. Les rendre mesurables exigerait de lier les applications à
  l'adresse du pont docker, ce que la règle « loopback uniquement » interdit.

## 5. Résultats

### 5.1 Synthèse

| app | piste | classes opposables | **vrais positifs** | **faux négatifs** | classes sans oracle | findings émis | ≥ MEDIUM revendiqués | run partiel |
|---|---|---|---|---|---|---|---|---|
| Juice Shop | A | 3 | **2** | 1 | 0 | 6 | 2 | non |
| Juice Shop | B | 3 | **0** | *(non mesuré)* | 0 | 873 | 0 | OUI — **cible morte** |
| DVWA | A | 9 | **3** | 6 | 5 | 15 | 3 | non |
| DVWA | B | 9 | **0** | 9 | 5 | 1806 | 4 | OUI (budget) |
| VAmPI | A | 4 | **1** | 3 | 3 | 8 | 1 | non |
| VAmPI | B | 4 | **1** | 3 | 3 | 1175 | 5 | OUI (budget) |
| DVGA | A | 7 | **0** | 7 | 6 | 15 | 0 | non |
| DVGA | B | 7 | **0** | 7 | 6 | 1849 | 0 | OUI (budget) |

### 5.2 Faux positifs — chaque ≥ MEDIUM rejoué à la main

**15 revendications ≥ MEDIUM au total : 7 vrais positifs, 8 FAUX POSITIFS, 0 non vérifié.**

| verdict | n | qui | pourquoi |
|---|---|---|---|
| **TP** | 2 | `access_control.idor` (Juice Shop, VAmPI ×2 → 3 lignes) | marqueur de la victime réellement lu depuis la session de l'attaquant ; Juice Shop **certifié par l'app** (challenge « View Basket » passé à `solved`) |
| **TP** | 3 | `sqli.probe` (DVWA ×2, Juice Shop) | erreur SGBD / différentiel booléen / différentiel d'autorisation rejoués à la main ; Juice Shop **certifié par l'app** (« Login Admin » `solved`) |
| **TP** | 1 | `path.traversal` (DVWA) | canari lu ; et la LFI prouvée **indépendamment** du canari (`?page=/etc/passwd` → `root:x:0:0`) |
| **FP** | 5 | `header_injection.probe` (DVWA ×4, VAmPI ×1) | redirection de répertoire : `Location` construit depuis `Host` — défaut universel Apache **et** Werkzeug |
| **FP** | 3 | `ssrf.xspa` (VAmPI) | 9 des 10 ports « joignables » sont FERMÉS (connexion TCP directe) ; l'endpoint n'est pas SSRF-able |

Le taux de faux positifs sur les revendications actionnables est de **8/15 ≈ 53 %**, et **la totalité
des faux positifs vient du mode autonome** (piste B) : la piste A, amorcée à la main, n'a produit
**aucun** faux positif sur les 4 applications.

### 5.3 Faux négatifs — expliqués, un par un

| classe manquée | app | cause établie |
|---|---|---|
| injection de commande / RCE | DVWA | **D6** — la sonde POST ne porte QUE le paramètre injecté ; DVWA exige le co-paramètre `Submit`. Payload identique **avec** `Submit` → commande exécutée |
| XSS réfléchi | DVWA | conception : `xss.reflected` exige un contexte JS-exécutable (`<script>`/`on*=`/DOM sink). DVWA réfléchit en contenu HTML — l'oracle VOIT `réfléchi=True, non_échappé=True` et refuse de promouvoir |
| XSS stocké | DVWA, DVGA | **D7** — verdict fabriqué à partir d'une erreur du service navigateur (qui ne peut pas joindre le loopback de l'hôte) |
| XSS DOM | DVWA, Juice Shop | non mesurable ici (navigateur hors espace réseau) — `skipped`, correctement |
| CSRF | DVWA | le détecteur d'anti-CSRF cherche `"csrf"` dans **tout le corps** ; la page DVWA « CSRF » contient le mot dans ses liens et titres → `anti_CSRF_absent=False`. Second facteur : aucun `Set-Cookie` observé → `SameSite_absent=None` |
| SQLi | VAmPI | le point d'injection est un **segment de chemin** (`/users/v1/{username}`) ; les oracles d'injection n'écrivent que dans un paramètre de query ou un corps de formulaire |
| BFLA (mot de passe d'autrui) | VAmPI | abstention **correcte** : la méthode `PUT` mute l'objet d'un tiers → refusée tant que `allow_destructive` est faux |
| JWT à clé faible | VAmPI | **D12** — la liste HMAC par défaut (16 entrées) ne contient pas `random`. Avec la liste étendue : **HIGH · vulnerable** |
| introspection GraphQL | DVGA | détectée (`introspection=True`) mais rendue **INFO** par conception (divulgation seule ≠ impact) ; et le chemin exige `b_marker` + `query`, absents sur une app anonyme |
| cmdi / SQLi / traversal / XSS / SSRF GraphQL | DVGA | tous les points d'injection sont des **arguments dans un corps JSON GraphQL** ; aucun oracle ne sait écrire dedans |
| toutes (piste B, DVWA/DVGA) | — | la découverte n'a produit **aucune URL portant un paramètre de query** ; les oracles param-drivés rendent tous « config manquante » |
| toutes (piste B, Juice Shop) | — | **D13** — l'application est morte pendant la campagne |

### 5.4 Le contrôle a bien reproduit la mesure de référence

Juice Shop, piste A : `access_control.idor` → **IDOR CONFIRMÉ**, `sqli.probe` → **SQLi CONFIRMÉ**,
et l'app l'atteste elle-même (`GET /api/Challenges` : « View Basket » et « Login Admin » passés à
`solved`). Le banc n'introduit donc pas de biais : les écarts observés sur DVWA/VAmPI/DVGA sont bien
ceux du moteur.

### 5.5 Verdict honnête sur la généralisation

**Forge généralise, mais étroitement, et seulement quand on l'amorce.**

- **Ce qui tient sur plusieurs stacks** : `sqli.probe` (PHP/MariaDB *et* Node/SQLite, par trois
  mécanismes de preuve distincts), `access_control.idor` (Node *et* Python, à condition de lui
  fournir 2 comptes + une cible marquée) et `path.traversal` (avec canari). Ce sont **3 classes
  d'oracle sur 25 opposables**, mais ce sont précisément les classes qui paient.
- **Ce qui ne généralise pas** : tout ce qui n'est pas « un paramètre de query sur une URL déjà
  connue ». Segment de chemin (VAmPI), corps JSON GraphQL (DVGA), formulaire POST multi-champs
  (DVWA) : **0 détection**. Sur DVGA — une stack entière — le score est **0 sur 7**, dans les deux
  pistes.
- **Le mode autonome ne trouve presque rien et se trompe souvent.** 5703 findings émis sur les
  4 campagnes, **1 seul vrai positif** (la BOLA de VAmPI, et uniquement parce que l'opérateur avait
  déclaré la cible IDOR dans le scope), contre **8 faux positifs**. La cause n'est pas le jugement :
  c'est que la découverte ne produit pas de surface paramétrée, et qu'elle produit du bruit (404
  ingérés en endpoints) sur lequel 60 modules sont balayés.
- **Répondre à la question posée** : *forge a-t-il été ajusté à Juice Shop ?* Non — les deux oracles
  qui marchent sur Juice Shop marchent aussi ailleurs. *Mais l'échantillon de 1 masquait bien
  quelque chose* : il masquait que hors « paramètre de query », la couverture tombe à zéro, et que
  le mode autonome produit plus de faux HIGH que de vrais.

**Recommandation de publication.** En l'état, publier le mode `--auto-pentest` comme un scanner
serait indéfendable : plus de faux positifs que de vrais, et un plantage de la cible. En revanche
les **oracles amorcés** (piste A) sont défendables et honnêtes : 0 faux positif, des preuves
reproductibles, et des abstentions nommées. Le chemin de publication le plus solide est donc
« forge = un vérificateur d'hypothèses amorcé par l'opérateur », pas « forge = un scanner
autonome » — jusqu'à ce que D3/D4/D5/D8 soient corrigés.

## 6. Défauts mis au jour par le banc — CONSIGNÉS, NON CORRIGÉS

Aucun fichier de `forge/**` n'a été modifié. Chaque entrée porte sa preuve : une commande, une sortie,
ou un extrait de code à la ligne près. L'ordre est celui de la gravité pour un opérateur.

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

## 7. Ce qui a bien tenu (à ne pas perdre)

- **L'anti-masquage est réel.** Le run DVWA a été coupé par le budget et le rapport l'annonce en
  tête : « RAPPORT PARTIEL — RUN INTERROMPU », « 1751 action(s) exécutée(s) sur 2700 planifiée(s),
  **949 jamais tentée(s)** », suivi d'une section « Couverture NON vérifiée » listant chaque action
  non démarrée avec « AUCUN verdict n'est émis pour cette action (non testée, pas “rien trouvé”) ».
- **La discipline de preuve tient sur les négatifs.** 1770 des 1806 findings DVWA sont des `INFO`
  `tested`/`skipped` explicites : aucun verdict aveugle, chaque abstention est nommée.
- **Une revendication d'outil tiers reste cantonnée.** `dalfox` a signalé un XSS réfléchi sur
  `/docs?any=…` ; vérification manuelle : la charge revient **URL-encodée** dans le `href`, donc
  inerte. Forge l'a classé `reported_by_tool` / LOW, sous « Signal à qualifier (exploitabilité NON
  démontrée) » — jamais promu. C'est le bon comportement.
- **Le scope-guard fait ce qu'il dit.** `scope-check` in-scope → 0, hors périmètre → 1, sur les
  quatre engagements ; aucune requête n'est sortie de la boucle locale.

## 8. Reproduire

```bash
python3 -m bench.detection.run_bench --workdir /tmp/bench --track both --budget 900
python3 -m bench.detection.report   --workdir /tmp/bench --verdicts verdicts.json
python3 -c "from bench.detection import provision; provision.teardown()"
```

`run_bench` écrit `manifest.json` (amorçage, scope rédigé, durées, drapeau `partial` par piste),
un store `--memory` JSONL par piste et par application (les findings bruts), le rapport markdown du
moteur et son ledger signé.
