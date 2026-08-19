# SPDX-License-Identifier: AGPL-3.0-or-later
"""VÉRITÉ TERRAIN du banc de détection multi-applications.

RÈGLE MÉTHODOLOGIQUE CENTRALE : **la vérité terrain vient de l'APPLICATION, jamais de forge.**
Chaque entrée cite sa SOURCE (registre de challenges, liste de modules, README, page de solutions
livrée par l'app) et la COMMANDE MANUELLE qui prouve que la vuln est vivante sur l'instance lancée.
Sans référence externe on mesurerait forge avec lui-même.

Une entrée `GroundTruth` = UNE vuln connue, décrite par :
  - `vuln_class` : la classe de vulnérabilité (vocabulaire neutre, pas un nom de module forge) ;
  - `oracle`     : le kind de module forge qui PRÉTEND couvrir cette classe — ou `None` si AUCUN
                   oracle du dépôt ne la revendique (le banc doit dire « pas d'oracle », pas
                   « forge a raté ») ;
  - `endpoint`/`method`/`param` : où la vuln vit, et par quel point d'injection ;
  - `source`     : d'où vient la vérité terrain (fichier/URL/page de l'app) ;
  - `proof`      : la commande qui la vérifie à la main, hors forge ;
  - `banned`     : True si la classe est bannie du périmètre bug-bounty du workspace (DoS, brute
                   force, absence de rate-limit…) — comptée à part, jamais en faux négatif.

Aucune de ces structures n'est importée par `forge/**` : le banc est un OBSERVATEUR.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class GroundTruth:
    app: str
    vuln_class: str
    oracle: str | None
    endpoint: str
    source: str
    method: str = "GET"
    param: str = ""
    proof: str = ""
    banned: bool = False
    note: str = ""


@dataclass(frozen=True)
class App:
    """Une application cible du banc : image, port loopback, et ce qu'on lui a AMORCÉ.

    `primed` décrit HONNÊTEMENT ce que l'opérateur fournit à forge (session, comptes, marqueur
    IDOR). « forge trouve X avec 2 comptes fournis » et « forge trouve X sans rien » sont deux
    affirmations différentes : le banc rend les deux lisibles."""
    name: str
    image: str
    base_url: str
    host_port: str            # forme `host:port` telle qu'elle entre dans scope.in_scope
    stack: str
    truth_source: str
    primed: str = ""


# ---------------------------------------------------------------------------------------------
# APPLICATIONS — stacks volontairement variées (Node/Angular, PHP/MySQL, Python/Flask REST,
# Python/GraphQL) pour ne pas mesurer un ajustement à une seule cible.
# ---------------------------------------------------------------------------------------------
APPS = {
    "juiceshop": App(
        name="juiceshop",
        image="bkimminich/juice-shop:latest",
        base_url="http://127.0.0.1:3000",
        host_port="127.0.0.1:3000",
        stack="Node.js / Express / Angular SPA / SQLite",
        truth_source="registre de challenges de l'app : GET /api/Challenges (fourni par l'app elle-même)",
    ),
    "dvwa": App(
        name="dvwa",
        image="vulnerables/web-dvwa:latest",
        base_url="http://127.0.0.1:8081",
        host_port="127.0.0.1:8081",
        stack="PHP 7 / Apache / MariaDB",
        truth_source="liste de modules de l'app : /var/www/html/vulnerabilities/ (dans le conteneur)",
    ),
    "vampi": App(
        name="vampi",
        image="erev0s/vampi:latest",
        base_url="http://127.0.0.1:5001",
        host_port="127.0.0.1:5001",
        stack="Python 3 / Flask + connexion / OpenAPI3 / SQLite",
        truth_source="README de l'app (/vampi/README.md dans le conteneur) : « List of Vulnerabilities »",
    ),
    "dvga": App(
        name="dvga",
        image="dolevf/dvga:latest",
        base_url="http://127.0.0.1:5013",
        host_port="127.0.0.1:5013",
        stack="Python 3 / Flask / Graphene GraphQL / SQLite",
        truth_source="pages de solutions livrées par l'app : /opt/dvga/templates/partials/solutions/*.html",
    ),
}


# ---------------------------------------------------------------------------------------------
# DVWA — vérité terrain = les modules que l'application déclare elle-même.
# Source : `ls /var/www/html/vulnerabilities/` dans le conteneur ->
#   brute captcha csp csrf exec fi javascript sqli sqli_blind upload weak_id xss_d xss_r xss_s
# Niveau de sécurité : low (cookie `security=low`, réglage natif de l'app).
# ---------------------------------------------------------------------------------------------
_DVWA_SRC = "DVWA: /var/www/html/vulnerabilities/ (modules déclarés par l'app)"

DVWA = [
    GroundTruth("dvwa", "sqli", "sqli.probe",
                "/vulnerabilities/sqli/?id=1&Submit=Submit", _DVWA_SRC, param="id",
                proof="curl '…/sqli/?id=1%27&Submit=Submit' -> « You have an error in your SQL syntax »"),
    GroundTruth("dvwa", "sqli_blind", "sqli.probe",
                "/vulnerabilities/sqli_blind/?id=1&Submit=Submit", _DVWA_SRC, param="id",
                proof="différentiel booléen id=1'+AND+'1'='1 vs id=1'+AND+'1'='2"),
    GroundTruth("dvwa", "command_injection", "cmdi.probe",
                "/vulnerabilities/exec/", _DVWA_SRC, method="POST", param="ip",
                proof="POST ip=127.0.0.1;id -> « uid=33(www-data) »"),
    GroundTruth("dvwa", "command_injection_rce", "rce.probe",
                "/vulnerabilities/exec/", _DVWA_SRC, method="POST", param="ip",
                proof="idem — mesuré séparément car forge a DEUX oracles distincts sur cette classe"),
    GroundTruth("dvwa", "path_traversal", "path.traversal",
                "/vulnerabilities/fi/?page=include.php", _DVWA_SRC, param="page",
                proof="curl '…/fi/?page=/etc/passwd' -> « root:x:0:0:root »"),
    GroundTruth("dvwa", "xss_reflected", "xss.reflected",
                "/vulnerabilities/xss_r/?name=forge", _DVWA_SRC, param="name",
                proof="curl '…/xss_r/?name=FORGEMARK<b>x</b>' -> réfléchi NON échappé dans <pre>"),
    GroundTruth("dvwa", "xss_stored", "xss.stored",
                "/vulnerabilities/xss_s/", _DVWA_SRC, method="POST", param="mtxMessage",
                proof="POST txtName/mtxMessage puis GET de la même page -> message rendu brut"),
    GroundTruth("dvwa", "xss_dom", "xss.execution",
                "/vulnerabilities/xss_d/?default=English", _DVWA_SRC, param="default",
                proof="sink DOM côté client — exige un rendu navigateur",
                note="oracle navigateur : exige le service browser-automation"),
    GroundTruth("dvwa", "csrf", "csrf.state_change",
                "/vulnerabilities/csrf/?password_new=a&password_conf=a&Change=Change", _DVWA_SRC,
                param="password_new",
                proof="changement de mot de passe en GET, aucun jeton anti-CSRF au niveau low"),
    GroundTruth("dvwa", "file_upload", None,
                "/vulnerabilities/upload/", _DVWA_SRC, method="POST",
                proof="upload PHP arbitraire",
                note="AUCUN oracle forge ne revendique l'upload arbitraire — hors capacité, pas un raté"),
    GroundTruth("dvwa", "weak_session_id", None,
                "/vulnerabilities/weak_id/", _DVWA_SRC,
                proof="dvwaSession incrémental",
                note="aucun oracle forge sur la prédictibilité d'identifiant de session"),
    GroundTruth("dvwa", "csp_bypass", None,
                "/vulnerabilities/csp/", _DVWA_SRC,
                note="aucun oracle forge de contournement CSP (web.security_headers AUDITE, ne contourne pas)"),
    GroundTruth("dvwa", "brute_force", None,
                "/vulnerabilities/brute/", _DVWA_SRC, banned=True,
                note="classe BANNIE (brute force) — jamais comptée en faux négatif"),
    GroundTruth("dvwa", "insecure_captcha", None,
                "/vulnerabilities/captcha/", _DVWA_SRC,
                note="inerte sans clés reCAPTCHA ; aucun oracle forge"),
    GroundTruth("dvwa", "javascript_challenge", None,
                "/vulnerabilities/javascript/", _DVWA_SRC,
                note="défi client-side ; aucun oracle forge"),
]


# ---------------------------------------------------------------------------------------------
# VAmPI — vérité terrain = la section « List of Vulnerabilities » du README livré DANS l'image,
# recoupée avec le code (`if vuln:` marque chaque branche vulnérable).
# ---------------------------------------------------------------------------------------------
_VAMPI_SRC = "VAmPI: /vampi/README.md « List of Vulnerabilities » + branches `if vuln:` du code"

VAMPI = [
    GroundTruth("vampi", "sqli", "sqli.probe",
                "/users/v1/{username}", _VAMPI_SRC, param="<segment de chemin>",
                proof="models/user_model.py get_user() : f\"SELECT * FROM users WHERE username = '{username}'\"",
                note="point d'injection = SEGMENT DE CHEMIN, pas un paramètre de query"),
    GroundTruth("vampi", "idor_bola", "access_control.idor",
                "/books/v1/{book}", _VAMPI_SRC,
                proof="attacker1 lit le secret de victim1 : GET /books/v1/victimbook -> VICTIM_SECRET_MARKER_7Q3",
                note="Broken Object Level Authorization — api_views/books.py get_by_title()"),
    GroundTruth("vampi", "broken_function_level_authz", "access_control.privesc",
                "/users/v1/{username}/password", _VAMPI_SRC, method="PUT",
                proof="api_views/users.py update_password() : `if vuln:` cible `username` de l'URL, pas le sujet du jeton",
                note="changement de mot de passe d'un AUTRE utilisateur avec son propre jeton"),
    GroundTruth("vampi", "mass_assignment", None,
                "/users/v1/register", _VAMPI_SRC, method="POST", param="admin",
                proof="api_views/users.py register_user() : `if vuln and 'admin' in request_data`",
                note="AUCUN oracle forge ne revendique le mass assignment"),
    GroundTruth("vampi", "excessive_data_exposure", None,
                "/users/v1/_debug", _VAMPI_SRC,
                proof="GET /users/v1/_debug -> mots de passe en clair de tous les utilisateurs",
                note=("AUCUN oracle forge ne revendique l'exposition excessive GÉNÉRIQUE. "
                      "`framework.exposure` ne couvre que Spring Actuator / Next.js / Laravel "
                      "(surfaces de FRAMEWORK nommées) — le compter en faux négatif reviendrait à "
                      "reprocher au moteur une classe qu'il n'a jamais prétendu couvrir")),
    GroundTruth("vampi", "user_enumeration", None,
                "/users/v1/login", _VAMPI_SRC, method="POST",
                proof="messages distincts « Username does not exist » vs « Password is not correct »",
                note="aucun oracle forge d'énumération d'utilisateur"),
    GroundTruth("vampi", "jwt_weak_key", "jwt.weakness",
                "/users/v1/login", _VAMPI_SRC, method="POST",
                proof="config.py : SECRET_KEY = 'random' — HS256 signé avec un secret devinable"),
    GroundTruth("vampi", "regex_dos", None,
                "/users/v1/{username}/email", _VAMPI_SRC, method="PUT", banned=True,
                note="classe BANNIE (DoS)"),
    GroundTruth("vampi", "no_rate_limiting", None,
                "/", _VAMPI_SRC, banned=True,
                note="classe BANNIE (rate limiting)"),
]


# ---------------------------------------------------------------------------------------------
# DVGA — vérité terrain = les pages de SOLUTIONS livrées par l'application
# (/opt/dvga/templates/partials/solutions/*.html), une par challenge.
# ---------------------------------------------------------------------------------------------
_DVGA_SRC = "DVGA: /opt/dvga/templates/partials/solutions/*.html (challenges déclarés par l'app)"

DVGA = [
    GroundTruth("dvga", "graphql_introspection", None,
                "/graphql", _DVGA_SRC, method="POST",
                proof="POST {\"query\":\"{__schema{types{name}}}\"} -> schéma complet",
                note=("CLASSE NON OPPOSABLE À FORGE, PAR POLITIQUE ET NON PAR MANQUE. `graphql.access` "
                      "SONDE bien l'introspection, mais l'émet en `INFO`/`tested` à dessein : « info "
                      "disclosure seule ne vaut pas preuve d'impact » est une règle du dépôt, et le "
                      "scorer ne compte un succès qu'en `status=vulnerable` (`score.PROOF_STATUS`). "
                      "La compter en FAUX NÉGATIF revenait à reprocher à forge d'appliquer sa propre "
                      "doctrine — et gonflait le « 0/7 » d'une ligne qu'aucun correctif ne pouvait "
                      "faire basculer. Second empêchement mesuré : l'oracle exige `params.b_marker` + "
                      "`params.query` (preuve BOLA à deux comptes), or DVGA n'a NI compte NI session — "
                      "il rend donc `skipped` sur cette application, introspection incluse.")),
    GroundTruth("dvga", "graphql_interface_exposed", None,
                "/graphiql", _DVGA_SRC,
                proof="GET /graphiql -> IDE GraphQL exposé",
                note=("aucun oracle ne SONDE /graphiql : `graphql.access` est un oracle BOLA qui POSTe "
                      "sur l'endpoint GraphQL, il ne cherche pas l'IDE")),
    GroundTruth("dvga", "command_injection", "cmdi.probe",
                "/graphql", _DVGA_SRC, method="POST", param="<argument GraphQL systemDiagnostics/importPaste>",
                proof="mutation/queries `systemDiagnostics(cmd:…)` et `importPaste(host,port,path,scheme)`"),
    GroundTruth("dvga", "sqli", "sqli.probe",
                "/graphql", _DVGA_SRC, method="POST", param="<argument GraphQL pastes(filter:…)>",
                proof="query `pastes(filter:\"…\")` concaténée dans le SQL"),
    GroundTruth("dvga", "xss_stored", "xss.stored",
                "/graphql", _DVGA_SRC, method="POST", param="<argument GraphQL createPaste(content:…)>",
                proof="createPaste puis rendu de /pastes"),
    GroundTruth("dvga", "path_traversal", "path.traversal",
                "/graphql", _DVGA_SRC, method="POST", param="<argument GraphQL uploadPaste(filename:…)>",
                proof="uploadPaste(filename:\"../../…\") — écriture de fichier arbitraire"),
    GroundTruth("dvga", "ssrf", "ssrf.xspa",
                "/graphql", _DVGA_SRC, method="POST", param="<argument GraphQL importPaste(host,port,path)>",
                proof="importPaste force le serveur à émettre une requête HTTP arbitraire",
                note=("l'autre oracle candidat, `ssrf.callback`, exige un collecteur de callback HORS "
                      "de l'hôte : exclu par la contrainte loopback, donc non opposable ici")),
    GroundTruth("dvga", "jwt_forge", "jwt.weakness",
                "/graphql", _DVGA_SRC, method="POST",
                proof="jeton JWT forgeable (challenge « GraphQL JWT Token Forge »)"),
    GroundTruth("dvga", "stack_trace_disclosure", None,
                "/graphql", _DVGA_SRC, method="POST",
                note="divulgation d'information seule — aucun oracle forge dédié"),
    GroundTruth("dvga", "field_suggestions", None,
                "/graphql", _DVGA_SRC, method="POST",
                note="aucun oracle forge sur la suggestion de champs GraphQL"),
    GroundTruth("dvga", "log_injection", None, "/graphql", _DVGA_SRC, method="POST",
                note="aucun oracle forge"),
    GroundTruth("dvga", "html_injection", None, "/graphql", _DVGA_SRC, method="POST",
                note="aucun oracle forge dédié (xss.* juge l'exécution, pas l'injection HTML inerte)"),
    GroundTruth("dvga", "weak_password_protection", None, "/graphql", _DVGA_SRC, method="POST",
                banned=True, note="classe BANNIE (protection par mot de passe faible / brute force)"),
    GroundTruth("dvga", "dos_batch_query", None, "/graphql", _DVGA_SRC, method="POST", banned=True),
    GroundTruth("dvga", "dos_deep_recursion", None, "/graphql", _DVGA_SRC, method="POST", banned=True),
    GroundTruth("dvga", "dos_circular_fragment", None, "/graphql", _DVGA_SRC, method="POST", banned=True),
    GroundTruth("dvga", "dos_resource_intensive", None, "/graphql", _DVGA_SRC, method="POST", banned=True),
    GroundTruth("dvga", "dos_field_duplication", None, "/graphql", _DVGA_SRC, method="POST", banned=True),
    GroundTruth("dvga", "dos_aliases", None, "/graphql", _DVGA_SRC, method="POST", banned=True),
    GroundTruth("dvga", "denylist_bypass", None, "/graphql", _DVGA_SRC, method="POST",
                note="contournement d'allow/deny-list — aucun oracle forge"),
]


# ---------------------------------------------------------------------------------------------
# Juice Shop — CONTRÔLE. C'est la seule cible déjà mesurée par le dépôt (ROADMAP §« Pouvoir de
# détection »). Elle est rejouée à l'identique pour vérifier que le banc REPRODUIT la mesure connue
# — sans quoi on ne saurait pas si un écart vient de forge ou du banc.
# Vérité terrain : le registre de challenges servi par l'app elle-même (GET /api/Challenges).
# ---------------------------------------------------------------------------------------------
_JUICE_SRC = "Juice Shop: GET /api/Challenges (registre de challenges de l'app)"

JUICESHOP = [
    GroundTruth("juiceshop", "idor_bola", "access_control.idor",
                "/rest/basket/{id}", _JUICE_SRC,
                proof="challenge « View Basket » passe à solved quand le panier d'autrui est lu"),
    GroundTruth("juiceshop", "sqli", "sqli.probe",
                "/rest/user/login", _JUICE_SRC, method="POST", param="email",
                proof="challenge « Login Admin » passe à solved sur ' OR 1=1--"),
    GroundTruth("juiceshop", "xss_dom", "xss.execution",
                "/#/search?q=", _JUICE_SRC, param="q",
                proof="challenge « DOM XSS » — sink Angular, exige un rendu navigateur",
                note="limite structurelle documentée : un oracle qui juge la RÉPONSE SERVEUR ne le voit pas"),
]


ALL: list[GroundTruth] = DVWA + VAMPI + DVGA + JUICESHOP


def for_app(app: str) -> list[GroundTruth]:
    return [g for g in ALL if g.app == app]


def scorable(app: str) -> list[GroundTruth]:
    """Entrées OPPOSABLES à forge : classe non bannie ET un oracle du dépôt la revendique.
    Une classe sans oracle n'est PAS un faux négatif — c'est une lacune de couverture, comptée
    séparément pour ne pas gonfler artificiellement le dénominateur."""
    return [g for g in for_app(app) if g.oracle and not g.banned]


def unclaimed(app: str) -> list[GroundTruth]:
    """Vulns réelles de l'app qu'AUCUN oracle forge ne revendique (hors classes bannies)."""
    return [g for g in for_app(app) if not g.oracle and not g.banned]


def banned(app: str) -> list[GroundTruth]:
    return [g for g in for_app(app) if g.banned]
