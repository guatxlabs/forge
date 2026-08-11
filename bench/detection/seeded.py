# SPDX-License-Identifier: AGPL-3.0-or-later
"""PISTE A — oracles AMORCÉS À LA MAIN, un par vuln connue.

Pourquoi deux pistes. Une campagne autonome mesure DEUX choses en même temps : la capacité à
DÉCOUVRIR la surface, et la capacité à JUGER une fois dessus. Quand elle ne trouve rien on ne sait
pas laquelle a échoué — c'est exactement ce qui a rendu illisibles les trois campagnes contre
l'infra réelle (ROADMAP §« Le mur »). La piste A neutralise la découverte : on donne à chaque oracle
l'URL et le paramètre EXACTS de la vuln, et on ne mesure plus que son verdict.

La piste B (campagne autonome, `run_bench.py`) mesure la chaîne complète. Les deux chiffres sont
rapportés séparément parce qu'ils ne disent pas la même chose.

Les actions ci-dessous ne DÉCIDENT de rien : elles décrivent où regarder. Le verdict reste celui de
l'oracle, et chaque finding ≥ MEDIUM est revérifié à la main contre la vérité terrain.
"""
from __future__ import annotations


#: Canari BÉNIGN déposé par le banc dans la racine web de DVWA (`provision.plant_canary`).
#: `path.traversal` REFUSE par conception de cibler /etc/passwd : il exige un marqueur bénin
#: fourni par l'opérateur. Le banc le fournit, et le déclare.
CANARY_NAME = "forge-canary.txt"
CANARY_MARKER = "FORGE_BENCH_CANARY_9Z4K"


def _a(kind, target, params=None, desc=""):
    return {"kind": kind, "target": target, "params": params or {}, "desc": desc}


def _auth_params(auth):
    """Comptes + cibles IDOR passés EXPLICITEMENT dans l'action.

    Sur le chemin `forge campaign` l'engine injecte ce bloc depuis `scope.auth` (engine.py
    `_prepare`). Sur le chemin `forge run --actions`, `Engine.run()` n'appelle PAS `_prepare` :
    l'injection n'a pas lieu et les oracles de contrôle d'accès rendent « config manquante » même
    avec un `scope.auth` complet. Le banc contourne en passant les mêmes valeurs dans l'action —
    et l'écart est consigné comme défaut, pas corrigé."""
    return {"accounts": [dict(a) for a in auth.accounts],
            "idor_targets": [dict(t) for t in auth.idor_targets]}


def dvwa_actions(base, cookie):
    """DVWA — chaque module de l'app est amorcé sur son point d'injection réel."""
    hdr = {"Cookie": cookie}
    sqli = f"{base}/vulnerabilities/sqli/?id=1&Submit=Submit"
    blind = f"{base}/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    fi = f"{base}/vulnerabilities/fi/?page=include.php"
    xssr = f"{base}/vulnerabilities/xss_r/?name=forge"
    # CO-PARAMÈTRE EXIGÉ : DVWA teste `isset($_POST['Submit'])` — sans lui la RCE est hors
    # d'atteinte quelle que soit la charge. C'est D6 vu depuis l'AMORÇAGE : l'action ne
    # déclarait le co-paramètre nulle part, donc rien ne pouvait le porter.
    exec_ = f"{base}/vulnerabilities/exec/?Submit=Submit"
    xsss = f"{base}/vulnerabilities/xss_s/"
    csrf = f"{base}/vulnerabilities/csrf/?password_new=a&password_conf=a&Change=Change"
    return [
        _a("sqli.probe", sqli, {"param": "id", "value": "1", "headers": hdr},
           "SQLi error-based, paramètre id"),
        _a("sqli.probe", blind, {"param": "id", "value": "1", "headers": hdr},
           "SQLi aveugle (différentiel booléen), paramètre id"),
        _a("cmdi.probe", exec_, {"param": "ip", "value": "127.0.0.1", "method": "POST",
                                 "headers": hdr}, "injection de commande, paramètre ip"),
        _a("rce.probe", exec_, {"param": "ip", "value": "127.0.0.1", "method": "POST",
                                "headers": hdr}, "RCE, paramètre ip"),
        _a("path.traversal", fi,
           {"param": "page", "value": "include.php", "headers": hdr,
            "canary_name": CANARY_NAME, "canary_marker": CANARY_MARKER},
           "inclusion de fichier / traversal, paramètre page (canari bénin fourni)"),
        _a("xss.reflected", xssr, {"param": "name", "value": "forge", "headers": hdr},
           "XSS réfléchi, paramètre name"),
        _a("xss.stored", xsss, {"param": "mtxMessage", "store_url": xsss, "view_url": xsss,
                                "store_method": "POST", "headers": hdr},
           "XSS stocké : écriture puis relecture de la même page"),
        _a("csrf.state_change", csrf, {"param": "password_new", "critical": True, "headers": hdr},
           "changement d'état sans jeton anti-CSRF"),
        _a("xss.execution", f"{base}/vulnerabilities/xss_d/?default=English",
           {"param": "default", "headers": hdr}, "XSS DOM (exige le rendu navigateur)"),
        _a("web.security_headers", base, {"headers": hdr}, "audit d'en-têtes (repère de bruit)"),
    ]


def vampi_actions(base, auth):
    """VAmPI — REST. Le point d'injection SQLi est un SEGMENT DE CHEMIN, pas un paramètre de query :
    on l'amorce des DEUX façons (chemin brut, et paramètre nommé) pour distinguer « l'oracle ne sait
    pas juger » de « l'oracle ne sait pas atteindre un segment de chemin »."""
    att = auth.extra["accounts"]["attacker"][1]
    hdr = {"Authorization": f"Bearer {att}"}
    marker = auth.extra["marker"]
    ap = _auth_params(auth)
    return [
        _a("sqli.probe", f"{base}/users/v1/name1", {"headers": hdr},
           "SQLi : segment de chemin /users/v1/{username} (aucun paramètre de query)"),
        _a("sqli.probe", f"{base}/users/v1/name1?username=name1",
           {"param": "username", "value": "name1", "headers": hdr},
           "SQLi : même endpoint, point d'injection présenté comme paramètre de query"),
        _a("access_control.idor", f"{base}/books/v1/victimbook",
           {**ap, "urls": [f"{base}/books/v1/victimbook"]},
           "BOLA : le livre de la victime lu avec la session de l'attaquant"),
        _a("access_control.privesc", f"{base}/users/v1/victim1/password",
           {**ap, "method": "PUT", "admin_urls": [f"{base}/users/v1/victim1/password"],
            "admin_marker": "Updated", "body": {"password": "hijacked"}},
           "BFLA : changement du mot de passe d'un AUTRE utilisateur"),
        _a("auth.takeover", base, {**ap, "whoami_url": f"{base}/me",
                                   "victim_marker": "victim1"},
           "ATO : la session de l'attaquant rend-elle l'identité de la victime ?"),
        _a("framework.exposure", f"{base}/users/v1/_debug", {},
           "exposition excessive de données (endpoint de debug anonyme)"),
        _a("jwt.weakness", f"{base}/users/v1/login",
           {"token": att, "self_marker": "attacker1", "headers": hdr},
           "JWT signé HS256 avec le secret 'random'"),
        _a("graphql.access", base, {"b_marker": marker},
           "sonde GraphQL sur une API REST (vrai négatif attendu)"),
        _a("cors.credentials", base,
           {"attacker_origin": "https://attacker.example", "session_marker": marker,
            "auth_headers": hdr}, "CORS + credentials (vrai négatif attendu)"),
    ]


def dvga_actions(base):
    """DVGA — tout passe par POST /graphql. Les oracles param-drivés de forge attaquent un
    PARAMÈTRE (query/corps de formulaire) : le banc les amorce quand même sur /graphql pour mesurer
    ce qu'ils font face à un corps JSON GraphQL."""
    gql = f"{base}/graphql"
    return [
        _a("graphql.access", base, {"b_marker": "DVGA_BENCH_MARKER"},
           "introspection + interface GraphQL exposées"),
        _a("graphql.access", gql, {"b_marker": "DVGA_BENCH_MARKER"},
           "introspection sur l'endpoint /graphql lui-même"),
        _a("cmdi.probe", gql, {"param": "cmd", "method": "POST"},
           "injection de commande via un argument GraphQL"),
        _a("sqli.probe", gql, {"param": "filter", "method": "POST"},
           "SQLi via l'argument `filter` de la query pastes"),
        _a("path.traversal", gql, {"param": "filename", "method": "POST",
                                   "canary_name": CANARY_NAME, "canary_marker": CANARY_MARKER},
           "écriture arbitraire / traversal via uploadPaste"),
        _a("xss.stored", gql, {"param": "content", "store_url": gql, "view_url": f"{base}/pastes",
                               "store_method": "POST"},
           "XSS stocké : createPaste puis rendu de /pastes"),
        _a("ssrf.xspa", gql, {"param": "host", "method": "POST"},
           "SSRF via importPaste(host,port,path)"),
        _a("jwt.weakness", base, {"self_marker": "DVGA_BENCH_MARKER"}, "jeton JWT forgeable"),
        _a("framework.exposure", base, {}, "divulgation par trace d'exécution / interface"),
        _a("web.security_headers", base, {}, "audit d'en-têtes (repère de bruit)"),
    ]


def juiceshop_actions(base, auth):
    """Juice Shop — CONTRÔLE, amorçage identique à la mesure de référence du dépôt."""
    att = auth.extra["accounts"]["attacker"][1]
    basket = auth.extra["basket_id"]
    ap = _auth_params(auth)
    return [
        _a("access_control.idor", f"{base}/rest/basket/{basket}",
           {**ap, "urls": [f"{base}/rest/basket/{basket}"]},
           "IDOR : panier de la victime lu avec la session de l'attaquant"),
        _a("sqli.probe", f"{base}/rest/user/login",
           {"param": "email", "value": "a@b.c", "method": "POST"},
           "SQLi de contournement d'authentification"),
        _a("cors.credentials", base,
           {"attacker_origin": "https://attacker.example",
            "auth_headers": {"Authorization": f"Bearer {att}"}},
           "CORS + credentials (vrai négatif attendu)"),
        _a("ssti.eval", f"{base}/rest/products/search?q=apple", {"param": "q", "value": "apple"},
           "SSTI (vrai négatif attendu)"),
        _a("path.traversal", f"{base}/ftp?doc=legal.md",
           {"param": "doc", "value": "legal.md",
            "canary_name": CANARY_NAME, "canary_marker": CANARY_MARKER},
           "traversal (vrai négatif attendu sur ce chemin)"),
        _a("xss.reflected", f"{base}/#/search?q=forge", {"param": "q", "value": "forge"},
           "XSS réfléchi (limite structurelle connue : le XSS de cette cible est DOM/Angular)"),
    ]


BUILDERS = {
    "dvwa": lambda app, auth: dvwa_actions(app.base_url, auth.extra["cookie"]),
    "vampi": lambda app, auth: vampi_actions(app.base_url, auth),
    "dvga": lambda app, auth: dvga_actions(app.base_url),
    "juiceshop": lambda app, auth: juiceshop_actions(app.base_url, auth),
}


def build(app, auth):
    return BUILDERS[app.name](app, auth)
