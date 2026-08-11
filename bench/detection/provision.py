# SPDX-License-Identifier: AGPL-3.0-or-later
"""Amorçage du banc : lever les applications en LOOPBACK STRICT, les semer, et écrire ce qu'on
fournit à forge.

SÛRETÉ. Ces applications sont DÉLIBÉRÉMENT vulnérables : elles ne doivent jamais être exposées.
Chaque conteneur est publié sur `127.0.0.1` uniquement, et `verify_loopback_only()` REFUSE de
continuer si un socket d'écoute sort de la boucle locale. Le démontage est dans `teardown()`, qui
VÉRIFIE son propre effet : il relit docker après avoir retiré et rend ce qui subsiste. Un démontage
qui rend la main sans rien constater n'est pas une garantie, c'est une intention — et le rejeu du
2026-08-11 a trouvé un conteneur DVWA encore à l'écoute APRÈS un `teardown()` réputé complet.

HONNÊTETÉ D'AMORÇAGE. `AuthMaterial.declared` porte, en une phrase, EXACTEMENT ce qui a été fourni
à forge pour cette application. Le rapport le recopie tel quel : « forge trouve X avec 2 comptes
fournis » et « forge trouve X sans rien » sont deux affirmations différentes.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .groundtruth import APPS, App

PREFIX = "forge-bench-"
# Modules qui, par construction, interrogent un TIERS (CT logs, Wayback, résolveurs DNS publics,
# dépôts de templates, collecteur de callback hors-hôte). Exclus du banc : la contrainte est
# « aucun trafic vers un tiers », et ces modules ne parlent PAS qu'à la cible.
THIRD_PARTY_MODULES = (
    "recon.subdomains",   # crt.sh (recon_surface.py:381)
    "recon.urls",         # web.archive.org (recon_surface.py:687)
    "recon.gau", "recon.amass", "recon.subfinder", "recon.dnsx", "recon.gobuster_dns",
    "recon.dns", "recon.dig",
    "origin.find",        # subfinder + httpx sur l'espace DNS public
    "subdomain.takeover",
    "web.nuclei",         # met à jour ses templates depuis le dépôt amont
    "web.wpscan",         # base de vulns amont
    "ssrf.callback",      # exige un collecteur de callback hors de l'hôte
    "rfi.probe",          # exige une ressource marqueur hébergée hors de l'hôte
)


@dataclass
class AuthMaterial:
    """Ce que l'opérateur FOURNIT à forge pour une application — et rien de plus."""
    declared: str
    session: dict = field(default_factory=dict)      # scope.session (matériel global)
    accounts: list = field(default_factory=list)     # scope.auth.accounts (labellisés)
    idor_targets: list = field(default_factory=list)  # scope.auth.idor_targets ({url,owner,marker})
    extra: dict = field(default_factory=dict)         # valeurs utiles au banc (jetons, ids…)


# ------------------------------------------------------------------ HTTP minimal (stdlib)
def http(url, method="GET", body=None, headers=None, timeout=20):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body.encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                                   # noqa: BLE001
        return 0, str(e)


def wait_up(url, tries=60, delay=2):
    for _ in range(tries):
        st, _ = http(url)
        if st and st < 500:
            return True
        time.sleep(delay)
    return False


def sh(*args, check=False):
    return subprocess.run(args, capture_output=True, text=True, check=check)


# ------------------------------------------------------------------ cycle de vie des conteneurs
def _run_container(name, image, publish=None, env=None, host_network=False):
    sh("docker", "rm", "-f", PREFIX + name)
    cmd = ["docker", "run", "-d", "--name", PREFIX + name]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    if host_network:
        # DVGA se lie à 127.0.0.1 DANS le conteneur : une publication de port ne l'atteint pas.
        # `--network host` la laisse écouter sur la boucle locale de l'hôte — vérifié par
        # verify_loopback_only() juste après.
        cmd += ["--network", "host"]
    elif publish:
        cmd += ["-p", publish]
    cmd += [image]
    r = sh(*cmd)
    return r.returncode == 0


def bring_up(apps):
    """Lève les conteneurs demandés. Retourne la liste de ceux qui répondent."""
    up = []
    for name in apps:
        a = APPS[name]
        if name == "dvga":
            _run_container(name, a.image, host_network=True)
        elif name == "vampi":
            # tokentimetolive par défaut = 60 s : trop court pour un banc. Rallongé DÉLIBÉRÉMENT
            # (c'est de l'amorçage, pas de la détection) et déclaré comme tel.
            _run_container(name, a.image, publish="127.0.0.1:5001:5000",
                           env={"vulnerable": "1", "tokentimetolive": "86400"})
        elif name == "dvwa":
            _run_container(name, a.image, publish="127.0.0.1:8081:80")
        elif name == "juiceshop":
            _run_container(name, a.image, publish="127.0.0.1:3000:3000")
        if wait_up(a.base_url):
            up.append(name)
    return up


def list_bench_containers():
    """Conteneurs du banc RÉELLEMENT présents, DÉRIVÉS de docker et non d'une liste tenue à la main.

    Une liste écrite à la main rate exactement ce qu'il faut voir : un conteneur levé sous un nom
    absent de `APPS`, ou levé par une invocation antérieure. Le banc lève des applications
    délibérément vulnérables — sa question n'est pas « ai-je démonté ce que je crois avoir levé »
    mais « reste-t-il quelque chose ». Seule l'interrogation de docker répond à la seconde."""
    r = sh("docker", "ps", "-a", "--filter", f"name={PREFIX}", "--format", "{{.Names}}")
    return sorted({n.strip() for n in r.stdout.splitlines() if n.strip()})


def ports_still_listening(ports):
    """Sockets d'écoute encore ouverts SUR CES PORTS. Ancré aux limites : `:3000` ne doit pas se
    reconnaître dans `:30000`."""
    if not ports:
        return []
    r = sh("ss", "-ltnH")
    pat = re.compile(r"[:.](%s)\s" % "|".join(re.escape(str(p)) for p in ports))
    return [ln.strip() for ln in r.stdout.splitlines() if pat.search(ln)]


def ports_of_bench_containers(names):
    """Ports que LE BANC occupe réellement, dérivés des conteneurs PRÉSENTS — jamais d'une liste
    d'applications connues.

    Un socket n'accuse le banc que s'il a levé le conteneur qui le tient. Interroger « le port 3000
    est-il occupé ? » sans se demander PAR QUI, c'est confondre « le banc n'a pas démonté » avec
    « quelqu'un d'autre écoute » — mesuré le 2026-08-11 : `teardown()` a rendu `ok=False` en
    accusant un conteneur `fjs` étranger au banc, sur un port qu'aucune application du banc
    n'occupait à ce moment-là. Un garde qui accuse à tort finit ignoré, ce qui le rend inutile
    exactement le jour où il a raison."""
    ports = []
    for n in names:
        app = APPS.get(n[len(PREFIX):] if n.startswith(PREFIX) else n)
        if app and ":" in app.host_port:
            ports.append(app.host_port.rsplit(":", 1)[1])
    return sorted(set(ports))


def teardown(apps=None, ports=None):
    """Démonte le banc et VÉRIFIE SON PROPRE EFFET. Rend `(ok, restes)`.

    Un `teardown()` qui rend la main sans rien constater n'est pas une garantie de sûreté, c'est
    une intention. Celui-ci relit docker APRÈS avoir retiré, et rend `ok=False` avec la liste de
    ce qui subsiste — mesuré, pas supposé.

    `apps=None` retire TOUT ce qui porte le préfixe. C'est le défaut, et il est délibéré :
    l'ancienne signature ne retirait que les applications que l'appelant *croyait* avoir levées.

    `ports=None` (défaut) ne vérifie QUE les ports des conteneurs que ce démontage vient de
    retirer — voir `ports_of_bench_containers` : le banc ne s'accuse pas des sockets d'autrui."""
    names = [PREFIX + n for n in apps] if apps else list_bench_containers()
    if ports is None:
        ports = ports_of_bench_containers(names)
    if names:
        sh("docker", "rm", "-f", *names)
    restes = list_bench_containers()
    if ports:
        restes += ports_still_listening(ports)
    return (not restes), restes


def verify_loopback_only(ports):
    """REFUSE de continuer si un port du banc écoute ailleurs que sur la boucle locale.
    Retourne (ok, lignes observées). C'est un garde-fou DUR, pas un avertissement."""
    r = sh("ss", "-ltnH")
    lines = [ln for ln in r.stdout.splitlines() if any(f":{p}" in ln for p in ports)]
    bad = [ln for ln in lines
           if not re.search(r"\s(127\.0\.0\.1|\[?::1\]?):(%s)\s" % "|".join(str(p) for p in ports), ln)]
    return (not bad), lines


# ------------------------------------------------------------------ amorçage par application
def plant_canary(container, path, marker):
    """Dépose un CANARI BÉNIGN dans la cible. `path.traversal` refuse par conception de cibler
    /etc/passwd : il exige un marqueur bénin FOURNI par l'opérateur. Le banc le fournit — c'est de
    l'amorçage, déclaré comme tel, et sans lui l'oracle ne peut structurellement rien confirmer."""
    return sh("docker", "exec", PREFIX + container, "sh", "-c",
              f"printf '{marker}\\n' > {path}").returncode == 0


def prime_dvwa(base):
    """DVWA exige un login (admin/password) et une base créée. On fournit à forge UNE session
    authentifiée + le niveau de sécurité natif `low`. Sans cela chaque module rendrait la page de
    login : on mesurerait l'amorçage, pas la détection."""
    jar = {}

    def _get_token(path):
        st, body = http(base + path, headers=_ck(jar))
        m = re.search(r"user_token'\s*value='([0-9a-f]+)'", body)
        return m.group(1) if m else ""

    def _ck(j):
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in j.items())} if j else {}

    # 1er contact -> PHPSESSID + security=low
    req = urllib.request.Request(base + "/login.php")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            for h in r.headers.get_all("Set-Cookie") or []:
                k, _, v = h.split(";", 1)[0].partition("=")
                jar[k.strip()] = v.strip()
    except Exception:                                       # noqa: BLE001
        pass
    jar.setdefault("security", "low")

    tok = _get_token("/setup.php")
    http(base + "/setup.php", "POST",
         f"create_db=Create+/+Reset+Database&user_token={tok}",
         {**_ck(jar), "Content-Type": "application/x-www-form-urlencoded"})
    tok = _get_token("/login.php")
    http(base + "/login.php", "POST",
         f"username=admin&password=password&Login=Login&user_token={tok}",
         {**_ck(jar), "Content-Type": "application/x-www-form-urlencoded"})

    plant_canary("dvwa", "/var/www/html/forge-canary.txt", "FORGE_BENCH_CANARY_9Z4K")

    cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
    return AuthMaterial(
        declared=("1 session authentifiée (admin/password, compte natif de l'app) + niveau de "
                  "sécurité natif `low` + 1 canari BÉNIGN déposé dans la racine web "
                  "(/var/www/html/forge-canary.txt) que `path.traversal` exige par conception. "
                  "AUCUN endpoint vulnérable, AUCUN paramètre, AUCUN compte victime n'est fourni à "
                  "la campagne autonome : elle doit trouver la surface seule."),
        session={"cookies": cookie},
        extra={"cookie": cookie},
    )


def prime_vampi(base):
    """VAmPI : base peuplée + DEUX comptes à nous (attacker/victim) + un livre appartenant à la
    victime porteur d'un MARQUEUR. C'est exactement le bloc `auth` par-engagement prévu par
    scope.json — sans lui les oracles de contrôle d'accès rendent `skipped`."""
    http(base + "/createdb")
    accounts = {}
    for label, user, pw in (("attacker", "attacker1", "attackerpw"), ("victim", "victim1", "victimpw")):
        http(base + "/users/v1/register", "POST",
             {"username": user, "password": pw, "email": f"{user}@bench.local"})
        st, body = http(base + "/users/v1/login", "POST", {"username": user, "password": pw})
        try:
            accounts[label] = (user, json.loads(body).get("auth_token", ""))
        except Exception:                                   # noqa: BLE001
            accounts[label] = (user, "")

    marker = "VICTIM_SECRET_MARKER_7Q3"
    http(base + "/books/v1", "POST", {"book_title": "victimbook", "secret": marker},
         {"Authorization": f"Bearer {accounts['victim'][1]}"})

    return AuthMaterial(
        declared=("2 comptes à nous (attacker1 / victim1, créés par self-signup) + 1 ressource "
                  "possédée par la victime (`victimbook`) décrite par son marqueur. C'est le bloc "
                  "`auth` par-engagement de scope.json, rien de plus."),
        session={"bearer": accounts["attacker"][1]},
        accounts=[
            {"label": "attacker", "headers": {"Authorization": f"Bearer {accounts['attacker'][1]}"}},
            {"label": "victim", "headers": {"Authorization": f"Bearer {accounts['victim'][1]}"}},
        ],
        idor_targets=[{"url": f"{base}/books/v1/victimbook", "owner": "victim", "marker": marker}],
        extra={"accounts": accounts, "marker": marker},
    )


def prime_juiceshop(base):
    """Juice Shop — CONTRÔLE. Même amorçage que la mesure de référence du dépôt : 2 comptes à nous
    et le panier de la victime comme cible IDOR marquée."""
    accounts = {}
    for label, email, pw in (("attacker", "attacker@bench.local", "Benchpass1!"),
                             ("victim", "victim@bench.local", "Benchpass2!")):
        http(base + "/api/Users", "POST",
             {"email": email, "password": pw, "passwordRepeat": pw,
              "securityQuestion": {"id": 1}, "securityAnswer": "bench"})
        st, body = http(base + "/rest/user/login", "POST", {"email": email, "password": pw})
        tok = ""
        try:
            tok = json.loads(body).get("authentication", {}).get("token", "")
        except Exception:                                   # noqa: BLE001
            pass
        accounts[label] = (email, tok)

    # panier de la victime : /rest/basket/{id}. L'id est celui du BasketId de l'utilisateur.
    basket_id, marker = "", ""
    st, body = http(base + "/rest/basket/1", headers={"Authorization": f"Bearer {accounts['victim'][1]}"})
    st2, whoami = http(base + "/rest/user/whoami",
                       headers={"Authorization": f"Bearer {accounts['victim'][1]}"})
    try:
        uid = json.loads(whoami).get("user", {}).get("id")
    except Exception:                                       # noqa: BLE001
        uid = None
    for cand in range(1, 30):
        st, body = http(base + f"/rest/basket/{cand}",
                        headers={"Authorization": f"Bearer {accounts['victim'][1]}"})
        if st == 200:
            try:
                d = json.loads(body).get("data", {})
                if d.get("UserId") == uid:
                    basket_id, marker = str(cand), str(d.get("UserId"))
                    break
            except Exception:                               # noqa: BLE001
                pass
    if not basket_id:
        basket_id, marker = "1", "1"

    return AuthMaterial(
        declared=("2 comptes à nous (attacker@ / victim@, créés par self-signup) + le panier de la "
                  "victime comme cible IDOR marquée. Amorçage IDENTIQUE à la mesure de référence "
                  "du dépôt (ROADMAP §« Pouvoir de détection »)."),
        session={"bearer": accounts["attacker"][1]},
        accounts=[
            {"label": "attacker", "headers": {"Authorization": f"Bearer {accounts['attacker'][1]}"}},
            {"label": "victim", "headers": {"Authorization": f"Bearer {accounts['victim'][1]}"}},
        ],
        idor_targets=[{"url": f"{base}/rest/basket/{basket_id}", "owner": "victim", "marker": marker}],
        extra={"accounts": accounts, "basket_id": basket_id},
    )


def prime_dvga(base):
    """DVGA n'a ni compte ni session : tout passe par POST /graphql anonyme. On ne fournit
    DONC RIEN — et c'est une affirmation en soi (« forge trouve X sans rien »)."""
    return AuthMaterial(declared="AUCUN amorçage : l'application est entièrement anonyme.")


PRIMERS = {"dvwa": prime_dvwa, "vampi": prime_vampi,
           "juiceshop": prime_juiceshop, "dvga": prime_dvga}


def prime(name: str) -> AuthMaterial:
    return PRIMERS[name](APPS[name].base_url)


# ------------------------------------------------------------------ fichiers d'engagement
def write_scope(app: App, auth: AuthMaterial, out: Path, allow_exploit=True):
    """scope.json BORNÉ AU PORT de l'application (`127.0.0.1:PORT`), loopback autorisé
    explicitement (`allow_private`), `allow_exploit` déclaré — les oracles de contrôle d'accès
    (access_control.*, auth.takeover) en dépendent."""
    scope = {
        "mode": "grey",
        "in_scope": [app.host_port],
        "out_scope": [],
        "rate": 20,
        "allow_exploit": bool(allow_exploit),
        "allow_destructive": False,
        "allow_private": True,
    }
    if auth.session:
        scope["session"] = auth.session
    if auth.accounts or auth.idor_targets:
        scope["auth"] = {"accounts": auth.accounts, "idor_targets": auth.idor_targets}
    out.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    return scope


def write_targets(app: App, out: Path):
    out.write_text(json.dumps([{"host": app.host_port, "kind": "app",
                                "attrs": {"service": "http"}}], indent=2), encoding="utf-8")
