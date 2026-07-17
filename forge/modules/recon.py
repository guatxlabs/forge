"""Modules de recon — wrappers réels sur des outils externes via le runner.

Recon = non-exploit, mais touche quand même le réseau -> reste gaté (in-scope + armé requis).
Auto-neutralisation (`available`) si ni binaire ni docker présents : discipline héritée de Plume.
"""
import json
import re

from .registry import register, Module
from .oracle import Oracle
from .. import runner
from .. import techniques
from .toolspec import FlagAllowlistMixin, check_extra_args, safe_value

# Ports web STANDARD : déjà couverts par l'hôte de base (recon/oracles semés dessus) -> on n'émet PAS
# de cible `host:port` redondante pour eux. Seuls les ports NON standard (ex. console interne :7100)
# ont besoin d'être surfacés comme NOUVELLE surface chaînable.
_STANDARD_WEB_PORTS = frozenset({80, 443})
_MAX_DISCOVERED_SERVICES = 25            # borne le fan-out (un scan -p- ne doit pas exploser le plan)
_MAX_PROBED_PORTS = 25                   # borne les sondes de CONFIRMATION HTTP (un -p- peut ouvrir bcp de ports)
_NMAP_OPEN_PORT_RX = re.compile(r"^(\d{1,5})/tcp\s+open\s+(\S+)", re.MULTILINE)


def _bare_host(target):
    """Hôte nu (scheme/userinfo/path/port retirés) d'une cible. Miroir simplifié de `Scope._host` :
    sert à ANCRER un `host:port` découvert sur l'hôte DÉJÀ gaté par le ROE (jamais un autre hôte).
    Pur, ne lève jamais."""
    s = str(target).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):                            # IPv6 littéral [::1]:port -> garde l'adresse
        return s.split("]", 1)[0].lstrip("[")
    if s.count(":") == 1:                            # host:port (pas IPv6 nu)
        s = s.split(":", 1)[0]
    return s


def _service_discovery_findings(module, action, ports, tool):
    """Un finding de DÉCOUVERTE par port web NON standard (target = `host:port`, marqueur
    DISCOVERY_SERVICE_MARKER) -> le port devient un NŒUD du graphe que le cerveau chaîne (actions web
    de base + modules web explicites via _directive_actions) sur cette nouvelle surface. Ancré sur
    l'hôte DÉJÀ gaté par le ROE (`_bare_host(action.target)`) : jamais un autre hôte -> la re-gate ROE
    de la vague suivante le laisse passer s'il est in-scope (host in-scope => host:port in-scope) et le
    VÉTOe sinon. Ports 80/443 et le port propre de la cible ignorés (déjà couverts). Borné + dédupliqué."""
    host = _bare_host(action.target)
    tgt_netloc = str(action.target).split("://")[-1].split("/", 1)[0]
    out, seen = [], set()
    for port in ports:
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        if p in _STANDARD_WEB_PORTS or p in seen or not (0 < p < 65536):
            continue
        hp = f"{host}:{p}"
        if hp == tgt_netloc:                         # déjà la cible courante -> pas de nœud self-référent
            continue
        seen.add(p)
        out.append(module.finding(
            target=hp, title=f"{techniques.DISCOVERY_SERVICE_MARKER} : {hp}",
            severity="INFO", category="recon", mitre=getattr(module, "mitre", ""), status="tested",
            tool=tool,
            evidence=(f"Service web découvert sur le port non standard {p} ({hp}) via {tool} — "
                      f"nouvelle surface web chaînable (fingerprint/oracles à la vague suivante)."),
            poc=f"# {tool} : service web exposé sur {hp}"))
        if len(out) >= _MAX_DISCOVERED_SERVICES:
            break
    return out


def _httpx_web_ports(out):
    """Ports des services web VIVANTS listés par httpx (JSON par-ligne : chaque ligne = un service
    répondant). Pur, tolérant (lignes non-JSON ignorées). Ne lève jamais."""
    ports = []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        port = j.get("port")
        if port is not None:
            ports.append(port)
    return ports


def _nmap_web_ports(out):
    """Ports TCP OUVERTS dont le service nmap est HTTP (`http`, `http-proxy`, `ssl/http`, `https`…).
    Pur, dérivé du texte `-sV`. Ne lève jamais."""
    ports = []
    for m in _NMAP_OPEN_PORT_RX.finditer(out or ""):
        if "http" in m.group(2).lower():
            ports.append(m.group(1))
    return ports


def _nmap_nonhttp_open_ports(out):
    """Ports TCP OUVERTS que nmap N'A PAS reconnus comme HTTP (ex. `font-service?` : la sonde brute de
    nmap reçoit le 421 anti-rebinding de la console et MISLABELLISE). Candidats à une CONFIRMATION HTTP
    active (GET avec Host correct). 80/443 exclus (déjà couverts par l'hôte de base). Pur, ne lève
    jamais — c'est cette liste que `_http_confirmed_ports` filtre pour ne surfacer QUE le vrai HTTP."""
    ports = []
    for m in _NMAP_OPEN_PORT_RX.finditer(out or ""):
        if "http" in m.group(2).lower():
            continue
        p = m.group(1)
        try:
            if int(p) in _STANDARD_WEB_PORTS:
                continue
        except ValueError:
            continue
        ports.append(p)
    return ports


def _http_confirmed_ports(module, host, ports):
    """Sous-ensemble de `ports` (ouverts mais NON labellisés http par nmap) qui parlent RÉELLEMENT HTTP,
    prouvé par une sonde GET (Host correct) via le seam `module._fetch` — là où la sonde brute de nmap
    reçoit un 421 (anti-rebinding) et mislabellise, un vrai GET renvoie un STATUS HTTP (200/401/421…),
    tandis qu'un service NON-HTTP (VNC 5900…) casse le parse HTTP -> None -> jamais confirmé -> ZÉRO
    bruit. Sonde BORNÉE (`_MAX_PROBED_PORTS`) : un `-p-` peut ouvrir beaucoup de ports, on n'explose pas.
    Ancré sur l'hôte DÉJÀ gaté par le ROE (`host` = l'hôte in-scope de la cible nmap) : la sonde ne peut
    PHYSIQUEMENT pas quitter le périmètre. Pur, ne lève jamais (sonde qui lève => traitée non-HTTP)."""
    out, n = [], 0
    for p in ports:
        if n >= _MAX_PROBED_PORTS:
            break
        n += 1
        try:
            st = module._fetch(f"http://{host}:{p}")
        except Exception:            # noqa: BLE001  (réseau/protocole hostile : jamais un crash)
            st = None
        if st is not None:           # une RÉPONSE HTTP (quel que soit le code) => le port parle HTTP
            out.append(p)
    return out


def _path_argval(val):
    """True si `val` est une valeur de CHEMIN/EXTENSION sûre à passer à un drapeau (-path/-e) : chaîne
    non vide, ne COMMENCE PAS par '-' (anti option-smuggling), sans NUL ni espace. AUTORISE '/' et '.'
    en tête (chemins `/admin`, extensions `.php`) que `safe_value` refuserait. Pur, ne lève jamais."""
    s = str(val) if val is not None else ""
    return bool(s) and not s.startswith("-") and "\x00" not in s and not any(c.isspace() for c in s)


def _truthy(v):
    """True si `v` exprime un OUI booléen : True natif, ou chaîne 'true'/'1'/'yes'/'on' (insensible à la
    casse/espaces). Tout le reste (None, '', 'false', 'off', 0) -> False. Pur, ne lève jamais. Sert au
    param opt-in `full_ports` qui vient de l'UI (select) OU du CLI (chaîne)."""
    if v is True:
        return True
    return str(v).strip().lower() in ("1", "true", "yes", "on") if v is not None else False


def _rate_flag(params):
    """Débit req/s (entier positif) depuis params['rate'], ou None (aucun drapeau -> byte-identique au
    défaut). Le débit n'est PRÉSENT que si l'opérateur l'a fixé (module_params) — jamais injecté par
    défaut sur les outils natifs. Ne lève jamais."""
    r = (params or {}).get("rate")
    try:
        n = int(r)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


@register("recon.httpx")
class HttpxFingerprint(FlagAllowlistMixin, Module):
    kind = "recon.httpx"
    exploit = False
    mitre = "T1595"
    _refuse_mitre = "T1595"                       # provenance du finding de refus (mixin) — inchangée
    _refuse_tool = "httpx"
    description = ("Fingerprint HTTP (httpx) : status, titre, techno détectées. Params UI : threads "
                   "(-threads), rate (-rl), status-codes (-mc), paths (-path), extra_args (allowlist). "
                   "Défaut inchangé quand rien n'est fourni.")
    BIN, IMG = "httpx", "projectdiscovery/httpx"
    available = property(lambda self: runner.available("httpx", "projectdiscovery/httpx", prefer_docker=True))

    # SCHÉMA servi à l'UI (source unique) — rendu dynamiquement par modules-form.js via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "threads", "type": "number", "label": "threads (-threads)", "flag": "-threads"},
        {"name": "rate", "type": "number", "label": "rate-limit (-rl req/s)", "flag": "-rl"},
        {"name": "status_codes", "type": "text", "label": "codes filtrés (-mc, ex 200,301)", "flag": "-mc"},
        {"name": "paths", "type": "text", "label": "chemins probés (-path, ex /,/admin)", "flag": "-path"},
        FlagAllowlistMixin.extra_args_param(),
    ]
    # ALLOWLIST des drapeaux acceptés en argument libre (extra_args) — tout flag hors liste est REFUSÉ.
    # EXCLUS : -o/-output (écriture fichier), -sr/-srd (store-response dans un dossier), -proxy/-http-proxy
    # (exfil), -config (lecture fichier de config arbitraire).
    FLAG_ALLOWLIST = ("-rl", "-t", "-threads", "-mc", "-fc", "-path", "-status-code", "-title",
                      "-tech-detect", "-server", "-cl", "-follow-redirects", "-fr", "-timeout",
                      "-retries", "-x", "-silent", "-no-color", "-json")

    def _args(self, action):
        p = action.params or {}
        argv = ["-u", action.target, "-silent", "-status-code", "-title", "-tech-detect", "-json", "-no-color"]
        threads = p.get("threads")
        if threads not in (None, "") and safe_value(str(threads)):
            argv += ["-threads", str(threads)]
        rate = _rate_flag(p)                              # débit -> -rl <n> (opt-in ; absent = rien)
        if rate is not None:
            argv += ["-rl", str(rate)]
        codes = p.get("status_codes")
        if codes is not None and safe_value(str(codes)):
            argv += ["-mc", str(codes)]
        paths = p.get("paths")
        # un chemin peut légitimement commencer par '/' (rejeté par safe_value) : on garde le garde-fou
        # ESSENTIEL (anti option-smuggling : refus si commence par '-', NUL ou espace) mais on autorise '/'.
        if _path_argval(paths):
            argv += ["-path", str(paths)]
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)  # tokens VALIDÉS (fire gate en amont)
        argv += extra
        return argv

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action), prefer_docker=True)

    def fire(self, action):
        # EXTRA_ARGS gouvernés : un drapeau libre hors allowlist (ou non-liste) -> refus fail-closed.
        if (refused := self.gate_extra_args(action)):
            return refused
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action), timeout=60, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "httpx")
        if failed:
            return [failed]
        summary = self.finding(
            target=action.target, title="Fingerprint HTTP (httpx)", severity="INFO",
            category="recon", mitre="T1595", status="tested", tool="httpx",
            evidence=(out or err).strip()[:1500], poc=self.dry(action))
        # DÉCOUVERTE de surface : un service web sur un port NON standard (ex. :7100) devient une cible
        # chaînable (target=host:port) au lieu de rester enfoui dans le texte de sortie.
        return [summary] + _service_discovery_findings(self, action, _httpx_web_ports(out), "httpx")


@register("recon.nmap")
class NmapServices(FlagAllowlistMixin, Module):
    kind = "recon.nmap"
    exploit = False
    mitre = "T1046"
    _refuse_mitre = "T1046"                       # provenance du finding de refus (mixin) — inchangée
    _refuse_tool = "nmap"
    description = ("Découverte des services exposés (nmap -sV). Params UI : full_ports (-p-, GAGNE), ports "
                   "(-p), top_ports (--top-ports), scripts NSE (--script), timing (-T0..5), extra_args "
                   "(allowlist). Défaut : -sV -Pn --top-ports 1000 quand rien n'est fourni.")
    BIN, IMG = "nmap", "instrumentisto/nmap"
    available = property(lambda self: runner.available("nmap", "instrumentisto/nmap", prefer_docker=True))

    # SCHÉMA servi à l'UI (source unique) : chaque descripteur mappe un param à son drapeau CLI. Rendu
    # dynamiquement par le formulaire de lancement (modules-form.js) via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "full_ports", "type": "select", "label": "full-ports (-p- scan 1-65535, gagne)", "flag": "-p-",
         "allowed": ["", "true"]},
        {"name": "ports", "type": "text", "label": "ports (-p, ex 1-65535 ou 80,443)", "flag": "-p"},
        {"name": "top_ports", "type": "number", "label": "top-ports (--top-ports N)", "flag": "--top-ports"},
        {"name": "scripts", "type": "text", "label": "scripts NSE (--script, ex http-* ou default)", "flag": "--script"},
        {"name": "timing", "type": "select", "label": "timing (-T0..5)", "flag": "-T",
         "allowed": ["0", "1", "2", "3", "4", "5"]},
        FlagAllowlistMixin.extra_args_param(),
    ]
    # ALLOWLIST des drapeaux acceptés en argument libre (extra_args) — tout flag hors liste est REFUSÉ.
    FLAG_ALLOWLIST = ("-sV", "-sC", "-sT", "-sS", "-p", "-p-", "--top-ports", "--script",
                      "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "--max-rate", "--scan-delay",
                      "--min-rate", "-Pn", "-n")

    def _port_spec(self, p):
        """Fragment de spécification de ports. PRIORITÉ : `full_ports` opt-in -> `-p-` (scan 1-65535, GAGNE
        sur tout) ; sinon `-p <ports>` (si valide) ; sinon `--top-ports <N>` (si valide 1..65535) ; sinon le
        défaut historique `--top-ports 1000`. Valeur hostile (commençant par '-') ignorée. `full_ports` ABSENT
        -> byte-identique au comportement historique (aucun `-p-`)."""
        if _truthy(p.get("full_ports")):                  # opt-in explicite -> plage complète, aucun --top-ports
            return ["-p-"]
        ports = p.get("ports")
        if ports is not None and safe_value(str(ports)):
            return ["-p", str(ports)]
        top = p.get("top_ports")
        if top not in (None, ""):
            try:
                n = int(top)
                if 1 <= n <= 65535:
                    return ["--top-ports", str(n)]
            except (TypeError, ValueError):
                pass
        return ["--top-ports", "1000"]

    def _args(self, action):
        p = action.params or {}
        argv = ["-sV", "-Pn"] + self._port_spec(p)
        scripts = p.get("scripts")
        if scripts is not None and safe_value(str(scripts)):
            argv += ["--script", str(scripts)]
        timing = p.get("timing")
        if timing not in (None, ""):
            try:
                t = int(timing)
                if 0 <= t <= 5:
                    argv.append(f"-T{t}")
            except (TypeError, ValueError):
                pass
        rate = _rate_flag(p)                              # débit -> --max-rate <n> (opt-in ; absent = rien)
        if rate is not None:
            argv += ["--max-rate", str(rate)]
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)  # tokens VALIDÉS (fire gate en amont)
        argv += extra
        argv.append(action.target)                            # cible en POSITIONNEL (dernier)
        return argv

    @staticmethod
    def _fetch(url, timeout=5):
        """Sonde de CONFIRMATION HTTP d'un port ouvert -> status (int) ou None. GET avec Host correct
        via le câblage urllib partagé (`Oracle._http`) : là où la sonde brute de nmap reçoit un 421
        (anti-rebinding de la console) et MISLABELLISE le service (`font-service?`), un vrai GET obtient
        un STATUS HTTP -> le port est confirmé web. Un service NON-HTTP (VNC…) casse le parse HTTP ->
        None -> jamais confirmé. Seam monkeypatché par les tests. Pur, ne lève jamais."""
        st, _body, _h = Oracle._http(url, timeout=timeout, method="GET", maxlen=2048)
        return st

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action), prefer_docker=True)

    def fire(self, action):
        # GARDE-FOU anti-injection d'argument : cible positionnelle commençant par '-' -> refus fail-closed.
        if str(action.target).startswith("-"):
            return self._refuse(action, "cible positionnelle ambiguë (commence par '-')")
        # EXTRA_ARGS gouvernés : un drapeau libre hors allowlist (ou non-liste) -> refus fail-closed.
        if (refused := self.gate_extra_args(action)):
            return refused
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action), timeout=300, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "nmap")
        if failed:
            return [failed]
        summary = self.finding(
            target=action.target, title="Services exposés (nmap -sV)", severity="INFO",
            category="recon", mitre="T1046", status="tested", tool="nmap",
            evidence=(out or err).strip()[:1500], poc=self.dry(action))
        # DÉCOUVERTE de surface : chaque service HTTP sur un port NON standard devient une cible chaînable
        # (target=host:port) -> le cerveau y sème les actions web à la vague suivante. Deux sources :
        #  (1) les ports que nmap LABELLISE http (confiance directe) ;
        #  (2) les ports OUVERTS que nmap NE reconnaît PAS comme HTTP mais CONFIRMÉS par une sonde GET
        #      (Host correct) — couvre les services que nmap mislabellise (ex. console anti-rebinding
        #      qui renvoie 421 à la sonde brute -> `font-service?`). Sonde bornée + ancrée sur l'hôte
        #      in-scope (jamais un autre hôte) ; les vrais non-HTTP (VNC…) ne sont JAMAIS confirmés.
        host = _bare_host(action.target)
        ports = _nmap_web_ports(out) + _http_confirmed_ports(self, host, _nmap_nonhttp_open_ports(out))
        return [summary] + _service_discovery_findings(self, action, ports, "nmap")
