# SPDX-License-Identifier: AGPL-3.0-or-later
"""Modules de recon — wrappers réels sur des outils externes via le runner.

Recon = non-exploit, mais touche quand même le réseau -> reste gaté (in-scope + armé requis).
Auto-neutralisation (`available`) si ni binaire ni docker présents : discipline héritée de Plume.
"""
import json
import re

from .registry import register, Module
from .oracle import Oracle
from .. import blindness as _blind
from .. import runner
from .toolspec import FlagAllowlistMixin, check_extra_args, safe_value
# Découverte de service (host:port chaînable) — SOURCE UNIQUE partagée avec les wrappers spec-driven
# (naabu/masscan via toolspec.py). recon.nmap/httpx y émettent leurs `host:port` EXACTEMENT comme avant.
from ._discovery import (
    bare_host as _bare_host, service_discovery_findings as _service_discovery_findings,
    http_confirmed_ports, port_inventory_finding, _STANDARD_WEB_PORTS)

_NMAP_OPEN_PORT_RX = re.compile(r"^(\d{1,5})/tcp\s+open\s+(\S+)", re.MULTILINE)

# =================================================================================================
#  « J'AI SCANNÉ 0 HÔTE » N'EST PAS « J'AI VÉRIFIÉ » — défaut D16 du banc de détection.
#
#  Le correctif D9 avait fait tomber le NOMBRE de tirs nmap aveugles (72 -> 13) ; le rejeu a montré
#  que les 13 restants scannaient TOUS 0 hôte et rendaient TOUS `status=tested` sous le titre
#  « Services exposés (nmap -sV) ». Un opérateur y lit « vérifié ». MESURÉ contre le vrai binaire :
#
#      nmap -sV -Pn --top-ports 20 http://127.0.0.1:8081   Unable to split netmask from target
#                                                          expression -> Nmap done: 0 IP addresses
#                                                          (0 hosts up)                       rc=0
#      nmap … 127.0.0.1:8081                               Failed to resolve "127.0.0.1:8081"
#                                                          -> Nmap done: 0 IP addresses …      rc=0
#      nmap … 127.0.0.1                                    Nmap done: 1 IP address (1 host up) rc=0
#
#  Les trois sortent **rc=0** : ni `Module.tool_failed` (borne `rc != 0`) ni
#  `blindness.tool_did_not_run` (`rc != 0` ET stdout vide) ne peuvent voir ce silence — et
#  `blindness` REFUSE délibérément d'élargir à `rc == 0`, parce qu'un outil qui a bien tourné sur une
#  cible saine sort lui aussi à rc=0 avec peu de sortie. La distinction n'est donc PAS dans le rc :
#  elle est DÉCLARÉE PAR NMAP LUI-MÊME, en toutes lettres, dans sa ligne de bilan. Un scan réussi qui
#  ne trouve rien dit « 1 IP address (1 host up) scanned » — un verdict légitime, qu'on garde intact.
#  Zéro hôte scanné n'est pas un verdict : c'est une ABSTENTION, et elle se dit `skipped`.
#  Le cerveau évite désormais de PROPOSER ces cibles (`brain._raw_target_kinds`) ; ceci est la
#  seconde ligne — ce qui tire quand même ne peut plus affirmer avoir vérifié.
# =================================================================================================
_NMAP_NO_HOST_RX = re.compile(r"Nmap done:\s*0 IP addresses\s*\(0 hosts up\)"
                              r"|No targets were specified, so 0 hosts scanned", re.IGNORECASE)


def _nmap_scanned_nothing(out, err):
    """nmap a-t-il DÉCLARÉ n'avoir scanné AUCUN hôte ? Lecture de SA ligne de bilan, pas une
    heuristique sur le rc (cf. le bloc ci-dessus). `1 IP address (1 host up) scanned` — le scan
    légitime qui ne trouve rien — ne matche PAS : le verdict négatif reste un verdict. Pur, ne lève
    jamais."""
    return bool(_NMAP_NO_HOST_RX.search(f"{out or ''}\n{err or ''}"))


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


def _nmap_all_open_ports(out):
    """TOUS les ports TCP OUVERTS listés par nmap (HTTP ou non), pour le finding d'INVENTAIRE de surface.
    Pur, dérivé du texte `-sV`. Ne lève jamais."""
    return [m.group(1) for m in _NMAP_OPEN_PORT_RX.finditer(out or "")]


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
    # EGRESS TIERS DÉCLARÉ (cf. docs/CONFIGURATION.md §2quater). MESURÉ, pas supposé : `-tech-detect`
    # a téléchargé 92,6 Mio depuis huggingface.co à CHACUN des 4 tirs de ce module (~370 Mio) — le
    # SEUL egress prouvé sur 4 906 findings, dans un banc annoncé « loopback strict ». Le module SAIT
    # s'en passer (statut, titre, serveur ne sortent pas), donc `egress_required` reste False : sans
    # autorisation il DÉGRADE (retire le drapeau) au lieu d'être écarté — borner, pas supprimer.
    egress = ("huggingface.co", "cdn-lfs.huggingface.co")
    egress_required = False
    _refuse_mitre = "T1595"                       # provenance du finding de refus (mixin) — inchangée
    _refuse_tool = "httpx"
    description = ("Fingerprint HTTP (httpx) : status, titre, techno détectées. Params UI : threads "
                   "(-threads), rate (-rl), status-codes (-mc), paths (-path), extra_args (allowlist). "
                   "Défaut inchangé quand rien n'est fourni. `-tech-detect` SORT vers huggingface.co "
                   "(92,6 Mio par tir) : retiré sauf `scope.allow_tool_egress`.")
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
        # `_egress_allowed` est posé par `Engine._decide_blocking` d'après `scope.allow_tool_egress`
        # (protocole symétrique de `_pinned_ips` / `_budget_remaining`). ABSENT => False, fail-closed :
        # un appelant qui court-circuite le moteur (test, script) ne doit pas déclencher 92,6 Mio de
        # téléchargement sans l'avoir demandé.
        egress_ok = bool(p.get("_egress_allowed"))
        argv = ["-u", action.target, "-silent", "-status-code", "-title", "-json", "-no-color"]
        if egress_ok:
            argv.insert(5, "-tech-detect")        # même position -> argv BYTE-IDENTIQUE si autorisé
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
        if not egress_ok:
            # L'ALLOWLIST N'EST PAS LA PORTE D'EGRESS : `-tech-detect` y figure légitimement (c'est un
            # drapeau sûr du point de vue option-smuggling). Le laisser passer par `extra_args`
            # rouvrirait par la fenêtre l'egress qu'on vient de fermer par la porte.
            extra = [tok for tok in extra if tok != "-tech-detect"]
        argv += extra
        return argv

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action), prefer_docker=True)

    def fire(self, action):
        # EXTRA_ARGS gouvernés : un drapeau libre hors allowlist (ou non-liste) -> refus fail-closed.
        if (refused := self.gate_extra_args(action)):
            return refused
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action), timeout=60, prefer_docker=True)
        # ============================================================================================
        #  SEMER L'ÉTAT DU MUR — httpx est le PREMIER à voir la cible, et il l'a DÉJÀ vue.
        #
        #  Dans le ledger `gxrun2`, ce module a enregistré **19 fois** `{"status_code":403,
        #  "title":"Just a moment...","content_length":5506}` — l'interstitiel Cloudflare, en toutes
        #  lettres, horodaté avant tous les autres outils. Cette connaissance mourait dans un finding
        #  INFO pendant que nuclei, zap-baseline et katana concluaient « aucun hit » derrière le même
        #  mur, faute de savoir qu'il existait. On la verse donc à l'état de franchissement gouverné
        #  (`SessionStore`), la MÊME voie qu'alimentent `Oracle._http` (premier lot) et les wrappers
        #  d'outils : ceux qui passent après LISENT au lieu de deviner. Aucune requête de plus, aucun
        #  secret, scope-guardé par le store — et la borne reste celle du premier lot (interstitiel
        #  explicite, jamais un simple 403 : le JSON d'un 403 NU ne porte aucune de ces chaînes).
        # ============================================================================================
        _blind.note_tool_output(action.target, out, err)
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
        # ABSTENTION NOMMÉE (D16) — nmap déclare n'avoir scanné AUCUN hôte : rien n'a été regardé,
        # donc rien ne peut être affirmé. `skipped` (« pas vérifié »), jamais `tested` (« vérifié,
        # rien trouvé »). Aucune découverte/inventaire n'est dérivé d'un scan vide.
        if _nmap_scanned_nothing(out, err):
            return [self.finding(
                target=action.target,
                title="Services exposés — NON VÉRIFIÉ : nmap n'a scanné AUCUN hôte",
                severity="INFO", category="recon", mitre="T1046", status="skipped", tool="nmap",
                evidence=("nmap a rendu « 0 IP addresses (0 hosts up) » : la cible ne lui a pas été "
                          "présentée sous une forme qu'il sait résoudre (une URL — « Unable to split "
                          "netmask from target expression » — ou un `host:port`, qu'il lit comme un "
                          "NOM D'HÔTE : « Failed to resolve »). Il sort rc=0, donc ni `tool_failed` "
                          "(rc != 0) ni `blindness.tool_did_not_run` ne le voient : sans cette "
                          "abstention, l'action rendait « Services exposés — vérifié » après avoir "
                          "regardé zéro hôte. Rejouer sur l'HÔTE NU de la cible.\n\n"
                          + (out or err).strip()[:900]),
                poc=self.dry(action))]
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
        ports = _nmap_web_ports(out) + http_confirmed_ports(self._fetch, host, _nmap_nonhttp_open_ports(out))
        # INVENTAIRE : la surface ouverte (TOUS les host:port) en UN finding INFO (visible d'un coup,
        # au lieu d'être noyée dans le texte de sortie). Additif — n'affecte pas la découverte chaînable.
        inv = port_inventory_finding(self, action, "nmap", _nmap_all_open_ports(out))
        inventory = [inv] if inv else []
        return [summary] + inventory + _service_discovery_findings(self, action, ports, "nmap")
