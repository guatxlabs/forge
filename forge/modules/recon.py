"""Modules de recon — wrappers réels sur des outils externes via le runner.

Recon = non-exploit, mais touche quand même le réseau -> reste gaté (in-scope + armé requis).
Auto-neutralisation (`available`) si ni binaire ni docker présents : discipline héritée de Plume.
"""
from .registry import register, Module
from .. import runner
from .toolspec import check_extra_args, safe_value


def _path_argval(val):
    """True si `val` est une valeur de CHEMIN/EXTENSION sûre à passer à un drapeau (-path/-e) : chaîne
    non vide, ne COMMENCE PAS par '-' (anti option-smuggling), sans NUL ni espace. AUTORISE '/' et '.'
    en tête (chemins `/admin`, extensions `.php`) que `safe_value` refuserait. Pur, ne lève jamais."""
    s = str(val) if val is not None else ""
    return bool(s) and not s.startswith("-") and "\x00" not in s and not any(c.isspace() for c in s)


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
class HttpxFingerprint(Module):
    kind = "recon.httpx"
    exploit = False
    mitre = "T1595"
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
        {"name": "extra_args", "type": "list", "label": "extra args (allowlist de drapeaux)", "flag": ""},
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

    def _refuse(self, action, reason):
        return [self.finding(
            target=action.target, title=f"{self.kind} non exécuté — {reason}", severity="INFO",
            category="recon", mitre="T1595", status="skipped", tool="httpx",
            evidence=f"{reason}. Aucun processus lancé (fail-closed).")]

    def fire(self, action):
        p = action.params or {}
        # EXTRA_ARGS gouvernés : un drapeau libre hors allowlist (ou non-liste) -> refus fail-closed.
        bad_extra, _ = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
        if bad_extra is not None:
            return self._refuse(action, f"argument libre refusé ({bad_extra})")
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action), timeout=60, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "httpx")
        if failed:
            return [failed]
        return [self.finding(
            target=action.target, title="Fingerprint HTTP (httpx)", severity="INFO",
            category="recon", mitre="T1595", status="tested", tool="httpx",
            evidence=(out or err).strip()[:1500], poc=self.dry(action))]


@register("recon.nmap")
class NmapServices(Module):
    kind = "recon.nmap"
    exploit = False
    mitre = "T1046"
    description = ("Découverte des services exposés (nmap -sV). Params UI : ports (-p), top_ports "
                   "(--top-ports), scripts NSE (--script), timing (-T0..5), extra_args (allowlist). "
                   "Défaut : -sV -Pn --top-ports 1000 quand rien n'est fourni.")
    BIN, IMG = "nmap", "instrumentisto/nmap"
    available = property(lambda self: runner.available("nmap", "instrumentisto/nmap", prefer_docker=True))

    # SCHÉMA servi à l'UI (source unique) : chaque descripteur mappe un param à son drapeau CLI. Rendu
    # dynamiquement par le formulaire de lancement (modules-form.js) via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "ports", "type": "text", "label": "ports (-p, ex 1-65535 ou 80,443)", "flag": "-p"},
        {"name": "top_ports", "type": "number", "label": "top-ports (--top-ports N)", "flag": "--top-ports"},
        {"name": "scripts", "type": "text", "label": "scripts NSE (--script, ex http-* ou default)", "flag": "--script"},
        {"name": "timing", "type": "select", "label": "timing (-T0..5)", "flag": "-T",
         "allowed": ["0", "1", "2", "3", "4", "5"]},
        {"name": "extra_args", "type": "list", "label": "extra args (allowlist de drapeaux)", "flag": ""},
    ]
    # ALLOWLIST des drapeaux acceptés en argument libre (extra_args) — tout flag hors liste est REFUSÉ.
    FLAG_ALLOWLIST = ("-sV", "-sC", "-sT", "-sS", "-p", "-p-", "--top-ports", "--script",
                      "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "--max-rate", "--scan-delay",
                      "--min-rate", "-Pn", "-n")

    def _port_spec(self, p):
        """Fragment de spécification de ports : `-p <ports>` (si valide) sinon `--top-ports <N>` (si valide
        1..65535) sinon le défaut historique `--top-ports 1000`. Valeur hostile (commençant par '-') ignorée."""
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

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action), prefer_docker=True)

    def _refuse(self, action, reason):
        return [self.finding(
            target=action.target, title=f"{self.kind} non exécuté — {reason}", severity="INFO",
            category="recon", mitre="T1046", status="skipped", tool="nmap",
            evidence=f"{reason}. Aucun processus lancé (fail-closed).")]

    def fire(self, action):
        p = action.params or {}
        # GARDE-FOU anti-injection d'argument : cible positionnelle commençant par '-' -> refus fail-closed.
        if str(action.target).startswith("-"):
            return self._refuse(action, "cible positionnelle ambiguë (commence par '-')")
        # EXTRA_ARGS gouvernés : un drapeau libre hors allowlist (ou non-liste) -> refus fail-closed.
        bad_extra, _ = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
        if bad_extra is not None:
            return self._refuse(action, f"argument libre refusé ({bad_extra})")
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action), timeout=300, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "nmap")
        if failed:
            return [failed]
        return [self.finding(
            target=action.target, title="Services exposés (nmap -sV)", severity="INFO",
            category="recon", mitre="T1046", status="tested", tool="nmap",
            evidence=(out or err).strip()[:1500], poc=self.dry(action))]
