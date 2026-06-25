"""Modules web — scan (nuclei) + la classe qualifiante n°1 : IDOR/BOLA (différentiel 2-comptes).

`access_control.idor` est porté de `secpipe/access_control.py` : oracle différentiel (A possède
l'objet, B le récupère-t-il ? unauth refusé ?). exploit=True -> exige allow_exploit dans le ROE.
Pur urllib (stdlib). Lit comptes+URLs depuis action.params (injectés par la CLI depuis le scope).
"""
import json
import urllib.error
import urllib.request

from .registry import register, Module
from .. import runner


@register("web.nuclei")
class NucleiScan(Module):
    kind = "web.nuclei"
    exploit = False
    mitre = "T1595.002"
    description = "Scan de vulnérabilités par templates nuclei (medium/high/critical)."
    BIN, IMG = "nuclei", "projectdiscovery/nuclei"
    available = property(lambda self: runner.available("nuclei", "projectdiscovery/nuclei", prefer_docker=True))
    _SEV = {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
    _ALLOWED_SEV = ("info", "low", "medium", "high", "critical")
    _DEFAULT_SEV = "medium,high,critical"

    def _severity(self, action):
        """Niveaux de sévérité (param UI/console `severity`), filtrés contre la liste blanche nuclei.
        Accepte une chaîne CSV ou une liste. Valeur absente/invalide -> défaut medium,high,critical
        (jamais d'élargissement de capacité : c'est un filtre de templates, pas une bascule ROE)."""
        raw = action.params.get("severity")
        if isinstance(raw, str):
            wanted = [s.strip().lower() for s in raw.split(",")]
        elif isinstance(raw, (list, tuple)):
            wanted = [str(s).strip().lower() for s in raw]
        else:
            return self._DEFAULT_SEV
        levels = [s for s in wanted if s in self._ALLOWED_SEV]
        return ",".join(levels) if levels else self._DEFAULT_SEV

    def _args(self, target, severity=None):
        return ["-u", target, "-severity", severity or self._DEFAULT_SEV,
                "-jsonl", "-silent", "-no-color"]

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action.target, self._severity(action)),
                              prefer_docker=True)

    def fire(self, action):
        rc, out, err = runner.tool(self.BIN, self.IMG,
                                   self._args(action.target, self._severity(action)),
                                   timeout=600, prefer_docker=True)
        # Parser stdout d'ABORD : nuclei peut sortir rc!=0 sur condition bénigne tout en ayant
        # émis du JSONL valide. On ne renvoie le finding d'échec QUE si aucune ligne ne parse.
        findings = []
        for line in (out or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except ValueError:
                continue
            info = j.get("info", {})
            sev = self._SEV.get(str(info.get("severity", "info")).lower(), "INFO")
            # Pas de sur-classement : un hit nuclei est signalé PAR L'OUTIL sur sa sévérité
            # auto-déclarée, sans preuve d'exploitabilité côté Forge. On conserve la sévérité
            # (priorisation) mais on émet `reported_by_tool` plutôt que `vulnerable` — la
            # promotion en `vulnerable` est réservée aux oracles à preuve (IDOR, origine vérifiée).
            findings.append(self.finding(
                target=j.get("matched-at", action.target),
                title=f"nuclei: {info.get('name', j.get('template-id', '?'))}",
                severity=sev, category=j.get("template-id", "nuclei"),
                mitre="", status="reported_by_tool" if sev in ("HIGH", "CRITICAL") else "tested",
                tool="nuclei", evidence=line[:1500], poc=self.dry(action)))
        if not findings:
            failed = self.tool_failed(action, rc, out, err, "nuclei", category="nuclei")
            if failed:
                return [failed]
            findings.append(self.finding(
                target=action.target, title="nuclei: aucun hit medium+", severity="INFO",
                category="nuclei", status="tested", tool="nuclei", poc=self.dry(action)))
        return findings


@register("access_control.idor")
class IdorDifferential(Module):
    kind = "access_control.idor"
    exploit = True                       # accède à l'objet d'un autre user -> exige allow_exploit
    available = True                     # urllib stdlib
    mitre = "T1190"                      # Exploit Public-Facing Application (CWE-639)
    description = ("Oracle différentiel IDOR/BOLA sur 2 comptes : A possède l'objet, "
                  "B le récupère-t-il ? (anon refusé) — CWE-639.")

    def dry(self, action):
        urls = action.params.get("urls", [])
        n = len(urls) or "?"
        return (f"# différentiel IDOR 2-comptes sur {n} URL(s) possédées par le compte A : "
                f"GET en A, en B, en anonyme ; flag si B obtient ~le même corps que A et anon refusé")

    @staticmethod
    def _fetch(url, headers, timeout=15):
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:                # noqa: BLE001  (réseau hostile : on ne crashe pas)
            return None, ""

    @staticmethod
    def _similar(a, b):
        if not a or not b:
            return False
        m = max(len(a), len(b))
        return abs(len(a) - len(b)) <= 0.05 * m and a[:500] == b[:500]

    def fire(self, action):
        accounts = action.params.get("accounts", [])
        urls = action.params.get("urls", [])
        if len(accounts) < 2 or not urls:
            return [self.finding(
                target=action.target, title="IDOR non testé — config manquante", severity="INFO",
                category="CWE-639", status="tested", tool="forge/modules/web.py:access_control.idor",
                evidence="Requiert params.accounts (>=2 : A propriétaire, B attaquant) et params.urls.",
                poc=self.dry(action))]
        A, B = accounts[0], accounts[1]
        findings = []
        for url in urls:
            sa, ba = self._fetch(url, A.get("headers", {}))
            sb, bb = self._fetch(url, B.get("headers", {}))
            su, _ = self._fetch(url, {})
            vuln = (sb == 200 and self._similar(ba, bb) and su in (401, 403))
            findings.append(self.finding(
                target=url,
                title=("IDOR PROBABLE — B accède à l'objet de A" if vuln else "IDOR non confirmé"),
                severity=("HIGH" if vuln else "INFO"),
                category="CWE-639", mitre="T1190",
                status=("vulnerable" if vuln else "not_vulnerable"),
                tool="forge/modules/web.py:access_control.idor",
                evidence=f"A={sa} B={sb} anon={su} similaire={self._similar(ba, bb)} (confirmer manuellement)",
                poc=self._curl(url, B.get("headers", {}))))
        return findings

    @staticmethod
    def _curl(url, headers):
        """PoC curl valide : un drapeau -H par en-tête (l'ancienne version sérialisait le dict
        d'en-têtes en repr Python -> `curl -H '{...}'`, commande invalide non rejouable)."""
        parts = ["curl", "-sS"]
        for k, v in (headers or {}).items():
            parts += ["-H", f"'{k}: {v}'"]
        parts.append(f"'{url}'")
        return " ".join(parts)
