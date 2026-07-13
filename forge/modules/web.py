"""Module web — scan par templates nuclei (`web.nuclei`).

Ce fichier n'enregistre plus QUE `web.nuclei`. La classe qualifiante IDOR/BOLA
(`access_control.idor`), qui squattait ici, a été extraite dans `access_control.py` (bâtie sur la
base `Oracle`). nuclei n'apporte AUCUNE preuve d'exploitabilité côté Forge : un hit est signalé sur
la sévérité auto-déclarée par l'outil (`reported_by_tool`), jamais promu `vulnerable`.
"""
import json

from .registry import register, Module
from .. import runner
from .. import techniques
from .toolspec import check_extra_args, safe_value


@register("web.nuclei")
class NucleiScan(Module):
    kind = "web.nuclei"
    exploit = False
    mitre = techniques.mitre_for("web.nuclei")   # source de vérité : forge/techniques.py
    description = ("Scan de vulnérabilités par templates nuclei (medium/high/critical par défaut). "
                   "Params UI : severity (allow-listée), templates (-t), tags (-tags), extra_args (allowlist).")
    BIN, IMG = "nuclei", "projectdiscovery/nuclei"
    available = property(lambda self: runner.available("nuclei", "projectdiscovery/nuclei", prefer_docker=True))
    _SEV = {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
    _ALLOWED_SEV = ("info", "low", "medium", "high", "critical")
    _DEFAULT_SEV = "medium,high,critical"
    # SCHÉMA servi à l'UI (source unique) — rendu dynamiquement par modules-form.js via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "severity", "type": "select", "label": "severity (filtre templates)", "flag": "-severity",
         "allowed": ["info", "low", "medium", "high", "critical"]},
        {"name": "templates", "type": "text", "label": "templates (-t, ex cves/ ou http/…)", "flag": "-t"},
        {"name": "tags", "type": "text", "label": "tags (-tags, ex cve,rce)", "flag": "-tags"},
        {"name": "extra_args", "type": "list", "label": "extra args (allowlist de drapeaux)", "flag": ""},
    ]
    # ALLOWLIST des drapeaux acceptés en argument libre (extra_args) — tout flag hors liste est REFUSÉ.
    FLAG_ALLOWLIST = ("-severity", "-t", "-tags", "-etags", "-itags", "-rl", "-c", "-timeout",
                      "-retries", "-silent", "-jsonl", "-no-color", "-nc")

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

    def _args(self, action):
        p = action.params or {}
        argv = ["-u", action.target, "-severity", self._severity(action)]
        templates = p.get("templates")
        if templates is not None and safe_value(str(templates)):
            argv += ["-t", str(templates)]
        tags = p.get("tags")
        if tags is not None and safe_value(str(tags)):
            argv += ["-tags", str(tags)]
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)  # tokens VALIDÉS (fire gate en amont)
        argv += extra
        argv += ["-jsonl", "-silent", "-no-color"]
        return argv

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action), prefer_docker=True)

    def _refuse(self, action, reason):
        return [self.finding(
            target=action.target, title=f"{self.kind} non exécuté — {reason}", severity="INFO",
            category="nuclei", status="skipped", tool="nuclei",
            evidence=f"{reason}. Aucun processus lancé (fail-closed).")]

    def fire(self, action):
        p = action.params or {}
        if str(action.target).startswith("-"):
            return self._refuse(action, "cible positionnelle ambiguë (commence par '-')")
        bad_extra, _ = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
        if bad_extra is not None:
            return self._refuse(action, f"argument libre refusé ({bad_extra})")
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action),
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
