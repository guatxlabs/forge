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
from .toolspec import FlagAllowlistMixin, check_extra_args, safe_value


@register("web.nuclei")
class NucleiScan(FlagAllowlistMixin, Module):
    kind = "web.nuclei"
    exploit = False
    _refuse_category = "nuclei"                   # provenance du finding de refus (mixin) — inchangée
    _refuse_tool = "nuclei"
    mitre = techniques.mitre_for("web.nuclei")   # source de vérité : forge/techniques.py
    description = ("Scan de vulnérabilités par templates nuclei (info→critical par défaut, pour faire "
                   "remonter les expositions info/low : swagger/openapi, panels LLM, exposed-files). "
                   "Params UI : severity (allow-listée), templates (-t), tags (-tags), extra_args (allowlist).")
    BIN, IMG = "nuclei", "projectdiscovery/nuclei"
    available = property(lambda self: runner.available("nuclei", "projectdiscovery/nuclei", prefer_docker=True))
    _SEV = {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
    _ALLOWED_SEV = ("info", "low", "medium", "high", "critical")
    # Défaut élargi à info,low pour faire remonter les EXPOSITIONS (swagger/openapi, panels LLM,
    # exposed-files) qu'un scan manuel voit et que le filtre medium+ masquait. AUCUNE inflation :
    # la sévérité du finding reste = sévérité RÉELLE du template (INFO template -> finding INFO, cf. _SEV).
    _DEFAULT_SEV = "info,low,medium,high,critical"
    # SCHÉMA servi à l'UI (source unique) — rendu dynamiquement par modules-form.js via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "severity", "type": "select", "label": "severity (filtre templates)", "flag": "-severity",
         "allowed": ["info", "low", "medium", "high", "critical"]},
        {"name": "templates", "type": "text", "label": "templates (-t, ex cves/ ou http/…)", "flag": "-t"},
        {"name": "tags", "type": "text", "label": "tags (-tags, ex cve,rce)", "flag": "-tags"},
        FlagAllowlistMixin.extra_args_param(),
    ]
    # ALLOWLIST des drapeaux acceptés en argument libre (extra_args) — tout flag hors liste est REFUSÉ.
    FLAG_ALLOWLIST = ("-severity", "-t", "-tags", "-etags", "-itags", "-rl", "-c", "-timeout",
                      "-retries", "-silent", "-jsonl", "-no-color", "-nc")

    def _severity(self, action):
        """Niveaux de sévérité (param UI/console `severity`), filtrés contre la liste blanche nuclei.
        Accepte une chaîne CSV ou une liste. Valeur absente/invalide -> défaut info,low,medium,high,critical
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
        try:                                              # débit -> -rl <n> (opt-in ; absent = rien)
            rl = int(p.get("rate"))
            if rl > 0:
                argv += ["-rl", str(rl)]
        except (TypeError, ValueError):
            pass
        _, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)  # tokens VALIDÉS (fire gate en amont)
        argv += extra
        argv += ["-jsonl", "-silent", "-no-color"]
        return argv

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action), prefer_docker=True)

    def fire(self, action):
        p = action.params or {}
        if str(action.target).startswith("-"):
            return self._refuse(action, "cible positionnelle ambiguë (commence par '-')")
        if (refused := self.gate_extra_args(action)):     # extra_args gouvernés (mixin, fail-closed)
            return refused
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
                target=action.target, title="nuclei: aucun hit", severity="INFO",
                category="nuclei", status="tested", tool="nuclei", poc=self.dry(action)))
        return findings
