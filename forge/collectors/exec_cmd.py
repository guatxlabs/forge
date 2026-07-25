"""Collecteur `exec` — INTÉGRATION DE CONFIANCE (admin uniquement).

Exécute une commande CONFIGURÉE qui imprime des événements natifs en JSON sur stdout (ex un script
maison qui interroge une API propriétaire, `crowdsec-cli decisions list -o json`, etc.), puis normalise
via `mapping`. Pensé pour les infras sans transport standard.

SÉCURITÉ (le kind `exec` n'est configurable QUE par un admin — la console verrouille qui peut poser
`detection_source`) :
- AUCUN SHELL : `subprocess.run([...], shell=False)` avec un argv FIXE lu de la config (`cmd`/`argv`,
  liste d'arguments). Les métacaractères shell ne sont donc JAMAIS interprétés.
- TIMEOUT dur (`timeout`, défaut 15 s) -> `TimeoutExpired` -> `[]` + doctor échoue (jamais de blocage).
- PAS D'INJECTION D'ENV : la commande reçoit un env MINIMAL sur liste blanche (PATH/LANG/LC_ALL/TZ/HOME
  + `env` explicites de la config). Le secret de détection (`FORGE_DETECTION_SOURCE`, `auth.secret`)
  n'est JAMAIS propagé au process enfant.
- Ne JAMAIS passer d'entrée non fiable dans l'argv : la config vient d'un admin, pas d'un utilisateur.
"""
import json
import os
import subprocess

from .base import Collector, register, records_from, aggregate

# Liste blanche d'env transmis au process enfant (jamais le secret de détection ni l'env parent complet).
_SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "HOME")


def _clean_env(source):
    """Env MINIMAL (liste blanche) + `env` explicites de la config. Exclut TOUT le reste de l'env parent
    (donc `FORGE_DETECTION_SOURCE` porteur du secret) : pas d'injection ni de fuite vers l'enfant."""
    env = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    extra = source.get("env")
    if isinstance(extra, dict):
        for k, v in extra.items():
            if isinstance(k, str) and isinstance(v, str):
                env[k] = v
    return env


@register("exec")
class ExecCollector(Collector):
    def config_error(self):
        cmd = self.source.get("cmd") or self.source.get("argv")
        if not (isinstance(cmd, list) and cmd):
            return "exec: 'cmd' (liste d'arguments argv, no-shell) requis"
        return None

    def _collect(self, since):
        cmd = self.source.get("cmd") or self.source.get("argv")
        argv = [str(a).replace("{since}", str(int(since))) for a in cmd]
        timeout = self._timeout(default=15.0)
        p = subprocess.run(                       # noqa: S603 — argv FIXE de config admin, shell=False
            argv, capture_output=True, timeout=timeout, shell=False, env=_clean_env(self.source),
        )
        if p.returncode != 0:
            raise ValueError(f"la commande exec a renvoyé le code {p.returncode}")
        parsed = json.loads(p.stdout.decode("utf-8", "replace"))
        return aggregate(records_from(parsed, self.mapping), self.mapping)
