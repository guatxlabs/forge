# SPDX-License-Identifier: AGPL-3.0-only
"""EXEMPLE de plugin `.py` DROP-IN (chargé via FORGE_PLUGINS — jamais auto-découvert : `contrib/` est
exclu du scan in-tree). Montre la voie Python : déclarer un `ToolSpec` et l'enregistrer via
`register_spec` — l'outil apparaît alors dans `forge modules --json`, le pipeline, les profils et le
plan du cerveau, SOUS la même gouvernance qu'un module natif (scope-guard fail-closed, plancher exploit,
statut clampé à tested/reported_by_tool).

Charger :  FORGE_PLUGINS=/chemin/vers/forge/modules/contrib/example_plugin.py python -m forge.cli modules

La voie Python permet aussi une classe `@register(...)` custom (logique de sonde propre) — voir
`forge/modules/registry.py` (contrat `dry`/`fire`). Pour un simple enrobage d'outil CLI, préférer le
ToolSpec (déclaratif, gouverné par construction), en Python ci-dessous OU en JSON/YAML (example.toolspec.json)."""
from forge.modules.toolspec import ToolSpec, register_spec

register_spec(ToolSpec(
    kind="recon.example_pyplugin",
    vuln_class="Recon",
    binary="whatweb",
    argv_template=("--no-errors", "{target_url}"),
    cwe="CWE-200",
    mitre="T1595",
    phase="recon",
    capability="passive",
    attck_tactic="Reconnaissance",
    parser="lines",
    hit_status="tested",
    hit_is_asset=False,
    description="EXEMPLE de plugin Python — enrobe whatweb via ToolSpec/register_spec (gouverne : "
                "argv fixe no-shell, scope-guard fail-closed, proof-oriented tested)."))
