# SPDX-License-Identifier: AGPL-3.0-or-later
"""Commandes catalogue/ingest de la CLI Forge : `techniques`, `workflows`, `detections`, `import`.
Extrait de l'ancien `forge/cli.py` (pur déplacement, comportement inchangé)."""
import json
import os
import sys
from pathlib import Path

from ..roe import Scope
from .. import console_client
from .. import collectors
from .. import techniques
from .. import workflows
from .engine import _workflows_path


def _load_technique_selection(args):
    """Résout la SÉLECTION de techniques par-scope (profil + toggles) pour `forge techniques` :
    `--selection` (env:NOM | @fichier | JSON littéral), sinon env `FORGE_TECHNIQUE_SELECTION`, sinon
    vide (défaut profil bug_bounty). Tolère `techniques`/`techniques_enabled` et `categories`/
    `categories_enabled` (alias). Ne lève jamais (JSON illisible -> sélection vide)."""
    raw = getattr(args, "selection", None)
    text = None
    if raw:
        if raw.startswith("env:"):
            text = os.environ.get(raw[4:], "")
        elif raw.startswith("@"):
            try:
                text = Path(raw[1:]).read_text(encoding="utf-8")
            except OSError:
                text = None
        else:
            text = raw
    if text is None:
        text = os.environ.get("FORGE_TECHNIQUE_SELECTION", "")
    sel = {}
    if text:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                sel = data
        except ValueError:
            sel = {}
    return {
        "profile": sel.get("profile"),
        "techniques": sel.get("techniques", sel.get("techniques_enabled")),
        "categories": sel.get("categories", sel.get("categories_enabled")),
    }


def cmd_techniques(args):
    """Catalogue des TECHNIQUES GROUPÉ par catégorie (vuln_class), DÉRIVÉ de la table unique — c'est la
    vue « catalogue + sélection » consommée par `GET /api/techniques` et l'opérateur. Reflète l'état
    ACTIVÉ (`enabled_for_current_scope`) pour une SÉLECTION par-scope (profil + toggles ; défaut profil
    bug_bounty) résolue par `techniques.resolve_enabled_kinds` (SOURCE UNIQUE partagée avec l'enforcement).
    Sortie JSON : {profile, profiles, selection, enabled:[...], groups:{catégorie:[{kind,tools,...}]}}."""
    sel = _load_technique_selection(args)
    profile = sel.get("profile") or "bug_bounty"
    enabled = techniques.resolve_enabled_kinds(
        profile=profile, techniques_enabled=sel.get("techniques"),
        categories_enabled=sel.get("categories"))
    groups = {}
    for cat, kinds_ in techniques.by_vuln_class().items():
        rows = []
        for k in sorted(kinds_):
            t = techniques.technique_for(k)
            rows.append({
                "kind": k, "vuln_class": cat, "tools": list(t.tools),
                "bug_bounty_eligible": bool(t.bug_bounty_eligible),
                "pentest_only": bool(t.pentest_only),
                "mitre": t.mitre or "", "cwe": t.cwe or "",
                "phase": t.phase or "", "stage": t.stage or "",
                "enabled_for_current_scope": k in enabled,
            })
        groups[cat] = rows
    out = {"profile": profile, "profiles": list(techniques.PROFILE_NAMES),
           "selection": sel, "enabled": sorted(enabled),
           "groups": {c: groups[c] for c in sorted(groups)}}
    print(json.dumps(out))
    return 0


def cmd_workflows(args):
    """Workflows sauvegardés (pipelines composés) — DÉRIVÉS du registre pour les INTÉGRÉS + fichier
    UTILISATEUR optionnel. C'est LA vue consommée par `GET /api/workflows` (la console) et l'opérateur
    CLI. Chaque workflow porte {name, description, builtin, steps:[{kind, params}], step_kinds}.
    Sortie JSON : {builtins:[...], workflows:[...]} (builtins = intégrés dérivés ; workflows = utilisateur).
    Avec `--resolve @scope.json`, ajoute par workflow `kept`/`dropped` (l'aperçu fail-closed : quelles
    étapes seraient activées/larguées pour ce scope)."""
    store = workflows.WorkflowStore.load(_workflows_path(args))
    enabled = None
    if getattr(args, "resolve", None):
        try:
            enabled = Scope.load(args.resolve.lstrip("@")).effective_technique_kinds()
        except Exception:                              # noqa: BLE001 — scope illisible -> pas d'aperçu
            enabled = None

    def _row(wf):
        row = {"name": wf["name"], "description": wf.get("description", ""),
               "builtin": bool(wf.get("builtin")), "steps": wf.get("steps", []),
               "step_kinds": workflows.step_kinds(wf), "step_count": len(wf.get("steps", []))}
        if enabled is not None:
            kept, dropped = workflows.resolve(wf, enabled)
            row["kept"] = [s["kind"] for s in kept]
            row["dropped"] = [s["kind"] for s in dropped]
        return row

    builtins = workflows.builtin_workflows()
    out = {
        "builtins": [_row(builtins[n]) for n in sorted(builtins)],
        "workflows": [_row(store.user[n]) for n in sorted(store.user)],
    }
    print(json.dumps(out))
    return 0


def cmd_detections(args):
    """Collecteur de détections (délégué par la console pour les sources « messy »). Lit la SOURCE
    (`--source env:NOM` | `@fichier` | JSON littéral), INSTANCIE le collecteur du bon `kind`, et
    imprime `{"detections":[{mitre,count,first_ts}]}` sur stdout.

    CONTRAT fail-open lisible (ce que la console spawne et interprète) :
    - source JOIGNABLE (même 0 détection) -> stdout `{"detections":[...]}`, code 0 (reachable=True) ;
    - source INJOIGNABLE / mal configurée / kind inconnu -> code non nul + message RÉDIGÉ du secret
      sur stderr, stdout VIDE -> la console bascule en `source_reachable:false` sans rien fabriquer.
    Le secret d'auth n'est JAMAIS imprimé. `fetch()` du collecteur ne lève jamais ; c'est `reachable`
    qui distingue « joignable mais vide » de « injoignable »."""
    source = None
    try:
        source = collectors.load_source(args.source)
    except Exception as e:  # noqa: BLE001 — spec illisible : fail-open, message rédigé
        sys.stderr.write(collectors.safe_error(e, source) + "\n")
        return 1
    col = collectors.get_collector(source)
    if col is None:
        sys.stderr.write("kind de source non pris en charge par le collecteur Python: "
                         + str(source.get("kind", "none")) + "\n")
        return 1
    rows = col.fetch(args.since)              # ne lève jamais : [] sur erreur, positionne reachable
    if not col.reachable:
        sys.stderr.write(col.error_detail() + "\n")   # rédigé du secret
        return 1
    print(json.dumps({"detections": rows}, ensure_ascii=False, separators=(",", ":")))
    return 0


def _parse_map(spec):
    """Parse un mapping de colonnes générique 'target=host,title=name,severity=risk' -> dict.
    None/'' -> None (aucun remappage). Ignore les entrées mal formées (fail-safe, jamais de crash)."""
    if not spec:
        return None
    out = {}
    for pair in str(spec).split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            k, v = k.strip(), v.strip()
            if k and v:
                out[k] = v
    return out or None


def cmd_import(args):
    """`forge import` — ingère une SORTIE DE SCANNER EXISTANTE (nmap/nuclei/burp/httpx/ffuf/hosts/
    generic-json/generic-csv) en findings Forge ORIENTÉS PREUVE (jamais `vulnerable` : scanner ->
    `reported_by_tool`, recon -> `tested`). Auto-détecte le format (`--format auto`/défaut). Les secrets
    du fichier sont RÉDIGÉS avant tout finding. Avec `--scope`, applique le SCOPE-GUARD (`roe.Scope`) :
    les findings HORS périmètre sont JETÉS (défaut) ou MARQUÉS (`--flag-out-of-scope`, status=skipped).

    Sortie : `--json` -> enveloppe {format, counts, findings} ; sinon résumé lisible. `--console URL`
    (+ `--console-token`) ingère aussi les findings dans la console (POST /api/ingest). PUR DATA — zéro
    exécution, zéro I/O réseau de scan (le fichier est déjà produit). Codes : 0 OK, 2 erreur."""
    from .. import importers
    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"forge import : fichier introuvable: {args.file}")
    try:
        fmt, findings = importers.parse_file(path, fmt=(args.format or "auto"),
                                             mapping=_parse_map(getattr(args, "map", None)))
    except ValueError as e:
        raise SystemExit(f"forge import : {e}")
    counts = {"parsed": len(findings), "in_scope": None, "out_of_scope": None, "emitted": len(findings)}
    if args.scope:
        scope = Scope.load(args.scope)
        findings, counts = importers.scope_filter(
            findings, scope, flag_out_of_scope=getattr(args, "flag_out_of_scope", False))
    envelope = {"format": fmt, "counts": counts, "findings": [f.to_dict() for f in findings]}
    if args.console:
        try:
            st, _resp = console_client.ingest(args.campaign, findings, [],
                                              url=args.console, token=args.console_token)
            envelope["console"] = {"status": st}
        except Exception as e:  # noqa: BLE001 — l'ingest console ne doit pas faire échouer le parse
            envelope["console"] = {"error": repr(e)}
    if getattr(args, "json", False):
        print(json.dumps(envelope))
        return 0
    print(f"# forge import — format={fmt} fichier={args.file}")
    print(f"parsed={counts['parsed']} in_scope={counts['in_scope']} "
          f"out_of_scope={counts['out_of_scope']} emitted={counts['emitted']}")
    for f in findings[:500]:
        print(f"  [{f.severity:8}] {f.status:16} {f.tool:16} {f.target}  {f.title}")
    if "console" in envelope:
        print(f"Console <- ingest: {envelope['console']}")
    return 0
