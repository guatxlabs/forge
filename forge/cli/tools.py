# SPDX-License-Identifier: AGPL-3.0-or-later
"""Commandes `forge tools {list|install|update|remove}` — cycle de vie des outils au RUNTIME.

Surface OPERATEUR de `forge/toolsinstall.py` : elle n'ajoute AUCUNE capacite, elle expose celles qui
sont deja gouvernees la-bas. En particulier, il n'y a volontairement **ni option `--url` ni option
`--sha256`** : la source et le digest viennent du manifeste (`forge/tools.json`), jamais de la ligne
de commande. Installer une version hors manifeste demanderait d'accepter un digest saisi a la main —
c'est une decision d'UX d'integrite a part entiere, non prise ici (cf. docs/TOOLS_LIFECYCLE.md).

`list` est en LECTURE SEULE : il ne cree rien, ne telecharge rien et n'EXECUTE aucun outil (lister ne
doit pas etre une execution) — la version installee est lue dans le recu depose a l'installation.
"""
import json

from .. import toolsinstall
from .. import toolsmanifest


def _fail(msg):
    print(f"REFUS ⛔ — {msg}")
    return 1


def cmd_tools_list(args):
    """Etat par outil : version cible du manifeste, resolution PATH, provenance (runtime/baseline)."""
    try:
        rows = toolsinstall.status()
    except toolsmanifest.ManifestError as e:
        return _fail(str(e))
    if getattr(args, "json", False):
        print(json.dumps(rows))
        return 0
    arch = rows[0]["arch"] if rows else toolsinstall.current_arch()
    print(f"=== forge tools — manifeste forge/tools.json, architecture {arch} ===")
    print(f"    repertoire runtime : {toolsinstall.bin_dir()}  (en tete du PATH ; vide = baseline seule)\n")
    for r in rows:
        if r["source"] == "runtime":
            mark = "RUNTIME" if r["up_to_date"] else "RUNTIME (obsolete)"
            seen = r["installed_version"] or "?"
        elif r["source"] == "baseline":
            mark, seen = "BASELINE", "—"
        else:
            mark, seen = "ABSENT", "—"
        pin = "pinne" if r["installable"] else f"NON pinne pour {arch}"
        print(f"  [{mark:18}] {r['name']:14} cible={r['version']:10} installe={seen:10} ({pin})")
        if r["resolved_path"]:
            print(f"      PATH : {r['resolved_path']}")
    print("\nNote : `install`/`update` verifient le SHA256 pin du manifeste AVANT de poser quoi que ce "
          "soit sur le PATH, et journalisent l'acte au ledger. Un outil installe ici reste soumis aux "
          "memes gates (scope-guard ROE, plancher exploit) qu'un outil de la baseline.")
    return 0


def _act(fn, args, verb):
    try:
        res = fn(args.name, ledger_path=getattr(args, "ledger", None),
                 actor=getattr(args, "actor", "") or "")
    except (toolsinstall.ToolInstallError, toolsmanifest.ManifestError) as e:
        return _fail(str(e))
    if getattr(args, "json", False):
        print(json.dumps(res))
        return 0
    action = res.get("action")
    if action == "unchanged":
        print(f"{res['name']} {res['version']} deja installe (runtime) — rien a faire "
              f"(`update` pour reposer la meme version).")
        return 0
    if action == "absent":
        print(f"{res['name']} n'etait pas installe dans la couche runtime — rien a retirer "
              f"(la baseline bakee, si presente, est intacte).")
        return 0
    if action == "removed":
        print(f"{res['name']} retire de la couche runtime ({res['path']}) — journalise au ledger. "
              f"Le PATH retombe sur la baseline si elle embarque cet outil.")
        return 0
    print(f"{verb} ✅ {res['name']} {res['version']} ({res['arch']}) -> {res['path']}")
    print(f"    SHA256 verifie : {res['sha256']}")
    print(f"    source         : {res['url']}")
    print("    journalise au ledger (tools.install/tools.update).")
    return 0


def cmd_tools_install(args):
    return _act(toolsinstall.install, args, "Installe")


def cmd_tools_update(args):
    return _act(toolsinstall.update, args, "Mis a jour")


def cmd_tools_remove(args):
    return _act(toolsinstall.remove, args, "Retire")


def add_parser(sub):
    """Branche `forge tools ...` sur le sous-parseur principal (appele par `build_parser`)."""
    tl = sub.add_parser("tools", help="cycle de vie des outils externes : etat, installation, mise a "
                                      "jour, retrait — sans rebuild, SHA256 pin + ledger")
    tls = tl.add_subparsers(dest="tcmd", required=True)

    ls = tls.add_parser("list", help="etat des outils du manifeste (lecture seule, n'execute rien)")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=cmd_tools_list)

    for name, fn, helptext in (
            ("install", cmd_tools_install, "installe un outil DU MANIFESTE (SHA256 verifie, journalise)"),
            ("update", cmd_tools_update, "reinstalle a la version du MANIFESTE (bumper le manifeste d'abord)"),
            ("remove", cmd_tools_remove, "retire l'outil de la couche runtime (la baseline reste intacte)")):
        p = tls.add_parser(name, help=helptext)
        p.add_argument("name", help="nom de l'outil, tel qu'il figure dans forge/tools.json")
        p.add_argument("--ledger", help="ledger d'engagement a journaliser (sinon env "
                                        "FORGE_CONSOLE_LEDGER). ABSENT DES DEUX -> action REFUSEE : "
                                        "aucun changement de capacite sans trace auditable")
        p.add_argument("--actor", default="", help="qui declenche l'action (estampille dans le ledger)")
        p.add_argument("--json", action="store_true")
        p.set_defaults(fn=fn)
    return tl
