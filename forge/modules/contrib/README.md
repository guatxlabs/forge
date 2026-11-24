# Forge — DROP-IN plugins (extremely modular)

[English](README.md) | [Français](README.fr.md)

Three ways to add a module, **all governed identically** (fail-closed scope-guard,
exploit floor, status clamped to `tested`/`reported_by_tool`) — they converge on the same
`registry.REGISTRY` + `register_spec` + the `Engine.execute → roe.decide` dispatch.

## 1. Drop a `.py` in-tree (auto-discovered)

Create `forge/modules/mon_module.py` with a `@register("ma.technique")` class (`dry`/`fire` contract,
see `registry.py`) **or** a `ToolSpec` + `register_spec(...)`. **No** editing of `__init__.py`:
the package scans itself on first import (`pkgutil.iter_modules`), excluding the infra
(`registry`, `toolspec`, `oracle`, `_scopeguard`, `loader`, `contrib`).

## 2. Add a CLI tool WITHOUT touching the repository — two paths

### a) An external `.py` file (FORGE_PLUGINS)

```bash
export FORGE_PLUGINS=/opt/forge-plugins:/chemin/mon_plugin.py   # folders (scan *.py) or files, `:`-separated
python -m forge.cli modules --json        # the plugin's kind shows up
```
See `example_plugin.py`. Loaded **after** the in-tree modules → can override a kind. **Fail-soft**: a
broken plugin is logged (warning naming the file + the cause) and ignored, the engine starts.

### b) A declarative JSON/YAML spec — **zero Python** (FORGE_TOOLSPECS / --toolspec)

```bash
export FORGE_TOOLSPECS=/opt/forge-toolspecs        # folder scanned for *.json / *.yaml / *.yml
# or, one-off and fail-CLOSED (hard error if the spec is invalid):
python -m forge.cli run --scope scope.json --toolspec forge/modules/contrib/example.toolspec.json ...
```
See `example.toolspec.json`. The fields are validated **fail-closed** against the `ToolSpec`
constructor (unknown field / missing required field → error naming the file). YAML is only read if `pyyaml`
is installed (**optional** dependency; otherwise JSON only, no hard dependency added).

Required fields of a ToolSpec: `kind`, `vuln_class`, `binary`, `argv_template`. The rest has defaults
(see `toolspec.py`). `argv_template`: list of tokens; a token can be a group (nested list =
all-or-nothing). Placeholders: `{target}` `{target_host}` `{target_url}` `{param:NOM}` `{param:NOM:DEFAUT}`.

## Governance — invariant

A plugin/spec loaded through **any** of these paths can NOT fire out of scope
(fail-closed scope-guard → `skipped`, zero I/O), nor self-promote to `vulnerable` (clamped), nor
cross the exploit floor without opt-in. Nothing to wire: everything goes through the same registry + the ROE.
