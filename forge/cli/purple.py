# SPDX-License-Identifier: AGPL-3.0-only
"""Préflight de la boucle purple pour la CLI Forge : `doctor --purple` (console /health + source de
détection / Plume, LECTURE SEULE). Extrait de l'ancien `forge/cli.py` (pur déplacement, comportement
inchangé). `_configured_source` vit ici (source de détection visible par la CLI) et est réutilisé par
`doctor` (via le paquet)."""
import json
import os
import re
import urllib.error
import urllib.request

from .. import console_client
from .. import collectors


# Une « technique » ATT&CK : Txxxx éventuellement suivie d'un sous-technique .yyy (ex T1190, T1059.001).
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Marqueurs de la checklist purple (aligné sur le style "OK ✅"/"INDISPONIBLE ⛔" de doctor).
_PURPLE_MARK = {"ok": "OK ✅", "fail": "FAIL ❌", "na": "N/A ➖", "info": "INFO ℹ️"}


def _purple_get(url, basic_b64=None, timeout=8.0):
    """GET en LECTURE SEULE, tolérant aux pannes (ne lève JAMAIS). Retourne (status, body, err) :
      - (200, "<body>", None)              réponse OK ;
      - (<code>, "<body>", None)           réponse HTTP reçue (même 401/500) -> service JOIGNABLE ;
      - (None, "", "<repr err>")           injoignable (DNS, refus de connexion, timeout...).
    `basic_b64` (base64 de user:pass) -> en-tête `Authorization: Basic ...` (comme la console Rust)."""
    headers = {}
    if basic_b64:
        headers["Authorization"] = "Basic " + basic_b64
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:                # service joignable mais réponse d'erreur HTTP
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:                              # noqa: BLE001
            body = ""
        return e.code, body, None
    except Exception as e:                             # noqa: BLE001 — injoignable (URLError, timeout, ...)
        return None, "", repr(e)


def _parse_detections(body):
    """Extrait la liste de détections de la réponse Plume. Tolère `{"detections":[...]}` (forme
    nominale, cf. console Rust) et un tableau nu `[...]`. Retourne None si le JSON est illisible."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if isinstance(data, dict):
        arr = data.get("detections", [])
        return list(arr) if isinstance(arr, list) else None
    if isinstance(data, list):
        return data
    return None


def _count_mitre_tagged(detections):
    """Nombre de détections portant un champ technique de forme Txxxx (`mitre` ou `technique`)."""
    n = 0
    for d in detections:
        if not isinstance(d, dict):
            continue
        val = d.get("mitre") or d.get("technique") or ""
        if isinstance(val, str) and _TECHNIQUE_RE.search(val):
            n += 1
    return n


def _configured_source():
    """Résout la source de détection VISIBLE par la CLI (diagnostic) : env `FORGE_DETECTION_SOURCE`
    (JSON posé par la console), sinon repli rétro-compat `PLUME_URL`/`PLUME_TOKEN` -> preset `plume`,
    sinon None (non configurée -> boucle purple INERTE). Ne lève jamais."""
    raw = os.environ.get("FORGE_DETECTION_SOURCE", "").strip()
    if raw:
        try:
            return collectors.load_source("env:FORGE_DETECTION_SOURCE")
        except Exception:  # noqa: BLE001 — JSON illisible -> traité comme non configuré
            return None
    url = os.environ.get("PLUME_URL", "").strip()
    if url:
        return {"kind": "plume", "endpoint": url.rstrip("/"),
                "auth": {"type": "basic", "secret": os.environ.get("PLUME_TOKEN", "")}}
    return None


def _doctor_source_preflight(args, source):
    """Préflight GÉNÉRALISÉ à la source de détection CONFIGURÉE (kind ≠ plume/legacy). LECTURE SEULE :
    GET console `/health` + `collector.doctor()` (sonde de joignabilité) + une collecte de sonde pour
    compter détections/tags MITRE. Dégrade gracieusement (FAIL/N/A, jamais de crash). Critiques =
    console joignable + source joignable/configurée. Le secret n'apparaît jamais (détails rédigés)."""
    console_url = console_client.base_url()
    timeout = getattr(args, "timeout", None) or 8.0
    lines = []
    critical_ok = True

    st, body, err = _purple_get(console_url + "/health", timeout=timeout)
    if st == 200:
        lines.append(("ok", "console-reachable", f"{console_url}/health -> 200 {body.strip()[:16]}"))
    elif st is not None:
        lines.append(("fail", "console-reachable", f"{console_url}/health -> HTTP {st}")); critical_ok = False
    else:
        lines.append(("fail", "console-reachable", f"{console_url}/health injoignable ({err})")); critical_ok = False

    col = collectors.get_collector(source)
    if col is None:
        lines.append(("fail", "source-configured", f"kind inconnu: {source.get('kind')}")); critical_ok = False
        for lbl in ("source-reachable", "detections-returned", "mitre-tagged"):
            lines.append(("na", lbl, "kind inconnu"))
    else:
        cfg_err = col.config_error()
        if cfg_err:
            lines.append(("fail", "source-configured", collectors.safe_error(ValueError(cfg_err), source)))
            critical_ok = False
        else:
            lines.append(("ok", "source-configured", collectors.describe(source)))
        rows = col.fetch(0)                    # sonde LECTURE SEULE (ne lève jamais)
        if col.reachable:
            lines.append(("ok", "source-reachable", col.doctor().get("detail", "")))
            n = len(rows)
            lines.append(("ok" if n else "info", "detections-returned", f"{n} technique(s)"))
            if n == 0:
                lines.append(("na", "mitre-tagged", "aucune détection à inspecter"))
            else:
                tagged = _count_mitre_tagged(rows)
                state = "ok" if tagged else "info"
                lines.append((state, "mitre-tagged", f"champ technique Txxxx présent ({tagged}/{n})"))
        else:
            lines.append(("fail", "source-reachable", col.error_detail())); critical_ok = False
            for lbl in ("detections-returned", "mitre-tagged"):
                lines.append(("na", lbl, "source injoignable"))

    if getattr(args, "json", False):
        print(json.dumps({"ok": critical_ok,
                          "checks": [{"check": lbl, "state": state, "detail": detail}
                                     for state, lbl, detail in lines]}))
        return 0 if critical_ok else 1
    verdict = "PRÊTE ✅" if critical_ok else "INCOMPLÈTE ⛔"
    print(f"=== forge doctor --purple — boucle purple {verdict} (source: {source.get('kind')}) ===\n")
    for state, lbl, detail in lines:
        print(f"  [{_PURPLE_MARK.get(state, state):8}] {lbl:20} {detail}")
    print("\nNote : lecture seule — aucun tir, ni scope ni ledger touchés. Critiques = console joignable "
          "+ source configurée/joignable. Détections/MITRE sont informatifs (0 détection = SOC frais).")
    return 0 if critical_ok else 1


def cmd_doctor_purple(args):
    """Préflight de la boucle purple (LECTURE SEULE, ne tire rien, ne touche ni scope ni ledger) :
    GET console `/health` + sonde de la SOURCE DE DÉTECTION configurée. Imprime une checklist claire
    et DÉGRADE GRACIEUSEMENT si une dépendance est injoignable (ligne FAIL/N/A, jamais de crash).

    Si une source NON-legacy est configurée (env `FORGE_DETECTION_SOURCE`, kind ≠ plume/none) ->
    préflight généralisé via le collecteur. Sinon -> chemin legacy `PLUME_URL`/`PLUME_TOKEN` INCHANGÉ
    (rétro-compat : GET Plume `/api/coverage/detections?since=0`, Basic auth)."""
    src = _configured_source()
    if src is not None and str(src.get("kind", "")).strip() not in ("", "none", "plume"):
        return _doctor_source_preflight(args, src)

    console_url = console_client.base_url()            # respecte FORGE_CONSOLE_URL (défaut 127.0.0.1:7100)
    plume_url = os.environ.get("PLUME_URL", "").rstrip("/")
    plume_token = os.environ.get("PLUME_TOKEN", "")    # base64 de user:pass -> Authorization: Basic
    timeout = getattr(args, "timeout", None) or 8.0

    lines = []                                         # (state, label, detail)
    critical_ok = True

    # --- 1) console joignable (GET /health, non authentifié) ---
    st, body, err = _purple_get(console_url + "/health", timeout=timeout)
    if st == 200:
        lines.append(("ok", "console-reachable", f"{console_url}/health -> 200 {body.strip()[:16]}"))
    elif st is not None:
        lines.append(("fail", "console-reachable", f"{console_url}/health -> HTTP {st}"))
        critical_ok = False
    else:
        lines.append(("fail", "console-reachable", f"{console_url}/health injoignable ({err})"))
        critical_ok = False

    # --- 2) plume joignable + 3) auth-ok + 4) détections + 5) tag MITRE ---
    if not plume_url:
        lines.append(("fail", "plume-reachable", "PLUME_URL non configuré"))
        for lbl in ("auth-ok", "detections-returned", "mitre-tagged"):
            lines.append(("na", lbl, "PLUME_URL non configuré"))
        critical_ok = False
    else:
        purl = plume_url + "/api/coverage/detections?since=0"
        st, body, err = _purple_get(purl, basic_b64=(plume_token or None), timeout=timeout)
        if st is None:                                 # injoignable -> le reste est N/A (pas mesurable)
            lines.append(("fail", "plume-reachable", f"{purl} injoignable ({err})"))
            for lbl in ("auth-ok", "detections-returned", "mitre-tagged"):
                lines.append(("na", lbl, "Plume injoignable"))
            critical_ok = False
        else:
            lines.append(("ok", "plume-reachable", f"{purl} -> HTTP {st}"))
            if st in (401, 403):
                lines.append(("fail", "auth-ok", f"HTTP {st} — vérifier PLUME_TOKEN (base64 user:pass)"))
                for lbl in ("detections-returned", "mitre-tagged"):
                    lines.append(("na", lbl, "auth échouée"))
                critical_ok = False
            elif st != 200:
                lines.append(("fail", "auth-ok", f"HTTP {st} inattendu"))
                for lbl in ("detections-returned", "mitre-tagged"):
                    lines.append(("na", lbl, f"HTTP {st}"))
                critical_ok = False
            else:
                lines.append(("ok", "auth-ok", "HTTP 200 (Basic accepté)"))
                dets = _parse_detections(body)
                if dets is None:
                    lines.append(("fail", "detections-returned", "réponse JSON illisible"))
                    lines.append(("na", "mitre-tagged", "réponse illisible"))
                    critical_ok = False
                else:
                    n = len(dets)
                    # 0 détection = état valide (SOC frais) : informatif, pas un échec critique.
                    lines.append(("ok" if n else "info", "detections-returned", f"{n} règle(s)"))
                    if n == 0:
                        lines.append(("na", "mitre-tagged", "aucune détection à inspecter"))
                    else:
                        tagged = _count_mitre_tagged(dets)
                        if tagged:
                            lines.append(("ok", "mitre-tagged",
                                          f"champ technique Txxxx présent ({tagged}/{n})"))
                        else:
                            lines.append(("info", "mitre-tagged",
                                          "aucun champ technique Txxxx détecté"))

    if getattr(args, "json", False):
        print(json.dumps({"ok": critical_ok,
                          "checks": [{"check": lbl, "state": state, "detail": detail}
                                     for state, lbl, detail in lines]}))
        return 0 if critical_ok else 1

    verdict = "PRÊTE ✅" if critical_ok else "INCOMPLÈTE ⛔"
    print(f"=== forge doctor --purple — boucle purple {verdict} ===\n")
    for state, lbl, detail in lines:
        print(f"  [{_PURPLE_MARK.get(state, state):8}] {lbl:20} {detail}")
    print("\nNote : lecture seule — aucun tir, ni scope ni ledger touchés. Critiques = console/Plume "
          "joignables + auth. Détections/MITRE sont informatifs (0 détection = SOC frais, pas un échec).")
    return 0 if critical_ok else 1
