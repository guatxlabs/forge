#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""E2E de la BOUCLE PURPLE — le contrat entre le moteur Forge et la colonne bleue, exécuté en vrai.

Ce script ferme la boucle COMPLÈTE, sans mock des morceaux intermédiaires :

    moteur Python (gate ROE -> fire -> run-record ATT&CK)
        -> POST /api/ingest            (console Rust, binaire réel)
        -> GET  /api/coverage/detections?since=N   (SOC : `tools/mock_plume.py`, fixture DEMO)
        -> GET  /api/purple/coverage   (jointure MITRE + detection_rate + MTTD calculés par la console)

et ÉCHOUE si l'un des maillons du contrat dérive : nom de champ du run-record, forme de la réponse
du SOC, sémantique de la fenêtre `since`, calcul de la couverture ou du taux.

POURQUOI C'EST AUTORISÉ EN CI (contrainte Forge : AUCUN I/O RÉSEAU OFFENSIF)
---------------------------------------------------------------------------
Rien ne sort de la machine — vérifiable ligne à ligne, pas sur parole :
  * `tools/mock_plume.py` est du LOOPBACK PUR : stdlib seule (http.server), `--host 127.0.0.1` par
    défaut et FORCÉ ici en argv ; il ne fait AUCUNE requête sortante (il ne fait que RÉPONDRE) et
    lit son seed dans un fichier local. Aucune socket cliente n'y existe.
  * la console est lancée sur `FORGE_CONSOLE_ADDR=127.0.0.1:<port>` et sa source de détection
    (`PLUME_URL`) pointe le loopback : son seul fetch sortant va sur 127.0.0.1.
  * le TIR est `demo.fingerprint` — le module de démonstration dont `fire()` produit un finding
    SYNTHÉTIQUE, zéro I/O réseau (cf. `forge/modules/demo.py`). Aucun outil offensif n'est invoqué.
  * les cibles sont des IP littérales de la boucle locale (127.0.0.x) : le ROE les épingle SANS
    aucune résolution DNS (`Scope.resolve_target_ips` renvoie une IP littérale sans I/O) — la CI
    n'émet donc même pas une requête DNS.
Le scope `allow_private:true` de ce test est ce qui rend les cibles loopback tirables ; il vit dans
un fichier temporaire jetable, jamais dans le dépôt.

CE QUI EST VÉRIFIÉ (chaque attente est DÉRIVÉE, jamais copiée d'un run)
----------------------------------------------------------------------
Le scénario tire 5 actions portant 4 techniques distinctes, et le seed du SOC est ÉCRIT APRÈS le tir,
à partir des horodatages RÉELS des run-records — donc les valeurs attendues (MTTD compris) sont
calculées, pas devinées :
  T1595  tirée 2 fois (2 cibles)  + détectée par le SOC  -> detected, MTTD = 60 s
  T1046  tirée 1 fois             + détectée par le SOC  -> detected, MTTD = 30 s
  T1110  tirée 1 fois, détection présente dans le seed mais DATÉE AVANT la fenêtre `since`
                                                          -> missed (prouve le filtrage `since`)
  T1566  tirée 1 fois, absente du SOC                     -> missed
=> techniques_fired=4, detected=2, missed=2, detection_rate=0.5, mttd_avg=45.0, mttd_max=60.

Sortie : une ligne par contrôle, `E2E PURPLE OK` + code 0 si tout tient, sinon la première violation
et code 1.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))          # paquet `forge`
sys.path.insert(0, str(REPO / "tools"))  # `mock_plume` (tools/ n'est pas un paquet)

# --- scénario (SOURCE DE VÉRITÉ des attentes) ------------------------------------------------
# (cible, technique tirée, rôle attendu). Les cibles sont des IP littérales loopback : aucune
# résolution DNS n'est émise par le ROE.
FIRES = [
    ("127.0.0.1", "T1595"),
    ("127.0.0.2", "T1595"),   # 2e tir de la MÊME technique -> `fires`=2 côté couverture
    ("127.0.0.3", "T1046"),
    ("127.0.0.4", "T1110"),   # détection présente mais HORS fenêtre `since` -> attendue missed
    ("127.0.0.5", "T1566"),   # aucune détection -> attendue missed
]
DETECTED = {"T1595": 60, "T1046": 30}   # technique -> MTTD (s) injecté dans le seed du SOC
MISSED_OUT_OF_WINDOW = "T1110"          # détectée AVANT le 1er tir : le `since` doit l'exclure
MISSED_ABSENT = "T1566"
ALERT_COUNTS = {"T1595": 3, "T1046": 5, MISSED_OUT_OF_WINDOW: 7}


class Fail(Exception):
    """Violation du contrat — message unique, remonté tel quel en sortie."""


_checks = 0


def ok(label, detail=""):
    global _checks
    _checks += 1
    print(f"  [OK]   {label}{(' — ' + detail) if detail else ''}")


def expect(cond, label, detail=""):
    if not cond:
        raise Fail(f"{label}{(' — ' + detail) if detail else ''}")
    ok(label, detail)


def expect_eq(got, want, label):
    expect(got == want, label, f"attendu {want!r}, obtenu {got!r}")


def free_port():
    """Port libre sur la boucle locale (bind éphémère puis relâché)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url, timeout=30.0, label=""):
    """Attend qu'une URL loopback réponde (n'importe quel code HTTP). Lève Fail au bout du délai."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception as e:  # noqa: BLE001 — pas encore écouté
            last = repr(e)
            time.sleep(0.2)
    raise Fail(f"{label or url} n'a pas répondu en {timeout:g}s (dernier: {last})")


def get_json(url, token=None, timeout=15):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


# --- 1) LE TIR : moteur réel, gate ROE réelle, run-records réels -------------------------------

def fire_engine(workdir):
    """Arme le moteur sur un scope jetable et TIRE `demo.fingerprint` (zéro I/O réseau) une fois par
    entrée de FIRES, en imposant la technique ATT&CK via `action.params['mitre']` (la voie que la
    console/le scope utilisent — cf. la priorité du mitre dans `Engine.execute`).
    Retourne (engine, run_records)."""
    from forge.roe import Scope, Action
    from forge.engine import Engine

    scope_path = workdir / "scope.json"
    scope_path.write_text(json.dumps({
        "mode": "grey",
        "in_scope": [t for t, _ in FIRES],
        "out_scope": [],
        "allow_exploit": False,
        "allow_destructive": False,
        # cibles loopback : sans ce drapeau le ROE VÉTO toute IP privée (fail-closed) et rien ne tire.
        "allow_private": True,
        "notes": "E2E purple loop — cibles loopback, module de démonstration sans I/O réseau.",
    }), encoding="utf-8")

    engine = Engine(Scope.load(scope_path), mode="propose",
                    campaign="e2e-purple", run_id="e2e-purple-run")
    engine.arm("purple_loop_e2e: tir synthétique loopback (aucun I/O réseau)")
    actions = [Action(kind="demo.fingerprint", target=target, desc=f"E2E purple {mitre}",
                      params={"mitre": mitre}) for target, mitre in FIRES]
    for a in actions:
        engine.approve(a.id, "purple_loop_e2e")
    engine.run(actions)

    rr = engine.run_records
    expect_eq(len(rr), len(FIRES), "le tir produit UN run-record par action tirée")
    for rec, (target, mitre) in zip(rr, FIRES):
        for field in ("ts", "target", "kind", "mitre", "fired", "source"):
            expect(field in rec, "le run-record porte le champ de contrat "
                                 f"`{field}` (consommé par POST /api/ingest)")
        expect_eq(rec["mitre"], mitre, f"run-record {target}: technique ATT&CK")
        expect_eq(rec["fired"], True, f"run-record {target}: fired=true (la technique a été TIRÉE)")
    return engine, rr


# --- 2) LE SOC : seed DÉRIVÉ des tirs réels, servi par mock_plume (loopback) --------------------

def build_seed(run_records, path):
    """Écrit le seed JSONL du SOC à partir des horodatages RÉELS des run-records.

    - technique détectée : `first_ts` = (tir le PLUS RÉCENT de cette technique) + MTTD voulu
      -> la console doit retrouver EXACTEMENT ce MTTD (elle joint sur le dernier tir) ;
    - `MISSED_OUT_OF_WINDOW` : `first_ts` = (tir le plus ANCIEN) - 3600 -> mock_plume doit l'exclure
      de la fenêtre `since` que la console dérive du plus ancien tir, donc la technique reste MISSED.
    Retourne (dict {technique: first_ts} effectivement écrit, horodatage du tir le plus ancien)."""
    ts_by_mitre = {}
    for rec in run_records:
        epoch = iso_to_epoch(rec["ts"])
        ts_by_mitre.setdefault(rec["mitre"], []).append(epoch)
    oldest_fire = min(t for v in ts_by_mitre.values() for t in v)

    seed = {}
    for mitre, mttd in DETECTED.items():
        seed[mitre] = max(ts_by_mitre[mitre]) + mttd
    seed[MISSED_OUT_OF_WINDOW] = oldest_fire - 3600
    lines = [json.dumps({"mitre": m, "count": ALERT_COUNTS[m], "first_ts": ts,
                         "rule": "e2e-fixture", "source": "mock_plume (DEMO FIXTURE)"})
             for m, ts in seed.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return seed, oldest_fire


def iso_to_epoch(ts):
    """ISO-8601 UTC (ce que `forge.purple.run_record` émet) -> epoch secondes."""
    from datetime import datetime
    return int(datetime.fromisoformat(ts).timestamp())


# --- 3) orchestration ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--console-bin", required=True,
                    help="binaire de la console Forge (cargo build [--release] -> target/*/forge)")
    ap.add_argument("--keep", action="store_true", help="conserve le répertoire de travail (debug)")
    args = ap.parse_args(argv)

    console_bin = Path(args.console_bin).resolve()
    if not console_bin.is_file() or not os.access(console_bin, os.X_OK):
        print(f"E2E PURPLE ÉCHEC — binaire console introuvable/non exécutable: {console_bin}",
              file=sys.stderr)
        return 2

    workdir = Path(tempfile.mkdtemp(prefix="forge-purple-e2e-"))
    procs = []
    try:
        run_e2e(console_bin, workdir, procs)
    except Fail as e:
        print(f"\nE2E PURPLE ÉCHEC — contrat violé : {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 — un plantage est un échec, pas un succès silencieux
        print(f"\nE2E PURPLE ÉCHEC — exception : {e!r}", file=sys.stderr)
        return 1
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        if args.keep:
            print(f"[e2e] répertoire conservé: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
    print(f"\nE2E PURPLE OK — {_checks} contrôles de contrat, boucle fermée "
          f"(tir -> ingest -> détections -> couverture).")
    return 0


def run_e2e(console_bin, workdir, procs):
    from forge import console_client

    # (1) TIR — moteur réel, aucun I/O réseau (module de démonstration synthétique).
    print("[e2e] 1/4 tir du moteur (demo.fingerprint, zéro I/O réseau)")
    engine, run_records = fire_engine(workdir)

    # (2) SOC — seed dérivé des tirs, servi en LOOPBACK par la fixture mock_plume.
    print("[e2e] 2/4 démarrage du SOC de démonstration (tools/mock_plume.py, 127.0.0.1)")
    seed_path = workdir / "detections.jsonl"
    seed, oldest_fire = build_seed(run_records, seed_path)
    plume_port = free_port()
    procs.append(subprocess.Popen(
        [sys.executable, str(REPO / "tools" / "mock_plume.py"),
         "--host", "127.0.0.1", "--port", str(plume_port), "--detections", str(seed_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    plume_url = f"http://127.0.0.1:{plume_port}"
    wait_http(f"{plume_url}/health", label="mock_plume")

    # contrat SOC lu par la console : {"detections":[{mitre,count,first_ts}]} + fenêtre `since`.
    _, body = get_json(f"{plume_url}/api/coverage/detections?since=0")
    expect(isinstance(body.get("detections"), list),
           "le SOC répond {detections:[...]} (la clé que `parse_plume_detections` lit)")
    expect_eq({d["mitre"] for d in body["detections"]}, set(seed), "le SOC sert le seed complet")
    _, windowed = get_json(f"{plume_url}/api/coverage/detections?since={oldest_fire}")
    expect(MISSED_OUT_OF_WINDOW not in {d["mitre"] for d in windowed["detections"]},
           f"la fenêtre `since` exclut la détection antérieure au 1er tir ({MISSED_OUT_OF_WINDOW})")

    # (3) CONSOLE — binaire réel, source de détection = le SOC loopback.
    print("[e2e] 3/4 démarrage de la console + POST /api/ingest")
    console_port = free_port()
    token = "e2e-purple-token"
    env = dict(os.environ)
    env.update({
        "FORGE_CONSOLE_ADDR": f"127.0.0.1:{console_port}",
        "FORGE_CONSOLE_DB": str(workdir / "forge.db"),
        "FORGE_CONSOLE_LEDGER": str(workdir / "engagement.jsonl"),
        "FORGE_CONSOLE_TOKEN": token,
        "PLUME_URL": plume_url,          # source de détection legacy -> kind=plume, endpoint loopback
        # La console refuse par défaut tout fetch d'INTÉGRATION vers une IP interne (garde anti-SSRF,
        # console/src/net.rs::integration_ip_denied) — donc aussi vers le SOC loopback de ce test.
        # L'escape-hatch documenté est le SEUL moyen d'exercer la boucle sans sortir de la machine ; il
        # est posé sur CE processus console jetable uniquement, jamais dans une config livrée.
        "FORGE_ALLOW_INTERNAL_INTEGRATIONS": "1",
    })
    env.pop("FORGE_DETECTION_SOURCE", None)
    env.pop("PLUME_TOKEN", None)
    procs.append(subprocess.Popen([str(console_bin)], cwd=str(workdir), env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    console_url = f"http://127.0.0.1:{console_port}"
    wait_http(f"{console_url}/health", label="console")

    # INGEST — la voie réelle du moteur (forge.console_client), pas un curl bricolé.
    status, resp = console_client.ingest("e2e-purple", engine.findings, run_records,
                                         url=console_url, token=token,
                                         run_id="e2e-purple-run", coverage=engine.coverage())
    expect_eq(status, 200, "POST /api/ingest accepte le lot du moteur")
    expect_eq(resp.get("runrecords_ingested"), len(run_records),
              "l'ingest persiste TOUS les run-records tirés")

    # (4) COUVERTURE — la console joint red x blue et publie le verdict purple.
    print("[e2e] 4/4 GET /api/purple/coverage (jointure MITRE + MTTD)")
    status, cov = get_json(f"{console_url}/api/purple/coverage", token=token)
    expect_eq(status, 200, "GET /api/purple/coverage répond 200")
    # FAIL-OPEN LISIBLE : quand la source n'a pas pu être lue, la console renvoie `error` — on le
    # remonte tel quel, sinon l'échec du E2E n'apprend rien sur la CAUSE.
    expect(cov.get("source_reachable") is True,
           "la source de détection est JOIGNABLE (sinon la mesure n'a pas eu lieu)",
           f"source_reachable={cov.get('source_reachable')!r} error={cov.get('error')!r}")
    expect_eq(cov.get("source_kind"), "plume", "kind de source résolu depuis PLUME_URL")

    detected = {d["mitre"]: d for d in cov.get("detected", [])}
    missed = {m["mitre"]: m for m in cov.get("missed", [])}
    expect_eq(set(detected), set(DETECTED), "`detected` = exactement les techniques vues par le SOC")
    expect_eq(set(missed), {MISSED_OUT_OF_WINDOW, MISSED_ABSENT},
              "`missed` = exactement les TROUS de détection (dont celui hors fenêtre)")

    n_fired = len({m for _, m in FIRES})
    expect_eq(cov.get("techniques_fired"), n_fired, "techniques_fired = techniques DISTINCTES tirées")
    expect_eq(cov.get("techniques_detected"), len(DETECTED), "techniques_detected")
    expect_eq(cov.get("techniques_missed"), 2, "techniques_missed")
    # taux ATTENDU dérivé du scénario — et NON du nombre de TIRS (5) : la dérive « rate par tir »
    # donnerait 3/5=0.6 au lieu de 2/4=0.5, et doit rougir ici.
    expect_eq(cov.get("detection_rate"), len(DETECTED) / n_fired,
              "detection_rate = techniques détectées / techniques tirées")

    for mitre, mttd in DETECTED.items():
        d = detected[mitre]
        expect_eq(d.get("mttd_secs"), mttd, f"MTTD({mitre}) = first_detection_ts - dernier tir")
        expect_eq(d.get("alert_count"), ALERT_COUNTS[mitre], f"alert_count({mitre}) vient du SOC")
        expect_eq(d.get("first_detection_ts"), seed[mitre],
                  f"first_detection_ts({mitre}) = l'horodatage servi par le SOC")
    expect_eq(detected["T1595"].get("fires"), 2,
              "les 2 tirs de T1595 sont comptés (agrégation par technique)")

    mttds = sorted(DETECTED.values())
    expect_eq(cov.get("mttd_max_secs"), max(mttds), "mttd_max_secs")
    expect_eq(cov.get("mttd_avg_secs"), sum(mttds) / len(mttds), "mttd_avg_secs")


if __name__ == "__main__":
    sys.exit(main())
