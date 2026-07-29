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
Le scénario tire 7 actions portant 6 techniques distinctes, et le seed du SOC est ÉCRIT APRÈS le tir,
à partir des horodatages RÉELS des run-records — donc les valeurs attendues (MTTD compris) sont
calculées, pas devinées. La jointure a TROIS états (detected-exact / detected-parent-approx / missed) :
  T1595      tirée 2 fois (2 cibles) + détectée par le SOC       -> detected-exact, MTTD = 60 s
  T1046      tirée 1 fois            + détectée par le SOC       -> detected-exact, MTTD = 30 s
  T1110      tirée 1 fois, détection présente dans le seed mais DATÉE AVANT la fenêtre `since`
                                                                 -> missed (prouve le filtrage `since`)
  T1566      tirée 1 fois, absente du SOC                        -> missed
  T1552.001  tirée 1 fois ; le SOC n'a de règle QUE sur la parente T1552, servie DANS la fenêtre
             (mttd apparent 900 s)                               -> detected-parent-approx :
             NI détectée (le taux ne bouge pas) NI un simple missed (l'angle mort est NOMMÉ), et son
             MTTD apparent de 900 s NE DOIT PAS entrer dans mttd_avg/mttd_max.
  T1592.002  tirée 1 fois ; le SOC répond avec un tag MULTI-TECHNIQUES "T1592.002 T1594" (norme
             SigmaHQ : plusieurs `attack.` par règle)            -> detected-exact des DEUX côtés
             (sans l'éclatement du tag, la jointure par égalité de chaîne fabriquerait un faux missed)
=> techniques_fired=6, detected=3, parent_approx=1, missed=2, detection_rate=3/6=0.5,
   mttd_avg=(60+30+45)/3=45.0, mttd_max=60.

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
    ("127.0.0.6", "T1552.001"),  # SOUS-technique : le SOC n'a que la parente -> parent-approx
    ("127.0.0.7", "T1592.002"),  # détectée via un tag SOC MULTI-TECHNIQUES -> detected-exact
]
# technique -> MTTD (s) injecté dans le seed du SOC. Ce sont les detected-EXACT attendus.
DETECTED = {"T1595": 60, "T1046": 30, "T1592.002": 45}
MISSED_OUT_OF_WINDOW = "T1110"          # détectée AVANT le 1er tir : le `since` doit l'exclure
MISSED_ABSENT = "T1566"

# --- TROIS ÉTATS : le cas parent/sous-technique --------------------------------------------------
# Forge tire la SOUS-technique ; le SOC n'a de règle que sur la PARENTE, et son alerte tombe DANS la
# fenêtre (donc rien ne l'exclut : seule la règle des trois états peut la classer correctement).
# Ce n'est PAS un « détecté » (une règle parente générique ne prouve pas la couverture du vecteur
# tiré) et ce n'est pas non plus un simple trou muet : c'est un angle mort NOMMÉ.
PARENT_APPROX_SUB = "T1552.001"
PARENT_APPROX_PARENT = "T1552"
# MTTD APPARENT du rapprochement parent : s'il entrait dans l'échantillon, mttd_max passerait de 60 à
# 900 et mttd_avg de 45 à 258.75. C'est CE chiffre inventé que la garde doit interdire.
PARENT_APPROX_APPARENT_MTTD = 900

# --- TAG MULTI-TECHNIQUES (norme SigmaHQ) --------------------------------------------------------
# Le SOC sert UNE ligne dont le champ `mitre` porte DEUX techniques. Sans éclatement, la jointure par
# égalité de chaîne ne matche aucune des deux -> faux « missed » fabriqué par le corpus Sigma.
MULTI_TAG_FIRED = "T1592.002"
MULTI_TAG_SERVED = "T1592.002 T1594"

ALERT_COUNTS = {"T1595": 3, "T1046": 5, MISSED_OUT_OF_WINDOW: 7,
                MULTI_TAG_SERVED: 2, PARENT_APPROX_PARENT: 4}


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

    - technique détectée EXACTEMENT : `first_ts` = (tir le PLUS RÉCENT de cette technique) + MTTD voulu
      -> la console doit retrouver EXACTEMENT ce MTTD (elle joint sur le dernier tir). Pour
      `MULTI_TAG_FIRED`, la ligne servie porte le tag MULTI-TECHNIQUES `MULTI_TAG_SERVED` : le MTTD
      n'est retrouvé QUE si la console éclate le tag ;
    - `MISSED_OUT_OF_WINDOW` : `first_ts` = (tir le plus ANCIEN) - 3600 -> mock_plume doit l'exclure
      de la fenêtre `since` que la console dérive du plus ancien tir, donc la technique reste MISSED ;
    - `PARENT_APPROX_PARENT` : servie DANS la fenêtre, à (tir de la SOUS-technique) +
      `PARENT_APPROX_APPARENT_MTTD`. Rien ne l'exclut : c'est la règle des trois états — et elle
      seule — qui doit empêcher ce rapprochement de compter comme détecté et de polluer le MTTD.
    Retourne (dict {tag servi: first_ts} effectivement écrit, horodatage du tir le plus ancien)."""
    ts_by_mitre = {}
    for rec in run_records:
        epoch = iso_to_epoch(rec["ts"])
        ts_by_mitre.setdefault(rec["mitre"], []).append(epoch)
    oldest_fire = min(t for v in ts_by_mitre.values() for t in v)

    seed = {}
    for mitre, mttd in DETECTED.items():
        # le SOC peut servir la technique sous un tag COMPOSÉ (cas Sigma) : la clé du seed est le TAG.
        tag = MULTI_TAG_SERVED if mitre == MULTI_TAG_FIRED else mitre
        seed[tag] = max(ts_by_mitre[mitre]) + mttd
    seed[MISSED_OUT_OF_WINDOW] = oldest_fire - 3600
    seed[PARENT_APPROX_PARENT] = max(ts_by_mitre[PARENT_APPROX_SUB]) + PARENT_APPROX_APPARENT_MTTD
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
    approx = {a["mitre"]: a for a in cov.get("parent_approx", [])}
    missed = {m["mitre"]: m for m in cov.get("missed", [])}
    expect_eq(set(detected), set(DETECTED),
              "`detected` = exactement les techniques vues EXACTEMENT par le SOC")
    expect_eq(set(approx), {PARENT_APPROX_SUB},
              "`parent_approx` = exactement les sous-techniques dont SEULE la parente est couverte")
    expect_eq(set(missed), {MISSED_OUT_OF_WINDOW, MISSED_ABSENT},
              "`missed` = exactement les TROUS de détection (dont celui hors fenêtre)")

    n_fired = len({m for _, m in FIRES})
    expect_eq(cov.get("techniques_fired"), n_fired, "techniques_fired = techniques DISTINCTES tirées")
    expect_eq(cov.get("techniques_detected"), len(DETECTED), "techniques_detected (EXACT seulement)")
    expect_eq(cov.get("techniques_parent_approx"), 1, "techniques_parent_approx")
    expect_eq(cov.get("techniques_missed"), 2, "techniques_missed")
    # INVARIANT des trois états : chaque technique tirée tombe dans EXACTEMENT une case.
    expect_eq(cov.get("techniques_detected") + cov.get("techniques_parent_approx")
              + cov.get("techniques_missed"), n_fired,
              "detected + parent_approx + missed == techniques_fired")
    # taux ATTENDU dérivé du scénario — et NON du nombre de TIRS (7) : la dérive « rate par tir »
    # donnerait 4/7 au lieu de 3/6=0.5, et doit rougir ici.
    expect_eq(cov.get("detection_rate"), len(DETECTED) / n_fired,
              "detection_rate = techniques détectées EXACTEMENT / techniques tirées")
    # LA GARDE DU TAUX : compter le parent-approx comme détecté donnerait 4/6 = 0.666… . On assert le
    # NON-effet explicitement, sinon la garde ne mord que par ricochet.
    expect(cov.get("detection_rate") != (len(DETECTED) + 1) / n_fired,
           "le parent-approx N'ENTRE PAS dans detection_rate",
           f"un taux de {(len(DETECTED) + 1) / n_fired} signifierait qu'il a été compté comme détecté")

    for mitre, mttd in DETECTED.items():
        d = detected[mitre]
        # le SOC a pu servir cette technique sous un tag COMPOSÉ : la clé du seed est le TAG servi.
        tag = MULTI_TAG_SERVED if mitre == MULTI_TAG_FIRED else mitre
        expect_eq(d.get("mttd_secs"), mttd, f"MTTD({mitre}) = first_detection_ts - dernier tir")
        expect_eq(d.get("alert_count"), ALERT_COUNTS[tag], f"alert_count({mitre}) vient du SOC")
        expect_eq(d.get("first_detection_ts"), seed[tag],
                  f"first_detection_ts({mitre}) = l'horodatage servi par le SOC")
        expect_eq(d.get("state"), "detected-exact", f"état NOMMÉ de {mitre}")
    expect_eq(detected["T1595"].get("fires"), 2,
              "les 2 tirs de T1595 sont comptés (agrégation par technique)")

    # --- TAG MULTI-TECHNIQUES : la garde de l'éclatement ------------------------------------------
    # Le SOC n'a JAMAIS servi la clé nue `T1592.002` : il a servi `"T1592.002 T1594"`. Sans éclatement
    # côté console, la jointure par égalité de chaîne ne matche rien et fabrique un faux « missed ».
    expect(MULTI_TAG_FIRED not in {d["mitre"] for d in body["detections"]},
           "le SOC n'a JAMAIS servi la clé nue — seulement le tag composé",
           f"détections servies : {sorted(d['mitre'] for d in body['detections'])}")
    expect(MULTI_TAG_FIRED in detected,
           "un tag SOC MULTI-TECHNIQUES est ÉCLATÉ : la sous-technique tirée est bien détectée",
           f"le SOC a servi le tag composé {MULTI_TAG_SERVED!r} ; sans éclatement -> faux missed")
    expect(MULTI_TAG_SERVED not in detected and MULTI_TAG_SERVED not in missed,
           "le tag composé n'apparaît JAMAIS tel quel comme une pseudo-technique")
    expect("T1594" not in detected and "T1594" not in missed,
           "l'éclatement n'INVENTE pas de technique tirée : T1594 (jamais tirée) reste absente")

    # --- PARENT-APPROX : la garde du troisième état -----------------------------------------------
    a = approx[PARENT_APPROX_SUB]
    expect_eq(a.get("state"), "detected-parent-approx", "état NOMMÉ du rapprochement parent")
    expect_eq(a.get("parent"), PARENT_APPROX_PARENT, "la technique PARENTE est nommée (exploitable)")
    expect_eq(a.get("parent_alert_count"), ALERT_COUNTS[PARENT_APPROX_PARENT],
              "les alertes de la parente restent lisibles (information, pas déchet)")
    expect(PARENT_APPROX_SUB not in detected,
           "la sous-technique N'EST PAS comptée comme détectée (une règle parente ne le prouve pas)")
    expect(PARENT_APPROX_SUB not in missed,
           "…et n'est pas non plus un trou MUET : l'angle mort est NOMMÉ")
    expect(a.get("mttd_secs") is None,
           "aucun MTTD n'est fabriqué sur un rapprochement approximatif",
           f"mttd_secs={a.get('mttd_secs')!r}")
    expect(isinstance(a.get("why"), str) and PARENT_APPROX_PARENT in a["why"],
           "le libellé explique l'angle mort, en nommant la parente")

    # MTTD : échantillonné sur les detected-EXACT SEULEMENT. Le rapprochement parent a un MTTD
    # APPARENT de 900 s ; s'il était échantillonné, max passerait à 900 et la moyenne à 258.75.
    mttds = sorted(DETECTED.values())
    expect_eq(cov.get("mttd_max_secs"), max(mttds), "mttd_max_secs (détections exactes seulement)")
    expect_eq(cov.get("mttd_avg_secs"), sum(mttds) / len(mttds), "mttd_avg_secs (exactes seulement)")
    polluted = sorted(mttds + [PARENT_APPROX_APPARENT_MTTD])
    expect(cov.get("mttd_max_secs") != max(polluted),
           "le MTTD APPARENT du parent-approx n'a pas pollué mttd_max",
           f"un max de {max(polluted)} signifierait qu'il a été échantillonné")
    expect(cov.get("mttd_avg_secs") != sum(polluted) / len(polluted),
           "…ni mttd_avg",
           f"une moyenne de {sum(polluted) / len(polluted)} signifierait qu'il a été échantillonné")


if __name__ == "__main__":
    sys.exit(main())
