"""G3 — PARALLÉLISME INTRA-VAGUE BORNÉ, LEDGER/INGEST SÉRIALISÉ DÉTERMINISTE.

L'exécuteur du moteur exécute les TIRS bloquants (module.fire/dry) dans un pool de threads BORNÉ
(`FORGE_PARALLELISM`), mais APPLIQUE toutes les mutations d'état (append ledger, decision ROE,
findings/graphe/compteurs, ingest) STRICTEMENT DANS L'ORDRE d'action, sur le thread principal.

Preuves (HERMÉTIQUES — modules stubés, cibles = IP LITTÉRALES publiques donc ZÉRO DNS/réseau) :

  1. DÉTERMINISME (le critère MAKE-OR-BREAK) : la MÊME vague jouée avec pool=1 (sériel) et pool=8
     (parallèle) produit un LEDGER IDENTIQUE (même ORDRE, même contenu par entrée, horodatages exclus),
     et des findings / run-records / décisions ROE identiques EN ORDRE ET EN CONTENU. Les tirs finissent
     VOLONTAIREMENT dans le désordre (sleeps décroissants -> l'action soumise en dernier finit en
     premier) : sans application ordonnée, le ledger se réordonnerait. La chaîne append-only reste
     reproductible (`ledger.verify()` OK des deux côtés).

  2. SPEEDUP RÉEL : N tirs indépendants qui « dorment » tournent en ~1 sleep en parallèle vs ~N en
     sériel -> le mur parallèle est nettement inférieur (preuve d'un vrai recouvrement I/O), résultats
     COMPLETS (tous les findings présents).

  3. CANCEL/TIMEOUT COMPOSE (E3/E4) : plusieurs « outils » EN VOL simultanés (sessions séparées) sont
     TOUS coupés par `runner.terminate_live_tool_groups` — pas un seul. Le registre pgid est thread-safe
     sous mutations concurrentes des workers (snapshot verrouillé, aucun `RuntimeError`).

  4. GOUVERNANCE INTACTE EN PARALLÈLE : une cible hors-scope (VETO) et un plancher exploit (VETO) gatent
     CHAQUE action même sous parallélisme ; un kind sans module devient un engine.error tracé.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                          # noqa: E402
from forge.engine import Engine                              # noqa: E402
from forge.ledger import Ledger                              # noqa: E402
from forge.memory import Memory                              # noqa: E402
from forge.schema import Finding                             # noqa: E402
from forge.modules import registry                           # noqa: E402
from forge import runner                                     # noqa: E402


# --- stub module : fire() DORT une durée fixée par cible puis rend un finding déterministe -----------
_SLEEPS = {}   # target -> secondes à dormir dans fire() (force un ordre de complétion != ordre de soumission)


class _SleepHit(registry.Module):
    exploit = False
    mitre = "T1190"

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        s = _SLEEPS.get(action.target, 0.0)
        if s:
            time.sleep(s)
        # 1 finding par cible, titre déterministe (dédup exact quand la MÊME cible est rejouée).
        return [Finding(target=action.target, title=f"hit:{action.target}",
                        severity="LOW", category="demo", mitre="T1190")]


class _swap:
    def __init__(self, mapping):
        self.mapping = mapping
        self._saved = {}

    def __enter__(self):
        for kind, cls in self.mapping.items():
            self._saved[kind] = registry.REGISTRY.get(kind)
            registry.REGISTRY[kind] = type(f"Stub_{kind.replace('.', '_')}", (cls,), {"kind": kind})
        return self

    def __exit__(self, *exc):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        return False


def _strip_ts(obj):
    """Retire récursivement toute clé volatile (horodatages) — non reproductible d'un run à l'autre,
    même en sériel. Ce qui reste est le CONTENU LOGIQUE que le déterminisme parallèle==sériel doit fixer."""
    if isinstance(obj, dict):
        return {k: _strip_ts(v) for k, v in obj.items() if k not in ("ts", "started")}
    if isinstance(obj, list):
        return [_strip_ts(v) for v in obj]
    return obj


def _ledger_shape(path):
    """Séquence ORDONNÉE des entrées du ledger réduite à (kind, detail-sans-ts). Exclut hash/prev/sig/ts
    (dérivés de l'horloge -> diffèrent même entre deux runs sériels) ; garde l'ORDRE et le CONTENU logique."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        out.append((rec["kind"], _strip_ts(rec["detail"])))
    return out


def _scope():
    # in_scope = IP LITTÉRALES PUBLIQUES -> resolve_target_ips court-circuite (aucune I/O DNS), FIRE.
    return Scope({"mode": "grey",
                  "in_scope": ["93.184.216.34", "1.1.1.1", "8.8.8.8", "9.9.9.9",
                               "208.67.222.222", "198.51.100.7"],
                  "allow_exploit": True, "allow_destructive": False})


# actions FIRE (IP publiques) avec sleeps DÉCROISSANTS : la dernière soumise finit en PREMIER.
_FIRE_IPS = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "198.51.100.7"]


def _wave_actions():
    acts = [Action("par.hit", ip) for ip in _FIRE_IPS]
    # un DOUBLON exact de la 1re cible (même (target,title)) -> exercice de la dédup mémoire ORDONNÉE.
    acts.append(Action("par.hit", _FIRE_IPS[0], desc="dup"))
    # une cible HORS-SCOPE -> VETO (gouvernance en parallèle).
    acts.append(Action("par.hit", "203.0.113.99", desc="oos"))
    # un kind SANS module -> engine.error tracé.
    acts.append(Action("par.nomodule", _FIRE_IPS[1], desc="nomod"))
    return acts


def _run_wave(pool, ledger_path):
    os.environ["FORGE_PARALLELISM"] = str(pool)
    # sleeps décroissants pour forcer une complétion DÉSORDONNÉE sous parallélisme.
    _SLEEPS.clear()
    for i, ip in enumerate(_FIRE_IPS):
        _SLEEPS[ip] = 0.02 * (len(_FIRE_IPS) - i)
    ledger = Ledger(ledger_path)
    eng = Engine(_scope(), ledger=ledger, mode="auto", memory=Memory(), campaign="camp", run_id="run-1")
    eng.arm("test parallel determinism")
    with _swap({"par.hit": _SleepHit}):
        eng.run(_wave_actions())
    return eng, ledger


class TestDeterminism(unittest.TestCase):
    """LE critère : parallèle (pool>1) == sériel (pool=1) — ORDRE + CONTENU du ledger, findings,
    run-records, décisions ROE. C'est la preuve que la sérialisation ordonnée tient malgré les tirs
    parallèles qui finissent dans le désordre."""

    def setUp(self):
        self._saved_env = os.environ.get("FORGE_PARALLELISM")

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = self._saved_env

    def test_parallel_equals_serial_ledger_and_state(self):
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="g3-det-"))
        try:
            eng_s, led_s = _run_wave(1, d / "serial.ledger")     # SÉRIEL (référence)
            eng_p, led_p = _run_wave(8, d / "parallel.ledger")   # PARALLÈLE (pool 8, complétion désordonnée)

            shape_s = _ledger_shape(d / "serial.ledger")
            shape_p = _ledger_shape(d / "parallel.ledger")

            # (a) LE LEDGER — ORDRE ET CONTENU IDENTIQUES (le make-or-break). Même séquence d'entrées.
            self.assertEqual(shape_p, shape_s,
                             "l'ordre/contenu du ledger parallèle DOIT être identique au sériel")
            # la 1re entrée d'une action FIRE est roe.decision, PUIS finding — ordre relatif préservé.
            kinds = [k for (k, _d) in shape_s]
            self.assertIn("roe.decision", kinds)
            self.assertIn("finding", kinds)
            self.assertIn("purple.runrecord", kinds)
            self.assertIn("engine.error", kinds)      # le kind sans module
            # roe.decision de la 1re action FIRE précède son finding.
            self.assertLess(kinds.index("roe.decision"), kinds.index("finding"))

            # (b) FINDINGS — même ORDRE, même contenu (horodatage exclu). L'ordre = ordre d'action.
            fs = [_strip_ts(f.to_dict()) for f in eng_s.findings]
            fp = [_strip_ts(f.to_dict()) for f in eng_p.findings]
            self.assertEqual(fp, fs, "findings parallèles identiques (ordre + contenu) au sériel")
            self.assertEqual([f["target"] for f in fs], _FIRE_IPS,
                             "findings dans l'ORDRE d'action (le doublon est dédupliqué)")

            # (c) RUN-RECORDS et DÉCISIONS ROE — même ORDRE, même contenu.
            self.assertEqual([_strip_ts(r) for r in eng_p.run_records],
                             [_strip_ts(r) for r in eng_s.run_records])
            self.assertEqual(eng_p.roe_decisions(), eng_s.roe_decisions())

            # (d) COMPTEURS identiques : dédup (1 doublon), findings, dups.
            self.assertEqual(eng_p.dups, eng_s.dups)
            self.assertEqual(eng_s.dups, 1, "le doublon exact a été dédupliqué UNE fois")
            self.assertEqual(len(eng_p.findings), len(eng_s.findings))

            # (e) CHAÎNE APPEND-ONLY intègre des DEUX côtés (tamper-evident préservé).
            self.assertTrue(led_s.verify()["ok"])
            self.assertTrue(led_p.verify()["ok"])

            # (f) GOUVERNANCE : le VETO hors-scope présent dans les deux (même nombre).
            vetoed_s = [r for r in eng_s.results if r["verdict"] == "VETO"]
            vetoed_p = [r for r in eng_p.results if r["verdict"] == "VETO"]
            self.assertEqual(len(vetoed_p), len(vetoed_s))
            self.assertEqual(len(vetoed_s), 1, "la cible hors-scope est VETOÉE (gouvernance en parallèle)")
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class TestSpeedup(unittest.TestCase):
    def setUp(self):
        self._saved_env = os.environ.get("FORGE_PARALLELISM")

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = self._saved_env

    def test_parallel_is_wall_clock_faster(self):
        ips = _FIRE_IPS
        _SLEEPS.clear()
        for ip in ips:
            _SLEEPS[ip] = 0.2                          # chaque tir DORT 0.2s (I/O simulée, libère le GIL)
        acts = [Action("par.hit", ip) for ip in ips]   # 6 tirs INDÉPENDANTS

        def _wall(pool):
            os.environ["FORGE_PARALLELISM"] = str(pool)
            eng = Engine(_scope(), mode="auto")
            eng.arm("speedup")
            with _swap({"par.hit": _SleepHit}):
                t0 = time.monotonic()
                eng.run(list(acts))
                return time.monotonic() - t0, eng

        serial_wall, eng_s = _wall(1)
        par_wall, eng_p = _wall(6)

        # RÉSULTATS COMPLETS des deux côtés (le parallélisme n'a rien perdu).
        self.assertEqual(len(eng_s.findings), len(ips))
        self.assertEqual(len(eng_p.findings), len(ips))
        # SPEEDUP RÉEL : 6 tirs de 0.2s -> ~1.2s en sériel, ~0.2s en parallèle. Marge conservatrice
        # (env chargé) : le mur parallèle doit être NETTEMENT sous le sériel (< la moitié).
        self.assertLess(par_wall, serial_wall * 0.5,
                        f"attendu un speedup réel : parallèle={par_wall:.3f}s vs sériel={serial_wall:.3f}s")


@unittest.skipUnless(hasattr(os, "killpg") and hasattr(signal, "SIGKILL"), "POSIX process groups requis")
class TestCancelComposesWithMultipleInflight(unittest.TestCase):
    """E3/E4 sous parallélisme : PLUSIEURS outils en vol simultanément -> un cancel les coupe TOUS."""

    def setUp(self):
        runner._LIVE_TOOL_PGIDS.clear()

    def tearDown(self):
        runner._LIVE_TOOL_PGIDS.clear()

    def _pid_gone(self, pid):
        try:
            os.kill(pid, 0)
            return False
        except ProcessLookupError:
            return True
        except PermissionError:
            return False

    def test_terminate_kills_ALL_inflight_tool_groups(self):
        procs = []
        try:
            # 4 « outils » en vol simultanés, chacun leader de SA session (start_new_session) — exactement
            # le cas de 4 workers du pool qui ont lancé 4 sous-process en parallèle.
            for _ in range(4):
                p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                     start_new_session=True)
                procs.append(p)
                runner._register_tool_pgid(p.pid)
            for p in procs:
                self.assertFalse(self._pid_gone(p.pid), "chaque outil doit être vivant avant le reap")

            # UN SEUL cancel doit couper les QUATRE groupes en vol (pas un seul).
            runner.terminate_live_tool_groups(force=True)
            for p in procs:
                p.wait(timeout=5)
            for p in procs:
                self.assertTrue(self._pid_gone(p.pid), "TOUS les outils en vol doivent être tués (aucun orphelin)")
        finally:
            for p in procs:
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait(timeout=5)
                    except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
                        pass

    def test_registry_snapshot_is_threadsafe_under_concurrent_mutation(self):
        # Les workers du pool mutent le registre en parallèle pendant que le handler prend un snapshot :
        # sans verrou, `list(set)` lèverait `RuntimeError: Set changed size during iteration`. On martèle.
        stop = threading.Event()
        errors = []

        def churn(base):
            # pgids FANTÔMES bien AU-DESSUS de pid_max (~4M) -> killpg -> ESRCH avalé, JAMAIS de victime réelle.
            i = 0
            while not stop.is_set():
                pgid = 2_000_000_000 + base * 1000 + (i % 500)
                runner._register_tool_pgid(pgid)
                runner._unregister_tool_pgid(pgid)
                i += 1

        def snap():
            while not stop.is_set():
                try:
                    runner.terminate_live_tool_groups(force=False)   # snapshot sous verrou (pgids fantômes -> ESRCH avalé)
                except Exception as e:  # noqa: BLE001
                    errors.append(e)

        threads = [threading.Thread(target=churn, args=(b,)) for b in range(1, 6)]
        threads.append(threading.Thread(target=snap))
        for t in threads:
            t.start()
        time.sleep(0.5)
        stop.set()
        for t in threads:
            t.join(timeout=5)
        self.assertEqual(errors, [], f"le snapshot du registre doit être thread-safe (aucune erreur) : {errors}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
