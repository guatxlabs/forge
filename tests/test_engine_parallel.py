# SPDX-License-Identifier: AGPL-3.0-or-later
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

  5. PRÉCHAUFFAGE DES ACTIONS LONGUES : les actions au coût le plus élevé (== les plus lentes) sont
     SOUMISES d'avance au lieu d'attendre leur tour en fin de vague. Prouvé sur l'ordre de DÉMARRAGE
     OBSERVÉ (propriété STRUCTURELLE, pas un chronomètre) + contrôle négatif : l'ordre d'APPLICATION
     ne bouge pas d'un pouce, et le ledger reste identique au sériel MÊME quand les coûts diffèrent.
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
from tests._tmp import temp_dir  # noqa: E402


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
        d = temp_dir(self, "g3-det-")
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


class TestSlidingWindowDoesNotStallOnASlowHead(unittest.TestCase):
    """Une action LENTE EN TÊTE ne doit PAS immobiliser le pool.

    L'application des résultats est SÉRIELLE et ORDONNÉE (c'est l'invariant de déterminisme, prouvé
    par `TestDeterminism`). La conséquence piège : si la fenêtre de SOUMISSION est égale au pool, on
    attend la tête pour ré-alimenter — les workers qui ont fini restent au repos. Chaque lot était
    donc payé au prix de sa plus lente action.

    Mesuré avant correctif, 12 actions dont une lente par lot (1,2 s contre 0,05 s), pool=4 :
    **3,90 s pour un plancher sériel de 4,05 s**. Après (fenêtre = 2 x pool) : **2,47 s**.

    Ce test n'est PAS chronométré — un test au wall-clock serait flaky sous charge. Il mesure la
    propriété STRUCTURELLE qui produit le gain : combien d'actions ont DÉMARRÉ pendant que la tête
    est encore bloquée. Avec une fenêtre égale au pool : `pool`. Avec `2 x pool` : le double."""

    POOL = 4

    def _run_with_blocked_head(self):
        started = []
        lock = threading.Lock()
        release_head = threading.Event()

        class Stub(registry.Module):
            kind = "demo.window"
            exploit = False
            web_allowed = True
            mitre = "T9999"

            def dry(self, action):
                return "dry"

            def fire(self, action):
                with lock:
                    started.append(action.target)
                    is_head = len(started) == 1
                if is_head:
                    release_head.wait(timeout=10)   # la TÊTE bloque jusqu'au relâchement
                return [Finding(target=action.target, title="ok", severity="INFO",
                                category="recon", status="tested")]

        saved = registry.REGISTRY.get("demo.window")
        registry.REGISTRY["demo.window"] = Stub
        prev = os.environ.get("FORGE_PARALLELISM")
        os.environ["FORGE_PARALLELISM"] = str(self.POOL)
        try:
            targets = [f"h{i}.test" for i in range(4 * self.POOL)]
            sc = Scope({"mode": "grey", "in_scope": ["*.test"], "allow_exploit": True})
            eng = Engine(sc, mode="auto")
            eng.arm("test")
            acts = [Action(kind="demo.window", target=t) for t in targets]
            th = threading.Thread(target=eng.run, args=(acts,), daemon=True)
            th.start()
            # Laisse la fenêtre se remplir, tête toujours bloquée.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with lock:
                    if len(started) >= 2 * self.POOL:
                        break
                time.sleep(0.02)
            with lock:
                during_head = len(started)
            release_head.set()
            th.join(timeout=20)
            return during_head, targets
        finally:
            release_head.set()
            os.environ.pop("FORGE_PARALLELISM", None) if prev is None else os.environ.__setitem__("FORGE_PARALLELISM", prev)
            if saved is None:
                registry.REGISTRY.pop("demo.window", None)
            else:
                registry.REGISTRY["demo.window"] = saved

    def test_pool_keeps_working_while_the_head_is_blocked(self):
        during_head, _ = self._run_with_blocked_head()
        self.assertGreaterEqual(
            during_head, 2 * self.POOL,
            f"seules {during_head} actions avaient démarré pendant que la tête bloquait : la fenêtre "
            f"de soumission est retombée à la taille du pool, donc une action lente ré-immobilise les "
            f"workers (régression du lot verrouillé)")

    def test_the_window_stays_BOUNDED(self):
        """Contrôle NÉGATIF : la fenêtre ne doit pas devenir « tout soumettre ».

        Sans borne, un cancel/watchdog trouverait un nombre ARBITRAIRE d'actions déjà tirées au-delà
        du point d'application — c'est précisément ce que le découpage en lots protégeait."""
        during_head, targets = self._run_with_blocked_head()
        self.assertLess(
            during_head, len(targets),
            "la fenêtre a soumis TOUTES les actions : le travail au-delà du point d'application n'est "
            "plus borné")


_PREHEAT_FAST = [f"198.51.100.{i}" for i in range(1, 41)]      # 40 actions COURTES (cost 1.0)
_PREHEAT_SLOW = [f"203.0.113.{i}" for i in range(1, 4)]        # 3 actions LONGUES (cost 3.0), EN QUEUE


class TestLongestFirstPreheat(unittest.TestCase):
    """LES ACTIONS LONGUES SONT MISES AU FOUR D'AVANCE — et RIEN D'AUTRE ne bouge.

    LE PROBLÈME. `_apply` est sériel et ORDONNÉ (invariant de déterminisme). La fenêtre glissante a
    réglé le blocage de TÊTE, mais rien n'ORDONNAIT le travail : le planner trie par
    EV = value*confidence/cost, donc un coût ÉLEVÉ (== une action LENTE : `brain._CONTENT_SCANNER_EV`
    annote littéralement ses coûts « LENT » / « TRÈS LENT ») donne une EV BASSE et une place en FIN DE
    VAGUE. Quand ces actions démarrent enfin, il ne reste plus rien pour occuper les autres workers.

    CE QUI EST PROUVÉ ICI, ET COMMENT. Aucun chronomètre : un test au wall-clock est flaky sous charge.
    On mesure la propriété STRUCTURELLE qui produit le gain — la POSITION des actions longues dans
    l'ordre de DÉMARRAGE observé. Elle est déterministe : un `ThreadPoolExecutor` est une FILE FIFO,
    les `2 x pool` premiers éléments dépilés sont donc exactement les `2 x pool` premiers SOUMIS, quel
    que soit l'ordonnancement de l'OS. Le chiffrage au wall-clock, lui, vit dans le banc
    `tests/bench_engine_parallel_order.py` (pool=4, 52 actions ordonnées par le VRAI planner :
    2,45 s -> 1,83 s, soit -25 %, à 1,02x le plancher théorique travail/pool au lieu de 1,36x).
    """

    POOL = 4
    WINDOW = 2 * POOL
    KIND = "demo.preheat"

    def setUp(self):
        self._saved_env = os.environ.get("FORGE_PARALLELISM")

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = self._saved_env

    def _actions(self):
        """Vague à la forme de PRODUCTION : la masse d'actions courtes devant, les longues (coût 3.0,
        le `cost` que le cerveau pose sur testssl/auth.takeover) rejetées EN QUEUE par l'EV."""
        acts = [Action(self.KIND, ip, cost=1.0) for ip in _PREHEAT_FAST]
        acts += [Action(self.KIND, ip, cost=3.0) for ip in _PREHEAT_SLOW]
        return acts

    def _run(self, pool, mutate=False, ledger_path=None):
        """Joue la vague et rend (ordre de DÉMARRAGE observé, engine, ledger).

        `mutate=True` RETIRE l'ordonnancement (`_preheat_order` -> liste vide) : c'est la preuve par
        MUTATION, le moteur retombe alors sur la fenêtre glissante en ordre d'indice."""
        started = []
        lock = threading.Lock()
        kind = self.KIND

        class Stub(registry.Module):
            exploit = False
            mitre = "T1190"

            def dry(self, action):
                return "dry"

            def fire(self, action):
                with lock:                      # ordre d'ENTRÉE dans le tir == ordre de DÉMARRAGE
                    started.append(action.target)
                return [Finding(target=action.target, title=f"hit:{action.target}",
                                severity="LOW", category="demo", mitre="T1190")]

        saved_mod = registry.REGISTRY.get(kind)
        registry.REGISTRY[kind] = type("StubPreheat", (Stub,), {"kind": kind})
        saved_order = Engine._preheat_order
        if mutate:
            Engine._preheat_order = lambda _self, _acts, _cap: []
        os.environ["FORGE_PARALLELISM"] = str(pool)
        try:
            ledger = Ledger(ledger_path) if ledger_path else None
            eng = Engine(_scope_preheat(), ledger=ledger, mode="auto", memory=Memory(),
                         campaign="camp", run_id="run-1")
            eng.arm("test préchauffage")
            eng.run(self._actions())
            return started, eng, ledger
        finally:
            Engine._preheat_order = saved_order
            if saved_mod is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = saved_mod

    # --- (1) LA PROPRIÉTÉ QUI PRODUIT LE GAIN ----------------------------------------------------
    def test_the_slowest_actions_start_within_the_first_window(self):
        """Les 3 actions LONGUES sont en QUEUE de vague (indices 40-42) et démarrent pourtant en TÊTE :
        elles sont mises au four d'avance, elles ne se retrouvent plus seules à la fin pendant que le
        pool se vide.

        SEUIL À `2 x fenêtre` ET NON À LA FENÊTRE EXACTE. L'ensemble SOUMIS d'avance, lui, est exact et
        vérifié séparément (`test_the_preheat_stays_inside_the_bounded_window` : `_preheat_order` rend
        EXACTEMENT [40, 41, 42]). Ce qu'on observe ici est l'ordre d'ENTRÉE dans `fire()`, qui suit
        l'ordre de dépilement FIFO de l'exécuteur À UNE COURSE PRÈS : entre le moment où un worker
        dépile son élément et celui où il prend le verrou d'enregistrement, un autre worker peut le
        doubler. La marge absorbe cette course sans rien concéder au pouvoir discriminant : mesuré
        4-8 avec ordonnancement, >= 32 sans (cf. le test de MUTATION juste en dessous)."""
        started, eng, _ = self._run(self.POOL)
        self.assertEqual(len(started), len(_PREHEAT_FAST) + len(_PREHEAT_SLOW))
        positions = {t: started.index(t) for t in _PREHEAT_SLOW}
        self.assertLess(
            max(positions.values()), 2 * self.WINDOW,
            f"les actions longues démarrent en positions {sorted(positions.values())} : elles ne sont "
            f"PAS préchauffées, le pool se videra en fin de vague en les attendant")
        # résultats COMPLETS (le préchauffage ne perd ni ne double rien)
        self.assertEqual(len(eng.findings), len(_PREHEAT_FAST) + len(_PREHEAT_SLOW))

    def test_MUTATION_without_preheat_the_slow_actions_start_at_the_very_end(self):
        """PREUVE PAR MUTATION : on retire l'ordonnancement -> le test ci-dessus DOIT rougir. Sans
        préchauffage, les actions longues ne sont soumises que quand la fenêtre glissante les atteint,
        c'est-à-dire à `2 x pool` actions de la fin."""
        started, _eng, _ = self._run(self.POOL, mutate=True)
        positions = {t: started.index(t) for t in _PREHEAT_SLOW}
        self.assertGreaterEqual(
            min(positions.values()), len(_PREHEAT_FAST) - self.WINDOW,
            "sans ordonnancement, une action longue de la QUEUE ne peut pas démarrer tôt — si elle le "
            "fait, la mutation ne mute rien et le test de gain ne prouve rien")
        self.assertGreaterEqual(max(positions.values()), self.WINDOW,
                                "la mutation DOIT faire échouer la propriété prouvée ci-dessus")

    # --- (2) CONTRÔLE NÉGATIF : L'ORDRE D'APPLICATION N'A PAS BOUGÉ -------------------------------
    def test_application_order_is_STILL_the_action_order(self):
        """L'ORDRE D'APPLICATION EST L'INVARIANT : réordonner la SOUMISSION ne doit RIEN changer à
        l'ordre dans lequel findings / results / ledger sortent. On le vérifie sur la vague qui a
        EFFECTIVEMENT été réordonnée (les longues ont démarré en tête, cf. le test précédent)."""
        expected = [a.target for a in self._actions()]                # == l'ordre d'ACTION
        started, eng, _ = self._run(self.POOL)
        self.assertNotEqual(started, expected,
                            "la vague n'a PAS été réordonnée : ce contrôle ne contrôle rien")
        self.assertEqual([f.target for f in eng.findings], expected,
                         "les findings DOIVENT sortir dans l'ordre d'action, pas dans l'ordre de tir")
        self.assertEqual([r["target"] for r in eng.results], expected)
        self.assertEqual([r["target"] for r in eng.run_records], expected)
        self.assertEqual([d["target"] for d in eng.roe_decisions()], expected)

    def test_ledger_is_identical_to_serial_even_with_heterogeneous_costs(self):
        """LE MAKE-OR-BREAK, SUR LE CHEMIN RÉORDONNÉ. `TestDeterminism` compare sériel et pool=8 sur une
        vague à coût UNIFORME — où `_preheat_order` rend une liste vide et ne réordonne donc RIEN. Cette
        preuve-ci rejoue la même comparaison sur une vague à coûts HÉTÉROGÈNES, celle qui exerce
        vraiment le préchauffage : même ORDRE, même CONTENU, chaîne append-only intègre des deux côtés."""
        d = temp_dir(self, "g3-preheat-")
        _st_s, eng_s, led_s = self._run(1, ledger_path=d / "serial.ledger")     # SÉRIEL (référence)
        st_p, eng_p, led_p = self._run(8, ledger_path=d / "parallel.ledger")    # PARALLÈLE réordonné

        self.assertNotEqual(st_p, [a.target for a in self._actions()],
                            "la vague parallèle n'a pas été réordonnée : la preuve serait vide")
        self.assertEqual(_ledger_shape(d / "parallel.ledger"), _ledger_shape(d / "serial.ledger"),
                         "l'ordre/contenu du ledger DOIT rester identique au sériel malgré le "
                         "réordonnancement des SOUMISSIONS")
        self.assertEqual([_strip_ts(f.to_dict()) for f in eng_p.findings],
                         [_strip_ts(f.to_dict()) for f in eng_s.findings])
        self.assertEqual([_strip_ts(r) for r in eng_p.run_records],
                         [_strip_ts(r) for r in eng_s.run_records])
        self.assertEqual(eng_p.roe_decisions(), eng_s.roe_decisions())
        self.assertTrue(led_s.verify()["ok"])
        self.assertTrue(led_p.verify()["ok"])

    # --- (3) LA BORNE DE TRAVAIL EN AVANCE N'A PAS BOUGÉ ------------------------------------------
    def test_the_preheat_stays_inside_the_bounded_window(self):
        """Le préchauffage ne doit pas devenir « tout soumettre » : il est plafonné à `pool - 1`
        actions, donc au plus `2 x pool` tirs restent soumis-non-appliqués — la MÊME borne de travail
        au-delà du point d'application qu'avant l'ordonnancement (c'est elle qui borne le travail
        gaspillé quand un cancel/watchdog tombe)."""
        eng = Engine(_scope_preheat(), mode="auto")
        # EXACT (aucune course, fonction pure) : le préchauffage == les 3 actions longues de la QUEUE.
        self.assertEqual(eng._preheat_order(self._actions(), self.POOL - 1), [40, 41, 42])
        for pool in (2, 4, 8, 12):
            with self.subTest(pool=pool):
                idx = eng._preheat_order(self._actions(), pool - 1)
                self.assertLessEqual(len(idx), pool - 1)
                self.assertEqual(len(set(idx)), len(idx), "aucun indice préchauffé deux fois")
        # coûts UNIFORMES -> AUCUN préchauffage : on retombe exactement sur la fenêtre glissante d'avant.
        flat = [Action(self.KIND, ip) for ip in _PREHEAT_FAST]        # cost = défaut 1.0 partout
        self.assertEqual(eng._preheat_order(flat, self.POOL - 1), [],
                         "une vague à coût uniforme ne doit RIEN réordonner (chemin historique intact)")
        # un palier qui remplit le pool À LUI SEUL n'a rien à gagner -> pas préchauffé non plus.
        big = [Action(self.KIND, ip, cost=1.0) for ip in _PREHEAT_FAST[:10]]
        big += [Action(self.KIND, ip, cost=3.0) for ip in _PREHEAT_FAST[10:10 + self.POOL]]
        self.assertEqual(eng._preheat_order(big, self.POOL - 1), [],
                         "un palier de `pool` actions longues occupe déjà tout le pool : rien à gagner")

    def test_a_broken_cost_never_breaks_the_ordering(self):
        """`cost` vient d'un cerveau (voire d'un LLM) : il peut arriver absurde. Un coût NaN / négatif /
        non numérique est traité comme neutre — le tri reste total, la vague part quand même."""
        eng = Engine(_scope_preheat(), mode="auto")
        acts = [Action(self.KIND, _PREHEAT_FAST[0], cost=float("nan")),
                Action(self.KIND, _PREHEAT_FAST[1], cost=-5.0),
                Action(self.KIND, _PREHEAT_FAST[2], cost=0.0),
                Action(self.KIND, _PREHEAT_FAST[3], cost=1.0),
                Action(self.KIND, _PREHEAT_FAST[4], cost=9.0)]
        acts[0].cost = "beaucoup"                          # coût carrément non numérique
        idx = eng._preheat_order(acts, 3)
        self.assertEqual(idx, [4], "seul le coût 9.0 est un palier supérieur ; les coûts cassés = 1.0")


def _scope_preheat():
    return Scope({"mode": "grey", "in_scope": _PREHEAT_FAST + _PREHEAT_SLOW,
                  "allow_exploit": True, "allow_destructive": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
