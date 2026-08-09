# SPDX-License-Identifier: AGPL-3.0-or-later
"""DURÉES OBSERVÉES PAR KIND — la mesure qui remplace `cost` dans le préchauffage, et ses gardes.

CE QUE CE FICHIER PROUVE, ET POURQUOI CHAQUE PREUVE EXISTE.

`engine._preheat_order` met « au four d'avance » les actions les plus LONGUES d'une vague. Sa seule
estimation de lenteur était `action.cost` — une donnée de GOUVERNANCE (le prix qu'on accepte de payer),
pas une mesure de DURÉE. `forge/durations.py` apporte la mesure ; ce fichier tient les quatre promesses
qui vont avec :

  1. REPLI EXACT — zéro donnée observée doit produire le comportement d'AVANT, à l'identique. C'est la
     première preuve du fichier, et elle a sa MUTATION : casser le repli DOIT la faire rougir.
  2. LA MESURE PRIME QUAND ELLE EXISTE — un `cost` qui MENT (cher-mais-rapide / gratuit-mais-lent) est
     déclassé par la durée observée du kind, et un kind vu UNE seule fois n'est PAS cru (n=1 == bruit).
  3. RIEN D'IDENTIFIANT SUR LE DISQUE — la preuve LIT LES OCTETS ÉCRITS, elle ne fait pas confiance à
     l'API : aucune cible, aucun hôte, aucune URL ne peut apparaître dans le magasin, et sa taille est
     BORNÉE (nombre de kinds plafonné, agrégat de taille fixe par kind).
  4. DÉTERMINISME ET INVARIANTS DU MOTEUR — l'ordre d'APPLICATION ne bouge pas (ledger/findings/
     décisions identiques au sériel), et deux runs sur le MÊME magasin préchauffent pareil.

Tout est HERMÉTIQUE : modules stubés, cibles = IP LITTÉRALES publiques RFC5737 (zéro DNS, zéro réseau),
`temp_dir` pour les fixtures. Le chiffrage au wall-clock, lui, vit dans le banc
`tests/bench_engine_parallel_order.py` (formes « straggler » et « cost-lies »).
"""
import json
import os
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.durations import DurationStore, _quantize         # noqa: E402
from forge.engine import Engine, _action_cost                # noqa: E402
from forge.ledger import Ledger                              # noqa: E402
from forge.memory import Memory                              # noqa: E402
from forge.modules import registry                           # noqa: E402
from forge.roe import Action, Scope                          # noqa: E402
from forge.schema import Finding                             # noqa: E402
from tests._tmp import temp_dir                              # noqa: E402
from tests.test_engine_parallel import _ledger_shape, _strip_ts  # noqa: E402

# Cibles = IP LITTÉRALES publiques (RFC5737 TEST-NET-2/3) -> `resolve_target_ips` court-circuite :
# aucune résolution DNS, aucun paquet. Ce sont AUSSI les chaînes que la preuve de non-identification
# cherche (et ne doit pas trouver) dans le magasin écrit sur disque.
_FAST = [f"198.51.100.{i}" for i in range(1, 41)]
_SLOW = [f"203.0.113.{i}" for i in range(1, 4)]

_KIND_FAST = "demo.quick"        # kind « rapide »
_KIND_SLOW = "demo.grind"        # kind « lent »


def _scope():
    return Scope({"mode": "grey", "in_scope": _FAST + _SLOW,
                  "allow_exploit": True, "allow_destructive": False})


def _store_with(**kinds_seconds):
    """Magasin PRÉ-OBSERVÉ en mémoire : `MIN_SAMPLES` observations par kind, donc CRU par `estimate`.
    Construit par la voie publique `record()` + `save()`/`load()` quand un chemin est fourni."""
    st = DurationStore()
    for kind, secs in kinds_seconds.items():
        for _ in range(DurationStore.MIN_SAMPLES):
            st.record(kind, secs)
    # `estimate` est GELÉ à la construction : on reconstruit depuis le tampon pour obtenir un magasin
    # qui RÉPOND (c'est exactement ce que fait un run qui recharge le fichier écrit par le précédent).
    return DurationStore(None, st._pending)


class _Stub(registry.Module):
    """Module stub : rend un finding déterministe. Les sous-classes fixent `kind`."""

    exploit = False
    mitre = "T1190"

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        return [Finding(target=action.target, title=f"{self.kind}:{action.target}",
                        severity="LOW", category=self.kind, mitre="T1190")]


class _Swap:
    """Substitue des modules dans le registre, restaure à la sortie (aucune fuite entre tests)."""

    def __init__(self, case, kinds, base=_Stub):
        self.kinds, self.base, self._saved = list(kinds), base, {}
        case.addCleanup(self.restore)

    def __enter__(self):
        for kind in self.kinds:
            self._saved[kind] = registry.REGISTRY.get(kind)
            registry.REGISTRY[kind] = type(f"Stub_{kind.replace('.', '_')}",
                                           (self.base,), {"kind": kind})
        return self

    def __exit__(self, *exc):
        self.restore()
        return False

    def restore(self):
        for kind, prev in self._saved.items():
            if prev is None:
                registry.REGISTRY.pop(kind, None)
            else:
                registry.REGISTRY[kind] = prev
        self._saved = {}


# =====================================================================================================
# 1. LE REPLI EXACT — zéro donnée observée == le comportement d'avant l'instrumentation
# =====================================================================================================
class TestFallbackIsExact(unittest.TestCase):
    """SANS MESURE, RIEN NE BOUGE. C'est la promesse la plus importante du chantier : une install qui
    n'a jamais rien mesuré (premier run d'un engagement, CLI sans `--ledger`, suite de tests) doit
    ordonner EXACTEMENT comme avant. On le prouve sur l'ensemble PRÉCHAUFFÉ lui-même — la seule chose
    que ce chantier peut déplacer — en comparant au calcul de référence PAR LES COÛTS, réimplémenté
    ici indépendamment du moteur."""

    POOL = 4

    def _wave(self):
        """Vague à la forme de production : masse d'actions courtes devant, les chères en QUEUE."""
        acts = [Action(_KIND_FAST, ip, cost=1.0) for ip in _FAST]
        acts += [Action(_KIND_SLOW, ip, cost=3.0) for ip in _SLOW]
        return acts

    @staticmethod
    def _reference_by_cost(actions, capacity):
        """RÉFÉRENCE INDÉPENDANTE : l'algorithme de paliers d'AVANT, écrit ici sur `action.cost` seul.
        Si le moteur en dévie sans magasin, c'est une régression du repli."""
        costs = [_action_cost(a) for a in actions]
        tiers = sorted(set(costs), reverse=True)
        if len(tiers) < 2:
            return []
        out = []
        for tier in tiers[:-1]:
            members = [i for i, c in enumerate(costs) if c == tier]
            if len(out) + len(members) > capacity:
                break
            out.extend(members)
        return out

    def test_no_store_at_all_orders_exactly_like_the_cost_reference(self):
        eng = Engine(_scope(), mode="auto")                       # durations=None (défaut)
        self.assertIsNone(eng.durations)
        for cap in (1, 3, 7, 11):
            with self.subTest(capacity=cap):
                self.assertEqual(eng._preheat_order(self._wave(), cap),
                                 self._reference_by_cost(self._wave(), cap))

    def test_an_EMPTY_store_orders_exactly_like_the_cost_reference(self):
        """Le cas du PREMIER run d'un engagement : le fichier existe (ou pas), il est VIDE."""
        eng = Engine(_scope(), mode="auto", durations=DurationStore())
        self.assertEqual(eng.durations.observed_kinds(), 0)
        for cap in (1, 3, 7, 11):
            with self.subTest(capacity=cap):
                self.assertEqual(eng._preheat_order(self._wave(), cap),
                                 self._reference_by_cost(self._wave(), cap))

    def test_a_store_that_knows_OTHER_kinds_still_falls_back_for_this_wave(self):
        """Repli PAR KIND : un magasin bien garni mais sur d'AUTRES kinds ne doit rien changer ici."""
        eng = Engine(_scope(), mode="auto",
                     durations=_store_with(**{"web.testssl": 60.0, "recon.httpx": 0.5}))
        self.assertEqual(eng._preheat_order(self._wave(), self.POOL - 1),
                         self._reference_by_cost(self._wave(), self.POOL - 1))

    def test_MUTATION_breaking_the_fallback_makes_the_three_proofs_above_red(self):
        """PREUVE PAR MUTATION. On casse le repli exactement comme un refactor maladroit le ferait :
        `_preheat_key` rend 0.0 quand le kind est inconnu du magasin, au lieu de `action.cost`. Les
        clés deviennent alors toutes égales -> plus AUCUN palier -> préchauffage VIDE. Si cette
        assertion ne rougit pas, les trois tests ci-dessus ne prouvent rien."""
        saved = Engine._preheat_key
        try:
            Engine._preheat_key = lambda _self, _a: 0.0        # le repli disparaît
            eng = Engine(_scope(), mode="auto", durations=DurationStore())
            mutated = eng._preheat_order(self._wave(), self.POOL - 1)
        finally:
            Engine._preheat_key = saved
        expected = self._reference_by_cost(self._wave(), self.POOL - 1)
        self.assertNotEqual(mutated, expected,
                            "la mutation ne mute RIEN : le test de repli ci-dessus est décoratif")
        self.assertEqual(expected, [40, 41, 42], "la référence par coût préchauffe bien la queue chère")


# =====================================================================================================
# 2. LA MESURE PRIME — mais seulement quand on peut la croire
# =====================================================================================================
class TestObservedDurationBeatsALyingCost(unittest.TestCase):
    """LE SEUL CAS OÙ CE CHANTIER CHANGE QUELQUE CHOSE : quand `cost` MENT. Les coûts sont ici
    ANTI-CORRÉLÉS aux durées réelles — les actions CHÈRES sont RAPIDES, les GRATUITES sont LENTES.
    Sur `cost`, le préchauffage se trompe de cible ; sur la durée observée, il vise juste."""

    CAP = 3

    def _wave(self):
        """`_KIND_SLOW` est GRATUIT (cost 1.0) mais LENT ; `_KIND_FAST` est CHER (cost 3.0) mais RAPIDE."""
        acts = [Action(_KIND_FAST, ip, cost=3.0) for ip in _FAST[:10]]
        acts += [Action(_KIND_SLOW, ip, cost=1.0) for ip in _SLOW]
        return acts

    def test_without_measurement_the_lying_cost_preheats_the_WRONG_actions(self):
        """CONTRÔLE : sans mesure, le palier cher (les 10 RAPIDES) ne tient pas dans la capacité ->
        rien n'est préchauffé, et les 3 actions réellement LENTES restent en queue de vague."""
        eng = Engine(_scope(), mode="auto")
        self.assertEqual(eng._preheat_order(self._wave(), self.CAP), [],
                         "sur un coût menteur, le préchauffage n'a AUCUNE chance de viser juste")

    def test_with_measurement_the_truly_slow_actions_are_preheated(self):
        eng = Engine(_scope(), mode="auto",
                     durations=_store_with(**{_KIND_FAST: 0.03, _KIND_SLOW: 1.20}))
        self.assertEqual(eng._preheat_order(self._wave(), self.CAP), [10, 11, 12],
                         "les 3 actions LENTES (indices 10-12) doivent passer au four d'avance")

    def test_MUTATION_ignoring_the_store_puts_the_wrong_actions_back(self):
        """PREUVE PAR MUTATION : on rend le magasin muet -> la propriété ci-dessus DOIT disparaître."""
        saved = DurationStore.estimate
        try:
            DurationStore.estimate = lambda _self, _kind: None
            eng = Engine(_scope(), mode="auto",
                         durations=_store_with(**{_KIND_FAST: 0.03, _KIND_SLOW: 1.20}))
            mutated = eng._preheat_order(self._wave(), self.CAP)
        finally:
            DurationStore.estimate = saved
        self.assertNotEqual(mutated, [10, 11, 12],
                            "sans consommer le magasin, l'ordre ne doit PAS être le bon — sinon la "
                            "preuve de gain ne mesure pas ce qu'elle prétend")

    @staticmethod
    def _seen_once():
        """Magasin où CHAQUE kind de la vague n'a qu'UNE observation — la vérité, mais sur n=1."""
        st = DurationStore()
        st.record(_KIND_FAST, 0.03)
        st.record(_KIND_SLOW, 1.20)
        return DurationStore(None, st._pending)

    def test_a_kind_seen_ONCE_is_not_trusted(self):
        """n=1 EST DU BRUIT. Sous `MIN_SAMPLES` observations, le kind n'a pas d'estimation et l'ordre
        retombe sur `cost` — le magasin ne peut donc pas être détourné par UN tir aberrant."""
        one_shot = self._seen_once()
        self.assertIsNone(one_shot.estimate(_KIND_SLOW))
        eng = Engine(_scope(), mode="auto", durations=one_shot)
        self.assertEqual(eng._preheat_order(self._wave(), self.CAP), [],
                         "une observation unique ne doit PAS déplacer l'ordre")

    def test_MUTATION_trusting_n_equals_1_would_change_the_order(self):
        """PREUVE PAR MUTATION : à magasin IDENTIQUE, abaisser le seuil de confiance à 1 DOIT faire
        bouger l'ordre — sinon le test ci-dessus passerait même sans seuil, et ne prouverait rien."""
        saved = DurationStore.MIN_SAMPLES
        try:
            DurationStore.MIN_SAMPLES = 1
            eng = Engine(_scope(), mode="auto", durations=self._seen_once())
            mutated = eng._preheat_order(self._wave(), self.CAP)
        finally:
            DurationStore.MIN_SAMPLES = saved
        self.assertEqual(mutated, [10, 11, 12],
                         "à seuil 1, les observations uniques SONT crues : le seuil est bien la seule "
                         "chose qui retenait l'ordre dans le test précédent")

    def test_comparable_durations_land_in_the_SAME_tier(self):
        """LA QUANTIFICATION N'EST PAS COSMÉTIQUE. `_preheat_order` raisonne par PALIERS et applique
        « palier complet ou rien » — la règle qui empêche de CASSER en deux un groupe d'actions lentes
        (mesuré ailleurs à -16 % quand on le casse). Deux médianes MESURÉES ne sont jamais égales : sans
        quantification, chaque kind formerait son propre palier et le groupe serait scindé. Ici, deux
        kinds de lenteur comparable (0,62 s et 0,58 s) doivent former UN SEUL palier de 4 actions, qui
        DÉPASSE la capacité -> rien n'est préchauffé, le groupe reste entier."""
        wave = [Action(_KIND_FAST, ip, cost=1.0) for ip in _FAST[:10]]
        wave += [Action("demo.grind_a", ip, cost=1.0) for ip in _SLOW[:2]]
        wave += [Action("demo.grind_b", ip, cost=1.0) for ip in _SLOW[:2]]
        eng = Engine(_scope(), mode="auto", durations=_store_with(**{
            _KIND_FAST: 0.03, "demo.grind_a": 0.62, "demo.grind_b": 0.58}))
        self.assertEqual(eng._preheat_order(wave, self.CAP), [],
                         "0,62 s et 0,58 s doivent tomber dans le MÊME palier : le groupe lent ne se "
                         "coupe pas en deux")

    def test_MUTATION_without_quantization_the_slow_group_is_SPLIT(self):
        """PREUVE PAR MUTATION : on retire la quantification (l'estimation devient la médiane brute) ->
        les deux kinds forment deux paliers, et le préchauffage n'emporte que la MOITIÉ du groupe."""
        import forge.durations as durmod
        saved = durmod._quantize
        try:
            durmod._quantize = lambda s: float(s)
            wave = [Action(_KIND_FAST, ip, cost=1.0) for ip in _FAST[:10]]
            wave += [Action("demo.grind_a", ip, cost=1.0) for ip in _SLOW[:2]]
            wave += [Action("demo.grind_b", ip, cost=1.0) for ip in _SLOW[:2]]
            eng = Engine(_scope(), mode="auto", durations=_store_with(**{
                _KIND_FAST: 0.03, "demo.grind_a": 0.62, "demo.grind_b": 0.58}))
            self.assertEqual(eng._preheat_order(wave, self.CAP), [10, 11],
                             "sans quantification le groupe lent EST scindé — la quantification est "
                             "bien la seule chose qui le tenait ensemble")
        finally:
            durmod._quantize = saved

    def test_the_median_absorbs_one_aberrant_tir(self):
        """Un tir qui ÉCHOUE en 3 ms (outil absent) ne doit pas faire passer un kind lent pour rapide :
        la médiane de l'anneau l'absorbe tant qu'il reste minoritaire."""
        st = DurationStore()
        for _ in range(4):
            st.record(_KIND_SLOW, 1.20)
        st.record(_KIND_SLOW, 0.003)                           # l'aberration
        self.assertEqual(DurationStore(None, st._pending).estimate(_KIND_SLOW), _quantize(1.20))


# =====================================================================================================
# 3. LE MAGASIN N'IDENTIFIE RIEN — prouvé sur les OCTETS ÉCRITS, pas sur l'API
# =====================================================================================================
class TestStoreNeverIdentifiesATarget(unittest.TestCase):
    """UN MAGASIN DE DURÉES PAR CIBLE SERAIT UN JOURNAL DE RECONNAISSANCE qui survit à l'engagement
    (« combien de temps l'hôte X a mis à répondre »). L'agrégat est donc PAR KIND, et on le vérifie en
    LISANT LE FICHIER : faire confiance à la signature de `record()` ne prouverait rien contre un
    appelant futur qui lui passerait autre chose."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-durations-priv-")
        self._env = os.environ.get("FORGE_PARALLELISM")
        os.environ["FORGE_PARALLELISM"] = "4"

    def tearDown(self):
        if self._env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = self._env

    def _run_and_read(self):
        """Joue une vraie vague gouvernée contre des cibles NOMMÉES, puis rend les octets du magasin."""
        ledger_path = self.dir / "engagement-7.jsonl"
        store = DurationStore.for_ledger(str(ledger_path))
        with _Swap(self, [_KIND_FAST, _KIND_SLOW]):
            eng = Engine(_scope(), ledger=Ledger(str(ledger_path)), mode="auto",
                         memory=Memory(), durations=store)
            eng.arm("test non-identification")
            eng.run([Action(_KIND_FAST, ip) for ip in _FAST]
                    + [Action(_KIND_SLOW, ip, cost=3.0) for ip in _SLOW])
        self.assertTrue(store.save())
        path = Path(str(ledger_path) + ".durations")
        return path, path.read_text(encoding="utf-8")

    def test_the_bytes_on_disk_contain_no_target_no_host_no_url(self):
        path, raw = self._run_and_read()
        for target in _FAST + _SLOW:
            self.assertNotIn(target, raw, f"la cible {target} a FUITÉ dans {path}")
        for octet in ("198.51", "203.0", "http", "://", "/"):
            self.assertNotIn(octet, raw, f"fragment identifiant '{octet}' présent dans {path}")

    def test_the_keys_are_module_kinds_and_the_values_are_numbers_only(self):
        """Contrôle POSITIF : le fichier n'est pas vide (sinon le test précédent passerait tout seul),
        et sa STRUCTURE ne laisse de place à rien d'autre que des kinds et des nombres."""
        _path, raw = self._run_and_read()
        data = json.loads(raw)
        self.assertEqual(data["v"], DurationStore.VERSION)
        self.assertEqual(sorted(data["kinds"]), [_KIND_SLOW, _KIND_FAST],
                         "les SEULES clés sont les kinds tirés")
        for kind, blob in data["kinds"].items():
            self.assertTrue(DurationStore._valid_kind(kind))
            self.assertEqual(sorted(blob), ["n", "s"])
            self.assertIsInstance(blob["n"], int)
            for s in blob["s"]:
                self.assertIsInstance(s, float)

    def test_record_REFUSES_anything_that_is_not_a_module_kind(self):
        """GARDE STRUCTURELLE, indépendante de l'appelant : une IP, un host:port, une URL, un chemin
        ou un nom en majuscules ne PEUVENT PAS devenir une clé, même si quelqu'un les passe."""
        st = DurationStore()
        for bad in ("198.51.100.7", "203.0.113.1:8443", "https://cible.example/a", "/etc/passwd",
                    "Cible.Example", "cible-client.example", "", "x" * 200, None, 42):
            for _ in range(DurationStore.MIN_SAMPLES):
                st.record(bad, 1.0)
        self.assertEqual(st._pending, {}, "un identifiant de cible ne doit JAMAIS entrer au magasin")
        st.record("web.nuclei", 1.0)                            # contrôle positif : un vrai kind passe
        self.assertEqual(list(st._pending), ["web.nuclei"])

    def test_MUTATION_dropping_the_kind_guard_lets_a_target_in(self):
        """PREUVE PAR MUTATION : sans la garde, une cible ENTRE — c'est donc bien elle qui protège."""
        # `__dict__` : le DESCRIPTEUR classmethod. `DurationStore._valid_kind` rendrait une méthode
        # DÉJÀ LIÉE, et la reposer figerait `cls` sur `DurationStore` pour toute sous-classe.
        saved = DurationStore.__dict__["_valid_kind"]
        try:
            DurationStore._valid_kind = classmethod(lambda _cls, k: isinstance(k, str) and bool(k))
            st = DurationStore()
            st.record("198.51.100.7", 1.0)
            self.assertEqual(list(st._pending), ["198.51.100.7"],
                             "la mutation ne mute rien : la garde testée n'est pas celle qui protège")
        finally:
            DurationStore._valid_kind = saved

    def test_a_kind_read_back_from_a_TAMPERED_file_is_dropped(self):
        """Fail-closed EN LECTURE aussi : quelqu'un qui écrirait des cibles dans le fichier à la main
        ne les verrait pas ressortir — elles sont écartées à la charge, sans invalider le reste."""
        p = self.dir / "tampered.durations"
        p.write_text(json.dumps({"v": DurationStore.VERSION, "kinds": {
            "198.51.100.7": {"n": 9, "s": [1.0, 1.0, 1.0]},
            "https://cible.example/a": {"n": 9, "s": [2.0]},
            "web.nuclei": {"n": 9, "s": [0.5, 0.5, 0.5]}}}), encoding="utf-8")
        st = DurationStore.load(p)
        self.assertEqual(list(st._disk), ["web.nuclei"])
        self.assertIsNone(st.estimate("198.51.100.7"))


# =====================================================================================================
# 4. TAILLE BORNÉE — un agrégat, pas une liste qui grandit
# =====================================================================================================
class TestStoreIsBounded(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir(self, "forge-durations-bounds-")

    def test_ten_thousand_observations_do_not_grow_the_aggregate(self):
        st = DurationStore()
        for i in range(10_000):
            st.record("web.nuclei", 0.1 + (i % 7) / 1000.0)
        self.assertEqual(len(st._pending["web.nuclei"].samples), DurationStore.RING)
        self.assertEqual(st._pending["web.nuclei"].n, 10_000)

    def test_the_number_of_kinds_is_capped(self):
        st = DurationStore()
        for i in range(DurationStore.MAX_KINDS + 50):
            st.record(f"fam{i}.probe", 1.0)
        self.assertEqual(len(st._pending), DurationStore.MAX_KINDS)

    def test_the_eviction_is_DETERMINISTIC_and_keeps_the_most_observed(self):
        """Éviction par `n` DÉCROISSANT puis NOM croissant : jamais par ordre d'insertion d'un dict.
        On le prouve en fusionnant DEUX FOIS le même contenu dans un ordre d'insertion INVERSÉ."""
        base = {f"k{i:03d}.a": _stat(1) for i in range(DurationStore.MAX_KINDS)}
        newcomers = {f"z{i}.a": _stat(99) for i in range(10)}
        merged = DurationStore._merge(base, newcomers)
        self.assertEqual(len(merged), DurationStore.MAX_KINDS)
        self.assertTrue(set(newcomers) <= set(merged),
                        "les entrées les PLUS observées doivent survivre à l'éviction")
        shuffled = DurationStore._merge(dict(reversed(list(base.items()))),
                                        dict(reversed(list(newcomers.items()))))
        self.assertEqual(sorted(merged), sorted(shuffled),
                         "le résultat de l'éviction ne doit PAS dépendre de l'ordre d'insertion")

    def test_the_written_file_stays_small_after_a_long_run(self):
        p = self.dir / "big.durations"
        st = DurationStore(p)
        for k in range(80):                                    # ~ la taille du registre réel
            for _ in range(500):
                st.record(f"fam{k}.probe", 1.234)
        st.save()
        size = p.stat().st_size
        self.assertLess(size, 32_768, f"magasin de {size} octets — l'agrégat n'est plus borné")


def _stat(n):
    from forge.durations import _KindStat
    return _KindStat(n, [1.0])


# =====================================================================================================
# 5. DÉTERMINISME ET INVARIANTS DU MOTEUR
# =====================================================================================================
class TestDeterminismAndEngineInvariants(unittest.TestCase):
    POOL = 4

    def setUp(self):
        self.dir = temp_dir(self, "forge-durations-det-")
        self._env = os.environ.get("FORGE_PARALLELISM")

    def tearDown(self):
        if self._env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = self._env

    def _wave(self):
        acts = [Action(_KIND_FAST, ip, cost=3.0) for ip in _FAST[:10]]
        acts += [Action(_KIND_SLOW, ip, cost=1.0) for ip in _SLOW]
        return acts

    def test_estimates_are_FROZEN_for_the_whole_run(self):
        """L'ordre de soumission d'un run est une fonction PURE de (vague, magasin AU DÉMARRAGE) : ce
        qu'on mesure PENDANT le run n'est lisible qu'au run suivant. Sans ce gel, deux exécutions
        identiques dévieraient au gré des microsecondes mesurées."""
        st = _store_with(**{_KIND_SLOW: 1.20, _KIND_FAST: 0.03})
        before = st.estimate(_KIND_SLOW)
        for _ in range(50):
            st.record(_KIND_SLOW, 0.001)                        # mesures « de ce run »
        self.assertEqual(st.estimate(_KIND_SLOW), before,
                         "une mesure du run courant ne doit PAS déplacer l'estimation du run courant")
        st2 = DurationStore(None, st._merge(st._disk, st._pending))
        self.assertNotEqual(st2.estimate(_KIND_SLOW), before,
                            "…mais le run SUIVANT doit bien en profiter (sinon rien n'est appris)")

    def test_two_engines_on_the_same_store_preheat_IDENTICALLY(self):
        p = self.dir / "eng.jsonl.durations"
        seed = DurationStore(p)
        for _ in range(DurationStore.MIN_SAMPLES):
            seed.record(_KIND_SLOW, 1.20)
            seed.record(_KIND_FAST, 0.03)
        seed.save()
        orders = [Engine(_scope(), mode="auto", durations=DurationStore.load(p))
                  ._preheat_order(self._wave(), self.POOL - 1) for _ in range(5)]
        self.assertEqual(orders, [[10, 11, 12]] * 5)

    def test_record_is_safe_from_many_threads(self):
        """`record()` est appelé depuis les workers de tir : 8 threads x 500 observations doivent
        toutes être comptées, sans exception ni perte."""
        st = DurationStore()

        def worker():
            for _ in range(500):
                st.record("web.nuclei", 0.42)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(st._pending["web.nuclei"].n, 4000)

    def test_application_order_and_ledger_are_UNCHANGED_with_a_store_attached(self):
        """L'INVARIANT DU MOTEUR. Le magasin ne pilote QUE l'ordre de SOUMISSION : la vague est
        réellement réordonnée (contrôle positif), et pourtant ledger / findings / décisions sortent
        EXACTEMENT comme en sériel."""
        started, eng_p, led_p = self._play(8, self.dir / "parallel.jsonl")
        _st_s, eng_s, led_s = self._play(1, self.dir / "serial.jsonl")
        self.assertNotEqual(started, [a.target for a in self._wave()],
                            "la vague n'a pas été réordonnée : la preuve serait vide")
        self.assertEqual(_ledger_shape(self.dir / "parallel.jsonl"),
                         _ledger_shape(self.dir / "serial.jsonl"))
        self.assertEqual([_strip_ts(f.to_dict()) for f in eng_p.findings],
                         [_strip_ts(f.to_dict()) for f in eng_s.findings])
        self.assertEqual(eng_p.roe_decisions(), eng_s.roe_decisions())
        self.assertTrue(led_p.verify()["ok"])
        self.assertTrue(led_s.verify()["ok"])

    def _play(self, pool, ledger_path):
        """Joue la vague MENTEUSE avec un magasin qui dit la vérité, et rend l'ordre de DÉMARRAGE."""
        started, lock = [], threading.Lock()

        class Recorder(_Stub):
            def fire(self, action):
                with lock:
                    started.append(action.target)
                return _Stub.fire(self, action)

        os.environ["FORGE_PARALLELISM"] = str(pool)
        with _Swap(self, [_KIND_FAST, _KIND_SLOW], base=Recorder):
            ledger = Ledger(str(ledger_path))
            eng = Engine(_scope(), ledger=ledger, mode="auto", memory=Memory(),
                         campaign="camp", run_id="run-1",
                         durations=_store_with(**{_KIND_FAST: 0.03, _KIND_SLOW: 1.20}))
            eng.arm("test invariant")
            eng.run(self._wave())
        return started, eng, ledger


# =====================================================================================================
# 6. PERSISTANCE PAR-ENGAGEMENT — le fichier, sa portée, et son inertie en cas de pépin
# =====================================================================================================
class TestPerEngagementPersistence(unittest.TestCase):
    def setUp(self):
        self.dir = temp_dir(self, "forge-durations-scope-")
        self._env = os.environ.get("FORGE_DURATIONS")

    def tearDown(self):
        if self._env is None:
            os.environ.pop("FORGE_DURATIONS", None)
        else:
            os.environ["FORGE_DURATIONS"] = self._env

    def test_the_store_is_a_sidecar_of_the_ENGAGEMENT_ledger(self):
        led = self.dir / "engagement-42.jsonl"
        st = DurationStore.for_ledger(str(led))
        self.assertEqual(st.path, Path(str(led) + ".durations"),
                         "le magasin doit vivre À CÔTÉ du ledger de SON engagement (comme .hwm), "
                         "donc être supprimé avec lui — jamais un état global sous $HOME")

    def test_no_ledger_means_no_file_at_all(self):
        """CLI directe / tests : aucun fichier n'apparaît, et le moteur retombe sur `cost`."""
        self.assertIsNone(DurationStore.for_ledger(None))
        self.assertIsNone(DurationStore.for_ledger(""))
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_the_kill_switch_disables_the_store_entirely(self):
        for off in ("0", "off", "false", "NO"):
            with self.subTest(value=off):
                os.environ["FORGE_DURATIONS"] = off
                self.assertIsNone(DurationStore.for_ledger(str(self.dir / "x.jsonl")))
        os.environ["FORGE_DURATIONS"] = "1"
        self.assertIsNotNone(DurationStore.for_ledger(str(self.dir / "x.jsonl")))

    def test_two_engagements_never_see_each_others_durations(self):
        a, b = self.dir / "engagement-1.jsonl", self.dir / "engagement-2.jsonl"
        sa = DurationStore.for_ledger(str(a))
        for _ in range(DurationStore.MIN_SAMPLES):
            sa.record("web.nuclei", 9.0)
        sa.save()
        sb = DurationStore.for_ledger(str(b))
        self.assertIsNone(sb.estimate("web.nuclei"), "aucune fuite d'un engagement vers l'autre")
        self.assertEqual(DurationStore.load(str(a) + ".durations").estimate("web.nuclei"), 9.0)

    def test_a_second_run_MERGES_instead_of_overwriting(self):
        led = str(self.dir / "engagement-3.jsonl")
        first = DurationStore.for_ledger(led)
        for _ in range(DurationStore.MIN_SAMPLES):
            first.record("web.nuclei", 1.0)
        first.save()
        second = DurationStore.for_ledger(led)
        self.assertEqual(second.estimate("web.nuclei"), 1.0)     # le run 2 profite du run 1
        for _ in range(DurationStore.MIN_SAMPLES):
            second.record("recon.httpx", 0.2)
        second.save()
        third = DurationStore.load(led + ".durations")
        self.assertEqual(third.estimate("web.nuclei"), 1.0)
        self.assertEqual(third.estimate("recon.httpx"), 0.2)
        self.assertEqual(third._disk["web.nuclei"].n, DurationStore.MIN_SAMPLES)

    def test_a_missing_or_corrupt_or_unreadable_store_is_INERT(self):
        """Un cache de performance ne casse JAMAIS un run : chaque avarie rend un magasin muet, donc
        le repli `cost`, sans exception."""
        cases = {"absent": None, "vide": "", "binaire": "\x00\x01\x02", "json-invalide": "{",
                 "mauvaise-version": '{"v": 999, "kinds": {"web.nuclei": {"n": 9, "s": [1.0]}}}',
                 "kinds-liste": '{"v": 1, "kinds": [1, 2, 3]}',
                 "n-non-entier": '{"v": 1, "kinds": {"web.nuclei": {"n": "beaucoup", "s": [1.0]}}}',
                 "durees-absurdes": '{"v": 1, "kinds": {"web.nuclei": {"n": 9, "s": [-1, 1e9, null]}}}'}
        for name, content in cases.items():
            with self.subTest(case=name):
                p = self.dir / f"{name}.durations"
                if content is not None:
                    p.write_text(content, encoding="utf-8")
                st = DurationStore.load(p)
                self.assertEqual(st.observed_kinds(), 0)
                self.assertIsNone(st.estimate("web.nuclei"))
                self.assertEqual(Engine(_scope(), mode="auto", durations=st)
                                 ._preheat_key(Action("web.nuclei", _FAST[0], cost=2.0)), 2.0)

    def test_saving_to_an_impossible_path_returns_False_without_raising(self):
        st = DurationStore(self.dir / "nope" / "\x00bad" / "s.durations")
        st.record("web.nuclei", 1.0)
        self.assertFalse(st.save())

    def test_saving_nothing_writes_nothing(self):
        p = self.dir / "untouched.durations"
        self.assertTrue(DurationStore(p).save())
        self.assertFalse(p.exists(), "un run sans tir ne doit pas créer de fichier")


# =====================================================================================================
# 7. CE QUI EST MESURÉ — le tir, et seulement lui
# =====================================================================================================
class TestOnlyRealFiresAreMeasured(unittest.TestCase):
    """`dry()` est SANS effet de bord par contrat, donc quasi instantané. Le chronométrer
    EMPOISONNERAIT le magasin : une campagne non armée apprendrait que `web.testssl` prend 3 ms, et le
    run armé suivant ne le préchaufferait plus. Seul le TIR est mesuré."""

    def setUp(self):
        self._env = os.environ.get("FORGE_PARALLELISM")
        os.environ["FORGE_PARALLELISM"] = "4"

    def tearDown(self):
        if self._env is None:
            os.environ.pop("FORGE_PARALLELISM", None)
        else:
            os.environ["FORGE_PARALLELISM"] = self._env

    def _play(self, armed):
        store = DurationStore()
        with _Swap(self, [_KIND_SLOW]):
            eng = Engine(_scope(), mode="auto", durations=store)
            if armed:
                eng.arm("test mesure")
            eng.run([Action(_KIND_SLOW, ip) for ip in _SLOW])
        return store

    def test_a_dry_run_records_NOTHING(self):
        self.assertEqual(self._play(armed=False)._pending, {},
                         "une campagne non armée ne doit rien apprendre au magasin")

    def test_an_armed_run_records_the_fires(self):
        """Contrôle POSITIF : sans lui, le test ci-dessus passerait aussi sur une instrumentation morte."""
        pending = self._play(armed=True)._pending
        self.assertEqual(list(pending), [_KIND_SLOW])
        self.assertEqual(pending[_KIND_SLOW].n, len(_SLOW))

    def test_a_VETOED_action_records_nothing(self):
        """Rien n'est tiré, donc rien n'est mesuré — et surtout aucun 0,0 s qui ferait passer un kind
        lent pour instantané."""
        store = DurationStore()
        with _Swap(self, [_KIND_SLOW]):
            eng = Engine(Scope({"mode": "grey", "in_scope": ["autre.example"]}), mode="auto",
                         durations=store)
            eng.arm("test veto")
            eng.run([Action(_KIND_SLOW, ip) for ip in _SLOW])
        self.assertEqual(store._pending, {})

    def test_a_fire_that_RAISES_is_still_measured(self):
        """Le worker a bien été occupé : la mesure est honnête. La médiane absorbe l'aberration si
        l'échec est minoritaire (cf. `test_the_median_absorbs_one_aberrant_tir`)."""
        class Boom(_Stub):
            def fire(self, action):
                raise RuntimeError("outil absent")

        store = DurationStore()
        with _Swap(self, [_KIND_SLOW], base=Boom):
            eng = Engine(_scope(), mode="auto", durations=store)
            eng.arm("test exception")
            eng.run([Action(_KIND_SLOW, ip) for ip in _SLOW])
        self.assertEqual(store._pending[_KIND_SLOW].n, len(_SLOW))

    def test_MUTATION_measuring_the_dry_path_poisons_the_store(self):
        """PREUVE PAR MUTATION : si l'on chronométrait aussi le DRY-RUN, une campagne non armée
        écrirait des durées quasi nulles pour un kind lent — exactement l'empoisonnement que la
        conception évite. La mutation le montre en enregistrant explicitement sur le chemin dry."""
        store = DurationStore()
        with _Swap(self, [_KIND_SLOW]):
            eng = Engine(_scope(), mode="auto", durations=store)
            for ip in _SLOW * 2:                               # simule un dry-run instrumenté
                eng._record_duration(_KIND_SLOW, 0.0003)
        poisoned = DurationStore(None, store._pending)
        self.assertEqual(poisoned.estimate(_KIND_SLOW), _quantize(0.0003))
        self.assertLess(poisoned.estimate(_KIND_SLOW), 0.01,
                        "un magasin nourri au dry-run croit qu'un kind lent est instantané — c'est "
                        "précisément pourquoi `_decide_blocking` ne chronomètre QUE le tir")


if __name__ == "__main__":
    unittest.main(verbosity=2)
