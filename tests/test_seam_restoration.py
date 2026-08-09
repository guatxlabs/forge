# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEAMS DE TEST — la restauration d'un seam monkeypatché doit reposer le DESCRIPTEUR, pas sa valeur.

LE DÉFAUT. Le motif employé par la suite pour patcher un seam d'oracle était :

    orig = Cls._fetch                 # <- LECTURE D'ATTRIBUT : rend la FONCTION, pas le descripteur
    Cls._fetch = staticmethod(fn)
    ...
    Cls._fetch = orig                 # <- « restauration » : repose une FONCTION NUE

Reposer une fonction nue sur une classe en fait une MÉTHODE D'INSTANCE. Tout appel ultérieur au VRAI
seam via une instance (`self._fetch(url, headers)`) reçoit alors `self` en 1er positionnel, décale
tous les autres, et `Oracle._http` reçoit l'URL dans `headers` -> `ValueError: dictionary update
sequence element #0 has length 1; 2 is required`. Le décalage est SILENCIEUX tant que personne ne
rappelle le vrai seam après une restauration — d'où une pollution latente, CROISÉE entre fichiers et
sensible à l'ordre d'exécution.

DEUX FORMES, selon que la classe POSSÈDE le seam ou en HÉRITE :
  - `SecurityHeaders`/`AuthTakeover`/`CorsCredentials` POSSÈDENT `_fetch` (`@staticmethod`) : la
    restauration fautive DÉGRADE le descripteur en fonction nue -> décalage d'arguments (le cas dur) ;
  - la plupart des oracles en HÉRITENT (`Oracle._fetch`, `_ContentTypedOracle._fetch`,
    `ClientFlowOracle._fetch`) : la restauration fautive pose sur la SOUS-CLASSE un RÉSIDU qui masque
    le descripteur hérité — fonction nue (héritage d'un `staticmethod` -> même décalage) ou méthode
    déjà liée (héritage d'un `classmethod` -> `cls` figé sur la mauvaise classe).

LE CORRECTIF, par site : lire le DESCRIPTEUR BRUT et retirer l'override quand il était HÉRITÉ ::

    had  = "_fetch" in cls.__dict__
    orig = cls.__dict__.get("_fetch")     # DESCRIPTEUR (staticmethod/classmethod), pas fonction
    cls._fetch = staticmethod(fn)
    ...
    cls._fetch = orig if had else delattr(cls, "_fetch")

C'est déjà l'idiome de 8 fichiers de la suite (`test_authrace_oracles`, `test_tokenapi_oracles`,
`test_clientflow_oracles`, `test_chaining`, `test_recon_active`, `test_recon_surface`,
`test_pentest_registry`, `test_injection_protocol_oracles`) : le correctif ALIGNE, il n'invente pas.

CE QUE CE FICHIER APPORTE — trois niveaux, du mécanisme au garde-fou :

1. `TestFaultyMotifBreaksTheSeam` — reproduit le mécanisme sur le VRAI seam de production
   (`SecurityHeaders._fetch`) : le motif fautif casse l'appel, le motif correct ne le casse pas.
   Ce test passait déjà AVANT le correctif : il documente et VERROUILLE le « pourquoi ».

2. `TestEverySeamSiteRestoresFaithfully` — pilote CHAQUE site de la suite (helper appelé
   directement, ou test porteur exécuté) et vérifie qu'aucun descripteur de `forge/` n'a été dégradé
   ni masqué. C'est le contrôle qui ÉCHOUAIT AVANT le correctif et qui passe APRÈS.

3. `TestSuiteHasNoRawDescriptorRestore` — le GARDE-FOU : un balayage AST de `tests/` qui REFUSE le
   motif. Un helper partagé serait contournable en copiant-collant le motif brut — c'est exactement
   ainsi que les 18 sites sont apparus ; un contrôle qui ROUGIT ne l'est pas. Sa propre preuve par
   MUTATION est dans `TestGuardrailBites`.

L'INVARIANT MESURÉ (niveaux 1-2) est adossé à la SOURCE de `forge/` (AST) et non aux objets déjà
chargés : une pollution installée par un module exécuté plus tôt dans la session ne peut donc pas
rendre ces contrôles vacueux. Ses deux exceptions (dunders synthétisés par `Enum`, et un `def` nu qui
masque DÉLIBÉRÉMENT un descripteur hérité — `SecurityHeaders._curl`) sont mesurées, pas supposées :
`test_invariant_is_clean_on_a_pristine_import` les épingle.
"""
import ast
import importlib
import io
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests._dns import setUpModule, tearDownModule            # noqa: F401,E402
from forge.modules import registry                            # noqa: E402
from forge.modules.injection import SstiEval                  # noqa: E402
from forge.modules.oracle import Oracle                       # noqa: E402
from forge.modules.security_headers import SecurityHeaders    # noqa: E402

REPO = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO / "tests"
FORGE_DIR = REPO / "forge"

_DESCRIPTORS = ("staticmethod", "classmethod")

#: seul fichier autorisé à ÉCRIRE le motif fautif : celui qui le démontre (ci-dessous). L'exemption
#: est nominative et vérifiée (`test_the_only_exempt_file_is_this_one`) — pas une porte de sortie.
_GUARDRAIL_EXEMPT = frozenset({"test_seam_restoration.py"})


# =================================================================================================
# Carte de référence : ce que la SOURCE de `forge/` déclare, classe par classe.
# =================================================================================================
def _source_members():
    """{(module_pointé, Classe): {attr: "staticmethod"|"classmethod"|"plain"}} pour tout `forge/`.

    Les ALIAS de classe (`_fetch = _fetch_body`, cf. `Oracle`) héritent du genre de leur cible : sans
    ça, le seam le plus patché de la suite serait invisible pour l'invariant.
    """
    members = {}
    for path in sorted(FORGE_DIR.rglob("*.py")):
        dotted = ".".join(path.relative_to(REPO).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in tree.body:                                  # classes de PREMIER niveau
            if not isinstance(node, ast.ClassDef):
                continue
            attrs = {}
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = "plain"
                    for deco in member.decorator_list:
                        if isinstance(deco, ast.Name) and deco.id in _DESCRIPTORS:
                            kind = deco.id
                    attrs[member.name] = kind
                elif isinstance(member, ast.Assign) and isinstance(member.value, ast.Name):
                    aliased = attrs.get(member.value.id)         # `_fetch = _fetch_body`
                    for target in member.targets:
                        if isinstance(target, ast.Name) and aliased:
                            attrs[target.id] = aliased
            members[(dotted, node.name)] = attrs
    return members


SOURCE = _source_members()
#: alphabet du garde-fou : tout nom d'attribut que `forge/` porte via un descripteur.
SEAM_ATTR_NAMES = frozenset(a for attrs in SOURCE.values()
                            for a, k in attrs.items() if k in _DESCRIPTORS)


def _forge_classes():
    """Toutes les classes `forge` vivantes, y compris celles GÉNÉRÉES au runtime (registry outils)."""
    roots = set()
    for name, module in list(sys.modules.items()):
        if not name.startswith("forge") or module is None:
            continue
        for attr in dir(module):
            obj = getattr(module, attr, None)
            if isinstance(obj, type) and getattr(obj, "__module__", "").startswith("forge"):
                roots.add(obj)
    for obj in registry.REGISTRY.values():
        roots.add(obj if isinstance(obj, type) else type(obj))
    seen, stack = set(), list(roots)
    while stack:                                                 # + sous-classes transitives
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        stack.extend(cls.__subclasses__())
    return seen


def _declared_on(cls, attr):
    """Genre déclaré pour `attr` DANS LA SOURCE de `cls` elle-même, ou None si `cls` ne le déclare pas."""
    attrs = SOURCE.get((getattr(cls, "__module__", ""), getattr(cls, "__qualname__", "")))
    return attrs.get(attr) if attrs else None


_DESCRIPTOR_TYPES = (staticmethod, classmethod)
#: ce qu'une restauration fautive laisse derrière elle : une fonction NUE (le `staticmethod` a été
#: déréférencé) ou une méthode DÉJÀ LIÉE (le `classmethod` a été déréférencé).
_BARE_CALLABLES = (types.FunctionType, types.MethodType)


def _inherited_descriptor(cls, attr):
    """Descripteur que `cls` HÉRITE pour `attr` (le premier trouvé en remontant la MRO), ou None."""
    for ancestor in cls.__mro__[1:]:
        if attr in vars(ancestor):
            value = vars(ancestor)[attr]
            return value if isinstance(value, _DESCRIPTOR_TYPES) else None
    return None


def _degraded():
    """Seams dont l'état RUNTIME contredit la déclaration source — le résidu d'une restauration fautive.

    (a) DÉGRADATION : `cls` déclare l'attribut `@staticmethod`/`@classmethod` mais porte autre chose ;
    (b) MASQUAGE   : `cls` ne le déclare PAS en source, porte une fonction nue / méthode déjà liée,
        et masque ainsi un descripteur hérité.
    Exceptions : les dunders (`Enum` synthétise `__new__`) et tout attribut que la source de `cls`
    déclare en `def` nu (masquage DÉLIBÉRÉ, ex. `SecurityHeaders._curl`).
    """
    bad = []
    for cls in _forge_classes():
        for attr, value in list(vars(cls).items()):
            if attr.startswith("__") and attr.endswith("__"):
                continue
            declared = _declared_on(cls, attr)
            if declared in _DESCRIPTORS:
                want = staticmethod if declared == "staticmethod" else classmethod
                if not isinstance(value, want):
                    bad.append(f"{cls.__name__}.{attr} : déclaré {declared}, "
                               f"trouvé {type(value).__name__}")
            elif declared is None and isinstance(value, _BARE_CALLABLES):
                inherited = _inherited_descriptor(cls, attr)
                if inherited is not None:
                    bad.append(f"{cls.__name__}.{attr} : {type(value).__name__} nue masquant un "
                               f"{type(inherited).__name__} hérité")
    return sorted(set(bad))


def _normalize():
    """Repose l'état sain : ré-enveloppe une dégradation, retire un masquage. Renvoie les réparations.

    Idempotent, et SANS EFFET quand la suite est saine (le cas APRÈS correctif). Ce n'est pas un
    contournement : les contrôles ci-dessous comparent l'état APRÈS le pilotage d'un site à un état de
    départ normalisé, pour qu'une pollution héritée d'un module exécuté plus tôt ne les fausse pas.
    """
    repaired = []
    for cls in _forge_classes():
        for attr, value in list(vars(cls).items()):
            if attr.startswith("__") and attr.endswith("__"):
                continue
            declared = _declared_on(cls, attr)
            if declared in _DESCRIPTORS:
                want = staticmethod if declared == "staticmethod" else classmethod
                if isinstance(value, want):
                    continue
                raw = value.__func__ if isinstance(value, types.MethodType) else value
                if callable(raw):
                    setattr(cls, attr, want(raw))
                    repaired.append(f"{cls.__name__}.{attr} (ré-enveloppé)")
            elif declared is None and isinstance(value, _BARE_CALLABLES) \
                    and _inherited_descriptor(cls, attr) is not None:
                delattr(cls, attr)                    # retire le résidu -> l'héritage redevient visible
                repaired.append(f"{cls.__name__}.{attr} (résidu retiré)")
    return repaired


class _FakeResp:
    """Réponse minimale pour le seam bas-niveau `Oracle._raw_open` (aucun paquet n'est émis)."""

    status = 200
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=None):
        return b"ok"


class _raw_open:
    """Contexte : substitue `Oracle._raw_open` PROPREMENT (descripteur brut) et le repose tel quel."""

    def __enter__(self):
        self._orig = Oracle.__dict__["_raw_open"]
        Oracle._raw_open = staticmethod(lambda req, timeout=15: _FakeResp())
        return self

    def __exit__(self, *a):
        Oracle._raw_open = self._orig
        return False


# =================================================================================================
# 1. Le mécanisme, sur le vrai seam de production.
# =================================================================================================
class TestFaultyMotifBreaksTheSeam(unittest.TestCase):
    """Pourquoi `orig = Cls._fetch` est faux — démontré, pas raisonné."""

    def setUp(self):
        _normalize()
        self.addCleanup(_normalize)

    def test_invariant_is_clean_on_a_pristine_import(self):
        """Contrôle NÉGATIF de l'invariant : sans pollution, il ne signale rien. Sinon tout le reste
        de ce fichier serait du bruit — et ses exceptions (Enum `__new__`, `SecurityHeaders._curl`)
        seraient des suppositions au lieu de mesures."""
        self.assertEqual(_normalize(), [], "état de départ déjà pollué après normalisation")
        self.assertEqual(_degraded(), [])
        self.assertIn("_fetch", SEAM_ATTR_NAMES)
        self.assertIn("_raw_open", SEAM_ATTR_NAMES)
        self.assertGreater(len(SOURCE), 50, "carte source vide -> contrôles vacueux")

    def test_attribute_read_save_rebuilds_an_instance_method(self):
        orig = SecurityHeaders._fetch                      # LE MOTIF FAUTIF : lecture d'attribut
        SecurityHeaders._fetch = staticmethod(lambda url, headers=None, timeout=15: (200, "", {}))
        SecurityHeaders._fetch = orig                      # « restauration »

        left = SecurityHeaders.__dict__["_fetch"]
        self.assertIsInstance(left, types.FunctionType,
                              "le motif fautif est censé laisser une FONCTION NUE sur la classe")
        self.assertNotIsInstance(left, staticmethod)
        self.assertEqual(len(_degraded()), 1, "l'invariant doit VOIR cette dégradation")
        # conséquence OBSERVABLE : l'attribut se lie à l'instance -> décalage d'arguments.
        self.assertIsNot(SecurityHeaders()._fetch, SecurityHeaders._fetch)
        with self.assertRaises(ValueError):
            SecurityHeaders()._fetch("http://127.0.0.1/x", {})

    def test_descriptor_save_keeps_the_seam_callable(self):
        orig = SecurityHeaders.__dict__["_fetch"]          # LE CORRECTIF : descripteur brut
        SecurityHeaders._fetch = staticmethod(lambda url, headers=None, timeout=15: (200, "", {}))
        SecurityHeaders._fetch = orig

        self.assertIsInstance(SecurityHeaders.__dict__["_fetch"], staticmethod)
        self.assertIs(SecurityHeaders()._fetch, SecurityHeaders._fetch)
        self.assertEqual(_degraded(), [])
        with _raw_open():
            status, body, _headers = SecurityHeaders()._fetch("http://127.0.0.1/x", {})
        self.assertEqual((status, body), (200, "ok"))


# =================================================================================================
# 2. Chaque site de la suite, piloté puis mesuré.
# =================================================================================================
#: helpers de patch de niveau MODULE : (module, nom du helper, le helper prend-il `cls` ?).
#: Les helpers `(cls, fn)` sont génériques en `cls` — on leur passe un oracle de production réel.
_HELPER_SITES = (
    ("tests.test_security_headers", "_patch", False),
    ("tests.test_auth_context", "_patch_fetch", False),
    ("tests.test_ato_auth_context", "_patch_fetch", False),
    ("tests.test_ato_signals_r7", "_patch_fetch", False),
    ("tests.test_auth_material_dead", "_patch", True),
    ("tests.test_finding_redaction_and_soundness", "_patch", True),
    ("tests.test_g1_injectable_endpoint_chain", "_patch_fetch", True),
    ("tests.test_injection_oracles", "_patch", True),
    ("tests.test_oracles", "_patch", True),
    ("tests.test_refactor_equivalence", "_patch", True),
    ("tests.test_schema_fix", "_patch", True),
    ("tests.test_unreachable_no_verdict", "_patch", True),
)

#: classes passées aux helpers `(cls, fn)` : une qui POSSÈDE le seam, une qui en HÉRITE — les deux
#: formes du défaut (dégradation de descripteur / résidu masquant) sont donc exercées à chaque site.
_HELPER_CLASSES = (SecurityHeaders, SstiEval)

#: sites INLINE (motif écrit dans le corps d'un test ou d'un helper de méthode) : on exécute le test
#: porteur, ce qui exerce le round-trip patch/restore exactement comme la suite le fait.
_METHOD_SITES = (
    "tests.test_p2b.TestIdorOracleDifferential.test_vulnerable_when_b_reads_a_and_anon_refused",
    "tests.test_p2b.TestIdorOracleDifferential.test_write_method_effect_oracle",
    "tests.test_p2b.TestIdorOracleDifferential.test_write_method_not_mutated_is_tested",
    "tests.test_p2b.TestIdorOracleDifferential.test_write_method_fail_closed_without_destructive",
    "tests.test_llm_payload_enrich_r6.TestSstiConsumesLlmPayloads.test_llm_payloads_appear_in_tested_set",
    "tests.test_rate_limit.TestHttpThrottleAndBackoff.test_http_throttles_between_requests",
    "tests.test_refactor_equivalence.TestSharedHttpWiring.test_success_shapes",
    "tests.test_engine_durations.TestStoreNeverIdentifiesATarget."
    "test_MUTATION_dropping_the_kind_guard_lets_a_target_in",
)


def _noop_fetch(*a, **k):
    return (200, "", {})


class TestEverySeamSiteRestoresFaithfully(unittest.TestCase):
    """AUCUN site de patch de la suite ne doit laisser un descripteur dégradé ou masqué derrière lui."""

    def setUp(self):
        _normalize()
        self.addCleanup(_normalize)

    def _assert_no_degradation(self, label, drive):
        _normalize()                                   # plan de mesure remis à zéro
        self.assertEqual(_degraded(), [], f"{label} : normalisation impossible — mesure invalide")
        drive()
        self.assertEqual(
            _degraded(), [],
            f"{label} : seam laissé dans un état non déclaré après restauration.\n"
            f"    Corriger le site : `orig = Cls.__dict__.get(\"<attr>\")` (descripteur) + `delattr` "
            f"si l'attribut était HÉRITÉ — jamais `orig = Cls.<attr>` (fonction résolue).")

    def test_module_level_patch_helpers(self):
        for module_name, helper_name, takes_cls in _HELPER_SITES:
            module = importlib.import_module(module_name)
            helper = getattr(module, helper_name)
            for cls in (_HELPER_CLASSES if takes_cls else (None,)):
                label = f"{module_name}.{helper_name}" + (f" [{cls.__name__}]" if cls else "")
                with self.subTest(site=label):
                    def drive(helper=helper, cls=cls):
                        restore = helper(_noop_fetch) if cls is None else helper(cls, _noop_fetch)
                        restore()

                    self._assert_no_degradation(label, drive)

    def test_inline_patch_sites(self):
        for test_id in _METHOD_SITES:
            with self.subTest(site=test_id):
                def drive(test_id=test_id):
                    suite = unittest.defaultTestLoader.loadTestsFromName(test_id)
                    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
                    # non-vacuité : un test porteur qui ne tourne pas (ou casse) ne prouve rien.
                    self.assertEqual(result.testsRun, 1, f"{test_id} n'a pas été exécuté")
                    self.assertTrue(result.wasSuccessful(),
                                    f"{test_id} a échoué : {result.errors or result.failures}")

                self._assert_no_degradation(test_id, drive)


# =================================================================================================
# 3. Le garde-fou : balayage AST de `tests/`.
# =================================================================================================
def _attr_write(node):
    """(attribut, valeur) si `node` écrit un attribut (`X.a = v` / `setattr(X, "a", v)`), sinon None."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Attribute):
        return node.targets[0].attr, node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr" \
            and len(node.args) == 3 and isinstance(node.args[1], ast.Constant) \
            and isinstance(node.args[1].value, str):
        return node.args[1].value, node.args[2]
    return None


def _wraps_descriptor(node):
    """True si `node` est `staticmethod(...)` / `classmethod(...)` — une restauration qui ré-enveloppe."""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in _DESCRIPTORS)


def _save_key(target):
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return "." + target.attr                       # `self._saved_raw = Oracle._raw_open`
    return None


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _in_scope(node):
    """Nœuds du corps de `node` SANS descendre dans les scopes imbriqués (fonctions/lambdas/classes)."""
    def walk(child):
        yield child
        if isinstance(child, _SCOPES):
            return                                     # nouveau scope -> traité séparément
        for sub in ast.iter_child_nodes(child):
            yield from walk(sub)

    for child in ast.iter_child_nodes(node):
        yield from walk(child)


def _nested_scopes(node):
    return [n for n in _in_scope(node) if isinstance(n, _SCOPES)]


def _saved_attr(value):
    """Attribut sauvegardé par LECTURE (`Cls.attr` / `getattr(Cls, "attr")`), sinon None.

    `cls.__dict__["attr"]` / `.get("attr")` ne passent pas par ici : ce sont des Subscript/Call sur
    `__dict__`, c'est-à-dire la forme CORRECTE — le garde-fou ne doit surtout pas la signaler.
    """
    if isinstance(value, ast.Attribute):                               # orig = Cls.attr
        return value.attr
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
            and value.func.id == "getattr" and len(value.args) >= 2 \
            and isinstance(value.args[1], ast.Constant):               # orig = getattr(Cls, "attr")
        return value.args[1].value
    return None


def scan_source(source, label):
    """Sites « sauvegarde par LECTURE D'ATTRIBUT + restauration BRUTE » d'un attribut à descripteur.

    Alphabet surveillé : les attributs que `forge/` porte via un descripteur, plus ceux que CE
    fichier remplace par `staticmethod(...)`/`classmethod(...)` (une classe de test peut avoir son
    propre seam). NE SONT PAS signalés — parce qu'ils sont corrects : une sauvegarde via
    `cls.__dict__[...]`, et une restauration qui ré-enveloppe (`setattr(C, "a", staticmethod(orig))`).

    L'analyse est LEXICALE (un scope + ses englobants), pas globale au fichier : sans ça, un fichier
    où coexistent un helper CORRIGÉ et un helper fautif partageant le nom `orig` verrait le helper
    corrigé signalé à tort. Seules les sauvegardes sur ATTRIBUT D'INSTANCE (`self._saved = ...`) sont
    suivies à l'échelle du fichier — elles traversent les méthodes (`_patch_raw` -> `tearDown`).
    """
    tree = ast.parse(source, label)

    seam_attrs = set(SEAM_ATTR_NAMES)
    for node in ast.walk(tree):
        write = _attr_write(node)
        if write and _wraps_descriptor(write[1]):
            seam_attrs.add(write[0])

    def saves_in(scope):
        """{clé: [(ligne, attribut), ...]} pour les sauvegardes par lecture faites DANS ce scope."""
        found = {}
        for node in _in_scope(scope):
            if not isinstance(node, ast.Assign):
                continue
            if isinstance(node.value, ast.Tuple) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Tuple):
                pairs = list(zip(node.targets[0].elts, node.value.elts))
            else:
                pairs = [(t, node.value) for t in node.targets]
            for target, value in pairs:
                attr, key = _saved_attr(value), _save_key(target)
                if attr in seam_attrs and key:
                    found.setdefault(key, []).append((node.lineno, attr))
        return found

    #: sauvegardes sur attribut d'instance — portée FICHIER (elles franchissent les méthodes).
    instance_saves = {k: v for k, v in
                      {kk: vv for scope in [tree] + [n for n in ast.walk(tree)
                                                     if isinstance(n, _SCOPES)]
                       for kk, vv in saves_in(scope).items()}.items() if k.startswith(".")}

    violations = []

    def visit(scope, visible):
        visible = dict(visible)
        for key, entries in saves_in(scope).items():
            visible.setdefault(key, []).extend(entries)          # closure : le scope voit ses parents
        for node in _in_scope(scope):
            write = _attr_write(node)
            if not write:
                continue
            attr, value = write
            key = _save_key(value) if isinstance(value, (ast.Name, ast.Attribute)) else None
            if key is None:
                continue                               # staticmethod(orig), lambda, littéral -> sain
            lines = [ln for ln, a in visible.get(key, ()) if a == attr]
            if not lines:
                continue
            before = [ln for ln in lines if ln <= node.lineno]
            violations.append({"file": label, "restore_line": node.lineno, "attr": attr,
                               "save_line": max(before) if before else min(lines)})
        for nested in _nested_scopes(scope):
            visit(nested, visible)

    visit(tree, instance_saves)
    return sorted(violations, key=lambda v: v["restore_line"])


def scan_paths(paths):
    out = []
    for path in paths:
        out.extend(scan_source(Path(path).read_text(encoding="utf-8"), str(path)))
    return out


def _guardrail_targets():
    return [p for p in sorted(TESTS_DIR.glob("*.py")) if p.name not in _GUARDRAIL_EXEMPT]


_FAULTY_MUTANT = '''
class Probe:
    @staticmethod
    def _fetch(url, headers=None):
        return None

def patch(fn):
    orig = Probe._fetch
    Probe._fetch = staticmethod(fn)
    return lambda: setattr(Probe, "_fetch", orig)
'''

_CORRECT_MUTANT = _FAULTY_MUTANT.replace("orig = Probe._fetch", 'orig = Probe.__dict__["_fetch"]')


class TestSuiteHasNoRawDescriptorRestore(unittest.TestCase):
    """GARDE-FOU. Le motif fautif est refusé PARTOUT dans `tests/`, pas seulement là où on l'a corrigé.

    Pourquoi un contrôle plutôt qu'un helper partagé : les 18 sites d'origine sont nés d'un
    copier-coller du motif brut. Un helper n'aurait rien empêché — il suffit de ne pas s'en servir.
    Un test qui rougit, lui, arrête le prochain copier-coller au moment où il est écrit.
    """

    def test_no_test_file_saves_a_descriptor_by_attribute_read(self):
        violations = scan_paths(_guardrail_targets())
        detail = "\n".join(f"  {Path(v['file']).name}: sauvegarde L{v['save_line']} -> restauration "
                           f"brute L{v['restore_line']} de `{v['attr']}`" for v in violations)
        self.assertEqual(
            violations, [],
            "Motif de restauration fautif détecté (la lecture d'attribut rend la FONCTION, pas le "
            "descripteur ; la reposer en fait une méthode d'instance et décale tous les arguments "
            "du seam) :\n" + detail + "\n\nForme correcte :\n"
            '    had  = "<attr>" in cls.__dict__\n'
            '    orig = cls.__dict__.get("<attr>")        # DESCRIPTEUR, pas fonction résolue\n'
            "    cls.<attr> = staticmethod(fn)\n"
            "    ...\n"
            '    cls.<attr> = orig if had else delattr(cls, "<attr>")\n')

    def test_the_only_exempt_file_is_this_one(self):
        """L'exemption ne doit jamais devenir une porte de sortie pour un vrai site."""
        self.assertEqual(set(_GUARDRAIL_EXEMPT), {Path(__file__).name})
        self.assertGreater(len(_guardrail_targets()), 90, "le balayage ne couvre presque rien")


class TestGuardrailBites(unittest.TestCase):
    """PREUVE PAR MUTATION du garde-fou : réintroduire le motif fautif doit le faire rougir."""

    def test_faulty_motif_is_reported(self):
        violations = scan_source(_FAULTY_MUTANT, "<mutant-fautif>")
        self.assertEqual(len(violations), 1, f"le garde-fou ne mord pas : {violations}")
        self.assertEqual(violations[0]["attr"], "_fetch")

    def test_correct_motif_is_not_reported(self):
        self.assertEqual(scan_source(_CORRECT_MUTANT, "<mutant-correct>"), [],
                         "le garde-fou signale la forme CORRECTE — il serait inutilisable")

    def test_rewrapped_restore_is_not_reported(self):
        source = _FAULTY_MUTANT.replace('setattr(Probe, "_fetch", orig)',
                                        'setattr(Probe, "_fetch", staticmethod(orig))')
        self.assertEqual(scan_source(source, "<mutant-ré-enveloppé>"), [],
                         "une restauration qui ré-enveloppe repose bien un descripteur")

    def test_self_attribute_save_is_reported(self):
        """La variante « sauvegarde sur `self` » (celle de `test_rate_limit`) doit mordre aussi."""
        source = ("import x\n"
                  "class T:\n"
                  "    def p(self, fn):\n"
                  "        self._saved = x.Oracle._raw_open\n"
                  "        x.Oracle._raw_open = staticmethod(fn)\n"
                  "    def tearDown(self):\n"
                  "        x.Oracle._raw_open = self._saved\n")
        violations = scan_source(source, "<mutant-self>")
        self.assertEqual(len(violations), 1, f"variante `self.` non détectée : {violations}")

    def test_mutating_a_real_suite_file_is_caught(self):
        """Injecté dans une COPIE d'un VRAI fichier de la suite, le motif ajoute exactement 1 violation."""
        real_path = TESTS_DIR / "test_oracles.py"
        real = real_path.read_text(encoding="utf-8")
        baseline = len(scan_source(real, str(real_path)))
        mutant = real + ("\n\ndef _mutant_patch(cls, fn):\n"
                         "    orig = cls._fetch\n"
                         "    cls._fetch = staticmethod(fn)\n"
                         "    return lambda: setattr(cls, '_fetch', orig)\n")
        self.assertEqual(len(scan_source(mutant, "<copie-mutée>")), baseline + 1,
                         "la mutation d'un fichier réel n'a pas rougi")


if __name__ == "__main__":
    unittest.main()
