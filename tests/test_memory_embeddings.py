# SPDX-License-Identifier: AGPL-3.0-or-later
"""Backend mémoire à EMBEDDINGS — gouvernance de l'egress, dégradation gracieuse, dedup sémantique.

`forge/memory_faiss.py` existait mais n'était exercé par AUCUN test : `sentence-transformers` est une
dépendance lourde, absente de la CI, donc son import échouait et seul le REPLI était couvert. 61 lignes
de code mort à la vérification. Ces tests l'exercent HERMÉTIQUEMENT, en injectant un encodeur FACTICE
dans `sys.modules` — zéro réseau, zéro dépendance lourde, zéro téléchargement de modèle.

Ce que le faux encodeur PROUVE et ce qu'il NE PROUVE PAS. Il prouve la PLOMBERIE : que la similarité
consultée est bien celle de l'encodeur, que la fusion est BORNÉE à la même cible, que l'index se
reconstruit depuis le disque, et que les gardes d'egress s'appliquent au chargement du modèle. Il ne
prouve RIEN sur la QUALITÉ sémantique du vrai all-MiniLM-L6-v2 — aucun test hermétique ne le peut.

Gardes prouvées (chacune vérifiée par mutation) :
  (1) DÉFAUT STDLIB  : `mode='auto'` ne TENTE MÊME PAS le backend — aucun encodeur n'est construit ;
  (2) OPT-IN         : seul `mode='embeddings'` (alias `'faiss'`) l'active ;
  (3) EGRESS GATÉ    : le modèle est chargé sous HF_HUB_OFFLINE/TRANSFORMERS_OFFLINE, sauf opt-in
                       `allow_download=True` — un modèle non caché DÉGRADE au lieu de télécharger ;
  (4) ENV RESTAURÉ   : l'environnement du processus revient exactement à son état antérieur ;
  (5) DÉGRADATION    : toute indisponibilité => `JaccardMemory` (stdlib), jamais une exception ;
  (6) CACHE PAR NOM  : deux modèles distincts => deux encodeurs (plus de réutilisation silencieuse) ;
  (7) SANS NUMPY     : le module reste importable sans numpy (le balayage est en Python pur).
"""
import json
import os
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.memory import JaccardMemory, Memory, make_memory   # noqa: E402
from forge.schema import Finding                              # noqa: E402
from tests._tmp import temp_dir                               # noqa: E402

OFFLINE_VARS = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE")

# Dimensions assignées à la PREMIÈRE rencontre d'un jeton, longueur de vecteur FIXE : déterministe et
# SANS COLLISION pour le petit vocabulaire de ces tests (contrairement à un hachage modulo D).
_DIMS: dict = {}
_D = 256

# Le faux encodeur replie quelques jetons sur un synonyme commun. C'est la seule façon, hors du vrai
# modèle, de MONTRER la différence avec le repli Jaccard : « Server-Side Request Forgery » et « SSRF »
# n'ont AUCUN trigramme commun, donc Jaccard ne peut PAS les fusionner, alors qu'un espace vectoriel
# les rapproche. Le faux encodeur simule cette propriété — il ne la démontre pas.
_SYNONYMS = {"server": "ssrf", "side": "ssrf", "request": "ssrf", "forgery": "ssrf"}


def _tokens(text):
    out = []
    for raw in "".join(c if c.isalnum() else " " for c in str(text).lower()).split():
        out.append(_SYNONYMS.get(raw, raw))
    return set(out)


class FakeEncoder:
    """Encodeur DÉTERMINISTE : sac-de-mots binaire L2-normalisé. Le produit scalaire de deux vecteurs
    vaut |A∩B| / sqrt(|A|·|B|) — un cosinus honnête, calculable de tête pour écrire des assertions.

    Il enregistre l'ENVIRONNEMENT vu AU CHARGEMENT : c'est ainsi qu'on prouve que la garde hors-ligne
    est bien active au moment où le vrai modèle irait chercher ses poids sur le réseau.
    """

    constructed = []          # noms de modèles construits, dans l'ordre (compteur d'egress potentiels)
    cached_models = {"all-MiniLM-L6-v2"}      # « déjà dans le cache local » — les autres exigent le réseau

    def __init__(self, name):
        self.name = name
        self.env_at_load = {k: os.environ.get(k) for k in OFFLINE_VARS}
        FakeEncoder.constructed.append(name)
        offline = all(self.env_at_load.get(k) == "1" for k in OFFLINE_VARS)
        if offline and name not in FakeEncoder.cached_models:
            # exactement ce que fait huggingface_hub sous HF_HUB_OFFLINE=1 : il LÈVE au lieu de télécharger.
            raise OSError(f"modèle '{name}' absent du cache local et mode hors-ligne actif")

    def encode(self, text, normalize_embeddings=False):
        vec = [0.0] * _D
        toks = _tokens(text)
        for t in toks:
            vec[_DIMS.setdefault(t, len(_DIMS))] = 1.0
        assert len(_DIMS) < _D, "vocabulaire de test au-delà de la dimension fixe"
        if normalize_embeddings and toks:
            n = len(toks) ** 0.5
            vec = [v / n for v in vec]
        return vec


def _install_fake_encoder(case, factory=FakeEncoder, module_missing=False):
    """Injecte (ou retire) `sentence_transformers` dans `sys.modules` et purge `forge.memory_faiss` pour
    que son import PARESSEUX soit réévalué. Restauré par `addCleanup` quoi qu'il arrive."""
    import forge.memory_faiss as mf

    saved_mod = sys.modules.get("sentence_transformers")
    saved_models = dict(mf._MODELS)
    FakeEncoder.constructed = []

    def restore():
        if saved_mod is None:
            sys.modules.pop("sentence_transformers", None)
        else:
            sys.modules["sentence_transformers"] = saved_mod
        mf._MODELS.clear()
        mf._MODELS.update(saved_models)

    case.addCleanup(restore)
    mf._MODELS.clear()                      # cache vide -> chaque test refait un « chargement » observable
    if module_missing:
        sys.modules.pop("sentence_transformers", None)
        return mf
    mod = types.ModuleType("sentence_transformers")
    mod.SentenceTransformer = factory
    sys.modules["sentence_transformers"] = mod
    return mf


def f(target, title, sev="HIGH"):
    return Finding(target=target, title=title, severity=sev)


# ==================================================================================================
class TestDefaultIsStdlibNoEgress(unittest.TestCase):
    """(1)(2) — le repli stdlib est le DÉFAUT, et il l'est SANS CONDITION."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-emb-def-")
        _install_fake_encoder(self)          # encodeur DISPONIBLE : c'est justement le cas piégeux

    def test_auto_never_constructs_an_encoder(self):
        """Le cas qui motive la garde : `sentence-transformers` se TROUVE installé (pour une autre
        raison), et le mode par défaut bascule en silence sur un backend qui télécharge un modèle.
        `auto` ne doit même pas TENTER l'import."""
        mem = make_memory(self.dir / "m.jsonl", mode="auto")
        self.assertIsInstance(mem, JaccardMemory)
        self.assertEqual(FakeEncoder.constructed, [], "auto a construit un encodeur => egress implicite")

    def test_default_mode_argument_is_auto(self):
        mem = make_memory(self.dir / "m.jsonl")            # aucun mode passé
        self.assertIsInstance(mem, JaccardMemory)
        self.assertEqual(FakeEncoder.constructed, [])

    def test_exact_and_jaccard_modes_untouched(self):
        self.assertIsInstance(make_memory(mode="exact"), Memory)
        self.assertNotIsInstance(make_memory(mode="exact"), JaccardMemory)
        self.assertIsInstance(make_memory(mode="jaccard"), JaccardMemory)
        self.assertEqual(FakeEncoder.constructed, [])

    def test_explicit_optin_activates_backend(self):
        from forge.memory_faiss import EmbeddingMemory
        import forge.memory_faiss as mf
        for mode in ("embeddings", "faiss"):               # 'faiss' = alias historique
            with self.subTest(mode=mode):
                FakeEncoder.constructed = []
                mf._MODELS.clear()                         # chaque mode refait un chargement observable
                mem = make_memory(self.dir / f"{mode}.jsonl", mode=mode)
                self.assertIsInstance(mem, EmbeddingMemory)
                self.assertEqual(FakeEncoder.constructed, ["all-MiniLM-L6-v2"])


# ==================================================================================================
class TestModelLoadEgressGate(unittest.TestCase):
    """(3)(4) — charger un modèle d'embeddings est un EGRESS : hors-ligne par défaut, opt-in explicite."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-emb-egress-")
        self.mf = _install_fake_encoder(self)
        self._saved_env = {k: os.environ.get(k) for k in OFFLINE_VARS}

        def restore_env():
            for k, v in self._saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        self.addCleanup(restore_env)
        for k in OFFLINE_VARS:
            os.environ.pop(k, None)

    def _encoder(self):
        return self.mf._MODELS["all-MiniLM-L6-v2"]

    def test_offline_forced_during_load_by_default(self):
        make_memory(self.dir / "m.jsonl", mode="embeddings")
        self.assertEqual(self._encoder().env_at_load,
                         {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"})

    def test_allow_download_optin_does_not_force_offline(self):
        make_memory(self.dir / "m.jsonl", mode="embeddings", allow_download=True)
        self.assertEqual(self._encoder().env_at_load, {k: None for k in OFFLINE_VARS})

    def test_environment_restored_after_load(self):
        make_memory(self.dir / "m.jsonl", mode="embeddings")
        for k in OFFLINE_VARS:
            self.assertIsNone(os.environ.get(k), f"{k} laissée dans l'environnement du processus")

    def test_preexisting_environment_value_restored_verbatim(self):
        os.environ["HF_HUB_OFFLINE"] = "0"                 # un opérateur l'avait réglée EXPRÈS
        make_memory(self.dir / "m.jsonl", mode="embeddings")
        self.assertEqual(os.environ["HF_HUB_OFFLINE"], "0")

    def test_uncached_model_raises_offline_instead_of_downloading(self):
        """LE test d'egress, au niveau du chargement : modèle ABSENT du cache local.
          - sans opt-in  => la garde hors-ligne est active, le chargement LÈVE (huggingface_hub se
            comporte ainsi sous HF_HUB_OFFLINE=1) : AUCUN téléchargement n'est déclenché ;
          - avec opt-in  => la garde est levée, le chargement aboutit (le réseau était autorisé).
        Le cas `sans opt-in` est celui que `make_memory` traduit en repli Jaccard (test suivant)."""
        with self.assertRaises(OSError):
            self.mf.EmbeddingMemory(self.dir / "o.jsonl", model="modele-jamais-telecharge")
        self.mf._MODELS.clear()
        mem = self.mf.EmbeddingMemory(self.dir / "o.jsonl", model="modele-jamais-telecharge",
                                      allow_download=True)
        self.assertEqual(mem._model.name, "modele-jamais-telecharge")

    def test_uncached_model_falls_back_to_jaccard_via_factory(self):
        """Même scénario, vu du seul point d'entrée de production (`make_memory`) : la dégradation est
        GRACIEUSE — un objet mémoire utilisable, pas une exception qui casse le run."""
        self.mf._MODELS.clear()
        original = self.mf.EmbeddingMemory

        def uncached(path=None, threshold=0.85, model="all-MiniLM-L6-v2", allow_download=False):
            return original(path, threshold=threshold, model="modele-jamais-telecharge",
                            allow_download=allow_download)

        self.mf.EmbeddingMemory = uncached
        self.addCleanup(setattr, self.mf, "EmbeddingMemory", original)
        mem = make_memory(self.dir / "m.jsonl", mode="embeddings")
        self.assertIsInstance(mem, JaccardMemory)
        self.assertTrue(mem.store(f("api.test/x", "SSRF")))          # utilisable immédiatement

    def test_cached_model_is_loaded_once_and_keyed_by_name(self):
        """(6) — le cache était un attribut de CLASSE unique : une 2e instance demandant un AUTRE
        modèle réutilisait silencieusement le PREMIER chargé."""
        FakeEncoder.cached_models = FakeEncoder.cached_models | {"autre-modele"}
        self.addCleanup(setattr, FakeEncoder, "cached_models", {"all-MiniLM-L6-v2"})
        a = self.mf.EmbeddingMemory(self.dir / "a.jsonl")
        b = self.mf.EmbeddingMemory(self.dir / "b.jsonl")            # même modèle -> pas de rechargement
        c = self.mf.EmbeddingMemory(self.dir / "c.jsonl", model="autre-modele")
        self.assertEqual(FakeEncoder.constructed, ["all-MiniLM-L6-v2", "autre-modele"])
        self.assertIs(a._model, b._model)
        self.assertIsNot(a._model, c._model)
        self.assertEqual(c._model.name, "autre-modele")


# ==================================================================================================
class TestGracefulDegradation(unittest.TestCase):
    """(5) — une dépendance absente ou un encodeur qui explose ne casse JAMAIS un run."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-emb-deg-")

    def test_missing_dependency_falls_back(self):
        _install_fake_encoder(self, module_missing=True)
        mem = make_memory(self.dir / "m.jsonl", mode="embeddings")
        self.assertIsInstance(mem, JaccardMemory)
        self.assertTrue(mem.store(f("api.test/x", "SSRF in url parameter")))

    def test_exploding_encoder_falls_back(self):
        class Boom:
            def __init__(self, name):
                raise RuntimeError("modèle corrompu / OOM / torch cassé")

        _install_fake_encoder(self, factory=Boom)
        mem = make_memory(self.dir / "m.jsonl", mode="embeddings")
        self.assertIsInstance(mem, JaccardMemory)

    def test_fallback_threshold_is_bounded_for_jaccard(self):
        """Le seuil 0.85 vise un cosinus d'embeddings ; les trigrammes Jaccard saturent plus bas. Le
        repli DOIT re-borner, sinon la dégradation supprime en pratique toute dedup floue."""
        _install_fake_encoder(self, module_missing=True)
        mem = make_memory(self.dir / "m.jsonl", mode="embeddings", threshold=0.99)
        self.assertLessEqual(mem.threshold, 0.8)


# ==================================================================================================
class TestSemanticDedup(unittest.TestCase):
    """La raison d'être du backend : fusionner ce que la chaîne de caractères ne rapproche pas, sans
    JAMAIS fusionner deux cibles distinctes."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-emb-dedup-")
        self.mf = _install_fake_encoder(self)

    def _mem(self, name="m.jsonl", threshold=0.85):
        return self.mf.EmbeddingMemory(self.dir / name, threshold=threshold)

    def test_merges_a_reformulation_that_jaccard_cannot(self):
        a, b = "SSRF in url parameter", "Server Side Request Forgery in url parameter"
        jac = JaccardMemory(self.dir / "j.jsonl", threshold=0.8)
        self.assertTrue(jac.store(f("api.test/x", a)))
        self.assertTrue(jac.store(f("api.test/x", b)))            # Jaccard : deux findings distincts
        self.assertEqual(jac.stats()["records"], 2)

        emb = self._mem()
        self.assertTrue(emb.store(f("api.test/x", a)))
        self.assertFalse(emb.store(f("api.test/x", b)))           # embeddings : un seul
        self.assertEqual(emb.stats()["records"], 1)

    def test_different_target_never_merged(self):
        m = self._mem()
        self.assertTrue(m.store(f("api.test/orders/1", "IDOR sur la commande")))
        self.assertTrue(m.store(f("api.test/orders/2", "IDOR sur la commande")))
        self.assertEqual(m.stats()["records"], 2)

    def test_different_vulnerability_same_target_not_merged(self):
        m = self._mem()
        self.assertTrue(m.store(f("api.test/x", "SSRF in url parameter")))
        self.assertTrue(m.store(f("api.test/x", "SQL injection in login form")))
        self.assertEqual(m.stats()["records"], 2)

    def test_seen_does_not_store(self):
        m = self._mem()
        m.store(f("api.test/x", "XXE via DOCTYPE"))
        self.assertTrue(m.seen(f("api.test/x", "XXE via DOCTYPE")))
        self.assertFalse(m.seen(f("api.test/y", "XXE via DOCTYPE")))
        self.assertEqual(m.stats()["records"], 1)

    def test_index_rebuilt_from_disk(self):
        self._mem().store(f("api.test/x", "XXE via DOCTYPE"))
        reloaded = self._mem()                                    # relit le JSONL, ré-encode
        self.assertEqual(len(reloaded._vecs), len(reloaded.records))   # index ALIGNÉ sur les records
        self.assertFalse(reloaded.store(f("api.test/x", "XXE via DOCTYPE")))

    def test_threshold_is_honoured(self):
        loose = self._mem("loose.jsonl", threshold=0.1)            # tout se ressemble
        self.assertTrue(loose.store(f("api.test/x", "SSRF in url parameter")))
        self.assertFalse(loose.store(f("api.test/x", "SQL injection in login form")))
        strict = self._mem("strict.jsonl", threshold=1.01)         # rien ne se ressemble
        self.assertTrue(strict.store(f("api.test/x", "SSRF in url parameter")))
        self.assertTrue(strict.store(f("api.test/x", "SSRF in url parameter")))

    def test_persisted_lines_are_valid_jsonl(self):
        m = self._mem()
        m.store(f("api.test/x", "SSRF in url parameter"))
        lines = (self.dir / "m.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["title"], "SSRF in url parameter")

    def test_accepts_plain_dicts_as_well_as_findings(self):
        m = self._mem()
        self.assertTrue(m.store({"target": "api.test/x", "title": "SSRF in url parameter"}))
        self.assertFalse(m.store(f("api.test/x", "SSRF in url parameter")))


# ==================================================================================================
class TestNoHeavyImportDependency(unittest.TestCase):
    """(7) — le module ne doit plus exiger numpy à l'import : c'est ce qui le rend testable sans la
    pile lourde, et une raison de moins d'échouer chez un utilisateur."""

    def test_importable_without_numpy(self):
        import importlib

        import forge

        saved_np = sys.modules.get("numpy")
        saved_mf = sys.modules.pop("forge.memory_faiss", None)

        def restore():
            if saved_np is None:
                sys.modules.pop("numpy", None)
            else:
                sys.modules["numpy"] = saved_np
            if saved_mf is not None:
                # RESTAURER LES DEUX : `sys.modules` ET l'attribut du paquet. `import forge.memory_faiss
                # as mf` lit l'ATTRIBUT du paquet, alors que `from .memory_faiss import …` (dans
                # forge/memory.py) lit `sys.modules` — les laisser diverger donnerait DEUX objets module
                # distincts, donc deux caches `_MODELS`, et des tests voisins verts pour de fausses raisons.
                sys.modules["forge.memory_faiss"] = saved_mf
                forge.memory_faiss = saved_mf

        self.addCleanup(restore)
        sys.modules["numpy"] = None                # tout `import numpy` lèvera ImportError
        mod = importlib.import_module("forge.memory_faiss")
        self.assertTrue(hasattr(mod, "EmbeddingMemory"))

    def test_dot_product_is_cosine_on_normalised_vectors(self):
        from forge.memory_faiss import _dot
        self.assertAlmostEqual(_dot([0.6, 0.8], [0.6, 0.8]), 1.0)
        self.assertAlmostEqual(_dot([1.0, 0.0], [0.0, 1.0]), 0.0)


# ==================================================================================================
class TestCliReachability(unittest.TestCase):
    """`make_memory` n'avait AUCUN appelant de production : la CLI construisait toujours un `Memory`
    exact en dur, si bien qu'AUCUN des backends de la fabrique n'était atteignable par un utilisateur.
    `--memory-mode` les branche — en gardant le comportement HISTORIQUE par défaut."""

    def setUp(self):
        self.dir = temp_dir(self, "forge-emb-cli-")
        _install_fake_encoder(self)
        from forge.cli import build_parser
        from forge.cli import engine as cli_engine
        self.parser, self.cli_engine = build_parser(), cli_engine

    def _args(self, *extra):
        return self.parser.parse_args(["run", "--scope", "s.json", *extra])

    def test_defaults_are_the_historical_behaviour(self):
        args = self._args("--memory", str(self.dir / "m.jsonl"))
        self.assertEqual(args.memory_mode, "exact")
        self.assertFalse(args.memory_allow_download)
        mem = self.cli_engine._make_memory(args)
        self.assertIsInstance(mem, Memory)
        self.assertNotIsInstance(mem, JaccardMemory)       # backend EXACT, comme avant
        self.assertEqual(FakeEncoder.constructed, [])      # et surtout : aucun encodeur, aucun egress

    def test_no_memory_flag_still_means_no_store(self):
        self.assertIsNone(self.cli_engine._make_memory(self._args()))

    def test_modes_are_reachable_from_the_command_line(self):
        from forge.memory_faiss import EmbeddingMemory
        import forge.memory_faiss as mf
        for mode, expected in (("jaccard", JaccardMemory), ("embeddings", EmbeddingMemory)):
            with self.subTest(mode=mode):
                mf._MODELS.clear()
                args = self._args("--memory", str(self.dir / f"{mode}.jsonl"), "--memory-mode", mode)
                self.assertIsInstance(self.cli_engine._make_memory(args), expected)

    def test_download_optin_is_a_distinct_explicit_flag(self):
        import forge.memory_faiss as mf
        mf._MODELS.clear()
        args = self._args("--memory", str(self.dir / "m.jsonl"),
                          "--memory-mode", "embeddings", "--memory-allow-download")
        self.assertTrue(args.memory_allow_download)
        self.cli_engine._make_memory(args)
        # opt-in honoré jusqu'au chargement : la garde hors-ligne n'a PAS été posée.
        self.assertEqual(mf._MODELS["all-MiniLM-L6-v2"].env_at_load, {k: None for k in OFFLINE_VARS})

    def test_campaign_shares_the_same_flags(self):
        args = self.parser.parse_args(["campaign", "--scope", "s.json", "--targets", "t.json",
                                       "--memory", str(self.dir / "m.jsonl"), "--memory-mode", "jaccard"])
        self.assertIsInstance(self.cli_engine._make_memory(args), JaccardMemory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
