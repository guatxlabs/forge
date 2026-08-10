# SPDX-License-Identifier: AGPL-3.0-or-later
"""`origin.find` — LA BORNE DE DURÉE D'UN TIR, et le fait qu'un tir coupé ne MENT pas.

LE DÉFAUT, MESURÉ (campagne H1 publique `kong`, 2026-08-10, budget 3 600 s de mur)
----------------------------------------------------------------------------------
`ledger.jsonl.durations` : `origin.find` = 32,43 / 32,86 / **1 799,08 s**. Le tir long vaut **51 %
du budget** et **24 % de tout le travail du run**. Module NATIF -> aucun `spec.timeout`, aucune
`max_runtime` : `Engine._budget_gate` fail-open sans borne déclarée, et la part de budget par kind
(`interrupt.KindShare`) ne le borne qu'en RÉPÉTITION — jamais au PREMIER débordement, qu'aucune
mesure antérieure ne permet de prédire.

D'OÙ VENAIT LE TEMPS — L'ARTEFACT SUFFIT À LE DIRE. Le rapport de ce tir porte 429 findings
`origin-exposure`, et les 429 sont « IP résolue HORS-SCOPE — connexion refusée » : cette branche
`continue` AVANT tout httpx, et la baseline de corrélation est PARESSEUSE. **Zéro httpx émis.** Le
temps est donc, à subfinder près (≤ 120 s), dans la boucle `socket.gethostbyname` — séquentielle,
bloquante, sans timeout propre. `tests/bench_origin_bound.py` REPRODUIT la durée à 0,1 s près.

QUELLE BORNE PORTE — LE CONTRE-FACTUEL EST TESTÉ ICI, PAS SUPPOSÉ
------------------------------------------------------------------
Un plafond sur le NOMBRE de candidats borne la boucle DNS (l'étage qui a explosé ce jour-là) et rien
d'autre : sur une cible dont les IP sont IN-SCOPE, les mêmes candidates partent en vérification httpx
à 30 s pièce. `TestWhichBoundCarries` le MESURE — cap 300 -> 9 485 s, échéance -> 600 s.

Hermétique : `runner.tool`, `socket.gethostbyname` et `origin.time` sont des seams. Le temps est
INJECTÉ (horloge virtuelle), jamais attendu — aucun test ne dort, zéro réseau.
"""
from __future__ import annotations

import sys
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import runner                                       # noqa: E402
from forge.engine import Engine                                # noqa: E402
from forge.interrupt import ACTION_BUDGET_PARAM                # noqa: E402
from forge.modules import origin as origin_mod                 # noqa: E402
from forge.modules.origin import OriginFind                    # noqa: E402
from forge.roe import Action                                   # noqa: E402
from tests.bench_origin_bound import _Harness, run_case        # noqa: E402

DOMAIN = "konghq.com"


def _assert_mutation_kills(case, check, patcher, label):
    """Preuve par MUTATION, en deux temps NON NÉGOCIABLES (même contrat que
    `tests/test_planner_discovery_first.py`).

    1. ATTEIGNABILITÉ + VÉRITÉ : `check()` passe sur le code LIVRÉ ;
    2. LÉTALITÉ : sous `patcher`, `check()` DOIT lever `AssertionError`. Sinon la mutation n'est pas
       atteinte par ce test — on le DIT, on ne s'en félicite pas."""
    check()
    with patcher:
        try:
            check()
        except AssertionError:
            return
    case.fail(f"MUTATION NON LÉTALE — « {label} » : la propriété passe encore une fois le correctif "
              f"retiré. Le test ne prouve donc RIEN sur ce point.")


def _fire(harness, *, in_scope=None, budget=None, max_runtime=None):
    """Un tir de `origin.find` sous les seams du banc. Rend (findings, écoulé virtuel)."""
    action = Action("origin.find", DOMAIN)
    action.params.update({"in_scope": list(in_scope or [DOMAIN]), "out_scope": []})
    if budget is not None:
        action.params[ACTION_BUDGET_PARAM] = budget
    patches = list(harness.patches())
    if max_runtime is not None:
        patches.append(mock.patch.object(origin_mod, "MAX_RUNTIME", max_runtime))
    stack = []
    try:
        for p in patches:
            p.__enter__()
            stack.append(p)
        return OriginFind().fire(action), harness.clock.t
    finally:
        for p in reversed(stack):
            p.__exit__(None, None, None)


def _titles(findings):
    return [f.title for f in findings]


# ---------------------------------------------------------------------------------------------
class TestDeclaredBound(unittest.TestCase):
    """La borne est DÉCLARÉE au moteur — c'est ce qui manquait : `_budget_gate` fail-open sans borne."""

    def test_le_module_annonce_desormais_une_borne_au_moteur(self):
        action = Action("origin.find", DOMAIN)

        def check():
            self.assertEqual(Engine._runtime_bound(OriginFind(), action), float(origin_mod.MAX_RUNTIME))

        # MUTATION = l'état d'AVANT ce lot : le module natif ne déclare rien, la gate est aveugle.
        _assert_mutation_kills(
            self, check, mock.patch.object(OriginFind, "max_runtime", lambda self, a: None),
            "max_runtime retirée (module natif sans borne déclarée, comme avant ce lot)")

    def test_sans_borne_declaree_la_gate_du_moteur_est_aveugle(self):
        """La raison d'être de la déclaration, dite en une assertion : sans elle, `_runtime_bound`
        rend None et `_budget_gate` ne peut RIEN refuser (fail-open documenté de l'engine)."""
        with mock.patch.object(OriginFind, "max_runtime", lambda self, a: None):
            self.assertIsNone(Engine._runtime_bound(OriginFind(), Action("origin.find", DOMAIN)))

    def test_la_borne_annoncee_est_rabotee_au_budget_restant_comme_nuclei(self):
        """Contrat partagé avec `NucleiScan.max_runtime` : ce qu'on ANNONCE == ce que `fire()` peut
        prendre. Le module S'ADAPTE au temps restant au lieu d'être écarté en entier."""
        m = OriginFind()
        for left, expected in ((120.0, 120.0), (9999.0, float(origin_mod.MAX_RUNTIME)), (0.0, 0.0)):
            a = Action("origin.find", DOMAIN)
            a.params[ACTION_BUDGET_PARAM] = left
            self.assertEqual(m.max_runtime(a), expected, f"budget restant {left}")

    def test_sans_budget_pose_la_borne_est_pleine_et_rien_ne_change(self):
        """NO-OP STRICT sans budget (appel programmatique, CLI sans `--run-timeout`) : borne pleine,
        et les timeouts des sous-processus sont EXACTEMENT les valeurs historiques (120 / 30)."""
        m = OriginFind()
        self.assertEqual(m.max_runtime(Action("origin.find", DOMAIN)), float(origin_mod.MAX_RUNTIME))
        for bad in (None, "", "abc", float("nan")):
            a = Action("origin.find", DOMAIN)
            a.params[ACTION_BUDGET_PARAM] = bad
            self.assertEqual(m.max_runtime(a), float(origin_mod.MAX_RUNTIME), f"budget illisible {bad!r}")


# ---------------------------------------------------------------------------------------------
class TestShotIsBounded(unittest.TestCase):
    """Le tir de 1 799 s tient désormais dans sa borne — mesuré à l'horloge virtuelle."""

    @staticmethod
    def _kong_harness():
        """La FORME du tir réel : 1 644 hôtes rendus par subfinder, 429 résolvent, 1 s par résolution
        (le couple qui reproduit 1 799,08 s — cf. `bench_origin_bound`)."""
        return _Harness(hosts=1644, latency=1.0, candidates=429)

    def test_le_tir_de_1799s_tient_dans_la_borne(self):
        # La borne ATTENDUE est FIGÉE ici, hors de la mutation : la lire dans `origin_mod` pendant
        # que la mutation la met à 10**9 rendait l'assertion vraie par construction — une mutation
        # non létale, et le test ne prouvait rien (attrapé par `_assert_mutation_kills`).
        bound = float(origin_mod.MAX_RUNTIME)

        def check():
            _findings, elapsed = _fire(self._kong_harness())
            self.assertLessEqual(elapsed, bound, "le tir dépasse sa propre borne")

        # MUTATION = échéance neutralisée (l'état d'avant) -> on retombe sur les 1 799 s mesurés.
        _assert_mutation_kills(self, check, mock.patch.object(origin_mod, "MAX_RUNTIME", 10 ** 9),
                               "échéance de tir neutralisée")

    def test_sans_borne_le_banc_reproduit_la_duree_mesuree(self):
        """ATTEIGNABILITÉ de la mutation ci-dessus, en chiffres : sans échéance, la forme du tir réel
        coûte 1 799 s — la valeur du ledger à 0,1 s près, et ZÉRO httpx comme dans le rapport."""
        h = self._kong_harness()
        with mock.patch.object(origin_mod, "MAX_RUNTIME", 10 ** 9):
            _findings, elapsed = _fire(h)
        self.assertAlmostEqual(elapsed, 1799.0833, delta=0.5)
        self.assertEqual(h.httpx_calls, 0, "l'artefact ne porte AUCUN httpx sur ce tir")
        self.assertEqual(h.dns_calls, 1679, "le temps est dans la boucle de résolution")

    def test_le_budget_du_moteur_raccourcit_le_tir_pour_de_vrai(self):
        """La borne annoncée n'est pas décorative : un budget de 200 s BORNE l'exécution à 200 s."""
        _findings, elapsed = _fire(self._kong_harness(), budget=200.0)
        self.assertLessEqual(elapsed, 200.0)

    def test_budget_nul_ne_lance_aucun_processus(self):
        h = self._kong_harness()
        findings, elapsed = _fire(h, budget=0.0)
        self.assertEqual(elapsed, 0.0)
        self.assertEqual((h.dns_calls, h.httpx_calls), (0, 0), "aucun travail avec un budget nul")
        self.assertEqual([f.status for f in findings], ["skipped"])
        self.assertIn("borne de durée épuisée", findings[0].title)


# ---------------------------------------------------------------------------------------------
class TestCutIsSkippedNeverTested(unittest.TestCase):
    """LA LIGNE ROUGE — un tir coupé rend `skipped` NOMMÉ, JAMAIS `tested`.

    C'est le défaut réparé sur les lots nuclei tués à leur mur : chaque cible non atteinte ressortait
    en « aucun hit », un verdict négatif FABRIQUÉ. Une borne qui le réintroduirait serait pire que
    l'absence de borne."""

    @staticmethod
    def _harness():
        return _Harness(hosts=1644, latency=1.0, candidates=429)

    def test_ce_qui_na_pas_ete_resolu_ressort_en_skipped_nomme(self):
        findings, _ = _fire(self._harness())
        cut = [f for f in findings if "borne de durée atteinte" in f.title]
        self.assertTrue(cut, "aucun constat de coupe : le trou de couverture est SILENCIEUX")
        for f in cut:
            self.assertEqual(f.status, "skipped", f"{f.title!r} n'est pas un `skipped`")
        self.assertTrue(any("non résolu" in f.title for f in cut))
        # le COMPTE des hôtes non résolus est dit, pas seulement le fait qu'il y en a.
        self.assertRegex(" ".join(f.title for f in cut), r"\d+ hôte\(s\) non résolu")

    def test_un_tir_coupe_nemet_JAMAIS_le_constat_dabsence(self):
        """« Aucune origine hors-CDN trouvée » (`tested`) est une AFFIRMATION D'ABSENCE. Elle doit
        être inatteignable dès qu'un étage a été coupé."""
        def check():
            findings, _ = _fire(self._harness())
            titles = _titles(findings)
            self.assertTrue(any("borne de durée atteinte" in t for t in titles),
                            "le test perd son sens si rien n'est coupé")
            self.assertNotIn("Aucune origine hors-CDN trouvée", titles,
                             "VERDICT FABRIQUÉ : un tir tronqué affirme une absence")

        # MUTATION : la coupe cesse d'être NOMMÉE -> `findings` peut redevenir vide -> le constat
        # d'absence reprend la main. C'est exactement le défaut nuclei, transposé ici.
        _assert_mutation_kills(
            self, check,
            mock.patch.object(OriginFind, "_cut", lambda self, a, d, unres, unver: []),
            "les constats de coupe ne sont plus émis (le tir tronqué redevient muet)")

    def test_la_mutation_est_bien_atteinte_le_constat_dabsence_revient(self):
        """ATTEIGNABILITÉ EXPLICITE de la mutation : sans les constats de coupe, un tir coupé AVANT
        toute candidate affirme « Aucune origine hors-CDN trouvée » en `tested`."""
        h = _Harness(hosts=1644, latency=1.0, candidates=0)      # aucune résolution ne réussit
        with mock.patch.object(OriginFind, "_cut", lambda self, a, d, unres, unver: []):
            findings, _ = _fire(h)
        self.assertEqual(_titles(findings), ["Aucune origine hors-CDN trouvée"])
        self.assertEqual(findings[0].status, "tested")           # le verdict FABRIQUÉ, en clair

    def test_les_candidates_non_verifiees_sont_comptees_et_skipped(self):
        """Forme `in-scope` : la coupe tombe sur la VÉRIFICATION. Chaque candidate non sondée est
        comptée, aucune n'est conclue."""
        h = _Harness(hosts=1644, latency=1.0, candidates=429)
        findings, _ = _fire(h, in_scope=["9.0.0.0/8", DOMAIN])
        unver = [f for f in findings if "candidate(s) non vérifiée" in f.title]
        self.assertEqual(len(unver), 1)
        self.assertEqual(unver[0].status, "skipped")
        self.assertIn("429", unver[0].title)
        self.assertFalse([f for f in findings if f.status == "vulnerable"],
                         "un tir coupé ne PROMEUT rien")

    def test_les_constats_gratuits_survivent_a_la_coupe(self):
        """La garde est placée APRÈS le refus hors-scope, qui ne coûte RIEN. La borne ne doit pas
        supprimer de l'information gratuite : les 429 constats du tir de référence restent émis."""
        def check():
            findings, _ = _fire(_Harness(hosts=1644, latency=1.0, candidates=429))
            refused = [f for f in findings if "HORS-SCOPE" in f.title]
            self.assertEqual(len(refused), 429,
                             "la borne a mangé des constats qui ne coûtaient aucune requête")

        # MUTATION : la garde remonte en TÊTE de boucle (le placement « évident ») -> les constats
        # gratuits disparaissent avec la coupe.
        _assert_mutation_kills(self, check,
                               mock.patch.object(origin_mod._Deadline, "expired", lambda self: True),
                               "échéance considérée expirée dès l'entrée dans la boucle de candidates")


# ---------------------------------------------------------------------------------------------
class TestWhichBoundCarries(unittest.TestCase):
    """LE CONTRE-FACTUEL : un plafond de candidats borne UN étage, l'échéance borne LE TIR.

    Mesuré au banc (`bench_origin_bound.run_case`, horloge virtuelle) — c'est la justification du
    choix de conception, encodée en test pour qu'elle ne dérive pas."""

    KW = {"hosts": 1644, "latency": 1.0, "candidates": 429, "cap": 300, "max_runtime": 600.0}

    def test_le_plafond_de_candidats_ne_borne_pas_la_forme_in_scope(self):
        cap = run_case("in-scope", "cap", **self.KW)
        self.assertGreater(cap["elapsed"], 9000,
                           "le plafond de candidats suffirait — la conception serait à revoir")

    def test_lecheance_borne_les_DEUX_formes(self):
        for shape in ("hors-scope", "in-scope"):
            with self.subTest(shape=shape):
                r = run_case(shape, "échéance", **self.KW)
                self.assertLessEqual(r["elapsed"], self.KW["max_runtime"])
                self.assertEqual(r["absence"], 0, "un tir coupé affirme une absence")

    def test_sans_borne_les_deux_formes_debordent(self):
        """Atteignabilité : les deux formes dépassent bel et bien la borne sans elle (sinon les deux
        tests ci-dessus ne prouveraient rien)."""
        for shape, floor in (("hors-scope", 1700), ("in-scope", 14000)):
            with self.subTest(shape=shape):
                self.assertGreater(run_case(shape, "aucune", **self.KW)["elapsed"], floor)


# ---------------------------------------------------------------------------------------------
class TestNoOpWithoutBudget(unittest.TestCase):
    """Sans budget posé et sur une cible rapide, RIEN ne change — argv et timeouts historiques."""

    def test_les_timeouts_des_sous_processus_sont_les_valeurs_historiques(self):
        seen = []

        def tool(binary, image, argv, timeout=None, prefer_docker=False):
            seen.append((binary, timeout))
            if binary == OriginFind.SUB:
                return 0, "a.konghq.com\n", ""
            return 0, f"http://x [200] [{DOMAIN}]", ""

        action = Action("origin.find", DOMAIN)
        action.params.update({"in_scope": ["9.0.0.0/8", DOMAIN], "out_scope": []})
        with mock.patch.object(runner, "tool", tool), \
             mock.patch.object(origin_mod.socket, "gethostbyname", lambda n: "9.9.9.9"):
            OriginFind().fire(action)
        self.assertEqual(seen[0], (OriginFind.SUB, 120), "timeout subfinder historique = 120 s")
        self.assertTrue(all(t == 30 for b, t in seen[1:] if b == OriginFind.HX),
                        f"timeout httpx historique = 30 s ; vu : {seen}")


if __name__ == "__main__":
    unittest.main()
