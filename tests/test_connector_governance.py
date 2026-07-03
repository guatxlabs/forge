"""GOUVERNANCE CONNECTEUR (#4) — enforcement AU TIR de la désactivation console, côté moteur.

La console (Rust) gouverne l'intention opérateur sur chaque connecteur (`enabled` / `available_override`)
et l'INJECTE au run de deux façons complémentaires :
  (a) filtre `--modules` -> la sélection explicite exclut les connecteurs désactivés (testé côté Rust) ;
  (b) clé `disabled_modules` dans le scope.json -> le MOTEUR skippe ces kinds, y compris ceux choisis par
      le PLANNER (au-delà de `--modules`).

Ces preuves couvrent (b) : un connecteur désactivé est SKIP par le moteur MÊME quand son binaire/service
EST présent (module.available=True). C'est l'enforcement réel (pas cosmétique) : `disabling` un connecteur
empêche véritablement le module de tirer. Toutes les preuves sont HERMÉTIQUES (module stubé, zéro réseau).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Scope, Action                            # noqa: E402
from forge.engine import Engine                                # noqa: E402
from forge.modules import registry                             # noqa: E402
from forge.schema import Finding                               # noqa: E402


class _PresentModule(registry.Module):
    """Connecteur dont l'outil sous-jacent EST présent (available=True) et qui tire un finding.

    Sert à prouver que la désactivation console (scope.disabled_modules) prime sur la présence host :
    un tel module DOIT tirer s'il n'est pas désactivé, et être SKIP s'il l'est."""
    available = True          # binaire/service présent (auto-neutralisation NON déclenchée)
    exploit = False
    web_allowed = True
    mitre = "T1046"

    def dry(self, action):
        return f"# dry {self.kind} {action.target}"

    def fire(self, action):
        return [Finding(target=action.target, title=f"hit {self.kind}", severity="INFO",
                        category="recon", status="tested", tool=self.kind)]


class _register_present:
    """Context manager : enregistre `_PresentModule` sous un kind, restaure le REGISTRY à la sortie."""
    def __init__(self, kind):
        self.kind = kind
        self._saved = None

    def __enter__(self):
        self._saved = registry.REGISTRY.get(self.kind)
        cls = type("Stub_present", (_PresentModule,), {"kind": self.kind})
        registry.REGISTRY[self.kind] = cls
        return self

    def __exit__(self, *exc):
        if self._saved is None:
            registry.REGISTRY.pop(self.kind, None)
        else:
            registry.REGISTRY[self.kind] = self._saved
        return False


def _armed_auto(scope):
    """Moteur armé + mode auto : toute action in-scope/autorisée FIRE sans approbation 1-à-1 (le ROE
    reste seul juge du périmètre/capacité). Isole la variable testée = la désactivation connecteur."""
    eng = Engine(scope, mode="auto")
    eng.arm("test gouvernance connecteur")
    return eng


KIND = "recon.present"


class TestScopeLoadsDisabledModules(unittest.TestCase):
    def test_scope_parses_disabled_modules(self):
        # forme nominale : liste de kinds -> set. Additif : absent => set vide (comportement inchangé).
        sc = Scope({"in_scope": ["app.test"], "disabled_modules": ["a.b", "c.d"]})
        self.assertEqual(sc.disabled_modules, {"a.b", "c.d"})
        self.assertEqual(Scope({"in_scope": ["app.test"]}).disabled_modules, set(),
                         "clé absente => aucun module désactivé")

    def test_scope_ignores_non_string_entries(self):
        # fail-closed lisible : les entrées non-string sont ignorées (jamais une exception -> jamais un
        # FIRE fabriqué faute de parsing). Les strings valides sont conservées.
        sc = Scope({"in_scope": ["app.test"], "disabled_modules": ["ok.kind", 123, None, {"x": 1}]})
        self.assertEqual(sc.disabled_modules, {"ok.kind"})


class TestEngineHonorsDisabledModules(unittest.TestCase):
    def test_present_module_fires_when_not_disabled(self):
        # CONTRÔLE : sans désactivation, un module PRÉSENT (available=True) armé/in-scope TIRE.
        with _register_present(KIND):
            sc = Scope({"mode": "grey", "in_scope": ["app.test"], "allow_exploit": False})
            eng = _armed_auto(sc)
            res = eng.execute(Action(kind=KIND, target="app.test"))
        self.assertEqual(res["verdict"], "FIRE", "module présent + armé + in-scope -> FIRE (contrôle)")
        self.assertEqual(len(eng.findings), 1, "le module a bien tiré un finding")

    def test_disabled_module_is_skipped_despite_present_binary(self):
        # PREUVE (b) : le kind est PRÉSENT (available=True) MAIS désactivé via scope.disabled_modules ->
        # le moteur le SKIP (aucun tir, aucun finding). C'est l'enforcement réel de la gouvernance console.
        with _register_present(KIND):
            sc = Scope({"mode": "grey", "in_scope": ["app.test"], "allow_exploit": False,
                        "disabled_modules": [KIND]})
            eng = _armed_auto(sc)
            res = eng.execute(Action(kind=KIND, target="app.test"))
        self.assertEqual(res["verdict"], "SKIP",
                         "connecteur désactivé -> SKIP même si le binaire/service est présent")
        self.assertIn("désactivé", " ".join(res["reasons"]).lower(),
                      "la raison du SKIP doit citer la désactivation console (transparence anti-masquage)")
        self.assertEqual(eng.findings, [], "un connecteur désactivé NE tire aucun finding")

    def test_disabled_skip_is_visible_in_coverage_errors(self):
        # transparence : le SKIP apparaît dans la couverture (errors), pas silencieusement supprimé —
        # miroir du traitement d'un outil absent (anti-masquage : rien n'est caché du rapport).
        with _register_present(KIND):
            sc = Scope({"mode": "grey", "in_scope": ["app.test"], "disabled_modules": [KIND]})
            eng = _armed_auto(sc)
            eng.execute(Action(kind=KIND, target="app.test"))
            cov = eng.coverage()
        self.assertEqual(len(cov["errors"]), 1, "le SKIP figure dans la couverture (errors), visible au rapport")
        self.assertEqual(len(cov["fired"]), 0, "aucun tir")

    def test_only_named_kind_disabled_others_unaffected(self):
        # sélectivité : désactiver un kind n'affecte PAS un autre connecteur présent (pas de sur-blocage).
        other = "recon.other"
        with _register_present(KIND), _register_present(other):
            sc = Scope({"mode": "grey", "in_scope": ["app.test"], "disabled_modules": [KIND]})
            eng = _armed_auto(sc)
            r_dis = eng.execute(Action(kind=KIND, target="app.test"))
            r_ok = eng.execute(Action(kind=other, target="app.test"))
        self.assertEqual(r_dis["verdict"], "SKIP", "le kind nommé est désactivé")
        self.assertEqual(r_ok["verdict"], "FIRE", "un autre connecteur présent reste actif")


if __name__ == "__main__":
    unittest.main(verbosity=2)
