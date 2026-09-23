"""Tests hermetiques de `parserdiff.unicode` — aucun reseau.

CE QUI EST EN JEU. La preuve d'un differentiel est une CONJONCTION de trois observations, et
c'est fragile par nature : chacune prise seule ne prouve rien. Un confusable qui passe peut
n'etre qu'un caractere accepte parmi d'autres ; un ASCII refuse peut l'etre pour une tout autre
raison. Seul l'ECART entre les deux lectures est la faille. Les tests ci-dessous epinglent
chaque moitie de la conjonction separement, pour qu'aucun relachement futur ne puisse promouvoir
une observation isolee en preuve.
"""
from __future__ import annotations

import unicodedata
import unittest

from forge.roe import Action
from forge.modules import unicodenorm as mod
from forge.modules.unicodenorm import UnicodeNormalization, marker, build_probes, nfkc_reduces_to

TGT = "https://app.test/search"
SCOPE = {"in_scope": ["app.test"], "param": "q"}


def _fire(repondre, params=None, target=TGT):
    """Tire l'oracle avec `_send` remplace. `repondre(payload) -> (status, corps)`.

    `_send` est une methode d'INSTANCE (pas un descripteur `staticmethod`) : la remplacer par
    une fonction normale conserve le binding, et le garde-fou de `test_seam_restoration.py` ne
    s'applique donc pas ici. On restaure quand meme depuis `__dict__`, par principe.
    """
    avait = "_send" in UnicodeNormalization.__dict__
    orig = UnicodeNormalization.__dict__.get("_send")

    def faux(self, action, param, payload, method, timeout):
        return repondre(payload)

    UnicodeNormalization._send = faux
    try:
        p = dict(SCOPE)
        p.update(params or {})
        return UnicodeNormalization().fire(Action("parserdiff.unicode", target, params=p))
    finally:
        if avait and orig is not None:
            UnicodeNormalization._send = orig
        else:
            try:
                delattr(UnicodeNormalization, "_send")
            except AttributeError:
                pass


class TestTableConfusables(unittest.TestCase):
    """La table est DERIVEE par balayage NFKC, pas ecrite a la main.

    Ce test l'a d'ailleurs impose : la premiere version portait une table de memoire, et il a
    pris en defaut la barre de fraction U+2044, qui ne se normalise PAS en `/`. La table derivee
    ne peut plus se tromper — ces controles restent pour epingler l'INVARIANT, pas la saisie."""

    def test_chaque_substitut_se_ramene_bien_a_son_ascii(self):
        for ascii_char, variantes in mod.CONFUSABLES.items():
            for nom, sub in variantes:
                self.assertEqual(unicodedata.normalize("NFKC", sub), ascii_char,
                                 f"« {nom} » ({sub!r}) ne se normalise PAS en {ascii_char!r}")

    def test_les_substituts_ne_sont_pas_deja_leur_ascii(self):
        # Un substitut identique a l'ASCII ne franchirait aucun filtre : ce serait une preuve
        # fabriquee de toutes pieces.
        for ascii_char, variantes in mod.CONFUSABLES.items():
            for _nom, sub in variantes:
                self.assertNotEqual(sub, ascii_char)

    def test_case_expanders_changent_bien_de_longueur(self):
        for nom, ch in mod.CASE_EXPANDERS:
            plus_long = (len(ch.lower()) > len(ch)
                         or len(unicodedata.normalize("NFKC", ch)) > len(ch))
            self.assertTrue(plus_long, f"« {nom} » ({ch!r}) ne s'allonge pas — hors sujet ici")

    def test_nfkc_reduces_to(self):
        self.assertTrue(nfkc_reduces_to("＜", "<"))
        self.assertFalse(nfkc_reduces_to("x", "<"))


class TestSondes(unittest.TestCase):

    def test_marqueur_inerte_et_deterministe(self):
        a, b = marker(TGT, "q"), marker(TGT, "q")
        self.assertEqual(a, b, "le marqueur doit etre rejouable")
        self.assertTrue(a.startswith("forgeuni"))
        self.assertTrue(a.isalnum(), "le marqueur doit traverser tout filtre : alphanumerique pur")

    def test_les_sondes_n_ont_rien_d_actif(self):
        # Les caracteres sensibles ENTOURENT le marqueur ; il n'y a jamais de nom de balise
        # derriere un chevron, donc rien d'executable ne peut sortir de ces sondes.
        for _nom, sonde_ascii, sonde_conf, _c in build_probes(marker(TGT, "q")):
            for s in (sonde_ascii, sonde_conf):
                bas = s.lower()
                self.assertNotIn("script", bas)
                self.assertNotIn("onerror", bas)
                self.assertNotIn("</", bas)

    def test_fan_out_borne(self):
        self.assertLessEqual(len(build_probes(marker(TGT, "q"))), mod.MAX_PROBES)

    def test_la_table_derivee_est_plus_riche_qu_une_table_manuelle(self):
        # Mesure : 5 substituts pour `(`, 4 pour `=`, 4 pour `;` (dont le point d'interrogation
        # grec U+037E). Une table ecrite a la main en portait un seul par caractere.
        self.assertGreaterEqual(len(mod.CONFUSABLES.get("(", [])), 4)
        self.assertGreaterEqual(len(mod.CONFUSABLES.get(";", [])), 3)
        self.assertGreaterEqual(sum(len(v) for v in mod.CONFUSABLES.values()), 18)

    def test_selection_par_caracteres(self):
        sondes = build_probes(marker(TGT, "q"), chars=["<"])
        self.assertTrue(sondes)
        self.assertTrue(all(c == "<" for *_r, c in sondes))


class TestDegradations(unittest.TestCase):
    """« Pas teste » ne doit jamais etre rendu comme « pas vulnerable »."""

    def test_hors_scope(self):
        appels = []
        out = _fire(lambda p: (appels.append(p), (200, p))[1], target="https://evil.test/s")
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(appels, [], "fail-closed : aucune requete hors perimetre")

    def test_parametre_absent(self):
        out = _fire(lambda p: (200, p), params={"param": None})
        self.assertEqual(out[0].status, "skipped")

    def test_reseau_indisponible(self):
        out = _fire(lambda p: (None, ""))
        self.assertEqual(out[0].status, "skipped")

    def test_sans_reflet_on_ne_conclut_pas_a_une_vuln(self):
        out = _fire(lambda p: (200, "page sans reflet"))
        self.assertEqual(out[0].status, "tested")
        self.assertIn("pas reflete", out[0].title.lower())


class TestConjonction(unittest.TestCase):
    """Chaque moitie de la conjonction, isolee : aucune ne doit suffire a prouver."""

    def test_ascii_non_filtre_ne_prouve_rien(self):
        # Tout est reflete tel quel : il n'y a aucun filtre a franchir.
        out = _fire(lambda p: (200, p))
        self.assertEqual(out[0].status, "tested")

    def test_confusable_non_normalise_ne_prouve_rien(self):
        # L'ASCII est bien filtre, mais le confusable revient TEL QUEL : l'application ne
        # normalise pas, donc aucun ecart n'est exploitable.
        mark = marker(TGT, "q")

        def rep(p):
            if p == mark:
                return (200, p)                     # temoin reflete
            if any(c in p for c in "<>\"'/()="):
                return (403, "")                    # ASCII refuse
            return (200, p)                         # confusable reflete SANS normalisation
        out = _fire(rep)
        self.assertEqual(out[0].status, "tested")

    def test_les_trois_reunis_prouvent(self):
        mark = marker(TGT, "q")

        def rep(p):
            if p == mark:
                return (200, p)                     # (1) temoin reflete
            if any(c in p for c in "<>\"'/()="):
                return (403, "")                    # (2) ASCII refuse par le filtre
            # (3) confusable : passe ET l'application le normalise en ASCII
            return (200, unicodedata.normalize("NFKC", p))
        out = _fire(rep)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "MEDIUM")
        self.assertIn("DIFFERENTIEL", out[0].title)

    def test_la_preuve_rappelle_le_gate_impact(self):
        # Un differentiel prouve que le FILTRE est franchissable, pas qu'une injection aboutit.
        # L'evidence doit le dire, sans quoi ce finding serait soumis tel quel et refuse.
        mark = marker(TGT, "q")

        def rep(p):
            if p == mark:
                return (200, p)
            if any(c in p for c in "<>\"'/()="):
                return (403, "")
            return (200, unicodedata.normalize("NFKC", p))
        out = _fire(rep)
        self.assertIn("Gate Impact", out[0].evidence)


class TestGardes(unittest.TestCase):

    def test_flags_declares(self):
        # Marqueurs inertes : cet oracle n'execute rien -> exploit=False, contrairement a
        # xss.execution. Le confondre reclamerait `allow_exploit` sans raison.
        self.assertFalse(UnicodeNormalization.exploit)
        self.assertFalse(UnicodeNormalization.destructive)

    def test_reflet_insensible_a_la_casse(self):
        # Plusieurs piles normalisent en minuscules au passage : exiger l'identique produirait
        # des faux negatifs sur des reflets pourtant bien presents.
        self.assertTrue(UnicodeNormalization._reflected("ABC-FORGEUNI12345678-X", "forgeuni12345678"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
