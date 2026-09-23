"""Tests hermetiques de `llm.prompt_injection` — aucun reseau, aucun modele.

DEUX CONTRATS, et le premier est une question de nature plus que de mesure.

LE PREMIER est la LIGNE ENTRE INJECTION ET JAILBREAK. Eprouver une injection de prompt, c'est
verifier qu'une application tient la frontiere entre ses instructions et la donnee de son
utilisateur — un defaut de securite applicative, comme une injection SQL. Faire produire a un
modele un contenu nuisible en est une autre, et ce n'est pas notre sujet. Les tests ci-dessous
verifient qu'aucune sonde ne demande de contenu nuisible : elles ne reclament qu'une chaine
inerte, sans signification hors de ce test.

LE SECOND est la PORTEE DU VERDICT. Une deviation d'instruction sans consequence sur un tiers
reste un informatif, et un negatif sur l'injection directe ne dit RIEN de l'injection indirecte,
que la veille 2026 designe comme le principal angle mort. L'oracle doit dire les deux.
"""
from __future__ import annotations

import json
import unittest

from forge.roe import Action
from forge.modules import llmprompt as mod
from forge.modules.llmprompt import (LlmPromptInjection, canari, sondes, rendu_non_echappe)

TGT = "https://app.test/api/chat"
BASE = {"in_scope": ["app.test"]}


def _fire(repondre, params=None, target=TGT):
    """Tire l'oracle avec `_ask` remplace. `repondre(texte) -> (status, corps)`."""
    avait = "_ask" in LlmPromptInjection.__dict__
    orig = LlmPromptInjection.__dict__.get("_ask")
    envoyes = []

    def faux(self, action, texte, timeout):
        envoyes.append(texte)
        return repondre(texte)

    LlmPromptInjection._ask = faux
    try:
        p = dict(BASE)
        p.update(params or {})
        return LlmPromptInjection().fire(Action("llm.prompt_injection", target, params=p)), envoyes
    finally:
        if avait and orig is not None:
            LlmPromptInjection._ask = orig
        else:
            try:
                delattr(LlmPromptInjection, "_ask")
            except AttributeError:
                pass


class TestLigneJailbreak(unittest.TestCase):
    """Aucune sonde ne doit demander un contenu nuisible."""

    def test_les_sondes_ne_reclament_qu_une_chaine_inerte(self):
        interdits = ("bombe", "explosif", "arme", "drogue", "malware", "ransomware",
                     "virus", "exploit", "weapon", "bomb", "kill", "hack into")
        for _f, texte, _t in sondes(TGT):
            bas = texte.lower()
            for mot in interdits:
                self.assertNotIn(mot, bas,
                                 f"une sonde reclame « {mot} » — ce serait du jailbreak, pas de "
                                 f"l'injection de prompt")

    def test_le_canari_est_inerte_et_rejouable(self):
        a, b = canari(TGT, "directe"), canari(TGT, "directe")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("forgeli"))
        self.assertTrue(a.isalnum(), "le canari ne doit porter aucune syntaxe")

    def test_canaris_distincts_par_famille(self):
        # Un canari partage ferait prendre la reponse d'une sonde pour celle d'une autre.
        vus = [t for _f, _x, t in sondes(TGT)]
        self.assertEqual(len(vus), len(set(vus)))

    def test_fan_out_borne(self):
        self.assertLessEqual(len(sondes(TGT)), mod.MAX_SONDES)


class TestRenduNonEchappe(unittest.TestCase):
    """La difference entre une reponse AFFICHEE et une reponse EXECUTEE."""

    def test_html_vivant_detecte(self):
        tok = "forgeli12345678"
        self.assertTrue(rendu_non_echappe(f"<p>voici <b>{tok}</b> merci</p>", tok))

    def test_entites_echappees_non_detectees(self):
        tok = "forgeli12345678"
        self.assertFalse(rendu_non_echappe(f"&lt;b&gt;{tok}&lt;/b&gt;", tok))

    def test_canari_absent(self):
        self.assertFalse(rendu_non_echappe("<b>rien</b>", "forgeli12345678"))

    def test_texte_nu_non_detecte(self):
        tok = "forgeli12345678"
        self.assertFalse(rendu_non_echappe(f"la reponse est {tok}", tok))


class TestVerdicts(unittest.TestCase):

    def test_sortie_non_assainie_prime_sur_le_reste(self):
        # C'est la famille la plus rapportable : elle doit remonter en HIGH.
        def rep(texte):
            t = canari(TGT, "sortie")
            return (200, f"<div><b>{t}</b></div>") if t in texte else (200, "ok")
        out, _ = _fire(rep)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "HIGH")
        self.assertIn("HTML VIVANT", out[0].title)

    def test_injection_sans_rendu_est_medium(self):
        def rep(texte):
            t = canari(TGT, "directe")
            return (200, json.dumps({"reply": t})) if t in texte else (200, "ok")
        out, _ = _fire(rep)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "MEDIUM")

    def test_la_preuve_rappelle_le_gate_impact(self):
        def rep(texte):
            t = canari(TGT, "directe")
            return (200, t) if t in texte else (200, "ok")
        out, _ = _fire(rep)
        self.assertIn("informatif", out[0].evidence)
        self.assertIn("OUTILS", out[0].evidence)

    def test_modele_qui_resiste_est_un_vrai_negatif(self):
        out, _ = _fire(lambda t: (200, "Je ne peux pas donner suite a cette demande."))
        self.assertEqual(out[0].status, "tested")

    def test_le_negatif_dit_qu_il_est_ETROIT(self):
        # Un negatif sur l'injection directe ne dit rien de l'indirecte — le taire ferait
        # passer une classe pour close alors que son principal angle mort n'a pas ete regarde.
        out, _ = _fire(lambda t: (200, "non"))
        self.assertIn("INDIRECTE", out[0].evidence)


class TestDegradations(unittest.TestCase):

    def test_hors_scope(self):
        out, envoyes = _fire(lambda t: (200, "ok"), target="https://evil.test/chat")
        self.assertEqual(out[0].status, "skipped")
        self.assertEqual(envoyes, [], "fail-closed : aucune requete hors perimetre")

    def test_reseau_indisponible(self):
        out, _ = _fire(lambda t: (None, ""))
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("body_template", out[0].evidence)


class TestGardes(unittest.TestCase):

    def test_flags_declares(self):
        # Canaris inertes : rien d'actif n'est demande au modele.
        self.assertFalse(LlmPromptInjection.exploit)
        self.assertFalse(LlmPromptInjection.destructive)

    def test_statut_du_module_ecrit_dans_le_docstring(self):
        # Ce module est une BASE posee en avance du besoin : les perimetres exposant un actif IA
        # restent rares. Le docstring doit le dire, sinon une exploitation future le lancera par
        # habitude sur des cibles qui n'ont pas de modele.
        self.assertIn("restent RARES", mod.__doc__)
        self.assertIn("PAS un outil de jailbreak", mod.__doc__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
