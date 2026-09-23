"""Tests hermetiques de `ssrf.redirect_loop` — aucun reseau.

DEUX CONTRATS SONT EPINGLES, et le second pese autant que le premier.

Le premier est la CONJONCTION. La preuve exige que du contenu interne apparaisse AVEC la boucle
et PAS sans elle. Sans la sonde directe on s'attribuerait un resultat que la cible donnait deja,
et le rapport serait faux — pas dans son constat, mais dans ce qu'il attribue a la technique.

Le second est le MASQUAGE. Cet oracle vise des points de metadonnees cloud, donc frole des
identifiants. Un rapport de bug bounty circule : il est lu au triage, archive, parfois joint a
un ticket. Y faire figurer une cle d'acces temporaire la diffuserait plus largement que ne l'a
fait la vulnerabilite elle-meme. Les tests ci-dessous verifient qu'aucune valeur de secret ne
peut entrer dans un finding.
"""
from __future__ import annotations

import unittest

from forge.roe import Action
from forge.modules import ssrfloop as mod
from forge.modules.ssrfloop import SsrfRedirectLoop, masquer, marqueurs_presents, loop_url

TGT = "https://app.test/fetch"
BASE = {"in_scope": ["app.test"], "param": "url", "callback_base": "https://oast.test"}

REPONSE_META = ('{"Code":"Success","AccessKeyId":"ASIA1234567890ABCDEF",'
                '"SecretAccessKey":"wJalrXUtnFEMIbK7MDENGbPxRfiCYEXAMPLEKEY",'
                '"Token":"IQoJb3JpZ2luX2VjEExample","instance-id":"i-0abc"}')


def _fire(repondre, atteste=None, params=None, target=TGT):
    """Tire l'oracle avec `_send` et `_atteste` remplaces. `repondre(valeur) -> (status, corps)`."""
    sauve = {}
    for nom in ("_send", "_atteste"):
        sauve[nom] = (nom in SsrfRedirectLoop.__dict__, SsrfRedirectLoop.__dict__.get(nom))

    def faux_send(self, action, param, valeur, timeout):
        return repondre(valeur)

    def faux_att(self, action, token, timeout):
        return atteste

    SsrfRedirectLoop._send = faux_send
    SsrfRedirectLoop._atteste = faux_att
    try:
        p = dict(BASE)
        p.update(params or {})
        return SsrfRedirectLoop().fire(Action("ssrf.redirect_loop", target, params=p))
    finally:
        for nom, (avait, orig) in sauve.items():
            if avait and orig is not None:
                setattr(SsrfRedirectLoop, nom, orig)
            else:
                try:
                    delattr(SsrfRedirectLoop, nom)
                except AttributeError:
                    pass


class TestMasquage(unittest.TestCase):
    """Aucune valeur de secret ne doit pouvoir entrer dans un finding."""

    def test_cle_aws_temporaire_masquee(self):
        out = masquer(REPONSE_META)
        self.assertNotIn("ASIA1234567890ABCDEF", out)
        self.assertNotIn("wJalrXUtnFEMIbK7MDENGbPxRfiCYEXAMPLEKEY", out)

    def test_secret_et_token_masques_par_champ(self):
        out = masquer(REPONSE_META)
        self.assertIn("[MASQUE]", out)
        self.assertNotIn("IQoJb3JpZ2luX2VjEExample", out)

    def test_jwt_masque(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef"
        self.assertNotIn(jwt, masquer("token=" + jwt))

    def test_extrait_borne(self):
        self.assertLessEqual(len(masquer("A" * 5000)), mod.MAX_EVIDENCE)

    def test_les_noms_de_champs_survivent(self):
        # Le masquage doit retirer les VALEURS sans effacer les NOMS : ce sont eux qui prouvent.
        self.assertIn("instance-id", masquer(REPONSE_META))


class TestMarqueurs(unittest.TestCase):

    def test_reconnait_les_champs_structurels(self):
        m = marqueurs_presents(REPONSE_META)
        self.assertIn("instance-id", m)
        self.assertIn("AccessKeyId", m)

    def test_page_ordinaire_ne_declenche_rien(self):
        self.assertEqual(marqueurs_presents("<html>bienvenue</html>"), [])

    def test_url_de_boucle_bien_formee(self):
        u = loop_url("https://oast.test/", "tok123", "http://169.254.169.254/x", 7)
        self.assertIn("/_redir?t=tok123&n=0", u)
        self.assertIn("max=7", u)
        self.assertIn("169.254.169.254", u)


class TestDegradations(unittest.TestCase):
    """« Pas rendu visible » ne doit jamais etre confondu avec « pas de SSRF »."""

    def test_hors_scope(self):
        appels = []
        _fire(lambda v: (appels.append(v), (200, ""))[1], target="https://evil.test/f")
        self.assertEqual(appels, [], "fail-closed : aucune requete hors perimetre")

    def test_config_manquante(self):
        out = _fire(lambda v: (200, ""), params={"callback_base": None})
        self.assertEqual(out[0].status, "skipped")
        self.assertIn("oast_server", out[0].evidence)

    def test_reseau_indisponible(self):
        out = _fire(lambda v: (None, ""))
        self.assertEqual(out[0].status, "skipped")

    def test_negatif_invite_a_faire_varier_avant_de_conclure(self):
        out = _fire(lambda v: (200, "<html>rien</html>"))
        self.assertEqual(out[0].status, "tested")
        self.assertIn("max_redirects", out[0].evidence)


class TestConjonction(unittest.TestCase):

    def _rep(self, direct="", boucle=""):
        def r(valeur):
            return (200, boucle if "/_redir" in valeur else direct)
        return r

    def test_boucle_revele_ce_que_la_directe_ne_donnait_pas(self):
        out = _fire(self._rep(direct="<html>rien</html>", boucle=REPONSE_META), atteste=True)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertEqual(out[0].severity, "HIGH")
        self.assertIn("RENDU VISIBLE", out[0].title)

    def test_deja_visible_sans_boucle_est_dit_comme_tel(self):
        # Attribuer a la technique un resultat que la sonde directe donnait deja serait faux.
        out = _fire(self._rep(direct=REPONSE_META, boucle=REPONSE_META), atteste=True)
        self.assertEqual(out[0].status, "vulnerable")
        self.assertIn("DEJA VISIBLE", out[0].title)

    def test_rien_nulle_part_est_un_negatif(self):
        out = _fire(self._rep(direct="rien", boucle="rien"), atteste=True)
        self.assertEqual(out[0].status, "tested")

    def test_atteinte_non_attestee_est_dite(self):
        out = _fire(self._rep(direct="rien", boucle="rien"), atteste=False)
        self.assertIn("NON attestee", out[0].evidence)

    def test_atteinte_non_verifiable_est_dite(self):
        out = _fire(self._rep(direct="rien", boucle="rien"), atteste=None)
        self.assertIn("non verifiee", out[0].evidence)


class TestPreuveNeFuitPas(unittest.TestCase):

    def test_la_preuve_ne_transporte_aucun_secret(self):
        out = _fire(lambda v: (200, REPONSE_META if "/_redir" in v else "rien"), atteste=True)
        self.assertEqual(out[0].status, "vulnerable")
        for secret in ("ASIA1234567890ABCDEF",
                       "wJalrXUtnFEMIbK7MDENGbPxRfiCYEXAMPLEKEY",
                       "IQoJb3JpZ2luX2VjEExample"):
            self.assertNotIn(secret, out[0].evidence)
        self.assertIn("instance-id", out[0].evidence)   # le NOM prouve, la valeur est inutile


class TestGardes(unittest.TestCase):

    def test_flags_declares(self):
        # On fait suivre des redirections : aucune charge active, aucun etat mute.
        self.assertFalse(SsrfRedirectLoop.exploit)
        self.assertFalse(SsrfRedirectLoop.destructive)

    def test_sauts_bornes(self):
        vus = []

        def r(v):
            vus.append(v)
            return (200, "rien")
        _fire(r, params={"max_redirects": 999})
        boucles = [v for v in vus if "/_redir" in v]
        self.assertTrue(boucles)
        self.assertIn("max=15", boucles[0])   # borne DURE, alignee sur le collecteur OAST


if __name__ == "__main__":
    unittest.main(verbosity=2)
