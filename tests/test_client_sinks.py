"""Tests hermetiques de `recon.client_sinks` — aucun reseau, aucun fichier hors du depot.

Chaque test epingle un garde-fou qui a REELLEMENT saute pendant la construction du module
le 2026-09-09. Ce ne sont pas des cas theoriques : ce sont quatre faux negatifs successifs,
trouves chacun par un controle negatif, et dont la correction est ce qui a fait passer la
detection de ZERO a 64 candidats sur 1,1 Mo de bundles Angular reels.
"""
from __future__ import annotations

import pathlib
import re
import unittest

from forge.modules import client_sinks as cs


class TestCheminAvantVariable(unittest.TestCase):
    """Le filtre anti-bruit : un `${}` en PREFIXE d'hote n'est pas un segment de chemin."""

    def test_prefixe_hote_rejete(self):
        # `${basePath}` est l'hote, pas un segment traversable : rien a signaler.
        self.assertFalse(cs.chemin_avant_variable('.request("get",`${b}${l}`'))

    def test_segment_de_chemin_accepte(self):
        self.assertTrue(cs.chemin_avant_variable('let u=`/api/users/${'))

    def test_concatenation_par_plus_acceptee(self):
        # REGRESSION 2026-09-09 : la 1re version regardait le DERNIER fragment apres
        # delimiteur. La concatenation ferme le litteral et ne laisse qu'un `+` derriere,
        # donc `fetch("/api/u/"+id)` etait rejete a tort.
        self.assertTrue(cs.chemin_avant_variable('fetch("/api/u/"+'))

    def test_sans_delimiteur_rejete(self):
        self.assertFalse(cs.chemin_avant_variable('foo(bar'))


class TestMotifsCspt(unittest.TestCase):
    """Les motifs eux-memes, un par piege rencontre."""

    def _candidat(self, txt):
        for nom, rx in cs.CSPT_SINKS.items():
            for m in re.finditer(rx, txt):
                if cs.chemin_avant_variable(m.group(0)):
                    return nom
        return None

    def test_chemin_litteral_ignore(self):
        self.assertIsNone(self._candidat('fetch("/api/config")'))

    def test_template_sans_chemin_ignore(self):
        self.assertIsNone(self._candidat('let base=`${env.api}`'))

    def test_fetch_construit(self):
        self.assertIsNotNone(self._candidat('fetch(`/api/x/${a}`)'))

    def test_axios_construit(self):
        self.assertIsNotNone(self._candidat('axios.get(`/orders/${n}/items`)'))

    def test_angular_request_methode_en_argument(self):
        # REGRESSION : Angular passe la methode en ARGUMENT (`request("put", url)`), pas
        # comme nom de fonction. Sans entree dediee, tout client genere passait a travers.
        self.assertIsNotNone(self._candidat('this.http.request("put",`/e/file/${x}`)'))

    def test_openapi_generator_chemin_en_variable(self):
        # REGRESSION, et c'est le cas DOMINANT : openapi-generator ne met jamais le chemin
        # parametre en ligne dans l'appel, il le construit dans une variable intermediaire.
        # Sans cette entree, des bundles truffes de chemins parametres rendaient ZERO candidat.
        self.assertIsNotNone(
            self._candidat('let l=`/ReimbursementClaim/${this.conf.encodeParam({name:"id"})}`'))


class TestAnalyse(unittest.TestCase):
    """L'appariement complet, sur du code synthetique."""

    def test_flux_xss_dom_apparie_par_proximite(self):
        code = 'var h=location.hash;document.getElementById("x").innerHTML=h;'
        flux = cs.analyser({"a.js": code})
        self.assertTrue(any(f["motif"] == "XSS_DOM" and f["puits"] == "innerHTML" for f in flux))

    def test_cspt_ne_reclame_PAS_de_source_proche(self):
        # Choix DELIBERE, mesure a l'appui : sur 1,1 Mo de bundles Angular reels, exiger une
        # source a proximite rend ZERO candidat, parce que la source (parametre de route) et
        # le puits (service d'API genere) vivent dans des FONCTIONS DIFFERENTES.
        code = 'function f(id){let p=`/api/users/${id}`;return this.http.request("get",p);}'
        flux = cs.analyser({"a.js": code})
        self.assertTrue(any(f["motif"] == "CSPT" for f in flux),
                        "le candidat CSPT doit sortir SANS source a proximite")

    def test_reparse_entites_signale(self):
        code = 'el.innerHTML = other.textContent;'
        flux = cs.analyser({"a.js": code})
        self.assertTrue(any(f["motif"] == "REPARSE_ENTITES" for f in flux))

    def test_ternaire_bootstrap_non_apparie(self):
        # Faux positif rencontre sur une cible reelle : deux branches EXCLUSIVES, aucun flux.
        code = 'this._config.html ? el.innerHTML = this._san(h) : el.textContent = h;'
        flux = cs.analyser({"a.js": code})
        self.assertFalse(any(f["motif"] == "REPARSE_ENTITES" for f in flux))

    def test_ordre_reparse_puis_cspt_puis_xss(self):
        code = ('el.innerHTML = o.textContent;'
                'let p=`/api/u/${i}`;'
                'var h=location.hash;d.innerHTML=h;')
        motifs = [f["motif"] for f in cs.analyser({"a.js": code})]
        self.assertEqual(motifs[0], "REPARSE_ENTITES")
        self.assertLess(motifs.index("CSPT"), motifs.index("XSS_DOM"))


class TestScripts(unittest.TestCase):
    """L'extraction ne doit JAMAIS sortir du site analyse."""

    def test_script_tiers_ignore(self):
        html = ('<script src="https://cdn.tiers.test/a.js"></script>'
                '<script src="/local/b.js"></script>')
        urls, inline = cs.extraire_scripts(html, "https://app.test/p")
        self.assertEqual(urls, ["https://app.test/local/b.js"])
        self.assertEqual(inline, [])

    def test_script_inline_collecte(self):
        urls, inline = cs.extraire_scripts('<script>var a=1;</script>', "https://app.test/")
        self.assertEqual(urls, [])
        self.assertEqual(len(inline), 1)


class TestJumeauToolkit(unittest.TestCase):
    """Les catalogues sont DUPLIQUES dans `toolkit/web/dom_sink_finder.py` (forge doit rester
    autonome). Ce test empeche les deux copies de deriver en silence — et se saute proprement
    si le jumeau est absent, pour que forge reste testable hors de son depot parent."""

    def test_catalogues_alignes_si_jumeau_present(self):
        # tests/ -> forge/ -> toolkit/  : parents[2] est bien `toolkit`, d'ou `toolkit/web/`.
        jumeau = (pathlib.Path(__file__).resolve().parents[2]
                  / "web" / "dom_sink_finder.py")
        if not jumeau.exists():
            self.skipTest("jumeau toolkit absent — forge reste autonome")
        src = jumeau.read_text(encoding="utf8", errors="replace")
        for nom in list(cs.SOURCES) + list(cs.SINKS) + list(cs.CSPT_SINKS):
            self.assertIn(nom, src, f"« {nom} » manque dans le jumeau toolkit — les deux "
                                    f"catalogues ont derive")


if __name__ == "__main__":
    unittest.main(verbosity=2)
