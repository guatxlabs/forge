# SPDX-License-Identifier: AGPL-3.0-or-later
"""D16 — 13 nmap sur 13 rendaient « j'ai vérifié » après avoir scanné **0 hôte**. Prouvé DANS LES
DEUX SENS (`docs/BENCH_DETECTION.md` §6, D16).

CE QU'A MESURÉ LE REJEU DU BANC
--------------------------------
Le correctif D9 avait fait chuter le NOMBRE de tirs nmap aveugles (72 -> 13) en appliquant au
balayage autonome le garde hôte/endpoint du plan de base. Le défaut que D9 NOMMAIT — « un outil qui
n'a rien scanné est rendu en “j'ai vérifié” » — est resté intact, et sa fréquence est passée de
22/72 à **13/13** : les 13 findings portent `Nmap done: 0 IP addresses (0 hosts up)` sous le titre
« Services exposés (nmap -sV) », en `status=tested`.

Reconstruction du 13 depuis le ledger du banc (85 findings nmap, 100 % aveugles), en ne gardant que
ceux que le garde D9 (`not is_endpoint_target`) laisse passer — 9 URL de RACINE + 4 `host:port` :

    dvga  127.0.0.1:5013 · http://127.0.0.1:5013 · http://127.0.0.1:5013/
    dvwa  127.0.0.1:8081 · http://127.0.0.1:8081 · http://127.0.0.1:8081/ · https://127.0.0.1:8081
    juice 127.0.0.1:3000 · http://127.0.0.1:3000
    vampi 127.0.0.1:5001 · http://127.0.0.1:5001 · http://127.0.0.1:5001/ · https://127.0.0.1:5001

DEUX FORMES, MESURÉES CONTRE LE VRAI BINAIRE (`instrumentisto/nmap` 7.98, loopback) :

    nmap -sV -Pn --top-ports 20 http://127.0.0.1:8081   Unable to split netmask from target
                                                        expression -> 0 IP addresses (0 hosts up)
    nmap … http://127.0.0.1:8081/                       idem
    nmap … 127.0.0.1:8081                               Failed to resolve "127.0.0.1:8081"
                                                        -> 0 IP addresses (0 hosts up)
    nmap … 127.0.0.1                                    1 IP address (1 host up) scanned  <- le vrai

Les trois formes aveugles sortent **rc=0** : ni `Module.tool_failed` (`rc != 0`) ni
`blindness.tool_did_not_run` (`rc != 0` ET stdout vide) ne peuvent les voir — et `blindness` refuse
délibérément d'élargir à `rc == 0` (un scan légitime d'une cible saine sort lui aussi à rc=0).

DEUX LIGNES, PAS UNE
---------------------
  1. LE GARDE, COUVERTURE ÉTENDUE (`brain._raw_target_kinds` + `planner.is_bare_host_target`) — le
     cerveau ne PROPOSE plus les kinds qui reçoivent la cible SANS normalisation sur une cible qui
     n'est pas un hôte nu. Sous-ensemble STRICT du garde D9 : sur une URL de racine,
     katana/feroxbuster/content/httpx/js_endpoints — tous hôte-scopés — travaillent parfaitement.
  2. L'ABSTENTION (`recon._nmap_scanned_nothing`) — ce qui tire quand même sur 0 hôte rend
     `skipped`, jamais `tested`. C'est nmap LUI-MÊME qui le déclare dans sa ligne de bilan.

LES DEUX SENS :
  SENS 1 — les 13 formes du banc : 0 proposition, et `skipped` si l'action tire quand même.
  SENS 2 — l'hôte NU : nmap est toujours proposé, et un scan RÉEL (y compris un scan légitime qui
           ne trouve AUCUN port ouvert) rend toujours `tested` — le verdict négatif reste un verdict.
  MUTATION — les deux lignes neutralisées une par une : les tirs aveugles et le `tested` mensonger
           REVIENNENT.
"""
import sys
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import forge.modules  # noqa: F401,E402  (charge le registre : specs + natifs)
from forge import runner                                           # noqa: E402
from forge.brain import AutoPentestBrain                           # noqa: E402
from forge.graph import EngagementGraph                            # noqa: E402
from forge.modules import recon as recon_mod                       # noqa: E402
from forge.modules import registry                                 # noqa: E402
from forge.modules.recon import NmapServices, _nmap_scanned_nothing  # noqa: E402
from forge.planner import is_bare_host_target, is_endpoint_target  # noqa: E402
from forge.roe import Action                                       # noqa: E402

#: les 13 cibles que le rejeu a tirées à l'aveugle (reconstruites du ledger du banc).
CIBLES_AVEUGLES = [
    "127.0.0.1:5013", "http://127.0.0.1:5013", "http://127.0.0.1:5013/",
    "127.0.0.1:8081", "http://127.0.0.1:8081", "http://127.0.0.1:8081/", "https://127.0.0.1:8081",
    "127.0.0.1:3000", "http://127.0.0.1:3000",
    "127.0.0.1:5001", "http://127.0.0.1:5001", "http://127.0.0.1:5001/", "https://127.0.0.1:5001",
]

# --- sorties VERBATIM du binaire nmap 7.98, capturées en loopback -------------------------------
OUT_URL = ('Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-11 12:27 +0000\n'
           'Unable to split netmask from target expression: "http://127.0.0.1:8081"\n'
           'WARNING: No targets were specified, so 0 hosts scanned.\n'
           'Nmap done: 0 IP addresses (0 hosts up) scanned in 0.18 seconds\n')
OUT_HOSTPORT = ('Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-11 12:27 +0000\n'
                'Failed to resolve "127.0.0.1:8081".\n'
                'Nmap done: 0 IP addresses (0 hosts up) scanned in 0.66 seconds\n'
                'WARNING: No targets were specified, so 0 hosts scanned.\n')
OUT_REEL = ('Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-11 12:37 +0000\n'
            'Nmap scan report for localhost (127.0.0.1)\n'
            'Host is up (0.0000090s latency).\n\n'
            'PORT     STATE  SERVICE       VERSION\n'
            '8080/tcp open   http          Uvicorn\n\n'
            'Nmap done: 1 IP address (1 host up) scanned in 6.30 seconds\n')
OUT_REEL_VIDE = ('Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-11 12:47 +0000\n'
                 'Nmap scan report for localhost (127.0.0.1)\n'
                 'Host is up (0.000041s latency).\n\n'
                 'PORT  STATE  SERVICE VERSION\n'
                 '9/tcp closed discard\n\n'
                 'Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds\n')


def _graph(target, kind="url"):
    g = EngagementGraph()
    g.add_host(target, kind=kind, service="http")
    return g


def _nmap_actions(target):
    return [a for a in AutoPentestBrain().propose(_graph(target)) if a.kind == "recon.nmap"]


def _fire(target, out, rc=0):
    """Tire `recon.nmap` avec une sortie d'outil IMPOSÉE (aucun réseau, aucun docker)."""
    with mock.patch.object(runner, "tool", lambda *a, **k: (rc, out, "")):
        return NmapServices().fire(Action("recon.nmap", target, params={}))


# =================================================================================================
class TestPredicatDeForme(unittest.TestCase):
    """`is_bare_host_target` — « pas un endpoint » ne veut PAS dire « un hôte ». C'est tout D16."""

    def test_les_formes_aveugles_ne_sont_PAS_des_hotes_nus(self):
        for t in CIBLES_AVEUGLES:
            self.assertFalse(is_bare_host_target(t), t)

    def test_mais_le_garde_D9_les_prend_toutes_pour_des_hotes(self):
        """La démonstration du trou : `is_endpoint_target` rend False sur les 13 — c'est pour ça
        qu'elles échappaient au garde."""
        for t in CIBLES_AVEUGLES:
            self.assertFalse(is_endpoint_target(t), t)

    def test_les_hotes_nus_le_sont(self):
        for t in ("127.0.0.1", "example.com", "sub.example.com", "::1", "fe80::1", "10.0.0.7"):
            self.assertTrue(is_bare_host_target(t), t)

    def test_les_autres_formes_ne_le_sont_pas(self):
        for t in ("http://x/a?b=1", "x/a", "user@example.com", "[::1]:8081", "", "  "):
            self.assertFalse(is_bare_host_target(t), t)


# =================================================================================================
class TestGardeDeriveEtNonListe(unittest.TestCase):
    """L'ensemble bloqué se DÉDUIT de ce que le dépôt déclare — comme son aîné `_host_scoped_kinds`."""

    def test_contient_nmap(self):
        self.assertIn("recon.nmap", AutoPentestBrain._raw_target_kinds())

    def test_est_un_SOUS_ENSEMBLE_STRICT_du_garde_endpoint(self):
        """Il le FAUT : sur une URL de racine, katana/feroxbuster/content/httpx/js_endpoints — tous
        hôte-scopés — travaillent parfaitement. Appliquer D9 tel quel aux URL décapiterait la
        découverte de contenu (c'est feroxbuster qui a produit les 1558 findings de DVWA piste B)."""
        raw = AutoPentestBrain._raw_target_kinds()
        host_scoped = AutoPentestBrain._host_scoped_kinds()
        self.assertTrue(raw < host_scoped, "doit être un sous-ensemble STRICT")
        for kind in ("recon.katana", "recon.feroxbuster", "recon.content", "recon.httpx",
                     "recon.js_endpoints", "evasion.discover", "web.testssl", "origin.find"):
            self.assertNotIn(kind, raw, f"{kind} sait consommer une URL / normalise sa cible")

    def test_un_nouvel_outil_a_cible_BRUTE_entre_automatiquement(self):
        """Un `ToolSpec` ajouté demain avec un `{target}` BRUT (ni `{target_host}` ni
        `{target_url}`) est classé sans que personne n'ait à toucher ce fichier."""
        class _Spec:
            argv_template = ("-x", "{target}")
            speaks_http = False
            asset_hits = False
            emit_endpoint_discovery = False
            emit_service_discovery = False

        class _Mod:
            kind = "recon.tout_brut"
            spec = _Spec()

        registry.REGISTRY["recon.tout_brut"] = _Mod()
        try:
            self.assertIn("recon.tout_brut", AutoPentestBrain._raw_target_kinds())
        finally:
            registry.REGISTRY.pop("recon.tout_brut", None)

    def test_aucun_oracle_ny_tombe(self):
        raw = AutoPentestBrain._raw_target_kinds()
        for kind in ("access_control.idor", "sqli.probe", "xss.reflected", "ssrf.callback",
                     "auth.takeover", "rce.probe", "web.nuclei", "header_injection.probe"):
            self.assertNotIn(kind, raw, kind)


# =================================================================================================
class TestSens1LesTreizeTirsAveuglesDisparaissent(unittest.TestCase):

    def test_aucune_des_13_cibles_ne_recoit_nmap(self):
        restants = [t for t in CIBLES_AVEUGLES if _nmap_actions(t)]
        self.assertEqual(restants, [], f"{len(restants)} tir(s) nmap aveugle(s) subsistent")

    def test_le_service_decouvert_host_port_non_plus(self):
        """Le nœud `service` (host:port émis par httpx/nmap) passait par `_base_actions`, pas par le
        balayage : le garde doit couvrir LES DEUX chemins."""
        self.assertEqual(_nmap_actions("127.0.0.1:5013"), [])
        g = _graph("127.0.0.1:5013", kind="service")
        self.assertEqual([a for a in AutoPentestBrain().propose(g) if a.kind == "recon.nmap"], [])


# =================================================================================================
class TestSens2LeVraiTirEstCONSERVE(unittest.TestCase):
    """L'excès inverse coûterait la technique entière : sur un hôte, rien ne change."""

    def test_nmap_reste_propose_sur_un_hote_nu(self):
        for t in ("127.0.0.1", "example.com", "::1"):
            self.assertTrue(_nmap_actions(t), t)

    def test_la_couverture_dune_URL_de_racine_est_INTACTE_hors_nmap(self):
        """Le garde ne retire QUE nmap : tout le reste du balayage doit rester identique."""
        apres = {a.kind for a in AutoPentestBrain().propose(_graph("http://127.0.0.1:8081"))}
        with mock.patch.object(AutoPentestBrain, "_raw_target_kinds",
                               staticmethod(lambda: frozenset())):
            avant = {a.kind for a in AutoPentestBrain().propose(_graph("http://127.0.0.1:8081"))}
        self.assertEqual(avant - apres, {"recon.nmap"},
                         "le garde ne doit retirer QUE recon.nmap sur une URL de racine")
        for kind in ("recon.katana", "recon.feroxbuster", "recon.content", "recon.httpx",
                     "recon.js_endpoints", "access_control.idor", "sqli.probe"):
            self.assertIn(kind, apres, kind)


# =================================================================================================
class TestAbstentionDuModule(unittest.TestCase):
    """Seconde ligne : ce qui tire QUAND MÊME sur 0 hôte ne peut plus affirmer avoir vérifié."""

    def test_le_discriminant_lit_la_ligne_de_BILAN_de_nmap(self):
        self.assertTrue(_nmap_scanned_nothing(OUT_URL, ""))
        self.assertTrue(_nmap_scanned_nothing(OUT_HOSTPORT, ""))
        self.assertFalse(_nmap_scanned_nothing(OUT_REEL, ""))
        self.assertFalse(_nmap_scanned_nothing(OUT_REEL_VIDE, ""))
        self.assertFalse(_nmap_scanned_nothing("", ""))

    def test_forme_URL_rend_skipped(self):
        fs = _fire("http://127.0.0.1:8081", OUT_URL)
        self.assertEqual([f.status for f in fs], ["skipped"])
        self.assertIn("NON VÉRIFIÉ", fs[0].title)
        self.assertIn("0 IP addresses (0 hosts up)", fs[0].evidence)

    def test_forme_host_port_rend_skipped(self):
        fs = _fire("127.0.0.1:8081", OUT_HOSTPORT)
        self.assertEqual([f.status for f in fs], ["skipped"])

    def test_un_scan_REEL_rend_toujours_tested_et_ses_decouvertes(self):
        fs = _fire("127.0.0.1", OUT_REEL)
        self.assertEqual(fs[0].status, "tested")
        self.assertIn("Services exposés", fs[0].title)
        self.assertTrue(any("8080" in f.title for f in fs[1:]),
                        "l'inventaire / la découverte de service doivent survivre")

    def test_BORNE_un_scan_legitime_SANS_port_ouvert_reste_un_VERDICT(self):
        """L'excès inverse exact que `blindness` refuse : un scan qui a bien tourné sur un hôte VIVANT
        et n'a trouvé aucun port ouvert dit « rien trouvé », pas « pas vérifié »."""
        fs = _fire("127.0.0.1", OUT_REEL_VIDE)
        self.assertEqual(fs[0].status, "tested")
        self.assertNotIn("NON VÉRIFIÉ", fs[0].title)

    def test_un_echec_rc_non_nul_garde_son_chemin_historique(self):
        fs = _fire("127.0.0.1", "", rc=127)
        self.assertIn("indisponible", fs[0].title)


# =================================================================================================
class TestMutationLesDeuxLignesSontPORTEUSES(unittest.TestCase):
    """MUTATION, une ligne à la fois : neutralisée, le défaut REVIENT. Sinon on ne saurait pas que
    c'est bien elle qui l'écarte."""

    def test_garde_neutralise_les_13_tirs_aveugles_REVIENNENT(self):
        with mock.patch.object(AutoPentestBrain, "_raw_target_kinds",
                               staticmethod(lambda: frozenset())):
            revenus = [t for t in CIBLES_AVEUGLES if _nmap_actions(t)]
        self.assertEqual(len(revenus), 13,
                         "MUTATION INATTEIGNABLE : ce n'est pas le garde qui écarte ces 13 tirs")

    def test_abstention_neutralisee_le_tested_mensonger_REVIENT(self):
        with mock.patch.object(recon_mod, "_nmap_scanned_nothing", lambda out, err: False):
            fs = _fire("http://127.0.0.1:8081", OUT_URL)
        self.assertEqual(fs[0].status, "tested")
        self.assertIn("Services exposés (nmap -sV)", fs[0].title)
        self.assertIn("0 IP addresses (0 hosts up)", fs[0].evidence)


if __name__ == "__main__":
    unittest.main()
