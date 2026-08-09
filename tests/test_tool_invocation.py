# SPDX-License-Identifier: AGPL-3.0-or-later
"""L'INVOCATION D'UN OUTIL EST UNE ASSERTION — ces tests la verrouillent.

CE QUE LE LEDGER A MONTRE. Quatre entrees du catalogue n'avaient JAMAIS tourne, sur aucune cible,
depuis leur integration. Le ledger signe `gxrun2` (11 Mo) porte **52 findings pour CHACUNE des
quatre causes** — quatre outils mal invoques sur CHAQUE cible, tous rendus en « j'ai verifie, rien
trouve » :

    gobuster dns -d <hote>   -> invalid value "<hote>" for flag -d: parse error   rc=1
    masscan <hote>           -> FAIL: unknown command-line parameter "<hote>"      rc=1
    dnsx -d <hote>           -> missing wordlist(w) flag required with domain(d)   rc=1
    theHarvester             -> pull access denied (l'image n'existe pas)          rc=125

LA GARDE D'HONNETETE (`blindness.tool_did_not_run`) fait desormais rendre `skipped` a ces
echecs-la. Ce fichier verrouille l'autre moitie du travail : que l'invocation soit CORRECTE, et
que ce qui ne peut PAS etre rendu correct ne reste PAS au catalogue.

DEUX DIAGNOSTICS « EVIDENTS » ETAIENT FAUX, ET LA MESURE LES A SORTIS :
  1. gobuster — « il manque -w » etait incomplet. En gobuster >= 3.x, **`-d` EST l'abreviation de
     `--delay`** (une duree) : `-d guatx.com` demandait de lire un nom d'hote comme un delai. Le
     domaine s'appelle `--domain`. `-w` est bien requis, mais n'aurait jamais ete atteint.
  2. gobuster (encore) — meme avec l'argv corrige, le PARSEUR du spec (`^Found:\\s+(\\S+)`) datait
     de gobuster <= 3.6 ; la 3.8 ecrit `<hote> <ip>`. Un argv juste + un parseur perime = le meme
     « aucun hit ». D'ou la regle : on ne valide pas un correctif d'invocation sans avoir LU une
     sortie reelle.

LES SORTIES INJECTEES ICI SONT MESUREES, pas inventees — obtenues en executant les outils contre
un serveur DNS stub sur 127.0.0.1 (aucun paquet vers une cible tierce) :
  gobuster 3.8.2 -> `www.lab.test 127.0.0.42`
  dnsx           -> `www.lab.test [A] [127.0.0.42]`  (avec `-nc` ; sans lui, des echappements ANSI)
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge import modules as mods                                              # noqa: E402
from forge.modules import toolcatalog                                          # noqa: E402
from forge.modules.toolspec import (build_argv, missing_required_params,       # noqa: E402
                                    parse_output)
from forge.roe import Action                                                   # noqa: E402


def _spec(kind):
    return mods.get(kind).spec


class _Boom(Exception):
    pass


def _boom(*a, **k):
    raise _Boom("runner.tool NE DOIT PAS etre atteint (fail-closed)")


class _Patch:
    """Patch de `forge.runner.available` / `.tool` — restaure a la sortie."""

    def __init__(self, available=None, tool=None):
        self.available, self.tool = available, tool

    def __enter__(self):
        from forge import runner
        self._sv = (runner.available, runner.tool)
        if self.available is not None:
            runner.available = self.available
        if self.tool is not None:
            runner.tool = self.tool
        return self

    def __exit__(self, *a):
        from forge import runner
        runner.available, runner.tool = self._sv
        return False


def _fire(kind, target, params):
    return mods.get(kind).fire(Action(kind, target, params=params))


# =================================================================================================
class TestGobusterArgvMeasured(unittest.TestCase):
    """gobuster 3.8.2 — `--domain`, jamais `-d <hote>` (qui EST `--delay`)."""

    def test_the_domain_goes_to_the_domain_flag(self):
        argv = build_argv(_spec("recon.gobuster_dns"), "app.test", {"wordlist": "/wl.txt"})
        self.assertIn("--domain", argv)
        self.assertEqual(argv[argv.index("--domain") + 1], "app.test")

    def test_the_host_is_never_passed_to_dash_d(self):
        """LA REGRESSION EXACTE, epinglee : `-d` suivi d'un nom d'hote. `-d` est une DUREE en
        gobuster 3.x ; l'y remettre ferait revenir `parse error` et ses 52 findings."""
        argv = build_argv(_spec("recon.gobuster_dns"), "app.test", {"wordlist": "/wl.txt"})
        for i, tok in enumerate(argv):
            if tok == "-d":
                self.assertNotEqual(argv[i + 1], "app.test",
                                    "le nom d'hote est repasse a -d (= --delay) : regression")

    def test_the_delay_derived_from_the_roe_rate_still_reaches_gobuster(self):
        """Le debit reste GOUVERNE : `scope.rate_explicit` -> `rate_delay_dur` -> `--delay`.
        Une enumeration par wordlist est du brute-force PAR VOLUME ; son debit ne doit pas
        s'echapper du ROE au passage du correctif."""
        argv = build_argv(_spec("recon.gobuster_dns"), "app.test",
                          {"wordlist": "/wl.txt", "rate_delay_dur": "200ms"})
        self.assertEqual(argv[argv.index("--delay") + 1], "200ms")

    def test_the_domain_flag_is_not_allowlisted_for_extra_args(self):
        """Un 2e `--domain` en argument libre ECRASERAIT la cible scope-guardee (le dernier gagne).
        Il ne doit donc JAMAIS etre allowlistable."""
        allow = set(_spec("recon.gobuster_dns").flag_allowlist)
        self.assertNotIn("--domain", allow)
        self.assertNotIn("--do", allow)

    def test_no_file_writing_or_file_reading_flag_is_allowlisted(self):
        allow = set(_spec("recon.gobuster_dns").flag_allowlist)
        for bad in ("-o", "--output", "-p", "--pattern", "--discover-pattern"):
            self.assertNotIn(bad, allow, f"{bad} ne doit pas etre allowlist")


# =================================================================================================
class TestParsersReadRealOutput(unittest.TestCase):
    """Le parseur doit lire la sortie REELLE de la version REELLEMENT invoquee."""

    def test_gobuster_38_output_shape_is_parsed(self):
        # MESURE : gobuster 3.8.2, mode dns, `-q` -> `<hote> <ip>` (aucun prefixe « Found: »).
        hits = parse_output(_spec("recon.gobuster_dns"), 0,
                            "www.lab.test 127.0.0.42\nmail.lab.test 127.0.0.42\n", "")
        self.assertEqual(hits, ["www.lab.test", "mail.lab.test"])

    def test_the_historic_found_prefix_still_parses(self):
        # gobuster <= 3.6 est encore deploye : le prefixe reste TOLERE (optionnel).
        hits = parse_output(_spec("recon.gobuster_dns"), 0, "Found: api.lab.test\n", "")
        self.assertEqual(hits, ["api.lab.test"])

    def test_gobuster_usage_text_yields_no_hit(self):
        """Le texte d'usage que gobuster deverse sur stdout quand il refuse un argv ne doit
        produire AUCUN hit — sinon un echec d'invocation se deguiserait en decouverte."""
        usage = ('Incorrect Usage: invalid value "app.test" for flag -d: parse error\n\n'
                 'NAME:\n   gobuster dns - Uses DNS subdomain enumeration mode\n'
                 'USAGE:\n   gobuster dns [command options]\n')
        self.assertEqual(parse_output(_spec("recon.gobuster_dns"), 1, usage, ""), [])

    def test_dnsx_asks_for_no_color_so_evidence_carries_no_escape_sequences(self):
        """MESURE : `-silent` ne suffit pas — dnsx colore meme redirige vers un fichier. Sans
        `-nc`, chaque finding embarquait des sequences ANSI dans son evidence et dans le ledger."""
        self.assertIn("-nc", build_argv(_spec("recon.dnsx"), "app.test", {"wordlist": "www"}))


# =================================================================================================
class TestWordlistPolicyIsInertButNamed(unittest.TestCase):
    """POLITIQUE : pas de wordlist embarquee ; pas de lancement sans wordlist. Inerte, mais NOMME."""

    KINDS = ("recon.gobuster_dns", "recon.dnsx")

    def test_missing_wordlist_skips_with_zero_process(self):
        for kind in self.KINDS:
            with _Patch(available=lambda *a, **k: True, tool=_boom):
                f = _fire(kind, "app.test", {"in_scope": ["app.test"]})
            self.assertEqual([x.status for x in f], ["skipped"], kind)
            self.assertIn("pré-requis manquant", f[0].title, kind)
            self.assertIn("wordlist", f[0].title, kind)

    def test_the_skip_is_never_tested(self):
        """LA LIGNE A NE PAS FRANCHIR : un pre-requis absent ne doit jamais devenir « j'ai
        verifie, rien trouve ». C'est la meme maladie que celle que ce chantier soigne."""
        for kind in self.KINDS:
            with _Patch(available=lambda *a, **k: True, tool=_boom):
                f = _fire(kind, "app.test", {"in_scope": ["app.test"]})
            self.assertNotIn("tested", [x.status for x in f], kind)

    def test_the_evidence_says_how_to_supply_it(self):
        for kind in self.KINDS:
            with _Patch(available=lambda *a, **k: True, tool=_boom):
                f = _fire(kind, "app.test", {"in_scope": ["app.test"]})
            self.assertIn("params.wordlist", f[0].evidence, kind)

    def test_a_supplied_wordlist_lets_the_tool_run(self):
        seen = {}

        def fake_tool(binary, image=None, args=None, **k):
            seen["argv"] = list(args or [])
            return (0, "www.app.test 127.0.0.42\n", "")

        with _Patch(available=lambda *a, **k: True, tool=fake_tool):
            f = _fire("recon.gobuster_dns", "app.test",
                      {"in_scope": ["app.test", "*.app.test"], "wordlist": "/wl.txt"})
        self.assertIn("-w", seen["argv"])
        self.assertEqual([x.status for x in f], ["tested"])
        self.assertEqual(f[0].target, "www.app.test")

    def test_empty_values_count_as_missing(self):
        """Une valeur vide (`""`, `[]`) est aussi ABSENTE : `build_argv` abandonne deja le groupe
        bati dessus, l'argv serait tout aussi incomplet."""
        spec = _spec("recon.dnsx")
        for empty in ("", [], None):
            self.assertEqual(missing_required_params(spec, {"wordlist": empty}), ("wordlist",))
        self.assertEqual(missing_required_params(spec, {"wordlist": "www"}), ())

    def test_the_gate_does_not_shadow_the_out_of_scope_refusal(self):
        """ORDRE DES PORTES : une cible HORS perimetre est refusee AVANT le pre-requis — le
        scope-guard reste la premiere porte, quoi qu'il arrive."""
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            f = _fire("recon.dnsx", "evil.attacker.com", {"in_scope": ["app.test"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("hors périmètre", f[0].title)

    def test_the_gate_does_not_shadow_the_extra_args_refusal(self):
        with _Patch(available=lambda *a, **k: True, tool=_boom):
            f = _fire("recon.dnsx", "app.test",
                      {"in_scope": ["app.test"], "extra_args": ["-o", "/etc/x"]})
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("argument libre refusé", f[0].title)


# =================================================================================================
class TestRemovedEntriesCannotComeBackSilently(unittest.TestCase):
    """DEUX ENTREES RETIREES. Une entree de catalogue qui ne peut pas fonctionner est PIRE qu'une
    entree absente : elle fait croire a une couverture. Les remettre exige de repasser par ce test
    — donc de REPROUVER qu'elles tournent."""

    REMOVED = {
        "recon.theharvester": (
            "l'image declaree (laramies/theharvester) N'EXISTE PAS ; l'image officielle de "
            "l'auteur (ghcr.io/laramies/theharvester) a pour entrypoint `restfulHarvest` — un "
            "SERVEUR REST que `runner` ne sait pas contourner (aucun --entrypoint)."),
        "recon.masscan": (
            "SYN brut : sur un hote multi-homed la reponse ne revient pas par l'adaptateur "
            "auto-detecte -> rc=0 STDOUT VIDE, que `tool_did_not_run` (borne rc != 0) ne peut "
            "PAS rattraper. Corriger l'argv aurait converti un `skipped` correct en `tested` "
            "mensonger. `recon.naabu` couvre les ports et, lui, il tourne."),
    }

    def test_removed_kinds_are_not_registered(self):
        for kind, why in self.REMOVED.items():
            self.assertNotIn(kind, list(mods.kinds()), f"{kind} de retour — {why}")

    def test_removed_kinds_are_not_in_the_catalog_specs(self):
        kinds = {s.kind for s in toolcatalog.CATALOG_SPECS}
        for kind, why in self.REMOVED.items():
            self.assertNotIn(kind, kinds, f"{kind} de retour au catalogue — {why}")

    def test_the_dead_docker_image_is_referenced_nowhere_as_a_spec_image(self):
        images = {s.docker_image for s in toolcatalog.CATALOG_SPECS if s.docker_image}
        self.assertNotIn("laramies/theharvester", images)

    def test_ports_are_still_covered_by_a_tool_that_runs(self):
        """CE QUE LA COUVERTURE NE PERD PAS : naabu reste au catalogue, emet la decouverte de
        service chainable, et accepte la plage complete."""
        self.assertIn("recon.naabu", list(mods.kinds()))
        self.assertTrue(_spec("recon.naabu").emit_service_discovery)
        argv = build_argv(_spec("recon.naabu"), "app.test", {"ports": "1-65535"})
        self.assertEqual(argv[argv.index("-p") + 1], "1-65535")

    def test_subdomains_are_still_covered_three_times(self):
        """CE QUE LA COUVERTURE NE PERD PAS non plus : theHarvester n'apportait d'unique que les
        EMAILS (jamais un asset scannable). Les sous-domaines restent couverts trois fois."""
        kinds = list(mods.kinds())
        for k in ("recon.subfinder", "recon.amass", "recon.subdomains"):
            self.assertIn(k, kinds)


# =================================================================================================
class TestHonestyGuardStillBites(unittest.TestCase):
    """NON-REGRESSION D'HONNETETE : le correctif ne doit pas rendre un echec SILENCIEUX. Ce qui ne
    tourne toujours pas reste `skipped`, avec sa raison nommee — jamais `tested`."""

    def test_a_tool_that_fails_after_the_gate_is_still_downgraded(self):
        """Pre-requis SATISFAIT, mais l'outil echoue quand meme (resolveur injoignable, image
        cassee) : rc != 0 + stdout vide -> la garde `tool_did_not_run` mord toujours."""
        with _Patch(available=lambda *a, **k: True,
                    tool=lambda *a, **k: (1, "", "[FTL] some other failure")):
            f = _fire("recon.dnsx", "app.test", {"in_scope": ["app.test"], "wordlist": "www"})
        self.assertEqual([x.status for x in f], ["skipped"])
        self.assertIn("NON VÉRIFIÉ", f[0].evidence)
        self.assertIn("rc=1", f[0].evidence)

    def test_a_healthy_empty_result_still_says_tested(self):
        """L'EXCES INVERSE, borne : un outil qui a tourne (rc=0) et n'a rien trouve a bel et bien
        verifie. Le declasser detruirait la valeur du rapport."""
        with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (0, "", "")):
            f = _fire("recon.dnsx", "app.test", {"in_scope": ["app.test"], "wordlist": "www"})
        self.assertEqual([x.status for x in f], ["tested"])


if __name__ == "__main__":
    unittest.main()
