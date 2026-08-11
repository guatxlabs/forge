# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEUX CONSTATS MESURÉS — la phrase « aucun hit » quand TOUT a été filtré hors-scope, et la voie
docker du runner (montages REFUSÉS, `--entrypoint` LIVRÉ et gouverné).

═══ (A) « AUCUN HIT » ALORS QUE L'OUTIL AVAIT TROUVÉ ═══
REPRODUIT : `recon.gobuster_dns` rend `www.lab.test` + `mail.lab.test` sur `in_scope=["lab.test"]`
(un motif d'hôte est EXACT — les sous-domaines exigeraient `*.lab.test`). La re-validation fail-closed
les écarte TOUS — correctement — et `toolspec._hits_to_findings` rendait alors :

    [tested] « recon.gobuster_dns — gobuster: aucun hit »
             evidence: « Outil exécuté (in-scope), aucun résultat. »

Le FILTRAGE est le scope-guard qui fait son travail : il est VERROUILLÉ ICI, à l'identique
(`TestFilterStillDropsOutOfScope`). Le VERDICT `tested` est correct aussi : l'outil a bel et bien
tourné et regardé — en faire un `skipped` serait l'excès inverse, et il est verrouillé ICI AUSSI
(`test_status_stays_tested_never_skipped`). C'est la PHRASE qui était fausse : « j'ai trouvé, mais
hors périmètre » n'est pas « rien ».

CE QUI EST PROUVÉ : le COMPTE des écartés est dans le titre ET l'évidence ; les VALEURS écartées n'y
sont NULLE PART (titre, évidence, PoC) — un finding est journalisé au ledger signé puis exporté, y
déposer des hôtes/URL de TIERS hors périmètre serait une fuite de reconnaissance sur eux ; et le
chemin « 0 hit brut » reste BYTE-IDENTIQUE (aucune régression sur la phrase historique).

═══ (B) LA VOIE DOCKER DU RUNNER ═══
`runner` construit `docker run --rm --network host [--entrypoint E] <image> <args…>`.
  - AUCUN `-v`/`--mount` — décision documentée, VERROUILLÉE ici (`TestNoVolumeMountEver`) : un montage,
    même `:ro`, borne les écritures et pas les LECTURES, et `--network host` est déjà là (une lecture
    est à un `curl` de l'exfiltration) ; le chemin viendrait d'un PARAM d'exécution (canal de plus
    basse confiance) ; et le borner correctement imposerait un défaut vide (gain nul par défaut).
  - `--entrypoint` EST livré (il n'expose aucun fichier) et débloque un cas MESURÉ : l'entrypoint de
    `ghcr.io/laramies/theharvester` est `restfulHarvest` (serveur REST), pas la CLI.
  - GOUVERNÉ FAIL-CLOSED : un entrypoint interpréteur/shell est REFUSÉ (sinon un ToolSpec DÉCLARATIF
    du dossier `./toolspecs` — monté `:ro` PAR DÉFAUT et vendu « gouverné, zéro code » — poserait
    `docker_entrypoint: "sh"` + `argv_template: ["-c", …]` et réintroduirait le shell).
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import modules as mods                                          # noqa: E402
from forge import runner                                                   # noqa: E402
from forge.roe import Action                                               # noqa: E402
from forge.modules import loader as _loader                                # noqa: E402
from forge.modules.toolspec import (ToolSpec, asset_of, asset_rejected,    # noqa: E402
                                    make_module, out_of_scope_hits)

_THEHARVESTER_IMG = "ghcr.io/laramies/theharvester:latest"


class _Patch:
    """Remplace temporairement des attributs du module `runner` (référencé à l'appel par toolspec)."""

    def __init__(self, **attrs):
        self.attrs = attrs
        self.saved = {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(runner, k)
            setattr(runner, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(runner, k, v)


def _fire(kind, target, stdout, params, rc=0, stderr="sortie d'erreur de l'outil"):
    """Tire un module de catalogue avec `runner.tool` MOCKÉ (zéro I/O réel)."""
    m = mods.get(kind)
    with _Patch(available=lambda *a, **k: True, tool=lambda *a, **k: (rc, stdout, stderr)):
        return m.fire(Action(kind, target, params=params))


def _surface(f):
    """TOUT ce qu'un finding publie (titre + évidence + PoC) — la surface où une fuite se verrait."""
    return " ".join([f.title or "", f.evidence or "", f.poc or ""])


# =================================================================================================
#  (A1) LE FILTRE NE BOUGE PAS — c'est le scope-guard, et il reste intact
# =================================================================================================
class TestFilterStillDropsOutOfScope(unittest.TestCase):
    """Contre-preuve du chantier : on corrige une PHRASE, pas un filtre. Si l'un de ces tests casse,
    c'est que le correctif a élargi le périmètre — le contraire de ce qui était demandé."""

    def test_no_out_of_scope_asset_is_ever_emitted(self):
        f = _fire("recon.gobuster_dns", "lab.test",
                  "www.lab.test 127.0.0.42\nmail.lab.test 127.0.0.43\n",
                  {"in_scope": ["lab.test"], "wordlist": "/w.txt"})
        for x in f:
            self.assertEqual(x.target, "lab.test", "un asset HORS périmètre a été émis comme cible")

    def test_in_scope_assets_still_pass_and_out_of_scope_still_dropped(self):
        f = _fire("recon.gobuster_dns", "lab.test",
                  "www.lab.test 127.0.0.42\nevil.attacker.test 127.0.0.43\n",
                  {"in_scope": ["lab.test", "*.lab.test"], "wordlist": "/w.txt"})
        targets = {x.target for x in f}
        self.assertIn("www.lab.test", targets)
        self.assertNotIn("evil.attacker.test", targets)

    def test_partial_filtering_never_reaches_the_absence_branch(self):
        """Un seul survivant in-scope => on émet CE constat, jamais un constat d'absence."""
        f = _fire("recon.gobuster_dns", "lab.test",
                  "www.lab.test 1.2.3.4\nmail.other.test 5.6.7.8\n",
                  {"in_scope": ["lab.test", "www.lab.test"], "wordlist": "/w.txt"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].target, "www.lab.test")
        self.assertNotIn("hors périmètre", f[0].title)

    def test_predicate_is_shared_by_filter_and_counter(self):
        """`asset_rejected` est LE prédicat des deux côtés (filtre + compteur) : un hit rejeté par le
        prédicat est compté par `out_of_scope_hits`, et réciproquement — ils ne peuvent pas diverger."""
        class _Sc:
            def is_in_scope(self, t):
                return t == "keep.test"
        sc, spec = _Sc(), mods.get("recon.gobuster_dns").spec
        hits = ["keep.test 1.1.1.1", "drop.test 2.2.2.2", "other.test 3.3.3.3"]
        rejected = [h for h in hits if asset_rejected(True, sc, h)]
        self.assertEqual(len(rejected), 2)
        self.assertEqual(out_of_scope_hits(spec, True, sc, hits), len(rejected))
        self.assertEqual(asset_of("www.lab.test 127.0.0.42"), "www.lab.test")

    def test_counter_is_zero_without_injected_scope(self):
        """Sans périmètre injecté (dev/test) rien n'est écarté -> aucun compte, phrase historique."""
        spec = mods.get("recon.gobuster_dns").spec
        self.assertEqual(out_of_scope_hits(spec, False, None, ["a.test x", "b.test y"]), 0)


# =================================================================================================
#  (A2) LA PHRASE — le COMPTE est dit, les VALEURS ne le sont pas, le statut ne bouge pas
# =================================================================================================
class TestAllFilteredIsNotNothing(unittest.TestCase):

    def _all_filtered(self):
        return _fire("recon.gobuster_dns", "lab.test",
                     "www.lab.test 127.0.0.42\nmail.lab.test 127.0.0.43\n",
                     {"in_scope": ["lab.test"], "wordlist": "/w.txt"})

    def test_count_is_reported_in_title_and_evidence(self):
        f = self._all_filtered()
        self.assertEqual(len(f), 1)
        self.assertIn("2 résultat(s)", f[0].title)
        self.assertIn("hors périmètre", f[0].title)
        self.assertIn("RENDU 2 résultat(s)", f[0].evidence)

    def test_the_false_phrase_is_gone(self):
        f = self._all_filtered()
        self.assertNotIn("aucun hit", f[0].title)
        self.assertNotIn("aucun résultat", f[0].evidence)

    def test_status_stays_tested_never_skipped(self):
        """BORNE INVERSE : l'outil A tourné et A regardé -> `tested`. Le déclasser en `skipped` serait
        l'excès symétrique (« je n'ai pas pu vérifier » alors qu'on a parfaitement vérifié)."""
        for x in self._all_filtered():
            self.assertEqual(x.status, "tested")

    def test_out_of_scope_values_are_never_written_anywhere(self):
        """LA fuite à ne pas commettre : un finding est journalisé au ledger et exporté. Le compte est
        publiable ; les hôtes découverts HORS périmètre sont de la reconnaissance sur des TIERS."""
        f = self._all_filtered()
        surface = _surface(f[0])
        for leaked in ("www.lab.test", "mail.lab.test", "127.0.0.42", "127.0.0.43"):
            self.assertNotIn(leaked, surface, f"valeur hors-périmètre {leaked!r} publiée dans le finding")

    def test_zero_raw_hits_keeps_the_historic_phrase_byte_identical(self):
        """La borne de non-régression : « 0 hit brut » n'est PAS « N hits tous filtrés »."""
        f = _fire("recon.gobuster_dns", "lab.test", "", {"in_scope": ["lab.test"], "wordlist": "/w.txt"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "tested")
        self.assertEqual(f[0].title, "recon.gobuster_dns — gobuster: aucun hit")
        self.assertEqual(f[0].evidence, "Outil exécuté (in-scope), aucun résultat.")

    def test_non_asset_tool_is_untouched(self):
        """Un outil qui RAPPORTE sur la cible (pas d'assets découverts) n'a pas de filtre de périmètre
        sur ses hits : sa phrase d'absence reste l'historique."""
        f = _fire("recon.wafw00f", "http://lab.test", "", {"in_scope": ["lab.test"]})
        self.assertEqual(f[0].evidence, "Outil exécuté (in-scope), aucun résultat.")

    def test_rc_nonzero_with_all_filtered_hits_also_says_the_count(self):
        f = _fire("recon.gobuster_dns", "lab.test", "www.lab.test 1.2.3.4\n",
                  {"in_scope": ["lab.test"], "wordlist": "/w.txt"}, rc=2)
        self.assertEqual(f[0].status, "tested")
        self.assertIn("1 résultat(s) rendus, tous hors périmètre", f[0].title)
        self.assertIn("sortie d'erreur de l'outil", f[0].evidence)   # la sortie d'outil est CONSERVÉE
        self.assertNotIn("www.lab.test", _surface(f[0]))

    def test_rc_nonzero_without_filtering_keeps_the_historic_note(self):
        f = _fire("recon.gobuster_dns", "lab.test", "", {"in_scope": ["lab.test"], "wordlist": "/w.txt"},
                  rc=2)
        self.assertIn("aucun hit exploitable", f[0].title)


# =================================================================================================
#  (A3) MÊME PHRASE, VOIE ENDPOINT — un crawler dont toutes les URLs sortent du périmètre
# =================================================================================================
class TestCrawlerEndpointsAllFiltered(unittest.TestCase):

    def _all_filtered(self, kind="recon.gau"):
        return _fire(kind, "lab.test",
                     "http://a.evil.test/x?p=1\nhttp://b.evil.test/y\nhttp://c.evil.test/z\n",
                     {"in_scope": ["lab.test"]})

    def test_count_reported_and_urls_never_leaked(self):
        for kind in ("recon.gau", "recon.katana"):
            with self.subTest(kind=kind):
                f = self._all_filtered(kind)
                self.assertEqual(len(f), 1)
                self.assertEqual(f[0].status, "tested")
                self.assertIn("3 résultat(s)", f[0].title)
                self.assertNotIn("evil.test", _surface(f[0]))

    def test_in_scope_endpoints_still_emitted_as_chainable_nodes(self):
        f = _fire("recon.gau", "lab.test",
                  "http://lab.test/a?p=1\nhttp://b.evil.test/y\n", {"in_scope": ["lab.test"]})
        self.assertEqual([x.target for x in f], ["http://lab.test/a?p=1"])

    def test_zero_urls_keeps_the_historic_phrase(self):
        f = _fire("recon.gau", "lab.test", "", {"in_scope": ["lab.test"]})
        self.assertEqual(f[0].title, "recon.gau — gau: aucun hit")


# =================================================================================================
#  (B1) AUCUN MONTAGE — jamais, sur aucun chemin
# =================================================================================================
class TestNoVolumeMountEver(unittest.TestCase):
    """Décision documentée (cf. `runner`, §1 de la voie docker) : le moteur ne fabrique JAMAIS d'accès
    au système de fichiers de l'hôte pour une image tierce. Ce test est le verrou de ce refus."""

    def test_docker_argv_has_no_mount_flag(self):
        for ep in (None, "theHarvester"):
            argv = runner._docker_argv("img:1", ["-a", "b"], ep)
            self.assertNotIn("-v", argv)
            self.assertNotIn("--mount", argv)
            self.assertNotIn("--volume", argv)
            self.assertFalse(any(":ro" in t for t in argv))

    def test_cmdline_docker_shape_is_exactly_the_documented_one(self):
        with _Patch(**{}):
            pass
        line = runner.cmdline("nosuchbinary__forge", "img:1", ["-a"], prefer_docker=True)
        self.assertEqual(line, "docker run --rm --network host img:1 -a")


# =================================================================================================
#  (B2) `--entrypoint` — livré, visible dans la décision, et gouverné fail-closed
# =================================================================================================
class TestDockerEntrypoint(unittest.TestCase):

    def test_absent_by_default_byte_identical(self):
        self.assertEqual(runner._docker_argv("img:1", ["-a"]),
                         ["docker", "run", "--rm", "--network", "host", "img:1", "-a"])
        self.assertEqual(runner._docker_argv("img:1", ["-a"], ""),
                         ["docker", "run", "--rm", "--network", "host", "img:1", "-a"])

    def test_entrypoint_is_placed_before_the_image(self):
        argv = runner._docker_argv("img:1", ["-a"], "theHarvester")
        self.assertEqual(argv, ["docker", "run", "--rm", "--network", "host",
                                "--entrypoint", "theHarvester", "img:1", "-a"])

    def test_what_is_shown_is_what_is_launched(self):
        """VISIBILITÉ : `cmdline` (le PoC affiché/journalisé) et `tool` (ce qui tourne) partagent le
        MÊME constructeur d'argv — l'entrypoint ne peut pas être appliqué en douce sans apparaître.

        RUPTURE NOMMÉE (défaut D21, conteneur orphelin). Les deux argv diffèrent désormais d'UNE
        paire : `--name forge-tool-<pid>-<n>`, posée sur la seule voie d'exécution. Elle est
        INDISPENSABLE — mesuré le 2026-08-11, deux conteneurs feroxbuster ont survécu des heures à
        leurs runs, et sans nom un conteneur qui survit au client `docker run` n'est plus
        identifiable, donc plus arrêtable. Elle est aussi ABSENTE du PoC à dessein : ce qu'on montre
        à un humain doit rester copiable tel quel.

        L'invariant que ce test protège reste ENTIER : un nom de conteneur ne change RIEN à ce que
        l'outil fait. C'est pourquoi la comparaison se fait modulo cette seule paire — et le test
        VÉRIFIE que la différence se limite à elle."""
        seen = {}

        def _fake_spawn(cmd, timeout, env, container=None):
            seen["cmd"] = list(cmd)
            seen["container"] = container
            return (0, "", "")

        saved = runner._spawn_and_wait
        runner._spawn_and_wait = _fake_spawn
        try:
            runner.tool("nosuchbinary__forge", "img:1", ["-a"], prefer_docker=True,
                        docker_entrypoint="theHarvester")
        finally:
            runner._spawn_and_wait = saved
        shown = runner.cmdline("nosuchbinary__forge", "img:1", ["-a"], prefer_docker=True,
                               docker_entrypoint="theHarvester")
        lance = list(seen["cmd"])
        self.assertIn("--name", lance, "un conteneur sans nom est un conteneur qu'on ne peut plus arrêter")
        i = lance.index("--name")
        self.assertEqual(lance[i + 1], seen["container"])
        del lance[i:i + 2]                       # … et à part CE nom, tout doit coïncider
        self.assertEqual(shown, " ".join(lance))
        self.assertIn("--entrypoint theHarvester", shown)

    def test_accepted_forms(self):
        for ep in ("theHarvester", "/usr/local/bin/theHarvester", "nuclei", "my_tool-v2.1", None, ""):
            self.assertIsNone(runner.entrypoint_refusal(ep), f"{ep!r} aurait dû passer")

    def test_interpreters_and_shells_are_refused(self):
        for ep in ("sh", "bash", "/bin/sh", "/bin/busybox", "python3.11", "/usr/bin/env",
                   "BUSYBOX", "node", "perl", "socat"):
            with self.subTest(ep=ep):
                reason = runner.entrypoint_refusal(ep)
                self.assertIsNotNone(reason, f"entrypoint interpréteur {ep!r} accepté")
                self.assertIn("interpréteur/shell", reason)

    def test_charset_refusals(self):
        for ep in ("-v", "--privileged", "a b", "x;y", "a|b", "a$b", "./x", "../x", "a\x00b", 42):
            with self.subTest(ep=ep):
                self.assertIsNotNone(runner.entrypoint_refusal(ep), f"entrypoint {ep!r} accepté")

    def test_refused_entrypoint_launches_zero_process(self):
        def _boom(*a, **k):
            raise AssertionError("un processus a été lancé malgré un entrypoint REFUSÉ")

        saved = runner._spawn_and_wait
        runner._spawn_and_wait = _boom
        try:
            rc, out, err = runner.tool("nosuchbinary__forge", "img:1", ["-a"], prefer_docker=True,
                                       docker_entrypoint="sh")
        finally:
            runner._spawn_and_wait = saved
        self.assertEqual(rc, 126)
        self.assertEqual(out, "")
        self.assertIn("refusé", err)

    def test_cmdline_shows_the_refusal_not_a_command(self):
        line = runner.cmdline("nosuchbinary__forge", "img:1", ["-a"], prefer_docker=True,
                              docker_entrypoint="bash")
        self.assertTrue(line.startswith("# refusé:"), line)
        self.assertNotIn("docker run", line)

    def test_local_binary_path_ignores_entrypoint(self):
        """L'entrypoint ne concerne QUE la voie docker : la voie locale exécute le binaire lui-même."""
        line = runner.cmdline("sh", "img:1", ["-c"], prefer_docker=False, docker_entrypoint="whatever")
        self.assertFalse(line.startswith("docker "), line)

    def test_toolspec_threads_the_entrypoint_through(self):
        """Un `ToolSpec` déclarant `docker_entrypoint` le passe à `runner.tool` ; un spec SANS le champ
        n'en passe PAS LE KWARG DU TOUT.

        Cette seconde moitié est la borne qui a MORDU : passer `docker_entrypoint=None` pour les ~20
        outils qui n'en veulent pas change la SIGNATURE D'APPEL de `runner.tool` et casse toute doublure
        de test déclarant la signature exacte (9 tests, mesuré). « Byte-identique » se prouve sur la
        forme de l'appel, pas seulement sur l'argv produit."""
        for ep, expect_key in (("theHarvester", True), ("", False)):
            seen = {}

            def _tool(binary, image=None, args=None, **kw):
                seen.update(kw)
                seen["_called"] = True
                return (0, "", "")

            spec = ToolSpec(kind=f"custom.ep{bool(ep)}", vuln_class="Recon", binary="nosuchbinary__forge",
                            argv_template=("{target_host}",), docker_image="img:1", prefer_docker=True,
                            docker_entrypoint=ep, parser="lines", hit_is_asset=False)
            mod = make_module(spec)()
            with _Patch(available=lambda *a, **k: True, tool=_tool):
                mod.fire(Action(spec.kind, "lab.test", params={"in_scope": ["lab.test"]}))
            self.assertTrue(seen.get("_called"), "runner.tool n'a pas été atteint")
            self.assertEqual("docker_entrypoint" in seen, expect_key)
            if expect_key:
                self.assertEqual(seen["docker_entrypoint"], ep)

    def test_existing_specs_call_runner_with_the_historic_signature(self):
        """Contre-preuve directe de la régression : une doublure déclarant la signature EXACTE
        d'avant (aucun `**kwargs`) doit encore être appelable par un outil du catalogue."""
        def _strict_tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=120):
            return (0, "", "")

        with _Patch(available=lambda *a, **k: True, tool=_strict_tool):
            f = mods.get("recon.gau").fire(
                Action("recon.gau", "lab.test", params={"in_scope": ["lab.test"]}))
        self.assertTrue(f)


class TestInterpreterListParity(unittest.TestCase):
    """VERROU DE PARITÉ : la liste d'interpréteurs de `runner` est un MIROIR de celle du loader (elle
    n'est pas importée pour garder `runner` sans dépendance sur le paquet `modules`). Si la liste amont
    gagne une entrée, ce test CASSE — au lieu de laisser le refus de `runner` silencieusement en retard."""

    def test_runner_refuses_at_least_everything_the_loader_refuses(self):
        missing = set(_loader._INTERPRETER_BINARIES) - set(runner._ENTRYPOINT_INTERPRETERS)
        self.assertEqual(missing, set(), f"interpréteurs connus du loader non refusés en entrypoint: {missing}")

    def test_the_declarative_shell_smuggling_path_is_closed(self):
        """Le scénario exact que ce refus ferme : un ToolSpec DÉCLARATIF (dossier `./toolspecs`, monté
        `:ro` par défaut, vendu « gouverné, zéro code ») posant un entrypoint `sh` + un argv `-c …`."""
        spec = ToolSpec(kind="custom.smuggle", vuln_class="Recon", binary="nosuchbinary__forge",
                        argv_template=("-c", "{target_host}"), docker_image="img:1",
                        prefer_docker=True, docker_entrypoint="sh", parser="lines", hit_is_asset=False)
        mod = make_module(spec)()

        def _boom(*a, **k):
            raise AssertionError("un shell a été lancé via --entrypoint")

        saved = runner._spawn_and_wait
        runner._spawn_and_wait = _boom
        try:
            with _Patch(available=lambda *a, **k: True):
                f = mod.fire(Action(spec.kind, "lab.test", params={"in_scope": ["lab.test"]}))
        finally:
            runner._spawn_and_wait = saved
        # rc=126 + stdout vide -> la garde d'honnêteté existante déclasse le constat : jamais un `tested`
        # sur un outil qui n'a pas tourné.
        self.assertEqual(f[0].status, "skipped")


# =================================================================================================
#  (B3) PREUVE PAR EXÉCUTION — un vrai `docker run`, sur une image LOCALE, sans aucun trafic tiers
# =================================================================================================
def _docker_image_present(image):
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", image],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(_docker_image_present(_THEHARVESTER_IMG),
                     f"image locale {_THEHARVESTER_IMG} absente (preuve par exécution ignorée)")
class TestRealDockerEntrypoint(unittest.TestCase):
    """LE cas mesuré qui motivait `--entrypoint` : l'entrypoint de l'image officielle theHarvester est
    `["restfulHarvest","-H","0.0.0.0","-p","80"]` — un SERVEUR REST. Sans override, tout argv de CLI y
    est rejeté ; avec override, la CLI répond. `--help` uniquement : aucun trafic vers un tiers."""

    def test_without_override_the_rest_server_answers_instead_of_the_cli(self):
        rc, out, err = runner.tool("nosuchbinary__forge", _THEHARVESTER_IMG, ["--help"],
                                   prefer_docker=True, timeout=120)
        self.assertIn("restfulharvest", (out + err).lower())

    def test_with_override_the_real_cli_answers(self):
        rc, out, err = runner.tool("nosuchbinary__forge", _THEHARVESTER_IMG, ["--help"],
                                   prefer_docker=True, timeout=120,
                                   docker_entrypoint="theHarvester")
        self.assertEqual(rc, 0, err[:400])
        self.assertIn("usage", out.lower())
        self.assertNotIn("restfulharvest", out.lower())


if __name__ == "__main__":
    unittest.main()
