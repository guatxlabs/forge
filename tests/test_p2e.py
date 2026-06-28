"""P2 (runner + parsing) — exécuteur d'outils, parsing JSONL nuclei, host-header origin.

Hermétique : on stub `runner.tool` (aucun outil externe lancé, aucun réseau) ou on exerce le
vrai runner sur des binaires triviaux du système (echo / binaire inexistant / sleep).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                               # noqa: E402
from forge import runner, schema                           # noqa: E402
from forge.modules import web as webmod                    # noqa: E402
from forge.modules import origin as originmod              # noqa: E402
from forge.modules import evasion as evasionmod            # noqa: E402
from forge.modules.web import NucleiScan, IdorDifferential # noqa: E402
from forge.modules.origin import OriginFind                # noqa: E402


class TestRunnerTool(unittest.TestCase):
    """Le vrai runner.tool sur des binaires triviaux — rc 0 / 127 / 124 / prefer_docker."""

    def test_rc_zero_with_output(self):
        rc, out, err = runner.tool("echo", args=["forge-runner-ok"])
        self.assertEqual(rc, 0)
        self.assertIn("forge-runner-ok", out)

    def test_missing_binary_no_docker_is_127(self):
        rc, out, err = runner.tool("definitely-not-a-real-binary-zzz", docker_image=None)
        self.assertEqual(rc, 127)
        self.assertIn("indisponible", err)

    def test_timeout_is_124(self):
        # 'sleep 5' avec timeout 1s -> 124 (le runner attrape TimeoutExpired)
        rc, out, err = runner.tool("sleep", args=["5"], timeout=1)
        self.assertEqual(rc, 124)
        self.assertIn("timeout", err)

    def test_prefer_docker_without_docker_falls_back_to_local(self):
        # NOUVEAU CONTRAT : prefer_docker est une PRÉFÉRENCE d'ordre, pas une exigence. Docker absent
        # mais binaire local présent -> on REPLIE sur le binaire local (au lieu de 127). Ici 'echo'
        # existe, 'docker' non -> la commande locale s'exécute réellement (rc 0, sortie capturée).
        orig_which = runner.shutil.which
        runner.shutil.which = lambda name: "/usr/bin/echo" if name == "echo" else None
        try:
            rc, out, err = runner.tool("echo", docker_image="some/image",
                                       args=["forge-fallback-local"], prefer_docker=True)
        finally:
            runner.shutil.which = orig_which
        self.assertEqual(rc, 0)                              # repli local, pas 127
        self.assertIn("forge-fallback-local", out)

    def test_prefer_docker_no_docker_no_local_is_127(self):
        # 127 conservé QUAND NI docker NI binaire local n'est présent (le seul vrai « indisponible »).
        orig_which = runner.shutil.which
        runner.shutil.which = lambda name: None              # ni 'docker' ni le binaire
        try:
            rc, out, err = runner.tool("nuclei", docker_image="projectdiscovery/nuclei",
                                       args=["-u", "x"], prefer_docker=True)
        finally:
            runner.shutil.which = orig_which
        self.assertEqual(rc, 127)
        self.assertIn("indisponible", err)

    def test_prefer_docker_uses_docker_when_both_present(self):
        # Préférence respectée : docker ET binaire local présents + prefer_docker -> docker gagne.
        orig_which = runner.shutil.which
        orig_run = runner.subprocess.run
        runner.shutil.which = lambda name: f"/usr/bin/{name}"  # tout présent
        captured = {}

        class _P:
            returncode, stdout, stderr = 0, "ok", ""

        def fake_run(cmd, **k):
            captured["cmd"] = cmd
            return _P()

        runner.subprocess.run = fake_run
        try:
            runner.tool("nuclei", docker_image="projectdiscovery/nuclei",
                        args=["-u", "x"], prefer_docker=True)
        finally:
            runner.shutil.which = orig_which
            runner.subprocess.run = orig_run
        self.assertEqual(captured["cmd"][0], "docker")        # docker préféré quand dispo
        self.assertIn("projectdiscovery/nuclei", captured["cmd"])

    def test_available_local_binary_visible_despite_prefer_docker(self):
        # available() ne masque plus un binaire local présent sous prétexte de prefer_docker.
        orig_which = runner.shutil.which
        runner.shutil.which = lambda name: "/usr/bin/nuclei" if name == "nuclei" else None
        try:
            self.assertTrue(runner.available("nuclei", "projectdiscovery/nuclei", prefer_docker=True))
        finally:
            runner.shutil.which = orig_which


class TestNucleiJsonlParsing(unittest.TestCase):
    """Parsing JSONL nuclei : stdout d'abord (un rc!=0 bénin n'écrase pas des lignes valides)."""

    def _patch_tool(self, rc, out, err=""):
        orig = webmod.runner.tool
        webmod.runner.tool = lambda *a, **k: (rc, out, err)
        self.addCleanup(lambda: setattr(webmod.runner, "tool", orig))

    def test_parses_jsonl_hits_into_findings(self):
        jsonl = "\n".join([
            '{"template-id":"cve-2021-1","matched-at":"https://app.test/x","info":{"name":"RCE","severity":"critical"}}',
            '{"template-id":"misc","matched-at":"https://app.test/y","info":{"name":"Info leak","severity":"medium"}}',
        ])
        self._patch_tool(0, jsonl)
        findings = NucleiScan().fire(Action("web.nuclei", "https://app.test"))
        self.assertEqual(len(findings), 2)
        crit = [f for f in findings if f.severity == "CRITICAL"][0]
        # un hit nuclei high/critical est `reported_by_tool` (sévérité auto-déclarée par l'outil),
        # PAS `vulnerable` — la promotion en vulnerable est réservée aux oracles à preuve de Forge
        self.assertEqual(crit.status, "reported_by_tool")
        self.assertIn(crit.status, schema.STATUSES)          # statut connu de la machine d'état
        self.assertEqual(crit.severity, "CRITICAL")          # la sévérité de l'outil est conservée
        self.assertEqual(crit.target, "https://app.test/x")
        med = [f for f in findings if f.severity == "MEDIUM"][0]
        self.assertEqual(med.status, "tested")               # medium -> testé (sous le seuil de report)

    def test_valid_jsonl_survives_nonzero_rc(self):
        # nuclei peut sortir rc!=0 tout en ayant émis du JSONL valide -> on garde le hit, pas un échec
        jsonl = '{"template-id":"t","matched-at":"https://app.test/z","info":{"name":"H","severity":"high"}}'
        self._patch_tool(2, jsonl, "warning bénin")
        findings = NucleiScan().fire(Action("web.nuclei", "https://app.test"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertNotIn("indisponible", findings[0].title)

    def test_no_output_unavailable_is_failure_finding(self):
        self._patch_tool(127, "", "indisponible")
        findings = NucleiScan().fire(Action("web.nuclei", "https://app.test"))
        self.assertEqual(len(findings), 1)
        self.assertIn("indisponible", findings[0].title)

    def test_clean_run_no_hits_is_info(self):
        self._patch_tool(0, "")                              # succès, aucun hit
        findings = NucleiScan().fire(Action("web.nuclei", "https://app.test"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "INFO")
        self.assertIn("aucun hit", findings[0].title)


class TestOriginHostHeader(unittest.TestCase):
    """origin.find : la vérif host-header (httpx -H 'Host: domain') gouverne le flag HIGH."""

    def _patch(self, tool_fn, gethostbyname=None):
        orig_tool = originmod.runner.tool
        originmod.runner.tool = tool_fn
        self.addCleanup(lambda: setattr(originmod.runner, "tool", orig_tool))
        if gethostbyname is not None:
            orig_g = originmod.socket.gethostbyname
            originmod.socket.gethostbyname = gethostbyname
            self.addCleanup(lambda: setattr(originmod.socket, "gethostbyname", orig_g))

    def test_verified_origin_flags_high(self):
        # subfinder renvoie un sous-domaine ; il résout sur une IP hors-CF ; httpx confirme via Host header
        def tool_fn(binary, docker_image=None, args=None, **k):
            if binary == "subfinder":
                return (0, "app.exemple.test\n", "")
            if binary == "httpx":
                # vérifie que l'en-tête Host est bien passé à httpx
                assert "Host: exemple.test" in args, f"host header manquant: {args}"
                return (0, "http://9.9.9.9 [200]", "")
            return (127, "", "?")
        self._patch(tool_fn, gethostbyname=lambda s: "9.9.9.9")  # hors plage Cloudflare
        findings = OriginFind().fire(Action("origin.find", "exemple.test"))
        hi = [f for f in findings if f.severity == "HIGH"]
        self.assertEqual(len(hi), 1)
        self.assertEqual(hi[0].target, "9.9.9.9")
        self.assertEqual(hi[0].status, "vulnerable")
        self.assertIn("VÉRIFIÉE", hi[0].title)

    def test_unverified_origin_stays_info(self):
        # httpx ne confirme pas (pas de code 2xx/3xx/403) -> pas de flag HIGH
        def tool_fn(binary, docker_image=None, args=None, **k):
            if binary == "subfinder":
                return (0, "app.exemple.test\n", "")
            if binary == "httpx":
                return (0, "http://9.9.9.9 [000]", "")          # pas de hit -> non vérifié
            return (127, "", "?")
        self._patch(tool_fn, gethostbyname=lambda s: "9.9.9.9")
        findings = OriginFind().fire(Action("origin.find", "exemple.test"))
        self.assertTrue(all(f.severity != "HIGH" for f in findings))
        self.assertTrue(any("non confirmée" in f.title for f in findings))

    def test_subfinder_failure_is_failure_finding(self):
        def tool_fn(binary, docker_image=None, args=None, **k):
            return (127, "", "indisponible")
        self._patch(tool_fn)
        findings = OriginFind().fire(Action("origin.find", "exemple.test"))
        self.assertEqual(len(findings), 1)
        self.assertIn("indisponible", findings[0].title)


class TestOriginFailClosedScope(unittest.TestCase):
    """Régression — fail-closed sur les IP résolues HORS-SCOPE : un sous-domaine peut pointer vers
    une infra tierce/mutualisée. AVANT toute connexion httpx, on revérifie is_in_scope(ip) ; une IP
    hors-scope -> finding INFO et AUCUN httpx (jamais d'élargissement de périmètre par omission)."""

    def _patch(self, tool_fn, gethostbyname):
        orig_tool = originmod.runner.tool
        originmod.runner.tool = tool_fn
        self.addCleanup(lambda: setattr(originmod.runner, "tool", orig_tool))
        orig_g = originmod.socket.gethostbyname
        originmod.socket.gethostbyname = gethostbyname
        self.addCleanup(lambda: setattr(originmod.socket, "gethostbyname", orig_g))

    def test_out_of_scope_ip_skips_httpx_fail_closed(self):
        # L'IP résolue (9.9.9.9, hors-CF) n'est PAS dans in_scope -> on ne doit JAMAIS lancer httpx.
        httpx_calls = []

        def tool_fn(binary, docker_image=None, args=None, **k):
            if binary == "subfinder":
                return (0, "tiers.exemple.test\n", "")
            if binary == "httpx":
                httpx_calls.append(args)                      # ne DOIT jamais arriver
                return (0, "http://9.9.9.9 [200]", "")
            return (127, "", "?")
        self._patch(tool_fn, gethostbyname=lambda s: "9.9.9.9")
        action = Action("origin.find", "exemple.test",
                        params={"in_scope": ["exemple.test"], "out_scope": []})
        findings = OriginFind().fire(action)
        self.assertEqual(httpx_calls, [])                     # aucune connexion httpx hors-scope
        self.assertTrue(any("HORS-SCOPE" in f.title for f in findings))
        self.assertTrue(all(f.severity != "HIGH" for f in findings))

    def test_no_scope_in_params_is_fail_closed_no_httpx(self):
        # Aucun scope injecté (in_scope/out_scope absents) -> enforce=False : chemin dev/test direct.
        # On NE doit toujours pas flaguer HIGH par omission de périmètre — ici subfinder ne renvoie
        # qu'un sous-domaine résolvant hors-CF mais httpx ne confirme pas -> reste INFO.
        def tool_fn(binary, docker_image=None, args=None, **k):
            if binary == "subfinder":
                return (0, "exemple.test\n", "")
            if binary == "httpx":
                return (0, "http://9.9.9.9 [000]", "")        # non confirmé
            return (127, "", "?")
        self._patch(tool_fn, gethostbyname=lambda s: "9.9.9.9")
        findings = OriginFind().fire(Action("origin.find", "exemple.test"))   # pas de params scope
        self.assertTrue(all(f.severity != "HIGH" for f in findings))


class TestEvasionAvailableMemoized(unittest.TestCase):
    """Régression — `evasion.available` (property) memoïse la sonde de santé (TTL court) : lire
    `.available` sur tous les modules d'évasion (cmd_modules au catalogue) ne doit PAS déclencher
    un probe réseau par lecture, sinon ~6s au boot. Le cache coalesce les lectures rapprochées."""

    def setUp(self):
        # cache de classe partagé -> on le vide pour partir d'un état déterministe
        evasionmod._EvasionBase._health_cache.clear()
        self.addCleanup(evasionmod._EvasionBase._health_cache.clear)

    def test_available_probes_once_across_reads(self):
        calls = {"n": 0}

        def fake_health(timeout=2):
            calls["n"] += 1
            return True
        orig = evasionmod.bc.health
        evasionmod.bc.health = fake_health
        self.addCleanup(lambda: setattr(evasionmod.bc, "health", orig))
        # plusieurs modules d'évasion, plusieurs lectures de .available dans la fenêtre TTL
        mods = [evasionmod.EvasionXhr(), evasionmod.EvasionTurnstile(),
                evasionmod.EvasionIdorIntercept()]
        results = [m.available for m in mods] + [mods[0].available, mods[1].available]
        self.assertTrue(all(results))
        self.assertEqual(calls["n"], 1)                       # UN seul probe réseau (memoïsé TTL/URL)

    def test_url_change_reprobes(self):
        calls = {"n": 0}

        def fake_health(timeout=2):
            calls["n"] += 1
            return True
        orig_h = evasionmod.bc.health
        orig_u = evasionmod.bc.base_url
        evasionmod.bc.health = fake_health
        self.addCleanup(lambda: setattr(evasionmod.bc, "health", orig_h))
        self.addCleanup(lambda: setattr(evasionmod.bc, "base_url", orig_u))
        evasionmod.bc.base_url = lambda: "http://host-a:8080"
        self.assertTrue(evasionmod.EvasionXhr().available)
        evasionmod.bc.base_url = lambda: "http://host-b:8080"   # URL différente -> re-sonde
        self.assertTrue(evasionmod.EvasionXhr().available)
        self.assertEqual(calls["n"], 2)                       # une sonde par URL distincte


class TestIdorCurlPoc(unittest.TestCase):
    """Régression — le PoC curl de access_control.idor émet UN drapeau -H par en-tête (l'ancienne
    version sérialisait le dict en repr Python : `curl -H '{...}'`, commande invalide non rejouable)."""

    def test_curl_one_h_flag_per_header(self):
        headers = {"Authorization": "Bearer B-token", "X-Custom": "v1"}
        poc = IdorDifferential._curl("https://app.test/api/objs/42", headers)
        # un -H par en-tête, chacun au format 'Nom: valeur', et l'URL bien quotée en dernier
        self.assertEqual(poc.count(" -H "), len(headers))
        self.assertIn("-H 'Authorization: Bearer B-token'", poc)
        self.assertIn("-H 'X-Custom: v1'", poc)
        self.assertTrue(poc.endswith("'https://app.test/api/objs/42'"))
        self.assertNotIn("{", poc)                            # pas de repr de dict (ancien bug)
        self.assertNotIn("}", poc)

    def test_curl_no_headers_is_still_valid(self):
        poc = IdorDifferential._curl("https://app.test/x", {})
        self.assertEqual(poc, "curl -sS 'https://app.test/x'")

    def test_idor_fire_poc_uses_b_headers(self):
        # fire() doit produire un PoC rejouable avec les en-têtes du compte B (l'attaquant).
        # _fetch durci -> 3-uple (status, body, content_type).
        orig_fetch = IdorDifferential._fetch
        IdorDifferential._fetch = staticmethod(
            lambda url, headers, timeout=15, method="GET", body=None: (200, "body", "text/plain"))
        self.addCleanup(lambda: setattr(IdorDifferential, "_fetch", staticmethod(orig_fetch)))
        action = Action("access_control.idor", "https://app.test", params={
            "accounts": [{"headers": {"Authorization": "A"}},
                         {"headers": {"Authorization": "Bearer B"}}],
            "urls": ["https://app.test/obj/1"]})
        findings = IdorDifferential().fire(action)
        self.assertEqual(len(findings), 1)
        self.assertIn("-H 'Authorization: Bearer B'", findings[0].poc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
