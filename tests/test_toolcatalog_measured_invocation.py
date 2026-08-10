# SPDX-License-Identifier: AGPL-3.0-or-later
"""L'INVOCATION DU CATALOGUE, VERROUILLÉE SUR DES SORTIES RÉELLES — pas sur ce qu'on croit qu'un outil
rend.

POURQUOI CE FICHIER EXISTE. Deux passes successives ont trouvé la même famille de fautes, et aucune
n'était visible en LISANT le code : un argv refusé par la version réellement installée, une image
dont l'entrypoint n'est pas la CLI, un `parser_regex` qui ne matche plus la sortie de l'outil. Elles
se rendent TOUTES de la même façon — « j'ai vérifié, rien trouvé » — c'est-à-dire une phrase fausse
là où la seule réponse honnête était « je n'ai pas pu regarder ». La passe de 2026-08-10 en a trouvé
une variante SYMÉTRIQUE, tout aussi trompeuse : un parseur TROP LARGE, qui rend des findings ne
parlant pas de la cible (l'en-tête de rapport de nikto, l'avis « No WPScan API Token » de wpscan, le
« not vulnerable (OK) » de testssl compté comme une vulnérabilité).

CE QUE CES TESTS SONT, ET CE QU'ILS NE SONT PAS. Les constantes ci-dessous ne sont pas des exemples
inventés : ce sont des EXTRAITS VERBATIM de sorties capturées en exécutant chaque outil (image docker
déclarée, ou binaire livré dans l'image Forge `full`) contre une cible LOOPBACK jetable — serveur
HTTP/HTTPS local, routes découvrables, paramètre reflété brut, endpoint SQLite réellement injectable,
marqueurs WordPress, certificat auto-signé. Aucun paquet vers un tiers. Les tests rejouent ces
sorties dans le VRAI parseur (`toolspec.parse_output`) et le VRAI constructeur d'argv
(`toolspec.build_argv`) : ce qui casse ici casserait en production.

Zéro I/O : aucun processus n'est lancé par ces tests (ils rejouent des sorties enregistrées).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import modules as mods                                              # noqa: E402
from forge import runner                                                       # noqa: E402
from forge.modules.toolspec import build_argv, parse_output                    # noqa: E402


def _spec(kind):
    return mods.get(kind).spec


def _hits(kind, stdout, rc=0):
    return parse_output(_spec(kind), rc, stdout, "")


# =================================================================================================
#  SORTIES RÉELLES CAPTURÉES (verbatim, tronquées) — cible loopback, 2026-08-10
# =================================================================================================
NIKTO_OUT = """- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    127.0.0.1
+ Target Port:        18080
+ Start Time:         2026-08-10 08:48:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.49 (Unix) PHP/5.4.45
+ /: Retrieved x-powered-by header: PHP/5.4.45.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /uploads/: Directory indexing found.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ Apache/2.4.49 appears to be outdated (current is at least 2.4.63). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: A Wordpress installation was found.
+ 8087 requests: 0 error(s) and 16 item(s) reported on remote host
+ End Time:           2026-08-10 08:53:37 (GMT0) (337 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""

WPSCAN_OUT = """[+] URL: http://127.0.0.1:18080/ [127.0.0.1]
[+] Started: Mon Aug 10 08:54:57 2026

[+] WordPress version 6.4.2 identified (Insecure, released on 2023-12-06).
 | Found By: Meta Generator (Passive Detection)

[+] WordPress theme in use: twentytwentyone
 | [!] The version is out of date, the latest version is 2.8
 | Style Name: Twenty Twenty-One  Version: 1.9

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register
[+] Finished: Mon Aug 10 08:55:00 2026
"""

TESTSSL_OUT = """ Testing server defaults (Server Hello)

 subjectAltName (SAN)         missing (NOT ok) -- Browsers are complaining
 Chain of trust               NOT ok (self signed)
                              NOT ok -- neither CRL nor OCSP URI provided

 Testing vulnerabilities

 Heartbleed (CVE-2014-0160)                not vulnerable (OK), no heartbeat extension
 CCS (CVE-2014-0224)                       not vulnerable (OK)
"""

DALFOX_OUT = ("[POC][V][GET][inHTML] http://127.0.0.1:18080/search?q=%3Csvg%20onload%3Dalert%281%29"
              "%20class%3Ddlxc4c46bd1%3E\n"
              "  ├── Issue: XSS payload DOM object identified\n"
              "  ├── Payload: <svg onload=alert(1) class=dlxc4c46bd1>\n"
              "  └── L1: l><body>results for <svg onload=alert(1) class=dlxc4c46bd1></body></html>\n")

FEROX_OUT = ("http://127.0.0.1:18080/uploads\nhttp://127.0.0.1:18080/backup\n"
             "http://127.0.0.1:18080/admin\nhttp://127.0.0.1:18080/config.php\n")

GAU_OUT = ("http://lab.test/index.php?id=1\nhttp://lab.test/admin/login\n"
           "http://lab.test/api/v1/users?uid=42&debug=true\nhttp://lab.test/static/app.js\n")

WHATWEB_OUT = ("http://127.0.0.1:18080 [200 OK] Apache[2.4.49], HTML5, "
               "HTTPServer[Unix][Apache/2.4.49 (Unix) PHP/5.4.45], IP[127.0.0.1], "
               "MetaGenerator[WordPress 6.4.2], PHP[5.4.45], WordPress[6.4.2]\n")

# Sortie RÉELLE mesurée AVANT le correctif `--colour never` (whatweb colore même derrière un pipe).
WHATWEB_ANSI_OUT = ("\x1b[1m\x1b[34mhttp://127.0.0.1:18080\x1b[0m [200 OK] "
                    "\x1b[1mApache\x1b[0m[\x1b[1m\x1b[32m2.4.49\x1b[0m], \x1b[1mHTML5\x1b[0m, "
                    "\x1b[1mWordPress\x1b[0m[\x1b[1m\x1b[32m6.4.2\x1b[0m]\n")

WAFW00F_OUT = """[*] Checking http://127.0.0.1:18080
[+] Generic Detection results:
[-] No WAF detected by the generic detection
[~] Number of requests: 7
"""

SQLMAP_OUT = """GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
[08:58:26] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
"""


# =================================================================================================
class TestParserAgainstRealOutput(unittest.TestCase):
    """Le parseur de chaque spec, confronté à la SORTIE RÉELLE de l'outil qu'il enveloppe."""

    def test_feroxbuster_parses_discovered_urls(self):
        self.assertEqual(_hits("recon.feroxbuster", FEROX_OUT),
                         ["http://127.0.0.1:18080/uploads", "http://127.0.0.1:18080/backup",
                          "http://127.0.0.1:18080/admin", "http://127.0.0.1:18080/config.php"])

    def test_gau_parses_archive_urls(self):
        hits = _hits("recon.gau", GAU_OUT)
        self.assertEqual(len(hits), 4)
        self.assertIn("http://lab.test/api/v1/users?uid=42&debug=true", hits)

    def test_dalfox_parses_poc_line_only(self):
        hits = _hits("xss.dalfox", DALFOX_OUT)
        self.assertEqual(len(hits), 1, "seule la ligne [POC] est un constat, pas ses 3 lignes de détail")
        self.assertTrue(hits[0].startswith("[POC][V][GET][inHTML] http://127.0.0.1:18080/search?q="))

    def test_whatweb_line_carries_no_ansi(self):
        hits = _hits("recon.whatweb", WHATWEB_OUT)
        self.assertEqual(len(hits), 1)
        self.assertNotIn("\x1b", hits[0], "l'argv doit porter `--colour never` (ANSI dans le ledger)")

    def test_whatweb_ansi_can_only_be_fixed_in_the_argv(self):
        """CE QUE CE TEST DIT DE PLUS QUE LE PRÉCÉDENT — et pourquoi il existe.

        `WHATWEB_ANSI_OUT` est la sortie RÉELLE mesurée AVANT le correctif (whatweb colore même
        derrière un pipe). Rejouée dans le parseur, elle rend un hit qui EMBARQUE les séquences
        d'échappement : le parseur `lines` ne peut RIEN y faire, et ce n'est pas son rôle. La seule
        garde effective est donc `--colour never` dans l'argv (cf.
        `TestArgvMatchesInstalledVersion.test_whatweb_argv_disables_colour`) — ce test est là pour
        qu'on ne prenne pas le test « pas d'ANSI » ci-dessus pour une protection qu'il n'offre pas."""
        hits = _hits("recon.whatweb", WHATWEB_ANSI_OUT)
        self.assertEqual(len(hits), 1)
        self.assertIn("\x1b", hits[0])

    def test_wafw00f_verdict_line(self):
        self.assertEqual(_hits("recon.wafw00f", WAFW00F_OUT),
                         ["[-] No WAF detected by the generic detection"])

    def test_sqlmap_reports_parameter_and_dbms(self):
        hits = _hits("sqli.sqlmap", SQLMAP_OUT)
        self.assertIn("Parameter: id (GET)", hits)
        self.assertIn("back-end DBMS: SQLite", hits)


# =================================================================================================
class TestParserNotTooWide(unittest.TestCase):
    """L'AUTRE phrase fausse : un parseur qui rend des « findings » ne parlant pas de la cible.

    Chacun de ces trois cas a été MESURÉ en production du parseur d'origine — ce ne sont pas des
    hypothèses défensives."""

    def test_nikto_drops_report_header_and_footer(self):
        hits = _hits("web.nikto", NIKTO_OUT)
        self.assertTrue(hits, "nikto doit garder ses constats substantiels")
        joined = "\n".join(hits)
        for noise in ("Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:",
                      "host(s) tested", "requests: 0 error", "No CGI Directories found"):
            self.assertNotIn(noise, joined, f"méta-scan rendu comme finding: {noise!r}")
        self.assertIn("+ /uploads/: Directory indexing found.", hits)
        self.assertIn("+ /config.php: PHP Config file may contain database IDs and passwords.", hits)

    def test_wpscan_drops_api_token_notice_and_keeps_real_findings(self):
        hits = _hits("web.wpscan", WPSCAN_OUT)
        joined = "\n".join(hits)
        self.assertNotIn("No WPScan API Token", joined,
                         "cet avis parle de NOTRE configuration, jamais de la cible")
        self.assertNotIn("You can get a free API token", joined)
        self.assertIn("[+] WordPress version 6.4.2 identified (Insecure, released on 2023-12-06).", hits)
        self.assertIn("| [!] The version is out of date, the latest version is 2.8",
                      [h.strip() for h in hits], "les [!] de wpscan sont INDENTÉS dans leurs blocs")

    def test_testssl_keeps_whole_line_and_ignores_not_vulnerable(self):
        hits = _hits("web.testssl", TESTSSL_OUT)
        # (1) la LIGNE ENTIÈRE, pas le seul mot-clé (le groupe doit rester NON-capturant)
        self.assertIn("subjectAltName (SAN)         missing (NOT ok) -- Browsers are complaining",
                      [h.strip() for h in hits])
        self.assertNotIn("NOT ok", hits, "un hit réduit au mot-clé ne dit pas DE QUOI il s'agit")
        # (2) « not vulnerable (OK) » est une BONNE nouvelle — jamais un constat
        joined = "\n".join(hits)
        self.assertNotIn("not vulnerable", joined)
        self.assertNotIn("Heartbleed", joined)
        self.assertEqual(len(hits), 3, "exactement les 3 lignes NOT ok de la sortie mesurée")


# =================================================================================================
class TestArgvMatchesInstalledVersion(unittest.TestCase):
    """L'argv du spec, confronté à ce que la version RÉELLEMENT lancée accepte."""

    def test_dalfox_uses_url_flag_and_no_bare_only_poc(self):
        argv = build_argv(_spec("xss.dalfox"), "http://host.test/?q=1", {})
        self.assertEqual(argv[:4], ["url", "--url", "http://host.test/?q=1", "--silence"])
        # `--only-poc` NU est refusé par dalfox 3.x (« a value is required ») -> hors argv fixe,
        # mais toujours ALLOWLISTÉ pour un opérateur qui le passe en deux tokens.
        self.assertNotIn("--only-poc", argv)
        self.assertIn("--only-poc", _spec("xss.dalfox").flag_allowlist)

    def test_dalfox_allowlist_has_no_flags_removed_in_v3(self):
        allow = _spec("xss.dalfox").flag_allowlist
        for gone in ("-w", "--mining-dict", "--mining-dom", "--skip-mining-all", "--deep-domxss"):
            self.assertNotIn(gone, allow, f"{gone} n'existe plus en dalfox 3.x")

    def test_whatweb_argv_disables_colour(self):
        argv = build_argv(_spec("recon.whatweb"), "http://host.test", {})
        self.assertIn("--colour", argv)
        self.assertEqual(argv[argv.index("--colour") + 1], "never")

    def test_amass_argv_flags_exist_in_both_shipped_versions(self):
        # v4.2.0 (image caffix/amass) ET v5.1.1 (binaire épinglé tools.json) : mesuré `enum -h`.
        argv = build_argv(_spec("recon.amass"), "host.test", {})
        self.assertEqual(argv, ["enum", "-passive", "-norecursive", "-d", "host.test"])


# =================================================================================================
class TestDeclaredImagesAndEntrypoints(unittest.TestCase):
    """Les images DÉCLARÉES sont celles qui ont été tirées, exécutées et parsées — et l'entrypoint
    optionnel reste gouverné (jamais un interpréteur)."""

    EXPECTED = {
        "recon.feroxbuster": "epi052/feroxbuster",      # Docker Hub de l'auteur (epi052)
        "recon.gau": "sxcurity/gau",                    # image désignée par le README amont (lc/gau)
        "recon.amass": "caffix/amass",                  # label OCI source = github.com/owasp-amass/amass
        "web.nikto": "ghcr.io/sullo/nikto",             # label OCI source = github.com/sullo/nikto
        "web.testssl": "drwetter/testssl.sh",           # Docker Hub de l'auteur
        "web.wpscan": "wpscanteam/wpscan",              # label OCI source = github.com/wpscanteam/wpscan
        "xss.dalfox": "hahwul/dalfox",                  # label OCI source = github.com/hahwul/dalfox
    }

    def test_images_declared_as_measured(self):
        for kind, image in self.EXPECTED.items():
            self.assertEqual(_spec(kind).docker_image, image, kind)

    def test_binary_only_tools_declare_no_third_party_rebuild(self):
        # Aucune image publiée sous le nom du projet (vérifié) -> BINAIRE-SEUL. On ne comble PAS le
        # trou avec un rebuild tiers (secsi/…, googlesky/…) : règle héritée de `secsi/theharvester`.
        for kind in ("recon.whatweb", "recon.wafw00f", "sqli.sqlmap"):
            self.assertEqual(_spec(kind).docker_image, "", kind)

    def test_dalfox_entrypoint_is_needed_and_governed(self):
        # L'image n'a PAS d'Entrypoint (juste un Cmd `./dalfox`) : sans override, `docker run IMAGE
        # url …` tentait d'exécuter « url » (mesuré rc=127).
        ep = _spec("xss.dalfox").docker_entrypoint
        self.assertEqual(ep, "/app/dalfox")
        self.assertIsNone(runner.entrypoint_refusal(ep), "l'entrypoint déclaré doit être acceptable")

    def test_no_spec_declares_an_interpreter_entrypoint(self):
        seen = 0
        for kind in mods.kinds():
            spec = getattr(mods.get(kind), "spec", None)
            if spec is None:
                continue
            seen += 1
            self.assertIsNone(runner.entrypoint_refusal(spec.docker_entrypoint), kind)
        self.assertGreater(seen, 15, "le balayage doit couvrir tout le catalogue, pas 2 kinds")

    def test_feroxbuster_prefers_the_self_sufficient_image(self):
        # Sans wordlist, un feroxbuster local sort rc=0 stdout VIDE (mesuré) — silence que la garde
        # `rc != 0` ne rattrape pas. L'image amont EMBARQUE sa wordlist : on la préfère.
        self.assertTrue(_spec("recon.feroxbuster").prefer_docker)


# =================================================================================================
class TestGospiderRetired(unittest.TestCase):
    """gospider RETIRÉ : aucune image publiée en amont, et `katana` couvre la même fonction AVEC
    une image officielle. Une entrée qui ne peut tourner que si on l'installe à la main affiche une
    couverture que l'exécution ne rend pas."""

    def test_kind_is_gone(self):
        self.assertIsNone(mods.get("recon.gospider"))

    def test_katana_still_covers_the_crawl_to_endpoint_chain(self):
        katana = _spec("recon.katana")
        self.assertTrue(katana.emit_endpoint_discovery)
        self.assertEqual(katana.docker_image, "projectdiscovery/katana")


if __name__ == "__main__":
    unittest.main()
