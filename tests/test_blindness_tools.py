# SPDX-License-Identifier: AGPL-3.0-or-later
"""UN OUTIL EXTERNE QUI N'A RIEN VU NE DOIT PAS DIRE « J'AI VÉRIFIÉ, RIEN TROUVÉ » — et la borne
doit rester ÉTROITE, y compris là où le premier lot n'avait pas à la poser.

CE QUE LA MESURE A DIT (corpus `gxrun2`, ledger signé de 11 Mo, 5 318 findings). Sur les 4 839
`tested`, **2 553 ne passent PAS par `Oracle._http`** : ce sont des sorties d'outils externes et de
modules de surface. Le cadrage « ils concluent tous sur un mur » est FAUX pour 96 % d'entre eux, et
le décompte l'a montré :

    1 594  OBSERVATIONS (une ligne de sortie = un finding : `curl: cf-mitigated: challenge`,
           `nuclei: WAF Detection`) — elles CONSIGNENT le mur, elles n'affirment rien. INTOUCHABLES.
      669  verdicts NON-HTTP (dig/dnsx/subfinder jugent du DNS, naabu/masscan des ports, crt.sh et
           Wayback sont des tiers) — un interstitiel HTTP ne les aveugle pas. INTOUCHABLES.
      205  ZÉRO paquet émis (avis `network.smb`/`network.ssh`, `demo`) — le piège des 1 750 `skip()`
           du premier lot sous un autre nom.
      105  vraies affirmations d'absence rendues DERRIÈRE UN MUR.
      251  vraies affirmations d'absence rendues alors que **l'outil n'avait pas tourné** — plus
           nombreuses que le mur, et découvertes seulement en mesurant.

CE QUI REND CE LOT DIFFÉRENT. Un oracle urllib voit un code et un corps ; un outil rend un `rc` et du
texte. Derrière un mur, nuclei ne dit pas « challenge » : il dit **0 résultat**, INDISCERNABLE d'une
cible saine. La signature n'arrive jamais jusqu'à la décision — il faut donc la chercher là où elle
SURVIT : l'état `CHALLENGED` du store (semé par `Oracle._http`, par `recon.httpx` qui a vu le
`403 / "Just a moment…"` avant tout le monde, et par les outils qui déversent l'interstitiel).

LES DEUX SENS SONT TESTÉS, et le second est le plus dur ici — plus dur que dans le premier lot,
parce que ce lot a DEUX façons neuves de sur-convertir, et que la première a RÉELLEMENT eu lieu :
  - au premier rejeu du corpus, l'abstention posée sur l'état de l'hôte a fait taire **53 verdicts
    DNS/OSINT valides** (`dig: aucun hit` 12, `subfinder` 18, `gobuster` 23). D'où `speaks_http`,
    dérivé de l'argv (classe `TestNonHttpToolsKeepTheirVerdict`) ;
  - un SCANNER NOMME les fournisseurs qu'il détecte : sur une cible parfaitement saine, `nuclei`
    émet « Cloudflare Turnstile detect » et `wafw00f` écrit « DataDome ». Réutiliser telle quelle la
    liste de signatures d'un CORPS de réponse ferait taire ces cibles-là. D'où
    `_TOOL_OUTPUT_SIGNATURES` (classe `TestScannerNamingAVendorIsNotAWall`).

Chaque assertion à prouver vit dans SON PROPRE test : une assertion antérieure qui avorterait
masquerait celle qu'on veut voir tomber sous mutation.

HERMÉTIQUE : aucun paquet ne sort. Les outils externes ne sont jamais lancés — le seam est `_run`
(instance), le connecteur documenté entre le module et `runner.tool` ; les triplets `(rc, stdout,
stderr)` injectés sont ceux MESURÉS par ré-exécution des mêmes argv (`dnsx`/`masscan`/`naabu`/
`theHarvester`/`gobuster`/`nuclei`/`zap-baseline` sous `--network none`), pas des inventions.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import blindness, challenge, session                       # noqa: E402
from forge.modules.registry import REGISTRY                           # noqa: E402
import forge.modules as _modules                                      # noqa: E402,F401
from forge.roe import Action, Scope                                   # noqa: E402
from tests._dns import setUpModule, tearDownModule                    # noqa: F401,E402

HOST = "app.test"
URL = f"http://{HOST}"
IN_SCOPE = [HOST]

# --- Sorties d'outils MESURÉES (ré-exécution des argv du catalogue, `docker run --network none`) ----
# Le point commun de ces quatre-là : rc non nul, stdout VIDE. L'outil s'est arrêté avant d'observer
# quoi que ce soit — sa réponse « aucun hit » ne peut rien affirmer.
# HISTORIQUE : les quatre argv fautifs ont depuis ete CORRIGES ou RETIRES du catalogue (cf.
# `toolcatalog` : gobuster/dnsx corriges + wordlist REQUISE ; masscan et theHarvester retires).
# Les chaines restent ici parce que ce fichier documente ce que le LEDGER a montre, et parce que
# `TestRemovedEntriesCannotComeBackSilently` verrouille le fait que ces causes ne peuvent plus
# se produire. DNSX_ERR sert encore de sortie d'erreur GENERIQUE (rc=1, stdout vide).
DNSX_ERR = "[FTL] missing wordlist(w) flag required with domain(d) input"
MASSCAN_ERR = 'FAIL: unknown command-line parameter "app.test"\n [hint] did you want "--app.test"?'
THARV_ERR = ("Unable to find image 'laramies/theharvester:latest' locally\n"
             "docker: Error response from daemon: pull access denied for laramies/theharvester")
# Params MINIMAUX qui satisfont le pre-requis d'invocation d'un outil a wordlist (gobuster/dnsx) —
# sans eux, `fire()` skippe AVANT tout tir et les tests de degradation ne seraient jamais atteints.
WORDLIST_OK = {"wordlist": "www,mail"}
NUCLEI_ERR = "[FTL] Could not run nuclei: no templates provided for scan"
# gobuster, lui, DÉVERSE son texte d'usage sur stdout (2 080 octets mesurés) : la borne factuelle
# « stdout vide » ne l'attrape donc pas, et c'est un RÉSIDU ASSUMÉ (cf. le test qui l'épingle).
GOBUSTER_OUT = ('Incorrect Usage: invalid value "app.test" for flag -d: parse error\n\n'
                'NAME:\n   gobuster dns - Uses DNS subdomain enumeration mode\n')
GOBUSTER_ERR = 'invalid value "app.test" for flag -d: parse error'
# nikto/testssl sortent en erreur APRÈS avoir rendu leurs résultats : stdout non vide -> verdict GARDÉ.
NIKTO_OUT = "+ Server: nginx\n+ 0 host(s) tested\n"

# L'interstitiel tel que `curl -i` le déverse : en-tête de mitigation + page de défi.
CURL_WALL_DUMP = ("HTTP/2 403\r\ncf-mitigated: challenge\r\nserver: cloudflare\r\n\r\n"
                  "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
                  '<body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1">'
                  "</script></body></html>")
# Le JSON httpx EXACT du corpus (tronqué aux champs qui comptent) : la preuve était là, horodatée.
HTTPX_WALL_JSON = json.dumps({
    "url": "https://app.test", "input": "app.test", "title": "Just a moment...",
    "status_code": 403, "content_length": 5506, "webserver": "cloudflare", "cdn": True})
HTTPX_HEALTHY_JSON = json.dumps({
    "url": "https://app.test", "input": "app.test", "title": "Espace client",
    "status_code": 200, "content_length": 8123, "webserver": "nginx"})


class _Case(unittest.TestCase):
    """Socle : périmètre gouverné, action, et tir d'un module avec son seam d'exécution neutralisé."""

    def store(self, challenged=()):
        st = session.SessionStore.from_scope(Scope({"in_scope": IN_SCOPE, "out_scope": []}))
        for u in challenged:
            st.mark_challenged(u)
        return st

    @staticmethod
    def act(kind, target=URL, extra=None):
        return Action(kind, target,
                      params=dict(extra or {}, in_scope=IN_SCOPE, out_scope=[]))

    def module(self, kind):
        """Instance du VRAI module, disponibilité forcée (aucun binaire requis, aucun processus).
        `runner.available` est une fonction de module : la patcher ne touche AUCUN descripteur de
        classe (cf. `test_seam_restoration`)."""
        from forge import runner
        orig = runner.available
        runner.available = lambda *a, **k: True
        self.addCleanup(lambda: setattr(runner, "available", orig))
        return REGISTRY[kind]()

    def fire_tool(self, kind, rc, out, err, target=URL, store=None, params=None):
        """Tir d'un `ExternalToolModule` — `_run` est stubé SUR L'INSTANCE (jamais sur la classe).
        `params` sert aux outils dont le spec exige un pre-requis d'invocation (`requires_params`) :
        sans lui, `fire()` skipperait AVANT le tir et le comportement teste ne serait pas atteint."""
        mod = self.module(kind)
        mod._run = lambda argv: (rc, out, err)
        with session.using(store if store is not None else self.store()):
            return mod.fire(self.act(kind, target, params))

    def fire_nuclei(self, rc, out, err, target=URL, store=None):
        from forge.modules import web as W
        orig = W.runner.tool
        W.runner.tool = lambda *a, **k: (rc, out, err)
        self.addCleanup(lambda: setattr(W.runner, "tool", orig))
        with session.using(store if store is not None else self.store()):
            return REGISTRY["web.nuclei"]().fire(self.act("web.nuclei", target))

    def fire_httpx(self, rc, out, err, target=HOST, store=None):
        from forge.modules import recon as R
        orig = R.runner.tool
        R.runner.tool = lambda *a, **k: (rc, out, err)
        self.addCleanup(lambda: setattr(R.runner, "tool", orig))
        st = store if store is not None else self.store()
        with session.using(st):
            REGISTRY["recon.httpx"]().fire(self.act("recon.httpx", target))
        return st

    @staticmethod
    def statuses(findings):
        return [f.status for f in findings]


# =====================================================================================
#  SENS 1 — L'OUTIL QUI N'A PAS TOURNÉ (251 findings mesurés — la cause la plus fréquente)
# =====================================================================================
class TestToolDidNotRunProducesAbstention(_Case):

    def test_a_tool_stopped_before_observing_anything_does_not_claim_a_verdict(self):
        """MESURÉ : `dnsx` refusait l'argv du catalogue (`-d` sans `-w`), rc=1, stdout VIDE — et les
        52 findings correspondants du ledger disaient `tested`. Un outil arrêté avant de regarder
        n'a rien vérifié. L'argv est corrigé (la wordlist est désormais REQUISE et fournie ici),
        mais la GARDE doit rester : tout arrêt précoce ultérieur (résolveur injoignable, image
        cassée) produit la même forme rc!=0 + stdout vide, et doit rester `skipped`."""
        f = self.fire_tool("recon.dnsx", 1, "", DNSX_ERR, target=HOST, params=WORDLIST_OK)
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_nuclei_that_never_started_does_not_claim_a_verdict(self):
        """`[FTL] Could not run nuclei: no templates provided for scan` — un scanner qui n'a pas
        démarré ne peut pas rendre « aucun hit »."""
        f = self.fire_nuclei(1, "", NUCLEI_ERR)
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_the_downgraded_evidence_names_the_return_code_and_keeps_the_error(self):
        """Le finding déclassé doit DIRE pourquoi (rc) et conserver la sortie d'erreur d'origine."""
        f = self.fire_tool("recon.dnsx", 1, "", DNSX_ERR, target=HOST, params=WORDLIST_OK)[0]
        self.assertIn("NON VÉRIFIÉ", f.evidence)
        self.assertIn("rc=1", f.evidence)
        self.assertIn("missing wordlist", f.evidence)


# =====================================================================================
#  SENS 1 (suite) — LE MUR : l'information survit dans l'état de l'hôte, pas dans la sortie
# =====================================================================================
class TestToolWallProducesAbstention(_Case):

    def test_nuclei_no_hit_behind_a_known_wall_is_skipped(self):
        """`nuclei: aucun hit` sur un hôte déjà constaté CHALLENGED : 0 résultat n'y veut pas dire
        « rien à trouver ». C'est le cœur du lot — nuclei ne rend NI code NI corps."""
        f = self.fire_nuclei(0, "", "", store=self.store(challenged=[URL]))
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_an_http_tool_with_no_hit_behind_a_known_wall_is_skipped(self):
        f = self.fire_tool("recon.katana", 0, "", "", store=self.store(challenged=[URL]))
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_a_tool_silences_itself_from_the_wall_it_just_dumped(self):
        """SANS état préalable, en UN SEUL tir : `katana` derrière le mur reçoit l'interstitiel,
        n'en tire AUCUN endpoint in-scope (les lignes de HTML ne sont pas des assets), et rc=0.
        L'interstitiel est versé à l'état de l'hôte au retour de l'outil, puis relu à la branche
        d'absence — c'est la boucle complète en une action, sans devoir deviner."""
        f = self.fire_tool("recon.katana", 0, CURL_WALL_DUMP, "")
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_js_endpoints_marker_stops_saying_tested(self):
        """Le module NOMMAIT déjà le challenge dans son titre en rendant `tested` — 20 fois dans le
        ledger. L'information n'était pas manquante, elle n'était pas suivie d'effet."""
        mod = self.module("recon.js_endpoints")
        mod._http_get = lambda url, headers=None, timeout=20, maxlen=500000: (403, "", {})
        with session.using(self.store(challenged=[URL])):
            f = mod.fire(self.act("recon.js_endpoints"))
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_downgraded_evidence_names_the_wall_and_keeps_the_original(self):
        f = self.fire_nuclei(0, "", "", store=self.store(challenged=[URL]))[0]
        self.assertIn("NON VÉRIFIÉ", f.evidence)
        self.assertIn("CHALLENGED", f.evidence)


# =====================================================================================
#  SENS 1 (suite) — LA PROPAGATION : ce que l'un a vu, les suivants le savent
# =====================================================================================
class TestWallStatePropagation(_Case):

    def test_httpx_seeds_the_wall_state_for_everyone_else(self):
        """`recon.httpx` a enregistré `{"title":"Just a moment...","status_code":403}` **19 fois**
        dans le ledger, AVANT tout autre outil, et cette connaissance mourait dans un finding INFO."""
        st = self.fire_httpx(0, HTTPX_WALL_JSON, "")
        self.assertEqual(st.clearance_state(URL), st.CHALLENGED)

    def test_a_tool_that_saw_the_wall_silences_the_next_one(self):
        """LA CHAÎNE COMPLÈTE, DE BOUT EN BOUT : curl voit le mur -> l'état est posé -> nuclei, qui
        ne voit RIEN d'autre qu'un stdout vide, s'abstient. C'est ce chaînage qui manquait."""
        st = self.store()
        self.fire_tool("recon.curl", 0, CURL_WALL_DUMP, "", store=st)
        f = self.fire_nuclei(0, "", "", store=st)
        self.assertEqual(self.statuses(f), ["skipped"])

    def test_marking_stays_inside_the_declared_perimeter(self):
        st = self.store()
        with session.using(st):
            self.assertFalse(blindness.note_tool_output("https://elsewhere.invalid/", CURL_WALL_DUMP))

    def test_propagation_is_a_noop_without_a_bound_store(self):
        """Hors moteur (dev/test/appel direct), aucun état n'existe -> comportement historique."""
        self.assertFalse(blindness.note_tool_output(URL, CURL_WALL_DUMP))


# =====================================================================================
#  SENS 2 — LA BORNE : « rien trouvé » sur une cible SAINE reste un verdict
# =====================================================================================
class TestNarrowBound(_Case):

    def test_a_legitimate_empty_result_stays_tested(self):
        """LE TEST QUI VERROUILLE LA BORNE. Un outil qui a tourné (rc=0) et n'a rien trouvé sur une
        cible SAINE a bel et bien vérifié. Le transformer en `skipped` détruirait la valeur du
        rapport — c'est l'excès inverse. Assertion ISOLÉE."""
        f = self.fire_tool("recon.katana", 0, "", "")
        self.assertEqual(self.statuses(f), ["tested"])

    def test_nuclei_with_no_hit_on_a_healthy_target_stays_tested(self):
        f = self.fire_nuclei(0, "", "")
        self.assertEqual(self.statuses(f), ["tested"])

    def test_a_nonzero_exit_WITH_stdout_stays_tested(self):
        """LA BORNE « stdout vide », ET LE RÉSIDU QU'ELLE ASSUME. `gobuster` refuse lui aussi l'argv
        du catalogue, mais DÉVERSE son texte d'usage sur stdout (2 080 octets mesurés) : la borne ne
        l'attrape pas, et ses 52 findings du ledger restent `tested`. C'est délibéré — la borne est
        FACTUELLE (« l'outil a-t-il écrit quoi que ce soit ? »), pas une liste de mots-clés, parce
        que `nikto` et `testssl` sortent en erreur APRÈS avoir rendu leurs résultats. Élargir à
        « rc != 0 » les rendrait `skipped` sur une cible parfaitement saine.
        Le vrai correctif de gobuster est son argv, pas son statut (cf. rapport de mission)."""
        f = self.fire_tool("recon.gobuster_dns", 1, GOBUSTER_OUT, GOBUSTER_ERR, target=HOST,
                           params=dict(WORDLIST_OK))
        self.assertEqual(self.statuses(f), ["tested"])

    def test_a_scanner_that_errored_after_producing_results_keeps_them(self):
        """`nikto` : rc=1 mais des résultats sur stdout -> ses hits sont émis, rien n'est déclassé."""
        f = self.fire_tool("web.nikto", 1, NIKTO_OUT, "erreur non fatale")
        self.assertNotIn("skipped", self.statuses(f))

    def test_a_bare_403_in_a_tools_output_is_not_a_wall(self):
        """Un 403 NU reste un verdict applicatif — ici sous la forme où un outil le RECRACHE. La
        même borne que le premier lot, au même endroit du raisonnement."""
        f = self.fire_tool("recon.curl", 0, "HTTP/1.1 403 Forbidden\r\nserver: nginx\r\n\r\n", "")
        self.assertNotIn("skipped", self.statuses(f))

    def test_a_bare_403_does_not_mark_the_host_challenged(self):
        st = self.store()
        with session.using(st):
            blindness.note_tool_output(URL, "HTTP/1.1 403 Forbidden\r\nserver: nginx\r\n\r\n")
        self.assertEqual(st.clearance_state(URL), st.UNKNOWN)

    def test_a_bare_403_page_does_not_mark_the_host_from_passive_surface(self):
        """Même borne sur la voie `recon_surface._http_get` : le corps d'erreur est prélevé pour
        JUGER, mais un 403 sans signature ne marque RIEN (sinon toute la recon se tairait)."""
        import urllib.error, io, email.message                        # noqa: E401
        msg = email.message.Message()
        msg["server"] = "nginx"
        st = self.store()

        def raiser(*a, **k):
            raise urllib.error.HTTPError(URL, 403, "err", msg, io.BytesIO(b"<h1>Forbidden</h1>"))
        from forge.modules import recon_surface as RS
        orig = RS.urllib.request.urlopen
        RS.urllib.request.urlopen = raiser
        self.addCleanup(lambda: setattr(RS.urllib.request, "urlopen", orig))
        with session.using(st):
            status, body, _h = RS.PassiveSurface._http_get(URL)
        self.assertEqual((status, body, st.clearance_state(URL)), (403, "", st.UNKNOWN))


# =====================================================================================
#  SENS 2 (suite) — UN SCANNER NOMME LES FOURNISSEURS QU'IL DÉTECTE
# =====================================================================================
class TestScannerNamingAVendorIsNotAWall(_Case):
    """Le piège PROPRE À CE LOT. `challenge.CHALLENGE_BODY_SIGNATURES` juge un CORPS de réponse — un
    corps qui contient « datadome » a bien été servi par DataDome. La sortie d'un SCANNER, elle, est
    du texte d'outil : sur une cible parfaitement saine, nuclei émet « Cloudflare Turnstile detect »
    et wafw00f écrit le nom du WAF. Réutiliser la liste telle quelle ferait taire ces cibles-là."""

    def test_a_template_named_turnstile_does_not_mark_a_healthy_host_as_walled(self):
        """Le danger n'est pas seulement pour CE tir : marquer l'hôte ferait taire TOUS les modules
        qui passent ensuite. On vérifie donc l'ÉTAT, pas seulement le statut rendu — un scanner qui
        NOMME un fournisseur ne doit rien poser dans le périmètre gouverné."""
        hit = json.dumps({"info": {"name": "Cloudflare Turnstile detect", "severity": "info"},
                          "matched-at": URL + "/login"})
        st = self.store()
        f = self.fire_nuclei(0, hit + "\n", "", store=st)
        self.assertEqual((st.clearance_state(URL), "skipped" in self.statuses(f)),
                         (st.UNKNOWN, False))

    def test_wafw00f_naming_datadome_does_not_silence_a_healthy_target(self):
        f = self.fire_tool("recon.wafw00f", 0, "", "detected: DataDome / Turnstile")
        self.assertNotIn("skipped", self.statuses(f))

    def test_the_tool_signature_list_is_a_strict_subset_of_the_upstream_one(self):
        """SOURCE UNIQUE, PAS DÉRIVE : la liste d'ici est plus ÉTROITE, jamais différente. Si une
        signature est renommée en amont, ce test rougit — au lieu de laisser la détection devenir
        silencieusement inerte. Assertion ISOLÉE."""
        upstream = set(challenge.CHALLENGE_BODY_SIGNATURES)
        mine = set(blindness._TOOL_OUTPUT_SIGNATURES)
        self.assertTrue(mine < upstream, f"hors de la liste amont : {sorted(mine - upstream)}")

    def test_the_excluded_vendor_names_are_exactly_the_ambiguous_ones(self):
        """Ce qu'on a DÉLIBÉRÉMENT laissé de côté, nommé : des noms de produit qu'un scanner écrit
        sur une cible saine. Épinglé pour qu'un élargissement soit un choix, pas un accident."""
        excluded = set(challenge.CHALLENGE_BODY_SIGNATURES) - set(blindness._TOOL_OUTPUT_SIGNATURES)
        self.assertLessEqual({"turnstile", "datadome", "attention required"}, excluded)


# =====================================================================================
#  SENS 2 (suite) — LES OUTILS QUI NE PARLENT PAS HTTP GARDENT LEUR VERDICT
# =====================================================================================
class TestNonHttpToolsKeepTheirVerdict(_Case):
    """LA RÉGRESSION QUI A RÉELLEMENT EU LIEU, épinglée. Au premier rejeu du corpus, l'abstention
    posée sur l'état de l'hôte a fait taire **53 constats valides** : `dig: aucun hit` (12),
    `subfinder: aucun hit` (18), `gobuster` (23). Un interstitiel HTTP n'aveugle ni une résolution
    DNS, ni un scan de ports, ni une interrogation de CT logs."""

    def test_dig_still_renders_its_verdict_on_a_challenged_host(self):
        f = self.fire_tool("recon.dig", 0, "", "", target=HOST, store=self.store(challenged=[URL]))
        self.assertEqual(self.statuses(f), ["tested"])

    def test_subfinder_still_renders_its_verdict_on_a_challenged_host(self):
        f = self.fire_tool("recon.subfinder", 0, "", "", target=HOST,
                           store=self.store(challenged=[URL]))
        self.assertEqual(self.statuses(f), ["tested"])

    def test_a_port_scanner_still_renders_its_verdict_on_a_challenged_host(self):
        f = self.fire_tool("recon.naabu", 0, "", "", target=HOST, store=self.store(challenged=[URL]))
        self.assertNotIn("skipped", self.statuses(f))

    def test_speaks_http_is_derived_from_the_argv_not_from_a_hand_kept_list(self):
        """Le discriminant vit dans les DONNÉES du spec : un outil invoqué avec une URL parle HTTP,
        un outil invoqué avec un hôte nu fait du DNS/TCP/TLS ou interroge un tiers. Un `ToolSpec`
        ajouté demain est donc classé sans que personne n'ait à penser à ce fichier."""
        speak = {s.kind for s in _catalog() if s.speaks_http}
        mute = {s.kind for s in _catalog() if not s.speaks_http}
        self.assertLessEqual({"recon.curl", "recon.katana", "web.zap_baseline", "web.nikto"}, speak)
        self.assertLessEqual({"recon.dig", "recon.dnsx", "recon.subfinder", "recon.naabu",
                              "recon.gobuster_dns"}, mute)

    def test_a_non_http_tool_that_never_ran_is_still_abstained(self):
        """La borne « parle HTTP » ne concerne QUE le mur. Un outil DNS qui ne s'est pas lancé n'a
        rien vérifié non plus — les deux causes restent bien distinctes."""
        f = self.fire_tool("recon.dnsx", 1, "", DNSX_ERR, target=HOST, params=WORDLIST_OK)
        self.assertEqual(self.statuses(f), ["skipped"])


# =====================================================================================
#  LES OBSERVATIONS NE SONT PAS DES VERDICTS — 1 594 findings à NE PAS TOUCHER
# =====================================================================================
class TestObservationsAreNeverDowngraded(_Case):

    def test_a_tool_that_produced_hits_keeps_them_even_behind_a_wall(self):
        """`curl` DÉVERSE la page de défi : chaque ligne devient une observation. Les déclasser
        détruirait la preuve MÊME du mur et noierait le seau `unverified` du rapport."""
        f = self.fire_tool("recon.curl", 0, CURL_WALL_DUMP, "", store=self.store(challenged=[URL]))
        self.assertTrue(f)
        self.assertNotIn("skipped", self.statuses(f))

    def test_a_nuclei_hit_behind_a_wall_is_kept(self):
        hit = json.dumps({"info": {"name": "WAF Detection", "severity": "info"},
                          "matched-at": URL})
        f = self.fire_nuclei(0, hit + "\n", "", store=self.store(challenged=[URL]))
        self.assertNotIn("skipped", self.statuses(f))

    def test_a_proven_finding_is_never_downgraded(self):
        """Une preuve reste une preuve — les deux déclassements ne touchent QUE `tested`."""
        f = REGISTRY["web.nuclei"]().finding(_proven=True, target=URL, title="preuve",
                                             status="vulnerable", severity="HIGH", evidence="e")
        blindness.downgrade_did_not_run([f], 1)
        blindness.downgrade(blindness.ToolWitness(HOST, challenged=True), [f])
        self.assertEqual(f.status, "vulnerable")

    def test_a_katana_hit_behind_a_wall_is_kept(self):
        """LA CONTRE-PREUVE STRUCTURELLE, ÉPINGLÉE. Sur le MÊME hôte challengé et le MÊME module que
        `test_a_tool_silences_itself_from_the_wall_it_just_dumped`, il suffit qu'UN endpoint in-scope
        soit extrait pour que le tir reparte avec ses findings — la branche d'absence n'est jamais
        atteinte. C'est ce qui garantit que 1 594 observations du corpus restent des observations."""
        f = self.fire_tool("recon.katana", 0, f"{URL}/api/v1/users\n", "",
                           store=self.store(challenged=[URL]))
        self.assertTrue(f)
        self.assertNotIn("skipped", self.statuses(f))


# =====================================================================================
#  CONTRAT — rien d'autre ne bouge
# =====================================================================================
class TestContractPreserved(_Case):

    def test_passive_surface_still_returns_an_empty_error_body(self):
        """Le corps d'erreur est prélevé pour JUGER, jamais rendu : sans quoi `recon.js_endpoints`
        extrairait des « endpoints » DEPUIS LA PAGE DE DÉFI."""
        import urllib.error, io, email.message                        # noqa: E401
        msg = email.message.Message()
        msg["server"] = "cloudflare"
        from forge.modules import recon_surface as RS
        orig = RS.urllib.request.urlopen

        def raiser(*a, **k):
            raise urllib.error.HTTPError(URL, 403, "err", msg,
                                         io.BytesIO(b"<title>Just a moment...</title>"))
        RS.urllib.request.urlopen = raiser
        self.addCleanup(lambda: setattr(RS.urllib.request, "urlopen", orig))
        with session.using(self.store()):
            status, body, _h = RS.PassiveSurface._http_get(URL)
        self.assertEqual((status, body), (403, ""))

    def test_the_peeked_error_body_is_what_marks_the_host(self):
        """Et c'est bien ce prélèvement qui rend le défi visible (même cause racine, même remède
        que `Oracle._http` au premier lot)."""
        import urllib.error, io, email.message                        # noqa: E401
        msg = email.message.Message()
        msg["server"] = "cloudflare"
        from forge.modules import recon_surface as RS
        orig = RS.urllib.request.urlopen

        def raiser(*a, **k):
            raise urllib.error.HTTPError(URL, 403, "err", msg,
                                         io.BytesIO(b"<title>Just a moment...</title>"))
        RS.urllib.request.urlopen = raiser
        self.addCleanup(lambda: setattr(RS.urllib.request, "urlopen", orig))
        st = self.store()
        with session.using(st):
            RS.PassiveSurface._http_get(URL)
        self.assertEqual(st.clearance_state(URL), st.CHALLENGED)

    def test_a_healthy_httpx_run_marks_nothing(self):
        st = self.fire_httpx(0, HTTPX_HEALTHY_JSON, "")
        self.assertEqual(st.clearance_state(URL), st.UNKNOWN)

    def test_the_helpers_never_raise_on_hostile_input(self):
        for bad in (None, object(), 3, b"\xff"):
            self.assertFalse(blindness.output_is_challenge(bad, bad))
            self.assertFalse(blindness.tool_did_not_run(bad, bad))
        self.assertFalse(blindness.ToolWitness(None).blind())
        self.assertIn("—", blindness.ToolWitness(None, challenged=True).why())

    def test_did_not_run_is_false_when_the_tool_succeeded(self):
        """rc==0 n'est JAMAIS un « n'a pas tourné », même sans une ligne de sortie : c'est
        exactement le cas du `aucun hit` légitime."""
        self.assertFalse(blindness.tool_did_not_run(0, ""))


def _catalog():
    from forge.modules.toolcatalog import CATALOG_SPECS
    return CATALOG_SPECS


if __name__ == "__main__":
    unittest.main()
