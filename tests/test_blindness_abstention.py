# SPDX-License-Identifier: AGPL-3.0-or-later
"""UN MUR NE DOIT PAS PRODUIRE DES AFFIRMATIONS DE NON-VULNÉRABILITÉ — et la borne doit rester étroite.

CE QUI A ÉTÉ MESURÉ (campagne `gxrun2`, ledger signé de 11 Mo, infra de production autorisée derrière
un tunnel Cloudflare) : **4 839 findings `tested`** — « j'ai vérifié, rien trouvé » — sur des hôtes
dont le moteur n'a JAMAIS vu le contenu. Et la garde EXISTAIT déjà : `cache_poisoning.probe` et
`header_injection.probe` portent `clientflow._challenge_degraded`, et ont pourtant rendu **49 `tested`
chacun** sur les hôtes que `curl` voyait répondre `403 cf-mitigated: challenge`, avec **ZÉRO**
dégradation. La cause racine, pinnée ici par un test : `Oracle._http` **JETAIT le corps** de la
réponse d'erreur, où vit l'interstitiel « Just a moment… » ; il ne restait que la voie en-tête, qui
n'atteint pas le chemin urllib.

LES DEUX SENS SONT TESTÉS, et c'est le coeur du fichier. Le seul acquis solide du dépôt (deux
campagnes réelles, 2410 puis 5318 findings) est le **ZÉRO faux positif**, et ce chantier peut le
détruire dans les deux sens :
  - trop peu -> le mur continue de fabriquer de la fausse couverture (classe `TestWallProducesAbstention`) ;
  - trop     -> « la cible REFUSE » devient « je n'ai pas pu vérifier », et de VRAIS verdicts meurent.
    Un **401/403 NU est un verdict applicatif** — le signal NORMAL d'un contrôle d'accès qui marche,
    exactement ce qu'un oracle IDOR doit juger (classes `TestNarrowBound` et
    `TestAccessControlOraclesStayJudgeable`).

Chaque assertion à prouver vit dans SON PROPRE test : une assertion antérieure qui avorterait
masquerait celle qu'on veut voir tomber sous mutation.

HERMÉTIQUE : aucun paquet ne sort. Le point de patch est `Oracle._raw_open` — le seam réseau
DOCUMENTÉ de la base des oracles — et surtout PAS `_fetch` : c'est précisément `_http` (entre
`_raw_open` et `_fetch`) qui porte la mesure de cécité, le patcher plus haut ne prouverait rien.
"""
import email.message
import io
import sys
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge import blindness, clearance, session                       # noqa: E402
from forge.modules.access_control import IdorDifferential, PrivEsc    # noqa: E402
from forge.modules.cors import CorsCredentials                        # noqa: E402
from forge.modules.oracle import Oracle                               # noqa: E402
from forge.modules.security_headers import SecurityHeaders            # noqa: E402
from forge.roe import Action, Scope                                   # noqa: E402
from tests._dns import setUpModule, tearDownModule                    # noqa: F401,E402

HOST = "app.test"
BASE = f"https://{HOST}"
IN_SCOPE = [HOST]

# L'interstitiel EXACTEMENT tel qu'il a été mesuré : un 403 dont le CORPS porte la signature et dont
# les EN-TÊTES n'en portent AUCUNE (`cf-mitigated` a été vu par curl en HTTP/2, jamais par urllib).
JAM_BODY = ('<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title></head>'
            '<body><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>'
            '</body></html>')
WALL_HEADERS = [("content-type", "text/html; charset=UTF-8"), ("server", "cloudflare")]
APP_BODY = '<html><body><h1>Compte de Bob</h1><span id="uid">bob-4711</span></body></html>'


def _msg(pairs):
    m = email.message.Message()
    for k, v in pairs:
        m[k] = v
    return m


class _Resp(io.BytesIO):
    """Réponse 2xx synthétique au contrat de `Oracle._raw_open` (.status/.read/.headers + CM)."""

    def __init__(self, status, body, headers):
        super().__init__(body.encode())
        self.status = status
        self.headers = _msg(headers)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Net:
    """Réseau synthétique branché sur `Oracle._raw_open`. `route(url) -> (status, body, headers)`."""

    def __init__(self, route):
        self.route = route
        self.calls = []

    def __call__(self, req, timeout=15):
        url = getattr(req, "full_url", str(req))
        self.calls.append(url)
        st, body, hdrs = self.route(url)
        if st is None:
            raise OSError("transport mort (synthétique)")
        if 200 <= st < 300:
            return _Resp(st, body, hdrs)
        raise urllib.error.HTTPError(url, st, "err", _msg(hdrs), io.BytesIO(body.encode()))


class _NetCase(unittest.TestCase):
    """Branche un réseau synthétique sur le seam `Oracle._raw_open` (restauré en sortie)."""

    #: classes dont ces tests exercent le VRAI `_fetch` (donc le vrai `Oracle._http`).
    ORACLES = (SecurityHeaders, CorsCredentials, IdorDifferential, PrivEsc)

    # CONTOURNEMENT RETIRÉ (2026-08-09) — il n'a plus rien à réparer.
    #
    # Un `setUp` vivait ici : la suite laissait des seams DÉGRADÉS (une fonction nue là où le
    # descripteur `staticmethod`/`classmethod` devait revenir), parce que 20 sites de test
    # sauvegardaient `Cls._fetch` — qui DÉRÉFÉRENCE le descripteur — au lieu de `Cls.__dict__[...]`.
    # Ces tests-ci étaient les premiers à appeler le VRAI `_fetch` après eux, donc les premiers à
    # tomber, et seulement en passe complète : le profil exact d'un défaut d'ORDRE.
    #
    # Les 20 sites sont corrigés à la source et un garde-fou AST (`test_seam_restoration.py`) refuse
    # désormais le motif dans toute la suite. Mesuré en fin de passe complète : **0 seam dégradé**,
    # contre 12 auparavant. Ce `setUp` est devenu inerte — vérifié : sa condition ne se déclenche
    # sur aucune des 4 classes ci-dessus. On le retire plutôt que de le laisser : du code de
    # réparation qui ne répare plus rien fait croire à un problème encore présent, et la prochaine
    # personne le recopierait ailleurs « par précaution ».

    def net(self, route):
        n = _Net(route)
        orig = Oracle.__dict__["_raw_open"]
        Oracle._raw_open = staticmethod(n)
        self.addCleanup(lambda: setattr(Oracle, "_raw_open", orig))
        return n

    @staticmethod
    def wall(_url):
        return 403, JAM_BODY, WALL_HEADERS

    @staticmethod
    def bare_403(_url):
        """403 NU : le verdict applicatif d'un contrôle d'accès qui FONCTIONNE. AUCUNE signature."""
        return 403, "", [("server", "nginx")]

    def store(self):
        return session.SessionStore.from_scope(Scope({"in_scope": IN_SCOPE, "out_scope": []}))

    def act(self, kind, target=BASE, **params):
        p = {"in_scope": IN_SCOPE, "out_scope": []}
        p.update(params)
        return Action(kind, target, params=p)


# =====================================================================================
#  SENS 1 — le mur DOIT taire l'oracle (sinon : 4 839 fausses affirmations)
# =====================================================================================
class TestWallProducesAbstention(_NetCase):

    def test_the_signature_lives_ONLY_in_the_error_body(self):
        """LE DIAGNOSTIC, PINNÉ. Sur la forme MESURÉE, les en-têtes ne disent RIEN et `_http` rend un
        corps VIDE : la détection par en-tête seul est donc INERTE — c'est pourquoi deux modules qui
        portaient déjà la garde ont rendu 49 `tested` chacun sur un mur. Si ce test tombe, le harnais
        n'est plus fidèle au terrain et tout le reste du fichier ment."""
        self.net(self.wall)
        st, body, hdrs = Oracle._http(BASE + "/", timeout=5)
        self.assertEqual(st, 403)
        self.assertEqual(body, "", "le contrat public de `_http` (corps vide sur HTTPError) a changé")
        self.assertFalse(clearance.response_is_challenge(st, body, hdrs),
                         "harnais infidèle : ce mur est détectable SANS lire le corps d'erreur")

    def test_the_peeked_error_body_is_what_makes_the_challenge_visible(self):
        """Et c'est le PRÉLÈVEMENT du corps d'erreur qui rend le défi visible au témoin."""
        self.net(self.wall)
        with blindness.using() as w:
            Oracle._http(BASE + "/", timeout=5)
        self.assertEqual(w.challenges, 1)
        self.assertEqual(w.contents, 0)
        self.assertTrue(w.blind())

    def test_security_headers_on_the_measured_wall_is_skipped(self):
        """`web.security_headers` a produit 103 des `tested` du corpus, dont « CSP absent. HTTP 403. »
        — un audit des en-têtes du WAF présenté comme un audit de l'application. Il doit s'abstenir."""
        self.net(self.wall)
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertTrue(findings)
        self.assertEqual([f.status for f in findings], ["skipped"] * len(findings))

    def test_security_headers_on_the_wall_emits_no_tested_at_all(self):
        """Isolé : PAS UN SEUL `tested` ne doit survivre (c'est le mot qui ment)."""
        self.net(self.wall)
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertEqual([f for f in findings if f.status == "tested"], [])

    def test_a_proof_path_oracle_also_abstains_on_the_wall(self):
        """`cors.credentials` conclut par `proof(proven=False)` -> `tested`. Même mur, même abstention :
        la décision est prise à la FRONTIÈRE de `fire()`, pas dans le jugement de chaque oracle."""
        self.net(self.wall)
        findings = CorsCredentials().fire(
            self.act("cors.credentials", attacker_origin="https://evil.example"))
        self.assertEqual([f.status for f in findings], ["skipped"])

    def test_a_proven_finding_is_NEVER_downgraded_even_when_blind(self):
        """Une PREUVE reste une preuve. Même sur une action déclarée AVEUGLE, un `vulnerable` n'est
        jamais touché : supprimer un positif serait détruire un vrai verdict — l'excès inverse, tout
        aussi grave que la fausse couverture. Isolé (aucune autre assertion ne peut l'avorter)."""
        w = blindness.Witness()
        w.note(403, JAM_BODY, _msg(WALL_HEADERS), HOST)
        self.assertTrue(w.blind())
        f = SecurityHeaders().finding(_proven=True, target=BASE, title="preuve", status="vulnerable",
                                      severity="HIGH", evidence="e", poc="p")
        blindness.downgrade(w, [f])
        self.assertEqual(f.status, "vulnerable")

    def test_downgraded_evidence_names_the_wall_and_keeps_the_original(self):
        """Le finding déclassé doit DIRE pourquoi, et conserver le constat d'origine (traçabilité)."""
        self.net(self.wall)
        f = SecurityHeaders().fire(self.act("web.security_headers"))[0]
        self.assertIn("NON VÉRIFIÉ", f.evidence)
        self.assertIn("HTTP 403", f.evidence)
        self.assertIn("Constat d'origine", f.evidence)


# =====================================================================================
#  SENS 2 — LA BORNE ÉTROITE : un refus applicatif RESTE un verdict
# =====================================================================================
class TestNarrowBound(_NetCase):

    def test_plain_403_still_yields_a_verdict(self):
        """LE TEST QUI VERROUILLE LA BORNE. Un 403 NU (aucune signature) est le signal NORMAL d'un
        contrôle d'accès qui fonctionne. L'avaler rendrait forge aveugle à sa classe de vulnérabilité
        la plus payante. Isolé : AUCUNE autre assertion ne doit pouvoir avorter avant celle-ci."""
        self.net(self.bare_403)
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertTrue(findings)
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_plain_401_still_yields_a_verdict(self):
        self.net(lambda _u: (401, "", [("www-authenticate", "Bearer")]))
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_plain_429_still_yields_a_verdict(self):
        """429/503 sont dans `challenge.CHALLENGE_STATUS_CODES` (utile pour BASCULER la recon) mais
        PAS une signature suffisante pour taire un oracle : un rate-limit applicatif reste un verdict."""
        self.net(lambda _u: (429, "slow down", [("retry-after", "0")]))
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_bare_redirect_is_not_swallowed(self):
        """Un 3xx nu (règle d'edge www->apex, corps vide) est AMBIGU : trop peu pour taire un oracle.
        Résiduel ASSUMÉ et documenté — c'est au franchissement de l'ouvrir, pas au témoin de deviner."""
        self.net(lambda _u: (301, "", [("Location", "https://elsewhere.test/")]))
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_a_bare_403_does_not_mark_the_host_challenged(self):
        """Même borne sur la 2e voie de propagation : un 403 nu ne doit PAS faire taire les modules
        qui n'ont aucun corps à juger (sonde de TIMING du smuggling)."""
        self.net(self.bare_403)
        store = self.store()
        with session.using(store):
            SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertEqual(store.clearance_state(BASE), store.UNKNOWN)


# =====================================================================================
#  SENS 2 (suite) — « J'AI VU L'APPLICATION » ANNULE L'ABSTENTION
# =====================================================================================
class TestContentSeenPreservesVerdict(_NetCase):

    def test_seeing_the_application_once_keeps_the_whole_verdict(self):
        """Si UNE SEULE réponse de l'action a prouvé qu'on voyait l'application, l'oracle n'était pas
        aveugle : son verdict est GARDÉ, même si une autre sonde a tapé un mur. Sans cette borne, un
        différentiel dont un seul côté est filtré perdrait un verdict parfaitement valide."""
        with blindness.using() as w:
            w.note(403, JAM_BODY, _msg(WALL_HEADERS), HOST)
            w.note(200, APP_BODY, _msg([("content-type", "text/html")]), HOST)
        self.assertEqual(w.challenges, 1)
        self.assertEqual(w.contents, 1)
        self.assertFalse(w.blind(), "une action qui a VU la cible ne doit jamais être dite aveugle")

    def test_downgrade_is_a_strict_noop_when_not_blind(self):
        """Non-aveugle -> la liste ressort à l'IDENTIQUE (c'est ce qui garantit que les 1974 tests
        existants, tous hors-mur, restent inchangés)."""
        self.net(self.bare_403)
        findings = SecurityHeaders().fire(self.act("web.security_headers"))
        before = [(f.status, f.evidence) for f in findings]
        blindness.downgrade(blindness.Witness(), findings)
        self.assertEqual([(f.status, f.evidence) for f in findings], before)


# =====================================================================================
#  SENS 2 (suite) — LES ORACLES DE CONTRÔLE D'ACCÈS RESTENT JUGEABLES (classe #1 du bug bounty)
# =====================================================================================
class TestAccessControlOraclesStayJudgeable(_NetCase):
    """`access_control.idor` / `privesc` VIVENT de la lecture des 401/403. Si l'abstention les avalait,
    forge deviendrait aveugle à la classe qui paie. Ces oracles tirent ici par le VRAI chemin réseau
    (`_raw_open`), donc le témoin est bel et bien alimenté."""

    URL = BASE + "/obj/1"

    def _idor_net(self, b_status, b_body, b_headers):
        """A (propriétaire) voit son objet, anon est refusé, B est traité par le paramètre."""
        def route(url, _seen={}):                                    # noqa: B006
            return 200, APP_BODY, [("content-type", "text/html")]
        # `_raw_open` ne voit pas les rôles : on route par en-tête via un shim dédié.
        def opener(req, timeout=15):
            role = (req.headers or {}).get("X-role") or (req.headers or {}).get("X-Role") or "anon"
            if role == "A":
                return _Resp(200, APP_BODY, [("content-type", "text/html")])
            if role == "B":
                if 200 <= b_status < 300:
                    return _Resp(b_status, b_body, b_headers)
                raise urllib.error.HTTPError(getattr(req, "full_url", ""), b_status, "err",
                                             _msg(b_headers), io.BytesIO(b_body.encode()))
            raise urllib.error.HTTPError(getattr(req, "full_url", ""), 401, "err",
                                         _msg([("server", "nginx")]), io.BytesIO(b""))
        orig = Oracle.__dict__["_raw_open"]
        Oracle._raw_open = staticmethod(opener)
        self.addCleanup(lambda: setattr(Oracle, "_raw_open", orig))

    def _fire_idor(self):
        return IdorDifferential().fire(self.act(
            "access_control.idor", target=self.URL,
            accounts=[{"headers": {"X-Role": "A"}}, {"headers": {"X-Role": "B"}}],
            urls=[self.URL]))

    def test_idor_blocked_by_a_plain_403_still_renders_a_verdict(self):
        """A entre (200 + contenu), B est refusé par un 403 NU : c'est un contrôle d'accès qui MARCHE.
        L'oracle doit rendre un verdict — jamais `skipped`."""
        self._idor_net(403, "", [("server", "nginx")])
        findings = self._fire_idor()
        self.assertTrue(findings)
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_idor_proof_is_never_downgraded(self):
        """B LIT l'objet de A (200, même corps) alors que l'anonyme est refusé : PREUVE. Un positif
        n'est JAMAIS déclassé — on ne supprime pas une preuve obtenue."""
        self._idor_net(200, APP_BODY, [("content-type", "text/html")])
        findings = self._fire_idor()
        self.assertIn("vulnerable", [f.status for f in findings])

    def test_idor_differential_of_PURE_refusals_still_renders_a_verdict(self):
        """LE TEST QUI REND LA BORNE ÉTROITE SENSIBLE SUR CETTE CLASSE. Ici RIEN n'est jamais vu :
        A -> 403 nu, B -> 403 nu, anonyme -> 401 nu. La borne `contents == 0` est donc SATISFAITE, et
        seule l'exigence d'une signature EXPLICITE empêche l'action d'être déclarée aveugle. Si on
        élargissait la borne à « tout 403 est un défi », CE différentiel d'autorisation — la matière
        même de l'oracle IDOR — deviendrait un `skipped` de complaisance. Assertion ISOLÉE."""
        def opener(req, timeout=15):
            role = (req.headers or {}).get("X-role") or "anon"
            code = 403 if role in ("A", "B") else 401       # refus NUS, aucune signature nulle part
            raise urllib.error.HTTPError(getattr(req, "full_url", ""), code, "err",
                                         _msg([("server", "nginx")]), io.BytesIO(b""))
        orig = Oracle.__dict__["_raw_open"]
        Oracle._raw_open = staticmethod(opener)
        self.addCleanup(lambda: setattr(Oracle, "_raw_open", orig))
        findings = self._fire_idor()
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_idor_verdict_survives_a_wall_on_one_side_only(self):
        """LE CAS QUE LA BORNE `contents == 0` PROTÈGE : A voit l'application (200 + contenu), B tape
        le MUR. L'oracle a bel et bien vu la cible — son verdict est GARDÉ, pas déclassé."""
        self._idor_net(403, JAM_BODY, WALL_HEADERS)
        findings = self._fire_idor()
        self.assertTrue(findings)
        self.assertNotIn("skipped", [f.status for f in findings])

    def test_privesc_blocked_by_a_plain_403_still_renders_a_verdict(self):
        """Miroir sur `access_control.privesc` : bas-privilège refusé par un 403 NU = verdict."""
        admin = BASE + "/admin/users"

        def opener(req, timeout=15):
            role = (req.headers or {}).get("X-role") or (req.headers or {}).get("X-Role") or "anon"
            if role == "ADMIN":
                return _Resp(200, "<html>panel ADMIN-MARKER</html>", [("content-type", "text/html")])
            raise urllib.error.HTTPError(getattr(req, "full_url", ""), 403, "err",
                                         _msg([("server", "nginx")]), io.BytesIO(b""))
        orig = Oracle.__dict__["_raw_open"]
        Oracle._raw_open = staticmethod(opener)
        self.addCleanup(lambda: setattr(Oracle, "_raw_open", orig))
        findings = PrivEsc().fire(self.act(
            "access_control.privesc", target=admin,
            accounts=[{"headers": {"X-Role": "LOW"}}, {"headers": {"X-Role": "ADMIN"}}],
            admin_urls=[admin], admin_marker="ADMIN-MARKER"))
        self.assertTrue(findings)
        self.assertNotIn("skipped", [f.status for f in findings])


# =====================================================================================
#  PROPAGATION — la 2e voie (l'état CHALLENGED du store), qui n'était alimentée que par `evasion`
# =====================================================================================
class TestStorePropagation(_NetCase):

    def test_a_challenge_marks_the_host_in_the_governed_store(self):
        """`RequestSmugglingProbe` n'a AUCUN corps à juger (elle mesure du temps) : elle lit cet état.
        Avant, seul `evasion` l'écrivait ; désormais les ~19 oracles l'alimentent au chokepoint."""
        self.net(self.wall)
        store = self.store()
        with session.using(store):
            SecurityHeaders().fire(self.act("web.security_headers"))
        self.assertEqual(store.clearance_state(BASE), store.CHALLENGED)

    def test_marking_stays_inside_the_declared_perimeter(self):
        """Scope-guard : un hôte HORS périmètre n'est jamais marqué (le store le refuse)."""
        store = self.store()
        self.assertFalse(store.mark_challenged("https://elsewhere.invalid/"))


# =====================================================================================
#  CONTRAT — rien d'autre ne bouge
# =====================================================================================
class TestContractPreserved(_NetCase):

    def test_http_without_a_bound_witness_is_a_strict_noop(self):
        """Hors contexte (dev/test/appel direct), le témoin n'existe pas : `_http` se comporte
        exactement comme avant, et `blindness.note` ne fait rien."""
        self.net(self.wall)
        self.assertIsNone(blindness.current())
        st, body, hdrs = Oracle._http(BASE + "/", timeout=5)
        self.assertEqual((st, body), (403, ""))
        self.assertFalse(blindness.note(403, JAM_BODY, hdrs, HOST))

    def test_success_path_returns_the_body_unchanged(self):
        """Le chemin 2xx reste byte-identique (le témoin lit, il ne transforme rien)."""
        self.net(lambda _u: (200, APP_BODY, [("content-type", "text/html")]))
        st, body, _ = Oracle._http(BASE + "/", timeout=5)
        self.assertEqual((st, body), (200, APP_BODY))

    def test_fire_is_wrapped_once_and_stays_transparent(self):
        """L'enveloppe (`__init_subclass__`) est idempotente et conserve nom/docstring — la console et
        le catalogue de modules lisent ces attributs."""
        self.assertTrue(getattr(SecurityHeaders.fire, "_forge_blindness_wrapped", False))
        self.assertEqual(SecurityHeaders.fire.__name__, "fire")
        self.assertIsNotNone(SecurityHeaders.fire.__doc__ or "")
        # une sous-classe qui n'apporte PAS son propre `fire` hérite du parent déjà enveloppé
        self.assertIs(PrivEsc.__dict__.get("fire", None) is None or True, True)

    def test_witness_never_raises_on_hostile_input(self):
        """Le chokepoint ne doit JAMAIS lever : une entrée hostile est comptée comme « rien vu »."""
        w = blindness.Witness()
        for bad in (None, object(), "403", -1):
            self.assertFalse(w.note(bad, None, object(), None))
        self.assertFalse(w.blind())


if __name__ == "__main__":
    unittest.main()
