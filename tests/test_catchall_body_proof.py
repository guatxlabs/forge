# SPDX-License-Identifier: AGPL-3.0-or-later
"""UN CODE 200 N'EST PAS UNE PREUVE — verrou des deux sens, sur le défaut le plus grave du dépôt.

CE QUI S'EST PASSÉ (campagne `kong`, ledger signé `.../tmp/kong/ledger.jsonl`, 2026-08-10)
-------------------------------------------------------------------------------------------
Première campagne de forge contre une cible tierce à surface anonyme RÉELLE (programme HackerOne
public). Résultat : **16 findings, 8 distincts, TOUS `[HIGH] vulnerable`, TOUS FAUX** —
`/actuator/beans`, `/actuator/threaddump`, `/actuator/heapdump`, `/actuator/httptrace`, et les
variantes Boot 1.x `/beans`, `/heapdump`, `/threaddump`, `/trace`. La cible est une SPA qui rend son
`index.html` — **3 427 octets IDENTIQUES, HTTP 200** — pour `/wp-admin`, `/.git/config`,
`/server-status` ou `/zzz-chemin-inexistant-12345`. Il n'y a aucun Actuator dessus. L'evidence des 8
findings PORTE la preuve du défaut : elle cite `<!DOCTYPE html>\\n<html lang="en-US">…` comme
« fuite de configuration/état ».

LA CAUSE, LOCALISÉE — `forge/modules/exposure.py` (avant correctif) :

    if is_sensitive and (leaks or path.endswith(("/heapdump", "/threaddump", "/beans",
                                                 "/httptrace", "/trace"))):
        exposures.append({… "severity": "HIGH", "proven": True, …})

Pour ces CINQ chemins, `path.endswith(…)` est VRAI INCONDITIONNELLEMENT : la disjonction rendait
`leaks` — le seul terme qui lisait le CORPS — totalement inopérant, et le verdict `HIGH, proven=True`
tombait sur le seul `st == 200`.

POURQUOI IL N'AVAIT JAMAIS ÉTÉ VU. Le dépôt tenait un « 0 faux positif » mesuré sur 2 410 puis 5 318
puis 2 771 findings. Il n'a tenu que parce que les cibles précédentes étaient MURÉES : ni guatx
(Cloudflare) ni l'UAT syfe (404 partout) ne rendaient 200 avec du contenu. **Le défaut se révèle à la
PREMIÈRE cible réellement atteignable.**

CE QUE CE FICHIER VERROUILLE — LES DEUX SENS, JAMAIS UN SEUL
-------------------------------------------------------------
Un correctif qui se contenterait d'éteindre le faux positif serait aussi mauvais que le défaut : un
actuator RÉELLEMENT exposé est un finding qui paie. Chaque classe ci-dessous porte donc les DEUX :

  1. `TestActuatorBodyProof`         — faux positif ÉTEINT (HTML/SPA) **et** vrai positif CONSERVÉ
                                       (JSON `/beans`, `"traces"`, threaddump, magic HPROF).
  2. `TestPathDiscriminationProbe`   — la sonde de contrôle : catch-all constaté / cible qui
                                       discrimine / indéterminé (elle ne PROMEUT jamais).
  3. `TestExposureCatchall`          — sur une cible catch-all : `skipped`, aucun chemin sondé.
  4. `TestNoInverseExcess`           — une cible qui discrimine garde son comportement historique,
                                       BYTE pour BYTE (aucun `skipped` fabriqué).

MÉTHODE : aucun réseau réel. Le seam `_fetch` de chaque oracle est monkeypatché, et le corps servi au
cas nominal est le CORPS RÉEL prélevé dans le ledger de la campagne fautive (`_KONG_SPA_HTML`).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forge.roe import Action                                        # noqa: E402
from forge.modules.exposure import FrameworkExposure                # noqa: E402
from forge.modules import exposure as expmod                        # noqa: E402
from forge.modules.oracle import Oracle, PathDiscrimination         # noqa: E402


# Corps RÉEL servi par `cloud.konghq.com` à TOUT chemin (prélevé dans l'evidence des 8 findings du
# ledger `kong`). C'est CE corps qui a été rapporté comme « fuite de configuration/état ».
_KONG_SPA_HTML = (
    '<!DOCTYPE html>\n<html lang="en-US">\n\n  <head>\n\n\n    <meta charset="utf-8">\n'
    '    <meta http-equiv="X-UA-Compatible" content="IE=edge">\n'
    '    <meta name="viewport" content="width=device-width,initial-scale=1.0">\n'
    '    <meta name="robots" content="noindex nofollow" />\n'
    '    <meta name="service" content="app-root" />\n'
    '    <meta name="client" content="b352db3" />\n'
    '    <meta name="child-app" content="" />\n  </head>\n  <body><div id="root"></div></body>\n</html>\n'
)

# Corps d'actuators RÉELLEMENT exposés (formes Spring Boot 1.x et 2.x) — le VRAI POSITIF à conserver.
_REAL_BEANS = ('{"contexts":{"application":{"beans":{"dataSource":{"aliases":[],"scope":"singleton",'
               '"type":"com.zaxxer.hikari.HikariDataSource"}}}}}')
_REAL_TRACES = ('{"traces":[{"timestamp":"2026-08-10T08:47:13Z","request":{"method":"GET",'
                '"uri":"http://app/internal"},"response":{"status":200}}]}')
_REAL_THREADDUMP = ('{"threads":[{"threadName":"http-nio-8080-exec-1","threadId":42,'
                    '"threadState":"RUNNABLE","lockedMonitors":[]}]}')
_REAL_THREADDUMP_TEXT = ('"http-nio-8080-exec-1" #42 daemon prio=5 nid=0x2a runnable\n'
                         '   java.lang.Thread.State: RUNNABLE\n\tat java.base/java.net.read(Native Method)\n')
_REAL_HEAPDUMP = "JAVA PROFILE 1.0.2\x00\x00\x00\x08\x00\x00\x01\x92�� binary hprof payload"
_REAL_ENV = ('{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties",'
             '"properties":{"db.password":{"value":"s3cr3t-value-xyz"}}}]}')


def _patch(cls, fn):
    """Remplace `cls._fetch` par `fn` et restaure PROPREMENT (delattr si le seam était hérité)."""
    had = "_fetch" in cls.__dict__
    orig = cls.__dict__.get("_fetch")
    cls._fetch = staticmethod(fn)

    def restore():
        if had:
            cls._fetch = orig
        else:
            try:
                delattr(cls, "_fetch")
            except AttributeError:
                pass
    return restore


def _fire(fake, params=None):
    restore = _patch(FrameworkExposure, fake)
    p = dict({"in_scope": ["app.test"]}, **(params or {}))
    try:
        return FrameworkExposure().fire(Action("framework.exposure", "app.test", params=p))
    finally:
        restore()


# =================================================================================================
class TestActuatorBodyProof(unittest.TestCase):
    """`_actuator_leak` — la PREUVE POSITIVE par CORPS, chemin par chemin. Les deux sens."""

    # --- SENS 1 : le faux positif est ÉTEINT ------------------------------------------------------
    def test_spa_html_never_proves_any_actuator_path(self):
        """LE défaut, à la source. Les 5 chemins qui tombaient sur `path.endswith(...)` doivent tous
        rendre False sur le corps RÉEL de la cible kong."""
        for path in ("/actuator/beans", "/actuator/heapdump", "/actuator/threaddump",
                     "/actuator/httptrace", "/beans", "/heapdump", "/threaddump", "/trace",
                     "/actuator/env", "/configprops"):
            with self.subTest(path=path):
                leak, why = expmod._actuator_leak(path, _KONG_SPA_HTML)
                self.assertFalse(leak, f"{path} : une page HTML n'est un actuator dans AUCUN cas")
                self.assertEqual(why, "")

    def test_empty_and_garbage_bodies_never_prove(self):
        for body in ("", None, "   ", "not found", "404", "<!doctype html><html>x</html>",
                     "Access denied", "OK"):
            for path in ("/actuator/beans", "/heapdump", "/actuator/threaddump", "/trace"):
                with self.subTest(path=path, body=repr(body)[:24]):
                    self.assertFalse(expmod._actuator_leak(path, body)[0])

    def test_json_without_the_endpoint_signature_never_proves(self):
        """Une API JSON quelconque servie sur `/beans` n'est PAS un actuator : la signature doit être
        celle de CET endpoint, pas « du JSON »."""
        self.assertFalse(expmod._actuator_leak("/beans", '{"ok":true,"data":[]}')[0])
        self.assertFalse(expmod._actuator_leak("/actuator/httptrace", '{"ok":true}')[0])
        self.assertFalse(expmod._actuator_leak("/actuator/threaddump", '{"items":[1,2,3]}')[0])

    def test_heapdump_requires_the_hprof_magic(self):
        """Le heapdump est BINAIRE : sa seule signature honnête est le magic HPROF en tête. Ni du
        JSON, ni du HTML, ni le mot « heapdump » quelque part dans une page."""
        self.assertFalse(expmod._actuator_leak("/heapdump", '{"heapdump":"yes"}')[0])
        self.assertFalse(expmod._actuator_leak("/actuator/heapdump", "see /actuator/heapdump")[0])
        self.assertTrue(expmod._actuator_leak("/actuator/heapdump", _REAL_HEAPDUMP)[0])

    # --- SENS 2 : le VRAI POSITIF est CONSERVÉ ----------------------------------------------------
    def test_real_actuators_are_still_proven(self):
        """Un actuator RÉELLEMENT exposé DOIT rester détecté — c'est un finding qui paie."""
        for path, body, expect in (
                ("/actuator/beans", _REAL_BEANS, '"beans"'),
                ("/beans", _REAL_BEANS, '"beans"'),
                ("/actuator/httptrace", _REAL_TRACES, '"traces"'),
                ("/trace", _REAL_TRACES, '"traces"'),
                ("/actuator/threaddump", _REAL_THREADDUMP, "threaddump"),
                ("/threaddump", _REAL_THREADDUMP_TEXT, "jstack"),
                ("/actuator/heapdump", _REAL_HEAPDUMP, "HPROF"),
                ("/actuator/env", _REAL_ENV, "actuator"),
                ("/configprops", _REAL_ENV, "actuator")):
            with self.subTest(path=path):
                leak, why = expmod._actuator_leak(path, body)
                self.assertTrue(leak, f"{path} : un actuator réel doit rester PROUVÉ")
                self.assertIn(expect, why)

    def test_end_to_end_real_actuator_still_vulnerable_high(self):
        """Bout en bout : cible qui DISCRIMINE ses routes + `/actuator/beans` réel -> `vulnerable` HIGH."""
        def fake(url, headers=None, timeout=15):
            if url.endswith("/actuator/beans"):
                return (200, _REAL_BEANS)
            if url.endswith("/"):
                return (200, "<html>app</html>")
            return (404, "")
        f = _fire(fake)
        vuln = [x for x in f if x.status == "vulnerable"]
        self.assertEqual(len(vuln), 1, [x.title for x in f])
        self.assertEqual(vuln[0].severity, "HIGH")
        self.assertIn("/actuator/beans", vuln[0].target)
        self.assertIn("PREUVE DE CORPS", vuln[0].evidence)

    def test_end_to_end_spa_produces_zero_vulnerable(self):
        """LA RÉGRESSION DE LA CAMPAGNE `kong`, rejouée : le même corps, sur tous les chemins ->
        ZÉRO `vulnerable`. Avant correctif : 8 findings HIGH."""
        def fake(url, headers=None, timeout=15):
            return (200, _KONG_SPA_HTML)                    # 200 pour TOUT — la cible réelle
        f = _fire(fake)
        self.assertEqual([x for x in f if x.status == "vulnerable"], [],
                         "aucune promotion ne peut venir d'un index.html")

    def test_end_to_end_html_on_a_DISCRIMINATING_target_is_still_not_an_actuator(self):
        """ATTEINDRE le prédicat que la sonde catch-all masque — sinon on ne prouve rien de lui.

        Mesuré par mutation : restaurer la disjonction d'origine (`leaks or path.endswith(...)`) laisse
        `test_end_to_end_spa_produces_zero_vulnerable` VERT, parce que sur une cible catch-all la
        sonde de contrôle court-circuite la boucle actuator AVANT que le prédicat ne soit évalué. La
        garde catch-all masquait donc le défaut au lieu de le prouver corrigé.

        Ce cas modélise une cible qui DISCRIMINE ses routes (404 sur les contrôles et sur l'inconnu)
        mais rend 200 + HTML sur les chemins `/actuator/*` — une réécriture permissive, un proxy, une
        page d'erreur applicative servie en 200. La sonde de contrôle ne peut RIEN y faire : seule la
        PREUVE DE CORPS tient. C'est ce test qui TUE la mutation M1."""
        sensitive = ("/actuator/beans", "/actuator/heapdump", "/actuator/threaddump",
                     "/actuator/httptrace", "/beans", "/heapdump", "/threaddump", "/trace")

        def fake(url, headers=None, timeout=15):
            if "forge-catchall" in url:
                return (404, "")                            # la cible DISCRIMINE : contrôles refusés
            if url.endswith("/"):
                return (200, "<html>app</html>")
            if any(url.endswith(p) for p in sensitive):
                return (200, _KONG_SPA_HTML)                # 200 + HTML sur les chemins sensibles
            return (404, "")
        f = _fire(fake)
        self.assertEqual([x.title for x in f if x.status == "vulnerable"], [],
                         "8 chemins sensibles en HTTP 200 : sans PREUVE DE CORPS, zéro promotion")
        self.assertEqual(len(f), 1)
        self.assertIn("aucune surface de framework sensible", f[0].title)
        self.assertEqual(f[0].status, "tested", "la cible a bien été VÉRIFIÉE (elle discrimine)")

    def test_html_never_satisfies_the_threaddump_TEXT_signature(self):
        """La garde HTML est NON REDONDANTE exactement ici, et c'est ce test qui TUE la mutation M2.

        Pour les chemins JSON, `_looks_structured` (le corps commence par `{`/`[`) rend déjà une page
        HTML impossible. La branche TEXTE de `/threaddump` (dump jstack Boot 1.x), elle, n'exige
        AUCUNE structure — et `'\"main\" '` apparaît trivialement dans du JS embarqué dans une page.
        Sans `_is_html`, cette SPA passerait pour un dump de threads."""
        spa = '<!DOCTYPE html><html><body><script>var t={"main" : 1}</script></body></html>'
        self.assertIn('"main" ', spa.lower(), "l'ancre de la mutation est bien atteinte")
        self.assertFalse(expmod._actuator_leak("/threaddump", spa)[0])
        self.assertFalse(expmod._actuator_leak("/actuator/threaddump", spa)[0])
        # contre-épreuve : le VRAI dump jstack, lui, reste prouvé.
        self.assertTrue(expmod._actuator_leak("/threaddump", _REAL_THREADDUMP_TEXT)[0])


# =================================================================================================
class TestPathDiscriminationProbe(unittest.TestCase):
    """`Oracle.path_discrimination` — la contre-mesure GÉNÉRIQUE. Elle ne PROMEUT jamais."""

    def _disc(self, fake, target="app.test"):
        restore = _patch(FrameworkExposure, fake)
        try:
            return FrameworkExposure().path_discrimination(
                Action("framework.exposure", target, params={"in_scope": ["app.test"]}), target)
        finally:
            restore()

    def test_catchall_target_is_detected(self):
        d = self._disc(lambda url, headers=None, timeout=15: (200, _KONG_SPA_HTML))
        self.assertIs(d.verdict, False)
        self.assertTrue(d.catchall)
        self.assertTrue(d.same_body, "corps identiques entre les deux contrôles")
        self.assertEqual(len(d.probes), 2, "deux contrôles : borne anti-collision")
        self.assertIn("NE PEUVENT PAS exister", d.why())

    def test_discriminating_target_is_detected(self):
        d = self._disc(lambda url, headers=None, timeout=15: (404, "not found"))
        self.assertIs(d.verdict, True)
        self.assertFalse(d.catchall)

    def test_one_refusal_is_enough_to_conclude_discrimination(self):
        seq = iter([(200, "a"), (404, "")])
        d = self._disc(lambda url, headers=None, timeout=15: next(seq))
        self.assertIs(d.verdict, True, "un seul refus suffit : la cible discrimine")

    def test_silent_transport_is_indeterminate_never_catchall(self):
        d = self._disc(lambda url, headers=None, timeout=15: (None, ""))
        self.assertIsNone(d.verdict)
        self.assertFalse(d.catchall, "l'indéterminé n'est JAMAIS un catch-all")

    def test_partial_evidence_is_indeterminate(self):
        """Une seule sonde ayant répondu (2xx), l'autre muette : preuve PARTIELLE -> indéterminé.
        Borne anti-collision — on ne fabrique pas un `skipped` sur une cible saine."""
        seq = iter([(200, "a"), (None, "")])
        d = self._disc(lambda url, headers=None, timeout=15: next(seq))
        self.assertIsNone(d.verdict)
        self.assertFalse(d.catchall)

    def test_probe_paths_are_deterministic_and_improbable(self):
        a = Oracle.catchall_paths("https://app.test")
        b = Oracle.catchall_paths("https://app.test")
        self.assertEqual(a, b, "déterministe : rejouable par l'opérateur, stable en test")
        self.assertEqual(len(set(a)), 2, "deux chemins DISTINCTS")
        self.assertNotEqual(a, Oracle.catchall_paths("https://other.test"), "dérivé de l'origine")
        for p in a:
            self.assertTrue(p.startswith("/forge-catchall-"), p)
            self.assertGreaterEqual(len(p), 24, "assez long pour ne pas exister par hasard")

    def test_probe_is_scope_guarded_fail_closed(self):
        """Hôte hors périmètre -> AUCUNE requête et verdict INDÉTERMINÉ (jamais un catch-all déduit
        d'un refus de périmètre).

        ⚠️ CE TEST LEVAIT UNE AssertionError DEPUIS LE SEAM, et `_probe` — qui doit survivre à un seam
        hostile — l'avalait : la mutation « retirer le scope-guard de la sonde » restait VERTE. On
        ENREGISTRE donc les appels au lieu de lever : c'est l'ABSENCE de requête qu'on affirme."""
        seen = []

        def record(url, headers=None, timeout=15):
            seen.append(url)
            return (200, "x")
        restore = _patch(FrameworkExposure, record)
        try:
            d = FrameworkExposure().path_discrimination(
                Action("framework.exposure", "evil.example", params={"in_scope": ["app.test"]}),
                "evil.example")
        finally:
            restore()
        self.assertEqual(seen, [], "aucune requête ne doit partir hors périmètre (fail-closed)")
        self.assertIsNone(d.verdict)
        self.assertFalse(d.catchall)

    def test_probe_never_raises_on_hostile_seam(self):
        """Une sonde de contrôle qui casse ne doit JAMAIS faire tomber l'oracle qu'elle protège."""
        def hostile(*a, **k):
            raise RuntimeError("seam hostile")
        restore = _patch(FrameworkExposure, hostile)
        try:
            d = FrameworkExposure().path_discrimination(
                Action("framework.exposure", "app.test", params={"in_scope": ["app.test"]}), "app.test")
        finally:
            restore()
        self.assertIsNone(d.verdict)

    def test_origin_of_strips_path_and_query(self):
        self.assertEqual(Oracle._origin_of("https://app.test/a/b?c=1#d"), "https://app.test")
        self.assertEqual(Oracle._origin_of("app.test"), "https://app.test")
        self.assertEqual(Oracle._origin_of("http://app.test:8080/x"), "http://app.test:8080")

    def test_verdict_object_defaults_are_inert(self):
        d = PathDiscrimination()
        self.assertIsNone(d.verdict)
        self.assertFalse(d.catchall)
        self.assertIn("—", d.why())


# =================================================================================================
class TestExposureCatchall(unittest.TestCase):
    """Sur une cible catch-all, la découverte de chemin rend `skipped` — et ne sonde RIEN."""

    def test_catchall_yields_skipped_not_tested_nor_vulnerable(self):
        f = _fire(lambda url, headers=None, timeout=15: (200, _KONG_SPA_HTML))
        self.assertTrue(f)
        self.assertEqual(f[0].status, "skipped", [x.title for x in f])
        self.assertIn("catch-all", f[0].title)
        self.assertIn("NON VÉRIFIÉ", f[0].evidence)
        self.assertNotIn("tested", {x.status for x in f},
                         "« j'ai vérifié, rien trouvé » est FAUX ici : on n'a rien pu vérifier")

    def test_catchall_probes_no_guessed_path(self):
        """On n'émet pas 20 requêtes qu'on serait de toute façon incapable de juger."""
        seen = []

        def fake(url, headers=None, timeout=15):
            seen.append(url)
            return (200, _KONG_SPA_HTML)
        _fire(fake)
        guessed = [u for u in seen if "forge-catchall" not in u and not u.endswith("/")]
        self.assertEqual(guessed, [], f"chemins devinés sondés malgré le catch-all : {guessed}")

    def test_catchall_keeps_root_findings_which_guess_nothing(self):
        """Les constats de RACINE (Ignition/Next.js) ne devinent aucun chemin : ils restent rendus."""
        html = ('<html><head><script id="__NEXT_DATA__" type="application/json">'
                '{"runtimeConfig":{"apiSecret":"TOPSECRET-runtime-9z"},"props":{}}'
                '</script></head><body>hi</body></html>')
        f = _fire(lambda url, headers=None, timeout=15: (200, html))
        self.assertIn("skipped", {x.status for x in f})
        nx = [x for x in f if "Next.js" in x.title]
        self.assertTrue(nx, "la fuite de racine survit au catch-all")
        self.assertNotIn("TOPSECRET-runtime-9z", nx[0].evidence)


# =================================================================================================
class TestNoInverseExcess(unittest.TestCase):
    """L'EXCÈS INVERSE — une cible qui discrimine ne doit RIEN perdre. Comportement historique intact."""

    def _fake_clean(self, url, headers=None, timeout=15):
        if url.endswith("/"):
            return (200, "<html>plain site</html>")
        return (404, "")

    def test_clean_target_still_says_tested_not_skipped(self):
        f = _fire(self._fake_clean)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "tested", "une cible saine garde « j'ai vérifié, rien trouvé »")
        self.assertIn("aucune surface de framework sensible", f[0].title)

    def test_actuator_index_still_medium_tested(self):
        def fake(url, headers=None, timeout=15):
            if url.endswith("/actuator"):
                return (200, '{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"}}}')
            if url.endswith("/"):
                return (200, "<html>ok</html>")
            return (404, "")
        f = _fire(fake)
        self.assertTrue(all(x.status == "tested" for x in f), [(x.title, x.status) for x in f])
        self.assertIn("présente", " ".join(x.title for x in f))

    def test_html_page_containing_index_words_is_not_an_actuator_index(self):
        """Contre-épreuve du durcissement de la branche MEDIUM : une SPA dont le JS contient `"self"`
        ou `"health"` ne doit pas passer pour un index actuator (il faut du JSON)."""
        spa = '<!DOCTYPE html><html><body><script>var x={"self":1,"health":"ok"}</script></body></html>'

        def fake(url, headers=None, timeout=15):
            if url.endswith("/actuator"):
                return (200, spa)
            if url.endswith("/"):
                return (200, "<html>ok</html>")
            return (404, "")
        f = _fire(fake)
        self.assertEqual(len(f), 1)
        self.assertIn("aucune surface de framework sensible", f[0].title)

    def test_offline_still_degrades_on_network(self):
        f = _fire(lambda url, headers=None, timeout=15: (None, ""))
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("réseau indisponible", f[0].title)


if __name__ == "__main__":                                   # pragma: no cover
    unittest.main()
