# SPDX-License-Identifier: AGPL-3.0-or-later
"""`web.nuclei` MUTUALISÉ PAR HÔTE — une invocation, N cibles, zéro garde contournée.

MESURE (campagne réelle, `gxrun2/ledger.jsonl`) : **65 tirs `web.nuclei` pour 10 noms d'hôte**.
nuclei recharge sa base de templates À CHAQUE invocation (mesuré sur le binaire réel,
`projectdiscovery/nuclei` v3.11.0, cibles mortes : 1 cible = 26,0 s · 5 cibles = 27,0 s · 20 cibles
= 23,7 s — le coût est FIXE, la cible marginale est dans le bruit). 55 des 65 invocations étaient
donc du rechargement de templates pur.

Ce fichier verrouille les QUATRE propriétés qui rendent le regroupement acceptable :

  1. le chemin UNE cible reste BYTE-IDENTIQUE (argv, findings, budget de timeout) ;
  2. la COUVERTURE PAR CIBLE est démontrable — chaque cible d'un lot ressort avec SON finding
     (hit, « aucun hit », échec, ou `skipped` NOMMÉ) ; jamais une troncature muette ;
  3. le SCOPE-GUARD s'applique CIBLE PAR CIBLE, et le lot est fail-closed sans périmètre injecté ;
  4. l'ÉPINGLAGE IP tient — un lot n'admet que des cibles du MÊME hôte que la tête gatée par le ROE.

Hermétique : aucun réseau, aucun binaire externe (`runner.tool` est doublé).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forge.modules import web as webmod                                        # noqa: E402
from forge.modules.web import (NucleiScan, attribute_hit, coalesce_nuclei, host_of,  # noqa: E402
                               norm_target, unsafe_batch_target)
from forge.roe import Action                                                   # noqa: E402

SCOPE = {"in_scope": ["*.test", "app.test"], "out_scope": ["evil.test"]}


def act(target, **params):
    return Action("web.nuclei", target, params=dict(params))


def scoped(target, targets=None, **params):
    """Action AVEC périmètre injecté (ce que fera le moteur) — le seul mode où un lot est accepté."""
    p = dict(SCOPE)
    if targets is not None:
        p["targets"] = list(targets)
    p.update(params)
    return Action("web.nuclei", target, params=p)


class _ToolDouble:
    """Double du binaire nuclei : enregistre chaque invocation, rend un JSONL scripté."""

    def __init__(self, rc=0, out="", err=""):
        self.rc, self.out, self.err = rc, out, err
        self.calls = []

    def __call__(self, *a, **k):
        self.calls.append({"args": list(a[2] if len(a) > 2 else k.get("args") or []),
                           "timeout": k.get("timeout")})
        return (self.rc, self.out, self.err)


class _Doubled(unittest.TestCase):
    def double(self, rc=0, out="", err=""):
        d = _ToolDouble(rc, out, err)
        orig = webmod.runner.tool
        webmod.runner.tool = d
        self.addCleanup(lambda: setattr(webmod.runner, "tool", orig))
        return d

    @staticmethod
    def targets_of(call):
        argv = call["args"]
        return argv[argv.index("-u") + 1].split(",")


# =====================================================================================================
#  1. LE CHEMIN UNE CIBLE NE BOUGE PAS
# =====================================================================================================
class TestSingleTargetUnchanged(_Doubled):

    def test_argv_identical_without_batch_param(self):
        argv = NucleiScan()._args(act("https://app.test"))
        self.assertEqual(argv[:2], ["-u", "https://app.test"], "l'argv une-cible a changé")

    def test_timeout_identical_without_batch_param(self):
        d = self.double(0, "")
        NucleiScan().fire(act("https://app.test"))
        self.assertEqual(d.calls[0]["timeout"], 600, "le budget d'un tir une-cible a changé")

    def test_no_hit_emits_exactly_one_finding(self):
        self.double(0, "")
        findings = NucleiScan().fire(act("https://app.test"))
        self.assertEqual([(f.title, f.target) for f in findings],
                         [("nuclei: aucun hit", "https://app.test")])


# =====================================================================================================
#  2. MUTUALISATION — une invocation par HÔTE
# =====================================================================================================
class TestCoalescing(unittest.TestCase):

    def test_one_action_per_host(self):
        actions = [act(t) for t in ("guatx.com", "https://guatx.com", "guatx.com:8443",
                                    "www.guatx.com", "http://www.guatx.com:80")]
        out = coalesce_nuclei(actions)
        self.assertEqual([a.target for a in out], ["guatx.com", "www.guatx.com"])
        self.assertEqual(out[0].params["targets"],
                         ["guatx.com", "https://guatx.com", "guatx.com:8443"])
        self.assertEqual(out[1].params["targets"], ["www.guatx.com", "http://www.guatx.com:80"])

    def test_head_keeps_its_action_id_and_position(self):
        first = act("zzz.test")                       # tête du groupe : garde sa place dans l'ordre EV
        actions = [first, Action("recon.httpx", "aaa.test"), act("https://zzz.test")]
        out = coalesce_nuclei(actions)
        self.assertEqual([a.kind for a in out], ["web.nuclei", "recon.httpx"])
        self.assertIs(out[0], first)
        self.assertEqual(first.id, "web.nuclei:zzz.test")

    def test_other_kinds_are_untouched_and_ordered(self):
        others = [Action("recon.httpx", "a.test"), Action("cors.credentials", "b.test")]
        out = coalesce_nuclei([others[0], act("h.test"), others[1], act("https://h.test")])
        self.assertEqual([a.kind for a in out], ["recon.httpx", "web.nuclei", "cors.credentials"])
        self.assertIs(out[0], others[0])
        self.assertIs(out[2], others[1])

    def test_max_batch_caps_a_group(self):
        actions = [act(f"https://h.test/{i}") for i in range(60)]
        out = coalesce_nuclei(actions, max_batch=25)
        self.assertEqual(len(out), 3, "un hôte à 60 URLs doit redonner ceil(60/25) actions")
        self.assertEqual([len(a.params["targets"]) for a in out], [25, 25, 10])
        self.assertEqual(len({a.id for a in out}), 3, "les têtes de tranche doivent avoir des id distincts")

    def test_unparsable_host_is_never_folded(self):
        bad = act("")
        out = coalesce_nuclei([act("h.test"), bad, act("https://h.test")])
        self.assertIn(bad, out)
        self.assertEqual(len(out), 2)

    def test_action_already_batched_is_left_alone(self):
        pre = act("h.test", targets=["h.test", "https://h.test"])
        out = coalesce_nuclei([pre, act("https://h.test:8443")])
        self.assertEqual(len(out), 2, "une action déjà porteuse d'un lot ne doit pas être re-fusionnée")
        self.assertEqual(pre.params["targets"], ["h.test", "https://h.test"])

    def test_argv_carries_the_whole_batch(self):
        a = scoped("app.test", ["app.test", "https://app.test", "app.test:8443"])
        argv = NucleiScan()._args(a, NucleiScan()._batch(a)[0])
        self.assertEqual(argv[:2], ["-u", "app.test,https://app.test,app.test:8443"])

    def test_real_campaign_corpus_65_targets_10_invocations(self):
        """Corpus RÉEL (les 65 cibles `web.nuclei` de gxrun2) : 65 invocations -> 10."""
        real = _REAL_CAMPAIGN_TARGETS
        self.assertEqual(len(real), 65)
        out = coalesce_nuclei([act(t) for t in real], max_batch=100)
        self.assertEqual(len(out), 10)
        self.assertEqual(sum(len(a.params.get("targets", [a.target])) for a in out), 65,
                         "une cible a disparu du regroupement")


# =====================================================================================================
#  3. SCOPE-GUARD PAR CIBLE — grouper ne contourne RIEN
# =====================================================================================================
class TestScopeGuardPerTarget(_Doubled):

    def test_out_of_scope_member_never_reaches_argv(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", "evil.test"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"])

    def test_out_of_scope_member_is_named_not_silent(self):
        self.double(0, "")
        findings = NucleiScan().fire(scoped("app.test", ["app.test", "evil.test"]))
        named = [f for f in findings if f.target == "evil.test"]
        self.assertEqual(len(named), 1, "la cible écartée doit ressortir NOMMÉE")
        self.assertEqual(named[0].status, "skipped")
        self.assertIn("hors périmètre", named[0].title)

    def test_batch_is_fail_closed_without_injected_scope(self):
        """Sans périmètre injecté, `_scope` serait PERMISSIF : le lot entier doit être refusé."""
        d = self.double(0, "")
        NucleiScan().fire(act("app.test", targets=["app.test", "anything.test"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"],
                         "un lot sans périmètre injecté a été scanné -> scope-guard contournable")

    def test_fail_closed_batch_names_every_dropped_target(self):
        self.double(0, "")
        findings = NucleiScan().fire(act("app.test", targets=["app.test", "anything.test"]))
        dropped = [f for f in findings if f.target == "anything.test"]
        self.assertEqual(len(dropped), 1)
        self.assertEqual(dropped[0].status, "skipped")
        self.assertIn("aucun périmètre injecté", dropped[0].title)

    # `https://app.test/a,b` est IN-SCOPE et du BON hôte : ni le scope-guard ni le contrôle
    # d'épinglage ne l'arrêtent. SEUL le refus de la virgule empêche `-u` de fabriquer la cible
    # fantôme `b` — non gardée, jamais résolue, jamais épinglée. C'est le cas où ce garde PORTE.
    COMMA_URL = "https://app.test/a,b"

    def test_comma_target_cannot_smuggle_a_phantom_target(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", self.COMMA_URL]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"],
                         "une virgule a fabriqué une cible fantôme dans `-u a,b`")

    def test_comma_target_rejection_is_named(self):
        self.double(0, "")
        findings = NucleiScan().fire(scoped("app.test", ["app.test", self.COMMA_URL]))
        named = [f for f in findings if f.target == self.COMMA_URL]
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0].status, "skipped")

    def test_head_target_starting_with_dash_is_refused_before_any_process(self):
        """Garde historique de la TÊTE (option smuggling) — aucun processus ne doit être lancé."""
        d = self.double(0, "")
        findings = NucleiScan().fire(act("-oN/tmp/pwn"))
        self.assertEqual(d.calls, [], "un processus a été lancé sur une cible en '-'")
        self.assertEqual(findings[0].status, "skipped")

    def test_leading_dash_member_is_refused(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", "-oN/tmp/pwn"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"])

    def test_whitespace_member_is_refused(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", "app.test /x"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"])

    def test_unsafe_batch_target_is_pinned_as_a_unit(self):
        """La fonction de garde elle-même, indépendamment de l'ordre des portes de `_batch`."""
        for bad in ("", "  ", " app.test", "-oN", "a,b", "a b", "a\tb", "a\x00b"):
            self.assertIsNotNone(unsafe_batch_target(bad), repr(bad))
        for ok in ("app.test", "https://app.test:8443/x", "1.2.3.4:8080"):
            self.assertIsNone(unsafe_batch_target(ok), repr(ok))

    def test_head_is_always_scanned_even_if_batch_is_fully_refused(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", "evil.test", "-oN"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"])


# =====================================================================================================
#  4. ÉPINGLAGE IP — un lot ne mélange jamais deux hôtes
# =====================================================================================================
class TestPinInvariant(_Doubled):

    def test_foreign_host_member_never_reaches_argv(self):
        """Le moteur n'épingle QUE `action.target` : une cible d'un AUTRE hôte se connecterait à une
        IP NON épinglée (fenêtre de rebinding)."""
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", "other.test"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test"])

    def test_foreign_host_rejection_names_the_pin(self):
        self.double(0, "")
        findings = NucleiScan().fire(scoped("app.test", ["app.test", "other.test"]))
        named = [f for f in findings if f.target == "other.test"]
        self.assertEqual(len(named), 1)
        self.assertIn("épinglé", named[0].title)

    def test_same_host_variants_are_accepted(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", ["app.test", "https://app.test/", "app.test:8443"]))
        self.assertEqual(self.targets_of(d.calls[0]), ["app.test", "https://app.test/", "app.test:8443"])

    def test_coalescer_never_groups_two_hosts(self):
        out = coalesce_nuclei([act("a.test"), act("b.test"), act("https://a.test")])
        for a in out:
            hosts = {host_of(t) for t in a.params.get("targets", [a.target])}
            self.assertEqual(len(hosts), 1, f"lot multi-hôtes: {hosts}")


# =====================================================================================================
#  5. COUVERTURE PAR CIBLE — rien ne disparaît dans un lot
# =====================================================================================================
class TestCoveragePerTarget(_Doubled):

    # Forme RÉELLE d'un groupe de la campagne (le run avait bel et bien `guatx.com` ET
    # `https://guatx.com` comme deux cibles distinctes du même hôte).
    BATCH = ["app.test", "https://app.test", "app.test:8443", "http://app.test:8080"]
    HIT = ('{"template-id":"t","matched-at":"https://app.test/x",'
           '"info":{"name":"X","severity":"info"}}')

    def test_every_batched_target_is_accounted_for(self):
        """PARTITION : chaque cible du lot est SOIT porteuse d'un hit (par sa surface normalisée),
        SOIT porteuse de SON « aucun hit ». Jamais ni l'un ni l'autre."""
        self.double(0, self.HIT)
        findings = NucleiScan().fire(scoped("app.test", self.BATCH))
        hit_surfaces = {norm_target(f.target) for f in findings if f.title.startswith("nuclei: X")}
        no_hit = [f.target for f in findings if f.title == "nuclei: aucun hit"]
        for t in self.BATCH:
            covered = any(norm_target(t) == s or s.startswith(norm_target(t) + "/") for s in hit_surfaces)
            self.assertTrue(covered ^ (no_hit.count(t) == 1),
                            f"cible {t}: ni hit ni « aucun hit » (ou les deux) -> couverture perdue")

    def test_no_target_gets_a_lying_no_hit_line(self):
        """`app.test` et `https://app.test` sont LA MÊME surface : un hit sur l'une ne doit pas
        laisser l'autre déclarer « aucun hit »."""
        self.double(0, self.HIT)
        findings = NucleiScan().fire(scoped("app.test", self.BATCH))
        no_hit = [f.target for f in findings if f.title == "nuclei: aucun hit"]
        self.assertEqual(sorted(no_hit), ["app.test:8443", "http://app.test:8080"])

    def test_tool_failure_fans_out_to_every_batched_target(self):
        self.double(127, "", "indisponible")
        findings = NucleiScan().fire(scoped("app.test", self.BATCH))
        failed = {f.target for f in findings if "indisponible" in f.title}
        self.assertEqual(failed, set(self.BATCH),
                         "un tir raté doit être visible pour CHAQUE cible du lot")

    def test_timeout_budget_scales_with_batch_size(self):
        d = self.double(0, "")
        NucleiScan().fire(scoped("app.test", self.BATCH))
        self.assertEqual(d.calls[0]["timeout"], 600 + 120 * 3,
                         "un lot avec le budget d'UNE cible échangerait des tirs contre des timeouts")

    def test_poc_is_the_batched_command(self):
        self.double(0, "")
        findings = NucleiScan().fire(scoped("app.test", self.BATCH))
        self.assertIn(",".join(self.BATCH), findings[0].poc, "le PoC doit être rejouable tel quel")


# =====================================================================================================
#  6. ATTRIBUTION D'UN HIT À SA CIBLE D'ENTRÉE
# =====================================================================================================
class TestAttribution(unittest.TestCase):

    def test_exact_match(self):
        self.assertEqual(attribute_hit("guatx.com", ["guatx.com", "www.guatx.com"]), "guatx.com")

    def test_path_boundary(self):
        self.assertEqual(attribute_hit("https://guatx.com:8443/robots.txt",
                                       ["guatx.com", "https://guatx.com:8443"]),
                         "https://guatx.com:8443")

    def test_port_boundary(self):
        self.assertEqual(attribute_hit("guatx.com:443", ["guatx.com"]), "guatx.com")

    def test_longest_prefix_wins(self):
        self.assertEqual(attribute_hit("https://guatx.com:8443/x",
                                       ["guatx.com", "guatx.com:8443", "https://guatx.com:8443"]),
                         "guatx.com:8443")

    def test_no_bare_text_prefix_match(self):
        self.assertIsNone(attribute_hit("guatx.community/x", ["guatx.com"]),
                          "un préfixe de TEXTE nu ne doit jamais attribuer un hit au mauvais hôte")

    def test_scheme_is_ignored(self):
        self.assertEqual(attribute_hit("http://app.test/x", ["https://app.test"]), "https://app.test")

    def test_unattributable_hit_returns_none(self):
        self.assertIsNone(attribute_hit("https://elsewhere.test/x", ["app.test"]))

    def test_unattributable_hit_still_produces_its_finding(self):
        """Un hit non attribuable ne fait perdre AUCUN finding : il reste porté par son `matched-at`."""
        orig = webmod.runner.tool
        webmod.runner.tool = lambda *a, **k: (0, '{"template-id":"t","matched-at":"weird://x",'
                                                '"info":{"name":"W","severity":"high"}}', "")
        self.addCleanup(lambda: setattr(webmod.runner, "tool", orig))
        findings = NucleiScan().fire(scoped("app.test", ["app.test", "https://app.test"]))
        self.assertIn("weird://x", [f.target for f in findings])
        self.assertEqual([f.title for f in findings].count("nuclei: aucun hit"), 2,
                         "on sous-déclare (2 « aucun hit »), on ne perd jamais le hit")


class TestCoverageEquivalenceOnRealCorpus(_Doubled):
    """CONTREFACTUEL sur le corpus RÉEL : 65 tirs un-par-URL vs 10 tirs groupés, MÊME nuclei doublé.
    Les SURFACES couvertes doivent être IDENTIQUES — sinon le gain de temps est payé en trous."""

    def scripted(self):
        """Double dont la sortie DÉPEND des cibles reçues (un hit sur les URLs finissant par '/')."""
        calls = []

        def tool(*a, **k):
            argv = list(a[2] if len(a) > 2 else k.get("args") or [])
            targets = argv[argv.index("-u") + 1].split(",")
            calls.append(targets)
            hits = [f'{{"template-id":"robots","matched-at":"{t}robots.txt",'
                    f'"info":{{"name":"robots","severity":"info"}}}}'
                    for t in targets if t.endswith("/")]
            return (0, "\n".join(hits), "")

        orig = webmod.runner.tool
        webmod.runner.tool = tool
        self.addCleanup(lambda: setattr(webmod.runner, "tool", orig))
        return calls

    @staticmethod
    def surfaces(findings):
        return {norm_target(f.target) for f in findings}

    @classmethod
    def covered(cls, findings, urls):
        """URLs COUVERTES par un jeu de findings — une URL est couverte si un finding porte SA
        surface ou une surface qui en DESCEND (`…/robots.txt` couvre `…/`). C'est la notion que
        `report_view` exploite (le finding cite l'endroit exact), pas l'égalité de chaînes."""
        surf = cls.surfaces(findings)
        return {u for u in urls
                if any(s == norm_target(u) or s.startswith(norm_target(u) + "/")
                       or s.startswith(norm_target(u) + ":") for s in surf)}

    @staticmethod
    def scope_all(target, targets=None):
        p = {"in_scope": ["*.com"], "out_scope": []}
        if targets:
            p["targets"] = list(targets)
        return Action("web.nuclei", target, params=p)

    def _fire_all(self, actions):
        mod = NucleiScan()
        return [f for a in actions for f in mod.fire(a)]

    def test_invocations_65_to_10(self):
        calls = self.scripted()
        self._fire_all([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS])
        before = len(calls)
        calls.clear()
        self._fire_all(coalesce_nuclei([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS],
                                       max_batch=100))
        self.assertEqual((before, len(calls)), (65, 10))

    def test_url_coverage_is_identical_before_and_after(self):
        """LE contrefactuel : les 65 URLs couvertes avant le sont TOUTES après — et réciproquement."""
        calls = self.scripted()
        f_before = self._fire_all([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS])
        f_after = self._fire_all(coalesce_nuclei([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS],
                                                 max_batch=100))
        self.assertEqual(self.covered(f_before, _REAL_CAMPAIGN_TARGETS), set(_REAL_CAMPAIGN_TARGETS))
        self.assertEqual(self.covered(f_after, _REAL_CAMPAIGN_TARGETS),
                         self.covered(f_before, _REAL_CAMPAIGN_TARGETS),
                         "une URL couverte avant ne l'est plus après regroupement")
        self.assertEqual(len(calls), 75)                # 65 + 10, les deux passes

    def test_named_behaviour_change_redundant_no_hit_lines_collapse(self):
        """RUPTURE NOMMÉE : `guatx.com` + `https://guatx.com` + `https://guatx.com/` sont LA MÊME
        surface. Un-par-URL en émettait 2 lignes « aucun hit » redondantes en plus du hit ; groupé,
        le hit les couvre. MOINS de lignes, PAS moins de couverture (cf. le test ci-dessus)."""
        self.scripted()
        f_before = self._fire_all([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS])
        f_after = self._fire_all(coalesce_nuclei([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS],
                                                 max_batch=100))
        self.assertEqual((len(f_before), len(f_after)), (65, 53))

    def test_every_real_url_is_still_covered_after_grouping(self):
        self.scripted()
        findings = self._fire_all(coalesce_nuclei(
            [self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS], max_batch=100))
        surfaces = self.surfaces(findings)
        for u in _REAL_CAMPAIGN_TARGETS:
            n = norm_target(u)
            self.assertTrue(any(s == n or s.startswith(n + "/") or s.startswith(n + ":")
                                for s in surfaces), f"URL {u} non couverte après regroupement")

    def test_grouping_never_mixes_two_hosts_on_the_real_corpus(self):
        calls = self.scripted()
        self._fire_all(coalesce_nuclei([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS],
                                       max_batch=100))
        for batch in calls:
            self.assertEqual(len({host_of(t) for t in batch}), 1, f"lot multi-hôtes: {batch}")

    def test_no_target_is_dropped_on_the_real_corpus(self):
        calls = self.scripted()
        self._fire_all(coalesce_nuclei([self.scope_all(u) for u in _REAL_CAMPAIGN_TARGETS],
                                       max_batch=100))
        self.assertEqual(sorted(t for b in calls for t in b), sorted(_REAL_CAMPAIGN_TARGETS))


class TestHostOf(unittest.TestCase):

    def test_variants_share_one_host(self):
        for t in ("guatx.com", "https://guatx.com", "guatx.com:8443", "http://guatx.com:80/x"):
            self.assertEqual(host_of(t), "guatx.com", t)

    def test_case_insensitive(self):
        self.assertEqual(host_of("HTTPS://GuatX.COM"), "guatx.com")

    def test_unparsable_returns_none(self):
        for t in ("", None, "   "):
            self.assertIsNone(host_of(t))


#: les 65 cibles `web.nuclei` RÉELLEMENT tirées par la campagne gxrun2 (extraites du ledger signé,
#: verdicts FIRE, ordre d'apparition). Corpus de la mesure avant/après — pas un corpus inventé.
_REAL_CAMPAIGN_TARGETS = [
    "guatx.com", "www.guatx.com", "https://guatx.com", "guatx.com:443", "www.guatx.com:443",
    "https://www.guatx.com", "guatx.com:8080", "guatx.com:8443", "guatx.com:80", "http://guatx.com",
    "https://guatx.com/", "imap.guatx.com", "mail.guatx.com", "pop3.guatx.com", "smtp.guatx.com",
    "webmail.guatx.com", "auth.guatx.com", "www.guatx.com:8443", "www.guatx.com:8080",
    "www.guatx.com:80", "http://www.guatx.com", "https://www.guatx.com/",
    "https://guatx.com/favicon.ico", "https://www.guatx.com/favicon.ico", "http://guatx.com:8080",
    "mail._domainkey.guatx.com", "_dmarc.guatx.com", "https://guatx.com:8443", "http://guatx.com:80",
    "mail.guatx.com:143", "mail.guatx.com:22", "http://webmail.guatx.com", "webmail.guatx.com:443",
    "https://webmail.guatx.com/", "https://auth.guatx.com", "https://www.guatx.com:8443",
    "http://www.guatx.com:8080", "http://www.guatx.com:80", "https://guatx.com:443",
    "https://www.guatx.com:443", "https://guatx.com:8080", "https://guatx.com:80",
    "https://imap.guatx.com", "https://mail.guatx.com", "https://pop3.guatx.com",
    "https://smtp.guatx.com", "https://webmail.guatx.com", "https://www.guatx.com:8080",
    "https://www.guatx.com:80", "http://guatx.com:443", "http://www.guatx.com:443",
    "http://imap.guatx.com", "http://mail.guatx.com", "http://pop3.guatx.com", "mail.guatx.com:993",
    "http://smtp.guatx.com", "webmail.guatx.com:80", "auth.guatx.com:8080", "auth.guatx.com:8443",
    "auth.guatx.com:80", "auth.guatx.com:443", "http://auth.guatx.com", "https://auth.guatx.com/",
    "http://guatx.com:8443", "http://www.guatx.com:8443",
]


if __name__ == "__main__":
    unittest.main()
