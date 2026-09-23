# SPDX-License-Identifier: AGPL-3.0-or-later
"""LOT FILE UPLOAD — oracle de VÉRIFICATION `upload.unrestricted` (CWE-434).

POURQUOI CE MODULE EXISTE. `FileUpload` est mesurée à 50 % d'acceptation sur 2 077 rapports de
hacktivité réelle — l'une des cinq classes les mieux payées — et c'était la SEULE d'entre elles sans
aucun module. `coverage_gaps()` ne pouvait donc jamais signaler « upload jamais tenté ».

Contrat vérifié ici (calqué sur les oracles à preuve existants) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise (le seam
      `_fetch` monkeypatché LÈVE s'il est appelé) ;
  (2) PREUVE MINIMALE : promotion `vulnerable` UNIQUEMENT si le marqueur inerte est RESSERVI ; une
      fixture négative rend `tested` (jamais de verdict à l'aveugle) ;
  (3) CONTENU INERTE : le corps téléversé ne contient QUE le marqueur — aucun `<script>`, aucune
      balise PHP, aucun code. C'est ce qui distingue la vérification de la weaponization ;
  (4) VARIANTE TRAVERSAL GARDÉE : `../` peut écraser hors du dossier de dépôt -> capacité destructive,
      non tirée sans `action.destructive` (miroir du chemin write de `access_control.idor`) ;
  (5) ÉCHELLE DE PREUVE : Content-Type rendant -> HIGH ; extension dangereuse seule -> MEDIUM ;
  (6) SCOPE-GUARD SUR L'URL SERVIE : un fichier resservi depuis un hôte HORS périmètre ne promeut pas ;
  (7) DÉGRADATION GRACIEUSE : transport indisponible -> `skipped` (offline-safe) ;
  (8) MEMBERSHIP : mitre/cwe/cls dérivés de la table unique (`forge/techniques.py`).

Tests HERMÉTIQUES : `_fetch` (dépôt) et `Oracle._http` (relecture) sont monkeypatchés — zéro réseau.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from forge.roe import Action                                     # noqa: E402
from forge import modules as mods                                # noqa: E402
from forge import techniques                                     # noqa: E402
from forge.modules.oracle import Oracle, ScopeGuardedOracle      # noqa: E402
from forge.modules.upload import UnrestrictedUpload              # noqa: E402

MARK = "fg7c1e9d"
TGT = "https://app.test/api/upload"


def _patch(cls, name, fn):
    """Remplace cls.<name> par fn (staticmethod) et restaure PROPREMENT (delattr si hérité)."""
    had = name in cls.__dict__
    orig = cls.__dict__.get(name)
    setattr(cls, name, staticmethod(fn))

    def restore():
        if had:
            setattr(cls, name, orig)
        else:
            try:
                delattr(cls, name)
            except AttributeError:
                pass
    return restore


def _boom(*a, **k):
    raise AssertionError("réseau émis alors qu'aucun ne devait l'être (scope-guard / config)")


class _Bench:
    """Faux serveur d'upload : accepte les dépôts, mémorise ce qui a été envoyé, et ressert le
    fichier selon la politique passée (`serve_ctype`, `serve_url`, `serve` on/off)."""

    def __init__(self, serve=True, serve_ctype="application/octet-stream",
                 serve_url="https://app.test/uploads/{name}", accept=True):
        self.serve, self.ctype, self.serve_url, self.accept = serve, serve_ctype, serve_url, accept
        self.uploads = []          # (filename, corps envoyé)

    def fetch(self, url, headers=None, timeout=15, method="GET", data=None):
        body = (data or b"").decode("utf-8", "replace")
        fn = ""
        for line in body.split("\r\n"):
            if "filename=" in line:
                fn = line.split('filename="', 1)[1].rsplit('"', 1)[0]
        self.uploads.append((fn, body))
        if not self.accept:
            return (400, '{"error":"type not allowed"}')
        served = self.serve_url.replace("{name}", fn.lstrip("./"))
        return (200, '{"ok":true,"url":"%s"}' % served)

    def http(self, url, *, headers=None, timeout=15, method="GET", data=None,
             maxlen=200000, follow_redirects=False):
        if not self.serve:
            return (404, "", {})
        return (200, "forge benign upload marker -- no payload, no code -- %s\n" % MARK,
                {"Content-Type": self.ctype})


def _fire(bench, params=None, destructive=False):
    r1 = _patch(UnrestrictedUpload, "_fetch", bench.fetch)
    r2 = _patch(Oracle, "_http", bench.http)
    try:
        p = {"file_param": "file", "marker": MARK, "in_scope": ["app.test"]}
        if params:
            p.update(params)
        a = Action("upload.unrestricted", TGT, params=p)
        a.destructive = destructive
        return UnrestrictedUpload().fire(a)
    finally:
        r2(); r1()


# =================================================================================================
class TestUploadRegistration(unittest.TestCase):
    def test_registered_and_typed(self):
        self.assertIn("upload.unrestricted", mods.kinds())
        m = mods.get("upload.unrestricted")
        self.assertIsInstance(m, ScopeGuardedOracle)
        self.assertIsInstance(m, Oracle)

    def test_metadata_derives_from_single_table(self):
        m = mods.get("upload.unrestricted")
        self.assertEqual(m.mitre, techniques.mitre_for("upload.unrestricted"))
        self.assertEqual(m.cwe, techniques.cwe_for("upload.unrestricted"))
        self.assertEqual(m.cwe, "CWE-434")

    def test_class_token_is_the_checklist_token(self):
        # SANS cela, coverage_gaps() ne relierait PAS ce module à la classe "file_upload" et la
        # lacune resterait invisible — c'est très exactement le défaut que ce lot corrige.
        self.assertEqual(techniques.action_class("upload.unrestricted"), "file_upload")
        self.assertIn("file_upload", techniques.DEFAULT_CHECKLIST)
        self.assertIn("file_upload", techniques.qualifying_classes())

    def test_capabilities_are_declared_non_exploit_non_destructive(self):
        m = mods.get("upload.unrestricted")
        self.assertFalse(m.exploit)          # vérification de recevabilité, pas de weaponization
        self.assertFalse(m.destructive)      # le chemin traversal est gardé séparément
        self.assertTrue(m.web_allowed)


# =================================================================================================
class TestUploadGuards(unittest.TestCase):
    def test_out_of_scope_emits_no_network(self):
        r1 = _patch(UnrestrictedUpload, "_fetch", _boom)
        r2 = _patch(Oracle, "_http", _boom)
        try:
            a = Action("upload.unrestricted", "https://evil.test/up",
                       params={"file_param": "f", "marker": MARK, "in_scope": ["app.test"]})
            f = UnrestrictedUpload().fire(a)
        finally:
            r2(); r1()
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, "skipped")

    def test_missing_config_emits_no_network(self):
        r1 = _patch(UnrestrictedUpload, "_fetch", _boom)
        r2 = _patch(Oracle, "_http", _boom)
        try:
            f = UnrestrictedUpload().fire(
                Action("upload.unrestricted", TGT, params={"in_scope": ["app.test"]}))
        finally:
            r2(); r1()
        self.assertEqual(f[0].status, "skipped")
        self.assertIn("config manquante", f[0].title)

    def test_traversal_variant_is_gated_and_never_sent(self):
        b = _Bench()
        f = _fire(b, destructive=False)
        # (a) un finding explicite dit que la variante n'a pas été tirée
        gated = [x for x in f if "traversal" in x.title]
        self.assertTrue(gated, "la variante traversal doit être annoncée comme non tirée")
        self.assertEqual(gated[0].status, "skipped")
        # (b) et AUCUN dépôt ne porte `../` — le garde-fou est réel, pas déclaratif
        self.assertTrue(b.uploads, "des dépôts bénins auraient dû être émis")
        for fn, _body in b.uploads:
            self.assertNotIn("..", fn, f"nom de fichier traversal émis sans autorisation : {fn}")

    def test_traversal_variant_fires_when_ROE_authorises(self):
        b = _Bench(serve=False)
        _fire(b, destructive=True)
        self.assertTrue(any(".." in fn for fn, _ in b.uploads),
                        "autorisée, la variante traversal doit être tirée")

    def test_uploaded_content_is_inert(self):
        """(3) Le corps déposé ne contient AUCUN code — c'est la ligne rouge du module."""
        b = _Bench()
        _fire(b, destructive=True)
        self.assertTrue(b.uploads)
        for fn, body in b.uploads:
            low = body.lower()
            for forbidden in ("<script", "<?php", "<?=", "eval(", "system(", "passthru",
                              "shell_exec", "base64_decode", "onerror=", "onload="):
                self.assertNotIn(forbidden, low, f"charge active dans le dépôt {fn} : {forbidden}")
            self.assertIn(MARK, body, "le marqueur bénin doit être présent")


# =================================================================================================
class TestUploadProofScale(unittest.TestCase):
    def test_rendering_content_type_proves_HIGH(self):
        f = _fire(_Bench(serve=True, serve_ctype="text/html"))
        proof = [x for x in f if x.status in ("vulnerable", "tested")][0]
        self.assertEqual(proof.status, "vulnerable")
        self.assertEqual(proof.severity, "HIGH")
        self.assertIn("CONFIRMÉ", proof.title)

    def test_dangerous_extension_alone_proves_MEDIUM(self):
        f = _fire(_Bench(serve=True, serve_ctype="application/octet-stream"))
        proof = [x for x in f if x.status in ("vulnerable", "tested")][0]
        self.assertEqual(proof.status, "vulnerable")
        self.assertEqual(proof.severity, "MEDIUM")

    def test_not_served_back_is_tested_never_vulnerable(self):
        f = _fire(_Bench(serve=False))
        proof = [x for x in f if x.status in ("vulnerable", "tested")][0]
        self.assertEqual(proof.status, "tested")
        self.assertEqual(proof.severity, "INFO")

    def test_upload_refused_is_tested(self):
        f = _fire(_Bench(accept=False))
        proof = [x for x in f if x.status in ("vulnerable", "tested")][0]
        self.assertEqual(proof.status, "tested")

    def test_served_from_out_of_scope_host_does_not_promote(self):
        """(6) Un fichier resservi depuis un hôte HORS périmètre ne prouve rien d'in-scope."""
        b = _Bench(serve=True, serve_ctype="text/html",
                   serve_url="https://cdn.evil.test/uploads/{name}")
        f = _fire(b)
        proof = [x for x in f if x.status in ("vulnerable", "tested")][0]
        self.assertEqual(proof.status, "tested")

    def test_inert_served_type_and_safe_extension_does_not_promote(self):
        """Resservi mais ni type rendant ni extension dangereuse -> aucune preuve."""
        b = _Bench(serve=True, serve_ctype="text/plain",
                   serve_url="https://app.test/uploads/{name}.bin")
        f = _fire(b)
        proof = [x for x in f if x.status in ("vulnerable", "tested")][0]
        self.assertEqual(proof.status, "tested")

    def test_network_down_degrades_gracefully(self):
        def dead(*a, **k):
            return (None, "")
        r1 = _patch(UnrestrictedUpload, "_fetch", dead)
        try:
            a = Action("upload.unrestricted", TGT,
                       params={"file_param": "f", "marker": MARK, "in_scope": ["app.test"]})
            a.destructive = False
            f = UnrestrictedUpload().fire(a)
        finally:
            r1()
        self.assertTrue(any(x.status == "skipped" and "réseau indisponible" in x.title for x in f))

    def test_volume_is_bounded(self):
        """(5) On sonde, on n'inonde pas : le nombre de dépôts reste borné."""
        b = _Bench(serve=False)
        _fire(b, destructive=True)
        self.assertLessEqual(len(b.uploads), 9, "trop de dépôts émis")


if __name__ == "__main__":
    unittest.main()
