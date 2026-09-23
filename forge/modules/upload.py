# SPDX-License-Identifier: AGPL-3.0-or-later
"""upload.unrestricted — oracle FILE UPLOAD dangereux à PREUVE BÉNIGNE (T1190 / CWE-434).

POURQUOI CE MODULE EXISTE
-------------------------
`FileUpload` est mesurée à **50 % d'acceptation** sur 2 077 rapports de hacktivité réelle — l'une des
cinq classes les mieux payées du marché — et c'était la SEULE d'entre elles sans aucun module dans le
moteur. Un `coverage_gaps()` ne pouvait donc jamais signaler « upload jamais tenté ».

CE QU'IL PROUVE, ET CE QU'IL NE FAIT PAS
----------------------------------------
Il prouve que l'application **accepte puis ressert** un fichier dont l'extension ou le type MIME
auraient dû être rejetés. Le fichier téléversé est **INERTE** : son corps ne contient qu'un marqueur
textuel unique de l'opérateur. **Aucun webshell, aucun script, aucune charge n'est jamais construit
ni téléversé** — le module vérifie la *recevabilité* du fichier, jamais son exécution.

  PREUVE = le marqueur bénin revient sur une URL servie, ET le fichier a conservé une extension
  dangereuse OU est servi avec un Content-Type qui rendrait/exécuterait le contenu.

C'est la distinction qui compte pour le triage : « le filtre d'extension se contourne » est un fait
démontrable sans jamais déposer de code exécutable.

ÉCHELLE DE PREUVE (le statut n'est jamais posé à l'aveugle)
-----------------------------------------------------------
  HIGH   : marqueur resservi ET Content-Type rendant/exécutant (text/html, image/svg+xml, …)
           -> le contournement débouche sur une exécution dans le navigateur d'un autre user.
  MEDIUM : marqueur resservi ET extension dangereuse préservée dans l'URL, mais servi en type inerte
           (application/octet-stream, text/plain) -> le filtre est contourné, l'impact reste à établir.
  tested : pas de marqueur resservi -> AUCUNE promotion (contrat `Oracle.proof`).

GARDE-FOUS (tous prouvés par les tests)
---------------------------------------
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise ;
  (2) PREUVE MINIMALE & BÉNIGNE : promotion UNIQUEMENT si le marqueur inerte est resservi ;
  (3) CONTENU INERTE : le corps téléversé est un marqueur texte ; le SVG est sans `<script>` ;
  (4) ⚠️ VARIANTE TRAVERSAL GARDÉE : un nom de fichier `../` peut ÉCRASER un fichier hors du dossier
      de dépôt. C'est destructif -> elle exige `action.destructive` (ROE `allow_destructive`), exactement
      comme le chemin write de `access_control.idor`. Sans autorisation : non tirée, finding INFO ;
  (5) VOLUME BORNÉ : au plus `_MAX_VARIANTS` dépôts, chacun un fichier de quelques dizaines d'octets,
      tous nommés `forge-<marqueur>` pour être identifiables et supprimables par le propriétaire ;
  (6) SESSION SECRÈTE : matériel d'auth gouverné fusionné par `Oracle._http` sur URL in-scope ;
  (7) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe).

Bâti sur `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP + curl partagés).
"""
import re
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques

# Nombre maximal de dépôts émis en une passe (garde-fou de VOLUME : on sonde, on n'inonde pas).
_MAX_VARIANTS = 8

# Corps INERTE téléversé. Aucun code, aucune balise exécutable — juste le marqueur de l'opérateur.
_INERT_BODY = "forge benign upload marker -- no payload, no code -- {marker}\n"
# Variante SVG : structurellement un SVG valide pour passer un contrôle de contenu, SANS <script>.
_INERT_SVG = ('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
              '<title>{marker}</title></svg>\n')

# Content-Types qui RENDENT ou EXÉCUTENT le contenu servi -> la preuve monte en HIGH.
_RENDERING_TYPES = ("text/html", "application/xhtml+xml", "image/svg+xml",
                    "application/x-httpd-php", "text/xml", "application/xml")

# Extensions dangereuses — comparées à l'extension FINALE de l'URL servie (cf. _final_ext).
_DANGEROUS_EXT = (".php", ".phtml", ".php5", ".phar", ".jsp", ".jspx", ".asp", ".aspx",
                  ".cer", ".shtml", ".svg", ".html", ".htm", ".xhtml")

# VARIANTES DE CONTOURNEMENT : (libellé, gabarit de nom, MIME déclaré, corps).
# Chaque entrée cible UNE faiblesse de filtre documentée. Le contenu reste inerte dans tous les cas.
_VARIANTS = [
    ("extension dangereuse nue",      "forge-{m}.php",          "application/x-php",   "text"),
    ("MIME menteur (php en jpeg)",    "forge-{m}.php",          "image/jpeg",          "text"),
    ("double extension (jpg.php)",    "forge-{m}.jpg.php",      "image/jpeg",          "text"),
    ("double extension (php.jpg)",    "forge-{m}.php.jpg",      "image/jpeg",          "text"),
    ("casse mixte",                   "forge-{m}.pHp",          "image/jpeg",          "text"),
    ("point final (contourne rtrim)", "forge-{m}.php.",         "image/jpeg",          "text"),
    ("SVG inerte (vecteur XSS)",      "forge-{m}.svg",          "image/svg+xml",       "svg"),
    ("HTML inerte (vecteur XSS)",     "forge-{m}.html",         "text/html",           "text"),
]

# Variante DESTRUCTIVE, tirée UNIQUEMENT si le ROE l'autorise (cf. garde-fou (4)).
_TRAVERSAL_VARIANT = ("traversal dans le nom (écrase hors dossier)",
                      "../forge-{m}.php", "image/jpeg", "text")


def _multipart(field, filename, mime, body):
    """Corps multipart/form-data (bytes) + son Content-Type. stdlib pure, aucune dépendance.

    Le nom de fichier est inséré TEL QUEL : c'est précisément l'objet du test (point final, octet nul,
    traversal). On n'échappe donc PAS `filename`, mais on le borne au jeu d'octets latin-1 pour ne
    jamais émettre d'en-tête invalide."""
    boundary = "----forgeUploadOracle"
    fn = str(filename)
    parts = [
        f"--{boundary}\r\n",
        f'Content-Disposition: form-data; name="{field}"; filename="{fn}"\r\n',
        f"Content-Type: {mime}\r\n\r\n",
        body,
        f"\r\n--{boundary}--\r\n",
    ]
    return "".join(parts).encode("utf-8", "replace"), f"multipart/form-data; boundary={boundary}"


def _final_ext(url):
    """Extension FINALE du chemin d'une URL, en minuscules ('' si aucune). Ne lève jamais.

    ⚠️ POURQUOI PAS UNE RECHERCHE EN SOUS-CHAÎNE. Un premier jet cherchait `".php" in url` : un
    fichier servi en `forge-x.php.bin` était alors promu « extension dangereuse préservée » alors
    que son extension effective est `.bin` et qu'il ne s'exécutera jamais. C'est la fabrique à
    faux positif — et donc à rapport informatif. Seule la DERNIÈRE extension décide."""
    try:
        path = urllib.parse.urlsplit(str(url)).path
    except Exception:            # noqa: BLE001
        path = str(url)
    name = path.rsplit("/", 1)[-1]
    return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


def _extract_url(base, body, needle):
    """URL servie devinée depuis la réponse de dépôt : première URL/chemin contenant `needle`.

    Beaucoup d'API renvoient le chemin de stockage (JSON `{"url": "..."}`, HTML `<img src=...>`).
    On cherche donc le marqueur DANS la réponse plutôt que d'exiger un gabarit. Ne lève jamais."""
    if not body or not needle:
        return None
    for m in re.finditer(r'["\'(\s]((?:https?://|/)[^"\'\s)<>]*' + re.escape(needle) + r'[^"\'\s)<>]*)', body):
        cand = m.group(1)
        return cand if cand.startswith("http") else urllib.parse.urljoin(base, cand)
    return None


@register("upload.unrestricted")
class UnrestrictedUpload(ScopeGuardedOracle):
    kind = "upload.unrestricted"
    exploit = False                      # VÉRIFICATION de recevabilité (fichier inerte) -> non-exploit
    destructive = False                  # dépôt d'un fichier inerte ; la variante traversal est GARDÉE
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("upload.unrestricted")
    cwe = "CWE-434"
    tool = "forge/modules/upload.py:upload.unrestricted"
    fix = ("Valider le type de fichier côté serveur par ALLOWLIST d'extensions ET par inspection du "
           "contenu (magic bytes), jamais par le Content-Type déclaré ni par la seule extension. "
           "Normaliser le nom (rejeter `..`, l'octet nul, les points/espaces finaux) ou le remplacer "
           "par un identifiant généré. Servir les fichiers déposés depuis un domaine distinct sans "
           "cookies, avec `Content-Disposition: attachment` et `X-Content-Type-Options: nosniff`, et "
           "les stocker hors de la racine web sans droit d'exécution (CWE-434).")
    description = ("Oracle FILE UPLOAD à PREUVE BÉNIGNE : téléverse un fichier INERTE (marqueur texte, "
                   "aucun code) sous des noms qui contournent les filtres d'extension/MIME ; PREUVE = le "
                   "marqueur est RESSERVI, avec extension dangereuse préservée ou Content-Type rendant. "
                   "Aucun webshell n'est jamais construit. Sinon tested. CWE-434.")

    def dry(self, action):
        field = action.params.get("file_param", "<champ_fichier>")
        return (f"# téléverse des fichiers INERTES (marqueur texte, aucun code) sur {action.target} "
                f"via le champ `{field}`, sous {len(_VARIANTS)} noms contournant les filtres "
                f"(double extension, MIME menteur, casse, point final, SVG/HTML) ; PREUVE = le marqueur "
                f"est resservi avec extension dangereuse ou Content-Type rendant ; sinon tested")

    def _upload(self, action, headers, field, filename, mime, body):
        """Émet UN dépôt. Renvoie (status, corps_de_reponse)."""
        data, ctype = _multipart(field, filename, mime, body)
        h = dict(headers)
        h["Content-Type"] = ctype
        return self._fetch(action.target, headers=h, method="POST", data=data)

    def _serve_check(self, url, headers):
        """GET sur l'URL servie -> (status, corps, content_type). Aucune promotion sans ce tir."""
        st, body, resp_h = Oracle._http(url, headers=dict(headers), method="GET", maxlen=self.MAXLEN)
        ctype = ""
        try:
            ctype = (resp_h.get("Content-Type") or "").lower() if resp_h is not None else ""
        except Exception:            # noqa: BLE001
            ctype = ""
        return st, body, ctype

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]

        field = action.params.get("file_param")
        marker = action.params.get("marker")
        if not field or not marker:
            return [self.skip(
                target=action.target, title="Upload non testé — config manquante",
                evidence=("Requiert params.file_param (nom du champ fichier du formulaire) et "
                          "params.marker (marqueur bénin unique). Optionnel : params.fetch_url_template "
                          "(gabarit {name} de l'URL servie), params.headers, params.fields (champs "
                          "additionnels du formulaire)."),
                poc=self.dry(action))]

        headers = dict(action.params.get("headers", {}))
        template = action.params.get("fetch_url_template")
        findings = []

        variants = list(_VARIANTS)[:_MAX_VARIANTS]
        # (4) VARIANTE TRAVERSAL — écrasement possible hors dossier de dépôt : capacité DESTRUCTIVE.
        # Le module ne s'auto-élargit jamais une capacité non gardée (miroir du chemin write de l'IDOR).
        if getattr(action, "destructive", False):
            variants.append(_TRAVERSAL_VARIANT)
        else:
            findings.append(self.skip(
                target=action.target,
                title="Upload — variante traversal non tirée (capacité destructive non autorisée)",
                evidence=("Un nom de fichier `../` peut ÉCRASER un fichier hors du dossier de dépôt "
                          "(destructif). Requiert allow_destructive dans le ROE + action.destructive=True. "
                          "Aucun dépôt traversal émis (fail-closed)."),
                poc="# variante gardée : ../forge-<marqueur>.php"))

        best = None                       # (severite, libelle, nom, url, ctype)
        seen_network = False
        for label, name_tmpl, mime, kind in variants:
            filename = name_tmpl.format(m=marker)
            body = (_INERT_SVG if kind == "svg" else _INERT_BODY).format(marker=marker)
            st, resp = self._upload(action, headers, field, filename, mime, body)
            if st is not None:
                seen_network = True
            if st is None or st >= 400:
                continue                  # dépôt refusé : le filtre a tenu pour cette variante

            # Localiser le fichier servi : gabarit explicite, sinon extraction depuis la réponse.
            served = None
            if template:
                served = str(template).replace("{name}", urllib.parse.quote(filename.lstrip("./")))
            else:
                served = _extract_url(action.target, resp, f"forge-{marker}")
            if not served:
                continue                  # accepté mais introuvable : pas de preuve, on ne promeut pas

            # (1bis) Le scope-guard porte AUSSI sur l'URL servie : elle peut pointer un autre hôte.
            if not self._in_scope(action, served):
                continue

            gst, gbody, ctype = self._serve_check(served, headers)
            if gst is None:
                continue
            if marker not in (gbody or ""):
                continue                  # pas resservi -> aucune preuve

            rendering = any(t in ctype for t in _RENDERING_TYPES)
            ext_kept = _final_ext(served) in _DANGEROUS_EXT
            if not (rendering or ext_kept):
                continue                  # resservi mais inoffensif : ni type rendant, ni extension gardée
            sev = "HIGH" if rendering else "MEDIUM"
            cand = (sev, label, filename, served, ctype)
            if best is None or (sev == "HIGH" and best[0] != "HIGH"):
                best = cand
            if sev == "HIGH":
                break                     # preuve maximale atteinte : on arrête de déposer

        # (7) DÉGRADATION GRACIEUSE : aucune réponse -> skipped (offline-safe).
        if not seen_network:
            findings.append(self.degraded(
                target=action.target,
                title="Upload non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur (transport indisponible) ; offline-safe.",
                poc=self.dry(action)))
            return findings

        proven = best is not None
        if proven:
            sev, label, filename, served, ctype = best
            title = (f"UPLOAD DANGEREUX CONFIRMÉ — filtre contourné par « {label} », fichier resservi"
                     + (" avec un Content-Type rendant" if sev == "HIGH" else " avec extension dangereuse"))
            evidence = (f"variante={label} ; nom déposé={filename} ; URL servie={served} ; "
                        f"Content-Type={ctype or '(absent)'} ; marqueur inerte resservi=oui ; "
                        f"contenu SANS code (marqueur texte uniquement) ; "
                        f"{'rendu/exécuté par le navigateur' if sev == 'HIGH' else 'servi en type inerte — impact à établir'}")
            poc = (f"# 1) dépôt (fichier INERTE, aucun code) :\n"
                   f"#    curl -sS -F '{field}=@forge-marker;filename={filename};type=<mime>' '{action.target}'\n"
                   f"# 2) preuve — le marqueur revient :\n"
                   f"#    {self._curl(served, headers, 'GET')}\n"
                   f"# PREUVE = le marqueur {marker} apparaît dans la réponse ; webshell JAMAIS déposé")
        else:
            sev, title = "INFO", "Upload dangereux non confirmé — aucune variante resservie"
            evidence = (f"{len(variants)} variante(s) de contournement tentées (double extension, MIME "
                        f"menteur, casse, point final, SVG/HTML) ; aucun fichier inerte n'a été resservi "
                        f"avec extension dangereuse ni Content-Type rendant ; aucun code déposé")
            poc = self.dry(action)

        findings.append(self.proof(
            target=action.target, proven=proven, title=title, severity=sev,
            evidence=evidence, poc=poc))
        return findings
