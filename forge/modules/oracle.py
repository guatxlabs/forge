"""Base commune des modules-oracles à PREUVE (`Oracle`) — factorise le squelette répété par les
quatre vérificateurs à preuve : `access_control.idor`, `ssrf.callback`, `auth.takeover`,
`cors.credentials`.

Contrat commun (le « pas de preuve => tested » est ici la loi, pas une convention par module) :
  - PREUVE obtenue  -> `proof(proven=True, ...)`  -> status='vulnerable' (sévérité HIGH/CRITICAL) ;
  - PAS de preuve    -> `proof(proven=False, ...)` -> status='tested' (jamais 'vulnerable' à l'aveugle) ;
  - config manquante -> `skip(...)`               -> finding INFO 'tested', AUCUN réseau émis.

Ce que la base fournit (chaque oracle concret se réduit à : métadonnées + logique de sonde/jugement) :
  - `proof(...)` / `skip(...)` : construction UNIFORME de Finding qui estampille kind/mitre/cwe/category/
    tool/fix et applique le toggle de statut (preuve => vulnerable, sinon tested) ;
  - `_http(...)` : le CÂBLAGE urllib partagé (Request + urlopen + gestion HTTPError/transport). Chaque
    oracle garde son `_fetch` (le seam monkeypatché par les tests) mais l'adosse à `_http` ;
  - `_curl(...)` : PoC curl rejouable (un `-H` par en-tête), partagé par IDOR/SSRF/ATO.

Aucune capacité n'est élargie ici : les flags exploit/destructive/web_allowed restent déclarés par
chaque module concret et restent gardés par le ROE.
"""
import urllib.error
import urllib.request

from .registry import Module
from .. import session as _session


class Oracle(Module):
    """Base des oracles à preuve. Un oracle concret déclare ses métadonnées (kind/mitre/cwe/fix/tool)
    et surcharge une petite méthode de sonde/jugement — toute la plomberie Finding/HTTP vit ici."""

    web_allowed = True          # interaction web (réseau) -> gardée par le ROE (commun aux 4 oracles)
    available = True            # urllib stdlib -> toujours disponible
    cwe = ""                    # CWE canonique de l'oracle (ex "CWE-918") : sert de category ET de cwe
    fix = ""                    # remédiation par défaut de l'oracle (le fix explicite d'un finding prime)
    tool = ""                   # chaîne de provenance estampillée sur les findings

    # --- construction UNIFORME de Finding (le coeur factorisé) ---
    def proof(self, *, target, proven, title, severity, evidence, poc, fix=None):
        """Finding sur le CHEMIN DE PREUVE. Estampille category=self.cwe, cwe=self.cwe, mitre=self.mitre,
        tool=self.tool, fix (self.fix par défaut, override par argument). `proven` applique le contrat :
        True -> status='vulnerable', False -> status='tested' (jamais vulnerable sans preuve)."""
        return self.finding(
            target=target, title=title, severity=severity,
            category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix if fix is None else fix,
            status="vulnerable" if proven else "tested",
            tool=self.tool, evidence=evidence, poc=poc)

    def skip(self, *, target, title, evidence, poc, severity="INFO"):
        """Finding 'non testé / config manquante' : category=self.cwe, status='tested', tool=self.tool,
        et AUCUN mitre/cwe/fix estampillé (le schema dérivera cwe depuis category + fix depuis le mapping).
        Sert aussi aux refus fail-closed (ex : write IDOR non autorisé) — INFO, aucun réseau émis."""
        return self.finding(
            target=target, title=title, severity=severity,
            category=self.cwe, status="tested", tool=self.tool,
            evidence=evidence, poc=poc)

    # --- câblage HTTP partagé (les `_fetch` concrets adaptent la forme du tuple retourné) ---
    @staticmethod
    def _http(url, *, headers=None, timeout=15, method="GET", data=None, maxlen=200000):
        """Requête urllib partagée -> (status, body, resp_headers).

        - succès        : (r.status, corps décodé tronqué à maxlen, r.headers) ;
        - HTTPError     : (e.code, "", e.headers | None) — corps vide, en-têtes si disponibles ;
        - erreur transport (réseau hostile) : (None, "", None) — on ne crashe jamais.
        Chaque oracle en dérive sa propre forme (content-type, dict d'en-têtes…) dans son `_fetch`.

        SESSION GOUVERNÉE : si un `SessionStore` est lié (par le moteur autour de fire()), le matériel
        d'authentification SECRET applicable à `url` — et UNIQUEMENT si `url` est IN-SCOPE (scope-guard
        du store) — est fusionné SOUS les en-têtes de l'appelant dans la requête sortante. Il n'est
        JAMAIS renvoyé ni exposé : l'appelant bâtit ses PoC depuis SES propres en-têtes (`_curl`), pas
        depuis la requête. Sans store lié (dev/test/offline) -> aucune modification (byte-à-byte)."""
        req_headers = dict(headers or {})
        store = _session.current()
        if store is not None:                        # scope-guard PAR-URL : {} si url hors-scope
            for k, v in store.headers_for(url).items():
                req_headers.setdefault(k, v)         # les en-têtes explicites de l'appelant priment
        payload = data.encode("utf-8") if isinstance(data, str) else data
        req = urllib.request.Request(url, headers=req_headers, method=method, data=payload)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(maxlen).decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            try:
                return e.code, "", e.headers
            except Exception:            # noqa: BLE001
                return e.code, "", None
        except Exception:                # noqa: BLE001  (réseau hostile : on ne crashe pas)
            return None, "", None

    # --- PoC curl partagé (IDOR / SSRF / ATO) — un drapeau -H par en-tête (commande rejouable) ---
    @staticmethod
    def _curl(url, headers, method="GET", data=None):
        """PoC curl valide : un `-H` par en-tête (jamais un repr de dict), `-X` si non-GET,
        `--data` si corps, URL quotée en dernier. Sortie identique pour IDOR/SSRF/ATO."""
        parts = ["curl", "-sS"]
        if method and method.upper() != "GET":
            parts += ["-X", method.upper()]
        for k, v in (headers or {}).items():
            parts += ["-H", f"'{k}: {v}'"]
        if data is not None:
            parts += ["--data", f"'{data}'"]
        parts.append(f"'{url}'")
        return " ".join(parts)
