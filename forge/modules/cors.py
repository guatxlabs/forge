"""cors.credentials — oracle CORS-with-credentials à PREUVE (T1539 / CWE-942, CWE-346).

Une mauvaise config CORS n'est exploitable QUE si l'origine attaquante peut LIRE une réponse
authentifiée d'autrui. La preuve n'est pas « ACAO reflète mon origine » seul (souvent bénin) : c'est
la COMBINAISON `Access-Control-Allow-Origin: <origine-attaquante>` + `Access-Control-Allow-Credentials:
true` sur un endpoint qui sert des données de session — exactement ce qui permet à un site tiers de
lire le compte de la victime via fetch(credentials:'include'). Sans cette combinaison vérifiée sur
l'origine attaquante exacte -> `tested`.

PREUVE (vérifiable, sans navigateur) :
  - on envoie une requête (idéalement authentifiée : params.auth_headers) avec `Origin: <attaquante>` ;
  - on lit les en-têtes de réponse : ACAO == origine attaquante (reflet exact, PAS `*`) ET ACAC == true ;
    (`*` + credentials est interdit par les navigateurs -> non exploitable, donc NON promu).
  - bonus de preuve : un `params.session_marker` présent dans le corps atteste qu'il y a bien des
    données sensibles derrière (sinon HIGH au lieu de CRITICAL).

exploit=True (chaîne vers le vol de données cross-origin authentifiées) -> exige allow_exploit.
destructive=False (lecture seule). web_allowed via le ROE. Pur urllib (stdlib). Bâti sur la base
`Oracle` (construction Finding + câblage HTTP partagés).
"""
from .oracle import Oracle
from .registry import register
from .. import techniques


@register("cors.credentials")
class CorsCredentials(Oracle):
    kind = "cors.credentials"
    exploit = True                       # lecture cross-origin authentifiée d'autrui -> allow_exploit
    destructive = False                  # lecture seule
    web_allowed = True
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("cors.credentials")   # source de vérité : forge/techniques.py (T1539)
    cwe = "CWE-942"                      # category + cwe des findings (via Oracle.proof/skip)
    tool = "forge/modules/cors.py:cors.credentials"
    fix = ("Ne JAMAIS combiner le reflet d'une Origin arbitraire (ou ACAO: *) avec "
           "Access-Control-Allow-Credentials: true. Refléter uniquement des origines issues d'une "
           "allowlist stricte et n'autoriser les credentials que pour ces origines de confiance "
           "(CWE-942/CWE-346).")
    description = ("Oracle CORS-credentials à PREUVE : ACAO reflète l'origine attaquante (pas *) ET "
                  "ACAC=true sur un endpoint authentifié -> lecture cross-origin. Sinon tested. CWE-942.")

    @staticmethod
    def _fetch(url, headers=None, timeout=15):
        """(status, body, headers_dict minuscules) — adosse le câblage urllib partagé (Oracle._http).
        Seam monkeypatché par les tests (GET seul : la preuve est dans les en-têtes de réponse)."""
        st, body, h = Oracle._http(url, headers=headers, timeout=timeout, method="GET", maxlen=100000)
        return st, body, ({k.lower(): v for k, v in h.items()} if h is not None else {})

    def dry(self, action):
        origin = action.params.get("attacker_origin", "https://attacker.example")
        return (f"# GET {action.target} avec Origin: {origin} (+ session victime) ; "
                f"PREUVE = Access-Control-Allow-Origin == {origin} ET "
                f"Access-Control-Allow-Credentials: true -> lecture cross-origin authentifiée ; sinon tested")

    def fire(self, action):
        origin = action.params.get("attacker_origin")
        if not origin:
            return [self.skip(
                target=action.target, title="CORS non testé — config manquante",
                evidence=("Requiert params.attacker_origin (origine contrôlée à refléter). "
                          "Optionnel : params.auth_headers (session victime), params.session_marker."),
                poc=self.dry(action))]
        hdr = dict(action.params.get("auth_headers", {}))
        hdr["Origin"] = origin
        st, body, resp_h = self._fetch(action.target, headers=hdr)
        acao = (resp_h.get("access-control-allow-origin") or "").strip()
        acac = (resp_h.get("access-control-allow-credentials") or "").strip().lower()
        # PREUVE : reflet EXACT de l'origine attaquante (pas '*', que les navigateurs refusent avec
        # credentials) ET credentials autorisés. C'est la seule combinaison réellement exploitable.
        reflects = (acao == origin)
        creds_ok = (acac == "true")
        exploitable = reflects and creds_ok
        marker = action.params.get("session_marker")
        has_data = bool(marker and marker in (body or ""))
        sev = "CRITICAL" if (exploitable and has_data) else "HIGH" if exploitable else "INFO"
        return [self.proof(
            target=action.target, proven=exploitable,
            title=("CORS exploitable — lecture cross-origin AVEC credentials confirmée"
                   if exploitable else "CORS non exploitable (pas de reflet+credentials sur origine attaquante)"),
            severity=sev,
            evidence=(f"HTTP {st} ; ACAO={acao!r} (reflet_exact={reflects}) ; "
                      f"ACAC={acac!r} (credentials={creds_ok}) ; données_session_visibles={has_data}"),
            poc=(f"curl -sS -H 'Origin: {origin}' "
                 + " ".join(f"-H '{k}: {v}'" for k, v in action.params.get("auth_headers", {}).items())
                 + f" -D - '{action.target}'  # vérifier ACAO=={origin} + ACAC: true"))]
