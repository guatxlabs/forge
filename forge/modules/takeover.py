"""subdomain.takeover — oracle de PRISE DE CONTRÔLE DE SOUS-DOMAINE à PREUVE MINIMALE (T1584.001 /
CWE-350).

Pour une racine/un hôte IN-SCOPE, détecte un enregistrement CNAME PENDANT (dangling) pointant vers un
service tiers NON RÉCLAMÉ (GitHub Pages, Heroku, S3, Azure, Fastly, Shopify…). La PREUVE est la
SIGNATURE de prise de contrôle : le CNAME pointe vers un service tiers connu ET (a) le service renvoie
sa page « ressource non réclamée » (fingerprint), OU (b) la cible du CNAME ne résout PAS elle-même
(NXDOMAIN) — les deux méthodes classiques et BÉNIGNES de confirmation.

INVARIANT PROOF-MINIMAL — on NE RÉCLAME JAMAIS la ressource (aucun enregistrement créé, aucun bucket/app
provisionné) : on se contente de RÉSOUDRE le DNS (lecture) et d'un GET BÉNIGN pour lire la page d'erreur
du service. On FLAGUE la cible pendante (le CNAME + le service) pour que l'opérateur la corrige/réclame
lui-même. Aucune mutation, aucune exfiltration.

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : hôte hors périmètre -> `skipped`, AUCUN DNS ni HTTP émis ;
  (2) PREUVE MINIMALE : promotion `vulnerable` UNIQUEMENT si (service tiers connu ET (fingerprint de
      non-réclamation OU cible CNAME non résolvable)) ; sinon `tested` (jamais de verdict aveugle) ;
  (3) NON DESTRUCTIF : lecture DNS + GET bénin, la ressource n'est JAMAIS réclamée (exploit=False,
      destructive=False) ;
  (4) DÉGRADATION GRACIEUSE : résolution DNS indisponible (pas de backend / réseau) -> `skipped`.

Bâti sur `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP partagés). Le
backend DNS (dnspython > dig) est OPTIONNEL : absent -> dégradation `skipped`. Tout accès réseau passe
par un seam monkeypatchable (`_resolve_cname` / `_fetch`) : les tests unitaires sont hermétiques.
"""
import shutil

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import runner
from .. import techniques
from ..roe import Scope


# --- Table de fingerprints de prise de contrôle (sous-ensemble curé de can-i-take-over-xyz) ----------
# (label_service, (sous-chaînes de CNAME du service), (signatures BODY « ressource non réclamée »)).
# La PREUVE exige à la fois le CNAME vers le service ET l'une de ses signatures de non-réclamation.
# Signatures volontairement DISTINCTIVES (sous-chaînes non ambiguës) pour éviter les faux positifs.
_TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", ("github.io", "github.map.fastly.net"),
     ("there isn't a github pages site here",
      "for root urls (like http://example.com/) you must provide an index.html file")),
    ("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
     ("no such app", "herokucdn.com/error-pages/no-such-app.html", "there's nothing here, yet.")),
    ("AWS S3", ("s3.amazonaws.com", "s3-website", "amazonaws.com"),
     ("nosuchbucket", "the specified bucket does not exist")),
    ("Azure", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
               "blob.core.windows.net", "azureedge.net", "azure-api.net"),
     ("404 web site not found", "the resource you are looking for has been removed")),
    ("Fastly", ("fastly.net",),
     ("fastly error: unknown domain", "please check that this domain has been added to a service")),
    ("Ghost", ("ghost.io",),
     ("the thing you were looking for is no longer here",)),
    ("Shopify", ("myshopify.com",),
     ("sorry, this shop is currently unavailable",)),
    ("Pantheon", ("pantheonsite.io",),
     ("the gods are wise, but do not know of the site which you seek",)),
    ("Surge.sh", ("surge.sh",),
     ("project not found",)),
    ("Bitbucket", ("bitbucket.io",),
     ("repository not found",)),
    ("Read the Docs", ("readthedocs.io",),
     ("unknown to read the docs", "the requested host does not exist")),
    ("Tumblr", ("domains.tumblr.com",),
     ("whatever you were looking for doesn't currently exist at this address",)),
    ("Unbounce", ("unbouncepages.com",),
     ("the requested url was not found on this server",)),
    ("Wordpress.com", ("wordpress.com",),
     ("do you want to register",)),
    ("Cargo Collective", ("cargocollective.com",),
     ("404 not found",)),
]


@register("subdomain.takeover")
class SubdomainTakeover(ScopeGuardedOracle):
    kind = "subdomain.takeover"
    exploit = False                      # lecture DNS + GET bénin ; la ressource n'est JAMAIS réclamée
    destructive = False                  # aucune mutation, aucun enregistrement/provisionnement
    web_allowed = True                   # interaction web/DNS (réseau) -> gardée par le ROE
    available = True                     # stdlib (dégrade si backend DNS absent)
    mitre = techniques.mitre_for("subdomain.takeover")   # source de vérité : techniques.py (T1584.001)
    cwe = "CWE-350"                                       # category + cwe des findings
    tool = "forge/modules/takeover.py:subdomain.takeover"
    MAXLEN = 100000                                        # troncature du corps lu (cf. Oracle._fetch_body)
    fix = ("Supprimer ou re-pointer l'enregistrement DNS PENDANT (dangling) sans attendre : retirer le "
           "CNAME/ALIAS dès qu'un service tiers est déprovisionné, tenir un inventaire à jour des "
           "sous-domaines et de leurs cibles, et RÉCLAMER/verrouiller la ressource tierce si elle doit "
           "rester utilisée — un CNAME vers un service non réclamé permet à un tiers de prendre le "
           "contrôle du sous-domaine (CWE-350).")
    description = ("Oracle de prise de contrôle de sous-domaine à PREUVE MINIMALE : détecte un CNAME "
                   "pendant vers un service tiers NON RÉCLAMÉ (fingerprint OU cible NXDOMAIN). NE réclame "
                   "JAMAIS la ressource — flague la cible pendante. Sinon tested. CWE-350.")

    @staticmethod
    def _resolve_cname(host):
        """(cname, cname_resolves, ok) — seam monkeypatché par les tests.

        - cname          : la cible du CNAME de `host` (str vide si `host` n'a pas de CNAME) ;
        - cname_resolves : la cible du CNAME résout-elle elle-même vers une IP ? (False = NXDOMAIN =
                           signal FORT de record pendant) — non pertinent si cname == "" ;
        - ok             : la résolution DNS a-t-elle pu être effectuée ? (False = backend absent / réseau
                           indisponible -> l'appelant DÉGRADE en `skipped`). Ne lève JAMAIS.

        Backends, dans l'ordre : dnspython (optionnel) > dig (optionnel). Aucun -> ok=False (dégradation).
        `socket` ne renvoie pas le CNAME -> non utilisé pour ce module (dégradation propre à la place)."""
        # 1) dnspython (optionnel) — CNAME + résolution de la cible
        try:
            import dns.resolver as _dnsr                      # noqa: WPS433
            cname = ""
            try:
                ans = _dnsr.resolve(host, "CNAME", lifetime=8)
                cname = str(ans[0].target).rstrip(".") if len(ans) else ""
            except Exception:                                 # noqa: BLE001 (NoAnswer/NXDOMAIN/timeout)
                cname = ""
            if not cname:
                return "", False, True                        # pas de CNAME (résolution OK)
            resolves = False
            for rt in ("A", "AAAA"):
                try:
                    if len(_dnsr.resolve(cname, rt, lifetime=8)):
                        resolves = True
                        break
                except Exception:                             # noqa: BLE001
                    continue
            return cname, resolves, True
        except ImportError:
            pass
        except Exception:                                     # noqa: BLE001
            pass
        # 2) dig (optionnel)
        if shutil.which("dig"):
            rc, out, _ = runner.tool("dig", None, ["+short", "CNAME", host], timeout=15)
            if rc == 127:
                return "", False, False                       # dig disparu -> dégradation
            cname = next((ln.strip().rstrip(".") for ln in (out or "").splitlines() if ln.strip()), "")
            if not cname:
                return "", False, (rc == 0)
            rc2, out2, _ = runner.tool("dig", None, ["+short", "A", cname], timeout=15)
            resolves = bool([ln for ln in (out2 or "").splitlines() if ln.strip()])
            return cname, resolves, True
        # 3) aucun backend DNS -> dégradation gracieuse
        return "", False, False

    @staticmethod
    def _match_service(cname):
        """(label, signatures) du service tiers connu vers lequel `cname` pointe, ou (None, ()) si aucun."""
        low = str(cname or "").lower()
        for label, needles, signs in _TAKEOVER_FINGERPRINTS:
            if any(n in low for n in needles):
                return label, signs
        return None, ()

    def dry(self, action):
        host = Scope._host(action.target)
        return (f"# résout le CNAME de {host} ; si CNAME -> service tiers connu, GET bénin sur {host} pour "
                f"lire la page d'erreur ; PREUVE = fingerprint de NON-RÉCLAMATION du service OU cible CNAME "
                f"NXDOMAIN ; la ressource n'est JAMAIS réclamée (on flague la cible pendante) ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hôte hors périmètre -> skipped, AUCUN DNS/HTTP émis.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        host = Scope._host(action.target)
        cname, cname_resolves, ok = self._resolve_cname(host)
        # (4) DÉGRADATION GRACIEUSE — résolution DNS indisponible (backend absent / réseau) -> skipped.
        if not ok:
            return [self.degraded(
                target=host, title="subdomain.takeover non testé — résolution DNS indisponible (dégradation)",
                evidence=("Aucun backend DNS (dnspython/dig) ou réseau indisponible ; impossible de résoudre "
                          "le CNAME. Aucune ressource réclamée. Installer dnspython/dig pour activer."),
                poc=self.dry(action))]
        if not cname:
            return [self.proof(
                target=host, proven=False,
                title="subdomain.takeover non confirmé — aucun CNAME (pas de cible tierce pendante)",
                severity="INFO",
                evidence=(f"{host} n'a pas d'enregistrement CNAME vers un service tiers ; pas de vecteur de "
                          f"prise de contrôle par CNAME pendant. Aucune ressource réclamée."),
                poc=self.dry(action))]
        service, signs = self._match_service(cname)
        if not service:
            return [self.proof(
                target=host, proven=False,
                title="subdomain.takeover non confirmé — CNAME vers une cible non reconnue",
                severity="INFO",
                evidence=(f"{host} -> CNAME {cname} : cible non répertoriée parmi les services tiers connus "
                          f"(pas de signature de prise de contrôle connue). cible_résout={cname_resolves}. "
                          f"Aucune ressource réclamée."),
                poc=self.dry(action))]
        # Service tiers CONNU : (a) fingerprint HTTP de non-réclamation, OU (b) cible CNAME NXDOMAIN.
        fingerprint_hit, http_status, seen_http = False, None, False
        st, body = self._fetch(self._url(host), timeout=action.params.get("timeout", 15))
        if st is not None:
            seen_http = True
            http_status = st
            low = (body or "").lower()
            fingerprint_hit = any(sig in low for sig in signs)
        dangling_nxdomain = (not cname_resolves)
        proven = fingerprint_hit or dangling_nxdomain
        method = ("fingerprint de non-réclamation" if fingerprint_hit else "") + \
                 (" + " if (fingerprint_hit and dangling_nxdomain) else "") + \
                 ("cible CNAME non résolvable (NXDOMAIN)" if dangling_nxdomain else "")
        return [self.proof(
            target=host, proven=proven,
            title=(f"Subdomain takeover CONFIRMÉ — CNAME pendant vers {service} NON RÉCLAMÉ (cible pendante "
                   f"flaguée, ressource JAMAIS réclamée)" if proven
                   else f"Subdomain takeover non confirmé — CNAME vers {service} mais ressource réclamée/servie"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"{host} -> CNAME {cname} (service tiers = {service}) ; cible_résout={cname_resolves} ; "
                      f"HTTP={http_status if seen_http else 'n/a'} ; fingerprint_non_réclamé={fingerprint_hit} ; "
                      f"nxdomain={dangling_nxdomain}" + (f" ; méthode={method}" if proven else "")
                      + " ; INFORMATIONNEL — la ressource tierce n'a JAMAIS été réclamée (aucun "
                        "enregistrement/bucket/app créé), la cible pendante est seulement flaguée"),
            poc=(f"# 1) dig +short CNAME {host}   # -> {cname} ({service})\n"
                 f"# 2) curl -sSi {self._url(host)}   # page 'ressource non réclamée' du service\n"
                 f"# NE PAS réclamer la ressource — flaguer/corriger le CNAME pendant"))]

    @staticmethod
    def _url(host):
        return host if "://" in str(host) else "https://" + str(host)
