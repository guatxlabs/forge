"""business_logic.scan — SCAFFOLD SEMI-AUTOMATISÉ de checks de logique métier (T1190 / CWE-840).

PENTEST-ONLY. La logique métier est le domaine le MOINS automatisable : la plupart des abus exigent un
JUGEMENT HUMAIN (comprendre le flux d'achat, la comptabilité des points, les règles de remise). Ce module
est donc un SCAFFOLD explicitement SEMI-AUTOMATISÉ :

  - AUTOMATISABLE (où c'est SÛREMENT détectable) : quand l'opérateur fournit une sonde NON DESTRUCTIVE
    (un endpoint de DEVIS/quote en lecture qui reflète le total calculé) + un `anomaly_marker`, le check
    injecte une valeur trafiquée (quantité négative / prix client / coupon dupliqué) et cherche le
    marqueur d'anomalie dans la réponse. PREUVE concrète -> `vulnerable`. Marqueur absent -> `tested`.
  - MANUEL (jugement humain requis) : sans sonde sûre configurée, le check n'invente RIEN — il émet un
    finding `status='tested'` avec une NOTE « manual review » décrivant précisément quoi vérifier à la
    main. Anti-lacune silencieuse : chaque classe de check demandée produit un finding traçable.

Checks scaffoldés (params.checks, défaut = les trois) :
  - negative_quantity : quantité négative -> total/prix négatif ou remboursement indu ;
  - price_tamper      : prix/montant côté client accepté (tamper de montant) ;
  - coupon_stack      : empilement/réutilisation de coupon au-delà de la règle.

GARDE-FOUS :
  (1) SCOPE-GUARD fail-closed : cible/sonde hors périmètre -> `skipped`, AUCUNE requête émise ;
  (2) NON DESTRUCTIF : la sonde automatisable est un GET de DEVIS en LECTURE (jamais une commande
      committée) ; exploit=False, destructive=False. Aucune mutation d'état n'est émise par ce module ;
  (3) PREUVE MINIMALE : promotion `vulnerable` uniquement sur `anomaly_marker` concret ; sinon `tested` ;
  (4) SESSION SECRÈTE : matériel d'auth gouverné fusionné par `Oracle._http` sur URL in-scope, jamais fuité ;
  (5) DÉGRADATION GRACIEUSE : réseau indisponible sur une sonde -> ce check dégrade en note manuelle `tested`.

Bâti sur `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP + curl partagés).
"""
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques

# Catalogue des checks scaffoldés : nom -> (libellé, description de ce qu'un humain doit vérifier).
_CHECKS = {
    "negative_quantity": (
        "quantité négative",
        "soumettre une QUANTITÉ NÉGATIVE et vérifier si le total/prix devient négatif ou déclenche un "
        "remboursement/crédit indu (au lieu d'être rejeté)."),
    "price_tamper": (
        "prix trafiqué (client-side)",
        "trafiquer le PRIX/MONTANT côté client (ex champ caché, param) et vérifier si le serveur accepte "
        "la valeur fournie au lieu de recalculer côté serveur."),
    "coupon_stack": (
        "empilement de coupon",
        "appliquer PLUSIEURS FOIS le même coupon (ou en empiler plusieurs) et vérifier si la remise "
        "dépasse la règle (réutilisation/stacking non prévu)."),
}
_DEFAULT_CHECKS = ("negative_quantity", "price_tamper", "coupon_stack")


@register("business_logic.scan")
class BusinessLogicScan(ScopeGuardedOracle):
    kind = "business_logic.scan"
    exploit = False                      # scaffold de détection : aucune exploitation
    destructive = False                  # sonde de DEVIS en lecture : aucune mutation d'état émise
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("business_logic.scan")  # source de vérité : techniques.py (T1190)
    cwe = "CWE-840"                                       # Business Logic Errors
    tool = "forge/modules/business_logic.py:business_logic.scan"
    fix = ("Valider et RECALCULER côté serveur toute donnée à valeur métier (quantité >= 0, prix/total "
           "depuis le catalogue serveur, unicité/plafond des coupons) ; ne jamais faire confiance à un "
           "montant/quantité/coupon fourni par le client ; appliquer des invariants métier (bornes, "
           "idempotence des remises) et journaliser les anomalies (CWE-840).")
    description = ("Scaffold SEMI-AUTOMATISÉ de logique métier (pentest-only) : quantité négative / "
                   "price-tamper / coupon-stack. Automatisé via une sonde DEVIS non destructive + "
                   "anomaly_marker ; sinon note 'manual review' (status=tested). CWE-840.")

    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None):
        """(status, body) — adosse le câblage urllib partagé (Oracle._http). Seam monkeypatché par les tests."""
        st, body, _ = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=200000)
        return st, body

    def _check_cfg(self, action, name):
        """Config de sonde d'un check : params.probes[name] = {probe_url, param, tamper_value,
        anomaly_marker}. Absente -> check MANUEL (note 'manual review')."""
        probes = action.params.get("probes") or {}
        cfg = probes.get(name) if isinstance(probes, dict) else None
        return cfg if isinstance(cfg, dict) else None

    def _manual(self, action, name, why):
        """Finding `status='tested'` de REVUE MANUELLE (jugement humain) — anti-lacune silencieuse."""
        label, guidance = _CHECKS.get(name, (name, "revue manuelle du flux métier concerné."))
        return self.finding(
            target=action.target,
            title=f"Logique métier — {label} : REVUE MANUELLE (manual review) requise (semi-automatisé)",
            severity="INFO", category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix, status="tested", tool=self.tool,
            evidence=(f"check={name} : {why}. Jugement humain requis — À VÉRIFIER À LA MAIN : {guidance} "
                      f"Ce module n'émet AUCUNE requête destructive ; fournir params.probes['{name}'] "
                      f"(probe_url DE DEVIS non destructif + param + tamper_value + anomaly_marker) pour "
                      f"automatiser sûrement ce check."),
            poc=(f"# manuel : {guidance}"))

    def _automated(self, action, name, cfg):
        """Sonde NON DESTRUCTIVE (GET de devis) : injecte `tamper_value` dans `param` de `probe_url` et
        cherche `anomaly_marker`. PREUVE concrète -> `vulnerable` ; marqueur absent -> `tested` ; réseau
        KO -> dégrade en note manuelle."""
        label, guidance = _CHECKS.get(name, (name, ""))
        probe_url = str(cfg.get("probe_url"))
        # (1bis) SCOPE-GUARD PAR-URL fail-closed sur la sonde — hors périmètre : aucun I/O.
        if not self._in_scope(action, probe_url):
            return self.degraded(
                target=probe_url,
                title=f"Logique métier — {label} non sondé (probe hors périmètre, scope-guard fail-closed)",
                evidence="La sonde de devis n'est pas in-scope ; aucune requête émise (fail-closed).",
                poc=f"# probe hors scope : {probe_url}")
        param = str(cfg.get("param", ""))
        tamper = str(cfg.get("tamper_value", ""))
        marker = str(cfg.get("anomaly_marker", ""))
        if not param or not marker:
            return self._manual(action, name, "sonde incomplète (param/anomaly_marker manquant)")
        headers = dict(action.params.get("headers", {}))
        sep = "&" if "?" in probe_url else "?"
        url = f"{probe_url}{sep}{urllib.parse.urlencode({param: tamper})}"
        st, body = self._fetch(url, headers=headers, method="GET")     # DEVIS en LECTURE (non destructif)
        if st is None:
            return self._manual(action, name, "sonde de devis injoignable (réseau indisponible)")
        anomaly = marker in (body or "")
        return self.proof(
            target=probe_url, proven=anomaly,
            title=(f"Logique métier CONFIRMÉE — {label} : anomalie détectée (marqueur d'anomalie présent)"
                   if anomaly else f"Logique métier — {label} : aucune anomalie détectée (devis non destructif)"),
            severity=("HIGH" if anomaly else "INFO"),
            evidence=(f"check={name} ; sonde DEVIS non destructive {param}={tamper} sur {probe_url} ; "
                      f"anomaly_marker_présent={anomaly} (HTTP {st}) ; aucune commande committée/mutation émise ; "
                      f"session gouvernée non journalisée"),
            poc=(f"# sonde DEVIS non destructive : curl -sS '{url}'\n"
                 f"# PREUVE = le marqueur d'anomalie apparaît (ex total négatif / prix client accepté / "
                 f"remise empilée) ; committer la commande reste une action MANUELLE gouvernée"))

    def dry(self, action):
        checks = list(action.params.get("checks") or _DEFAULT_CHECKS)
        auto = [c for c in checks if self._check_cfg(action, c)]
        return (f"# scaffold SEMI-AUTOMATISÉ logique métier sur {action.target} : checks={checks} ; "
                f"automatisés (sonde devis + anomaly_marker)={auto or 'aucun'} ; les autres -> note "
                f"'manual review' (status=tested) ; aucune requête destructive émise")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed sur la cible — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        checks = [c for c in (action.params.get("checks") or _DEFAULT_CHECKS) if c in _CHECKS]
        if not checks:
            return [self.skip(
                target=action.target, title="Logique métier non testé — aucun check valide",
                evidence=(f"params.checks doit contenir au moins un check parmi {sorted(_CHECKS)}. "
                          f"Optionnel : params.probes[<check>] (sonde DEVIS non destructive) pour automatiser."),
                poc=self.dry(action))]
        findings = []
        for name in checks:
            cfg = self._check_cfg(action, name)
            if cfg:
                findings.append(self._automated(action, name, cfg))     # automatisable (sonde sûre)
            else:
                findings.append(self._manual(action, name, "aucune sonde non destructive configurée"))
        return findings
