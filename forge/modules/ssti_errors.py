# SPDX-License-Identifier: AGPL-3.0-or-later
"""ssti.errors — SSTI AVEUGLE rendu visible par le CANAL D'ERREUR (« Successful Errors »).

Complète `ssti.eval` (injection.py), qui prouve la SSTI quand le produit arithmétique évalué est
RÉFLÉCHI dans la réponse normale. Quand la sortie est supprimée/assainie (SSTI *aveugle*), ce chemin
ne voit rien — et c'est précisément le cas que la technique « Successful Errors » de Gareth Heyes
(1re du Top 10 des techniques web 2025 de PortSwigger) adresse : même sans réflexion, une expression
qui DÉCLENCHE UNE ERREUR d'évaluation fait fuiter, par le message d'erreur/la page 500, la preuve
que le moteur a bel et bien INTERPRÉTÉ l'entrée.

CE QUE L'ORACLE PROUVE, ET COMMENT — preuve par CONJONCTION (jamais une observation isolée) :
Pour chaque syntaxe de template, on compare TROIS sondes sur le même paramètre :
  · TÉMOIN  : un marqueur inerte SANS délimiteur (`forgeInert…`)         -> ligne de base pure.
  · CONTRÔLE: les délimiteurs autour du marqueur inerte (`{{forgeInert…}}`) -> les délimiteurs seuls
              ne doivent PAS produire une erreur ARITHMÉTIQUE (au pire une UndefinedError/parse).
  · TEST    : la même syntaxe portant `N*M/0` (le produit PUIS une division par zéro).
La PREUVE d'évaluation = une signature d'erreur ARITHMÉTIQUE (ZeroDivisionError, « / by zero »,
« attempt to divide by zero »…) présente dans le TEST **et absente du CONTRÔLE et du TÉMOIN**. Une
division par zéro ne survient QUE si le moteur a évalué l'expression : ni la réflexion, ni les
délimiteurs seuls, ni un texte brut ne la produisent. C'est ce différentiel qui rend la preuve solide.

PALIER FORT (fuite de valeur) : si, EN PLUS, le produit `N*M` apparaît dans le corps d'erreur du TEST
sans apparaître dans le témoin ni le contrôle, l'erreur a divulgué une valeur que SEULE l'évaluation
pouvait produire — corroboration directe (severité HIGH). Sinon, évaluation confirmée par la seule
signature d'erreur (severité MEDIUM).

BÉNIGN & NON DESTRUCTIF : on n'envoie qu'un produit arithmétique suivi d'une division par zéro — aucune
exécution de commande, aucune lecture de fichier, aucune mutation d'état. Une division par zéro est
inerte pour la cible (elle lève une exception, gérée par le moteur). exploit=False, destructive=False.

⚠️ CE QU'IL NE FAIT PAS : il ne déduit ni n'exfiltre aucune donnée. Il établit UNE chose — le moteur
évalue l'entrée — et la severité HIGH n'est posée que sur la fuite du produit, jamais sur une donnée
tierce. L'escalade (RCE réelle) relève de l'accord du programme et n'est pas tentée ici.
"""
import hashlib

from .injection import InjectionOracle
from .registry import register
from .. import techniques

# Syntaxes de template — sentinelles N/M/INERT substituées. Le TEST porte `N*M/0` (produit puis
# division par zéro) ; le CONTRÔLE porte le marqueur inerte SEUL (mêmes délimiteurs, aucune arithmétique).
# `//` (Python floor-div) ET `/` (Twig/JS/Java/EL) couverts pour maximiser les moteurs touchés.
_TEST_TEMPLATES = [
    "{{N*M//0}}", "{{N*M/0}}",           # Jinja2 / Twig / Nunjucks
    "${N*M/0}",                          # Freemarker / JSP-EL / Thymeleaf / SpEL
    "#{N*M/0}",                          # Ruby / JSF-EL
    "<%= N*M/0 %>",                      # ERB / EJS
    "{N*M/0}",                           # Smarty
    "*{N*M/0}",                          # SpEL selection
    "@(N*M/0)",                          # Razor
    "#set($e=N*M/0)$e",                  # Velocity
]
# Contrôle par syntaxe : mêmes délimiteurs, marqueur INERTE, aucune arithmétique (donc aucune erreur
# arithmétique attendue même si le moteur parse les délimiteurs).
_CONTROL_TEMPLATES = [
    "{{INERT}}", "{{INERT}}", "${INERT}", "#{INERT}", "<%= INERT %>", "{INERT}", "*{INERT}",
    "@(INERT)", "#set($e=INERT)$e",
]

# Signatures d'erreur STRICTEMENT ARITHMÉTIQUES — elles ne surviennent QUE si la division a été
# évaluée. Volontairement pas de nom de moteur nu (« twig », « jinja ») : ceux-là peuvent apparaître
# dans un contrôle et affaibliraient le différentiel.
_ARITH_ERROR_SIGS = [
    "zerodivisionerror",
    "division by zero",
    "divide by zero",
    "divided by zero",
    "attempt to divide by zero",
    "integer division or modulo by zero",
    "modulo by zero",
    "/ by zero",                          # java.lang.ArithmeticException: / by zero
    "arithmeticexception",
    "divisionbyzeroerror",                # PHP DivisionByZeroError
]


@register("ssti.errors")
class SstiErrors(InjectionOracle):
    kind = "ssti.errors"
    mitre = techniques.mitre_for("ssti.errors")          # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-1336"
    tool = "forge/modules/ssti_errors.py:ssti.errors"
    fix = ("Ne jamais concaténer d'entrée utilisateur dans un template évalué côté serveur ; traiter "
           "l'entrée comme des DONNÉES (contexte/variables), moteur en mode sandbox/logic-less. Et ne "
           "jamais renvoyer au client le message d'exception brut du moteur de template : une page "
           "d'erreur générique empêche le canal d'erreur de confirmer l'évaluation (CWE-1336, CWE-209).")
    description = ("Oracle SSTI AVEUGLE par le canal d'erreur (« Successful Errors ») : preuve par "
                   "conjonction — une erreur ARITHMÉTIQUE apparaît sur N*M/0 (test) mais pas sur le "
                   "marqueur inerte (contrôle) ni le témoin. HIGH si le produit fuite dans l'erreur, "
                   "sinon MEDIUM. Aucune exécution de code. Sinon tested. CWE-1336.")

    _MAX_LEN = 220

    @classmethod
    def _marker(cls, target, param):
        """(n, m, produit, inerte) déterministe-par-cible (rejouable, pas de random) et DISTINCTIF :
        deux facteurs à 6 chiffres -> produit à ~11-12 chiffres ; marqueur inerte unique dérivé du
        même hash. Aucune collision fortuite plausible dans une réponse."""
        h = int(hashlib.sha256(f"{target}|{param}|forge-ssti-err".encode()).hexdigest(), 16)
        n = 100003 + (h % 899000)
        m = 100003 + ((h >> 64) % 899000)
        inert = "forgeInert" + hashlib.sha256(f"{target}|{param}|inert".encode()).hexdigest()[:8]
        return n, m, n * m, inert

    @staticmethod
    def _has_arith_error(body):
        """True si le corps porte une signature d'erreur ARITHMÉTIQUE (division par zéro évaluée).
        Insensible à la casse. Pur, ne lève jamais."""
        low = (body or "").lower()
        return any(sig in low for sig in _ARITH_ERROR_SIGS)

    def dry(self, action):
        param = action.params.get("param", "?")
        n, m, prod, _inert = self._marker(action.target, action.params.get("param", ""))
        return (f"# injecte {param}={{{{{n}*{m}/0}}}} (et ${{…}}/#{{…}}/<%= … %>/…) dans {action.target} ; "
                f"PREUVE = erreur ARITHMÉTIQUE (division par zéro) sur le test, ABSENTE du contrôle inerte "
                f"et du témoin -> le moteur a évalué l'expression ; HIGH si le produit {prod} fuite dans "
                f"l'erreur. Aucune exécution de code ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="SSTI (canal d'erreur) non testé — config manquante",
                evidence="Requiert params.param (paramètre injectable). Optionnel : params.method, params.headers.",
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        n, m, product, inert = self._marker(action.target, param)
        prod_s = str(product)
        seen_network = False

        # TÉMOIN (une seule fois) : marqueur inerte nu, sans délimiteur. Établit la ligne de base —
        # une erreur arithmétique déjà présente ici invaliderait toute conclusion (page d'erreur
        # permanente, WAF renvoyant un gabarit d'erreur…), on la neutralise par le différentiel.
        w_where, w_st, w_body = self._send(action, param, inert, method)
        if w_st is not None:
            seen_network = True
        witness_err = self._has_arith_error(w_body)
        witness_has_product = prod_s in (w_body or "")

        templates = list(zip(_TEST_TEMPLATES, _CONTROL_TEMPLATES)) + [
            (p, None) for p in self._llm_extra_payloads(action)]     # candidats LLM : test sans contrôle dédié
        proven, strong, matched, where = False, False, "", w_where
        for test_tmpl, control_tmpl in templates:
            test_payload = test_tmpl.replace("N", str(n)).replace("M", str(m))
            if len(test_payload) > self._MAX_LEN:
                continue
            where, st_t, body_t = self._send(action, param, test_payload, method)
            if st_t is not None:
                seen_network = True
            if witness_err or not self._has_arith_error(body_t):
                continue                                            # pas d'erreur arith imputable au test
            # Candidat : confirmer le DIFFÉRENTIEL avec le contrôle (mêmes délimiteurs, inerte).
            # Sans contrôle dédié (payload LLM), on retombe sur le seul différentiel témoin.
            control_err = False
            if control_tmpl is not None:
                _cw, st_c, body_c = self._send(action, param, control_tmpl.replace("INERT", inert), method)
                if st_c is not None:
                    seen_network = True
                control_err = self._has_arith_error(body_c)
            if control_err:
                continue                                            # les délimiteurs seuls suffisent -> non concluant
            # PREUVE : erreur arith dans le test, absente du témoin ET du contrôle.
            proven, matched = True, test_tmpl
            strong = (prod_s in (body_t or "")) and not witness_has_product
            break

        if not seen_network:
            return [self.degraded(
                target=where, title="SSTI (canal d'erreur) non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse sur les sondes (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        sev = "HIGH" if (proven and strong) else ("MEDIUM" if proven else "INFO")
        return [self.proof(
            target=where, proven=proven, severity=sev,
            title=("SSTI AVEUGLE CONFIRMÉE par le canal d'erreur — le moteur a évalué l'expression"
                   + (" (produit divulgué dans l'erreur)" if strong else "")
                   if proven else
                   "SSTI (canal d'erreur) non confirmée — aucune évaluation (pas de verdict à l'aveugle)"),
            evidence=(f"marqueur {n}*{m}/0 ; erreur arithmétique observée sur le TEST, absente du "
                      f"contrôle inerte et du témoin"
                      + (f" ; produit {prod_s} divulgué dans l'erreur" if strong else "")
                      + (f" ; syntaxe={matched}" if proven else "")
                      if proven else
                      f"aucune erreur arithmétique différentielle sur {len(_TEST_TEMPLATES)} syntaxe(s) "
                      f"(témoin_err={witness_err})"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = division par zéro ÉVALUÉE (erreur arith. test-only), "
                 f"{'produit ' + prod_s + ' dans l’erreur' if strong else 'valeur non divulguée'}"))]
