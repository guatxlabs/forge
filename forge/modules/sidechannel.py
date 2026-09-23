# SPDX-License-Identifier: AGPL-3.0-or-later
"""sidechannel.shape — CANAL AUXILIAIRE par FORME DE RÉPONSE (famille XS-Leak / length-leak).

Détecte qu'un requêteur qui NE DEVRAIT PAS pouvoir observer l'état privé d'un autre utilisateur le
distingue quand même par la FORME OBSERVABLE de la réponse — code de statut, présence/valeur d'ETag,
longueur du corps — alors même que le corps est identique ou que l'accès est nominalement refusé.
C'est le cœur de la famille « side-channels » du Top 10 des techniques web 2025 (ETag length leak,
XS-Leaks), ramené à une PREUVE server-side sûre.

POURQUOI CE N'EST PAS « de l'info-disclosure seule » (non qualifiante) : la doctrine bannit la simple
divulgation d'un hôte/config. Ici la fuite est un ORACLE D'EXISTENCE sur l'état d'un TIERS — énumérer
qu'un compte existe, qu'une ressource privée est présente, qu'une valeur est valide. C'est la
frontière que l'application ne doit pas laisser franchir, et elle est mesurée par différentiel.

CE QUE L'ORACLE PROUVE — preuve par CONJONCTION (jamais une observation isolée) :
Trois sondes read-only sur le même paramètre, avec des valeurs de RÉFÉRENCE fournies par l'opérateur :
  · PRÉSENT (×2)  : une valeur qui mappe un état RÉEL mais que le requêteur ne devrait pas distinguer
                    (id d'une ressource d'un autre compte, nom d'utilisateur connu existant…).
  · ABSENT        : un canari bénin qui ne mappe RIEN.
La forme = (statut, ETag présent, longueur quantifiée). PREUVE = la forme du PRÉSENT est STABLE entre
ses deux tirs (canal peu bruité) **et** DIFFÈRE de celle de l'ABSENT. Si le présent n'est pas stable
(contenu dynamique, nonce, horodatage), le canal est trop bruité -> PAS de verdict (tested). Le double
tir du présent EST la mesure du plancher de bruit — sans lui, une simple variance passerait pour une fuite.

BÉNIGN & NON DESTRUCTIF : lecture seule de valeurs de référence que l'opérateur contrôle déjà ; aucune
mutation d'état, aucun impact sur le trafic d'un tiers. exploit=False, destructive=False.

⚠️ CE QU'IL NE FAIT PAS : il ne lit PAS le contenu privé — il prouve seulement qu'on peut DISTINGUER
présent d'absent. Sévérité MEDIUM (oracle d'énumération) ; l'ampleur réelle (combien d'états
énumérables, quelle sensibilité) et l'escalade relèvent de l'analyse humaine et de l'accord du programme.
"""
import hashlib

from .injection import InjectionOracle
from .registry import register
from .. import techniques

# Seuil de longueur : deux corps dont les longueurs diffèrent de <= LEN_BUCKET octets sont réputés
# de MÊME forme (tolère une micro-variance : espaces, nonce court). Au-delà, formes différentes.
_LEN_BUCKET = 48


def _shape(status, headers, body):
    """(statut, etag_présent, longueur) — la forme OBSERVABLE d'une réponse. Pur, ne lève jamais."""
    etag = False
    if headers:
        etag = any(str(k).lower() == "etag" for k in headers)
    return (status, etag, len(body or ""))


def _same_shape(a, b):
    """Deux formes sont-elles équivalentes (même statut, même présence d'ETag, longueur au bucket) ?"""
    if a is None or b is None:
        return False
    return a[0] == b[0] and a[1] == b[1] and abs(a[2] - b[2]) <= _LEN_BUCKET


@register("sidechannel.shape")
class SideChannelShape(InjectionOracle):
    kind = "sidechannel.shape"
    mitre = techniques.mitre_for("sidechannel.shape")    # source de vérité : forge/techniques.py
    cwe = "CWE-203"                                       # Observable Discrepancy
    tool = "forge/modules/sidechannel.py:sidechannel.shape"
    fix = ("Rendre la FORME de réponse indistinguable entre état présent et absent quand le requêteur "
           "n'est pas autorisé à connaître l'état : même code de statut, même gabarit (donc même "
           "longueur à la variance près), pas d'ETag dérivé du contenu privé. Répondre 404 uniforme "
           "(jamais 403-vs-404), et éviter les réponses dont la taille dépend d'un secret (CWE-203).")
    description = ("Oracle de CANAL AUXILIAIRE par forme de réponse (XS-Leak / length-leak) : PREUVE = "
                   "la forme (statut/ETag/longueur) du PRÉSENT est stable ET diffère de l'ABSENT, "
                   "révélant un oracle d'existence sur l'état d'un tiers. Read-only, bénin. Sinon tested. CWE-203.")

    # `_fetch` d'InjectionOracle renvoie (status, body) ; on a besoin des EN-TÊTES pour l'ETag.
    # On enveloppe l'appel via un second seam qui, s'il n'est pas fourni, retombe sur _fetch (etag=absent).
    def _probe(self, action, param, value, method):
        """(forme, status_vu) pour une valeur de référence. Utilise _fetch_full si présent (avec
        en-têtes), sinon _fetch (sans en-têtes -> ETag jamais détecté, dégradation honnête)."""
        headers = dict(action.params.get("headers", {}))
        url, data = self.inject_request(action.target, param, value, method,
                                        body_template=action.params.get("body_template"))
        full = getattr(self, "_fetch_full", None)
        if callable(full):
            st, hdrs, body = full(url, headers=headers, method=method.upper(), data=data)
        else:
            st, body = self._fetch(url, headers=headers, method=method.upper(), data=data)
            hdrs = {}
        return (_shape(st, hdrs, body) if st is not None else None), st

    def dry(self, action):
        p = action.params.get("param", "?")
        return (f"# read-only : compare la FORME (statut/ETag/longueur) de {p}=PRÉSENT (×2) vs "
                f"{p}=ABSENT sur {action.target} ; PREUVE = présent STABLE et != absent "
                f"(oracle d'existence sur l'état d'un tiers). Aucune mutation.")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        present = action.params.get("present_value")
        absent = action.params.get("absent_value")
        if not (param and present is not None and absent is not None):
            return [self.skip(
                target=action.target, title="Canal auxiliaire non testé — config manquante",
                evidence=("Requiert params.param, params.present_value (valeur mappant un état RÉEL non "
                          "distinguable par le requêteur) et params.absent_value (canari inexistant). "
                          "Optionnel : method, headers."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()

        shape_p1, st_p1 = self._probe(action, param, str(present), method)
        shape_p2, st_p2 = self._probe(action, param, str(present), method)
        shape_a, st_a = self._probe(action, param, str(absent), method)

        if st_p1 is None and st_p2 is None and st_a is None:
            return [self.degraded(
                target=action.target,
                title="Canal auxiliaire non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse sur les 3 sondes (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        stable = _same_shape(shape_p1, shape_p2)
        differs = (shape_p1 is not None and shape_a is not None
                   and not _same_shape(shape_p1, shape_a))
        proven = bool(stable and differs)

        # Diagnostic honnête quand ce n'est PAS prouvé : distingue « canal bruité » de « pas de fuite ».
        if proven:
            why = ""
        elif not stable:
            why = " (présent NON stable entre deux tirs -> canal trop bruité, pas de verdict)"
        else:
            why = " (présent et absent de même forme -> aucune fuite observable)"

        return [self.proof(
            target=action.target, proven=proven, severity="MEDIUM" if proven else "INFO",
            title=("Canal auxiliaire CONFIRMÉ — la forme de réponse distingue présent d'absent "
                   "(oracle d'existence sur l'état d'un tiers)"
                   if proven else
                   "Canal auxiliaire non confirmé — pas d'oracle de forme fiable" + why),
            evidence=(f"forme présent#1={shape_p1} ; présent#2={shape_p2} ; absent={shape_a} ; "
                      f"stable={stable} ; diffère={differs} (bucket longueur={_LEN_BUCKET} o)"),
            poc=(f"# {self.dry(action)}\n"
                 f"# PREUVE = présent stable {shape_p1} != absent {shape_a}"))]
