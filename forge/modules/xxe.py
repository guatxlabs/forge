"""xxe.probe — oracle XXE (XML External Entity) à PREUVE BÉNIGNE (T1190 / CWE-611).

Détecte le TRAITEMENT d'entités externes XML par un marqueur STRICTEMENT BÉNIGN — VÉRIFICATION pour
test autorisé, PAS de weaponization ni de lecture de fichier sensible :

  - mode OOB (out-of-band)  : injecte un DOCTYPE dont l'entité externe SYSTEM pointe vers un collecteur
                              CONTRÔLÉ PAR L'OPÉRATEUR (`{callback_base}/{token}`), puis interroge ce
                              collecteur. PREUVE = le token a RÉELLEMENT été reçu côté collecteur (le
                              parseur XML a résolu l'entité externe -> XXE confirmé). L'entité ne fait
                              que joindre un marqueur bénin — aucune donnée sensible transportée.
  - mode canari in-band     : l'entité SYSTEM pointe vers un CANARI BÉNIGN NON sensible (URL/ressource
                              fournie par l'opérateur dont le contenu = un marqueur unique). PREUVE = le
                              marqueur bénin revient dans la réponse (XXE in-band). JAMAIS /etc/passwd,
                              jamais un fichier système/credential.

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise (hérité de
      `ScopeGuardedOracle._in_scope` ; défense en profondeur, l'engine gate déjà en Couche 2).
  (2) PREUVE MINIMALE & BÉNIGNE : promotion `vulnerable` UNIQUEMENT sur preuve concrète (token OOB reçu
      OU marqueur bénin in-band renvoyé). Sinon `tested` (jamais de verdict à l'aveugle).
  (3) JAMAIS DE FICHIER SENSIBLE : un canari dont l'URL ressemble à un fichier système/credential est
      REFUSÉ avant tout réseau (`_is_sensitive` -> `skipped`). Marqueurs bénins seulement.
  (4) NON DESTRUCTIF : lecture/vérification seule (exploit=False, destructive=False) ; le plancher
      exploit/destructif du ROE reste OFF par défaut.
  (5) SESSION SECRÈTE : le matériel d'auth gouverné (SessionStore) est fusionné par `Oracle._http`
      UNIQUEMENT sur des URL in-scope et n'est JAMAIS journalisé/rapporté.
  (6) DÉGRADATION GRACIEUSE : réseau indisponible -> `skipped` (offline-safe).

Bâti sur `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP + curl partagés).
"""
import hashlib
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques

# Fragments de chemin SENSIBLES : un canari les visant est REFUSÉ (jamais de lecture de fichier système/
# credential via XXE). Volontairement conservateur — la preuve reste un marqueur BÉNIGN.
_SENSITIVE_HINTS = (
    "etc/passwd", "etc/shadow", "etc/hosts", "etc/group", "id_rsa", ".ssh", "win.ini", "boot.ini",
    "web.config", "proc/self", "proc/", "/root/", ".env", "credential", "secret", "private_key",
    "id_dsa", ".aws", ".git/", "wp-config", "database.yml", "settings.py",
)


@register("xxe.probe")
class XxeProbe(ScopeGuardedOracle):
    kind = "xxe.probe"
    exploit = False                      # sonde de VÉRIFICATION bénigne (marqueur bénin) -> non-exploit
    destructive = False                  # lecture/vérification seule : aucune mutation d'état
    web_allowed = True                   # interaction web (réseau) -> gardée par le ROE
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("xxe.probe")            # source de vérité : techniques.py (T1190)
    cwe = "CWE-611"                                       # category + cwe des findings
    tool = "forge/modules/xxe.py:xxe.probe"
    fix = ("Désactiver la résolution des entités externes et des DTD dans le parseur XML (secure "
           "processing / FEATURE_SECURE_PROCESSING, `disallow-doctype-decl`, entités externes off) ; "
           "valider/allowlister le XML entrant ; préférer des formats sans entités (JSON) là où possible ; "
           "ne jamais laisser un parseur résoudre une entité SYSTEM contrôlée par le client (CWE-611).")
    description = ("Oracle XXE à PREUVE BÉNIGNE : entité externe -> callback OOB opérateur (token reçu) "
                   "OU canari BÉNIGN non sensible (marqueur renvoyé). Refuse les fichiers sensibles. "
                   "Sinon tested. CWE-611.")

    @staticmethod
    def _token(target):
        """Token déterministe-par-cible (reproductible, distinctif) pour distinguer ce test côté collecteur."""
        return "forgexxe" + hashlib.sha1(f"{target}|forge-xxe".encode()).hexdigest()[:16]

    @staticmethod
    def _is_sensitive(url):
        """True si l'URL/chemin du canari vise un fichier système/credential (refusé avant tout réseau)."""
        low = str(url or "").lower()
        return any(h in low for h in _SENSITIVE_HINTS)

    @staticmethod
    def _xml(entity_url):
        """Payload XML BÉNIGN : DOCTYPE + entité externe SYSTEM -> `entity_url` ; le corps référence &x;."""
        return ('<?xml version="1.0" encoding="UTF-8"?>'
                f'<!DOCTYPE forge [<!ENTITY x SYSTEM "{entity_url}">]>'
                '<forge><probe>&x;</probe></forge>')

    def _send_xml(self, action, xml):
        """Émet le XML vers la cible : dans params.param (urlencodé) si fourni, sinon en corps brut
        (Content-Type application/xml). Renvoie (status, body). Les en-têtes explicites priment ; la
        session gouvernée scope-guardée est fusionnée SOUS eux par `Oracle._http`."""
        headers = dict(action.params.get("headers", {}))
        method = str(action.params.get("method", "POST")).upper()
        param = action.params.get("param")
        if param:
            if method == "GET":
                sep = "&" if "?" in action.target else "?"
                url = f"{action.target}{sep}{urllib.parse.urlencode({param: xml})}"
                return self._fetch(url, headers=headers, method="GET")
            return self._fetch(action.target, headers=headers, method=method,
                               data=urllib.parse.urlencode({param: xml}))
        headers.setdefault("Content-Type", "application/xml")
        return self._fetch(action.target, headers=headers, method=method, data=xml)

    def dry(self, action):
        modes = []
        if action.params.get("callback_base") and action.params.get("callback_check_url"):
            modes.append("OOB (entité -> collecteur opérateur, token reçu)")
        if action.params.get("canary_url") and action.params.get("canary_marker"):
            modes.append("canari in-band (marqueur bénin non sensible renvoyé)")
        return (f"# POST un XML BÉNIGN (DOCTYPE + entité SYSTEM) à {action.target} ; modes: "
                f"{' + '.join(modes) or '<non configuré>'} ; PREUVE = token OOB reçu OU marqueur bénin "
                f"in-band renvoyé ; JAMAIS de fichier sensible ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        cb_base = action.params.get("callback_base")
        cb_check = action.params.get("callback_check_url")
        canary_url = action.params.get("canary_url")
        canary_marker = action.params.get("canary_marker")
        oob = bool(cb_base and cb_check)
        inband = bool(canary_url and canary_marker)
        if not oob and not inband:
            return [self.skip(
                target=action.target, title="XXE non testé — config manquante",
                evidence=("Requiert un mode de preuve BÉNIGN : OOB (params.callback_base + "
                          "params.callback_check_url) OU canari in-band (params.canary_url + "
                          "params.canary_marker). Optionnel : params.param, params.method, params.headers."),
                poc=self.dry(action))]
        # (3) JAMAIS DE FICHIER SENSIBLE — un canari visant un fichier système/credential est REFUSÉ.
        if inband and self._is_sensitive(canary_url):
            return [self.skip(
                target=action.target, title="XXE non testé — canari sensible refusé (fail-closed)",
                evidence=(f"Le canari '{canary_url}' vise un fichier système/credential : REFUSÉ. Cet oracle "
                          f"n'utilise que des marqueurs BÉNINS non sensibles (aucune requête émise pour ce canari)."),
                poc=self.dry(action))]

        proven, proof_bits, seen_network = False, [], False

        # (a) mode canari IN-BAND : l'entité pointe vers un canari bénin ; le marqueur bénin revient-il ?
        if inband:
            st, body = self._send_xml(action, self._xml(canary_url))
            if st is not None:
                seen_network = True
                if canary_marker in (body or ""):
                    proven = True
                    proof_bits.append("marqueur bénin du canari renvoyé (XXE in-band)")

        # (b) mode OOB : l'entité pointe vers le collecteur opérateur ; le token a-t-il été reçu ?
        if oob and not proven:
            token = self._token(action.target)
            entity = f"{str(cb_base).rstrip('/')}/{token}"
            st, _ = self._send_xml(action, self._xml(entity))
            if st is not None:
                seen_network = True
            cs, cbody = self._fetch(cb_check, timeout=action.params.get("callback_timeout", 15), method="GET")
            if cs is not None:
                seen_network = True
            if cs == 200 and token in (cbody or ""):
                proven = True
                proof_bits.append("callback OOB reçu côté collecteur opérateur (entité externe résolue)")

        # (6) DÉGRADATION GRACIEUSE : aucune réponse (réseau indisponible) -> skipped (offline-safe).
        if not seen_network:
            return [self.degraded(
                target=action.target,
                title="XXE non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur ni du collecteur (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        return [self.proof(
            target=action.target, proven=proven,
            title=("XXE CONFIRMÉ — traitement d'entité externe XML prouvé par marqueur BÉNIGN"
                   if proven else "XXE non confirmé — entité externe non résolue (pas de verdict à l'aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"mode(s)={'OOB' if oob else ''}{'+' if oob and inband else ''}{'in-band' if inband else ''} ; "
                      f"preuve={'; '.join(proof_bits) if proof_bits else '—'} ; marqueur STRICTEMENT bénin "
                      f"(aucun fichier système/credential lu) ; non destructif ; session gouvernée non journalisée"),
            poc=(f"# POST à {action.target} un XML BÉNIGN : <!DOCTYPE forge [<!ENTITY x SYSTEM "
                 f"\"<MARQUEUR_BENIN|COLLECTEUR/{'<token>' if oob else '<canari>'}>\">]><forge>&x;</forge>\n"
                 f"# PREUVE = token OOB reçu côté collecteur OU marqueur bénin du canari renvoyé "
                 f"(JAMAIS /etc/passwd)"))]
