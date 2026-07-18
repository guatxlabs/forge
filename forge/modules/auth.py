"""auth.takeover — oracle ATO/auth-bypass à PREUVE (T1212 / CWE-287, CWE-640).

L'« account takeover théorique » est un classique vétoé. Cet oracle exige une PREUVE concrète :
après le flux de bypass/reset (réinitialisation de mot de passe, token prévisible, confusion de
session…), on s'authentifie et on lit un endpoint « whoami » (profil/session) — si l'identité
renvoyée est celle de la VICTIME (et non celle de l'attaquant), c'est un takeover prouvé. Sinon
-> `tested` (jamais `vulnerable` sur une intuition).

Mécanique générique (data-driven, aucune cible en dur) :
  1. l'attaquant exécute l'étape de bypass (params.bypass : method/url/body/headers) — ex: POST reset ;
  2. avec la session/headers obtenus (params.attacker_session_headers, éventuellement enrichis par
     l'étape 1 via un token extrait), on GET params.whoami_url ;
  3. PREUVE = le corps whoami contient l'identifiant VICTIME (params.victim_marker) ET PAS celui de
     l'attaquant (params.attacker_marker, optionnel) -> takeover confirmé.

exploit=True (prend le contrôle du compte d'autrui) -> exige allow_exploit. destructive selon le flux
(un reset de mot de passe MUTE le compte victime) : exposé via params.destructive (défaut True pour le
reset). web_allowed via le ROE. Bâti sur la base `Oracle` (Finding + HTTP + curl partagés).
"""
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .. import techniques
from ..redact import redact_secrets


@register("auth.takeover")
class AuthTakeover(ScopeGuardedOracle):
    kind = "auth.takeover"
    exploit = True                       # obtient la session/identité d'autrui -> allow_exploit
    destructive = True                   # un reset/forge de credential MUTE le compte victime -> allow_destructive
    web_allowed = True
    available = True                     # urllib stdlib
    mitre = techniques.mitre_for("auth.takeover")   # source de vérité : forge/techniques.py (T1212)
    cwe = "CWE-287"                      # category + cwe des findings (via Oracle.proof/skip)
    tool = "forge/modules/auth.py:auth.takeover"
    fix = ("Renforcer l'authentification et le flux de reset : tokens de réinitialisation aléatoires "
           "(CSPRNG), à usage unique, liés au compte et à durée de vie courte ; invalider/relancer "
           "toutes les sessions après un reset ; MFA sur les actions sensibles ; ne jamais dériver "
           "l'identité d'un état contrôlable côté client (CWE-287/640).")
    description = ("Oracle ATO/auth-bypass à PREUVE : après le flux de bypass, le whoami renvoie-t-il "
                  "l'identité de la VICTIME ? Sinon tested (pas de takeover théorique). CWE-287/640.")

    @staticmethod
    def _fetch(url, headers=None, timeout=15, method="GET", data=None):
        """(status, body, headers_dict) — adosse le câblage urllib partagé (Oracle._http).
        Seam monkeypatché par les tests."""
        st, body, h = Oracle._http(url, headers=headers, timeout=timeout, method=method, data=data, maxlen=200000)
        return st, body, (dict(h) if h is not None else {})

    def dry(self, action):
        p = action.params
        bp = p.get("bypass", {})
        return (f"# 1) {str(bp.get('method', 'POST')).upper()} {bp.get('url', '<bypass>')} "
                f"(flux de bypass attaquant)\n"
                f"# 2) GET {p.get('whoami_url', '<whoami>')} avec la session attaquant\n"
                f"# PREUVE = whoami contient le marqueur VICTIME ({p.get('victim_marker', '<victime>')}) "
                f"-> takeover ; sinon tested")

    @staticmethod
    def _attacker_headers(accounts):
        """En-têtes du compte ATTAQUANT parmi les comptes LABELLISÉS (R5b) : le compte 'attacker' si
        présent, sinon le 1er (convention). None si aucun compte. Chaque compte = {label, headers}.
        Miroir EXACT de `IdorDifferential._attacker_headers` (les deux oracles consomment le même
        `AuthContext.accounts` — SOURCE unique de la convention de labels)."""
        if not accounts:
            return None
        for a in accounts:
            if str(a.get("label", "")).strip().lower() == "attacker":
                return a.get("headers", {}) or {}
        return accounts[0].get("headers", {}) or {}

    def _fire_auth_context(self, action, accounts, targets):
        """R5b — SLICE ATO/TAKEOVER via CONTEXTE AUTH PAR-ENGAGEMENT. La session de l'ATTAQUANT (compte
        de l'opérateur) rejoue chaque idor_target {url, owner, marker} (endpoint whoami/profil) ; PREUVE
        NETTE d'un takeover cross-compte = le MARQUEUR D'IDENTITÉ de la victime (`marker`) apparaît dans
        SA réponse authentifiée (2xx) — l'identité renvoyée est celle d'un AUTRE utilisateur, pas la
        sienne. Sans marqueur -> pas de signal d'identité, on ne CONFIRME jamais (skip, anti-faux-positif :
        jamais « n'importe quel 200 »). Lecture seule (GET). Scope-guard fail-closed PAR-URL (aucune
        requête hors périmètre). Le PoC/evidence est RÉDIGÉ à la source (les en-têtes de l'attaquant
        portent le matériel d'auth SECRET — masqué AVANT de figer dans le finding, ledger inclus)."""
        attacker = self._attacker_headers(accounts)
        findings = []
        for t in targets:
            url = (t or {}).get("url")
            if not url:
                continue
            marker = str((t or {}).get("marker") or "")
            owner = str((t or {}).get("owner") or "victim")
            # SCOPE-GUARD PAR-URL fail-closed — une cible hors périmètre : AUCUN I/O vers elle (le
            # matériel d'auth secret ne peut physiquement pas quitter le périmètre déclaré).
            if not self._in_scope(action, url):
                findings.append(self.degraded(
                    target=url,
                    title="ATO non testé — idor_target hors périmètre (scope-guard fail-closed)",
                    evidence="Cette cible n'est pas in-scope ; aucune requête émise (fail-closed).",
                    poc=self.dry(action)))
                continue
            if attacker is None:
                findings.append(self.skip(
                    target=url, title="ATO non testé — compte attaquant manquant",
                    evidence=("Requiert au moins un compte (auth.accounts) fournissant les en-têtes de "
                              "l'attaquant pour rejouer la requête cross-compte."),
                    poc=self.dry(action)))
                continue
            if not marker:
                # sans marqueur d'identité victime, aucune PREUVE de takeover possible (un 2xx seul ne
                # prouve pas que l'identité renvoyée est celle d'AUTRUI) -> jamais confirmé.
                findings.append(self.skip(
                    target=url, title="ATO non testé — marqueur d'identité victime manquant",
                    evidence=("Requiert un `marker` (identifiant unique de la victime attendu dans la "
                              "réponse) pour prouver que la session attaquant renvoie l'identité d'AUTRUI."),
                    poc=self.dry(action)))
                continue
            ws, wbody, _ = self._fetch(url, headers=attacker)
            att_ok = ws in (200, 206)
            marker_hit = att_ok and (marker in (wbody or ""))
            # PREUVE : session attaquant 2xx ET marqueur d'identité VICTIME présent dans SA réponse
            # (identity-of-another-user). Jamais « n'importe quel 200 » (marqueur requis ci-dessus).
            proven = marker_hit
            poc = redact_secrets(self._curl(url, attacker))
            evidence = redact_secrets(
                f"attaquant={ws} marqueur_victime={'présent' if marker_hit else 'absent'} "
                f"owner={owner!r} ; preuve=identité de la victime renvoyée à la session de l'attaquant ; "
                "compte attaquant DÉTENU par l'opérateur (jamais un tiers) ; matériel d'auth rédigé")
            findings.append(self.proof(
                target=url, proven=proven,
                title=("ATO CONFIRMÉ — la session attaquant renvoie l'identité de la VICTIME (cross-compte)"
                       if proven else "ATO non confirmé — la réponse ne porte pas l'identité victime"),
                severity=("CRITICAL" if proven else "INFO"),
                evidence=evidence, poc=poc))
        return findings

    def fire(self, action):
        # SCOPE-GUARD fail-closed sur la cible primaire — hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        p = action.params
        # CONTEXTE AUTH PAR-ENGAGEMENT (R5b) : comptes LABELLISÉS + idor_targets structurés injectés par
        # l'engine (mêmes que l'IDOR). La session de l'attaquant rejoue chaque cible ; un takeover est
        # prouvé si le marqueur d'IDENTITÉ de la victime revient. Ne consomme QUE le compte attaquant.
        # ABSENT => chemin config-driven historique (whoami_url/victim_marker), byte-identique.
        auth_accounts = p.get("accounts")
        auth_targets = p.get("idor_targets")
        if auth_accounts and auth_targets:
            return self._fire_auth_context(action, auth_accounts, list(auth_targets))
        whoami = p.get("whoami_url")
        victim = p.get("victim_marker")
        sess = dict(p.get("attacker_session_headers", {}))
        if not whoami or not victim:
            return [self.skip(
                target=action.target, title="ATO non testé — config manquante",
                evidence=("Requiert params.whoami_url (endpoint profil/session) et params.victim_marker "
                          "(identifiant unique de la victime attendu dans le whoami). "
                          "Optionnel : params.bypass (étape de bypass), params.attacker_marker."),
                poc=self.dry(action))]
        # SCOPE-GUARD PAR-URL fail-closed — whoami/bypass sont des URL dérivées de params : on ne tire
        # (et surtout on n'attache la session attaquant) que si elles sont IN-SCOPE.
        bp = p.get("bypass")
        for u in (whoami, (bp or {}).get("url")):
            if u and not self._in_scope(action, u):
                return [self.degraded(
                    target=u,
                    title="ATO non testé — URL (whoami/bypass) hors périmètre (scope-guard fail-closed)",
                    evidence="L'URL whoami/bypass n'est pas in-scope ; aucune requête émise (fail-closed).",
                    poc=self.dry(action))]
        # le flag destructif réel suit le flux : un GET-only n'est pas destructif, un reset l'est.
        # On NE modifie PAS self.destructive (déclaration de capacité, lue par le ROE avant fire) — c'est
        # le module qui est gardé `destructive=True` par prudence (un reset MUTE la victime).
        if bp and bp.get("url"):
            self._fetch(bp["url"], headers=bp.get("headers", {}),
                        method=str(bp.get("method", "POST")).upper(),
                        data=(urllib.parse.urlencode(bp["body"]) if isinstance(bp.get("body"), dict)
                              else bp.get("body")))
        ws, wbody, _ = self._fetch(whoami, headers=sess)
        attacker = p.get("attacker_marker")
        # PREUVE NETTE : whoami accordé (2xx), contient le marqueur VICTIME, et — si fourni — PAS celui
        # de l'attaquant (sinon on regarde juste sa propre session : faux positif classique).
        is_victim = (ws in (200, 206) and victim in (wbody or "")
                     and (attacker is None or attacker not in (wbody or "")))
        return [self.proof(
            target=whoami, proven=is_victim,
            title=("ATO CONFIRMÉ — la session attaquant lit l'identité de la VICTIME"
                   if is_victim else "ATO non confirmé — whoami ne renvoie pas l'identité victime"),
            severity=("CRITICAL" if is_victim else "INFO"),
            evidence=(f"whoami HTTP {ws} ; victim_marker_présent={victim in (wbody or '')} ; "
                      f"attacker_marker_absent={attacker is None or attacker not in (wbody or '')} "
                      f"(extrait={(wbody or '')[:120]!r})"),
            poc=self._curl(whoami, sess))]
