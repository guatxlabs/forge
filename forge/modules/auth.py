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
# R7 — réutilise la NORMALISATION/HASH de corps de l'oracle IDOR (source unique, cf. reference pattern
# access_control._fire_auth_targets) pour le signal « différentiel de contenu victime-vs-attaquant » :
# on compare la STRUCTURE/DONNÉE (CSRF/nonce/horodatages retirés), pas le bruit de session. Import de
# fonctions pures, module NON modifié (auth.py ne dépend de rien qui réimporte auth -> aucun cycle).
from .access_control import _normalize_body, _body_hash
from .. import techniques
from .. import session as _session
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
        """En-têtes du compte ATTAQUANT (labellisé 'attacker' sinon le 1er). DÉLÈGUE à la SOURCE UNIQUE
        `session.attacker_headers_from_params` — même sélection byte-identique que IdorDifferential (les
        deux oracles consomment le même `AuthContext.accounts` sérialisé)."""
        return _session.attacker_headers_from_params(accounts)

    @staticmethod
    def _attacker_label(accounts):
        """Le LABEL du compte attaquant (miroir de `_attacker_headers` : compte 'attacker' si présent,
        sinon le 1er). Sert au garde anti-faux-positif du signal status-delta : on ne flag JAMAIS
        l'attaquant lisant SA PROPRE ressource (owner == label attaquant)."""
        if not accounts:
            return ""
        for a in accounts:
            if str(a.get("label", "")).strip().lower() == "attacker":
                return str(a.get("label", "")).strip()
        return str(accounts[0].get("label", "")).strip()

    @staticmethod
    def _account_headers(accounts, label):
        """En-têtes du compte LABELLISÉ `label` (insensible à la casse), ou None si absent. Sert à
        récupérer la vue authentifiée du PROPRIÉTAIRE (victime) pour le différentiel de contenu."""
        if not accounts or not label:
            return None
        lo = str(label).strip().lower()
        for a in accounts:
            if str(a.get("label", "")).strip().lower() == lo:
                return a.get("headers", {}) or {}
        return None

    def _fire_auth_context(self, action, accounts, targets):
        """R5b + R7 — SLICE ATO/TAKEOVER via CONTEXTE AUTH PAR-ENGAGEMENT. La session de l'ATTAQUANT
        (compte de l'opérateur) rejoue chaque idor_target {url, owner, marker} (endpoint whoami/profil)
        et l'on CONFIRME un takeover cross-compte sur N'IMPORTE LEQUEL de ces signaux à faible taux de
        faux positifs, l'evidence NOMMANT lequel a tiré :

          (A) MARQUEUR D'IDENTITÉ VICTIME (R5b, conservé) : le `marker` de la victime apparaît dans la
              réponse authentifiée (2xx) de l'attaquant — l'identité renvoyée est celle d'AUTRUI.
          (B) STATUS-DELTA (R7) : l'attaquant obtient un 2xx là où un CONTRÔLE ANONYME est refusé
              (401/403) sur une ressource dont le PROPRIÉTAIRE n'est PAS l'attaquant (owner ≠ label
              attaquant) — la ressource est bien contrôlée en accès et un AUTRE utilisateur l'atteint.
              Le garde owner≠attaquant interdit de flagger l'attaquant lisant SA PROPRE ressource.
          (C) DIFFÉRENTIEL DE CONTENU VICTIME-vs-ATTAQUANT (R7, le plus fort — exige un compte VICTIME
              configuré) : on lit la cible AVEC la session VICTIME/PROPRIÉTAIRE ET avec celle de
              l'attaquant ; si le corps NORMALISÉ non vide de l'attaquant est IDENTIQUE à la vue
              authentifiée de la victime ET DIFFÈRE de la vue anonyme -> l'attaquant voit la donnée
              PRIVÉE de la victime (exposition cross-compte). Jamais « les deux en 200 » : il faut un
              discriminant concret (même contenu privé que la victime, absent de la vue anonyme).

        Anti-faux-positif : un 200 public (que voit aussi l'anonyme) ne tire AUCUN signal ; la ressource
        que l'attaquant possède légitimement (owner == attaquant) ne tire ni (B) ni (C).
        ⚠️ LIMITATION résiduelle (partagé-autorisé) : (B)/(C) ne distinguent pas « l'attaquant n'est PAS
        habilité » de « attaquant et victime sont TOUS DEUX légitimement habilités à une ressource
        PARTAGÉE » (doc d'équipe protégée de l'anonyme) : le status-delta et le corps identique-victime
        se produisent aussi. Contrat : les `idor_target` (`url`/`owner`/`marker`) DOIVENT désigner des
        ressources PRIVÉES à la victime auxquelles l'attaquant n'a AUCUN droit ; le `marker` d'identité
        victime UNIQUE (voie A, préféré) prouve l'usurpation d'identité et évite ce faux positif. Lecture seule
        (GET). Scope-guard fail-closed PAR-URL (aucune requête — victime, attaquant, anonyme — hors
        périmètre). Le PoC/evidence est RÉDIGÉ à la source (les en-têtes portent le matériel d'auth
        SECRET — masqué AVANT de figer dans le finding, ledger inclus)."""
        attacker = self._attacker_headers(accounts)
        attacker_label = self._attacker_label(accounts)
        findings = []
        for t in targets:
            url = (t or {}).get("url")
            if not url:
                continue
            marker = str((t or {}).get("marker") or "")
            owner = str((t or {}).get("owner") or "victim")
            # SCOPE-GUARD PAR-URL fail-closed — une cible hors périmètre : AUCUN I/O vers elle (le
            # matériel d'auth secret ne peut physiquement pas quitter le périmètre déclaré). UNE seule
            # vérif couvre les trois variantes d'en-têtes (victime/attaquant/anonyme) : même URL.
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
            owner_diff = owner.strip().lower() != str(attacker_label).strip().lower()

            # --- SONDES (in-scope) : attaquant + contrôle anonyme (toujours) ; propriétaire (si compte) ---
            ws, wbody, _ = self._fetch(url, headers=attacker)
            anon_s, anon_body, _ = self._fetch(url, headers={})
            att_ok = ws in (200, 206)
            anon_denied = anon_s in (401, 403)

            # (A) marqueur d'identité victime dans la réponse authentifiée de l'attaquant.
            sig_marker = bool(marker) and att_ok and (marker in (wbody or ""))
            # (B) status-delta : attaquant 2xx / anon refusé, sur une ressource d'un AUTRE user.
            #     CORROBORATEUR FAIBLE, JAMAIS PROMOUVANT : owner_diff est un compare de LABELS
            #     (owner "victim" ≠ label "attacker") et AUCUNE requête n'est faite avec la session du
            #     PROPRIÉTAIRE — ce signal se réduit donc à « attaquant 2xx ET anon refusé », VRAI pour
            #     tout endpoint per-user que l'attaquant possède LÉGITIMEMENT (/api/me, /api/settings).
            #     Il ne démontre AUCUN accès cross-compte -> il n'entre PAS dans la promotion (jadis il
            #     suffisait à un faux CRITICAL « ATO CONFIRMÉ » sur un accès à sa propre ressource).
            sig_status = att_ok and anon_denied and owner_diff
            # (C) différentiel de contenu vs la vue authentifiée du PROPRIÉTAIRE (victime).
            sig_content = False
            owner_status = None
            owner_headers = self._account_headers(accounts, owner)
            if owner_headers is None:                 # repli : compte 'victim' explicite
                owner_headers = self._account_headers(accounts, "victim")
            if owner_diff and owner_headers is not None and owner_headers != attacker:
                owner_status, owner_body, _ = self._fetch(url, headers=owner_headers)
                owner_ok = owner_status in (200, 206)
                att_norm = _normalize_body(wbody)
                sig_content = bool(
                    att_ok and owner_ok and att_norm
                    and _body_hash(wbody) == _body_hash(owner_body)          # attaquant voit la vue victime
                    and _body_hash(wbody) != _body_hash(anon_body))          # ... absente de la vue anonyme

            # SEULS les signaux SAINS (impliquant la donnée/session du PROPRIÉTAIRE) PROMEUVENT :
            # (A) marqueur d'identité victime, (C) différentiel de contenu à session propriétaire. Le
            # status-delta (B) reste un corroborateur FAIBLE nommé dans l'evidence, jamais promouvant.
            sound = [name for name, hit in (("marqueur-identité-victime", sig_marker),
                                            ("content-differential", sig_content)) if hit]
            proven = bool(sound)
            signals = "+".join(sound) if sound else "aucun"
            poc = redact_secrets(self._curl(url, attacker))
            evidence = redact_secrets(
                f"attaquant={ws} anon={anon_s}"
                + (f" propriétaire={owner_status}" if owner_status is not None else "")
                + f" owner={owner!r} owner≠attaquant={owner_diff} ; "
                f"marqueur={'présent' if sig_marker else 'absent'} "
                f"status-delta={sig_status} (corroborateur faible, non-promouvant) "
                f"content-differential={sig_content} ; signal(s) promouvant(s)={signals} ; "
                "comptes (attaquant/victime) DÉTENUS par l'opérateur (jamais un tiers) ; "
                "matériel d'auth rédigé")
            if proven:
                title = f"ATO CONFIRMÉ (cross-compte) — signal(s) : {signals}"
                severity = "CRITICAL"
            elif sig_status:
                title = ("ATO non confirmé — endpoint requiert une auth ; accès cross-compte NON prouvé "
                         "(ni marqueur victime, ni différentiel propriétaire)")
                severity = "INFO"
            else:
                title = "ATO non confirmé — aucun signal cross-compte concluant"
                severity = "INFO"
            findings.append(self.proof(
                target=url, proven=proven,
                title=title,
                severity=severity,
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
