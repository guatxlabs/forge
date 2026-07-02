"""Registre unique de techniques / taxonomie — LA SOURCE DE VÉRITÉ (stdlib only, zéro dépendance).

Avant ce module, la même donnée « technique » (ATT&CK, CWE, classe de vuln, caractère qualifiant,
remédiation) était recopiée et DÉRIVAIT dans quatre endroits :
  - chaque module (ses chaînes `kind` / `mitre` / `cwe`),
  - `planner.py`  (l'ensemble QUALIFYING + DEFAULT_CHECKLIST),
  - `brain.py`    (les affectations par kind `Action(cls=..., exploit=...)`),
  - `schema.py`   (le dict de remédiation DEFAULT_FIXES),
  - `purple.py`   (le repli ATT&CK par kind DEFAULT_MITRE_BY_KIND).

Ici, une seule table `TECHNIQUES` mappe une CLÉ (kind de module OU jeton de classe OU clé CWE) vers un
enregistrement `Technique`. Les autres fichiers DÉRIVENT leurs vues de cette table :
  - schema.DEFAULT_FIXES         = {clé: remediation}    pour toute clé avec remédiation ;
  - planner.QUALIFYING           = {clé}                 pour toute clé qualifiante ;
  - brain (cls/exploit par kind) = action_class(kind) / action_exploit(kind) ;
  - purple.DEFAULT_MITRE_BY_KIND = mitre_by_kind()       (repli par kind, sous-ensemble curé) ;
  - modules (mitre/cwe)          = TECHNIQUES[kind].mitre / .cwe.

Trois espaces de clés cohabitent SANS collision dans la même table :
  - les *kinds* de module contiennent un point (`ssrf.callback`, `access_control.idor`, `web.nuclei`) ;
  - les *jetons de classe* planner sont des mots simples (`ssrf`, `access_control`, `auth`, `biz`…) ;
  - les *clés CWE* de remédiation sont préfixées (`cwe-918`, `cwe-639`…).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    """Un enregistrement de technique. Tous les champs sont optionnels — une clé n'active que les
    vues pertinentes (ex : une clé CWE ne porte que `remediation` ; un kind porte `mitre`/`cwe`/`cls`)."""
    key: str
    cls: str = ""              # classe planner (override brain) ; "" => Action dérive du suffixe du kind
    cwe: str = ""              # CWE canonique (ex "CWE-918") — category+cwe des findings d'oracle
    mitre: str = ""            # ATT&CK id (badge module + repli purple)
    exploit: bool = False      # capacité exploit (déclaration module + flag Action du brain)
    qualifying: bool = False   # classe qualifiante -> plancher anti-starvation du planner
    remediation: str = ""      # repli de remédiation (schema.DEFAULT_FIXES)


def _t(key, **kw):
    return Technique(key=key, **kw)


# --- Remédiations verbatim (identiques à l'ancien schema.DEFAULT_FIXES — NE PAS reformuler) ---
_R_CWE639 = ("Contrôle d'ownership côté serveur : vérifier que l'utilisateur authentifié possède "
             "bien la ressource (objet lié au compte) avant tout accès ; ne jamais se fier à un "
             "identifiant fourni par le client. Préférer des identifiants non énumérables (UUID).")
_R_CWE284 = ("Appliquer un contrôle d'accès systématique côté serveur (deny-by-default) sur chaque "
             "endpoint et chaque objet ; centraliser l'autorisation, ne pas la dériver du client.")
_R_CWE862 = ("Ajouter une vérification d'autorisation manquante sur l'endpoint : exiger une session "
             "valide ET vérifier les droits sur la ressource ciblée avant de répondre.")
_R_IDOR = ("Contrôle d'ownership côté serveur avant tout accès à la ressource ; identifiants non "
           "énumérables (UUID) et autorisation centralisée deny-by-default.")
_R_ACCESS = ("Contrôle d'accès deny-by-default côté serveur sur chaque endpoint/objet ; "
             "ne jamais dériver l'autorisation d'un identifiant fourni par le client.")
_R_BOLA = ("Vérifier l'ownership de l'objet côté serveur (Broken Object Level Authorization) avant "
           "de servir ou muter la ressource.")
_R_CWE918 = ("Allowlist stricte des hôtes/schemas autorisés côté serveur ; bloquer les IP internes "
             "(RFC1918, loopback, link-local) et les endpoints de métadonnées cloud (169.254.169.254) ; "
             "résoudre puis re-valider l'IP (anti-DNS-rebinding), désactiver les redirections.")
_R_SSRF = ("Allowlist d'hôtes/schemas, blocage des IP internes et des métadonnées cloud "
           "(169.254.169.254), re-validation post-résolution DNS, pas de suivi de redirection.")
_R_CWE287 = ("Renforcer l'authentification : invalider les sessions après reset, tokens de reset "
             "à usage unique liés à l'utilisateur et à durée de vie courte, MFA sur les actions "
             "sensibles ; ne jamais accepter un état d'auth dérivable côté client.")
_R_CWE640 = ("Sécuriser le flux de réinitialisation : token aléatoire imprévisible (CSPRNG), à usage "
             "unique, lié au compte et expirant rapidement ; ne pas divulguer la validité du compte.")
_R_AUTH = ("Authentification serveur robuste : sessions invalidées au reset, tokens à usage unique, "
           "MFA sur actions sensibles ; aucun état d'auth dérivable côté client.")
_R_ATO = ("Bloquer la prise de contrôle de compte : tokens de reset à usage unique liés au compte, "
          "rotation de session, MFA, et détection des anomalies de connexion.")
_R_CWE942 = ("Ne JAMAIS combiner Access-Control-Allow-Origin: * (ou reflet d'origine arbitraire) avec "
             "Access-Control-Allow-Credentials: true. Refléter uniquement des origines d'une allowlist "
             "stricte et n'autoriser les credentials que pour ces origines de confiance.")
_R_CWE346 = ("Valider strictement l'origine (allowlist exacte, pas de reflet d'Origin arbitraire) "
             "avant d'autoriser une lecture cross-origin authentifiée.")
_R_CORS = ("Allowlist d'origines stricte ; ne pas refléter une Origin arbitraire avec "
           "Access-Control-Allow-Credentials: true (combinaison non exploitable mais à proscrire).")
_R_ORIGIN = ("Restreindre l'accès à l'IP d'origine au seul CDN/WAF : allowlist des plages IP "
             "du fournisseur (Cloudflare) au niveau pare-feu/groupe de sécurité, refuser tout "
             "trafic direct ; rendre l'origine non joignable hors du CDN.")
_R_CWE89 = ("Requêtes paramétrées / ORM avec liaison des variables ; jamais de concaténation de "
            "données utilisateur dans une requête SQL ; principe du moindre privilège sur le compte DB.")
_R_SQLI = ("Requêtes paramétrées (prepared statements), validation/échappement, moindre privilège DB.")
_R_CWE79 = ("Échapper/encoder la sortie selon le contexte (HTML/attribut/JS/URL) ; CSP stricte ; "
            "préférer des frameworks qui encodent par défaut ; valider les entrées en allowlist.")
_R_XSS = ("Encodage contextuel de la sortie, CSP stricte, frameworks auto-échappants, validation "
          "d'entrée en allowlist.")
_R_CWE78 = ("Éviter l'exécution de commandes shell avec des données utilisateur ; utiliser des APIs "
            "natives ; si inévitable, allowlist d'arguments et exécution sans shell (execve).")
_R_CWE352 = ("Jeton anti-CSRF par requête mutante + cookies SameSite=Lax/Strict ; vérifier l'en-tête "
             "Origin/Referer sur les actions sensibles.")
_R_CSRF = ("Token anti-CSRF par requête mutante, cookies SameSite, vérification Origin/Referer.")
_R_CWE918_BLIND = ("Allowlist + blocage métadonnées/IP internes (voir CWE-918).")


# --- La table unique -------------------------------------------------------------------------------
# Ordre : (1) kinds de module, (2) jetons de classe qualifiants, (3) clés CWE / classes de remédiation.
TECHNIQUES = {t.key: t for t in [
    # (1) KINDS de module — mitre (badge/purple), cwe (category+cwe des findings), cls/exploit (brain).
    #     `cls` = override de classe planner pour le brain ("" => Action dérive du suffixe du kind).
    _t("access_control.idor", cls="access_control", cwe="CWE-639", mitre="T1190", exploit=True),
    _t("ssrf.callback",       cls="ssrf",           cwe="CWE-918", mitre="T1190", exploit=True),
    _t("auth.takeover",       cls="auth",           cwe="CWE-287", mitre="T1212", exploit=True),
    _t("cors.credentials",    cls="access_control", cwe="CWE-942", mitre="T1539", exploit=True),
    _t("web.nuclei",          mitre="T1595.002"),
    _t("origin.find",         mitre="T1590.005"),
    _t("recon.httpx",         mitre="T1595"),
    _t("recon.nmap",          mitre="T1046"),
    _t("demo.fingerprint",    mitre="T1595"),

    # (2) JETONS de classe QUALIFIANTS (plancher planner). Certains portent aussi une remédiation.
    _t("idor",           qualifying=True, remediation=_R_IDOR),
    _t("bola",           qualifying=True, remediation=_R_BOLA),
    _t("access_control", qualifying=True, remediation=_R_ACCESS),
    _t("auth",           qualifying=True, remediation=_R_AUTH),
    _t("auth_bypass",    qualifying=True),
    _t("ato",            qualifying=True, remediation=_R_ATO),
    _t("rce",            qualifying=True),
    _t("sqli",           qualifying=True, remediation=_R_SQLI),
    _t("ssrf",           qualifying=True, remediation=_R_SSRF),
    _t("business_logic", qualifying=True),
    _t("biz",            qualifying=True),
    _t("privesc",        qualifying=True),

    # (3) CLÉS CWE / classes de remédiation (repli fix — non qualifiantes).
    _t("cwe-639",       remediation=_R_CWE639),
    _t("cwe-284",       remediation=_R_CWE284),
    _t("cwe-862",       remediation=_R_CWE862),
    _t("cwe-918",       remediation=_R_CWE918),
    _t("cwe-287",       remediation=_R_CWE287),
    _t("cwe-640",       remediation=_R_CWE640),
    _t("cwe-942",       remediation=_R_CWE942),
    _t("cwe-346",       remediation=_R_CWE346),
    _t("cors",          remediation=_R_CORS),
    _t("origin-exposure", remediation=_R_ORIGIN),
    _t("cwe-89",        remediation=_R_CWE89),
    _t("cwe-79",        remediation=_R_CWE79),
    _t("xss",           remediation=_R_XSS),
    _t("cwe-78",        remediation=_R_CWE78),
    _t("cwe-352",       remediation=_R_CWE352),
    _t("csrf",          remediation=_R_CSRF),
    _t("cwe-918-blind", remediation=_R_CWE918_BLIND),
]}

# checklist par défaut = ce qu'on veut couvrir sur une cible web (ordre = priorité hacktivity).
# Constante ordonnée (non dérivable des flags) — vit ici pour rester la source unique côté planner.
DEFAULT_CHECKLIST = ["access_control", "auth", "ato", "ssrf", "sqli", "rce", "business_logic"]

# Sous-ensemble curé de kinds pour le repli purple (identique à l'ancien purple.DEFAULT_MITRE_BY_KIND).
# Ce n'est PAS « tous les kinds à point » : evasion/msf/burp n'ont jamais eu de repli purple.
PURPLE_FALLBACK_KINDS = (
    "demo.fingerprint", "recon.httpx", "recon.nmap", "web.nuclei", "access_control.idor",
    "ssrf.callback", "auth.takeover", "cors.credentials", "origin.find",
)


# --- Vues dérivées ---------------------------------------------------------------------------------
def remediation_map():
    """Dict clé -> remédiation (== l'ancien schema.DEFAULT_FIXES). Toute clé avec `remediation`."""
    return {k: t.remediation for k, t in TECHNIQUES.items() if t.remediation}


def qualifying_classes():
    """Ensemble des jetons de classe qualifiants (== l'ancien planner.QUALIFYING)."""
    return {k for k, t in TECHNIQUES.items() if t.qualifying}


def mitre_by_kind():
    """Repli ATT&CK par kind (== l'ancien purple.DEFAULT_MITRE_BY_KIND). Sous-ensemble curé."""
    return {k: TECHNIQUES[k].mitre for k in PURPLE_FALLBACK_KINDS}


def action_class(kind):
    """Classe planner à passer au brain pour ce kind ("" si aucune override -> Action dérive le suffixe)."""
    t = TECHNIQUES.get(kind)
    return t.cls if t else ""


def action_exploit(kind):
    """Flag exploit à passer au brain pour ce kind (False si inconnu)."""
    t = TECHNIQUES.get(kind)
    return bool(t.exploit) if t else False


def mitre_for(kind):
    """ATT&CK id d'un kind ("" si inconnu)."""
    t = TECHNIQUES.get(kind)
    return t.mitre if t else ""


def cwe_for(kind):
    """CWE canonique d'un kind ("" si inconnu)."""
    t = TECHNIQUES.get(kind)
    return t.cwe if t else ""
