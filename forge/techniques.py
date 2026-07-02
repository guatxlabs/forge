"""Registre unique de techniques / taxonomie — LA SOURCE DE VÉRITÉ (stdlib only, zéro dépendance).

Avant ce module, la même donnée « technique » (ATT&CK, CWE, classe de vuln, caractère qualifiant,
remédiation) était recopiée et DÉRIVAIT dans quatre endroits :
  - chaque module (ses chaînes `kind` / `mitre` / `cwe`),
  - `planner.py`  (l'ensemble QUALIFYING + DEFAULT_CHECKLIST),
  - `brain.py`    (les affectations par kind `Action(cls=..., exploit=...)`),
  - `schema.py`   (le dict de remédiation DEFAULT_FIXES),
  - `purple.py`   (le repli ATT&CK par kind DEFAULT_MITRE_BY_KIND).

Ici, une table `TECHNIQUES` mappe une CLÉ (kind de module OU jeton de classe OU clé CWE) vers un
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

CATALOGUE ATT&CK STRUCTURÉ (LOT SURFACE) — chaque enregistrement porte désormais des champs
structurés additifs : `attck_tactic` (tactique ATT&CK lisible), `phase` (recon | access | exploit),
`capability` (passive | active | exploit) et `proof_required` (une promotion au-delà de
`status=tested` EXIGE une preuve concrète). Ces champs sont OPTIONNELS : un alias de classe/CWE les
laisse vides (ce ne sont pas des « techniques de module »), un kind de module les porte.

DEUX TABLES, UN CATALOGUE — pour garantir l'invariance BYTE-À-BYTE des vues dérivées historiques :
  - `TECHNIQUES` = le noyau HÉRITÉ (classes de vuln, clés CWE, kinds de modules LIVRÉS). Son ensemble
    de clés est FIGÉ : les vues `remediation_map()` / `qualifying_classes()` / `mitre_by_kind()`
    l'itèrent et restent donc identiques au pré-refactor (aucune clé surface ne peut les polluer).
  - `SURFACE` = les entrées de cartographie de surface d'attaque (métadonnées seules ; le code des
    modules arrive dans des slices ultérieures). Chaque entrée a `phase="recon"`, une `capability`
    passive/active, un `mitre` ATT&CK, et une remédiation propre — SANS jamais entrer dans le map de
    remédiation des vulns (elle vit hors de `TECHNIQUES`).
  - `CATALOG = {**TECHNIQUES, **SURFACE}` = le catalogue consolidé et ÉLARGI : le squelette dans
    lequel les nouveaux modules s'enregistrent et que les vues `by_phase()`/`by_capability()`/
    `by_tactic()` exposent. Les résolveurs `mitre_for()`/`cwe_for()`/`action_*()` l'interrogent
    (superset de `TECHNIQUES` : identique pour toute clé héritée, résout en plus les kinds surface).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    """Un enregistrement de technique. Tous les champs sont optionnels — une clé n'active que les
    vues pertinentes (ex : une clé CWE ne porte que `remediation` ; un kind porte `mitre`/`cwe`/`cls`
    et, pour le catalogue de surface, `attck_tactic`/`phase`/`capability`/`proof_required`)."""
    key: str
    cls: str = ""              # classe planner (override brain) ; "" => Action dérive du suffixe du kind
    cwe: str = ""              # CWE canonique (ex "CWE-918") — category+cwe des findings d'oracle
    mitre: str = ""            # ATT&CK id (badge module + repli purple)
    exploit: bool = False      # capacité exploit (déclaration module + flag Action du brain)
    qualifying: bool = False   # classe qualifiante -> plancher anti-starvation du planner
    remediation: str = ""      # repli de remédiation (schema.DEFAULT_FIXES)
    attck_tactic: str = ""     # tactique ATT&CK lisible (ex "Reconnaissance", "Initial Access")
    phase: str = ""            # phase d'engagement : recon | access | exploit ("" = alias non-phasé)
    capability: str = ""       # capacité : passive | active | exploit ("" = alias non-phasé)
    proof_required: bool = False  # promotion au-delà de status=tested EXIGE une preuve concrète


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

# --- Remédiations du catalogue de SURFACE D'ATTAQUE (nouvelles ; hors du map de remédiation vuln) ---
# Ces conseils accompagnent les entrées `SURFACE` : réduire l'exposition, non « corriger une vuln ».
_R_SURFACE = ("Réduire la surface exposée : maintenir un inventaire à jour des sous-domaines, "
              "retirer/désactiver les enregistrements DNS obsolètes ou pendants (dangling) pour "
              "éviter les prises de contrôle, et n'exposer publiquement que les services nécessaires.")
_R_DNS = ("Hygiène DNS : restreindre les transferts de zone (AXFR) aux seuls secondaires autorisés, "
          "supprimer les enregistrements périmés, limiter l'usage des wildcards, et surveiller les "
          "délégations pour prévenir les prises de contrôle de sous-domaine.")
_R_WEB_DISCOVER = ("Ne pas exposer de routes non documentées : contrôle d'accès deny-by-default, "
                   "authentification sur les endpoints d'admin/debug, désactivation du listing de "
                   "répertoires, et retrait des artefacts de build/backup accessibles.")
_R_JS_ENDPOINTS = ("Ne pas divulguer d'endpoints internes/admin dans le JS client ; appliquer une "
                   "autorisation côté serveur sur CHAQUE endpoint référencé et éviter de fuiter la "
                   "structure d'API sensible dans les bundles livrés au navigateur.")
_R_SECRETS = ("Révoquer et faire tourner IMMÉDIATEMENT tout secret exposé ; ne jamais embarquer de "
              "credential dans le code client ou les dépôts ; utiliser un gestionnaire de secrets et "
              "un scan de secrets en CI (pre-commit + pipeline).")
_R_TECH = ("Minimiser la divulgation de versions (en-têtes Server/X-Powered-By, bannières) et "
           "maintenir les composants à jour ; le fingerprint seul est informatif mais réduit la "
           "surface de ciblage d'exploits connus.")
_R_WAF = ("S'assurer que le WAF/CDN ne peut être contourné : verrouiller l'origine sur les plages IP "
          "du fournisseur au niveau pare-feu, et ne pas divulguer d'informations facilitant son "
          "identification ou son contournement.")


# --- La table HÉRITÉE (ensemble de clés FIGÉ) ------------------------------------------------------
# Ordre : (1) kinds de module, (2) jetons de classe qualifiants, (3) clés CWE / classes de remédiation.
# Les kinds de module portent désormais aussi attck_tactic/phase/capability (catalogue structuré) —
# additif, aucune vue dérivée ne les lit (remediation_map/qualifying_classes/mitre_by_kind inchangées).
TECHNIQUES = {t.key: t for t in [
    # (1) KINDS de module — mitre (badge/purple), cwe (category+cwe des findings), cls/exploit (brain).
    #     `cls` = override de classe planner pour le brain ("" => Action dérive du suffixe du kind).
    _t("access_control.idor", cls="access_control", cwe="CWE-639", mitre="T1190", exploit=True,
       attck_tactic="Initial Access", phase="exploit", capability="exploit", proof_required=True),
    _t("ssrf.callback",       cls="ssrf",           cwe="CWE-918", mitre="T1190", exploit=True,
       attck_tactic="Initial Access", phase="exploit", capability="exploit", proof_required=True),
    _t("auth.takeover",       cls="auth",           cwe="CWE-287", mitre="T1212", exploit=True,
       attck_tactic="Credential Access", phase="exploit", capability="exploit", proof_required=True),
    _t("cors.credentials",    cls="access_control", cwe="CWE-942", mitre="T1539", exploit=True,
       attck_tactic="Credential Access", phase="exploit", capability="exploit", proof_required=True),
    _t("web.nuclei",          mitre="T1595.002",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _t("origin.find",         mitre="T1590.005",
       attck_tactic="Reconnaissance", phase="recon", capability="active", proof_required=True),
    _t("recon.httpx",         mitre="T1595",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _t("recon.nmap",          mitre="T1046",
       attck_tactic="Discovery", phase="recon", capability="active"),
    # KINDS de modules PASSIFS de cartographie de surface (slice recon_surface.py) — comme
    # recon.httpx/recon.nmap, ce sont des kinds de modules LIVRÉS : ils portent mitre + phase/
    # capability et ONT un module enregistré (test_module_mitre_matches_table). Aucune remédiation
    # ni caractère qualifiant -> remediation_map()/qualifying_classes()/mitre_by_kind() INCHANGÉES.
    _t("recon.subdomains",    mitre="T1590",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _t("recon.dns",           mitre="T1590.002",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _t("recon.js_endpoints",  mitre="T1594",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _t("recon.urls",          mitre="T1596",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _t("recon.tech",          mitre="T1592.002",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    # KINDS de modules ACTIFS de reachability/discovery (slice recon_active.py) — scope-locked,
    # rate-limited, lecture/énumération SEULE (aucune exploitation). Comme recon.subdomains/recon.tech,
    # ce sont des kinds de modules LIVRÉS portant mitre + phase/capability, SANS remédiation ni
    # caractère qualifiant (recon non destructif) -> remediation_map()/qualifying_classes()/
    # mitre_by_kind() restent INCHANGÉES (byte-à-byte). Chaque kind a un module enregistré
    # (test_module_mitre_matches_table) et son mitre == cette table (source de vérité).
    _t("recon.content",       mitre="T1595.003",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _t("recon.secrets",       mitre="T1552.001",
       attck_tactic="Credential Access", phase="recon", capability="passive", proof_required=True),
    _t("recon.waf",           mitre="T1590",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _t("demo.fingerprint",    mitre="T1595",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    # KINDS d'ÉVASION (accès derrière CDN/WAF/anti-bot via browser-automation) — planner-SELECTABLE
    # pour les cibles PROTÉGÉES (le brain les propose sur un host marqué protégé / fingerprint WAF).
    # `xhr`/`turnstile` sont des ENABLERS d'accès (non-exploit) ; `idor_intercept` tamper une requête
    # en vol -> exploit=True (gardé par le ROE). mitre == la déclaration du module (source de vérité,
    # cf. test_module_mitre_matches_table). Aucune remédiation ni caractère qualifiant -> les vues
    # héritées (remediation_map/qualifying_classes/mitre_by_kind) restent INCHANGÉES (byte-à-byte).
    _t("evasion.xhr",            cls="evasion", mitre="T1190",
       attck_tactic="Defense Evasion", phase="access", capability="active"),
    _t("evasion.turnstile",      cls="evasion", mitre="T1556",
       attck_tactic="Defense Evasion", phase="access", capability="active"),
    _t("evasion.idor_intercept", cls="evasion", mitre="T1190", exploit=True,
       attck_tactic="Defense Evasion", phase="exploit", capability="exploit"),

    # (2) JETONS de classe QUALIFIANTS (plancher planner). Certains portent aussi une remédiation.
    #     Ce sont des ALIAS de classe (pas des kinds de module) : pas de phase/capability.
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


# --- Le catalogue de SURFACE D'ATTAQUE (ADDITIF — métadonnées seules, modules dans des slices ult.) -
# Chaque classe de technique de cartographie que les prochaines slices implémenteront. Toutes en
# phase=recon, capability passive/active, ATT&CK renseigné, remédiation propre, `proof_required` là
# où une simple détection ne vaut pas preuve (secret exposé, IP d'origine). VIT HORS DE `TECHNIQUES`
# pour garantir que les vues dérivées historiques restent byte-à-byte identiques (aucune pollution).
SURFACE = {t.key: t for t in [
    # subdomain / attack-surface enumeration (T1590 Gather Victim Network Information / T1595 Active Scanning)
    _t("surface.subdomains", mitre="T1590",     attck_tactic="Reconnaissance", phase="recon",
       capability="passive", remediation=_R_SURFACE),
    # DNS enumeration (T1590.002 DNS)
    _t("dns.enum",           mitre="T1590.002", attck_tactic="Reconnaissance", phase="recon",
       capability="active",  remediation=_R_DNS),
    # web content / route discovery (T1595.003 Wordlist Scanning)
    _t("web.discover",       mitre="T1595.003", attck_tactic="Reconnaissance", phase="recon",
       capability="active",  remediation=_R_WEB_DISCOVER),
    # JS / endpoint extraction (T1594 Search Victim-Owned Websites)
    _t("js.endpoints",       mitre="T1594",     attck_tactic="Reconnaissance", phase="recon",
       capability="passive", remediation=_R_JS_ENDPOINTS),
    # exposed-secret detection (T1552.001 Credentials In Files) — détection != preuve : proof requise
    _t("secrets.detect",     mitre="T1552.001", attck_tactic="Credential Access", phase="recon",
       capability="passive", proof_required=True, remediation=_R_SECRETS),
    # technology fingerprint (T1592.002 Software)
    _t("tech.fingerprint",   mitre="T1592.002", attck_tactic="Reconnaissance", phase="recon",
       capability="passive", remediation=_R_TECH),
    # WAF / CDN identification (T1590 Gather Victim Network Information)
    _t("waf.identify",       mitre="T1590",     attck_tactic="Reconnaissance", phase="recon",
       capability="passive", remediation=_R_WAF),
    # origin discovery (T1590.005 IP Addresses) — l'IP d'origine trouvée doit être PROUVÉE (même app)
    _t("surface.origin",     mitre="T1590.005", attck_tactic="Reconnaissance", phase="recon",
       capability="active",  proof_required=True, remediation=_R_ORIGIN),
]}

# Le catalogue consolidé et ÉLARGI : squelette d'enregistrement des nouveaux modules + base des vues
# by_phase/by_capability/by_tactic. Superset de TECHNIQUES (clés héritées identiques) + SURFACE.
CATALOG = {**TECHNIQUES, **SURFACE}
# Clés du catalogue de surface (métadonnées seules) — utile pour distinguer héritage vs surface.
SURFACE_KEYS = frozenset(SURFACE)

# checklist par défaut = ce qu'on veut couvrir sur une cible web (ordre = priorité hacktivity).
# Constante ordonnée (non dérivable des flags) — vit ici pour rester la source unique côté planner.
DEFAULT_CHECKLIST = ["access_control", "auth", "ato", "ssrf", "sqli", "rce", "business_logic"]

# Sous-ensemble curé de kinds pour le repli purple (identique à l'ancien purple.DEFAULT_MITRE_BY_KIND).
# Ce n'est PAS « tous les kinds à point » : evasion/msf/burp n'ont jamais eu de repli purple.
PURPLE_FALLBACK_KINDS = (
    "demo.fingerprint", "recon.httpx", "recon.nmap", "web.nuclei", "access_control.idor",
    "ssrf.callback", "auth.takeover", "cors.credentials", "origin.find",
)


# --- Vues dérivées HISTORIQUES (byte-à-byte identiques — itèrent le noyau hérité TECHNIQUES) -------
def remediation_map():
    """Dict clé -> remédiation (== l'ancien schema.DEFAULT_FIXES). Toute clé HÉRITÉE avec `remediation`.

    Itère `TECHNIQUES` (le noyau figé) : les entrées `SURFACE` portent leur propre remédiation mais
    n'entrent PAS dans le map de remédiation des vulns (elles vivent hors de `TECHNIQUES`)."""
    return {k: t.remediation for k, t in TECHNIQUES.items() if t.remediation}


def qualifying_classes():
    """Ensemble des jetons de classe qualifiants (== l'ancien planner.QUALIFYING). Noyau hérité."""
    return {k for k, t in TECHNIQUES.items() if t.qualifying}


def mitre_by_kind():
    """Repli ATT&CK par kind (== l'ancien purple.DEFAULT_MITRE_BY_KIND). Sous-ensemble curé."""
    return {k: TECHNIQUES[k].mitre for k in PURPLE_FALLBACK_KINDS}


# --- Vues du CATALOGUE ÉLARGI (héritage + surface) -------------------------------------------------
def by_phase(phase):
    """Sous-catalogue {clé -> Technique} des entrées d'une `phase` (recon | access | exploit)."""
    return {k: t for k, t in CATALOG.items() if t.phase == phase}


def by_capability(capability):
    """Sous-catalogue {clé -> Technique} des entrées d'une `capability` (passive | active | exploit)."""
    return {k: t for k, t in CATALOG.items() if t.capability == capability}


def by_tactic(tactic):
    """Sous-catalogue {clé -> Technique} des entrées d'une tactique ATT&CK (`attck_tactic`)."""
    return {k: t for k, t in CATALOG.items() if t.attck_tactic == tactic}


def technique_for(key):
    """L'enregistrement `Technique` du catalogue consolidé pour `key` (None si inconnu). Pur."""
    return CATALOG.get(key)


# --- Résolveurs par kind (interrogent le catalogue consolidé : héritage identique + kinds surface) -
def action_class(kind):
    """Classe planner à passer au brain pour ce kind ("" si aucune override -> Action dérive le suffixe)."""
    t = CATALOG.get(kind)
    return t.cls if t else ""


def action_exploit(kind):
    """Flag exploit à passer au brain pour ce kind (False si inconnu)."""
    t = CATALOG.get(kind)
    return bool(t.exploit) if t else False


def mitre_for(kind):
    """ATT&CK id d'un kind ("" si inconnu)."""
    t = CATALOG.get(kind)
    return t.mitre if t else ""


def cwe_for(kind):
    """CWE canonique d'un kind ("" si inconnu)."""
    t = CATALOG.get(kind)
    return t.cwe if t else ""
