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
    # --- CONSOLIDATION TAXONOMIE (LOT REGISTRY) — rendre les techniques SCALABLES -------------------
    # Une entrée de KIND de module porte désormais TOUTE sa taxonomie : catégorie de vuln, éligibilité
    # bug bounty, profils, outils qui la couvrent, et son ordonnancement dans le pipeline pentest. Les
    # ALIAS de classe/CWE laissent ces champs vides (ce ne sont pas des techniques de module).
    vuln_class: str = ""       # CATÉGORIE (SQLi/XSS/RCE/IDOR/Auth/SSRF/CORS/… ; "" = alias non-technique)
    bug_bounty_eligible: bool = False  # produit un finding PAYABLE en bug bounty (classe qualifiante)
    pentest_only: bool = False  # ne tourne que dans le profil pentest (hors profil bug_bounty)
    tools: tuple = ()          # kinds de module / connecteurs qui COUVRENT cette technique
    stage: str = ""            # étage du pipeline pentest automatisé (== phase pour un kind de module)
    depends_on: tuple = ()     # kinds requis EN AMONT (ordonnancement topologique du pipeline)
    default_profiles: tuple = ()  # profils par défaut (("bug_bounty","pentest") | ("pentest",))

    @property
    def pipeline(self):
        """Descripteur d'ordonnancement du pipeline pentest automatisé : {stage, depends_on:[kinds]}.
        Dérivé (dict frais à chaque accès) pour garder le dataclass frozen ET hashable (les champs de
        stockage `stage`/`depends_on` sont des scalaires/tuples immuables)."""
        return {"stage": self.stage, "depends_on": list(self.depends_on)}


def _t(key, **kw):
    return Technique(key=key, **kw)


def _k(key, vuln_class, bug_bounty_eligible, depends_on=(), tools=None, **kw):
    """Helper d'une entrée de KIND de module — technique SELF-DESCRIBING. Dérive automatiquement
    `pentest_only`, `default_profiles`, `tools` (défaut : le kind lui-même) et `stage` (== la phase),
    pour qu'UN SEUL appel décrive entièrement une technique. C'est le cœur du contrat « une nouvelle
    technique = UNE entrée ici + un module @register » : rien d'autre à câbler."""
    profiles = ("bug_bounty", "pentest") if bug_bounty_eligible else ("pentest",)
    return Technique(
        key=key, vuln_class=vuln_class, bug_bounty_eligible=bug_bounty_eligible,
        pentest_only=not bug_bounty_eligible, stage=kw.get("phase", ""),
        depends_on=tuple(depends_on),
        tools=tuple(tools) if tools is not None else (key,),
        default_profiles=profiles, **kw)


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
    # (1) KINDS de module — chaque entrée est SELF-DESCRIBING via `_k(key, vuln_class, bug_bounty_eligible,
    #     depends_on=..., ...)` : elle porte sa CATÉGORIE de vuln, son éligibilité bug bounty, son étage
    #     de pipeline (== phase) et ses dépendances amont, EN PLUS de mitre/cwe/cls/exploit/phase ATT&CK.
    #     `_k` en dérive pentest_only/default_profiles/tools/stage. UN nouveau module = UNE entrée ici.
    #     `cls` = override de classe planner pour le brain ("" => Action dérive du suffixe du kind).
    _k("access_control.idor", "IDOR", True, depends_on=("recon.httpx",),
       cls="access_control", cwe="CWE-639", mitre="T1190", exploit=True,
       attck_tactic="Initial Access", phase="exploit", capability="exploit", proof_required=True),
    _k("ssrf.callback",       "SSRF", True, depends_on=("recon.httpx",),
       cls="ssrf",           cwe="CWE-918", mitre="T1190", exploit=True,
       attck_tactic="Initial Access", phase="exploit", capability="exploit", proof_required=True),
    _k("auth.takeover",       "Auth", True, depends_on=("recon.httpx",),
       cls="auth",           cwe="CWE-287", mitre="T1212", exploit=True,
       attck_tactic="Credential Access", phase="exploit", capability="exploit", proof_required=True),
    _k("cors.credentials",    "CORS", True, depends_on=("recon.httpx",),
       cls="access_control", cwe="CWE-942", mitre="T1539", exploit=True,
       attck_tactic="Credential Access", phase="exploit", capability="exploit", proof_required=True),
    # ORACLES d'INJECTION server-side à PREUVE BÉNIGNE (slice injection.py) — VÉRIFICATION, pas
    # weaponization : marqueur arithmétique (SSTI -> RCE), canari bénin (traversal -> LFI), différentiel
    # booléen / version SGBD (SQLi). exploit=False/destructive=False (sondes bénignes non destructives)
    # -> capability="active", phase="access". `proof_required` : promotion `vulnerable` sur preuve
    # concrète seulement. Aucune `remediation`/`qualifying` ici -> remediation_map()/qualifying_classes()/
    # mitre_by_kind() restent INCHANGÉES (byte-à-byte) ; le fix est déclaré explicitement par le module.
    _k("ssti.eval",           "RCE", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-1336", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    _k("path.traversal",      "LFI", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-22",   mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    _k("sqli.probe",          "SQLi", True, depends_on=("recon.js_endpoints",),
       cls="sqli", cwe="CWE-89", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # ORACLES CLIENT-SIDE / FLUX DE REQUÊTE à PREUVE MINIMALE (slice clientflow.py) — VÉRIFICATION,
    # pas weaponization : marqueur bénin réfléchi en contexte JS-exécutable (XSS reflected), cible de
    # redirection attaquant-contrôlée ET chaînable (open redirect), action critique sans anti-CSRF ni
    # SameSite (CSRF). exploit=False/destructive=False (sondes bénignes non destructives) ->
    # capability="active", phase="access". `proof_required` : promotion `vulnerable` seulement sur
    # preuve concrète ET impactante (contexte exécutable / chaîne sensible / action critique). Aucune
    # `remediation`/`qualifying` ici -> remediation_map()/qualifying_classes()/mitre_by_kind() restent
    # INCHANGÉES (byte-à-byte) ; le fix est déclaré explicitement par chaque module.
    _k("xss.reflected",       "XSS", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-79",  mitre="T1059",
       attck_tactic="Execution", phase="access", capability="active", proof_required=True),
    _k("redirect.open",       "OpenRedirect", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-601", mitre="T1204.001",
       attck_tactic="Execution", phase="access", capability="active", proof_required=True),
    _k("csrf.state_change",   "CSRF", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-352", mitre="T1204",
       attck_tactic="Execution", phase="access", capability="active", proof_required=True),
    # ORACLES TOKEN/API à PREUVE COMPTE-OPÉRATEUR (slice tokenapi.py) — VÉRIFICATION scope-locked, pas
    # weaponization : jetons forgés acceptés POUR le compte de l'opérateur (jwt.weakness -> Auth, signature
    # contournable), objet d'un SECOND compte détenu lu cross-compte (graphql.access -> IDOR/Access, BOLA).
    # Jamais un tiers. exploit=False/destructive=False (sondes bénignes non destructives) ->
    # capability="active", phase="access". `proof_required` : promotion `vulnerable` sur preuve concrète
    # compte-opérateur seulement. Aucune `remediation`/`qualifying` ici -> remediation_map()/
    # qualifying_classes()/mitre_by_kind() restent INCHANGÉES ; le fix est déclaré par le module.
    _k("jwt.weakness",        "Auth", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-347", mitre="T1606",
       attck_tactic="Credential Access", phase="access", capability="active", proof_required=True),
    _k("graphql.access",      "IDOR", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-639", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # SCANNERS / CONNECTEURS (recon-phase active) — nuclei/burp signalent (reported_by_tool), ne
    # confirment pas ; vuln_class="Scanner", pentest_only (pas de finding payable en propre).
    _k("web.nuclei",          "Scanner", False, depends_on=("recon.httpx",), mitre="T1595.002",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _k("burp.scan",           "Scanner", False, depends_on=("recon.httpx",), mitre="T1595.002",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _k("origin.find",         "Recon", False, depends_on=("recon.httpx",), mitre="T1590.005",
       attck_tactic="Reconnaissance", phase="recon", capability="active", proof_required=True),
    _k("recon.httpx",         "Recon", False, depends_on=("recon.subdomains",), mitre="T1595",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _k("recon.nmap",          "Recon", False, mitre="T1046",
       attck_tactic="Discovery", phase="recon", capability="active"),
    # KINDS de modules PASSIFS de cartographie de surface (slice recon_surface.py) — comme
    # recon.httpx/recon.nmap, ce sont des kinds de modules LIVRÉS : ils portent mitre + phase/
    # capability et ONT un module enregistré (test_module_mitre_matches_table). Aucune remédiation
    # ni caractère qualifiant -> remediation_map()/qualifying_classes()/mitre_by_kind() INCHANGÉES.
    _k("recon.subdomains",    "Recon", False, mitre="T1590",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _k("recon.dns",           "Recon", False, depends_on=("recon.subdomains",), mitre="T1590.002",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _k("recon.js_endpoints",  "Recon", False, depends_on=("recon.httpx",), mitre="T1594",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _k("recon.urls",          "Recon", False, mitre="T1596",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _k("recon.tech",          "Recon", False, depends_on=("recon.httpx",), mitre="T1592.002",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    # KINDS de modules ACTIFS de reachability/discovery (slice recon_active.py) — scope-locked,
    # rate-limited, lecture/énumération SEULE (aucune exploitation). Comme recon.subdomains/recon.tech,
    # ce sont des kinds de modules LIVRÉS portant mitre + phase/capability, SANS remédiation ni
    # caractère qualifiant (recon non destructif) -> remediation_map()/qualifying_classes()/
    # mitre_by_kind() restent INCHANGÉES (byte-à-byte). recon.secrets -> ExposedSecrets (BB, preuve exigée).
    _k("recon.content",       "Recon", False, depends_on=("recon.httpx",), mitre="T1595.003",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    _k("recon.secrets",       "ExposedSecrets", True, depends_on=("recon.js_endpoints",), mitre="T1552.001",
       attck_tactic="Credential Access", phase="recon", capability="passive", proof_required=True),
    _k("recon.waf",           "Recon", False, depends_on=("recon.httpx",), mitre="T1590",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    _k("demo.fingerprint",    "Recon", False, mitre="T1595",
       attck_tactic="Reconnaissance", phase="recon", capability="passive"),
    # KINDS d'ÉVASION (accès derrière CDN/WAF/anti-bot via browser-automation) — planner-SELECTABLE
    # pour les cibles PROTÉGÉES (le brain les propose sur un host marqué protégé / fingerprint WAF).
    # `xhr`/`turnstile` sont des ENABLERS d'accès (non-exploit, vuln_class="Evasion") ; `idor_intercept`
    # tamper une requête en vol -> vuln_class="IDOR", exploit=True (gardé par le ROE, pentest_only :
    # variante exploit-floor du benign oracle access_control.idor). mitre == la déclaration du module
    # (source de vérité, cf. test_module_mitre_matches_table). Aucune remédiation ni caractère qualifiant
    # -> les vues héritées (remediation_map/qualifying_classes/mitre_by_kind) restent INCHANGÉES.
    _k("evasion.xhr",            "Evasion", False, depends_on=("recon.waf",),
       cls="evasion", mitre="T1190",
       attck_tactic="Defense Evasion", phase="access", capability="active"),
    _k("evasion.turnstile",      "Evasion", False, depends_on=("recon.waf",),
       cls="evasion", mitre="T1556",
       attck_tactic="Defense Evasion", phase="access", capability="active"),
    _k("evasion.idor_intercept", "IDOR", False, depends_on=("evasion.discover",),
       cls="evasion", mitre="T1190", exploit=True,
       attck_tactic="Defense Evasion", phase="exploit", capability="exploit"),
    # DÉCOUVERTE BACKED-BROWSER derrière WAF/challenge managé : pilote le browser-automation pour
    # franchir le challenge, PUIS extrait les endpoints du rendu (DOM/JS/XHR) — cartographie active,
    # navigate/lecture SEULE (exploit=False, non destructif, vuln_class="Recon"). C'est le jumeau
    # browser de recon.js_endpoints : il émet le MÊME DISCOVERY_ENDPOINT_MARKER (T1594) pour que le
    # cerveau chaîne les oracles — d'où phase=recon/capability=active même s'il vit dans la famille
    # évasion (cls="evasion", proposé sur les cibles PROTÉGÉES par le brain).
    _k("evasion.discover",       "Recon", False, depends_on=("recon.waf",),
       cls="evasion", mitre="T1594",
       attck_tactic="Reconnaissance", phase="recon", capability="active"),
    # CONNECTEUR METASPLOIT (opérateur opt-in, EXPLOIT-phase) — un module MSF peut être un exploit
    # fort-impact (exploit=True au niveau classe -> l'engine exige allow_exploit) : vuln_class="Exploit",
    # pentest_only. mitre T1210 (Exploitation of Remote Services). SANS remédiation/qualifying ->
    # vues héritées INCHANGÉES ; son mitre == la déclaration du module (test_module_mitre_matches_table).
    _k("msf.module",          "Exploit", False, depends_on=("recon.nmap",), mitre="T1210", exploit=True,
       attck_tactic="Lateral Movement", phase="exploit", capability="exploit"),

    # =============================================================================================
    #  LOT SCALE — nouvelles classes de vuln, chacune SELF-DESCRIBING via `_k(...)` : UNE entrée ici
    #  + UN module @register (importé dans modules/__init__.py) = auto-intégration dans le catalogue
    #  groupé par catégorie (by_vuln_class), le pipeline pentest ordonné (pipeline_ordered), la
    #  sélection par-scope et les bons profils (profile_set) — SANS câblage par-technique ailleurs.
    #  C'est la DÉMONSTRATION du point d'extension (« drop-in technique »). Aucune `remediation`/
    #  `qualifying` ici -> remediation_map()/qualifying_classes()/mitre_by_kind() restent INCHANGÉES
    #  (le fix est déclaré explicitement par chaque module ; la classe qualifiante vient de l'alias).
    # ---------------------------------------------------------------------------------------------
    # access_control.privesc — élévation de privilège VERTICALE / function-level (BB) : depuis le
    # compte BAS-PRIVILÈGE de l'opérateur, atteindre une fonction/objet admin-only qui devrait être
    # REFUSÉ (comptes-opérateur UNIQUEMENT, jamais un tiers réel). exploit=True -> exige allow_exploit.
    _k("access_control.privesc", "PrivEsc", True, depends_on=("recon.httpx",),
       cls="access_control", cwe="CWE-269", mitre="T1068", exploit=True,
       attck_tactic="Privilege Escalation", phase="exploit", capability="exploit", proof_required=True),
    # xxe.probe — traitement d'entité externe XML (BB) détecté par marqueur BÉNIGN (callback OOB vers le
    # collecteur opérateur OU lecture d'un canari bénin NON sensible) ; JAMAIS de fichier système/cred.
    # Sonde de VÉRIFICATION bénigne (exploit=False) -> phase=access, capability=active.
    _k("xxe.probe",           "XXE", True, depends_on=("recon.js_endpoints",),
       cls="xxe", cwe="CWE-611", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # rfi.probe — remote file inclusion (BB) : preuve = le contenu d'un marqueur BÉNIGN contrôlé par
    # l'opérateur est INCLUS par l'app (aucune charge malveillante). exploit=False (marqueur bénin).
    _k("rfi.probe",           "RFI", True, depends_on=("recon.js_endpoints",),
       cls="rfi", cwe="CWE-98", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # ssrf.xspa — variante SSRF port-scan (BB) : joignabilité de ports internes via différentiel de
    # réponse/timing CONTRE LA CIBLE IN-SCOPE UNIQUEMENT ; informatif/proof-minimal, non destructif
    # (exploit=False : aucune requête vers une infra attaquant, aucun tiers). phase=access/active.
    _k("ssrf.xspa",           "XSPA", True, depends_on=("recon.httpx",),
       cls="ssrf", cwe="CWE-918", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # xss.stored — XSS stocké/DOM (BB) via le chemin browser/évasion : persiste un marqueur BÉNIGN
    # unique et confirme qu'il se reflète en contexte JS-exécutable sur une AUTRE vue (dégrade en
    # skipped si le module navigateur est absent). exploit=False (marqueur bénin, compte opérateur).
    _k("xss.stored",          "XSS", True, depends_on=("recon.js_endpoints",),
       cwe="CWE-79", mitre="T1059",
       attck_tactic="Execution", phase="access", capability="active", proof_required=True),
    # rce.probe — VÉRIFICATION d'exécution de code distante GOUVERNÉE (PENTEST-ONLY) : preuve par
    # marqueur de commande BÉNIGN (arithmétique/echo dont la sortie UNIQUE revient), scope-locked, NON
    # destructif, GARDÉE derrière le plancher opt-in exploit/fort-impact (refusée sans allow_exploit/
    # allow_high_impact + opérateur + scope). exploit=True, pentest_only (jamais un finding BB payable).
    _k("rce.probe",           "RCE", False, depends_on=("recon.js_endpoints",),
       cls="rce", cwe="CWE-78", mitre="T1059", exploit=True,
       attck_tactic="Execution", phase="exploit", capability="exploit", proof_required=True),
    # business_logic.scan — SCAFFOLD de checks de logique métier automatisables (PENTEST-ONLY, SEMI-
    # automatisé) : quantité négative / price-tamper / coupon-stack là où détectable SÛREMENT ; là où un
    # jugement humain est requis -> status=tested avec note « manual review ». exploit=False, non destructif.
    _k("business_logic.scan", "BusinessLogic", False, depends_on=("recon.js_endpoints",),
       cls="business_logic", cwe="CWE-840", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),

    # =============================================================================================
    #  LOT INJECTION/PROTOCOLE — classes d'attaque injection & protocole HTTP prouvées utilisées par le
    #  toolkit opérateur (FAISS) mais absentes de Forge. Chacune SELF-DESCRIBING via `_k(...)` : UNE
    #  entrée ici + UN module @register (importé dans modules/__init__.py) = auto-intégration dans
    #  by_vuln_class / pipeline_ordered / la sélection par-scope / les profils / `modules --json`, SANS
    #  câblage par-technique. Sondes de VÉRIFICATION BÉNIGNES & NON DESTRUCTIVES (exploit=False) ->
    #  phase=access, capability=active, proof_required (promotion `vulnerable` sur preuve concrète seule).
    #  Aucune `remediation`/`qualifying` ici -> remediation_map()/qualifying_classes()/mitre_by_kind()
    #  restent INCHANGÉES (byte-à-byte) ; le fix est déclaré explicitement par chaque module.
    # ---------------------------------------------------------------------------------------------
    # nosql.probe — injection NoSQL (BB) par différentiel d'OPÉRATEUR (Mongo $ne/$gt/$regex broaden vs
    # $eq/$lt narrow) prouvant que les opérateurs de requête sont interprétés. Aucun dump (hash/statut).
    _k("nosql.probe",         "NoSQLi", True, depends_on=("recon.js_endpoints",),
       cls="nosqli", cwe="CWE-943", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # prototype_pollution.probe — pollution de prototype client/serveur (BB) par marqueur d'injection de
    # propriété BÉNIGN (`__proto__[MARK]=VAL`) dont l'EFFET est réfléchi UNIQUEMENT via le vecteur proto
    # (différentiel vs contrôle) -> propriété polluée surfacée. Aucun gadget exploité.
    _k("prototype_pollution.probe", "PrototypePollution", True, depends_on=("recon.js_endpoints",),
       cls="prototype_pollution", cwe="CWE-1321", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # request_smuggling.probe — désync HTTP CL.TE/TE.CL (BB) par sonde de TIMING différentielle NON
    # destructive : une variante ambiguë HANG (back-end attend un terminateur) là où la baseline répond
    # vite. Sonde AUTO-CONTENUE sur NOTRE connexion (aucun poisoning de file d'un autre user).
    _k("request_smuggling.probe", "RequestSmuggling", True, depends_on=("recon.httpx",),
       cls="request_smuggling", cwe="CWE-444", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # cache_poisoning.probe — web cache poisoning (BB) : un en-tête NON CLÉ (X-Forwarded-Host…) portant un
    # marqueur BÉNIGN se REFLÈTE dans une réponse CACHEABLE (diff vs contrôle). Cache-buster unique ->
    # jamais de persistance d'entrée nuisible pour de vrais users (probe-only).
    _k("cache_poisoning.probe", "CachePoisoning", True, depends_on=("recon.httpx",),
       cls="cache_poisoning", cwe="CWE-525", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # header_injection.probe — injection d'en-tête / Host header (BB) par marqueur BÉNIGN : CRLF response-
    # splitting (un en-tête bénin injecté apparaît dans la réponse, CWE-113) OU host poisoning (marqueur
    # d'hôte reflété dans le corps/Location, CWE-644, ex reset-password). Non destructif. cwe canonique
    # CWE-113 (host header CWE-644 noté dans l'evidence).
    _k("header_injection.probe", "HeaderInjection", True, depends_on=("recon.httpx",),
       cls="header_injection", cwe="CWE-113", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # lucene.probe — injection de requête de recherche Lucene/Elasticsearch (BB) par différentiel de
    # RUPTURE DE SYNTAXE BÉNIGNE : une entrée invalide provoque une ParseException Lucene (absente de la
    # baseline) OU un différentiel booléen (OR broaden / AND narrow). Aucun dump.
    _k("lucene.probe",        "SearchInjection", True, depends_on=("recon.js_endpoints",),
       cls="lucene", cwe="CWE-943", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # cmdi.probe — VÉRIFICATION d'injection de commande OS (BB) à PREUVE STRICTEMENT BÉNIGNE : marqueur
    # echo/arithmétique dont la SORTIE UNIQUE revient. DISTINCT de rce.probe (l'exploit gouverné pentest-
    # only derrière le plancher exploit) : cmdi reste exploit=False, non destructif, NE lance JAMAIS de
    # commande nuisible (garde-fou benign). mitre T1059/Execution (comme xss.reflected/cmdline).
    _k("cmdi.probe",          "CommandInjection", True, depends_on=("recon.js_endpoints",),
       cls="cmdi", cwe="CWE-78", mitre="T1059",
       attck_tactic="Execution", phase="access", capability="active", proof_required=True),

    # =============================================================================================
    #  LOT AUTH-FLOW / RACE — classes d'attaque flux-d'authentification & concurrence prouvées utilisées
    #  par le toolkit opérateur (FAISS : PoC race recovery-code / refresh-token / device-code, faiblesses
    #  de flux OAuth redirect_uri/state) mais absentes de Forge. Chacune SELF-DESCRIBING via `_k(...)` :
    #  UNE entrée ici + UN module @register (importé dans modules/__init__.py) = auto-intégration dans
    #  by_vuln_class / pipeline_ordered / la sélection par-scope / les profils / `modules --json`, SANS
    #  câblage par-technique. Sondes GOUVERNÉES, COMPTE-OPÉRATEUR & NON DESTRUCTIVES (exploit=False) ->
    #  phase=access, capability=active, proof_required (promotion `vulnerable` sur preuve concrète seule).
    #  Aucune `remediation`/`qualifying` ici -> remediation_map()/qualifying_classes()/mitre_by_kind()
    #  restent INCHANGÉES (byte-à-byte) ; le fix est déclaré explicitement par chaque module.
    # ---------------------------------------------------------------------------------------------
    # race.condition — RaceCondition/TOCTOU (BB) sur une ressource LIMITÉE du compte OPÉRATEUR (code à
    # usage unique, coupon, refresh/device/recovery token, solde) : une PETITE rafale de requêtes
    # PARALLÈLES (bornée, jamais un DoS) prouve qu'une action à usage limité a réussi PLUS que le quota
    # autorisé. Preuve = la limite est DÉMONTRABLEMENT contournée sur le compte PROPRE de l'opérateur ;
    # jamais un tiers. Sonde de VÉRIFICATION (exploit=False, non destructif au-delà de ce qui prouve sur
    # la ressource propre). cwe canonique CWE-362 (Race Condition ; TOCTOU CWE-367 noté dans l'evidence).
    _k("race.condition",      "RaceCondition", True, depends_on=("recon.js_endpoints",),
       cls="race", cwe="CWE-362", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),
    # oauth.flow — faiblesses de FLUX OAuth/OIDC (BB) sur le PROPRE flux de l'opérateur (son client_id
    # enregistré, jamais une identité tierce) : bypass de validation redirect_uri (open-redirect dans la
    # redirection OAuth -> vol de code/jeton), `state` manquant/faible (CSRF sur le flux), manipulation de
    # scope/`idp_hint`, downgrade/absence de PKCE. Preuve MINIMALE (redirect_uri vers un hôte bénin
    # contrôlé par l'opérateur ACCEPTÉ ; `state` non imposé) ; la partie redirection suit la discipline
    # CHAÎNABLE-SEULEMENT (miroir redirect.open). Réutilise jwt.weakness pour les problèmes de JETON ; ceci
    # couvre le FLUX. cwe canonique CWE-601 (redirect_uri ; CSRF CWE-352 & auth CWE-287 notés dans l'evidence).
    _k("oauth.flow",          "OAuthFlow", True, depends_on=("recon.js_endpoints",),
       cls="oauth", cwe="CWE-601", mitre="T1528",
       attck_tactic="Credential Access", phase="access", capability="active", proof_required=True),

    # =============================================================================================
    #  LOT RECON/EXPOSURE/TAKEOVER — classes de recon/exposition/takeover prouvées utilisées par le
    #  toolkit opérateur (FAISS : subdomain takeover, actuator/framework exposure, SSRF métadonnées cloud)
    #  mais absentes de Forge. Chacune SELF-DESCRIBING via `_k(...)` : UNE entrée + UN module @register =
    #  auto-intégration (by_vuln_class / pipeline_ordered / sélection par-scope / profils / modules --json),
    #  SANS câblage par-technique. Native, scope-lockées, PREUVE MINIMALE & BÉNIGNE (jamais de réclamation
    #  de ressource, ni de vol de secret — valeurs rédigées). bug_bounty_eligible. Aucune `remediation`/
    #  `qualifying` ici -> les vues héritées restent INCHANGÉES (le fix est déclaré par chaque module).
    # ---------------------------------------------------------------------------------------------
    # subdomain.takeover — prise de contrôle de sous-domaine (BB) : CNAME PENDANT vers un service tiers NON
    # RÉCLAMÉ (fingerprint OU cible NXDOMAIN). INFORMATIONNEL/proof-minimal — la ressource n'est JAMAIS
    # réclamée (on flague la cible pendante). Recon-phase (comme recon.secrets), preuve exigée.
    _k("subdomain.takeover",  "SubdomainTakeover", True, depends_on=("recon.subdomains",),
       cwe="CWE-350", mitre="T1584.001",
       attck_tactic="Resource Development", phase="recon", capability="active", proof_required=True),
    # framework.exposure — surface de framework exposée (BB) : Spring Actuator /actuator/*, Next.js
    # __NEXT_DATA__/runtimeConfig, Laravel Telescope/Horizon/Ignition. PREUVE = surface sensible joignable
    # qui FUIT config/données (secret RÉDIGÉ). Recon-phase, active, preuve exigée.
    _k("framework.exposure",  "Exposure", True, depends_on=("recon.httpx",),
       cwe="CWE-200", mitre="T1592.002",
       attck_tactic="Reconnaissance", phase="recon", capability="active", proof_required=True),
    # ssrf.cloud_metadata — SSRF vers les métadonnées cloud (BB) : AWS/GCP/Azure IMDS (169.254.169.254 /
    # metadata.google.internal). PREUVE = signature de contenu métadonnées in-band (reflet neutralisé,
    # credential RÉDIGÉ) OU callback collecteur out-of-band. Scope-lockée, bénigne (chemins index non-secrets).
    _k("ssrf.cloud_metadata", "SSRF", True, depends_on=("recon.httpx",),
       cls="ssrf", cwe="CWE-918", mitre="T1190",
       attck_tactic="Initial Access", phase="access", capability="active", proof_required=True),

    # =============================================================================================
    #  LOT PENTEST-ONLY (réseau/mobile) — classes d'attaque réseau/mobile PROUVÉES par le pentest mais qui
    #  ne sont PAS des surfaces bug-bounty et NE doivent PAS embarquer de capacité offensive native dans
    #  Forge. On les ENREGISTRE (catalogue + profil pentest) en POINTANT vers les connecteurs gouvernés
    #  (`msf.module`, `tools=(...)`) / outils externes documentés (nmap NSE, MobSF/apktool). Le module
    #  @register est un AVIS GOUVERNÉ (scope-guard + plancher exploit + dégradation), ZÉRO exploit natif.
    #  bug_bounty_eligible=False -> pentest_only, EXCLUES du profil bug_bounty (phase NON-recon : jamais
    #  tirées comme « infrastructure de découverte »). Les classes EXPLOIT (smb/ssh) portent exploit=True
    #  -> le ROE exige allow_exploit (plancher opt-in), re-vérifié en défense en profondeur par le module.
    # ---------------------------------------------------------------------------------------------
    _k("network.smb",         "SMB", False, depends_on=("recon.nmap",), tools=("msf.module",),
       mitre="T1210", exploit=True,
       attck_tactic="Lateral Movement", phase="exploit", capability="exploit"),
    _k("network.ftp",         "FTP", False, depends_on=("recon.nmap",), tools=("recon.nmap", "msf.module"),
       mitre="T1046",
       attck_tactic="Discovery", phase="access", capability="active"),
    _k("network.ssh",         "SSH", False, depends_on=("recon.nmap",), tools=("recon.nmap", "msf.module"),
       mitre="T1110.001", exploit=True,
       attck_tactic="Credential Access", phase="exploit", capability="exploit"),
    _k("mobile.apk",          "MobileApp", False,
       mitre="T1406",
       attck_tactic="Discovery", phase="access", capability="active"),

    # (2) JETONS de classe QUALIFIANTS (plancher planner). Certains portent aussi une remédiation.
    #     Ce sont des ALIAS de classe (pas des kinds de module) : pas de vuln_class/phase/capability.
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

# --- Marqueurs de titre des findings de DÉCOUVERTE par-hôte/par-endpoint (SOURCE UNIQUE) -----------
# Les modules de recon PASSIVE (recon_surface.py) émettent, par hôte/endpoint in-scope découvert, un
# finding informatif dont le TITRE porte l'un de ces marqueurs. Le cerveau (brain._chained_actions)
# les détecte pour CHAÎNER la vérification (discovery -> verification) sur la cible découverte, en
# restant scope-locked. Constantes partagées entre l'émetteur et le détecteur = zéro dérive possible.
DISCOVERY_SUBDOMAIN_MARKER = "Sous-domaine in-scope"       # recon.subdomains : nouvel hôte in-scope
DISCOVERY_ENDPOINT_MARKER = "Endpoint in-scope"            # recon.js_endpoints : endpoint référencé JS
DISCOVERY_HISTORICAL_URL_MARKER = "URL historique in-scope"  # recon.urls : URL d'archive in-scope
# Marqueur de titre : la découverte plain-HTTP a été BLOQUÉE par un challenge/WAF managé — signature
# de challenge/403 observée ET aucun endpoint extrait. Émis par recon.js_endpoints / recon.content
# (les émetteurs de découverte HTTP) quand la recon curl est challengée (le trou historique :
# « WAF -> recon challengée -> 0 endpoint -> 0 oracle »). Le cerveau (brain, edge (f)) le détecte pour
# AUTO-PROPOSER la voie backed-browser `evasion.discover` sur ce host in-scope, qui franchit le
# challenge et ré-alimente la chaîne discovery->oracle. Constante partagée émetteur/détecteur (zéro
# dérive), distincte des DISCOVERY_*_MARKER par-hôte/endpoint (elle marque un host CHALLENGE-GATÉ, pas
# une cible DÉCOUVERTE) — donc ignorée par le fan-out bound `_discovery_marker`.
DISCOVERY_CHALLENGE_MARKER = "découverte HTTP challengée (WAF/challenge managé)"

# --- Détection de challenge/WAF managé sur une réponse HTTP (pur, stdlib, jamais de réseau) ---------
# Codes de statut typiques d'un blocage/challenge managé (Cloudflare & co) et sous-chaînes d'interstitiel
# de challenge dans le corps HTML. Sert aux modules de découverte HTTP à SIGNALER « recon bloquée par un
# challenge » (0 endpoint + signature) pour que le cerveau bascule sur la voie backed-browser. Volontairement
# CONSERVATEUR (sous-chaînes non ambiguës) pour éviter les faux positifs.
CHALLENGE_STATUS_CODES = frozenset({403, 429, 503})
CHALLENGE_BODY_SIGNATURES = (
    "just a moment", "checking your browser", "attention required", "cf-chl", "__cf_chl",
    "cf-mitigated", "cf_chl_opt", "/cdn-cgi/challenge-platform", "turnstile", "captcha-delivery",
    "datadome", "please enable javascript and cookies", "please stand by, while we are checking",
    "ddos protection by", "incapsula incident id", "this request was blocked",
)


def looks_like_challenge(status, body=""):
    """True si une réponse HTTP porte une SIGNATURE de challenge/WAF managé : code de blocage
    (403/429/503) OU interstitiel de challenge dans le corps HTML (Cloudflare « Just a moment »,
    DataDome, Turnstile…). Pur, ne lève jamais ; conservateur (sous-chaînes non ambiguës). Sert de
    signal « recon plain-HTTP bloquée » pour basculer sur la découverte backed-browser."""
    try:
        if status in CHALLENGE_STATUS_CODES:
            return True
        low = (body or "").lower()
        return any(sig in low for sig in CHALLENGE_BODY_SIGNATURES)
    except Exception:                                        # noqa: BLE001 (entrée hostile)
        return False


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


def mitre_for_cwe(cwe):
    """ATT&CK id de la PREMIÈRE technique du catalogue dont le CWE canonique == `cwe` ("" si aucune).

    Résolveur INVERSE (CWE -> ATT&CK) : un outil tiers (Burp/nuclei) signale une classe de vuln par
    son CWE (ex "CWE-89") sans porter d'ATT&CK. On rattache ce CWE à la tactique/technique ATT&CK de
    la table (source de vérité) pour que le finding rejoigne la boucle purple. Pur, ne lève jamais ;
    ignore les entrées sans mitre ; casse-insensible sur l'identifiant CWE."""
    if not cwe:
        return ""
    target = str(cwe).strip().upper()
    for t in CATALOG.values():
        if t.cwe and t.mitre and t.cwe.upper() == target:
            return t.mitre
    return ""


# --- CONSOLIDATION taxonomie : vues DÉRIVÉES « scale » (LOT REGISTRY) ------------------------------
# Le contrat « derive-everywhere » : un module qui s'enregistre avec UNE entrée technique apparaît
# AUTOMATIQUEMENT dans le catalogue groupé par catégorie (`by_vuln_class`), le pipeline pentest
# ordonné (`pipeline_ordered`/`techniques_for`), la sélection par-scope et les bons profils
# (`profile_set`) — sans câblage par-technique ailleurs. Ces vues DÉRIVENT toutes de la table unique.
PROFILES = ("bug_bounty", "pentest")
_PHASE_RANK = {"recon": 0, "access": 1, "exploit": 2, "": 3}


def technique_kinds():
    """Liste des KINDS de module-technique du catalogue (clé pointée portant une `vuln_class`). C'est
    l'ensemble des techniques RÉELLES (un module enregistré) — à l'exclusion des ALIAS de classe/CWE
    (non-phasés, sans vuln_class) et des placeholders de SURFACE (métadonnées sans module livré)."""
    return [k for k, t in CATALOG.items() if "." in k and t.vuln_class]


def by_vuln_class():
    """Dict CATÉGORIE -> [kinds triés] : LE catalogue groupé par classe de vuln (SQLi/XSS/IDOR/SSRF/…).
    C'est la vue « catalogue » : un nouveau module apparaît sous sa catégorie sans autre câblage."""
    out = {}
    for k in technique_kinds():
        out.setdefault(CATALOG[k].vuln_class, []).append(k)
    for v in out.values():
        v.sort()
    return out


def profile_set(profile, custom=None):
    """Ensemble de kinds appartenant à un PROFIL :
      - "pentest"     -> TOUTES les techniques (le pentest peut tout lancer) ;
      - "bug_bounty"  -> les techniques `bug_bounty_eligible` (les classes payables) ;
      - "custom"      -> l'ensemble fourni par l'appelant (`custom=...`) ;
      - un ensemble/liste/tuple de kinds passé DIRECTEMENT -> pris tel quel (custom implicite) ;
      - tout autre nom de profil -> les techniques dont `default_profiles` contient ce nom.
    Pur ; ne lève jamais. Cohérent par construction : `bug_bounty` via le flag == via default_profiles."""
    kinds = technique_kinds()
    if isinstance(profile, (set, frozenset, list, tuple)):
        return set(profile)
    if profile == "pentest":
        return set(kinds)
    if profile == "bug_bounty":
        return {k for k in kinds if CATALOG[k].bug_bounty_eligible}
    if profile == "custom":
        return set(custom or ())
    return {k for k in kinds if profile in CATALOG[k].default_profiles}


def pipeline_ordered():
    """Les kinds-techniques ordonnés TOPOLOGIQUEMENT par phase (recon < access < exploit) puis par
    dépendances (`depends_on`) — l'ordonnancement du pipeline pentest automatisé. Déterministe
    (tie-break stable : rang de phase puis clé). Robuste : un `depends_on` hors de l'ensemble est
    ignoré ; un cycle (ne devrait jamais arriver — les deps pointent vers des phases antérieures) est
    brisé en repli sur l'ordre de priorité (jamais de boucle infinie)."""
    kinds = technique_kinds()
    nodeset = set(kinds)
    deps = {k: [d for d in CATALOG[k].depends_on if d in nodeset] for k in kinds}

    def prio(k):
        return (_PHASE_RANK.get(CATALOG[k].phase, 3), k)

    ordered, placed, remaining = [], set(), set(kinds)
    while remaining:
        ready = [k for k in remaining if all(d in placed for d in deps[k])]
        if not ready:                                    # cycle défensif : ne jamais boucler
            ready = list(remaining)
        nxt = min(ready, key=prio)
        ordered.append(nxt)
        placed.add(nxt)
        remaining.discard(nxt)
    return ordered


def techniques_for(selection):
    """Le pipeline FILTRÉ + ORDONNÉ pour une sélection : un nom de profil ("bug_bounty"/"pentest"/
    "custom") OU un ensemble explicite de kinds activés (sélection par-scope). Retourne les kinds
    ACTIVÉS dans l'ordre de `pipeline_ordered`. Les dépendances non activées sont simplement absentes
    (filtrage, pas d'auto-ajout) : c'est « le pipeline filtré » demandé par la sélection."""
    if isinstance(selection, str):
        enabled = profile_set(selection)
    else:
        enabled = set(selection or ())
    return [k for k in pipeline_ordered() if k in enabled]


# --- SÉLECTION PAR-SCOPE : profil + toggles catégorie/technique (DÉRIVÉE de la table unique) --------
# Contrat : un scope (ou la console) porte un `profile` + des toggles explicites, et l'ENSEMBLE EFFECTIF
# de techniques activées en est RÉSOLU — sans câblage par-technique. C'est LA fonction que l'enforcement
# (engine/planner/brain, cf. Scope.effective_technique_kinds) et l'API `GET /api/techniques` partagent.
# La résolution ci-dessous est la SPEC PARTAGÉE (mirroir Rust côté console) : garder les deux en phase.
PROFILE_NAMES = PROFILES + ("custom",)              # bug_bounty | pentest | custom (noms de profil)


def recon_infra_kinds():
    """Kinds de PHASE recon = infrastructure de DÉCOUVERTE de surface (subdomains/httpx/js_endpoints/…,
    scanners, origin). TOUJOURS inclus dans la base du profil bug_bounty : un profil choisit les CLASSES
    de vuln à VÉRIFIER, pas s'il faut découvrir la surface — un profil sans recon affamerait tout le
    pipeline (recon -> chaînage -> oracles). Restent DÉSACTIVABLES explicitement (toggle -> fail-closed)."""
    return {k for k in technique_kinds() if CATALOG[k].phase == "recon"}


def _profile_base(profile, custom=None):
    """Ensemble de BASE d'un profil pour la sélection PAR-SCOPE :
      - "pentest"    -> TOUTES les techniques (le pentest peut tout balayer) ;
      - "bug_bounty" -> les techniques bug_bounty_eligible + l'infrastructure de recon (surface) ;
      - "custom"     -> vide (l'opérateur construit tout via les toggles explicites) ;
      - un ensemble/liste/tuple passé DIRECTEMENT -> pris tel quel.
    Distinct de `profile_set` (INCHANGÉ — contrat historique où bug_bounty == strictement bb-eligible) :
    ce base AJOUTE le recon au bug_bounty pour que la sélection reste un PIPELINE FONCTIONNEL. Pur."""
    if isinstance(profile, (set, frozenset, list, tuple)):
        return set(profile)
    if profile == "pentest":
        return set(technique_kinds())
    if profile == "bug_bounty":
        return profile_set("bug_bounty") | recon_infra_kinds()
    if profile == "custom":
        return set(custom or ())
    return profile_set(profile)                     # nom inconnu -> via default_profiles (cohérent)


def _split_toggles(spec):
    """Sépare une spec de toggles en (activés, désactivés). Accepte :
      - None                -> (set(), set()) ;
      - un ITÉRABLE de clés -> toutes ACTIVÉES (forme « ensemble d'ajouts ») ;
      - une MAP {clé: bool}  -> True = activée, False = désactivée (forme « panneau de toggles »).
    Pur ; ne lève jamais (une valeur non-bool d'une map est traitée par sa véracité)."""
    enabled, disabled = set(), set()
    if spec is None:
        return enabled, disabled
    if isinstance(spec, dict):
        for k, v in spec.items():
            (enabled if v else disabled).add(k)
    else:
        try:
            for k in spec:
                enabled.add(k)
        except TypeError:                           # spec non itérable -> ignorée (fail-safe)
            pass
    return enabled, disabled


def resolve_enabled_kinds(profile="bug_bounty", techniques_enabled=None,
                          categories_enabled=None, custom=None):
    """L'ENSEMBLE EFFECTIF de kinds-techniques ACTIVÉS pour un scope. Sémantique CLAIRE (SPEC PARTAGÉE) :
      1. BASE   = le profil (bug_bounty = classes payables + recon ; pentest = tout ; custom = vide) ;
      2. + ADD  = activations explicites (catégories entières PUIS techniques) ;
      3. − DROP = désactivations explicites (catégories PUIS techniques) — qui PRIMENT (fail-closed) ;
      4. ∩ technique_kinds() (seuls des kinds RÉELS survivent).
    `techniques_enabled` / `categories_enabled` acceptent chacun soit un ITÉRABLE (tout activé), soit une
    MAP {clé: bool} (toggle on/off) — exactement ce qu'un panneau de sélection produit. Les DÉSACTIVATIONS
    l'emportent sur les activations (ordre-indépendant, fail-closed) : « au scope retirer une technique/
    catégorie des tests automatiques » supprime DÉFINITIVEMENT ces kinds de l'ensemble effectif. Pur."""
    all_kinds = set(technique_kinds())
    base = _profile_base(profile if profile else "bug_bounty", custom=custom)
    cat_en, cat_dis = _split_toggles(categories_enabled)
    tech_en, tech_dis = _split_toggles(techniques_enabled)
    bvc = by_vuln_class()
    enabled = set(base)
    for cat in cat_en:                              # (2) ADD catégories entières
        enabled |= set(bvc.get(cat, ()))
    enabled |= {k for k in tech_en if k in all_kinds}   # (2) ADD techniques
    for cat in cat_dis:                             # (3) DROP catégories (PRIMENT)
        enabled -= set(bvc.get(cat, ()))
    enabled -= set(tech_dis)                        # (3) DROP techniques (PRIMENT)
    return enabled & all_kinds                      # (4) seuls des kinds réels
