# SPDX-License-Identifier: AGPL-3.0-only
"""Données FIGÉES du registre de techniques — LA SOURCE DE VÉRITÉ (stdlib only).

Ce module ne porte QUE des DONNÉES : le dataclass `Technique`, ses helpers `_t`/`_k`, les
chaînes de remédiation `_R_*`, les tables `TECHNIQUES`/`SURFACE`/`CATALOG`, les marqueurs de
découverte et les constantes de profil. Les VUES/RÉSOLVEURS dérivés vivent dans
`forge/techniques.py` (qui ré-exporte ces noms : les chemins d'import publics restent stables).
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
    # AUDIT de durcissement HTTP (en-têtes de sécurité + cookies) — natif Forge, urllib stdlib, non
    # exploit/non destructif. Observation de CONFIG (INFO/LOW, status=tested, jamais vulnerable) : ce
    # que nuclei ne signale pas même toutes sévérités. vuln_class="Hardening", pentest_only.
    _k("web.security_headers", "Hardening", False, depends_on=("recon.httpx",), mitre="T1595.002",
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
# recon.httpx / recon.nmap : service web DÉCOUVERT sur un port NON standard (ex. host:7100). Émis en
# PLUS du finding de synthèse, target = `host:port` -> devient un nœud du graphe que le cerveau chaîne
# (actions web de base + modules web explicites via _directive_actions) sur cette NOUVELLE surface. Sans
# lui, un service web sur un port non standard restait enfoui dans le texte de sortie (jamais une cible).
DISCOVERY_SERVICE_MARKER = "Service web in-scope"
# Marqueur de titre : la découverte plain-HTTP a été BLOQUÉE par un challenge/WAF managé — signature
# de challenge/403 observée ET aucun endpoint extrait. Émis par recon.js_endpoints / recon.content
# (les émetteurs de découverte HTTP) quand la recon curl est challengée (le trou historique :
# « WAF -> recon challengée -> 0 endpoint -> 0 oracle »). Le cerveau (brain, edge (f)) le détecte pour
# AUTO-PROPOSER la voie backed-browser `evasion.discover` sur ce host in-scope, qui franchit le
# challenge et ré-alimente la chaîne discovery->oracle. Constante partagée émetteur/détecteur (zéro
# dérive), distincte des DISCOVERY_*_MARKER par-hôte/endpoint (elle marque un host CHALLENGE-GATÉ, pas
# une cible DÉCOUVERTE) — donc ignorée par le fan-out bound `_discovery_marker`.
DISCOVERY_CHALLENGE_MARKER = "découverte HTTP challengée (WAF/challenge managé)"


# --- Constantes de PROFIL (consommées par les vues dérivées et l'API techniques) -----------------
PROFILES = ("bug_bounty", "pentest")
_PHASE_RANK = {"recon": 0, "access": 1, "exploit": 2, "": 3}
PROFILE_NAMES = PROFILES + ("custom",)              # bug_bounty | pentest | custom (noms de profil)
