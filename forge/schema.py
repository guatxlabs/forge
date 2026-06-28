"""Modèle de données rouge de Forge (stdlib only).

Aligné sur la `Finding` de secpipe (réutilisation), + champs orientés engagement :
`status` (machine d'état), `mitre` (clé de jointure de la boucle purple avec Plume),
`target_id`. Target et Campaign donnent la cohérence multi-cible / multi-étape.

ENRICHISSEMENT (LOT SCHEMA/FIX) — remédiation + taxonomie exploitables côté client :
  - `fix` : remédiation par défaut auto-déduite (catégorie/technique -> conseil), JAMAIS au détriment
    d'un `fix` explicite passé par le module (le fix spécifique d'un module PRIME).
  - `cwe` : champ dédié, séparé de `category` (qui restait un fourre-tout CWE/CIS). Rétro-compat :
    si le module n'a passé que `category="CWE-639"`, on en dérive `cwe` automatiquement — `category`
    n'est jamais effacé.
  - `cvss_vector`/`cvss_score` : vecteur/score de BASE par classe d'oracle, dérivé de la sévérité quand
    le module n'en fournit pas (repère grossier de priorisation, pas un calcul CVSS complet).
Tous ces enrichissements sont ADDITIFS et FAIL-OPEN : aucun n'écrase une valeur fournie par le module,
et l'absence de mapping laisse simplement le champ vide (zéro régression de comportement).
"""
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# machine d'état d'un finding (reprend la logique FAISS du toolkit YWH).
# `reported_by_tool` : un outil tiers (ex: nuclei) a signalé un hit sur sa propre sévérité
# auto-déclarée — ce n'est PAS une vuln confirmée par Forge. On garde la sévérité de l'outil
# pour la priorisation, mais ce statut empêche le sur-classement en `vulnerable` (pas de preuve
# différentielle/manuelle). La promotion en `vulnerable` reste réservée aux oracles de Forge (IDOR,
# origine vérifiée) qui apportent une preuve d'exploitabilité.
STATUSES = ["tested", "reported_by_tool", "vulnerable", "not_vulnerable", "submitted", "accepted", "informative", "invalid"]

# ---------------------------------------------------------------------------
# Remédiation par défaut — mapping clé (catégorie/CWE/technique normalisée) -> conseil de fix.
# Sert de REPLI : si un module émet un finding sans `fix`, on en déduit une remédiation générique à
# partir de sa `category`/`cwe`. Un `fix` explicite du module PRIME toujours (jamais écrasé).
# Les clés sont normalisées (minuscule, sans espaces autour) ; on tente plusieurs formes (CWE brut,
# label de catégorie type 'origin-exposure', etc.) pour maximiser la couverture sans casser la compat.
# ---------------------------------------------------------------------------
DEFAULT_FIXES = {
    # --- Access control / IDOR / BOLA (CWE-639, CWE-284, CWE-862) ---
    "cwe-639": ("Contrôle d'ownership côté serveur : vérifier que l'utilisateur authentifié possède "
                "bien la ressource (objet lié au compte) avant tout accès ; ne jamais se fier à un "
                "identifiant fourni par le client. Préférer des identifiants non énumérables (UUID)."),
    "cwe-284": ("Appliquer un contrôle d'accès systématique côté serveur (deny-by-default) sur chaque "
                "endpoint et chaque objet ; centraliser l'autorisation, ne pas la dériver du client."),
    "cwe-862": ("Ajouter une vérification d'autorisation manquante sur l'endpoint : exiger une session "
                "valide ET vérifier les droits sur la ressource ciblée avant de répondre."),
    "idor": ("Contrôle d'ownership côté serveur avant tout accès à la ressource ; identifiants non "
             "énumérables (UUID) et autorisation centralisée deny-by-default."),
    "access_control": ("Contrôle d'accès deny-by-default côté serveur sur chaque endpoint/objet ; "
                        "ne jamais dériver l'autorisation d'un identifiant fourni par le client."),
    "bola": ("Vérifier l'ownership de l'objet côté serveur (Broken Object Level Authorization) avant "
             "de servir ou muter la ressource."),
    # --- SSRF (CWE-918) ---
    "cwe-918": ("Allowlist stricte des hôtes/schemas autorisés côté serveur ; bloquer les IP internes "
                "(RFC1918, loopback, link-local) et les endpoints de métadonnées cloud (169.254.169.254) ; "
                "résoudre puis re-valider l'IP (anti-DNS-rebinding), désactiver les redirections."),
    "ssrf": ("Allowlist d'hôtes/schemas, blocage des IP internes et des métadonnées cloud "
             "(169.254.169.254), re-validation post-résolution DNS, pas de suivi de redirection."),
    # --- Auth / ATO (CWE-287, CWE-640) ---
    "cwe-287": ("Renforcer l'authentification : invalider les sessions après reset, tokens de reset "
                "à usage unique liés à l'utilisateur et à durée de vie courte, MFA sur les actions "
                "sensibles ; ne jamais accepter un état d'auth dérivable côté client."),
    "cwe-640": ("Sécuriser le flux de réinitialisation : token aléatoire imprévisible (CSPRNG), à usage "
                "unique, lié au compte et expirant rapidement ; ne pas divulguer la validité du compte."),
    "auth": ("Authentification serveur robuste : sessions invalidées au reset, tokens à usage unique, "
             "MFA sur actions sensibles ; aucun état d'auth dérivable côté client."),
    "ato": ("Bloquer la prise de contrôle de compte : tokens de reset à usage unique liés au compte, "
            "rotation de session, MFA, et détection des anomalies de connexion."),
    # --- CORS (CWE-942, CWE-346) ---
    "cwe-942": ("Ne JAMAIS combiner Access-Control-Allow-Origin: * (ou reflet d'origine arbitraire) avec "
                "Access-Control-Allow-Credentials: true. Refléter uniquement des origines d'une allowlist "
                "stricte et n'autoriser les credentials que pour ces origines de confiance."),
    "cwe-346": ("Valider strictement l'origine (allowlist exacte, pas de reflet d'Origin arbitraire) "
                "avant d'autoriser une lecture cross-origin authentifiée."),
    "cors": ("Allowlist d'origines stricte ; ne pas refléter une Origin arbitraire avec "
             "Access-Control-Allow-Credentials: true (combinaison non exploitable mais à proscrire)."),
    # --- Exposition d'origine derrière CDN/WAF ---
    "origin-exposure": ("Restreindre l'accès à l'IP d'origine au seul CDN/WAF : allowlist des plages IP "
                        "du fournisseur (Cloudflare) au niveau pare-feu/groupe de sécurité, refuser tout "
                        "trafic direct ; rendre l'origine non joignable hors du CDN."),
    # --- Injections classiques (replis utiles si des modules les émettent plus tard) ---
    "cwe-89": ("Requêtes paramétrées / ORM avec liaison des variables ; jamais de concaténation de "
               "données utilisateur dans une requête SQL ; principe du moindre privilège sur le compte DB."),
    "sqli": ("Requêtes paramétrées (prepared statements), validation/échappement, moindre privilège DB."),
    "cwe-79": ("Échapper/encoder la sortie selon le contexte (HTML/attribut/JS/URL) ; CSP stricte ; "
               "préférer des frameworks qui encodent par défaut ; valider les entrées en allowlist."),
    "xss": ("Encodage contextuel de la sortie, CSP stricte, frameworks auto-échappants, validation "
            "d'entrée en allowlist."),
    "cwe-78": ("Éviter l'exécution de commandes shell avec des données utilisateur ; utiliser des APIs "
               "natives ; si inévitable, allowlist d'arguments et exécution sans shell (execve)."),
    "cwe-352": ("Jeton anti-CSRF par requête mutante + cookies SameSite=Lax/Strict ; vérifier l'en-tête "
                "Origin/Referer sur les actions sensibles."),
    "csrf": ("Token anti-CSRF par requête mutante, cookies SameSite, vérification Origin/Referer."),
    "cwe-918-blind": ("Allowlist + blocage métadonnées/IP internes (voir CWE-918)."),
}

# ---------------------------------------------------------------------------
# CVSS de base par sévérité — repère grossier de priorisation (PAS un calcul CVSS complet par finding).
# Vecteur CVSS 3.1 « plausible » pour une classe d'impact donnée + score représentatif de la bande.
# Dérivé UNIQUEMENT quand le module ne fournit pas son propre vecteur/score (fail-open, additif).
# ---------------------------------------------------------------------------
CVSS_BASE_BY_SEVERITY = {
    "CRITICAL": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "HIGH":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "MEDIUM":   ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "LOW":      ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "INFO":     ("", 0.0),
}

# Repère un identifiant CWE dans une chaîne (ex: "CWE-639", "cwe_639", "CWE 639").
_CWE_RX = re.compile(r"(?i)\bcwe[\s_-]?(\d+)\b")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_cwe(text):
    """Extrait un identifiant CWE canonique ('CWE-639') d'une chaîne, ou '' si absent. Pur."""
    if not text:
        return ""
    m = _CWE_RX.search(text)
    return f"CWE-{m.group(1)}" if m else ""


def default_fix_for(cwe="", category="", mitre=""):
    """Conseil de remédiation par défaut pour une (cwe/category/mitre). '' si aucun mapping.

    Stratégie de recherche, du plus spécifique au plus large (toutes clés normalisées minuscule) :
      1. le CWE dédié (ex 'cwe-639') ;
      2. un CWE éventuellement niché dans `category` ;
      3. la `category` brute normalisée (ex 'origin-exposure', 'idor', 'cors') ;
      4. chaque token de la `category` (gère 'access_control.idor' -> 'access_control' / 'idor').
    Pur, sans effet de bord. Ne lève jamais.
    """
    cat = (category or "").strip().lower()
    candidates = []
    if cwe:
        candidates.append(cwe.strip().lower())
    nested = extract_cwe(category).lower()
    if nested:
        candidates.append(nested)
    if cat:
        candidates.append(cat)
        # tokens : 'access_control.idor' -> ['access_control', 'idor'] ; 'cors.credentials' -> ...
        for tok in re.split(r"[.\s/_-]+", cat):
            tok = tok.strip()
            if tok and tok not in candidates:
                candidates.append(tok)
    for key in candidates:
        if key in DEFAULT_FIXES:
            return DEFAULT_FIXES[key]
    return ""


def cvss_base_for(severity):
    """(vecteur, score) CVSS de base pour une sévérité. ('', 0.0) si inconnue. Pur."""
    return CVSS_BASE_BY_SEVERITY.get((severity or "").upper(), ("", 0.0))


@dataclass
class Finding:
    target: str
    title: str
    severity: str = "INFO"
    category: str = ""          # CWE / CIS (checklist) — fourre-tout historique, conservé (rétro-compat)
    cwe: str = ""               # CWE dédié (ex 'CWE-639') — séparé de category ; auto-dérivé si vide
    mitre: str = ""             # ATT&CK technique id (T1190...) — jointure boucle purple avec Plume
    status: str = "tested"
    evidence: str = ""
    fix: str = ""               # remédiation — auto-déduite si vide (le fix explicite du module PRIME)
    cvss_vector: str = ""       # vecteur CVSS 3.1 de base (dérivé de la sévérité si vide)
    cvss_score: float = 0.0     # score CVSS de base représentatif (dérivé de la sévérité si vide)
    tool: str = ""
    poc: str = ""               # commande/PoC reproductible
    ts: str = field(default_factory=_now)

    def __post_init__(self):
        # 1) CWE dédié : si non fourni, le dériver de `category` (rétro-compat avec les modules qui
        #    n'utilisaient que `category="CWE-639"`). `category` n'est jamais modifié.
        if not self.cwe:
            self.cwe = extract_cwe(self.category)
        # 2) Remédiation : ne JAMAIS écraser un `fix` explicite (le fix spécifique du module prime).
        #    Sinon, replier sur le mapping par défaut (cwe -> category -> tokens).
        if not self.fix:
            self.fix = default_fix_for(cwe=self.cwe, category=self.category, mitre=self.mitre)
        # 3) CVSS de base : dérivé de la sévérité UNIQUEMENT si le module n'en fournit pas
        #    (fail-open ; INFO -> vecteur vide / score 0.0).
        if not self.cvss_vector and not self.cvss_score:
            self.cvss_vector, self.cvss_score = cvss_base_for(self.severity)

    def sev_rank(self):
        return SEVERITIES.index(self.severity) if self.severity in SEVERITIES else 0

    def to_dict(self):
        return asdict(self)


@dataclass
class Target:
    host: str
    kind: str = "host"          # host | service | url | app
    attrs: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Campaign:
    name: str
    scope_path: str = ""
    started: str = field(default_factory=_now)
    notes: str = ""

    def to_dict(self):
        return asdict(self)
