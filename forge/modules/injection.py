"""LOT INJECTION — trois oracles de VÉRIFICATION d'injection server-side à PREUVE BÉNIGNE
(`ssti.eval`, `path.traversal`, `sqli.probe`).

Ces oracles CONFIRMENT qu'une faiblesse d'injection est RÉELLE avec une preuve MINIMALE et BÉNIGNE —
c'est de la détection/vérification pour test autorisé, PAS de la weaponization ni du vol de données :

  - ssti.eval      : injecte un marqueur arithmétique aléatoire-unique (un produit N*M) à travers les
                     syntaxes de template courantes ({{…}}, ${…}, #{…}, <%= … %>, …). PREUVE = le
                     PRODUIT évalué est réfléchi dans la réponse (le moteur a ÉVALUÉ l'expression). On ne
                     déclenche JAMAIS d'exécution de code — un simple produit arithmétique, rien d'autre.
  - path.traversal : tente de LIRE un CANARI BÉNIGN et NON SENSIBLE atteignable via traversal (jamais
                     /etc/passwd, jamais un fichier système/credential). PREUVE = le contenu du canari
                     bénin (un marqueur unique fourni par l'opérateur) revient dans la réponse.
  - sqli.probe     : détecte l'injection SQL par différentiel BOOLÉEN et/ou extraction error-based de la
                     VERSION du SGBD UNIQUEMENT (convention workspace « SQLi = version du SGBD seule »).
                     JAMAIS de dump de table/ligne. Enrobe éventuellement sqlmap via le connecteur SANS
                     shell `runner.tool` (absent -> `skipped`) ; la détection PRIMAIRE reste native.

GARDE-FOUS (chaque oracle les respecte, prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : une cible hors périmètre est REFUSÉE avant tout réseau (`_in_scope`
      reconstruit le Scope depuis le périmètre injecté par l'engine ; hors-scope -> `skipped`, AUCUNE
      requête émise). Défense en profondeur : l'engine gate déjà en Couche 2, on re-valide localement.
  (2) PREUVE MINIMALE & BÉNIGNE : promotion `vulnerable` UNIQUEMENT sur preuve concrète (produit
      arithmétique échoé / canari bénin renvoyé / différentiel booléen fiable OU version SGBD). Sinon
      `tested` (jamais de verdict à l'aveugle). Marqueurs bénins seulement — aucune charge weaponisée.
  (3) NON DESTRUCTIF : lecture/vérification seule, aucune mutation d'état (destructive=False). Le
      plancher exploit/destructif du ROE reste OFF par défaut (opt-in inchangé).
  (4) SESSION SECRÈTE : le matériel d'auth gouverné (SessionStore) est fusionné par `Oracle._http`
      UNIQUEMENT sur des URL in-scope et n'est JAMAIS journalisé/rapporté (les PoC dérivent des en-têtes
      de l'appelant, pas de la requête fusionnée).
  (5) DÉGRADATION GRACIEUSE : outil optionnel (sqlmap) ou réseau indisponible -> `skipped` (offline-safe).

Bâti sur la base `Oracle` (construction Finding + câblage HTTP + curl partagés). exploit=False,
destructive=False : sondes de vérification BÉNIGNES (elles n'exfiltrent rien, ne mutent rien) — gardées
par le ROE comme toute interaction web (web_allowed).
"""
import hashlib
import re
import urllib.parse

from .oracle import Oracle, ScopeGuardedOracle
from .registry import register
from .access_control import _body_hash, _normalize_body
from .toolspec import check_extra_args, safe_value
from .. import runner
from .. import techniques


class InjectionOracle(ScopeGuardedOracle):
    """Base des 3 oracles d'injection à PREUVE BÉNIGNE. Hérite de `ScopeGuardedOracle` le scope-guard
    NATIF fail-closed (refus hors périmètre AVANT tout réseau) et le Finding `skipped` de dégradation ;
    ajoute un seam `_fetch` monkeypatchable et l'injection d'un marqueur dans un paramètre (query GET
    ou corps POST)."""

    exploit = False              # sonde de VÉRIFICATION bénigne (ni exfil ni exécution) -> non-exploit
    destructive = False          # lecture/vérification seule : aucune mutation d'état
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # urllib stdlib -> toujours disponible ; dégrade à runtime si besoin

    # --- injection d'un payload dans un paramètre : query si GET, corps urlencodé sinon ---
    def _send(self, action, param, payload, method="GET"):
        """Émet la requête d'injection et renvoie (où, status, body). GET -> payload dans la query ;
        autre méthode -> payload dans un corps urlencodé. Les en-têtes explicites (action.params.headers)
        priment ; la session gouvernée (scope-guardée) est fusionnée SOUS eux par `_http`."""
        headers = dict(action.params.get("headers", {}))
        if method.upper() == "GET":
            sep = "&" if "?" in action.target else "?"
            url = f"{action.target}{sep}{urllib.parse.urlencode({param: payload})}"
            st, body = self._fetch(url, headers=headers, method="GET")
            return url, st, body
        st, body = self._fetch(action.target, headers=headers, method=method.upper(),
                               data=urllib.parse.urlencode({param: payload}))
        return action.target, st, body


# =================================================================================================
#  ssti.eval — Server-Side Template Injection à PREUVE par marqueur arithmétique (T1190 / CWE-1336)
# =================================================================================================
# Syntaxes de template courantes (sentinelles N/M remplacées par les facteurs) — Jinja2/Twig/Nunjucks,
# Freemarker/JSP-EL/Thymeleaf, Ruby/JSF-EL, ERB/EJS, Smarty, Thymeleaf-selection, Razor, Velocity.
_SSTI_TEMPLATES = [
    "{{N*M}}", "${N*M}", "#{N*M}", "<%= N*M %>", "{N*M}", "*{N*M}", "@(N*M)", "#set($f=N*M)$f",
]


@register("ssti.eval")
class SstiEval(InjectionOracle):
    kind = "ssti.eval"
    mitre = techniques.mitre_for("ssti.eval")            # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-1336"                                      # category + cwe des findings
    tool = "forge/modules/injection.py:ssti.eval"
    fix = ("Ne jamais concaténer d'entrée utilisateur dans un template évalué côté serveur : traiter "
           "l'entrée comme des DONNÉES (contexte/variables), pas comme du template ; utiliser un moteur "
           "en mode sandbox/logic-less (auto-échappement), et valider/allowlister strictement toute "
           "entrée qui influence le rendu (CWE-1336).")
    description = ("Oracle SSTI à PREUVE BÉNIGNE : injecte un produit arithmétique unique à travers les "
                   "syntaxes de template ; PREUVE = le produit ÉVALUÉ est réfléchi. Aucune exécution de "
                   "code. Sinon tested. CWE-1336.")

    @classmethod
    def _marker(cls, target, param):
        """(n, m, produit) déterministe-par-cible (reproductible, pas de random non rejouable) et
        DISTINCTIF : deux facteurs à 6 chiffres -> produit à ~11-12 chiffres, quasi impossible à
        rencontrer par coïncidence dans une réponse. Le produit ≠ la réflexion brute `n*m`."""
        h = int(hashlib.sha256(f"{target}|{param}|forge-ssti".encode()).hexdigest(), 16)
        n = 100003 + (h % 899000)
        m = 100003 + ((h >> 64) % 899000)
        return n, m, n * m

    def dry(self, action):
        param = action.params.get("param", "?")
        n, m, prod = self._marker(action.target, action.params.get("param", ""))
        return (f"# injecte {param}={{{{{n}*{m}}}}} (et ${{…}}/#{{…}}/<%= … %>/…) dans {action.target} ; "
                f"PREUVE = le PRODUIT évalué {prod} est réfléchi (le moteur a évalué l'expression) — "
                f"aucune exécution de code ; sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="SSTI non testé — config manquante",
                evidence="Requiert params.param (paramètre injectable). Optionnel : params.method, params.headers.",
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        n, m, product = self._marker(action.target, param)
        prod_s = str(product)
        evaluated, matched_syntax, where = False, "", action.target
        for tmpl in _SSTI_TEMPLATES:
            payload = tmpl.replace("N", str(n)).replace("M", str(m))
            where, st, body = self._send(action, param, payload, method)
            # PREUVE : le PRODUIT apparaît dans la réponse -> l'expression a été ÉVALUÉE côté serveur.
            # (une simple réflexion brute renverrait `n*m` littéral, jamais le produit.)
            if prod_s in (body or ""):
                evaluated, matched_syntax = True, tmpl
                break
        return [self.proof(
            target=where, proven=evaluated,
            title=("SSTI CONFIRMÉ — le moteur de template a évalué l'expression injectée"
                   if evaluated else "SSTI non confirmé — aucune évaluation (pas de verdict à l'aveugle)"),
            severity=("HIGH" if evaluated else "INFO"),
            evidence=(f"marqueur arithmétique {n}*{m} ; produit attendu={prod_s} ; "
                      f"évalué={evaluated}" + (f" ; syntaxe={matched_syntax}" if evaluated else "")),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = le produit {prod_s} apparaît dans la réponse (expression évaluée)"))]


# =================================================================================================
#  path.traversal — Path Traversal / LFI à PREUVE par CANARI BÉNIGN (CWE-22)
# =================================================================================================
# Tokens de traversal (variantes d'encodage / de séparateur) — PRÉFIXÉS devant un canari BÉNIGN
# fourni par l'opérateur. On NE cible JAMAIS de fichier système/credential (pas de /etc/passwd).
_TRAVERSAL_TOKENS = ["../", "..%2f", "..%252f", "....//", "..\\", "%2e%2e/"]
_DEFAULT_CANARY_NAME = "forge-canary.txt"                 # canari BÉNIGN par défaut (déposé par l'opérateur)


@register("path.traversal")
class PathTraversal(InjectionOracle):
    kind = "path.traversal"
    mitre = techniques.mitre_for("path.traversal")       # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-22"                                        # category + cwe des findings
    tool = "forge/modules/injection.py:path.traversal"
    fix = ("Ne jamais construire un chemin de fichier à partir d'une entrée utilisateur : résoudre le "
           "chemin canonique (realpath) et vérifier qu'il reste SOUS un répertoire racine autorisé "
           "(allowlist), rejeter les séquences de traversal et les encodages ; préférer un identifiant "
           "indirect (map id -> fichier) plutôt qu'un nom de fichier fourni par le client (CWE-22).")
    description = ("Oracle path-traversal à PREUVE BÉNIGNE : lit un CANARI non sensible via traversal "
                   "(jamais de fichier système). PREUVE = le marqueur bénin du canari revient. Sinon "
                   "tested. CWE-22.")
    MAX_DEPTH = 8                                         # profondeur max de `../` (borne les requêtes)

    def _payloads(self, action):
        """Liste des payloads de traversal à essayer. `params.canary_rel` (chaîne ou liste) prime :
        chemin(s) relatif(s) exact(s) fourni(s) par l'opérateur. Sinon, on génère token×profondeur +
        nom de canari bénin (`params.canary_name`, défaut `forge-canary.txt`)."""
        rel = action.params.get("canary_rel")
        if rel:
            return [rel] if isinstance(rel, str) else list(rel)
        name = str(action.params.get("canary_name") or _DEFAULT_CANARY_NAME).lstrip("/")
        try:
            depth = max(1, min(int(action.params.get("max_depth") or self.MAX_DEPTH), 12))
        except (TypeError, ValueError):
            depth = self.MAX_DEPTH
        payloads = []
        for tok in _TRAVERSAL_TOKENS:
            for d in range(1, depth + 1):
                payloads.append(tok * d + name)
        return payloads

    def dry(self, action):
        param = action.params.get("param", "?")
        name = str(action.params.get("canary_name") or _DEFAULT_CANARY_NAME)
        return (f"# injecte {param}=../../…/{name} (canari BÉNIGN, jamais /etc/passwd) dans "
                f"{action.target} ; PREUVE = le marqueur bénin du canari revient dans la réponse ; "
                f"sinon tested")

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        marker = action.params.get("canary_marker")
        if not param or not marker:
            return [self.skip(
                target=action.target, title="Path traversal non testé — config manquante",
                evidence=("Requiert params.param (paramètre de fichier) et params.canary_marker (marqueur "
                          "unique BÉNIGN attendu dans le canari non sensible). Optionnel : params.canary_name "
                          "/ params.canary_rel / params.max_depth / params.method."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        read, matched, where = False, "", action.target
        for payload in self._payloads(action):
            where, st, body = self._send(action, param, payload, method)
            # PREUVE : le marqueur BÉNIGN du canari revient -> le paramètre lit un fichier via traversal.
            if marker in (body or ""):
                read, matched = True, payload
                break
        return [self.proof(
            target=where, proven=read,
            title=("Path traversal CONFIRMÉ — lecture d'un canari bénin via traversal"
                   if read else "Path traversal non confirmé — le canari bénin n'est pas revenu"),
            severity=("HIGH" if read else "INFO"),
            evidence=(f"canari bénin lu={read} (marqueur bénin fourni par l'opérateur ; "
                      f"aucun fichier système ciblé)" + (f" ; payload={matched}" if read else "")),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = le marqueur bénin du canari apparaît dans la réponse"))]


# =================================================================================================
#  sqli.probe — SQL Injection à PREUVE (différentiel booléen / version SGBD error-based) — CWE-89
# =================================================================================================
# Signatures d'erreur SGBD (minuscules) — leur APPARITION (absente de la baseline) atteste une injection
# error-based. On n'extrait QUE la version (jamais de données de table/ligne).
_SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax", "warning: mysqli", "warning: mysql",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "sqlstate", "org.postgresql.util.psqlexception", "psql: error", "pg_query", "pg_exec",
    "syntax error at or near", "sqlite3::", "sqlite_error", "unrecognized token",
    "microsoft ole db provider", "odbc sql server driver", "microsoft sql native client",
    "ora-00933", "ora-01756", "ora-00921", "supplied argument is not a valid mysql",
    "mysql_fetch", "division by zero", "conversion failed when converting",
]
# Extraction de la VERSION du SGBD UNIQUEMENT (convention workspace « SQLi = version du SGBD seule »).
_DBMS_VERSION_RX = re.compile(
    r"(?i)\b(mariadb|mysql|postgresql|postgres|sqlite|oracle|microsoft sql server|mssql)\b[^\r\n]{0,40}?(\d+\.\d+(?:\.\d+)?)")
# Paires (VRAI, FAUX) de différentiel booléen — contextes chaîne et numérique.
_BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
]


@register("sqli.probe")
class SqliProbe(InjectionOracle):
    kind = "sqli.probe"
    mitre = techniques.mitre_for("sqli.probe")           # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-89"                                        # category + cwe des findings
    tool = "forge/modules/injection.py:sqli.probe"
    fix = ("Requêtes paramétrées / ORM avec liaison des variables ; ne JAMAIS concaténer d'entrée "
           "utilisateur dans une requête SQL ; validation/allowlist des entrées et principe du moindre "
           "privilège sur le compte de base de données (CWE-89).")
    description = ("Oracle SQLi à PREUVE : différentiel BOOLÉEN fiable et/ou version SGBD error-based "
                   "UNIQUEMENT (jamais de dump de données). sqlmap optionnel via runner (absent -> "
                   "skipped) ; détection primaire native. Sinon tested. CWE-89. Params UI sqlmap : "
                   "level/risk/technique/dbms/delay + extra_args (allowlist).")
    SQLMAP_BIN = "sqlmap"
    # SCHÉMA servi à l'UI — la sonde native lit param/value/method ; les knobs sqlmap tunent la
    # corroboration OPT-IN (params.sqlmap). Rendu par modules-form.js via `forge modules --json`.
    PARAMS_SCHEMA = [
        {"name": "param", "type": "text", "label": "paramètre injectable (requis)", "flag": ""},
        {"name": "value", "type": "text", "label": "valeur de base (défaut 1)", "flag": ""},
        {"name": "method", "type": "select", "label": "méthode HTTP", "flag": "", "allowed": ["GET", "POST"]},
        {"name": "level", "type": "select", "label": "sqlmap --level", "flag": "--level",
         "allowed": ["1", "2", "3", "4", "5"]},
        {"name": "risk", "type": "select", "label": "sqlmap --risk", "flag": "--risk",
         "allowed": ["1", "2", "3"]},
        {"name": "technique", "type": "text", "label": "sqlmap --technique (défaut BE)", "flag": "--technique"},
        {"name": "dbms", "type": "text", "label": "sqlmap --dbms (ex MySQL)", "flag": "--dbms"},
        {"name": "extra_args", "type": "list", "label": "extra args sqlmap (allowlist)", "flag": ""},
    ]
    # ALLOWLIST CONSERVATRICE des drapeaux sqlmap acceptés en argument libre — tout flag hors liste est
    # REFUSÉ. EXCLUS explicitement : --dump/--dump-all/--os-shell/--os-cmd/--sql-shell/--file-read/
    # --file-write/--eval/-r/--tamper/--proxy/--output-dir/--config (exfil, RCE, I/O fichier, exfil réseau
    # — au-delà de l'usage gouverné « SQLi = détection + version SGBD seule »).
    FLAG_ALLOWLIST = ("--level", "--risk", "--technique", "--dbms", "--delay", "--timeout", "--threads",
                      "--batch", "--random-agent", "-p", "--banner", "--time-sec", "--retries",
                      "--string", "--not-string", "--code")

    # --- seams sqlmap (patchables ; corroboration OPTIONNELLE opt-in, jamais la détection primaire) ---
    @staticmethod
    def _sqlmap_available():
        """Seam (patchable) : le binaire sqlmap est-il présent ? Absent -> dégradation `skipped`."""
        return runner.available(SqliProbe.SQLMAP_BIN, None)

    @staticmethod
    def _run_sqlmap(url, param, method, timeout, opts=None):
        """Seam sous-processus SANS shell (via runner.tool) : lance sqlmap en mode NON destructif
        (batch, sans dump). Renvoie (rc, stdout, stderr). Patchable par les tests. `opts` (dict optionnel)
        pilote level/risk/technique/dbms/delay + extra_args VALIDÉS -> argv BYTE-IDENTIQUE au défaut
        (level 1, risk 1, technique BE) quand `opts` est absent/vide."""
        o = opts or {}
        level = o.get("level") if safe_value(str(o.get("level", ""))) else "1"
        risk = o.get("risk") if safe_value(str(o.get("risk", ""))) else "1"
        tech = o.get("technique") if safe_value(str(o.get("technique", ""))) else "BE"
        args = ["-u", url, "-p", param, "--batch", "--level", str(level), "--risk", str(risk),
                "--technique", str(tech), "--flush-session", "--answers", "quit=N",
                "--timeout", "10", "--retries", "1", "--disable-coloring"]
        dbms = o.get("dbms")
        if dbms and safe_value(str(dbms)):
            args += ["--dbms", str(dbms)]
        delay = o.get("delay")
        if delay and safe_value(str(delay)):
            args += ["--delay", str(delay)]
        args += list(o.get("extra") or ())
        if method and method.upper() != "GET":
            args += ["--method", method.upper()]
        return runner.tool(SqliProbe.SQLMAP_BIN, None, args, timeout=timeout)

    def dry(self, action):
        param = action.params.get("param", "?")
        return (f"# différentiel booléen sur {param} de {action.target} : baseline vs "
                f"`AND 1=1` (VRAI) vs `AND 1=2` (FAUX) ; + version SGBD error-based (guillemet) — "
                f"PREUVE = différentiel booléen fiable OU version SGBD ; JAMAIS de dump ; sinon tested")

    @staticmethod
    def _dbms_from_error(body):
        """(signature d'erreur trouvée | '', version SGBD extraite | '') — VERSION SEULE, aucune donnée."""
        low = (body or "").lower()
        sign = next((s for s in _SQL_ERROR_SIGNS if s in low), "")
        m = _DBMS_VERSION_RX.search(body or "")
        version = f"{m.group(1)} {m.group(2)}" if m else ""
        return sign, version

    def fire(self, action):
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        param = action.params.get("param")
        if not param:
            return [self.skip(
                target=action.target, title="SQLi non testé — config manquante",
                evidence=("Requiert params.param (paramètre injectable). Optionnel : params.value "
                          "(valeur de base), params.method, params.headers, params.sqlmap (corroboration)."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "GET")).upper()
        value = str(action.params.get("value", "1"))

        # baseline (référence de comparaison du différentiel booléen)
        where, base_st, base_body = self._send(action, param, value, method)
        base_hash = _body_hash(base_body)
        base_sign, _ = self._dbms_from_error(base_body)

        # (A) différentiel BOOLÉEN : VRAI ~= baseline (même corps normalisé, même statut) ET FAUX ≠ VRAI.
        bool_confirmed, bool_ctx = False, ""
        for ptrue, pfalse in _BOOL_PAIRS:
            _, t_st, t_body = self._send(action, param, value + ptrue, method)
            _, f_st, f_body = self._send(action, param, value + pfalse, method)
            same_true = (t_st == base_st and _normalize_body(t_body) and _body_hash(t_body) == base_hash)
            differs = _body_hash(f_body) != _body_hash(t_body)
            if same_true and differs:
                bool_confirmed, bool_ctx = True, ptrue.strip()
                break

        # (B) error-based : un guillemet provoque une erreur SGBD ABSENTE de la baseline -> injection.
        #     On n'extrait QUE la version du SGBD (jamais de données). Signature déjà présente en
        #     baseline -> non probante (l'app affiche cette erreur en temps normal).
        _, e_st, e_body = self._send(action, param, value + "'", method)
        err_sign, err_version = self._dbms_from_error(e_body)
        error_confirmed = bool(err_sign) and not base_sign

        proven = bool_confirmed or error_confirmed
        tech = ", ".join(t for t in (
            ("différentiel booléen" if bool_confirmed else ""),
            ("error-based (version SGBD)" if error_confirmed else "")) if t) or "aucune"
        findings = [self.proof(
            target=where, proven=proven,
            title=("SQLi CONFIRMÉ — " + tech if proven
                   else "SQLi non confirmé — ni différentiel booléen ni erreur SGBD (pas de verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"technique={tech} ; contexte_booléen={bool_ctx or '—'} ; "
                      f"erreur_SGBD={err_sign or '—'} ; version_SGBD={err_version or '—'} "
                      f"(version seule — aucun dump de données)"),
            poc=(f"# {self._curl(where, dict(action.params.get('headers', {})), method)}\n"
                 f"# PREUVE = différentiel booléen (AND 1=1 vs AND 1=2) OU version SGBD error-based ; "
                 f"jamais de dump"))]

        # (C) corroboration sqlmap OPTIONNELLE (opt-in params.sqlmap) — connecteur SANS shell.
        #     Absente -> DÉGRADATION GRACIEUSE `skipped` (offline-safe) ; la détection native prime.
        if action.params.get("sqlmap"):
            findings.append(self._sqlmap_corroborate(action, where, param, method))
        return findings

    def _sqlmap_corroborate(self, action, url, param, method):
        """Corroboration sqlmap (opt-in). Binaire absent -> `skipped`. Présent -> exécution NON
        destructive (technique BE, sans dump) ; sortie mappée en finding INFO (jamais de dump)."""
        if not self._sqlmap_available():
            return self.degraded(
                target=url, title="sqli.probe — corroboration sqlmap ignorée (sqlmap indisponible)",
                evidence=("Le binaire sqlmap est absent : corroboration sautée (dégradation gracieuse). "
                          "La détection native reste la source de vérité. Installer sqlmap pour activer."),
                poc=self.dry(action))
        # EXTRA_ARGS gouvernés : un drapeau sqlmap libre hors allowlist (ou non-liste) -> refus fail-closed.
        bad_extra, extra = check_extra_args(action.params.get("extra_args"), self.FLAG_ALLOWLIST)
        if bad_extra is not None:
            return self.degraded(
                target=url, title="sqli.probe — corroboration sqlmap refusée (argument libre hors allowlist)",
                evidence=f"extra_args refusé : {bad_extra}. Aucun processus lancé (fail-closed).",
                poc=self.dry(action))
        try:
            timeout = max(30, min(int(action.params.get("timeout") or 120), 600))
        except (TypeError, ValueError):
            timeout = 120
        opts = {"level": action.params.get("level"), "risk": action.params.get("risk"),
                "technique": action.params.get("technique"), "dbms": action.params.get("dbms"),
                "delay": action.params.get("rate_delay_s"), "extra": extra}
        rc, out, err = self._run_sqlmap(url, param, method, timeout, opts)
        if rc in (124, 127) or (rc != 0 and not out):
            return self.degraded(
                target=url, title="sqli.probe — corroboration sqlmap non concluante (échec/indisponible)",
                evidence=(f"rc={rc} ; " + ((err or out) or "").strip()[:300]) or f"rc={rc}",
                poc=self.dry(action))
        low = (out or "").lower()
        confirmed = ("is vulnerable" in low or "parameter" in low and "injectable" in low)
        # sqlmap ne fait que CORROBORER : on remonte un INFO `tested` (la promotion vulnerable vient de
        # la preuve native), en n'exposant que le verdict + la bannière SGBD (jamais de données).
        return self.finding(
            target=url, severity="INFO", category=self.cwe, cwe=self.cwe, mitre=self.mitre,
            fix=self.fix, status="tested", tool=self.tool,
            title=("sqli.probe — sqlmap corrobore l'injection (paramètre injectable)"
                   if confirmed else "sqli.probe — sqlmap n'a pas corroboré"),
            evidence=(f"sqlmap rc={rc} ; corroboré={confirmed} (version/bannière seules, aucun dump)"),
            poc=self.dry(action))
