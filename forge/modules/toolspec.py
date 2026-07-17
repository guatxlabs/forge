# SPDX-License-Identifier: AGPL-3.0-only
"""Wrapper GÉNÉRIQUE gouverné d'outils externes — déclarer N'IMPORTE QUEL outil CLI de sécurité comme
un module Forge À PARTIR D'UN SPEC, SOUS la même gouvernance que les modules natifs.

C'est le point d'extension qui ABSORBE la propriété « wrap-any-tool » de Trickest / Faraday / Osmedeus :
un utilisateur qui migre déclare un `ToolSpec` (nom/kind, vuln_class, binaire, gabarit d'argv, parseur de
sortie, mapping technique/cwe/mitre, timeout, sonde de disponibilité, flags exploit/destructif, profils)
et `register_spec(spec)` :
  1. FOLD la technique dans `forge/techniques.py` (via `techniques.register_kind`) -> elle apparaît
     automatiquement au catalogue groupé (`by_vuln_class`), au pipeline ordonné, à la sélection par-scope
     et aux bons profils, SANS câblage par-technique ;
  2. GÉNÈRE une sous-classe `Module` et l'enregistre via `@register` -> elle apparaît dans
     `forge modules --json`, l'admin console et le plan du cerveau.

INVARIANTS (jamais affaiblis — hérités des modules natifs, prouvés par les tests) :
  - SCOPE-GUARD ROE fail-closed : une cible HORS périmètre -> `status='skipped'`, ZÉRO I/O (aucun
    processus lancé) ; un ASSET DÉCOUVERT hors périmètre n'est JAMAIS émis (re-validation fail-closed).
  - NO-SHELL / argv FIXE : `target`/`params` deviennent des ÉLÉMENTS d'argv, jamais concaténés dans une
    chaîne shell -> une cible contenant des métacaractères shell reste UN SEUL élément (anti-injection).
    L'exécution passe par `runner.tool()` (subprocess sans shell), le connecteur no-shell partagé.
  - PROOF-ORIENTED : un hit de scanner devient `status='tested'` ou `reported_by_tool` AVEC attribution
    de l'outil — JAMAIS `vulnerable` (aucune preuve différentielle côté Forge ; la promotion `vulnerable`
    reste réservée aux oracles à preuve). Le statut est CLAMPÉ à {tested, reported_by_tool}.
  - PLANCHER EXPLOIT : un outil de classe exploit (`spec.exploit=True`, ex sqlmap) est gaté par l'opt-in
    (le ROE de l'engine exige `allow_exploit` ; défense en profondeur ré-vérifiée ici si un scope est lié).
  - DÉGRADATION GRACIEUSE : binaire absent (ni local ni docker) -> `status='skipped'` (offline-safe).
  - SECRETS : les valeurs de params SECRÈTES (token/clé) ne sont pas fabriquées ici ; le spec passe des
    noms de params, jamais des credentials en dur.

Zéro dépendance (stdlib) — cohérent avec le cœur Forge.
"""
import json
import re

from . import _daemon_reap
from . import _discovery
from ._scopeguard import ScopeGuardMixin
from .registry import register, Module
from .. import runner
from .. import techniques
from ..challenge import looks_like_challenge

_MISSING = object()                      # sentinelle : placeholder requis manquant -> token abandonné
_MAX_HITS = 200                          # borne le nombre de findings émis par exécution (anti-flood)
_TOK_RX = re.compile(r"\{([^{}]*)\}")    # un placeholder `{...}` dans un token de gabarit


# =================================================================================================
#  ToolSpec — la DÉCLARATION unique d'un outil (source de vérité ; tout en DÉRIVE)
# =================================================================================================
class ToolSpec:
    """Spécification déclarative d'un outil CLI externe. Immuable après construction (aucune méthode ne
    la mute). Champs :

      kind            : clé de module POINTÉE et UNIQUE (ex "recon.subfinder", "xss.dalfox").
      vuln_class      : CATÉGORIE de vuln/fonction (ex "Recon", "XSS", "SQLi", "PortScan", "TLS").
      binary          : binaire local (résolu via PATH). `docker_image` = repli conteneurisé optionnel.
      argv_template   : tuple de TOKENS. Un token = littéral OU placeholder `{...}` OU un GROUPE (tuple
                        de tokens = tout-ou-rien : abandonné en bloc si un placeholder requis manque).
                        Placeholders : {target} {target_host} {target_url} {param:NAME} {param:NAME:DEF}.
                        RÉSOLUTION en éléments d'argv SÉPARÉS — jamais de concaténation shell.
      cwe / mitre     : mapping technique (le finding porte ces valeurs ; mitre == la table).
      phase           : recon | access | exploit.  capability : passive | active | exploit.
      attck_tactic    : tactique ATT&CK lisible (requise pour une entrée phasée).
      bug_bounty_eligible : produit un finding PAYABLE en propre ? (défaut False : un scanner REPORTE).
      exploit / destructive : capacité gouvernée (exploit -> gaté par le plancher opt-in).
      depends_on      : kinds requis en amont (ordonnancement pipeline ; doivent être enregistrés).
      timeout         : borne d'exécution (s).  prefer_docker : préférence d'ordre binaire/docker.
      parser          : lines | regex | json | jsonl | none  (comment extraire les hits de la sortie).
      parser_regex    : regex pour parser="regex" (group(1) si présent, sinon group(0)).
      parser_json_path: tuple de clés pour parser=json/jsonl (chemin vers la valeur du hit).
      severity        : sévérité par défaut d'un hit (proof-oriented : INFO/LOW).
      hit_status      : 'tested' (recon/découverte) | 'reported_by_tool' (scanner) — CLAMPÉ à ces deux.
      hit_is_asset    : True -> chaque hit est un ASSET découvert (attribué + re-validé scope fail-closed) ;
                        False -> hit attribué à `action.target` ; None -> dérivé (phase=='recon').
      tool_name       : label de provenance estampillé (défaut = binary).  description : texte console.
    """

    __slots__ = (
        "kind", "vuln_class", "binary", "argv_template", "cwe", "mitre", "phase", "capability",
        "attck_tactic", "proof_required", "bug_bounty_eligible", "exploit", "destructive", "cls",
        "depends_on", "tools", "docker_image", "prefer_docker", "timeout", "parser", "parser_regex",
        "parser_json_path", "severity", "hit_status", "hit_is_asset", "tool_name", "description",
        "params_schema", "flag_allowlist", "emit_service_discovery", "emit_endpoint_discovery",
        "skip_bare_ip", "reap_daemon",
    )

    def __init__(self, kind, vuln_class, binary, argv_template, *, cwe="", mitre="", phase="recon",
                 capability="active", attck_tactic="Reconnaissance", proof_required=True,
                 bug_bounty_eligible=False, exploit=False, destructive=False, cls="", depends_on=(),
                 tools=(), docker_image="", prefer_docker=False, timeout=300, parser="lines",
                 parser_regex="", parser_json_path=(), severity="INFO", hit_status="reported_by_tool",
                 hit_is_asset=None, tool_name="", description="", params_schema=(), flag_allowlist=(),
                 emit_service_discovery=False, emit_endpoint_discovery=False, skip_bare_ip=False,
                 reap_daemon=False):
        self.kind = kind
        self.vuln_class = vuln_class
        self.binary = binary
        self.argv_template = tuple(argv_template)
        self.cwe = cwe
        self.mitre = mitre
        self.phase = phase
        self.capability = capability
        self.attck_tactic = attck_tactic
        self.proof_required = proof_required
        self.bug_bounty_eligible = bug_bounty_eligible
        self.exploit = exploit
        self.destructive = destructive
        self.cls = cls
        self.depends_on = tuple(depends_on)
        self.tools = tuple(tools)
        self.docker_image = docker_image
        self.prefer_docker = prefer_docker
        self.timeout = timeout
        self.parser = parser
        self.parser_regex = parser_regex
        self.parser_json_path = tuple(parser_json_path)
        self.severity = severity
        self.hit_status = hit_status
        self.hit_is_asset = hit_is_asset
        self.tool_name = tool_name or binary
        self.description = description
        # SCHÉMA DE PARAMS (source unique servie à l'UI) : tuple de descripteurs
        #   {name, type in (text|number|select|list|flag), label, flag (drapeau CLI mappé), allowed?, default?}
        # ADDITIF : consommé par `forge modules --json` (→ console → formulaire dynamique). N'élargit
        # AUCUNE capacité : les valeurs restent des ÉLÉMENTS d'argv (no-shell), et un `{args}` custom est
        # borné par `flag_allowlist` (tout flag hors liste est REFUSÉ fail-closed, aucun processus lancé).
        self.params_schema = tuple(params_schema)
        # ALLOWLIST de drapeaux pour `{args}`/extra_args : ensemble EXACT des flags (`-x`/`--x`) qu'un
        # opérateur peut passer en argument libre. Vide => aucun extra_arg drapeau accepté (fail-closed).
        self.flag_allowlist = tuple(flag_allowlist)
        # DÉCOUVERTE DE SERVICE : un SCANNER DE PORTS (naabu/masscan) émet, en PLUS de ses hits bruts, un
        # finding de découverte porteur du marqueur `DISCOVERY_SERVICE_MARKER` par port HTTP-confirmé ->
        # le `host:port` devient un NŒUD chaînable (le cerveau y sème fingerprint/oracles/scanners de
        # contenu), EXACTEMENT comme recon.nmap/httpx. Défaut False (les autres outils n'en émettent pas).
        self.emit_service_discovery = bool(emit_service_discovery)
        # DÉCOUVERTE D'ENDPOINT : un CRAWLER (katana/gospider) ou un lister d'URLs (gau) émet, au lieu d'un
        # simple finding texte par-URL rattaché à l'hôte, un finding de découverte porteur du marqueur
        # `DISCOVERY_ENDPOINT_MARKER` par URL in-scope -> chaque endpoint devient un NŒUD chaînable que le
        # cerveau branche aux oracles à injection (le paramètre de query -> sonde RÉELLE au lieu de « config
        # manquante »). Re-validé fail-closed, injectables priorisés, borné. Défaut False (byte-identique).
        self.emit_endpoint_discovery = bool(emit_endpoint_discovery)
        # SKIP CIBLE IP-LITTÉRALE : un module d'ARCHIVE WEB (gau/Wayback) ne trouve RIEN d'utile sur une IP
        # nue (les archives sont indexées par NOM de domaine) -> skip propre, aucun processus lancé (au lieu
        # d'un flot d'URLs d'archive bruitées). Défaut False.
        self.skip_bare_ip = bool(skip_bare_ip)
        # REAP DAEMON FUITÉ : certains outils (amass v4 `enum`) démarrent un daemon persistant DÉTACHÉ
        # (`amass engine`, pprof exposé sur :6060) qui SURVIT à la fin de l'enum et ÉCHAPPE au reap par
        # groupe de processus. reap_daemon=True -> l'outil est lancé avec un HOME privé + un marqueur unique
        # (cf. `_daemon_reap.reaping_env`) et tout survivant portant ce marqueur est TERMINÉ après l'exécution
        # (succès/timeout/annulation), de façon CIBLÉE (jamais un amass tiers). Défaut False (aucun reap →
        # chemin d'exécution BYTE-IDENTIQUE pour tous les autres outils, env hérité comme avant).
        self.reap_daemon = bool(reap_daemon)

    @property
    def asset_hits(self):
        """Un hit est-il un ASSET découvert (attribution + re-validation scope) ? Dérivé si non déclaré :
        les outils de PHASE recon découvrent des assets ; les scanners rapportent SUR la cible donnée."""
        return self.phase == "recon" if self.hit_is_asset is None else bool(self.hit_is_asset)


# =================================================================================================
#  Résolution d'argv — NO-SHELL, anti-injection (target/params = éléments d'argv, jamais de shell)
# =================================================================================================
def _host(target):
    """Hôte canonique : retire scheme/path/query/fragment/userinfo (conserve host[:port]). Ne lève jamais."""
    s = str(target).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    return s


def _url(target):
    """URL avec scheme garanti (http:// ajouté si absent). Ne lève jamais."""
    s = str(target).strip()
    return s if "://" in s else "http://" + s


def _resolve_placeholder(body, ctx):
    """Résout le CORPS d'un placeholder `{...}`. Renvoie une str, ou `_MISSING` (placeholder requis
    manquant / inconnu -> le token sera abandonné). Pur, ne lève jamais."""
    parts = body.split(":")
    key = parts[0]
    if key == "target":
        return str(ctx["target"])
    if key == "target_host":
        return _host(ctx["target"])
    if key == "target_url":
        return _url(ctx["target"])
    if key == "param":
        name = parts[1] if len(parts) > 1 else ""
        default = parts[2] if len(parts) > 2 else _MISSING     # {param:NAME:DEFAULT}
        val = (ctx["params"] or {}).get(name, _MISSING)
        if val is _MISSING or val is None or val == "":
            return default
        return str(val)
    return _MISSING                                            # placeholder inconnu -> fail-safe (drop)


def _resolve_token(tok, ctx):
    """Résout UN token de gabarit -> str (élément d'argv) OU None (abandonner ce token). Un littéral
    (sans `{`) passe tel quel. TOUT le texte résolu reste UN SEUL élément — jamais de découpe shell."""
    tok = str(tok)
    if "{" not in tok:
        return tok
    out, last = [], 0
    for m in _TOK_RX.finditer(tok):
        out.append(tok[last:m.start()])
        val = _resolve_placeholder(m.group(1), ctx)
        if val is _MISSING:                                   # placeholder requis manquant -> drop token
            return None
        out.append(val)
        last = m.end()
    out.append(tok[last:])
    return "".join(out)


# Tokens de gabarit dont la valeur EST la cible POSITIONNELLE (pas un flag type `-u{target}`) : leur
# résolution est susceptible d'injection d'argument si la cible commence par `-`/`--`.
_POSITIONAL_TARGET_TOKENS = ("{target}", "{target_host}", "{target_url}")


def unsafe_positional_target(spec, target, params=None):
    """Renvoie la 1re valeur de cible POSITIONNELLE résolue commençant par `-` (risque d'injection
    d'argument : l'outil enveloppé pourrait la lire comme une OPTION et non comme un opérande), sinon
    None. Un token cible positionnel est un token ÉGAL à `{target}`/`{target_host}`/`{target_url}`
    (un `-u{target}` est un flag+valeur, pas un positionnel). Pur, ne lève jamais. Sert de garde-fou
    fail-closed AVANT tout lancement de processus (cf. `ExternalToolModule.fire`)."""
    ctx = {"target": target, "params": params or {}}

    def _scan(tokens):
        for t in tokens:
            if isinstance(t, (list, tuple)):
                r = _scan(t)
                if r is not None:
                    return r
            elif isinstance(t, str) and t.strip() in _POSITIONAL_TARGET_TOKENS:
                val = _resolve_placeholder(t.strip()[1:-1], ctx)   # corps du placeholder (sans les {})
                if isinstance(val, str) and val.startswith("-"):
                    return val
        return None

    return _scan(spec.argv_template)


# =================================================================================================
#  EXTRA_ARGS / `{args}` — arguments libres GOUVERNÉS par une allowlist de drapeaux (fail-closed)
# =================================================================================================
def _looks_like_flag(tok):
    """True si le token RESSEMBLE à un drapeau CLI (`-x`/`--x`) — donc soumis à l'allowlist. Un `-`
    seul ou une valeur ordinaire (port/wordlist/nom de script) n'y ressemble pas. Ne lève jamais."""
    t = str(tok)
    return len(t) >= 2 and t.startswith("-")


def check_extra_args(extra, allowlist):
    """Valide `extra_args` (arguments libres de l'opérateur) contre une allowlist de drapeaux. FAIL-CLOSED.

    Contrat (source unique, partagée par les wrappers ToolSpec ET les modules natifs nmap/nuclei) :
      - `extra` absent/None                        -> (None, [])            : no-op (byte-identique au défaut).
      - `extra` PAS une liste/tuple                -> (raison, [])          : REFUS (doit être une LISTE de
                                                                              tokens déjà séparés — jamais une
                                                                              chaîne shell-splittée).
      - un élément non-string ou porteur d'un NUL  -> (raison, [])          : REFUS.
      - un token RESSEMBLANT à un drapeau (`-x`)   -> DOIT être EXACTEMENT dans `allowlist`, sinon REFUS.
        (la forme `--flag=val` n'est jamais dans l'allowlist -> REFUSÉE : imposer `--flag val` en 2 tokens ;
        ferme AUSSI l'injection d'argument — un token-valeur commençant par `-` est un drapeau non listé
        => refusé, comme `unsafe_positional_target` le fait pour la cible positionnelle.)
    Retourne `(reason_or_None, tokens)`. `tokens` n'est JAMAIS renvoyé si une raison est présente ([]).
    Pur, ne lève jamais. Chaque token validé reste UN SEUL élément d'argv (no-shell)."""
    if extra is None:
        return None, []
    if not isinstance(extra, (list, tuple)):
        return ("extra_args doit être une LISTE de tokens déjà séparés (pas une chaîne, "
                "jamais de découpe shell)"), []
    allow = set(allowlist or ())
    tokens = []
    for el in extra:
        if not isinstance(el, str):
            return (f"token extra_args non-string refusé: {el!r}"), []
        if "\x00" in el:
            return "token extra_args contient un octet NUL (refusé)", []
        if _looks_like_flag(el) and el not in allow:
            return (f"drapeau '{el}' hors allowlist — refusé fail-closed (aucun processus lancé) ; "
                    f"utiliser un flag autorisé ou la forme `--flag val` en deux tokens"), []
        tokens.append(el)
    return None, tokens


_SAFE_VALUE_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9,._:/*-]*$")


def safe_value(val):
    """True si `val` est une VALEUR d'argv sûre à passer à un drapeau : chaîne non vide, ne COMMENCE PAS
    par '-' (anti option-smuggling), caractères bornés (alphanum + `, . _ : / * -`). Sert aux modules
    NATIFS (nmap/nuclei) à valider les valeurs de params mappées à un flag (ports/scripts/…) — une valeur
    hostile (`-oN`, métacaractère shell) est REJETÉE. Pur, ne lève jamais."""
    return bool(isinstance(val, str) and val and _SAFE_VALUE_RX.match(val))


def unsafe_extra_args(spec, params=None):
    """Garde-fou fail-closed AVANT tout lancement : renvoie la RAISON de refus si `params['extra_args']`
    contient un token invalide/non-allowlisté pour ce spec, sinon None. Adosse `check_extra_args` à la
    `flag_allowlist` du spec (vide => tout extra_arg drapeau est refusé). Pur, ne lève jamais."""
    reason, _ = check_extra_args((params or {}).get("extra_args"), spec.flag_allowlist)
    return reason


def _safe_extra_tokens(allowlist, params):
    """Tokens extra_args VALIDÉS (list[str]) à insérer dans l'argv, ou [] si absent/INVALIDE. build_argv
    ne lève jamais : c'est le garde-fou de fire() (`unsafe_extra_args`) qui REFUSE le lancement avant que
    ces tokens ne comptent. Ici on ne fait qu'EXPANDRE ce qui est déjà prouvé sûr."""
    _, tokens = check_extra_args((params or {}).get("extra_args"), allowlist)
    return tokens


# =================================================================================================
#  FlagAllowlistMixin — plomberie extra_args DÉDUPLIQUÉE pour les modules-wrappers ÉCRITS À LA MAIN
# =================================================================================================
class FlagAllowlistMixin:
    """Mixin léger factorisant la plomberie `extra_args` DUPLIQUÉE dans les modules-wrappers ÉCRITS À
    LA MAIN (ceux qui ne descendent PAS de `ExternalToolModule`, lequel centralise déjà ce contrat dans
    son `fire()`). Source unique de trois éléments jusque-là recopiés d'un module à l'autre :

      - `extra_args_param(label=…)`  : le descripteur de params `{"name":"extra_args",…}` répété à
                                       l'identique dans chaque PARAMS_SCHEMA (label paramétrable car il
                                       varie par outil : « extra args ffuf/subfinder/sqlmap … ») ;
      - `_refuse(action, reason)`    : le finding de REFUS fail-closed (`status='skipped'`, aucun
                                       processus lancé), dont category/mitre/tool sont pris SUR la classe
                                       concrète (`_refuse_*`) pour rester BYTE-IDENTIQUE à l'ex-`_refuse`
                                       local du module (nuclei/httpx/nmap) ;
      - `gate_extra_args(action)`    : la porte fail-closed — `None` si OK, sinon le finding de refus
                                       déjà construit (à retourner tel quel depuis `fire()`).

    Aucune capacité élargie : `FLAG_ALLOWLIST` reste déclarée PAR CHAQUE module (intrinsèque à l'outil
    enveloppé — jamais centralisée). Le mixin ne fait que dédupliquer la plomberie, à comportement
    strictement préservé (même allowlist, même refus, même argv). Un module dont le refus a un libellé
    propre (ex origin/recon.content via `_skipped`, sqli.probe via `degraded`) réutilise
    `extra_args_param()` mais garde son émetteur de refus spécifique."""

    FLAG_ALLOWLIST = ()                  # déclarée (surchargée) par chaque module concret
    # Provenance du finding de REFUS — posée par chaque module pour rester byte-identique à son ex-`_refuse`.
    _refuse_category = "recon"
    _refuse_mitre = ""
    _refuse_tool = ""

    @classmethod
    def extra_args_param(cls, label="extra args (allowlist de drapeaux)"):
        """Descripteur de params UI pour `extra_args` (source unique de l'entrée répétée)."""
        return {"name": "extra_args", "type": "list", "label": label, "flag": ""}

    def _refuse(self, action, reason):
        """Finding de REFUS fail-closed (aucun processus lancé) — remplace les `_refuse` copiés verbatim
        dans nuclei/httpx/nmap. category/mitre/tool lus sur la classe (`_refuse_*`) : sortie
        BYTE-IDENTIQUE à l'ancien `_refuse` local de chaque module."""
        return [self.finding(
            target=action.target, title=f"{self.kind} non exécuté — {reason}", severity="INFO",
            category=self._refuse_category, mitre=self._refuse_mitre, status="skipped",
            tool=self._refuse_tool,
            evidence=f"{reason}. Aucun processus lancé (fail-closed).")]

    def gate_extra_args(self, action):
        """Porte `extra_args` fail-closed : `None` si les arguments libres sont valides/allowlistés, sinon
        le finding de refus (`_refuse`) prêt à retourner. Adosse `check_extra_args` à `self.FLAG_ALLOWLIST`."""
        bad_extra, _ = check_extra_args((action.params or {}).get("extra_args"), self.FLAG_ALLOWLIST)
        if bad_extra is not None:
            return self._refuse(action, f"argument libre refusé ({bad_extra})")
        return None


def build_argv(spec, target, params=None):
    """Construit l'argv FIXE (list[str]) à partir du gabarit du spec — SANS SHELL. Chaque placeholder
    devient un/des élément(s) d'argv distinct(s) ; une cible avec métacaractères shell reste UN élément.
    Un GROUPE (token itérable) est tout-ou-rien : abandonné en bloc si un placeholder requis manque
    (évite un flag orphelin). Le token spécial `{args}` s'EXPAND en les tokens extra_args VALIDÉS
    (allowlist du spec) — chaque élément reste UN argv distinct, jamais shell-splitté. Pur, ne lève jamais."""
    ctx = {"target": target, "params": params or {}}
    argv = []
    for elem in spec.argv_template:
        if isinstance(elem, str) and elem.strip() == "{args}":  # EXPANSION extra_args gouvernée
            argv.extend(_safe_extra_tokens(spec.flag_allowlist, params))
            continue
        if isinstance(elem, (list, tuple)):                   # GROUPE tout-ou-rien
            resolved = [_resolve_token(t, ctx) for t in elem]
            if any(r is None for r in resolved):
                continue                                      # un requis manque -> drop le groupe entier
            argv.extend(resolved)
        else:
            r = _resolve_token(elem, ctx)
            if r is not None:
                argv.append(r)
    return argv


# =================================================================================================
#  Parseurs de sortie -> hits (proof-oriented ; le module en fait des Findings)
# =================================================================================================
def _extract_json(obj, path):
    """Extrait via un chemin de clés depuis un dict/list JSON -> list[str]. Pur, ne lève jamais."""
    out = []
    items = obj if isinstance(obj, list) else [obj]
    for it in items:
        v, ok = it, True
        for k in path:
            if isinstance(v, dict) and k in v:
                v = v[k]
            else:
                ok = False
                break
        if ok and v is not None:
            out.append(v if isinstance(v, str) else (json.dumps(v) if isinstance(v, (dict, list)) else str(v)))
    return out


def parse_output(spec, rc, stdout, stderr=""):
    """Extrait la liste des HITS (str) de la sortie de l'outil selon `spec.parser`. Dé-dupliqué (ordre
    préservé) et borné à `_MAX_HITS`. Pur, ne lève jamais (entrée d'outil hostile tolérée)."""
    text = stdout or ""
    hits = []
    try:
        if spec.parser == "none":
            hits = []
        elif spec.parser == "lines":
            hits = [ln.strip() for ln in text.splitlines() if ln.strip()]
        elif spec.parser == "regex":
            if spec.parser_regex:
                rx = re.compile(spec.parser_regex)
                for m in rx.finditer(text):
                    hits.append((m.group(1) if m.groups() else m.group(0)).strip())
        elif spec.parser == "json":
            try:
                hits = _extract_json(json.loads(text), spec.parser_json_path)
            except ValueError:
                hits = []
        elif spec.parser == "jsonl":
            for ln in text.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    hits.extend(_extract_json(json.loads(ln), spec.parser_json_path))
                except ValueError:
                    continue
    except re.error:
        return []
    seen, uniq = set(), []
    for h in hits:
        h = (h or "").strip()
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
        if len(uniq) >= _MAX_HITS:
            break
    return uniq


# =================================================================================================
#  ExternalToolModule — la base GOUVERNÉE que toute sous-classe générée hérite
# =================================================================================================
class ExternalToolModule(ScopeGuardMixin, Module):
    """Base des modules-wrappers générés depuis un `ToolSpec`. Aucune sous-classe n'ajoute de logique :
    le comportement gouverné (scope-guard, plancher exploit, dégradation, parsing proof-oriented) vit
    ICI ; le spec porte les données. Non enregistrée (base abstraite : aucun `@register`)."""

    spec = None                              # ToolSpec, posé par make_module sur chaque sous-classe
    _toolname = ""                           # label de provenance, posé par make_module
    # Seam de CONFIRMATION HTTP (sonde GET) pour la découverte de service — monkeypatchable par les tests
    # (comme `NmapServices._fetch`). Par défaut : la sonde partagée `_discovery.http_probe`.
    _fetch = staticmethod(_discovery.http_probe)

    @property
    def available(self):
        """Disponibilité au catalogue/fire : binaire local OU image docker présents (PATH/`docker`,
        aucune I/O réseau). Dégrade proprement à False si aucun (offline-safe)."""
        s = self.spec
        return runner.available(s.binary, s.docker_image or None, prefer_docker=s.prefer_docker)

    # --- scope-guard fail-closed : voir ScopeGuardMixin (source unique) ---

    def _argv(self, action):
        return build_argv(self.spec, action.target, action.params)

    def _run(self, argv):
        """Exécute l'outil (argv fixe, no-shell) et retourne (rc, out, err). Pour un outil qui FUIT un
        daemon persistant (`spec.reap_daemon` — amass v4 `enum` -> `amass engine`), l'exécution se fait
        sous `_daemon_reap.reaping_env` : HOME privé + marqueur unique dans l'env de l'enfant, et REAP
        ciblé du survivant portant ce marqueur à la SORTIE (succès, timeout rc=124, OU exception/annulation
        — le reap est dans le `finally`, donc il compose avec le SIGTERM/timeout de D1). Un outil sans
        reap_daemon suit le chemin HISTORIQUE (env hérité, aucun reap) → BYTE-IDENTIQUE."""
        s = self.spec
        if not s.reap_daemon:
            return runner.tool(s.binary, s.docker_image or None, argv,
                               prefer_docker=s.prefer_docker, timeout=s.timeout)
        with _daemon_reap.reaping_env(prefix="forge-%s-" % s.binary) as env:
            return runner.tool(s.binary, s.docker_image or None, argv,
                               prefer_docker=s.prefer_docker, timeout=s.timeout, env=env)

    def dry(self, action):
        s = self.spec
        return runner.cmdline(s.binary, s.docker_image or None, self._argv(action),
                              prefer_docker=s.prefer_docker)

    def _mk(self, action, *, title, status, evidence, severity="INFO", target=None):
        """Construit un Finding estampillé (kind/cwe/mitre/tool/poc). `category=cwe||vuln_class` pour que
        le schema dérive la remédiation. `poc` = la commande no-shell reproductible (dry)."""
        s = self.spec
        return self.finding(
            target=target or action.target, title=title, severity=severity,
            category=s.cwe or s.vuln_class, cwe=s.cwe, mitre=s.mitre, status=status,
            tool=self._toolname, evidence=(evidence or "")[:1500], poc=self.dry(action))

    def fire(self, action):
        s = self.spec
        # (1) SCOPE-GUARD fail-closed — cible HORS périmètre -> skipped, ZÉRO I/O (aucun processus lancé).
        if not self._in_scope(action, action.target):
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} non exécuté — cible hors périmètre (scope-guard fail-closed)",
                evidence="La cible n'appartient pas au périmètre in-scope ; aucun processus lancé (fail-closed).")]
        # (1a2) SKIP CIBLE IP-LITTÉRALE (modules d'ARCHIVE WEB : gau/Wayback) — les archives sont indexées
        # par NOM de domaine ; une IP nue n'a jamais d'archive utile (que du bruit : gau sur 127.0.0.1
        # remontait ~195 URLs d'archive fantômes). Skip PROPRE (finding visible), aucun processus lancé.
        if s.skip_bare_ip and _discovery.is_ip_literal(_discovery.bare_host(action.target)):
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} non exécuté — cible IP littérale (archives web indexées par domaine)",
                evidence=(f"La cible {action.target!r} est une IP littérale ; les archives web "
                          f"(Wayback/CommonCrawl) sont indexées par NOM de domaine et n'ont aucune entrée "
                          f"utile pour une IP -> skip propre (aucun processus lancé, zéro URL fantôme)."))]
        # (1b) ANTI-INJECTION D'ARGUMENT — une cible POSITIONNELLE résolue commençant par `-`/`--`
        # pourrait être interprétée comme une OPTION par l'outil enveloppé. Refus fail-closed (aucun
        # processus lancé) : la tokenisation no-shell empêche l'injection SHELL, ce garde-fou ferme
        # l'injection d'ARGUMENT (option smuggling).
        bad = unsafe_positional_target(s, action.target, action.params)
        if bad is not None:
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} non exécuté — cible positionnelle ambiguë (anti-injection d'argument)",
                evidence=(f"La cible positionnelle résolue {bad!r} commence par '-' et pourrait être lue "
                          f"comme une option par '{s.binary}'. Refusé fail-closed (aucun processus lancé) ; "
                          f"fournir un schéma explicite (http://) ou passer la cible via un flag dédié."))]
        # (1c) EXTRA_ARGS GOUVERNÉS — un argument libre (`{args}`/params.extra_args) doit être une LISTE
        # de tokens et chaque drapeau (`-x`) DOIT être dans l'allowlist du spec. Un flag hors liste (ex
        # `-oN`, `--script=<rce>`) ou une chaîne non-liste est REFUSÉ fail-closed (aucun processus lancé) :
        # ni le shell (argv fixe) ni l'injection d'argument (allowlist stricte) ne peuvent passer.
        bad_extra = unsafe_extra_args(s, action.params)
        if bad_extra is not None:
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} non exécuté — argument libre refusé (allowlist de drapeaux fail-closed)",
                evidence=(f"extra_args refusé : {bad_extra}. Aucun processus lancé (fail-closed)."))]
        # (2) PLANCHER EXPLOIT (défense en profondeur) — classe exploit + scope lié + opt-in non armé -> refus.
        if s.exploit:
            scope, armed = self._bound_allow_exploit()
            if scope is not None and not armed:
                return [self._mk(
                    action, status="skipped",
                    title=f"{self.kind} refusé — plancher exploit/fort-impact non armé",
                    evidence=(f"Classe EXPLOIT ({self.kind}) : un scope gouverné est lié mais l'opt-in "
                              f"allow_exploit/allow_high_impact n'est PAS armé -> refusé (défense en "
                              f"profondeur), aucun processus lancé."))]
        # (3) DISPONIBILITÉ — binaire (ni local ni docker) absent -> skipped (dégradation gracieuse).
        if not self.available:
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} non exécuté — binaire '{s.binary}' absent (dégradation gracieuse)",
                evidence=(f"Ni le binaire local '{s.binary}' ni une image docker "
                          f"'{s.docker_image or '—'}' ne sont présents. Aucun processus lancé (offline-safe). "
                          f"Installer l'outil pour l'activer."))]
        # (4) EXÉCUTION — argv FIXE, NO-SHELL (via le connecteur subprocess partagé runner.tool).
        argv = self._argv(action)
        rc, out, err = self._run(argv)
        # (5) DÉGRADATION — indisponible (127) / timeout (124) -> skipped (offline-safe, jamais un faux hit).
        if rc == 127:
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} non exécuté — outil indisponible (dégradation gracieuse)",
                evidence=(err or "outil indisponible")[:500])]
        if rc == 124:
            return [self._mk(
                action, status="skipped",
                title=f"{self.kind} — timeout après {s.timeout}s (résultat partiel ignoré)",
                evidence=(err or "timeout")[:500])]
        # (6) PARSING PROOF-ORIENTED — les hits deviennent tested/reported_by_tool, JAMAIS vulnerable.
        hits = parse_output(s, rc, out, err)
        # (6a) DÉCOUVERTE D'ENDPOINT (crawlers katana/gospider/gau) : chaque URL crawlée in-scope devient un
        # NŒUD chaînable (marqueur DISCOVERY_ENDPOINT_MARKER, target=URL) que le cerveau branche aux oracles
        # à injection (le paramètre de query -> sonde RÉELLE au lieu de « config manquante »), AU LIEU d'un
        # simple finding texte par-URL jamais vérifié. Re-validé fail-closed, injectables priorisés, borné.
        # Sans le flag -> chemin HISTORIQUE (`_hits_to_findings`) BYTE-IDENTIQUE.
        if s.emit_endpoint_discovery:
            findings = self._endpoint_discovery(action, hits)
        else:
            findings = self._hits_to_findings(action, hits)
        # (6b) DÉCOUVERTE DE SERVICE (scanners de ports naabu/masscan) : chaque port HTTP-confirmé devient
        # une cible CHAÎNABLE (host:port + marqueur DISCOVERY_SERVICE_MARKER) que le cerveau scanne à la
        # vague suivante (fingerprint/oracles/scanners de contenu) — EXACTEMENT comme recon.nmap/httpx.
        # Sans ceci, les ports trouvés par naabu/masscan restaient de simples findings texte, jamais
        # scannés par les scanners de CONTENU HTTP. Ajoute aussi un finding d'INVENTAIRE (surface ouverte).
        if s.emit_service_discovery:
            findings = self._service_discovery(action, hits) + findings
        if findings:
            return findings
        # Aucun hit : outil exécuté sans résultat. rc!=0 sans hit -> finding d'échec traçable (tested INFO).
        # RATE-LIMIT / WAF : une sortie portant une signature de challenge (429/WAF) est SIGNALÉE dans le
        # titre (au lieu d'un « aucun hit » trompeur) — l'opérateur voit que le scan a été throttlé/bloqué.
        if rc != 0:
            blocked = looks_like_challenge(None, (out or "") + " " + (err or ""))
            note = " — rate-limited/WAF détecté dans la sortie" if blocked else ", aucun hit exploitable"
            return [self._mk(
                action, status="tested",
                title=f"{self.kind} — {s.binary} rc={rc}{note}",
                evidence=((err or out) or f"rc={rc}").strip()[:500])]
        return [self._mk(
            action, status="tested", title=f"{self.kind} — {s.tool_name}: aucun hit",
            evidence="Outil exécuté (in-scope), aucun résultat.")]

    def _service_discovery(self, action, hits):
        """Convertit les hits d'un SCANNER DE PORTS (naabu/masscan) en findings de DÉCOUVERTE chaînables :
        (1) un finding d'INVENTAIRE listant TOUS les host:port ouverts (surface visible d'un coup) ;
        (2) un finding de découverte (marqueur DISCOVERY_SERVICE_MARKER, target=host:port) par port
        HTTP-CONFIRMÉ (sonde GET via le seam `_fetch` — un port non-HTTP casse le parse -> jamais surfacé,
        zéro bruit). Ancré sur l'hôte DÉJÀ gaté par le ROE (`bare_host(action.target)`) ; borné
        (`_MAX_DISCOVERED_SERVICES`/`_MAX_PROBED_PORTS`). Pur (hormis la sonde), ne lève jamais."""
        ports = _discovery.ports_from_hits(hits)
        if not ports:
            return []
        host = _discovery.bare_host(action.target)
        out = []
        inv = _discovery.port_inventory_finding(self, action, self._toolname, ports)
        if inv:
            out.append(inv)
        confirmed = _discovery.http_confirmed_ports(self._fetch, host, ports)
        out += _discovery.service_discovery_findings(self, action, confirmed, self._toolname)
        return out

    def _endpoint_discovery(self, action, hits):
        """Convertit les URLs crawlées (hits) en findings de DÉCOUVERTE D'ENDPOINT chaînables (marqueur
        DISCOVERY_ENDPOINT_MARKER, target=URL) via `_discovery.endpoint_discovery_findings` : re-validé
        fail-closed contre le périmètre, injectables (avec `?param=`) priorisés, borné. Le cerveau y branche
        ensuite les oracles à injection (edge e). Pur, ne lève jamais."""
        return _discovery.endpoint_discovery_findings(self, action, hits, self._toolname)

    def _hits_to_findings(self, action, hits):
        """Mappe les hits en Findings PROOF-ORIENTED. Statut CLAMPÉ à {tested, reported_by_tool} (jamais
        `vulnerable`). Si le spec produit des ASSETS découverts, chacun est RE-VALIDÉ fail-closed contre
        le périmètre injecté (un asset hors-scope n'est JAMAIS émis) et le finding lui est ATTRIBUÉ."""
        s = self.spec
        enforce, sc = self._scope(action)
        status = s.hit_status if s.hit_status in ("tested", "reported_by_tool") else "reported_by_tool"
        out, seen = [], set()
        for h in hits:
            if s.asset_hits:
                asset = h.split()[0] if h.split() else h      # 1er jeton = l'asset découvert (host/URL)
                if enforce and not sc.is_in_scope(asset):
                    continue                                  # fail-closed : jamais un asset hors-scope
                target = asset
            else:
                target = action.target
            key = (target, h)
            if key in seen:
                continue
            seen.add(key)
            out.append(self._mk(
                action, target=target, status=status, severity=s.severity,
                title=f"{s.tool_name}: {h[:120]}", evidence=h))
            if len(out) >= _MAX_HITS:
                break
        return out


# =================================================================================================
#  Fabrique + enregistrement — un ToolSpec -> une technique (techniques.py) + un module (@register)
# =================================================================================================
def spec_to_technique(spec):
    """Construit l'enregistrement `Technique` d'un spec via `techniques._k` (le MÊME dériveur que les
    kinds livrés) -> pentest_only / default_profiles / stage / tools dérivés à L'IDENTIQUE (invariants
    de cohérence de profil/stage garantis pour un tool-spec comme pour un kind natif)."""
    return techniques._k(
        spec.kind, spec.vuln_class, spec.bug_bounty_eligible,
        depends_on=spec.depends_on, tools=(spec.tools or None),
        cls=spec.cls, cwe=spec.cwe, mitre=spec.mitre, exploit=spec.exploit,
        attck_tactic=spec.attck_tactic, phase=spec.phase, capability=spec.capability,
        proof_required=spec.proof_required)


def make_module(spec):
    """Génère (sans l'enregistrer) la sous-classe `ExternalToolModule` pour un spec — métadonnées
    figées en attributs de classe (kind/exploit/destructive/mitre/description/cwe/tool)."""
    attrs = {
        "spec": spec, "kind": spec.kind, "exploit": bool(spec.exploit),
        "destructive": bool(spec.destructive), "mitre": spec.mitre, "cwe": spec.cwe,
        "_toolname": spec.tool_name,
        # SCHÉMA de params servi à l'UI (via `forge modules --json`) + allowlist de drapeaux extra_args.
        "PARAMS_SCHEMA": list(spec.params_schema), "FLAG_ALLOWLIST": tuple(spec.flag_allowlist),
        "description": spec.description or (
            f"Wrapper gouverné de l'outil externe '{spec.binary}' ({spec.vuln_class}) — argv fixe "
            f"no-shell, scope-guard fail-closed, proof-oriented (reported_by_tool), dégrade si absent."),
    }
    return type(f"ExternalTool_{spec.kind.replace('.', '_')}", (ExternalToolModule,), attrs)


def register_spec(spec):
    """ENREGISTRE un `ToolSpec` de bout en bout : (1) FOLD la technique dans `forge/techniques.py`
    (`register_kind` -> catalogue/pipeline/profils/sélection par-scope) ; (2) GÉNÈRE et enregistre le
    module (`@register` -> `modules --json`, console, plan du cerveau). Un seul appel = l'outil est
    intégré partout, SOUS gouvernance. Retourne la classe de module générée. Idempotent."""
    techniques.register_kind(spec_to_technique(spec))
    cls = make_module(spec)
    register(spec.kind)(cls)
    return cls
