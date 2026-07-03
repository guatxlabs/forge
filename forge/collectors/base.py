"""Contrat de base des collecteurs de détection — pont INFRA-AGNOSTIQUE de la boucle purple.

La console Rust interroge nativement (en clair, http) les sources `plume`/`generic_http`. Pour tout
le reste — SIEM/IDS/pare-feu hétérogènes qui ne parlent PAS MITRE nativement — elle délègue à un
COLLECTEUR PYTHON via `forge.cli detections --since N --source <spec>`. Chaque collecteur lit sa
source, la NORMALISE en `[{mitre, count, first_ts}]` (epoch s), prête pour la jointure MITRE côté
console (INCHANGÉE — pure égalité de champ `mitre`).

CONTRAT D'UN COLLECTEUR (une classe par `kind`) :
- `fetch(since_epoch) -> list[{mitre,count,first_ts}]` : NE LÈVE JAMAIS. Toute erreur (mauvaise
  config, source injoignable, réponse illisible) -> `[]` + échec `doctor()`. C'est ce qui permet à
  la console de basculer en `source_reachable:false` SANS inventer de detected/missed/MTTD.
- `doctor() -> {ok, detail}` : sonde LECTURE SEULE, ne lève jamais. `ok=False` + astuce rédigée
  quand la source est injoignable/mal configurée (mapping manquant pour une infra native, etc.).
- `config_error() -> str|None` : validation STATIQUE (sans I/O) ; renvoie une astuce si la config
  est intrinsèquement invalide (mapping REQUIS absent pour une infra non taggée MITRE...).

DISTINCTION CLÉ (fail-open lisible) : une source JOIGNABLE qui renvoie `[]` (SOC frais, rien détecté)
est un état VALIDE — `reachable=True`, la CLI imprime `{"detections":[]}` (code 0). Une source
INJOIGNABLE/mal configurée -> `reachable=False`, la CLI sort en code non nul (fail-open) : la console
distingue ainsi « joignable mais vide » de « injoignable » et ne fabrique jamais de couverture.

SECRET : le secret d'auth (`auth.secret`) n'est JAMAIS imprimé, journalisé, ni inséré dans un message
d'erreur (rédaction défensive via `safe_error`).
"""
import json
import os
import re
import ssl
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Registre kind -> classe de collecteur (peuplé par les modules de `forge.collectors`).
REGISTRY = {}


def register(kind):
    """Décorateur : enregistre une classe de collecteur pour un `kind` (miroir de modules/registry)."""
    def deco(cls):
        REGISTRY[kind] = cls
        cls.kind = kind
        return cls
    return deco


def get_collector(source):
    """Instancie le collecteur correspondant à `source['kind']`, ou None si le kind est inconnu.
    Ne lève jamais (une config non-dict -> None)."""
    if not isinstance(source, dict):
        return None
    cls = REGISTRY.get(str(source.get("kind", "")).strip())
    return cls(source) if cls else None


def kinds():
    """Liste triée des kinds pris en charge par le collecteur Python."""
    return sorted(REGISTRY)


# --------------------------------------------------------------------------------------------------
# Chargement de la spec `--source`
# --------------------------------------------------------------------------------------------------
def load_source(spec):
    """Charge la config source depuis `--source` : `env:NOM` (variable d'env — voie PRIVILÉGIÉE, la
    console y met le JSON AVEC secret pour ne PAS le fuiter via argv/`ps`), `@chemin` (fichier), ou du
    JSON littéral. Retourne un dict. Lève ValueError si illisible/non-objet."""
    if spec is None:
        raise ValueError("--source requis")
    s = spec.strip()
    if s.startswith("env:"):
        name = s[4:]
        raw = os.environ.get(name, "")
        if not raw:
            raise ValueError(f"variable d'environnement {name} vide ou absente")
    elif s.startswith("@"):
        raw = Path(s[1:]).read_text(encoding="utf-8")
    else:
        raw = s
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("la config de source doit être un objet JSON")
    return data


# --------------------------------------------------------------------------------------------------
# Helpers de mapping (chemins pointés, epochs, agrégation, résolution MITRE)
# --------------------------------------------------------------------------------------------------
def _dotget(obj, path):
    """Valeur à un chemin POINTÉ ('a.b.c') ; None si un segment manque. Chemin vide -> obj."""
    if not path:
        return obj
    cur = obj
    for seg in path.split("."):
        if not seg:
            continue
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return None
    return cur


def to_epoch(v):
    """Normalise un horodatage en epoch s (int). Accepte int/float (epoch s ; ms auto-détectés si
    > 10^12), string epoch, ou ISO-8601. 0 si illisible/absent."""
    if v is None or isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        n = int(v)
        return n // 1000 if n > 1_000_000_000_000 else n
    if isinstance(v, str):
        t = v.strip()
        if not t:
            return 0
        if t.isdigit():
            n = int(t)
            return n // 1000 if n > 1_000_000_000_000 else n
        try:
            dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            return 0
    return 0


def _to_int(v, default=0):
    try:
        if isinstance(v, bool):
            return default
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str) and v.strip():
            return int(v.strip())
    except (ValueError, TypeError):
        return default
    return default


def resolve_mitre(rec, mapping):
    """Résout la technique MITRE d'un enregistrement NATIF via `mapping`. Deux modes :
      - TABLE (infras natives non taggées MITRE) : `mapping.table` = {signature natif -> 'Txxxx'} ;
        la signature est lue au champ `mapping.field` (défaut 'signature'). Signature ABSENTE de la
        table -> '' (ignorée) : on NE DEVINE JAMAIS une technique.
      - DIRECT : `mapping.mitre` (défaut 'mitre') = chemin pointé d'un champ qui porte DÉJÀ le 'Txxxx'.
    """
    table = mapping.get("table")
    if isinstance(table, dict) and table:
        field = mapping.get("field") or mapping.get("mitre") or "signature"
        raw = _dotget(rec, field)
        if raw is None:
            return ""
        key = raw if isinstance(raw, str) else str(raw)
        return str(table.get(key, "") or "")
    mitre_f = mapping.get("mitre", "mitre")
    v = _dotget(rec, mitre_f)
    if isinstance(v, str):
        return v.strip()
    return "" if v is None else str(v)


def records_from(parsed, mapping):
    """Localise le tableau d'enregistrements dans une réponse JSON. `mapping.records` = chemin pointé ;
    sinon défauts courants (tableau racine, puis champs detections/results, puis hits.hits pour ES)."""
    path = (mapping or {}).get("records", "")
    if path:
        node = _dotget(parsed, path)
    elif isinstance(parsed, list):
        node = parsed
    elif isinstance(parsed, dict):
        node = parsed.get("detections")
        if node is None:
            node = parsed.get("results")
        if node is None:
            node = _dotget(parsed, "hits.hits")
    else:
        node = None
    if not isinstance(node, list):
        raise ValueError(f"aucun tableau de détections trouvé (records='{path}')")
    return node


def aggregate(records, mapping):
    """Agrège des enregistrements natifs en `[{mitre, count, first_ts}]`. `mapping` : mitre/table+field
    (résolution via `resolve_mitre`), ts (défaut 'first_ts'), count OPTIONNEL (absent -> chaque
    enregistrement compte 1). count sommé, first_ts = min. Enregistrements sans mitre résolu ignorés.
    Tri par mitre (déterministe)."""
    mapping = mapping or {}
    ts_f = mapping.get("ts", "first_ts")
    count_f = mapping.get("count")
    agg = {}  # mitre -> [count, first_ts]
    for rec in records:
        mitre = resolve_mitre(rec, mapping)
        if not mitre:
            continue
        ts = to_epoch(_dotget(rec, ts_f))
        c = _to_int(_dotget(rec, count_f), 1) if count_f else 1
        if mitre not in agg:
            agg[mitre] = [0, ts]
        agg[mitre][0] += c
        if ts < agg[mitre][1]:
            agg[mitre][1] = ts
    return [{"mitre": k, "count": v[0], "first_ts": v[1]} for k, v in sorted(agg.items())]


def syslog_aggregate(path, rules, max_lines=None):
    """Parse un fichier syslog/filterlog via des RÈGLES regex `rules` = [{match: regex, mitre: 'Txxxx'}].
    Chaque ligne matchée incrémente le count du mitre ; `first_ts` provient d'un groupe nommé
    `(?P<ts>...)` (epoch) si présent, 0 sinon. Une ligne peut matcher plusieurs règles (chacune
    compte). Retourne `[{mitre,count,first_ts}]` trié. `max_lines` borne la lecture (garde-fou)."""
    compiled = []
    for r in rules or []:
        if isinstance(r, dict) and r.get("match") and r.get("mitre"):
            compiled.append((re.compile(r["match"]), r["mitre"]))
    if not compiled:
        raise ValueError("syslog: 'mapping.rules' (règles regex -> mitre) requis")
    agg = {}  # mitre -> [count, first_ts]
    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if max_lines is not None and i >= max_lines:
                break
            for rx, mitre in compiled:
                m = rx.search(line)
                if not m:
                    continue
                ts = to_epoch(m.group("ts")) if "ts" in (m.groupdict() or {}) else 0
                if mitre not in agg:
                    agg[mitre] = [0, ts]
                agg[mitre][0] += 1
                if ts < agg[mitre][1]:
                    agg[mitre][1] = ts
    return [{"mitre": k, "count": v[0], "first_ts": v[1]} for k, v in sorted(agg.items())]


# --------------------------------------------------------------------------------------------------
# Transport HTTP mutualisé (un seul point de patch pour les tests) + auth
# --------------------------------------------------------------------------------------------------
def apply_auth(source, headers, default_api_header="X-API-Key"):
    """Pose l'en-tête d'auth selon `auth.type` (+ tolérance `auth_type` plate). Secret vide -> pas
    d'en-tête (anonyme). `mtls`/`none` -> pas d'en-tête (mTLS relève du transport, hors de ce helper)."""
    auth = source.get("auth") if isinstance(source.get("auth"), dict) else {}
    atype = auth.get("type") or source.get("auth_type") or "none"
    secret = auth.get("secret", "") or ""
    if atype == "basic" and secret:
        headers["Authorization"] = "Basic " + secret
    elif atype == "bearer" and secret:
        headers["Authorization"] = "Bearer " + secret
    elif atype == "api_key_header" and secret:
        headers[auth.get("header") or default_api_header] = secret


def parse_query_into_url(endpoint, query, since):
    """Colle une `query`-string à `endpoint` (`{since}` substitué par l'epoch). `query` None/vide ou
    non-str -> endpoint inchangé. Gère le `?`/`&` selon la présence d'un query-string existant."""
    url = (endpoint or "").strip()
    if isinstance(query, str) and query.strip():
        q = query.replace("{since}", str(int(since))).lstrip("?&")
        url = url + ("&" if "?" in url else "?") + q
    return url


def http_json(url, *, method="GET", data=None, headers=None, timeout=8.0, insecure_tls=False):
    """GET/POST une URL et renvoie le JSON parsé. `insecure_tls` (opt-in EXPLICITE) désactive la vérif
    TLS pour un endpoint https self-signed (lab). Lève sur erreur réseau/HTTP/JSON."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    ctx = None
    if url.startswith("https://") and insecure_tls:
        ctx = ssl._create_unverified_context()  # noqa: S323 — opt-in EXPLICITE (self-signed/lab)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        raw = r.read().decode("utf-8", "replace")
    return json.loads(raw)


# --------------------------------------------------------------------------------------------------
# Rédaction du secret
# --------------------------------------------------------------------------------------------------
def safe_error(exc, source=None):
    """Représentation d'erreur RÉDIGÉE du secret (défense en profondeur). Ne renvoie JAMAIS
    `auth.secret`, même si un message d'exception l'avait capturé par accident."""
    msg = f"{type(exc).__name__}: {exc}"
    secret = ""
    if isinstance(source, dict):
        auth = source.get("auth") if isinstance(source.get("auth"), dict) else {}
        secret = auth.get("secret", "") or ""
    if isinstance(secret, str) and len(secret) >= 4:
        msg = msg.replace(secret, "[secret rédigé]")
    return msg


def describe(source):
    """Résumé NON SECRET d'une source pour le diagnostic (kind + endpoint/chemin/commande)."""
    src = source if isinstance(source, dict) else {}
    kind = str(src.get("kind", "none"))
    ep = src.get("endpoint") or src.get("path") or src.get("cmd") or ""
    if isinstance(ep, list):
        ep = str(ep[0]) if ep else ""
    return f"{kind} @ {ep}" if ep else kind


# --------------------------------------------------------------------------------------------------
# Classe de base
# --------------------------------------------------------------------------------------------------
class Collector:
    """Base d'un collecteur. Un collecteur concret surcharge `config_error()` (validation statique) et
    `_collect(since)` (récupération + normalisation, PEUT lever). `fetch()`/`doctor()` (fournis ici) ne
    lèvent JAMAIS et pilotent le contrat fail-open lisible."""
    kind = "base"
    requires_mapping = False   # une infra native non taggée MITRE exige un mapping (sinon -> [] + astuce)

    def __init__(self, source):
        self.source = source if isinstance(source, dict) else {}
        m = self.source.get("mapping")
        self.mapping = m if isinstance(m, dict) else {}
        self._fetched = False
        self._error = None       # dernière exception (rédaction-aware via safe_error)
        self._reachable = None   # None=inconnu ; True/False après fetch/probe

    # ---- hooks à surcharger ----
    def config_error(self):
        """Astuce (str) si la config est STATIQUEMENT invalide, sinon None. Sans I/O."""
        return None

    def _collect(self, since):
        """Récupère + normalise -> `[{mitre,count,first_ts}]`. PEUT lever (fail-open côté fetch)."""
        raise NotImplementedError

    # ---- API stricte (LÈVE) : voie legacy `detections.collect` ----
    def collect_strict(self, since):
        err = self.config_error()
        if err:
            raise ValueError(err)
        rows = self._collect(int(since))
        return rows if isinstance(rows, list) else []

    # ---- API sûre (NE LÈVE JAMAIS) : voie collecteur ----
    def fetch(self, since):
        try:
            rows = self.collect_strict(since)
            self._error, self._reachable, self._fetched = None, True, True
            return rows
        except Exception as e:  # noqa: BLE001 — FAIL-OPEN : jamais de crash brut vers l'appelant
            self._error, self._reachable, self._fetched = e, False, True
            return []

    def doctor(self):
        """Sonde LECTURE SEULE -> {ok, detail}. Ne lève jamais. Valide d'abord la config (sans I/O),
        puis effectue une sonde de joignabilité (une seule collecte, réutilisée si `fetch` a déjà tourné)."""
        err = self.config_error()
        if err:
            return {"ok": False, "detail": safe_error(ValueError(err), self.source)}
        if not self._fetched:
            self.fetch(0)
        if self._reachable:
            return {"ok": True, "detail": self._ok_detail()}
        return {"ok": False, "detail": self.error_detail()}

    def _ok_detail(self):
        return f"{self.kind}: source joignable ({describe(self.source)})"

    def error_detail(self):
        if self._error is not None:
            return safe_error(self._error, self.source)
        return f"{self.kind}: source injoignable"

    # ---- accès ----
    @property
    def reachable(self):
        return bool(self._reachable)

    @property
    def error(self):
        return self._error

    def _timeout(self, default=8.0):
        try:
            return float(self.source.get("timeout", default))
        except (TypeError, ValueError):
            return default
