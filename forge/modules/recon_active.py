"""Modules ACTIFS de reachability/discovery — énumération STRICTEMENT gouvernée : verrouillée au
périmètre (fail-closed), rate-limitée, en LECTURE/ÉNUMÉRATION SEULE (aucune exploitation, aucune
mutation). Ils DÉGRADENT proprement (`status='skipped'`) quand l'outil externe optionnel ou le
réseau est indisponible — la suite offline reste verte.

Trois modules, bâtis sur la base `PassiveSurface` (recon_surface.py) pour hériter de la plomberie
Finding + HTTP + re-validation fail-closed du périmètre, calqués sur le pattern de connecteur
sous-processus SANS shell de `web.nuclei` / `msf.module` (construction d'une liste d'arguments,
exécution via `runner.tool`, mapping de la sortie en Finding) :

  - recon.content : découverte de contenu/routes web en requêtant des chemins candidats — enveloppe
                    l'outil ffuf (binaire local, connecteur sans shell). ffuf absent -> skipped.
                    Rate-limité (`-rate` dérivé du scope/params), verrou périmètre, honore le ROE (T1595.003).
  - recon.secrets : détecte les SECRETS EXPOSÉS dans les assets in-scope JOIGNABLES (bundles JS,
                    fichiers de config) en enveloppant trufflehog OU gitleaks (binaire local). Récupère
                    les assets in-scope, les scanne hors-ligne, et REMONTE toute exposition accidentelle
                    (finding défensif, secret REDACTÉ). Aucun scanner présent / réseau KO -> skipped (T1552.001).
  - recon.waf     : identifie le WAF/CDN devant un hôte in-scope (fingerprint INFORMATIF uniquement) —
                    heuristique passive sur en-têtes/cookies/corps, enrichie par wafw00f si présent (T1590).

DISCIPLINE (héritée de recon_surface.py + web.nuclei/msf.module) :
  - exploit=False, destructive=False : énumération seule — jamais d'exploitation, jamais de mutation.
  - ROE / scope-guard : la cible est gatée en amont par l'engine (Couche 2, in-scope fail-closed) ;
    en profondeur, la cible et CHAQUE asset dérivé/résolu à runtime sont RE-VALIDÉS fail-closed contre
    le périmètre injecté par l'engine (in_scope/out_scope dans action.params). Hors périmètre -> écarté,
    jamais requêté. Sans scope injecté (appel direct dev/test), on n'élargit jamais le périmètre.
  - rate-limité : l'engine injecte `rate` (débit ROE du scope) dans action.params ; ffuf reçoit `-rate`,
    la collecte d'assets est bornée (nombre max). Aucun flood.
  - dégradation gracieuse : outil externe absent / réseau indisponible -> finding `status='skipped'`
    (INFO) au lieu d'un crash (offline-safe).
  - modèle à preuve : findings informatifs de surface (`status='tested'`) ; JAMAIS promus `vulnerable`
    (pas d'exploitation). Un secret exposé est un finding défensif (exposition prouvée != impact exploité).

Docker vs binaire local : ffuf (`-w wordlist`) et trufflehog/gitleaks (scan d'un dossier local)
LISENT DES FICHIERS LOCAUX que le connecteur sans shell `runner.tool` NE monte PAS dans un conteneur
(`docker run` sans `-v`). On restreint donc ces outils au BINAIRE LOCAL (docker_image=None) : absent -> skipped.
"""
import json
import os
import re
import shutil
import tempfile

from .registry import register
from .recon_surface import PassiveSurface, _host_only
from .. import runner
from .. import techniques


# =================================================================================================
#  recon.content — découverte de contenu/routes web (wrapper ffuf, connecteur sans shell)
# =================================================================================================
# Liste de chemins candidats par défaut (compacte mais utile) — surchargée par params.paths /
# params.wordlist. Constante module-level (convention toolkit : payloads en constantes).
DEFAULT_PATHS = [
    "admin", "administrator", "login", "api", "api/v1", "api/v2", "graphql", "graphiql",
    "config", "config.json", "config.js", "app.config.js", ".env", ".env.local",
    ".git/config", ".git/HEAD", "backup", "backup.zip", "dump.sql", "db.sql",
    "robots.txt", "sitemap.xml", "wp-admin", "wp-login.php", "phpinfo.php", "info.php",
    "server-status", "actuator", "actuator/health", "actuator/env", "swagger", "swagger.json",
    "openapi.json", "api-docs", "debug", "test", "dev", "staging", "old", "tmp", "uploads",
    "static", "assets", "console", "dashboard", "internal", "metrics", "health", "status",
    "version", ".well-known/security.txt",
]


@register("recon.content")
class ContentDiscovery(PassiveSurface):
    kind = "recon.content"
    mitre = techniques.mitre_for("recon.content")            # T1595.003 (source de vérité : techniques.py)
    tool = "forge/modules/recon_active.py:recon.content"
    category = "recon"
    description = ("Découverte ACTIVE de contenu/routes web via ffuf (chemins candidats) — "
                   "scope-locked, rate-limité, lecture seule. ffuf absent -> skipped (T1595.003).")
    BIN, IMG = "ffuf", None                                  # binaire LOCAL seul (docker ne monte pas la wordlist)
    # codes de statut « intéressants » (route existante/protégée) — pas 404/400.
    MATCH_CODES = "200,201,202,203,204,301,302,307,308,401,403,405,500"
    MAX_ROUTES = 300                                         # borne le nombre de findings par-route

    @staticmethod
    def _tool_available():
        """Seam (patchable) : ffuf (binaire local) est-il présent ? Absent -> le module dégrade en skipped."""
        return runner.available(ContentDiscovery.BIN, None)

    @staticmethod
    def _run_ffuf(url, wordlist, rate, threads, timeout):
        """Seam sous-processus SANS shell (comme web.nuclei) : construit la liste d'args ffuf et
        l'exécute via runner.tool. Renvoie (rc, stdout, stderr). Patchable par les tests (aucun binaire)."""
        args = ["-u", url.rstrip("/") + "/FUZZ", "-w", str(wordlist) + ":FUZZ",
                "-mc", ContentDiscovery.MATCH_CODES, "-rate", str(int(rate)), "-t", str(int(threads)),
                "-timeout", "10", "-json", "-s", "-noninteractive"]
        return runner.tool(ContentDiscovery.BIN, None, args, timeout=timeout)

    def _rate(self, action):
        """Débit (req/s) : `rate` injecté par l'engine depuis le débit ROE du scope, défaut modeste 10."""
        try:
            return max(1, int(action.params.get("rate") or 10))
        except (TypeError, ValueError):
            return 10

    def _threads(self, action):
        """Concurrence bornée (<= débit, plafond 40) — pas de flood."""
        return max(1, min(self._rate(action), 40))

    def _timeout(self, action):
        try:
            return max(10, min(int(action.params.get("timeout") or 120), 600))
        except (TypeError, ValueError):
            return 120

    def _wordlist(self, action):
        """(chemin_wordlist, n_chemins, tmp?) : `params.wordlist` (fichier existant) sinon
        `params.paths`/DEFAULT_PATHS écrits dans un fichier temporaire (nettoyé après)."""
        wl = action.params.get("wordlist")
        if wl and os.path.isfile(wl):
            try:
                n = sum(1 for _ in open(wl, "r", encoding="utf-8", errors="replace"))
            except OSError:
                n = 0
            return wl, n, False
        paths = [str(p).strip().lstrip("/") for p in (action.params.get("paths") or DEFAULT_PATHS) if str(p).strip()]
        fd, path = tempfile.mkstemp(prefix="forge-ffuf-", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(paths) + "\n")
        return path, len(paths), True

    def dry(self, action):
        rate = self._rate(action)
        return (f"# ffuf -u {self._url(action.target).rstrip('/')}/FUZZ -w <wordlist>:FUZZ "
                f"-mc {self.MATCH_CODES} -rate {rate} -t {self._threads(action)} -json -s "
                f"# rate-limité, lecture seule, in-scope")

    def fire(self, action):
        target = action.target
        if not self._target_allowed(action):
            return [self._skipped(target, "recon.content non exécuté — cible hors périmètre (fail-closed)",
                                  "La cible n'appartient pas au périmètre in-scope ; aucune requête émise.",
                                  self.dry(action))]
        if not self._tool_available():
            return [self._skipped(target, "recon.content non exécuté — ffuf indisponible (dégradation)",
                                  "Le binaire ffuf est absent ; aucune découverte de contenu possible. "
                                  "Installer ffuf (binaire local) pour activer ce module.", self.dry(action))]
        wl, n_paths, is_tmp = self._wordlist(action)
        try:
            rc, out, err = self._run_ffuf(self._url(target), wl, self._rate(action),
                                          self._threads(action), self._timeout(action))
        finally:
            if is_tmp:
                try:
                    os.unlink(wl)
                except OSError:
                    pass
        results = self._parse_ffuf(out)
        # VERROU périmètre (défense en profondeur) : ne garder que les URLs dont l'hôte est in-scope
        # (une redirection ffuf peut pointer hors périmètre). Sans scope injecté (dev/test) -> permissif.
        kept = [r for r in results if self._in_scope_flat(action, _host_only(r.get("url") or target))]
        if not results and rc != 0:
            return [self._skipped(target, "recon.content non concluant — ffuf a échoué",
                                  (f"rc={rc} ; " + ((err or out) or "").strip()[:300]) or f"rc={rc}",
                                  self.dry(action))]
        if not kept:
            return [self._finding(target, "recon.content — aucune route découverte",
                                  f"ffuf: {n_paths} chemin(s) testé(s), aucune route sur code(s) {self.MATCH_CODES}.",
                                  self.dry(action))]
        findings = [self._finding(
            target, f"Routes découvertes (ffuf) : {len(kept)} in-scope",
            (f"{len(kept)} route(s) sur {n_paths} chemin(s) testé(s) "
             f"({len(results) - len(kept)} hors périmètre écartée(s)). "
             f"Exemples : {', '.join(sorted(str(r.get('url')) for r in kept)[:30]) or '—'}"),
            self.dry(action))]
        for r in kept[:self.MAX_ROUTES]:
            url = r.get("url") or target
            code, length, redir = r.get("status"), r.get("length"), r.get("redirect")
            findings.append(self._finding(
                url, f"Route in-scope : {url} [{code}]",
                (f"HTTP {code} ; length={length}" + (f" ; -> {redir}" if redir else "")
                 + " (découverte, jamais exploitée)"),
                f"curl -sI {url}"))
        return findings

    @staticmethod
    def _parse_ffuf(out):
        """Parse la sortie ffuf de façon ROBUSTE (ne lève jamais). Gère les deux formes rencontrées :
          - objet JSON global `{"results": [ {url,status,length,redirectlocation,input}, ... ]}` ;
          - flux JSONL (un objet résultat par ligne). Renvoie list[{url,status,length,redirect}]."""
        def _norm(r):
            url = r.get("url")
            if not url:
                inp = r.get("input")
                fuzz = inp.get("FUZZ") if isinstance(inp, dict) else None
                url = fuzz or ""
            return {"url": url, "status": r.get("status"), "length": r.get("length"),
                    "redirect": r.get("redirectlocation") or r.get("redirect") or ""}
        text = out or ""
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("results"), list):
            return [_norm(r) for r in obj["results"] if isinstance(r, dict)]
        if isinstance(obj, list):
            return [_norm(r) for r in obj if isinstance(r, dict)]
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except ValueError:
                continue
            if isinstance(j, dict):
                if isinstance(j.get("results"), list):
                    results += [_norm(r) for r in j["results"] if isinstance(r, dict)]
                elif ("url" in j) or ("input" in j):
                    results.append(_norm(j))
        return results


# =================================================================================================
#  recon.secrets — détection de secrets EXPOSÉS dans les assets in-scope (wrapper trufflehog/gitleaks)
# =================================================================================================
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# chemins de config couramment exposés — probés SOUS la racine in-scope (GET bornés, in-scope only).
DEFAULT_CONFIG_PATHS = [
    "/.env", "/config.json", "/config.js", "/app.config.js", "/settings.json",
    "/.git/config", "/credentials.json", "/secrets.json",
]


@register("recon.secrets")
class SecretScan(PassiveSurface):
    kind = "recon.secrets"
    mitre = techniques.mitre_for("recon.secrets")            # T1552.001
    tool = "forge/modules/recon_active.py:recon.secrets"
    category = "recon"
    description = ("Détecte les SECRETS EXPOSÉS dans les assets in-scope joignables (bundles JS, "
                   "config) en enveloppant trufflehog OU gitleaks. Secret redacté. Absent/réseau KO "
                   "-> skipped (T1552.001, finding défensif).")
    MAX_ASSETS = 20                                          # borne la collecte (rate/politesse)
    _SECRETS_FIX = ("Révoquer et faire tourner IMMÉDIATEMENT tout secret exposé ; ne jamais "
                    "embarquer de credential dans le code client ou les dépôts ; utiliser un "
                    "gestionnaire de secrets et un scan de secrets en CI (pre-commit + pipeline).")

    @staticmethod
    def _pick_scanner():
        """Seam (patchable) : ('trufflehog'|'gitleaks', binaire) selon disponibilité LOCALE (le scan
        d'un dossier local n'est pas montable en docker via le connecteur sans shell), sinon (None, None)."""
        if runner.available("trufflehog", None):
            return "trufflehog", "trufflehog"
        if runner.available("gitleaks", None):
            return "gitleaks", "gitleaks"
        return None, None

    @staticmethod
    def _scan(name, path):
        """Seam sous-processus SANS shell : scanne le dossier `path` avec le scanner choisi et renvoie
        (rc, stdout_json, stderr). Patchable par les tests. gitleaks écrit un rapport JSON -> on le relit."""
        if name == "trufflehog":
            return runner.tool("trufflehog", None, ["filesystem", path, "--json", "--no-update"], timeout=180)
        # gitleaks : rapport JSON dans un fichier temporaire, relu et renvoyé comme stdout.
        fd, report = tempfile.mkstemp(prefix="forge-gitleaks-", suffix=".json")
        os.close(fd)
        try:
            rc, _out, err = runner.tool(
                "gitleaks", None,
                ["dir", path, "--no-banner", "--report-format", "json", "--report-path", report],
                timeout=180)
            try:
                with open(report, "r", encoding="utf-8", errors="replace") as f:
                    data = f.read()
            except OSError:
                data = ""
            return rc, data, err
        finally:
            try:
                os.unlink(report)
            except OSError:
                pass

    def _collect_assets(self, action):
        """Récupère les assets in-scope à scanner : page cible + JS référencés in-scope + config-paths
        sous la racine + `params.asset_urls` (in-scope only). Renvoie list[(nom, contenu)]. Verrou
        fail-closed : jamais de fetch hors périmètre. Borné à MAX_ASSETS (rate)."""
        target = action.target
        assets, seen = [], set()

        def _add(url, body):
            if body and url not in seen and len(assets) < self.MAX_ASSETS:
                seen.add(url)
                assets.append((self._safe_name(url), body))

        # 1) page cible (in-scope : déjà validée par _target_allowed)
        st, html, _ = self._http_get(self._url(target), timeout=action.params.get("timeout", 20))
        if st is not None and html:
            _add(self._url(target), html)
            # 2) JS référencés (<script src>) — UNIQUEMENT in-scope (fail-closed)
            for src in _SCRIPT_SRC.findall(html):
                absu = self._absurl(target, src)
                if absu.startswith("http") and self._host_in_scope(action, _host_only(absu)):
                    jst, jbody, _ = self._http_get(absu, timeout=action.params.get("timeout", 20))
                    if jst is not None and jbody:
                        _add(absu, jbody)
        # 3) chemins de config sous la racine (in-scope) — bornés
        base = self._url(target).rstrip("/")
        for p in (action.params.get("config_paths") or DEFAULT_CONFIG_PATHS):
            if len(assets) >= self.MAX_ASSETS:
                break
            u = base + (p if str(p).startswith("/") else "/" + str(p))
            cst, cbody, _ = self._http_get(u, timeout=action.params.get("timeout", 20))
            if cst is not None and cbody:
                _add(u, cbody)
        # 4) assets explicites (params.asset_urls) — in-scope only (fail-closed)
        for u in (action.params.get("asset_urls") or []):
            if len(assets) >= self.MAX_ASSETS:
                break
            if self._host_in_scope(action, _host_only(u)):
                ast, abody, _ = self._http_get(u, timeout=action.params.get("timeout", 20))
                if ast is not None and abody:
                    _add(u, abody)
        return assets

    @staticmethod
    def _absurl(target, src):
        import urllib.parse
        base = target if "://" in str(target) else "https://" + str(target)
        return urllib.parse.urljoin(base, src)

    @staticmethod
    def _safe_name(url):
        """Nom de fichier sûr, déterministe, dérivé de l'URL (pour écrire l'asset dans le dossier scanné)."""
        name = re.sub(r"[^a-zA-Z0-9._-]", "_", str(url))[-120:]
        return name or "asset"

    def dry(self, action):
        return (f"# GET assets in-scope de {action.target} (page + JS + config) -> scan trufflehog/"
                f"gitleaks (hors-ligne) ; secret REDACTÉ ; jamais exploité")

    def fire(self, action):
        target = action.target
        if not self._target_allowed(action):
            return [self._skipped(target, "recon.secrets non exécuté — cible hors périmètre (fail-closed)",
                                  "La cible n'appartient pas au périmètre in-scope ; aucune requête émise.",
                                  self.dry(action))]
        name, binary = self._pick_scanner()
        if not name:
            return [self._skipped(target, "recon.secrets non exécuté — aucun scanner (trufflehog/gitleaks) (dégradation)",
                                  "Ni trufflehog ni gitleaks (binaire local) n'est présent ; détection "
                                  "de secrets impossible. Installer l'un des deux pour activer ce module.",
                                  self.dry(action))]
        assets = self._collect_assets(action)
        if not assets:
            return [self._skipped(target, "recon.secrets non concluant — assets injoignables",
                                  "Aucun asset in-scope n'a pu être récupéré (réseau indisponible ou "
                                  "aucun contenu). Rien à scanner.", self.dry(action))]
        workdir = tempfile.mkdtemp(prefix="forge-secrets-")
        try:
            for fname, body in assets:
                try:
                    with open(os.path.join(workdir, fname), "w", encoding="utf-8", errors="replace") as f:
                        f.write(body)
                except OSError:
                    continue
            rc, out, err = self._scan(name, workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        secrets = self._parse_secrets(name, out)
        if not secrets:
            # gitleaks rend rc=1 QUAND il trouve des leaks (donc pas un échec) ; on ne dégrade en
            # skipped que sur un vrai échec d'outil (indisponible/timeout) sans aucun résultat parsé.
            if rc in (124, 127):
                return [self._skipped(target, f"recon.secrets non concluant — {name} indisponible/timeout",
                                      (f"rc={rc} ; " + ((err or out) or "").strip()[:300]) or f"rc={rc}",
                                      self.dry(action))]
            return [self._finding(target, f"recon.secrets — aucun secret exposé ({name})",
                                  f"{name}: {len(assets)} asset(s) in-scope scanné(s), aucun secret détecté.",
                                  self.dry(action))]
        findings = [self._finding(
            target, f"Secrets EXPOSÉS détectés ({name}) : {len(secrets)}",
            (f"{len(secrets)} secret(s) dans {len(assets)} asset(s) in-scope scanné(s). "
             f"Détecteurs : {', '.join(sorted({str(s.get('detector')) for s in secrets}))[:300]}"),
            self.dry(action))]
        for s in secrets[:self.MAX_ASSETS * 5]:
            verified = bool(s.get("verified"))
            findings.append(self.finding(
                target=target,
                title=f"Secret exposé : {s.get('detector')}" + (" (VÉRIFIÉ)" if verified else ""),
                severity=("MEDIUM" if verified else "LOW"),
                category=self.category, mitre=self.mitre, status="tested", tool=name,
                fix=self._SECRETS_FIX,
                evidence=(f"détecteur={s.get('detector')} vérifié={verified} "
                          f"fichier={s.get('file')}:{s.get('line')} valeur={self._redact(s.get('raw'))} "
                          f"(exposition prouvée ; secret NON utilisé/exploité)")[:1800],
                poc=self.dry(action)))
        return findings

    @staticmethod
    def _redact(raw):
        """Masque un secret : ne JAMAIS restituer la valeur complète dans le finding (défensif)."""
        s = str(raw or "")
        if len(s) <= 6:
            return "***"
        return s[:4] + "…" + s[-2:] + f" ({len(s)} car.)"

    @staticmethod
    def _parse_secrets(name, out):
        """Parse la sortie du scanner en list[{detector,verified,raw,file,line}] (ne lève jamais).
          - trufflehog : JSONL (DetectorName/Verified/Raw/SourceMetadata.Data.Filesystem.file/line) ;
          - gitleaks   : tableau JSON (RuleID/Description/Secret/File/StartLine/Match)."""
        text = out or ""
        found = []
        if name == "trufflehog":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(j, dict) or not j.get("DetectorName"):
                    continue
                meta = (((j.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
                found.append({"detector": j.get("DetectorName"), "verified": bool(j.get("Verified")),
                              "raw": j.get("Raw") or j.get("Redacted") or "",
                              "file": meta.get("file", "?"), "line": meta.get("line", "?")})
            return found
        # gitleaks : tableau JSON (ou {} si aucun leak)
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, list):
            for it in data:
                if not isinstance(it, dict):
                    continue
                found.append({"detector": it.get("RuleID") or it.get("Description") or "gitleaks",
                              "verified": False,
                              "raw": it.get("Secret") or it.get("Match") or "",
                              "file": it.get("File", "?"), "line": it.get("StartLine", "?")})
        return found


# =================================================================================================
#  recon.waf — identification WAF/CDN (fingerprint INFORMATIF, passif)
# =================================================================================================
@register("recon.waf")
class WafIdentify(PassiveSurface):
    kind = "recon.waf"
    mitre = techniques.mitre_for("recon.waf")                # T1590
    tool = "forge/modules/recon_active.py:recon.waf"
    category = "recon"
    description = ("Identifie le WAF/CDN devant un hôte in-scope (heuristique passive en-têtes/cookies/"
                   "corps + wafw00f si présent). Fingerprint INFORMATIF uniquement (T1590).")
    # signatures d'en-têtes (sous-chaîne de clé/valeur -> label). Passif : lu sur une réponse normale.
    _HEADER_SIGS = {
        "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
        "x-sucuri-id": "Sucuri CloudProxy", "x-sucuri-cache": "Sucuri CloudProxy",
        "x-akamai-transformed": "Akamai", "akamai-grn": "Akamai",
        "x-iinfo": "Imperva Incapsula", "x-cdn": "Imperva Incapsula",
        "x-amz-cf-id": "AWS CloudFront", "x-amz-cf-pop": "AWS CloudFront",
        "x-fastly-request-id": "Fastly", "x-served-by": "Fastly/Varnish",
        "x-varnish": "Varnish", "x-distil-cs": "Imperva (Distil)",
        "x-sourcefiles": "Microsoft URLScan", "x-waf-event-info": "Reblaze",
    }
    # signatures dans les valeurs (Server / etc.)
    _SERVER_SIGS = {
        "cloudflare": "Cloudflare", "cloudfront": "AWS CloudFront", "akamaighost": "Akamai",
        "sucuri/cloudproxy": "Sucuri CloudProxy", "awselb": "AWS ELB", "bigip": "F5 BIG-IP",
        "mod_security": "ModSecurity", "barracuda": "Barracuda", "airee": "Airee",
    }
    # signatures de cookies (nom de cookie -> label)
    _COOKIE_SIGS = {
        "__cfduid": "Cloudflare", "__cf_bm": "Cloudflare", "incap_ses": "Imperva Incapsula",
        "visid_incap": "Imperva Incapsula", "nlbi_": "Imperva Incapsula", "awsalb": "AWS ELB",
        "ak_bmsc": "Akamai Bot Manager", "bm_sz": "Akamai Bot Manager", "sucuri": "Sucuri CloudProxy",
        "barra_counter_session": "Barracuda", "citrix_ns_id": "Citrix NetScaler",
    }
    WAFW00F_BIN = "wafw00f"

    @staticmethod
    def _wafw00f_available():
        """Seam (patchable) : wafw00f (binaire local) présent ? Absent -> heuristique seule (pas d'échec)."""
        return runner.available(WafIdentify.WAFW00F_BIN, None)

    @staticmethod
    def _run_wafw00f(url):
        """Seam sous-processus SANS shell : wafw00f -a -f json -o - <url> -> (rc, stdout, stderr)."""
        return runner.tool(WafIdentify.WAFW00F_BIN, None, ["-a", "-f", "json", "-o", "-", url], timeout=60)

    def dry(self, action):
        return (f"# GET {action.target} -> analyse en-têtes/cookies/Server (WAF/CDN) "
                f"(+ wafw00f -a si présent) — fingerprint informatif, passif")

    def fire(self, action):
        target = action.target
        if not self._target_allowed(action):
            return [self._skipped(target, "recon.waf non exécuté — cible hors périmètre (fail-closed)",
                                  "La cible n'appartient pas au périmètre in-scope ; aucune requête émise.",
                                  self.dry(action))]
        detected, evidence_bits = set(), []
        st, body, headers = self._http_get(self._url(target), timeout=action.params.get("timeout", 20))
        if st is not None:
            low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
            for hk, label in self._HEADER_SIGS.items():
                if hk in low:
                    detected.add(label)
            server_via = " ".join(low.get(h, "") for h in ("server", "via", "x-powered-by")).lower()
            for sig, label in self._SERVER_SIGS.items():
                if sig in server_via:
                    detected.add(label)
            setc = low.get("set-cookie", "").lower()
            for ck, label in self._COOKIE_SIGS.items():
                if ck in setc:
                    detected.add(label)
            evidence_bits.append(f"HTTP {st} ; Server={low.get('server', '—')}")
        # enrichissement OPTIONNEL par wafw00f (binaire local) — n'échoue jamais la détection.
        if action.params.get("use_wafw00f", True) and self._wafw00f_available():
            rc, out, _ = self._run_wafw00f(self._url(target))
            if rc == 0 and out:
                evidence_bits.append("wafw00f: " + out.strip()[:300])
                for fw in self._parse_wafw00f(out):
                    detected.add(fw)
        if st is None and not detected:
            return [self._skipped(target, "recon.waf non concluant — cible injoignable et wafw00f indisponible",
                                  "Aucune réponse HTTP et pas de wafw00f pour le fingerprint (dégradation).",
                                  self.dry(action))]
        return [self._finding(
            target,
            (f"WAF/CDN identifié : {', '.join(sorted(detected))}" if detected
             else "WAF/CDN : aucune signature identifiée"),
            (("Signatures : " + ", ".join(sorted(detected)) if detected else "Aucune signature WAF/CDN")
             + (" || " + " ; ".join(evidence_bits) if evidence_bits else "")
             + " (fingerprint informatif — aucune tentative de contournement)"),
            self.dry(action))]

    @staticmethod
    def _parse_wafw00f(out):
        """Extrait les WAF détectés d'une sortie wafw00f JSON (list[{detected,firewall}] ou
        {results:[...]}). Robuste, ne lève jamais."""
        firewalls = set()
        try:
            data = json.loads(out or "")
        except ValueError:
            return firewalls
        rows = data.get("results") if isinstance(data, dict) else data
        if isinstance(rows, list):
            for r in rows:
                if isinstance(r, dict) and r.get("detected") and r.get("firewall"):
                    fw = str(r.get("firewall")).strip()
                    if fw and fw.lower() not in ("none", "generic"):
                        firewalls.add(fw)
        return firewalls
