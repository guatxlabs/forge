# SPDX-License-Identifier: AGPL-3.0-only
"""Rapport d'ENGAGEMENT agrégé — le LIVRABLE CLIENT (couche à la Ghostwriter).

`report.py` produit le rapport markdown d'UN run (transparence ROE). Ce module produit, lui, le
rapport AGRÉGÉ d'un ENGAGEMENT (tous ses findings/runs), brandé au commanditaire, dans plusieurs
formats de livraison : HTML (primaire), PDF (via weasyprint/wkhtmltopdf résolus par `shutil.which`,
dégradé proprement en HTML+note d'impression si absents), DOCX (OOXML minimal VALIDE via `zipfile`
stdlib — zéro dépendance lourde ; repli documenté « DOCX via pandoc » si indisponible), CSV et JSON.

CONTRAT D'ENTRÉE (dict, tolérant aux clefs manquantes) — assemblé PAR L'APPELANT (la console Rust
l'exporte ISOLÉ à un seul engagement, ou un pipeline CLI) :

    {
      "generated":  "<iso ts>",                     # optionnel (auto si absent)
      "branding":   {"customer_name","logo","vendor","confidentiality"},
      "engagement": {"id","name","mode","status","classification","scope_in":[],"scope_out":[]},
      "findings":   [ {"target","title","severity","category"/"vuln_class","cwe","mitre",
                       "cvss_vector","cvss_score","status","tool","evidence","poc","fix",
                       "campaign","ts","engagement_id"} , ... ],
      "runs":       [ {"run_id","campaign","mode","status","started","finished","started_by",
                       "fired","dry_run","vetoed","errors"} , ... ],
      "attack":     {"techniques":[{"mitre","kinds":[],"targets":[],"fires"}],
                     "detection_source_configured": bool,
                     "techniques_fired","techniques_detected","techniques_missed","detection_rate",
                     "detected":[{"mitre","alert_count","mttd_secs"}],
                     "missed":[{"mitre","fires"}]},
      "custody":    {"ledger_path","entries","head","alg","chain_ok","why","pubkey","actor"}
    }

ISOLATION : le générateur rend EXACTEMENT les findings/runs qu'on lui donne — il ne va JAMAIS lire
d'autres données. `filter_findings_for_engagement` sert de garde côté appelant. SECRETS : chaque
champ texte est passé par `redact_secrets` AVANT rendu, dans TOUS les formats (HTML/CSV/JSON/DOCX).
"""
import csv
import io
import json
import re
import shutil
import subprocess
from collections import OrderedDict
from datetime import datetime, timezone

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

REDACT = "[REDACTED]"

# --- rédaction des secrets -------------------------------------------------------------------
# Ensemble de motifs à haut signal (formes de secrets connues) + paires clef=valeur sensibles.
# Idempotent : réappliquer sur un texte déjà rédigé ne change rien. Ne lève jamais.
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),                               # AWS access key id
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),  # JWT
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),                             # GitHub token
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"),                            # Slack token
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),                                # Google API key
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                                    # OpenAI-style key
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),                              # GitLab PAT
]
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}")
_URL_CRED = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://)([^/\s:@]+):([^/\s@]+)@")
_KV = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|secret[_-]?key|client[_-]?secret|api[_-]?key|apikey|"
    r"access[_-]?key|access[_-]?token|token|authorization|auth|x-api-key|cookie|set-cookie|"
    r"private[_-]?key|session[_-]?token)\b(\s*[:=]\s*)(\"?)([^\s\"'&;,]{3,})"
)


def redact_secrets(text):
    """Neutralise les secrets d'une chaîne (formes connues + paires clef=valeur + creds d'URL).
    Renvoie l'entrée telle quelle si ce n'est pas une chaîne (int/None…). Pur, ne lève jamais."""
    if not isinstance(text, str) or not text:
        return text
    s = text
    for p in _SECRET_PATTERNS:
        s = p.sub(REDACT, s)
    s = _BEARER.sub("Bearer " + REDACT, s)
    s = _URL_CRED.sub(lambda m: f"{m.group(1)}{m.group(2)}:{REDACT}@", s)
    s = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACT}", s)
    return s


def redact_finding(f):
    """Copie d'un finding avec TOUS ses champs texte passés au rédacteur (evidence/poc/fix/title/…).
    Les champs non-texte (cvss_score, engagement_id) sont conservés tels quels."""
    out = {}
    for k, v in (f or {}).items():
        out[k] = redact_secrets(v) if isinstance(v, str) else v
    return out


# --- normalisation / agrégation --------------------------------------------------------------

def _vuln_class(f):
    """Classe de vuln d'un finding : `vuln_class` explicite, sinon `category` (fourre-tout console)."""
    return (f.get("vuln_class") or f.get("category") or "").strip()


def _norm_sev(f):
    s = (f.get("severity") or "INFO").strip().upper()
    return s if s in SEV_RANK else "INFO"


def filter_findings_for_engagement(findings, engagement_id):
    """GARDE D'ISOLATION (côté appelant) : ne retient QUE les findings estampillés `engagement_id`
    == la valeur demandée. Un finding sans `engagement_id` n'est JAMAIS attribué à un engagement
    ciblé (fail-closed). Pur."""
    out = []
    for f in findings or []:
        if str(f.get("engagement_id", "")) == str(engagement_id):
            out.append(f)
    return out


def summarize(findings):
    """Compteurs du résumé exécutif : par sévérité, par classe de vuln, par statut, + total.
    Aucune donnée sensible (juste des comptes). Déterministe (clefs triées)."""
    by_sev = OrderedDict((s, 0) for s in reversed(SEVERITIES))
    by_class = {}
    by_status = {}
    for f in findings or []:
        by_sev[_norm_sev(f)] = by_sev.get(_norm_sev(f), 0) + 1
        vc = _vuln_class(f) or "(non classé)"
        by_class[vc] = by_class.get(vc, 0) + 1
        st = (f.get("status") or "tested").strip() or "tested"
        by_status[st] = by_status.get(st, 0) + 1
    return {
        "total": sum(by_sev.values()),
        "by_severity": dict(by_sev),
        "by_vuln_class": dict(sorted(by_class.items())),
        "by_status": dict(sorted(by_status.items())),
    }


def group_findings(findings):
    """Groupe les findings PAR SÉVÉRITÉ (décroissante) PUIS PAR CLASSE DE VULN (alpha). Renvoie une
    liste de tuples `(severity, [(vuln_class, [findings]) , ...])`. Déterministe."""
    buckets = {}
    for f in findings or []:
        buckets.setdefault(_norm_sev(f), {}).setdefault(_vuln_class(f) or "(non classé)", []).append(f)
    out = []
    for sev in sorted(buckets, key=lambda s: -SEV_RANK.get(s, 0)):
        classes = [(vc, buckets[sev][vc]) for vc in sorted(buckets[sev])]
        out.append((sev, classes))
    return out


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize(data):
    """Renvoie une copie NORMALISÉE et RÉDIGÉE du dict d'entrée : findings redigés, summary (re)calculé,
    horodatage `generated` posé si absent. C'est cette structure qui alimente tous les formats."""
    data = dict(data or {})
    findings = [redact_finding(f) for f in (data.get("findings") or [])]
    runs = [{k: (redact_secrets(v) if isinstance(v, str) else v) for k, v in (r or {}).items()}
            for r in (data.get("runs") or [])]
    out = {
        "generated": data.get("generated") or _now_iso(),
        "branding": dict(data.get("branding") or {}),
        "engagement": dict(data.get("engagement") or {}),
        "findings": findings,
        "runs": runs,
        "attack": dict(data.get("attack") or {}),
        "custody": dict(data.get("custody") or {}),
    }
    out["summary"] = summarize(findings)
    return out


# --- helpers d'affichage ---------------------------------------------------------------------

def _brand_name(branding):
    return (branding.get("customer_name") or "").strip() or "Commanditaire"


def _cvss_display(f):
    try:
        score = float(f.get("cvss_score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    vec = (f.get("cvss_vector") or "").strip()
    if score <= 0 and not vec:
        return ""
    if not vec:
        return f"{score:.1f}"
    return f"{score:.1f} ({vec})"


def _dash(s):
    s = (s or "").strip() if isinstance(s, str) else s
    return s if s else "—"


# =============================================================================================
#  CSV
# =============================================================================================
_CSV_COLS = ["severity", "vuln_class", "cwe", "cvss_score", "cvss_vector", "mitre", "status",
             "target", "title", "tool", "campaign", "evidence", "poc", "fix", "ts"]


def build_csv(data_or_findings):
    """Export CSV des findings (déjà rédigés). Accepte soit le dict complet, soit la liste findings.
    En-tête stable (_CSV_COLS) — round-trip par `csv.reader`. Échappement standard (guillemets)."""
    if isinstance(data_or_findings, dict):
        findings = data_or_findings.get("findings") or []
        # si on reçoit un dict brut non normalisé, on rédige à la volée (idempotent).
        findings = [redact_finding(f) for f in findings]
    else:
        findings = [redact_finding(f) for f in (data_or_findings or [])]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(_CSV_COLS)
    for f in findings:
        row = []
        for c in _CSV_COLS:
            v = f.get("vuln_class") or f.get("category") if c == "vuln_class" else f.get(c, "")
            row.append("" if v is None else str(v))
        w.writerow(row)
    return buf.getvalue()


# =============================================================================================
#  JSON
# =============================================================================================

def build_json(data):
    """Export JSON du rapport agrégé (findings/runs rédigés + summary + attack + custody). Stable
    (clefs triées, indenté)."""
    norm = data if data.get("summary") else normalize(data)
    return json.dumps(norm, ensure_ascii=False, indent=2, sort_keys=True)


# =============================================================================================
#  HTML (primaire) — document AUTONOME brandé
# =============================================================================================
_HTML_CSS = """<style>
:root{--bg:#0b0f17;--card:#141b27;--bd:#243044;--hd:#eaf2fb;--fg:#cdd9e6;--mut:#8aa0b4;--acc:#ff5a5f;
--crit:#ff6b6b;--high:#ffa94d;--med:#ffd43b;--low:#74c0fc;--info:#8aa0b4;
--sans:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;--mono:ui-monospace,'JetBrains Mono',monospace}
*{box-sizing:border-box}body{margin:0 auto;max-width:920px;padding:0 28px 64px;background:var(--bg);
color:var(--fg);font-family:var(--sans);line-height:1.6;font-size:14px}
h1,h2,h3{color:var(--hd);line-height:1.25}h2{font-size:20px;margin:30px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--bd)}
h3{font-size:15px;margin:16px 0 8px}code{font-family:var(--mono);background:#0c1422;border:1px solid var(--bd);border-radius:5px;padding:1px 5px;color:var(--acc)}
pre{font-family:var(--mono);font-size:12px;background:#0c1422;border:1px solid var(--bd);border-radius:8px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:var(--mut)}.cover{text-align:center;padding:56px 0 24px;border-bottom:1px solid var(--bd)}
.cover img{max-height:96px;max-width:280px;margin-bottom:14px}
.cover .cust{font-size:30px;font-weight:800;color:var(--hd)}.cover .vendor{color:var(--mut);margin-top:4px}
.cover .title{font-size:22px;margin:18px 0 6px;color:var(--acc)}.cover .conf{margin-top:24px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.sevgrid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.sevcard{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 8px;text-align:center}
.sevcard .n{font-size:26px;font-weight:800}.sevcard .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.sev-CRITICAL{border-color:var(--crit)}.sev-CRITICAL .n{color:var(--crit)}
.sev-HIGH{border-color:var(--high)}.sev-HIGH .n{color:var(--high)}
.sev-MEDIUM{border-color:var(--med)}.sev-MEDIUM .n{color:var(--med)}
.sev-LOW{border-color:var(--low)}.sev-LOW .n{color:var(--low)}
.finding{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;margin:12px 0;break-inside:avoid}
.badge{display:inline-block;font-size:11px;font-weight:800;padding:2px 8px;border-radius:6px;border:1px solid var(--bd)}
.b-CRITICAL{color:var(--crit);border-color:var(--crit)}.b-HIGH{color:var(--high);border-color:var(--high)}
.b-MEDIUM{color:var(--med);border-color:var(--med)}.b-LOW{color:var(--low);border-color:var(--low)}.b-INFO{color:var(--info)}
.chip{display:inline-block;font-size:11px;background:#0c1422;border:1px solid var(--bd);border-radius:6px;padding:2px 7px;margin:2px 4px 2px 0}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid var(--bd);padding:5px 8px;text-align:left}
th{color:var(--mut);font-weight:600}
@media print{body{max-width:none;color:#000;background:#fff}.finding,.sevcard{break-inside:avoid}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>"""


def _e(s):
    """Échappe le HTML d'une valeur quelconque (coercée en str)."""
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def build_html(data):
    """Rapport d'engagement HTML BRANDÉ, document autonome (CSS inliné, imprimable). Contenu : en-tête
    de branding (nom client + logo), résumé exécutif (comptes par sévérité/classe/statut), findings
    groupés sévérité→classe (CWE/MITRE/sévérité/evidence/PoC/remédiation, secrets RÉDIGÉS), couverture
    ATT&CK (techniques exercées + détecté/raté si source configurée), annexe chaîne-de-custody (head
    du ledger + clé publique Ed25519). Tout texte dynamique est échappé HTML."""
    norm = data if data.get("summary") else normalize(data)
    b = norm["branding"]
    eng = norm["engagement"]
    summ = norm["summary"]
    findings = norm["findings"]
    vendor = (b.get("vendor") or "GuatX Forge").strip()
    conf = (b.get("confidentiality") or "Document confidentiel — diffusion restreinte au commanditaire").strip()

    h = ['<!doctype html><html lang="fr"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f'<title>{_e(_brand_name(b))} — rapport d\'engagement</title>', _HTML_CSS, "</head><body>"]

    # ---- page de garde / branding ----
    h.append('<section class="cover">')
    logo = (b.get("logo") or "").strip()
    if logo:
        h.append(f'<img src="{_e(logo)}" alt="logo">')
    h.append(f'<div class="cust">{_e(_brand_name(b))}</div>')
    h.append(f'<div class="vendor">Évaluation de sécurité — {_e(vendor)}</div>')
    h.append(f'<div class="title">Rapport d\'engagement : {_e(eng.get("name") or "engagement")}</div>')
    meta = [f'engagement #{_e(eng.get("id"))}', f'mode {_e(eng.get("mode") or "—")}',
            f'statut {_e(eng.get("status") or "—")}', f'généré le {_e(norm.get("generated"))}']
    if eng.get("classification"):
        meta.append(f'classification {_e(eng.get("classification"))}')
    h.append(f'<div class="muted">{" · ".join(meta)}</div>')
    h.append(f'<div class="conf">{_e(conf)}</div>')
    h.append("</section>")

    # ---- résumé exécutif ----
    h.append('<section><h2>Résumé exécutif</h2>')
    scope_in = ", ".join(eng.get("scope_in") or []) or "—"
    h.append(f'<p>Cet engagement a couvert le périmètre <code>{_e(scope_in)}</code>. '
             f'{_e(_prose_counts(summ))}</p>')
    h.append('<div class="sevgrid">')
    for s in reversed(SEVERITIES):
        h.append(f'<div class="sevcard sev-{s}"><div class="n">{summ["by_severity"].get(s, 0)}</div>'
                 f'<div class="l">{s}</div></div>')
    h.append("</div>")
    if summ["by_vuln_class"]:
        h.append("<h3>Par classe de vulnérabilité</h3><table><tr><th>Classe</th><th>#</th></tr>")
        for vc, n in summ["by_vuln_class"].items():
            h.append(f"<tr><td>{_e(vc)}</td><td>{n}</td></tr>")
        h.append("</table>")
    if summ["by_status"]:
        h.append("<h3>Par statut</h3><table><tr><th>Statut</th><th>#</th></tr>")
        for st, n in summ["by_status"].items():
            h.append(f"<tr><td>{_e(st)}</td><td>{n}</td></tr>")
        h.append("</table>")
    h.append("</section>")

    # ---- findings groupés sévérité -> classe ----
    h.append('<section><h2>Findings</h2>')
    if not findings:
        h.append('<p class="muted">Aucun finding retenu sur cet engagement.</p>')
    for sev, classes in group_findings(findings):
        h.append(f'<h3><span class="badge b-{sev}">{sev}</span></h3>')
        for vc, items in classes:
            h.append(f'<div class="muted">Classe : <b>{_e(vc)}</b></div>')
            for f in items:
                h.append('<article class="finding">')
                h.append(f'<h3>{_e(f.get("title") or "(sans titre)")} '
                         f'<span class="muted">{_e(f.get("target"))}</span></h3>')
                h.append(f'<div><span class="chip"><b>CWE</b> {_e(_dash(f.get("cwe")))}</span>'
                         f'<span class="chip"><b>CVSS</b> {_e(_dash(_cvss_display(f)))}</span>'
                         f'<span class="chip"><b>ATT&amp;CK</b> {_e(_dash(f.get("mitre")))}</span>'
                         f'<span class="chip"><b>Statut</b> {_e(_dash(f.get("status")))}</span>'
                         f'<span class="chip"><b>Outil</b> {_e(_dash(f.get("tool")))}</span></div>')
                if f.get("evidence"):
                    h.append(f'<div><b>Evidence</b><pre>{_e(f.get("evidence"))}</pre></div>')
                if f.get("poc"):
                    h.append(f'<div><b>PoC</b><pre>{_e(f.get("poc"))}</pre></div>')
                if f.get("fix"):
                    h.append(f'<div><b>Remédiation</b><p>{_e(f.get("fix"))}</p></div>')
                h.append("</article>")
    h.append("</section>")

    # ---- couverture ATT&CK ----
    h.append('<section><h2>Couverture ATT&amp;CK</h2>')
    _html_attack(h, norm.get("attack") or {})
    h.append("</section>")

    # ---- annexe chaîne de custody ----
    h.append('<section><h2>Annexe — chaîne de custody</h2>')
    _html_custody(h, norm.get("custody") or {})
    h.append("</section>")

    h.append("</body></html>")
    return "".join(h)


def _prose_counts(summ):
    total = summ.get("total", 0)
    if total == 0:
        return "Aucun finding n'a été retenu."
    parts = []
    labels = {"CRITICAL": "critique", "HIGH": "élevé", "MEDIUM": "moyen", "LOW": "faible", "INFO": "informatif"}
    for s in reversed(SEVERITIES):
        n = summ["by_severity"].get(s, 0)
        if n:
            w = labels[s] + ("s" if n > 1 else "")
            parts.append(f"{n} {w}")
    return f"L'évaluation a retenu {total} finding{'s' if total > 1 else ''} : {', '.join(parts)}."


def _html_attack(h, attack):
    techs = attack.get("techniques") or []
    if techs:
        h.append("<h3>Techniques exercées</h3><table><tr><th>ATT&amp;CK</th><th>Kind(s)</th>"
                 "<th>Cible(s)</th><th>Tirs</th></tr>")
        for t in techs:
            kinds = ", ".join(t.get("kinds") or []) or "—"
            tgts = ", ".join(t.get("targets") or []) or "—"
            h.append(f'<tr><td><code>{_e(t.get("mitre"))}</code></td><td>{_e(kinds)}</td>'
                     f'<td>{_e(tgts)}</td><td>{_e(t.get("fires"))}</td></tr>')
        h.append("</table>")
    else:
        h.append('<p class="muted">Aucune technique ATT&amp;CK taggée n\'a été tirée sur cet engagement.</p>')
    if not attack.get("detection_source_configured"):
        h.append('<p class="muted">Aucune source de détection configurée — Forge en autonome. '
                 'Matrice détecté/raté indisponible (aucune couverture inventée).</p>')
        return
    h.append("<h3>Détection (source configurée)</h3><ul>")
    h.append(f'<li>Tirées : {_e(attack.get("techniques_fired", 0))} · '
             f'Détectées : {_e(attack.get("techniques_detected", 0))} · '
             f'Ratées : {_e(attack.get("techniques_missed", 0))}</li></ul>')
    missed = attack.get("missed") or []
    if missed:
        h.append("<h3>Techniques NON détectées (trous)</h3><ul>")
        for m in missed:
            h.append(f'<li><code>{_e(m.get("mitre"))}</code> — tirée {_e(m.get("fires", 0))}×</li>')
        h.append("</ul>")
    detected = attack.get("detected") or []
    if detected:
        h.append("<h3>Techniques détectées</h3><ul>")
        for d in detected:
            h.append(f'<li><code>{_e(d.get("mitre"))}</code> — {_e(d.get("alert_count", 0))} alerte(s), '
                     f'MTTD {_e(d.get("mttd_secs", "—"))}</li>')
        h.append("</ul>")


def _html_custody(h, custody):
    if not custody:
        h.append('<p class="muted">Aucune annexe de custody (ledger non fourni).</p>')
        return
    ok = custody.get("chain_ok")
    integrity = ("VALIDE (chaîne SHA-256 recalculée)" if ok
                 else f"ROMPUE — {custody.get('why') or 'intégrité non vérifiée'}")
    rows = [("Ledger", custody.get("ledger_path")), ("Entrées", custody.get("entries")),
            ("Algorithme", custody.get("alg") or "—"), ("Head (dernier hash)", custody.get("head") or "—"),
            ("Intégrité", integrity)]
    if custody.get("pubkey"):
        rows.append(("Clé publique (Ed25519)", custody.get("pubkey")))
    h.append('<p class="muted">Preuve d\'intégrité de l\'audit : chaîne de hachage SHA-256 du ledger '
             "d'engagement (chaque acte chaîné au précédent). La clé publique permet une vérification "
             "externe sans aucun secret.</p><table>")
    for k, v in rows:
        h.append(f"<tr><th>{_e(k)}</th><td><code>{_e(v)}</code></td></tr>")
    h.append("</table>")
    if custody.get("pubkey") and custody.get("ledger_path"):
        h.append(f'<pre>forge ledger verify --ledger {_e(custody.get("ledger_path"))} '
                 f'--pubkey {_e(custody.get("pubkey"))}</pre>')


# =============================================================================================
#  DOCX — OOXML minimal VALIDE via zipfile stdlib (aucune dépendance lourde)
# =============================================================================================
_CONTENT_TYPES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                  '<Default Extension="xml" ContentType="application/xml"/>'
                  '<Override PartName="/word/document.xml" '
                  'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
                  "</Types>")
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" '
         'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
         'Target="word/document.xml"/></Relationships>')


def _xml_escape(s):
    s = "" if s is None else str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _para(text, bold=False, size=None, heading=False):
    """Un paragraphe OOXML `<w:p>`. `bold`/`size` (demi-points) stylent le run sans styles.xml."""
    rpr = []
    if bold or heading:
        rpr.append("<w:b/>")
    if size:
        rpr.append(f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>')
    rpr_xml = f"<w:rPr>{''.join(rpr)}</w:rPr>" if rpr else ""
    # `xml:space=preserve` conserve les espaces ; retours à la ligne -> <w:br/>.
    parts = _xml_escape(text).split("\n")
    runs = f'<w:r>{rpr_xml}<w:t xml:space="preserve">{parts[0]}</w:t></w:r>'
    for seg in parts[1:]:
        runs += f'<w:r>{rpr_xml}<w:br/><w:t xml:space="preserve">{seg}</w:t></w:r>'
    return f"<w:p>{runs}</w:p>"


def _docx_document_xml(norm):
    b = norm["branding"]
    eng = norm["engagement"]
    summ = norm["summary"]
    body = [_para(_brand_name(b), bold=True, size=44),
            _para(f'Rapport d\'engagement : {eng.get("name") or "engagement"}', size=32),
            _para(f'{(b.get("vendor") or "GuatX Forge")} · engagement #{eng.get("id")} · '
                  f'mode {eng.get("mode") or "—"} · généré le {norm.get("generated")}'),
            _para(b.get("confidentiality") or "Document confidentiel — diffusion restreinte au commanditaire"),
            _para("Résumé exécutif", heading=True, size=28),
            _para(_prose_counts(summ))]
    for s in reversed(SEVERITIES):
        body.append(_para(f"{s} : {summ['by_severity'].get(s, 0)}"))
    body.append(_para("Findings", heading=True, size=28))
    if not norm["findings"]:
        body.append(_para("Aucun finding retenu."))
    for sev, classes in group_findings(norm["findings"]):
        body.append(_para(f"[{sev}]", bold=True))
        for vc, items in classes:
            body.append(_para(f"Classe : {vc}", bold=True))
            for f in items:
                body.append(_para(f"{f.get('title') or '(sans titre)'} — {f.get('target') or ''}", bold=True))
                body.append(_para(f"CWE {_dash(f.get('cwe'))} · CVSS {_dash(_cvss_display(f))} · "
                                  f"ATT&CK {_dash(f.get('mitre'))} · Statut {_dash(f.get('status'))}"))
                if f.get("evidence"):
                    body.append(_para(f"Evidence : {f.get('evidence')}"))
                if f.get("poc"):
                    body.append(_para(f"PoC : {f.get('poc')}"))
                if f.get("fix"):
                    body.append(_para(f"Remédiation : {f.get('fix')}"))
    # ATT&CK
    body.append(_para("Couverture ATT&CK", heading=True, size=28))
    attack = norm.get("attack") or {}
    for t in (attack.get("techniques") or []):
        body.append(_para(f"{t.get('mitre')} — kinds {', '.join(t.get('kinds') or []) or '—'} — "
                          f"tirs {t.get('fires', 0)}"))
    if not (attack.get("techniques") or []):
        body.append(_para("Aucune technique ATT&CK taggée tirée."))
    if not attack.get("detection_source_configured"):
        body.append(_para("Aucune source de détection configurée — matrice détecté/raté indisponible."))
    # custody
    body.append(_para("Annexe — chaîne de custody", heading=True, size=28))
    c = norm.get("custody") or {}
    if c:
        body.append(_para(f"Ledger : {c.get('ledger_path')}"))
        body.append(_para(f"Entrées : {c.get('entries')} · Algorithme : {c.get('alg') or '—'}"))
        body.append(_para(f"Head : {c.get('head') or '—'}"))
        body.append(_para(f"Intégrité : {'VALIDE' if c.get('chain_ok') else 'ROMPUE'}"))
        if c.get("pubkey"):
            body.append(_para(f"Clé publique (Ed25519) : {c.get('pubkey')}"))
    else:
        body.append(_para("Aucune annexe de custody (ledger non fourni)."))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f'<w:body>{"".join(body)}<w:sectPr/></w:body></w:document>')


def build_docx(data):
    """Génère un .docx OOXML minimal mais VALIDE (ZIP : [Content_Types].xml + _rels/.rels +
    word/document.xml) via `zipfile` stdlib. Renvoie les octets. Secrets déjà rédigés (via normalize)."""
    import zipfile
    norm = data if data.get("summary") else normalize(data)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", _docx_document_xml(norm))
    return buf.getvalue()


def build_docx_or_pandoc(data):
    """DOCX : chemin primaire = `build_docx` (zipfile stdlib, toujours disponible). Le repli documenté
    « DOCX via pandoc » n'est utile que si l'on préfère un rendu riche depuis le HTML — tenté seulement
    si `pandoc` est présent (shutil.which) ET que le chemin stdlib est explicitement désactivé. Ici on
    renvoie toujours le DOCX stdlib (valide, sans dépendance). Fonction fournie pour la parité de contrat."""
    return build_docx(data)


# =============================================================================================
#  PDF — réutilise le chemin HTML->PDF via weasyprint/wkhtmltopdf (shutil.which). Dégrade proprement.
# =============================================================================================
_PRINT_NOTE = ("Aucun moteur PDF (weasyprint/wkhtmltopdf) détecté — ouvrez le HTML puis « Imprimer » "
               "→ « Enregistrer au format PDF » (CSS @media print fourni).")


def build_pdf(html):
    """Rend un PDF depuis le HTML brandé via un outil SYSTÈME résolu par `shutil.which` :
    wkhtmltopdf (stdin->stdout) ou weasyprint (fichier temp->stdout). AUCUNE dépendance lourde.
    Renvoie `(bytes, "")` si produit, sinon `(None, note d'impression)` (dégradation gracieuse)."""
    wk = shutil.which("wkhtmltopdf")
    if wk:
        try:
            out = subprocess.run([wk, "--quiet", "--print-media-type", "-", "-"],
                                 input=html.encode("utf-8"), stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, check=False)
            if out.returncode == 0 and out.stdout:
                return out.stdout, ""
        except OSError:
            pass
    wp = shutil.which("weasyprint")
    if wp:
        import tempfile
        import os
        d = tempfile.mkdtemp(prefix="forge-report-")
        try:
            p = os.path.join(d, "report.html")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(html)
            out = subprocess.run([wp, p, "-"], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, check=False)
            if out.returncode == 0 and out.stdout:
                return out.stdout, ""
        except OSError:
            pass
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return None, _PRINT_NOTE


# =============================================================================================
#  Dispatch + CLI (stdin JSON -> stdout octets/texte). Sert la délégation DOCX depuis la console Rust.
# =============================================================================================

def render(data, fmt):
    """Rend `data` dans `fmt` ∈ {html,pdf,docx,csv,json}. Renvoie `(content, content_type, note)` où
    `content` est `str` (html/csv/json) ou `bytes` (pdf/docx), `note` non-vide en cas de dégradation."""
    fmt = (fmt or "html").lower()
    norm = normalize(data)
    if fmt == "json":
        return build_json(norm), "application/json; charset=utf-8", ""
    if fmt == "csv":
        return build_csv(norm), "text/csv; charset=utf-8", ""
    if fmt == "html":
        return build_html(norm), "text/html; charset=utf-8", ""
    if fmt == "docx":
        return (build_docx(norm),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "")
    if fmt == "pdf":
        html = build_html(norm)
        pdf, note = build_pdf(html)
        if pdf is not None:
            return pdf, "application/pdf", ""
        return html, "text/html; charset=utf-8", note  # dégradé : HTML imprimable + note
    raise ValueError(f"format inconnu '{fmt}' (html|pdf|docx|csv|json)")


def _main(argv=None):
    """CLI : `python -m forge.report_engagement --format docx [--stdin] [--in F] [--out F]`.
    Lit le dict JSON du rapport (stdin par défaut) et écrit le rendu (stdout par défaut). C'est ce
    point d'entrée que la console Rust invoque pour la délégation DOCX (JSON via stdin -> octets stdout)."""
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Rapport d'engagement agrégé (livrable client).")
    ap.add_argument("--format", default="html", choices=["html", "pdf", "docx", "csv", "json"])
    ap.add_argument("--stdin", action="store_true", help="lire le JSON du rapport sur stdin (défaut)")
    ap.add_argument("--in", dest="infile", help="fichier JSON d'entrée (au lieu de stdin)")
    ap.add_argument("--out", dest="outfile", help="fichier de sortie (au lieu de stdout)")
    args = ap.parse_args(argv)
    raw = open(args.infile, "r", encoding="utf-8").read() if args.infile else sys.stdin.read()
    data = json.loads(raw or "{}")
    content, _ctype, note = render(data, args.format)
    if note:
        sys.stderr.write(note + "\n")
    payload = content.encode("utf-8") if isinstance(content, str) else content
    if args.outfile:
        with open(args.outfile, "wb") as fh:
            fh.write(payload)
    else:
        out = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
        out.write(payload)
        out.flush()
    # code de sortie 3 = dégradation PDF (HTML renvoyé au lieu du PDF) — l'appelant peut le détecter.
    return 3 if (args.format == "pdf" and note) else 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
