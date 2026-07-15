import { api, withCampaign } from '../core/api.js';
import { $, LOC, esc } from '../core/dom.js';
import { barEl, runQ } from './explore.js';

export async function loadOverview() {
  // résumé boucle purple : compteurs findings + run-records
  const sumHost = $('#ov-summary .body');
  try {
    const f = await api(withCampaign('/findings?limit=1'));
    const rr = await api(withCampaign('/runrecords?limit=1'));
    const rrFired = await api(withCampaign('/runrecords?fired=1&limit=1'));
    const cov = await api(withCampaign('/coverage'));
    const tech = Array.isArray(cov) ? cov.length : 0;
    if (sumHost) sumHost.innerHTML =
      `<div class="kv"><span>Findings</span><b>${f.total != null ? f.total : '?'}</b></div>`
      + `<div class="kv"><span>Run-records (lus)</span><b>${Array.isArray(rr) ? rr.length + (rr.length >= 1 ? '+' : '') : '?'}</b></div>`
      + `<div class="kv"><span>Techniques couvertes</span><b>${tech}</b></div>`;
    $('#status').textContent = 'connecté';
    $('#updated').textContent = new Date().toLocaleTimeString(LOC);
    const p = $('#posture');
    if (p) { p.textContent = (f.total > 0) ? `${f.total} finding(s)` : 'aucun finding'; p.className = 'posture ' + (f.total > 0 ? 'bad' : 'ok'); }
  } catch (e) {
    if (sumHost) sumHost.innerHTML = '<div class="bad">hors-ligne : ' + esc(e.message) + '</div>';
    $('#status').textContent = 'hors-ligne (' + e.message + ')';
  }
  // findings par sévérité (via soql stats)
  const sevHost = $('#ov-sev .body');
  try {
    const j = await runQ('search | stats count by severity | sort -count', true);
    if (sevHost) {
      const rows = j.rows || [];
      if (!rows.length) sevHost.innerHTML = '<div class="muted">aucun finding</div>';
      else sevHost.replaceChildren(barEl(j.columns, rows, ''));
    }
  } catch (e) { if (sevHost) sevHost.innerHTML = '<div class="muted">—</div>'; }
}

// =====================================================================================
//  Statuts findings : peuplent le filtre depuis les findings vus (tested/vulnerable/...)
// =====================================================================================
export async function loadStatuses() {
  const sel = $('#f-status'); if (!sel) return;
  try {
    const j = await runQ('search | stats count by status', true);
    const rows = j.rows || [];
    const cur = sel.value;
    sel.replaceChildren();
    const o0 = document.createElement('option'); o0.value = ''; o0.textContent = 'Tous statuts'; sel.appendChild(o0);
    rows.map(r => r[0]).filter(Boolean).sort().forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; sel.appendChild(o); });
    if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
  } catch (e) { /* le moteur peut ne pas exposer status en stats ; on garde le sélecteur tel quel */ }
}

// =====================================================================================
//  LANCEMENT (capacité PRIVILÉGIÉE, gouvernée + auditée) — endpoints consommés :
//    POST /api/run                  (écriture ; en-tête X-Forge-Operator requis)
//    GET  /api/runs?status=         (liste, viewer)        GET /api/runs/:id (détail, viewer)
//    POST /api/runs/:id/cancel      (écriture ; X-Forge-Operator)
//    GET  /api/runs/:id/events      (SSE log+status)       GET /api/runs/:id/logs?after= (fallback polling)
//    GET  /api/modules              (catalogue — filtre web_allowed côté UI)
//  Le secret opérateur N'EST stocké qu'en mémoire de session (variable JS) — jamais localStorage,
//  jamais en clair persistant. Il est envoyé via l'en-tête X-Forge-Operator sur run/cancel uniquement.
// =====================================================================================
