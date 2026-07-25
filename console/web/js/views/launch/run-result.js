import { api } from '../../core/api.js';
import { $, esc, raw, SEV_BADGE } from '../../core/dom.js';
import { TERMINAL_RUN } from './live.js';

// =====================================================================================
//  ISSUE PAR MODULE + FINDINGS PAR RUN (visibilité — #4/#5)
//  Le compteur `errors` de run_job AGRÈGE SKIP (module indisponible/désactivé, technique retirée) ET
//  ERROR (échec réel) — cf. Engine.coverage(). On RE-SÉPARE ces deux à l'affichage en dérivant depuis
//  les lignes roe_decision (GET /api/roe?run_id=...), SANS changer la sémantique serveur (pur display).
// =====================================================================================
// verdict d'action -> classe de badge. ERROR (échec) distinct de SKIP (indisponible/gouvernance).
export const RUN_VERDICT_BADGE = { FIRE: 'v-FIRE', DRY_RUN: 'v-DRY_RUN', VETO: 'v-VETO', SKIP: 'mut', ERROR: 'destr' };

// Dérive les compteurs d'issue depuis les lignes roe_decision d'un run (SKIP compté À PART de ERROR).
export function deriveOutcome(roeRows) {
  const o = { skipped: 0, errors: 0, fired: 0, dry_run: 0, vetoed: 0 };
  (Array.isArray(roeRows) ? roeRows : []).forEach(r => {
    const v = String(r.verdict || '').toUpperCase();
    if (v === 'SKIP') o.skipped++;
    else if (v === 'ERROR') o.errors++;
    else if (v === 'FIRE') o.fired++;
    else if (v === 'DRY_RUN') o.dry_run++;
    else if (v === 'VETO') o.vetoed++;
  });
  return o;
}

// HTML des tuiles de compteurs. Avec `outcome` (dérivé roe) : SKIP et ERREURS affichés SÉPARÉMENT ;
// sinon (live avant l'ingest des lignes roe) repli sur le compteur agrégé run_job (errors = SKIP+ERROR).
export function runCountTilesHtml(d, outcome) {
  const tiles = [['FIRE', (outcome ? outcome.fired : d.fired), 'v-FIRE'],
                 ['DRY_RUN', (outcome ? outcome.dry_run : d.dry_run), 'v-DRY_RUN'],
                 ['VETO', (outcome ? outcome.vetoed : d.vetoed), 'v-VETO']];
  if (outcome) tiles.push(['SKIP/ignoré', outcome.skipped, 'skipped'], ['ERREURS', outcome.errors, 'errors']);
  else tiles.push(['ERREURS', d.errors, 'errors']);
  return tiles.map(([lab, n, cls]) => `<div class="roecount ${cls}"><span class="rcn">${Number(n || 0)}</span><span class="rcl">${esc(lab)}</span></div>`).join('');
}

// Table d'ISSUE PAR MODULE (anti-masquage) : une ligne par action évaluée — kind / cible / verdict /
// raison. Rend VISIBLES les SKIP (outil absent, connecteur/technique désactivés) et VETO que les tuiles
// agrègent. Retourne un fragment DOM. Source : lignes roe_decision du run.
export function renderOutcomeTable(roeRows) {
  const rows = Array.isArray(roeRows) ? roeRows : [];
  const wrap = document.createElement('div');
  const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = 'Issue par module (' + rows.length + ')';
  wrap.appendChild(h);
  if (!rows.length) {
    const e = document.createElement('div'); e.className = 'muted'; e.textContent = '(aucune décision enregistrée pour ce run)';
    wrap.appendChild(e); return wrap;
  }
  const scroller = document.createElement('div'); scroller.className = 'lc-tablescroll';
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Type</th><th>Cible</th><th>Verdict</th><th>Raison</th></tr></thead>';
  const tb = document.createElement('tbody');
  rows.forEach(r => {
    const v = String(r.verdict || '').toUpperCase();
    const cls = RUN_VERDICT_BADGE[v] || 'mut';
    const reason = Array.isArray(r.reasons) ? r.reasons.join(' ; ') : (r.reasons == null ? '' : String(r.reasons));
    const tr = document.createElement('tr');
    const kTd = document.createElement('td'); kTd.innerHTML = r.kind ? `<code>${esc(r.kind)}</code>` : '<span class="muted">-</span>';
    const tTd = document.createElement('td'); tTd.textContent = r.target || '-';
    const vTd = document.createElement('td'); vTd.innerHTML = `<span class="badge ${cls}">${esc(v || '?')}</span>`;
    const rTd = document.createElement('td'); rTd.className = 'lc-oreason'; rTd.textContent = reason || '-'; rTd.title = reason || '';
    tr.append(kTd, tTd, vTd, rTd);
    tb.appendChild(tr);
  });
  table.appendChild(tb); scroller.appendChild(table); wrap.appendChild(scroller);
  return wrap;
}

// Liste des FINDINGS de ce run (titre / sévérité / cible / outil) + ÉTAT VIDE explicite récapitulant
// l'issue (0 finding · N fired · M ignorés · K erreurs). Retourne un fragment DOM. Source :
// GET /api/findings?run_id=... (déjà borné à l'engagement actif côté serveur).
export function renderRunFindings(findings, outcome, status) {
  const rows = Array.isArray(findings) ? findings : [];
  const wrap = document.createElement('div');
  const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = 'Findings de ce run (' + rows.length + ')';
  wrap.appendChild(h);
  if (!rows.length) {
    const o = outcome || {};
    const term = TERMINAL_RUN.has(status) ? 'Run terminé' : 'Run en cours';
    const e = document.createElement('div'); e.className = 'lc-emptyfind';
    e.textContent = `${term} — 0 finding · ${Number(o.fired || 0)} fired · ${Number(o.skipped || 0)} ignorés · ${Number(o.errors || 0)} erreurs`;
    wrap.appendChild(e); return wrap;
  }
  const scroller = document.createElement('div'); scroller.className = 'lc-tablescroll';
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Titre</th><th>Sévérité</th><th>Cible</th><th>Outil</th></tr></thead>';
  const tb = document.createElement('tbody');
  rows.forEach(f => {
    const tr = document.createElement('tr');
    const tiTd = document.createElement('td'); tiTd.textContent = f.title || '(sans titre)'; tiTd.title = f.title || '';
    const sTd = document.createElement('td'); sTd.innerHTML = raw(SEV_BADGE(f.severity));
    const tgTd = document.createElement('td'); tgTd.textContent = f.target || '-';
    const toTd = document.createElement('td'); toTd.className = 'mut'; toTd.textContent = f.tool || '-';
    tr.append(tiTd, sTd, tgTd, toTd);
    tb.appendChild(tr);
  });
  table.appendChild(tb); scroller.appendChild(table); wrap.appendChild(scroller);
  return wrap;
}

// Charge les lignes roe_decision + findings d'un run (parallèle, best-effort). Retourne
// { roe:[], findings:[], outcome:{} } — arrays vides si un fetch échoue (l'affichage dégrade proprement).
export async function fetchRunOutcome(runId) {
  const [roe, fnd] = await Promise.all([
    api('/roe?limit=2000&run_id=' + encodeURIComponent(runId)).catch(() => []),
    api('/findings?limit=200&run_id=' + encodeURIComponent(runId)).catch(() => ({ findings: [] })),
  ]);
  const roeRows = Array.isArray(roe) ? roe : [];
  const findings = (fnd && Array.isArray(fnd.findings)) ? fnd.findings : [];
  return { roe: roeRows, findings, outcome: deriveOutcome(roeRows) };
}

// Rend le PANNEAU RÉSULTAT du live (à la fin d'un run) : tuiles séparées SKIP/ERREURS + liste de
// findings (ou état vide). Best-effort : ne casse jamais le flux live. `#lc-result` est le conteneur.
export async function lcRenderLiveResult(runId, status) {
  const host = $('#lc-result'); if (!host) return;
  let data;
  try { data = await fetchRunOutcome(runId); }
  catch (e) { return; }
  host.hidden = false;
  host.replaceChildren();
  const counts = document.createElement('div'); counts.className = 'roecounters'; counts.style.marginTop = '4px';
  const det = { fired: data.outcome.fired, dry_run: data.outcome.dry_run, vetoed: data.outcome.vetoed, errors: data.outcome.errors };
  counts.innerHTML = runCountTilesHtml(det, data.outcome);
  host.appendChild(counts);
  host.appendChild(renderRunFindings(data.findings, data.outcome, status));
  host.appendChild(renderOutcomeTable(data.roe));
}
