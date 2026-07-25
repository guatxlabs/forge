import { api } from '../../core/api.js';
import { $, esc, fmtTs } from '../../core/dom.js';
import { guardList, infoModal, toast } from '../../core/ui.js';
import { RUNSTAT_BADGE } from './live.js';
import { fetchRunOutcome, renderOutcomeTable, renderRunFindings, runCountTilesHtml } from './run-result.js';
import { openRunReport, openRunReportHtml } from './reports.js';

// liste des runs (récents d'abord) — clic = détail.
export let LC_RUNS = [];
export async function loadRuns() {
  const host = $('#lc-runresult'); if (!host) return;
  const st = $('#lc-runstatus') && $('#lc-runstatus').value;
  let rows = [];
  try { rows = await api('/runs?limit=100' + (st ? '&status=' + encodeURIComponent(st) : '')); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  LC_RUNS = Array.isArray(rows) ? rows : [];
  if ($('#lc-runcount')) $('#lc-runcount').textContent = LC_RUNS.length + ' runs';
  if (guardList(host, LC_RUNS, 'aucun run')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = `<thead><tr><th>#</th><th>Statut</th><th>Campagne</th><th>Mode</th><th>FIRE/DRY/VETO</th><th>Err</th><th>Cibles</th><th>Date</th></tr></thead>`;
  const tb = document.createElement('tbody');
  LC_RUNS.forEach((x, i) => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour le détail du run';
    const cls = RUNSTAT_BADGE[x.status] || 'mut';
    const ntgt = Array.isArray(x.targets) ? x.targets.length : 0;
    tr.innerHTML = `<td class="numcol">${Number(i + 1)}</td><td><span class="badge ${cls}">${esc(x.status)}</span></td><td>${esc(x.campaign)}</td>`
      + `<td class="mut">${esc(x.mode)}</td><td class="mono">${Number(x.fired || 0)}/${Number(x.dry_run || 0)}/${Number(x.vetoed || 0)}</td>`
      + `<td class="mut">${Number(x.errors || 0)}</td><td class="mut">${ntgt}</td><td class="mut">${esc(fmtTs(x.ts))}</td>`;
    tr.onclick = () => openRun(x.run_id);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}

// détail d'un run (status, counts, coverage_gaps, skipped_budget, log_tail).
export async function openRun(runId) {
  let d, logs;
  try { d = await api('/runs/' + encodeURIComponent(runId)); }
  catch (e) { toast('Détail run : ' + e.message, 'bad'); return; }
  try { logs = await api('/runs/' + encodeURIComponent(runId) + '/logs?limit=200'); } catch (e) { logs = { lines: [] }; }
  // ISSUE PAR MODULE + FINDINGS (#4/#5) : dérivés des lignes roe_decision/findings du run. Best-effort
  // (arrays vides si indisponibles) — l'affichage dégrade proprement sur la vue compteurs run_job.
  let ro = { roe: [], findings: [], outcome: null };
  try { ro = await fetchRunOutcome(runId); } catch (e) { /* dégradé : pas d'issue détaillée */ }
  infoModal('Run ' + (d.campaign || '') + ' — ' + runId, body => {
    const meta = document.createElement('div'); meta.className = 'findmeta';
    const cls = RUNSTAT_BADGE[d.status] || 'mut';
    meta.innerHTML = `<span class="badge ${cls}">${esc(d.status)}</span> <span class="badge mut">${esc(d.mode)}</span>`
      + (d.exit_code != null ? ` <span class="badge mut">exit ${esc(d.exit_code)}</span>` : '')
      + ` <span class="badge mut">par ${esc(d.started_by || '-')}</span>`;
    // bouton « Rapport » : GET /api/runs/:id/report -> markdown (modale read-only).
    const rep = document.createElement('button'); rep.type = 'button'; rep.className = 'k-theme'; rep.style.marginLeft = '8px';
    rep.textContent = 'Rapport'; rep.title = 'Voir le rapport markdown de ce run (synthèse + findings + transparence ROE)';
    rep.onclick = () => openRunReport(runId);
    meta.appendChild(rep);
    // bouton « Rapport HTML » : livrable client brandé (thème Aurora, page de garde, CSS print).
    const repHtml = document.createElement('button'); repHtml.type = 'button'; repHtml.className = 'k-theme'; repHtml.style.marginLeft = '8px';
    repHtml.textContent = 'Rapport HTML'; repHtml.title = 'Ouvrir le rapport client brandé (HTML imprimable, résumé exécutif, CWE/CVSS, chaîne de custody)';
    repHtml.onclick = () => openRunReportHtml(runId, false);
    meta.appendChild(repHtml);
    // bouton « Imprimer / PDF » : ouvre le HTML brandé et lance l'impression (Enregistrer en PDF).
    const repPdf = document.createElement('button'); repPdf.type = 'button'; repPdf.className = 'k-theme'; repPdf.style.marginLeft = '8px';
    repPdf.textContent = 'Imprimer / PDF'; repPdf.title = 'Ouvre le rapport brandé et lance l\'impression (« Enregistrer au format PDF »)';
    repPdf.onclick = () => openRunReportHtml(runId, true);
    meta.appendChild(repPdf);
    body.appendChild(meta);
    const counts = document.createElement('div'); counts.className = 'roecounters'; counts.style.marginTop = '12px';
    // avec les lignes roe (ro.outcome) : SKIP/ignoré et ERREURS séparés ; sinon repli run_job (agrégé).
    counts.innerHTML = runCountTilesHtml(d, ro.outcome);
    body.appendChild(counts);
    const kv = document.createElement('dl'); kv.className = 'kvdetail';
    const targets = Array.isArray(d.targets) ? d.targets.join(', ') : '';
    const modules = Array.isArray(d.modules) ? d.modules.join(', ') : '';
    const gaps = d.coverage_gaps && typeof d.coverage_gaps === 'object' ? Object.keys(d.coverage_gaps) : [];
    const skipped = Array.isArray(d.skipped_budget) ? d.skipped_budget : [];
    [['Campagne', d.campaign], ['Cibles', targets], ['Modules', modules || '(planner)'], ['Raison', d.reason],
     ['Lacunes couverture', gaps.length ? gaps.join(', ') : '-'], ['Différé (budget)', skipped.length ? skipped.join(', ') : '-'],
     ['Démarré', fmtTs(d.started || d.ts)], ['Terminé', d.finished ? fmtTs(d.finished) : '-']].forEach(([k, v]) => {
      const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = (v == null || v === '') ? '-' : String(v); kv.append(dt, dd);
    });
    body.appendChild(kv);
    // FINDINGS de ce run (ou état vide explicite) + ISSUE PAR MODULE (kind/cible/verdict/raison).
    body.appendChild(renderRunFindings(ro.findings, ro.outcome, d.status));
    body.appendChild(renderOutcomeTable(ro.roe));
    // log_tail
    const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = 'Log (extrait)';
    const pre = document.createElement('pre'); pre.className = 'mailtext';
    const lines = (logs.lines || []).map(l => (l.stream === 'stderr' ? '[err] ' : l.stream === 'system' ? '[sys] ' : '') + l.line);
    pre.textContent = lines.length ? lines.join('\n') : '(aucune ligne)';
    body.append(h, pre);
  });
}
