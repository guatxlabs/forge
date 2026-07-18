import { api } from '../core/api.js';
import { $, esc, fmtTs } from '../core/dom.js';
import { guardList } from '../core/ui.js';

export async function loadRoe() {
  const host = $('#roe-result'); if (!host) return;
  const qp = new URLSearchParams();
  const camp = $('#campaign') && $('#campaign').value; if (camp) qp.set('campaign', camp);
  const v = $('#roe-verdict') && $('#roe-verdict').value; if (v) qp.set('verdict', v);
  let rows = [];
  try { rows = await api('/roe' + (qp.toString() ? '?' + qp.toString() : '')); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  rows = Array.isArray(rows) ? rows : [];
  if ($('#roe-count')) $('#roe-count').textContent = rows.length + ' décisions';
  // compteurs par verdict
  const counts = { FIRE: 0, DRY_RUN: 0, VETO: 0 };
  rows.forEach(r => { const k = String(r.verdict || '').toUpperCase(); if (counts[k] != null) counts[k]++; });
  const cc = $('#roe-counters');
  if (cc) cc.innerHTML = ['FIRE', 'DRY_RUN', 'VETO'].map(k => `<div class="roecount v-${esc(k)}"><span class="rcn">${Number(counts[k]) || 0}</span><span class="rcl">${esc(k)}</span></div>`).join('');
  if (guardList(host, rows, 'aucune décision ROE')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = `<thead><tr><th>#</th><th>Verdict</th><th>Cible</th><th>Type</th><th>Risque</th><th>Raisons</th><th>Date</th></tr></thead>`;
  const tb = document.createElement('tbody');
  rows.forEach((r, i) => {
    const verdict = String(r.verdict || '').toUpperCase();
    const risk = [r.exploit ? 'exploit' : '', r.destructive ? 'destructif' : ''].filter(Boolean).join(' · ') || '-';
    const reasons = Array.isArray(r.reasons) ? r.reasons.join(' ; ') : (r.reasons == null ? '' : String(r.reasons));
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="numcol">${Number(i + 1)}</td><td><span class="badge v-${esc(verdict)}">${esc(verdict)}</span></td><td>${esc(r.target)}</td><td><code>${esc(r.kind)}</code></td><td class="mut">${esc(risk)}</td><td>${esc(reasons)}</td><td class="mut">${esc(fmtTs(r.ts))}</td>`;
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}
if ($('#roe-verdict')) $('#roe-verdict').addEventListener('change', loadRoe);

