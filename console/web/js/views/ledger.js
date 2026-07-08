import { api } from '../core/api.js';
import { $, esc, fmtTs, ic } from '../core/dom.js';
import { guardList, infoModal } from '../core/ui.js';

export async function loadLedger() {
  const host = $('#lg-result'); if (!host) return;
  // badge de vérification
  const badge = $('#lg-verify');
  try {
    const vr = await api('/ledger/verify');
    if (badge) {
      const ok = vr.ok;
      badge.className = 'badge ' + (ok ? 'ok' : 'destr');
      badge.innerHTML = `${ic(ok ? 'check' : 'warn')} ${ok ? 'chaîne intègre' : 'chaîne ROMPUE'} (${vr.entries} entrées) ${ic('lock')} signature non vérifiée`;
      badge.title = `alg=${vr.alg || '?'} · sig_checked=false (la console ne détient pas la clé) · ${vr.broken != null ? 'rompu au seq ' + vr.broken + ' : ' + (vr.why || '') : (vr.why || '')}`;
    }
  } catch (e) { if (badge) { badge.className = 'badge destr'; badge.textContent = 'vérif indisponible'; } }
  let d;
  try { d = await api('/ledger?limit=200'); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  if ($('#lg-path')) $('#lg-path').textContent = d.path || '';
  const entries = d.entries || [];
  if (guardList(host, entries, 'ledger vide ou absent')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = `<thead><tr><th>Seq</th><th>Date</th><th>Type</th><th>Hash</th><th>Alg</th></tr></thead>`;
  const tb = document.createElement('tbody');
  entries.forEach(e => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour voir l\'entrée complète';
    const hash = String(e.hash || ''); const short = hash ? hash.slice(0, 12) + '…' : '-';
    tr.innerHTML = `<td class="numcol">${esc(e.seq)}</td><td class="mut">${esc(fmtTs(e.ts))}</td><td><code>${esc(e.kind)}</code></td><td class="mono mut">${esc(short)}</td><td class="mut">${esc(e.alg)}</td>`;
    tr.onclick = () => infoModal('Ledger seq ' + e.seq, body => {
      const pre = document.createElement('pre'); pre.className = 'mailtext'; pre.textContent = JSON.stringify(e, null, 2); body.appendChild(pre);
    });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}

