import { api } from '../core/api.js';
import { $, esc, fmtTs } from '../core/dom.js';
import { guardList } from '../core/ui.js';

export let CAMPAIGNS = [];
export async function loadCampaigns() {
  const host = $('#cm-result'); if (!host) return;
  let camps = [];
  try { camps = await api('/campaigns'); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  CAMPAIGNS = Array.isArray(camps) ? camps : [];
  // alimente le sélecteur de campagne header
  const sel = $('#campaign');
  if (sel) {
    const cur = sel.value;
    sel.replaceChildren();
    const o0 = document.createElement('option'); o0.value = ''; o0.textContent = 'Toutes campagnes'; sel.appendChild(o0);
    CAMPAIGNS.forEach(c => { const o = document.createElement('option'); o.value = c.campaign; o.textContent = c.campaign; sel.appendChild(o); });
    if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
  }
  renderCampaigns();
}
export function renderCampaigns() {
  const host = $('#cm-result'); if (!host) return;
  const filt = ($('#cm-filter') && $('#cm-filter').value.trim().toLowerCase()) || '';
  const list = CAMPAIGNS.filter(c => !filt || String(c.campaign).toLowerCase().includes(filt));
  if ($('#cm-count')) $('#cm-count').textContent = CAMPAIGNS.length + ' campagnes';
  if (guardList(host, list, 'aucune campagne')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = `<thead><tr><th>Campagne</th><th>Findings</th><th>Dernier</th></tr></thead>`;
  const tb = document.createElement('tbody');
  list.forEach(c => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour filtrer sur cette campagne';
    tr.innerHTML = `<td>${esc(c.campaign)}</td><td>${c.findings}</td><td class="mut">${esc(fmtTs(c.last_ts))}</td>`;
    tr.onclick = () => { const sel = $('#campaign'); if (sel) { sel.value = c.campaign; sel.dispatchEvent(new Event('change')); } location.hash = 'findings'; };
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}
if ($('#cm-filter')) $('#cm-filter').addEventListener('input', renderCampaigns);

