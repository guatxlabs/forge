import { api } from '../core/api.js';
import { $, esc, ic } from '../core/dom.js';
import { guardList } from '../core/ui.js';

// =====================================================================================
//  SECTIONS Forge : Modules, Findings, Coverage, Campaigns, ROE, Ledger, Overview
// =====================================================================================
export let MODULES = [];
export async function loadModules() {
  const grid = $('#mod-grid'); const cnt = $('#mod-count');
  let mods = [];
  try { mods = await api('/modules'); } catch (e) { if (grid) grid.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  MODULES = Array.isArray(mods) ? mods : [];
  if (cnt) cnt.textContent = MODULES.length + ' modules';
  renderModules();
  // mini-résumé en vue d'ensemble
  const ovm = $('#ov-modules .body');
  if (ovm) {
    const avail = MODULES.filter(m => m.available).length;
    const web = MODULES.filter(m => m.web_allowed).length;
    const expl = MODULES.filter(m => m.exploit).length;
    ovm.innerHTML = MODULES.length
      ? `<div class="kv"><span>Modules</span><b>${MODULES.length}</b></div><div class="kv"><span>Disponibles</span><b class="${avail ? 'ok' : 'mut'}">${avail}</b></div><div class="kv"><span>Autorisés web</span><b>${web}</b></div><div class="kv"><span>Exploit</span><b>${expl}</b></div>`
      : '<div class="muted">aucun module</div>';
  }
}
export function renderModules() {
  const grid = $('#mod-grid'); if (!grid) return;
  const onlyAvail = $('#mod-avail') && $('#mod-avail').checked;
  const list = MODULES.filter(m => !onlyAvail || m.available).sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
  if (guardList(grid, list, 'aucun module' + (onlyAvail ? ' disponible' : ''))) return;
  grid.replaceChildren(...list.map(m => {
    // « effectif » = enabled ET (override ?? sonde) — grise la carte si le connecteur ne tirerait pas.
    const effective = (m.effective_available === undefined) ? m.available : m.effective_available;
    const card = document.createElement('div'); card.className = 'modcard' + (effective ? '' : ' off');
    const badges = [];
    badges.push(`<span class="badge ${m.available ? 'ok' : 'mut'}">${m.available ? 'dispo' : 'indispo'}</span>`);
    if (m.enabled === false) badges.push('<span class="badge bad">désactivé</span>');
    else if (m.available_override === true) badges.push('<span class="badge webyes">forcé dispo</span>');
    else if (m.available_override === false) badges.push('<span class="badge bad">forcé indispo</span>');
    if (m.web_allowed) badges.push('<span class="badge webyes">web</span>');
    if (m.exploit) badges.push('<span class="badge expl">exploit</span>');
    if (m.destructive) badges.push('<span class="badge destr">destructif</span>');
    card.innerHTML = `<div class="modhead"><span class="modkind">${ic('flask')} ${esc(m.kind)}</span><span class="modbadges">${badges.join('')}</span></div>`
      + (m.mitre ? `<div class="modmitre"><code>${esc(m.mitre)}</code></div>` : '')
      + `<div class="moddescr">${esc(m.descr || '(pas de description)')}</div>`;
    return card;
  }));
}
if ($('#mod-avail')) $('#mod-avail').addEventListener('change', renderModules);

// =====================================================================================
//  Techniques & Sélection PAR-SCOPE — catalogue GROUPÉ PAR CATÉGORIE (lecture /api/techniques,
//  DÉRIVÉ du registre) + panneau de sélection (profil + toggles catégorie/technique). La mutation
//  (POST /api/techniques/selection) est operator/admin + ledgerisée. « Au scope retirer des tests
//  automatiques » : le moteur ENFORCE l'ensemble effectif (profil ∪ activations − désactivations) —
//  une technique décochée n'est NI planifiée NI tirée (fail-closed), en plus du scope-guard.
// =====================================================================================

export function setModules(v) { MODULES = v; }
