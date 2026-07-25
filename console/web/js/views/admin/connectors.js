import { adminApi, api } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { guardList, toast } from '../../core/ui.js';
import { loadModules } from '../modules.js';

// =====================================================================================
//  ADMINISTRATION — connecteurs (gouvernance enabled / available_override / web_allowed)
//  Contrepartie ECRITURE de GET /api/modules : POST /api/modules/:kind (check_admin, attribue + ledgerise).
//  Desactiver un connecteur l'empeche REELLEMENT de tirer (scope.json disabled_modules + filtre --modules
//  + refus validate_modules), y compris pour les modules choisis par le planner. Admin-only (le serveur
//  reste l'autorite : les mutations sont 403 sans session admin).
// =====================================================================================
export const OVR_OPTS = [
  { value: '', label: 'auto (sonde host)' },
  { value: 'true', label: 'forcer disponible' },
  { value: 'false', label: 'forcer indisponible' },
];
export async function loadAdminConnectors() {
  const host = $('#admin-connectors-body'); if (!host) return;
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if ($('#admin-conn-count')) $('#admin-conn-count').textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let mods;
  try { mods = await api('/modules'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const list = Array.isArray(mods) ? mods.slice().sort((a, b) => String(a.kind).localeCompare(String(b.kind))) : [];
  if ($('#admin-conn-count')) $('#admin-conn-count').textContent = list.length + ' connecteur' + (list.length > 1 ? 's' : '');
  if (guardList(host, list, 'aucun connecteur')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Connecteur</th><th>Sonde host</th><th>Etat</th><th>Override dispo</th><th>Effectif</th><th>Web</th><th>Actions</th></tr></thead>';
  const tb = document.createElement('tbody');
  list.forEach(m => {
    const tr = document.createElement('tr');
    const enabled = m.enabled !== false; // enabled absent (ancienne API) -> considere actif
    const risk = m.exploit ? ' <span class="badge expl">exploit</span>' : (m.destructive ? ' <span class="badge destr">destructif</span>' : '');
    const probed = m.available ? '<span class="badge ok">dispo</span>' : '<span class="badge mut">absente</span>';
    const state = enabled ? '<span class="badge ok">actif</span>' : '<span class="badge bad">desactive</span>';
    const eff = m.effective_available ? '<span class="badge ok">oui</span>' : '<span class="badge bad">non</span>';
    const web = m.web_allowed ? '<span class="badge webyes">web</span>' : '<span class="badge mut">—</span>';
    // structure des cellules (badges = markup STATIQUE derive de booleens ; texte = esc()). Les deux
    // cellules interactives (override select, actions) sont des placeholders peuples en DOM ci-dessous.
    tr.innerHTML =
      `<td class="mono">${esc(m.kind)}${risk}${m.mitre ? ' <code>' + esc(m.mitre) + '</code>' : ''}</td>` +
      `<td>${probed}</td>` +
      `<td>${state}</td>` +
      `<td class="conn-ovr"></td>` +
      `<td>${eff}</td>` +
      `<td>${web}</td>` +
      `<td class="admin-act"></td>`;
    // override select : auto (null) / forcer disponible (true) / forcer indisponible (false).
    const sel = document.createElement('select'); sel.title = 'available_override : « auto » suit la sonde host ; « forcer » masque ou expose le connecteur independamment du binaire present';
    const cur = (m.available_override === true) ? 'true' : (m.available_override === false ? 'false' : '');
    OVR_OPTS.forEach(o => { const op = document.createElement('option'); op.value = o.value; op.textContent = o.label; if (o.value === cur) op.selected = true; sel.appendChild(op); });
    sel.onchange = () => connectorSet(m.kind, { available_override: sel.value === '' ? null : (sel.value === 'true') });
    tr.querySelector('.conn-ovr').appendChild(sel);
    const act = tr.querySelector('.admin-act');
    const mk = (label, title, fn, danger) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'k-theme' + (danger ? ' danger' : ''); b.textContent = label; b.title = title; b.onclick = fn; return b; };
    act.appendChild(mk(enabled ? 'Desactiver' : 'Activer', enabled ? 'Desactiver le connecteur : SKIP au tir (y compris plan planner)' : 'Reactiver le connecteur', () => connectorSet(m.kind, { enabled: !enabled }), enabled));
    act.appendChild(mk(m.web_allowed ? 'Retirer web' : 'Autoriser web', 'Basculer la lancabilite depuis le web (web_allowed)', () => connectorSet(m.kind, { web_allowed: !m.web_allowed })));
    tb.appendChild(tr);
  });
  table.appendChild(tb); host.replaceChildren(table);
}
// Applique un patch de gouvernance a un connecteur (POST /api/modules/:kind, admin + ledgerise), puis
// recharge la table + la grille Capacites (source /api/modules) pour refleter l'effectif.
export async function connectorSet(kind, patch) {
  try {
    await adminApi('/modules/' + encodeURIComponent(kind), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(patch) });
    toast('Connecteur « ' + kind + ' » mis a jour.', 'ok');
    loadAdminConnectors();
    if (typeof loadModules === 'function') loadModules(); // refleter l'effectif dans la vue Capacites
  } catch (e) { toast('Mise a jour refusee : ' + e.message, 'bad'); }
}
