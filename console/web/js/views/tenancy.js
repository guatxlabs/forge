import { loginError } from './admin/users.js';
import { adminApi, api } from '../core/api.js';
import { $, esc, fmtTs } from '../core/dom.js';
import { reloadCurrentView, renderEngagementSelector } from './engagements.js';
import { loadStatuses } from './overview.js';
import { ENGAGEMENTS, setActiveEngagement } from '../core/state.js';
import { confirmModal, guardList, modal, toast } from '../core/ui.js';

export let TENANCY = { enabled: false };
export const TENANT_ROLES = [
  { value: 'tenant_admin', label: 'tenant_admin — administre le tenant' },
  { value: 'tenant_operator', label: 'tenant_operator — opère' },
  { value: 'tenant_viewer', label: 'tenant_viewer — lecture seule' },
];
export function tenancyOn() { return !!(TENANCY && TENANCY.enabled); }
export function tenancyAdmin() { return !!(tenancyOn() && TENANCY.is_platform_admin); }

// Tenant actif (persisté client, comme l'engagement). Null tant qu'aucun n'est choisi.
export function activeTenant() { const v = localStorage.getItem('forge_tenant'); return v == null || v === '' ? null : Number(v); }
export function setActiveTenant(id) { if (id == null) localStorage.removeItem('forge_tenant'); else localStorage.setItem('forge_tenant', String(id)); }

// Engagements VISIBLES compte tenu du tenant actif. Community/flag OFF => tous (byte-identique). Sinon, si
// un tenant est actif, on ne montre QUE ses engagements (le serveur a DÉJÀ filtré /api/engagements aux
// tenants accordés — ce filtre client est la 2e moitié de la hiérarchie tenant → engagement).
export function visibleEngagements() {
  if (!tenancyOn()) return ENGAGEMENTS;
  const t = activeTenant();
  if (t == null) return ENGAGEMENTS;
  return ENGAGEMENTS.filter(e => e.tenant_id === t);
}

// Choisit un tenant actif VALIDE : le persisté s'il est encore accessible, sinon le 1er accessible.
export function pickActiveTenant() {
  const list = (TENANCY && Array.isArray(TENANCY.tenants)) ? TENANCY.tenants : [];
  const cur = activeTenant();
  if (cur != null && list.some(t => t.id === cur)) return cur;
  const id = list.length ? list[0].id : null;
  setActiveTenant(id);
  return id;
}

// Peuple le sélecteur de tenant (header) + affiche/masque la barre selon le flag et l'accès.
export function renderTenantSelector() {
  const bar = $('#tenant-bar');
  if (!bar) return;
  const list = (TENANCY && Array.isArray(TENANCY.tenants)) ? TENANCY.tenants : [];
  if (!tenancyOn() || !list.length) { bar.hidden = true; return; }
  bar.hidden = false;
  const sel = $('#tenant');
  if (!sel) return;
  sel.replaceChildren();
  list.forEach(t => {
    const o = document.createElement('option');
    o.value = String(t.id);
    o.textContent = t.name + (t.status === 'archived' ? ' [archivé]' : '');
    sel.appendChild(o);
  });
  const act = pickActiveTenant();
  if (act != null) sel.value = String(act);
  const n = list.length;
  bar.title = 'Tenant actif — ' + n + ' tenant' + (n > 1 ? 's' : '') + ' accessible' + (n > 1 ? 's' : '') + (TENANCY.is_superadmin ? ' (super-admin : tous)' : '');
}

// Bascule de tenant actif : réinitialise l'engagement (les engagements d'un autre tenant ne sont pas dans
// le nouveau pool), re-rend les deux sélecteurs, recharge la vue courante + les statuts.
export function switchTenant(id) {
  setActiveTenant(id);
  setActiveEngagement(null); // laisse pickActiveEngagement choisir un défaut DANS le nouveau tenant
  renderTenantSelector();
  renderEngagementSelector();
  reloadCurrentView();
  if (typeof loadStatuses === 'function') { try { loadStatuses(); } catch (e) {} }
  const t = (TENANCY.tenants || []).find(x => x.id === id);
  if (t) toast('Tenant actif : ' + t.name, 'ok');
}

// Charge le contexte de tenancy (GET /api/tenancy) et applique l'UI. Best-effort : tout échec retombe sur
// community (aucune surface tenant). Appelé au boot AVANT le sélecteur d'engagement (pour que le filtre
// tenant porte dès le 1er rendu).
export async function loadTenancyContext() {
  try {
    const r = await fetch('/api/tenancy', { headers: { Accept: 'application/json' } });
    TENANCY = r.ok ? (await r.json().catch(() => ({ enabled: false }))) : { enabled: false };
  } catch (e) { TENANCY = { enabled: false }; }
  if (!TENANCY || typeof TENANCY !== 'object') TENANCY = { enabled: false };
  applyTenancy();
}

// Applique l'état de tenancy : sélecteur header + lien nav #tenants (platform-admin) + garde de route.
export function applyTenancy() {
  renderTenantSelector();
  const link = $('#nav-tenants');
  if (link) link.hidden = !tenancyAdmin();
  if (!tenancyAdmin() && location.hash.slice(1) === 'tenants') location.hash = 'overview';
}

// --- Vue #tenants (platform-admin) : liste + CRUD + gestion des grants ---------------------------
// Réutilise adminApi (prefixe /api, lève sur !ok avec le `why` serveur contrôlé -> anti-XSS).
export async function loadTenants() {
  const host = $('#tenants-list'); if (!host) return;
  if (!tenancyAdmin()) { host.innerHTML = '<div class="muted">réservé au platform-admin (multi-tenancy enterprise)</div>'; if ($('#tenants-count')) $('#tenants-count').textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/tenants'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const tenants = (data && data.tenants) || [];
  if ($('#tenants-count')) $('#tenants-count').textContent = tenants.length + ' tenant' + (tenants.length > 1 ? 's' : '');
  if (guardList(host, tenants, 'aucun tenant')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>#</th><th>Nom</th><th>État</th><th>Engagements</th><th>Grants</th><th>Créé</th><th>Actions</th></tr></thead>';
  const tb = document.createElement('tbody');
  tenants.forEach(t => {
    const tr = document.createElement('tr');
    const state = t.status === 'archived' ? '<span class="badge bad">archivé</span>' : '<span class="badge ok">actif</span>';
    tr.innerHTML =
      `<td class="mut">${Number(t.id)}</td>` +
      `<td class="mono">${esc(t.name)}</td>` +
      `<td>${state}</td>` +
      `<td class="mut">${(t.counts && t.counts.engagements) || 0}</td>` +
      `<td class="mut">${(t.counts && t.counts.grants) || 0}</td>` +
      `<td class="mut">${esc(fmtTs(t.created))}</td>`;
    const act = document.createElement('td'); act.className = 'admin-act';
    const mk = (label, title, fn, danger) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'k-theme' + (danger ? ' danger' : ''); b.textContent = label; b.title = title; b.onclick = fn; return b; };
    act.appendChild(mk('Renommer', 'Renommer le tenant', () => tenantRename(t)));
    const archiving = t.status !== 'archived';
    act.appendChild(mk(archiving ? 'Archiver' : 'Réactiver', archiving ? 'Archiver le tenant (dernier actif protégé)' : 'Réactiver le tenant', () => tenantToggleArchive(t), archiving));
    act.appendChild(mk('Grants', 'Gérer les accès (grants) des utilisateurs à ce tenant', (ev) => tenantToggleGrants(t, tr, ev)));
    tr.appendChild(act);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}

export async function tenantCreate() {
  const r = await modal({
    title: 'Nouveau tenant', okText: 'Créer',
    message: 'Un espace multi-client ISOLÉ (ses engagements, findings, runs, ledger). Vous en devenez automatiquement tenant_admin.',
    fields: [{ name: 'name', label: 'Nom', required: true, placeholder: 'Acme Corp', hint: '1 à 80 caractères, sans tiret initial.' }],
    validate: v => (String(v.name || '').trim() ? null : 'Nom requis.'),
  });
  if (!r) return;
  try {
    await adminApi('/tenants', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ name: String(r.name).trim() }) });
    toast('Tenant « ' + String(r.name).trim() + ' » créé (ledgerisé).', 'ok');
    await loadTenants();
    await loadTenancyContext();
  } catch (e) { toast('Création refusée : ' + e.message, 'bad'); }
}

export async function tenantRename(t) {
  const r = await modal({
    title: 'Renommer — ' + t.name, okText: 'Enregistrer',
    fields: [{ name: 'name', label: 'Nom', value: t.name, required: true }],
    validate: v => (String(v.name || '').trim() ? null : 'Nom requis.'),
  });
  if (!r || String(r.name).trim() === t.name) return;
  try {
    await adminApi('/tenants/' + encodeURIComponent(t.id), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ name: String(r.name).trim() }) });
    toast('Tenant renommé.', 'ok');
    await loadTenants(); await loadTenancyContext();
  } catch (e) { toast('Renommage refusé : ' + e.message, 'bad'); }
}

export async function tenantToggleArchive(t) {
  const archiving = t.status !== 'archived';
  const ok = await confirmModal(
    (archiving ? 'Archiver' : 'Réactiver') + ' le tenant « ' + t.name + ' » ?' + (archiving ? ' (le dernier tenant actif ne peut être archivé)' : ''),
    { title: archiving ? 'Archiver le tenant' : 'Réactiver le tenant', okText: archiving ? 'Archiver' : 'Réactiver', danger: archiving });
  if (!ok) return;
  try {
    await adminApi('/tenants/' + encodeURIComponent(t.id), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ status: archiving ? 'archived' : 'active' }) });
    toast('Tenant ' + (archiving ? 'archivé' : 'réactivé') + '.', 'ok');
    await loadTenants(); await loadTenancyContext();
  } catch (e) { toast('Refusé : ' + e.message, 'bad'); }
}

// Panneau de grants INLINE sous la ligne du tenant (toggle). DOM natif (boutons réels), pas de modal-html.
export async function tenantToggleGrants(t, tr) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('tn-grants-row')) { existing.remove(); return; }
  // referme un autre panneau éventuellement ouvert.
  document.querySelectorAll('.tn-grants-row').forEach(el => el.remove());
  const gr = document.createElement('tr'); gr.className = 'tn-grants-row';
  const td = document.createElement('td'); td.colSpan = 7;
  td.innerHTML = '<div class="muted">chargement des grants…</div>';
  gr.appendChild(td); tr.after(gr);
  try {
    const data = await adminApi('/tenants/' + encodeURIComponent(t.id) + '/grants');
    renderGrantsPanel(t, td, (data && data.grants) || []);
  } catch (e) { td.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; }
}

export function renderGrantsPanel(t, td, grants) {
  td.replaceChildren();
  const wrap = document.createElement('div'); wrap.className = 'tn-grants';
  const head = document.createElement('div'); head.className = 'tn-grants-head';
  const title = document.createElement('b'); title.textContent = 'Grants — ' + t.name; head.appendChild(title);
  const add = document.createElement('button'); add.type = 'button'; add.className = 'k-theme'; add.textContent = '+ Grant';
  add.title = "Accorder l'accès d'un utilisateur à ce tenant"; add.onclick = () => tenantGrantAdd(t, td);
  head.appendChild(add); wrap.appendChild(head);
  if (!grants.length) { const m = document.createElement('div'); m.className = 'muted'; m.textContent = 'aucun grant'; wrap.appendChild(m); }
  else {
    const tbl = document.createElement('table'); tbl.className = 'qtable';
    tbl.innerHTML = '<thead><tr><th>Login</th><th>Rôle</th><th>Créé</th><th></th></tr></thead>';
    const tb = document.createElement('tbody');
    grants.forEach(g => {
      const r = document.createElement('tr');
      r.innerHTML = `<td class="mono">${esc(g.login)}</td><td><span class="badge mut">${esc(g.role)}</span></td><td class="mut">${esc(fmtTs(g.created))}</td>`;
      const a = document.createElement('td');
      const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'k-theme danger'; rm.textContent = 'Retirer';
      rm.title = 'Retirer ce grant (dernier tenant_admin protégé)'; rm.onclick = () => tenantGrantRemove(t, g.login, td);
      a.appendChild(rm); r.appendChild(a); tb.appendChild(r);
    });
    tbl.appendChild(tb); wrap.appendChild(tbl);
  }
  td.appendChild(wrap);
}

export async function tenantGrantAdd(t, td) {
  const r = await modal({
    title: 'Accorder un accès — ' + t.name, okText: 'Accorder',
    fields: [
      { name: 'login', label: 'Login', required: true, placeholder: '[A-Za-z0-9._-]', hint: "Compte EXISTANT à qui accorder l'accès à ce tenant." },
      { name: 'role', label: 'Rôle', type: 'select', options: TENANT_ROLES, value: 'tenant_viewer', hint: 'tenant_admin administre le tenant · tenant_operator opère · tenant_viewer lecture.' },
    ],
    validate: v => loginError(v.login),
  });
  if (!r) return;
  try {
    await adminApi('/tenants/' + encodeURIComponent(t.id) + '/grants', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ login: String(r.login).trim(), role: r.role }) });
    toast('Accès accordé à « ' + String(r.login).trim() + ' ».', 'ok');
    const data = await adminApi('/tenants/' + encodeURIComponent(t.id) + '/grants');
    renderGrantsPanel(t, td, (data && data.grants) || []);
    loadTenancyContext();
  } catch (e) { toast('Grant refusé : ' + e.message, 'bad'); }
}

export async function tenantGrantRemove(t, login, td) {
  const ok = await confirmModal("Retirer l'accès de « " + login + ' » au tenant « ' + t.name + ' » ?', { title: 'Retirer le grant', okText: 'Retirer', danger: true });
  if (!ok) return;
  try {
    await adminApi('/tenants/' + encodeURIComponent(t.id) + '/grants/' + encodeURIComponent(login), { method: 'DELETE', headers: { Accept: 'application/json' } });
    toast('Grant retiré.', 'ok');
    const data = await adminApi('/tenants/' + encodeURIComponent(t.id) + '/grants');
    renderGrantsPanel(t, td, (data && data.grants) || []);
    loadTenancyContext();
  } catch (e) { toast('Retrait refusé : ' + e.message, 'bad'); }
}

if ($('#tenant')) $('#tenant').addEventListener('change', ev => { const v = parseInt(ev.target.value, 10); if (Number.isInteger(v)) switchTenant(v); });
if ($('#tenants-reload')) $('#tenants-reload').addEventListener('click', loadTenants);
if ($('#tenants-new')) $('#tenants-new').addEventListener('click', tenantCreate);

