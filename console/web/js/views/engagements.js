import { adminApi, api, write } from '../core/api.js';
import { $, TLP_BADGE, esc, fmtTs } from '../core/dom.js';

// Options TLP 2.0 (#15) partagées par les modales create/edit d'engagement.
const TLP_OPTS = [
  { value: '', label: '(non classifié)' },
  { value: 'CLEAR', label: 'TLP:CLEAR' },
  { value: 'GREEN', label: 'TLP:GREEN' },
  { value: 'AMBER', label: 'TLP:AMBER' },
  { value: 'AMBER+STRICT', label: 'TLP:AMBER+STRICT' },
  { value: 'RED', label: 'TLP:RED' },
];
import { loadStatuses } from './overview.js';
import { LOADERS, VIEWS_HAS } from '../core/router.js';
import { ENGAGEMENTS, activeEngagement, getEngagements, setActiveEngagement, setEngagements } from '../core/state.js';
import { visibleEngagements, tenancyAdmin, TENANT_ROLES } from './tenancy.js';
import { restartPresence } from '../core/presence.js';
import { confirmModal, guardList, modal, toast } from '../core/ui.js';


// =====================================================================================
//  ENGAGEMENTS — vue de gestion + sélecteur d'engagement actif (header)
// =====================================================================================
// Charge /api/engagements, alimente le sélecteur header (#engagement) + l'indicateur proéminent, et
// rend la vue #engagements (liste + créer/éditer/archiver/supprimer/basculer). L'engagement actif est
// persisté localStorage (activeEngagement) et ajouté à CHAQUE requête (withEngagement) : chaque vue ne
// montre QUE ses données. create/edit = operator ; archive/delete = admin (gate serveur, fail-closed).

export async function fetchEngagements() {
  const d = await api('/engagements');
  setEngagements((d && Array.isArray(d.engagements)) ? d.engagements : []);
  return getEngagements();
}

// Choisit un engagement actif VALIDE : celui persisté s'il existe encore, sinon l'actif le plus récent,
// sinon le 1er. Corrige localStorage si l'id persisté a disparu (engagement supprimé entre-temps).
export function pickActiveEngagement() {
  // Le POOL est restreint au tenant actif quand la multi-tenancy ENTERPRISE est active (hiérarchie tenant
  // → engagement). Community/flag OFF : visibleEngagements() renvoie ENGAGEMENTS (identique, byte-pour-byte).
  const pool = visibleEngagements();
  const cur = activeEngagement();
  if (cur != null && pool.some(e => e.id === cur)) return cur;
  const act = [...pool].reverse().find(e => e.status === 'active') || pool[0];
  const id = act ? act.id : null;
  setActiveEngagement(id);
  return id;
}

// Peuple le sélecteur header + l'indicateur proéminent (nom · mode [· archivé]).
export function renderEngagementSelector() {
  const pool = visibleEngagements();
  const active = pickActiveEngagement();
  const sel = $('#engagement');
  if (sel) {
    sel.replaceChildren();
    if (!pool.length) {
      const o = document.createElement('option'); o.value = ''; o.textContent = '(aucun engagement)'; sel.appendChild(o);
    } else {
      pool.forEach(e => {
        const o = document.createElement('option');
        o.value = String(e.id);
        o.textContent = e.name + ' · ' + e.mode + (e.status === 'archived' ? ' [archivé]' : '');
        sel.appendChild(o);
      });
      if (active != null) sel.value = String(active);
    }
  }
  // L'engagement actif est montré UNE seule fois — par le sélecteur lui-même (l'option sélectionnée = l'actif,
  // « NOM · mode »). La barre porte le détail complet (nom, mode, statut) en tooltip (survol) ; on ne duplique
  // plus l'info dans un libellé séparé (C10 : « NOM · mode » n'apparaissait sinon deux fois).
  const bar = $('#eng-bar');
  const e = ENGAGEMENTS.find(x => x.id === active);
  if (bar) {
    bar.classList.toggle('archived', !!(e && e.status === 'archived'));
    bar.title = e ? ('Engagement actif : ' + e.name + ' (' + e.mode + ', ' + e.status + ')') : 'Aucun engagement';
  }
}

export function reloadCurrentView() {
  const v = location.hash.slice(1) || 'overview';
  const fn = LOADERS[VIEWS_HAS(v) ? v : 'overview']; if (fn) fn();
}

// Recharge la liste d'engagements + le sélecteur, puis (optionnel) recharge la vue courante.
export async function loadEngagementSelector(reloadView) {
  try { await fetchEngagements(); } catch (e) { /* fail-soft : sélecteur vide */ }
  renderEngagementSelector();
  if (reloadView) reloadCurrentView();
}

// bascule d'engagement actif (sélecteur header OU vue) -> persiste + recharge la vue + les statuts.
export function switchEngagement(id) {
  setActiveEngagement(id);
  renderEngagementSelector();
  reloadCurrentView();
  // PRÉSENCE (#9) : re-scoper le flux LIVE sur le nouvel engagement (leave l'ancien, join le nouveau).
  try { restartPresence(); } catch (e) {}
  if (typeof loadStatuses === 'function') { try { loadStatuses(); } catch (e) {} }
  const e = ENGAGEMENTS.find(x => x.id === id);
  if (e) toast('Engagement actif : ' + e.name, 'ok');
}

export const _scopeLines = s => String(s || '').split('\n').map(x => x.trim()).filter(Boolean);

// modale de création (operator) : nom + mode + scope in/out (une entrée par ligne).
export async function engagementCreateModal() {
  const vals = await modal({
    title: 'Nouvel engagement', okText: 'Créer', wide: true,
    message: 'Un nouvel espace de travail ISOLÉ, avec son propre scope (fail-closed) et son propre ledger tamper-evident. Réservé operator.',
    fields: [
      { name: 'name', label: 'Nom', type: 'text', required: true, placeholder: 'Client — Q3 pentest' },
      { name: 'mode', label: 'Mode', type: 'select', value: 'grey', options: [{ value: 'white', label: 'white' }, { value: 'grey', label: 'grey' }, { value: 'black', label: 'black' }] },
      { name: 'classification', label: 'Classification (TLP 2.0)', type: 'select', value: '', options: TLP_OPTS },
      { name: 'in_scope', label: 'In-scope (une entrée par ligne — host / *.wildcard / CIDR)', type: 'textarea', placeholder: 'app.example.com\n*.example.com\n10.0.0.0/8' },
      { name: 'out_scope', label: 'Out-of-scope (optionnel)', type: 'textarea', placeholder: 'admin.example.com' },
    ],
  });
  if (!vals) return;
  const body = {
    name: String(vals.name || '').trim(),
    mode: vals.mode || 'grey',
    classification: vals.classification || '',
    scope_json: { mode: vals.mode || 'grey', in_scope: _scopeLines(vals.in_scope), out_scope: _scopeLines(vals.out_scope) },
  };
  try {
    const r = await write('/api/engagements', { body, auth: 'operator' });
    const j = r.json;
    if (r.status === 403) { toast('Réservé à un compte operator.', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Engagement créé (ledgerisé).', 'ok');
    await fetchEngagements();
    if (j.engagement && j.engagement.id) setActiveEngagement(j.engagement.id);
    renderEngagementSelector();
    reloadCurrentView();
    if (location.hash.slice(1) === 'engagements') loadEngagements();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// modale d'édition (operator) : rename + mode + (optionnel) redéfinir le scope. AFFICHE le scope RÉEL
// courant (in/out + mode effectif servis par /api/engagements) pour que l'opérateur voie/confirme ce qui
// est persisté. Sémantique conservée : une zone scope VIDE = INCHANGÉE ; y saisir des hôtes REMPLACE la
// liste (un hôte par ligne). Le placeholder « fantôme » = le scope actuel (repère visuel, non soumis).
export async function engagementEditModal(e) {
  const curIn = Array.isArray(e.in_scope) ? e.in_scope : [];
  const curOut = Array.isArray(e.out_scope) ? e.out_scope : [];
  const curInTxt = curIn.length ? curIn.join(', ') : '(vide)';
  const curOutTxt = curOut.length ? curOut.join(', ') : '(vide)';
  const vals = await modal({
    title: 'Éditer « ' + e.name + ' »', okText: 'Enregistrer', wide: true,
    message: 'Scope actuel — mode ' + (e.mode || 'grey') + ' · in-scope: ' + curInTxt + ' · out-of-scope: ' + curOutTxt
      + '. Renommer / changer le mode / redéfinir le scope : laisser une zone scope VIDE la laisse INCHANGÉE ; y saisir des hôtes REMPLACE la liste (un hôte par ligne).',
    fields: [
      { name: 'name', label: 'Nom', type: 'text', value: e.name, required: true },
      { name: 'mode', label: 'Mode', type: 'select', value: e.mode, options: [{ value: 'white', label: 'white' }, { value: 'grey', label: 'grey' }, { value: 'black', label: 'black' }] },
      { name: 'classification', label: 'Classification (TLP 2.0)', type: 'select', value: e.classification || '', options: TLP_OPTS },
      { name: 'in_scope', label: 'Redéfinir in-scope (vide = inchangé — un hôte par ligne)', type: 'textarea', placeholder: curIn.length ? curIn.join('\n') : 'app.example.com', hint: 'Actuel : ' + curInTxt },
      { name: 'out_scope', label: 'Redéfinir out-of-scope (vide = inchangé)', type: 'textarea', placeholder: curOut.length ? curOut.join('\n') : 'admin.example.com', hint: 'Actuel : ' + curOutTxt },
    ],
  });
  if (!vals) return;
  const body = { name: String(vals.name || '').trim(), mode: vals.mode || e.mode, classification: vals.classification || '' };
  const inl = _scopeLines(vals.in_scope), outl = _scopeLines(vals.out_scope);
  if (inl.length || outl.length) body.scope_json = { mode: vals.mode || e.mode, in_scope: inl, out_scope: outl };
  await engagementMutate(e.id, body, 'Engagement mis à jour.');
}

// mutation POST /api/engagements/:id (edit/archive/activate/delete). operatorHeaders porte X-Forge-Operator
// ET le bearer de session (admin) : le serveur gate selon l'opération (fail-closed).
export async function engagementMutate(id, body, okMsg) {
  try {
    const r = await write('/api/engagements/' + id, { body, auth: 'operator' });
    const j = r.json;
    if (r.status === 403) { toast('Action non autorisée pour votre rôle.', 'bad'); return false; }
    if (r.status === 409) { toast(String(j.why || 'opération refusée (fail-closed)'), 'bad'); return false; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return false; }
    toast(okMsg || 'OK', 'ok');
    await loadEngagementSelector(true);
    if (location.hash.slice(1) === 'engagements') loadEngagements();
    return true;
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); return false; }
}

// rend la vue #engagements (table + actions : basculer/éditer/archiver-réactiver/supprimer).
export async function loadEngagements() {
  const host = $('#eg-result'); if (!host) return;
  try { await fetchEngagements(); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  renderEngagementSelector();
  const active = activeEngagement();
  if ($('#eg-count')) $('#eg-count').textContent = ENGAGEMENTS.length + ' engagement(s)';
  if (guardList(host, ENGAGEMENTS, 'aucun engagement')) return;
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>#</th><th>Nom</th><th>Mode</th><th>Statut</th><th>Findings</th><th>Runs</th><th>Actions</th></tr></thead>';
  const tb = document.createElement('tbody');
  ENGAGEMENTS.forEach(e => {
    const tr = document.createElement('tr');
    if (e.id === active) tr.classList.add('eg-active-row');
    const c = e.counts || {};
    const isActive = e.status === 'active';
    tr.innerHTML =
      '<td class="numcol">' + e.id + '</td>' +
      '<td>' + esc(e.name) + (e.id === active ? ' <span class="badge">actif</span>' : '') + (e.classification ? ' ' + TLP_BADGE(e.classification) : '') + '</td>' +
      '<td><code>' + esc(e.mode) + '</code></td>' +
      '<td><span class="badge ' + (isActive ? 'ok' : 'mut') + '">' + esc(e.status) + '</span></td>' +
      '<td>' + (c.findings != null ? c.findings : 0) + '</td>' +
      '<td>' + (c.runs != null ? c.runs : 0) + '</td>' +
      '<td class="eg-actions"></td>';
    const act = tr.querySelector('.eg-actions');
    const mkBtn = (label, cls, title, fn, disabled) => {
      const b = document.createElement('button'); b.className = cls; b.textContent = label;
      if (title) b.title = title; if (disabled) b.disabled = true; b.onclick = fn; act.appendChild(b); return b;
    };
    mkBtn('Basculer', 'k-theme', 'Rendre cet engagement actif', () => switchEngagement(e.id), e.id === active);
    mkBtn('Éditer', 'k-theme', 'Renommer / mode / scope (operator)', () => engagementEditModal(e));
    if (isActive) {
      mkBtn('Archiver', 'k-theme', 'Archiver (admin) — refusé si dernier actif', async () => {
        if (await confirmModal('Archiver « ' + e.name + ' » ?', { okText: 'Archiver' })) engagementMutate(e.id, { status: 'archived' }, 'Engagement archivé.');
      });
    } else {
      mkBtn('Réactiver', 'k-theme', 'Réactiver (operator)', () => engagementMutate(e.id, { status: 'active' }, 'Engagement réactivé.'));
    }
    if (e.id !== 1) {
      mkBtn('Supprimer', 'k-theme danger', 'Supprimer (admin) — supprime aussi findings/runs ; refusé si dernier actif', async () => {
        if (await confirmModal('Supprimer « ' + e.name + ' » et TOUTES ses données (findings/runs) ? Le ledger reste archivé sur disque.', { danger: true, okText: 'Supprimer' })) engagementMutate(e.id, { delete: true }, 'Engagement supprimé.');
      });
    }
    // PER-ENGAGEMENT RBAC (readiness #14) — platform-admin only (enterprise). Assign composable grants
    // (user × role) scoped to THIS engagement, overriding the tenant-wide role (most-specific-wins).
    if (tenancyAdmin()) {
      mkBtn('Grants', 'k-theme', 'Rôles par-engagement (operator/viewer) — override du grant tenant', (ev) => engagementToggleGrants(e, tr, ev));
    }
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}

// =====================================================================================
//  PER-ENGAGEMENT RBAC (readiness #14) — engagement-specific grant management (platform-admin, enterprise).
//  Inline panel under the engagement row (toggle), mirroring the tenant-grants panel. The server is the
//  authority (platform-admin gate + fail-closed effective role) ; this UI is convenience only. An engagement
//  grant OVERRIDES the user's tenant-wide role for THIS engagement (most-specific-wins). Removing it reverts
//  the user to their tenant role. Community (flag OFF) => tenancyAdmin() false => this surface never renders.
// =====================================================================================
const EG_GRANT_ROLES = (Array.isArray(TENANT_ROLES) && TENANT_ROLES.length) ? TENANT_ROLES : [
  { value: 'tenant_admin', label: 'tenant_admin — administre' },
  { value: 'tenant_operator', label: 'tenant_operator — opère' },
  { value: 'tenant_viewer', label: 'tenant_viewer — lecture seule' },
];

export async function engagementToggleGrants(e, tr) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('eg-grants-row')) { existing.remove(); return; }
  document.querySelectorAll('.eg-grants-row').forEach(el => el.remove());
  const gr = document.createElement('tr'); gr.className = 'eg-grants-row';
  const td = document.createElement('td'); td.colSpan = 7;
  td.innerHTML = '<div class="muted">chargement des grants…</div>';
  gr.appendChild(td); tr.after(gr);
  try {
    const data = await adminApi('/engagements/' + encodeURIComponent(e.id) + '/grants');
    renderEngagementGrantsPanel(e, td, data || {});
  } catch (err) { td.innerHTML = `<div class="bad">erreur : ${esc(err.message)}</div>`; }
}

export function renderEngagementGrantsPanel(e, td, data) {
  td.replaceChildren();
  const wrap = document.createElement('div'); wrap.className = 'eg-grants';
  const head = document.createElement('div'); head.className = 'eg-grants-head';
  const title = document.createElement('b'); title.textContent = 'Rôles par-engagement — ' + e.name; head.appendChild(title);
  const add = document.createElement('button'); add.type = 'button'; add.className = 'k-theme'; add.textContent = '+ Grant';
  add.title = "Accorder un rôle spécifique à cet engagement (override du tenant)"; add.onclick = () => engagementGrantAdd(e, td);
  head.appendChild(add); wrap.appendChild(head);
  // EFFECTIVE grants (most-specific-wins) — the ACTUAL role each user has on this engagement.
  const eff = Array.isArray(data.effective) ? data.effective : [];
  const effTbl = document.createElement('table'); effTbl.className = 'qtable';
  effTbl.innerHTML = '<thead><tr><th>Login</th><th>Rôle effectif</th><th>Source</th></tr></thead>';
  const effBody = document.createElement('tbody');
  if (!eff.length) { const r = document.createElement('tr'); r.innerHTML = '<td class="muted" colspan="3">aucun accès</td>'; effBody.appendChild(r); }
  eff.forEach(g => {
    const r = document.createElement('tr');
    const src = g.source === 'engagement' ? '<span class="badge ok">engagement</span>' : '<span class="badge mut">tenant (hérité)</span>';
    r.innerHTML = `<td class="mono">${esc(g.login)}</td><td><span class="badge">${esc(g.role)}</span></td><td>${src}</td>`;
    effBody.appendChild(r);
  });
  effTbl.appendChild(effBody); wrap.appendChild(effTbl);
  // ENGAGEMENT-SPECIFIC overrides (removable).
  const overrides = Array.isArray(data.grants) ? data.grants : [];
  const oh = document.createElement('div'); oh.className = 'muted'; oh.style.marginTop = '6px';
  oh.textContent = 'Overrides spécifiques à cet engagement :'; wrap.appendChild(oh);
  if (!overrides.length) { const m = document.createElement('div'); m.className = 'muted'; m.textContent = 'aucun override (les rôles ci-dessus proviennent du tenant)'; wrap.appendChild(m); }
  else {
    const tbl = document.createElement('table'); tbl.className = 'qtable';
    tbl.innerHTML = '<thead><tr><th>Login</th><th>Rôle</th><th>Créé</th><th></th></tr></thead>';
    const tb = document.createElement('tbody');
    overrides.forEach(g => {
      const r = document.createElement('tr');
      r.innerHTML = `<td class="mono">${esc(g.login)}</td><td><span class="badge">${esc(g.role)}</span></td><td class="mut">${esc(fmtTs(g.created))}</td>`;
      const a = document.createElement('td');
      const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'k-theme danger'; rm.textContent = 'Retirer';
      rm.title = "Retirer l'override (revient au rôle tenant)"; rm.onclick = () => engagementGrantRemove(e, g.login, td);
      a.appendChild(rm); r.appendChild(a); tb.appendChild(r);
    });
    tbl.appendChild(tb); wrap.appendChild(tbl);
  }
  td.appendChild(wrap);
}

function egLoginError(v) {
  const s = String(v || '').trim();
  if (!s) return 'Login requis.';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(s)) return 'Login invalide ([A-Za-z0-9._-], 1 à 64).';
  return null;
}

export async function engagementGrantAdd(e, td) {
  const r = await modal({
    title: 'Rôle par-engagement — ' + e.name, okText: 'Accorder',
    message: "Accorde un rôle SPÉCIFIQUE à cet engagement (override du rôle tenant, most-specific-wins).",
    fields: [
      { name: 'login', label: 'Login', required: true, placeholder: '[A-Za-z0-9._-]', hint: 'Compte EXISTANT.' },
      { name: 'role', label: 'Rôle', type: 'select', options: EG_GRANT_ROLES, value: 'tenant_operator', hint: 'operator opère · viewer lecture seule.' },
    ],
    validate: v => egLoginError(v.login),
  });
  if (!r) return;
  try {
    await adminApi('/engagements/' + encodeURIComponent(e.id) + '/grants', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ login: String(r.login).trim(), role: r.role }) });
    toast('Rôle « ' + r.role + ' » accordé à « ' + String(r.login).trim() + ' » sur cet engagement.', 'ok');
    const data = await adminApi('/engagements/' + encodeURIComponent(e.id) + '/grants');
    renderEngagementGrantsPanel(e, td, data || {});
  } catch (err) { toast('Grant refusé : ' + err.message, 'bad'); }
}

export async function engagementGrantRemove(e, login, td) {
  const ok = await confirmModal("Retirer l'override de « " + login + ' » sur « ' + e.name + ' » ? (revient au rôle tenant)', { title: 'Retirer le grant', okText: 'Retirer', danger: true });
  if (!ok) return;
  try {
    await adminApi('/engagements/' + encodeURIComponent(e.id) + '/grants/' + encodeURIComponent(login), { method: 'DELETE', headers: { Accept: 'application/json' } });
    toast('Override retiré.', 'ok');
    const data = await adminApi('/engagements/' + encodeURIComponent(e.id) + '/grants');
    renderEngagementGrantsPanel(e, td, data || {});
  } catch (err) { toast('Retrait refusé : ' + err.message, 'bad'); }
}

if ($('#engagement')) $('#engagement').addEventListener('change', ev => { const v = parseInt(ev.target.value, 10); if (Number.isInteger(v)) switchEngagement(v); });
if ($('#eng-new')) $('#eng-new').addEventListener('click', engagementCreateModal);
if ($('#eg-new2')) $('#eg-new2').addEventListener('click', engagementCreateModal);
if ($('#eg-reload')) $('#eg-reload').addEventListener('click', loadEngagements);

// =====================================================================================
//  MULTI-TENANCY (ENTERPRISE — separable, FLAG-GATED). Toute cette surface UI est INERTE tant que le
//  serveur ne renvoie pas enabled=true sur GET /api/tenancy. En COMMUNITY (défaut) TENANCY={enabled:false}
//  => AUCUN sélecteur de tenant, AUCUNE vue #tenants, AUCUN lien nav : shell mono-tenant BYTE-IDENTIQUE.
//  Le serveur reste l'autorité (filtre fail-closed + gates 403 enterprise/platform-admin) ; l'UI n'est que
//  commodité + défense en profondeur. Modèle : TENANT → ENGAGEMENT → findings/runs.
//    - Sélecteur de tenant (header, au-dessus de l'engagement) : filtre le sélecteur d'engagement au tenant
//      actif (hiérarchie tenant → engagement). Peuplé des tenants ACCESSIBLES (super-admin => tous).
//    - Vue #tenants (platform-admin) : CRUD tenant + gestion des grants ; tout ledgerisé côté serveur.
// =====================================================================================
