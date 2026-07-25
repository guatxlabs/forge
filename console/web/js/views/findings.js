import { api, write } from '../core/api.js';
import { withEngagement } from '../core/state.js';
import { $, FINDING_STATUSES, SEV_BADGE, TLP_BADGE, TLP_CLASSES, TLP_KEY, TRIAGE_BADGE, TRIAGE_NEXT, TRIAGE_STATES, esc, fmtTs, raw, safeHtml } from '../core/dom.js';
import { downloadReport } from './reports.js';
import { confirmModal, guardList, infoModal, modal, toast } from '../core/ui.js';

// F_STATE.selected = ensemble (Set) des ids de findings COCHÉS (sélection multi-page persistante jusqu'à
// « Désélectionner » ou un changement de filtre). Les bulk-ops n'agissent QUE sur ces ids, et le serveur
// re-valide chaque id contre l'engagement actif (fail-closed : un id hors scope est ignoré/absent).
export let F_STATE = { offset: 0, limit: 200, selected: new Set() };
export async function loadFindings(offset = 0) {
  const host = $('#f-result'); if (!host) return;
  F_STATE.offset = offset;
  // rafraîchit les vues sauvegardées sur un chargement « frais » (nouvelle vue / changement de filtre ou
  // d'engagement), pas à chaque pagination — la liste est scopée à l'engagement actif côté serveur.
  if (offset === 0) { loadSavedViews(); loadAssignableUsers(); ensureTriageOptions(); }
  const qp = new URLSearchParams();
  const camp = $('#campaign') && $('#campaign').value; if (camp) qp.set('campaign', camp);
  const sev = $('#f-sev') && $('#f-sev').value; if (sev) qp.set('severity', sev);
  const st = $('#f-status') && $('#f-status').value; if (st) qp.set('status', st);
  // OWNERSHIP (P1-4) : filtre par propriétaire — `unassigned` (assignee IS NULL) ou un user_id ; lié serveur.
  const asg = $('#f-assignee') && $('#f-assignee').value; if (asg) qp.set('assignee', asg);
  // TRIAGE : filtre par état du cycle de triage (validé serveur ; valeur hors vocabulaire ignorée).
  const tri = $('#f-triage') && $('#f-triage').value; if (tri) qp.set('triage', tri);
  const tg = $('#f-target') && $('#f-target').value.trim(); if (tg) qp.set('target', tg);
  qp.set('limit', F_STATE.limit); qp.set('offset', offset);
  let d;
  try { d = await api('/findings?' + qp.toString()); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  const rows = d.findings || [];
  if ($('#f-count')) $('#f-count').textContent = d.total + ' findings';
  if (guardList(host, rows, 'aucun finding')) return;
  const table = document.createElement('table'); table.className = 'qtable findtable';
  // en-tête : case « tout sélectionner » (page courante) + colonnes existantes.
  const thead = document.createElement('thead');
  const htr = document.createElement('tr');
  const selTh = document.createElement('th'); selTh.className = 'selcol';
  const selAll = document.createElement('input'); selAll.type = 'checkbox'; selAll.setAttribute('aria-label', 'Tout sélectionner (page)');
  selAll.checked = rows.length > 0 && rows.every(x => F_STATE.selected.has(x.id));
  selAll.onclick = e => { e.stopPropagation(); const on = selAll.checked; rows.forEach(x => { if (on) F_STATE.selected.add(x.id); else F_STATE.selected.delete(x.id); }); loadFindings(F_STATE.offset); };
  selTh.appendChild(selAll); htr.appendChild(selTh);
  htr.insertAdjacentHTML('beforeend', `<th>#</th><th>Sév.</th><th>Cible</th><th>Titre</th><th>ATT&CK</th><th>Statut</th><th>Triage</th><th>TLP</th><th>Proprio</th><th>Outil</th><th>Date</th>`);
  thead.appendChild(htr); table.appendChild(thead);
  const tb = document.createElement('tbody');
  rows.forEach((x, i) => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour voir le détail (evidence / PoC / fix)';
    const cbTd = document.createElement('td'); cbTd.className = 'selcol';
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = F_STATE.selected.has(x.id); cb.setAttribute('aria-label', 'Sélectionner ce finding');
    cb.onclick = e => { e.stopPropagation(); if (cb.checked) F_STATE.selected.add(x.id); else F_STATE.selected.delete(x.id); updateBulkBar(); selAll.checked = rows.every(r => F_STATE.selected.has(r.id)); };
    cbTd.appendChild(cb); tr.appendChild(cbTd);
    tr.insertAdjacentHTML('beforeend', safeHtml`<td class="numcol">${Number(offset + i + 1)}</td><td>${raw(SEV_BADGE(x.severity))}</td><td>${x.target}</td><td>${x.title}</td><td><code>${x.mitre}</code></td><td>${x.status}</td><td>${raw(TRIAGE_BADGE(x.triage))}</td><td>${raw(TLP_BADGE(x.classification))}</td><td class="mut">${x.assignee_login || '—'}</td><td class="mut">${x.tool}</td><td class="mut">${fmtTs(x.ts)}</td>`);
    tr.onclick = () => openFinding(x.id);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
  updateBulkBar();
  // pager simple offset/limit
  const pages = Math.max(1, Math.ceil(d.total / F_STATE.limit)), cur = Math.floor(offset / F_STATE.limit);
  if (pages > 1) {
    const pager = document.createElement('div'); pager.className = 'evpager';
    const prev = document.createElement('button'); prev.type = 'button'; prev.textContent = '◀'; prev.disabled = cur === 0; prev.onclick = () => loadFindings(Math.max(0, offset - F_STATE.limit));
    const next = document.createElement('button'); next.type = 'button'; next.textContent = '▶'; next.disabled = cur >= pages - 1; next.onclick = () => loadFindings(offset + F_STATE.limit);
    const lbl = document.createElement('span'); lbl.className = 'evtot'; lbl.textContent = `page ${cur + 1}/${pages} · ${d.total} total`;
    pager.append(prev, next, lbl); host.appendChild(pager);
  }
}
export async function openFinding(id) {
  let d;
  try { d = await api('/findings/' + id); } catch (e) { toast('Détail finding : ' + e.message, 'bad'); return; }
  infoModal(d.title || ('Finding #' + id), body => {
    const meta = document.createElement('div'); meta.className = 'findmeta';
    meta.innerHTML = safeHtml`${raw(SEV_BADGE(d.severity))} <span class="badge">${d.status}</span> ${raw(TRIAGE_BADGE(d.triage))} ${raw(TLP_BADGE(d.classification))} <code>${d.mitre}</code> <span class="muted">${d.category}</span>`;
    body.appendChild(meta);
    const kv = document.createElement('dl'); kv.className = 'kvdetail';
    [['Campagne', d.campaign], ['Cible', d.target], ['Outil', d.tool], ['Run', d.run_id], ['Date', fmtTs(d.ts)]].forEach(([k, v]) => {
      const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = (v == null || v === '') ? '-' : String(v); kv.append(dt, dd);
    });
    body.appendChild(kv);
    const sec = (label, val) => { if (!val) return; const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = label; const pre = document.createElement('pre'); pre.className = 'mailtext'; pre.textContent = val; body.append(h, pre); };
    sec('Evidence', d.evidence);
    sec('PoC', d.poc);
    sec('Correctif suggéré', d.fix);
    buildFindingControls(body, d);
    buildTriageControl(body, d);
    buildAssignControl(body, d);
  });
}

// Contrôle de TRIAGE (machine à états gouvernée) : ne propose QUE les transitions AUTORISÉES depuis l'état
// COURANT (miroir client TRIAGE_NEXT — le SERVEUR reste l'autorité et re-valide, 409 si illégal). L'état de
// triage est INDÉPENDANT du statut de PREUVE (cf. buildFindingControls) : cette transition n'écrit que
// `triage`. Endpoint dédié POST /api/findings/:id/triage. Aucune modale navigateur.
function buildTriageControl(body, d) {
  const el = (t, cls) => { const n = document.createElement(t); if (cls) n.className = cls; return n; };
  const cur = TRIAGE_STATES.includes(String(d.triage || '')) ? String(d.triage) : 'new';
  const next = TRIAGE_NEXT(cur);
  const wrap = el('div', 'findctl');
  const h = el('div', 'mailsec'); h.textContent = 'Triage (cycle de vie gouverné, operator)'; wrap.appendChild(h);
  const row = el('div', 'findctl-row');
  const state = el('div'); state.className = 'trib trib-' + cur; state.textContent = cur.replace(/_/g, ' ');
  const stLbl = el('label'); stLbl.textContent = 'État courant'; stLbl.appendChild(state); row.appendChild(stLbl);
  if (!next.length) {
    // État TERMINAL/sans transition sortante dans la matrice : aucune action possible (fail-closed côté UI).
    const info = el('div', 'muted'); info.textContent = 'Aucune transition disponible depuis cet état.'; row.appendChild(info);
    wrap.appendChild(row); body.appendChild(wrap); return;
  }
  const toLbl = el('label'); toLbl.textContent = 'Transition vers';
  const sel = el('select'); sel.setAttribute('aria-label', 'Transition de triage');
  next.forEach(s => { const o = el('option'); o.value = s; o.textContent = s.replace(/_/g, ' '); sel.appendChild(o); });
  toLbl.appendChild(sel); row.appendChild(toLbl);
  const save = el('button'); save.type = 'button'; save.className = 'k-theme'; save.textContent = 'Transitionner';
  save.onclick = async () => {
    const to = sel.value;
    if (!to) { toast('Choisis un état cible.', 'info'); return; }
    save.disabled = true;
    try {
      const r = await write('/api/findings/' + d.id + '/triage', { body: { to }, auth: 'operator', engagement: true });
      const j = r.json || {};
      if (r.status === 403) { toast('Réservé à un compte operator sur cet engagement.', 'bad'); return; }
      if (r.status === 409) { toast('Transition refusée (état courant modifié). États permis : ' + String((j.allowed || []).join(', ')), 'bad', 6000); return; }
      if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
      toast('Triage : ' + esc(cur) + ' → ' + esc(to) + ' (ledgerisé).', 'ok');
      d.triage = to;
      loadFindings(F_STATE.offset);
    } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
    finally { save.disabled = false; }
  };
  row.appendChild(save);
  wrap.appendChild(row);
  body.appendChild(wrap);
}

// Contrôle de PROPRIÉTÉ (P1-4) : assigne/désassigne le finding (operator, GRANT-SCOPÉ serveur). Le
// sélecteur est peuplé depuis le jeu ASSIGNABLE (users réellement sur l'engagement actif) ; l'assigné
// courant est toujours proposé, marqué « hors périmètre » s'il n'est plus assignable. Endpoint dédié
// POST /api/findings/:id/assign (distinct du cycle de vie/TLP). Aucune modale navigateur.
function buildAssignControl(body, d) {
  const el = (t, cls) => { const n = document.createElement(t); if (cls) n.className = cls; return n; };
  const wrap = el('div', 'findctl');
  const h = el('div', 'mailsec'); h.textContent = 'Propriétaire (assignee, operator)'; wrap.appendChild(h);
  const row = el('div', 'findctl-row');
  const lbl = el('label'); lbl.textContent = 'Assigné à';
  const sel = el('select'); sel.setAttribute('aria-label', 'Propriétaire du finding');
  const optNone = el('option'); optNone.value = ''; optNone.textContent = '(non assigné)'; sel.appendChild(optNone);
  let hasCur = false;
  ASSIGNABLE.forEach(u => {
    const o = el('option'); o.value = String(u.id); o.textContent = u.login;
    if (d.assignee != null && Number(u.id) === Number(d.assignee)) { o.selected = true; hasCur = true; }
    sel.appendChild(o);
  });
  // l'assigné courant hors du jeu assignable reste proposé (marqué), pour ne pas le perdre à l'ouverture.
  if (d.assignee != null && !hasCur) {
    const o = el('option'); o.value = String(d.assignee); o.textContent = (d.assignee_login || ('#' + d.assignee)) + ' (hors périmètre)'; o.selected = true; sel.appendChild(o);
  }
  lbl.appendChild(sel); row.appendChild(lbl);
  const save = el('button'); save.type = 'button'; save.className = 'k-theme'; save.textContent = 'Assigner';
  save.onclick = async () => {
    const v = sel.value;
    const assignee = v === '' ? null : Number(v);
    const cur = d.assignee == null ? null : Number(d.assignee);
    if (assignee === cur) { toast('Aucun changement.', 'info'); return; }
    save.disabled = true;
    try {
      const r = await write('/api/findings/' + d.id + '/assign', { body: { assignee }, auth: 'operator', engagement: true });
      const j = r.json || {};
      if (r.status === 403) { toast('Réservé à un compte operator (ou assigné hors périmètre de l’engagement).', 'bad'); return; }
      if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
      toast('Propriétaire mis à jour (ledgerisé).', 'ok');
      d.assignee = assignee;
      loadFindings(F_STATE.offset);
    } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
    finally { save.disabled = false; }
  };
  row.appendChild(save);
  wrap.appendChild(row);
  body.appendChild(wrap);
}

// Contrôles de MUTATION d'un finding (#15) : transition de cycle de vie (statut validé) + classification
// TLP 2.0. TOLÉRANT en lecture : un statut hérité (hors vocabulaire) est proposé comme option courante
// non normative — l'utilisateur reste libre de le laisser tel quel (aucun envoi) ou de transitionner vers
// une valeur validée. La mutation est OPÉRATEUR (gate serveur fail-closed) + ISOLÉE à l'engagement actif.
function buildFindingControls(body, d) {
  const el = (t, cls) => { const n = document.createElement(t); if (cls) n.className = cls; return n; };
  const wrap = el('div', 'findctl');
  const h = el('div', 'mailsec'); h.textContent = 'Cycle de vie & classification (operator)'; wrap.appendChild(h);
  const row = el('div', 'findctl-row');

  // --- statut (transition validée, tolérant du legacy) ---
  const curStatus = String(d.status || '');
  const stLbl = el('label'); stLbl.textContent = 'Statut'; const stSel = el('select'); stSel.setAttribute('aria-label', 'Transition de statut');
  if (!FINDING_STATUSES.includes(curStatus)) {
    const o = el('option'); o.value = ''; o.textContent = curStatus ? `${curStatus} (hérité — choisir…)` : '(aucun — choisir…)'; o.selected = true; stSel.appendChild(o);
  }
  FINDING_STATUSES.forEach(s => { const o = el('option'); o.value = s; o.textContent = s; if (s === curStatus) o.selected = true; stSel.appendChild(o); });
  stLbl.appendChild(stSel); row.appendChild(stLbl);

  // --- classification TLP ---
  const curClass = TLP_KEY(d.classification || '');
  const clLbl = el('label'); clLbl.textContent = 'Classification (TLP 2.0)'; const clSel = el('select'); clSel.setAttribute('aria-label', 'Classification TLP');
  [['', '(non classifié)']].concat(TLP_CLASSES.map(t => [t, 'TLP:' + t])).forEach(([v, l]) => { const o = el('option'); o.value = v; o.textContent = l; if (v === curClass) o.selected = true; clSel.appendChild(o); });
  clLbl.appendChild(clSel); row.appendChild(clLbl);

  const save = el('button'); save.type = 'button'; save.className = 'k-theme'; save.textContent = 'Appliquer';
  save.onclick = async () => {
    const b = {};
    const st = stSel.value; if (st && st !== curStatus) b.status = st;
    const cl = clSel.value; if (cl !== curClass) b.classification = cl;
    if (!Object.keys(b).length) { toast('Aucun changement.', 'info'); return; }
    save.disabled = true;
    try {
      const r = await write('/api/findings/' + d.id, { body: b, auth: 'operator', engagement: true });
      const j = r.json || {};
      if (r.status === 403) { toast('Réservé à un compte operator.', 'bad'); return; }
      if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
      toast('Finding mis à jour (ledgerisé).', 'ok');
      if ('classification' in b) { d.classification = b.classification; }
      if ('status' in b) { d.status = b.status; }
      loadFindings(F_STATE.offset);
    } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
    finally { save.disabled = false; }
  };
  row.appendChild(save);
  wrap.appendChild(row);
  body.appendChild(wrap);
}
['f-sev', 'f-status', 'f-assignee', 'f-triage', 'f-target'].forEach(idp => { const el = $('#' + idp); if (el) el.addEventListener(idp === 'f-target' ? 'input' : 'change', () => loadFindings(0)); });
// EXPORT depuis Findings : CSV / JSON de l'engagement ACTIF (secrets rédigés serveur) + accès au
// rapport complet brandé (vue #reports). downloadReport() est défini plus bas (déclaration hoistée).
if ($('#f-export-csv')) $('#f-export-csv').addEventListener('click', () => downloadReport('csv'));
if ($('#f-export-json')) $('#f-export-json').addEventListener('click', () => downloadReport('json'));
if ($('#f-report')) $('#f-report').addEventListener('click', () => { location.hash = 'reports'; });

// =====================================================================================
//  BULK-OPS (#8) — sélection multiple + barre d'actions de masse (transition de statut validée +
//  export CSV/JSON de la sélection). Tout est SERVEUR + engagement-scopé fail-closed : le client ne fait
//  qu'envoyer la LISTE d'ids cochés ; le serveur re-valide chaque id contre l'engagement actif.
// =====================================================================================

// Peuple (une fois) le sélecteur de transition de statut de masse depuis le vocabulaire validé.
function ensureBulkStatusOptions() {
  const sel = $('#f-bulk-status'); if (!sel || sel.dataset.filled) return;
  FINDING_STATUSES.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; sel.appendChild(o); });
  sel.dataset.filled = '1';
}

// Peuple (une fois) les sélecteurs de triage — filtre `#f-triage` (tous les états) + bulk `#f-bulk-triage`
// (états cibles). Miroir client de TRIAGE_STATES ; le serveur valide chaque transition par finding.
function ensureTriageOptions() {
  const f = $('#f-triage');
  if (f && !f.dataset.filled) {
    TRIAGE_STATES.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s.replace(/_/g, ' '); f.appendChild(o); });
    f.dataset.filled = '1';
  }
  const b = $('#f-bulk-triage');
  if (b && !b.dataset.filled) {
    TRIAGE_STATES.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = 'triage → ' + s.replace(/_/g, ' '); b.appendChild(o); });
    b.dataset.filled = '1';
  }
}

// Reflète l'état de la sélection dans la barre d'actions (visibilité + compteur).
function updateBulkBar() {
  const bar = $('#f-bulk'); if (!bar) return;
  ensureBulkStatusOptions();
  ensureTriageOptions();
  const n = F_STATE.selected.size;
  bar.hidden = n === 0;
  const c = $('#f-bulk-count'); if (c) c.textContent = n + ' sélectionné(s)';
}

// Transitionne les findings sélectionnés vers l'état de triage choisi (operator). Le serveur valide CHAQUE
// finding contre la matrice depuis SON état courant : les transitions illégales sont IGNORÉES (skipped), les
// légales appliquées. Réponse applied/skipped comme bulk-status.
async function bulkTriage() {
  const to = ($('#f-bulk-triage') && $('#f-bulk-triage').value) || '';
  if (!to) { toast('Choisis un état de triage cible.', 'info'); return; }
  const ids = Array.from(F_STATE.selected);
  if (!ids.length) { toast('Aucun finding sélectionné.', 'info'); return; }
  const ok = await confirmModal(`Transitionner ${ids.length} finding(s) vers le triage « ${to.replace(/_/g, ' ')} » ? Les transitions illégales seront ignorées.`, { title: 'Triage de masse', okText: 'Transitionner', danger: false });
  if (!ok) return;
  const btn = $('#f-bulk-triage-apply'); if (btn) btn.disabled = true;
  try {
    const r = await write('/api/findings/bulk/triage', { body: { ids, to }, auth: 'operator', engagement: true });
    const j = r.json || {};
    if (r.status === 403) { toast('Réservé à un compte operator sur cet engagement.', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    const ap = (j.applied || []).length, sk = (j.skipped || []).length;
    toast(`Triage appliqué à ${ap} finding(s)` + (sk ? `, ${sk} ignoré(s) (transition illégale ou hors périmètre)` : '') + ' (ledgerisé).', 'ok', 6000);
    (j.applied || []).forEach(id => F_STATE.selected.delete(id));
    loadFindings(F_STATE.offset);
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
  finally { if (btn) btn.disabled = false; }
}

// Applique la transition de statut choisie aux findings sélectionnés (operator, serveur valide chaque id).
async function bulkApplyStatus() {
  const status = ($('#f-bulk-status') && $('#f-bulk-status').value) || '';
  if (!status) { toast('Choisis un statut à appliquer.', 'info'); return; }
  const ids = Array.from(F_STATE.selected);
  if (!ids.length) { toast('Aucun finding sélectionné.', 'info'); return; }
  const ok = await confirmModal(`Appliquer le statut « ${status} » à ${ids.length} finding(s) sélectionné(s) ?`, { title: 'Transition de masse', okText: 'Appliquer', danger: false });
  if (!ok) return;
  const btn = $('#f-bulk-apply'); if (btn) btn.disabled = true;
  try {
    const r = await write('/api/findings/bulk/status', { body: { ids, status }, auth: 'operator', engagement: true });
    const j = r.json || {};
    if (r.status === 403) { toast('Réservé à un compte operator.', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    const ap = (j.applied || []).length, sk = (j.skipped || []).length;
    toast(`Statut appliqué à ${ap} finding(s)` + (sk ? `, ${sk} hors périmètre ignoré(s)` : '') + ' (ledgerisé).', 'ok', 5000);
    // on retire de la sélection les ids appliqués (les skippés restent cochés pour inspection).
    (j.applied || []).forEach(id => F_STATE.selected.delete(id));
    loadFindings(F_STATE.offset);
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
  finally { if (btn) btn.disabled = false; }
}

// Exporte la SÉLECTION (CSV/JSON) — POST serveur, engagement-scopé, déclenche un téléchargement.
async function bulkExport(fmt) {
  const ids = Array.from(F_STATE.selected);
  if (!ids.length) { toast('Aucun finding sélectionné.', 'info'); return; }
  let r;
  try {
    r = await fetch(withEngagement('/api/findings/bulk/export'), {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: '*/*' },
      body: JSON.stringify({ ids, format: fmt }),
    });
  } catch (e) { toast('Erreur réseau : ' + (e.message || e), 'bad'); return; }
  if (!r.ok) { toast('Export indisponible (HTTP ' + r.status + ').', 'bad'); return; }
  let blob; try { blob = await r.blob(); } catch (e) { toast('Lecture de l’export : ' + (e.message || e), 'bad'); return; }
  const objUrl = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = objUrl; a.download = 'forge-findings-selection.' + (fmt === 'csv' ? 'csv' : 'json');
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
  toast(`Export ${fmt.toUpperCase()} de ${ids.length} finding(s) sélectionné(s).`, 'ok');
}

// OWNERSHIP (P1-4) — jeu des utilisateurs ASSIGNABLES sur l'engagement actif (grant-scopé serveur). Peuple
// le filtre `#f-assignee` ET le sélecteur de bulk-assign `#f-bulk-assignee` (conserve leurs options statiques).
let ASSIGNABLE = [];
async function loadAssignableUsers() {
  let d;
  try { d = await api('/findings/assignable'); } catch (e) { return; } // silencieux : optionnel
  ASSIGNABLE = (d && d.users) || [];
  // repeuple un select en conservant ses `keep` premières options statiques, en restaurant la sélection.
  const fill = (sel, keep) => {
    if (!sel) return;
    const cur = sel.value;
    while (sel.options.length > keep) sel.remove(keep);
    ASSIGNABLE.forEach(u => { const o = document.createElement('option'); o.value = String(u.id); o.textContent = u.login; sel.appendChild(o); });
    if (Array.from(sel.options).some(o => o.value === cur)) sel.value = cur;
  };
  fill($('#f-assignee'), 2);      // « Tous propriétaires » + « Non assigné »
  fill($('#f-bulk-assignee'), 2); // « Assigner à… » + « (désassigner) »
}

// Assigne le propriétaire choisi aux findings sélectionnés (operator, serveur valide chaque id + le grant).
async function bulkAssign() {
  const sel = $('#f-bulk-assignee'); const v = (sel && sel.value) || '';
  if (!v) { toast('Choisis un propriétaire (ou « désassigner »).', 'info'); return; }
  const ids = Array.from(F_STATE.selected);
  if (!ids.length) { toast('Aucun finding sélectionné.', 'info'); return; }
  const assignee = v === '__none__' ? null : Number(v);
  const who = v === '__none__' ? '' : ((sel.options[sel.selectedIndex] && sel.options[sel.selectedIndex].textContent) || v);
  const ok = await confirmModal(`${assignee == null ? 'Désassigner' : 'Assigner à « ' + who + ' »'} ${ids.length} finding(s) sélectionné(s) ?`, { title: 'Assignation de masse', okText: 'Assigner', danger: false });
  if (!ok) return;
  const btn = $('#f-bulk-assign'); if (btn) btn.disabled = true;
  try {
    const r = await write('/api/findings/bulk/assign', { body: { ids, assignee }, auth: 'operator', engagement: true });
    const j = r.json || {};
    if (r.status === 403) { toast('Réservé à un compte operator (ou assigné hors périmètre).', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    const ap = (j.applied || []).length, sk = (j.skipped || []).length;
    toast(`Propriétaire appliqué à ${ap} finding(s)` + (sk ? `, ${sk} hors périmètre ignoré(s)` : '') + ' (ledgerisé).', 'ok', 5000);
    (j.applied || []).forEach(id => F_STATE.selected.delete(id));
    loadFindings(F_STATE.offset);
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
  finally { if (btn) btn.disabled = false; }
}

if ($('#f-bulk-apply')) $('#f-bulk-apply').addEventListener('click', bulkApplyStatus);
if ($('#f-bulk-assign')) $('#f-bulk-assign').addEventListener('click', bulkAssign);
if ($('#f-bulk-triage-apply')) $('#f-bulk-triage-apply').addEventListener('click', bulkTriage);
if ($('#f-bulk-csv')) $('#f-bulk-csv').addEventListener('click', () => bulkExport('csv'));
if ($('#f-bulk-json')) $('#f-bulk-json').addEventListener('click', () => bulkExport('json'));
if ($('#f-bulk-clear')) $('#f-bulk-clear').addEventListener('click', () => { F_STATE.selected.clear(); loadFindings(F_STATE.offset); });

// =====================================================================================
//  SAVED VIEWS (#8) — jeux de filtres sauvegardés (PERSONNELS, scopés au login de l'appelant + engagement
//  optionnel). « Enregistrer la vue » capture l'état de filtre courant ; sélectionner une vue le réapplique.
// =====================================================================================

// dernière liste de vues connue (pour retrouver le filtre à réappliquer sans refetch).
let SAVED_VIEWS = [];

// État de filtre COURANT de la vue Findings (severity/status/target/campaign) — objet sérialisable.
function collectFilterState() {
  const f = {};
  const sev = $('#f-sev') && $('#f-sev').value; if (sev) f.severity = sev;
  const st = $('#f-status') && $('#f-status').value; if (st) f.status = st;
  const asg = $('#f-assignee') && $('#f-assignee').value; if (asg) f.assignee = asg;
  const tri = $('#f-triage') && $('#f-triage').value; if (tri) f.triage = tri;
  const tg = $('#f-target') && $('#f-target').value.trim(); if (tg) f.target = tg;
  const camp = $('#campaign') && $('#campaign').value; if (camp) f.campaign = camp;
  return f;
}

// Réapplique un état de filtre (remet les contrôles puis recharge). Les clefs inconnues sont ignorées.
function applyFilterState(f) {
  f = f || {};
  if ($('#f-sev')) $('#f-sev').value = f.severity || '';
  if ($('#f-status')) $('#f-status').value = f.status || '';
  // `assignee` : la valeur ne « colle » que si son option existe (jeu ASSIGNABLE déjà chargé à l'init de la
  // vue). 'unassigned' est une option statique toujours présente ; un user_id l'est après loadAssignableUsers.
  if ($('#f-assignee')) $('#f-assignee').value = f.assignee || '';
  // `triage` : options statiques peuplées à l'init de la vue (ensureTriageOptions) — la valeur « colle ».
  if ($('#f-triage')) { ensureTriageOptions(); $('#f-triage').value = f.triage || ''; }
  if ($('#f-target')) $('#f-target').value = f.target || '';
  // `campaign` est un sélecteur global partagé : on ne le force que s'il existe dans ses options.
  if (f.campaign != null && $('#campaign')) { const opt = Array.from($('#campaign').options || []).some(o => o.value === f.campaign); if (opt) $('#campaign').value = f.campaign; }
  loadFindings(0);
}

// Charge les vues de l'appelant (globales + engagement actif) et peuple le sélecteur.
async function loadSavedViews() {
  const sel = $('#f-views'); if (!sel) return;
  let d;
  try { d = await api('/saved-views'); } catch (e) { return; } // silencieux : vue optionnelle
  SAVED_VIEWS = (d && d.views) || [];
  const cur = sel.value;
  sel.replaceChildren();
  const ph = document.createElement('option'); ph.value = ''; ph.textContent = SAVED_VIEWS.length ? 'Vues sauvegardées…' : 'Aucune vue sauvegardée'; sel.appendChild(ph);
  SAVED_VIEWS.forEach(v => { const o = document.createElement('option'); o.value = String(v.id); o.textContent = v.name + (v.engagement_id == null ? '' : ' ⚑'); sel.appendChild(o); });
  if (SAVED_VIEWS.some(v => String(v.id) === cur)) sel.value = cur;
  const del = $('#f-del-view'); if (del) del.hidden = !sel.value;
}

// Sauvegarde le jeu de filtres courant comme vue réutilisable (operator). Optionnel : rattacher à l'engagement.
async function saveCurrentView() {
  const f = collectFilterState();
  const r = await modal({
    title: 'Enregistrer la vue',
    message: 'Sauvegarde le jeu de filtres courant (sévérité, statut, cible, campagne) pour le réappliquer d’un clic.',
    fields: [
      { name: 'name', label: 'Nom de la vue', type: 'text', required: true, placeholder: 'ex. Critiques non triés' },
      { name: 'scope', label: 'Rattacher à l’engagement actif (sinon : globale)', type: 'checkbox', value: false },
    ],
    okText: 'Enregistrer',
  });
  if (!r) return;
  const body = { name: String(r.name || '').trim(), filter_json: f, scope_engagement: !!r.scope };
  const w = await write('/api/saved-views', { body, auth: 'operator', engagement: true });
  const j = w.json || {};
  if (w.status === 403) { toast('Réservé à un compte operator.', 'bad'); return; }
  if (!w.ok) { toast('Échec : ' + String(j.why || j.error || w.status), 'bad'); return; }
  toast('Vue enregistrée.', 'ok');
  await loadSavedViews();
  const sel = $('#f-views'); if (sel && j.view && j.view.id != null) { sel.value = String(j.view.id); const del = $('#f-del-view'); if (del) del.hidden = false; }
}

// Supprime la vue sélectionnée (operator, propriété stricte côté serveur).
async function deleteSelectedView() {
  const sel = $('#f-views'); const id = sel && sel.value; if (!id) { toast('Sélectionne une vue à supprimer.', 'info'); return; }
  const v = SAVED_VIEWS.find(x => String(x.id) === String(id));
  const ok = await confirmModal(`Supprimer la vue « ${(v && v.name) || id} » ?`, { title: 'Supprimer la vue', okText: 'Supprimer', danger: true });
  if (!ok) return;
  const w = await write('/api/saved-views/' + id, { method: 'DELETE', auth: 'operator' });
  const j = w.json || {};
  if (w.status === 403) { toast('Réservé à un compte operator.', 'bad'); return; }
  if (!w.ok) { toast('Échec : ' + String(j.why || j.error || w.status), 'bad'); return; }
  toast('Vue supprimée.', 'ok');
  await loadSavedViews();
}

if ($('#f-views')) $('#f-views').addEventListener('change', () => {
  const sel = $('#f-views'); const id = sel.value; const del = $('#f-del-view'); if (del) del.hidden = !id;
  if (!id) return;
  const v = SAVED_VIEWS.find(x => String(x.id) === String(id));
  if (v) applyFilterState(v.filter_json || {});
});
if ($('#f-save-view')) $('#f-save-view').addEventListener('click', saveCurrentView);
if ($('#f-del-view')) $('#f-del-view').addEventListener('click', deleteSelectedView);

// TRIAGE LIVE (SSE) — flux `/api/findings/events` (topic serveur FINDINGS_TOPIC) : quand un AUTRE opérateur
// transitionne un finding, on recharge la liste EN DIRECT (débouncé). On ne recharge QUE si la vue Findings
// est visible (offsetParent non nul), pour ne pas fetch inutilement depuis une autre vue. Le cookie de
// session est porté automatiquement (EventSource same-origin) ; EventSource re-tente seul en cas de coupure.
(function initTriageLive() {
  const host = $('#f-result'); if (!host || typeof EventSource === 'undefined') return;
  let timer = null;
  const refresh = () => {
    if (host.offsetParent === null) return; // vue non visible -> pas de fetch
    clearTimeout(timer);
    timer = setTimeout(() => loadFindings(F_STATE.offset), 250); // débounce léger (rafales)
  };
  try {
    const es = new EventSource('/api/findings/events');
    es.addEventListener('finding', refresh);
    es.onerror = () => { /* EventSource re-tente seul ; le prochain chargement rattrapera l'état */ };
  } catch (e) { /* SSE indisponible : la vue reste utilisable (refresh manuel/actions) */ }
})();

// =====================================================================================
//  FINDINGS LIBRARY — modèles de findings réutilisables (livrable client type Ghostwriter).
//  Les modèles sont GLOBAUX (réutilisables d'un engagement à l'autre) ; APPLIQUER un modèle crée UN
//  finding dans l'engagement ACTIF UNIQUEMENT (isolation, cf. serveur). create/edit = operator,
//  delete = admin, apply = operator — chaque action est ledgerisée côté serveur (fail-closed).
//  UI 100 % native (aucune modale navigateur) : réutilise modal()/confirmModal()/toast().
// =====================================================================================
