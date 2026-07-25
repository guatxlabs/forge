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
      { name: 'allow_private', label: 'Autoriser le réseau privé pour cet engagement (nécessite AUSSI la politique globale + le scope)', type: 'checkbox', value: false },
    ],
  });
  if (!vals) return;
  const body = {
    name: String(vals.name || '').trim(),
    mode: vals.mode || 'grey',
    classification: vals.classification || '',
    // POLITIQUE RÉSEAU (opt-in par engagement) : n'ouvre RIEN seul — l'effectif = ceci ET le master global
    // ET le scope. Défaut décoché (fail-closed).
    allow_private: !!vals.allow_private,
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
      { name: 'allow_private', label: 'Autoriser le réseau privé pour cet engagement (nécessite AUSSI la politique globale + le scope)', type: 'checkbox', value: !!e.allow_private },
    ],
  });
  if (!vals) return;
  const body = { name: String(vals.name || '').trim(), mode: vals.mode || e.mode, classification: vals.classification || '' };
  // POLITIQUE RÉSEAU : bascule l'opt-in par engagement (booléen strict ; n'ouvre rien sans le master global + scope).
  body.allow_private = !!vals.allow_private;
  const inl = _scopeLines(vals.in_scope), outl = _scopeLines(vals.out_scope);
  if (inl.length || outl.length) body.scope_json = { mode: vals.mode || e.mode, in_scope: inl, out_scope: outl };
  await engagementMutate(e.id, body, 'Engagement mis à jour.');
}

// =====================================================================================
//  CONTEXTE D'AUTHENTIFICATION PAR-ENGAGEMENT (R5b) — éditeur structuré du bloc `scope_json.auth`.
//  Deux sections à LIGNES RÉPÉTABLES : comptes de test LABELLISÉS (attacker/victim — matériel bearer/
//  cookies/headers) + cibles idor (url + owner + marker). Écrit le bloc DANS scope_json SANS écraser les
//  autres clés (mode/in_scope/out_scope repris de l'engagement). Aucun compte ni cible => bloc OMIS (le
//  serveur le supprime => engagement byte-identique, no-op). SECRETS : champs password (jamais réaffichés
//  ni journalisés) ; le résumé RÉDIGÉ (e.auth) sert seulement à ré-afficher labels/noms d'en-têtes/cibles.
//  Le serveur reste l'autorité (gate operator + validate_auth_block + rédaction des secrets côté moteur).
// =====================================================================================

// parse une zone "Nom: valeur" (une par ligne) -> objet {Nom: valeur}. Sûr (aucune éval, split simple).
function _parseHeaderLines(txt) {
  const out = {};
  String(txt || '').split('\n').forEach(line => {
    const s = line.trim();
    if (!s) return;
    const i = s.indexOf(':');
    if (i <= 0) return;
    const k = s.slice(0, i).trim();
    const v = s.slice(i + 1).trim();
    if (k) out[k] = v;
  });
  return out;
}

// construit une ligne "compte" (DOM sûr : createElement + value, jamais innerHTML avec de la donnée).
function _acctRow(container, seed) {
  const s = seed || {};
  const row = document.createElement('div'); row.className = 'auth-row';
  const mk = (labelTxt, el, hintTxt) => {
    const wrap = document.createElement('label'); wrap.className = 'modal-f';
    const sp = document.createElement('span'); sp.textContent = labelTxt; wrap.appendChild(sp);
    wrap.appendChild(el);
    if (hintTxt) { const h = document.createElement('small'); h.className = 'modal-fhint'; h.textContent = hintTxt; wrap.appendChild(h); }
    return wrap;
  };
  const label = document.createElement('input'); label.type = 'text'; label.dataset.k = 'label';
  label.placeholder = 'attacker / victim'; label.value = s.label || '';
  const bearer = document.createElement('input'); bearer.type = 'password'; bearer.dataset.k = 'bearer';
  bearer.autocomplete = 'new-password'; bearer.placeholder = s.has_bearer ? '•••• défini — ressaisir pour conserver' : 'jeton (optionnel)';
  const cookies = document.createElement('input'); cookies.type = 'password'; cookies.dataset.k = 'cookies';
  cookies.autocomplete = 'new-password'; cookies.placeholder = s.has_cookies ? '•••• défini — ressaisir pour conserver' : 'sid=abc; autre=xyz';
  const headers = document.createElement('textarea'); headers.dataset.k = 'headers'; headers.rows = 2; headers.spellcheck = false;
  headers.placeholder = 'X-CSRF: valeur\nAuthorization: Bearer …';
  if (Array.isArray(s.header_keys) && s.header_keys.length) headers.placeholder = s.header_keys.map(k => k + ': (ressaisir la valeur)').join('\n');
  row.appendChild(mk('Label', label, 'attacker = celui dont on rejoue la session ; victim = propriétaire des ressources.'));
  row.appendChild(mk('Bearer', bearer));
  row.appendChild(mk('Cookies', cookies, 'forme « nom=valeur; nom2=valeur2 ».'));
  row.appendChild(mk('En-têtes', headers, 'un « Nom: valeur » par ligne.'));
  const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'k-theme danger'; rm.textContent = 'Retirer';
  rm.onclick = () => row.remove(); row.appendChild(rm);
  container.appendChild(row);
}

// construit une ligne "cible idor" (url + owner + marker). Aucun secret ici (config non secrète).
function _tgtRow(container, seed) {
  const s = seed || {};
  const row = document.createElement('div'); row.className = 'auth-row';
  const mk = (labelTxt, el, ph, hintTxt) => {
    const wrap = document.createElement('label'); wrap.className = 'modal-f';
    const sp = document.createElement('span'); sp.textContent = labelTxt; wrap.appendChild(sp);
    el.type = 'text'; el.placeholder = ph; wrap.appendChild(el);
    if (hintTxt) { const h = document.createElement('small'); h.className = 'modal-fhint'; h.textContent = hintTxt; wrap.appendChild(h); }
    return wrap;
  };
  const url = document.createElement('input'); url.dataset.k = 'url'; url.value = s.url || '';
  const owner = document.createElement('input'); owner.dataset.k = 'owner'; owner.value = s.owner || '';
  const marker = document.createElement('input'); marker.dataset.k = 'marker'; marker.value = s.marker || '';
  row.appendChild(mk('URL (in-scope)', url, 'https://app/api/orders/1', 'ressource possédée par la victime (whoami/objet).'));
  row.appendChild(mk('Owner', owner, 'victim'));
  row.appendChild(mk('Marqueur', marker, 'donnée privée de la victime', 'preuve : présence dans la réponse de l\'attaquant.'));
  const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'k-theme danger'; rm.textContent = 'Retirer';
  rm.onclick = () => row.remove(); row.appendChild(rm);
  container.appendChild(row);
}

// éditeur structuré du contexte auth (operator). Overlay custom (lignes répétables) — DOM 100% sûr.
export async function engagementAuthModal(e) {
  const cur = (e && e.auth) || {};
  const seedAccounts = Array.isArray(cur.accounts) ? cur.accounts : [];
  const seedTargets = Array.isArray(cur.idor_targets) ? cur.idor_targets : [];
  const prevFocus = document.activeElement;
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal wide';
  box.setAttribute('role', 'dialog'); box.setAttribute('aria-modal', 'true');
  const form = document.createElement('form');

  const h = document.createElement('h3'); h.textContent = 'Contexte d\'authentification — ' + (e.name || ('#' + e.id)); form.appendChild(h);
  const msg = document.createElement('p'); msg.className = 'modal-msg';
  msg.textContent = 'Comptes de test de L\'OPÉRATEUR (attacker/victim) + cibles idor. La session de l\'attaquant est rejouée '
    + 'contre chaque cible ; un marqueur de la victime dans sa réponse prouve un accès/takeover cross-compte (oracles IDOR & ATO). '
    + 'Secrets jamais réaffichés : ressaisir un champ pour le conserver, le laisser vide efface ce matériel. Le périmètre (in/out) est inchangé.';
  form.appendChild(msg);

  const accHead = document.createElement('div'); accHead.className = 'auth-sec-head';
  const accTitle = document.createElement('b'); accTitle.textContent = 'Comptes'; accHead.appendChild(accTitle);
  const accAdd = document.createElement('button'); accAdd.type = 'button'; accAdd.className = 'k-theme'; accAdd.textContent = '+ Compte';
  const accBox = document.createElement('div'); accBox.className = 'auth-rows';
  accAdd.onclick = () => _acctRow(accBox, null); accHead.appendChild(accAdd); form.appendChild(accHead); form.appendChild(accBox);

  const tgtHead = document.createElement('div'); tgtHead.className = 'auth-sec-head';
  const tgtTitle = document.createElement('b'); tgtTitle.textContent = 'Cibles idor'; tgtHead.appendChild(tgtTitle);
  const tgtAdd = document.createElement('button'); tgtAdd.type = 'button'; tgtAdd.className = 'k-theme'; tgtAdd.textContent = '+ Cible';
  const tgtBox = document.createElement('div'); tgtBox.className = 'auth-rows';
  tgtAdd.onclick = () => _tgtRow(tgtBox, null); tgtHead.appendChild(tgtAdd); form.appendChild(tgtHead); form.appendChild(tgtBox);

  seedAccounts.forEach(a => _acctRow(accBox, a));
  seedTargets.forEach(t => _tgtRow(tgtBox, t));
  if (!seedAccounts.length) { _acctRow(accBox, null); _acctRow(accBox, null); }
  if (!seedTargets.length) _tgtRow(tgtBox, null);

  const err = document.createElement('div'); err.className = 'modal-err'; err.hidden = true; form.appendChild(err);
  const act = document.createElement('div'); act.className = 'modal-act';
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'm-cancel'; cancel.textContent = 'Annuler';
  const ok = document.createElement('button'); ok.type = 'submit'; ok.className = 'm-ok'; ok.textContent = 'Enregistrer';
  act.appendChild(cancel); act.appendChild(ok); form.appendChild(act);
  box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);

  const onKey = ev => { if (ev.key === 'Escape') close(); };
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); if (prevFocus && prevFocus.focus) { try { prevFocus.focus(); } catch (x) {} } };
  document.addEventListener('keydown', onKey);
  cancel.onclick = close;
  ov.onclick = ev => { if (ev.target === ov) close(); };

  form.onsubmit = ev => {
    ev.preventDefault();
    // COLLECTE (aucun secret dans un log/URL : tout reste en corps POST, champs password).
    const accounts = [];
    accBox.querySelectorAll('.auth-row').forEach(r => {
      const g = k => (r.querySelector('[data-k="' + k + '"]') || {}).value || '';
      const label = String(g('label')).trim();
      const bearer = String(g('bearer'));
      const cookies = String(g('cookies')).trim();
      const headers = _parseHeaderLines(g('headers'));
      const acc = { label };
      let has = false;
      if (bearer.trim()) { acc.bearer = bearer; has = true; }
      if (cookies) { acc.cookies = cookies; has = true; }
      if (Object.keys(headers).length) { acc.headers = headers; has = true; }
      if (label && has) accounts.push(acc);          // un compte sans matériel est ignoré (le serveur le drop aussi)
    });
    const idor_targets = [];
    tgtBox.querySelectorAll('.auth-row').forEach(r => {
      const g = k => (r.querySelector('[data-k="' + k + '"]') || {}).value || '';
      const url = String(g('url')).trim();
      if (!url) return;
      idor_targets.push({ url, owner: String(g('owner')).trim(), marker: String(g('marker')).trim() });
    });
    // scope_json COMPLET (préserve mode/in/out de l'engagement) + auth OMIS si vide (=> no-op serveur).
    const scope_json = { mode: e.mode || 'grey', in_scope: Array.isArray(e.in_scope) ? e.in_scope : [], out_scope: Array.isArray(e.out_scope) ? e.out_scope : [] };
    if (accounts.length || idor_targets.length) scope_json.auth = { accounts, idor_targets };
    close();
    engagementMutate(e.id, { scope_json }, (accounts.length || idor_targets.length) ? 'Contexte auth enregistré (secrets rédigés côté moteur).' : 'Contexte auth vidé.');
  };
  setTimeout(() => { const f = form.querySelector('input,textarea'); if (f) f.focus(); }, 30);
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
    mkBtn('Auth', 'k-theme', 'Contexte d\'authentification (comptes de test + cibles IDOR/ATO) — operator', () => engagementAuthModal(e));
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
