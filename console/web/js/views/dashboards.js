import { api, write } from '../core/api.js';
import { $, esc, ic, raw } from '../core/dom.js';
import { currentFrom, currentTo, runQuery, vizElement } from './explore.js';
import { confirmModal, modal, toast } from '../core/ui.js';

export let editing = false, panelCards = [], dashList = [];
export const tileBasis = c => 'calc(' + (Math.max(1, Math.min(4, c)) * 25) + '% - 12px)';
export function refreshPanels() { panelCards.forEach(c => { if (c.isConnected && c._panel) c._panel.reload(); }); }
export const VIZOPTS = [{ value: 'table', label: 'Table' }, { value: 'bar', label: 'Barres' }, { value: 'line', label: 'Courbe' }, { value: 'stat', label: 'Stat' }];

// --- préférences d'affichage client-side (cols/collapse par dashboard) — le backend n'a pas ces colonnes ---
export function dashPrefs() { try { return JSON.parse(localStorage.getItem('forge_dash_prefs') || '{}') || {}; } catch (e) { return {}; } }
export function dashPref(id) { return dashPrefs()[id] || {}; }
export function setDashPref(id, upd) { const all = dashPrefs(); all[id] = { ...(all[id] || {}), ...upd }; try { localStorage.setItem('forge_dash_prefs', JSON.stringify(all)); } catch (e) {} }

// --- vues = collections locales de dashboards (id) — pas d'endpoint backend ---
export function viewStore() { try { return JSON.parse(localStorage.getItem('forge_dash_views') || '{}') || {}; } catch (e) { return {}; } }
export function saveViewStore(v) { try { localStorage.setItem('forge_dash_views', JSON.stringify(v)); } catch (e) {} }

// PATCH d'un panneau (POST /api/panels/:id). Autorisé par la SESSION (admin|operator) — aucun token à
// coller. Le backend connaît name/query/viz/descr/col_span/position/dashboard_id.
export async function patchPanel(id, upd) {
  const r = await write('/api/panels/' + id, { body: upd, auth: 'admin' });
  if (r.status === 401 || r.status === 403) toast('Édition réservée à une session admin/operator — connectez-vous.', 'bad');
  return r;
}
// PATCH d'un dashboard (POST /api/dashboards/:id). Autorisé par la SESSION (admin|operator). Champs
// backend : name/descr/position.
export async function patchDash(id, upd) {
  const r = await write('/api/dashboards/' + id, { body: upd, auth: 'admin' });
  if (r.status === 401 || r.status === 403) toast('Édition réservée à une session admin/operator — connectez-vous.', 'bad');
  return r;
}
// crée un panneau dans le dashboard `did` (défaut 1). dashboard_id doit exister (sinon 400 unknown_dashboard).
export async function createPanelModal(did = 1, query = '') {
  const r = await modal({
    title: 'Nouveau panneau', okText: 'Créer', fields: [
      { name: 'name', label: 'Titre', required: true, value: 'Panneau' },
      { name: 'query', label: 'Requête (soql)', type: 'textarea', required: true, value: query, placeholder: 'search severity=HIGH | stats count by mitre | sort -count' },
      { name: 'viz', label: 'Visualisation', type: 'select', value: 'table', options: VIZOPTS },
      { name: 'descr', label: 'Description (optionnel)', value: '' },
    ],
  });
  if (!r) return;
  const body = { name: r.name.trim(), query: r.query.trim(), viz: r.viz, descr: r.descr, col_span: 1, position: 999 };
  if (did && Number(did) !== 1) body.dashboard_id = Number(did);   // 1 = défaut (omis pour rétro-compat)
  const resp = await write('/api/panels', { body, auth: 'admin' });
  const j = resp.json;
  if (!resp.ok) { toast(resp.status === 401 || resp.status === 403 ? 'Création réservée à une session admin/operator — connectez-vous.' : ('Erreur : ' + (j.error || resp.status)), 'bad'); return; }
  toast('Panneau créé', 'ok');
  loadDashboards();
}
// réordonne les panneaux d'une grille (place `from` avant/après `target`) et persiste les positions.
export function reorderPanels(grid, fromId, targetId, after) {
  const panels = () => [...grid.children].filter(c => c.classList && c.classList.contains('panel'));
  const cards = panels();
  const fromCard = cards.find(c => c._panelId === fromId), targetCard = cards.find(c => c._panelId === targetId);
  if (!fromCard || !targetCard || fromCard === targetCard) return;
  grid.insertBefore(fromCard, after ? targetCard.nextSibling : targetCard);
  panels().forEach((c, i) => patchPanel(c._panelId, { position: i }));
}
export function renderPanel(p) {
  const card = document.createElement('section'); card.className = 'card panel'; card._panelId = p.id;
  const head = document.createElement('div'); head.className = 'panelhead';
  const pgrip = document.createElement('span'); pgrip.className = 'pgrip editonly'; pgrip.innerHTML = ic('grip'); pgrip.title = 'Glisser pour déplacer le panneau'; pgrip.draggable = true;
  const t = document.createElement('h3'); t.textContent = p.name;
  const tools = document.createElement('div'); tools.className = 'paneltools';
  let curViz = p.viz || 'table';
  const seg = document.createElement('div'); seg.className = 'seg'; seg.setAttribute('role', 'group'); seg.setAttribute('aria-label', 'Visualisation');
  const btns = {};
  const VIZIC = { table: 'table', bar: 'bars', line: 'activity', stat: 'hash' };
  [['table', 'Table'], ['bar', 'Barres'], ['line', 'Courbe'], ['stat', 'Stat']].forEach(([m, lab]) => {
    const b = document.createElement('button'); b.innerHTML = ic(VIZIC[m]); b.title = lab; b.setAttribute('aria-label', lab);
    if (m === curViz) b.classList.add('on');
    b.onclick = () => { curViz = m; Object.values(btns).forEach(x => x.classList.remove('on')); b.classList.add('on'); draw(); patchPanel(p.id, { viz: m }); };
    btns[m] = b; seg.appendChild(b);
  });
  const open = document.createElement('button'); open.className = 'picon'; open.innerHTML = ic('ext'); open.title = 'Ouvrir dans Explore';
  open.onclick = () => { $('#sql').value = p.query; location.hash = 'explore'; runQuery(); };
  const edit = document.createElement('button'); edit.className = 'picon editonly'; edit.innerHTML = ic('pencil'); edit.title = 'Éditer le panneau';
  const del = document.createElement('button'); del.className = 'picon editonly'; del.innerHTML = ic('x'); del.title = 'Supprimer le panneau';
  del.onclick = async () => { if (await confirmModal('Supprimer ce panneau ?', { danger: true })) { await write('/api/panels/' + p.id, { method: 'DELETE', auth: 'admin' }); loadDashboards(); } };
  const wsel = document.createElement('select'); wsel.className = 'picon editonly'; wsel.title = 'Largeur (colonnes)';
  [1, 2, 3, 4].forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + ' col'; wsel.appendChild(o); });
  wsel.value = String(p.col_span || 1);
  wsel.onchange = () => { const n = Number(wsel.value); card.style.flexBasis = tileBasis(n); patchPanel(p.id, { col_span: n }); };
  tools.appendChild(seg);
  tools.appendChild(open);
  tools.append(wsel, edit, del);
  head.append(pgrip, t, tools); card.appendChild(head);
  // drag réordonner (mode édition)
  pgrip.addEventListener('dragstart', e => { if (!editing) { e.preventDefault(); return; } e.dataTransfer.setData('text/plain', 'panel:' + p.id); e.dataTransfer.effectAllowed = 'move'; card.classList.add('dragging'); });
  pgrip.addEventListener('dragend', () => card.classList.remove('dragging'));
  card.addEventListener('dragover', e => { if (!editing) return; e.preventDefault(); e.stopPropagation(); card.classList.add('dragover'); });
  card.addEventListener('dragleave', () => card.classList.remove('dragover'));
  card.addEventListener('drop', e => {
    e.preventDefault(); e.stopPropagation(); card.classList.remove('dragover');
    if (!editing) return;
    const dt = e.dataTransfer.getData('text/plain');
    if (!dt.startsWith('panel:')) return;
    const fromId = Number(dt.slice(6));
    if (fromId && fromId !== p.id && card.parentElement) {
      const r = card.getBoundingClientRect();
      reorderPanels(card.parentElement, fromId, p.id, (e.clientX - r.left) > r.width / 2);
    }
  });
  card.style.flexBasis = tileBasis(p.col_span || 1);
  const qline = document.createElement('code'); qline.className = 'panelq';
  qline.textContent = p.query + (p.descr ? '  — ' + p.descr : '');
  card.appendChild(qline);
  // formulaire d'édition (titre / requête / viz / dashboard cible / description)
  const ef = document.createElement('form'); ef.className = 'ruleform'; ef.hidden = true;
  ef.innerHTML = `<input class="pe-title" placeholder="titre"><textarea class="pe-query" rows="2" spellcheck="false"></textarea>`
    + `<div class="rf-row"><label>Viz <select class="pe-viz"><option value="table">Table</option><option value="bar">Barres</option><option value="line">Courbe</option><option value="stat">Stat</option></select></label>`
    + `<label>Dashboard <select class="pe-dash"></select></label></div>`
    + `<label class="pe-drill-l">Requête au clic / drill (vide = défaut) <textarea class="pe-drill" rows="2" spellcheck="false" placeholder="search mitre=$value | table ts,target,title,severity"></textarea></label>`
    + `<div class="rf-hint">Marqueurs au clic : $value (valeur cliquée, mise entre guillemets) ; $from / $to (bornes du bucket). Le drill est local à la session (non persisté côté serveur).</div>`
    + `<input class="pe-descr" placeholder="description (optionnel)">`
    + `<div class="rf-actions"><button type="submit">Enregistrer</button><button type="button" class="pe-cancel">Annuler</button></div>`;
  ef.querySelector('.pe-title').value = p.name; ef.querySelector('.pe-query').value = p.query; ef.querySelector('.pe-viz').value = curViz;
  // sélecteur de dashboard cible : déplacer le panneau via dashboard_id (POST /api/panels/:id)
  const dsel = ef.querySelector('.pe-dash');
  (dashList.length ? dashList : [{ id: 1, name: 'Défaut' }]).forEach(d => { const o = document.createElement('option'); o.value = d.id; o.textContent = d.name; dsel.appendChild(o); });
  dsel.value = String(p.dashboard_id || 1);
  ef.querySelector('.pe-drill').value = p._drill || '';
  ef.querySelector('.pe-descr').value = p.descr || '';
  edit.onclick = () => { ef.hidden = !ef.hidden; };
  ef.querySelector('.pe-cancel').onclick = () => { ef.hidden = true; };
  ef.onsubmit = async (e) => {
    e.preventDefault();
    const q = ef.querySelector('.pe-query').value.trim();
    p._drill = ef.querySelector('.pe-drill').value.trim();   // drill : client-side seulement (pas de colonne backend)
    const upd = { name: ef.querySelector('.pe-title').value.trim() || 'Panneau', query: q, viz: ef.querySelector('.pe-viz').value, descr: ef.querySelector('.pe-descr').value.trim() };
    const newDash = Number(dsel.value) || 1;
    if (newDash !== (p.dashboard_id || 1)) upd.dashboard_id = newDash;   // assigner à un autre dashboard
    const r = await patchPanel(p.id, upd);
    if (!r.ok) { toast('Erreur : ' + (r.json.error || r.status), 'bad'); return; }
    loadDashboards();
  };
  card.appendChild(ef);
  const body = document.createElement('div'); body.className = 'panelbody'; body.textContent = '...'; card.appendChild(body);
  if (p._height > 0) { body.style.height = p._height + 'px'; body.style.maxHeight = 'none'; }
  let lastH = p._height || 0;
  if ('ResizeObserver' in window) {
    new ResizeObserver(() => {
      if (!editing) return;
      const h = Math.round(body.clientHeight);
      if (h && Math.abs(h - lastH) > 8) { lastH = h; p._height = h; }   // hauteur : client-side (pas de persistance backend)
    }).observe(body);
  }
  // poignée de coin -> resize libre (hauteur px + largeur calée 1-4 col, persistée via col_span)
  const corner = document.createElement('div'); corner.className = 'rcorner editonly'; corner.title = 'Redimensionner (glisser)';
  card.appendChild(corner);
  corner.onmousedown = e => {
    e.preventDefault();
    const y0 = e.clientY, h0 = body.clientHeight, grid = card.parentElement;
    const slot = grid ? grid.clientWidth / 4 : 240;
    const left = card.getBoundingClientRect().left;
    const mv = ev => {
      body.style.maxHeight = 'none';
      body.style.height = Math.max(120, h0 + ev.clientY - y0) + 'px';
      const ncols = Math.max(1, Math.min(4, Math.round((ev.clientX - left) / slot)));
      card.style.flexBasis = tileBasis(ncols); card.dataset.cols = ncols;
    };
    const up = () => {
      document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up);
      const ncols = Number(card.dataset.cols) || (p.col_span || 1);
      if (wsel) wsel.value = String(ncols);
      p._height = Math.round(body.clientHeight);
      patchPanel(p.id, { col_span: ncols });
    };
    document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
  };
  let result = null;
  function draw() {
    if (!result) return;
    if (!result.rows.length) { body.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune donnée' })); return; }
    body.replaceChildren(vizElement(curViz, result.columns, result.rows, p.query, p._drill || ''));
  }
  async function load() {
    try {
      const from = currentFrom() || 0, to = currentTo() || 0;
      const r = await fetch(`/api/panels/${p.id}/data?from=${from}&to=${to}`);
      const j = await r.json();
      if (!r.ok || j.error) body.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + (j.error || r.status) }));
      else { result = { columns: j.columns, rows: j.rows }; draw(); }
    } catch (e) { body.textContent = 'erreur : ' + e.message; }
  }
  card._panel = { reload: load };
  load();
  return card;
}

// rend une TUILE-dashboard : en-tête (plier + poignée + titre + meta + outils) + grille de ses panneaux.
export function renderDashboard(d) {
  const pref = dashPref(d.id);
  const tile = document.createElement('section'); tile.className = 'dashtile card2'; tile.dataset.id = d.id; tile._dashId = d.id;
  const cols = Math.max(1, Math.min(4, pref.cols || 2));
  tile.style.flexBasis = tileBasis(cols);
  const collapsed = !!pref.collapsed;
  if (collapsed) tile.classList.add('collapsed');
  const head = document.createElement('div'); head.className = 'dashtile-head';
  const chev = document.createElement('button'); chev.type = 'button'; chev.className = 'chev picon'; chev.title = 'Plier / déplier'; chev.innerHTML = ic(collapsed ? 'chevright' : 'chevdown');
  const grip = document.createElement('span'); grip.className = 'grip editonly'; grip.innerHTML = ic('grip'); grip.title = 'Glisser l\'en-tête pour réordonner';
  const h = document.createElement('h3'); h.textContent = d.name;
  const meta = document.createElement('span'); meta.className = 'dashmeta'; meta.textContent = `${d.panels} panneau(x)` + (d.descr ? ' — ' + d.descr : '');
  const tools = document.createElement('div'); tools.className = 'paneltools';
  const addp = document.createElement('button'); addp.type = 'button'; addp.className = 'picon'; addp.innerHTML = ic('plus'); addp.title = 'Ajouter un panneau';
  const ren = document.createElement('button'); ren.type = 'button'; ren.className = 'picon editonly'; ren.innerHTML = ic('pencil'); ren.title = 'Renommer le dashboard';
  const wsel = document.createElement('select'); wsel.className = 'picon editonly'; wsel.title = 'Largeur de la tuile (colonnes — affichage local)';
  [1, 2, 3, 4].forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + ' col'; wsel.appendChild(o); });
  wsel.value = String(cols);
  const del = document.createElement('button'); del.type = 'button'; del.className = 'picon editonly'; del.innerHTML = ic('x'); del.title = (d.id === 1 ? 'Le dashboard par défaut ne peut pas être supprimé' : 'Supprimer le dashboard');
  if (d.id === 1) del.disabled = true;
  tools.append(addp, ren, wsel, del);
  head.append(chev, grip, h, meta, tools);
  tile.appendChild(head);
  const tbody = document.createElement('div'); tbody.className = 'dashtile-body';
  const grid = document.createElement('div'); grid.className = 'dashgrid'; grid.textContent = '...'; tbody.appendChild(grid);
  tile.appendChild(tbody);
  if (pref.height > 0) { tbody.style.height = pref.height + 'px'; tbody.style.overflow = 'auto'; }
  loadPanelsInto(grid, d);
  chev.onclick = () => {
    const c = !tile.classList.contains('collapsed');
    tile.classList.toggle('collapsed', c); chev.innerHTML = ic(c ? 'chevright' : 'chevdown');
    setDashPref(d.id, { collapsed: c });   // pli : préférence locale (le backend n'a pas ce champ)
  };
  addp.onclick = () => createPanelModal(d.id);
  ren.onclick = async () => {
    const r = await modal({
      title: 'Renommer le dashboard', okText: 'Enregistrer', fields: [
        { name: 'name', label: 'Nom', required: true, value: d.name },
        { name: 'descr', label: 'Description (optionnel)', value: d.descr || '' },
      ], validate: v => dashList.some(x => x.id !== d.id && x.name === v.name.trim()) ? 'Un dashboard porte déjà ce nom.' : null,
    });
    if (!r) return;
    const resp = await patchDash(d.id, { name: r.name.trim(), descr: r.descr.trim() });
    if (!resp.ok) { toast('Erreur : ' + (resp.json.error || resp.status), 'bad'); return; }
    loadDashboards();
  };
  wsel.onchange = () => { const n = Number(wsel.value); tile.style.flexBasis = tileBasis(n); setDashPref(d.id, { cols: n }); };
  del.onclick = async () => {
    if (d.id === 1) return;   // garde-fou : dashboard par défaut protégé (409 côté serveur de toute façon)
    if (!await confirmModal('Supprimer ce dashboard ? Ses panneaux seront réassignés au dashboard par défaut.', { danger: true })) return;
    const resp = await write('/api/dashboards/' + d.id, { method: 'DELETE', auth: 'admin' });
    const j = resp.json;
    if (!resp.ok) {
      const authErr = resp.status === 401 || resp.status === 403;
      toast(j.error === 'default_protected' ? 'Le dashboard par défaut ne peut pas être supprimé.'
        : authErr ? 'Suppression réservée à une session admin/operator — connectez-vous.'
        : ('Erreur : ' + (j.error || resp.status)), 'bad');
      return;
    }
    // retirer ce dashboard des collections de vues locales
    const vs = viewStore(); let changed = false;
    Object.keys(vs).forEach(k => { const i = (vs[k].ids || []).indexOf(d.id); if (i >= 0) { vs[k].ids.splice(i, 1); changed = true; } });
    if (changed) saveViewStore(vs);
    toast('Dashboard supprimé (panneaux réassignés au #1).', 'ok');
    loadDashboards(); loadViews();
  };
  // coin de redimensionnement (hauteur du corps + largeur 1-4 col) — préférence locale
  const corner = document.createElement('div'); corner.className = 'dcorner editonly'; corner.title = 'Redimensionner (glisser)';
  tile.appendChild(corner);
  corner.onmousedown = e => {
    e.preventDefault();
    const y0 = e.clientY, h0 = tbody.clientHeight || tbody.scrollHeight, gw = tile.parentElement;
    const slot = gw ? gw.clientWidth / 4 : 320;
    const left = tile.getBoundingClientRect().left;
    let ncols = cols, nh = h0;
    const mv = ev => {
      nh = Math.max(120, h0 + ev.clientY - y0); tbody.style.height = nh + 'px'; tbody.style.overflow = 'auto';
      ncols = Math.max(1, Math.min(4, Math.round((ev.clientX - left) / slot)));
      tile.style.flexBasis = tileBasis(ncols); wsel.value = String(ncols);
    };
    const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); setDashPref(d.id, { cols: ncols, height: Math.round(nh) }); };
    document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
  };
  // glisser-déposer pour réordonner les tuiles (mode édition ; poignée = en-tête) — persiste position
  head.draggable = true;
  head.addEventListener('dragstart', e => { if (!editing) { e.preventDefault(); return; } e.dataTransfer.setData('text/plain', 'dash:' + d.id); e.dataTransfer.effectAllowed = 'move'; tile.classList.add('dragging'); });
  head.addEventListener('dragend', () => tile.classList.remove('dragging'));
  tile.addEventListener('dragover', e => {
    if (!editing) return;
    e.preventDefault(); tile.classList.add('dragover');   // type de drag non lisible en dragover : on filtre au drop
  });
  tile.addEventListener('dragleave', () => tile.classList.remove('dragover'));
  tile.addEventListener('drop', e => {
    tile.classList.remove('dragover');
    if (!editing) return;
    const raw = e.dataTransfer.getData('text/plain');
    if (!raw.startsWith('dash:')) return;   // un drop de panneau est géré par la carte panneau
    e.preventDefault();
    const from = Number(raw.slice(5));
    if (from && from !== d.id) reorderDash(from, d.id);
  });
  return tile;
}
// charge les panneaux d'UN dashboard (GET /api/panels?dashboard_id=N) dans sa grille.
export async function loadPanelsInto(grid, d) {
  let panels = [];
  try { panels = await (await fetch('/api/panels?dashboard_id=' + d.id)).json(); }
  catch (e) { grid.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'erreur : ' + e.message })); return; }
  if (!Array.isArray(panels)) panels = [];
  if (!panels.length) {
    const es = document.createElement('div'); es.className = 'emptystate';
    es.append(Object.assign(document.createElement('div'), { textContent: 'Dashboard vide.' }));
    const b = document.createElement('button'); b.textContent = '+ Ajouter un panneau'; b.onclick = () => createPanelModal(d.id); es.appendChild(b);
    grid.replaceChildren(es); return;
  }
  // préserve les états client-side (drill/height) entre rechargements
  const prev = {}; panelCards.forEach(c => { if (c._panelId != null && c._srcPanel) prev[c._panelId] = c._srcPanel; });
  const cards = panels.map(p => { if (prev[p.id]) { p._drill = prev[p.id]._drill; p._height = prev[p.id]._height; } const c = renderPanel(p); c._srcPanel = p; return c; });
  cards.forEach(c => panelCards.push(c));
  grid.replaceChildren(...cards);
}
// réordonne les tuiles-dashboards (place `from` avant `target`) et persiste les positions (POST /api/dashboards/:id).
export function reorderDash(fromId, targetId) {
  const arr = dashList.slice();
  const fi = arr.findIndex(x => x.id === fromId);
  if (fi < 0) return;
  const [m] = arr.splice(fi, 1);
  const ti = arr.findIndex(x => x.id === targetId);
  arr.splice(ti < 0 ? arr.length : ti, 0, m);
  arr.forEach((x, i) => { if (x.position !== i) { x.position = i; patchDash(x.id, { position: i }); } });
  dashList = arr; renderDashboards();
}
// rend toutes les tuiles-dashboards de la vue courante (filtre client-side via la collection sélectionnée).
export function renderDashboards() {
  const host = $('#dashview'); if (!host) return;
  panelCards = [];
  host.replaceChildren();
  host.classList.toggle('editing', editing);
  // filtre de vue (collection locale d'ids) ; vide = tous les dashboards.
  const viewId = $('#view') ? $('#view').value : '';
  let list = dashList;
  if (viewId) { const vs = viewStore(); const ids = (vs[viewId] && vs[viewId].ids) || []; list = dashList.filter(d => ids.includes(d.id)); }
  if (!list.length) {
    const es = document.createElement('div'); es.className = 'emptystate muted';
    es.append(Object.assign(document.createElement('div'), { textContent: viewId ? 'Aucun dashboard dans cette vue. Édite la vue pour y ajouter des dashboards.' : 'Aucun dashboard. Clique « + Dashboard ».' }));
    if (!viewId) { const b = document.createElement('button'); b.textContent = '+ Dashboard'; b.onclick = () => $('#dash-new') && $('#dash-new').click(); es.appendChild(b); }
    host.replaceChildren(es); return;
  }
  list.forEach(d => host.appendChild(renderDashboard(d)));
}
// charge la liste des dashboards (GET /api/dashboards) puis rend les tuiles.
export async function loadDashboards() {
  const host = $('#dashview'); if (!host) return;
  let list = [];
  try { list = await (await fetch('/api/dashboards')).json(); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  dashList = Array.isArray(list) ? list : [];
  loadViews();          // (re)peuple le sélecteur de vues (collections locales) — préserve la sélection
  renderDashboards();
}

// --- vues = collections locales de dashboards ---
export function loadViews() {
  const sel = $('#view'); if (!sel) return;
  const vs = viewStore();
  const cur = sel.value;
  sel.replaceChildren();
  const all = document.createElement('option'); all.value = ''; all.textContent = 'Tous les dashboards'; sel.appendChild(all);
  Object.keys(vs).sort((a, b) => (vs[a].name || a).localeCompare(vs[b].name || b)).forEach(id => {
    const o = document.createElement('option'); o.value = id; o.textContent = `${vs[id].name || id} (${(vs[id].ids || []).length})`; sel.appendChild(o);
  });
  if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
}
// crée / édite une vue (collection) : choisit son nom + les dashboards membres (cases).
export async function viewModal(viewId) {
  const vs = viewStore();
  const existing = viewId ? (vs[viewId] || {}) : {};
  const memberSet = new Set(existing.ids || []);
  const r = await modal({
    title: viewId ? 'Éditer la vue' : 'Nouvelle vue', okText: viewId ? 'Enregistrer' : 'Créer', wide: true,
    fields: [
      { name: 'name', label: 'Nom de la vue', required: true, value: existing.name || '' },
      ...dashList.map(d => ({ name: 'd_' + d.id, label: d.name, type: 'checkbox', value: memberSet.has(d.id) })),
    ],
    validate: v => {
      const nm = (v.name || '').trim();
      const dup = Object.keys(vs).some(k => k !== viewId && (vs[k].name || '').trim() === nm);
      return dup ? 'Une vue porte déjà ce nom.' : null;
    },
  });
  if (!r) return;
  const ids = dashList.filter(d => r['d_' + d.id]).map(d => d.id);
  const store = viewStore();
  const id = viewId || ('v' + Date.now().toString(36));
  store[id] = { name: r.name.trim(), ids };
  saveViewStore(store);
  loadViews();
  if ($('#view')) $('#view').value = id;
  renderDashboards();
  toast(viewId ? 'Vue mise à jour' : 'Vue créée', 'ok');
}

if ($('#dash-new')) $('#dash-new').addEventListener('click', async () => {
  const r = await modal({
    title: 'Nouveau dashboard', okText: 'Créer', fields: [
      { name: 'name', label: 'Nom', required: true, placeholder: 'ex: Couverture offensive' },
      { name: 'descr', label: 'Description (optionnel)', value: '' },
    ], validate: v => dashList.some(d => d.name === v.name.trim()) ? 'Un dashboard porte déjà ce nom.' : null,
  });
  if (!r) return;
  const resp = await write('/api/dashboards', { body: { name: r.name.trim(), descr: r.descr.trim(), position: dashList.length }, auth: 'admin' });
  const j = resp.json;
  if (!resp.ok) { toast(resp.status === 401 || resp.status === 403 ? 'Création réservée à une session admin/operator — connectez-vous.' : ('Erreur : ' + (j.error || resp.status)), 'bad'); return; }
  toast('Dashboard créé', 'ok');
  loadDashboards();
});
if ($('#dash-edit')) $('#dash-edit').addEventListener('click', () => {
  editing = !editing;
  const v = $('#dashview'); if (v) v.classList.toggle('editing', editing);
  $('#dash-edit').classList.toggle('on', editing);
});
if ($('#view')) $('#view').addEventListener('change', renderDashboards);
if ($('#view-new')) $('#view-new').addEventListener('click', () => viewModal(null));
if ($('#view-rename')) {
  $('#view-rename').innerHTML = ic('pencil');
  $('#view-rename').addEventListener('click', () => {
    const id = $('#view') && $('#view').value;
    if (!id) { toast('Sélectionne une vue à éditer (pas « Tous les dashboards »).', 'bad'); return; }
    viewModal(id);
  });
}
if ($('#view-del')) {
  $('#view-del').innerHTML = ic('x');
  $('#view-del').addEventListener('click', async () => {
    const sel = $('#view'); const id = sel && sel.value;
    if (!id) { toast('Sélectionne une vue à supprimer.', 'bad'); return; }
    if (!await confirmModal('Supprimer cette vue ? Les dashboards sont conservés (seule la collection est supprimée).', { danger: true })) return;
    const vs = viewStore(); delete vs[id]; saveViewStore(vs);
    sel.value = ''; loadViews(); renderDashboards();
    toast('Vue supprimée', 'ok');
  });
}
// « Panneau » depuis Explore : enregistre la requête dans un dashboard (choisi si plusieurs).
if ($('#save-panel')) $('#save-panel').addEventListener('click', async () => {
  const q = $('#sql').value.trim(); if (!q) { toast("Écris une requête d'abord.", 'bad'); return; }
  let did = 1;
  if (dashList.length > 1) {
    const r = await modal({ title: 'Ajouter le panneau à', okText: 'Continuer', fields: [{ name: 'did', label: 'Dashboard', type: 'select', value: '1', options: dashList.map(d => ({ value: String(d.id), label: d.name })) }] });
    if (!r) return; did = Number(r.did) || 1;
  } else if (dashList.length === 1) { did = dashList[0].id; }
  createPanelModal(did, q);
});

