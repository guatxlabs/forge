// Forge — console (front Aurora). Porte la richesse de Plume (viz/explore/dashboards drag+resize,
// modales/toasts, drilldown/zoom) et l'adapte aux endpoints réels du moteur Forge.
//   lectures : /api/overview-like agrégées via /api/findings|modules|coverage|campaigns|roe|ledger
//   requêtes : POST /api/query {soql} -> {columns, rows[[...]], total, stats, compiled}
//   panels   : /api/panels (POST/POST :id/DELETE :id : Bearer token) + /api/panels/:id/data
const $ = s => document.querySelector(s);
// lit une variable de thème CSS (graphes SVG theme-aware : se recolorent au changement clair/sombre)
const CSSV = (n, d) => (getComputedStyle(document.documentElement).getPropertyValue(n).trim() || d);
const LANG = 'fr';
const LOC = 'fr-FR';
const fmtTs = t => {                                   // ts Forge = chaîne SQLite "YYYY-MM-DD HH:MM:SS" (UTC) OU epoch
  if (t == null || t === '') return '-';
  if (typeof t === 'number' || /^\d+$/.test(String(t))) { const n = Number(t); return new Date((n > 2e10 ? n : n * 1000)).toLocaleString(LOC); }
  const d = new Date(String(t).replace(' ', 'T') + (String(t).includes('Z') ? '' : 'Z'));
  return isNaN(d.getTime()) ? String(t) : d.toLocaleString(LOC);
};
// sévérités Forge = chaînes (CRITICAL/HIGH/MEDIUM/LOW/INFO). On les normalise pour les classes CSS.
const SEVKEY = s => { const u = String(s || '').toUpperCase(); return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(u) ? u : 'INFO'; };
const SEVRANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
// --- icônes SVG inline (zéro caractère non-ASCII dans l'UI ; héritent la couleur via currentColor) ---
const ICONS = {
  home: '<path d="M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>',
  flask: '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3"/><path d="M7 14h10"/>',
  layout: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  wrench: '<path d="M21 4a5 5 0 0 1-6 6L7 18l-3-3 8-8a5 5 0 0 1 6-6l-3 3 2 2z"/>',
  bell: '<path d="M6 9a6 6 0 0 1 12 0c0 7 3 7 3 7H3s3 0 3-7"/><path d="M10 21a2 2 0 0 0 4 0"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  plug: '<path d="M9 3v6M15 3v6M7 9h10v3a5 5 0 0 1-10 0zM12 17v4"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  save: '<path d="M5 3h11l3 3v15H5z"/><path d="M8 3v6h7M8 21v-6h8v6"/>',
  play: '<path d="M7 4l13 8-13 8z"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  pencil: '<path d="M4 20h4L20 8l-4-4L4 16z"/>',
  x: '<path d="M5 5l14 14M19 5L5 19"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M19 13v6H5V5h6"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 18h.01"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  moon: '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
  bars: '<path d="M4 20V10M10 20V4M16 20v-7M2 20h20"/>',
  hash: '<path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/>',
  table: '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 10h18M9 4v16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  chevdown: '<path d="M6 9l6 6 6-6"/>',
  chevright: '<path d="M9 6l6 6-6 6"/>',
  grip: '<circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/>',
  lock: '<rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
};
const ic = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;

// =====================================================================================
//  TOKEN (écritures panels : Bearer = l'« ingest token » affiché au démarrage du daemon)
// =====================================================================================
// Le token est lu de façon SYNCHRONE (authHeaders() est appelé dans des handlers non-async).
// S'il manque, on ne bloque pas avec un prompt() natif : on ouvre une modale in-app (asynchrone,
// dé-bouncée pour n'apparaître qu'une fois) qui mémorise le token puis invite à relancer l'action.
let _tokenAsking = false;
function promptToken() {
  if (_tokenAsking) return;
  _tokenAsking = true;
  modal({
    title: 'Token console',
    message: 'Colle l’« ingest token » affiché au démarrage du daemon (requis pour les écritures : panneaux, dashboards).',
    fields: [{ name: 'token', label: 'Token', type: 'password', required: true, placeholder: 'Bearer token' }],
    okText: 'Enregistrer',
  }).then(r => {
    _tokenAsking = false;
    if (r && r.token) { localStorage.setItem('forge_token', String(r.token).trim()); toast('Token enregistré — relance l’action.', 'ok'); }
  });
}
function token() {
  const t = localStorage.getItem('forge_token');
  if (!t) promptToken();
  return t || '';
}
function authHeaders(extra = {}) { return { Authorization: 'Bearer ' + token(), ...extra }; }

// =====================================================================================
//  API helpers
// =====================================================================================
async function api(path) {
  const r = await fetch('/api' + path, { headers: { Accept: 'application/json' } });
  const body = await r.text().catch(() => '');
  // On NE PROPAGE PAS le corps brut du serveur dans Error.message (un proxy/gateway peut renvoyer
  // du HTML non-fiable -> XSS si rendu via innerHTML en aval). On ne remonte que le code HTTP et,
  // pour une erreur JSON structurée du backend, son champ `error` (string contrôlée par nous).
  if (!r.ok) {
    let detail = '';
    try { const j = JSON.parse(body); if (j && typeof j.error === 'string') detail = ' ' + j.error; } catch (e) {}
    throw new Error('HTTP ' + r.status + detail);
  }
  if (!body) throw new Error('réponse vide du serveur');
  try { return JSON.parse(body); } catch { throw new Error('réponse non-JSON du serveur (HTTP ' + r.status + ')'); }
}
const campaignParam = () => { const c = $('#campaign') && $('#campaign').value; return c ? '?campaign=' + encodeURIComponent(c) : ''; };
const withCampaign = qs => { const c = $('#campaign') && $('#campaign').value; if (!c) return qs; return qs + (qs.includes('?') ? '&' : '?') + 'campaign=' + encodeURIComponent(c); };

// =====================================================================================
//  drilldown / historique / zoom (porté de Plume — pilote l'Explore)
// =====================================================================================
const DIMENSIONLESS = new Set(['ts', 'bucket', 'time']);
function drilldown(field, value) {
  if (value == null || value === '' || !field || DIMENSIONLESS.has(field)) return;
  histPush();
  const lit = /^-?\d+(\.\d+)?$/.test(String(value)) ? String(value) : `"${String(value).replace(/"/g, '')}"`;
  const sqlBox = $('#sql');
  if (sqlBox) sqlBox.value = `search ${field}=${lit}`;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  runQuery();
}
function drillTime(t, span) {
  histPush();
  zoomRange = { from: Math.floor(t), to: Math.ceil(t + (span || 60)) };
  updateZoomBadge();
  if ($('#sql')) $('#sql').value = 'search';
  location.hash = 'explore';
  runQuery();
}
function sanitizeVal(v) { return '"' + String(v).replace(/[|\[\]"\n\r]/g, ' ').trim() + '"'; }
function customDrill(tpl, ctx) {
  if (!tpl) return;
  histPush();
  let q = tpl;
  if (ctx.value !== undefined && ctx.value !== null) q = q.split('$value').join(sanitizeVal(ctx.value));
  const timed = ctx.from !== undefined;
  if (timed) {
    const f = Math.floor(ctx.from), t = Math.ceil(ctx.to !== undefined ? ctx.to : ctx.from + 60);
    q = q.split('$from').join(String(f)).split('$to').join(String(t));
    zoomRange = { from: f, to: t }; updateZoomBadge();
  }
  if ($('#sql')) $('#sql').value = q;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  runQuery();
}
let exploreHist = [];
function histPush() {
  const sql = $('#sql') ? $('#sql').value : '';
  if (!sql) return;
  const snap = { sql, zoom: zoomRange ? { ...zoomRange } : null };
  const t = exploreHist[exploreHist.length - 1];
  if (t && t.sql === snap.sql && JSON.stringify(t.zoom) === JSON.stringify(snap.zoom)) return;
  exploreHist.push(snap);
  if (exploreHist.length > 50) exploreHist.shift();
  histUpdateBtn();
}
function histBack() {
  const prev = exploreHist.pop();
  if (!prev) return;
  zoomRange = prev.zoom ? { ...prev.zoom } : null;
  updateZoomBadge();
  if ($('#sql')) $('#sql').value = prev.sql;
  histUpdateBtn();
  runQuery();
}
function histUpdateBtn() { const b = $('#qback'); if (b) b.hidden = exploreHist.length === 0; }
if ($('#qback')) $('#qback').addEventListener('click', histBack);
function statDrill(query, drill) {
  if (drill) return customDrill(drill, {});
  const q = (query || '').trim();
  if (!q) return;
  const target = /^\s*search\b/i.test(q) ? q.split('|')[0].trim() : q;
  if (!target) return;
  histPush();
  if ($('#sql')) $('#sql').value = target;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  runQuery();
}

// =====================================================================================
//  modales + toasts in-page (remplacent alert/confirm/prompt)
// =====================================================================================
function toast(msg, kind = 'info', ms = 3200) {
  let host = $('#toasts');
  if (!host) { host = document.createElement('div'); host.id = 'toasts'; document.body.appendChild(host); }
  const t = document.createElement('div'); t.className = 'toast ' + kind; t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 220); }, ms);
}
function showErr(form, msg) { const e = form.querySelector('.modal-err'); if (e) { e.textContent = msg; e.hidden = false; } }
function modal(opts = {}) {
  return new Promise(resolve => {
    const ov = document.createElement('div'); ov.className = 'modal-ov';
    const box = document.createElement('div'); box.className = 'modal' + (opts.danger ? ' danger' : '') + (opts.wide ? ' wide' : '');
    const form = document.createElement('form');
    let html = '';
    if (opts.title) html += `<h3>${esc(opts.title)}</h3>`;
    if (opts.message) html += `<p class="modal-msg">${esc(opts.message)}</p>`;
    (opts.fields || []).forEach(f => {
      html += `<label class="modal-f"><span>${esc(f.label || f.name)}</span>`;
      if (f.type === 'select') html += `<select data-n="${esc(f.name)}">${(f.options || []).map(o => `<option value="${esc(o.value)}"${String(o.value) === String(f.value) ? ' selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
      else if (f.type === 'checkbox') html += `<input type="checkbox" data-n="${esc(f.name)}"${f.value ? ' checked' : ''}>`;
      else if (f.type === 'textarea') html += `<textarea data-n="${esc(f.name)}" rows="2" spellcheck="false" placeholder="${esc(f.placeholder || '')}">${esc(f.value == null ? '' : f.value)}</textarea>`;
      else html += `<input type="${esc(f.type || 'text')}" data-n="${esc(f.name)}" value="${esc(f.value == null ? '' : f.value)}" placeholder="${esc(f.placeholder || '')}"${f.required ? ' required' : ''}>`;
      html += `</label>`;
    });
    html += `<div class="modal-err" hidden></div>`;
    html += `<div class="modal-act"><button type="button" class="m-cancel">${esc(opts.cancelText || 'Annuler')}</button><button type="submit" class="m-ok${opts.danger ? ' danger' : ''}">${esc(opts.okText || 'OK')}</button></div>`;
    form.innerHTML = html; box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);
    const close = val => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); resolve(val); };
    const onKey = e => { if (e.key === 'Escape') close(null); };
    document.addEventListener('keydown', onKey);
    const first = form.querySelector('input,select,textarea'); if (first) setTimeout(() => first.focus(), 30);
    form.querySelector('.m-cancel').onclick = () => close(null);
    ov.onclick = e => { if (e.target === ov) close(null); };
    form.onsubmit = e => {
      e.preventDefault();
      const vals = {}; form.querySelectorAll('[data-n]').forEach(el => { vals[el.dataset.n] = el.type === 'checkbox' ? el.checked : el.value; });
      for (const f of (opts.fields || [])) { if (f.required && !String(vals[f.name] || '').trim()) { showErr(form, `"${f.label || f.name}" est requis.`); return; } }
      if (opts.validate) { const err = opts.validate(vals); if (err) { showErr(form, err); return; } }
      close(vals);
    };
  });
}
async function confirmModal(message, opts = {}) {
  const r = await modal({ title: opts.title || 'Confirmer', message, okText: opts.okText || 'Confirmer', cancelText: opts.cancelText, danger: opts.danger !== false });
  return r !== null;
}
// modale d'info read-only (détail finding / entrée ledger) : DOM sûr (textContent).
function infoModal(title, buildBody) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal wide';
  const onKey = e => { if (e.key === 'Escape') close(); };
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  document.addEventListener('keydown', onKey);
  const h = document.createElement('h3'); h.textContent = title; box.appendChild(h);
  const body = document.createElement('div'); body.className = 'infobody'; box.appendChild(body);
  buildBody(body);
  const act = document.createElement('div'); act.className = 'modal-act';
  const cb = document.createElement('button'); cb.type = 'button'; cb.className = 'm-cancel'; cb.textContent = 'Fermer'; cb.onclick = close;
  act.appendChild(cb); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
}

// =====================================================================================
//  zoom temporel + infobulle de graphe (porté de Plume)
// =====================================================================================
let zoomRange = null; // {from,to}
function currentFrom() { return zoomRange ? zoomRange.from : 0; }
function currentTo() { return zoomRange ? zoomRange.to : 0; }
function setZoom(a, b) {
  const from = Math.floor(Math.min(a, b)), to = Math.ceil(Math.max(a, b));
  if (to - from < 1) return;
  zoomRange = { from, to }; updateZoomBadge();
  if (lastResult && $('#sql') && $('#sql').value.trim()) runQuery();
}
function clearZoom() { zoomRange = null; updateZoomBadge(); if ($('#sql') && $('#sql').value.trim()) runQuery(); }
function updateZoomBadge() {
  let el = $('#zoombadge');
  if (!el) {
    const tools = document.querySelector('.hdr-tools'); if (!tools) return;
    el = document.createElement('button'); el.id = 'zoombadge'; el.className = 'zoombadge'; el.type = 'button';
    el.title = 'Réinitialiser le zoom'; el.onclick = clearZoom; tools.insertBefore(el, tools.firstChild);
  }
  const f = t => new Date(t * 1000).toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit' });
  if (zoomRange) { el.hidden = false; el.innerHTML = `zoom ${f(zoomRange.from)}-${f(zoomRange.to)} ${ic('x')}`; }
  else el.hidden = true;
}
function attachZoom(svg, W, xToTime) {
  const NS = 'http://www.w3.org/2000/svg';
  let x0 = null, rectEl = null;
  const vbX = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
  svg.style.cursor = 'ew-resize';
  svg.addEventListener('mousedown', e => {
    x0 = vbX(e); rectEl = document.createElementNS(NS, 'rect');
    rectEl.setAttribute('y', 0); rectEl.setAttribute('height', '100%');
    rectEl.setAttribute('fill', CSSV('--acc', '#2dd4bf')); rectEl.setAttribute('opacity', '0.18');
    svg.appendChild(rectEl); e.preventDefault();
  });
  svg.addEventListener('mousemove', e => { if (x0 == null || !rectEl) return; const x1 = vbX(e); rectEl.setAttribute('x', Math.min(x0, x1)); rectEl.setAttribute('width', Math.abs(x1 - x0)); });
  const end = e => { if (x0 == null) return; const x1 = vbX(e); const a = Math.min(x0, x1), b = Math.max(x0, x1); x0 = null; if (rectEl) { rectEl.remove(); rectEl = null; } if (b - a > 4) { svg._zoomed = true; setZoom(xToTime(a), xToTime(b)); } };
  svg.addEventListener('mouseup', end); svg.addEventListener('mouseleave', end);
}
let _charttip;
function tipShow(text, e) {
  if (!_charttip) { _charttip = document.createElement('div'); _charttip.id = 'charttip'; document.body.appendChild(_charttip); }
  const t = _charttip; t.textContent = text; t.hidden = false;
  const pad = 14, w = t.offsetWidth, h = t.offsetHeight;
  let x = e.clientX + pad, y = e.clientY + pad;
  if (x + w > innerWidth) x = e.clientX - w - pad;
  if (y + h > innerHeight) y = e.clientY - h - pad;
  t.style.left = x + 'px'; t.style.top = y + 'px';
}
function tipHide() { if (_charttip) _charttip.hidden = true; }
function attachTip(svg, W, dataAt) {
  const vbX = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
  svg.addEventListener('mousemove', e => { const s = dataAt(vbX(e)); if (s) tipShow(s, e); else tipHide(); });
  svg.addEventListener('mouseleave', tipHide);
}

// =====================================================================================
//  moteur de requête + visualisations (porté de Plume, adapté Forge)
// =====================================================================================
// POST /api/query {soql} OR {q} -> {columns, rows[[...]], total, stats, compiled}
//   Contrat réel : /api/query NE prend PAS from/to/limit/offset (total = rows.length, jeu complet).
//   On ne borne PAS le temps ici (le zoom temporel est honoré côté serveur uniquement par
//   /api/panels/:id/data?from=&to=). La pagination Explore est donc faite CÔTÉ CLIENT (evLoad).
//   from/to/limit/offset sont envoyés à titre indicatif (forward-compat) mais ignorés par le backend.
async function runQ(query, isSoql, fromOverride, limit, offset) {
  const body = { soql: query };
  const f = (fromOverride !== undefined ? fromOverride : currentFrom());
  const t = currentTo();
  if (f) body.from = f;
  if (t) body.to = t;
  if (limit !== undefined && limit !== null) { body.limit = limit; body.offset = offset || 0; }
  const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
function vizElement(mode, cols, rows, query, drill) {
  if (mode === 'stat') return statEl(cols, rows, query, drill);
  if (mode === 'bar') return barEl(cols, rows, query, drill);
  if (mode === 'line') return lineEl(cols, rows, query, drill);
  return tableEl(cols, rows, query, drill);
}
// décompose une colonne `evidence`/`fields` JSON en colonnes individuelles (union des clés vues).
function expandFields(cols, rows) {
  let fi = cols.indexOf('fields');
  if (fi < 0) fi = cols.indexOf('evidence');
  if (fi < 0) return { cols, rows };
  const base = new Set(cols.filter((_, i) => i !== fi));
  const keys = [], seen = new Set();
  const parsed = rows.map(r => {
    let o = null; try { o = r[fi] ? JSON.parse(r[fi]) : null; } catch (e) { o = null; }
    if (o && typeof o === 'object' && !Array.isArray(o)) for (const k of Object.keys(o))
      if (!seen.has(k) && !base.has(k) && o[k] != null && o[k] !== '') { seen.add(k); keys.push(k); }
    return o;
  });
  if (!keys.length) return { cols, rows };
  keys.sort();
  const flat = v => (v == null ? null : (typeof v === 'object' ? JSON.stringify(v) : v));
  const ncols = []; cols.forEach((c, i) => { if (i === fi) keys.forEach(k => ncols.push(k)); else ncols.push(c); });
  const nrows = rows.map((r, ri) => {
    const o = parsed[ri] || {}, nr = [];
    cols.forEach((c, i) => { if (i === fi) keys.forEach(k => nr.push(flat(o[k]))); else nr.push(r[i]); });
    return nr;
  });
  return { cols: ncols, rows: nrows };
}
// sélecteur de colonnes : un seul menu ouvert à la fois (position:fixed pour échapper l'overflow).
let _colsMenuClose = null, _colsMenuOwner = null;
function closeColsMenu() { if (_colsMenuClose) { const f = _colsMenuClose; _colsMenuClose = null; _colsMenuOwner = null; f(); } }
function tableEl(cols, rows, query, drill) {
  ({ cols, rows } = expandFields(cols, rows));
  const last = cols.length - 1;
  const order = cols.map((_, i) => i);
  const widths = {};
  let sortIdx = -1, sortDir = 1;
  const cover = cols.map((_, i) => rows.length ? rows.reduce((n, r) => n + (r[i] != null && r[i] !== '' ? 1 : 0), 0) / rows.length : 1);
  const CORE = new Set(['ts', 'time', 'bucket', 'campaign', 'target', 'title', 'severity', 'mitre', 'status', 'message']);
  const hidden = new Set();
  if (order.length > 12) cols.forEach((c, i) => { if (!CORE.has(c) && cover[i] < 0.5) hidden.add(i); });
  const vcount = () => order.filter(oi => !hidden.has(oi)).length;
  const id = 'cm' + Math.random().toString(36).slice(2, 8);
  let colsBtn = null;
  const tbl = document.createElement('table'); tbl.className = 'qtable';
  const thead = document.createElement('thead'), tb = document.createElement('tbody');
  tbl.append(thead, tb);
  const TIMECOLS = new Set(['ts', 'time', 'bucket']);
  const fmtCell = (v, oi) => {
    if (TIMECOLS.has(cols[oi]) && v > 1e9 && v < 2e10) return fmtTs(Number(v));
    return (v == null ? '-' : String(v));
  };
  const chevron = up => `<svg class="ic" viewBox="0 0 24 24"><path d="${up ? 'M6 15l6-6 6 6' : 'M6 9l6 6 6-6'}"/></svg>`;
  function build() {
    const htr = document.createElement('tr');
    const numTh = document.createElement('th'); numTh.className = 'numcol'; numTh.textContent = '#'; htr.appendChild(numTh);
    order.forEach((oi, pos) => {
      if (hidden.has(oi)) return;
      const th = document.createElement('th'); th.draggable = true;
      const lab = document.createElement('span'); lab.textContent = cols[oi]; th.appendChild(lab);
      if (oi === sortIdx) { const ar = document.createElement('span'); ar.className = 'sortar'; ar.innerHTML = chevron(sortDir > 0); th.appendChild(ar); }
      if (widths[oi]) th.style.width = widths[oi] + 'px';
      th.onclick = e => { if (e.target.classList.contains('rsz')) return; if (sortIdx === oi) sortDir = -sortDir; else { sortIdx = oi; sortDir = 1; } build(); };
      th.ondragstart = e => e.dataTransfer.setData('text/plain', String(pos));
      th.ondragover = e => { e.preventDefault(); th.classList.add('dragover'); };
      th.ondragleave = () => th.classList.remove('dragover');
      th.ondrop = e => { e.preventDefault(); th.classList.remove('dragover'); const from = Number(e.dataTransfer.getData('text/plain')); if (Number.isInteger(from) && from !== pos) { const [m] = order.splice(from, 1); order.splice(pos, 0, m); build(); } };
      const rsz = document.createElement('span'); rsz.className = 'rsz'; th.appendChild(rsz);
      rsz.onmousedown = e => {
        e.preventDefault(); e.stopPropagation();
        const x0 = e.clientX, w0 = th.offsetWidth;
        const mv = ev => { widths[oi] = Math.max(40, w0 + ev.clientX - x0); th.style.width = widths[oi] + 'px'; };
        const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
      };
      htr.appendChild(th);
    });
    thead.replaceChildren(htr);
    let view = rows;
    if (sortIdx >= 0) {
      const ipv4 = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
      const ne = rows.filter(r => r[sortIdx] != null && r[sortIdx] !== '');
      const isIp = ne.length > 0 && ne.some(r => ipv4(String(r[sortIdx]))) && ne.every(r => { const v = String(r[sortIdx]); return ipv4(v) || v.includes(':'); });
      const numeric = !isIp && rows.every(r => r[sortIdx] == null || r[sortIdx] === '' || !isNaN(Number(r[sortIdx])));
      view = [...rows].sort((a, b) => {
        const x = a[sortIdx], y = b[sortIdx];
        if (isIp) {
          const xs = String(x == null ? '' : x), ys = String(y == null ? '' : y);
          const xo = ipv4(xs) ? xs.split('.').map(Number) : null;
          const yo = ipv4(ys) ? ys.split('.').map(Number) : null;
          if (xo && yo) { for (let i = 0; i < 4; i++) if (xo[i] !== yo[i]) return (xo[i] - yo[i]) * sortDir; return 0; }
          if (xo) return -sortDir;
          if (yo) return sortDir;
          return xs.localeCompare(ys) * sortDir;
        }
        if (numeric) return ((Number(x) || 0) - (Number(y) || 0)) * sortDir;
        return String(x == null ? '' : x).localeCompare(String(y == null ? '' : y)) * sortDir;
      });
    }
    tb.replaceChildren(...view.map((row, ri) => {
      const tr = document.createElement('tr');
      const numTd = document.createElement('td'); numTd.className = 'numcol'; numTd.textContent = String(ri + 1); tr.appendChild(numTd);
      order.forEach(oi => { if (hidden.has(oi)) return; const td = document.createElement('td'); td.textContent = fmtCell(row[oi], oi); tr.appendChild(td); });
      tr.style.cursor = 'pointer';
      tr.title = drill ? 'Cliquer pour exécuter le drill du panneau' : (DIMENSIONLESS.has(cols[0]) ? 'Cliquer pour voir tous les détails' : `Cliquer pour filtrer ${cols[0]}=${row[0]}`);
      tr.onclick = () => {
        if (drill) { const c = { value: row[0] }; if (DIMENSIONLESS.has(cols[0])) c.from = Number(row[0]); return customDrill(drill, c); }
        if (!DIMENSIONLESS.has(cols[0])) return drilldown(cols[0], row[0]);
        const nx = tr.nextSibling;
        if (nx && nx.classList && nx.classList.contains('rowdetail')) { nx.remove(); return; }
        const dtr = document.createElement('tr'); dtr.className = 'rowdetail';
        const td = document.createElement('td'); td.colSpan = vcount() + 1;
        const dl = document.createElement('dl'); dl.className = 'kvdetail';
        cols.forEach((c, i) => { const dt = document.createElement('dt'); dt.textContent = c; const dd = document.createElement('dd'); dd.textContent = (row[i] == null ? '-' : String(row[i])); dl.append(dt, dd); });
        td.appendChild(dl); dtr.appendChild(td); tr.after(dtr);
      };
      return tr;
    }));
    if (colsBtn) colsBtn.textContent = `Colonnes ${vcount()}/${order.length} ▾`;
  }
  build();
  if (order.length <= 7) return tbl;
  const wrap = document.createElement('div'); wrap.className = 'qtblwrap';
  const bar = document.createElement('div'); bar.className = 'qtblbar';
  colsBtn = document.createElement('button'); colsBtn.type = 'button'; colsBtn.className = 'colsbtn';
  colsBtn.textContent = `Colonnes ${vcount()}/${order.length} ▾`;
  colsBtn.onclick = (ev) => {
    ev.stopPropagation();
    const wasMine = _colsMenuOwner === id;
    closeColsMenu();
    if (wasMine) return;
    _colsMenuOwner = id;
    const menu = document.createElement('div'); menu.className = 'colsmenu';
    order.forEach(oi => {
      const lab = document.createElement('label');
      const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !hidden.has(oi);
      cb.onchange = () => { if (cb.checked) hidden.delete(oi); else hidden.add(oi); build(); };
      const nm = document.createElement('span'); nm.className = 'colsnm'; nm.textContent = cols[oi];
      const pc = document.createElement('span'); pc.className = 'colspc'; pc.textContent = Math.round(cover[oi] * 100) + '%';
      lab.append(cb, nm, pc); menu.appendChild(lab);
    });
    const allb = document.createElement('button'); allb.type = 'button'; allb.className = 'colsall'; allb.textContent = 'Tout afficher';
    allb.onclick = () => { hidden.clear(); build(); menu.querySelectorAll('input').forEach(c => c.checked = true); };
    menu.appendChild(allb);
    const r = colsBtn.getBoundingClientRect();
    menu.style.top = (r.bottom + 4) + 'px'; menu.style.right = (window.innerWidth - r.right) + 'px';
    document.body.appendChild(menu);
    const onclose = e => { if (!menu.contains(e.target) && e.target !== colsBtn) closeColsMenu(); };
    const onscroll = () => closeColsMenu();
    _colsMenuClose = () => { menu.remove(); document.removeEventListener('click', onclose); document.removeEventListener('scroll', onscroll, true); };
    setTimeout(() => { document.addEventListener('click', onclose); document.addEventListener('scroll', onscroll, true); }, 0);
  };
  bar.appendChild(colsBtn); wrap.append(bar, tbl);
  return wrap;
}
function statEl(cols, rows, query, drill) {
  const v = rows.length ? rows[0][rows[0].length - 1] : null;
  const d = document.createElement('div'); d.className = 'statbig'; d.textContent = (v == null ? '-' : String(v));
  if (query || drill) {
    d.style.cursor = 'pointer';
    d.title = drill ? 'Cliquer pour exécuter le drill du panneau' : 'Cliquer pour voir ce qui se cache derrière ce chiffre';
    d.onclick = () => statDrill(query, drill);
  }
  return d;
}
function barEl(cols, rows, query, drill) {
  const vi = cols.length - 1;
  const nums = rows.map(r => Number(r[vi]) || 0);
  const max = Math.max(1, ...nums);
  const wrap = document.createElement('div'); wrap.className = 'bars';
  rows.forEach((r, i) => {
    const row = document.createElement('div'); row.className = 'barrow';
    const lab = document.createElement('span'); lab.className = 'barlabel'; lab.textContent = String(r[0]);
    const track = document.createElement('div'); track.className = 'bartrack';
    const fill = document.createElement('div'); fill.className = 'barfill'; fill.style.width = (nums[i] / max * 100) + '%';
    track.appendChild(fill);
    const val = document.createElement('span'); val.className = 'barval'; val.textContent = String(r[vi]);
    const tipTxt = `${r[0]} : ${r[vi]}`;
    row.addEventListener('mousemove', e => tipShow(tipTxt, e));
    row.addEventListener('mouseleave', tipHide);
    if (drill) { row.style.cursor = 'pointer'; row.title = 'Cliquer pour exécuter le drill du panneau'; row.onclick = () => customDrill(drill, { value: r[0] }); }
    else if (!DIMENSIONLESS.has(cols[0])) { row.style.cursor = 'pointer'; row.title = 'Cliquer pour filtrer'; row.onclick = () => drilldown(cols[0], r[0]); }
    row.append(lab, track, val); wrap.appendChild(row);
  });
  return wrap;
}
function fmtMaybeTime(v) {
  const n = Number(v);
  if (n > 1e9 && n < 2e10) return new Date(n * 1000).toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit' });
  return String(v);
}
function lineEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const W = 640, H = 200, pad = 30;
  const xs = rows.map(r => Number(r[0]) || 0);
  const ys = rows.map(r => Number(r[r.length - 1]) || 0);
  const ymax = Math.max(1, ...ys), xmin = Math.min(...xs), xmax = Math.max(...xs);
  const sx = x => pad + (xmax > xmin ? (x - xmin) / (xmax - xmin) : 0.5) * (W - 2 * pad);
  const sy = y => H - pad - (y / ymax) * (H - 2 * pad);
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'linechart');
  const txt = (x, y, s, a) => { const e = mk('text'); e.setAttribute('x', x); e.setAttribute('y', y); e.setAttribute('fill', CSSV('--mut', '#8aa0b4')); e.setAttribute('font-size', '10'); e.setAttribute('text-anchor', a || 'start'); e.textContent = s; svg.appendChild(e); };
  const axis = mk('path'); axis.setAttribute('d', `M${pad},${pad} L${pad},${H - pad} L${W - pad},${H - pad}`); axis.setAttribute('stroke', CSSV('--bd', '#16202e')); axis.setAttribute('fill', 'none'); svg.appendChild(axis);
  if (rows.length) {
    const pts = rows.map((r, i) => `${sx(xs[i])},${sy(ys[i])}`);
    const area = mk('polygon');
    area.setAttribute('points', `${sx(xs[0])},${H - pad} ${pts.join(' ')} ${sx(xs[xs.length - 1])},${H - pad}`);
    area.setAttribute('fill', CSSV('--acc-soft', 'rgba(45,212,191,.16)')); svg.appendChild(area);
    const poly = mk('polyline'); poly.setAttribute('points', pts.join(' ')); poly.setAttribute('fill', 'none'); poly.setAttribute('stroke', CSSV('--acc', '#2dd4bf')); poly.setAttribute('stroke-width', '2'); svg.appendChild(poly);
    rows.forEach((r, i) => { const c = mk('circle'); c.setAttribute('cx', sx(xs[i])); c.setAttribute('cy', sy(ys[i])); c.setAttribute('r', rows.length === 1 ? '4' : '2.5'); c.setAttribute('fill', CSSV('--acc', '#2dd4bf')); svg.appendChild(c); });
    txt(3, pad, String(ymax));
    txt(pad, H - 8, fmtMaybeTime(xs[0]));
    if (xs.length > 1) txt(W - pad, H - 8, fmtMaybeTime(xs[xs.length - 1]), 'end');
  }
  if (rows.length > 1 && xmin > 1e9 && xmax < 2e10) {
    attachZoom(svg, W, vx => xmin + Math.max(0, Math.min(1, (vx - pad) / (W - 2 * pad))) * (xmax - xmin));
  }
  attachTip(svg, W, vx => { let b = 0, bd = 1e9; for (let i = 0; i < xs.length; i++) { const d = Math.abs(sx(xs[i]) - vx); if (d < bd) { bd = d; b = i; } } return (xs.length && bd < 40) ? `${fmtMaybeTime(xs[b])} : ${ys[b]}` : ''; });
  if (rows.length) {
    const cross = mk('line'); cross.setAttribute('y1', pad); cross.setAttribute('y2', H - pad); cross.setAttribute('stroke', CSSV('--mut', '#8aa0b4')); cross.setAttribute('stroke-dasharray', '3 3'); cross.style.display = 'none'; svg.appendChild(cross);
    const mark = mk('circle'); mark.setAttribute('r', '4.5'); mark.setAttribute('fill', CSSV('--acc', '#2dd4bf')); mark.setAttribute('stroke', CSSV('--card', '#0c1422')); mark.setAttribute('stroke-width', '2'); mark.style.display = 'none'; svg.appendChild(mark);
    let hi = -1;
    const vbx = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
    svg.addEventListener('mousemove', e => {
      const vx = vbx(e); let b = 0, bd = 1e9;
      for (let i = 0; i < xs.length; i++) { const d = Math.abs(sx(xs[i]) - vx); if (d < bd) { bd = d; b = i; } }
      if (bd < 60) { hi = b; const X = sx(xs[b]), Y = sy(ys[b]); cross.setAttribute('x1', X); cross.setAttribute('x2', X); cross.style.display = ''; mark.setAttribute('cx', X); mark.setAttribute('cy', Y); mark.style.display = ''; if (xs[b] > 1e9) svg.style.cursor = 'pointer'; }
      else { hi = -1; cross.style.display = 'none'; mark.style.display = 'none'; }
    });
    svg.addEventListener('mouseleave', () => { hi = -1; cross.style.display = 'none'; mark.style.display = 'none'; });
    svg.addEventListener('click', () => {
      if (svg._zoomed) { svg._zoomed = false; return; }
      if (hi < 0 || xs[hi] <= 1e9) return;
      const span = xs.length > 1 ? xs[1] - xs[0] : 60;
      if (drill) customDrill(drill, { from: xs[hi], to: xs[hi] + span, value: ys[hi] });
      else drillTime(xs[hi], span);
    });
  }
  return svg;
}

// =====================================================================================
//  Explore : facettes + pagination serveur + table/viz
// =====================================================================================
let lastResult = null;
function renderViz() {
  if (!lastResult) return;
  $('#qresult').replaceChildren(vizElement(($('#viz') && $('#viz').value) || 'table', lastResult.columns, lastResult.rows, $('#sql') ? $('#sql').value : ''));
}
function addSearchFilter(field, value) {
  const q = $('#sql').value.trim();
  const pipe = q.indexOf('|');
  let head = (pipe < 0 ? q : q.slice(0, pipe)).trim();
  if (!/^\s*search\b/i.test(head)) head = ('search ' + head).trim();
  const tail = pipe < 0 ? '' : ' ' + q.slice(pipe);
  const lit = /^-?\d+(\.\d+)?$/.test(String(value)) ? String(value) : `"${String(value).replace(/"/g, '')}"`;
  $('#sql').value = `${head} ${field}=${lit}`.replace(/\s+/g, ' ').trim() + tail;
  runQuery();
}
function facetBlock(rows, idx, field, label) {
  const counts = new Map();
  rows.forEach(r => { const raw = (r[idx] == null || r[idx] === '') ? null : r[idx]; counts.set(raw, (counts.get(raw) || 0) + 1); });
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const block = document.createElement('div'); block.className = 'fldblock';
  block.appendChild(Object.assign(document.createElement('div'), { className: 'fldname', textContent: label }));
  top.forEach(([raw, c]) => {
    const disp = raw == null ? '-' : String(raw);
    const row = document.createElement('button'); row.className = 'fldval';
    const s = document.createElement('span'); s.textContent = disp;
    const cc = document.createElement('span'); cc.className = 'fldc'; cc.textContent = c;
    row.append(s, cc);
    if (raw != null) row.onclick = () => addSearchFilter(field, raw);
    block.appendChild(row);
  });
  return block;
}
function renderFacets(cols, rows) {
  const host = $('#facets'); if (!host) return;
  host.replaceChildren();
  if (!rows.length) return;
  const ix = n => cols.indexOf(n);
  [['severity', 'sévérité'], ['status', 'statut'], ['mitre', 'ATT&CK'], ['target', 'cible'], ['category', 'catégorie']].forEach(([f, lab]) => {
    const idx = ix(f); if (idx >= 0) host.appendChild(facetBlock(rows, idx, f, lab));
  });
}
// pager Explore (pagination CLIENT-side : /api/query renvoie le jeu complet, on tranche localement).
let evState = { q: '', isSoql: true, page: 0, pageSize: 200, total: 0, shown: 0, cols: [], all: [] };
function evPagerHtml() {
  const PS = evState.pageSize, total = evState.total, numbered = total >= 0;
  const pages = numbered ? Math.max(1, Math.ceil(total / PS)) : evState.page + (evState.shown >= PS ? 2 : 1);
  if (pages <= 1) return '';
  const from = evState.page * PS;
  return `<div class="evpager"><button class="evprev" type="button" title="précédent" ${evState.page === 0 ? 'disabled' : ''}>◀</button>${numbered ? pageNums(evState.page, pages).map(n => n === '…' ? '<span class="evdots">…</span>' : `<button type="button" class="evnum${n - 1 === evState.page ? ' on' : ''}" data-p="${n - 1}">${n}</button>`).join('') : `<span class="evdots">page ${evState.page + 1}</span>`}<button class="evnext" type="button" title="suivant" ${(numbered ? evState.page >= pages - 1 : evState.shown < PS) ? 'disabled' : ''}>▶</button><span class="evtot">${total >= 0 ? total + ' · ' : ''}${from + 1}–${from + evState.shown}</span></div>`;
}
function wirePagers(root) {
  // navigation = re-tranchage local (le jeu complet est déjà en mémoire, pas de refetch).
  root.querySelectorAll('.evprev').forEach(b => b.onclick = () => { if (evState.page > 0) { evState.page--; evRenderPage(); } });
  root.querySelectorAll('.evnext').forEach(b => b.onclick = () => { evState.page++; evRenderPage(); });
  root.querySelectorAll('.evnum').forEach(b => b.onclick = () => { evState.page = Number(b.dataset.p); evRenderPage(); });
}
function renderTablePaged(host, cols, rows) {
  host.replaceChildren();
  const pgr = evPagerHtml();
  if (pgr) { const t = document.createElement('div'); t.innerHTML = pgr; host.appendChild(t.firstElementChild); }
  host.appendChild(tableEl(cols, rows, evState.q));
  if (pgr) { const b = document.createElement('div'); b.innerHTML = pgr; host.appendChild(b.firstElementChild); }
  wirePagers(host);
}
const evPageSize = () => { const s = $('#qsize'); return s ? (Number(s.value) || 200) : 200; };
function pageNums(cur, pages) {
  const c = cur + 1, s = new Set([1, pages]);
  for (let i = c - 2; i <= c + 2; i++) if (i >= 1 && i <= pages) s.add(i);
  const arr = [...s].sort((a, b) => a - b), out = []; let prev = 0;
  for (const n of arr) { if (n - prev > 1) out.push('…'); out.push(n); prev = n; }
  return out;
}
// Rend une page localement à partir du jeu complet déjà chargé (pas de requête réseau).
function evRenderPage() {
  evState.pageSize = evPageSize();
  const PS = evState.pageSize;
  const pages = Math.max(1, Math.ceil(evState.total / PS));
  if (evState.page > pages - 1) evState.page = pages - 1;
  if (evState.page < 0) evState.page = 0;
  const start = evState.page * PS;
  const slice = evState.all.slice(start, start + PS);
  evState.shown = slice.length;
  if ($('#viz')) $('#viz').hidden = true;
  renderTablePaged($('#qresult'), evState.cols, slice);
  $('#qstats').textContent = `page ${evState.page + 1}/${pages} · ${evState.total} ligne(s)` + (evState._net != null ? ` · ${evState._net} ms` : '');
  $('#qstats').title = evState._compiled || '';
}
// (re)charge le jeu complet depuis /api/query puis affiche la 1re page. Le backend renvoie tout
// (total = rows.length) — on garde les rows en mémoire et on pagine côté client.
async function evLoad() {
  evState.pageSize = evPageSize();
  $('#qstats').textContent = 'exécution…';
  const t0 = performance.now();
  try {
    const j = await runQ(evState.q, evState.isSoql);
    if (j.error) { $('#qresult').replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + j.error })); $('#qstats').textContent = ''; return; }
    evState.cols = j.columns || [];
    evState.all = j.rows || [];
    evState.total = (typeof j.total === 'number') ? j.total : evState.all.length;
    evState._net = Math.round(performance.now() - t0);
    evState._compiled = j.compiled || '';
    renderFacets(evState.cols, evState.all);   // facettes calculées sur le jeu complet
    evRenderPage();
  } catch (e) { $('#qstats').textContent = 'erreur : ' + e.message; }
}
async function runQuery() {
  const q = $('#sql').value.trim();
  if (!q) { $('#qresult').replaceChildren(); $('#qstats').textContent = ''; if ($('#facets')) $('#facets').replaceChildren(); return; }
  const isSoql = /^\s*search\b/i.test(q) || q.includes('|');
  const hasAgg = isSoql && /\|\s*(stats|timechart|top|rare|eventstats)\b/i.test(q);
  $('#qresult').replaceChildren();
  if (!hasAgg) {
    evState = { q, isSoql, page: 0, pageSize: evPageSize(), total: 0, shown: 0, cols: [], all: [] };
    await evLoad();
    return;
  }
  if ($('#facets')) $('#facets').replaceChildren();
  const t0 = performance.now();
  $('#qstats').textContent = 'exécution…';
  try {
    const j = await runQ(q, isSoql);
    if (j.error) { $('#qresult').replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + j.error })); $('#qstats').textContent = ''; return; }
    lastResult = { columns: j.columns, rows: j.rows };
    if ($('#viz')) $('#viz').hidden = false;
    renderViz();
    const net = Math.round(performance.now() - t0);
    const nrows = j.stats && typeof j.stats.rows === 'number' ? j.stats.rows : (j.rows ? j.rows.length : 0);
    $('#qstats').textContent = `${nrows} ligne(s) · total ${net} ms · soql`;
    $('#qstats').title = j.compiled || '';
  } catch (e) { $('#qstats').textContent = 'erreur : ' + e.message; }
}
if ($('#run')) $('#run').addEventListener('click', runQuery);
if ($('#sql')) $('#sql').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); } });
if ($('#viz')) $('#viz').addEventListener('change', renderViz);
if ($('#qsize')) $('#qsize').addEventListener('change', () => { if (evState.q && evState.all.length) { evState.page = 0; evRenderPage(); } });
// barre de recherche header -> Explore
if ($('#q')) $('#q').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const v = e.target.value.trim(); if (!v) return;
  location.hash = 'explore';
  $('#sql').value = (/^\s*search\b/i.test(v) || v.includes('|')) ? v : ('search ' + v);
  runQuery();
});

// =====================================================================================
//  Dashboards : panneaux soql (drag réordonner + resize) — schéma Forge (name/viz/col_span/position)
// =====================================================================================
// Hiérarchie portée de la console SOC (app.js L949-1316), recalée sur les endpoints RÉELS du backend
// Forge : modèle PLAT (pas d'entité « view » côté serveur). Chaque dashboard = une tuile avec sa grille
// de panneaux ; les panneaux portent un dashboard_id (assignable). Les attributs purement visuels que le
// backend ne persiste PAS (cols/collapse de tuile, hauteur/drill de panneau) sont stockés côté client
// (localStorage pour cols/collapse, mémoire de session pour drill/height). Les « Vues » sont des
// COLLECTIONS de dashboards locales (localStorage) : un filtre d'affichage, jamais un endpoint inventé.
let editing = false, panelCards = [], dashList = [];
const tileBasis = c => 'calc(' + (Math.max(1, Math.min(4, c)) * 25) + '% - 12px)';
function refreshPanels() { panelCards.forEach(c => { if (c.isConnected && c._panel) c._panel.reload(); }); }
const VIZOPTS = [{ value: 'table', label: 'Table' }, { value: 'bar', label: 'Barres' }, { value: 'line', label: 'Courbe' }, { value: 'stat', label: 'Stat' }];

// --- préférences d'affichage client-side (cols/collapse par dashboard) — le backend n'a pas ces colonnes ---
function dashPrefs() { try { return JSON.parse(localStorage.getItem('forge_dash_prefs') || '{}') || {}; } catch (e) { return {}; } }
function dashPref(id) { return dashPrefs()[id] || {}; }
function setDashPref(id, upd) { const all = dashPrefs(); all[id] = { ...(all[id] || {}), ...upd }; try { localStorage.setItem('forge_dash_prefs', JSON.stringify(all)); } catch (e) {} }

// --- vues = collections locales de dashboards (id) — pas d'endpoint backend ---
function viewStore() { try { return JSON.parse(localStorage.getItem('forge_dash_views') || '{}') || {}; } catch (e) { return {}; } }
function saveViewStore(v) { try { localStorage.setItem('forge_dash_views', JSON.stringify(v)); } catch (e) {} }

// PATCH d'un panneau (POST /api/panels/:id, Bearer). Le backend connaît name/query/viz/descr/col_span/position/dashboard_id.
async function patchPanel(id, upd) {
  const r = await fetch('/api/panels/' + id, { method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(upd) });
  if (r.status === 401) { localStorage.removeItem('forge_token'); toast('Token invalide ou requis pour éditer un panneau.', 'bad'); }
  return r;
}
// PATCH d'un dashboard (POST /api/dashboards/:id, Bearer). Champs backend : name/descr/position.
async function patchDash(id, upd) {
  const r = await fetch('/api/dashboards/' + id, { method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(upd) });
  if (r.status === 401) { localStorage.removeItem('forge_token'); toast('Token invalide ou requis pour éditer un dashboard.', 'bad'); }
  return r;
}
// crée un panneau dans le dashboard `did` (défaut 1). dashboard_id doit exister (sinon 400 unknown_dashboard).
async function createPanelModal(did = 1, query = '') {
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
  const resp = await fetch('/api/panels', { method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
  const j = await resp.json().catch(() => ({}));
  if (!resp.ok) { if (resp.status === 401) localStorage.removeItem('forge_token'); toast('Erreur : ' + (j.error || resp.status), 'bad'); return; }
  toast('Panneau créé', 'ok');
  loadDashboards();
}
// réordonne les panneaux d'une grille (place `from` avant/après `target`) et persiste les positions.
function reorderPanels(grid, fromId, targetId, after) {
  const panels = () => [...grid.children].filter(c => c.classList && c.classList.contains('panel'));
  const cards = panels();
  const fromCard = cards.find(c => c._panelId === fromId), targetCard = cards.find(c => c._panelId === targetId);
  if (!fromCard || !targetCard || fromCard === targetCard) return;
  grid.insertBefore(fromCard, after ? targetCard.nextSibling : targetCard);
  panels().forEach((c, i) => patchPanel(c._panelId, { position: i }));
}
function renderPanel(p) {
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
  del.onclick = async () => { if (await confirmModal('Supprimer ce panneau ?', { danger: true })) { await fetch('/api/panels/' + p.id, { method: 'DELETE', headers: authHeaders() }); loadDashboards(); } };
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
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast('Erreur : ' + (j.error || r.status), 'bad'); return; }
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
function renderDashboard(d) {
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
    if (!resp.ok) { const j = await resp.json().catch(() => ({})); toast('Erreur : ' + (j.error || resp.status), 'bad'); return; }
    loadDashboards();
  };
  wsel.onchange = () => { const n = Number(wsel.value); tile.style.flexBasis = tileBasis(n); setDashPref(d.id, { cols: n }); };
  del.onclick = async () => {
    if (d.id === 1) return;   // garde-fou : dashboard par défaut protégé (409 côté serveur de toute façon)
    if (!await confirmModal('Supprimer ce dashboard ? Ses panneaux seront réassignés au dashboard par défaut.', { danger: true })) return;
    const resp = await fetch('/api/dashboards/' + d.id, { method: 'DELETE', headers: authHeaders() });
    const j = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      if (resp.status === 401) localStorage.removeItem('forge_token');
      toast(j.error === 'default_protected' ? 'Le dashboard par défaut ne peut pas être supprimé.' : ('Erreur : ' + (j.error || resp.status)), 'bad');
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
async function loadPanelsInto(grid, d) {
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
function reorderDash(fromId, targetId) {
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
function renderDashboards() {
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
async function loadDashboards() {
  const host = $('#dashview'); if (!host) return;
  let list = [];
  try { list = await (await fetch('/api/dashboards')).json(); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  dashList = Array.isArray(list) ? list : [];
  loadViews();          // (re)peuple le sélecteur de vues (collections locales) — préserve la sélection
  renderDashboards();
}

// --- vues = collections locales de dashboards ---
function loadViews() {
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
async function viewModal(viewId) {
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
  const resp = await fetch('/api/dashboards', { method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ name: r.name.trim(), descr: r.descr.trim(), position: dashList.length }) });
  const j = await resp.json().catch(() => ({}));
  if (!resp.ok) { if (resp.status === 401) localStorage.removeItem('forge_token'); toast('Erreur : ' + (j.error || resp.status), 'bad'); return; }
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

// =====================================================================================
//  SECTIONS Forge : Modules, Findings, Coverage, Campaigns, ROE, Ledger, Overview
// =====================================================================================
let MODULES = [];
async function loadModules() {
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
function renderModules() {
  const grid = $('#mod-grid'); if (!grid) return;
  const onlyAvail = $('#mod-avail') && $('#mod-avail').checked;
  const list = MODULES.filter(m => !onlyAvail || m.available).sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
  if (!list.length) { grid.innerHTML = '<div class="muted">aucun module' + (onlyAvail ? ' disponible' : '') + '</div>'; return; }
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

const SEV_BADGE = s => `<span class="sevb sevb-${SEVKEY(s)}">${esc(String(s || '').toUpperCase() || 'INFO')}</span>`;
let F_STATE = { offset: 0, limit: 200 };
async function loadFindings(offset = 0) {
  const host = $('#f-result'); if (!host) return;
  F_STATE.offset = offset;
  const qp = new URLSearchParams();
  const camp = $('#campaign') && $('#campaign').value; if (camp) qp.set('campaign', camp);
  const sev = $('#f-sev') && $('#f-sev').value; if (sev) qp.set('severity', sev);
  const st = $('#f-status') && $('#f-status').value; if (st) qp.set('status', st);
  const tg = $('#f-target') && $('#f-target').value.trim(); if (tg) qp.set('target', tg);
  qp.set('limit', F_STATE.limit); qp.set('offset', offset);
  let d;
  try { d = await api('/findings?' + qp.toString()); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  const rows = d.findings || [];
  if ($('#f-count')) $('#f-count').textContent = d.total + ' findings';
  if (!rows.length) { host.innerHTML = '<div class="muted">aucun finding</div>'; return; }
  const table = document.createElement('table'); table.className = 'qtable findtable';
  table.innerHTML = `<thead><tr><th>#</th><th>Sév.</th><th>Cible</th><th>Titre</th><th>ATT&CK</th><th>Statut</th><th>Outil</th><th>Date</th></tr></thead>`;
  const tb = document.createElement('tbody');
  rows.forEach((x, i) => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour voir le détail (evidence / PoC / fix)';
    tr.innerHTML = `<td class="numcol">${offset + i + 1}</td><td>${SEV_BADGE(x.severity)}</td><td>${esc(x.target)}</td><td>${esc(x.title)}</td><td><code>${esc(x.mitre)}</code></td><td>${esc(x.status)}</td><td class="mut">${esc(x.tool)}</td><td class="mut">${esc(fmtTs(x.ts))}</td>`;
    tr.onclick = () => openFinding(x.id);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
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
async function openFinding(id) {
  let d;
  try { d = await api('/findings/' + id); } catch (e) { toast('Détail finding : ' + e.message, 'bad'); return; }
  infoModal(d.title || ('Finding #' + id), body => {
    const meta = document.createElement('div'); meta.className = 'findmeta';
    meta.innerHTML = `${SEV_BADGE(d.severity)} <span class="badge">${esc(d.status)}</span> <code>${esc(d.mitre)}</code> <span class="muted">${esc(d.category)}</span>`;
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
  });
}
['f-sev', 'f-status', 'f-target'].forEach(idp => { const el = $('#' + idp); if (el) el.addEventListener(idp === 'f-target' ? 'input' : 'change', () => loadFindings(0)); });

async function loadCoverage() {
  const host = $('#cov-result'); if (!host) return;
  let cov = [];
  try { cov = await api(withCampaign('/coverage')); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  if (!Array.isArray(cov) || !cov.length) { host.innerHTML = '<div class="muted">aucun run-record</div>'; return; }
  cov.sort((a, b) => (b.runs || 0) - (a.runs || 0));
  const max = Math.max(1, ...cov.map(c => c.runs || 0));
  const wrap = document.createElement('div'); wrap.className = 'bars';
  cov.forEach(c => {
    const row = document.createElement('div'); row.className = 'barrow covrow'; row.style.cursor = 'pointer'; row.title = 'Cliquer pour filtrer les findings sur cette technique';
    const lab = document.createElement('span'); lab.className = 'barlabel'; lab.innerHTML = `<code>${esc(c.mitre)}</code>`;
    const track = document.createElement('div'); track.className = 'bartrack';
    const fill = document.createElement('div'); fill.className = 'barfill'; fill.style.width = ((c.runs || 0) / max * 100) + '%';
    const firedFill = document.createElement('div'); firedFill.className = 'barfill fired'; firedFill.style.width = ((c.fired || 0) / max * 100) + '%';
    track.append(fill, firedFill);
    const val = document.createElement('span'); val.className = 'barval'; val.textContent = `${c.fired || 0}/${c.runs || 0}`;
    row.onclick = () => { $('#sql').value = `search mitre="${c.mitre}"`; location.hash = 'explore'; runQuery(); };
    row.append(lab, track, val); wrap.appendChild(row);
  });
  host.replaceChildren(wrap);
}

// =====================================================================================
//  DÉTECTION PURPLE — corrélation Forge (red, techniques tirées) vs Plume (blue, détections SOC)
//  Lecture seule : GET /api/purple/coverage[?campaign=X]. Mesure DÉFENSIVE pure (detected / missed
//  / MTTD) — expose les trous de détection du SOC. AUCUNE action offensive ici.
//  Contrat de réponse 200 (cf. blueprint) :
//    { plume_reachable, plume_url, techniques_fired, techniques_detected, techniques_missed,
//      detection_rate (0..1), mttd_avg_secs|null, mttd_max_secs|null,
//      detected:[{mitre,fires,alert_count,first_detection_ts,fire_ts|null,mttd_secs|null}] (tri mitre ASC),
//      missed:[{mitre,fires,fire_ts|null}], error (présent SEULEMENT si plume_reachable=false) }
//  Garantie côté serveur (qu'on REFLÈTE fidèlement, jamais on n'invente) : si plume_reachable=false,
//  detected=[] missed=[] rate=0 mttd=null detected/missed=0 -> on affiche la mesure comme IMPOSSIBLE
//  (FAIL-OPEN LISIBLE), pas comme « 0 % détecté ».
// =====================================================================================
function pcFmtSecs(s) {                                // MTTD : secondes -> libellé court lisible (Xs / Xm Ys / Xh Ym)
  if (s == null || !isFinite(s)) return '—';
  const n = Math.max(0, Math.round(Number(s)));
  if (n < 60) return n + 's';
  if (n < 3600) { const m = Math.floor(n / 60), r = n % 60; return r ? `${m}m ${r}s` : `${m}m`; }
  const h = Math.floor(n / 3600), m = Math.round((n % 3600) / 60); return m ? `${h}h ${m}m` : `${h}h`;
}
function pcMedian(nums) {                               // MTTD médian pour le bandeau (échantillons mesurables uniquement)
  const a = nums.filter(v => v != null && isFinite(v)).map(Number).sort((x, y) => x - y);
  if (!a.length) return null;
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}
function pcGotoTechnique(mitre) {                       // clic tuile -> filtre les findings sur la technique (Explore)
  if (!mitre) return;
  if ($('#sql')) $('#sql').value = `search mitre="${String(mitre).replace(/"/g, '')}"`;
  location.hash = 'explore';
  runQuery();
}
function pcTile(mitre, state, stateLabel, metaText, title) {
  const tile = document.createElement('div'); tile.className = 'pc-tile ' + state;
  tile.title = title || 'Cliquer pour filtrer les findings sur cette technique';
  const m = document.createElement('div'); m.className = 'pc-mitre'; m.textContent = mitre;
  const st = document.createElement('div'); st.className = 'pc-state';
  const dot = document.createElement('span'); dot.className = 'pc-dot';
  const lbl = document.createElement('span'); lbl.textContent = stateLabel;
  st.append(dot, lbl);
  tile.append(m, st);
  if (metaText) { const meta = document.createElement('div'); meta.className = 'pc-meta'; meta.textContent = metaText; tile.appendChild(meta); }
  tile.onclick = () => pcGotoTechnique(mitre);
  return tile;
}
async function loadPurpleCoverage() {
  const host = $('#pc-result'); if (!host) return;
  const plumeBadge = $('#pc-plume');
  let p;
  try { p = await api(withCampaign('/purple/coverage')); }
  catch (e) {
    host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>';
    if (plumeBadge) { plumeBadge.className = 'badge mut'; plumeBadge.textContent = '—'; }
    return;
  }
  // badge cible Plume
  if (plumeBadge) {
    const url = String(p.plume_url || '');
    if (!url) { plumeBadge.className = 'badge mut'; plumeBadge.textContent = 'Plume non configuré'; plumeBadge.title = 'PLUME_URL vide — corrélation de détection désactivée'; }
    else {
      const ok = p.plume_reachable === true;
      plumeBadge.className = 'badge ' + (ok ? 'ok' : 'destr');
      plumeBadge.innerHTML = `${ic(ok ? 'check' : 'warn')} Plume ${ok ? 'joignable' : 'injoignable'}`;
      plumeBadge.title = url;
    }
  }
  host.replaceChildren();

  // techniques distinctes tirées (toujours informatif, même si mesure impossible)
  const fired = Number(p.techniques_fired || 0);
  const detected = Array.isArray(p.detected) ? p.detected : [];
  const missed = Array.isArray(p.missed) ? p.missed : [];

  // FAIL-OPEN LISIBLE : Plume injoignable -> mesure impossible. On n'affiche AUCUN « détecté »
  // ni taux : ce ne sont pas des 0 réels, c'est de l'absence de mesure. On reste honnête.
  if (p.plume_reachable !== true) {
    const fo = document.createElement('div'); fo.className = 'pc-failopen';
    const head = document.createElement('div'); head.className = 'pc-fo-head';
    head.innerHTML = `${ic('warn')} <span>Mesure de détection impossible — Plume injoignable (fail-open lisible)</span><span class="pc-dtag">non mesuré</span>`;
    const det = document.createElement('div'); det.className = 'pc-fo-detail';
    const reason = (typeof p.error === 'string' && p.error) ? p.error : 'cible Plume injoignable';
    const urlTxt = p.plume_url ? `cible : ${p.plume_url}` : 'PLUME_URL non configuré';
    det.textContent = `${reason} — ${urlTxt}. Aucun « détecté » n'est inventé : detected/missed vides, taux et MTTD non mesurés. ${fired} technique(s) distincte(s) tirée(s) côté Forge (information offensive conservée).`;
    fo.append(head, det);
    host.appendChild(fo);
    return;
  }

  // ---- Plume joignable : mesure exploitable -------------------------------------------------
  const nDet = detected.length, nMiss = missed.length, total = nDet + nMiss;
  const rate = (typeof p.detection_rate === 'number' && isFinite(p.detection_rate)) ? p.detection_rate : (total ? nDet / total : 0);
  const ratePct = Math.round(Math.max(0, Math.min(1, rate)) * 100);
  const mttdMedian = pcMedian(detected.map(d => d.mttd_secs));

  // bandeau : « M/N détectées, MTTD médian Xs »
  const band = document.createElement('div'); band.className = 'pc-band';
  const rateEl = document.createElement('span'); rateEl.className = 'pc-rate'; rateEl.textContent = ratePct + '%';
  const subEl = document.createElement('span'); subEl.className = 'pc-sub';
  subEl.textContent = `${nDet}/${total || fired} technique(s) détectée(s) par le SOC`;
  band.append(rateEl, subEl);
  const sep1 = document.createElement('span'); sep1.className = 'pc-sep'; band.appendChild(sep1);
  const mttdEl = document.createElement('span'); mttdEl.className = 'pc-mttd pc-sub';
  mttdEl.innerHTML = `MTTD médian <b>${esc(pcFmtSecs(mttdMedian))}</b> · moyen <b>${esc(pcFmtSecs(p.mttd_avg_secs))}</b> · max <b>${esc(pcFmtSecs(p.mttd_max_secs))}</b>`;
  if (mttdMedian == null) mttdEl.title = 'aucun échantillon MTTD mesurable (ts de tir illisible ou aucune détection)';
  band.appendChild(mttdEl);
  if (nMiss > 0) {
    const sep2 = document.createElement('span'); sep2.className = 'pc-sep'; band.appendChild(sep2);
    const gapEl = document.createElement('span'); gapEl.className = 'pc-sub';
    gapEl.innerHTML = `<span class="badge destr">${nMiss} trou(s) de détection</span>`;
    band.appendChild(gapEl);
  }
  host.appendChild(band);

  // légende
  const legend = document.createElement('div'); legend.className = 'pc-legend';
  legend.innerHTML = '<span class="pc-lg"><span class="pc-dot detected"></span>détecté (+MTTD)</span>'
    + '<span class="pc-lg"><span class="pc-dot missed"></span>raté (trou SOC)</span>'
    + '<span class="pc-lg"><span class="pc-dot unfired"></span>non-tiré (couvert, pas joué)</span>';
  host.appendChild(legend);

  // GRIS = techniques couvertes (run-records ATT&CK) mais JAMAIS tirées -> ni détectées ni ratées.
  // On les dérive de /api/coverage (lecture seule, déjà consommé ailleurs). Échec silencieux : la
  // matrice reste valable sans ces tuiles (detected/missed restent la source de vérité purple).
  const firedSet = new Set([...detected.map(d => d.mitre), ...missed.map(m => m.mitre)]);
  let unfired = [];
  try {
    const cov = await api(withCampaign('/coverage'));
    if (Array.isArray(cov)) {
      const seen = new Set();
      cov.forEach(c => {
        const m = c && c.mitre;
        if (m && !firedSet.has(m) && !seen.has(m) && Number(c.fired || 0) === 0) { seen.add(m); unfired.push(m); }
      });
      unfired.sort((a, b) => String(a).localeCompare(String(b)));
    }
  } catch (e) { /* coverage optionnel : on n'affiche pas les GRIS si indisponible */ }

  // matrice : DÉTECTÉ (vert, +MTTD) puis RATÉ (rouge) puis NON-TIRÉ (gris)
  const matrix = document.createElement('div'); matrix.className = 'pc-matrix';
  detected.forEach(d => {
    const mttd = (d.mttd_secs != null && isFinite(d.mttd_secs)) ? `MTTD ${pcFmtSecs(d.mttd_secs)}` : 'MTTD n/d';
    const alerts = `${Number(d.alert_count || 0)} alerte(s)`;
    matrix.appendChild(pcTile(d.mitre, 'detected', 'détecté', `${mttd} · ${alerts} · ${Number(d.fires || 0)} tir(s)`,
      `Détecté par le SOC — ${mttd}, première détection ${fmtTs(d.first_detection_ts)}`));
  });
  missed.forEach(m => {
    matrix.appendChild(pcTile(m.mitre, 'missed', 'raté', `${Number(m.fires || 0)} tir(s) · 0 alerte`,
      'Tiré en red-team mais NON détecté par le SOC — trou de détection'));
  });
  unfired.forEach(m => {
    matrix.appendChild(pcTile(m, 'unfired', 'non-tiré', 'couvert, pas joué',
      'Technique couverte par le moteur mais jamais tirée — non mesurable en détection'));
  });

  if (!matrix.childElementCount) {
    host.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune technique tirée avec un identifiant MITRE — rien à corréler' }));
    return;
  }
  host.appendChild(matrix);
}

let CAMPAIGNS = [];
async function loadCampaigns() {
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
function renderCampaigns() {
  const host = $('#cm-result'); if (!host) return;
  const filt = ($('#cm-filter') && $('#cm-filter').value.trim().toLowerCase()) || '';
  const list = CAMPAIGNS.filter(c => !filt || String(c.campaign).toLowerCase().includes(filt));
  if ($('#cm-count')) $('#cm-count').textContent = CAMPAIGNS.length + ' campagnes';
  if (!list.length) { host.innerHTML = '<div class="muted">aucune campagne</div>'; return; }
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

async function loadRoe() {
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
  if (cc) cc.innerHTML = ['FIRE', 'DRY_RUN', 'VETO'].map(k => `<div class="roecount v-${k}"><span class="rcn">${counts[k]}</span><span class="rcl">${k}</span></div>`).join('');
  if (!rows.length) { host.innerHTML = '<div class="muted">aucune décision ROE</div>'; return; }
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = `<thead><tr><th>#</th><th>Verdict</th><th>Cible</th><th>Type</th><th>Risque</th><th>Raisons</th><th>Date</th></tr></thead>`;
  const tb = document.createElement('tbody');
  rows.forEach((r, i) => {
    const verdict = String(r.verdict || '').toUpperCase();
    const risk = [r.exploit ? 'exploit' : '', r.destructive ? 'destructif' : ''].filter(Boolean).join(' · ') || '-';
    const reasons = Array.isArray(r.reasons) ? r.reasons.join(' ; ') : (r.reasons == null ? '' : String(r.reasons));
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="numcol">${i + 1}</td><td><span class="badge v-${esc(verdict)}">${esc(verdict)}</span></td><td>${esc(r.target)}</td><td><code>${esc(r.kind)}</code></td><td class="mut">${esc(risk)}</td><td>${esc(reasons)}</td><td class="mut">${esc(fmtTs(r.ts))}</td>`;
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}
if ($('#roe-verdict')) $('#roe-verdict').addEventListener('change', loadRoe);

async function loadLedger() {
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
  if (!entries.length) { host.innerHTML = '<div class="muted">ledger vide ou absent</div>'; return; }
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

async function loadOverview() {
  // résumé boucle purple : compteurs findings + run-records
  const sumHost = $('#ov-summary .body');
  try {
    const f = await api(withCampaign('/findings?limit=1'));
    const rr = await api(withCampaign('/runrecords?limit=1'));
    const rrFired = await api(withCampaign('/runrecords?fired=1&limit=1'));
    const cov = await api(withCampaign('/coverage'));
    const tech = Array.isArray(cov) ? cov.length : 0;
    if (sumHost) sumHost.innerHTML =
      `<div class="kv"><span>Findings</span><b>${f.total != null ? f.total : '?'}</b></div>`
      + `<div class="kv"><span>Run-records (lus)</span><b>${Array.isArray(rr) ? rr.length + (rr.length >= 1 ? '+' : '') : '?'}</b></div>`
      + `<div class="kv"><span>Techniques couvertes</span><b>${tech}</b></div>`;
    $('#status').textContent = 'connecté';
    $('#updated').textContent = new Date().toLocaleTimeString(LOC);
    const p = $('#posture');
    if (p) { p.textContent = (f.total > 0) ? `${f.total} finding(s)` : 'aucun finding'; p.className = 'posture ' + (f.total > 0 ? 'bad' : 'ok'); }
  } catch (e) {
    if (sumHost) sumHost.innerHTML = '<div class="bad">hors-ligne : ' + esc(e.message) + '</div>';
    $('#status').textContent = 'hors-ligne (' + e.message + ')';
  }
  // findings par sévérité (via soql stats)
  const sevHost = $('#ov-sev .body');
  try {
    const j = await runQ('search | stats count by severity | sort -count', true);
    if (sevHost) {
      const rows = j.rows || [];
      if (!rows.length) sevHost.innerHTML = '<div class="muted">aucun finding</div>';
      else sevHost.replaceChildren(barEl(j.columns, rows, ''));
    }
  } catch (e) { if (sevHost) sevHost.innerHTML = '<div class="muted">—</div>'; }
}

// =====================================================================================
//  Statuts findings : peuplent le filtre depuis les findings vus (tested/vulnerable/...)
// =====================================================================================
async function loadStatuses() {
  const sel = $('#f-status'); if (!sel) return;
  try {
    const j = await runQ('search | stats count by status', true);
    const rows = j.rows || [];
    const cur = sel.value;
    sel.replaceChildren();
    const o0 = document.createElement('option'); o0.value = ''; o0.textContent = 'Tous statuts'; sel.appendChild(o0);
    rows.map(r => r[0]).filter(Boolean).sort().forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; sel.appendChild(o); });
    if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
  } catch (e) { /* le moteur peut ne pas exposer status en stats ; on garde le sélecteur tel quel */ }
}

// =====================================================================================
//  LANCEMENT C2 (capacité PRIVILÉGIÉE, gouvernée + auditée) — endpoints consommés :
//    POST /api/run                  (écriture ; en-tête X-Forge-Operator requis)
//    GET  /api/runs?status=         (liste, viewer)        GET /api/runs/:id (détail, viewer)
//    POST /api/runs/:id/cancel      (écriture ; X-Forge-Operator)
//    GET  /api/runs/:id/events      (SSE log+status)       GET /api/runs/:id/logs?after= (fallback polling)
//    GET  /api/modules              (catalogue — filtre web_allowed côté UI)
//  Le secret opérateur N'EST stocké qu'en mémoire de session (variable JS) — jamais localStorage,
//  jamais en clair persistant. Il est envoyé via l'en-tête X-Forge-Operator sur run/cancel uniquement.
// =====================================================================================
let OPERATOR_SECRET = '';            // mémoire de session : jamais persisté (ni localStorage ni cookie)
let lcC2Probed = false;              // sonde l'état C2 une seule fois (la sonde POSTe /api/run)
const TERMINAL_RUN = new Set(['done', 'failed', 'timeout', 'cancelled']);
const RUNSTAT_BADGE = { running: 'webyes', done: 'ok', failed: 'destr', timeout: 'expl', cancelled: 'mut' };
let LC_LIVE = null;                  // { runId, es, poll, lastId, terminal } — flux du run suivi
let lcModulesLoaded = false;

// en-têtes pour une écriture C2 : opérateur (toujours) + viewer (Bearer) si l'auth viewer est ON.
// En dev-open (pas de pass_hash), seul X-Forge-Operator est requis ; le Bearer est inerte mais inoffensif.
// INVARIANT (anti-régression) : le secret opérateur ne transite QUE via l'en-tête X-Forge-Operator
// d'une requête POST (jamais en query-string ni dans un corps GET). Il NE DOIT JAMAIS être mis sur
// une URL EventSource/SSE (cf. startSse : EventSource ne peut pas porter d'en-tête -> on bascule en
// polling, on n'expose PAS le secret) ni loggé/persisté. Toute écriture C2 passe par operatorHeaders().
function operatorHeaders(extra = {}) {
  const h = { 'X-Forge-Operator': OPERATOR_SECRET, ...extra };
  const t = localStorage.getItem('forge_token');     // ne PROMPT pas : le token viewer est optionnel ici
  if (t) h.Authorization = 'Bearer ' + t;
  return h;
}

// ---------------------------------------------------------------------------------
//  Params SPÉCIFIQUES par module (envoyés dans /api/run body.module_params).
//  Schéma additif : chaque clé = kind de module ; valeur = liste de champs.
//  Seuls les modules WEB-ALLOWED (et donc lançables depuis le web) consomment des params ;
//  les params sont passés verbatim au moteur (Action.params), snake_case + JSON-sérialisable.
//  Référence moteur : evasion.xhr (types/url_contains/tab), evasion.turnstile (strategy/threshold/tab).
//  type: text|number|select|list (list = séparé par virgules -> array). Vide = champ omis (no-op).
// ---------------------------------------------------------------------------------
const MODULE_PARAMS = {
  'evasion.xhr': [
    { name: 'types', type: 'list', label: 'types (séparés par virgule)', placeholder: 'xhr, fetch, document' },
    { name: 'url_contains', type: 'text', label: 'url_contains (filtre sous-chaîne)', placeholder: '/api/' },
    { name: 'tab', type: 'text', label: 'tab (onglet browser)', placeholder: 'default' },
  ],
  'evasion.turnstile': [
    { name: 'strategy', type: 'select', label: 'strategy', value: 'turnstile', options: [{ value: 'turnstile', label: 'turnstile' }] },
    { name: 'threshold', type: 'number', label: 'threshold (0..1)', placeholder: '0.55', min: 0, max: 1, step: 0.05 },
    { name: 'tab', type: 'text', label: 'tab (onglet browser)', placeholder: 'default' },
  ],
};

// rendu de la liste de modules dans le formulaire : web_allowed=1 -> case cochable ;
// exploit|destructive -> GRISÉE par défaut + mention « CLI/opérateur — activer l'opt-in ».
// Quand l'opt-in « fort impact » est activé (case lc-allowhi) ET les conditions de gouvernance
// remplies (armer + raison + secret), ces modules deviennent SÉLECTIONNABLES (liseré danger).
// Le scope-guard serveur reste dur : hors-scope = VETO, indépendamment de cet opt-in côté front.
// Si le module définit des params (MODULE_PARAMS), ses champs propres apparaissent quand la case est cochée.
function highImpactOptIn() { return !!($('#lc-allowhi') && $('#lc-allowhi').checked); }
function renderLaunchModules() {
  const host = $('#lc-modlist'); if (!host) return;
  const hint = $('#lc-modhint');
  const hiOn = highImpactOptIn();
  const sorted = [...MODULES].sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
  // connecteur DÉSACTIVÉ par l'admin (enabled=0 ou available_override=0) : jamais sélectionnable au
  // lancement (le serveur refuse de toute façon — module_disabled 400 ; on l'expose ici sans surprise).
  const connOff = m => (m.enabled === false) || (m.available_override === false);
  const webable = sorted.filter(m => m.web_allowed && !m.exploit && !m.destructive && !connOff(m));
  const blocked = sorted.filter(m => m.exploit || m.destructive || !m.web_allowed || connOff(m));
  if (hint) hint.textContent = `${webable.length} web · ${blocked.length} ${hiOn ? 'à gouverner' : 'bloqués'}`;
  if (!sorted.length) { host.innerHTML = '<div class="muted">aucun module exposé par le moteur</div>'; return; }
  host.replaceChildren();
  sorted.forEach(m => {
    const highImpact = !!(m.exploit || m.destructive);
    // un connecteur DÉSACTIVÉ par l'admin n'est JAMAIS sélectionnable (au-dessus du plancher exploit :
    // même l'opt-in fort-impact ne le débloque pas — le serveur le refuse via module_disabled).
    const disabledByAdmin = connOff(m);
    // un module est sélectionnable s'il est web_allowed non-exploit/non-destructif, OU s'il est à
    // fort impact ET que l'opt-in gouverné est activé — et JAMAIS s'il est désactivé par l'admin.
    const allowed = !disabledByAdmin && ((!!m.web_allowed && !highImpact) || (highImpact && hiOn));
    const armedHi = highImpact && allowed;   // module à fort impact débloqué par l'opt-in
    const specs = (allowed && MODULE_PARAMS[m.kind]) || null;
    const lab = document.createElement('label');
    lab.className = 'lc-modopt' + (allowed ? '' : ' disabled') + (armedHi ? ' hi-armed' : '') + (specs ? ' has-params' : '');
    // ligne du haut : case + nom (+ mention bloquée / fort impact)
    const top = document.createElement('div'); top.className = 'lc-modtop';
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.value = m.kind; cb.dataset.lcmod = '1';
    if (highImpact) cb.dataset.lchi = '1';
    cb.disabled = !allowed;
    const nm = document.createElement('span'); nm.className = 'lc-modname'; nm.textContent = m.kind;
    top.append(cb, nm);
    if (!allowed) {
      const why = disabledByAdmin
        ? 'désactivé (admin)'
        : (highImpact
          ? 'CLI/opérateur — activer l\'opt-in ' + [m.exploit ? 'exploit' : '', m.destructive ? 'destructif' : ''].filter(Boolean).join('/')
          : 'CLI opérateur uniquement — non autorisé web');
      const tag = document.createElement('span'); tag.className = 'lc-clionly'; tag.textContent = why;
      top.appendChild(tag);
      lab.title = disabledByAdmin
        ? 'Connecteur désactivé par un administrateur (gouvernance) — non lançable (le serveur le refuse : module_disabled).'
        : (highImpact
          ? 'Module à fort impact : active l\'opt-in « fort impact » (zone danger) pour le sélectionner.'
          : 'Ce module ne peut pas être lancé depuis le web (non autorisé web).');
    } else if (armedHi) {
      const tag = document.createElement('span'); tag.className = 'lc-clionly'; tag.textContent = 'fort impact — ' + [m.exploit ? 'exploit' : '', m.destructive ? 'destructif' : ''].filter(Boolean).join('/');
      top.appendChild(tag);
      lab.title = 'Module à fort impact débloqué par l\'opt-in gouverné (scope-borné, audité).' + (m.mitre ? ' ' + m.mitre : '');
    } else if (m.mitre) {
      lab.title = m.mitre + (m.descr ? ' — ' + m.descr : '');
    }
    lab.appendChild(top);
    // bloc de params spécifiques : visible seulement quand la case est cochée (params-open).
    if (specs) {
      const pbox = document.createElement('div'); pbox.className = 'lc-modparams'; pbox.dataset.lcparamsFor = m.kind;
      specs.forEach(f => {
        const pf = document.createElement('div'); pf.className = 'lc-pf';
        const cap = document.createElement('span'); cap.textContent = f.label || f.name; pf.appendChild(cap);
        let inp;
        if (f.type === 'select') {
          inp = document.createElement('select');
          (f.options || []).forEach(o => { const op = document.createElement('option'); op.value = o.value; op.textContent = o.label; if (String(o.value) === String(f.value)) op.selected = true; inp.appendChild(op); });
        } else {
          inp = document.createElement('input');
          inp.type = f.type === 'number' ? 'number' : 'text';
          if (f.type === 'number') { if (f.min != null) inp.min = f.min; if (f.max != null) inp.max = f.max; if (f.step != null) inp.step = f.step; }
          if (f.placeholder) inp.placeholder = f.placeholder;
          if (f.value != null) inp.value = f.value;
        }
        inp.dataset.lcparam = f.name; inp.dataset.lcparamType = f.type || 'text';
        // un clic dans un champ ne doit pas (dé)cocher la case parente (label)
        inp.addEventListener('click', e => e.stopPropagation());
        pf.appendChild(inp); pbox.appendChild(pf);
      });
      lab.appendChild(pbox);
      // (dé)révèle le bloc params au cochage ; clic sur un champ ne propage pas.
      cb.addEventListener('change', () => lab.classList.toggle('params-open', cb.checked));
    }
    host.appendChild(lab);
  });
}

// Construit body.module_params à partir des modules WEB-ALLOWED cochés qui ont des champs renseignés.
// Coercition : list -> array (vide ignoré) ; number -> Number (NaN ignoré) ; text/select -> string non vide.
// Un module sans aucun champ renseigné est omis (pas de clé vide -> no-op côté backend).
function collectModuleParams() {
  const out = {};
  document.querySelectorAll('#lc-modlist .lc-modparams').forEach(box => {
    const kind = box.dataset.lcparamsFor;
    const lab = box.closest('.lc-modopt');
    const cb = lab && lab.querySelector('input[data-lcmod]');
    if (!cb || !cb.checked) return;                 // seuls les modules cochés (et donc dans modules[])
    const params = {};
    box.querySelectorAll('[data-lcparam]').forEach(inp => {
      const key = inp.dataset.lcparam, t = inp.dataset.lcparamType, raw = (inp.value || '').trim();
      if (raw === '') return;
      if (t === 'list') { const arr = raw.split(',').map(s => s.trim()).filter(Boolean); if (arr.length) params[key] = arr; }
      else if (t === 'number') { const n = Number(raw); if (!Number.isNaN(n)) params[key] = n; }
      else params[key] = raw;
    });
    if (Object.keys(params).length) out[kind] = params;
  });
  return out;
}

// montre l'état du rôle opérateur C2 (FAIL-CLOSED) en sondant /api/run sans secret.
//  403 operator_required  -> rôle armé côté serveur (le secret est requis pour lancer).
//  202/400/409            -> dev-open : un secret vide est accepté (on l'indique).
async function probeC2State() {
  const el = $('#lc-c2state'); if (!el) return;
  el.className = 'badge mut'; el.textContent = 'sonde…';
  // sonde non-destructive : campagne valide mais sans secret. Le serveur valide l'opérateur EN PREMIER.
  // (aucun run n'est créé : soit 403 operator_required, soit une 400 de validation plus loin.)
  // dev-open ET armé renvoient TOUS DEUX 403 operator_required (fail-closed) ; on les distingue par
  // le `why` : « non provisionné » (C2 fermé) vs « invalide ou absente » (rôle armé, secret exigé).
  try {
    const r = await fetch('/api/run', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forge-Operator': '' }, body: JSON.stringify({ campaign: '__c2probe__', targets: [] }) });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) { el.className = 'badge expl'; el.textContent = 'auth viewer requise'; el.title = 'L\'auth viewer (Basic/Bearer) est exigée avant le rôle opérateur.'; }
    else if (r.status === 403 && /non provisionn|C2 ferm/i.test(String(j.why || ''))) { el.className = 'badge destr'; el.innerHTML = `${ic('ban')} C2 fermé`; el.title = 'FAIL-CLOSED : rôle opérateur non provisionné (FORGE_CONSOLE_OPERATOR_HASH absent). Tout lancement renverra 403.'; }
    else if (r.status === 403) { el.className = 'badge ok'; el.innerHTML = `${ic('lock')} opérateur armé`; el.title = 'Rôle opérateur C2 armé : le secret X-Forge-Operator est exigé pour lancer.'; }
    else { el.className = 'badge mut'; el.textContent = 'état inattendu (' + r.status + ')'; el.title = String(j.why || j.error || ''); }
  } catch (e) { el.className = 'badge mut'; el.textContent = 'indisponible'; el.title = String(e.message || e); }
}

async function loadLaunch() {
  // catalogue de modules (réutilise MODULES global ; le charge si pas encore fait).
  if (!MODULES.length && !lcModulesLoaded) {
    try { MODULES = await api('/modules'); } catch (e) { /* la liste restera vide, hint le dira */ }
    lcModulesLoaded = true;
  }
  renderLaunchModules();
  if (!lcC2Probed) { lcC2Probed = true; probeC2State(); }   // sonde C2 une fois (évite de marteler /api/run)
  loadRuns();
  // si un run est déjà suivi, on garde le flux ; sinon on tente de raccrocher le run courant.
  if (!LC_LIVE) reattachRunningRun();
}

// raccroche automatiquement au run 'running' s'il en existe un (reprise après navigation/reload).
async function reattachRunningRun() {
  try {
    const runs = await api('/runs?status=running&limit=1');
    if (Array.isArray(runs) && runs.length) followRun(runs[0].run_id, runs[0]);
  } catch (e) { /* pas de run vivant : on laisse l'état par défaut */ }
}

function lcLogLine(stream, line) {
  const host = $('#lc-log'); if (!host) return;
  const span = document.createElement('span');
  span.className = 'lcl lcl-' + (stream || 'stdout');
  span.textContent = line;
  host.appendChild(span);
  // auto-scroll seulement si l'utilisateur est déjà en bas (ne le contrarie pas s'il lit en arrière).
  const atBottom = host.scrollHeight - host.scrollTop - host.clientHeight < 40;
  if (atBottom) host.scrollTop = host.scrollHeight;
}
function lcStatusLine(status, exitCode) {
  const host = $('#lc-log'); if (!host) return;
  const span = document.createElement('span');
  span.className = 'lcl lcl-status';
  span.textContent = `— statut : ${status}` + (exitCode != null ? ` (exit ${exitCode})` : '');
  host.appendChild(span);
  host.scrollTop = host.scrollHeight;
}
function lcSetLiveBadge(status) {
  const b = $('#lc-livebadge'); if (!b) return;
  const cls = RUNSTAT_BADGE[status] || 'mut';
  b.className = 'badge ' + cls;
  b.textContent = status || 'aucun';
}
function lcSetTransport(mode) {
  const t = $('#lc-transport'); if (!t) return;
  if (!mode) { t.className = 'badge mut'; t.textContent = '—'; return; }
  t.className = 'badge ' + (mode === 'sse' ? 'webyes' : 'mut');
  t.textContent = mode === 'sse' ? 'flux SSE' : 'polling';
  t.title = mode === 'sse' ? 'EventSource(/api/runs/:id/events)' : 'fallback polling GET /api/runs/:id/logs + /api/runs/:id';
}

// arrête proprement le flux courant (EventSource + timer de polling).
function lcStopLive() {
  if (!LC_LIVE) return;
  if (LC_LIVE.es) { try { LC_LIVE.es.close(); } catch (e) {} }
  if (LC_LIVE.poll) clearTimeout(LC_LIVE.poll);
  LC_LIVE = null;
}

// suit un run : reset du panneau, amorce le backlog de logs (cas reprise), branche SSE,
// fallback polling si l'EventSource erre. lastId est posé sur le backlog pour ne rien re-rendre.
async function followRun(runId, runMeta) {
  lcStopLive();
  LC_LIVE = { runId, es: null, poll: null, lastId: 0, terminal: false };
  const host = $('#lc-log'); if (host) host.replaceChildren();
  lcSetLiveBadge(runMeta && runMeta.status ? runMeta.status : 'running');
  const cancelBtn = $('#lc-cancel'); if (cancelBtn) cancelBtn.hidden = false;
  lcUpdateCounts(runMeta || null);
  // amorce : rejoue les lignes déjà persistées (reprise d'un run en cours), puis n'incrémente
  // qu'à partir de lastId. SSE ne diffuse que les NOUVEAUX events broadcast — sans ça, on perdrait
  // le backlog d'un run déjà démarré. (Petite fenêtre de course tolérée pour l'UX live.)
  try {
    const lg = await api('/runs/' + encodeURIComponent(runId) + '/logs?limit=2000');
    if (LC_LIVE && LC_LIVE.runId === runId) {
      (lg.lines || []).forEach(l => lcLogLine(l.stream, l.line));
      if (typeof lg.last_id === 'number') LC_LIVE.lastId = lg.last_id;
    }
  } catch (e) { /* pas de backlog (run tout neuf) : on démarre vide */ }
  if (!LC_LIVE || LC_LIVE.runId !== runId) return;   // un autre run a pris la main entre-temps
  startSse(runId);
}

// transport préféré : SSE. En cas d'erreur (proxy bufferisant / auth viewer empêchant EventSource),
// bascule automatiquement sur le polling, sans perdre de lignes (les deux sources sont identiques).
function startSse(runId) {
  // EventSource ne peut pas porter d'en-tête Authorization : en mode auth-viewer ON il 401 -> on
  // bascule sur le polling. C'est le comportement attendu (fallback documenté du contrat).
  // INVARIANT (anti-régression) : NE JAMAIS contourner cette limite en passant un secret (opérateur
  // ou Bearer) en query-string de l'URL EventSource/GET — ça le ferait fuiter dans les logs proxy/
  // historique. Le secret opérateur ne transite que via l'en-tête X-Forge-Operator d'un POST.
  let es;
  try { es = new EventSource('/api/runs/' + encodeURIComponent(runId) + '/events'); }
  catch (e) { return startPolling(runId); }
  if (!LC_LIVE || LC_LIVE.runId !== runId) { try { es.close(); } catch (e) {} return; }
  LC_LIVE.es = es;
  lcSetTransport('sse');
  let gotAny = false;
  es.addEventListener('log', ev => {
    gotAny = true;
    try { const d = JSON.parse(ev.data); lcLogLine(d.stream, d.line); } catch (e) {}
  });
  es.addEventListener('status', ev => {
    gotAny = true;
    try { const d = JSON.parse(ev.data); onRunStatus(runId, d.status, d.exit_code); } catch (e) {}
  });
  es.onerror = () => {
    // Une erreur AVANT tout évènement = transport indispo (proxy/auth) -> polling. Après des
    // évènements et hors état terminal = coupure réseau -> polling pour finir proprement.
    if (LC_LIVE && LC_LIVE.runId === runId && !LC_LIVE.terminal) {
      try { es.close(); } catch (e) {}
      LC_LIVE.es = null;
      startPolling(runId);
    }
  };
}

// fallback polling : logs incrémentaux (after=lastId) + statut/exit_code via le détail du run.
function startPolling(runId) {
  if (!LC_LIVE || LC_LIVE.runId !== runId || LC_LIVE.terminal) return;
  lcSetTransport('polling');
  const tick = async () => {
    if (!LC_LIVE || LC_LIVE.runId !== runId || LC_LIVE.terminal) return;
    try {
      const lg = await api('/runs/' + encodeURIComponent(runId) + '/logs?after=' + LC_LIVE.lastId);
      (lg.lines || []).forEach(l => lcLogLine(l.stream, l.line));
      if (typeof lg.last_id === 'number') LC_LIVE.lastId = lg.last_id;
      const det = await api('/runs/' + encodeURIComponent(runId));
      lcUpdateCounts(det);
      if (det && TERMINAL_RUN.has(det.status)) { onRunStatus(runId, det.status, det.exit_code); return; }
    } catch (e) { /* transitoire : on re-tente au prochain tick */ }
    if (LC_LIVE && LC_LIVE.runId === runId && !LC_LIVE.terminal) LC_LIVE.poll = setTimeout(tick, 1500);
  };
  tick();
}

// transition terminale d'un run : ligne de statut, badge, bouton annuler masqué, liste rafraîchie.
function onRunStatus(runId, status, exitCode) {
  if (!LC_LIVE || LC_LIVE.runId !== runId) return;
  lcSetLiveBadge(status);
  if (status === 'running') return;     // simple transition vers running : pas terminal
  lcStatusLine(status, exitCode);
  if (TERMINAL_RUN.has(status)) {
    LC_LIVE.terminal = true;
    const cancelBtn = $('#lc-cancel'); if (cancelBtn) cancelBtn.hidden = true;
    lcStopLive();
    loadRuns();                          // la liste reflète l'état final
    // rafraîchit le détail (counts/coverage_gaps consolidés par le superviseur).
    api('/runs/' + encodeURIComponent(runId)).then(lcUpdateCounts).catch(() => {});
  }
}

// compteurs du run en cours (fired/dry_run/vetoed/errors) + coverage_gaps. maj live pendant le run.
function lcUpdateCounts(run) {
  const cc = $('#lc-counts'), gp = $('#lc-gaps');
  if (!run) { if (cc) cc.hidden = true; if (gp) gp.hidden = true; return; }
  if (cc) {
    cc.hidden = false;
    const items = [['FIRE', run.fired, 'v-FIRE'], ['DRY_RUN', run.dry_run, 'v-DRY_RUN'], ['VETO', run.vetoed, 'v-VETO'], ['ERREURS', run.errors, 'errors']];
    cc.innerHTML = items.map(([lab, n, cls]) => `<div class="roecount ${cls}"><span class="rcn">${Number(n || 0)}</span><span class="rcl">${lab}</span></div>`).join('');
  }
  if (gp) {
    const gaps = run.coverage_gaps && typeof run.coverage_gaps === 'object' ? Object.keys(run.coverage_gaps) : [];
    const skipped = Array.isArray(run.skipped_budget) ? run.skipped_budget : [];
    const parts = [];
    if (gaps.length) parts.push('lacunes de couverture : ' + gaps.map(esc).join(', '));
    if (skipped.length) parts.push('différé (budget) : ' + skipped.map(esc).join(', '));
    if (parts.length) { gp.hidden = false; gp.innerHTML = parts.join(' · '); }
    else gp.hidden = true;
  }
}

// affiche un message d'erreur clair sous le formulaire (mappe les codes du contrat run_create).
const LC_ERRMAP = {
  operator_required: 'Secret opérateur requis ou invalide (en-tête X-Forge-Operator). Renseigne le mot de passe opérateur C2.',
  bad_campaign: 'Nom de campagne invalide : ^[A-Za-z0-9._-]{1,64}$ et pas de « - » en tête.',
  no_targets: 'Au moins une cible est requise (une par ligne).',
  bad_target: 'Cible invalide : hostname ou IP/CIDR, sans espace ni métacaractère.',
  out_of_scope: 'Cible hors du scope serveur autorisé — refusée avant lancement (le périmètre n\'est jamais élargi via le web).',
  bad_mode: 'Mode invalide (propose|auto).',
  exploit_floor: 'Module exploit/destructif refusé : active l\'opt-in « fort impact » (armer + raison + secret opérateur) pour l\'autoriser.',
  high_impact_requires_arm_and_reason: 'Opt-in « fort impact » incomplet : il faut cocher « armer » ET renseigner une raison non vide (le secret opérateur reste requis avant ce contrôle).',
  not_web_allowed: 'Module non autorisé en cadre web.',
  unknown_module: 'Module inconnu du moteur.',
  bad_module_params: 'Params de module mal formés (objet attendu, profondeur/longueurs bornées, pas de NUL).',
  param_for_unrequested_module: 'Params fournis pour un module non sélectionné — sélectionne le module ou retire ses params.',
  run_in_progress: 'Un run est déjà en cours (FIFO : un seul à la fois). Attends sa fin ou annule-le.',
  mkdir_failed: 'Erreur serveur : création du répertoire de run impossible.',
  write_failed: 'Erreur serveur : écriture scope/targets impossible.',
  spawn_failed: 'Erreur serveur : démarrage du moteur impossible.',
};
function lcShowErr(msg) { const e = $('#lc-err'); if (e) { e.innerHTML = msg; e.hidden = false; } }
function lcClearErr() { const e = $('#lc-err'); if (e) { e.textContent = ''; e.hidden = true; } }

// POST /api/run avec validation côté client miroir du contrat (messages clairs avant l'aller-retour).
async function submitRun(e) {
  e.preventDefault();
  lcClearErr();
  const campaign = ($('#lc-campaign').value || '').trim();
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(campaign) || campaign.startsWith('-')) { lcShowErr(LC_ERRMAP.bad_campaign); return; }
  const targets = ($('#lc-targets').value || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!targets.length) { lcShowErr(LC_ERRMAP.no_targets); return; }
  const checkedCbs = [...document.querySelectorAll('#lc-modlist input[data-lcmod]:checked')];
  const modules = checkedCbs.map(c => c.value);
  // modules à fort impact (exploit/destructif) effectivement cochés — ne peuvent l'être que si l'opt-in est ON.
  const hiModules = checkedCbs.filter(c => c.dataset.lchi === '1').map(c => c.value);
  if (!OPERATOR_SECRET) { lcShowErr(LC_ERRMAP.operator_required); $('#lc-operator') && $('#lc-operator').focus(); return; }
  const arm = !!($('#lc-arm') && $('#lc-arm').checked);
  const allowHigh = highImpactOptIn();
  const reason = ($('#lc-reason') && $('#lc-reason').value || '').trim();
  // GOUVERNANCE opt-in fort impact (miroir client du gate serveur high_impact_requires_arm_and_reason) :
  // si l'opt-in est ON, exiger armer + raison non vide AVANT le POST (le secret est déjà vérifié ci-dessus).
  if (allowHigh && (!arm || !reason)) {
    lcShowErr(`<b>high_impact_requires_arm_and_reason</b> — ${esc(LC_ERRMAP.high_impact_requires_arm_and_reason)}`);
    if (!arm && $('#lc-arm')) $('#lc-arm').focus();
    else if ($('#lc-reason')) $('#lc-reason').focus();
    return;
  }
  const body = {
    campaign, targets,
    mode: ($('#lc-mode') && $('#lc-mode').value) || 'propose',
    arm,
    exhaustive: !!($('#lc-exhaustive') && $('#lc-exhaustive').checked),
    allow_high_impact: allowHigh,
  };
  if (modules.length) body.modules = modules;
  // params spécifiques par module : { kind: {...} } — uniquement pour les modules cochés (⊆ modules[]).
  const moduleParams = collectModuleParams();
  if (Object.keys(moduleParams).length) body.module_params = moduleParams;
  const budgetRaw = ($('#lc-budget') && $('#lc-budget').value || '').trim();
  if (budgetRaw !== '') { const b = Number(budgetRaw); if (!Number.isNaN(b)) body.budget = b; }
  if (reason) body.reason = reason.slice(0, 200);

  // DOUBLE-CONFIRMATION : tout lancement avec allow_high_impact=true exige une validation explicite
  // récapitulant cibles, modules à fort impact, scope (⊆ scope serveur — hors-scope vétoé), et raison.
  if (allowHigh) {
    const ok = await confirmHighImpact({ campaign, targets, hiModules, modules, reason, mode: body.mode });
    if (!ok) return;
  }

  const btn = $('#lc-submit'); const stat = $('#lc-formstat');
  if (btn) btn.disabled = true; if (stat) stat.textContent = 'lancement…';
  let r, j;
  try {
    r = await fetch('/api/run', { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    j = await r.json().catch(() => ({}));
  } catch (err) {
    if (btn) btn.disabled = false; if (stat) stat.textContent = '';
    lcShowErr('Erreur réseau : ' + esc(String(err.message || err))); return;
  }
  if (btn) btn.disabled = false; if (stat) stat.textContent = '';
  if (r.status === 202) {
    const hi = j.high_impact === true;
    toast(`Campagne « ${j.campaign} » lancée (${j.mode}${hi ? ' · fort impact' : ''}) — ${j.run_id}`, hi ? 'bad' : 'ok');
    location.hash = 'launch';
    followRun(j.run_id, { status: 'running', campaign: j.campaign, mode: j.mode, fired: 0, dry_run: 0, vetoed: 0, errors: 0 });
    loadRuns();
    return;
  }
  // refus : message clair (403 opérateur / 400 validation / 409 FIFO / 5xx serveur).
  const code = j && j.error ? j.error : ('http_' + r.status);
  const base = LC_ERRMAP[j && j.error] || ('Refus serveur (' + esc(code) + ')');
  lcShowErr(`<b>${esc(code)}</b> — ${esc(base)}` + (j && j.why ? `<br><span class="muted" style="margin:0">${esc(j.why)}</span>` : ''));
}

// DOUBLE-CONFIRMATION fort impact : modale récapitulative (DOM sûr, textContent) avant POST /api/run
// avec allow_high_impact=true. Liste cibles, modules à fort impact sélectionnés, scope et raison ;
// exige une confirmation explicite. Résout true (confirmé) / false (annulé).
function confirmHighImpact(ctx) {
  return new Promise(resolve => {
    const ov = document.createElement('div'); ov.className = 'modal-ov';
    const box = document.createElement('div'); box.className = 'modal danger wide';
    const done = val => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); resolve(val); };
    const onKey = e => { if (e.key === 'Escape') done(false); };
    document.addEventListener('keydown', onKey);
    const h = document.createElement('h3'); h.textContent = 'Confirmer un lancement à FORT IMPACT'; box.appendChild(h);
    const warn = document.createElement('p'); warn.className = 'modal-msg';
    warn.textContent = 'Tu actives des modules exploit/destructif. Action scope-bornée et auditée : toute cible hors du scope serveur sera vétoée. Confirme l\'engagement.';
    box.appendChild(warn);
    const wrap = document.createElement('div'); wrap.className = 'lc-hiconf';
    const dl = document.createElement('dl');
    const row = (label, build) => { const dt = document.createElement('dt'); dt.textContent = label; const dd = document.createElement('dd'); build(dd); dl.append(dt, dd); };
    row('Campagne', dd => dd.textContent = ctx.campaign || '-');
    row('Mode', dd => dd.textContent = ctx.mode || 'propose');
    row('Cibles (⊆ scope)', dd => dd.textContent = (ctx.targets || []).join(', ') || '-');
    row('Modules fort impact', dd => {
      const chips = document.createElement('div'); chips.className = 'lc-hichips';
      (ctx.hiModules || []).forEach(k => { const b = document.createElement('span'); b.className = 'badge destr'; b.textContent = k; chips.appendChild(b); });
      if (!(ctx.hiModules || []).length) { const s = document.createElement('span'); s.className = 'muted'; s.textContent = 'aucun coché'; chips.appendChild(s); }
      dd.appendChild(chips);
    });
    const otherMods = (ctx.modules || []).filter(m => !(ctx.hiModules || []).includes(m));
    if (otherMods.length) row('Autres modules', dd => dd.textContent = otherMods.join(', '));
    row('Raison (audit)', dd => dd.textContent = ctx.reason || '-');
    wrap.appendChild(dl);
    const scopeNote = document.createElement('div'); scopeNote.className = 'lc-warn bad'; scopeNote.style.margin = '0';
    scopeNote.textContent = 'Garde-fou de périmètre INCHANGÉ : le serveur revérifie chaque cible contre le scope autorisé. Hors-scope = VETO dur, sans exception. Le lancement est journalisé au ledger.';
    wrap.appendChild(scopeNote);
    box.appendChild(wrap);
    const act = document.createElement('div'); act.className = 'modal-act';
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'm-cancel'; cancel.textContent = 'Annuler'; cancel.onclick = () => done(false);
    const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'm-ok danger'; ok.textContent = 'Confirmer & lancer (fort impact)'; ok.onclick = () => done(true);
    act.append(cancel, ok); box.appendChild(act);
    ov.onclick = e => { if (e.target === ov) done(false); };
    ov.appendChild(box); document.body.appendChild(ov);
    setTimeout(() => cancel.focus(), 30);
  });
}

// État de la zone danger : reflète l'(in)complétude des conditions de gouvernance (armer/raison/secret)
// et bascule l'apparence + re-rend la liste de modules pour (dé)bloquer exploit/destructif.
function lcSyncDanger() {
  const dz = $('#lc-danger'); if (!dz) return;
  const on = highImpactOptIn();
  dz.classList.toggle('on', on);
  const reqs = $('#lc-hireqs');
  if (reqs) {
    if (!on) { reqs.replaceChildren(); }
    else {
      const arm = !!($('#lc-arm') && $('#lc-arm').checked);
      const reason = !!(($('#lc-reason') && $('#lc-reason').value || '').trim());
      const secret = !!OPERATOR_SECRET;
      reqs.replaceChildren();
      [['armer', arm], ['raison', reason], ['secret opérateur', secret]].forEach(([label, ok]) => {
        const s = document.createElement('span'); s.className = 'req ' + (ok ? 'ok' : 'miss');
        s.textContent = (ok ? '✓ ' : '✗ ') + label; reqs.appendChild(s);
      });
    }
  }
  renderLaunchModules();   // re-rend pour (dé)bloquer les modules à fort impact selon l'opt-in
}

async function cancelRun() {
  const runId = LC_LIVE && LC_LIVE.runId;
  if (!runId) { toast('Aucun run en cours à annuler.', 'bad'); return; }
  if (!OPERATOR_SECRET) { lcShowErr(LC_ERRMAP.operator_required); location.hash = 'launch'; return; }
  if (!(await confirmModal('Annuler le run en cours ? Le groupe de processus sera tué.', { danger: true, okText: 'Annuler le run' }))) return;
  let r, j;
  try {
    r = await fetch('/api/runs/' + encodeURIComponent(runId) + '/cancel', { method: 'POST', headers: operatorHeaders() });
    j = await r.json().catch(() => ({}));
  } catch (err) { toast('Erreur réseau : ' + (err.message || err), 'bad'); return; }
  if (r.ok) { toast('Annulation demandée — kill group envoyé.', 'ok'); lcSetLiveBadge('cancelled'); }
  else {
    const map = { operator_required: LC_ERRMAP.operator_required, not_running: 'Le run n\'est pas/plus en cours.', unknown_run: 'Run inconnu.' };
    toast((map[j && j.error] || ('Refus (' + (j && j.error || r.status) + ')')), 'bad');
  }
}

// liste des runs (récents d'abord) — clic = détail.
let LC_RUNS = [];
async function loadRuns() {
  const host = $('#lc-runresult'); if (!host) return;
  const st = $('#lc-runstatus') && $('#lc-runstatus').value;
  let rows = [];
  try { rows = await api('/runs?limit=100' + (st ? '&status=' + encodeURIComponent(st) : '')); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  LC_RUNS = Array.isArray(rows) ? rows : [];
  if ($('#lc-runcount')) $('#lc-runcount').textContent = LC_RUNS.length + ' runs';
  if (!LC_RUNS.length) { host.innerHTML = '<div class="muted">aucun run</div>'; return; }
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = `<thead><tr><th>#</th><th>Statut</th><th>Campagne</th><th>Mode</th><th>FIRE/DRY/VETO</th><th>Err</th><th>Cibles</th><th>Date</th></tr></thead>`;
  const tb = document.createElement('tbody');
  LC_RUNS.forEach((x, i) => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour le détail du run';
    const cls = RUNSTAT_BADGE[x.status] || 'mut';
    const ntgt = Array.isArray(x.targets) ? x.targets.length : 0;
    tr.innerHTML = `<td class="numcol">${i + 1}</td><td><span class="badge ${cls}">${esc(x.status)}</span></td><td>${esc(x.campaign)}</td>`
      + `<td class="mut">${esc(x.mode)}</td><td class="mono">${Number(x.fired || 0)}/${Number(x.dry_run || 0)}/${Number(x.vetoed || 0)}</td>`
      + `<td class="mut">${Number(x.errors || 0)}</td><td class="mut">${ntgt}</td><td class="mut">${esc(fmtTs(x.ts))}</td>`;
    tr.onclick = () => openRun(x.run_id);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}
if ($('#lc-runstatus')) $('#lc-runstatus').addEventListener('change', loadRuns);
if ($('#lc-runreload')) $('#lc-runreload').addEventListener('click', loadRuns);

// détail d'un run (status, counts, coverage_gaps, skipped_budget, log_tail).
async function openRun(runId) {
  let d, logs;
  try { d = await api('/runs/' + encodeURIComponent(runId)); }
  catch (e) { toast('Détail run : ' + e.message, 'bad'); return; }
  try { logs = await api('/runs/' + encodeURIComponent(runId) + '/logs?limit=200'); } catch (e) { logs = { lines: [] }; }
  infoModal('Run ' + (d.campaign || '') + ' — ' + runId, body => {
    const meta = document.createElement('div'); meta.className = 'findmeta';
    const cls = RUNSTAT_BADGE[d.status] || 'mut';
    meta.innerHTML = `<span class="badge ${cls}">${esc(d.status)}</span> <span class="badge mut">${esc(d.mode)}</span>`
      + (d.exit_code != null ? ` <span class="badge mut">exit ${esc(d.exit_code)}</span>` : '')
      + ` <span class="badge mut">par ${esc(d.started_by || '-')}</span>`;
    // bouton « Rapport » : GET /api/runs/:id/report -> markdown (modale read-only).
    const rep = document.createElement('button'); rep.type = 'button'; rep.className = 'k-theme'; rep.style.marginLeft = '8px';
    rep.textContent = 'Rapport'; rep.title = 'Voir le rapport markdown de ce run (synthèse + findings + transparence ROE)';
    rep.onclick = () => openRunReport(runId);
    meta.appendChild(rep);
    // bouton « Rapport HTML » : livrable client brandé (thème Aurora, page de garde, CSS print).
    const repHtml = document.createElement('button'); repHtml.type = 'button'; repHtml.className = 'k-theme'; repHtml.style.marginLeft = '8px';
    repHtml.textContent = 'Rapport HTML'; repHtml.title = 'Ouvrir le rapport client brandé (HTML imprimable, résumé exécutif, CWE/CVSS, chaîne de custody)';
    repHtml.onclick = () => openRunReportHtml(runId, false);
    meta.appendChild(repHtml);
    // bouton « Imprimer / PDF » : ouvre le HTML brandé et lance l'impression (Enregistrer en PDF).
    const repPdf = document.createElement('button'); repPdf.type = 'button'; repPdf.className = 'k-theme'; repPdf.style.marginLeft = '8px';
    repPdf.textContent = 'Imprimer / PDF'; repPdf.title = 'Ouvre le rapport brandé et lance l\'impression (« Enregistrer au format PDF »)';
    repPdf.onclick = () => openRunReportHtml(runId, true);
    meta.appendChild(repPdf);
    body.appendChild(meta);
    const counts = document.createElement('div'); counts.className = 'roecounters'; counts.style.marginTop = '12px';
    counts.innerHTML = [['FIRE', d.fired, 'v-FIRE'], ['DRY_RUN', d.dry_run, 'v-DRY_RUN'], ['VETO', d.vetoed, 'v-VETO'], ['ERREURS', d.errors, 'errors']]
      .map(([lab, n, c]) => `<div class="roecount ${c}"><span class="rcn">${Number(n || 0)}</span><span class="rcl">${lab}</span></div>`).join('');
    body.appendChild(counts);
    const kv = document.createElement('dl'); kv.className = 'kvdetail';
    const targets = Array.isArray(d.targets) ? d.targets.join(', ') : '';
    const modules = Array.isArray(d.modules) ? d.modules.join(', ') : '';
    const gaps = d.coverage_gaps && typeof d.coverage_gaps === 'object' ? Object.keys(d.coverage_gaps) : [];
    const skipped = Array.isArray(d.skipped_budget) ? d.skipped_budget : [];
    [['Campagne', d.campaign], ['Cibles', targets], ['Modules', modules || '(planner)'], ['Raison', d.reason],
     ['Lacunes couverture', gaps.length ? gaps.join(', ') : '-'], ['Différé (budget)', skipped.length ? skipped.join(', ') : '-'],
     ['Démarré', fmtTs(d.started || d.ts)], ['Terminé', d.finished ? fmtTs(d.finished) : '-']].forEach(([k, v]) => {
      const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = (v == null || v === '') ? '-' : String(v); kv.append(dt, dd);
    });
    body.appendChild(kv);
    // log_tail
    const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = 'Log (extrait)';
    const pre = document.createElement('pre'); pre.className = 'mailtext';
    const lines = (logs.lines || []).map(l => (l.stream === 'stderr' ? '[err] ' : l.stream === 'system' ? '[sys] ' : '') + l.line);
    pre.textContent = lines.length ? lines.join('\n') : '(aucune ligne)';
    body.append(h, pre);
  });
}

if ($('#lc-runform')) $('#lc-runform').addEventListener('submit', submitRun);
if ($('#lc-cancel')) $('#lc-cancel').addEventListener('click', cancelRun);
// secret opérateur : capté en mémoire de session uniquement (l'input ne reste pas porteur du secret).
if ($('#lc-operator')) $('#lc-operator').addEventListener('input', e => { OPERATOR_SECRET = e.target.value; lcSyncDanger(); });
if ($('#lc-clearop')) $('#lc-clearop').addEventListener('click', () => { OPERATOR_SECRET = ''; if ($('#lc-operator')) $('#lc-operator').value = ''; lcSyncDanger(); toast('Secret opérateur oublié (session).', 'ok'); });
// avertissement « armer » : visible quand la case est cochée + rafraîchit les conditions de gouvernance.
if ($('#lc-arm')) $('#lc-arm').addEventListener('change', e => { const w = $('#lc-armwarn'); if (w) w.hidden = !e.target.checked; lcSyncDanger(); });
if ($('#lc-reason')) $('#lc-reason').addEventListener('input', lcSyncDanger);
// ZONE DANGER : opt-in fort impact (défaut OFF) — (dé)bloque exploit/destructif + recalcule les conditions.
if ($('#lc-allowhi')) $('#lc-allowhi').addEventListener('change', lcSyncDanger);

// =====================================================================================
//  PARITÉ LECTURE/GOUVERNANCE : scope-check, dry-plan + approbation RECON, rapport de run.
//  Endpoints (tous viewer + host_guard) :
//    POST /api/scope-check {target}            -> {target, in_scope, mode, allow_exploit, allow_destructive} | 400 bad_target
//    POST /api/plan {targets, modules?}        -> {dry_run, mode, targets, modules, actions[], exit_ok, stdout, stderr, note} | 400
//    GET  /api/runs/:id/report                 -> text/markdown | 404 unknown_run
//  INVARIANT (transparence) : allow_exploit/allow_destructive sont TOUJOURS false (plancher exploit
//  côté web) — affiché comme un fait, jamais comme une bascule. Le dry-plan est INERTE (rien ne tire
//  ni ne persiste) ; l'approbation granulaire ne relance QUE des actions RECON/non-exploit en auto.
// =====================================================================================

// --- SCOPE-CHECK : champ cible -> badge IN/OUT scope + mode/flags (lecture pure) ---
async function lcScopeCheck() {
  const inp = $('#lc-scopetarget'); const out = $('#lc-scoperes'); const add = $('#lc-scopeadd');
  if (!inp || !out) return;
  const target = (inp.value || '').trim();
  if (add) add.hidden = true;
  if (!target) { out.hidden = true; return; }
  out.hidden = false;
  out.innerHTML = '<span class="muted">vérification…</span>';
  let r, j;
  try {
    r = await fetch('/api/scope-check', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ target }) });
    j = await r.json().catch(() => ({}));
  } catch (e) { out.innerHTML = `<span class="badge destr">erreur réseau</span> <span class="muted">${esc(String(e.message || e))}</span>`; return; }
  if (r.status === 400 || (j && j.error)) {
    out.innerHTML = `<span class="badge destr">${ic('warn')} ${esc(j && j.error || 'bad_target')}</span> <span class="muted">${esc((j && j.why) || 'cible malformée (validate_host)')}</span>`;
    return;
  }
  if (!r.ok) { out.innerHTML = `<span class="badge destr">refus serveur (${r.status})</span>`; return; }
  const inScope = j.in_scope === true;
  const badge = inScope
    ? `<span class="badge inscope">${ic('check')} IN SCOPE</span>`
    : `<span class="badge outscope">${ic('ban')} HORS SCOPE</span>`;
  // allow_exploit/allow_destructive sont TOUJOURS false (invariant plancher exploit) : on l'affiche comme un fait.
  const flags = `<span class="lc-scope-flags">mode <b>${esc(j.mode || '?')}</b> · exploit ${j.allow_exploit ? 'autorisé' : 'bloqué'} · destructif ${j.allow_destructive ? 'autorisé' : 'bloqué'}</span>`;
  out.innerHTML = `${badge} <code>${esc(j.target || target)}</code> ${flags}`;
  // si la cible est en scope, proposer de l'ajouter aux cibles du lancement (confort, pas une bascule).
  if (add && inScope) { add.hidden = false; add.dataset.target = j.target || target; }
}
function lcScopeAddTarget() {
  const add = $('#lc-scopeadd'); const ta = $('#lc-targets');
  if (!add || !ta) return;
  const t = add.dataset.target || '';
  if (!t) return;
  const lines = (ta.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!lines.includes(t)) { lines.push(t); ta.value = lines.join('\n'); toast('Cible ajoutée au lancement.', 'ok'); }
  else toast('Cible déjà dans la liste.', 'info');
}
if ($('#lc-scopecheck')) $('#lc-scopecheck').addEventListener('click', lcScopeCheck);
if ($('#lc-scopetarget')) $('#lc-scopetarget').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); lcScopeCheck(); } });
if ($('#lc-scopeadd')) $('#lc-scopeadd').addEventListener('click', lcScopeAddTarget);

// --- DRY-PLAN : POST /api/plan (INERTE) -> rendu action->verdict + cases d'approbation RECON ---
const PLAN_VERDICT_BADGE = { FIRE: 'v-FIRE', DRY_RUN: 'v-DRY_RUN', VETO: 'v-VETO', SKIP: 'mut' };
let LC_PLAN = null;   // dernier dry-plan : { targets, modules, actions[] } — base de l'approbation
// lit les cibles/modules courants du formulaire (mêmes règles miroir que submitRun, sans secret opérateur).
function lcReadTargetsModules() {
  const targets = ($('#lc-targets') && $('#lc-targets').value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const modules = [...document.querySelectorAll('#lc-modlist input[data-lcmod]:checked')].map(c => c.value);
  return { targets, modules };
}
async function lcDryPlan() {
  lcClearErr();
  const { targets, modules } = lcReadTargetsModules();
  if (!targets.length) { lcShowErr(LC_ERRMAP.no_targets); location.hash = 'launch'; return; }
  const sec = $('#lc-plan'); const host = $('#lc-planresult'); const cnt = $('#lc-plancount');
  if (sec) sec.hidden = false;
  if (host) host.innerHTML = '<div class="muted">dry-plan en cours… (INERTE — rien ne tire)</div>';
  if (cnt) { cnt.className = 'badge mut'; cnt.textContent = 'en cours…'; }
  const btn = $('#lc-dryplan'); if (btn) btn.disabled = true;
  const body = { targets };
  if (modules.length) body.modules = modules;
  let r, j;
  try {
    r = await fetch('/api/plan', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    j = await r.json().catch(() => ({}));
  } catch (e) {
    if (btn) btn.disabled = false;
    if (host) host.innerHTML = `<div class="bad">erreur réseau : ${esc(String(e.message || e))}</div>`;
    if (cnt) { cnt.className = 'badge destr'; cnt.textContent = 'erreur'; }
    return;
  }
  if (btn) btn.disabled = false;
  if (!r.ok || (j && j.error)) {
    const code = (j && j.error) || ('http_' + r.status);
    const msg = LC_ERRMAP[j && j.error] || ('Refus serveur (' + code + ')');
    if (host) host.innerHTML = `<div class="bad"><b>${esc(code)}</b> — ${esc(msg)}${(j && j.why) ? '<br><span class="muted">' + esc(j.why) + '</span>' : ''}</div>`;
    if (cnt) { cnt.className = 'badge destr'; cnt.textContent = code; }
    LC_PLAN = null; lcSyncApproveBtn();
    return;
  }
  LC_PLAN = { targets: Array.isArray(j.targets) ? j.targets : targets, modules: Array.isArray(j.modules) ? j.modules : modules, actions: Array.isArray(j.actions) ? j.actions : [] };
  renderPlan(j);
}
// rend la table action->verdict + colonne d'approbation (RECON/non-exploit cochable) + sortie brute moteur.
function renderPlan(j) {
  const host = $('#lc-planresult'); const cnt = $('#lc-plancount'); if (!host) return;
  const actions = Array.isArray(j.actions) ? j.actions : [];
  const tally = { FIRE: 0, DRY_RUN: 0, VETO: 0, SKIP: 0 };
  actions.forEach(a => { const v = String(a.verdict || '').toUpperCase(); if (tally[v] != null) tally[v]++; });
  if (cnt) { cnt.className = 'badge ' + (j.exit_ok ? 'ok' : 'mut'); cnt.textContent = `${actions.length} action(s)`; }
  host.replaceChildren();
  if (!actions.length) {
    const d = document.createElement('div'); d.className = 'muted';
    d.textContent = 'Aucune action proposée par le moteur (aperçu vide).';
    host.appendChild(d);
  } else {
    const table = document.createElement('table'); table.className = 'lc-plantbl';
    table.innerHTML = `<thead><tr><th>Approuver</th><th>Verdict</th><th>Type</th><th>Cible</th><th>Ligne moteur</th></tr></thead>`;
    const tb = document.createElement('tbody');
    actions.forEach((a, i) => {
      const verdict = String(a.verdict || '').toUpperCase();
      const cls = PLAN_VERDICT_BADGE[verdict] || 'mut';
      const tr = document.createElement('tr');
      // approbation : uniquement les actions qui PEUVENT être relancées (RECON/non-exploit) =
      // verdict non-VETO. Une action VETO ne sera jamais relançable depuis le web (plancher serveur).
      const approvable = verdict !== 'VETO';
      const apTd = document.createElement('td'); apTd.className = 'lc-papprove';
      if (approvable) {
        const cb = document.createElement('input'); cb.type = 'checkbox'; cb.className = 'lc-approve-cb';
        cb.dataset.idx = String(i); cb.title = 'Approuver cette action (RECON/non-exploit) pour relance en auto';
        cb.addEventListener('change', lcSyncApproveBtn);
        apTd.appendChild(cb);
      } else {
        apTd.innerHTML = '<span class="muted" title="VETO : jamais relançable depuis le web">—</span>';
      }
      const vTd = document.createElement('td'); vTd.innerHTML = `<span class="badge ${cls}">${esc(verdict || '?')}</span>`;
      const kTd = document.createElement('td'); kTd.innerHTML = a.kind ? `<code>${esc(a.kind)}</code>` : '<span class="muted">-</span>';
      const tTd = document.createElement('td'); tTd.textContent = a.target || '-';
      const lTd = document.createElement('td'); lTd.className = 'lc-pline'; lTd.textContent = a.line || '';
      tr.append(apTd, vTd, kTd, tTd, lTd);
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    const tally_line = document.createElement('div'); tally_line.className = 'lc-planhint'; tally_line.style.marginTop = '8px';
    tally_line.innerHTML = ['FIRE', 'DRY_RUN', 'VETO', 'SKIP'].map(k => `<span class="badge ${PLAN_VERDICT_BADGE[k]}">${k} ${tally[k]}</span>`).join(' ');
    host.append(table, tally_line);
  }
  // note d'inertie + sortie brute (transparence, repliée par défaut via <details>).
  if (j.note) { const n = document.createElement('div'); n.className = 'lc-planhint'; n.style.marginTop = '8px'; n.innerHTML = `<b>INERTE</b> — ${esc(j.note)}`; host.appendChild(n); }
  const rawOut = [(j.stdout || '').trim(), (j.stderr || '').trim() ? '[stderr]\n' + (j.stderr || '').trim() : ''].filter(Boolean).join('\n\n');
  if (rawOut) {
    const det = document.createElement('details');
    const sum = document.createElement('summary'); sum.className = 'muted'; sum.style.cursor = 'pointer'; sum.style.fontSize = '12px'; sum.textContent = `Sortie moteur (exit ${j.exit_ok ? 'OK' : 'non-OK'})`;
    const pre = document.createElement('pre'); pre.className = 'lc-planout'; pre.textContent = rawOut;
    det.append(sum, pre); host.appendChild(det);
  }
  const allBtn = $('#lc-approve-all'); if (allBtn) allBtn.hidden = !host.querySelector('.lc-approve-cb');
  lcSyncApproveBtn();
}
// active le bouton d'approbation selon le nombre d'actions cochées ; met à jour le libellé de statut.
function lcSyncApproveBtn() {
  const btn = $('#lc-approve'); const stat = $('#lc-approvestat');
  const checked = [...document.querySelectorAll('#lc-planresult .lc-approve-cb:checked')];
  if (btn) btn.disabled = checked.length === 0 || !LC_PLAN;
  if (stat) stat.textContent = checked.length ? `${checked.length} action(s) approuvée(s)` : '';
}
// relance les actions approuvées en mode auto (RECON/non-exploit). L'exploit reste bloqué côté serveur :
// on ne transmet QUE les modules des actions cochées (⊆ web_allowed non-exploit), via POST /api/run.
async function lcApproveAndRun() {
  if (!LC_PLAN) { toast('Lance d\'abord un dry-plan.', 'bad'); return; }
  const checked = [...document.querySelectorAll('#lc-planresult .lc-approve-cb:checked')].map(cb => Number(cb.dataset.idx));
  if (!checked.length) { toast('Coche au moins une action à approuver.', 'bad'); return; }
  // modules approuvés = kinds distincts des actions cochées (le moteur replanifie le reste).
  const kinds = [...new Set(checked.map(i => LC_PLAN.actions[i]).filter(Boolean).map(a => String(a.kind || '').trim()).filter(Boolean))];
  // garde-fou client : ne soumettre que des modules que la liste connaît comme web_allowed/non-exploit.
  const webable = new Set(MODULES.filter(m => m.web_allowed && !m.exploit && !m.destructive).map(m => m.kind));
  const safe = kinds.filter(k => webable.has(k));
  const dropped = kinds.filter(k => !webable.has(k));
  if (dropped.length) toast('Modules non lançables web ignorés : ' + dropped.join(', '), 'bad');
  if (!OPERATOR_SECRET) { lcShowErr(LC_ERRMAP.operator_required); location.hash = 'launch'; if ($('#lc-operator')) $('#lc-operator').focus(); return; }
  const campaign = ($('#lc-campaign') && $('#lc-campaign').value || '').trim();
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(campaign) || campaign.startsWith('-')) { lcShowErr(LC_ERRMAP.bad_campaign); location.hash = 'launch'; return; }
  if (!(await confirmModal(`Approuver et lancer ${checked.length} action(s) RECON en mode auto ? (l'exploit reste bloqué côté serveur)`, { okText: 'Approuver & lancer', danger: false }))) return;
  const body = { campaign, targets: LC_PLAN.targets.slice(), mode: 'auto', arm: false, exhaustive: false };
  if (safe.length) body.modules = safe;   // vide -> le planner choisit (toujours sous plancher exploit)
  const reason = ($('#lc-reason') && $('#lc-reason').value || '').trim();
  body.reason = (reason ? reason + ' — ' : '') + `approbation dry-plan (${checked.length} action(s) RECON)`;
  body.reason = body.reason.slice(0, 200);
  const stat = $('#lc-approvestat'); const btn = $('#lc-approve');
  if (btn) btn.disabled = true; if (stat) stat.textContent = 'lancement…';
  let r, j;
  try {
    r = await fetch('/api/run', { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    j = await r.json().catch(() => ({}));
  } catch (err) { if (btn) btn.disabled = false; if (stat) stat.textContent = ''; lcShowErr('Erreur réseau : ' + esc(String(err.message || err))); location.hash = 'launch'; return; }
  if (btn) btn.disabled = false; if (stat) stat.textContent = '';
  if (r.status === 202) {
    toast(`Campagne « ${j.campaign} » lancée (auto, RECON approuvé) — ${j.run_id}`, 'ok');
    location.hash = 'launch';
    followRun(j.run_id, { status: 'running', campaign: j.campaign, mode: j.mode, fired: 0, dry_run: 0, vetoed: 0, errors: 0 });
    loadRuns();
    return;
  }
  const code = (j && j.error) || ('http_' + r.status);
  const base = LC_ERRMAP[j && j.error] || ('Refus serveur (' + esc(code) + ')');
  lcShowErr(`<b>${esc(code)}</b> — ${esc(base)}` + (j && j.why ? `<br><span class="muted" style="margin:0">${esc(j.why)}</span>` : ''));
  location.hash = 'launch';
}
if ($('#lc-dryplan')) $('#lc-dryplan').addEventListener('click', lcDryPlan);
if ($('#lc-approve')) $('#lc-approve').addEventListener('click', lcApproveAndRun);
if ($('#lc-approve-all')) $('#lc-approve-all').addEventListener('click', () => {
  document.querySelectorAll('#lc-planresult .lc-approve-cb').forEach(cb => { cb.checked = true; });
  lcSyncApproveBtn();
});

// --- RAPPORT DE RUN : GET /api/runs/:id/report (text/markdown) -> modale read-only ---
async function openRunReport(runId) {
  let r, md;
  try {
    r = await fetch('/api/runs/' + encodeURIComponent(runId) + '/report', { headers: { Accept: 'text/markdown' } });
    md = await r.text().catch(() => '');
  } catch (e) { toast('Rapport : ' + (e.message || e), 'bad'); return; }
  if (r.status === 404) { toast('Run inconnu (pas de rapport).', 'bad'); return; }
  if (!r.ok) { toast('Rapport indisponible (' + r.status + ').', 'bad'); return; }
  infoModal('Rapport — ' + runId, body => {
    const pre = document.createElement('pre'); pre.className = 'mailtext lc-report'; pre.textContent = md || '(rapport vide)';
    body.appendChild(pre);
  });
}

// --- RAPPORT HTML BRANDÉ : GET /api/runs/:id/report?format=html -> nouvelle fenêtre imprimable ---
// L'endpoint est sous auth_guard : une navigation directe ne porterait pas le Bearer (localStorage).
// On FETCH avec l'en-tête d'auth, puis on écrit le HTML dans une fenêtre same-origin en injectant
// une <base href> (l'URL canonique du rapport) pour que les liens relatifs (?format=pdf/md) et
// /quetzal.svg résolvent correctement. `print=true` déclenche l'impression (« Enregistrer en PDF »).
async function openRunReportHtml(runId, print) {
  const url = '/api/runs/' + encodeURIComponent(runId) + '/report?format=html';
  let r, html;
  try {
    r = await fetch(url, { headers: authHeaders({ Accept: 'text/html' }) });
    html = await r.text().catch(() => '');
  } catch (e) { toast('Rapport HTML : ' + (e.message || e), 'bad'); return; }
  if (r.status === 404) { toast('Run inconnu (pas de rapport).', 'bad'); return; }
  if (!r.ok) { toast('Rapport HTML indisponible (' + r.status + ').', 'bad'); return; }
  // injecte une <base href> (URL canonique du rapport) pour que les liens relatifs (?format=pdf/md)
  // et /quetzal.svg résolvent en same-origin, puis publie le document via un Blob URL (évite
  // document.write ; le HTML provient de notre endpoint authentifié, tout dynamique étant échappé
  // côté serveur). Le Blob URL est révoqué après ouverture.
  const baseHref = new URL(url, location.href).href;
  const withBase = html.replace(/<head>/i, '<head><base href="' + baseHref.replace(/"/g, '&quot;') + '">');
  const blobUrl = URL.createObjectURL(new Blob([withBase], { type: 'text/html;charset=utf-8' }));
  const win = window.open(blobUrl, '_blank');
  if (!win) { URL.revokeObjectURL(blobUrl); toast('Pop-up bloquée : autorise les fenêtres pour ouvrir le rapport.', 'bad'); return; }
  if (print) {
    // laisse le rendu/quetzal se charger avant d'ouvrir le dialogue d'impression.
    win.addEventListener('load', () => setTimeout(() => { try { win.focus(); win.print(); } catch (e) {} }, 400));
  }
  // révoque le Blob une fois la fenêtre chargée (libère la mémoire sans casser l'affichage).
  setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
}

// --- MODULES : rafraîchir le registre (POST /api/modules/refresh — gate opérateur fail-closed) ---
async function refreshModules() {
  const btn = $('#mod-refresh');
  if (!OPERATOR_SECRET) {
    toast('Secret opérateur requis : renseigne-le dans « Lancement C2 » (en-tête X-Forge-Operator).', 'bad');
    location.hash = 'launch'; if ($('#lc-operator')) $('#lc-operator').focus();
    return;
  }
  if (btn) btn.disabled = true;
  let r, j;
  try {
    r = await fetch('/api/modules/refresh', { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }) });
    j = await r.json().catch(() => ({}));
  } catch (e) { if (btn) btn.disabled = false; toast('Erreur réseau : ' + (e.message || e), 'bad'); return; }
  if (btn) btn.disabled = false;
  if (r.status === 403) { toast('Rôle opérateur requis ou preuve invalide (fail-closed).', 'bad'); return; }
  if (!r.ok) { toast('Refus serveur (' + ((j && j.error) || r.status) + ').', 'bad'); return; }
  toast(`Registre rafraîchi : ${Number(j.refreshed || 0)} module(s).`, 'ok');
  // recharge depuis /api/modules (source canonique) pour réafficher grille + résumé + liste de lancement.
  await loadModules();
  if (location.hash.slice(1) === 'launch') renderLaunchModules();
}
if ($('#mod-refresh')) $('#mod-refresh').addEventListener('click', refreshModules);

// =====================================================================================
//  ADMINISTRATION — comptes utilisateurs (vue #admin, réservée role=admin)
//  Toutes les mutations passent par des routes gatées check_admin côté serveur (403 sinon), attribuées
//  à l'admin en session et ledgerisées. L'UI n'apparaît que si whoami.role === 'admin' (défense en
//  profondeur — le serveur reste l'autorité). Zéro alert/confirm/prompt natif : modales/toasts in-app.
//    GET    /api/users                 -> { users: [{login,role,disabled,created}] }  (jamais pass_hash)
//    POST   /api/users {login,role,password}
//    POST   /api/users/:login {role?|password?|disabled?}   (purge sessions sur disable/downgrade/reset)
//    DELETE /api/users/:login          (dernier admin activé protégé : 409)
// =====================================================================================
function isAdmin() { return !!(WHOAMI && String(WHOAMI.role) === 'admin'); }
const ADMIN_ROLES = [
  { value: 'viewer', label: 'viewer — lecture seule' },
  { value: 'operator', label: 'operator — arme le C2' },
  { value: 'admin', label: 'admin — administration' },
];
const LOGIN_RE = /^[A-Za-z0-9._-]{1,64}$/;
function loginError(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return 'Login requis.';
  if (s.startsWith('-')) return 'Le login ne peut pas commencer par « - ».';
  if (!LOGIN_RE.test(s)) return 'Login invalide (1-64 caractères, [A-Za-z0-9._-] uniquement).';
  return null;
}
// Appel API admin : renvoie le JSON parsé, lève une Error (avec .status) sur !ok. On ne remonte que le
// champ contrôlé `why`/`error` du backend (jamais un corps brut non-fiable -> anti-XSS, cf. api()).
async function adminApi(path, opts) {
  const r = await fetch('/api' + path, Object.assign({ headers: { Accept: 'application/json' } }, opts || {}));
  const body = await r.text().catch(() => '');
  let j = null; try { j = body ? JSON.parse(body) : null; } catch (e) {}
  if (!r.ok) {
    const why = (j && (typeof j.why === 'string' && j.why || typeof j.error === 'string' && j.error)) || ('HTTP ' + r.status);
    const err = new Error(why); err.status = r.status; throw err;
  }
  return j;
}
async function loadAdminUsers() {
  const host = $('#admin-users'); if (!host) return;
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if ($('#admin-count')) $('#admin-count').textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/users'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const users = (data && data.users) || [];
  if ($('#admin-count')) $('#admin-count').textContent = users.length + ' compte' + (users.length > 1 ? 's' : '');
  if (!users.length) { host.innerHTML = '<div class="muted">aucun compte</div>'; return; }
  const me = (WHOAMI && WHOAMI.login) || '';
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Login</th><th>Role</th><th>Etat</th><th>Cree</th><th>Actions</th></tr></thead>';
  const tb = document.createElement('tbody');
  users.forEach(u => {
    const tr = document.createElement('tr');
    const roleCls = ROLE_CLASSES.includes('role-' + u.role) ? 'role-' + u.role : 'mut';
    const state = u.disabled ? '<span class="badge bad">desactive</span>' : '<span class="badge ok">actif</span>';
    const self = u.login === me ? ' <span class="badge mut" title="votre compte">vous</span>' : '';
    tr.innerHTML =
      `<td class="mono">${esc(u.login)}${self}</td>` +
      `<td><span class="badge ${roleCls}">${esc(u.role)}</span></td>` +
      `<td>${state}</td>` +
      `<td class="mut">${esc(fmtTs(u.created))}</td>`;
    const act = document.createElement('td'); act.className = 'admin-act';
    const mk = (label, title, fn, danger) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'k-theme' + (danger ? ' danger' : ''); b.textContent = label; b.title = title; b.onclick = fn; return b; };
    act.appendChild(mk('Role', 'Changer le role du compte', () => adminEditRole(u)));
    act.appendChild(mk('Mot de passe', 'Reinitialiser le mot de passe (revoque les sessions)', () => adminResetPw(u)));
    act.appendChild(mk(u.disabled ? 'Reactiver' : 'Desactiver', u.disabled ? 'Reactiver le compte' : 'Desactiver le compte (revoque les sessions)', () => adminToggleDisabled(u), !u.disabled));
    act.appendChild(mk('Supprimer', 'Supprimer definitivement le compte', () => adminDeleteUser(u), true));
    tr.appendChild(act);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
}
async function adminCreateUser() {
  const r = await modal({
    title: 'Nouveau compte',
    okText: 'Creer',
    fields: [
      { name: 'login', label: 'Login', required: true, placeholder: '[A-Za-z0-9._-]' },
      { name: 'role', label: 'Role', type: 'select', options: ADMIN_ROLES, value: 'viewer' },
      { name: 'password', label: 'Mot de passe', type: 'password', required: true, placeholder: 'mot de passe du compte' },
    ],
    validate: v => loginError(v.login) || (!String(v.password || '') ? 'Mot de passe requis.' : null),
  });
  if (!r) return;
  try {
    await adminApi('/users', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ login: String(r.login).trim(), role: r.role, password: r.password }) });
    toast('Compte « ' + String(r.login).trim() + ' » cree.', 'ok');
    loadAdminUsers();
  } catch (e) { toast('Creation refusee : ' + e.message, 'bad'); }
}
async function adminEditRole(u) {
  const r = await modal({
    title: 'Changer le role — ' + u.login,
    okText: 'Appliquer',
    fields: [{ name: 'role', label: 'Role', type: 'select', options: ADMIN_ROLES, value: u.role }],
  });
  if (!r || r.role === u.role) return;
  try {
    await adminApi('/users/' + encodeURIComponent(u.login), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ role: r.role }) });
    toast('Role de « ' + u.login + ' » -> ' + r.role + '.', 'ok');
    loadAdminUsers();
  } catch (e) { toast('Changement de role refuse : ' + e.message, 'bad'); }
}
async function adminResetPw(u) {
  const r = await modal({
    title: 'Reinitialiser le mot de passe — ' + u.login,
    message: 'Les sessions actives de ce compte seront revoquees.',
    okText: 'Reinitialiser',
    fields: [{ name: 'password', label: 'Nouveau mot de passe', type: 'password', required: true, placeholder: 'nouveau mot de passe' }],
  });
  if (!r) return;
  try {
    await adminApi('/users/' + encodeURIComponent(u.login), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ password: r.password }) });
    toast('Mot de passe de « ' + u.login + ' » reinitialise.', 'ok');
    loadAdminUsers();
  } catch (e) { toast('Reinitialisation refusee : ' + e.message, 'bad'); }
}
async function adminToggleDisabled(u) {
  const disabling = !u.disabled;
  const ok = await confirmModal(
    (disabling ? 'Desactiver' : 'Reactiver') + ' le compte « ' + u.login + ' » ?' + (disabling ? ' Ses sessions actives seront revoquees.' : ''),
    { title: disabling ? 'Desactiver le compte' : 'Reactiver le compte', okText: disabling ? 'Desactiver' : 'Reactiver', danger: disabling });
  if (!ok) return;
  try {
    await adminApi('/users/' + encodeURIComponent(u.login), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ disabled: disabling }) });
    toast('Compte « ' + u.login + ' » ' + (disabling ? 'desactive' : 'reactive') + '.', 'ok');
    loadAdminUsers();
  } catch (e) { toast('Operation refusee : ' + e.message, 'bad'); }
}
async function adminDeleteUser(u) {
  const ok = await confirmModal('Supprimer definitivement le compte « ' + u.login + ' » ? Action irreversible.', { title: 'Supprimer le compte', okText: 'Supprimer', danger: true });
  if (!ok) return;
  try {
    await adminApi('/users/' + encodeURIComponent(u.login), { method: 'DELETE', headers: { Accept: 'application/json' } });
    toast('Compte « ' + u.login + ' » supprime.', 'ok');
    loadAdminUsers();
  } catch (e) { toast('Suppression refusee : ' + e.message, 'bad'); }
}
if ($('#admin-new')) $('#admin-new').addEventListener('click', adminCreateUser);
if ($('#admin-reload')) $('#admin-reload').addEventListener('click', loadAdminUsers);

// =====================================================================================
//  ADMINISTRATION — connecteurs (gouvernance enabled / available_override / web_allowed)
//  Contrepartie ECRITURE de GET /api/modules : POST /api/modules/:kind (check_admin, attribue + ledgerise).
//  Desactiver un connecteur l'empeche REELLEMENT de tirer (scope.json disabled_modules + filtre --modules
//  + refus validate_modules), y compris pour les modules choisis par le planner. Admin-only (le serveur
//  reste l'autorite : les mutations sont 403 sans session admin).
// =====================================================================================
const OVR_OPTS = [
  { value: '', label: 'auto (sonde host)' },
  { value: 'true', label: 'forcer disponible' },
  { value: 'false', label: 'forcer indisponible' },
];
async function loadAdminConnectors() {
  const host = $('#admin-connectors-body'); if (!host) return;
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if ($('#admin-conn-count')) $('#admin-conn-count').textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let mods;
  try { mods = await api('/modules'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const list = Array.isArray(mods) ? mods.slice().sort((a, b) => String(a.kind).localeCompare(String(b.kind))) : [];
  if ($('#admin-conn-count')) $('#admin-conn-count').textContent = list.length + ' connecteur' + (list.length > 1 ? 's' : '');
  if (!list.length) { host.innerHTML = '<div class="muted">aucun connecteur</div>'; return; }
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
async function connectorSet(kind, patch) {
  try {
    await adminApi('/modules/' + encodeURIComponent(kind), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(patch) });
    toast('Connecteur « ' + kind + ' » mis a jour.', 'ok');
    loadAdminConnectors();
    if (typeof loadModules === 'function') loadModules(); // refleter l'effectif dans la vue Capacites
  } catch (e) { toast('Mise a jour refusee : ' + e.message, 'bad'); }
}
if ($('#admin-conn-reload')) $('#admin-conn-reload').addEventListener('click', loadAdminConnectors);
// Vue #admin : charge comptes ET connecteurs (deux tables gouvernees, meme role admin).
function loadAdmin() { loadAdminUsers(); loadAdminConnectors(); }

// =====================================================================================
//  Navigation (sidebar repliable + hash-routing) + chargement par vue
// =====================================================================================
const VIEWS = {
  'ov-summary': 'overview', 'ov-sev': 'overview', 'ov-modules': 'overview',
  'lc-form': 'launch', 'lc-plan': 'launch', 'lc-live': 'launch', 'lc-runs': 'launch',
  modules: 'modules', findings: 'findings', explore: 'explore',
  coverage: 'coverage', 'purple-coverage': 'purple-coverage', campaigns: 'campaigns', roe: 'roe', ledger: 'ledger', dashboards: 'dashboards',
  admin: 'admin', 'admin-connectors': 'admin',
};
const LOADERS = {
  overview: loadOverview, launch: loadLaunch, modules: loadModules, findings: loadFindings,
  coverage: loadCoverage, 'purple-coverage': loadPurpleCoverage, campaigns: loadCampaigns, roe: loadRoe, ledger: loadLedger, dashboards: loadDashboards,
  admin: loadAdmin,
};
let loadedOnce = {};
function showView(v) {
  document.querySelectorAll('main > section').forEach(s => {
    // lc-plan : visibilité pilotée par le dry-plan (apparaît après /api/plan), pas par le routage —
    // on le masque seulement quand on quitte la vue launch, jamais on ne le force visible ici.
    if (s.id === 'lc-plan') { if (v !== 'launch') s.hidden = true; return; }
    s.hidden = (VIEWS[s.id] || 'overview') !== v;
  });
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + v));
  if ($('#q')) $('#q').hidden = (v !== 'explore' && v !== 'findings');
  const fn = LOADERS[v];
  if (fn) { try { fn(); } catch (e) { console.error(e); } loadedOnce[v] = true; }
}
function route() { let v = location.hash.slice(1) || 'overview'; if (!VIEWS_HAS(v)) v = 'overview'; if (v === 'admin' && !isAdmin()) v = 'overview'; showView(v); }
function VIEWS_HAS(v) { return Object.values(VIEWS).includes(v); }
window.addEventListener('hashchange', route);
if ($('#navtoggle')) $('#navtoggle').onclick = () => { const l = document.querySelector('.layout'); if (l) l.classList.toggle('collapsed'); };

// campagne globale : recharge la vue courante + les compteurs croisés
if ($('#campaign')) $('#campaign').addEventListener('change', () => {
  const v = location.hash.slice(1) || 'overview';
  const fn = LOADERS[VIEWS_HAS(v) ? v : 'overview']; if (fn) fn();
  if (v === 'findings') loadFindings(0);
});
if ($('#reload')) $('#reload').addEventListener('click', () => {
  const v = location.hash.slice(1) || 'overview';
  const fn = LOADERS[VIEWS_HAS(v) ? v : 'overview']; if (fn) fn();
});

// =====================================================================================
//  Thème clair / sombre (Aurora) + auto-refresh + boot
// =====================================================================================
(function initTheme() {
  const saved = localStorage.getItem('forge-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  const btn = $('#theme');
  const paint = () => { if (btn) btn.innerHTML = ic(document.documentElement.dataset.theme === 'light' ? 'moon' : 'sun'); };
  paint();
  if (btn) btn.onclick = () => {
    const t = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = t;
    localStorage.setItem('forge-theme', t);
    paint();
    // recolore les vues à graphes SVG (ils lisent les variables CSS au rendu)
    const v = location.hash.slice(1) || 'overview';
    const fn = LOADERS[VIEWS_HAS(v) ? v : 'overview']; if (fn) fn();
  };
})();

let autoTimer = null;
function applyAutoRefresh() {
  if (autoTimer) clearInterval(autoTimer);
  const s = Number(($('#refresh') && $('#refresh').value) || 0);
  if (s > 0) autoTimer = setInterval(() => {
    const v = location.hash.slice(1) || 'overview';
    const fn = LOADERS[VIEWS_HAS(v) ? v : 'overview']; if (fn) fn();
    if (v === 'dashboards') refreshPanels();
  }, s * 1000);
}
if ($('#refresh')) $('#refresh').addEventListener('change', applyAutoRefresh);

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

// version produit (source unique : fichier VERSION -> exposé par /health JSON) affichée au pied de page.
// Best-effort, jamais bloquant : /health est ouvert (hors auth), donc fetch nu sans en-tête.
async function loadVersion() {
  try {
    const j = await (await fetch('/health', { headers: { accept: 'application/json' } })).json();
    const el = $('#version');
    if (el && j && j.version) el.textContent = ' — forge v' + j.version;
  } catch (e) { /* pied de page informatif : ignorer toute erreur */ }
}

// =====================================================================================
//  AUTHENTIFICATION — portail de connexion (gate du shell) + badge whoami + déconnexion
//  Le boot sonde GET /api/whoami (route derrière auth_guard) :
//    - 401                        -> session requise et absente        -> vue de login.
//    - 200 {authenticated:true}   -> session valide                    -> shell + badge (login/rôle).
//    - 200 {authenticated:false}  -> mode dev-open (aucun hash serveur) -> shell sans badge.
//  Toutes les requêtes suivantes (findings, query, SSE /events, …) s'authentifient par le cookie
//  forge_session (HttpOnly, SameSite=Strict) posé par POST /api/login — jamais par un token en JS.
//  On NE stocke PAS le bearer renvoyé par /login : l'UI s'appuie exclusivement sur le cookie.
// =====================================================================================
let WHOAMI = null;
const ROLE_CLASSES = ['role-admin', 'role-operator', 'role-editor', 'role-viewer'];
function renderWhoami(w) {
  WHOAMI = w || null;
  const box = $('#whoami');
  if (!box) return;
  const authed = !!(w && w.authenticated);
  box.hidden = !authed;
  if (!authed) return;
  const roleEl = $('#whoami-role');
  if (roleEl) {
    const role = String(w.role || 'viewer');
    roleEl.textContent = role;
    roleEl.classList.remove(...ROLE_CLASSES);
    if (ROLE_CLASSES.includes('role-' + role)) roleEl.classList.add('role-' + role);
    roleEl.title = (w.is_operator ? 'Opérateur C2' : 'Lecture') + ' — rôle « ' + role + ' »' + (w.via_session ? '' : ' (repli bootstrap)');
  }
  const userEl = $('#whoami-user');
  if (userEl) userEl.textContent = w.login || '';
  // ADMIN : le lien de navigation n'apparaît que pour un admin (défense en profondeur — le serveur
  // reste l'autorité via check_admin). Si un non-admin se trouve sur #admin, on le ré-oriente.
  const adminLink = $('#nav-admin');
  if (adminLink) adminLink.hidden = !(authed && String(w.role) === 'admin');
  if (!isAdmin() && (location.hash.slice(1) === 'admin')) location.hash = 'overview';
}
function showLogin() {
  document.body.classList.add('gated');
  const v = $('#login-view'); if (v) v.hidden = false;
  const u = $('#login-user'); if (u) setTimeout(() => { try { u.focus(); } catch (e) {} }, 40);
}
function showApp() {
  document.body.classList.remove('gated');
  const v = $('#login-view'); if (v) v.hidden = true;
}
function loginErr(msg) { const e = $('#login-err'); if (e) { e.textContent = msg; e.hidden = false; } }
// POST /api/login {login,password} : succès -> le serveur pose le cookie de session (Set-Cookie). On
// efface le mot de passe et on (re)démarre le shell gaté. Message générique sur 401 (anti-énumération).
if ($('#login-form')) $('#login-form').addEventListener('submit', async e => {
  e.preventDefault();
  const errEl = $('#login-err'); if (errEl) errEl.hidden = true;
  const user = (($('#login-user') && $('#login-user').value) || '').trim();
  const pass = ($('#login-pass') && $('#login-pass').value) || '';
  if (!user || !pass) { loginErr('Identifiant et mot de passe requis.'); return; }
  const btn = $('#login-submit'); if (btn) btn.disabled = true;
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ login: user, password: pass }),
    });
    if (r.status === 401) {
      loginErr('Identifiants invalides.');
      const p = $('#login-pass'); if (p) { p.value = ''; try { p.focus(); } catch (e) {} }
      return;
    }
    if (!r.ok) {
      let why = 'HTTP ' + r.status;
      try { const j = await r.json(); if (j && typeof j.why === 'string') why = j.why; else if (j && typeof j.error === 'string') why = j.error; } catch (e) {}
      loginErr('Échec de connexion : ' + why);
      return;
    }
    const p = $('#login-pass'); if (p) p.value = '';
    showApp();
    toast('Connecté.', 'ok');
    await bootApp();
  } catch (err) {
    loginErr('Erreur réseau : ' + String((err && err.message) || err));
  } finally {
    if (btn) btn.disabled = false;
  }
});
// Déconnexion : POST /api/logout s'il existe (forward-compat), sinon effacement de la session côté
// client. NB : le cookie forge_session est HttpOnly (sa révocation DURE est côté serveur) ; ici on
// coupe les flux, on oublie les secrets de session en mémoire et on ramène l'UI au portail.
async function doLogout() {
  try { await fetch('/api/logout', { method: 'POST', headers: { Accept: 'application/json' } }); } catch (e) { /* endpoint absent : sans effet */ }
  try { document.cookie = 'forge_session=; Path=/; Max-Age=0; SameSite=Strict'; } catch (e) {}
  OPERATOR_SECRET = '';
  const opField = $('#lc-operator'); if (opField) opField.value = '';
  try { lcStopLive(); } catch (e) {}
  renderWhoami(null);
  showLogin();
  const pass = $('#login-pass'); if (pass) pass.value = '';
  toast('Déconnecté.', 'ok');
}
if ($('#logout')) $('#logout').addEventListener('click', async () => {
  if (await confirmModal('Se déconnecter de la console ?', { title: 'Déconnexion', okText: 'Déconnexion', cancelText: 'Rester', danger: false })) doLogout();
});

// boot gaté : sonde whoami, montre le portail sur 401 (ou erreur réseau, fail-closed lisible), sinon
// charge le contexte transverse (campagnes -> sélecteur, statuts -> filtre) puis route la vue.
async function bootApp() {
  let w = null;
  try {
    const r = await fetch('/api/whoami', { headers: { Accept: 'application/json' } });
    if (r.status === 401) { renderWhoami(null); showLogin(); return; }
    if (r.ok) w = await r.json().catch(() => null);
  } catch (e) {
    renderWhoami(null); showLogin(); return;
  }
  renderWhoami(w);
  showApp();
  loadCampaigns();
  loadStatuses();
  route();
}
loadVersion();
bootApp();
