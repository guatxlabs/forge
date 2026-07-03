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
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.4 2.4 0 0 1 4.4 1.3c0 1.6-2 1.9-2.4 3.3"/><path d="M12 17.2h.01"/>',
  book: '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19a2 2 0 0 1 2-2h13"/>',
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
//  ENGAGEMENT ACTIF (objet de 1re classe — à la workspace Metasploit)
// =====================================================================================
// L'engagement actif est persisté CÔTÉ CLIENT (localStorage) et ajouté à CHAQUE requête via
// `?engagement=<id>`. Le serveur FILTRE les vues (findings/runrecords/roe/ledger/coverage/runs) sur
// cet id -> un engagement ne voit JAMAIS les données d'un autre. Absent -> le serveur retombe sur
// l'engagement actif le plus récent (défaut mono-engagement = #1, rétro-compat).
let ENGAGEMENTS = [];        // dernière liste connue (id/name/status/mode/counts) pour le sélecteur + vue
function activeEngagement() {
  const v = localStorage.getItem('forge_engagement');
  const n = v == null ? NaN : parseInt(v, 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}
function setActiveEngagement(id) {
  if (id == null) localStorage.removeItem('forge_engagement');
  else localStorage.setItem('forge_engagement', String(id));
}
function activeEngagementName() {
  const id = activeEngagement();
  const e = ENGAGEMENTS.find(x => x.id === id) || ENGAGEMENTS.find(x => x.status === 'active') || ENGAGEMENTS[0];
  return e ? e.name : '';
}
// Ajoute ?engagement=<id> à une URL/chemin quelconque (idempotent : ne double jamais le param).
function withEngagement(url) {
  const id = activeEngagement();
  if (id == null || /[?&]engagement=/.test(url)) return url;
  return url + (url.includes('?') ? '&' : '?') + 'engagement=' + id;
}

// =====================================================================================
//  API helpers
// =====================================================================================
async function api(path) {
  // Toute LECTURE est scopée à l'engagement actif (withEngagement) — un endpoint qui ignore le param
  // le laisse inerte (sans effet), donc l'ajout global est sûr.
  const r = await fetch(withEngagement('/api' + path), { headers: { Accept: 'application/json' } });
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
      // indice explicatif optionnel sous le champ (accessible : décrit le champ, pas juste un label).
      if (f.hint) html += `<small class="modal-fhint">${esc(f.hint)}</small>`;
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
//  AIDE IN-APP — centre d'aide natif (aucun alert/confirm/prompt navigateur).
//  Un bouton « ? » persistant dans l'en-tête ouvre une modale accessible (role=dialog, aria-modal,
//  focus-trap, Escape/clic-dehors, restauration du focus) qui explique la vue COURANTE (déduite du
//  hash) et donne accès à toutes les rubriques, dont « Comment Forge fonctionne » (modèle de sûreté).
//  Le contenu est STATIQUE et rendu en DOM sûr (textContent) ; les liens sont des ancres in-app (#vue).
// =====================================================================================
// Rubriques ordonnées. blocks = [type, payload] : 'p' paragraphe, 'h' sous-titre, 'ul' liste, 'steps' étapes.
const HELP_TOPICS = [
  { key: 'governance', title: 'Comment Forge fonctionne — sûreté & gouvernance', icon: 'shield', doc: 'docs/SECURITY_MODEL.md', pinned: true, blocks: [
    ['p', "Forge est un produit d'évaluation red-team autorisé et gouverné : chaque action passe par des garde-fous conçus pour échouer du côté sûr (fail-closed). Voici le modèle de sûreté qu'un opérateur doit comprendre AVANT de lancer quoi que ce soit."],
    ['h', 'Scope-guard fail-closed'],
    ['p', "Le périmètre autorisé (scope serveur) fait autorité. Toute cible hors-scope est vétoée côté serveur (VETO dur) et ne peut JAMAIS être élargie depuis le web. En cas de doute, on refuse plutôt que d'autoriser."],
    ['h', 'Défaut non-exploit / non-destructif'],
    ['p', "Un lancement est non-exploit et non-destructif par défaut. Les modules exploit/destructif restent grisés tant que l'opt-in gouverné « fort impact » n'est pas activé — il exige d'armer, une raison d'audit ET le secret opérateur, plus une double-confirmation explicite."],
    ['h', 'Proof-oracles'],
    ['p', "Un résultat n'est retenu que s'il est étayé par une preuve vérifiable (oracle), pas par une supposition. On ne fabrique jamais de résultat : une mesure impossible (source injoignable) est déclarée impossible, jamais transformée en « détecté »."],
    ['h', 'Ledger tamper-evident'],
    ['p', "Chaque décision et chaque lancement sont journalisés dans un ledger append-only chaîné par SHA-256 et signé. Toute altération casse la chaîne et devient visible. La console recalcule l'intégrité hash ; la signature cryptographique se vérifie en CLI."],
  ] },
  { key: 'overview', title: "Vue d'ensemble", icon: 'home', doc: 'docs/OVERVIEW.md', view: 'overview', blocks: [
    ['p', "Tableau de bord d'entrée : l'état de la boucle purple, la répartition des findings par sévérité et les capacités disponibles. C'est le point de départ pour situer l'engagement en cours."],
    ['p', "Le sélecteur de campagne (en-tête) filtre toutes les vues sur une campagne précise. Le badge « posture » résume l'état de la boucle."],
  ] },
  { key: 'launch', title: 'Lancement C2 (campagne)', icon: 'play', doc: 'docs/PURPLE_CAMPAIGN.md', view: 'launch', blocks: [
    ['p', "Compose et lance une campagne C2-light gouvernée. Non-exploit / non-destructif par défaut ; tout est borné au scope serveur et journalisé au ledger (console.run.start)."],
    ['steps', [
      "Vérifiez une cible (lecture pure) : la décision in-scope / hors-scope s'affiche sans rien lancer.",
      "Renseignez la campagne, le mode (propose = simulation ; auto = exécute les actions FIRE) et les cibles (⊆ scope serveur, une par ligne).",
      "Choisissez des modules (vide = le planner décide). Les modules exploit/destructif restent grisés hors opt-in fort impact.",
      "Facultatif : « Dry-plan » affiche un aperçu INERTE des verdicts garde-fou (FIRE / DRY_RUN / VETO / SKIP) sans rien exécuter ni persister.",
      "Pour lancer : fournissez le secret opérateur. Pour le fort impact, activez la zone danger (armer + raison + secret) puis double-confirmez.",
    ]],
    ['p', "Le run en cours diffuse ses logs en direct ; la liste des runs conserve l'historique et permet d'annuler un run actif."],
  ] },
  { key: 'modules', title: 'Capacités & Modules', icon: 'flask', doc: 'docs/MODULES.md', view: 'modules', blocks: [
    ['p', "Catalogue des capacités du moteur. Le badge « web » marque un module lançable en cadre web ; « exploit » / « destructif » portent un risque accru et sont gatés par les ROE au lancement."],
    ['p', "La disponibilité EFFECTIVE d'un module dépend de la sonde host ET de la gouvernance des connecteurs (Administration). Un connecteur désactivé est SKIP au tir, même si son binaire est présent."],
  ] },
  { key: 'techniques', title: 'Techniques & Sélection', icon: 'flask', doc: 'docs/MODULES.md', view: 'techniques', blocks: [
    ['p', "Catalogue des techniques du moteur GROUPÉ PAR CATÉGORIE (SQLi, IDOR, SSRF, XSS…), DÉRIVÉ du registre : un nouveau module apparaît automatiquement sous sa catégorie. Chaque technique porte les outils qui la couvrent et son éligibilité (BB = bug bounty, pentest = pentest-only)."],
    ['p', "Sélection PAR-SCOPE : le profil (bug_bounty | pentest | custom) donne l'ensemble de base, puis les toggles par catégorie / par technique AJOUTENT ou RETIRENT (la désactivation prime — fail-closed). « Au scope, retirer un test automatique » : une technique décochée n'est NI planifiée NI tirée par le moteur, en plus du scope-guard."],
    ['p', "Enregistrer la sélection est réservé aux comptes operator/admin et journalisé au ledger. La sélection s'applique aux prochains runs (scope.json profile/techniques_enabled/categories_enabled)."],
  ] },
  { key: 'workflows', title: 'Workflows', icon: 'layout', doc: 'docs/MODULES.md', view: 'workflows', blocks: [
    ['p', "Pipelines COMPOSÉS sans code : une sélection ORDONNÉE de techniques/outils (+ params par étape), sauvegardée et éditable. Absorbe les scan-engines de reNgine, les workflows d'Osmedeus et les pipelines visuels de Trickest — le builder réutilise le catalogue par catégorie et l'état activé par le scope."],
    ['p', "GOUVERNANCE fail-closed : un workflow est une PROPOSITION. Le scope-guard ROE et la sélection par-scope restent seuls juges — une étape hors-scope / désactivée pour le scope est LARGUÉE au tir. Les étapes exploit restent derrière l'opt-in fort-impact. Les workflows intégrés (dérivés du registre) ne sont pas supprimables."],
    ['p', "Création/édition/suppression réservées operator/admin et journalisées au ledger (POST /api/workflows[/:name]). « Lancer ce workflow » passe par le C2 gouverné (POST /api/run modules=étapes, auto_pentest) : mêmes garde-fous que le lancement C2 standard."],
  ] },
  { key: 'findings', title: 'Findings', icon: 'shield', doc: 'docs/CONCEPTS.md', view: 'findings', blocks: [
    ['p', "Résultats d'évaluation normalisés : sévérité, cible, technique MITRE, statut. Filtrez par sévérité, statut ou cible ; cliquez un finding pour son détail complet (preuve, contexte, référence ledger)."],
    ['p', "Les findings alimentent la couverture ATT&CK et la boucle purple : une technique tirée devient « détectée » ou « ratée » côté défense."],
  ] },
  { key: 'reports', title: "Rapport d'engagement (livrable)", icon: 'shield', doc: 'docs/CONCEPTS.md', view: 'reports', blocks: [
    ['p', "Le LIVRABLE CLIENT agrégé de l'engagement ACTIF : page de garde brandée, résumé exécutif, findings détaillés (secrets rédigés), couverture ATT&CK et annexe chaîne-de-custody. Formats HTML / PDF / DOCX / CSV / JSON — l'aperçu HTML s'affiche dans la vue."],
    ['p', "ISOLATION : le rapport ne reflète QUE l'engagement actif (jamais les données d'un autre). Chaque génération et chaque configuration de branding sont journalisées au ledger. Le branding (nom du commanditaire, logo, prestataire) est réservé au rôle admin ; PDF/DOCX dégradent proprement si le moteur d'impression ou python est absent sur l'hôte."],
    ['p', "Depuis Findings, « Export CSV / JSON » télécharge les findings de l'engagement actif et « Rapport complet » ouvre cette vue."],
  ] },
  { key: 'explore', title: 'Recherche & Explore (soql)', icon: 'search', doc: 'docs/CONCEPTS.md', view: 'explore', blocks: [
    ['p', "Requêteur soql (langage de recherche en pipeline) sur les données de l'engagement, ex : search severity=HIGH | stats count by mitre | sort -count | head 20."],
    ['p', "Choisissez une visualisation (table / barres / courbe / stat). Cliquez une valeur pour un drilldown ; « Panneau » enregistre la requête comme panneau réutilisable dans un dashboard."],
  ] },
  { key: 'coverage', title: 'Couverture ATT&CK', icon: 'activity', doc: 'docs/PURPLE_CAMPAIGN.md', view: 'coverage', blocks: [
    ['p', "Couverture ATT&CK côté offensif : par technique MITRE, combien de runs l'ont tentée et combien ont « tiré » (déclenché un résultat)."],
    ['p', "Une technique tentée mais à 0 tiré est couverte sans résultat côté cible. Pour l'axe défensif (détecté vs raté), voir « Détection purple »."],
  ] },
  { key: 'purple-coverage', title: 'Détection purple', icon: 'layout', doc: 'docs/DETECTION.md', view: 'purple-coverage', blocks: [
    ['p', "Mesure DÉFENSIVE et OPTIONNELLE : pour chaque technique tirée en red-team, a-t-elle été détectée par votre source BLUE (SOC/IDS/pare-feu) ? Vert = détecté, rouge = trou de détection. Le MTTD mesure le délai tir → alerte."],
    ['p', "Aucune source n'est requise : sans source, Forge tourne en AUTONOME (standalone) et l'état est neutre — ce n'est pas une panne. Si une source est configurée mais injoignable, la mesure est déclarée impossible ; aucun « détecté » n'est inventé."],
    ['h', 'Connecter une source de détection'],
    ['steps', [
      "Ouvrez Administration → Source de détection.",
      "Choisissez le type (Plume, CrowdSec, Elastic/OpenSearch, FortiGate/pfSense, fichier, commande…), l'endpoint, l'authentification et le mapping MITRE.",
      "Testez la joignabilité, puis enregistrez. La boucle purple s'active dès que la source répond.",
    ]],
  ] },
  { key: 'campaigns', title: 'Campagnes', icon: 'server', doc: 'docs/PURPLE_CAMPAIGN.md', view: 'campaigns', blocks: [
    ['p', "Regroupe l'activité par campagne (une opération d'évaluation nommée). Sélectionnez-en une pour filtrer transversalement findings, couverture, ROE et ledger."],
  ] },
  { key: 'roe', title: 'ROE / Garde-fou', icon: 'shield', doc: 'docs/SECURITY_MODEL.md', view: 'roe', blocks: [
    ['p', "Journal des décisions du garde-fou (Rules of Engagement). Chaque action proposée par le moteur reçoit un verdict : FIRE (exécutée), DRY_RUN (simulée) ou VETO (bloquée), avec sa raison."],
    ['p', "C'est la transparence anti-masquage : on voit pourquoi une action a été autorisée, simulée ou refusée — jamais de refus silencieux."],
  ] },
  { key: 'ledger', title: "Ledger d'engagement", icon: 'lock', doc: 'docs/SECURITY_MODEL.md', view: 'ledger', blocks: [
    ['p', "Journal d'engagement append-only chaîné par SHA-256 : preuve d'intégrité de toutes les actions et décisions. La console recalcule la chaîne de hash (intégrité hash-only)."],
    ['p', "La signature cryptographique se vérifie hors-console : forge ledger verify --pubkey <clé>."],
  ] },
  { key: 'dashboards', title: 'Dashboards / Vues', icon: 'layout', doc: 'docs/CONCEPTS.md', view: 'dashboards', blocks: [
    ['p', "Compose des dashboards de panneaux soql (glisser pour réordonner, coin pour redimensionner). Une « vue » est une collection de dashboards — un simple filtre d'affichage local."],
  ] },
  { key: 'admin', title: 'Administration', icon: 'user', doc: 'docs/ADMINISTRATION.md', view: 'admin', blocks: [
    ['p', "Réservé au rôle admin. Toutes les mutations sont attribuées à votre compte et ledgerisées."],
    ['h', 'Comptes'],
    ['p', "viewer (lecture seule) · operator (arme le C2) · admin (administre). Désactivation, rétrogradation et réinitialisation de mot de passe révoquent immédiatement les sessions du compte. Le dernier admin activé est protégé (anti-verrouillage)."],
    ['h', 'Connecteurs'],
    ['p', "Interrupteur opérateur par module. Désactiver — ou forcer « indisponible » — un connecteur le rend SKIP au tir, y compris pour les modules choisis par le planner. Disponibilité effective = activé ET (override ?? sonde host)."],
    ['h', 'Source de détection'],
    ['p', "Câble une source BLUE (SIEM/IDS/pare-feu) sans code, corrélée par identité MITRE. Le secret est write-only. Une source absente/injoignable ⇒ mesure déclarée impossible."],
    ['h', 'Sauvegarde & restauration'],
    ['p', "Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305) embarquant base + ledger + clé de signature. La passphrase est obligatoire et jamais persistée. La restauration valide par défaut ; le swap en place exige une confirmation + un redémarrage."],
  ] },
];
const HELP_BY_KEY = Object.fromEntries(HELP_TOPICS.map(t => [t.key, t]));
// hash de la vue courante -> clé de rubrique (identité ; repli overview).
function currentHelpKey() { const v = (location.hash.slice(1) || 'overview'); return HELP_BY_KEY[v] ? v : 'overview'; }
function helpBlockEl(block) {
  const [type, payload] = block;
  if (type === 'h') { const e = document.createElement('h4'); e.className = 'help-h'; e.textContent = payload; return e; }
  if (type === 'ul') { const ul = document.createElement('ul'); ul.className = 'help-ul'; (payload || []).forEach(t => { const li = document.createElement('li'); li.textContent = t; ul.appendChild(li); }); return ul; }
  if (type === 'steps') { const ol = document.createElement('ol'); ol.className = 'help-steps'; (payload || []).forEach(t => { const li = document.createElement('li'); li.textContent = t; ol.appendChild(li); }); return ol; }
  const p = document.createElement('p'); p.className = 'help-p'; p.textContent = String(payload == null ? '' : payload); return p;
}
let _helpOpen = false;
function openHelp(startKey) {
  if (_helpOpen) return;              // une seule modale d'aide à la fois
  _helpOpen = true;
  const opener = document.activeElement; // pour restaurer le focus à la fermeture
  const titleId = 'help-title';
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div');
  box.className = 'modal wide help-modal';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-labelledby', titleId);

  // en-tête : titre générique + bouton fermer
  const head = document.createElement('div'); head.className = 'help-head';
  const h = document.createElement('h3'); h.id = titleId; h.textContent = 'Aide — Forge';
  const xb = document.createElement('button'); xb.type = 'button'; xb.className = 'k-theme help-x'; xb.setAttribute('aria-label', 'Fermer l\'aide'); xb.innerHTML = ic('x');
  head.append(h, xb);

  // corps : table des matières (nav) + panneau de contenu
  const body = document.createElement('div'); body.className = 'help-body';
  const toc = document.createElement('nav'); toc.className = 'help-toc'; toc.setAttribute('aria-label', 'Rubriques d\'aide');
  const content = document.createElement('div'); content.className = 'help-content'; content.tabIndex = -1;
  body.append(toc, content);

  // boutons de TOC (governance épinglée en tête, séparée par un filet)
  const tocBtns = {};
  let pinnedDone = false;
  HELP_TOPICS.forEach(t => {
    if (!t.pinned && !pinnedDone) { const sep = document.createElement('div'); sep.className = 'help-toc-sep'; toc.appendChild(sep); pinnedDone = true; }
    const b = document.createElement('button'); b.type = 'button'; b.className = 'help-toc-btn' + (t.pinned ? ' pinned' : '');
    b.innerHTML = ic(t.icon || 'book'); const sp = document.createElement('span'); sp.textContent = t.title; b.appendChild(sp);
    b.addEventListener('click', () => select(t.key, true));
    toc.appendChild(b); tocBtns[t.key] = b;
  });

  function renderContent(key) {
    const t = HELP_BY_KEY[key] || HELP_TOPICS[0];
    content.replaceChildren();
    const th = document.createElement('h4'); th.className = 'help-title'; th.textContent = t.title; content.appendChild(th);
    (t.blocks || []).forEach(bl => content.appendChild(helpBlockEl(bl)));
    // pied : lien vers la vue in-app (ferme la modale) + référence documentaire
    const meta = document.createElement('div'); meta.className = 'help-meta';
    if (t.view) {
      const a = document.createElement('a'); a.href = '#' + t.view; a.className = 'help-gotolink'; a.innerHTML = ic('ext'); const gs = document.createElement('span'); gs.textContent = 'Aller à la vue'; a.appendChild(gs);
      a.addEventListener('click', () => { close(); });
      meta.appendChild(a);
    }
    if (t.doc) {
      const d = document.createElement('span'); d.className = 'help-doc'; d.title = 'Fichier de documentation dans le dépôt';
      d.innerHTML = ic('book'); const dl = document.createElement('span'); dl.className = 'help-doc-l'; dl.textContent = 'Documentation : '; const dc = document.createElement('code'); dc.textContent = t.doc;
      d.append(dl, dc); meta.appendChild(d);
    }
    content.appendChild(meta);
    content.scrollTop = 0;
  }
  function select(key, focusContent) {
    Object.entries(tocBtns).forEach(([k, b]) => { const on = k === key; b.classList.toggle('on', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    renderContent(key);
    if (focusContent) { try { content.focus(); } catch (e) {} }
  }

  box.append(head, body);
  ov.appendChild(box);
  document.body.appendChild(ov);

  // --- accessibilité : focus-trap (Tab cycle), Escape/clic-dehors, restauration du focus ---
  const focusable = () => [...box.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')].filter(el => el.offsetParent !== null || el === document.activeElement);
  const onKey = e => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key === 'Tab') {
      const f = focusable(); if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  function close() {
    if (!_helpOpen) return;
    _helpOpen = false;
    document.removeEventListener('keydown', onKey, true);
    ov.classList.add('out'); setTimeout(() => ov.remove(), 160);
    try { if (opener && typeof opener.focus === 'function') opener.focus(); } catch (e) {}
  }
  xb.addEventListener('click', close);
  ov.addEventListener('click', e => { if (e.target === ov) close(); });
  document.addEventListener('keydown', onKey, true);

  select(HELP_BY_KEY[startKey] ? startKey : currentHelpKey(), false);
  // focus initial : le bouton de rubrique actif (dans le trap, annonçable au lecteur d'écran)
  setTimeout(() => { const active = tocBtns[HELP_BY_KEY[startKey] ? startKey : currentHelpKey()]; try { (active || xb).focus(); } catch (e) {} }, 30);
}
// bouton « ? » de l'en-tête : ouvre l'aide de la vue courante.
if ($('#help')) $('#help').addEventListener('click', () => openHelp(currentHelpKey()));
// raccourci clavier « ? » (Shift+/) — ignoré si l'utilisateur tape dans un champ.
document.addEventListener('keydown', e => {
  if (e.key !== '?' || e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target, tag = t && t.tagName;
  if (t && (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable)) return;
  if (document.body.classList.contains('gated')) return; // pas d'aide shell derrière le portail de login
  e.preventDefault(); openHelp(currentHelpKey());
});

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

// =====================================================================================
//  Techniques & Sélection PAR-SCOPE — catalogue GROUPÉ PAR CATÉGORIE (lecture /api/techniques,
//  DÉRIVÉ du registre) + panneau de sélection (profil + toggles catégorie/technique). La mutation
//  (POST /api/techniques/selection) est operator/admin + ledgerisée. « Au scope retirer des tests
//  automatiques » : le moteur ENFORCE l'ensemble effectif (profil ∪ activations − désactivations) —
//  une technique décochée n'est NI planifiée NI tirée (fail-closed), en plus du scope-guard.
// =====================================================================================
let TQ = { profile: 'bug_bounty', rowByKind: {}, groups: {}, desired: {} };

// Base d'un profil côté client — miroir COSMÉTIQUE de forge.techniques (prefill des cases au changement
// de profil). Le MOTEUR reste autoritatif : le prefill se recorrige au rechargement après enregistrement.
// bug_bounty = bb-eligible ∪ recon (infra) ; pentest = tout ; custom = rien.
function tqBase(row, profile) {
  if (profile === 'pentest') return true;
  if (profile === 'custom') return false;
  return !!row.bug_bounty_eligible || row.phase === 'recon';
}

async function loadTechniques() {
  const host = $('#tq-groups'); if (!host) return;
  let cat;
  try { cat = await api('/techniques'); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  if (cat && cat.error) {
    host.innerHTML = '<div class="bad">catalogue indisponible : ' + esc(String(cat.why || cat.error)) + '</div>';
    if ($('#tq-count')) $('#tq-count').textContent = '';
    return;
  }
  TQ.groups = cat.groups || {};
  TQ.profile = cat.profile || 'bug_bounty';
  TQ.rowByKind = {}; TQ.desired = {};
  let total = 0;
  Object.values(TQ.groups).forEach(rows => (rows || []).forEach(r => {
    TQ.rowByKind[r.kind] = r; TQ.desired[r.kind] = !!r.enabled_for_current_scope; total++;
  }));
  if ($('#tq-profile')) $('#tq-profile').value = TQ.profile;
  if ($('#tq-count')) $('#tq-count').textContent = total + ' techniques';
  renderTechniques();
}

function tqEnabledCount() { return Object.values(TQ.desired).filter(Boolean).length; }

function renderTechniques() {
  const host = $('#tq-groups'); if (!host) return;
  const cats = Object.keys(TQ.groups).sort();
  if (!cats.length) { host.innerHTML = '<div class="muted">aucune technique</div>'; return; }
  host.replaceChildren(...cats.map(cat => {
    const rows = (TQ.groups[cat] || []).slice().sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
    const on = rows.filter(r => TQ.desired[r.kind]).length;
    const card = document.createElement('div'); card.className = 'tq-cat';
    const head = document.createElement('div'); head.className = 'tq-cathead';
    head.innerHTML = `<span class="tq-catname">${esc(cat)} <span class="badge tq-catcount">${on}/${rows.length}</span></span>`;
    const acts = document.createElement('span'); acts.className = 'tq-catacts';
    const bAll = document.createElement('button'); bAll.type = 'button'; bAll.className = 'k-theme'; bAll.textContent = 'Tout activer';
    const bNone = document.createElement('button'); bNone.type = 'button'; bNone.className = 'k-theme'; bNone.textContent = 'Tout désactiver';
    bAll.onclick = () => { rows.forEach(r => { TQ.desired[r.kind] = true; }); renderTechniques(); };
    bNone.onclick = () => { rows.forEach(r => { TQ.desired[r.kind] = false; }); renderTechniques(); };
    acts.append(bAll, bNone); head.appendChild(acts); card.appendChild(head);
    const list = document.createElement('div'); list.className = 'tq-list';
    rows.forEach(r => {
      const lab = document.createElement('label'); lab.className = 'tq-item' + (TQ.desired[r.kind] ? '' : ' off');
      const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !!TQ.desired[r.kind];
      cb.onchange = () => {
        TQ.desired[r.kind] = cb.checked; lab.classList.toggle('off', !cb.checked);
        const b = head.querySelector('.tq-catcount'); if (b) b.textContent = rows.filter(x => TQ.desired[x.kind]).length + '/' + rows.length;
      };
      const meta = document.createElement('span'); meta.className = 'tq-meta';
      const badges = [];
      if (r.bug_bounty_eligible) badges.push('<span class="badge webyes">BB</span>');
      if (r.pentest_only) badges.push('<span class="badge expl">pentest</span>');
      const tools = (r.tools || []).join(', ');
      meta.innerHTML = `<span class="tq-kind">${esc(r.kind)}</span> ${badges.join('')}`
        + (r.mitre ? ` <code class="tq-mitre">${esc(r.mitre)}</code>` : '')
        + (tools ? `<span class="tq-tools" title="outils qui couvrent cette technique">${esc(tools)}</span>` : '');
      lab.append(cb, meta); list.appendChild(lab);
    });
    card.appendChild(list);
    return card;
  }));
}

// changement de profil : re-prefill COSMÉTIQUE des cases à la base du profil (moteur autoritatif au save).
if ($('#tq-profile')) $('#tq-profile').addEventListener('change', () => {
  TQ.profile = $('#tq-profile').value;
  Object.values(TQ.rowByKind).forEach(r => { TQ.desired[r.kind] = tqBase(r, TQ.profile); });
  renderTechniques();
});
if ($('#tq-reload')) $('#tq-reload').addEventListener('click', loadTechniques);
if ($('#tq-save')) $('#tq-save').addEventListener('click', async () => {
  // On envoie un profil + une map TECHNIQUE COMPLÈTE (kind -> désiré) : elle définit sans ambiguïté
  // l'ensemble activé pour les kinds courants, tout en laissant un futur module hériter de la base du
  // profil (kind absent de la map -> résolu par le profil). Le moteur ENFORCE ; ici on persiste l'intention.
  const techniques = {}; Object.keys(TQ.desired).forEach(k => { techniques[k] = !!TQ.desired[k]; });
  const body = { profile: TQ.profile, categories: {}, techniques };
  const st = $('#tq-status');
  try {
    const r = await fetch(withEngagement('/api/techniques/selection'), { method: 'POST', headers: authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    if (r.status === 403) { toast('Sélection réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Sélection enregistrée (ledgerisée)', 'ok');
    if (st) { st.hidden = false; st.textContent = 'Sélection persistée — appliquée aux prochains runs (' + tqEnabledCount() + ' techniques activées).'; }
    loadTechniques();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
});

// =====================================================================================
//  WORKFLOWS — pipelines COMPOSÉS sans code (absorbe reNgine/Osmedeus/Trickest). Un workflow est une
//  PROPOSITION gouvernée : GET /api/workflows (utilisateur + intégrés dérivés du registre) + le
//  catalogue /api/techniques (groupé par catégorie + état ACTIVÉ par le scope) alimentent le builder ;
//  la MUTATION (POST /api/workflows[/:name]) est operator/admin + ledgerisée. « Lancer ce workflow »
//  passe par le C2 GOUVERNÉ (POST /api/run modules=étapes, auto_pentest) — le scope-guard ROE, la
//  sélection par-scope et l'opt-in fort-impact restent seuls JUGES (étape hors-scope/désactivée larguée).
// =====================================================================================
let WF = { user: [], builtins: [], enabled: {}, groups: {}, rowByKind: {}, modmeta: {} };

async function loadWorkflows() {
  const host = $('#wf-list'); if (!host) return;
  let wfs;
  try { wfs = await api('/workflows'); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  let cat, mods;
  try { cat = await api('/techniques'); } catch (e) { cat = { groups: {} }; }
  try { mods = await api('/modules'); } catch (e) { mods = { modules: [] }; }
  WF.user = wfs.workflows || []; WF.builtins = wfs.builtins || [];
  WF.groups = (cat && cat.groups) || {};
  WF.enabled = {}; WF.rowByKind = {};
  Object.values(WF.groups).forEach(rows => (rows || []).forEach(r => { WF.rowByKind[r.kind] = r; WF.enabled[r.kind] = !!r.enabled_for_current_scope; }));
  WF.modmeta = {}; (((mods && mods.modules) || mods) || []).forEach(m => { if (m && m.kind) WF.modmeta[m.kind] = m; });
  if ($('#wf-count')) $('#wf-count').textContent = (WF.user.length + WF.builtins.length) + ' workflows';
  const st = $('#wf-status');
  if (st) { if (wfs.error) { st.hidden = false; st.textContent = 'workflows intégrés indisponibles : ' + String(wfs.why || wfs.error); } else { st.hidden = true; } }
  renderWorkflows();
}

// étape « lançable depuis le web » (web_allowed ET ni exploit ni destructif) — miroir client de la
// gouvernance /api/run (validate_modules). Kind inconnu du catalogue modules => non lançable (fail-safe).
function wfStepIsSafe(kind) { const m = WF.modmeta[kind]; return !!(m && m.web_allowed && !m.exploit && !m.destructive); }

function wfStepChip(kind) {
  const en = WF.enabled[kind];
  const chip = document.createElement('span');
  chip.className = 'wf-chip' + (en ? '' : ' off');
  chip.title = (en ? 'activée pour le scope courant' : 'hors sélection du scope — sera LARGUÉE (fail-closed)')
    + (wfStepIsSafe(kind) ? '' : ' · exploit/non-web : opt-in fort-impact requis');
  chip.innerHTML = esc(kind) + (wfStepIsSafe(kind) ? '' : ' <span class="badge expl">expl</span>');
  return chip;
}

function renderWorkflows() {
  const host = $('#wf-list'); if (!host) return;
  const all = WF.builtins.concat(WF.user);
  if (!all.length) { host.innerHTML = '<div class="muted">aucun workflow — cliquez « Nouveau workflow » pour composer un pipeline</div>'; return; }
  host.replaceChildren(...all.map(wf => {
    const card = document.createElement('div'); card.className = 'wf-card';
    const head = document.createElement('div'); head.className = 'wf-cardhead';
    const title = document.createElement('span'); title.className = 'wf-name';
    title.innerHTML = esc(wf.name) + ' '
      + (wf.builtin ? '<span class="badge webyes">intégré</span>' : '<span class="badge">perso</span>')
      + ` <span class="badge">${wf.step_count} étape${wf.step_count > 1 ? 's' : ''}</span>`;
    head.appendChild(title);
    const acts = document.createElement('span'); acts.className = 'wf-cardacts';
    const mkBtn = (label, cls, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = cls; b.textContent = label; b.onclick = fn; return b; };
    acts.appendChild(mkBtn('Lancer', 'k-theme', () => runWorkflow(wf)));
    acts.appendChild(mkBtn('Cloner', 'k-theme', () => openWorkflowBuilder(wf, { clone: true })));
    if (!wf.builtin) {
      acts.appendChild(mkBtn('Éditer', 'k-theme', () => openWorkflowBuilder(wf, {})));
      acts.appendChild(mkBtn('Supprimer', 'k-theme danger', () => deleteWorkflow(wf)));
    }
    head.appendChild(acts); card.appendChild(head);
    if (wf.description) { const d = document.createElement('p'); d.className = 'wf-desc'; d.textContent = wf.description; card.appendChild(d); }
    const steps = document.createElement('div'); steps.className = 'wf-steps';
    (wf.step_kinds || []).forEach(k => steps.appendChild(wfStepChip(k)));
    card.appendChild(steps);
    return card;
  }));
}

async function deleteWorkflow(wf) {
  const ok = await confirmModal('Supprimer le workflow « ' + wf.name + ' » ? (action ledgerisée)', { title: 'Supprimer le workflow', okText: 'Supprimer' });
  if (!ok) return;
  try {
    const r = await fetch(withEngagement('/api/workflows/' + encodeURIComponent(wf.name)), { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ delete: true }) });
    if (r.status === 403) { toast('Suppression réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Workflow supprimé (ledgerisé)', 'ok'); loadWorkflows();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Builder natif (aucune modale navigateur) : nom + description + catalogue GROUPÉ PAR CATÉGORIE
// (réutilise /api/techniques) pour AJOUTER des étapes, colonne d'étapes ORDONNÉES (monter/descendre/
// retirer) + params JSON optionnels par étape. Enregistre POST /api/workflows (création) ou
// /api/workflows/:name (édition). L'état activé du scope est affiché sur chaque technique.
function openWorkflowBuilder(existing, opts) {
  opts = opts || {};
  const editing = !!(existing && !opts.clone);
  let steps = existing ? (existing.steps || []).map(s => ({ kind: s.kind, params: JSON.stringify(s.params || {}) === '{}' ? '' : JSON.stringify(s.params) })) : [];
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal wide wf-builder';
  const onKey = e => { if (e.key === 'Escape') close(); };
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  document.addEventListener('keydown', onKey);
  const h = document.createElement('h3'); h.textContent = editing ? ('Éditer le workflow « ' + existing.name + ' »') : 'Nouveau workflow'; box.appendChild(h);

  const meta = document.createElement('div'); meta.className = 'wf-metarow';
  const nameL = document.createElement('label'); nameL.className = 'wf-fld';
  nameL.innerHTML = '<span>Nom</span>';
  const nameI = document.createElement('input'); nameI.type = 'text'; nameI.placeholder = 'ex: web-idor-hunt';
  nameI.value = existing ? (opts.clone ? existing.name + '-copy' : existing.name) : '';
  nameI.disabled = editing;                         // le nom = la clé : figé en édition
  nameL.appendChild(nameI);
  const descL = document.createElement('label'); descL.className = 'wf-fld wf-fld-grow';
  descL.innerHTML = '<span>Description</span>';
  const descI = document.createElement('input'); descI.type = 'text'; descI.placeholder = 'à quoi sert ce pipeline';
  descI.value = existing ? (existing.description || '') : '';
  descL.appendChild(descI);
  meta.append(nameL, descL); box.appendChild(meta);

  const cols = document.createElement('div'); cols.className = 'wf-cols';
  // colonne catalogue (gauche)
  const cat = document.createElement('div'); cat.className = 'wf-cat';
  cat.innerHTML = '<div class="wf-colh">Catalogue — cliquez pour ajouter une étape</div>';
  const catBody = document.createElement('div'); catBody.className = 'wf-catbody';
  const catNames = Object.keys(WF.groups).sort();
  if (!catNames.length) catBody.innerHTML = '<div class="muted">catalogue indisponible (voir la vue Techniques)</div>';
  catNames.forEach(c => {
    const g = document.createElement('div'); g.className = 'wf-catgrp';
    g.innerHTML = `<div class="wf-catname">${esc(c)}</div>`;
    (WF.groups[c] || []).slice().sort((a, b) => String(a.kind).localeCompare(String(b.kind))).forEach(r => {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'wf-add' + (WF.enabled[r.kind] ? '' : ' off');
      b.title = (WF.enabled[r.kind] ? 'activée pour le scope' : 'désactivée pour le scope — sera larguée au tir') + (wfStepIsSafe(r.kind) ? '' : ' · exploit (opt-in requis)');
      b.innerHTML = '+ ' + esc(r.kind) + (wfStepIsSafe(r.kind) ? '' : ' <span class="badge expl">expl</span>');
      b.onclick = () => { steps.push({ kind: r.kind, params: '' }); renderSteps(); };
      g.appendChild(b);
    });
    catBody.appendChild(g);
  });
  cat.appendChild(catBody);
  // colonne étapes (droite)
  const stcol = document.createElement('div'); stcol.className = 'wf-stcol';
  stcol.innerHTML = '<div class="wf-colh">Étapes (ordonnées) — l\'ordre d\'exécution reste topologique (recon → access → exploit)</div>';
  const stBody = document.createElement('div'); stBody.className = 'wf-stbody';
  stcol.appendChild(stBody);
  cols.append(cat, stcol); box.appendChild(cols);

  function renderSteps() {
    if (!steps.length) { stBody.innerHTML = '<div class="muted">aucune étape — ajoutez des techniques depuis le catalogue</div>'; return; }
    stBody.replaceChildren(...steps.map((s, i) => {
      const row = document.createElement('div'); row.className = 'wf-step';
      const kn = document.createElement('span'); kn.className = 'wf-stepkind' + (WF.enabled[s.kind] ? '' : ' off');
      kn.innerHTML = esc(s.kind) + (WF.enabled[s.kind] ? '' : ' <span class="badge mut">larguée au scope</span>') + (wfStepIsSafe(s.kind) ? '' : ' <span class="badge expl">expl</span>');
      const pin = document.createElement('input'); pin.type = 'text'; pin.className = 'wf-stepparams'; pin.placeholder = 'params JSON (optionnel) ex {"param":"q"}';
      pin.value = s.params || ''; pin.oninput = () => { s.params = pin.value; };
      const ctl = document.createElement('span'); ctl.className = 'wf-stepctl';
      const mk = (lbl, fn, dis) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'k-theme'; b.textContent = lbl; b.disabled = !!dis; b.onclick = fn; return b; };
      ctl.append(
        mk('↑', () => { if (i > 0) { [steps[i - 1], steps[i]] = [steps[i], steps[i - 1]]; renderSteps(); } }, i === 0),
        mk('↓', () => { if (i < steps.length - 1) { [steps[i + 1], steps[i]] = [steps[i], steps[i + 1]]; renderSteps(); } }, i === steps.length - 1),
        mk('✕', () => { steps.splice(i, 1); renderSteps(); })
      );
      row.append(kn, pin, ctl);
      return row;
    }));
  }
  renderSteps();

  const err = document.createElement('div'); err.className = 'modal-err'; err.hidden = true; box.appendChild(err);
  const act = document.createElement('div'); act.className = 'modal-act';
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'm-cancel'; cancel.textContent = 'Annuler'; cancel.onclick = close;
  const save = document.createElement('button'); save.type = 'button'; save.className = 'm-ok'; save.textContent = 'Enregistrer';
  save.onclick = async () => {
    err.hidden = true;
    const name = (nameI.value || '').trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(name) || name.startsWith('-')) { err.textContent = 'Nom invalide ([A-Za-z0-9._-], 1..64, pas de « - » en tête).'; err.hidden = false; return; }
    const outSteps = [];
    for (const s of steps) {
      let params = {};
      const raw = (s.params || '').trim();
      if (raw) { try { const o = JSON.parse(raw); if (!o || typeof o !== 'object' || Array.isArray(o)) throw 0; params = o; } catch (e) { err.textContent = 'Params JSON invalides pour l\'étape « ' + s.kind +' ».'; err.hidden = false; return; } }
      outSteps.push({ kind: s.kind, params });
    }
    const body = { name, description: (descI.value || '').trim(), steps: outSteps };
    const url = editing ? ('/api/workflows/' + encodeURIComponent(name)) : '/api/workflows';
    try {
      const r = await fetch(withEngagement(url), { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
      if (r.status === 403) { err.textContent = 'Réservé à un compte operator/admin.'; err.hidden = false; return; }
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { err.textContent = 'Échec : ' + String(j.why || j.error || r.status); err.hidden = false; return; }
      toast('Workflow enregistré (ledgerisé)', 'ok'); close(); loadWorkflows();
    } catch (e) { err.textContent = 'Erreur réseau : ' + String(e.message || e); err.hidden = false; }
  };
  act.append(cancel, save); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
  setTimeout(() => { (editing ? descI : nameI).focus(); }, 30);
}

async function runWorkflow(wf) {
  const kinds = wf.step_kinds || [];
  if (!kinds.length) { toast('Workflow vide — aucune étape à lancer', 'bad'); return; }
  const defCamp = ($('#campaign') && $('#campaign').value) || 'default';
  const vals = await modal({
    title: 'Lancer le workflow « ' + wf.name + ' »', wide: true, okText: 'Lancer',
    message: 'Lancement C2 gouverné : les étapes hors-scope / désactivées pour le scope sont LARGUÉES (fail-closed) ; les étapes exploit exigent l\'opt-in fort-impact (armer + raison). Le scope-guard reste seul juge du périmètre.',
    fields: [
      { name: 'campaign', label: 'Campagne', type: 'text', value: defCamp, required: true },
      { name: 'targets', label: 'Cibles (une par ligne, ⊆ scope serveur)', type: 'textarea', required: true, placeholder: 'app.example.com' },
      { name: 'operator', label: 'Secret opérateur', type: 'password', value: OPERATOR_SECRET, hint: 'jamais persisté — mémoire de session uniquement' },
      { name: 'mode', label: 'Mode', type: 'select', value: 'propose', options: [{ value: 'propose', label: 'propose (approbation requise)' }, { value: 'auto', label: 'auto' }] },
      { name: 'reason', label: 'Raison (requise pour l\'opt-in fort-impact)', type: 'text' },
      { name: 'high', label: 'Inclure les étapes fort-impact (opt-in gouverné : armer + raison)', type: 'checkbox' },
      { name: 'arm', label: 'Armer l\'engagement', type: 'checkbox' },
    ],
    validate: v => {
      if (v.high && (!v.arm || !String(v.reason || '').trim())) return 'L\'opt-in fort-impact exige d\'ARMER ET une RAISON non vide.';
      return null;
    },
  });
  if (!vals) return;
  OPERATOR_SECRET = vals.operator || '';
  if (!OPERATOR_SECRET) { toast('Secret opérateur requis', 'bad'); return; }
  const targets = String(vals.targets || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!targets.length) { toast('Au moins une cible requise', 'bad'); return; }
  const high = !!vals.high;
  // modules = étapes du workflow ; hors opt-in fort-impact -> uniquement les étapes lançables web
  // (les exploit exigent l'opt-in — sinon /api/run rejetterait tout le run via le plancher exploit).
  const modules = high ? kinds.slice() : kinds.filter(wfStepIsSafe);
  if (!modules.length) { toast('Aucune étape lançable depuis le web — activez l\'opt-in fort-impact ou éditez le workflow', 'bad'); return; }
  const mp = {};
  (wf.steps || []).forEach(s => { if (modules.includes(s.kind) && s.params && Object.keys(s.params).length) mp[s.kind] = { ...(mp[s.kind] || {}), ...s.params }; });
  const body = { campaign: String(vals.campaign || '').trim(), targets, mode: vals.mode || 'propose', auto_pentest: true, modules, arm: !!vals.arm, allow_high_impact: high };
  if (Object.keys(mp).length) body.module_params = mp;
  body.reason = (String(vals.reason || '').trim() || ('workflow: ' + wf.name)).slice(0, 200);
  // ENGAGEMENT : le run opère SUR l'engagement actif (son scope + son ledger gouvernent, cf. serveur).
  const _eng = activeEngagement(); if (_eng != null) body.engagement_id = _eng;
  let r, j;
  try { r = await fetch('/api/run', { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) }); j = await r.json().catch(() => ({})); }
  catch (err) { toast('Erreur réseau : ' + String(err.message || err), 'bad'); return; }
  if (r.status === 202) {
    toast('Workflow « ' + wf.name + ' » lancé (' + j.mode + ') — ' + j.run_id, 'ok');
    location.hash = 'launch';
    if (typeof followRun === 'function') followRun(j.run_id, { status: 'running', campaign: j.campaign, mode: j.mode, fired: 0, dry_run: 0, vetoed: 0, errors: 0 });
    if (typeof loadRuns === 'function') loadRuns();
    return;
  }
  const code = j && j.error ? j.error : ('http_' + r.status);
  toast('Refus (' + code + ')' + (j && j.why ? ' — ' + j.why : ''), 'bad');
}

if ($('#wf-new')) $('#wf-new').addEventListener('click', () => openWorkflowBuilder(null, {}));
if ($('#wf-reload')) $('#wf-reload').addEventListener('click', loadWorkflows);

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
// EXPORT depuis Findings : CSV / JSON de l'engagement ACTIF (secrets rédigés serveur) + accès au
// rapport complet brandé (vue #reports). downloadReport() est défini plus bas (déclaration hoistée).
if ($('#f-export-csv')) $('#f-export-csv').addEventListener('click', () => downloadReport('csv'));
if ($('#f-export-json')) $('#f-export-json').addEventListener('click', () => downloadReport('json'));
if ($('#f-report')) $('#f-report').addEventListener('click', () => { location.hash = 'reports'; });

// =====================================================================================
//  FINDINGS LIBRARY — modèles de findings réutilisables (livrable client type Ghostwriter).
//  Les modèles sont GLOBAUX (réutilisables d'un engagement à l'autre) ; APPLIQUER un modèle crée UN
//  finding dans l'engagement ACTIF UNIQUEMENT (isolation, cf. serveur). create/edit = operator,
//  delete = admin, apply = operator — chaque action est ledgerisée côté serveur (fail-closed).
//  UI 100 % native (aucune modale navigateur) : réutilise modal()/confirmModal()/toast().
// =====================================================================================
const FT_SEVS = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
let FT_TEMPLATES = [];

async function loadFindingsLibrary() {
  const host = $('#ftpl-list'); if (!host) return;
  let d;
  try { d = await api('/finding-templates'); }               // GLOBAL : le param ?engagement est inerte ici
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  FT_TEMPLATES = (d && d.templates) || [];
  if ($('#ftpl-count')) $('#ftpl-count').textContent = FT_TEMPLATES.length + ' modèle' + (FT_TEMPLATES.length > 1 ? 's' : '');
  if (!FT_TEMPLATES.length) { host.innerHTML = '<div class="muted">aucun modèle — cliquez « Nouveau modèle » pour capitaliser un finding réutilisable</div>'; return; }
  host.replaceChildren(...FT_TEMPLATES.map(renderTemplateCard));
}

// Extrait l'ensemble des placeholders {clef} présents dans les gabarits d'un modèle (titre/desc/reméd).
function ftPlaceholders(tpl) {
  const set = new Set();
  const re = /\{([A-Za-z0-9_.-]+)\}/g;
  [tpl.title_tmpl, tpl.description_tmpl, tpl.remediation_tmpl].forEach(t => {
    const s = String(t || ''); let m; re.lastIndex = 0;
    while ((m = re.exec(s)) !== null) set.add(m[1]);
  });
  return [...set];
}

function renderTemplateCard(tpl) {
  const card = document.createElement('div'); card.className = 'wf-card';
  const head = document.createElement('div'); head.className = 'wf-cardhead';
  const title = document.createElement('span'); title.className = 'wf-name';
  title.innerHTML = esc(tpl.name) + ' ' + SEV_BADGE(tpl.severity)
    + (tpl.cwe ? ` <span class="badge">${esc(tpl.cwe)}</span>` : '')
    + (tpl.vuln_class ? ` <span class="badge mut">${esc(tpl.vuln_class)}</span>` : '');
  head.appendChild(title);
  const acts = document.createElement('span'); acts.className = 'wf-cardacts';
  const mk = (label, cls, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = cls; b.textContent = label; b.onclick = fn; return b; };
  acts.appendChild(mk('Appliquer', 'k-theme', () => applyTemplate(tpl)));
  acts.appendChild(mk('Éditer', 'k-theme', () => openTemplateEditor(tpl)));
  acts.appendChild(mk('Supprimer', 'k-theme danger', () => deleteTemplate(tpl)));
  head.appendChild(acts); card.appendChild(head);
  if (tpl.title_tmpl) { const p = document.createElement('p'); p.className = 'wf-desc'; p.textContent = tpl.title_tmpl; card.appendChild(p); }
  const ph = ftPlaceholders(tpl);
  if (ph.length) {
    const chips = document.createElement('div'); chips.className = 'wf-steps';
    ph.forEach(k => { const c = document.createElement('span'); c.className = 'wf-chip'; c.textContent = '{' + k + '}'; c.title = 'placeholder rempli à l\'application'; chips.appendChild(c); });
    card.appendChild(chips);
  }
  return card;
}

// Éditeur de modèle (création si existing=null, édition sinon) — operator. Envoie TOUT le formulaire :
// le serveur mappe `references` -> colonne refs et normalise la sévérité (fail-closed si hors ensemble).
async function openTemplateEditor(existing) {
  const editing = !!existing;
  const vals = await modal({
    title: editing ? ('Éditer le modèle « ' + existing.name + ' »') : 'Nouveau modèle de finding',
    okText: editing ? 'Enregistrer' : 'Créer', wide: true,
    fields: [
      { name: 'name', label: 'Nom', value: editing ? existing.name : '', required: true, hint: 'libellé du modèle (ex: XSS reflété)' },
      { name: 'severity', label: 'Sévérité', type: 'select', value: editing ? existing.severity : 'INFO', options: FT_SEVS.map(s => ({ value: s, label: s })) },
      { name: 'vuln_class', label: 'Classe de vuln', value: editing ? existing.vuln_class : '', hint: 'ex: xss, sqli, idor — devient la catégorie du finding' },
      { name: 'cwe', label: 'CWE', value: editing ? existing.cwe : '', hint: 'ex: CWE-79' },
      { name: 'title_tmpl', label: 'Titre (gabarit)', value: editing ? existing.title_tmpl : '', hint: 'placeholders {target}/{param} remplis à l\'application' },
      { name: 'description_tmpl', label: 'Description (gabarit)', type: 'textarea', value: editing ? existing.description_tmpl : '', placeholder: 'ex: Le paramètre {param} sur {target} est injectable…' },
      { name: 'remediation_tmpl', label: 'Remédiation (gabarit)', type: 'textarea', value: editing ? existing.remediation_tmpl : '', placeholder: 'ex: Utiliser des requêtes paramétrées…' },
      { name: 'references', label: 'Références', value: editing ? (existing.references || '') : '', hint: 'liens / notes (libre)' },
    ],
    validate: v => (FT_SEVS.includes(v.severity) ? null : 'Sévérité invalide.'),
  });
  if (!vals) return;
  const path = editing ? '/api/finding-templates/' + existing.id : '/api/finding-templates';
  try {
    const r = await fetch(path, { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(vals) });
    if (r.status === 403) { toast('Création/édition réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast(editing ? 'Modèle enregistré (ledgerisé)' : 'Modèle créé (ledgerisé)', 'ok');
    loadFindingsLibrary();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Suppression d'un modèle — ADMIN (le cookie de session admin autorise ; pas de prompt de token).
async function deleteTemplate(tpl) {
  const ok = await confirmModal('Supprimer le modèle « ' + tpl.name + ' » ? (ledgerisé, réservé admin — les findings déjà créés ne sont pas affectés)', { title: 'Supprimer le modèle', okText: 'Supprimer' });
  if (!ok) return;
  try {
    const r = await fetch('/api/finding-templates/' + tpl.id, { method: 'DELETE', headers: { 'Content-Type': 'application/json', Accept: 'application/json' } });
    if (r.status === 403) { toast('Suppression réservée à un administrateur', 'bad'); return; }
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Modèle supprimé (ledgerisé)', 'ok'); loadFindingsLibrary();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Applique un modèle -> crée un finding dans l'engagement ACTIF. Un champ par placeholder + cible +
// campagne. operator (fail-closed serveur). Le finding produit appartient à l'engagement actif (isolation).
async function applyTemplate(tpl) {
  const ph = ftPlaceholders(tpl);
  const engName = activeEngagementName();
  const fields = [
    { name: '__target', label: 'Cible', value: '', hint: 'hôte/URL du finding (remplit aussi {target})' },
    { name: '__campaign', label: 'Campagne (option)', value: '', hint: 'sous-label libre au sein de l\'engagement' },
  ];
  ph.filter(k => k !== 'target').forEach(k => fields.push({ name: 'ph_' + k, label: 'Paramètre {' + k + '}', value: '' }));
  const vals = await modal({
    title: 'Appliquer « ' + tpl.name + ' »',
    message: 'Crée un finding dans l\'engagement ACTIF' + (engName ? ' : ' + engName : '') + '. Renseignez les placeholders ci-dessous.',
    okText: 'Créer le finding', wide: true, fields,
  });
  if (!vals) return;
  const params = {};
  Object.keys(vals).forEach(k => { if (k.startsWith('ph_')) params[k.slice(3)] = vals[k]; });
  if (vals.__target) params.target = vals.__target;
  const body = { target: vals.__target || '', campaign: vals.__campaign || '', params };
  const eng = activeEngagement(); if (eng != null) body.engagement_id = eng;    // isolation : engagement actif
  try {
    const r = await fetch(withEngagement('/api/finding-templates/' + tpl.id + '/apply'), { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    if (r.status === 403) { toast('Application réservée à un compte operator/admin', 'bad'); return; }
    const j = await r.json().catch(() => ({}));
    if (r.status === 409) { toast('Finding déjà présent (campagne/cible/titre identiques) — dédupliqué', 'info'); return; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Finding créé dans l\'engagement actif (ledgerisé)', 'ok');
    location.hash = 'findings';
    loadFindings(0);
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Affordance « Depuis un modèle » dans la vue Findings : choisir un modèle puis l'appliquer.
async function pickTemplateAndApply() {
  let list = FT_TEMPLATES;
  if (!list.length) {
    try { const d = await api('/finding-templates'); list = (d && d.templates) || []; FT_TEMPLATES = list; }
    catch (e) { toast('Chargement des modèles : ' + e.message, 'bad'); return; }
  }
  if (!list.length) { toast('Aucun modèle — créez-en un dans la Bibliothèque de findings', 'info'); location.hash = 'findings-library'; return; }
  const vals = await modal({
    title: 'Appliquer un modèle de finding',
    message: 'Le modèle choisi sera appliqué à l\'engagement ACTIF.',
    okText: 'Continuer',
    fields: [{ name: 'id', label: 'Modèle', type: 'select', value: String(list[0].id), options: list.map(t => ({ value: String(t.id), label: t.name + ' [' + t.severity + ']' })) }],
  });
  if (!vals) return;
  const tpl = list.find(t => String(t.id) === String(vals.id));
  if (tpl) applyTemplate(tpl);
}

if ($('#ftpl-new')) $('#ftpl-new').addEventListener('click', () => openTemplateEditor(null));
if ($('#ftpl-reload')) $('#ftpl-reload').addEventListener('click', () => loadFindingsLibrary());
if ($('#f-from-tpl')) $('#f-from-tpl').addEventListener('click', () => pickTemplateAndApply());

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
  // Une source de détection est-elle CONFIGURÉE ? Sinon Forge tourne en AUTONOME (standalone) : ce
  // n'est PAS une panne. Priorité au champ serveur `source_configured` ; repli (payload ancien) sur
  // la présence d'un endpoint. `reachable` accepte les deux noms (source_/plume_ rétro-compat).
  const srcUrl = String(p.source_url || p.plume_url || '');
  const configured = (p.source_configured === true)
    || (p.source_configured === undefined && !!srcUrl);
  const reachable = (p.source_reachable === true) || (p.plume_reachable === true);

  // badge source de détection : autonome (neutre) / joignable / injoignable.
  if (plumeBadge) {
    if (!configured) {
      plumeBadge.className = 'badge mut';
      plumeBadge.textContent = 'Autonome (standalone)';
      plumeBadge.title = 'Aucune source de détection configurée — Forge fonctionne en autonome. Connectez une source (Plume/CrowdSec/FortiGate/Elastic/fichier…) dans Administration pour activer la boucle purple.';
    } else {
      plumeBadge.className = 'badge ' + (reachable ? 'ok' : 'destr');
      plumeBadge.innerHTML = `${ic(reachable ? 'check' : 'warn')} Source ${reachable ? 'joignable' : 'injoignable'}`;
      plumeBadge.title = srcUrl || (p.source_kind ? ('kind=' + p.source_kind) : 'source de détection');
    }
  }
  host.replaceChildren();

  // techniques distinctes tirées (toujours informatif, même si mesure impossible)
  const fired = Number(p.techniques_fired || 0);
  const detected = Array.isArray(p.detected) ? p.detected : [];
  const missed = Array.isArray(p.missed) ? p.missed : [];

  // AUTONOME (standalone) : aucune source de détection configurée. État NEUTRE et ATTENDU — Forge ne
  // dépend d'aucune source. On rend un « connectez une source » clair, PAS une erreur : l'UI ne paraît
  // jamais cassée. Plume n'est qu'un préréglage parmi d'autres.
  if (!configured) {
    const so = document.createElement('div'); so.className = 'pc-standalone';
    const head = document.createElement('div'); head.className = 'pc-so-head';
    head.innerHTML = `${ic('plug')} <span>Aucune source de détection configurée — Forge fonctionne en autonome</span><span class="pc-dtag">standalone</span>`;
    const det = document.createElement('div'); det.className = 'pc-so-detail';
    det.innerHTML = `Forge ne dépend d'aucune source de détection. Connectez-en une (Plume, CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, fichier…) dans <a href="#admin-detection">Administration &rarr; Source de détection</a> pour activer la boucle purple (détecté / raté / MTTD). ${fired} technique(s) distincte(s) déjà tirée(s) côté Forge en attendant.`;
    // actions d'aide : ouvrir directement la source de détection + expliquer la boucle purple (aide in-app).
    const acts = document.createElement('div'); acts.className = 'pc-so-acts';
    const goBtn = document.createElement('a'); goBtn.href = '#admin-detection'; goBtn.className = 'k-theme'; goBtn.innerHTML = `${ic('plug')}<span>Connecter une source</span>`;
    const helpBtn = document.createElement('button'); helpBtn.type = 'button'; helpBtn.className = 'k-theme'; helpBtn.innerHTML = `${ic('help')}<span>Comment ça marche&nbsp;?</span>`;
    helpBtn.addEventListener('click', () => openHelp('purple-coverage'));
    acts.append(goBtn, helpBtn);
    so.append(head, det, acts);
    host.appendChild(so);
    return;
  }

  // FAIL-OPEN LISIBLE : source configurée mais INJOIGNABLE -> mesure impossible (anomalie). On n'affiche
  // AUCUN « détecté » ni taux : ce ne sont pas des 0 réels, c'est de l'absence de mesure. On reste honnête.
  if (!reachable) {
    const fo = document.createElement('div'); fo.className = 'pc-failopen';
    const head = document.createElement('div'); head.className = 'pc-fo-head';
    head.innerHTML = `${ic('warn')} <span>Mesure de détection impossible — source injoignable (fail-open lisible)</span><span class="pc-dtag">non mesuré</span>`;
    const det = document.createElement('div'); det.className = 'pc-fo-detail';
    const reason = (typeof p.error === 'string' && p.error) ? p.error : 'source de détection injoignable';
    const urlTxt = srcUrl ? `cible : ${srcUrl}` : 'endpoint non renseigné';
    det.textContent = `${reason} — ${urlTxt}. Aucun « détecté » n'est inventé : detected/missed vides, taux et MTTD non mesurés. ${fired} technique(s) distincte(s) tirée(s) côté Forge (information offensive conservée).`;
    fo.append(head, det);
    host.appendChild(fo);
    return;
  }

  // ---- source de détection joignable : mesure exploitable -----------------------------------
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

// =====================================================================================
//  ENGAGEMENTS — vue de gestion + sélecteur d'engagement actif (header)
// =====================================================================================
// Charge /api/engagements, alimente le sélecteur header (#engagement) + l'indicateur proéminent, et
// rend la vue #engagements (liste + créer/éditer/archiver/supprimer/basculer). L'engagement actif est
// persisté localStorage (activeEngagement) et ajouté à CHAQUE requête (withEngagement) : chaque vue ne
// montre QUE ses données. create/edit = operator ; archive/delete = admin (gate serveur, fail-closed).

async function fetchEngagements() {
  const d = await api('/engagements');
  ENGAGEMENTS = (d && Array.isArray(d.engagements)) ? d.engagements : [];
  return ENGAGEMENTS;
}

// Choisit un engagement actif VALIDE : celui persisté s'il existe encore, sinon l'actif le plus récent,
// sinon le 1er. Corrige localStorage si l'id persisté a disparu (engagement supprimé entre-temps).
function pickActiveEngagement() {
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
function renderEngagementSelector() {
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
  const bar = $('#eng-bar');
  if (bar) {
    const e = ENGAGEMENTS.find(x => x.id === active);
    bar.classList.toggle('archived', !!(e && e.status === 'archived'));
    bar.title = e ? ('Engagement actif : ' + e.name + ' (' + e.mode + ', ' + e.status + ')') : 'Aucun engagement';
  }
}

function reloadCurrentView() {
  const v = location.hash.slice(1) || 'overview';
  const fn = LOADERS[VIEWS_HAS(v) ? v : 'overview']; if (fn) fn();
}

// Recharge la liste d'engagements + le sélecteur, puis (optionnel) recharge la vue courante.
async function loadEngagementSelector(reloadView) {
  try { await fetchEngagements(); } catch (e) { /* fail-soft : sélecteur vide */ }
  renderEngagementSelector();
  if (reloadView) reloadCurrentView();
}

// bascule d'engagement actif (sélecteur header OU vue) -> persiste + recharge la vue + les statuts.
function switchEngagement(id) {
  setActiveEngagement(id);
  renderEngagementSelector();
  reloadCurrentView();
  if (typeof loadStatuses === 'function') { try { loadStatuses(); } catch (e) {} }
  const e = ENGAGEMENTS.find(x => x.id === id);
  if (e) toast('Engagement actif : ' + e.name, 'ok');
}

const _scopeLines = s => String(s || '').split('\n').map(x => x.trim()).filter(Boolean);

// modale de création (operator) : nom + mode + scope in/out (une entrée par ligne).
async function engagementCreateModal() {
  const vals = await modal({
    title: 'Nouvel engagement', okText: 'Créer', wide: true,
    message: 'Un nouvel espace de travail ISOLÉ, avec son propre scope (fail-closed) et son propre ledger tamper-evident. Réservé operator.',
    fields: [
      { name: 'name', label: 'Nom', type: 'text', required: true, placeholder: 'Client — Q3 pentest' },
      { name: 'mode', label: 'Mode', type: 'select', value: 'grey', options: [{ value: 'white', label: 'white' }, { value: 'grey', label: 'grey' }, { value: 'black', label: 'black' }] },
      { name: 'in_scope', label: 'In-scope (une entrée par ligne — host / *.wildcard / CIDR)', type: 'textarea', placeholder: 'app.example.com\n*.example.com\n10.0.0.0/8' },
      { name: 'out_scope', label: 'Out-of-scope (optionnel)', type: 'textarea', placeholder: 'admin.example.com' },
    ],
  });
  if (!vals) return;
  const body = {
    name: String(vals.name || '').trim(),
    mode: vals.mode || 'grey',
    scope_json: { mode: vals.mode || 'grey', in_scope: _scopeLines(vals.in_scope), out_scope: _scopeLines(vals.out_scope) },
  };
  try {
    const r = await fetch('/api/engagements', { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
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

// modale d'édition (operator) : rename + mode + (optionnel) redéfinir le scope.
async function engagementEditModal(e) {
  const vals = await modal({
    title: 'Éditer « ' + e.name + ' »', okText: 'Enregistrer', wide: true,
    message: 'Renommer / changer le mode / redéfinir le scope. Laisser les zones scope VIDES ne les modifie pas.',
    fields: [
      { name: 'name', label: 'Nom', type: 'text', value: e.name, required: true },
      { name: 'mode', label: 'Mode', type: 'select', value: e.mode, options: [{ value: 'white', label: 'white' }, { value: 'grey', label: 'grey' }, { value: 'black', label: 'black' }] },
      { name: 'in_scope', label: 'Redéfinir in-scope (vide = inchangé — une entrée par ligne)', type: 'textarea', placeholder: 'app.example.com' },
      { name: 'out_scope', label: 'Redéfinir out-of-scope (vide = inchangé)', type: 'textarea' },
    ],
  });
  if (!vals) return;
  const body = { name: String(vals.name || '').trim(), mode: vals.mode || e.mode };
  const inl = _scopeLines(vals.in_scope), outl = _scopeLines(vals.out_scope);
  if (inl.length || outl.length) body.scope_json = { mode: vals.mode || e.mode, in_scope: inl, out_scope: outl };
  await engagementMutate(e.id, body, 'Engagement mis à jour.');
}

// mutation POST /api/engagements/:id (edit/archive/activate/delete). operatorHeaders porte X-Forge-Operator
// ET le bearer de session (admin) : le serveur gate selon l'opération (fail-closed).
async function engagementMutate(id, body, okMsg) {
  try {
    const r = await fetch('/api/engagements/' + id, { method: 'POST', headers: operatorHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
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
async function loadEngagements() {
  const host = $('#eg-result'); if (!host) return;
  try { await fetchEngagements(); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  renderEngagementSelector();
  const active = activeEngagement();
  if ($('#eg-count')) $('#eg-count').textContent = ENGAGEMENTS.length + ' engagement(s)';
  if (!ENGAGEMENTS.length) { host.innerHTML = '<div class="muted">aucun engagement</div>'; return; }
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
      '<td>' + esc(e.name) + (e.id === active ? ' <span class="badge">actif</span>' : '') + '</td>' +
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
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
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
let TENANCY = { enabled: false };
const TENANT_ROLES = [
  { value: 'tenant_admin', label: 'tenant_admin — administre le tenant' },
  { value: 'tenant_operator', label: 'tenant_operator — opère' },
  { value: 'tenant_viewer', label: 'tenant_viewer — lecture seule' },
];
function tenancyOn() { return !!(TENANCY && TENANCY.enabled); }
function tenancyAdmin() { return !!(tenancyOn() && TENANCY.is_platform_admin); }

// Tenant actif (persisté client, comme l'engagement). Null tant qu'aucun n'est choisi.
function activeTenant() { const v = localStorage.getItem('forge_tenant'); return v == null || v === '' ? null : Number(v); }
function setActiveTenant(id) { if (id == null) localStorage.removeItem('forge_tenant'); else localStorage.setItem('forge_tenant', String(id)); }

// Engagements VISIBLES compte tenu du tenant actif. Community/flag OFF => tous (byte-identique). Sinon, si
// un tenant est actif, on ne montre QUE ses engagements (le serveur a DÉJÀ filtré /api/engagements aux
// tenants accordés — ce filtre client est la 2e moitié de la hiérarchie tenant → engagement).
function visibleEngagements() {
  if (!tenancyOn()) return ENGAGEMENTS;
  const t = activeTenant();
  if (t == null) return ENGAGEMENTS;
  return ENGAGEMENTS.filter(e => e.tenant_id === t);
}

// Choisit un tenant actif VALIDE : le persisté s'il est encore accessible, sinon le 1er accessible.
function pickActiveTenant() {
  const list = (TENANCY && Array.isArray(TENANCY.tenants)) ? TENANCY.tenants : [];
  const cur = activeTenant();
  if (cur != null && list.some(t => t.id === cur)) return cur;
  const id = list.length ? list[0].id : null;
  setActiveTenant(id);
  return id;
}

// Peuple le sélecteur de tenant (header) + affiche/masque la barre selon le flag et l'accès.
function renderTenantSelector() {
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
function switchTenant(id) {
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
async function loadTenancyContext() {
  try {
    const r = await fetch('/api/tenancy', { headers: { Accept: 'application/json' } });
    TENANCY = r.ok ? (await r.json().catch(() => ({ enabled: false }))) : { enabled: false };
  } catch (e) { TENANCY = { enabled: false }; }
  if (!TENANCY || typeof TENANCY !== 'object') TENANCY = { enabled: false };
  applyTenancy();
}

// Applique l'état de tenancy : sélecteur header + lien nav #tenants (platform-admin) + garde de route.
function applyTenancy() {
  renderTenantSelector();
  const link = $('#nav-tenants');
  if (link) link.hidden = !tenancyAdmin();
  if (!tenancyAdmin() && location.hash.slice(1) === 'tenants') location.hash = 'overview';
}

// --- Vue #tenants (platform-admin) : liste + CRUD + gestion des grants ---------------------------
// Réutilise adminApi (prefixe /api, lève sur !ok avec le `why` serveur contrôlé -> anti-XSS).
async function loadTenants() {
  const host = $('#tenants-list'); if (!host) return;
  if (!tenancyAdmin()) { host.innerHTML = '<div class="muted">réservé au platform-admin (multi-tenancy enterprise)</div>'; if ($('#tenants-count')) $('#tenants-count').textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/tenants'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const tenants = (data && data.tenants) || [];
  if ($('#tenants-count')) $('#tenants-count').textContent = tenants.length + ' tenant' + (tenants.length > 1 ? 's' : '');
  if (!tenants.length) { host.innerHTML = '<div class="muted">aucun tenant</div>'; return; }
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>#</th><th>Nom</th><th>État</th><th>Engagements</th><th>Grants</th><th>Créé</th><th>Actions</th></tr></thead>';
  const tb = document.createElement('tbody');
  tenants.forEach(t => {
    const tr = document.createElement('tr');
    const state = t.status === 'archived' ? '<span class="badge bad">archivé</span>' : '<span class="badge ok">actif</span>';
    tr.innerHTML =
      `<td class="mut">${t.id}</td>` +
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

async function tenantCreate() {
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

async function tenantRename(t) {
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

async function tenantToggleArchive(t) {
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
async function tenantToggleGrants(t, tr) {
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

function renderGrantsPanel(t, td, grants) {
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

async function tenantGrantAdd(t, td) {
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

async function tenantGrantRemove(t, login, td) {
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

// =====================================================================================
//  IDENTITY / SSO (ENTERPRISE, flag-gated) — vue #identity : (1) provider OIDC, (2) token SCIM,
//  (3) mapping groupe -> rôle/grant (RBAC avancé). Réservé admin + flag engagé (identityAdmin()).
//  Le serveur reste l'autorité (routes flag+admin -> 404/403) ; ce masquage = défense en profondeur.
//  Les secrets (client_secret, token SCIM) sont write-only : jamais réaffichés par les GET.
// =====================================================================================
function idErr(id, msg) { const e = $(id); if (e) { e.textContent = msg; e.hidden = !msg; } }

async function loadIdentity() {
  const sec = $('#identity'); if (!sec) return;
  if (!identityAdmin()) {
    // Défense en profondeur : masquer toutes les sous-cartes si non autorisé (le serveur 404/403 de toute façon).
    ['#id-oidc-wrap', '#id-scim-wrap', '#id-map-wrap'].forEach(s => { const el = $(s); if (el) el.hidden = true; });
    return;
  }
  // Sous-cartes affichées selon le flag actif (SSO -> OIDC ; SCIM -> token ; l'une OU l'autre -> mapping).
  const oidc = $('#id-oidc-wrap'); if (oidc) oidc.hidden = !ENTERPRISE.sso;
  const scim = $('#id-scim-wrap'); if (scim) scim.hidden = !ENTERPRISE.scim;
  const map = $('#id-map-wrap'); if (map) map.hidden = !identityOn();
  if (ENTERPRISE.sso) await loadIdentityOidc();
  if (ENTERPRISE.scim) await loadIdentityScim();
  if (identityOn()) await loadIdentityMap();
}

// (1) Provider OIDC — GET /api/sso/config (client_secret REDACTED -> client_secret_set booléen).
async function loadIdentityOidc() {
  idErr('#id-oidc-err', '');
  let data = null;
  try { data = await adminApi('/sso/config'); } catch (e) { idErr('#id-oidc-err', 'Chargement OIDC refusé : ' + e.message); return; }
  const c = (data && data.config) || {};
  const set = (id, v) => { const el = $(id); if (el) el.value = v == null ? '' : v; };
  set('#id-oidc-issuer', c.issuer);
  set('#id-oidc-clientid', c.client_id);
  set('#id-oidc-redirect', c.redirect_uri);
  set('#id-oidc-allow', Array.isArray(c.allowed_redirect_uris) ? c.allowed_redirect_uris.join('\n') : '');
  set('#id-oidc-prov', c.provisioning || 'match');
  set('#id-oidc-claim', c.user_claim || 'email');
  set('#id-oidc-role', c.default_role || 'viewer');
  const badge = $('#id-oidc-secret-badge');
  if (badge) badge.textContent = c.client_secret_set ? 'secret configuré' : 'secret non configuré';
  const secEl = $('#id-oidc-secret'); if (secEl) secEl.value = ''; // write-only : jamais pré-rempli
}
if ($('#id-oidc-form')) $('#id-oidc-form').addEventListener('submit', async e => {
  e.preventDefault(); idErr('#id-oidc-err', '');
  const val = id => (($(id) && $(id).value) || '').trim();
  const allow = val('#id-oidc-allow').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const body = {
    issuer: val('#id-oidc-issuer'), client_id: val('#id-oidc-clientid'), redirect_uri: val('#id-oidc-redirect'),
    allowed_redirect_uris: allow, provisioning: val('#id-oidc-prov'), user_claim: val('#id-oidc-claim'), default_role: val('#id-oidc-role'),
  };
  const secret = ($('#id-oidc-secret') && $('#id-oidc-secret').value) || '';
  if (secret) body.client_secret = secret; // write-only : envoyé seulement si (re)saisi
  try {
    await adminApi('/sso/config', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    toast('Provider OIDC enregistré', 'good'); await loadIdentityOidc();
  } catch (e) { idErr('#id-oidc-err', 'Enregistrement refusé : ' + e.message); }
});

// (2) Token SCIM — GET /api/scim/config (token JAMAIS renvoyé ; seulement token_set + default_role).
async function loadIdentityScim() {
  let data = null;
  try { data = await adminApi('/scim/config'); } catch (e) { toast('Chargement SCIM refusé : ' + e.message, 'bad'); return; }
  const badge = $('#id-scim-token-badge'); if (badge) badge.textContent = data && data.token_set ? 'token actif' : 'aucun token';
  const roleEl = $('#id-scim-role'); if (roleEl && data && data.default_role) roleEl.value = data.default_role;
  const ep = $('#id-scim-endpoint'); if (ep && data && data.endpoint) ep.textContent = data.endpoint;
  const once = $('#id-scim-token-once'); if (once) once.hidden = true; // le token ne survit pas à un reload
}
if ($('#id-scim-rotate')) $('#id-scim-rotate').addEventListener('click', async () => {
  try {
    const r = await adminApi('/scim/config', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ rotate: true }) });
    if (r && r.token) {
      const box = $('#id-scim-token-once'), val = $('#id-scim-token-val');
      if (val) val.textContent = r.token; if (box) box.hidden = false; // affiché UNE fois
    }
    toast('Token SCIM généré (copiez-le maintenant)', 'good'); await loadIdentityScim();
  } catch (e) { toast('Génération refusée : ' + e.message, 'bad'); }
});
if ($('#id-scim-revoke')) $('#id-scim-revoke').addEventListener('click', async () => {
  if (!confirm('Révoquer le token SCIM ? L\'IdP ne pourra plus provisionner.')) return;
  try {
    await adminApi('/scim/config', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ revoke: true }) });
    const once = $('#id-scim-token-once'); if (once) once.hidden = true;
    toast('Token SCIM révoqué', 'good'); await loadIdentityScim();
  } catch (e) { toast('Révocation refusée : ' + e.message, 'bad'); }
});
if ($('#id-scim-save-role')) $('#id-scim-save-role').addEventListener('click', async () => {
  const role = ($('#id-scim-role') && $('#id-scim-role').value) || 'viewer';
  try {
    await adminApi('/scim/config', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ default_role: role }) });
    toast('Rôle SCIM par défaut enregistré', 'good');
  } catch (e) { toast('Enregistrement refusé : ' + e.message, 'bad'); }
});
if ($('#id-scim-token-copy')) $('#id-scim-token-copy').addEventListener('click', () => {
  const val = $('#id-scim-token-val'); if (val && navigator.clipboard) navigator.clipboard.writeText(val.textContent || '').then(() => toast('Token copié', 'good'), () => {});
});

// (3) Mapping groupe -> rôle/grant (RBAC avancé) — GET/POST/DELETE /api/rbac/group-map (admin).
async function loadIdentityMap() {
  const host = $('#id-map-list'); if (!host) return;
  let data = null;
  try { data = await adminApi('/rbac/group-map'); } catch (e) { host.innerHTML = '<div class="muted">Chargement refusé : ' + esc(e.message) + '</div>'; return; }
  const rows = (data && Array.isArray(data.mappings)) ? data.mappings : [];
  if (!rows.length) { host.innerHTML = '<div class="muted">Aucun mapping — un groupe non mappé ne confère aucun droit (moindre privilège).</div>'; return; }
  let html = '<table class="id-map-tbl"><thead><tr><th>Groupe IdP</th><th>Rôle</th><th>Tenant</th><th>Rôle tenant</th><th></th></tr></thead><tbody>';
  rows.forEach(m => {
    html += '<tr><td><code>' + esc(m.group) + '</code></td><td>' + esc(m.role) + '</td><td>' + (m.tenant_id == null ? '—' : esc(m.tenant_id)) + '</td><td>' + (m.tenant_role == null ? '—' : esc(m.tenant_role)) + '</td>'
      + '<td><button class="k-theme id-map-del" type="button" data-group="' + esc(m.group) + '">Retirer</button></td></tr>';
  });
  html += '</tbody></table>';
  host.innerHTML = html;
  host.querySelectorAll('.id-map-del').forEach(b => b.addEventListener('click', async () => {
    const g = b.getAttribute('data-group') || '';
    if (!confirm('Retirer le mapping du groupe « ' + g + ' » ?')) return;
    try { await adminApi('/rbac/group-map/' + encodeURIComponent(g), { method: 'DELETE', headers: { Accept: 'application/json' } }); toast('Mapping retiré', 'good'); await loadIdentityMap(); }
    catch (e) { toast('Retrait refusé : ' + e.message, 'bad'); }
  }));
}
if ($('#id-map-form')) $('#id-map-form').addEventListener('submit', async e => {
  e.preventDefault(); idErr('#id-map-err', '');
  const group = (($('#id-map-group') && $('#id-map-group').value) || '').trim();
  const role = ($('#id-map-role') && $('#id-map-role').value) || 'viewer';
  const tenantRaw = (($('#id-map-tenant') && $('#id-map-tenant').value) || '').trim();
  const trole = ($('#id-map-trole') && $('#id-map-trole').value) || '';
  if (!group) { idErr('#id-map-err', 'Groupe IdP requis.'); return; }
  const body = { group, role };
  if (tenantRaw) { const t = parseInt(tenantRaw, 10); if (Number.isInteger(t) && t > 0) body.tenant_id = t; }
  if (trole) body.tenant_role = trole;
  try {
    await adminApi('/rbac/group-map', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    toast('Mapping enregistré', 'good');
    if ($('#id-map-group')) $('#id-map-group').value = '';
    await loadIdentityMap();
  } catch (e) { idErr('#id-map-err', 'Enregistrement refusé : ' + e.message); }
});
if ($('#identity-reload')) $('#identity-reload').addEventListener('click', loadIdentity);

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
  // ENGAGEMENT : le run opère SUR l'engagement actif (son scope + son ledger gouvernent, cf. serveur).
  { const _eng = activeEngagement(); if (_eng != null) body.engagement_id = _eng; }

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
//  IMPORT — migration : ingérer une SORTIE DE SCANNER EXISTANTE en findings orientés preuve.
//  POST /api/import (opérateur, ledgerisé, scope-guardé). PUR DATA : le fichier est parsé côté
//  serveur (moteur Python, SOURCE UNIQUE des parseurs), scope-filtré, secrets rédigés. Le secret
//  opérateur est partagé avec le lancement C2 (OPERATOR_SECRET, jamais persisté).
// =====================================================================================
function imShowErr(msg) { const e = $('#im-err'); if (e) { e.textContent = msg; e.hidden = !msg; } }

function loadImport() {
  // reflète l'état du secret opérateur en session (partagé avec la vue Lancement C2).
  const b = $('#im-c2state');
  if (b) {
    const ok = !!OPERATOR_SECRET;
    b.textContent = ok ? 'secret opérateur en session' : 'secret opérateur requis';
    b.className = 'badge ' + (ok ? 'webyes' : 'mut');
  }
  if ($('#im-operator') && OPERATOR_SECRET && !$('#im-operator').value) $('#im-operator').value = OPERATOR_SECRET;
}

function readFileText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result || ''));
    r.onerror = () => reject(new Error('lecture du fichier impossible'));
    r.readAsText(file);
  });
}

function renderImportResult(j) {
  const host = $('#im-result');
  if (!host) return;
  const c = j.counts || {};
  const cell = v => (v === null || v === undefined) ? '—' : esc(String(v));
  host.innerHTML =
    '<div class="roecounters" style="margin-top:10px">' +
    `<span class="badge ok">ingérés : ${esc(String(j.ingested ?? 0))}</span>` +
    `<span class="badge">format : ${esc(String(j.format || '—'))}</span>` +
    `<span class="badge mut">parsés : ${cell(c.parsed)}</span>` +
    `<span class="badge webyes">in-scope : ${cell(c.in_scope)}</span>` +
    `<span class="badge expl">hors-scope : ${cell(c.out_of_scope)}</span>` +
    `<span class="badge mut">run : ${esc(String(j.run_id || '—'))}</span>` +
    '</div>' +
    '<p class="muted" style="margin:8px 0 0">Findings orientés preuve (jamais <code>vulnerable</code>). ' +
    'Consulte-les dans <a href="#findings">Findings</a> ; l\'import est tracé au <a href="#ledger">Ledger</a> ' +
    '(<code>console.import</code>).</p>';
  host.hidden = false;
}

async function submitImport(ev) {
  if (ev) ev.preventDefault();
  imShowErr('');
  const campaign = ($('#im-campaign') && $('#im-campaign').value || '').trim();
  const format = ($('#im-format') && $('#im-format').value) || 'auto';
  const fileEl = $('#im-file');
  const file = fileEl && fileEl.files && fileEl.files[0];
  const flag = !!($('#im-flag') && $('#im-flag').checked);
  if (!OPERATOR_SECRET) { imShowErr('Secret opérateur C2 requis pour importer.'); if ($('#im-operator')) $('#im-operator').focus(); return; }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(campaign) || campaign.startsWith('-')) { imShowErr('Campagne invalide (^[A-Za-z0-9._-]{1,64}$, pas de « - » en tête).'); return; }
  if (!file) { imShowErr('Sélectionne un fichier de scan à importer.'); return; }
  const btn = $('#im-submit'); const stat = $('#im-stat');
  let content;
  try { content = await readFileText(file); }
  catch (e) { imShowErr('Erreur : ' + esc(String(e.message || e))); return; }
  if (!content.trim()) { imShowErr('Le fichier est vide.'); return; }
  if (btn) btn.disabled = true; if (stat) stat.textContent = 'import en cours…';
  let r;
  try {
    r = await fetch('/api/import', {
      method: 'POST',
      headers: operatorHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ campaign, format, filename: file.name || '', content, flag_out_of_scope: flag }),
    });
  } catch (err) {
    if (btn) btn.disabled = false; if (stat) stat.textContent = '';
    imShowErr('Erreur réseau : ' + esc(String(err.message || err))); return;
  }
  if (btn) btn.disabled = false; if (stat) stat.textContent = '';
  let j = {};
  try { j = await r.json(); } catch (e) { /* réponse non-JSON */ }
  if (r.status === 403) { imShowErr('Refusé : rôle opérateur requis (vérifie le secret opérateur C2).'); return; }
  if (!r.ok) { imShowErr('Import refusé : ' + esc(String((j && (j.why || j.error)) || ('HTTP ' + r.status)))); return; }
  renderImportResult(j);
  toast(`Import OK — ${j.ingested ?? 0} finding(s) ingéré(s) (format ${j.format || '?'}).`, 'ok');
}

if ($('#im-form')) $('#im-form').addEventListener('submit', submitImport);
if ($('#im-operator')) $('#im-operator').addEventListener('input', e => { OPERATOR_SECRET = e.target.value; loadImport(); });
if ($('#im-clearop')) $('#im-clearop').addEventListener('click', () => { OPERATOR_SECRET = ''; if ($('#im-operator')) $('#im-operator').value = ''; loadImport(); toast('Secret opérateur oublié (session).', 'ok'); });

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
  // ENGAGEMENT : le run opère SUR l'engagement actif (son scope + son ledger gouvernent, cf. serveur).
  { const _eng = activeEngagement(); if (_eng != null) body.engagement_id = _eng; }
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

// =====================================================================================
//  REPORTS — LIVRABLE CLIENT : rapport d'engagement AGRÉGÉ + branding admin + aperçu (vue #reports).
//  Toujours l'engagement ACTIF (activeEngagement) : GET /api/engagements/:id/report?format=… — formats
//  html|pdf|docx|csv|json, secrets rédigés côté serveur, ISOLÉ à l'engagement, chaque génération
//  journalisée au ledger. Branding : GET (viewer+) / POST (admin) /api/report/branding[?engagement=:id].
//  100 % natif : réutilise modal()/toast()/adminApi() + un iframe same-origin pour l'aperçu. Aucune
//  modale navigateur. Le serveur reste l'autorité (viewer+ pour lire, admin pour brander, fail-closed).
// =====================================================================================
const REP_FMT = { html: 'HTML', pdf: 'PDF', docx: 'DOCX', csv: 'CSV', json: 'JSON' };

// Engagement actif courant (id + objet), relu à CHAQUE appel : la vue suit le sélecteur d'en-tête.
function repActive() {
  const id = activeEngagement();
  return { id, e: ENGAGEMENTS.find(x => x.id === id) };
}

// rend la vue #reports : badge/nom de l'engagement actif, bouton branding gaté admin, aperçu HTML.
async function loadReports() {
  const { id, e } = repActive();
  const badge = $('#rep-eng'); if (badge) badge.textContent = e ? ('#' + id) : '';
  const nm = $('#rep-engname');
  if (nm) nm.textContent = e ? (e.name + ' · ' + e.mode + (e.status === 'archived' ? ' [archivé]' : '')) : '(aucun engagement actif)';
  // Branding réservé admin (défense en profondeur — le serveur gate aussi en 403).
  const bb = $('#rep-brand'); if (bb) bb.hidden = !isAdmin();
  const noEng = (id == null);
  ['rep-generate', 'rep-refresh'].forEach(bid => { const b = $('#' + bid); if (b) b.disabled = noEng; });
  const host = $('#rep-preview'); if (!host) return;
  if (noEng) { host.innerHTML = '<div class="muted">Aucun engagement actif — sélectionnez-en un dans l\'en-tête pour générer son rapport.</div>'; return; }
  await previewReport();
}

// Aperçu HTML du rapport de l'engagement ACTIF dans un iframe SANDBOX same-origin. Le HTML provient de
// notre endpoint authentifié (cookie same-origin) ; tout dynamique est échappé côté serveur. On injecte
// une <base href> (URL canonique du rapport) pour résoudre /quetzal.svg. Sandbox SANS allow-scripts :
// les éventuels handlers inline du document sont neutralisés (l'UI fournit ses propres contrôles).
async function previewReport() {
  const host = $('#rep-preview'); if (!host) return;
  const { id } = repActive(); if (id == null) return;
  const url = '/api/engagements/' + id + '/report?format=html';
  host.innerHTML = '<div class="muted">chargement de l\'aperçu…</div>';
  let r, html;
  try { r = await fetch(url, { headers: { Accept: 'text/html' } }); html = await r.text().catch(() => ''); }
  catch (err) { host.innerHTML = '<div class="bad">aperçu indisponible : ' + esc(err.message || err) + '</div>'; return; }
  if (r.status === 401 || r.status === 403) { host.innerHTML = '<div class="muted">Session requise (viewer+) pour générer un rapport.</div>'; return; }
  if (r.status === 404) { host.innerHTML = '<div class="muted">Engagement introuvable (supprimé ?).</div>'; return; }
  if (!r.ok) { host.innerHTML = '<div class="bad">aperçu indisponible (HTTP ' + r.status + ').</div>'; return; }
  const baseHref = new URL(url, location.href).href;
  const withBase = html.replace(/<head>/i, '<head><base href="' + baseHref.replace(/"/g, '&quot;') + '">');
  const blobUrl = URL.createObjectURL(new Blob([withBase], { type: 'text/html;charset=utf-8' }));
  const frame = document.createElement('iframe');
  frame.className = 'rep-frame'; frame.title = 'Aperçu du rapport d\'engagement';
  frame.setAttribute('sandbox', 'allow-same-origin');
  frame.src = blobUrl;
  frame.addEventListener('load', () => setTimeout(() => URL.revokeObjectURL(blobUrl), 5000));
  host.replaceChildren(frame);
}

// Génère + télécharge le rapport de l'engagement ACTIF au format choisi. Récupéré en blob (cookie auth),
// déclenche un download natif (<a download>) ; le PDF s'ouvre inline (nouvelle fenêtre). Dégradations
// 501 (pdf/docx indisponibles sur l'hôte) et 401/403/404 remontées en toast lisible.
async function downloadReport(format) {
  const { id } = repActive();
  if (id == null) { toast('Aucun engagement actif.', 'bad'); return; }
  const fmt = REP_FMT[format] ? format : 'html';
  const url = '/api/engagements/' + id + '/report?format=' + fmt;
  const btn = $('#rep-generate'); if (btn) btn.disabled = true;
  let r;
  try { r = await fetch(url, { headers: { Accept: '*/*' } }); }
  catch (e) { if (btn) btn.disabled = false; toast('Erreur réseau : ' + (e.message || e), 'bad'); return; }
  if (btn) btn.disabled = false;
  if (r.status === 401 || r.status === 403) { toast('Session requise (viewer+) pour générer un rapport.', 'bad'); return; }
  if (r.status === 404) { toast('Engagement introuvable.', 'bad'); return; }
  if (r.status === 501) {
    let j = null; try { j = await r.json(); } catch (e) {}
    const hint = (j && (j.hint || j.why)) || (REP_FMT[fmt] + ' indisponible sur l\'hôte.');
    toast(REP_FMT[fmt] + ' : ' + hint, 'bad', 6000);
    return;
  }
  if (!r.ok) { toast('Rapport indisponible (HTTP ' + r.status + ').', 'bad'); return; }
  let blob; try { blob = await r.blob(); } catch (e) { toast('Lecture du rapport : ' + (e.message || e), 'bad'); return; }
  const objUrl = URL.createObjectURL(blob);
  if (fmt === 'pdf') {
    const w = window.open(objUrl, '_blank');
    if (!w) toast('Pop-up bloquée — autorise les fenêtres pour ouvrir le PDF.', 'bad');
    setTimeout(() => URL.revokeObjectURL(objUrl), 60000);
  } else {
    const a = document.createElement('a'); a.href = objUrl; a.download = 'forge-engagement-' + id + '.' + fmt;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
  }
  toast('Rapport ' + REP_FMT[fmt] + ' généré (ledgerisé).', 'ok');
}

// Configuration du BRANDING (ADMIN) : nom du commanditaire, logo (URL ou data-URI), vendor, mention de
// confidentialité. Portée GLOBALE ou OVERRIDE de l'engagement actif (case à cocher). GET pré-remplit la
// valeur effective ; POST via adminApi (403 si non-admin). Round-trip + rafraîchit l'aperçu. Ledgerisé.
async function brandingModal() {
  if (!isAdmin()) { toast('Configuration du branding réservée aux administrateurs.', 'bad'); return; }
  const { id, e } = repActive();
  let cur = null;
  try { cur = await adminApi('/report/branding' + (id != null ? '?engagement=' + id : '')); }
  catch (err) { toast(err.status === 403 ? 'Réservé aux administrateurs.' : ('Branding : ' + err.message), 'bad'); return; }
  const eff = (cur && cur.effective) || {};
  const vals = await modal({
    title: 'Branding du rapport', okText: 'Enregistrer', wide: true,
    message: 'Marque le livrable au commanditaire (aucun secret). Portée GLOBALE (tous les engagements) ou OVERRIDE de l\'engagement actif' + (e ? ' « ' + e.name + ' »' : '') + '. Réservé admin, journalisé au ledger.',
    fields: [
      { name: 'customer_name', label: 'Nom du commanditaire', type: 'text', value: eff.customer_name || '', placeholder: 'ACME Corp' },
      { name: 'logo', label: 'Logo (URL ou data-URI, optionnel)', type: 'textarea', value: eff.logo || '', placeholder: 'data:image/png;base64,… ou /assets/logo.png', hint: 'Intégré tel quel dans la page de garde (document autonome). Vide = logo Forge par défaut.' },
      { name: 'vendor', label: 'Prestataire (vendor)', type: 'text', value: eff.vendor || '', placeholder: 'GuatX Forge' },
      { name: 'confidentiality', label: 'Mention de confidentialité', type: 'text', value: eff.confidentiality || '' },
      { name: 'per_engagement', label: 'Appliquer à l\'engagement actif uniquement (override)' + (e ? ' — ' + e.name : ''), type: 'checkbox', value: false },
    ],
  });
  if (!vals) return;
  const body = {};
  ['customer_name', 'logo', 'vendor', 'confidentiality'].forEach(k => { body[k] = String(vals[k] == null ? '' : vals[k]); });
  const scope = (vals.per_engagement && id != null) ? ('?engagement=' + id) : '';
  try {
    await adminApi('/report/branding' + scope, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    toast('Branding enregistré (ledgerisé).', 'ok');
    await previewReport();
  } catch (err) { toast(err.status === 403 ? 'Réservé aux administrateurs.' : ('Échec : ' + err.message), 'bad'); }
}

if ($('#rep-generate')) $('#rep-generate').addEventListener('click', () => downloadReport(($('#rep-format') && $('#rep-format').value) || 'html'));
if ($('#rep-refresh')) $('#rep-refresh').addEventListener('click', previewReport);
if ($('#rep-brand')) $('#rep-brand').addEventListener('click', brandingModal);

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
      { name: 'login', label: 'Login', required: true, placeholder: '[A-Za-z0-9._-]', hint: 'Identifiant de connexion : lettres, chiffres, . _ - (1 à 64 car., sans tiret initial).' },
      { name: 'role', label: 'Role', type: 'select', options: ADMIN_ROLES, value: 'viewer', hint: 'viewer = lecture seule (aucun tir) · operator = arme et lance le C2 (opt-in fort impact possible) · admin = administre comptes, connecteurs, source de détection et sauvegardes. Attribuez le minimum requis.' },
      { name: 'password', label: 'Mot de passe', type: 'password', required: true, placeholder: 'mot de passe du compte', hint: 'Haché en argon2id côté serveur (jamais stocké en clair). Choisissez une phrase de passe forte ; le compte pourra la changer.' },
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
    fields: [{ name: 'role', label: 'Role', type: 'select', options: ADMIN_ROLES, value: u.role, hint: 'viewer = lecture seule · operator = arme/lance le C2 · admin = administration complète. Rétrograder révoque immédiatement les sessions du compte.' }],
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

// =====================================================================================
//  SOURCE DE DÉTECTION — composant PARTAGÉ (panneau #admin ET étape 3 du wizard)
//  La source BLUE (SIEM/IDS/pare-feu) est configurable SANS code : `kind` + connexion (endpoint/auth/
//  query) + éditeur de mapping MITRE (règle/signature native -> technique). Le SECRET est WRITE-ONLY :
//  affiché ••• une fois posé (secret_set), jamais re-rendu par le serveur. GET/POST /api/detection/source
//  (admin, ledgerisé) ; test de joignabilité via POST /api/detection/test. Le même composant sert le
//  wizard et l'admin (parité stricte du jeu de champs — exigence de cohérence).
// =====================================================================================
// Liste FERMÉE des kinds (parité avec DETECTION_KINDS côté console + le registre collecteur Python).
const DETECTION_KINDS = [
  { value: 'none', label: 'Aucune (standalone) — Forge en autonome' },
  { value: 'plume', label: 'Plume (SOC) — préréglage optionnel' },
  { value: 'generic_http', label: 'HTTP générique (JSON)' },
  { value: 'crowdsec', label: 'CrowdSec (LAPI)' },
  { value: 'elastic', label: 'Elastic (_search)' },
  { value: 'opensearch', label: 'OpenSearch (_search)' },
  { value: 'fortigate_syslog', label: 'FortiGate (syslog)' },
  { value: 'pfsense', label: 'pfSense (filterlog)' },
  { value: 'opnsense', label: 'OPNsense (filterlog)' },
  { value: 'file_jsonl', label: 'Fichier JSONL' },
  { value: 'exec', label: 'Commande (exec)' },
];
const DET_HTTP_KINDS = new Set(['plume', 'generic_http', 'crowdsec', 'elastic', 'opensearch']);
const DET_SYSLOG_KINDS = new Set(['fortigate_syslog', 'pfsense', 'opnsense']);
const DET_TABLE_KINDS = new Set(['generic_http', 'crowdsec', 'elastic', 'opensearch', 'file_jsonl', 'exec']);
const DET_AUTH_KINDS = new Set(['plume', 'generic_http', 'crowdsec', 'elastic', 'opensearch']);
const DET_QUERY_KINDS = new Set(['generic_http', 'crowdsec', 'elastic', 'opensearch']);
const DET_JSON_QUERY_KINDS = new Set(['elastic', 'opensearch']); // query = corps JSON (dict)
// clés de mapping représentables par l'éditeur de lignes (le reste -> éditeur JSON avancé).
const DET_MAP_SIMPLE_KEYS = new Set(['table', 'field', 'rules', 'records', 'ts']);
// petit constructeur DOM sûr : détail = attrs (value/placeholder/type/...) posés via propriété (jamais innerHTML).
function detEl(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (attrs) for (const k in attrs) { if (k === 'text') e.textContent = attrs[k]; else e[k] = attrs[k]; }
  return e;
}
function detField(labelText, control, hint) {
  const l = detEl('label', 'login-f');
  l.appendChild(detEl('span', null, { text: labelText }));
  l.appendChild(control);
  // indice explicatif optionnel : reste dans le label -> se masque/affiche avec lui (refreshVisibility).
  if (hint) l.appendChild(detEl('small', 'det-fhint', { text: hint }));
  return l;
}
// Factory : monte le jeu de champs dans `host` et renvoie un contrôleur { setConfig, getConfig, clearSecret, el }.
function detectionSourceForm(host) {
  host.classList.add('det-form');
  host.replaceChildren();
  const st = { secretSet: false, secretDirty: false, kind: 'none' };

  const kindSel = detEl('select', 'det-kind');
  DETECTION_KINDS.forEach(k => kindSel.appendChild(detEl('option', null, { value: k.value, text: k.label })));
  host.appendChild(detField('Type de source (kind)', kindSel,
    'La famille de la source BLUE : « Aucune » = autonome (Forge tourne sans SOC). Les autres câblent un SIEM/IDS/pare-feu (Plume, CrowdSec, Elastic, FortiGate, fichier, commande…) — le reste du formulaire s\'adapte au type choisi.'));

  // endpoint / chemin / commande (une seule entrée, ré-étiquetée selon le kind).
  const epInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off' });
  const epLabel = detField('Endpoint', epInput,
    'Où lire les détections : une URL (HTTP), un chemin de fichier (syslog/JSONL) ou une commande (exec). Le libellé s\'ajuste au type de source.');
  host.appendChild(epLabel);

  // --- bloc auth (http kinds) ---
  const authWrap = detEl('div', 'det-block');
  const authSel = detEl('select');
  [['', '— aucune'], ['basic', 'Basic'], ['bearer', 'Bearer'], ['api_key_header', "En-tête d'API"]]
    .forEach(([v, l]) => authSel.appendChild(detEl('option', null, { value: v, text: l })));
  authWrap.appendChild(detField("Type d'authentification", authSel,
    'Comment Forge s\'authentifie auprès de la source : Basic (login:mot de passe), Bearer (jeton porteur) ou En-tête d\'API (clé dans un en-tête nommé). « Aucune » si l\'endpoint est ouvert.'));
  const hdrInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: X-Api-Key' });
  const hdrLabel = detField("Nom de l'en-tête d'API", hdrInput,
    'Uniquement pour « En-tête d\'API » : le nom de l\'en-tête HTTP qui portera le secret (ex : X-Api-Key pour CrowdSec).');
  authWrap.appendChild(hdrLabel);
  const secInput = detEl('input', null, { type: 'password', autocomplete: 'new-password', placeholder: 'secret / token' });
  secInput.addEventListener('input', () => { st.secretDirty = true; });
  authWrap.appendChild(detField('Secret / token (write-only)', secInput,
    'Write-only : envoyé au serveur puis affiché ••• (jamais renvoyé). Laissez vide pour conserver le secret déjà posé ; saisissez une valeur uniquement pour le remplacer.'));
  host.appendChild(authWrap);

  // --- query (http kinds) ---
  const qInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: since={since}' });
  const qLabel = detField('Query', qInput,
    'Filtre côté source : chaîne avec {since} substitué à la fenêtre (HTTP/CrowdSec), ou corps JSON de requête _search (Elastic/OpenSearch).');
  host.appendChild(qLabel);

  // --- mapping MITRE ---
  const mapWrap = detEl('div', 'det-block');
  mapWrap.appendChild(detEl('div', 'det-sub', { text: 'Mapping MITRE — règle/signature native → technique' }));
  const sigInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: scenario' });
  const sigLabel = detField('Champ signature natif', sigInput,
    'Le champ de l\'événement source qui porte la règle/signature native (ex : scenario chez CrowdSec). Les lignes ci-dessous traduisent chaque valeur de ce champ en technique MITRE.');
  mapWrap.appendChild(sigLabel);
  const rowsHost = detEl('div', 'det-rows');
  mapWrap.appendChild(rowsHost);
  const addBtn = detEl('button', 'k-theme det-addrow', { type: 'button', text: '+ ligne' });
  mapWrap.appendChild(addBtn);
  // options mapping fines (records / ts) — kinds http/fichier.
  const recInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: hits.hits' });
  const recLabel = detField('Chemin du tableau (records, optionnel)', recInput,
    'Où trouver le tableau d\'événements dans la réponse JSON (ex : hits.hits pour Elastic). Vide = la racine est déjà un tableau.');
  mapWrap.appendChild(recLabel);
  const tsInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: created_at' });
  const tsLabel = detField('Champ horodatage (ts, optionnel)', tsInput,
    'Champ portant l\'heure de l\'alerte — sert à calculer le MTTD (délai tir → détection). Vide = MTTD non mesuré pour cette source.');
  mapWrap.appendChild(tsLabel);
  const advTa = detEl('textarea', null, { rows: 3, spellcheck: false, placeholder: '{"mitre":"_source.threat.technique.id","ts":"@timestamp"}' });
  const advLabel = detField('Mapping avancé (JSON — écrase l’éditeur ci-dessus)', advTa,
    'Pour les cas non couverts par les lignes : un objet JSON de mapping (chemins mitre/ts/records…). S\'il est renseigné, il remplace l\'éditeur de lignes ci-dessus.');
  mapWrap.appendChild(advLabel);
  host.appendChild(mapWrap);

  const hint = detEl('div', 'det-hint muted');
  host.appendChild(hint);

  function addRow(native, technique) {
    const row = detEl('div', 'det-row');
    const a = detEl('input', 'det-row-native', { type: 'text', spellcheck: false, autocomplete: 'off', value: native || '' });
    const b = detEl('input', 'det-row-tech', { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'Txxxx', value: technique || '' });
    const rm = detEl('button', 'k-theme danger det-row-rm', { type: 'button', text: '×', title: 'Retirer la ligne' });
    rm.addEventListener('click', () => row.remove());
    row.appendChild(a); row.appendChild(b); row.appendChild(rm);
    rowsHost.appendChild(row);
  }
  addBtn.addEventListener('click', () => addRow('', ''));
  function setRows(rows) { rowsHost.replaceChildren(); (rows || []).forEach(r => addRow(r.native, r.technique)); }
  function collectRows() {
    return [...rowsHost.querySelectorAll('.det-row')].map(r => ({
      native: (r.querySelector('.det-row-native').value || '').trim(),
      technique: (r.querySelector('.det-row-tech').value || '').trim(),
    })).filter(r => r.native && r.technique);
  }

  const HINTS = {
    none: 'Aucune source (autonome / standalone) : Forge fonctionne SANS dépendre d’un SOC. La boucle purple reste en attente (source_reachable:false, aucune métrique inventée). Une source est OPTIONNELLE et ajoutable plus tard dans Administration.',
    plume: 'Préréglage Plume : GET {endpoint}/api/coverage/detections?since=N, Basic auth, mapping identité (aucun mapping requis).',
    generic_http: 'Source JSON : si elle porte déjà un champ `mitre`, aucun mapping ; sinon utilisez le mapping table (signature → technique).',
    crowdsec: 'CrowdSec n’est PAS taggé MITRE : mapping table scénario → technique REQUIS (endpoint LAPI + clé X-Api-Key).',
    elastic: 'Elastic _search : query = corps JSON (dict). Mapping via chemin `mitre` (ex _source.…) ou table + champ.',
    opensearch: 'OpenSearch _search : query = corps JSON (dict). Même dialecte qu’Elastic (hits.hits).',
    fortigate_syslog: 'FortiGate syslog : endpoint = chemin du fichier ; règles regex → technique REQUISES (pas de tag MITRE natif).',
    pfsense: 'pfSense filterlog : endpoint = chemin du fichier ; règles regex → technique REQUISES.',
    opnsense: 'OPNsense filterlog : endpoint = chemin du fichier ; règles regex → technique REQUISES.',
    file_jsonl: 'Fichier JSONL d’événements natifs : endpoint = chemin ; mapping table/champ (ou mitre direct).',
    exec: 'Commande (argv séparés par des espaces) imprimant du JSON sur stdout ; mapping table/champ. Admin de confiance uniquement.',
  };

  function refreshVisibility() {
    const kind = kindSel.value;
    st.kind = kind;
    const syslog = DET_SYSLOG_KINDS.has(kind);
    const isExec = kind === 'exec';
    const isFile = kind === 'file_jsonl';
    // libellé/visibilité de l'entrée connexion.
    if (isExec) { epLabel.querySelector('span').textContent = 'Commande (argv séparés par des espaces)'; epInput.placeholder = 'ex: /opt/soc/pull.sh --json'; }
    else if (syslog || isFile) { epLabel.querySelector('span').textContent = 'Chemin du fichier'; epInput.placeholder = 'ex: /var/log/filterlog'; }
    else { epLabel.querySelector('span').textContent = 'Endpoint (URL)'; epInput.placeholder = 'ex: http://soc.local:8080/api/coverage/detections'; }
    epLabel.hidden = (kind === 'none');
    authWrap.hidden = !DET_AUTH_KINDS.has(kind);
    hdrLabel.hidden = authSel.value !== 'api_key_header';
    qLabel.hidden = !DET_QUERY_KINDS.has(kind);
    qLabel.querySelector('span').textContent = DET_JSON_QUERY_KINDS.has(kind) ? 'Query (corps JSON)' : 'Query (chaîne, {since} substitué)';
    // mapping : masqué pour none et plume (identité) ; sinon visible. `field`/records/ts masqués en syslog.
    const showMap = kind !== 'none' && kind !== 'plume';
    mapWrap.hidden = !showMap;
    sigLabel.hidden = syslog || !DET_TABLE_KINDS.has(kind);
    recLabel.hidden = syslog || !showMap;
    tsLabel.hidden = syslog || !showMap;
    mapWrap.querySelector('.det-sub').textContent = syslog
      ? 'Mapping MITRE — regex (ligne syslog) → technique'
      : 'Mapping MITRE — signature native → technique';
    hint.textContent = HINTS[kind] || '';
  }
  kindSel.addEventListener('change', refreshVisibility);
  authSel.addEventListener('change', () => { hdrLabel.hidden = authSel.value !== 'api_key_header'; });

  function setConfig(cfg, secretSet) {
    cfg = (cfg && typeof cfg === 'object') ? cfg : {};
    kindSel.value = DETECTION_KINDS.some(k => k.value === cfg.kind) ? cfg.kind : 'none';
    // connexion
    if (cfg.kind === 'exec') epInput.value = Array.isArray(cfg.cmd) ? cfg.cmd.join(' ') : (Array.isArray(cfg.argv) ? cfg.argv.join(' ') : (cfg.cmd || ''));
    else epInput.value = cfg.endpoint || cfg.path || '';
    // auth
    const auth = (cfg.auth && typeof cfg.auth === 'object') ? cfg.auth : {};
    authSel.value = ['basic', 'bearer', 'api_key_header'].includes(auth.type || cfg.auth_type) ? (auth.type || cfg.auth_type) : '';
    hdrInput.value = auth.header || '';
    secInput.value = '';
    st.secretSet = !!secretSet; st.secretDirty = false;
    secInput.placeholder = secretSet ? '•••••••• (défini — laisser vide pour conserver)' : 'secret / token';
    // query
    const q = cfg.query;
    qInput.value = (typeof q === 'string') ? q : (q && typeof q === 'object' ? JSON.stringify(q) : '');
    // mapping
    const m = (cfg.mapping && typeof cfg.mapping === 'object') ? cfg.mapping : {};
    sigInput.value = m.field || '';
    recInput.value = m.records || '';
    tsInput.value = m.ts || '';
    const unrepresentable = Object.keys(m).some(k => !DET_MAP_SIMPLE_KEYS.has(k));
    if (unrepresentable) { advTa.value = JSON.stringify(m, null, 2); setRows([]); }
    else {
      advTa.value = '';
      if (Array.isArray(m.rules)) setRows(m.rules.filter(r => r && r.match).map(r => ({ native: r.match, technique: r.mitre || '' })));
      else if (m.table && typeof m.table === 'object') setRows(Object.entries(m.table).map(([k, v]) => ({ native: k, technique: String(v) })));
      else setRows([]);
    }
    refreshVisibility();
  }

  // Renvoie { config, keepSecret, error }. error non nul -> le hôte (save/test) affiche un toast et n'envoie rien.
  function getConfig() {
    const kind = kindSel.value;
    if (kind === 'none') return { config: { kind: 'none' }, keepSecret: false, error: null };
    const config = { kind };
    const ep = (epInput.value || '').trim();
    if (kind === 'exec') { if (ep) config.cmd = ep.split(/\s+/).filter(Boolean); }
    else if (ep) config.endpoint = ep;
    let keepSecret = false;
    if (DET_AUTH_KINDS.has(kind)) {
      const at = authSel.value;
      if (at) {
        const auth = { type: at };
        if (at === 'api_key_header' && (hdrInput.value || '').trim()) auth.header = hdrInput.value.trim();
        if (st.secretDirty && secInput.value) auth.secret = secInput.value;
        else if (st.secretSet && !st.secretDirty) keepSecret = true; // secret write-only conservé
        config.auth = auth;
      }
    }
    if (DET_QUERY_KINDS.has(kind)) {
      const qv = (qInput.value || '').trim();
      if (qv) {
        if (DET_JSON_QUERY_KINDS.has(kind)) {
          try { config.query = JSON.parse(qv); } catch (e) { return { config: null, keepSecret: false, error: 'Query (corps JSON) invalide : ' + e.message }; }
        } else config.query = qv;
      }
    }
    // mapping : JSON avancé prioritaire, sinon lignes.
    const adv = (advTa.value || '').trim();
    if (adv) {
      let parsed;
      try { parsed = JSON.parse(adv); } catch (e) { return { config: null, keepSecret: false, error: 'Mapping avancé (JSON) invalide : ' + e.message }; }
      if (parsed && typeof parsed === 'object') config.mapping = parsed;
    } else if (kind !== 'plume') {
      const mapping = {};
      const rows = collectRows();
      if (DET_SYSLOG_KINDS.has(kind)) { if (rows.length) mapping.rules = rows.map(r => ({ match: r.native, mitre: r.technique })); }
      else if (rows.length) {
        mapping.table = {}; rows.forEach(r => { mapping.table[r.native] = r.technique; });
        const fld = (sigInput.value || '').trim(); if (fld) mapping.field = fld;
      }
      const rec = (recInput.value || '').trim(); if (rec && !DET_SYSLOG_KINDS.has(kind)) mapping.records = rec;
      const ts = (tsInput.value || '').trim(); if (ts && !DET_SYSLOG_KINDS.has(kind)) mapping.ts = ts;
      if (Object.keys(mapping).length) config.mapping = mapping;
    }
    return { config, keepSecret, error: null };
  }
  function clearSecret() { secInput.value = ''; st.secretDirty = false; }

  refreshVisibility();
  return { el: host, setConfig, getConfig, clearSecret, kind: () => kindSel.value };
}

// --- Panneau admin « source de détection » : GET config (secret rédigé) -> monte le composant + actions
//     (Tester / Enregistrer). POST /api/detection/source (admin, ledgerisé) ; POST /api/detection/test.
let ADMIN_DET_FORM = null;
async function loadAdminDetection() {
  const host = $('#admin-det-form'); if (!host) return;
  const kindBadge = $('#admin-det-kind');
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if (kindBadge) kindBadge.textContent = '—'; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/detection/source'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const src = (data && data.source) || { kind: 'none' };
  const secretSet = !!(data && data.secret_set);
  host.replaceChildren();
  const formHost = detEl('div');
  host.appendChild(formHost);
  ADMIN_DET_FORM = detectionSourceForm(formHost);
  ADMIN_DET_FORM.setConfig(src, secretSet);
  if (kindBadge) kindBadge.textContent = src.kind || 'none';
  // barre d'actions + zone de résultat de test.
  const act = detEl('div', 'det-actions');
  const testBtn = detEl('button', 'k-theme', { type: 'button', text: 'Tester la connexion' });
  const saveBtn = detEl('button', 'login-btn det-save', { type: 'button', text: 'Enregistrer' });
  act.appendChild(testBtn); act.appendChild(saveBtn);
  host.appendChild(act);
  const resBox = detEl('div', 'det-testres muted');
  host.appendChild(resBox);

  testBtn.addEventListener('click', async () => {
    const { config, keepSecret, error } = ADMIN_DET_FORM.getConfig();
    if (error) { toast(error, 'bad'); return; }
    resBox.className = 'det-testres muted'; resBox.textContent = 'test en cours…';
    testBtn.disabled = true;
    try {
      const r = await adminApi('/detection/test', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ detection_source: config, keep_secret: keepSecret }),
      });
      const reachable = !!(r && r.reachable);
      const samples = (r && Array.isArray(r.sample_mitres)) ? r.sample_mitres : [];
      resBox.className = 'det-testres ' + (reachable ? 'ok' : 'bad');
      resBox.textContent = reachable
        ? `joignable — ${r.count || 0} détection(s)${samples.length ? ' · ' + samples.join(', ') : ''}`
        : `injoignable — ${(r && r.error) ? r.error : 'source_reachable:false'}`;
    } catch (e) { resBox.className = 'det-testres bad'; resBox.textContent = 'test refusé : ' + e.message; }
    finally { testBtn.disabled = false; }
  });
  saveBtn.addEventListener('click', async () => {
    const { config, keepSecret, error } = ADMIN_DET_FORM.getConfig();
    if (error) { toast(error, 'bad'); return; }
    saveBtn.disabled = true;
    try {
      await adminApi('/detection/source', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ detection_source: config, keep_secret: keepSecret }),
      });
      toast('Source de détection enregistrée.', 'ok');
      loadAdminDetection(); // recharge (secret rédigé, secret_set à jour)
    } catch (e) { toast('Enregistrement refusé : ' + e.message, 'bad'); }
    finally { saveBtn.disabled = false; }
  });
}
if ($('#admin-det-reload')) $('#admin-det-reload').addEventListener('click', loadAdminDetection);

// =====================================================================================
//  SAUVEGARDE & RESTAURATION CHIFFRÉES (panneau #admin, réservé role=admin)
//  L'archive est TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305) et embarque base + ledger + clé
//  .ed25519. La passphrase est OBLIGATOIRE et n'est JAMAIS persistée côté client (saisie -> requête ->
//  oubliée ; les champs sont vidés à la fermeture de la modale). GET /api/backup/policy ne renvoie
//  AUCUN secret (rédigé). Modales natives (helper modal()) uniquement. Détails : docs/BACKUP.md.
// =====================================================================================
const OFFSITE_KINDS = [
  { value: 'none', label: 'Aucun — pas d’expédition' },
  { value: 'local_dir', label: 'Dossier local (copie)' },
  { value: 'exec', label: 'Commande (argv fixe, sans shell)' },
];

// --- Créer une sauvegarde : demande la passphrase (jamais persistée) puis télécharge l'archive chiffrée.
async function backupCreate() {
  const vals = await modal({
    title: 'Créer une sauvegarde chiffrée',
    message: 'L’archive embarque la base, le ledger et la clé de signature .ed25519 — elle est TOUJOURS chiffrée. Choisissez une passphrase FORTE : sans elle, l’archive est irrécupérable. Elle n’est ni stockée, ni loggée, ni ledgerisée.',
    okText: 'Créer & télécharger',
    fields: [
      { name: 'passphrase', label: 'Passphrase (obligatoire)', type: 'password', required: true, hint: 'Dérive la clé (argon2id) qui chiffre l\'archive. Elle n\'est ni stockée, ni loggée, ni ledgerisée — conservez-la hors-ligne : sans elle, l\'archive est définitivement irrécupérable.' },
      { name: 'confirm', label: 'Confirmer la passphrase', type: 'password', required: true, hint: 'Ressaisie pour éviter une faute de frappe sur une passphrase qu\'on ne peut pas récupérer.' },
    ],
    validate: v => (v.passphrase !== v.confirm ? 'Les deux passphrases diffèrent.' : (String(v.passphrase).length < 1 ? 'Passphrase requise.' : null)),
  });
  if (!vals) return;
  try {
    const r = await fetch('/api/backup', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/octet-stream' },
      body: JSON.stringify({ passphrase: vals.passphrase }),
    });
    if (!r.ok) {
      let why = 'HTTP ' + r.status;
      try { const j = await r.json(); why = (j && (j.why || j.error)) || why; } catch (e) {}
      throw new Error(why);
    }
    const blob = await r.blob();
    const cd = r.headers.get('content-disposition') || '';
    const m = /filename="?([^"]+)"?/.exec(cd);
    const name = (m && m[1]) || 'forge-backup.forge';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast('Sauvegarde chiffrée téléchargée (' + name + ').', 'ok');
  } catch (e) { toast('Sauvegarde refusée : ' + e.message, 'bad'); }
}

// --- Restaurer : modale native (fichier + passphrase + apply/confirm). Par défaut VALIDE sans écrire.
function backupRestore() {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal wide danger';
  const form = document.createElement('form');
  form.innerHTML =
    '<h3>Restaurer une archive chiffrée</h3>' +
    '<p class="modal-msg">Par défaut, l’archive est <b>validée</b> (déchiffrement, sha256, chaîne ledger) sans rien écrire. Le <b>swap en place</b> (appliquer) remplace base + ledger + clé et <b>exige un redémarrage</b> de la console.</p>' +
    '<label class="modal-f"><span>Archive chiffrée (.forge)</span><input type="file" data-n="file" required><small class="modal-fhint">Le fichier produit par « Créer une sauvegarde » (base + ledger + clé de signature, chiffré).</small></label>' +
    '<label class="modal-f"><span>Passphrase</span><input type="password" data-n="passphrase" required><small class="modal-fhint">La passphrase utilisée à la création. Effacée du navigateur dès l\'envoi ; jamais conservée.</small></label>' +
    '<label class="modal-f det-inline"><input type="checkbox" data-n="apply"> <span>Appliquer le swap en place (destructif — redémarrage requis)</span></label>' +
    '<small class="modal-fhint">Décoché = validation seule (déchiffre + vérifie la chaîne ledger, n\'écrit rien). Coché = remplace la base/ledger/clé en place — irréversible, nécessite un redémarrage.</small>' +
    '<label class="modal-f det-inline"><input type="checkbox" data-n="confirm"> <span>Je confirme explicitement l’écrasement de l’installation existante</span></label>' +
    '<div class="modal-err" hidden></div>' +
    '<div class="modal-act"><button type="button" class="m-cancel">Annuler</button><button type="submit" class="m-ok danger">Valider / Restaurer</button></div>';
  box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  form.querySelector('.m-cancel').onclick = close;
  ov.onclick = e => { if (e.target === ov) close(); };
  const errBox = form.querySelector('.modal-err');
  const showE = m => { errBox.textContent = m; errBox.hidden = false; };
  form.onsubmit = async e => {
    e.preventDefault();
    const fileEl = form.querySelector('[data-n="file"]');
    const passEl = form.querySelector('[data-n="passphrase"]');
    const apply = form.querySelector('[data-n="apply"]').checked;
    const confirm = form.querySelector('[data-n="confirm"]').checked;
    const f = fileEl.files && fileEl.files[0];
    if (!f) { showE('Sélectionnez une archive.'); return; }
    if (!passEl.value) { showE('Passphrase requise.'); return; }
    if (apply && !confirm) { showE('Le swap en place exige la case de confirmation explicite.'); return; }
    const okBtn = form.querySelector('.m-ok'); okBtn.disabled = true;
    try {
      const archive_b64 = await new Promise((res, rej) => {
        const rd = new FileReader();
        rd.onerror = () => rej(new Error('lecture du fichier échouée'));
        rd.onload = () => res(String(rd.result).split(',')[1] || '');
        rd.readAsDataURL(f);
      });
      const j = await adminApi('/restore', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ archive_b64, passphrase: passEl.value, apply, confirm }),
      });
      // vide la passphrase du DOM aussitôt (ne jamais la garder côté client).
      passEl.value = '';
      if (j && j.applied) {
        close();
        infoModal('Restauration appliquée — redémarrage requis', body => {
          const p = document.createElement('p'); p.textContent = j.maintenance || 'Redémarrez la console pour charger l’état restauré.';
          body.appendChild(p);
        });
      } else {
        const v = (j && j.validated) || {};
        close();
        infoModal('Archive validée (aucune écriture)', body => {
          const add = (k, val) => { const d = document.createElement('div'); d.textContent = k + ' : ' + val; body.appendChild(d); };
          add('déchiffrable', 'oui'); add('chaîne ledger', v.ledger_ok ? 'intègre' : 'n/a');
          add('entrées ledger', v.ledger_entries != null ? v.ledger_entries : '—');
          add('contient base / ledger / clé', (v.has_db ? 'db ' : '') + (v.has_ledger ? 'ledger ' : '') + (v.has_key ? 'clé' : ''));
          const note = document.createElement('p'); note.className = 'muted';
          note.textContent = j.note || 'Pour appliquer : rouvrez la restauration, cochez « appliquer » + confirmation.';
          body.appendChild(note);
        });
      }
      toast(j && j.applied ? 'Restauration appliquée — redémarrez la console.' : 'Archive validée.', 'ok');
    } catch (e2) { showE('Refusé : ' + e2.message); okBtn.disabled = false; }
  };
  const first = form.querySelector('input'); if (first) setTimeout(() => first.focus(), 30);
}

// --- Panneau politique de sauvegarde programmée + offsite (GET rédige les secrets ; POST valide).
async function loadAdminBackup() {
  const host = $('#admin-bk-policy'); if (!host) return;
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/backup/policy'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const p = (data && data.policy) || { enabled: false, offsite: { kind: 'none' } };
  const off = p.offsite || { kind: 'none' };
  host.replaceChildren();

  const kindLabel = (OFFSITE_KINDS.find(k => k.value === (off.kind || 'none')) || {}).label || (off.kind || 'none');
  const summary = detEl('div', 'muted');
  summary.style.margin = '0 0 10px';
  summary.textContent = p.enabled
    ? `Programmée : toutes les ${p.interval_secs || '?'} s · rétention ${p.retention != null ? p.retention : '∞'} · passphrase via $${p.passphrase_env || '(non défini)'} · offsite : ${kindLabel}` + (data && data.last_run ? ` · dernière exécution @${data.last_run}` : '')
    : 'Aucune sauvegarde programmée (défaut). Configurez un intervalle + une variable d’ENV pour la passphrase pour activer le runner.';
  host.appendChild(summary);

  const edit = detEl('button', 'k-theme', { type: 'button', text: 'Éditer la politique…' });
  host.appendChild(edit);
  edit.addEventListener('click', () => editBackupPolicy(p));
}

// Éditeur de politique (modale native). N'affiche JAMAIS de secret ; `passphrase_env` = NOM d'ENV.
async function editBackupPolicy(current) {
  const off = current.offsite || { kind: 'none' };
  const vals = await modal({
    title: 'Politique de sauvegarde programmée',
    wide: true,
    okText: 'Enregistrer',
    message: 'La passphrase du backup programmé provient d’une VARIABLE D’ENV (nommée ci-dessous) — jamais stockée en clair. L’offsite « exec » lance un argv FIXE (aucun shell). Rien n’est programmé si « activer » est décoché.',
    fields: [
      { name: 'enabled', label: 'Activer la sauvegarde programmée', type: 'checkbox', value: !!current.enabled, hint: 'Décoché = aucune sauvegarde automatique (défaut). Coché = le runner crée une archive chiffrée à chaque intervalle.' },
      { name: 'interval_secs', label: 'Intervalle (secondes)', type: 'text', value: current.interval_secs != null ? String(current.interval_secs) : '', hint: 'Fréquence des sauvegardes automatiques, en secondes (ex : 86400 = quotidien). Requis et > 0 quand activé.' },
      { name: 'retention', label: 'Rétention (nb d’archives locales, 0 = illimité)', type: 'text', value: current.retention != null ? String(current.retention) : '', hint: 'Combien d\'archives locales conserver ; les plus anciennes au-delà sont purgées. 0 = tout garder.' },
      { name: 'passphrase_env', label: 'Variable d’ENV portant la passphrase (nom)', type: 'text', value: current.passphrase_env || '', hint: 'NOM d\'une variable d\'environnement (ex : FORGE_BACKUP_PASSPHRASE), pas la passphrase elle-même. Le runner la lit à l\'exécution — jamais stockée en clair.' },
      { name: 'staging_dir', label: 'Dossier de staging (optionnel)', type: 'text', value: current.staging_dir || '', hint: 'Où déposer les archives locales avant expédition offsite. Vide = dossier par défaut de la console.' },
      { name: 'offsite_kind', label: 'Destination offsite', type: 'select', value: off.kind || 'none', options: OFFSITE_KINDS, hint: 'Copie hors-machine de l\'archive chiffrée : Aucune, Dossier local (montage/partage) ou Commande (argv fixe, sans shell — ex : rclone/scp).' },
      { name: 'offsite_dir', label: 'Offsite local_dir : dossier', type: 'text', value: off.dir || '', hint: 'Uniquement pour « Dossier local » : chemin de destination où copier l\'archive.' },
      { name: 'offsite_program', label: 'Offsite exec : programme (chemin absolu)', type: 'text', value: off.program || '', hint: 'Uniquement pour « Commande » : chemin absolu de l\'exécutable (sans shell). L\'archive chiffrée lui est passée.' },
      { name: 'offsite_args', label: 'Offsite exec : arguments (un par ligne ; {archive} = chemin)', type: 'textarea', value: Array.isArray(off.args) ? off.args.join('\n') : '', hint: 'Arguments fixes de la commande, un par ligne. Le jeton {archive} est remplacé par le chemin de l\'archive à expédier.' },
    ],
    validate: v => {
      if (v.enabled) {
        if (!(parseInt(v.interval_secs, 10) > 0)) return 'Intervalle > 0 requis quand activé.';
        if (!String(v.passphrase_env).trim()) return 'Variable d’ENV de passphrase requise quand activé.';
      }
      if (v.offsite_kind === 'local_dir' && !String(v.offsite_dir).trim()) return 'Offsite local_dir : dossier requis.';
      if (v.offsite_kind === 'exec') {
        if (!String(v.offsite_program).trim()) return 'Offsite exec : programme requis.';
        if (!String(v.offsite_program).trim().startsWith('/')) return 'Offsite exec : le programme doit être un chemin absolu.';
      }
      return null;
    },
  });
  if (!vals) return;
  const policy = { enabled: !!vals.enabled };
  if (String(vals.interval_secs).trim()) policy.interval_secs = parseInt(vals.interval_secs, 10);
  if (String(vals.retention).trim()) policy.retention = parseInt(vals.retention, 10);
  if (String(vals.passphrase_env).trim()) policy.passphrase_env = String(vals.passphrase_env).trim();
  if (String(vals.staging_dir).trim()) policy.staging_dir = String(vals.staging_dir).trim();
  const kind = vals.offsite_kind || 'none';
  const offsite = { kind };
  if (kind === 'local_dir') offsite.dir = String(vals.offsite_dir).trim();
  if (kind === 'exec') {
    offsite.program = String(vals.offsite_program).trim();
    offsite.args = String(vals.offsite_args || '').split('\n').map(s => s.trim()).filter(Boolean);
  }
  policy.offsite = offsite;
  try {
    await adminApi('/backup/policy', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ policy }),
    });
    toast('Politique de sauvegarde enregistrée.', 'ok');
    loadAdminBackup();
  } catch (e) { toast('Enregistrement refusé : ' + e.message, 'bad'); }
}
if ($('#bk-create')) $('#bk-create').addEventListener('click', backupCreate);
if ($('#bk-restore')) $('#bk-restore').addEventListener('click', backupRestore);
if ($('#admin-bk-reload')) $('#admin-bk-reload').addEventListener('click', loadAdminBackup);

// Vue #admin : charge comptes, connecteurs, source de détection ET sauvegarde (gouvernées, meme role admin).
function loadAdmin() { loadAdminUsers(); loadAdminConnectors(); loadAdminDetection(); loadAdminBackup(); }

// =====================================================================================
//  Navigation (sidebar repliable + hash-routing) + chargement par vue
// =====================================================================================
const VIEWS = {
  'ov-summary': 'overview', 'ov-sev': 'overview', 'ov-modules': 'overview',
  engagements: 'engagements',
  'lc-form': 'launch', 'lc-plan': 'launch', 'lc-live': 'launch', 'lc-runs': 'launch',
  import: 'import',
  modules: 'modules', techniques: 'techniques', workflows: 'workflows', findings: 'findings', 'findings-library': 'findings-library', reports: 'reports', explore: 'explore',
  coverage: 'coverage', 'purple-coverage': 'purple-coverage', campaigns: 'campaigns', roe: 'roe', ledger: 'ledger', dashboards: 'dashboards',
  admin: 'admin', 'admin-connectors': 'admin', 'admin-detection': 'admin',
  tenants: 'tenants',
  identity: 'identity',
};
const LOADERS = {
  overview: loadOverview, engagements: loadEngagements, launch: loadLaunch, import: loadImport, modules: loadModules, techniques: loadTechniques, workflows: loadWorkflows, findings: loadFindings, 'findings-library': loadFindingsLibrary, reports: loadReports,
  coverage: loadCoverage, 'purple-coverage': loadPurpleCoverage, campaigns: loadCampaigns, roe: loadRoe, ledger: loadLedger, dashboards: loadDashboards,
  admin: loadAdmin,
  tenants: loadTenants,
  identity: loadIdentity,
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
function route() { let v = location.hash.slice(1) || 'overview'; if (!VIEWS_HAS(v)) v = 'overview'; if (v === 'admin' && !isAdmin()) v = 'overview'; if (v === 'tenants' && !tenancyAdmin()) v = 'overview'; if (v === 'identity' && !identityAdmin()) v = 'overview'; showView(v); }
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
  // ENTERPRISE identity (SSO / SCIM / advanced RBAC) — flags come from whoami.enterprise (all false in
  // the community default => nothing renders). Drives the "Identité / SSO" nav link + route guard.
  ENTERPRISE = (w && w.enterprise && typeof w.enterprise === 'object') ? w.enterprise : {};
  applyIdentityUi();
}
// ENTERPRISE identity flags (from whoami.enterprise). Community default = {} => every helper false.
let ENTERPRISE = {};
function identityOn() { return !!(ENTERPRISE && (ENTERPRISE.sso || ENTERPRISE.scim)); }
function identityAdmin() { return !!(identityOn() && isAdmin()); }
// Dé-masque le lien nav #identity (admin + flag engagé) ; ré-oriente hors #identity si non autorisé.
// Défense en profondeur : le serveur reste l'autorité (routes flag+admin -> 404/403).
function applyIdentityUi() {
  const link = $('#nav-identity');
  if (link) link.hidden = !identityAdmin();
  if (!identityAdmin() && location.hash.slice(1) === 'identity') location.hash = 'overview';
}
// SSO (ENTERPRISE) : disponibilité d'une connexion OIDC interactive, sondée pré-auth via GET
// /api/setup/state (sso.enabled). false en community (flag OFF / non configuré) => aucun bouton SSO.
let SSO_LOGIN = false;
function showLogin() {
  document.body.classList.add('gated');
  const sv = $('#setup-view'); if (sv) sv.hidden = true;
  const v = $('#login-view'); if (v) v.hidden = false;
  // Bouton "Se connecter avec le SSO" — affiché seulement si le serveur offre le SSO (flag + configuré).
  const sso = $('#login-sso'); if (sso) sso.hidden = !SSO_LOGIN;
  const u = $('#login-user'); if (u) setTimeout(() => { try { u.focus(); } catch (e) {} }, 40);
}
// Redirige vers le flux OIDC Authorization-Code + PKCE (le serveur pose ensuite forge_session au callback).
if ($('#login-sso-btn')) $('#login-sso-btn').addEventListener('click', () => { window.location.href = '/api/sso/login'; });
function showApp() {
  document.body.classList.remove('gated');
  const v = $('#login-view'); if (v) v.hidden = true;
  const sv = $('#setup-view'); if (sv) sv.hidden = true;
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

// =====================================================================================
//  WIZARD 1er DÉPLOIEMENT (self-deploy) — stepper de provisioning dans le skin Ember.
//  bootApp() sonde /api/setup/state ; needs_setup:true -> showSetup(). Le POST /api/setup crée le 1er
//  admin, pose le cookie de session (on atterrit connecté), puis on démarre le shell. ZÉRO défaut :
//  seuls identifiant + mot de passe sont requis ; détection/politique opérateur sont optionnels.
// =====================================================================================
let SETUP_STEP = 1;
const SETUP_MAX = 4;
let SETUP_DET_FORM = null; // composant source de détection partagé (étape 3 du wizard)
function showSetup(state) {
  document.body.classList.add('gated');
  const lv = $('#login-view'); if (lv) lv.hidden = true;
  const sv = $('#setup-view'); if (sv) sv.hidden = false;
  // étape 3 : monte le MÊME composant source de détection que le panneau admin (parité du jeu de champs).
  // Config vierge (aucun défaut, aucun secret posé) — tout est optionnel côté provisioning.
  const detHost = $('#su-det-form');
  if (detHost && typeof detectionSourceForm === 'function') {
    SETUP_DET_FORM = detectionSourceForm(detHost);
    SETUP_DET_FORM.setConfig({ kind: 'none' }, false);
  }
  // capacité SQLCipher : la bascule de chiffrement au repos n'apparaît QUE si le build l'expose
  // (capabilities.sqlcipher). Faux dans le build par défaut -> bascule masquée, note « indisponible ».
  const sqlcipher = !!(state && state.capabilities && state.capabilities.sqlcipher);
  const encWrap = $('#su-enc-wrap'); if (encWrap) encWrap.hidden = !sqlcipher;
  const encUnavail = $('#su-enc-unavail'); if (encUnavail) encUnavail.hidden = sqlcipher;
  setupGoto(1);
  const f = $('#su-login'); if (f) setTimeout(() => { try { f.focus(); } catch (e) {} }, 40);
}
function setupErr(msg) { const e = $('#setup-err'); if (e) { e.textContent = msg || ''; e.hidden = !msg; } }
function setupGoto(n) {
  SETUP_STEP = Math.max(1, Math.min(SETUP_MAX, n));
  setupErr('');
  document.querySelectorAll('#setup-view .setup-panel').forEach(p => p.classList.toggle('is-active', Number(p.dataset.panel) === SETUP_STEP));
  document.querySelectorAll('#setup-view .setup-step').forEach(s => {
    const sn = Number(s.dataset.step);
    s.classList.toggle('is-active', sn === SETUP_STEP);
    s.classList.toggle('is-done', sn < SETUP_STEP);
  });
  const back = $('#su-back'); if (back) back.hidden = SETUP_STEP === 1;
  const next = $('#su-next'); if (next) next.hidden = SETUP_STEP === SETUP_MAX;
  const fin = $('#su-finish'); if (fin) fin.hidden = SETUP_STEP !== SETUP_MAX;
}
// validation de l'étape 1 (SEULE étape avec des champs requis). Miroir léger de validate_login côté
// serveur (le serveur reste l'autorité) + confirmation du mot de passe.
function setupValidateStep1() {
  const login = (($('#su-login') && $('#su-login').value) || '').trim();
  const pass = ($('#su-pass') && $('#su-pass').value) || '';
  const pass2 = ($('#su-pass2') && $('#su-pass2').value) || '';
  if (!login) return 'Identifiant administrateur requis.';
  if (login.startsWith('-') || !/^[A-Za-z0-9._-]{1,64}$/.test(login)) return 'Identifiant : [A-Za-z0-9._-], 1 à 64 caractères, sans tiret initial.';
  if (!pass) return 'Mot de passe requis.';
  if (pass !== pass2) return 'Les mots de passe ne correspondent pas.';
  return null;
}
// construit le corps de POST /api/setup. Les blocs optionnels ne sont inclus que s'ils sont renseignés
// (aucune valeur par défaut envoyée quand l'utilisateur ne configure rien).
function setupBuildPayload() {
  const login = (($('#su-login') && $('#su-login').value) || '').trim();
  const pass = ($('#su-pass') && $('#su-pass').value) || '';
  const payload = { admin_login: login, admin_password: pass };
  // détection (étape 3) : lue depuis le composant partagé, verbatim, UNIQUEMENT si un kind est choisi
  // (kind != none). Même schéma canonique (auth:{type,secret}) que le panneau admin.
  if (SETUP_DET_FORM) {
    const { config } = SETUP_DET_FORM.getConfig();
    if (config && config.kind && config.kind !== 'none') payload.detection_source = config;
  }
  // politique opérateur (étape 4) : booléens explicites (require_reason par défaut ON = comportement
  // actuel) + allowlist CIDR source seulement si non vide (sinon aucune restriction — défaut = none).
  const op = {
    require_reason: !!($('#su-op-reason') && $('#su-op-reason').checked),
    high_impact_approval: !!($('#su-op-approval') && $('#su-op-approval').checked),
  };
  const cidrs = (($('#su-op-cidrs') && $('#su-op-cidrs').value) || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (cidrs.length) op.source_cidrs = cidrs;
  payload.operator_policy = op;
  return payload;
}
async function setupSubmit() {
  const e1 = setupValidateStep1();
  if (e1) { setupGoto(1); setupErr(e1); return; }
  // sanity légère sur les CIDR (pas d'espace interne) — le serveur reste l'autorité (fail-closed).
  const badCidr = (($('#su-op-cidrs') && $('#su-op-cidrs').value) || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean).find(l => /\s/.test(l));
  if (badCidr) { setupGoto(4); setupErr('CIDR invalide (espace interne) : ' + badCidr); return; }
  // détection (étape 3) : mapping avancé / query JSON invalide -> stop (le serveur reste l'autorité).
  if (SETUP_DET_FORM) { const dc = SETUP_DET_FORM.getConfig(); if (dc.error) { setupGoto(3); setupErr(dc.error); return; } }
  const fin = $('#su-finish'); if (fin) fin.disabled = true;
  setupErr('');
  try {
    const r = await fetch('/api/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(setupBuildPayload()),
    });
    if (r.status === 409) {
      // provisionné entre-temps (course) -> basculer vers le portail de connexion.
      toast('Console déjà provisionnée.', 'info');
      const sv = $('#setup-view'); if (sv) sv.hidden = true;
      renderWhoami(null); showLogin();
      return;
    }
    if (!r.ok) {
      let why = 'HTTP ' + r.status;
      try { const j = await r.json(); if (j && typeof j.why === 'string') why = j.why; else if (j && typeof j.error === 'string') why = j.error; } catch (e) {}
      setupErr('Échec du provisioning : ' + why);
      return;
    }
    // succès : le serveur a posé le cookie de session (nouvel admin). Efface les secrets, démarre le shell.
    ['#su-pass', '#su-pass2'].forEach(id => { const el = $(id); if (el) el.value = ''; });
    if (SETUP_DET_FORM) SETUP_DET_FORM.clearSecret();
    const sv = $('#setup-view'); if (sv) sv.hidden = true;
    showApp();
    toast('Console provisionnée — bienvenue.', 'ok');
    await bootApp();
  } catch (err) {
    setupErr('Erreur réseau : ' + String((err && err.message) || err));
  } finally {
    if (fin) fin.disabled = false;
  }
}
if ($('#su-next')) $('#su-next').addEventListener('click', () => {
  if (SETUP_STEP === 1) { const e = setupValidateStep1(); if (e) { setupErr(e); return; } }
  setupGoto(SETUP_STEP + 1);
});
if ($('#su-back')) $('#su-back').addEventListener('click', () => setupGoto(SETUP_STEP - 1));
// Entrée dans un champ soumet le form : avant la dernière étape on AVANCE (pas de provisioning
// prématuré) ; à la dernière étape (bouton Provisionner) on soumet réellement.
if ($('#setup-form')) $('#setup-form').addEventListener('submit', e => {
  e.preventDefault();
  if (SETUP_STEP < SETUP_MAX) {
    if (SETUP_STEP === 1) { const err = setupValidateStep1(); if (err) { setupErr(err); return; } }
    setupGoto(SETUP_STEP + 1);
    return;
  }
  setupSubmit();
});

// boot gaté : sonde D'ABORD /api/setup/state (1er déploiement). needs_setup -> wizard de provisioning,
// on s'arrête là. Sinon on retombe sur le flux normal : sonde whoami, portail sur 401 (ou erreur
// réseau, fail-closed lisible), sinon charge le contexte transverse puis route la vue.
async function bootApp() {
  // 1er déploiement : une install fraîche (aucun admin activé ni hash d'amorçage) affiche le wizard.
  try {
    const sr = await fetch('/api/setup/state', { headers: { Accept: 'application/json' } });
    if (sr.ok) {
      const st = await sr.json().catch(() => null);
      // SSO (ENTERPRISE) : capter la disponibilité AVANT toute sortie anticipée (pour l'écran de login).
      SSO_LOGIN = !!(st && st.sso && st.sso.enabled);
      if (st && st.needs_setup) { showSetup(st); return; }
    }
  } catch (e) { /* sonde best-effort : en cas d'échec on poursuit sur le flux whoami habituel */ }
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
  // TENANCY (ENTERPRISE, flag-gated) : charger le contexte AVANT le sélecteur d'engagement pour que le
  // filtre tenant → engagement porte dès le 1er rendu. Community => {enabled:false} : no-op (rien ne
  // s'affiche, comportement byte-identique).
  await loadTenancyContext();
  // ENGAGEMENT ACTIF : charger la liste + le sélecteur AVANT de router (pour que withEngagement porte
  // l'id dès la 1re vue). Fail-soft : en cas d'échec le sélecteur reste vide et le serveur défaut #1.
  await loadEngagementSelector();
  loadCampaigns();
  loadStatuses();
  route();
}
loadVersion();
bootApp();
