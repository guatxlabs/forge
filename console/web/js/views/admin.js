import { adminApi, api, token, write } from '../core/api.js';
import { ROLE_CLASSES, WHOAMI, isAdmin } from '../core/auth.js';
import { $, esc, fmtTs } from '../core/dom.js';
import { loadModules } from './modules.js';
import { confirmModal, emptyState, guardList, infoModal, modal, toast } from '../core/ui.js';

export const ADMIN_ROLES = [
  { value: 'viewer', label: 'viewer — lecture seule' },
  { value: 'operator', label: 'operator — arme le C2' },
  { value: 'admin', label: 'admin — administration' },
];
export const LOGIN_RE = /^[A-Za-z0-9._-]{1,64}$/;
export function loginError(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return 'Login requis.';
  if (s.startsWith('-')) return 'Le login ne peut pas commencer par « - ».';
  if (!LOGIN_RE.test(s)) return 'Login invalide (1-64 caractères, [A-Za-z0-9._-] uniquement).';
  return null;
}
export async function loadAdminUsers() {
  const host = $('#admin-users'); if (!host) return;
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if ($('#admin-count')) $('#admin-count').textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/users'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const users = (data && data.users) || [];
  if ($('#admin-count')) $('#admin-count').textContent = users.length + ' compte' + (users.length > 1 ? 's' : '');
  if (guardList(host, users, 'aucun compte')) return;
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
export async function adminCreateUser() {
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
export async function adminEditRole(u) {
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
export async function adminResetPw(u) {
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
export async function adminToggleDisabled(u) {
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
export async function adminDeleteUser(u) {
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
export const DETECTION_KINDS = [
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
export const DET_HTTP_KINDS = new Set(['plume', 'generic_http', 'crowdsec', 'elastic', 'opensearch']);
export const DET_SYSLOG_KINDS = new Set(['fortigate_syslog', 'pfsense', 'opnsense']);
export const DET_TABLE_KINDS = new Set(['generic_http', 'crowdsec', 'elastic', 'opensearch', 'file_jsonl', 'exec']);
export const DET_AUTH_KINDS = new Set(['plume', 'generic_http', 'crowdsec', 'elastic', 'opensearch']);
export const DET_QUERY_KINDS = new Set(['generic_http', 'crowdsec', 'elastic', 'opensearch']);
export const DET_JSON_QUERY_KINDS = new Set(['elastic', 'opensearch']); // query = corps JSON (dict)
// clés de mapping représentables par l'éditeur de lignes (le reste -> éditeur JSON avancé).
export const DET_MAP_SIMPLE_KEYS = new Set(['table', 'field', 'rules', 'records', 'ts']);
// petit constructeur DOM sûr : détail = attrs (value/placeholder/type/...) posés via propriété (jamais innerHTML).
export function detEl(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (attrs) for (const k in attrs) { if (k === 'text') e.textContent = attrs[k]; else e[k] = attrs[k]; }
  return e;
}
export function detField(labelText, control, hint) {
  const l = detEl('label', 'login-f');
  l.appendChild(detEl('span', null, { text: labelText }));
  l.appendChild(control);
  // indice explicatif optionnel : reste dans le label -> se masque/affiche avec lui (refreshVisibility).
  if (hint) l.appendChild(detEl('small', 'det-fhint', { text: hint }));
  return l;
}
// Factory : monte le jeu de champs dans `host` et renvoie un contrôleur { setConfig, getConfig, clearSecret, el }.
export function detectionSourceForm(host) {
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
export let ADMIN_DET_FORM = null;
export async function loadAdminDetection() {
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
export const OFFSITE_KINDS = [
  { value: 'none', label: 'Aucun — pas d’expédition' },
  { value: 'local_dir', label: 'Dossier local (copie)' },
  { value: 'exec', label: 'Commande (argv fixe, sans shell)' },
];

// --- Créer une sauvegarde : demande la passphrase (jamais persistée) puis télécharge l'archive chiffrée.
export async function backupCreate() {
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
export function backupRestore() {
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
export async function loadAdminBackup() {
  const host = $('#admin-bk-policy'); if (!host) return;
  if (!isAdmin()) { emptyState(host, 'reserve aux administrateurs'); return; }
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
export async function editBackupPolicy(current) {
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
export function loadAdmin() { loadAdminUsers(); loadAdminConnectors(); loadAdminDetection(); loadAdminBackup(); }

// =====================================================================================
//  Navigation (sidebar repliable + hash-routing) + chargement par vue
// =====================================================================================
