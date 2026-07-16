import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { guardList, toast } from '../../core/ui.js';
import { loadModules } from '../modules.js';
import { loadAdminConnectors } from './connectors.js';

// =====================================================================================
//  ADMINISTRATION — AJOUTER UN OUTIL (« add a tool from the web UI »), gouverné.
//  Déclare SON PROPRE outil CLI depuis l'UI (ToolSpec DÉCLARATIF : binaire + argv no-shell tokenisé +
//  params_schema typé + flag_allowlist) — SANS éditer de fichier ni recompiler. POST /api/tools
//  (check_admin, fail-closed, ledgerisé) valide, persiste (dir server-managed) et HOT-RELOAD le
//  catalogue : l'outil apparaît dans « Capacités » ET dans « Lancement » (son params_schema est rendu
//  dynamiquement). Aucun code arbitraire ici — uniquement de la donnée déclarative gouvernée par le
//  moteur (scope-guard, no-shell, allowlist, statut clampé, plancher exploit). Tout texte est échappé.
// =====================================================================================

// petit helper de création de noeud (cls + attrs) — attrs.text => textContent (anti-XSS par construction).
function el(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (attrs) for (const k in attrs) { if (k === 'text') e.textContent = attrs[k]; else e[k] = attrs[k]; }
  return e;
}
function field(labelText, input) {
  const wrap = el('div', 'at-field');
  const lab = el('label', 'at-lab', { text: labelText });
  wrap.appendChild(lab); wrap.appendChild(input); return wrap;
}
function opt(sel, value, label) { const o = el('option'); o.value = value; o.textContent = label || value; sel.appendChild(o); return o; }

const PARAM_TYPES = ['text', 'number', 'select', 'list', 'flag'];

// --- lignes répétables (tokens argv / drapeaux allowlist) ---
function repeatRow(host, placeholder) {
  const row = el('div', 'at-row');
  const inp = el('input', 'at-inp', { type: 'text', placeholder });
  inp.dataset.atToken = '1';
  const rm = el('button', 'k-theme danger at-rm', { type: 'button', text: '✕', title: 'Retirer' });
  rm.onclick = () => row.remove();
  row.appendChild(inp); row.appendChild(rm); host.appendChild(row);
  return inp;
}

// --- lignes répétables (descripteurs de params_schema) ---
function paramRow(host) {
  const row = el('div', 'at-prow');
  const name = el('input', 'at-inp', { type: 'text', placeholder: 'name (ex: level)' }); name.dataset.pName = '1';
  const type = el('select', 'at-inp'); type.dataset.pType = '1'; PARAM_TYPES.forEach(t => opt(type, t));
  const label = el('input', 'at-inp', { type: 'text', placeholder: 'label (affiché)' }); label.dataset.pLabel = '1';
  const flag = el('input', 'at-inp', { type: 'text', placeholder: 'flag CLI (opt., ex: --level)' }); flag.dataset.pFlag = '1';
  const allowed = el('input', 'at-inp', { type: 'text', placeholder: 'allowed (select, séparés par ,)' }); allowed.dataset.pAllowed = '1';
  const rm = el('button', 'k-theme danger at-rm', { type: 'button', text: '✕', title: 'Retirer ce champ' });
  rm.onclick = () => row.remove();
  [name, type, label, flag, allowed, rm].forEach(x => row.appendChild(x));
  host.appendChild(row);
  return row;
}

// Construit le corps ToolSpec depuis le formulaire (validation FRONT légère ; le SERVEUR reste l'autorité
// fail-closed). Retourne { body } ou { error }.
function collectSpec(root) {
  const val = sel => (root.querySelector(sel)?.value || '').trim();
  const kind = val('#at-kind');
  const vuln_class = val('#at-vulnclass');
  const binary = val('#at-binary');
  const docker_image = val('#at-docker');
  if (!kind) return { error: 'kind requis (ex: custom.mytool)' };
  if (!/^custom\./.test(kind)) return { error: 'kind doit commencer par « custom. »' };
  if (!vuln_class) return { error: 'vuln_class requis (ex: Recon)' };
  if (!binary && !docker_image) return { error: 'binary ou docker_image requis' };
  const argv = [...root.querySelectorAll('#at-argv [data-at-token]')].map(i => i.value).filter(v => v !== '');
  if (!argv.length) return { error: 'argv_template : au moins un token requis' };
  const flags = [...root.querySelectorAll('#at-flags [data-at-token]')].map(i => i.value.trim()).filter(Boolean);
  const params = [];
  root.querySelectorAll('#at-params .at-prow').forEach(r => {
    const name = (r.querySelector('[data-p-name]')?.value || '').trim();
    if (!name) return;
    const d = { name, type: r.querySelector('[data-p-type]')?.value || 'text' };
    const lbl = (r.querySelector('[data-p-label]')?.value || '').trim(); if (lbl) d.label = lbl;
    const flg = (r.querySelector('[data-p-flag]')?.value || '').trim(); if (flg) d.flag = flg;
    const alw = (r.querySelector('[data-p-allowed]')?.value || '').trim();
    if (alw) d.allowed = alw.split(',').map(s => s.trim()).filter(Boolean);
    params.push(d);
  });
  const body = { kind, vuln_class, binary, argv_template: argv };
  if (docker_image) body.docker_image = docker_image;
  if (flags.length) body.flag_allowlist = flags;
  if (params.length) body.params_schema = params;
  const parser = val('#at-parser'); if (parser) body.parser = parser;
  const phase = val('#at-phase'); if (phase) body.phase = phase;
  const capability = val('#at-cap'); if (capability) body.capability = capability;
  const severity = val('#at-sev'); if (severity) body.severity = severity;
  const hit_status = val('#at-hit'); if (hit_status) body.hit_status = hit_status;
  const mitre = val('#at-mitre'); if (mitre) body.mitre = mitre;
  const cwe = val('#at-cwe'); if (cwe) body.cwe = cwe;
  const descr = val('#at-descr'); if (descr) body.description = descr;
  if (root.querySelector('#at-exploit')?.checked) body.exploit = true;
  if (root.querySelector('#at-destr')?.checked) body.destructive = true;
  return { body };
}

export async function loadAddTool() {
  const host = $('#admin-addtool-body'); if (!host) return;
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; return; }
  host.replaceChildren();

  // --- formulaire ---
  const form = el('div', 'at-form');
  const grid = el('div', 'at-grid');
  const kind = el('input', 'at-inp', { type: 'text', id: 'at-kind', placeholder: 'custom.mytool' });
  const vc = el('input', 'at-inp', { type: 'text', id: 'at-vulnclass', placeholder: 'Recon' });
  const bin = el('input', 'at-inp', { type: 'text', id: 'at-binary', placeholder: 'httpx (binaire dans le PATH/l\'image)' });
  const docker = el('input', 'at-inp', { type: 'text', id: 'at-docker', placeholder: 'projectdiscovery/httpx (optionnel)' });
  grid.appendChild(field('kind (namespace custom.*)', kind));
  grid.appendChild(field('vuln_class', vc));
  grid.appendChild(field('binary', bin));
  grid.appendChild(field('docker_image', docker));
  form.appendChild(grid);

  // argv_template (liste de tokens no-shell)
  const argvBox = el('div', 'at-list'); argvBox.id = 'at-argv';
  const argvHead = el('div', 'at-listhead');
  argvHead.appendChild(el('span', 'at-lab', { text: 'argv_template — tokens (placeholders : {target} {target_host} {target_url} {param:NAME} {args})' }));
  const argvAdd = el('button', 'k-theme at-add', { type: 'button', text: '+ token' });
  argvAdd.onclick = () => repeatRow(argvBox, '-u ou {target_url}');
  argvHead.appendChild(argvAdd);
  form.appendChild(argvHead); form.appendChild(argvBox);
  repeatRow(argvBox, '-silent');
  repeatRow(argvBox, '{target_url}');

  // flag_allowlist (requis si {args} utilisé)
  const flagBox = el('div', 'at-list'); flagBox.id = 'at-flags';
  const flagHead = el('div', 'at-listhead');
  flagHead.appendChild(el('span', 'at-lab', { text: 'flag_allowlist — drapeaux autorisés pour {args} (ex: -t, --rate). REQUIS si {args} présent.' }));
  const flagAdd = el('button', 'k-theme at-add', { type: 'button', text: '+ drapeau' });
  flagAdd.onclick = () => repeatRow(flagBox, '--rate');
  flagHead.appendChild(flagAdd);
  form.appendChild(flagHead); form.appendChild(flagBox);

  // params_schema (champs typés servis au formulaire de Lancement)
  const paramBox = el('div', 'at-list'); paramBox.id = 'at-params';
  const paramHead = el('div', 'at-listhead');
  paramHead.appendChild(el('span', 'at-lab', { text: 'params_schema — champs de configuration (rendus dans « Campagne »)' }));
  const paramAdd = el('button', 'k-theme at-add', { type: 'button', text: '+ champ' });
  paramAdd.onclick = () => paramRow(paramBox);
  paramHead.appendChild(paramAdd);
  form.appendChild(paramHead); form.appendChild(paramBox);

  // méta (parser / phase / capability / severity / hit_status / mitre / cwe)
  const meta = el('div', 'at-grid');
  const mkSel = (id, opts, def) => { const s = el('select', 'at-inp', { id }); opts.forEach(o => opt(s, o)); if (def) s.value = def; return s; };
  meta.appendChild(field('parser', mkSel('at-parser', ['lines', 'regex', 'json', 'jsonl', 'none'], 'lines')));
  meta.appendChild(field('phase', mkSel('at-phase', ['recon', 'access', 'exploit'], 'recon')));
  meta.appendChild(field('capability', mkSel('at-cap', ['passive', 'active', 'exploit'], 'active')));
  meta.appendChild(field('severity', mkSel('at-sev', ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 'INFO')));
  meta.appendChild(field('hit_status', mkSel('at-hit', ['tested', 'reported_by_tool'], 'reported_by_tool')));
  meta.appendChild(field('mitre (ex: T1595)', el('input', 'at-inp', { type: 'text', id: 'at-mitre', placeholder: 'T1595' })));
  meta.appendChild(field('cwe (ex: CWE-200)', el('input', 'at-inp', { type: 'text', id: 'at-cwe', placeholder: 'CWE-200' })));
  form.appendChild(meta);

  // toggles gouvernance (exploit/destructif : non lançables web -> plancher opt-in/arm côté opérateur)
  const toggles = el('div', 'at-toggles');
  const mkChk = (id, label) => { const w = el('label', 'at-chk'); const c = el('input', null, { type: 'checkbox', id }); w.appendChild(c); w.appendChild(el('span', null, { text: ' ' + label })); return w; };
  toggles.appendChild(mkChk('at-exploit', 'exploit (gaté : arm + raison opérateur)'));
  toggles.appendChild(mkChk('at-destr', 'destructif (gaté)'));
  form.appendChild(toggles);

  const descr = el('textarea', 'at-inp at-descr', { id: 'at-descr', rows: 2, placeholder: 'description (affichée dans le catalogue)' });
  form.appendChild(field('description', descr));

  const actions = el('div', 'at-actions');
  const submit = el('button', 'login-btn', { type: 'button', text: 'Ajouter l\'outil' });
  submit.onclick = () => submitTool(form, submit);
  actions.appendChild(submit);
  const note = el('span', 'muted at-note', { text: 'Gouverné : no-shell, scope-guard, allowlist, admin-only, ledgerisé. Le binaire absent -> outil « indispo » (skippé au run).' });
  actions.appendChild(note);
  form.appendChild(actions);
  host.appendChild(form);

  // --- liste des outils déjà ajoutés (avec suppression) ---
  const listWrap = el('div', 'at-existing');
  listWrap.appendChild(el('h3', 'at-h3', { text: 'Outils ajoutés' }));
  const listHost = el('div'); listHost.id = 'at-list-host';
  listWrap.appendChild(listHost);
  host.appendChild(listWrap);
  renderUserTools(listHost);
}

async function submitTool(form, btn) {
  const { body, error } = collectSpec(form);
  if (error) { toast(error, 'bad'); return; }
  btn.disabled = true;
  try {
    const r = await adminApi('/tools', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    const reg = r && r.registered;
    toast('Outil « ' + body.kind + ' » ajouté' + (reg ? '' : ' (persisté ; registre indisponible — pris au prochain boot)') + '.', reg ? 'ok' : 'warn');
    loadAddTool();                                  // reset + rafraîchit la liste
    if (typeof loadModules === 'function') loadModules();          // refléter dans « Capacités » + « Lancement »
    if (typeof loadAdminConnectors === 'function') loadAdminConnectors();
  } catch (e) { toast('Ajout refusé : ' + e.message, 'bad'); }
  finally { btn.disabled = false; }
}

async function renderUserTools(listHost) {
  let data;
  try { data = await adminApi('/tools'); }
  catch (e) { listHost.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const tools = (data && Array.isArray(data.tools)) ? data.tools : [];
  if (guardList(listHost, tools, 'aucun outil ajouté par l\'UI')) return;
  const table = el('table', 'qtable');
  table.innerHTML = '<thead><tr><th>Outil</th><th>Binaire / image</th><th>Sonde</th><th>Actions</th></tr></thead>';
  const tb = el('tbody');
  tools.forEach(t => {
    const kind = (t && t.kind) || '';
    const m = (t && t.module) || {};
    const spec = (t && t.spec) || {};
    const binary = spec.binary || '';
    const docker = spec.docker_image || '';
    const avail = m.available ? '<span class="badge ok">dispo</span>' : '<span class="badge mut">absente</span>';
    const tr = el('tr');
    // cellules de données via textContent (anti-XSS) ; badges = markup statique dérivé de booléens.
    const c1 = el('td', 'mono'); c1.textContent = kind;
    const c2 = el('td', 'mono'); c2.textContent = binary + (docker ? '  ·  ' + docker : '');
    const c3 = el('td'); c3.innerHTML = avail;
    const c4 = el('td', 'admin-act');
    const del = el('button', 'k-theme danger', { type: 'button', text: 'Supprimer', title: 'Retirer cet outil ajouté par l\'UI' });
    del.onclick = () => deleteTool(kind);
    c4.appendChild(del);
    [c1, c2, c3, c4].forEach(c => tr.appendChild(c));
    tb.appendChild(tr);
  });
  table.appendChild(tb); listHost.replaceChildren(table);
}

async function deleteTool(kind) {
  try {
    await adminApi('/tools/' + encodeURIComponent(kind), { method: 'DELETE', headers: { Accept: 'application/json' } });
    toast('Outil « ' + kind + ' » supprimé.', 'ok');
    loadAddTool();
    if (typeof loadModules === 'function') loadModules();
    if (typeof loadAdminConnectors === 'function') loadAdminConnectors();
  } catch (e) { toast('Suppression refusée : ' + e.message, 'bad'); }
}
