import { OPERATOR_SECRET, api, setOperatorSecret, write } from '../core/api.js';
import { editing } from './dashboards.js';
import { $, esc, raw } from '../core/dom.js';
import { followRun, loadRuns } from './launch/index.js';
import { activeEngagement } from '../core/state.js';
import { confirmModal, guardList, modal, toast } from '../core/ui.js';

export let WF = { user: [], builtins: [], enabled: {}, groups: {}, rowByKind: {}, modmeta: {} };

export async function loadWorkflows() {
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
export function wfStepIsSafe(kind) { const m = WF.modmeta[kind]; return !!(m && m.web_allowed && !m.exploit && !m.destructive); }

export function wfStepChip(kind) {
  const en = WF.enabled[kind];
  const chip = document.createElement('span');
  chip.className = 'wf-chip' + (en ? '' : ' off');
  chip.title = (en ? 'activée pour le scope courant' : 'hors sélection du scope — sera LARGUÉE (fail-closed)')
    + (wfStepIsSafe(kind) ? '' : ' · exploit/non-web : opt-in fort-impact requis');
  chip.innerHTML = esc(kind) + (wfStepIsSafe(kind) ? '' : ' <span class="badge expl">expl</span>');
  return chip;
}

export function renderWorkflows() {
  const host = $('#wf-list'); if (!host) return;
  const all = WF.builtins.concat(WF.user);
  if (guardList(host, all, 'aucun workflow — cliquez « Nouveau workflow » pour composer un pipeline')) return;
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

export async function deleteWorkflow(wf) {
  const ok = await confirmModal('Supprimer le workflow « ' + wf.name + ' » ? (action ledgerisée)', { title: 'Supprimer le workflow', okText: 'Supprimer' });
  if (!ok) return;
  try {
    const r = await write('/api/workflows/' + encodeURIComponent(wf.name), { body: { delete: true }, auth: 'operator', engagement: true });
    if (r.status === 403) { toast('Suppression réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(r.json.why || r.json.error || r.status), 'bad'); return; }
    toast('Workflow supprimé (ledgerisé)', 'ok'); loadWorkflows();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Builder natif (aucune modale navigateur) : nom + description + catalogue GROUPÉ PAR CATÉGORIE
// (réutilise /api/techniques) pour AJOUTER des étapes, colonne d'étapes ORDONNÉES (monter/descendre/
// retirer) + params JSON optionnels par étape. Enregistre POST /api/workflows (création) ou
// /api/workflows/:name (édition). L'état activé du scope est affiché sur chaque technique.
export function openWorkflowBuilder(existing, opts) {
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
    if (guardList(stBody, steps, 'aucune étape — ajoutez des techniques depuis le catalogue')) return;
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
      const r = await write(url, { body, auth: 'operator', engagement: true });
      if (r.status === 403) { err.textContent = 'Réservé à un compte operator/admin.'; err.hidden = false; return; }
      const j = r.json;
      if (!r.ok) { err.textContent = 'Échec : ' + String(j.why || j.error || r.status); err.hidden = false; return; }
      toast('Workflow enregistré (ledgerisé)', 'ok'); close(); loadWorkflows();
    } catch (e) { err.textContent = 'Erreur réseau : ' + String(e.message || e); err.hidden = false; }
  };
  act.append(cancel, save); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
  setTimeout(() => { (editing ? descI : nameI).focus(); }, 30);
}

export async function runWorkflow(wf) {
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
  setOperatorSecret(vals.operator || '');
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
  try { r = await write('/api/run', { body, auth: 'operator' }); j = r.json; }
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

