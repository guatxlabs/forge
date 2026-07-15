import { OPERATOR_SECRET, write } from '../../core/api.js';
import { $, esc, ic } from '../../core/dom.js';
import { activeEngagement, withEngagement } from '../../core/state.js';
import { confirmModal, toast } from '../../core/ui.js';
import { MODULES } from '../modules.js';
import { LC_ERRMAP, lcClearErr, lcShowErr } from './submit.js';
import { followRun } from './live.js';
import { loadRuns } from './runs-list.js';

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
export async function lcScopeCheck() {
  const inp = $('#lc-scopetarget'); const out = $('#lc-scoperes'); const add = $('#lc-scopeadd');
  if (!inp || !out) return;
  const target = (inp.value || '').trim();
  if (add) add.hidden = true;
  if (!target) { out.hidden = true; return; }
  out.hidden = false;
  out.innerHTML = '<span class="muted">vérification…</span>';
  let r, j;
  try {
    // ENGAGEMENT-AWARE : scope-check résout contre le scope de l'engagement ACTIF (même règle que /api/run).
    r = await fetch(withEngagement('/api/scope-check'), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ target }) });
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
export function lcScopeAddTarget() {
  const add = $('#lc-scopeadd'); const ta = $('#lc-targets');
  if (!add || !ta) return;
  const t = add.dataset.target || '';
  if (!t) return;
  const lines = (ta.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!lines.includes(t)) { lines.push(t); ta.value = lines.join('\n'); toast('Cible ajoutée au lancement.', 'ok'); }
  else toast('Cible déjà dans la liste.', 'info');
}

// --- DRY-PLAN : POST /api/plan (INERTE) -> rendu action->verdict + cases d'approbation RECON ---
export const PLAN_VERDICT_BADGE = { FIRE: 'v-FIRE', DRY_RUN: 'v-DRY_RUN', VETO: 'v-VETO', SKIP: 'mut' };
export let LC_PLAN = null;   // dernier dry-plan : { targets, modules, actions[] } — base de l'approbation
// lit les cibles/modules courants du formulaire (mêmes règles miroir que submitRun, sans secret opérateur).
export function lcReadTargetsModules() {
  const targets = ($('#lc-targets') && $('#lc-targets').value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const modules = [...document.querySelectorAll('#lc-modlist input[data-lcmod]:checked:not(:disabled)')].map(c => c.value);
  return { targets, modules };
}
export async function lcDryPlan() {
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
    r = await fetch(withEngagement('/api/plan'), { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
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
export function renderPlan(j) {
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
export function lcSyncApproveBtn() {
  const btn = $('#lc-approve'); const stat = $('#lc-approvestat');
  const checked = [...document.querySelectorAll('#lc-planresult .lc-approve-cb:checked')];
  if (btn) btn.disabled = checked.length === 0 || !LC_PLAN;
  if (stat) stat.textContent = checked.length ? `${checked.length} action(s) approuvée(s)` : '';
}
// relance les actions approuvées en mode auto (RECON/non-exploit). L'exploit reste bloqué côté serveur :
// on ne transmet QUE les modules des actions cochées (⊆ web_allowed non-exploit), via POST /api/run.
export async function lcApproveAndRun() {
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
    r = await write('/api/run', { body, auth: 'operator' });
    j = r.json;
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
