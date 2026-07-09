import { OPERATOR_SECRET, api, authHeaders, setOperatorSecret, write } from '../core/api.js';
import { $, esc, fmtTs, ic, raw, SEV_BADGE } from '../core/dom.js';
import { MODULES, setModules } from './modules.js';
import { activeEngagement } from '../core/state.js';
import { confirmModal, guardList, infoModal, modal, toast } from '../core/ui.js';

export let lcC2Probed = false;              // sonde l'état C2 une seule fois (la sonde POSTe /api/run)
export const TERMINAL_RUN = new Set(['done', 'failed', 'timeout', 'cancelled']);
export const RUNSTAT_BADGE = { running: 'webyes', done: 'ok', failed: 'destr', timeout: 'expl', cancelled: 'mut' };
export let LC_LIVE = null;                  // { runId, es, poll, lastId, terminal } — flux du run suivi
export let lcModulesLoaded = false;

export const MODULE_PARAMS = {
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
export function highImpactOptIn() { return !!($('#lc-allowhi') && $('#lc-allowhi').checked); }
export function renderLaunchModules() {
  const host = $('#lc-modlist'); if (!host) return;
  const hint = $('#lc-modhint');
  const hiOn = highImpactOptIn();
  const sorted = [...MODULES].sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
  // connecteur DÉSACTIVÉ par l'admin (enabled=0 ou available_override=0) : jamais sélectionnable au
  // lancement (le serveur refuse de toute façon — module_disabled 400 ; on l'expose ici sans surprise).
  const connOff = m => (m.enabled === false) || (m.available_override === false);
  // disponibilité EFFECTIVE (sonde host ∧ intention opérateur) : effective_available si le moteur l'expose,
  // sinon la sonde brute `available`. Un module dont l'outil sous-jacent est ABSENT au niveau host n'est
  // PAS lançable — sans ce contrôle il serait sélectionnable puis SKIP silencieusement au run (no-op).
  const effAvail = m => (m.effective_available === undefined) ? (m.available !== false) : (m.effective_available !== false);
  // outil ABSENT (sonde host négative) SANS être une désactivation opérateur (enabled/override) : indispo.
  const toolAbsent = m => !effAvail(m) && !connOff(m);
  const webable = sorted.filter(m => m.web_allowed && !m.exploit && !m.destructive && !connOff(m) && !toolAbsent(m));
  const blocked = sorted.filter(m => m.exploit || m.destructive || !m.web_allowed || connOff(m) || toolAbsent(m));
  if (hint) hint.textContent = `${webable.length} web · ${blocked.length} ${hiOn ? 'à gouverner' : 'bloqués'}`;
  if (guardList(host, sorted, 'aucun module exposé par le moteur')) return;
  host.replaceChildren();
  sorted.forEach(m => {
    const highImpact = !!(m.exploit || m.destructive);
    // un connecteur DÉSACTIVÉ par l'admin n'est JAMAIS sélectionnable (au-dessus du plancher exploit :
    // même l'opt-in fort-impact ne le débloque pas — le serveur le refuse via module_disabled).
    const disabledByAdmin = connOff(m);
    // outil non installé sur l'hôte (sonde de disponibilité négative) : jamais lançable — le run le
    // SKIP en silence sinon (item no-op). Distinct d'une désactivation opérateur (disabledByAdmin).
    const disabledByAbsent = toolAbsent(m);
    // un module est sélectionnable s'il est web_allowed non-exploit/non-destructif, OU s'il est à
    // fort impact ET que l'opt-in gouverné est activé — et JAMAIS s'il est désactivé par l'admin
    // ou dont l'outil est absent du host.
    const allowed = !disabledByAdmin && !disabledByAbsent && ((!!m.web_allowed && !highImpact) || (highImpact && hiOn));
    const armedHi = highImpact && allowed;   // module à fort impact débloqué par l'opt-in
    const specs = (allowed && MODULE_PARAMS[m.kind]) || null;
    const lab = document.createElement('label');
    lab.className = 'lc-modopt' + (allowed ? '' : ' disabled') + (disabledByAbsent ? ' unavail' : '') + (armedHi ? ' hi-armed' : '') + (specs ? ' has-params' : '');
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
        : disabledByAbsent
          ? 'indispo (outil absent)'
          : (highImpact
            ? 'CLI/opérateur — activer l\'opt-in ' + [m.exploit ? 'exploit' : '', m.destructive ? 'destructif' : ''].filter(Boolean).join('/')
            : 'CLI opérateur uniquement — non autorisé web');
      const tag = document.createElement('span'); tag.className = 'lc-clionly'; tag.textContent = why;
      top.appendChild(tag);
      lab.title = disabledByAdmin
        ? 'Connecteur désactivé par un administrateur (gouvernance) — non lançable (le serveur le refuse : module_disabled).'
        : disabledByAbsent
          ? 'Outil non installé sur l\'hôte (sonde de disponibilité négative) — non lançable (le run le SKIP en silence).'
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

// Coche (on=true) / décoche (on=false) en masse les modules du formulaire de lancement.
// « Tout sélectionner » ne coche QUE les modules SÉLECTIONNABLES (checkbox non-disabled) : les modules
// désactivés (admin) ou dont l'outil est absent restent décochés (respect du gate d'indisponibilité).
// « Tout désélectionner » décoche tout (y compris un éventuel coché résiduel). On dispatche `change`
// pour que le bloc de params (params-open) reste synchronisé sans dupliquer la logique de rendu.
export function lcSelectModules(on) {
  [...document.querySelectorAll('#lc-modlist input[data-lcmod]')].forEach(cb => {
    if (on && cb.disabled) return;          // select-all ignore les modules non lançables
    if (cb.checked !== on) { cb.checked = on; cb.dispatchEvent(new Event('change')); }
  });
}

// Construit body.module_params à partir des modules WEB-ALLOWED cochés qui ont des champs renseignés.
// Coercition : list -> array (vide ignoré) ; number -> Number (NaN ignoré) ; text/select -> string non vide.
// Un module sans aucun champ renseigné est omis (pas de clé vide -> no-op côté backend).
export function collectModuleParams() {
  const out = {};
  document.querySelectorAll('#lc-modlist .lc-modparams').forEach(box => {
    const kind = box.dataset.lcparamsFor;
    const lab = box.closest('.lc-modopt');
    const cb = lab && lab.querySelector('input[data-lcmod]');
    if (!cb || !cb.checked || cb.disabled) return;  // seuls les modules cochés ET sélectionnables (⊆ modules[])
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
export async function probeC2State() {
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

export async function loadLaunch() {
  // catalogue de modules (réutilise MODULES global ; le charge si pas encore fait).
  if (!MODULES.length && !lcModulesLoaded) {
    try { setModules(await api('/modules')); } catch (e) { /* la liste restera vide, hint le dira */ }
    lcModulesLoaded = true;
  }
  renderLaunchModules();
  if (!lcC2Probed) { lcC2Probed = true; probeC2State(); }   // sonde C2 une fois (évite de marteler /api/run)
  loadRuns();
  // si un run est déjà suivi, on garde le flux ; sinon on tente de raccrocher le run courant.
  if (!LC_LIVE) reattachRunningRun();
}

// raccroche automatiquement au run 'running' s'il en existe un (reprise après navigation/reload).
export async function reattachRunningRun() {
  try {
    const runs = await api('/runs?status=running&limit=1');
    if (Array.isArray(runs) && runs.length) followRun(runs[0].run_id, runs[0]);
  } catch (e) { /* pas de run vivant : on laisse l'état par défaut */ }
}

export function lcLogLine(stream, line) {
  const host = $('#lc-log'); if (!host) return;
  const span = document.createElement('span');
  span.className = 'lcl lcl-' + (stream || 'stdout');
  span.textContent = line;
  host.appendChild(span);
  // auto-scroll seulement si l'utilisateur est déjà en bas (ne le contrarie pas s'il lit en arrière).
  const atBottom = host.scrollHeight - host.scrollTop - host.clientHeight < 40;
  if (atBottom) host.scrollTop = host.scrollHeight;
}
export function lcStatusLine(status, exitCode) {
  const host = $('#lc-log'); if (!host) return;
  const span = document.createElement('span');
  span.className = 'lcl lcl-status';
  span.textContent = `— statut : ${status}` + (exitCode != null ? ` (exit ${exitCode})` : '');
  host.appendChild(span);
  host.scrollTop = host.scrollHeight;
}
export function lcSetLiveBadge(status) {
  const b = $('#lc-livebadge'); if (!b) return;
  const cls = RUNSTAT_BADGE[status] || 'mut';
  b.className = 'badge ' + cls;
  b.textContent = status || 'aucun';
}
export function lcSetTransport(mode) {
  const t = $('#lc-transport'); if (!t) return;
  if (!mode) { t.className = 'badge mut'; t.textContent = '—'; return; }
  t.className = 'badge ' + (mode === 'sse' ? 'webyes' : 'mut');
  t.textContent = mode === 'sse' ? 'flux SSE' : 'polling';
  t.title = mode === 'sse' ? 'EventSource(/api/runs/:id/events)' : 'fallback polling GET /api/runs/:id/logs + /api/runs/:id';
}

// arrête proprement le flux courant (EventSource + timer de polling).
export function lcStopLive() {
  if (!LC_LIVE) return;
  if (LC_LIVE.es) { try { LC_LIVE.es.close(); } catch (e) {} }
  if (LC_LIVE.poll) clearTimeout(LC_LIVE.poll);
  LC_LIVE = null;
}

// suit un run : reset du panneau, amorce le backlog de logs (cas reprise), branche SSE,
// fallback polling si l'EventSource erre. lastId est posé sur le backlog pour ne rien re-rendre.
export async function followRun(runId, runMeta) {
  lcStopLive();
  LC_LIVE = { runId, es: null, poll: null, lastId: 0, terminal: false };
  const host = $('#lc-log'); if (host) host.replaceChildren();
  const res = $('#lc-result'); if (res) { res.hidden = true; res.replaceChildren(); }  // panneau résultat masqué tant que le run tourne
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
export function startSse(runId) {
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
export function startPolling(runId) {
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
export function onRunStatus(runId, status, exitCode) {
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
    // PANNEAU RÉSULTAT (#5/#4) : tuiles SKIP/ERREURS séparées + findings (ou état vide) + issue par
    // module, dérivés des lignes roe_decision/findings ingérées par le moteur. Best-effort.
    lcRenderLiveResult(runId, status);
  }
}

// compteurs du run en cours (fired/dry_run/vetoed/errors) + coverage_gaps. maj live pendant le run.
export function lcUpdateCounts(run) {
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

// =====================================================================================
//  ISSUE PAR MODULE + FINDINGS PAR RUN (visibilité — #4/#5)
//  Le compteur `errors` de run_job AGRÈGE SKIP (module indisponible/désactivé, technique retirée) ET
//  ERROR (échec réel) — cf. Engine.coverage(). On RE-SÉPARE ces deux à l'affichage en dérivant depuis
//  les lignes roe_decision (GET /api/roe?run_id=...), SANS changer la sémantique serveur (pur display).
// =====================================================================================
// verdict d'action -> classe de badge. ERROR (échec) distinct de SKIP (indisponible/gouvernance).
export const RUN_VERDICT_BADGE = { FIRE: 'v-FIRE', DRY_RUN: 'v-DRY_RUN', VETO: 'v-VETO', SKIP: 'mut', ERROR: 'destr' };

// Dérive les compteurs d'issue depuis les lignes roe_decision d'un run (SKIP compté À PART de ERROR).
export function deriveOutcome(roeRows) {
  const o = { skipped: 0, errors: 0, fired: 0, dry_run: 0, vetoed: 0 };
  (Array.isArray(roeRows) ? roeRows : []).forEach(r => {
    const v = String(r.verdict || '').toUpperCase();
    if (v === 'SKIP') o.skipped++;
    else if (v === 'ERROR') o.errors++;
    else if (v === 'FIRE') o.fired++;
    else if (v === 'DRY_RUN') o.dry_run++;
    else if (v === 'VETO') o.vetoed++;
  });
  return o;
}

// HTML des tuiles de compteurs. Avec `outcome` (dérivé roe) : SKIP et ERREURS affichés SÉPARÉMENT ;
// sinon (live avant l'ingest des lignes roe) repli sur le compteur agrégé run_job (errors = SKIP+ERROR).
export function runCountTilesHtml(d, outcome) {
  const tiles = [['FIRE', (outcome ? outcome.fired : d.fired), 'v-FIRE'],
                 ['DRY_RUN', (outcome ? outcome.dry_run : d.dry_run), 'v-DRY_RUN'],
                 ['VETO', (outcome ? outcome.vetoed : d.vetoed), 'v-VETO']];
  if (outcome) tiles.push(['SKIP/ignoré', outcome.skipped, 'skipped'], ['ERREURS', outcome.errors, 'errors']);
  else tiles.push(['ERREURS', d.errors, 'errors']);
  return tiles.map(([lab, n, cls]) => `<div class="roecount ${cls}"><span class="rcn">${Number(n || 0)}</span><span class="rcl">${esc(lab)}</span></div>`).join('');
}

// Table d'ISSUE PAR MODULE (anti-masquage) : une ligne par action évaluée — kind / cible / verdict /
// raison. Rend VISIBLES les SKIP (outil absent, connecteur/technique désactivés) et VETO que les tuiles
// agrègent. Retourne un fragment DOM. Source : lignes roe_decision du run.
export function renderOutcomeTable(roeRows) {
  const rows = Array.isArray(roeRows) ? roeRows : [];
  const wrap = document.createElement('div');
  const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = 'Issue par module (' + rows.length + ')';
  wrap.appendChild(h);
  if (!rows.length) {
    const e = document.createElement('div'); e.className = 'muted'; e.textContent = '(aucune décision enregistrée pour ce run)';
    wrap.appendChild(e); return wrap;
  }
  const scroller = document.createElement('div'); scroller.className = 'lc-tablescroll';
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Type</th><th>Cible</th><th>Verdict</th><th>Raison</th></tr></thead>';
  const tb = document.createElement('tbody');
  rows.forEach(r => {
    const v = String(r.verdict || '').toUpperCase();
    const cls = RUN_VERDICT_BADGE[v] || 'mut';
    const reason = Array.isArray(r.reasons) ? r.reasons.join(' ; ') : (r.reasons == null ? '' : String(r.reasons));
    const tr = document.createElement('tr');
    const kTd = document.createElement('td'); kTd.innerHTML = r.kind ? `<code>${esc(r.kind)}</code>` : '<span class="muted">-</span>';
    const tTd = document.createElement('td'); tTd.textContent = r.target || '-';
    const vTd = document.createElement('td'); vTd.innerHTML = `<span class="badge ${cls}">${esc(v || '?')}</span>`;
    const rTd = document.createElement('td'); rTd.className = 'lc-oreason'; rTd.textContent = reason || '-'; rTd.title = reason || '';
    tr.append(kTd, tTd, vTd, rTd);
    tb.appendChild(tr);
  });
  table.appendChild(tb); scroller.appendChild(table); wrap.appendChild(scroller);
  return wrap;
}

// Liste des FINDINGS de ce run (titre / sévérité / cible / outil) + ÉTAT VIDE explicite récapitulant
// l'issue (0 finding · N fired · M ignorés · K erreurs). Retourne un fragment DOM. Source :
// GET /api/findings?run_id=... (déjà borné à l'engagement actif côté serveur).
export function renderRunFindings(findings, outcome, status) {
  const rows = Array.isArray(findings) ? findings : [];
  const wrap = document.createElement('div');
  const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = 'Findings de ce run (' + rows.length + ')';
  wrap.appendChild(h);
  if (!rows.length) {
    const o = outcome || {};
    const term = TERMINAL_RUN.has(status) ? 'Run terminé' : 'Run en cours';
    const e = document.createElement('div'); e.className = 'lc-emptyfind';
    e.textContent = `${term} — 0 finding · ${Number(o.fired || 0)} fired · ${Number(o.skipped || 0)} ignorés · ${Number(o.errors || 0)} erreurs`;
    wrap.appendChild(e); return wrap;
  }
  const scroller = document.createElement('div'); scroller.className = 'lc-tablescroll';
  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Titre</th><th>Sévérité</th><th>Cible</th><th>Outil</th></tr></thead>';
  const tb = document.createElement('tbody');
  rows.forEach(f => {
    const tr = document.createElement('tr');
    const tiTd = document.createElement('td'); tiTd.textContent = f.title || '(sans titre)'; tiTd.title = f.title || '';
    const sTd = document.createElement('td'); sTd.innerHTML = raw(SEV_BADGE(f.severity));
    const tgTd = document.createElement('td'); tgTd.textContent = f.target || '-';
    const toTd = document.createElement('td'); toTd.className = 'mut'; toTd.textContent = f.tool || '-';
    tr.append(tiTd, sTd, tgTd, toTd);
    tb.appendChild(tr);
  });
  table.appendChild(tb); scroller.appendChild(table); wrap.appendChild(scroller);
  return wrap;
}

// Charge les lignes roe_decision + findings d'un run (parallèle, best-effort). Retourne
// { roe:[], findings:[], outcome:{} } — arrays vides si un fetch échoue (l'affichage dégrade proprement).
export async function fetchRunOutcome(runId) {
  const [roe, fnd] = await Promise.all([
    api('/roe?limit=2000&run_id=' + encodeURIComponent(runId)).catch(() => []),
    api('/findings?limit=200&run_id=' + encodeURIComponent(runId)).catch(() => ({ findings: [] })),
  ]);
  const roeRows = Array.isArray(roe) ? roe : [];
  const findings = (fnd && Array.isArray(fnd.findings)) ? fnd.findings : [];
  return { roe: roeRows, findings, outcome: deriveOutcome(roeRows) };
}

// Rend le PANNEAU RÉSULTAT du live (à la fin d'un run) : tuiles séparées SKIP/ERREURS + liste de
// findings (ou état vide). Best-effort : ne casse jamais le flux live. `#lc-result` est le conteneur.
export async function lcRenderLiveResult(runId, status) {
  const host = $('#lc-result'); if (!host) return;
  let data;
  try { data = await fetchRunOutcome(runId); }
  catch (e) { return; }
  host.hidden = false;
  host.replaceChildren();
  const counts = document.createElement('div'); counts.className = 'roecounters'; counts.style.marginTop = '4px';
  const det = { fired: data.outcome.fired, dry_run: data.outcome.dry_run, vetoed: data.outcome.vetoed, errors: data.outcome.errors };
  counts.innerHTML = runCountTilesHtml(det, data.outcome);
  host.appendChild(counts);
  host.appendChild(renderRunFindings(data.findings, data.outcome, status));
  host.appendChild(renderOutcomeTable(data.roe));
}

// affiche un message d'erreur clair sous le formulaire (mappe les codes du contrat run_create).
export const LC_ERRMAP = {
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
export function lcShowErr(msg) { const e = $('#lc-err'); if (e) { e.innerHTML = msg; e.hidden = false; } }
export function lcClearErr() { const e = $('#lc-err'); if (e) { e.textContent = ''; e.hidden = true; } }

// POST /api/run avec validation côté client miroir du contrat (messages clairs avant l'aller-retour).
export async function submitRun(e) {
  e.preventDefault();
  lcClearErr();
  const campaign = ($('#lc-campaign').value || '').trim();
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(campaign) || campaign.startsWith('-')) { lcShowErr(LC_ERRMAP.bad_campaign); return; }
  const targets = ($('#lc-targets').value || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!targets.length) { lcShowErr(LC_ERRMAP.no_targets); return; }
  // :not(:disabled) — défense en profondeur : un module désactivé/indispo (checkbox disabled) n'entre
  // JAMAIS dans le payload, même s'il a été coché programmatiquement (le serveur le refuserait de toute façon).
  const checkedCbs = [...document.querySelectorAll('#lc-modlist input[data-lcmod]:checked:not(:disabled)')];
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
    r = await write('/api/run', { body, auth: 'operator' });
    j = r.json;
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
export function confirmHighImpact(ctx) {
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
export function lcSyncDanger() {
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

export async function cancelRun() {
  const runId = LC_LIVE && LC_LIVE.runId;
  if (!runId) { toast('Aucun run en cours à annuler.', 'bad'); return; }
  if (!OPERATOR_SECRET) { lcShowErr(LC_ERRMAP.operator_required); location.hash = 'launch'; return; }
  if (!(await confirmModal('Annuler le run en cours ? Le groupe de processus sera tué.', { danger: true, okText: 'Annuler le run' }))) return;
  let r, j;
  try {
    r = await write('/api/runs/' + encodeURIComponent(runId) + '/cancel', { auth: 'operator' });
    j = r.json;
  } catch (err) { toast('Erreur réseau : ' + (err.message || err), 'bad'); return; }
  if (r.ok) { toast('Annulation demandée — kill group envoyé.', 'ok'); lcSetLiveBadge('cancelled'); }
  else {
    const map = { operator_required: LC_ERRMAP.operator_required, not_running: 'Le run n\'est pas/plus en cours.', unknown_run: 'Run inconnu.' };
    toast((map[j && j.error] || ('Refus (' + (j && j.error || r.status) + ')')), 'bad');
  }
}

// liste des runs (récents d'abord) — clic = détail.
export let LC_RUNS = [];
export async function loadRuns() {
  const host = $('#lc-runresult'); if (!host) return;
  const st = $('#lc-runstatus') && $('#lc-runstatus').value;
  let rows = [];
  try { rows = await api('/runs?limit=100' + (st ? '&status=' + encodeURIComponent(st) : '')); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  LC_RUNS = Array.isArray(rows) ? rows : [];
  if ($('#lc-runcount')) $('#lc-runcount').textContent = LC_RUNS.length + ' runs';
  if (guardList(host, LC_RUNS, 'aucun run')) return;
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
export async function openRun(runId) {
  let d, logs;
  try { d = await api('/runs/' + encodeURIComponent(runId)); }
  catch (e) { toast('Détail run : ' + e.message, 'bad'); return; }
  try { logs = await api('/runs/' + encodeURIComponent(runId) + '/logs?limit=200'); } catch (e) { logs = { lines: [] }; }
  // ISSUE PAR MODULE + FINDINGS (#4/#5) : dérivés des lignes roe_decision/findings du run. Best-effort
  // (arrays vides si indisponibles) — l'affichage dégrade proprement sur la vue compteurs run_job.
  let ro = { roe: [], findings: [], outcome: null };
  try { ro = await fetchRunOutcome(runId); } catch (e) { /* dégradé : pas d'issue détaillée */ }
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
    // avec les lignes roe (ro.outcome) : SKIP/ignoré et ERREURS séparés ; sinon repli run_job (agrégé).
    counts.innerHTML = runCountTilesHtml(d, ro.outcome);
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
    // FINDINGS de ce run (ou état vide explicite) + ISSUE PAR MODULE (kind/cible/verdict/raison).
    body.appendChild(renderRunFindings(ro.findings, ro.outcome, d.status));
    body.appendChild(renderOutcomeTable(ro.roe));
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
if ($('#lc-operator')) $('#lc-operator').addEventListener('input', e => { setOperatorSecret(e.target.value); lcSyncDanger(); });
if ($('#lc-clearop')) $('#lc-clearop').addEventListener('click', () => { setOperatorSecret(''); if ($('#lc-operator')) $('#lc-operator').value = ''; lcSyncDanger(); toast('Secret opérateur oublié (session).', 'ok'); });
// avertissement « armer » : visible quand la case est cochée + rafraîchit les conditions de gouvernance.
if ($('#lc-arm')) $('#lc-arm').addEventListener('change', e => { const w = $('#lc-armwarn'); if (w) w.hidden = !e.target.checked; lcSyncDanger(); });
if ($('#lc-reason')) $('#lc-reason').addEventListener('input', lcSyncDanger);
// ZONE DANGER : opt-in fort impact (défaut OFF) — (dé)bloque exploit/destructif + recalcule les conditions.
if ($('#lc-allowhi')) $('#lc-allowhi').addEventListener('change', lcSyncDanger);
// SÉLECTION EN MASSE des modules : « Tout sélectionner » (disponibles uniquement) / « Tout désélectionner ».
if ($('#lc-modall')) $('#lc-modall').addEventListener('click', () => lcSelectModules(true));
if ($('#lc-modnone')) $('#lc-modnone').addEventListener('click', () => lcSelectModules(false));

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
export function lcScopeAddTarget() {
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
if ($('#lc-dryplan')) $('#lc-dryplan').addEventListener('click', lcDryPlan);
if ($('#lc-approve')) $('#lc-approve').addEventListener('click', lcApproveAndRun);
if ($('#lc-approve-all')) $('#lc-approve-all').addEventListener('click', () => {
  document.querySelectorAll('#lc-planresult .lc-approve-cb').forEach(cb => { cb.checked = true; });
  lcSyncApproveBtn();
});

// --- RAPPORT DE RUN : GET /api/runs/:id/report (text/markdown) -> modale read-only ---
export async function openRunReport(runId) {
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
export async function openRunReportHtml(runId, print) {
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
