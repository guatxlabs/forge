import { api } from '../../core/api.js';
import { $, esc, ic } from '../../core/dom.js';
import { loadRuns } from './runs-list.js';
import { lcRenderLiveResult } from './run-result.js';

// live.js est le SEUL propriétaire de LC_LIVE : lui seul RÉAFFECTE la variable (via lcStopLive/followRun).
// Les autres modules importent LC_LIVE en lecture (binding live) et appellent ses fns exportées
// (followRun / lcStopLive / reattachRunningRun) — jamais ils ne mutent l'état du flux directement.
export const TERMINAL_RUN = new Set(['done', 'failed', 'timeout', 'cancelled']);
export const RUNSTAT_BADGE = { running: 'webyes', done: 'ok', failed: 'destr', timeout: 'expl', cancelled: 'mut' };
export let LC_LIVE = null;                  // { runId, es, poll, lastId, terminal } — flux du run suivi

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
