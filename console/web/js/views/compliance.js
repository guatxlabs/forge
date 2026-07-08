import { adminApi, api } from '../core/api.js';
import { complianceAdmin } from '../core/auth.js';
import { $, esc, raw } from '../core/dom.js';
import { ENGAGEMENTS, activeEngagement } from '../core/state.js';
import { visibleEngagements } from './tenancy.js';
import { toast } from '../core/ui.js';

// =====================================================================================
//  COMPLIANCE (ENTERPRISE, flag-gated) — vue #compliance : (1) politique de rétention,
//  (2) legal-hold, (3) signer KMS/HSM (rédigé, lecture seule), (4) export de preuves SOC 2 / ISO.
//  Réservé admin + flag engagé (complianceAdmin()). Le serveur reste l'autorité (routes flag+admin
//  -> 404/403) ; ce masquage = défense en profondeur. Les secrets sont rédigés : jamais affichés.
// =====================================================================================
export function cmpErr(id, msg) { const e = $(id); if (e) { e.textContent = msg; e.hidden = !msg; } }
// Le scope actif sélectionné dans la carte politique (global => pas d'id ; tenant/engagement => id requis).
export function cmpScopeBody() {
  const scope = ($('#cmp-scope') && $('#cmp-scope').value) || 'global';
  const body = { scope };
  if (scope !== 'global') {
    const id = parseInt(($('#cmp-scope-id') && $('#cmp-scope-id').value) || '', 10);
    if (Number.isInteger(id) && id > 0) body.id = id;
  }
  return body;
}
// Peuple le sélecteur d'engagement (export de preuves) depuis la liste connue (déjà tenant-filtrée serveur).
export function cmpFillEngagements() {
  const sel = $('#cmp-ev-engagement'); if (!sel) return;
  const cur = sel.value;
  const list = (typeof visibleEngagements === 'function') ? visibleEngagements() : ENGAGEMENTS;
  sel.innerHTML = '';
  (list || []).forEach(e => {
    const o = document.createElement('option');
    o.value = String(e.id);
    o.textContent = '#' + e.id + ' — ' + (e.name || '') + (e.status ? ' (' + e.status + ')' : '');
    sel.appendChild(o);
  });
  if (cur) sel.value = cur;
}
// Rend le signer du ledger (rédigé) : mode + clé publique + booléens *_set (jamais le secret).
export function cmpRenderSigner(s) {
  const host = $('#cmp-signer'); if (!host) return;
  const badge = $('#cmp-signer-badge');
  if (!s) { host.textContent = '—'; if (badge) badge.textContent = ''; return; }
  if (badge) badge.textContent = s.off_host ? ('hors-hôte : ' + esc(s.mode)) : ('local : ' + esc(s.mode));
  const pk = s.pubkey ? esc(s.pubkey) : '<span class="muted">non exposée (poser FORGE_CONSOLE_LEDGER_PUBKEY)</span>';
  const yn = b => b ? '<span class="badge ok">configuré</span>' : '<span class="badge mut">non configuré</span>';
  host.innerHTML =
    '<div class="id-row" style="gap:10px;flex-wrap:wrap">' +
      '<span class="badge">mode ' + esc(s.mode) + '</span>' +
      '<span class="badge">' + (s.off_host ? 'clé hors-hôte' : 'clé locale on-disk') + '</span>' +
    '</div>' +
    '<div class="muted" style="margin-top:6px">Clé publique Ed25519 (vérification)</div>' +
    '<div class="mono" style="word-break:break-all">' + pk + '</div>' +
    '<div class="id-row" style="gap:10px;flex-wrap:wrap;margin-top:6px">' +
      '<span>endpoint : ' + yn(!!s.endpoint_set) + '</span>' +
      '<span>credential : ' + yn(!!s.credential_set) + '</span>' +
      '<span>argv : ' + yn(!!s.argv_set) + '</span>' +
    '</div>' +
    (s.note ? '<div class="muted" style="margin-top:6px">' + esc(s.note) + '</div>' : '');
}
// Charge la politique effective + les valeurs brutes + le signer rédigé pour le scope courant.
export async function loadCompliance() {
  const sec = $('#compliance'); if (!sec) return;
  if (!complianceAdmin()) { const st = $('#cmp-policy-state'); if (st) st.textContent = 'réservé à un admin (compliance enterprise).'; return; }
  cmpFillEngagements();
  // engagement_id : celui choisi dans l'export si présent, sinon l'engagement actif, sinon 1.
  const evSel = $('#cmp-ev-engagement');
  const eid = (evSel && parseInt(evSel.value, 10)) || (typeof activeEngagement === 'function' && activeEngagement()) || 1;
  const state = $('#cmp-policy-state'); if (state) state.textContent = 'chargement…';
  let data = null;
  try { data = await adminApi('/compliance/policy?engagement_id=' + encodeURIComponent(eid)); }
  catch (e) { if (state) { state.textContent = 'Chargement refusé : ' + e.message; } return; }
  cmpRenderSigner(data && data.ledger_signer);
  if (state && data) {
    const ret = (data.effective_retention_secs == null) ? 'illimitée (aucune politique)' : (data.effective_retention_secs + ' s');
    const hold = data.legal_hold ? ('ACTIF (scope ' + esc(String(data.legal_hold_scope)) + ')') : 'aucun';
    state.innerHTML =
      '<b>Politique effective (engagement #' + esc(String(data.engagement_id)) + ', tenant ' + esc(String(data.tenant_id)) + ')</b> — ' +
      'rétention : <b>' + esc(ret) + '</b> · legal-hold : <b class="' + (data.legal_hold ? 'bad' : '') + '">' + esc(hold) + '</b>';
  }
}
// (1) POST /api/compliance/policy {scope,id?,retention_secs} — set/clear la rétention. Ledgerisé serveur.
if ($('#cmp-policy-form')) $('#cmp-policy-form').addEventListener('submit', async e => {
  e.preventDefault(); cmpErr('#cmp-policy-err', '');
  const body = cmpScopeBody();
  if (body.scope !== 'global' && !body.id) { cmpErr('#cmp-policy-err', 'scope ' + body.scope + ' requiert un id positif.'); return; }
  const raw = ($('#cmp-retention') && $('#cmp-retention').value || '').trim();
  body.retention_secs = raw === '' ? null : parseInt(raw, 10);
  try {
    await adminApi('/compliance/policy', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    toast('Rétention enregistrée (ledgerisée)', 'ok');
    await loadCompliance();
  } catch (err) { cmpErr('#cmp-policy-err', 'Enregistrement refusé : ' + err.message); }
});
// (2) POST /api/compliance/legal-hold {scope,id?,hold} — place/lève le hold. Ledgerisé serveur.
export async function cmpSetHold(hold) {
  cmpErr('#cmp-policy-err', '');
  const body = cmpScopeBody();
  if (body.scope !== 'global' && !body.id) { cmpErr('#cmp-policy-err', 'scope ' + body.scope + ' requiert un id positif.'); return; }
  body.hold = hold;
  try {
    await adminApi('/compliance/legal-hold', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
    toast(hold ? 'Legal-hold placé (ledgerisé)' : 'Legal-hold levé (ledgerisé)', 'ok');
    await loadCompliance();
  } catch (err) { cmpErr('#cmp-policy-err', 'Action refusée : ' + err.message); }
}
if ($('#cmp-hold-on')) $('#cmp-hold-on').addEventListener('click', () => cmpSetHold(true));
if ($('#cmp-hold-off')) $('#cmp-hold-off').addEventListener('click', () => cmpSetHold(false));
// Recharge la politique quand le scope/id change (feedback immédiat sur l'effectif).
if ($('#cmp-scope')) $('#cmp-scope').addEventListener('change', () => { if (complianceAdmin()) loadCompliance(); });
if ($('#cmp-scope-id')) $('#cmp-scope-id').addEventListener('change', () => { if (complianceAdmin()) loadCompliance(); });
if ($('#cmp-ev-engagement')) $('#cmp-ev-engagement').addEventListener('change', () => { if (complianceAdmin()) loadCompliance(); });
if ($('#cmp-reload')) $('#cmp-reload').addEventListener('click', loadCompliance);
// datetime-local (local) -> epoch secondes UTC. Vide => null (borne omise).
export function cmpEpoch(id) {
  const v = ($(id) && $(id).value || '').trim();
  if (!v) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}
// (4) GET /api/compliance/evidence?... — ouvre le bundle (téléchargement JSON / vue HTML|PDF). Ledgerisé serveur.
if ($('#cmp-evidence-form')) $('#cmp-evidence-form').addEventListener('submit', e => {
  e.preventDefault(); cmpErr('#cmp-ev-err', '');
  const sel = $('#cmp-ev-engagement');
  const eid = sel && parseInt(sel.value, 10);
  if (!Number.isInteger(eid) || eid <= 0) { cmpErr('#cmp-ev-err', 'Sélectionne un engagement.'); return; }
  const fmt = ($('#cmp-ev-format') && $('#cmp-ev-format').value) || 'json';
  const params = new URLSearchParams({ engagement_id: String(eid), format: fmt });
  const from = cmpEpoch('#cmp-ev-from'); if (from != null) params.set('from', String(from));
  const to = cmpEpoch('#cmp-ev-to'); if (to != null) params.set('to', String(to));
  // Ouvre dans un onglet : JSON (attachment) => téléchargement ; HTML/PDF (inline) => affichage auditeur.
  window.open('/api/compliance/evidence?' + params.toString(), '_blank');
  toast('Export de preuves lancé (ledgerisé)', 'ok');
});

// ---------------------------------------------------------------------------------
//  Params SPÉCIFIQUES par module (envoyés dans /api/run body.module_params).
//  Schéma additif : chaque clé = kind de module ; valeur = liste de champs.
//  Seuls les modules WEB-ALLOWED (et donc lançables depuis le web) consomment des params ;
//  les params sont passés verbatim au moteur (Action.params), snake_case + JSON-sérialisable.
//  Référence moteur : evasion.xhr (types/url_contains/tab), evasion.turnstile (strategy/threshold/tab).
//  type: text|number|select|list (list = séparé par virgules -> array). Vide = champ omis (no-op).
// ---------------------------------------------------------------------------------
