import { OPERATOR_SECRET, adminApi, api, write } from '../core/api.js';
import { isAdmin } from '../core/auth.js';
import { $, esc } from '../core/dom.js';
import { renderLaunchModules } from './launch/index.js';
import { loadModules } from './modules.js';
import { ENGAGEMENTS, activeEngagement } from '../core/state.js';
import { emptyState, modal, toast } from '../core/ui.js';

//  REPORTS — LIVRABLE CLIENT : rapport d'engagement AGRÉGÉ + branding admin + aperçu (vue #reports).
//  Toujours l'engagement ACTIF (activeEngagement) : GET /api/engagements/:id/report?format=… — formats
//  html|pdf|docx|csv|json, secrets rédigés côté serveur, ISOLÉ à l'engagement, chaque génération
//  journalisée au ledger. Branding : GET (viewer+) / POST (admin) /api/report/branding[?engagement=:id].
//  100 % natif : réutilise modal()/toast()/adminApi() + un iframe same-origin pour l'aperçu. Aucune
//  modale navigateur. Le serveur reste l'autorité (viewer+ pour lire, admin pour brander, fail-closed).
// =====================================================================================
export const REP_FMT = { html: 'HTML', pdf: 'PDF', docx: 'DOCX', csv: 'CSV', json: 'JSON' };

// Engagement actif courant (id + objet), relu à CHAQUE appel : la vue suit le sélecteur d'en-tête.
export function repActive() {
  const id = activeEngagement();
  return { id, e: ENGAGEMENTS.find(x => x.id === id) };
}

// rend la vue #reports : badge/nom de l'engagement actif, bouton branding gaté admin, aperçu HTML.
export async function loadReports() {
  const { id, e } = repActive();
  const badge = $('#rep-eng'); if (badge) badge.textContent = e ? ('#' + id) : '';
  const nm = $('#rep-engname');
  if (nm) nm.textContent = e ? (e.name + ' · ' + e.mode + (e.status === 'archived' ? ' [archivé]' : '')) : '(aucun engagement actif)';
  // Branding réservé admin (défense en profondeur — le serveur gate aussi en 403).
  const bb = $('#rep-brand'); if (bb) bb.hidden = !isAdmin();
  const noEng = (id == null);
  ['rep-generate', 'rep-refresh'].forEach(bid => { const b = $('#' + bid); if (b) b.disabled = noEng; });
  const host = $('#rep-preview'); if (!host) return;
  if (noEng) { emptyState(host, 'Aucun engagement actif — sélectionnez-en un dans l\'en-tête pour générer son rapport.'); return; }
  await previewReport();
}

// Aperçu HTML du rapport de l'engagement ACTIF dans un iframe SANDBOX same-origin. Le HTML provient de
// notre endpoint authentifié (cookie same-origin) ; tout dynamique est échappé côté serveur. On injecte
// une <base href> (URL canonique du rapport) pour résoudre /quetzal.svg. Sandbox SANS allow-scripts :
// les éventuels handlers inline du document sont neutralisés (l'UI fournit ses propres contrôles).
export async function previewReport() {
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
export async function downloadReport(format) {
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
export async function brandingModal() {
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
export async function refreshModules() {
  const btn = $('#mod-refresh');
  if (!OPERATOR_SECRET) {
    toast('Secret opérateur requis : renseigne-le dans « Lancement C2 » (en-tête X-Forge-Operator).', 'bad');
    location.hash = 'launch'; if ($('#lc-operator')) $('#lc-operator').focus();
    return;
  }
  if (btn) btn.disabled = true;
  let r, j;
  try {
    r = await write('/api/modules/refresh', { auth: 'operator' });
    j = r.json;
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
