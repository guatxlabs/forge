import { detectionSourceForm } from '../views/admin.js';
import { api, setOperatorSecret } from './api.js';
import { loadCampaigns } from '../views/campaigns.js';
import { $ } from './dom.js';
import { loadEngagementSelector } from '../views/engagements.js';
import { lcStopLive } from '../views/launch.js';
import { loadStatuses } from '../views/overview.js';
import { route } from './router.js';
import { loadTenancyContext } from '../views/tenancy.js';
import { confirmModal, toast } from './ui.js';

export function complianceOn() { return !!(ENTERPRISE && ENTERPRISE.compliance); }
export function complianceAdmin() { return !!(complianceOn() && isAdmin()); }
// Dé-masque le lien nav #compliance (admin + flag) ; ré-oriente hors #compliance si non autorisé.
export function applyComplianceUi() {
  const link = $('#nav-compliance');
  if (link) link.hidden = !complianceAdmin();
  if (!complianceAdmin() && location.hash.slice(1) === 'compliance') location.hash = 'overview';
}
export function isAdmin() { return !!(WHOAMI && String(WHOAMI.role) === 'admin'); }
export let WHOAMI = null;
export const ROLE_CLASSES = ['role-admin', 'role-operator', 'role-editor', 'role-viewer'];
export function renderWhoami(w) {
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
  applyComplianceUi();
}
// ENTERPRISE identity flags (from whoami.enterprise). Community default = {} => every helper false.
export let ENTERPRISE = {};
export function identityOn() { return !!(ENTERPRISE && (ENTERPRISE.sso || ENTERPRISE.scim)); }
export function identityAdmin() { return !!(identityOn() && isAdmin()); }
// Dé-masque le lien nav #identity (admin + flag engagé) ; ré-oriente hors #identity si non autorisé.
// Défense en profondeur : le serveur reste l'autorité (routes flag+admin -> 404/403).
export function applyIdentityUi() {
  const link = $('#nav-identity');
  if (link) link.hidden = !identityAdmin();
  if (!identityAdmin() && location.hash.slice(1) === 'identity') location.hash = 'overview';
}
// SSO (ENTERPRISE) : disponibilité d'une connexion OIDC interactive, sondée pré-auth via GET
// /api/setup/state (sso.enabled). false en community (flag OFF / non configuré) => aucun bouton SSO.
export let SSO_LOGIN = false;
export function showLogin() {
  document.body.classList.add('gated');
  const sv = $('#setup-view'); if (sv) sv.hidden = true;
  const v = $('#login-view'); if (v) v.hidden = false;
  // Bouton "Se connecter avec le SSO" — affiché seulement si le serveur offre le SSO (flag + configuré).
  const sso = $('#login-sso'); if (sso) sso.hidden = !SSO_LOGIN;
  const u = $('#login-user'); if (u) setTimeout(() => { try { u.focus(); } catch (e) {} }, 40);
}
// Redirige vers le flux OIDC Authorization-Code + PKCE (le serveur pose ensuite forge_session au callback).
if ($('#login-sso-btn')) $('#login-sso-btn').addEventListener('click', () => { window.location.href = '/api/sso/login'; });
export function showApp() {
  document.body.classList.remove('gated');
  const v = $('#login-view'); if (v) v.hidden = true;
  const sv = $('#setup-view'); if (sv) sv.hidden = true;
}
export function loginErr(msg) { const e = $('#login-err'); if (e) { e.textContent = msg; e.hidden = false; } }
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
export async function doLogout() {
  try { await fetch('/api/logout', { method: 'POST', headers: { Accept: 'application/json' } }); } catch (e) { /* endpoint absent : sans effet */ }
  try { document.cookie = 'forge_session=; Path=/; Max-Age=0; SameSite=Strict'; } catch (e) {}
  setOperatorSecret('');
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
export let SETUP_STEP = 1;
export const SETUP_MAX = 4;
export let SETUP_DET_FORM = null; // composant source de détection partagé (étape 3 du wizard)
export function showSetup(state) {
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
export function setupErr(msg) { const e = $('#setup-err'); if (e) { e.textContent = msg || ''; e.hidden = !msg; } }
export function setupGoto(n) {
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
export function setupValidateStep1() {
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
export function setupBuildPayload() {
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
export async function setupSubmit() {
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
export async function bootApp() {
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
