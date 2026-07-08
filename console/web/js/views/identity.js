import { adminApi, token } from '../core/api.js';
import { ENTERPRISE, identityAdmin, identityOn } from '../core/auth.js';
import { $, esc } from '../core/dom.js';
import { guardList, toast } from '../core/ui.js';

// =====================================================================================
//  IDENTITY / SSO (ENTERPRISE, flag-gated) — vue #identity : (1) provider OIDC, (2) token SCIM,
//  (3) mapping groupe -> rôle/grant (RBAC avancé). Réservé admin + flag engagé (identityAdmin()).
//  Le serveur reste l'autorité (routes flag+admin -> 404/403) ; ce masquage = défense en profondeur.
//  Les secrets (client_secret, token SCIM) sont write-only : jamais réaffichés par les GET.
// =====================================================================================
export function idErr(id, msg) { const e = $(id); if (e) { e.textContent = msg; e.hidden = !msg; } }

export async function loadIdentity() {
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
export async function loadIdentityOidc() {
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
export async function loadIdentityScim() {
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
export async function loadIdentityMap() {
  const host = $('#id-map-list'); if (!host) return;
  let data = null;
  try { data = await adminApi('/rbac/group-map'); } catch (e) { host.innerHTML = '<div class="muted">Chargement refusé : ' + esc(e.message) + '</div>'; return; }
  const rows = (data && Array.isArray(data.mappings)) ? data.mappings : [];
  if (guardList(host, rows, 'Aucun mapping — un groupe non mappé ne confère aucun droit (moindre privilège).')) return;
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

