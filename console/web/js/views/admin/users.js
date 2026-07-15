import { adminApi } from '../../core/api.js';
import { ROLE_CLASSES, WHOAMI, isAdmin } from '../../core/auth.js';
import { $, esc, fmtTs } from '../../core/dom.js';
import { confirmModal, guardList, modal, toast } from '../../core/ui.js';

export const ADMIN_ROLES = [
  { value: 'viewer', label: 'viewer — lecture seule' },
  { value: 'operator', label: 'operator — arme les campagnes' },
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
      { name: 'role', label: 'Role', type: 'select', options: ADMIN_ROLES, value: 'viewer', hint: 'viewer = lecture seule (aucun tir) · operator = arme et lance les campagnes (opt-in fort impact possible) · admin = administre comptes, connecteurs, source de détection et sauvegardes. Attribuez le minimum requis.' },
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
    fields: [{ name: 'role', label: 'Role', type: 'select', options: ADMIN_ROLES, value: u.role, hint: 'viewer = lecture seule · operator = arme/lance les campagnes · admin = administration complète. Rétrograder révoque immédiatement les sessions du compte.' }],
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
