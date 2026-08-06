import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { toast } from '../../core/ui.js';

// =====================================================================================
//  ADMINISTRATION — SLA DE TRIAGE (budgets par severite)
//
//  Contrepartie UI de GET/POST /api/notify/sla. Ce panneau n'arme PAS un canal : il arme une HORLOGE.
//  Ce qui remonte passe par les notifications in-app, et donc — si et seulement si le canal sortant est
//  lui-meme arme — par CE canal et ses redactions. Il n'y a pas de sortie propre au SLA.
//
//  Le GET porte `overdue_now` : le nombre de findings ACTUELLEMENT en retard selon la politique
//  ENREGISTREE, deja signales compris. C'est un APERCU en LECTURE SEULE (il ne notifie personne) — de
//  quoi calibrer des budgets sans armer la politique et regarder qui se fait spammer.
// =====================================================================================

function el(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  Object.entries(attrs || {}).forEach(([k, v]) => { if (k === 'text') e.textContent = v; else e.setAttribute(k, v); });
  return e;
}

export async function loadAdminNotifySla() {
  const host = $('#admin-sla-body'); if (!host) return;
  const badge = $('#admin-sla-state');
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if (badge) badge.textContent = '—'; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/notify/sla'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const pol = (data && data.policy) || {};
  const budgets = pol.budgets || {};
  const severities = (data && data.severities) || ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  if (badge) badge.textContent = data && data.enabled ? 'arme' : 'off';

  host.replaceChildren();
  const form = el('div', 'det-form');

  const enabled = el('input', null, { type: 'checkbox', id: 'sla-enabled' });
  enabled.checked = !!pol.enabled;
  const rowE = el('div', 'det-row');
  rowE.appendChild(enabled);
  rowE.appendChild(el('label', null, {
    for: 'sla-enabled',
    text: ' Activer le balayage SLA (off par defaut — sans budget positif, la politique reste inerte)',
  }));

  // Un champ d'heures PAR SEVERITE. Vide ou 0 = cette severite n'a PAS de SLA (jamais en retard).
  const rowB = el('div', 'det-row');
  rowB.appendChild(el('label', null, { text: 'Budget de triage par severite (heures ; 0 ou vide = aucun SLA pour cette severite)' }));
  const grid = el('div', 'det-form');
  const inputs = {};
  severities.forEach((s) => {
    const i = el('input', null, { type: 'number', min: '0', id: `sla-b-${s}`, placeholder: '0' });
    const v = budgets[s];
    i.value = (typeof v === 'number' && v > 0) ? String(v) : '';
    inputs[s] = i;
    const line = el('div', 'det-row');
    line.appendChild(el('label', null, { for: `sla-b-${s}`, text: s }));
    line.appendChild(i);
    grid.appendChild(line);
  });
  rowB.appendChild(grid);

  const esc2 = el('input', null, { type: 'text', id: 'sla-escalate', placeholder: 'login (facultatif)' });
  esc2.value = pol.escalate_to || '';
  const rowX = el('div', 'det-row');
  rowX.appendChild(el('label', null, {
    for: 'sla-escalate',
    text: 'Escalade des findings NON ASSIGNES (un seul login ; vide = ils sont comptes, jamais diffuses)',
  }));
  rowX.appendChild(esc2);

  form.appendChild(rowE); form.appendChild(rowB); form.appendChild(rowX);
  host.appendChild(form);

  // Le rouge se declenche AUSSI sur `capped` : un apercu tronque n'est pas rassurant, il est INCONNU.
  // Sans ca, « 0 en retard » sur une fenetre saturee se lit comme « tout va bien » — exactement la
  // panne de surveillance silencieuse corrigee cote serveur.
  const state = el('div', (data && (data.overdue_now || data.capped)) ? 'det-testres bad' : 'det-testres muted');
  state.textContent = `Apercu (lecture seule, ne notifie personne) : ${data && data.overdue_now || 0} finding(s) `
    + `actuellement en retard selon la politique ENREGISTREE — deja signales compris. `
    + `Etats de triage consideres comme OUVERTS : ${(data && data.open_triage || []).join(', ')}. `
    + `Au plus ${data && data.max_sweep_rows || 0} findings examines par balayage.`
    + (data && data.capped
        ? ` ATTENTION : apercu TRONQUE au plafond (${data && data.max_sweep_rows || 0} lignes lues) —`
          + ` il peut rester des retards NON COMPTES au-dela de la fenetre.`
        : '');
  host.appendChild(state);

  const note = el('div', 'muted');
  note.textContent = 'L\'horloge part de la DATE DE CREATION du finding et s\'arrete des que le triage quitte '
    + 'les etats ouverts. Un finding en retard produit AU PLUS UNE notification, jamais une par balayage. '
    + 'La remontee emprunte la porte des notifications : elle est grant-scopee (multi-tenant) et, si le '
    + 'canal sortant est arme, elle en herite les redactions. Sous HA, seul le leader balaie. Aucune '
    + 'colonne nouvelle : severite, etat de triage et date de creation suffisent.';
  host.appendChild(note);

  const act = el('div', 'det-actions');
  const saveBtn = el('button', 'login-btn det-save', { type: 'button', text: 'Enregistrer' });
  act.appendChild(saveBtn);
  host.appendChild(act);

  saveBtn.addEventListener('click', async () => {
    const b = {};
    let bad = null;
    severities.forEach((s) => {
      const raw = inputs[s].value.trim();
      if (!raw) return;
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 0) { bad = s; return; }
      if (n > 0) b[s] = n;
    });
    if (bad) { toast(`Budget invalide pour ${bad} : un nombre entier d'heures est attendu.`, 'bad'); return; }
    saveBtn.disabled = true;
    try {
      await adminApi('/notify/sla', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ policy: { enabled: enabled.checked, budgets: b, escalate_to: esc2.value.trim() } }),
      });
      toast('Politique SLA enregistree.', 'ok');
      loadAdminNotifySla();
    } catch (e) { toast('Enregistrement refuse : ' + e.message, 'bad'); }
    finally { saveBtn.disabled = false; }
  });
}
