import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { toast } from '../../core/ui.js';

// =====================================================================================
//  ADMINISTRATION — CANAL DE NOTIFICATION SORTANT (webhook)
//
//  Contrepartie UI de GET/POST /api/notify/channel (+ /test). Les notifications in-app restent la voie
//  par defaut : ce panneau arme LA SEULE sortie hors du processus. Il est donc explicitement un panneau
//  d'EGRESS, et il le dit.
//
//  Le jeton du canal est WRITE-ONLY : il n'est JAMAIS re-servi par le serveur. Le champ est donc vide a
//  chaque chargement et une case « Conserver le jeton enregistre » permet de corriger l'endpoint sans le
//  retaper (meme motif que le contexte auth d'engagement et la source de detection).
// =====================================================================================

function el(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  Object.entries(attrs || {}).forEach(([k, v]) => { if (k === 'text') e.textContent = v; else e.setAttribute(k, v); });
  return e;
}

export async function loadAdminNotifyChannel() {
  const host = $('#admin-notify-body'); if (!host) return;
  const badge = $('#admin-notify-state');
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if (badge) badge.textContent = '—'; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/notify/channel'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const ch = (data && data.channel) || { kind: 'none' };
  const auth = ch.auth || {};
  const secretSet = !!(data && data.secret_set);
  if (badge) badge.textContent = data && data.enabled ? 'arme' : 'off';

  host.replaceChildren();
  const form = el('div', 'det-form');

  const enabled = el('input', null, { type: 'checkbox', id: 'nch-enabled' });
  enabled.checked = !!ch.enabled;
  const lEnabled = el('label', null, { for: 'nch-enabled', text: ' Activer l\'envoi sortant (off par defaut — sans cela, aucun octet ne quitte le processus)' });
  const rowE = el('div', 'det-row'); rowE.appendChild(enabled); rowE.appendChild(lEnabled);

  const endpoint = el('input', null, { type: 'text', id: 'nch-endpoint', placeholder: 'http://collecteur.interne:8080/hook' });
  endpoint.value = ch.endpoint || '';
  const rowU = el('div', 'det-row');
  rowU.appendChild(el('label', null, { for: 'nch-endpoint', text: 'Endpoint (http:// uniquement — la console n\'a pas de client TLS ; terminer le TLS sur un relais)' }));
  rowU.appendChild(endpoint);

  const atype = el('select', null, { id: 'nch-authtype' });
  [['none', 'aucune'], ['bearer', 'Authorization: Bearer'], ['header', 'en-tete d\'API']].forEach(([v, l]) => {
    const o = el('option', null, { value: v, text: l }); if ((auth.type || 'none') === v) o.selected = true; atype.appendChild(o);
  });
  const aheader = el('input', null, { type: 'text', id: 'nch-authheader', placeholder: 'X-Forge-Token' });
  aheader.value = auth.header || '';
  const secret = el('input', null, { type: 'password', id: 'nch-secret', placeholder: secretSet ? '••••••• (enregistre)' : '' });
  const keep = el('input', null, { type: 'checkbox', id: 'nch-keep' });
  keep.checked = secretSet;
  const rowA = el('div', 'det-row');
  rowA.appendChild(el('label', null, { for: 'nch-authtype', text: 'Authentification du canal (jeton write-only : jamais re-servi en lecture)' }));
  rowA.appendChild(atype); rowA.appendChild(aheader); rowA.appendChild(secret);
  rowA.appendChild(keep); rowA.appendChild(el('label', null, { for: 'nch-keep', text: ' Conserver le jeton enregistre' }));

  form.appendChild(rowE); form.appendChild(rowU); form.appendChild(rowA);
  host.appendChild(form);

  const note = el('div', 'muted');
  note.textContent = 'Ce qui sort est MINIMAL et REDIGE : evenement, identifiants, et le texte passe par le '
    + 'redacteur des rapports puis par la neutralisation des URL (une URL de cible porte en general '
    + 'l\'identifiant de la victime). Les cibles internes (loopback, RFC1918, metadonnees cloud) sont '
    + 'refusees sauf FORGE_ALLOW_INTERNAL_INTEGRATIONS=1, et un jeton n\'est jamais envoye en clair vers '
    + 'une cible publique. Chaque envoi est journalise (canal, destinataire redige, issue) — jamais le contenu.';
  host.appendChild(note);

  const act = el('div', 'det-actions');
  const testBtn = el('button', 'k-theme', { type: 'button', text: 'Envoyer un test' });
  const saveBtn = el('button', 'login-btn det-save', { type: 'button', text: 'Enregistrer' });
  act.appendChild(testBtn); act.appendChild(saveBtn);
  host.appendChild(act);
  const resBox = el('div', 'det-testres muted');
  host.appendChild(resBox);

  saveBtn.addEventListener('click', async () => {
    const channel = {
      kind: 'webhook',
      enabled: enabled.checked,
      endpoint: endpoint.value.trim(),
      auth: { type: atype.value, header: aheader.value.trim() || 'X-Forge-Token' },
    };
    if (secret.value) channel.auth.secret = secret.value;
    saveBtn.disabled = true;
    try {
      await adminApi('/notify/channel', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ channel, keep_secret: keep.checked && !secret.value }),
      });
      toast('Canal de notification enregistre.', 'ok');
      loadAdminNotifyChannel();
    } catch (e) { toast('Enregistrement refuse : ' + e.message, 'bad'); }
    finally { saveBtn.disabled = false; }
  });

  // Le test utilise la config STOCKEE : l'endpoint n'est jamais un parametre de requete (sinon la route
  // deviendrait un proxy SSRF pour admin). Enregistrer d'abord, tester ensuite.
  testBtn.addEventListener('click', async () => {
    resBox.className = 'det-testres muted'; resBox.textContent = 'envoi en cours…';
    testBtn.disabled = true;
    try {
      const r = await adminApi('/notify/channel/test', { method: 'POST', headers: { Accept: 'application/json' } });
      const ok = !!(r && r.ok);
      resBox.className = 'det-testres ' + (ok ? 'ok' : 'bad');
      resBox.textContent = ok
        ? `envoye vers ${r.target} (HTTP ${r.status})`
        : `refuse/echoue : ${(r && r.why) || 'inconnu'}`;
    } catch (e) { resBox.className = 'det-testres bad'; resBox.textContent = 'test refuse : ' + e.message; }
    finally { testBtn.disabled = false; }
  });
}
