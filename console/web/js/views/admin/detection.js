import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { toast } from '../../core/ui.js';
import { detEl, detectionSourceForm } from '../../components/detection-source-form.js';

// =====================================================================================
//  SOURCE DE DÉTECTION — panneau admin (le composant de formulaire vit dans
//  js/components/detection-source-form.js, partagé avec le wizard de 1er déploiement).
// =====================================================================================
// --- Panneau admin « source de détection » : GET config (secret rédigé) -> monte le composant + actions
//     (Tester / Enregistrer). POST /api/detection/source (admin, ledgerisé) ; POST /api/detection/test.
export let ADMIN_DET_FORM = null;
export async function loadAdminDetection() {
  const host = $('#admin-det-form'); if (!host) return;
  const kindBadge = $('#admin-det-kind');
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if (kindBadge) kindBadge.textContent = '—'; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/detection/source'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const src = (data && data.source) || { kind: 'none' };
  const secretSet = !!(data && data.secret_set);
  host.replaceChildren();
  const formHost = detEl('div');
  host.appendChild(formHost);
  ADMIN_DET_FORM = detectionSourceForm(formHost);
  ADMIN_DET_FORM.setConfig(src, secretSet);
  if (kindBadge) kindBadge.textContent = src.kind || 'none';
  // barre d'actions + zone de résultat de test.
  const act = detEl('div', 'det-actions');
  const testBtn = detEl('button', 'k-theme', { type: 'button', text: 'Tester la connexion' });
  const saveBtn = detEl('button', 'login-btn det-save', { type: 'button', text: 'Enregistrer' });
  act.appendChild(testBtn); act.appendChild(saveBtn);
  host.appendChild(act);
  const resBox = detEl('div', 'det-testres muted');
  host.appendChild(resBox);

  testBtn.addEventListener('click', async () => {
    const { config, keepSecret, error } = ADMIN_DET_FORM.getConfig();
    if (error) { toast(error, 'bad'); return; }
    resBox.className = 'det-testres muted'; resBox.textContent = 'test en cours…';
    testBtn.disabled = true;
    try {
      const r = await adminApi('/detection/test', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ detection_source: config, keep_secret: keepSecret }),
      });
      const reachable = !!(r && r.reachable);
      const samples = (r && Array.isArray(r.sample_mitres)) ? r.sample_mitres : [];
      resBox.className = 'det-testres ' + (reachable ? 'ok' : 'bad');
      resBox.textContent = reachable
        ? `joignable — ${r.count || 0} détection(s)${samples.length ? ' · ' + samples.join(', ') : ''}`
        : `injoignable — ${(r && r.error) ? r.error : 'source_reachable:false'}`;
    } catch (e) { resBox.className = 'det-testres bad'; resBox.textContent = 'test refusé : ' + e.message; }
    finally { testBtn.disabled = false; }
  });
  saveBtn.addEventListener('click', async () => {
    const { config, keepSecret, error } = ADMIN_DET_FORM.getConfig();
    if (error) { toast(error, 'bad'); return; }
    saveBtn.disabled = true;
    try {
      await adminApi('/detection/source', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ detection_source: config, keep_secret: keepSecret }),
      });
      toast('Source de détection enregistrée.', 'ok');
      loadAdminDetection(); // recharge (secret rédigé, secret_set à jour)
    } catch (e) { toast('Enregistrement refusé : ' + e.message, 'bad'); }
    finally { saveBtn.disabled = false; }
  });
}
