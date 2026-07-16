import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { modalConfirm, toast } from '../../core/ui.js';

// =====================================================================================
//  POLITIQUE RÉSEAU — MASTER SWITCH GLOBAL (panneau #admin-network, réservé role=admin).
//  Le « gros bouton rouge » instance-wide : GET/POST /api/network-policy {allow_private}. OFF (défaut
//  sûr) => AUCUN engagement ne peut scanner de cible privée/LAN/loopback. Passer sur ON n'ouvre RIEN à
//  lui seul : l'effectif = ce master AND l'opt-in par engagement AND le scope (trois portes fail-closed).
//  Le serveur reste l'autorité (check_admin -> 403). La bascule utilise la modale stylée (jamais confirm()
//  natif) et est ledgerisée `console.settings.network_policy` (old->new).
// =====================================================================================
export async function loadAdminNetwork() {
  const host = $('#admin-net-body'); if (!host) return;
  const badge = $('#admin-net-state');
  if (!isAdmin()) {
    host.innerHTML = '<div class="muted">réservé aux administrateurs</div>';
    if (badge) { badge.textContent = '—'; badge.className = 'badge mut'; }
    return;
  }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/network-policy'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const on = !!(data && data.allow_private);
  if (badge) {
    badge.textContent = on ? 'ON — scan privé autorisé' : 'OFF — sûr (défaut)';
    badge.className = 'badge ' + (on ? 'destr' : 'ok');
  }
  host.replaceChildren();
  const line = document.createElement('div');
  line.className = 'muted';
  line.style.margin = '0 0 8px';
  line.textContent = on
    ? 'Master global ACTIF : les engagements qui ont coché leur opt-in peuvent scanner des cibles privées/LAN/loopback in-scope. Repasser sur OFF re-verrouille TOUT immédiatement, sans redémarrage.'
    : 'Master global INACTIF (défaut sûr) : aucun scan de cible privée/LAN/loopback possible, quel que soit l\'engagement.';
  host.appendChild(line);

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = on ? 'k-theme' : 'login-btn';
  btn.textContent = on ? 'Désactiver le scan privé (repasser en sûr)' : 'Activer le scan privé (master global)';
  host.appendChild(btn);

  btn.addEventListener('click', async () => {
    const next = !on;
    const ok = await modalConfirm({
      title: 'Politique réseau — master global',
      message: next
        ? 'ACTIVER le master global de scan des cibles PRIVÉES / LAN / loopback pour TOUTE l\'instance ? '
          + 'Rappel : cela n\'ouvre rien à lui seul — chaque engagement doit AUSSI activer son opt-in et la cible '
          + 'doit être dans son scope. La bascule est ledgerisée.'
        : 'DÉSACTIVER le master global ? Tous les engagements repassent immédiatement en mode sûr '
          + '(aucun scan de cible privée/LAN/loopback possible), sans redémarrage. La bascule est ledgerisée.',
      confirmText: next ? 'Activer' : 'Désactiver',
      danger: true,
    });
    if (!ok) return;
    btn.disabled = true;
    try {
      await adminApi('/network-policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ allow_private: next }),
      });
      toast('Politique réseau ' + (next ? 'activée' : 'désactivée') + ' (ledgerisée).', 'ok');
      await loadAdminNetwork();
    } catch (e) {
      toast('Bascule refusée : ' + e.message, 'bad');
      btn.disabled = false;
    }
  });
}
