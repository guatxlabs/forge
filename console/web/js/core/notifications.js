// Forge — NOTIFICATIONS (triage enrichi) : cloche + badge non-lu + panneau, in-app, PERSONNEL.
//
// Transport : un EventSource sur /api/notifications/events (cookie de session porté automatiquement —
// même auth que le SSE présence/runs). Le serveur ne FORWARDE que les notifs de CET utilisateur (filtre
// user_id côté serveur). CHAQUE event `notification` (nouvelle notif / sync / resync) signifie « quelque
// chose a changé » -> on re-fetch /api/notifications et on re-rend (pas de reconstruction incrémentale ->
// aucune désync possible). Discret : la cloche est masquée tant qu'il n'y a AUCUNE notif.
//
// Sécurité : tout texte de notification est inséré via textContent (JAMAIS innerHTML) -> aucune injection
// possible via un titre de finding / un login. Aucune dépendance externe, ES-module pur.

import { $, fmtTs } from './dom.js';
import { activeEngagement } from './state.js';
import { openFinding } from '../views/findings.js';
import { switchEngagement } from '../views/engagements.js';

let ES = null;             // EventSource courant (null si fermé)
let PANEL_OPEN = false;    // état du panneau déroulant
let ITEMS = [];            // dernière page connue (pour le rendu du panneau)
let UNREAD = 0;            // compteur non-lu courant (badge)

// Rend le badge (compteur non-lu) + la visibilité de la cloche. La cloche apparaît dès qu'il existe ≥1
// notification (lue ou non) ; le badge n'apparaît que s'il y a des NON-LUES.
function renderBadge() {
  const box = $('#notif');
  const badge = $('#notif-badge');
  const bell = $('#notif-bell');
  if (!box || !badge || !bell) return;
  // Discret : masqué tant qu'il n'y a rien du tout (aucune notif ET aucune non-lue).
  const hasAny = ITEMS.length > 0 || UNREAD > 0;
  box.hidden = !hasAny;
  if (UNREAD > 0) {
    badge.hidden = false;
    badge.textContent = UNREAD > 99 ? '99+' : String(UNREAD);
    bell.setAttribute('title', UNREAD + ' notification' + (UNREAD > 1 ? 's' : '') + ' non lue' + (UNREAD > 1 ? 's' : ''));
  } else {
    badge.hidden = true;
    bell.setAttribute('title', 'Notifications');
  }
}

// Rend la liste du panneau depuis ITEMS. Texte via textContent (anti-XSS). Chaque ligne lie son finding.
function renderList() {
  const list = $('#notif-list');
  if (!list) return;
  list.replaceChildren();
  if (!ITEMS.length) {
    const empty = document.createElement('div');
    empty.className = 'muted';
    empty.textContent = 'Aucune notification.';
    list.appendChild(empty);
    return;
  }
  ITEMS.forEach(n => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'notif-item' + (n.read ? '' : ' unread');
    row.setAttribute('role', 'menuitem');

    const dot = document.createElement('span');
    dot.className = 'notif-dot' + (n.read ? ' read' : '');
    dot.setAttribute('aria-hidden', 'true');

    const main = document.createElement('span');
    main.className = 'notif-main';
    const txt = document.createElement('span');
    txt.className = 'notif-text';
    txt.textContent = String(n.text || '');          // textContent : échappement garanti (anti-XSS)
    const meta = document.createElement('span');
    meta.className = 'notif-meta muted';
    const kindLbl = n.kind === 'finding.triage' ? 'triage' : (n.kind === 'finding.assigned' ? 'assignation' : String(n.kind || ''));
    meta.textContent = kindLbl + ' · ' + fmtTs(n.created);
    main.append(txt, meta);

    row.append(dot, main);
    row.addEventListener('click', () => onOpen(n));
    list.appendChild(row);
  });
}

// Ouvre le finding d'une notif : marque la notif lue, bascule d'engagement si nécessaire, navigue vers la
// vue Findings et ouvre le détail. Fail-soft à chaque étape.
async function onOpen(n) {
  try { if (!n.read) await markRead([n.id]); } catch (e) { /* best-effort */ }
  closePanel();
  const eng = n.engagement_id;
  if (eng != null && eng !== activeEngagement()) {
    try { switchEngagement(eng); } catch (e) { /* fail-soft */ }
  }
  if (n.finding_id != null) {
    location.hash = 'findings';
    try { await openFinding(n.finding_id); } catch (e) { /* le toast d'openFinding gère l'échec */ }
  }
}

// Re-fetch de la boîte (fail-soft : une erreur laisse l'état courant).
async function refresh() {
  try {
    const r = await fetch('/api/notifications', { headers: { Accept: 'application/json' } });
    if (!r.ok) return;
    const data = await r.json().catch(() => null);
    if (!data) return;
    ITEMS = Array.isArray(data.notifications) ? data.notifications : [];
    UNREAD = Number.isInteger(data.unread) ? data.unread : 0;
    renderBadge();
    if (PANEL_OPEN) renderList();
  } catch (e) { /* transitoire : re-fetch au prochain event */ }
}

// Marque LUES (les miennes) : ids fourni -> ce sous-ensemble ; null -> toutes. Re-fetch ensuite.
async function markRead(ids) {
  const body = ids && ids.length ? { ids } : {};
  try {
    await fetch('/api/notifications/read', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) { /* best-effort */ }
  await refresh();
}

function openPanel() {
  const panel = $('#notif-panel'); const bell = $('#notif-bell');
  if (!panel) return;
  PANEL_OPEN = true;
  panel.hidden = false;
  if (bell) bell.setAttribute('aria-expanded', 'true');
  renderList();
  refresh();
}
function closePanel() {
  const panel = $('#notif-panel'); const bell = $('#notif-bell');
  PANEL_OPEN = false;
  if (panel) panel.hidden = true;
  if (bell) bell.setAttribute('aria-expanded', 'false');
}
function togglePanel() { PANEL_OPEN ? closePanel() : openPanel(); }

// Ferme proprement le flux SSE courant.
function stop() { if (ES) { try { ES.close(); } catch (e) {} ES = null; } }

// (Re)démarre le flux SSE des notifications. Tout event = « re-fetch la boîte ».
function start() {
  stop();
  try { ES = new EventSource('/api/notifications/events'); } catch (e) { ES = null; }
  if (ES) {
    ES.addEventListener('notification', () => { refresh(); });
    ES.onerror = () => { /* EventSource re-tente seul ; le refresh au prochain event maintient l'UI */ };
  }
}

// Point d'entrée (appelé au boot, après whoami). Câble la cloche + le bouton « tout marquer lu » +
// la fermeture au clic extérieur, ouvre le flux LIVE et charge l'état initial.
export function initNotifications() {
  const bell = $('#notif-bell');
  const readall = $('#notif-readall');
  if (bell && !bell.dataset.wired) {
    bell.dataset.wired = '1';
    bell.addEventListener('click', (ev) => { ev.stopPropagation(); togglePanel(); });
  }
  if (readall && !readall.dataset.wired) {
    readall.dataset.wired = '1';
    readall.addEventListener('click', (ev) => { ev.stopPropagation(); markRead(null); });
  }
  // Clic hors du panneau -> ferme (ne pas fermer si le clic est dans le panneau/cloche).
  if (!document.body.dataset.notifOutside) {
    document.body.dataset.notifOutside = '1';
    document.addEventListener('click', (ev) => {
      if (!PANEL_OPEN) return;
      const box = $('#notif');
      if (box && !box.contains(ev.target)) closePanel();
    });
  }
  window.addEventListener('beforeunload', stop);
  start();
  refresh();
}
