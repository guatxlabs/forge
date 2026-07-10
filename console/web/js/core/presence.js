// Forge — PRÉSENCE (#9) : indicateur multi-opérateur LIVE (qui est connecté sur l'engagement actif).
//
// Transport : un EventSource sur /api/presence/events?engagement=<id> (cookie de session porté
// automatiquement — même auth que le SSE des runs). CHAQUE event `presence` (join/leave/sync/resync)
// signifie « quelque chose a changé » -> on re-fetch /api/presence?engagement=<id> et on re-rend (pas de
// reconstruction incrémentale -> aucune désync possible). Un heartbeat POST périodique maintient le TTL
// même si le proxy bufferise le flux. Sur changement d'engagement, on relance le flux avec le nouvel id.
//
// Discret : masqué tant qu'il n'y a personne d'autre que soi. Aucune dépendance externe, ES-module pur.

import { $, esc, ic } from './dom.js';
import { activeEngagement } from './state.js';

let ES = null;                 // EventSource courant (null si fermé)
let HB = null;                 // timer de heartbeat
let CUR_ENG = undefined;       // engagement du flux courant (pour ne relancer que si changé)
const HEARTBEAT_MS = 20000;    // < TTL serveur (45 s) — garde la présence fraîche
const MAX_AVATARS = 4;         // au-delà, on agrège en « +N »

// Initiales d'un login (1-2 lettres) pour l'avatar.
function initials(login) {
  const s = String(login || '?').trim();
  const parts = s.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]);
  return s.slice(0, 2);
}

// Rend l'indicateur depuis le roster serveur ({count, operators:[{login,role,self,...}]}).
function renderPresence(data) {
  const box = $('#presence');
  const avatars = $('#presence-avatars');
  const count = $('#presence-count');
  if (!box || !avatars || !count) return;
  const ops = Array.isArray(data && data.operators) ? data.operators : [];
  const others = ops.filter(o => !o.self).length;
  // Discret : on n'affiche l'indicateur QUE si au moins un autre opérateur est présent.
  if (others < 1) { box.hidden = true; avatars.replaceChildren(); return; }
  box.hidden = false;

  // Ordre d'affichage : soi en premier (repère), puis les autres. On chevauche via flex-row-reverse
  // (le DOM est en ordre inverse pour que le premier avatar soit au-dessus de la pile).
  const ordered = [...ops].sort((a, b) => (a.self === b.self ? 0 : a.self ? -1 : 1));
  const shown = ordered.slice(0, MAX_AVATARS);
  const extra = ops.length - shown.length;

  const frag = document.createDocumentFragment();
  if (extra > 0) {
    const more = document.createElement('span');
    more.className = 'pav more';
    more.textContent = '+' + extra;
    frag.appendChild(more);
  }
  // insérés en ordre inverse (flex-row-reverse remet visuellement le 1er en tête).
  [...shown].reverse().forEach(o => {
    const el = document.createElement('span');
    el.className = 'pav' + (o.self ? ' self' : '');
    el.textContent = initials(o.login);
    el.title = esc(o.login) + (o.role ? ' (' + esc(o.role) + ')' : '') + (o.self ? ' — vous' : '');
    frag.appendChild(el);
  });
  avatars.replaceChildren(frag);

  // ic('user') = SVG CONSTANTE (dom.js), ops.length = entier -> aucune donnée non fiable dans l'innerHTML.
  count.innerHTML = ic('user') + ops.length;
  count.title = ops.length + ' opérateur' + (ops.length > 1 ? 's' : '') + ' connecté' + (ops.length > 1 ? 's' : '') + ' sur cet engagement';
}

// Re-fetch du roster (scopé à l'engagement actif) + rendu. Fail-soft : une erreur laisse l'état courant.
async function refreshRoster() {
  const eng = activeEngagement();
  const url = '/api/presence' + (eng != null ? ('?engagement=' + encodeURIComponent(eng)) : '');
  try {
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) return;
    const data = await r.json().catch(() => null);
    if (data) renderPresence(data);
  } catch (e) { /* transitoire : on re-fetch au prochain event/heartbeat */ }
}

// Heartbeat léger : maintient le TTL côté serveur même si le flux SSE est bufferisé par un proxy.
async function heartbeat() {
  try { await fetch('/api/presence/heartbeat', { method: 'POST', headers: { Accept: 'application/json' } }); }
  catch (e) { /* best-effort */ }
}

// Ferme proprement le flux + le timer courants.
function stopPresence() {
  if (ES) { try { ES.close(); } catch (e) {} ES = null; }
  if (HB) { clearInterval(HB); HB = null; }
}

// (Re)démarre le flux de présence pour l'engagement ACTIF. No-op si l'engagement n'a pas changé et que le
// flux est déjà ouvert (évite de churner join/leave à chaque route()).
export function restartPresence() {
  const eng = activeEngagement();
  if (ES && CUR_ENG === eng) return; // déjà branché sur le bon engagement
  stopPresence();
  CUR_ENG = eng;
  // Le cookie de session est porté automatiquement (EventSource same-origin) — même auth que le SSE runs.
  const url = '/api/presence/events' + (eng != null ? ('?engagement=' + encodeURIComponent(eng)) : '');
  try { ES = new EventSource(url); }
  catch (e) { ES = null; }
  if (ES) {
    // Tout event de présence = « re-fetch le roster ».
    ES.addEventListener('presence', () => { refreshRoster(); });
    ES.onerror = () => { /* EventSource re-tente seul ; le heartbeat + refresh maintiennent l'UI */ };
  }
  refreshRoster();
  HB = setInterval(() => { heartbeat(); refreshRoster(); }, HEARTBEAT_MS);
}

// Point d'entrée (appelé au boot, après le sélecteur d'engagement). Ferme le flux quand l'onglet part.
export function initPresence() {
  restartPresence();
  window.addEventListener('beforeunload', stopPresence);
}
