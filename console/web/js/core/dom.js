// Forge — console (front Aurora). Porte la richesse de Plume (viz/explore/dashboards drag+resize,
// modales/toasts, drilldown/zoom) et l'adapte aux endpoints réels du moteur Forge.
//   lectures : /api/overview-like agrégées via /api/findings|modules|coverage|campaigns|roe|ledger
//   requêtes : POST /api/query {soql} -> {columns, rows[[...]], total, stats, compiled}
//   panels   : /api/panels (POST/POST :id/DELETE :id : Bearer token) + /api/panels/:id/data
export const $ = s => document.querySelector(s);
// lit une variable de thème CSS (graphes SVG theme-aware : se recolorent au changement clair/sombre)
export const CSSV = (n, d) => (getComputedStyle(document.documentElement).getPropertyValue(n).trim() || d);
export const LANG = 'fr';
export const LOC = 'fr-FR';
export const fmtTs = t => {                                   // ts Forge = chaîne SQLite "YYYY-MM-DD HH:MM:SS" (UTC) OU epoch
  if (t == null || t === '') return '-';
  if (typeof t === 'number' || /^\d+$/.test(String(t))) { const n = Number(t); return new Date((n > 2e10 ? n : n * 1000)).toLocaleString(LOC); }
  const d = new Date(String(t).replace(' ', 'T') + (String(t).includes('Z') ? '' : 'Z'));
  return isNaN(d.getTime()) ? String(t) : d.toLocaleString(LOC);
};
// sévérités Forge = chaînes (CRITICAL/HIGH/MEDIUM/LOW/INFO). On les normalise pour les classes CSS.
export const SEVKEY = s => { const u = String(s || '').toUpperCase(); return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(u) ? u : 'INFO'; };
export const SEVRANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
export const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// --- icônes SVG inline (zéro caractère non-ASCII dans l'UI ; héritent la couleur via currentColor) ---
export const ICONS = {
  home: '<path d="M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>',
  flask: '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3"/><path d="M7 14h10"/>',
  layout: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  wrench: '<path d="M21 4a5 5 0 0 1-6 6L7 18l-3-3 8-8a5 5 0 0 1 6-6l-3 3 2 2z"/>',
  bell: '<path d="M6 9a6 6 0 0 1 12 0c0 7 3 7 3 7H3s3 0 3-7"/><path d="M10 21a2 2 0 0 0 4 0"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  plug: '<path d="M9 3v6M15 3v6M7 9h10v3a5 5 0 0 1-10 0zM12 17v4"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  save: '<path d="M5 3h11l3 3v15H5z"/><path d="M8 3v6h7M8 21v-6h8v6"/>',
  play: '<path d="M7 4l13 8-13 8z"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  pencil: '<path d="M4 20h4L20 8l-4-4L4 16z"/>',
  x: '<path d="M5 5l14 14M19 5L5 19"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M19 13v6H5V5h6"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 18h.01"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  moon: '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
  bars: '<path d="M4 20V10M10 20V4M16 20v-7M2 20h20"/>',
  hash: '<path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/>',
  table: '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 10h18M9 4v16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  chevdown: '<path d="M6 9l6 6 6-6"/>',
  chevright: '<path d="M9 6l6 6-6 6"/>',
  grip: '<circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/>',
  lock: '<rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.4 2.4 0 0 1 4.4 1.3c0 1.6-2 1.9-2.4 3.3"/><path d="M12 17.2h.01"/>',
  book: '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19a2 2 0 0 1 2-2h13"/>',
};
export const ic = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;

// safeHtml`...` : gabarit balisé qui ECHAPPE AUTOMATIQUEMENT chaque interpolation via esc() (même
// contrat que les interpolations `${esc(x)}` open-codées, mais impossible à oublier). Pour insérer un
// fragment déjà connu-HTML/contrôlé (ex: SEV_BADGE(), ic()), l'envelopper dans raw() -> inséré tel quel.
export function raw(x) { return { __raw: String(x == null ? '' : x) }; }
export function safeHtml(strings, ...vals) {
  let out = strings[0];
  for (let i = 0; i < vals.length; i++) {
    const v = vals[i];
    out += ((v && typeof v === 'object' && '__raw' in v) ? v.__raw : esc(v)) + strings[i + 1];
  }
  return out;
}
export const SEV_BADGE = s => `<span class="sevb sevb-${SEVKEY(s)}">${esc(String(s || '').toUpperCase() || 'INFO')}</span>`;

// TLP 2.0 (classification/diffusion, #15) — jeu FERMÉ (CLEAR|GREEN|AMBER|AMBER+STRICT|RED). TLP_KEY
// normalise (casse, préfixe `TLP:`, espace -> `+`) et renvoie '' pour toute valeur hors jeu (non
// classifié). TLP_BADGE rend un badge coloré (classe .tlpb-<clé>) ou '' si non classifié.
export const TLP_CLASSES = ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'];
export const TLP_KEY = s => { const u = String(s == null ? '' : s).toUpperCase().replace('TLP:', '').trim().replace(/ +/g, '+'); return TLP_CLASSES.includes(u) ? u : ''; };
export const TLP_BADGE = s => { const k = TLP_KEY(s); if (!k) return ''; const cls = k.replace('+', '-').toLowerCase(); return `<span class="tlpb tlpb-${cls}" title="Traffic Light Protocol 2.0 — TLP:${esc(k)}">TLP:${esc(k)}</span>`; };
// Vocabulaire de cycle de vie d'un finding (#15) — miroir du serveur (findings.rs::FINDING_STATUSES).
export const FINDING_STATUSES = ['new', 'triaged', 'confirmed', 'remediated', 'false_positive', 'accepted', 'wontfix'];
