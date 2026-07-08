
// =====================================================================================
//  ENGAGEMENT ACTIF (objet de 1re classe — à la workspace Metasploit)
// =====================================================================================
// L'engagement actif est persisté CÔTÉ CLIENT (localStorage) et ajouté à CHAQUE requête via
// `?engagement=<id>`. Le serveur FILTRE les vues (findings/runrecords/roe/ledger/coverage/runs) sur
// cet id -> un engagement ne voit JAMAIS les données d'un autre. Absent -> le serveur retombe sur
// l'engagement actif le plus récent (défaut mono-engagement = #1, rétro-compat).
export let ENGAGEMENTS = [];        // dernière liste connue (id/name/status/mode/counts) pour le sélecteur + vue
export function activeEngagement() {
  const v = localStorage.getItem('forge_engagement');
  const n = v == null ? NaN : parseInt(v, 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}
export function setActiveEngagement(id) {
  if (id == null) localStorage.removeItem('forge_engagement');
  else localStorage.setItem('forge_engagement', String(id));
}
export function activeEngagementName() {
  const id = activeEngagement();
  const e = ENGAGEMENTS.find(x => x.id === id) || ENGAGEMENTS.find(x => x.status === 'active') || ENGAGEMENTS[0];
  return e ? e.name : '';
}
// Ajoute ?engagement=<id> à une URL/chemin quelconque (idempotent : ne double jamais le param).
export function withEngagement(url) {
  const id = activeEngagement();
  if (id == null || /[?&]engagement=/.test(url)) return url;
  return url + (url.includes('?') ? '&' : '?') + 'engagement=' + id;
}

export function setEngagements(v) { ENGAGEMENTS = v; }
export function getEngagements() { return ENGAGEMENTS; }
