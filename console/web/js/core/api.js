import { $ } from './dom.js';
import { withEngagement } from './state.js';

// =====================================================================================
//  AUTH DES ÉCRITURES — modèle
// =====================================================================================
// Les écritures UI (panneaux, dashboards, config d'affichage) sont autorisées par la SESSION de
// l'utilisateur connecté (cookie HttpOnly `forge_session`, envoyé automatiquement en same-origin) :
// AUCUN token à coller. Côté serveur, `check_writer` exige un rôle admin|operator. Le token d'ingest
// (`FORGE_CONSOLE_TOKEN`) est réservé à l'ingest MACHINE (POST /api/ingest depuis le moteur/outils) et
// n'est plus jamais demandé dans l'UI — il est seulement RÉVÉLÉ (admin) dans le wizard et l'admin.

// =====================================================================================
//  API helpers
// =====================================================================================
export async function api(path) {
  // Toute LECTURE est scopée à l'engagement actif (withEngagement) — un endpoint qui ignore le param
  // le laisse inerte (sans effet), donc l'ajout global est sûr.
  const r = await fetch(withEngagement('/api' + path), { headers: { Accept: 'application/json' } });
  const body = await r.text().catch(() => '');
  // On NE PROPAGE PAS le corps brut du serveur dans Error.message (un proxy/gateway peut renvoyer
  // du HTML non-fiable -> XSS si rendu via innerHTML en aval). On ne remonte que le code HTTP et,
  // pour une erreur JSON structurée du backend, son champ `error` (string contrôlée par nous).
  if (!r.ok) {
    let detail = '';
    try { const j = JSON.parse(body); if (j && typeof j.error === 'string') detail = ' ' + j.error; } catch (e) {}
    throw new Error('HTTP ' + r.status + detail);
  }
  if (!body) throw new Error('réponse vide du serveur');
  try { return JSON.parse(body); } catch { throw new Error('réponse non-JSON du serveur (HTTP ' + r.status + ')'); }
}
export const campaignParam = () => { const c = $('#campaign') && $('#campaign').value; return c ? '?campaign=' + encodeURIComponent(c) : ''; };
export const withCampaign = qs => { const c = $('#campaign') && $('#campaign').value; if (!c) return qs; return qs + (qs.includes('?') ? '&' : '?') + 'campaign=' + encodeURIComponent(c); };

// Ecriture centralisée (POST/DELETE). Réunit ce que ~20 sites open-codaient : choix d'en-têtes selon
// `auth` (operator = X-Forge-Operator[+Bearer] ; token = Bearer viewer ; admin = cookie de session),
// sérialisation JSON du corps, scoping engagement/campagne (UNIQUEMENT quand le site le faisait déjà,
// via les flags), et la MÊME extraction anti-XSS que api() : on ne renvoie JAMAIS le corps brut du
// serveur (un proxy/gateway peut renvoyer du HTML non-fiable), seulement le JSON structuré parsé (dont
// les champs contrôlés .why/.error) + le code HTTP. Retour : { ok, status, json } (json = {} si vide/
// non-JSON, exactement comme `await r.json().catch(() => ({}))`). operatorHeaders() préserve son effet
// de bord (injection du secret opérateur). `auth: 'admin'` s'appuie sur le cookie de session (aucun
// en-tête d'auth ajouté — le serveur applique check_admin/check_writer sur la session).
export async function write(path, { method = 'POST', body, auth = 'operator', engagement = false, campaign = false } = {}) {
  let url = path;
  if (engagement) url = withEngagement(url);
  if (campaign) url = withCampaign(url);
  const hasBody = body !== undefined;
  const extra = hasBody ? { 'Content-Type': 'application/json' } : {};
  const headers = auth === 'admin' ? { ...extra, Accept: 'application/json' }
    : operatorHeaders(extra);
  const opts = { method, headers };
  if (hasBody) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  const text = await r.text().catch(() => '');
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch (e) { json = {}; }
  return { ok: r.ok, status: r.status, json };
}
export let OPERATOR_SECRET = '';            // mémoire de session : jamais persisté (ni localStorage ni cookie)
// en-têtes pour une écriture opérateur : opérateur (toujours) + viewer (Bearer) si l'auth viewer est ON.
// En dev-open (pas de pass_hash), seul X-Forge-Operator est requis ; le Bearer est inerte mais inoffensif.
// INVARIANT (anti-régression) : le secret opérateur ne transite QUE via l'en-tête X-Forge-Operator
// d'une requête POST (jamais en query-string ni dans un corps GET). Il NE DOIT JAMAIS être mis sur
// une URL EventSource/SSE (cf. startSse : EventSource ne peut pas porter d'en-tête -> on bascule en
// polling, on n'expose PAS le secret) ni loggé/persisté. Toute écriture opérateur passe par operatorHeaders().
export function operatorHeaders(extra = {}) {
  // Le secret opérateur voyage via X-Forge-Operator ; l'AUTHN viewer/opérateur repose sur le cookie
  // de session `forge_session` (HttpOnly), envoyé automatiquement par le navigateur. On N'ATTACHE PLUS
  // de `Authorization: Bearer <forge_token>` : ce token legacy n'est écrit par AUCUN build courant
  // (résidu localStorage d'un ancien build) et, prioritaire côté serveur, il MASQUAIT le cookie de
  // session valide -> écritures opérateur/admin en 401 (ex. POST /api/engagements). Cf. C14 / ROADMAP.
  return { 'X-Forge-Operator': OPERATOR_SECRET, ...extra };
}
// Appel API admin : renvoie le JSON parsé, lève une Error (avec .status) sur !ok. On ne remonte que le
// champ contrôlé `why`/`error` du backend (jamais un corps brut non-fiable -> anti-XSS, cf. api()).
export async function adminApi(path, opts) {
  const r = await fetch('/api' + path, Object.assign({ headers: { Accept: 'application/json' } }, opts || {}));
  const body = await r.text().catch(() => '');
  let j = null; try { j = body ? JSON.parse(body) : null; } catch (e) {}
  if (!r.ok) {
    const why = (j && (typeof j.why === 'string' && j.why || typeof j.error === 'string' && j.error)) || ('HTTP ' + r.status);
    const err = new Error(why); err.status = r.status; throw err;
  }
  return j;
}

export function setOperatorSecret(v) { OPERATOR_SECRET = v; }
