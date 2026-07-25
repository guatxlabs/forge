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
//  LE SEUL POINT RÉSEAU DU SPA — et pourquoi c'est ÇA qu'on garde, pas les routes
// =====================================================================================
// L'invariant de gouvernance à tenir est : une requête qui MUTE doit porter la preuve opérateur.
// Trois versions de la garde ont essayé de le vérifier en CHERCHANT LES ROUTES dans le source ; à
// chaque fois l'écriture suivante passait au travers (littéral concaténé, gabarit interpolé,
// échappement `\x2F`, fichier hors du répertoire scanné, sous-chaîne `write(` fournie par `rewrite(`).
// Chercher une route dans du JavaScript, c'est énumérer des FORMES.
//
// Ici la propriété est INVERSÉE : le SPA n'a QU'UN SEUL endroit qui touche le réseau — `fetch` n'est
// appelé nulle part ailleurs (`tests/test_console_spa_governance.py` le vérifie EXHAUSTIVEMENT sur le
// graphe de modules réellement servi, sans lire une seule route), et ce seul endroit attache la preuve
// opérateur à TOUTE requête mutante. Conséquence : un nouveau site d'appel écrit demain, sous n'importe
// quelle forme, dans n'importe quel fichier, hérite de la preuve sans que son auteur ait à y penser ;
// et s'il court-circuite le helper, ce n'est plus une route à reconnaître mais un `fetch` de plus dans
// un module qui n'a pas le droit d'en avoir.
//
// GET/HEAD n'emportent PAS l'en-tête : ce sont des lectures, et l'attacher partout CHANGERAIT
// l'identité résolue côté serveur. Mesuré sur le binaire, posture bootstrap (hash env, aucune session)
// — `GET /api/whoami` sans l'en-tête : `{authenticated:false, login:null, role:null}` ; avec l'en-tête :
// `{authenticated:true, login:'bootstrap', role:'admin', is_operator:true}`. Une lecture ne doit pas
// changer d'identité au passage : l'en-tête reste réservé aux écritures.

// Construit les arguments de l'UNIQUE `fetch` : l'URL telle quelle, et des options dont les en-têtes
// portent la preuve opérateur dès que la méthode MUTE. Un en-tête fourni par l'appelant l'emporte
// (la sonde de posture C2 envoie `X-Forge-Operator: ''` à dessein).
function operatorInit(url, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const mutating = method !== 'GET' && method !== 'HEAD';
  const headers = mutating ? operatorHeaders(opts.headers || {}) : (opts.headers || {});
  return [url, { ...opts, headers }];
}

// L'UNIQUE appel réseau du SPA. Rend la `Response` brute : les appelants qui streament (SSE via
// ReadableStream), téléchargent un blob ou lisent du texte non-JSON en ont besoin.
export async function request(url, opts) {
  return fetch(...operatorInit(url, opts));
}

// =====================================================================================
//  API helpers
// =====================================================================================
export async function api(path) {
  // Toute LECTURE est scopée à l'engagement actif (withEngagement) — un endpoint qui ignore le param
  // le laisse inerte (sans effet), donc l'ajout global est sûr.
  const r = await request(withEngagement('/api' + path), { headers: { Accept: 'application/json' } });
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
// `auth` (operator = X-Forge-Operator[+Bearer] ; admin = cookie de session),
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
  // `auth: 'admin'` n'ajoute plus « pas d'en-tête opérateur » : c'est `request()` qui attache la preuve
  // à TOUTE écriture (l'en-tête est inerte quand le serveur résout une session admin — check_admin
  // n'a AUCUN repli par en-tête). Ce que `auth` choisit encore, c'est l'`Accept` de l'appel admin.
  const headers = auth === 'admin' ? { ...extra, Accept: 'application/json' } : extra;
  const opts = { method, headers };
  if (hasBody) opts.body = JSON.stringify(body);
  const r = await request(url, opts);
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
  const r = await request('/api' + path, Object.assign({ headers: { Accept: 'application/json' } }, opts || {}));
  const body = await r.text().catch(() => '');
  let j = null; try { j = body ? JSON.parse(body) : null; } catch (e) {}
  if (!r.ok) {
    const why = (j && (typeof j.why === 'string' && j.why || typeof j.error === 'string' && j.error)) || ('HTTP ' + r.status);
    const err = new Error(why); err.status = r.status; throw err;
  }
  return j;
}

export function setOperatorSecret(v) { OPERATOR_SECRET = v; }
