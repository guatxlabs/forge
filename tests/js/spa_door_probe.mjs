// SPDX-License-Identifier: AGPL-3.0-or-later
//
// SONDE COMPORTEMENTALE DE LA PORTE RÉSEAU DU SPA.
//
// POURQUOI CE FICHIER EXISTE. Les versions précédentes de la garde vérifiaient le TEXTE de la porte
// (`"operatorHeaders(" in body`). Mesuré : vider le corps du helper de preuve, l'appeler sous un nom
// SOSIE (`xoperatorHeaders`), ou laisser une CHAÎNE MORTE (`const dead = "operatorHeaders(";`) laissait
// la suite VERTE alors que TOUTES les écritures partaient sans preuve opérateur. Un test de texte ne
// peut pas distinguer ces trois cas ; l'exécution, si.
//
// CE QUE FAIT LA SONDE. Elle importe le module d'API RÉEL sous node, remplace TOUTES les primitives
// réseau du navigateur par des enregistreurs, appelle CHAQUE fonction exportée par le module (la liste
// vient de l'espace de noms importé — rien n'est écrit en dur ici : un helper ajouté demain est
// exercé sans que ce fichier bouge), et rend en JSON ce qui SERAIT PARTI sur le réseau.
//
// CE QUI A CHANGÉ, ET POURQUOI. La version précédente pilotait UNE SEULE URL (`/api/__probe__`) et
// QUATRE formes d'appel, ÉCRITES EN DUR ICI. Mesuré : une condition d'une ligne sur l'URL dans la porte
// (`… && String(url).indexOf('/plan') < 0`) laissait la suite 18/18 VERTE pendant que 24 écritures sur
// 120 partaient NUES — exactement l'inversion que la garde existe pour interdire. Idem sur la MÉTHODE :
// une porte qui ne prouve que POST/DELETE restait verte, PUT/PATCH nus. L'énumération n'avait pas
// disparu, elle avait changé d'axe : des ROUTES vers l'ÉCHANTILLON D'APPEL.
//
// La sonde ne CHOISIT donc plus rien : l'ensemble des URL et l'ensemble des MÉTHODES lui sont FOURNIS
// sur stdin par la garde Python, qui les DÉRIVE (routes réelles du serveur + URL engendrées ; partition
// fermée des méthodes HTTP + méthodes d'extension inventées). Ce fichier ne fait qu'exercer le produit
// cartésien et rendre les faits.
//
// CE QU'ELLE N'AFFIRME PAS. Elle n'affirme RIEN : elle observe et rend les faits. Les invariants
// (« la preuve est posée si et seulement si la méthode mute », « la décision ne dépend pas de l'URL »,
// « une seule primitive ») sont asservis côté Python, dans tests/test_console_spa_governance.py.
//
// PROTOCOLE. argv : <racine console/web> <chemin du module porte, relatif> <sentinelle>
// stdin : JSON {"urls": [...], "methods": [... | null]} — `null` = appel SANS objet d'options (c'est
// la forme qui exerce la méthode PAR DÉFAUT de chaque export).
// Sortie : une ligne JSON sur stdout. Code de sortie ≠ 0 = la sonde n'a pas pu s'exécuter (le test
// Python ÉCHOUE alors, il ne « passe » jamais sur une sonde muette).
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const [webDir, doorRel, SENTINEL] = process.argv.slice(2);
if (!webDir || !doorRel || !SENTINEL) {
  console.error('usage: spa_door_probe.mjs <webDir> <doorRel> <sentinel> ; plan de variation sur stdin');
  process.exit(2);
}

// --- plan de VARIATION, lu sur stdin (jamais décidé ici) ----------------------------------------
async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}
let PLAN;
try {
  PLAN = JSON.parse(await readStdin());
} catch (e) {
  console.error('plan de variation illisible sur stdin: ' + e);
  process.exit(2);
}
const URLS = Array.isArray(PLAN.urls) ? PLAN.urls : [];
const METHODS = Array.isArray(PLAN.methods) ? PLAN.methods : [];
if (!URLS.length || !METHODS.length) {
  console.error('plan de variation vide (urls=' + URLS.length + ', methods=' + METHODS.length + ')');
  process.exit(2);
}

// ---------------------------------------------------------------------------------------------
// enregistreur : tout ce qui part sur le réseau passe ici, quelle que soit la primitive utilisée
// ---------------------------------------------------------------------------------------------
const calls = [];
let recording = false;      // la phase d'amorçage (positionner le secret) n'est pas enregistrée
let current = null;         // export en cours d'exercice
let requested = null;       // méthode DEMANDÉE à cet export (null = appel sans options)

function record(primitive, method, url, headers) {
  if (!recording) return;
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k)] = String(v);
  calls.push({
    export: current, primitive, requested,
    method: String(method || 'GET').toUpperCase(), url: String(url), headers: h,
  });
}

// ---------------------------------------------------------------------------------------------
// shims DOM minimaux : le module d'API importe dom.js ($ = document.querySelector) et state.js
// (localStorage). On rend ces globales inertes — sauf celles qui PEUVENT écrire sur le réseau, qui
// sont instrumentées (createElement('form') rend un formulaire dont submit() est enregistré).
// ---------------------------------------------------------------------------------------------
function fakeElement(tag) {
  const el = {
    tagName: String(tag).toUpperCase(), style: {}, dataset: {}, children: [], attributes: {},
    method: 'GET', action: '', value: '', innerHTML: '', textContent: '',
    setAttribute(k, v) { this.attributes[k] = String(v); if (k === 'action') this.action = String(v); if (k === 'method') this.method = String(v); },
    getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; },
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { return c; },
    addEventListener() {}, removeEventListener() {}, remove() {}, click() {}, focus() {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    submit() { record('form.submit', this.method || 'GET', this.action || '', {}); },
    requestSubmit() { record('form.requestSubmit', this.method || 'GET', this.action || '', {}); },
  };
  return el;
}

globalThis.localStorage = {
  _m: {},
  getItem(k) { return k in this._m ? this._m[k] : null; },
  setItem(k, v) { this._m[k] = String(v); },
  removeItem(k) { delete this._m[k]; },
};
globalThis.document = {
  documentElement: fakeElement('html'),
  body: fakeElement('body'),
  querySelector: () => null,
  querySelectorAll: () => [],
  getElementById: () => null,
  createElement: tag => fakeElement(tag),
  addEventListener() {}, removeEventListener() {},
};
globalThis.getComputedStyle = () => ({ getPropertyValue: () => '' });
// certaines globales du runtime node (navigator, location) n'ont QU'UN getter : l'affectation simple
// jette. On les (re)définit donc explicitement — sinon la sonde meurt avant d'avoir rien observé.
function def(name, value) { Object.defineProperty(globalThis, name, { value, writable: true, configurable: true }); }
def('location', { href: 'http://127.0.0.1/', origin: 'http://127.0.0.1', search: '', pathname: '/' });
globalThis.window = globalThis;

// --- primitives réseau, TOUTES instrumentées ---------------------------------------------------
globalThis.fetch = async (url, opts = {}) => {
  record('fetch', (opts && opts.method) || 'GET', url, (opts && opts.headers) || {});
  return {
    ok: true, status: 200, headers: { get: () => null },
    text: async () => '{}', json: async () => ({}), blob: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0),
    body: null,
  };
};
globalThis.XMLHttpRequest = class {
  constructor() { this._h = {}; this._m = 'GET'; this._u = ''; }
  open(m, u) { this._m = m; this._u = u; }
  setRequestHeader(k, v) { this._h[k] = v; }
  send() { record('XMLHttpRequest', this._m, this._u, this._h); }
  abort() {}
  addEventListener() {}
};
def('navigator', {
  sendBeacon: (url) => { record('sendBeacon', 'POST', url, {}); return true; },
  userAgent: 'forge-probe',
});
globalThis.WebSocket = class { constructor(u) { record('WebSocket', 'WS', u, {}); } send() {} close() {} addEventListener() {} };
globalThis.importScripts = (...u) => { for (const x of u) record('importScripts', 'GET', x, {}); };
globalThis.EventSource = class { constructor(u) { record('EventSource', 'GET', u, {}); } close() {} addEventListener() {} };
// WORKERS : un worker est un site d'exécution SUPPLÉMENTAIRE qui peut parler au réseau (mesuré :
// `new Worker(URL.createObjectURL(new Blob([code])))` échappait à toute la garde, le code vivant dans
// une CHAÎNE). Instrumentés ici pour que la jambe RUNTIME les voie ; la jambe STATIQUE les interdit
// par identifiant, et la CSP servie refuse `blob:` (`worker-src 'self'`).
globalThis.Worker = class { constructor(u) { record('Worker', 'GET', u, {}); } postMessage() {} terminate() {} addEventListener() {} };
globalThis.SharedWorker = class { constructor(u) { record('SharedWorker', 'GET', u, {}); this.port = { postMessage() {}, start() {} }; } };

// ---------------------------------------------------------------------------------------------
// import du module RÉEL + exercice de CHAQUE export sur le produit URL × MÉTHODE
// ---------------------------------------------------------------------------------------------
const doorUrl = pathToFileURL(join(webDir, doorRel)).href;
let ns;
try {
  ns = await import(doorUrl);
} catch (e) {
  console.error('import du module porte impossible: ' + (e && e.stack || e));
  process.exit(3);
}

const fns = Object.entries(ns).filter(([, v]) => typeof v === 'function').map(([k]) => k);
const errors = [];

// amorçage : appelle chaque export avec la SENTINELLE seule -> un éventuel setter du secret opérateur
// le positionne. Non enregistré (on ne juge que la phase d'exercice).
async function seed() {
  recording = false;
  requested = null;
  for (const name of fns) {
    try { await ns[name](SENTINEL); } catch (e) { /* export non appelable ainsi : sans effet ici */ }
  }
}

await seed();
for (const name of fns) {
  current = name;
  for (const url of URLS) {
    for (const m of METHODS) {
      requested = m;
      recording = true;
      try {
        // `null` = appel SANS objet d'options : c'est la forme qui exerce la méthode PAR DÉFAUT de
        // l'export (p.ex. `write()` poste). Sinon on ne fournit QUE la méthode : la porte ne doit pas
        // avoir besoin d'autre chose pour décider.
        if (m === null) await ns[name](url);
        else await ns[name](url, { method: m });
      } catch (e) {
        errors.push({ export: name, url: String(url), method: String(m), error: String(e && e.message || e) });
      }
      recording = false;
    }
  }
  // le secret a pu être écrasé si `name` EST le setter : on le repositionne avant l'export suivant.
  await seed();
}

process.stdout.write(JSON.stringify({ door: doorRel, exports: fns, urls: URLS.length, methods: METHODS.length, calls, errors }) + '\n');
