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
// CE QU'ELLE N'AFFIRME PAS. Elle n'affirme RIEN : elle observe et rend les faits. Les invariants
// (« une écriture porte la preuve », « une lecture ne la porte pas », « une seule primitive ») sont
// asservis côté Python, dans tests/test_console_spa_governance.py.
//
// PROTOCOLE. argv : <racine console/web> <chemin du module porte, relatif> <sentinelle>
// Sortie : une ligne JSON sur stdout. Code de sortie ≠ 0 = la sonde n'a pas pu s'exécuter (le test
// Python ÉCHOUE alors, il ne « passe » jamais sur une sonde muette).
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const [webDir, doorRel, SENTINEL] = process.argv.slice(2);
if (!webDir || !doorRel || !SENTINEL) {
  console.error('usage: spa_door_probe.mjs <webDir> <doorRel> <sentinel>');
  process.exit(2);
}
const PROBE_PATH = '/api/__probe__';

// ---------------------------------------------------------------------------------------------
// enregistreur : tout ce qui part sur le réseau passe ici, quelle que soit la primitive utilisée
// ---------------------------------------------------------------------------------------------
const calls = [];
let recording = false;      // la phase d'amorçage (positionner le secret) n'est pas enregistrée
let current = null;         // export en cours d'exercice

function record(primitive, method, url, headers) {
  if (!recording) return;
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k)] = String(v);
  calls.push({ export: current, primitive, method: String(method || 'GET').toUpperCase(), url: String(url), headers: h });
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

// ---------------------------------------------------------------------------------------------
// import du module RÉEL + exercice de CHAQUE export
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
  for (const name of fns) {
    try { await ns[name](SENTINEL); } catch (e) { /* export non appelable ainsi : sans effet ici */ }
  }
}

const VARIANTS = [
  [PROBE_PATH, { method: 'POST', body: { a: 1 } }],
  [PROBE_PATH, { method: 'DELETE' }],
  [PROBE_PATH, { method: 'GET' }],
  [PROBE_PATH],
];

await seed();
for (const name of fns) {
  current = name;
  for (const args of VARIANTS) {
    recording = true;
    try {
      await ns[name](...args);
    } catch (e) {
      errors.push({ export: name, args: JSON.stringify(args), error: String(e && e.message || e) });
    }
    recording = false;
  }
  // le secret a pu être écrasé si `name` EST le setter : on le repositionne avant l'export suivant.
  await seed();
}

process.stdout.write(JSON.stringify({ door: doorRel, exports: fns, calls, errors }) + '\n');
