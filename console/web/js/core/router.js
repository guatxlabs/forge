import { loadAdmin } from '../views/admin.js';
import { complianceAdmin, identityAdmin, isAdmin } from './auth.js';
import { loadCampaigns } from '../views/campaigns.js';
import { loadCompliance } from '../views/compliance.js';
import { loadCoverage, loadPurpleCoverage } from '../views/coverage.js';
import { loadAttackMatrix } from '../views/attack-matrix.js';
import { loadDashboards, refreshPanels } from '../views/dashboards.js';
import { $, ic } from './dom.js';
import { loadEngagements, reloadCurrentView } from '../views/engagements.js';
import { loadFindings } from '../views/findings.js';
import { loadFindingsLibrary } from '../views/findings-library.js';
import { loadIdentity } from '../views/identity.js';
import { loadImport } from '../views/import.js';
import { loadLaunch } from '../views/launch.js';
import { loadLedger } from '../views/ledger.js';
import { loadModules } from '../views/modules.js';
import { loadOverview } from '../views/overview.js';
import { loadReports } from '../views/reports.js';
import { loadRoe } from '../views/roe.js';
import { loadTechniques } from '../views/techniques.js';
import { loadTenants, tenancyAdmin } from '../views/tenancy.js';
import { loadWorkflows } from '../views/workflows.js';

export const VIEWS = {
  'ov-summary': 'overview', 'ov-sev': 'overview', 'ov-modules': 'overview',
  engagements: 'engagements',
  'lc-form': 'launch', 'lc-plan': 'launch', 'lc-live': 'launch', 'lc-runs': 'launch',
  import: 'import',
  modules: 'modules', techniques: 'techniques', workflows: 'workflows', findings: 'findings', 'findings-library': 'findings-library', reports: 'reports', explore: 'explore',
  coverage: 'coverage', 'attack-matrix': 'attack-matrix', 'purple-coverage': 'purple-coverage', campaigns: 'campaigns', roe: 'roe', ledger: 'ledger', dashboards: 'dashboards',
  admin: 'admin', 'admin-connectors': 'admin', 'admin-detection': 'admin',
  tenants: 'tenants',
  identity: 'identity',
  compliance: 'compliance',
};
export const LOADERS = {
  overview: loadOverview, engagements: loadEngagements, launch: loadLaunch, import: loadImport, modules: loadModules, techniques: loadTechniques, workflows: loadWorkflows, findings: loadFindings, 'findings-library': loadFindingsLibrary, reports: loadReports,
  coverage: loadCoverage, 'attack-matrix': loadAttackMatrix, 'purple-coverage': loadPurpleCoverage, campaigns: loadCampaigns, roe: loadRoe, ledger: loadLedger, dashboards: loadDashboards,
  admin: loadAdmin,
  tenants: loadTenants,
  identity: loadIdentity,
  compliance: loadCompliance,
};
export let loadedOnce = {};
export function showView(v) {
  document.querySelectorAll('main > section').forEach(s => {
    // lc-plan : visibilité pilotée par le dry-plan (apparaît après /api/plan), pas par le routage —
    // on le masque seulement quand on quitte la vue launch, jamais on ne le force visible ici.
    if (s.id === 'lc-plan') { if (v !== 'launch') s.hidden = true; return; }
    s.hidden = (VIEWS[s.id] || 'overview') !== v;
  });
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.getAttribute('href') === '#' + v));
  if ($('#q')) $('#q').hidden = (v !== 'explore' && v !== 'findings');
  const fn = LOADERS[v];
  if (fn) { try { fn(); } catch (e) { console.error(e); } loadedOnce[v] = true; }
}
export function route() { let v = location.hash.slice(1) || 'overview'; if (!VIEWS_HAS(v)) v = 'overview'; if (v === 'admin' && !isAdmin()) v = 'overview'; if (v === 'tenants' && !tenancyAdmin()) v = 'overview'; if (v === 'identity' && !identityAdmin()) v = 'overview'; if (v === 'compliance' && !complianceAdmin()) v = 'overview'; showView(v); }
export function VIEWS_HAS(v) { return Object.values(VIEWS).includes(v); }
window.addEventListener('hashchange', route);
if ($('#navtoggle')) $('#navtoggle').onclick = () => { const l = document.querySelector('.layout'); if (l) l.classList.toggle('collapsed'); };

// campagne globale : recharge la vue courante + les compteurs croisés
if ($('#campaign')) $('#campaign').addEventListener('change', () => {
  reloadCurrentView();
  if ((location.hash.slice(1) || 'overview') === 'findings') loadFindings(0);
});
if ($('#reload')) $('#reload').addEventListener('click', () => { reloadCurrentView(); });

// =====================================================================================
//  Thème clair / sombre (Aurora) + auto-refresh + boot
// =====================================================================================
(function initTheme() {
  const saved = localStorage.getItem('forge-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  const btn = $('#theme');
  const paint = () => { if (btn) btn.innerHTML = ic(document.documentElement.dataset.theme === 'light' ? 'moon' : 'sun'); };
  paint();
  if (btn) btn.onclick = () => {
    const t = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = t;
    localStorage.setItem('forge-theme', t);
    paint();
    // recolore les vues à graphes SVG (ils lisent les variables CSS au rendu)
    reloadCurrentView();
  };
})();

export let autoTimer = null;
export function applyAutoRefresh() {
  if (autoTimer) clearInterval(autoTimer);
  const s = Number(($('#refresh') && $('#refresh').value) || 0);
  if (s > 0) autoTimer = setInterval(() => {
    reloadCurrentView();
    if ((location.hash.slice(1) || 'overview') === 'dashboards') refreshPanels();
  }, s * 1000);
}
if ($('#refresh')) $('#refresh').addEventListener('change', applyAutoRefresh);

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

// version produit (source unique : fichier VERSION -> exposé par /health JSON) affichée au pied de page.
// Best-effort, jamais bloquant : /health est ouvert (hors auth), donc fetch nu sans en-tête.
export async function loadVersion() {
  try {
    const j = await (await fetch('/health', { headers: { accept: 'application/json' } })).json();
    const el = $('#version');
    if (el && j && j.version) el.textContent = ' — forge v' + j.version;
  } catch (e) { /* pied de page informatif : ignorer toute erreur */ }
}

// =====================================================================================
//  AUTHENTIFICATION — portail de connexion (gate du shell) + badge whoami + déconnexion
//  Le boot sonde GET /api/whoami (route derrière auth_guard) :
//    - 401                        -> session requise et absente        -> vue de login.
//    - 200 {authenticated:true}   -> session valide                    -> shell + badge (login/rôle).
//    - 200 {authenticated:false}  -> mode dev-open (aucun hash serveur) -> shell sans badge.
//  Toutes les requêtes suivantes (findings, query, SSE /events, …) s'authentifient par le cookie
//  forge_session (HttpOnly, SameSite=Strict) posé par POST /api/login — jamais par un token en JS.
//  On NE stocke PAS le bearer renvoyé par /login : l'UI s'appuie exclusivement sur le cookie.
// =====================================================================================
