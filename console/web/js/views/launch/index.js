// =====================================================================================
//  LANCEMENT — composition root de la vue #launch.
//  launch.js a été éclaté en package js/views/launch/ (11 responsabilités -> modules dédiés) :
//    modules-form.js  — formulaire de modules + opt-in fort impact (MODULE_PARAMS, renderLaunchModules…)
//    run-result.js    — rendu pur du panneau résultat (tuiles, tables issue/findings)
//    live.js          — SEUL propriétaire de LC_LIVE : transport live (SSE/polling) du run suivi
//    submit.js        — POST /api/run + double-confirmation fort impact + annulation
//    runs-list.js     — liste des runs + modale de détail
//    scope-plan.js    — SEUL propriétaire de LC_PLAN : scope-check + dry-plan + approbation RECON
//    reports.js       — rapports markdown / HTML brandé
//  Ce fichier ne garde QUE loadLaunch() + TOUT le câblage d'évènements top-level (le composition root).
//  Il remplace l'ancien js/views/launch.js comme point d'entrée importé par l'app.
// =====================================================================================
import { api, setOperatorSecret } from '../../core/api.js';
import { $ } from '../../core/dom.js';
import { MODULES, setModules } from '../modules.js';
import { toast } from '../../core/ui.js';
import { lcSelectModules, lcSyncDanger, renderLaunchModules } from './modules-form.js';
import { LC_LIVE, followRun, lcStopLive, probeC2State, reattachRunningRun } from './live.js';
import { loadRuns } from './runs-list.js';
import { cancelRun, submitRun } from './submit.js';
import { lcApproveAndRun, lcDryPlan, lcScopeAddTarget, lcScopeCheck, lcSyncApproveBtn } from './scope-plan.js';
import { renderResourceProfile } from './resource.js';

// Surface publique du package (importée par d'autres vues / core) — index.js est le point d'entrée
// unique qui remplace l'ancien js/views/launch.js :
//   - lcStopLive        : auth.js (doLogout) coupe le flux live à la déconnexion.
//   - followRun/loadRuns: workflows.js relance un run et rafraîchit la liste.
//   - renderLaunchModules: reports.js re-rend la liste de modules quand la vue #launch est active.
export { lcStopLive, followRun, loadRuns, renderLaunchModules };

let lcC2Probed = false;              // sonde l'état opérateur une seule fois (la sonde POSTe /api/run)
let lcModulesLoaded = false;

export async function loadLaunch() {
  // catalogue de modules (réutilise MODULES global ; le charge si pas encore fait).
  if (!MODULES.length && !lcModulesLoaded) {
    try { setModules(await api('/modules')); } catch (e) { /* la liste restera vide, hint le dira */ }
    lcModulesLoaded = true;
  }
  renderLaunchModules();
  if (!lcC2Probed) { lcC2Probed = true; probeC2State(); }   // sonde l'état opérateur une fois (évite de marteler /api/run)
  loadRuns();
  // si un run est déjà suivi, on garde le flux ; sinon on tente de raccrocher le run courant.
  if (!LC_LIVE) reattachRunningRun();
}

// =====================================================================================
//  CÂBLAGE D'ÉVÈNEMENTS (top-level) — exécuté à l'import du module (DOM déjà prêt : app.js est ESM).
// =====================================================================================
// liste des runs : filtre de statut + rechargement manuel.
if ($('#lc-runstatus')) $('#lc-runstatus').addEventListener('change', loadRuns);
if ($('#lc-runreload')) $('#lc-runreload').addEventListener('click', loadRuns);
// formulaire de lancement + annulation.
if ($('#lc-runform')) $('#lc-runform').addEventListener('submit', submitRun);
// RESSOURCES (R3) : rendu initial (description + leviers read-only + placeholders) et resync au change.
if ($('#lc-resprofile')) { $('#lc-resprofile').addEventListener('change', renderResourceProfile); renderResourceProfile(); }
if ($('#lc-cancel')) $('#lc-cancel').addEventListener('click', cancelRun);
// secret opérateur : capté en mémoire de session uniquement (l'input ne reste pas porteur du secret).
if ($('#lc-operator')) $('#lc-operator').addEventListener('input', e => { setOperatorSecret(e.target.value); lcSyncDanger(); });
if ($('#lc-clearop')) $('#lc-clearop').addEventListener('click', () => { setOperatorSecret(''); if ($('#lc-operator')) $('#lc-operator').value = ''; lcSyncDanger(); toast('Secret opérateur oublié (session).', 'ok'); });
// avertissement « armer » : visible quand la case est cochée + rafraîchit les conditions de gouvernance.
if ($('#lc-arm')) $('#lc-arm').addEventListener('change', e => { const w = $('#lc-armwarn'); if (w) w.hidden = !e.target.checked; lcSyncDanger(); });
if ($('#lc-reason')) $('#lc-reason').addEventListener('input', lcSyncDanger);
// ZONE DANGER : opt-in fort impact (défaut OFF) — (dé)bloque exploit/destructif + recalcule les conditions.
if ($('#lc-allowhi')) $('#lc-allowhi').addEventListener('change', lcSyncDanger);
// SÉLECTION EN MASSE des modules : « Tout sélectionner » (disponibles uniquement) / « Tout désélectionner ».
if ($('#lc-modall')) $('#lc-modall').addEventListener('click', () => lcSelectModules(true));
if ($('#lc-modnone')) $('#lc-modnone').addEventListener('click', () => lcSelectModules(false));
// scope-check : champ cible -> badge in/out scope ; Entrée déclenche la vérif ; ajout aux cibles.
if ($('#lc-scopecheck')) $('#lc-scopecheck').addEventListener('click', lcScopeCheck);
if ($('#lc-scopetarget')) $('#lc-scopetarget').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); lcScopeCheck(); } });
if ($('#lc-scopeadd')) $('#lc-scopeadd').addEventListener('click', lcScopeAddTarget);
// dry-plan (INERTE) + approbation granulaire RECON.
if ($('#lc-dryplan')) $('#lc-dryplan').addEventListener('click', lcDryPlan);
if ($('#lc-approve')) $('#lc-approve').addEventListener('click', lcApproveAndRun);
if ($('#lc-approve-all')) $('#lc-approve-all').addEventListener('click', () => {
  document.querySelectorAll('#lc-planresult .lc-approve-cb').forEach(cb => { cb.checked = true; });
  lcSyncApproveBtn();
});
