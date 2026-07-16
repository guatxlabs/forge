// =====================================================================================
//  ADMINISTRATION — racine de la vue #admin (composition root).
//  La vue est découpée en domaines (comptes / connecteurs / source de détection / sauvegarde) sous
//  js/views/admin/. Ce fichier ne garde que loadAdmin() (charge les 4 panneaux) + le câblage des
//  boutons (« nouveau », « recharger », créer/restaurer une sauvegarde). Le composant de source de
//  détection vit désormais dans js/components/detection-source-form.js (partagé avec le wizard) — ce
//  qui casse le cycle d'imports auth.js ⇄ admin.js.
// =====================================================================================
import { $ } from '../core/dom.js';
import { adminCreateUser, loadAdminUsers } from './admin/users.js';
import { loadAdminConnectors } from './admin/connectors.js';
import { loadAddTool } from './admin/addtool.js';
import { loadAdminDetection } from './admin/detection.js';
import { backupCreate, backupRestore, loadAdminBackup } from './admin/backup.js';
import { loadConsolePanel } from './admin/console.js';
import { loadAdminNetwork } from './admin/network.js';

// Vue #admin : charge comptes, POLITIQUE RÉSEAU (master global), connecteurs, AJOUT D'OUTIL, source de
// détection, sauvegarde ET la Console Forge in-UI (runner gouverné P5) — tous réservés au role admin (le
// serveur reste l'autorité).
export function loadAdmin() { loadAdminUsers(); loadAdminNetwork(); loadAdminConnectors(); loadAddTool(); loadAdminDetection(); loadAdminBackup(); loadConsolePanel(); }

// --- Câblage des actions de la vue #admin (les handlers vivent dans les modules de domaine) ---
if ($('#admin-new')) $('#admin-new').addEventListener('click', adminCreateUser);
if ($('#admin-reload')) $('#admin-reload').addEventListener('click', loadAdminUsers);
if ($('#admin-conn-reload')) $('#admin-conn-reload').addEventListener('click', loadAdminConnectors);
if ($('#admin-addtool-reload')) $('#admin-addtool-reload').addEventListener('click', loadAddTool);
if ($('#admin-det-reload')) $('#admin-det-reload').addEventListener('click', loadAdminDetection);
if ($('#bk-create')) $('#bk-create').addEventListener('click', backupCreate);
if ($('#bk-restore')) $('#bk-restore').addEventListener('click', backupRestore);
if ($('#admin-bk-reload')) $('#admin-bk-reload').addEventListener('click', loadAdminBackup);
