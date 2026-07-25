// =====================================================================================
//  R3 — PROFIL DE RESSOURCES + OVERRIDES PAR-LEVIER (Launch UI).
//
//  Un bouton `low|balanced|full` fixe les défauts de ressources du moteur (R1,
//  `forge/resource_profile.py`). Overrides par-levier optionnels : parallélisme / timeout-run /
//  profil d'outils — LES SEULS que le moteur lit via variable d'environnement
//  (FORGE_PARALLELISM / FORGE_RUN_TIMEOUT / FORGE_TOOLS_PROFILE). Timeout par-action, sévérité
//  nuclei et caps de crawl SUIVENT le profil (affichés read-only ; la sévérité nuclei reste réglable
//  par-module). CHOIX DE RESSOURCE UNIQUEMENT — aucun impact scope / ROE / plancher d'exploit.
//
//  Précédence STRICTE (côté moteur) : override > profil > défaut. Ici : champ vide => on ne pose PAS
//  la variable => défaut du profil. `balanced` sans override => body.resource ABSENT => no-op.
//  Rendu DOM SÛR : textContent uniquement (jamais innerHTML avec de la donnée).
// =====================================================================================
import { $ } from '../../core/dom.js';

// Presets R1 (miroir de `forge/resource_profile.py` PROFILES) — HARDCODÉS pour l'affichage read-only.
// SOURCE DE VÉRITÉ = le moteur ; ici pur affichage (aucune décision serveur ne lit ces constantes).
export const RES_PRESETS = {
  low: {
    desc: 'Machine faible : exécution en série, outils légers, timeouts courts, caps de crawl réduits.',
    knobs: { parallelism: 1, action_timeout_secs: 60, run_timeout_secs: 1800, tools_profile: 'mini', nuclei_severity: 'medium,high,critical', crawl_max_endpoints: 10, crawl_max_params: 2 },
  },
  balanced: {
    desc: 'Défaut : équilibre standard — aucune variable forcée, comportement inchangé.',
    knobs: { parallelism: 4, action_timeout_secs: 120, run_timeout_secs: 3600, tools_profile: 'full', nuclei_severity: 'info,low,medium,high,critical', crawl_max_endpoints: 25, crawl_max_params: 3 },
  },
  full: {
    desc: 'Grosse machine : parallélisme élevé, timeouts longs, caps de crawl étendus.',
    knobs: { parallelism: 12, action_timeout_secs: 300, run_timeout_secs: 7200, tools_profile: 'full', nuclei_severity: 'info,low,medium,high,critical', crawl_max_endpoints: 50, crawl_max_params: 5 },
  },
};

// Libellés lisibles des leviers affichés en read-only (ordre = ordre d'affichage).
const KNOB_ROWS = [
  ['parallelism', 'Parallélisme (pool)'],
  ['action_timeout_secs', 'Timeout par-action (s)'],
  ['run_timeout_secs', 'Timeout run / watchdog (s)'],
  ['tools_profile', "Profil d'outils"],
  ['nuclei_severity', 'Sévérité nuclei'],
  ['crawl_max_endpoints', 'Crawl : endpoints max'],
  ['crawl_max_params', 'Crawl : params max'],
];

// Met à jour la description + le tableau read-only des leviers + les placeholders d'override selon le
// profil sélectionné. DOM SÛR : textContent uniquement.
export function renderResourceProfile() {
  const sel = $('#lc-resprofile');
  const prof = (sel && sel.value) || 'balanced';
  const p = RES_PRESETS[prof] || RES_PRESETS.balanced;
  const desc = $('#lc-resprofile-desc');
  if (desc) desc.textContent = p.desc;
  const tb = $('#lc-respresets') && $('#lc-respresets').querySelector('tbody');
  if (tb) {
    tb.textContent = '';
    for (const [key, label] of KNOB_ROWS) {
      const tr = document.createElement('tr');
      const th = document.createElement('th'); th.textContent = label; th.scope = 'row';
      const td = document.createElement('td'); td.textContent = String(p.knobs[key]);
      tr.append(th, td); tb.appendChild(tr);
    }
  }
  // placeholders indicatifs des overrides = valeur du profil (l'input reste vide => défaut du profil).
  const ph = (id, v) => { const el = $(id); if (el) el.placeholder = '(profil : ' + v + ')'; };
  ph('#lc-res-parallelism', p.knobs.parallelism);
  ph('#lc-res-runtimeout', p.knobs.run_timeout_secs);
  const ts = $('#lc-res-toolsprofile');
  if (ts && ts.options && ts.options.length) ts.options[0].textContent = '(profil : ' + p.knobs.tools_profile + ')';
}

// Assemble la portion `resource` du body /api/run. Champs vides/invalides => ABSENTS (défaut du profil).
// `balanced` sans override => objet VIDE => l'appelant NE l'ajoute PAS au body (no-op, comportement
// inchangé). Bornes miroir du serveur (parse_resource_options) : parallélisme [1,64], run-timeout >=1.
export function collectResourceBody() {
  const out = {};
  const prof = ($('#lc-resprofile') && $('#lc-resprofile').value) || 'balanced';
  // `balanced` (défaut) => on NE force PAS FORGE_RESOURCE_PROFILE (le serveur l'ignorerait de toute façon).
  if (prof === 'low' || prof === 'full') out.profile = prof;
  const par = ($('#lc-res-parallelism') && $('#lc-res-parallelism').value || '').trim();
  if (par !== '') { const n = Number(par); if (Number.isInteger(n) && n >= 1 && n <= 64) out.parallelism = n; }
  const rt = ($('#lc-res-runtimeout') && $('#lc-res-runtimeout').value || '').trim();
  if (rt !== '') { const n = Number(rt); if (Number.isInteger(n) && n >= 1 && n <= 604800) out.run_timeout = n; }
  const tp = ($('#lc-res-toolsprofile') && $('#lc-res-toolsprofile').value) || '';
  if (tp === 'mini' || tp === 'full') out.tools_profile = tp;
  return out;
}
