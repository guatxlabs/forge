import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { guardList, toast } from '../../core/ui.js';

// =====================================================================================
//  ADMINISTRATION — CYCLE DE VIE DES OUTILS (binaires externes du manifeste forge/tools.json)
//
//  Contrepartie UI de GET/POST /api/tools/runtime (admin-only, ledgerise). Le panneau montre, PAR OUTIL :
//  la version CIBLE du manifeste, la version INSTALLEE (lue dans le recu depose a l'installation — rien
//  n'est execute pour l'obtenir), la provenance (couche runtime / baseline bakee / absent), le chemin
//  resolu sur le PATH, et si l'outil est EPINGLE (SHA256) pour l'architecture courante.
//
//  CE PANNEAU N'A AUCUN CHAMP DE SAISIE, ET C'EST LE POINT. Les seules actions possibles sont trois
//  boutons attaches a une LIGNE DU MANIFESTE : installer / mettre a jour / retirer. Il n'existe ni champ
//  URL, ni champ empreinte, ni champ version — parce que l'API n'en accepte pas et que l'installeur
//  (forge/toolsinstall.py) n'en a pas non plus : la source est CALCULEE depuis le manifeste, qui EST
//  l'allowlist. Un outil non epingle pour l'architecture courante n'a simplement pas de bouton
//  « Installer » : il n'y a aucun chemin, meme cosmetique, vers un telechargement non verifie.
//  Bumper une version = editer forge/tools.json (changement revu et pinne) puis « Mettre a jour ».
// =====================================================================================

// Rendu d'une ligne : badges STATIQUES derives de booleens/enums serveur, texte toujours passe par esc().
function sourceBadge(r) {
  if (r.source === 'runtime') return r.up_to_date ? '<span class="badge ok">runtime</span>' : '<span class="badge bad">runtime (obsolete)</span>';
  if (r.source === 'baseline') return '<span class="badge mut">baseline</span>';
  return '<span class="badge mut">absent</span>';
}

export async function loadAdminToolsRuntime() {
  const host = $('#admin-toolsrt-body'); if (!host) return;
  const badge = $('#admin-toolsrt-count');
  if (!isAdmin()) { host.innerHTML = '<div class="muted">reserve aux administrateurs</div>'; if (badge) badge.textContent = ''; return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/tools/runtime'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const rows = (data && Array.isArray(data.tools)) ? data.tools : [];
  if (badge) badge.textContent = rows.length ? rows.length + ' outil' + (rows.length > 1 ? 's' : '') : '';
  if (data && data.probe_error) {
    host.innerHTML = `<div class="bad">etat indisponible : ${esc(data.probe_error)}</div>`
      + `<div class="muted">${esc(data.why || '')}</div>`;
    return;
  }
  if (guardList(host, rows, 'manifeste vide')) return;

  const table = document.createElement('table'); table.className = 'qtable';
  table.innerHTML = '<thead><tr><th>Outil</th><th>Cible</th><th>Installe</th><th>Provenance</th><th>Pin</th><th>PATH</th><th>Actions</th></tr></thead>';
  const tb = document.createElement('tbody');
  rows.forEach(r => {
    const tr = document.createElement('tr');
    const pin = r.installable ? '<span class="badge ok">pinne</span>' : '<span class="badge bad">non pinne</span>';
    tr.innerHTML =
      `<td class="mono">${esc(r.name || '')}</td>` +
      `<td class="mono">${esc(r.version || '')}</td>` +
      `<td class="mono">${esc(r.installed_version || '—')}</td>` +
      `<td>${sourceBadge(r)}</td>` +
      `<td>${pin}</td>` +
      `<td class="mono muted">${esc(r.resolved_path || '—')}</td>` +
      '<td class="admin-act"></td>';
    const act = tr.querySelector('.admin-act');
    const mk = (label, title, action, danger) => {
      const b = document.createElement('button'); b.type = 'button';
      b.className = 'k-theme' + (danger ? ' danger' : '');
      b.textContent = label; b.title = title;
      b.onclick = () => toolAction(action, r.name);
      return b;
    };
    // Pas de pin pour l'architecture courante -> AUCUNE action d'installation n'est offerte (l'API la
    // refuserait de toute facon : le refus vient de l'installeur, avant le moindre octet reseau).
    if (r.installable) {
      act.appendChild(mk('Installer', 'Installe la version du manifeste (SHA256 verifie avant la pose, journalise au ledger)', 'install'));
      act.appendChild(mk('Mettre a jour', 'Repose la version du MANIFESTE (il n\'existe pas d\'« update vers la derniere version amont » : ce serait un telechargement non pinne)', 'update'));
    }
    if (r.source === 'runtime') {
      act.appendChild(mk('Retirer', 'Retire de la couche runtime ; la baseline bakee reste intacte (le PATH y retombe)', 'remove', true));
    }
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
  const note = document.createElement('div'); note.className = 'muted';
  note.textContent = 'La source et l\'empreinte viennent du manifeste forge/tools.json — il n\'existe aucun champ '
    + 'URL, version ou empreinte, ni ici ni dans l\'API. Un outil installe reste soumis aux memes gates '
    + 'que la baseline (scope-guard ROE, plancher exploit, argv fixe no-shell).';
  host.appendChild(note);
}

// POST /api/tools/runtime {action, name} — le corps ne porte QUE ces deux champs (l'API refuse tout autre).
export async function toolAction(action, name) {
  if (!name) return;
  try {
    const r = await adminApi('/tools/runtime', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ action, name }),
    });
    const res = (r && r.result) || {};
    const done = res.action || action;
    toast(`${name} : ${done}${res.version ? ' ' + res.version : ''}`, 'ok');
  } catch (e) { toast(`Action « ${action} » refusee : ` + e.message, 'bad'); }
  loadAdminToolsRuntime();
}
