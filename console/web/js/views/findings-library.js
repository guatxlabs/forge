import { api, write } from '../core/api.js';
import { editing } from './dashboards.js';
import { $, SEV_BADGE, esc, raw, safeHtml } from '../core/dom.js';
import { loadFindings } from './findings.js';
import { activeEngagement, activeEngagementName } from '../core/state.js';
import { confirmModal, guardList, modal, toast } from '../core/ui.js';

export const FT_SEVS = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export let FT_TEMPLATES = [];

export async function loadFindingsLibrary() {
  const host = $('#ftpl-list'); if (!host) return;
  let d;
  try { d = await api('/finding-templates'); }               // GLOBAL : le param ?engagement est inerte ici
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  FT_TEMPLATES = (d && d.templates) || [];
  if ($('#ftpl-count')) $('#ftpl-count').textContent = FT_TEMPLATES.length + ' modèle' + (FT_TEMPLATES.length > 1 ? 's' : '');
  if (guardList(host, FT_TEMPLATES, 'aucun modèle — cliquez « Nouveau modèle » pour capitaliser un finding réutilisable')) return;
  host.replaceChildren(...FT_TEMPLATES.map(renderTemplateCard));
}

// Extrait l'ensemble des placeholders {clef} présents dans les gabarits d'un modèle (titre/desc/reméd).
export function ftPlaceholders(tpl) {
  const set = new Set();
  const re = /\{([A-Za-z0-9_.-]+)\}/g;
  [tpl.title_tmpl, tpl.description_tmpl, tpl.remediation_tmpl].forEach(t => {
    const s = String(t || ''); let m; re.lastIndex = 0;
    while ((m = re.exec(s)) !== null) set.add(m[1]);
  });
  return [...set];
}

export function renderTemplateCard(tpl) {
  const card = document.createElement('div'); card.className = 'wf-card';
  const head = document.createElement('div'); head.className = 'wf-cardhead';
  const title = document.createElement('span'); title.className = 'wf-name';
  title.innerHTML = safeHtml`${tpl.name} ${raw(SEV_BADGE(tpl.severity))}`
    + (tpl.cwe ? safeHtml` <span class="badge">${tpl.cwe}</span>` : '')
    + (tpl.vuln_class ? safeHtml` <span class="badge mut">${tpl.vuln_class}</span>` : '');
  head.appendChild(title);
  const acts = document.createElement('span'); acts.className = 'wf-cardacts';
  const mk = (label, cls, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = cls; b.textContent = label; b.onclick = fn; return b; };
  acts.appendChild(mk('Appliquer', 'k-theme', () => applyTemplate(tpl)));
  acts.appendChild(mk('Éditer', 'k-theme', () => openTemplateEditor(tpl)));
  acts.appendChild(mk('Supprimer', 'k-theme danger', () => deleteTemplate(tpl)));
  head.appendChild(acts); card.appendChild(head);
  if (tpl.title_tmpl) { const p = document.createElement('p'); p.className = 'wf-desc'; p.textContent = tpl.title_tmpl; card.appendChild(p); }
  const ph = ftPlaceholders(tpl);
  if (ph.length) {
    const chips = document.createElement('div'); chips.className = 'wf-steps';
    ph.forEach(k => { const c = document.createElement('span'); c.className = 'wf-chip'; c.textContent = '{' + k + '}'; c.title = 'placeholder rempli à l\'application'; chips.appendChild(c); });
    card.appendChild(chips);
  }
  return card;
}

// Éditeur de modèle (création si existing=null, édition sinon) — operator. Envoie TOUT le formulaire :
// le serveur mappe `references` -> colonne refs et normalise la sévérité (fail-closed si hors ensemble).
export async function openTemplateEditor(existing) {
  const editing = !!existing;
  const vals = await modal({
    title: editing ? ('Éditer le modèle « ' + existing.name + ' »') : 'Nouveau modèle de finding',
    okText: editing ? 'Enregistrer' : 'Créer', wide: true,
    fields: [
      { name: 'name', label: 'Nom', value: editing ? existing.name : '', required: true, hint: 'libellé du modèle (ex: XSS reflété)' },
      { name: 'severity', label: 'Sévérité', type: 'select', value: editing ? existing.severity : 'INFO', options: FT_SEVS.map(s => ({ value: s, label: s })) },
      { name: 'vuln_class', label: 'Classe de vuln', value: editing ? existing.vuln_class : '', hint: 'ex: xss, sqli, idor — devient la catégorie du finding' },
      { name: 'cwe', label: 'CWE', value: editing ? existing.cwe : '', hint: 'ex: CWE-79' },
      { name: 'title_tmpl', label: 'Titre (gabarit)', value: editing ? existing.title_tmpl : '', hint: 'placeholders {target}/{param} remplis à l\'application' },
      { name: 'description_tmpl', label: 'Description (gabarit)', type: 'textarea', value: editing ? existing.description_tmpl : '', placeholder: 'ex: Le paramètre {param} sur {target} est injectable…' },
      { name: 'remediation_tmpl', label: 'Remédiation (gabarit)', type: 'textarea', value: editing ? existing.remediation_tmpl : '', placeholder: 'ex: Utiliser des requêtes paramétrées…' },
      { name: 'references', label: 'Références', value: editing ? (existing.references || '') : '', hint: 'liens / notes (libre)' },
    ],
    validate: v => (FT_SEVS.includes(v.severity) ? null : 'Sévérité invalide.'),
  });
  if (!vals) return;
  const path = editing ? '/api/finding-templates/' + existing.id : '/api/finding-templates';
  try {
    const r = await write(path, { body: vals, auth: 'operator' });
    if (r.status === 403) { toast('Création/édition réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(r.json.why || r.json.error || r.status), 'bad'); return; }
    toast(editing ? 'Modèle enregistré (ledgerisé)' : 'Modèle créé (ledgerisé)', 'ok');
    loadFindingsLibrary();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Suppression d'un modèle — ADMIN (le cookie de session admin autorise ; pas de prompt de token).
export async function deleteTemplate(tpl) {
  const ok = await confirmModal('Supprimer le modèle « ' + tpl.name + ' » ? (ledgerisé, réservé admin — les findings déjà créés ne sont pas affectés)', { title: 'Supprimer le modèle', okText: 'Supprimer' });
  if (!ok) return;
  try {
    const r = await fetch('/api/finding-templates/' + tpl.id, { method: 'DELETE', headers: { 'Content-Type': 'application/json', Accept: 'application/json' } });
    if (r.status === 403) { toast('Suppression réservée à un administrateur', 'bad'); return; }
    if (!r.ok) { const j = await r.json().catch(() => ({})); toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Modèle supprimé (ledgerisé)', 'ok'); loadFindingsLibrary();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Applique un modèle -> crée un finding dans l'engagement ACTIF. Un champ par placeholder + cible +
// campagne. operator (fail-closed serveur). Le finding produit appartient à l'engagement actif (isolation).
export async function applyTemplate(tpl) {
  const ph = ftPlaceholders(tpl);
  const engName = activeEngagementName();
  const fields = [
    { name: '__target', label: 'Cible', value: '', hint: 'hôte/URL du finding (remplit aussi {target})' },
    { name: '__campaign', label: 'Campagne (option)', value: '', hint: 'sous-label libre au sein de l\'engagement' },
  ];
  ph.filter(k => k !== 'target').forEach(k => fields.push({ name: 'ph_' + k, label: 'Paramètre {' + k + '}', value: '' }));
  const vals = await modal({
    title: 'Appliquer « ' + tpl.name + ' »',
    message: 'Crée un finding dans l\'engagement ACTIF' + (engName ? ' : ' + engName : '') + '. Renseignez les placeholders ci-dessous.',
    okText: 'Créer le finding', wide: true, fields,
  });
  if (!vals) return;
  const params = {};
  Object.keys(vals).forEach(k => { if (k.startsWith('ph_')) params[k.slice(3)] = vals[k]; });
  if (vals.__target) params.target = vals.__target;
  const body = { target: vals.__target || '', campaign: vals.__campaign || '', params };
  const eng = activeEngagement(); if (eng != null) body.engagement_id = eng;    // isolation : engagement actif
  try {
    const r = await write('/api/finding-templates/' + tpl.id + '/apply', { body, auth: 'operator', engagement: true });
    if (r.status === 403) { toast('Application réservée à un compte operator/admin', 'bad'); return; }
    const j = r.json;
    if (r.status === 409) { toast('Finding déjà présent (campagne/cible/titre identiques) — dédupliqué', 'info'); return; }
    if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
    toast('Finding créé dans l\'engagement actif (ledgerisé)', 'ok');
    location.hash = 'findings';
    loadFindings(0);
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// Affordance « Depuis un modèle » dans la vue Findings : choisir un modèle puis l'appliquer.
export async function pickTemplateAndApply() {
  let list = FT_TEMPLATES;
  if (!list.length) {
    try { const d = await api('/finding-templates'); list = (d && d.templates) || []; FT_TEMPLATES = list; }
    catch (e) { toast('Chargement des modèles : ' + e.message, 'bad'); return; }
  }
  if (!list.length) { toast('Aucun modèle — créez-en un dans la Bibliothèque de findings', 'info'); location.hash = 'findings-library'; return; }
  const vals = await modal({
    title: 'Appliquer un modèle de finding',
    message: 'Le modèle choisi sera appliqué à l\'engagement ACTIF.',
    okText: 'Continuer',
    fields: [{ name: 'id', label: 'Modèle', type: 'select', value: String(list[0].id), options: list.map(t => ({ value: String(t.id), label: t.name + ' [' + t.severity + ']' })) }],
  });
  if (!vals) return;
  const tpl = list.find(t => String(t.id) === String(vals.id));
  if (tpl) applyTemplate(tpl);
}

if ($('#ftpl-new')) $('#ftpl-new').addEventListener('click', () => openTemplateEditor(null));
if ($('#ftpl-reload')) $('#ftpl-reload').addEventListener('click', () => loadFindingsLibrary());
if ($('#f-from-tpl')) $('#f-from-tpl').addEventListener('click', () => pickTemplateAndApply());

