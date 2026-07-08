import { api, token, write } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { guardList, toast } from '../core/ui.js';

export let TQ = { profile: 'bug_bounty', rowByKind: {}, groups: {}, desired: {} };

// Base d'un profil côté client — miroir COSMÉTIQUE de forge.techniques (prefill des cases au changement
// de profil). Le MOTEUR reste autoritatif : le prefill se recorrige au rechargement après enregistrement.
// bug_bounty = bb-eligible ∪ recon (infra) ; pentest = tout ; custom = rien.
export function tqBase(row, profile) {
  if (profile === 'pentest') return true;
  if (profile === 'custom') return false;
  return !!row.bug_bounty_eligible || row.phase === 'recon';
}

export async function loadTechniques() {
  const host = $('#tq-groups'); if (!host) return;
  let cat;
  try { cat = await api('/techniques'); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  if (cat && cat.error) {
    host.innerHTML = '<div class="bad">catalogue indisponible : ' + esc(String(cat.why || cat.error)) + '</div>';
    if ($('#tq-count')) $('#tq-count').textContent = '';
    return;
  }
  TQ.groups = cat.groups || {};
  TQ.profile = cat.profile || 'bug_bounty';
  TQ.rowByKind = {}; TQ.desired = {};
  let total = 0;
  Object.values(TQ.groups).forEach(rows => (rows || []).forEach(r => {
    TQ.rowByKind[r.kind] = r; TQ.desired[r.kind] = !!r.enabled_for_current_scope; total++;
  }));
  if ($('#tq-profile')) $('#tq-profile').value = TQ.profile;
  if ($('#tq-count')) $('#tq-count').textContent = total + ' techniques';
  renderTechniques();
}

export function tqEnabledCount() { return Object.values(TQ.desired).filter(Boolean).length; }

export function renderTechniques() {
  const host = $('#tq-groups'); if (!host) return;
  const cats = Object.keys(TQ.groups).sort();
  if (guardList(host, cats, 'aucune technique')) return;
  host.replaceChildren(...cats.map(cat => {
    const rows = (TQ.groups[cat] || []).slice().sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
    const on = rows.filter(r => TQ.desired[r.kind]).length;
    const card = document.createElement('div'); card.className = 'tq-cat';
    const head = document.createElement('div'); head.className = 'tq-cathead';
    head.innerHTML = `<span class="tq-catname">${esc(cat)} <span class="badge tq-catcount">${on}/${rows.length}</span></span>`;
    const acts = document.createElement('span'); acts.className = 'tq-catacts';
    const bAll = document.createElement('button'); bAll.type = 'button'; bAll.className = 'k-theme'; bAll.textContent = 'Tout activer';
    const bNone = document.createElement('button'); bNone.type = 'button'; bNone.className = 'k-theme'; bNone.textContent = 'Tout désactiver';
    bAll.onclick = () => { rows.forEach(r => { TQ.desired[r.kind] = true; }); renderTechniques(); };
    bNone.onclick = () => { rows.forEach(r => { TQ.desired[r.kind] = false; }); renderTechniques(); };
    acts.append(bAll, bNone); head.appendChild(acts); card.appendChild(head);
    const list = document.createElement('div'); list.className = 'tq-list';
    rows.forEach(r => {
      const lab = document.createElement('label'); lab.className = 'tq-item' + (TQ.desired[r.kind] ? '' : ' off');
      const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !!TQ.desired[r.kind];
      cb.onchange = () => {
        TQ.desired[r.kind] = cb.checked; lab.classList.toggle('off', !cb.checked);
        const b = head.querySelector('.tq-catcount'); if (b) b.textContent = rows.filter(x => TQ.desired[x.kind]).length + '/' + rows.length;
      };
      const meta = document.createElement('span'); meta.className = 'tq-meta';
      const badges = [];
      if (r.bug_bounty_eligible) badges.push('<span class="badge webyes">BB</span>');
      if (r.pentest_only) badges.push('<span class="badge expl">pentest</span>');
      const tools = (r.tools || []).join(', ');
      meta.innerHTML = `<span class="tq-kind">${esc(r.kind)}</span> ${badges.join('')}`
        + (r.mitre ? ` <code class="tq-mitre">${esc(r.mitre)}</code>` : '')
        + (tools ? `<span class="tq-tools" title="outils qui couvrent cette technique">${esc(tools)}</span>` : '');
      lab.append(cb, meta); list.appendChild(lab);
    });
    card.appendChild(list);
    return card;
  }));
}

// changement de profil : re-prefill COSMÉTIQUE des cases à la base du profil (moteur autoritatif au save).
if ($('#tq-profile')) $('#tq-profile').addEventListener('change', () => {
  TQ.profile = $('#tq-profile').value;
  Object.values(TQ.rowByKind).forEach(r => { TQ.desired[r.kind] = tqBase(r, TQ.profile); });
  renderTechniques();
});
if ($('#tq-reload')) $('#tq-reload').addEventListener('click', loadTechniques);
if ($('#tq-save')) $('#tq-save').addEventListener('click', async () => {
  // On envoie un profil + une map TECHNIQUE COMPLÈTE (kind -> désiré) : elle définit sans ambiguïté
  // l'ensemble activé pour les kinds courants, tout en laissant un futur module hériter de la base du
  // profil (kind absent de la map -> résolu par le profil). Le moteur ENFORCE ; ici on persiste l'intention.
  const techniques = {}; Object.keys(TQ.desired).forEach(k => { techniques[k] = !!TQ.desired[k]; });
  const body = { profile: TQ.profile, categories: {}, techniques };
  const st = $('#tq-status');
  try {
    const r = await write('/api/techniques/selection', { body, auth: 'token', engagement: true });
    if (r.status === 403) { toast('Sélection réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String(r.json.why || r.json.error || r.status), 'bad'); return; }
    toast('Sélection enregistrée (ledgerisée)', 'ok');
    if (st) { st.hidden = false; st.textContent = 'Sélection persistée — appliquée aux prochains runs (' + tqEnabledCount() + ' techniques activées).'; }
    loadTechniques();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
});

// =====================================================================================
//  WORKFLOWS — pipelines COMPOSÉS sans code (absorbe reNgine/Osmedeus/Trickest). Un workflow est une
//  PROPOSITION gouvernée : GET /api/workflows (utilisateur + intégrés dérivés du registre) + le
//  catalogue /api/techniques (groupé par catégorie + état ACTIVÉ par le scope) alimentent le builder ;
//  la MUTATION (POST /api/workflows[/:name]) est operator/admin + ledgerisée. « Lancer ce workflow »
//  passe par le C2 GOUVERNÉ (POST /api/run modules=étapes, auto_pentest) — le scope-guard ROE, la
//  sélection par-scope et l'opt-in fort-impact restent seuls JUGES (étape hors-scope/désactivée larguée).
// =====================================================================================
