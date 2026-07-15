import { api, write } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { guardList, modalConfirm, modalPrompt, toast } from '../core/ui.js';

// TQ.profile porte la valeur du sélecteur : un profil de BASE ('bug_bounty'|'pentest'|'custom') OU un
// profil NOMMÉ ('named:<nom>'). TQ.named = bibliothèque de profils nommés {nom: {profile,categories,
// techniques}} servie par /api/techniques. TQ.desired = LA sélection live (toggles) — source de vérité.
export let TQ = { profile: 'bug_bounty', rowByKind: {}, groups: {}, desired: {}, named: {} };

const BASE_PROFILES = ['bug_bounty', 'pentest', 'custom'];
const isNamed = p => String(p || '').startsWith('named:');
const namedName = p => String(p || '').slice(6);
const validProfileName = s => /^[A-Za-z0-9._-]{1,64}$/.test(s) && !s.startsWith('-') && !BASE_PROFILES.includes(s);

// Base d'un profil côté client — miroir COSMÉTIQUE de forge.techniques (prefill des cases au changement
// de profil). Le MOTEUR reste autoritatif : le prefill se recorrige au rechargement après enregistrement.
// bug_bounty = bb-eligible ∪ recon (infra) ; pentest = tout ; custom = rien.
export function tqBase(row, profile) {
  if (profile === 'pentest') return true;
  if (profile === 'custom') return false;
  return !!row.bug_bounty_eligible || row.phase === 'recon';
}

// Applique un profil NOMMÉ (snapshot complet) aux toggles courants : un kind présent dans le snapshot
// prend sa valeur, un kind absent (profil plus ancien qu'un module récent) = OFF (fail-closed).
function applyNamedSelection(sel) {
  const t = (sel && sel.techniques) || {};
  Object.keys(TQ.rowByKind).forEach(k => { TQ.desired[k] = !!t[k]; });
}

// Détecte le profil ACTIF à l'entrée : si les toggles chargés (sélection persistée) correspondent
// EXACTEMENT à un profil nommé, on le re-sélectionne (l'opérateur RETROUVE son profil, pas « custom ») ;
// sinon on garde le profil de base persisté par le moteur (cat.profile).
function detectActiveProfile(base) {
  const kinds = Object.keys(TQ.rowByKind);
  if (kinds.length) {
    for (const n of Object.keys(TQ.named).sort()) {
      const t = (TQ.named[n] && TQ.named[n].techniques) || {};
      if (kinds.every(k => (!!TQ.desired[k]) === (!!t[k]))) return 'named:' + n;
    }
  }
  return BASE_PROFILES.includes(base) ? base : 'custom';
}

// (Re)peuple le sélecteur : profils de base + optgroup des profils nommés. Sélectionne TQ.profile.
function renderProfileSelect() {
  const sel = $('#tq-profile'); if (!sel) return;
  sel.replaceChildren();
  BASE_PROFILES.forEach(p => { const o = document.createElement('option'); o.value = p; o.textContent = p; sel.appendChild(o); });
  const names = Object.keys(TQ.named).sort();
  if (names.length) {
    const og = document.createElement('optgroup'); og.label = 'Profils enregistrés';
    names.forEach(n => { const o = document.createElement('option'); o.value = 'named:' + n; o.textContent = n; og.appendChild(o); });
    sel.appendChild(og);
  }
  sel.value = TQ.profile;
  syncDeleteBtn();
}

// Le bouton « Supprimer le profil » n'est actif que si un profil NOMMÉ est sélectionné (fail-closed UI).
function syncDeleteBtn() {
  const btn = $('#tq-delete'); if (!btn) return;
  btn.disabled = !isNamed(TQ.profile);
  btn.title = isNamed(TQ.profile) ? 'Supprimer le profil enregistré sélectionné (operator/admin, ledgerisé)'
    : 'Sélectionne un profil enregistré pour pouvoir le supprimer';
}

export async function loadTechniques() {
  const host = $('#tq-groups'); if (!host) return;
  let cat;
  try { cat = await api('/techniques'); }
  catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  // Profils nommés servis même quand le moteur (groupes) est indisponible.
  TQ.named = (cat && cat.named_profiles && typeof cat.named_profiles === 'object') ? cat.named_profiles : {};
  if (cat && cat.error && !cat.groups) {
    TQ.groups = {}; TQ.rowByKind = {}; TQ.desired = {};
    host.innerHTML = '<div class="bad">catalogue indisponible : ' + esc(String(cat.why || cat.error)) + '</div>';
    if ($('#tq-count')) $('#tq-count').textContent = '';
    TQ.profile = BASE_PROFILES.includes(cat.profile) ? cat.profile : 'bug_bounty';
    renderProfileSelect();
    return;
  }
  TQ.groups = cat.groups || {};
  TQ.rowByKind = {}; TQ.desired = {};
  let total = 0;
  Object.values(TQ.groups).forEach(rows => (rows || []).forEach(r => {
    TQ.rowByKind[r.kind] = r; TQ.desired[r.kind] = !!r.enabled_for_current_scope; total++;
  }));
  // Charge la sélection SAUVÉE à l'entrée (persistance across nav) et re-sélectionne le profil actif.
  TQ.profile = detectActiveProfile(cat.profile || 'bug_bounty');
  renderProfileSelect();
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

// changement de profil : APPLIQUE le profil aux toggles (base = prefill cosmétique ; nommé = snapshot).
// Rien n'est persisté ici — « appliquer » est purement client ; c'est « Enregistrer comme profil… » qui
// persiste. La sélection résultante (TQ.desired) reste la source de vérité pour l'enregistrement.
if ($('#tq-profile')) $('#tq-profile').addEventListener('change', () => {
  TQ.profile = $('#tq-profile').value;
  if (isNamed(TQ.profile)) applyNamedSelection(TQ.named[namedName(TQ.profile)] || {});
  else Object.values(TQ.rowByKind).forEach(r => { TQ.desired[r.kind] = tqBase(r, TQ.profile); });
  syncDeleteBtn();
  renderTechniques();
});
if ($('#tq-reload')) $('#tq-reload').addEventListener('click', loadTechniques);

// Construit + POST la sélection courante (map TECHNIQUE COMPLÈTE kind->désiré : sans ambiguïté). `extra`
// porte `save_as` (enregistrer sous un nom réutilisable). auth:'operator' -> l'en-tête X-Forge-Operator +
// le COOKIE de session admin/operator autorisent (aucun token séparé à coller) ; mutation ledgerisée serveur.
async function saveSelection(extra) {
  const techniques = {}; Object.keys(TQ.desired).forEach(k => { techniques[k] = !!TQ.desired[k]; });
  const base = isNamed(TQ.profile) ? 'custom' : TQ.profile;
  const body = Object.assign({ profile: base, categories: {}, techniques }, extra || {});
  const st = $('#tq-status');
  try {
    const r = await write('/api/techniques/selection', { body, auth: 'operator', engagement: true });
    if (r.status === 403) { toast('Sélection réservée à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String((r.json && (r.json.why || r.json.error)) || r.status), 'bad'); return; }
    toast(extra && extra.save_as ? ('Profil « ' + extra.save_as + ' » enregistré (ledgerisé)') : 'Sélection enregistrée (ledgerisée)', 'ok');
    if (st) { st.hidden = false; st.textContent = 'Sélection persistée — appliquée aux prochains runs (' + tqEnabledCount() + ' techniques activées).'; }
    loadTechniques();
  } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
}

// « Enregistrer comme profil… » : DEMANDE un nom, puis enregistre la sélection courante SOUS ce nom
// (création ou mise à jour) EN PLUS de l'appliquer comme sélection active de l'engagement.
if ($('#tq-save')) $('#tq-save').addEventListener('click', async () => {
  const suggested = isNamed(TQ.profile) ? namedName(TQ.profile) : '';
  const name = await modalPrompt({
    title: 'Enregistrer comme profil',
    message: 'Enregistre la sélection COURANTE (toggles) sous un nom RÉUTILISABLE (ex : bug_bounty_web, pentest_interne). Un nom existant est mis à jour. Operator/admin — action ledgerisée.',
    label: 'Nom du profil',
    value: suggested,
    placeholder: 'bug_bounty_web',
    confirmText: 'Enregistrer',
    hint: '[A-Za-z0-9._-], 1 à 64 — hors bug_bounty/pentest/custom (réservés).',
    required: true,
    validate: v => { const s = String(v || '').trim(); return validProfileName(s) ? null : 'Nom invalide ou réservé.'; },
  });
  if (name === null) return;
  await saveSelection({ save_as: String(name).trim() });
});

// « Supprimer le profil » : retire le profil NOMMÉ sélectionné (global). N'affecte PAS la sélection active.
if ($('#tq-delete')) $('#tq-delete').addEventListener('click', async () => {
  if (!isNamed(TQ.profile)) { toast('Sélectionne un profil enregistré à supprimer.', 'bad'); return; }
  const name = namedName(TQ.profile);
  if (!(await modalConfirm({ title: 'Supprimer le profil', message: 'Supprimer le profil « ' + name + ' » ? La sélection active de l\'engagement n\'est pas modifiée.', confirmText: 'Supprimer', danger: true }))) return;
  try {
    const r = await write('/api/techniques/selection', { body: { delete_profile: name }, auth: 'operator' });
    if (r.status === 403) { toast('Réservé à un compte operator/admin', 'bad'); return; }
    if (!r.ok) { toast('Échec : ' + String((r.json && (r.json.why || r.json.error)) || r.status), 'bad'); return; }
    toast('Profil « ' + name + ' » supprimé.', 'ok');
    TQ.profile = 'custom';
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
