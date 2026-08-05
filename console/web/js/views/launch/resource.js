// =====================================================================================
//  R3 — PROFIL DE RESSOURCES + OVERRIDES PAR-LEVIER (Launch UI).
//
//  Un bouton `low|balanced|full` fixe les défauts de ressources du moteur, et CHAQUE levier de
//  ressource reste surchargeable individuellement pour ce lancement (« laisser vide = défaut du
//  profil »). CHOIX DE RESSOURCE UNIQUEMENT — aucun impact scope / ROE / plancher d'exploit /
//  sévérité nuclei / coverage-safety.
//
//  SOURCE DE VÉRITÉ = le serveur. `GET /api/resource-profile` fournit (a) l'ALLOWLIST des leviers
//  réglables avec leurs bornes et leurs libellés opérateur, (b) les DÉFAUTS de chaque profil lus dans
//  le moteur (`forge/resource_profile.py`), (c) les leviers de GOUVERNANCE volontairement NON
//  réglables ici, avec la raison. L'UI n'en garde AUCUNE copie : rien à re-synchroniser quand la table
//  du moteur bouge. Si le moteur est injoignable, les champs restent réglables — seuls les défauts
//  affichés manquent (« — »).
//
//  Précédence STRICTE (côté moteur) : override > profil > défaut. Ici : champ vide => on ne pose PAS
//  la variable => défaut du profil. `balanced` sans override => body.resource ABSENT => no-op.
//  Rendu DOM SÛR : textContent uniquement (jamais innerHTML avec de la donnée).
// =====================================================================================
import { api } from '../../core/api.js';
import { $ } from '../../core/dom.js';

// Catalogue servi par /api/resource-profile (null tant qu'il n'est pas chargé / si la lecture échoue).
export let RES_CATALOG = null;

// Charge le catalogue UNE fois par session de page, puis (re)rend le bloc ressources. Idempotent :
// un second appel réutilise le catalogue déjà obtenu (aucune requête supplémentaire).
export async function loadResourceCatalog() {
  if (RES_CATALOG) return RES_CATALOG;
  try {
    RES_CATALOG = await api('/resource-profile');
  } catch (e) {
    RES_CATALOG = null;                       // l'UI reste utilisable, sans les défauts affichés
  }
  renderResourceProfile();
  return RES_CATALOG;
}

// Défauts du profil sélectionné, tels que le MOTEUR les définit ({} si le moteur est injoignable).
function profileKnobs() {
  const prof = ($('#lc-resprofile') && $('#lc-resprofile').value) || 'balanced';
  const profiles = (RES_CATALOG && RES_CATALOG.profiles) || {};
  return profiles[prof] || {};
}

// Valeurs DÉJÀ saisies, relevées avant un re-render (changer de profil ne doit pas effacer le travail
// de l'opérateur : seuls les DÉFAUTS affichés en placeholder changent).
function currentOverrides() {
  const kept = {};
  document.querySelectorAll('#lc-res-overrides input[data-reskey]').forEach(el => {
    if ((el.value || '').trim() !== '') kept[el.dataset.reskey] = el.value;
  });
  return kept;
}

// Un champ d'override : <label><span>libellé</span><input number …></label>. Le placeholder porte le
// défaut du profil (ce que l'opérateur obtient s'il ne touche à rien) ; title porte l'explication.
function knobField(k, defaults, kept) {
  const def = defaults[k.knob];
  const label = document.createElement('label');
  label.style.flex = '0 0 auto';
  label.title = `${k.hint}\nBornes : ${k.min}–${k.max}. Vide = défaut du profil. Variable moteur : ${k.env}.`;
  const span = document.createElement('span');
  span.className = 'lc-lbl';
  span.textContent = k.label;
  const input = document.createElement('input');
  input.type = 'number';
  input.id = 'lc-res-' + k.key;
  input.step = '1';
  input.min = String(k.min);
  input.max = String(k.max);
  input.style.width = '150px';
  input.dataset.reskey = k.key;
  input.dataset.resmin = String(k.min);
  input.dataset.resmax = String(k.max);
  input.placeholder = def === undefined ? '(profil)' : '(profil : ' + def + ')';
  if (kept && kept[k.key] !== undefined) input.value = kept[k.key];   // survit au changement de profil
  label.append(span, input);
  return label;
}

// Le profil d'outils est un ENUM (mini|full) -> select, avec le défaut du profil en 1re option.
function toolsProfileField(choices, defaults) {
  const prev = $('#lc-res-toolsprofile') && $('#lc-res-toolsprofile').value;
  const label = document.createElement('label');
  label.style.flex = '0 0 auto';
  label.title = "Image d'outils du moteur : mini = paquet léger, full = complet. Vide = défaut du profil.";
  const span = document.createElement('span');
  span.className = 'lc-lbl';
  span.textContent = "Paquet d'outils";
  const sel = document.createElement('select');
  sel.id = 'lc-res-toolsprofile';
  const def = defaults.tools_profile;
  const opt0 = document.createElement('option');
  opt0.value = '';
  opt0.textContent = def === undefined ? '(profil)' : '(profil : ' + def + ')';
  sel.appendChild(opt0);
  for (const c of choices) {
    const o = document.createElement('option');
    o.value = c.value;
    o.textContent = c.label;
    sel.appendChild(o);
  }
  if (prev) sel.value = prev;                 // ne perd pas le choix de l'opérateur au re-render
  label.append(span, sel);
  return label;
}

// Rend le bloc ressources : description du profil, champs d'override (générés depuis l'allowlist
// serveur) et tableau des leviers NON réglables ici (gouvernance). DOM SÛR : textContent uniquement.
export function renderResourceProfile() {
  const prof = ($('#lc-resprofile') && $('#lc-resprofile').value) || 'balanced';
  const defaults = profileKnobs();
  const desc = $('#lc-resprofile-desc');
  if (desc) {
    if (!RES_CATALOG) desc.textContent = 'Leviers de ressources : chargement…';
    else if (prof === 'balanced') desc.textContent = 'Défaut : aucune variable forcée, comportement inchangé. Chaque levier reste surchargeable ci-dessous.';
    else if (prof === 'low') desc.textContent = 'Machine faible : exécution en série, outils légers, délais courts, exploration réduite.';
    else desc.textContent = 'Grosse machine : plus d\'actions en parallèle, délais longs, exploration étendue.';
  }
  // (1) champs d'override — un par levier de l'allowlist SERVEUR (l'UI n'en invente aucun).
  const box = $('#lc-res-overrides');
  if (box) {
    const kept = currentOverrides();          // relevé AVANT de vider (re-render = changement de profil)
    box.textContent = '';
    if (!RES_CATALOG || !Array.isArray(RES_CATALOG.knobs)) {
      const p = document.createElement('span');
      p.className = 'muted';
      p.textContent = 'Leviers indisponibles (catalogue non chargé) — le profil ci-dessus reste applicable.';
      box.appendChild(p);
    } else {
      box.appendChild(toolsProfileField(RES_CATALOG.tools_profile_choices || [], defaults));
      for (const k of RES_CATALOG.knobs) box.appendChild(knobField(k, defaults, kept));
    }
  }
  // (2) leviers de GOUVERNANCE : affichés avec leur valeur de profil ET la raison pour laquelle ils
  //     ne se règlent PAS ici (le profil de ressources n'élargit aucune capacité).
  const tb = $('#lc-respresets') && $('#lc-respresets').querySelector('tbody');
  if (tb) {
    tb.textContent = '';
    for (const g of (RES_CATALOG && RES_CATALOG.governed) || []) {
      const tr = document.createElement('tr');
      const th = document.createElement('th');
      th.scope = 'row';
      th.textContent = g.label;
      const td = document.createElement('td');
      const v = defaults[g.knob];
      td.textContent = (v === undefined ? '—' : String(v)) + ' — ' + g.why;
      tr.append(th, td);
      tb.appendChild(tr);
    }
  }
}

// Assemble la portion `resource` du body /api/run. Champs vides/invalides => ABSENTS (défaut du
// profil). `balanced` sans override => objet VIDE => l'appelant NE l'ajoute PAS au body (no-op,
// comportement inchangé). Les bornes sont celles ANNONCÉES par le serveur (data-*) — le serveur les
// re-valide de toute façon (allowlist + bornes côté Rust : une clé inconnue n'atteint jamais l'env).
export function collectResourceBody() {
  const out = {};
  const prof = ($('#lc-resprofile') && $('#lc-resprofile').value) || 'balanced';
  // `balanced` (défaut) => on NE force PAS FORGE_RESOURCE_PROFILE (le serveur l'ignorerait de toute façon).
  if (prof === 'low' || prof === 'full') out.profile = prof;
  const tp = ($('#lc-res-toolsprofile') && $('#lc-res-toolsprofile').value) || '';
  if (tp === 'mini' || tp === 'full') out.tools_profile = tp;
  document.querySelectorAll('#lc-res-overrides input[data-reskey]').forEach(el => {
    const raw = (el.value || '').trim();
    if (raw === '') return;                   // vide = défaut du profil (aucune variable posée)
    const n = Number(raw);
    const min = Number(el.dataset.resmin);
    const max = Number(el.dataset.resmax);
    if (Number.isInteger(n) && n >= min && n <= max) out[el.dataset.reskey] = n;
  });
  return out;
}
