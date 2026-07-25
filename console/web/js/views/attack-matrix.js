// =====================================================================================
//  MATRICE ATT&CK PAR ENGAGEMENT (#P2-1) — vraie grille TACTIQUE × TECHNIQUE (kill-chain), pas une
//  liste classée. Colonnes = tactiques ATT&CK ; cellule = technique, colorée par état :
//    · exercée + détectée (fired>0)   -> vert   (am-detected)
//    · exercée, non détectée (fired=0)-> ambre  (am-exercised)
//    · non exercée (catalogue, 0 run) -> grise  (am-none)
//  Le MTTD (source de détection / purple) est fusionné best-effort par id de technique et surfacé en
//  annotation + tooltip. Données : GET /api/attack-matrix (ENGAGEMENT-SCOPÉ côté serveur) + enrichi par
//  GET /api/purple/coverage (MTTD, optionnel — échec silencieux). AUCUNE donnée d'un autre engagement.
// =====================================================================================
import { api, withCampaign } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { runQuery } from './explore.js';
import { pcFmtSecs, pcMedian } from './coverage.js';

// Noms ATT&CK lisibles (SUCRE d'affichage — l'id reste la vérité, toujours montré). Best-effort :
// un id absent de ce map n'affiche que son id (jamais de nom inventé). Miroir des ids émis par
// forge/techniques_data.py (champ `mitre`).
const ATTACK_NAMES = {
  'T1046': 'Network Service Discovery',
  'T1059': 'Command and Scripting Interpreter',
  'T1068': 'Exploitation for Privilege Escalation',
  'T1110': 'Brute Force',
  'T1110.001': 'Brute Force : Password Guessing',
  'T1190': 'Exploit Public-Facing Application',
  'T1204': 'User Execution',
  'T1204.001': 'User Execution : Malicious Link',
  'T1210': 'Exploitation of Remote Services',
  'T1212': 'Exploitation for Credential Access',
  'T1406': 'Obfuscated Files or Information',
  'T1528': 'Steal Application Access Token',
  'T1539': 'Steal Web Session Cookie',
  'T1552': 'Unsecured Credentials',
  'T1552.001': 'Unsecured Credentials : Credentials In Files',
  'T1556': 'Modify Authentication Process',
  'T1584': 'Compromise Infrastructure',
  'T1584.001': 'Compromise Infrastructure : Domains',
  'T1590': 'Gather Victim Network Information',
  'T1590.002': 'Gather Victim Network Information : DNS',
  'T1590.005': 'Gather Victim Network Information : IP Addresses',
  'T1592': 'Gather Victim Host Information',
  'T1592.002': 'Gather Victim Host Information : Software',
  'T1594': 'Search Victim-Owned Websites',
  'T1595': 'Active Scanning',
  'T1595.002': 'Active Scanning : Vulnerability Scanning',
  'T1595.003': 'Active Scanning : Wordlist Scanning',
  'T1596': 'Search Open Technical Databases',
  'T1606': 'Forge Web Credentials',
};
const techName = id => ATTACK_NAMES[id] || '';

// filtre les findings sur une technique (réutilise le pont Explore, comme la couverture purple).
function gotoTechnique(mitre) {
  if (!mitre) return;
  if ($('#sql')) $('#sql').value = `search mitre="${String(mitre).replace(/"/g, '')}"`;
  location.hash = 'explore';
  runQuery();
}

function cellEl(t, mttdById) {
  const id = String(t && t.id || '');
  const exercised = !!(t && t.exercised);
  const detected = !!(t && t.detected);
  const runs = Number(t && t.runs || 0);
  const fired = Number(t && t.fired || 0);
  const state = !exercised ? 'am-none' : (detected ? 'am-detected' : 'am-exercised');
  const stateLabel = !exercised ? 'non exercée' : (detected ? 'détectée' : 'exercée');

  const cell = document.createElement('div');
  cell.className = 'am-cell ' + state;
  cell.tabIndex = 0;
  cell.setAttribute('role', 'button');

  const mid = document.createElement('div'); mid.className = 'am-id';
  mid.textContent = id;                                  // esc implicite : textContent, pas d'innerHTML
  cell.appendChild(mid);

  const nm = techName(id);
  if (nm) { const nmEl = document.createElement('div'); nmEl.className = 'am-name'; nmEl.textContent = nm; cell.appendChild(nmEl); }

  const st = document.createElement('div'); st.className = 'am-st';
  const dot = document.createElement('span'); dot.className = 'am-dot';
  const lbl = document.createElement('span'); lbl.textContent = stateLabel;
  st.append(dot, lbl); cell.appendChild(st);

  // MTTD : surfacé UNIQUEMENT si mesuré (null-safe). Sur cellule détectée : annotation ; sinon tooltip.
  const mttd = mttdByIdGet(mttdById, id);
  const meta = document.createElement('div'); meta.className = 'am-meta';
  if (exercised) {
    let m = `${fired}/${runs} tir/run`;
    if (detected && mttd != null) m += ` · MTTD ${pcFmtSecs(mttd)}`;
    meta.textContent = m;
    cell.appendChild(meta);
  }

  const nmT = nm ? ` — ${nm}` : '';
  const mttdT = (detected && mttd != null) ? ` · MTTD ${pcFmtSecs(mttd)}` : (detected ? ' · MTTD n/d' : '');
  cell.title = `${id}${nmT} — ${stateLabel} (${runs} run(s), ${fired} tir(s))${mttdT}. Cliquer pour filtrer les findings.`;
  const go = () => gotoTechnique(id);
  cell.onclick = go;
  cell.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } };
  return cell;
}

// MTTD by id : tolère T1595.003 mesuré sous sa base T1595 (repli), sinon exact.
function mttdByIdGet(map, id) {
  if (!map) return null;
  if (map.has(id)) return map.get(id);
  const dot = id.indexOf('.');
  if (dot > 0 && map.has(id.slice(0, dot))) return map.get(id.slice(0, dot));
  return null;
}

export async function loadAttackMatrix() {
  const host = $('#am-result'); if (!host) return;
  host.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'chargement…' }));

  let data;
  try { data = await api(withCampaign('/attack-matrix')); }
  catch (e) { host.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'erreur : ' + e.message })); return; }

  const tactics = data && Array.isArray(data.tactics) ? data.tactics : [];

  // MTTD best-effort : /api/purple/coverage (mesure défensive optionnelle). Échec/standalone => pas de
  // MTTD affiché, la grille reste valable (exercé/détecté sont la source de vérité).
  const mttdById = new Map();
  try {
    const p = await api(withCampaign('/purple/coverage'));
    const det = p && Array.isArray(p.detected) ? p.detected : [];
    det.forEach(d => { if (d && d.mitre != null && d.mttd_secs != null && isFinite(d.mttd_secs)) mttdById.set(String(d.mitre), Number(d.mttd_secs)); });
  } catch (e) { /* MTTD optionnel */ }

  // agrégats pour le bandeau (sur l'ensemble des tactiques).
  let totalTech = 0, exTech = 0, detTech = 0;
  const mttdSamples = [];
  tactics.forEach(t => (t.techniques || []).forEach(x => {
    totalTech++;
    if (x.exercised) exTech++;
    if (x.detected) { detTech++; const mv = mttdByIdGet(mttdById, String(x.id || '')); if (mv != null) mttdSamples.push(mv); }
  }));

  host.replaceChildren();

  // bandeau : couverture globale + MTTD médian (si mesuré).
  const band = document.createElement('div'); band.className = 'pc-band';
  const rate = document.createElement('span'); rate.className = 'pc-rate';
  rate.textContent = totalTech ? Math.round(exTech / totalTech * 100) + '%' : '—';
  const sub = document.createElement('span'); sub.className = 'pc-sub';
  sub.textContent = `${exTech}/${totalTech} technique(s) exercée(s) · ${detTech} détectée(s)`;
  band.append(rate, sub);
  const med = pcMedian(mttdSamples);
  if (med != null) {
    const sep = document.createElement('span'); sep.className = 'pc-sep'; band.appendChild(sep);
    const mttdEl = document.createElement('span'); mttdEl.className = 'pc-sub';
    mttdEl.innerHTML = `MTTD médian <b>${esc(pcFmtSecs(med))}</b>`;
    band.appendChild(mttdEl);
  }
  host.appendChild(band);

  // légende.
  const legend = document.createElement('div'); legend.className = 'pc-legend';
  legend.innerHTML = '<span class="pc-lg"><span class="am-dot detected"></span>exercée + détectée</span>'
    + '<span class="pc-lg"><span class="am-dot exercised"></span>exercée, non détectée</span>'
    + '<span class="pc-lg"><span class="am-dot none"></span>non exercée (couverture manquante)</span>';
  host.appendChild(legend);

  // grille : une colonne par tactique (ordre kill-chain, fourni par le serveur). Défilement horizontal
  // pour ne jamais faire déborder la page. Colonne vide = trou de couverture (rendu explicite).
  const grid = document.createElement('div'); grid.className = 'am-grid';
  tactics.forEach(t => {
    const col = document.createElement('div'); col.className = 'am-col';
    const techs = Array.isArray(t.techniques) ? t.techniques : [];
    const ex = techs.filter(x => x.exercised).length;
    const head = document.createElement('div'); head.className = 'am-colhead';
    const h = document.createElement('div'); h.className = 'am-ct'; h.textContent = String(t.tactic || '');
    const cnt = document.createElement('div'); cnt.className = 'am-cc'; cnt.textContent = `${ex}/${techs.length}`;
    head.append(h, cnt); col.appendChild(head);
    if (!techs.length) {
      const empty = document.createElement('div'); empty.className = 'am-empty'; empty.textContent = '—';
      col.appendChild(empty);
    } else {
      techs.forEach(x => col.appendChild(cellEl(x, mttdById)));
    }
    grid.appendChild(col);
  });
  if (!grid.childElementCount) {
    host.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune technique ATT&CK — lancez un run pour peupler la matrice' }));
    return;
  }
  host.appendChild(grid);
}
