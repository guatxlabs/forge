// =====================================================================================
//  MATRICE ATT&CK PAR ENGAGEMENT (#P2-1) — vraie grille TACTIQUE × TECHNIQUE (kill-chain), pas une
//  liste classée. Colonnes = tactiques ATT&CK ; cellule = technique, colorée par état ROUGE :
//    · exercée + TIRÉE (fires>0)      -> vert   (am-fired)
//    · exercée, non tirée (fires=0)   -> ambre  (am-exercised)
//    · non exercée (catalogue, 0 run) -> grise  (am-none)
//  ATTENTION AU NOM : `fired` = « un run-record de cette technique a TIRÉ » (côté ROUGE). Ce n'est PAS
//  « le SOC l'a détectée » — la détection BLEUE vient de /api/purple/coverage, à trois états
//  (detected-exact / detected-parent-approx / missed). L'API portait la même étiquette `detected` pour
//  ces deux notions distinctes ; elle s'appelle désormais `fired`, et le compte de tirs `fires`.
//  L'enrichissement purple ajoute, best-effort et par id EXACT de technique : le MTTD (détections
//  EXACTES) et le marqueur « parente seule » (angle mort). Données : GET /api/attack-matrix
//  (ENGAGEMENT-SCOPÉ côté serveur) + GET /api/purple/coverage (optionnel — échec silencieux).
//  AUCUNE donnée d'un autre engagement.
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

function cellEl(t, mttdById, approxById) {
  const id = String(t && t.id || '');
  const exercised = !!(t && t.exercised);
  const fired = !!(t && t.fired);                        // côté ROUGE : un run-record a TIRÉ
  const runs = Number(t && t.runs || 0);
  const fires = Number(t && t.fires || 0);
  const state = !exercised ? 'am-none' : (fired ? 'am-fired' : 'am-exercised');
  const stateLabel = !exercised ? 'non exercée' : (fired ? 'tirée' : 'exercée, non tirée');

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

  // ENRICHISSEMENT BLEU (purple, optionnel) : MTTD surfacé UNIQUEMENT s'il a été MESURÉ sur une
  // détection EXACTE de CETTE technique. Le rapprochement « parente seule » est signalé comme tel et
  // n'affiche JAMAIS de MTTD — il n'y a pas de détection de ce vecteur à dater.
  const mttd = mttdById && mttdById.has(id) ? mttdById.get(id) : null;
  const approx = approxById && approxById.get(id);
  const meta = document.createElement('div'); meta.className = 'am-meta';
  if (exercised) {
    let m = `${fires}/${runs} tir/run`;
    if (mttd != null) m += ` · MTTD ${pcFmtSecs(mttd)}`;
    else if (approx) m += ` · SOC : parente ${approx.parent} seule`;
    meta.textContent = m;
    cell.appendChild(meta);
  }

  const nmT = nm ? ` — ${nm}` : '';
  let socT = '';
  if (mttd != null) socT = ` · SOC : détecté exact, MTTD ${pcFmtSecs(mttd)}`;
  else if (approx) socT = ` · SOC : seule la technique parente ${approx.parent} est couverte — la détection de CE vecteur n'est pas prouvée (non comptée dans le taux)`;
  cell.title = `${id}${nmT} — ${stateLabel} (${runs} run(s), ${fires} tir(s))${socT}. Cliquer pour filtrer les findings.`;
  const go = () => gotoTechnique(id);
  cell.onclick = go;
  cell.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } };
  return cell;
}

export async function loadAttackMatrix() {
  const host = $('#am-result'); if (!host) return;
  host.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'chargement…' }));

  let data;
  try { data = await api(withCampaign('/attack-matrix')); }
  catch (e) { host.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'erreur : ' + e.message })); return; }

  const tactics = data && Array.isArray(data.tactics) ? data.tactics : [];

  // ENRICHISSEMENT BLEU best-effort : /api/purple/coverage (mesure défensive optionnelle).
  // Échec/standalone => pas de MTTD ni de marqueur affiché, la grille reste valable (exercé/tiré sont
  // la source de vérité ROUGE). Le rapprochement se fait sur l'id EXACT de la technique : le repli
  // « T1595.003 mesuré sous sa base T1595 » a été RETIRÉ — c'était précisément le parent-approx
  // affiché comme un MTTD de la sous-technique, un chiffre qui ne mesure pas ce qu'il prétend.
  const mttdById = new Map();
  const approxById = new Map();
  try {
    const p = await api(withCampaign('/purple/coverage'));
    const det = p && Array.isArray(p.detected) ? p.detected : [];
    det.forEach(d => { if (d && d.mitre != null && d.mttd_secs != null && isFinite(d.mttd_secs)) mttdById.set(String(d.mitre), Number(d.mttd_secs)); });
    const ap = p && Array.isArray(p.parent_approx) ? p.parent_approx : [];
    ap.forEach(a => { if (a && a.mitre != null) approxById.set(String(a.mitre), { parent: String(a.parent || ''), why: String(a.why || '') }); });
  } catch (e) { /* enrichissement purple optionnel */ }

  // agrégats pour le bandeau (sur l'ensemble des tactiques).
  let totalTech = 0, exTech = 0, firedTech = 0;
  const mttdSamples = [];
  tactics.forEach(t => (t.techniques || []).forEach(x => {
    totalTech++;
    if (x.exercised) exTech++;
    if (x.fired) firedTech++;
    const mv = mttdById.get(String(x.id || ''));
    if (mv != null) mttdSamples.push(mv);
  }));

  host.replaceChildren();

  // bandeau : couverture globale + MTTD médian (si mesuré).
  const band = document.createElement('div'); band.className = 'pc-band';
  const rate = document.createElement('span'); rate.className = 'pc-rate';
  rate.textContent = totalTech ? Math.round(exTech / totalTech * 100) + '%' : '—';
  const sub = document.createElement('span'); sub.className = 'pc-sub';
  sub.textContent = `${exTech}/${totalTech} technique(s) exercée(s) · ${firedTech} tirée(s)`;
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
  legend.innerHTML = '<span class="pc-lg"><span class="am-dot fired"></span>exercée + tirée</span>'
    + '<span class="pc-lg"><span class="am-dot exercised"></span>exercée, non tirée</span>'
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
      techs.forEach(x => col.appendChild(cellEl(x, mttdById, approxById)));
    }
    grid.appendChild(col);
  });
  if (!grid.childElementCount) {
    host.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune technique ATT&CK — lancez un run pour peupler la matrice' }));
    return;
  }
  host.appendChild(grid);
}
