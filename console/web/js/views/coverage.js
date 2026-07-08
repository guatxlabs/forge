import { api, withCampaign } from '../core/api.js';
import { $, esc, fmtTs, ic } from '../core/dom.js';
import { runQuery } from './explore.js';
import { openHelp } from '../core/help.js';
import { guardList } from '../core/ui.js';

export async function loadCoverage() {
  const host = $('#cov-result'); if (!host) return;
  let cov = [];
  try { cov = await api(withCampaign('/coverage')); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  if (guardList(host, Array.isArray(cov) && cov, 'aucun run-record')) return;
  cov.sort((a, b) => (b.runs || 0) - (a.runs || 0));
  const max = Math.max(1, ...cov.map(c => c.runs || 0));
  const wrap = document.createElement('div'); wrap.className = 'bars';
  cov.forEach(c => {
    const row = document.createElement('div'); row.className = 'barrow covrow'; row.style.cursor = 'pointer'; row.title = 'Cliquer pour filtrer les findings sur cette technique';
    const lab = document.createElement('span'); lab.className = 'barlabel'; lab.innerHTML = `<code>${esc(c.mitre)}</code>`;
    const track = document.createElement('div'); track.className = 'bartrack';
    const fill = document.createElement('div'); fill.className = 'barfill'; fill.style.width = ((c.runs || 0) / max * 100) + '%';
    const firedFill = document.createElement('div'); firedFill.className = 'barfill fired'; firedFill.style.width = ((c.fired || 0) / max * 100) + '%';
    track.append(fill, firedFill);
    const val = document.createElement('span'); val.className = 'barval'; val.textContent = `${c.fired || 0}/${c.runs || 0}`;
    row.onclick = () => { $('#sql').value = `search mitre="${c.mitre}"`; location.hash = 'explore'; runQuery(); };
    row.append(lab, track, val); wrap.appendChild(row);
  });
  host.replaceChildren(wrap);
}

// =====================================================================================
//  DÉTECTION PURPLE — corrélation Forge (red, techniques tirées) vs Plume (blue, détections SOC)
//  Lecture seule : GET /api/purple/coverage[?campaign=X]. Mesure DÉFENSIVE pure (detected / missed
//  / MTTD) — expose les trous de détection du SOC. AUCUNE action offensive ici.
//  Contrat de réponse 200 (cf. blueprint) :
//    { plume_reachable, plume_url, techniques_fired, techniques_detected, techniques_missed,
//      detection_rate (0..1), mttd_avg_secs|null, mttd_max_secs|null,
//      detected:[{mitre,fires,alert_count,first_detection_ts,fire_ts|null,mttd_secs|null}] (tri mitre ASC),
//      missed:[{mitre,fires,fire_ts|null}], error (présent SEULEMENT si plume_reachable=false) }
//  Garantie côté serveur (qu'on REFLÈTE fidèlement, jamais on n'invente) : si plume_reachable=false,
//  detected=[] missed=[] rate=0 mttd=null detected/missed=0 -> on affiche la mesure comme IMPOSSIBLE
//  (FAIL-OPEN LISIBLE), pas comme « 0 % détecté ».
// =====================================================================================
export function pcFmtSecs(s) {                                // MTTD : secondes -> libellé court lisible (Xs / Xm Ys / Xh Ym)
  if (s == null || !isFinite(s)) return '—';
  const n = Math.max(0, Math.round(Number(s)));
  if (n < 60) return n + 's';
  if (n < 3600) { const m = Math.floor(n / 60), r = n % 60; return r ? `${m}m ${r}s` : `${m}m`; }
  const h = Math.floor(n / 3600), m = Math.round((n % 3600) / 60); return m ? `${h}h ${m}m` : `${h}h`;
}
export function pcMedian(nums) {                               // MTTD médian pour le bandeau (échantillons mesurables uniquement)
  const a = nums.filter(v => v != null && isFinite(v)).map(Number).sort((x, y) => x - y);
  if (!a.length) return null;
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}
export function pcGotoTechnique(mitre) {                       // clic tuile -> filtre les findings sur la technique (Explore)
  if (!mitre) return;
  if ($('#sql')) $('#sql').value = `search mitre="${String(mitre).replace(/"/g, '')}"`;
  location.hash = 'explore';
  runQuery();
}
export function pcTile(mitre, state, stateLabel, metaText, title) {
  const tile = document.createElement('div'); tile.className = 'pc-tile ' + state;
  tile.title = title || 'Cliquer pour filtrer les findings sur cette technique';
  const m = document.createElement('div'); m.className = 'pc-mitre'; m.textContent = mitre;
  const st = document.createElement('div'); st.className = 'pc-state';
  const dot = document.createElement('span'); dot.className = 'pc-dot';
  const lbl = document.createElement('span'); lbl.textContent = stateLabel;
  st.append(dot, lbl);
  tile.append(m, st);
  if (metaText) { const meta = document.createElement('div'); meta.className = 'pc-meta'; meta.textContent = metaText; tile.appendChild(meta); }
  tile.onclick = () => pcGotoTechnique(mitre);
  return tile;
}
export async function loadPurpleCoverage() {
  const host = $('#pc-result'); if (!host) return;
  const plumeBadge = $('#pc-plume');
  let p;
  try { p = await api(withCampaign('/purple/coverage')); }
  catch (e) {
    host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>';
    if (plumeBadge) { plumeBadge.className = 'badge mut'; plumeBadge.textContent = '—'; }
    return;
  }
  // Une source de détection est-elle CONFIGURÉE ? Sinon Forge tourne en AUTONOME (standalone) : ce
  // n'est PAS une panne. Priorité au champ serveur `source_configured` ; repli (payload ancien) sur
  // la présence d'un endpoint. `reachable` accepte les deux noms (source_/plume_ rétro-compat).
  const srcUrl = String(p.source_url || p.plume_url || '');
  const configured = (p.source_configured === true)
    || (p.source_configured === undefined && !!srcUrl);
  const reachable = (p.source_reachable === true) || (p.plume_reachable === true);

  // badge source de détection : autonome (neutre) / joignable / injoignable.
  if (plumeBadge) {
    if (!configured) {
      plumeBadge.className = 'badge mut';
      plumeBadge.textContent = 'Autonome (standalone)';
      plumeBadge.title = 'Aucune source de détection configurée — Forge fonctionne en autonome. Connectez une source (Plume/CrowdSec/FortiGate/Elastic/fichier…) dans Administration pour activer la boucle purple.';
    } else {
      plumeBadge.className = 'badge ' + (reachable ? 'ok' : 'destr');
      plumeBadge.innerHTML = `${ic(reachable ? 'check' : 'warn')} Source ${reachable ? 'joignable' : 'injoignable'}`;
      plumeBadge.title = srcUrl || (p.source_kind ? ('kind=' + p.source_kind) : 'source de détection');
    }
  }
  host.replaceChildren();

  // techniques distinctes tirées (toujours informatif, même si mesure impossible)
  const fired = Number(p.techniques_fired || 0);
  const detected = Array.isArray(p.detected) ? p.detected : [];
  const missed = Array.isArray(p.missed) ? p.missed : [];

  // AUTONOME (standalone) : aucune source de détection configurée. État NEUTRE et ATTENDU — Forge ne
  // dépend d'aucune source. On rend un « connectez une source » clair, PAS une erreur : l'UI ne paraît
  // jamais cassée. Plume n'est qu'un préréglage parmi d'autres.
  if (!configured) {
    const so = document.createElement('div'); so.className = 'pc-standalone';
    const head = document.createElement('div'); head.className = 'pc-so-head';
    head.innerHTML = `${ic('plug')} <span>Aucune source de détection configurée — Forge fonctionne en autonome</span><span class="pc-dtag">standalone</span>`;
    const det = document.createElement('div'); det.className = 'pc-so-detail';
    det.innerHTML = `Forge ne dépend d'aucune source de détection. Connectez-en une (Plume, CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, fichier…) dans <a href="#admin-detection">Administration &rarr; Source de détection</a> pour activer la boucle purple (détecté / raté / MTTD). ${fired} technique(s) distincte(s) déjà tirée(s) côté Forge en attendant.`;
    // actions d'aide : ouvrir directement la source de détection + expliquer la boucle purple (aide in-app).
    const acts = document.createElement('div'); acts.className = 'pc-so-acts';
    const goBtn = document.createElement('a'); goBtn.href = '#admin-detection'; goBtn.className = 'k-theme'; goBtn.innerHTML = `${ic('plug')}<span>Connecter une source</span>`;
    const helpBtn = document.createElement('button'); helpBtn.type = 'button'; helpBtn.className = 'k-theme'; helpBtn.innerHTML = `${ic('help')}<span>Comment ça marche&nbsp;?</span>`;
    helpBtn.addEventListener('click', () => openHelp('purple-coverage'));
    acts.append(goBtn, helpBtn);
    so.append(head, det, acts);
    host.appendChild(so);
    return;
  }

  // FAIL-OPEN LISIBLE : source configurée mais INJOIGNABLE -> mesure impossible (anomalie). On n'affiche
  // AUCUN « détecté » ni taux : ce ne sont pas des 0 réels, c'est de l'absence de mesure. On reste honnête.
  if (!reachable) {
    const fo = document.createElement('div'); fo.className = 'pc-failopen';
    const head = document.createElement('div'); head.className = 'pc-fo-head';
    head.innerHTML = `${ic('warn')} <span>Mesure de détection impossible — source injoignable (fail-open lisible)</span><span class="pc-dtag">non mesuré</span>`;
    const det = document.createElement('div'); det.className = 'pc-fo-detail';
    const reason = (typeof p.error === 'string' && p.error) ? p.error : 'source de détection injoignable';
    const urlTxt = srcUrl ? `cible : ${srcUrl}` : 'endpoint non renseigné';
    det.textContent = `${reason} — ${urlTxt}. Aucun « détecté » n'est inventé : detected/missed vides, taux et MTTD non mesurés. ${fired} technique(s) distincte(s) tirée(s) côté Forge (information offensive conservée).`;
    fo.append(head, det);
    host.appendChild(fo);
    return;
  }

  // ---- source de détection joignable : mesure exploitable -----------------------------------
  const nDet = detected.length, nMiss = missed.length, total = nDet + nMiss;
  const rate = (typeof p.detection_rate === 'number' && isFinite(p.detection_rate)) ? p.detection_rate : (total ? nDet / total : 0);
  const ratePct = Math.round(Math.max(0, Math.min(1, rate)) * 100);
  const mttdMedian = pcMedian(detected.map(d => d.mttd_secs));

  // bandeau : « M/N détectées, MTTD médian Xs »
  const band = document.createElement('div'); band.className = 'pc-band';
  const rateEl = document.createElement('span'); rateEl.className = 'pc-rate'; rateEl.textContent = ratePct + '%';
  const subEl = document.createElement('span'); subEl.className = 'pc-sub';
  subEl.textContent = `${nDet}/${total || fired} technique(s) détectée(s) par le SOC`;
  band.append(rateEl, subEl);
  const sep1 = document.createElement('span'); sep1.className = 'pc-sep'; band.appendChild(sep1);
  const mttdEl = document.createElement('span'); mttdEl.className = 'pc-mttd pc-sub';
  mttdEl.innerHTML = `MTTD médian <b>${esc(pcFmtSecs(mttdMedian))}</b> · moyen <b>${esc(pcFmtSecs(p.mttd_avg_secs))}</b> · max <b>${esc(pcFmtSecs(p.mttd_max_secs))}</b>`;
  if (mttdMedian == null) mttdEl.title = 'aucun échantillon MTTD mesurable (ts de tir illisible ou aucune détection)';
  band.appendChild(mttdEl);
  if (nMiss > 0) {
    const sep2 = document.createElement('span'); sep2.className = 'pc-sep'; band.appendChild(sep2);
    const gapEl = document.createElement('span'); gapEl.className = 'pc-sub';
    gapEl.innerHTML = `<span class="badge destr">${nMiss} trou(s) de détection</span>`;
    band.appendChild(gapEl);
  }
  host.appendChild(band);

  // légende
  const legend = document.createElement('div'); legend.className = 'pc-legend';
  legend.innerHTML = '<span class="pc-lg"><span class="pc-dot detected"></span>détecté (+MTTD)</span>'
    + '<span class="pc-lg"><span class="pc-dot missed"></span>raté (trou SOC)</span>'
    + '<span class="pc-lg"><span class="pc-dot unfired"></span>non-tiré (couvert, pas joué)</span>';
  host.appendChild(legend);

  // GRIS = techniques couvertes (run-records ATT&CK) mais JAMAIS tirées -> ni détectées ni ratées.
  // On les dérive de /api/coverage (lecture seule, déjà consommé ailleurs). Échec silencieux : la
  // matrice reste valable sans ces tuiles (detected/missed restent la source de vérité purple).
  const firedSet = new Set([...detected.map(d => d.mitre), ...missed.map(m => m.mitre)]);
  let unfired = [];
  try {
    const cov = await api(withCampaign('/coverage'));
    if (Array.isArray(cov)) {
      const seen = new Set();
      cov.forEach(c => {
        const m = c && c.mitre;
        if (m && !firedSet.has(m) && !seen.has(m) && Number(c.fired || 0) === 0) { seen.add(m); unfired.push(m); }
      });
      unfired.sort((a, b) => String(a).localeCompare(String(b)));
    }
  } catch (e) { /* coverage optionnel : on n'affiche pas les GRIS si indisponible */ }

  // matrice : DÉTECTÉ (vert, +MTTD) puis RATÉ (rouge) puis NON-TIRÉ (gris)
  const matrix = document.createElement('div'); matrix.className = 'pc-matrix';
  detected.forEach(d => {
    const mttd = (d.mttd_secs != null && isFinite(d.mttd_secs)) ? `MTTD ${pcFmtSecs(d.mttd_secs)}` : 'MTTD n/d';
    const alerts = `${Number(d.alert_count || 0)} alerte(s)`;
    matrix.appendChild(pcTile(d.mitre, 'detected', 'détecté', `${mttd} · ${alerts} · ${Number(d.fires || 0)} tir(s)`,
      `Détecté par le SOC — ${mttd}, première détection ${fmtTs(d.first_detection_ts)}`));
  });
  missed.forEach(m => {
    matrix.appendChild(pcTile(m.mitre, 'missed', 'raté', `${Number(m.fires || 0)} tir(s) · 0 alerte`,
      'Tiré en red-team mais NON détecté par le SOC — trou de détection'));
  });
  unfired.forEach(m => {
    matrix.appendChild(pcTile(m, 'unfired', 'non-tiré', 'couvert, pas joué',
      'Technique couverte par le moteur mais jamais tirée — non mesurable en détection'));
  });

  if (!matrix.childElementCount) {
    host.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune technique tirée avec un identifiant MITRE — rien à corréler' }));
    return;
  }
  host.appendChild(matrix);
}

