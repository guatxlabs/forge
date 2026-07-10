import { api, write } from '../core/api.js';
import { $, FINDING_STATUSES, SEV_BADGE, TLP_BADGE, TLP_CLASSES, TLP_KEY, esc, fmtTs, raw, safeHtml } from '../core/dom.js';
import { downloadReport } from './reports.js';
import { guardList, infoModal, toast } from '../core/ui.js';

export let F_STATE = { offset: 0, limit: 200 };
export async function loadFindings(offset = 0) {
  const host = $('#f-result'); if (!host) return;
  F_STATE.offset = offset;
  const qp = new URLSearchParams();
  const camp = $('#campaign') && $('#campaign').value; if (camp) qp.set('campaign', camp);
  const sev = $('#f-sev') && $('#f-sev').value; if (sev) qp.set('severity', sev);
  const st = $('#f-status') && $('#f-status').value; if (st) qp.set('status', st);
  const tg = $('#f-target') && $('#f-target').value.trim(); if (tg) qp.set('target', tg);
  qp.set('limit', F_STATE.limit); qp.set('offset', offset);
  let d;
  try { d = await api('/findings?' + qp.toString()); } catch (e) { host.innerHTML = '<div class="bad">erreur : ' + esc(e.message) + '</div>'; return; }
  const rows = d.findings || [];
  if ($('#f-count')) $('#f-count').textContent = d.total + ' findings';
  if (guardList(host, rows, 'aucun finding')) return;
  const table = document.createElement('table'); table.className = 'qtable findtable';
  table.innerHTML = `<thead><tr><th>#</th><th>Sév.</th><th>Cible</th><th>Titre</th><th>ATT&CK</th><th>Statut</th><th>TLP</th><th>Outil</th><th>Date</th></tr></thead>`;
  const tb = document.createElement('tbody');
  rows.forEach((x, i) => {
    const tr = document.createElement('tr'); tr.style.cursor = 'pointer'; tr.title = 'Cliquer pour voir le détail (evidence / PoC / fix)';
    tr.innerHTML = safeHtml`<td class="numcol">${offset + i + 1}</td><td>${raw(SEV_BADGE(x.severity))}</td><td>${x.target}</td><td>${x.title}</td><td><code>${x.mitre}</code></td><td>${x.status}</td><td>${raw(TLP_BADGE(x.classification))}</td><td class="mut">${x.tool}</td><td class="mut">${fmtTs(x.ts)}</td>`;
    tr.onclick = () => openFinding(x.id);
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  host.replaceChildren(table);
  // pager simple offset/limit
  const pages = Math.max(1, Math.ceil(d.total / F_STATE.limit)), cur = Math.floor(offset / F_STATE.limit);
  if (pages > 1) {
    const pager = document.createElement('div'); pager.className = 'evpager';
    const prev = document.createElement('button'); prev.type = 'button'; prev.textContent = '◀'; prev.disabled = cur === 0; prev.onclick = () => loadFindings(Math.max(0, offset - F_STATE.limit));
    const next = document.createElement('button'); next.type = 'button'; next.textContent = '▶'; next.disabled = cur >= pages - 1; next.onclick = () => loadFindings(offset + F_STATE.limit);
    const lbl = document.createElement('span'); lbl.className = 'evtot'; lbl.textContent = `page ${cur + 1}/${pages} · ${d.total} total`;
    pager.append(prev, next, lbl); host.appendChild(pager);
  }
}
export async function openFinding(id) {
  let d;
  try { d = await api('/findings/' + id); } catch (e) { toast('Détail finding : ' + e.message, 'bad'); return; }
  infoModal(d.title || ('Finding #' + id), body => {
    const meta = document.createElement('div'); meta.className = 'findmeta';
    meta.innerHTML = safeHtml`${raw(SEV_BADGE(d.severity))} <span class="badge">${d.status}</span> ${raw(TLP_BADGE(d.classification))} <code>${d.mitre}</code> <span class="muted">${d.category}</span>`;
    body.appendChild(meta);
    const kv = document.createElement('dl'); kv.className = 'kvdetail';
    [['Campagne', d.campaign], ['Cible', d.target], ['Outil', d.tool], ['Run', d.run_id], ['Date', fmtTs(d.ts)]].forEach(([k, v]) => {
      const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = (v == null || v === '') ? '-' : String(v); kv.append(dt, dd);
    });
    body.appendChild(kv);
    const sec = (label, val) => { if (!val) return; const h = document.createElement('div'); h.className = 'mailsec'; h.textContent = label; const pre = document.createElement('pre'); pre.className = 'mailtext'; pre.textContent = val; body.append(h, pre); };
    sec('Evidence', d.evidence);
    sec('PoC', d.poc);
    sec('Correctif suggéré', d.fix);
    buildFindingControls(body, d);
  });
}

// Contrôles de MUTATION d'un finding (#15) : transition de cycle de vie (statut validé) + classification
// TLP 2.0. TOLÉRANT en lecture : un statut hérité (hors vocabulaire) est proposé comme option courante
// non normative — l'utilisateur reste libre de le laisser tel quel (aucun envoi) ou de transitionner vers
// une valeur validée. La mutation est OPÉRATEUR (gate serveur fail-closed) + ISOLÉE à l'engagement actif.
function buildFindingControls(body, d) {
  const el = (t, cls) => { const n = document.createElement(t); if (cls) n.className = cls; return n; };
  const wrap = el('div', 'findctl');
  const h = el('div', 'mailsec'); h.textContent = 'Cycle de vie & classification (operator)'; wrap.appendChild(h);
  const row = el('div', 'findctl-row');

  // --- statut (transition validée, tolérant du legacy) ---
  const curStatus = String(d.status || '');
  const stLbl = el('label'); stLbl.textContent = 'Statut'; const stSel = el('select'); stSel.setAttribute('aria-label', 'Transition de statut');
  if (!FINDING_STATUSES.includes(curStatus)) {
    const o = el('option'); o.value = ''; o.textContent = curStatus ? `${curStatus} (hérité — choisir…)` : '(aucun — choisir…)'; o.selected = true; stSel.appendChild(o);
  }
  FINDING_STATUSES.forEach(s => { const o = el('option'); o.value = s; o.textContent = s; if (s === curStatus) o.selected = true; stSel.appendChild(o); });
  stLbl.appendChild(stSel); row.appendChild(stLbl);

  // --- classification TLP ---
  const curClass = TLP_KEY(d.classification || '');
  const clLbl = el('label'); clLbl.textContent = 'Classification (TLP 2.0)'; const clSel = el('select'); clSel.setAttribute('aria-label', 'Classification TLP');
  [['', '(non classifié)']].concat(TLP_CLASSES.map(t => [t, 'TLP:' + t])).forEach(([v, l]) => { const o = el('option'); o.value = v; o.textContent = l; if (v === curClass) o.selected = true; clSel.appendChild(o); });
  clLbl.appendChild(clSel); row.appendChild(clLbl);

  const save = el('button'); save.type = 'button'; save.className = 'k-theme'; save.textContent = 'Appliquer';
  save.onclick = async () => {
    const b = {};
    const st = stSel.value; if (st && st !== curStatus) b.status = st;
    const cl = clSel.value; if (cl !== curClass) b.classification = cl;
    if (!Object.keys(b).length) { toast('Aucun changement.', 'info'); return; }
    save.disabled = true;
    try {
      const r = await write('/api/findings/' + d.id, { body: b, auth: 'operator', engagement: true });
      const j = r.json || {};
      if (r.status === 403) { toast('Réservé à un compte operator.', 'bad'); return; }
      if (!r.ok) { toast('Échec : ' + String(j.why || j.error || r.status), 'bad'); return; }
      toast('Finding mis à jour (ledgerisé).', 'ok');
      if ('classification' in b) { d.classification = b.classification; }
      if ('status' in b) { d.status = b.status; }
      loadFindings(F_STATE.offset);
    } catch (e) { toast('Erreur réseau : ' + String(e.message || e), 'bad'); }
    finally { save.disabled = false; }
  };
  row.appendChild(save);
  wrap.appendChild(row);
  body.appendChild(wrap);
}
['f-sev', 'f-status', 'f-target'].forEach(idp => { const el = $('#' + idp); if (el) el.addEventListener(idp === 'f-target' ? 'input' : 'change', () => loadFindings(0)); });
// EXPORT depuis Findings : CSV / JSON de l'engagement ACTIF (secrets rédigés serveur) + accès au
// rapport complet brandé (vue #reports). downloadReport() est défini plus bas (déclaration hoistée).
if ($('#f-export-csv')) $('#f-export-csv').addEventListener('click', () => downloadReport('csv'));
if ($('#f-export-json')) $('#f-export-json').addEventListener('click', () => downloadReport('json'));
if ($('#f-report')) $('#f-report').addEventListener('click', () => { location.hash = 'reports'; });

// =====================================================================================
//  FINDINGS LIBRARY — modèles de findings réutilisables (livrable client type Ghostwriter).
//  Les modèles sont GLOBAUX (réutilisables d'un engagement à l'autre) ; APPLIQUER un modèle crée UN
//  finding dans l'engagement ACTIF UNIQUEMENT (isolation, cf. serveur). create/edit = operator,
//  delete = admin, apply = operator — chaque action est ledgerisée côté serveur (fail-closed).
//  UI 100 % native (aucune modale navigateur) : réutilise modal()/confirmModal()/toast().
// =====================================================================================
