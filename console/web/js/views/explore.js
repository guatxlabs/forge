import { api } from '../core/api.js';
import { $, CSSV, LOC, fmtTs, ic, raw } from '../core/dom.js';


// =====================================================================================
//  drilldown / historique / zoom (porté de Plume — pilote l'Explore)
// =====================================================================================
export const DIMENSIONLESS = new Set(['ts', 'bucket', 'time']);
export function drilldown(field, value) {
  if (value == null || value === '' || !field || DIMENSIONLESS.has(field)) return;
  histPush();
  const lit = /^-?\d+(\.\d+)?$/.test(String(value)) ? String(value) : `"${String(value).replace(/"/g, '')}"`;
  const sqlBox = $('#sql');
  if (sqlBox) sqlBox.value = `search ${field}=${lit}`;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  runQuery();
}
export function drillTime(t, span) {
  histPush();
  zoomRange = { from: Math.floor(t), to: Math.ceil(t + (span || 60)) };
  updateZoomBadge();
  if ($('#sql')) $('#sql').value = 'search';
  location.hash = 'explore';
  runQuery();
}
export function sanitizeVal(v) { return '"' + String(v).replace(/[|\[\]"\n\r]/g, ' ').trim() + '"'; }
export function customDrill(tpl, ctx) {
  if (!tpl) return;
  histPush();
  let q = tpl;
  if (ctx.value !== undefined && ctx.value !== null) q = q.split('$value').join(sanitizeVal(ctx.value));
  const timed = ctx.from !== undefined;
  if (timed) {
    const f = Math.floor(ctx.from), t = Math.ceil(ctx.to !== undefined ? ctx.to : ctx.from + 60);
    q = q.split('$from').join(String(f)).split('$to').join(String(t));
    zoomRange = { from: f, to: t }; updateZoomBadge();
  }
  if ($('#sql')) $('#sql').value = q;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  runQuery();
}
export let exploreHist = [];
export function histPush() {
  const sql = $('#sql') ? $('#sql').value : '';
  if (!sql) return;
  const snap = { sql, zoom: zoomRange ? { ...zoomRange } : null };
  const t = exploreHist[exploreHist.length - 1];
  if (t && t.sql === snap.sql && JSON.stringify(t.zoom) === JSON.stringify(snap.zoom)) return;
  exploreHist.push(snap);
  if (exploreHist.length > 50) exploreHist.shift();
  histUpdateBtn();
}
export function histBack() {
  const prev = exploreHist.pop();
  if (!prev) return;
  zoomRange = prev.zoom ? { ...prev.zoom } : null;
  updateZoomBadge();
  if ($('#sql')) $('#sql').value = prev.sql;
  histUpdateBtn();
  runQuery();
}
export function histUpdateBtn() { const b = $('#qback'); if (b) b.hidden = exploreHist.length === 0; }
if ($('#qback')) $('#qback').addEventListener('click', histBack);
export function statDrill(query, drill) {
  if (drill) return customDrill(drill, {});
  const q = (query || '').trim();
  if (!q) return;
  const target = /^\s*search\b/i.test(q) ? q.split('|')[0].trim() : q;
  if (!target) return;
  histPush();
  if ($('#sql')) $('#sql').value = target;
  if ($('#viz')) $('#viz').value = 'table';
  location.hash = 'explore';
  runQuery();
}
export let zoomRange = null; // {from,to}
export function currentFrom() { return zoomRange ? zoomRange.from : 0; }
export function currentTo() { return zoomRange ? zoomRange.to : 0; }
export function setZoom(a, b) {
  const from = Math.floor(Math.min(a, b)), to = Math.ceil(Math.max(a, b));
  if (to - from < 1) return;
  zoomRange = { from, to }; updateZoomBadge();
  if (lastResult && $('#sql') && $('#sql').value.trim()) runQuery();
}
export function clearZoom() { zoomRange = null; updateZoomBadge(); if ($('#sql') && $('#sql').value.trim()) runQuery(); }
export function updateZoomBadge() {
  let el = $('#zoombadge');
  if (!el) {
    const tools = document.querySelector('.hdr-tools'); if (!tools) return;
    el = document.createElement('button'); el.id = 'zoombadge'; el.className = 'zoombadge'; el.type = 'button';
    el.title = 'Réinitialiser le zoom'; el.onclick = clearZoom; tools.insertBefore(el, tools.firstChild);
  }
  const f = t => new Date(t * 1000).toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit' });
  if (zoomRange) { el.hidden = false; el.innerHTML = `zoom ${f(zoomRange.from)}-${f(zoomRange.to)} ${ic('x')}`; }
  else el.hidden = true;
}
export function attachZoom(svg, W, xToTime) {
  const NS = 'http://www.w3.org/2000/svg';
  let x0 = null, rectEl = null;
  const vbX = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
  svg.style.cursor = 'ew-resize';
  svg.addEventListener('mousedown', e => {
    x0 = vbX(e); rectEl = document.createElementNS(NS, 'rect');
    rectEl.setAttribute('y', 0); rectEl.setAttribute('height', '100%');
    rectEl.setAttribute('fill', CSSV('--acc', '#2dd4bf')); rectEl.setAttribute('opacity', '0.18');
    svg.appendChild(rectEl); e.preventDefault();
  });
  svg.addEventListener('mousemove', e => { if (x0 == null || !rectEl) return; const x1 = vbX(e); rectEl.setAttribute('x', Math.min(x0, x1)); rectEl.setAttribute('width', Math.abs(x1 - x0)); });
  const end = e => { if (x0 == null) return; const x1 = vbX(e); const a = Math.min(x0, x1), b = Math.max(x0, x1); x0 = null; if (rectEl) { rectEl.remove(); rectEl = null; } if (b - a > 4) { svg._zoomed = true; setZoom(xToTime(a), xToTime(b)); } };
  svg.addEventListener('mouseup', end); svg.addEventListener('mouseleave', end);
}
export let _charttip;
export function tipShow(text, e) {
  if (!_charttip) { _charttip = document.createElement('div'); _charttip.id = 'charttip'; document.body.appendChild(_charttip); }
  const t = _charttip; t.textContent = text; t.hidden = false;
  const pad = 14, w = t.offsetWidth, h = t.offsetHeight;
  let x = e.clientX + pad, y = e.clientY + pad;
  if (x + w > innerWidth) x = e.clientX - w - pad;
  if (y + h > innerHeight) y = e.clientY - h - pad;
  t.style.left = x + 'px'; t.style.top = y + 'px';
}
export function tipHide() { if (_charttip) _charttip.hidden = true; }
export function attachTip(svg, W, dataAt) {
  const vbX = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
  svg.addEventListener('mousemove', e => { const s = dataAt(vbX(e)); if (s) tipShow(s, e); else tipHide(); });
  svg.addEventListener('mouseleave', tipHide);
}

// =====================================================================================
//  moteur de requête + visualisations (porté de Plume, adapté Forge)
// =====================================================================================
// POST /api/query {soql} OR {q} -> {columns, rows[[...]], total, stats, compiled}
//   Contrat réel : /api/query NE prend PAS from/to/limit/offset (total = rows.length, jeu complet).
//   On ne borne PAS le temps ici (le zoom temporel est honoré côté serveur uniquement par
//   /api/panels/:id/data?from=&to=). La pagination Explore est donc faite CÔTÉ CLIENT (evLoad).
//   from/to/limit/offset sont envoyés à titre indicatif (forward-compat) mais ignorés par le backend.
export async function runQ(query, isSoql, fromOverride, limit, offset) {
  const body = { soql: query };
  const f = (fromOverride !== undefined ? fromOverride : currentFrom());
  const t = currentTo();
  if (f) body.from = f;
  if (t) body.to = t;
  if (limit !== undefined && limit !== null) { body.limit = limit; body.offset = offset || 0; }
  const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
export function vizElement(mode, cols, rows, query, drill) {
  if (mode === 'stat') return statEl(cols, rows, query, drill);
  if (mode === 'bar') return barEl(cols, rows, query, drill);
  if (mode === 'line') return lineEl(cols, rows, query, drill);
  return tableEl(cols, rows, query, drill);
}
// décompose une colonne `evidence`/`fields` JSON en colonnes individuelles (union des clés vues).
export function expandFields(cols, rows) {
  let fi = cols.indexOf('fields');
  if (fi < 0) fi = cols.indexOf('evidence');
  if (fi < 0) return { cols, rows };
  const base = new Set(cols.filter((_, i) => i !== fi));
  const keys = [], seen = new Set();
  const parsed = rows.map(r => {
    let o = null; try { o = r[fi] ? JSON.parse(r[fi]) : null; } catch (e) { o = null; }
    if (o && typeof o === 'object' && !Array.isArray(o)) for (const k of Object.keys(o))
      if (!seen.has(k) && !base.has(k) && o[k] != null && o[k] !== '') { seen.add(k); keys.push(k); }
    return o;
  });
  if (!keys.length) return { cols, rows };
  keys.sort();
  const flat = v => (v == null ? null : (typeof v === 'object' ? JSON.stringify(v) : v));
  const ncols = []; cols.forEach((c, i) => { if (i === fi) keys.forEach(k => ncols.push(k)); else ncols.push(c); });
  const nrows = rows.map((r, ri) => {
    const o = parsed[ri] || {}, nr = [];
    cols.forEach((c, i) => { if (i === fi) keys.forEach(k => nr.push(flat(o[k]))); else nr.push(r[i]); });
    return nr;
  });
  return { cols: ncols, rows: nrows };
}
// sélecteur de colonnes : un seul menu ouvert à la fois (position:fixed pour échapper l'overflow).
export let _colsMenuClose = null, _colsMenuOwner = null;
export function closeColsMenu() { if (_colsMenuClose) { const f = _colsMenuClose; _colsMenuClose = null; _colsMenuOwner = null; f(); } }
export function tableEl(cols, rows, query, drill) {
  ({ cols, rows } = expandFields(cols, rows));
  const last = cols.length - 1;
  const order = cols.map((_, i) => i);
  const widths = {};
  let sortIdx = -1, sortDir = 1;
  const cover = cols.map((_, i) => rows.length ? rows.reduce((n, r) => n + (r[i] != null && r[i] !== '' ? 1 : 0), 0) / rows.length : 1);
  const CORE = new Set(['ts', 'time', 'bucket', 'campaign', 'target', 'title', 'severity', 'mitre', 'status', 'message']);
  const hidden = new Set();
  if (order.length > 12) cols.forEach((c, i) => { if (!CORE.has(c) && cover[i] < 0.5) hidden.add(i); });
  const vcount = () => order.filter(oi => !hidden.has(oi)).length;
  const id = 'cm' + Math.random().toString(36).slice(2, 8);
  let colsBtn = null;
  const tbl = document.createElement('table'); tbl.className = 'qtable';
  const thead = document.createElement('thead'), tb = document.createElement('tbody');
  tbl.append(thead, tb);
  const TIMECOLS = new Set(['ts', 'time', 'bucket']);
  const fmtCell = (v, oi) => {
    if (TIMECOLS.has(cols[oi]) && v > 1e9 && v < 2e10) return fmtTs(Number(v));
    return (v == null ? '-' : String(v));
  };
  const chevron = up => `<svg class="ic" viewBox="0 0 24 24"><path d="${up ? 'M6 15l6-6 6 6' : 'M6 9l6 6 6-6'}"/></svg>`;
  function build() {
    const htr = document.createElement('tr');
    const numTh = document.createElement('th'); numTh.className = 'numcol'; numTh.textContent = '#'; htr.appendChild(numTh);
    order.forEach((oi, pos) => {
      if (hidden.has(oi)) return;
      const th = document.createElement('th'); th.draggable = true;
      const lab = document.createElement('span'); lab.textContent = cols[oi]; th.appendChild(lab);
      if (oi === sortIdx) { const ar = document.createElement('span'); ar.className = 'sortar'; ar.innerHTML = chevron(sortDir > 0); th.appendChild(ar); }
      if (widths[oi]) th.style.width = widths[oi] + 'px';
      th.onclick = e => { if (e.target.classList.contains('rsz')) return; if (sortIdx === oi) sortDir = -sortDir; else { sortIdx = oi; sortDir = 1; } build(); };
      th.ondragstart = e => e.dataTransfer.setData('text/plain', String(pos));
      th.ondragover = e => { e.preventDefault(); th.classList.add('dragover'); };
      th.ondragleave = () => th.classList.remove('dragover');
      th.ondrop = e => { e.preventDefault(); th.classList.remove('dragover'); const from = Number(e.dataTransfer.getData('text/plain')); if (Number.isInteger(from) && from !== pos) { const [m] = order.splice(from, 1); order.splice(pos, 0, m); build(); } };
      const rsz = document.createElement('span'); rsz.className = 'rsz'; th.appendChild(rsz);
      rsz.onmousedown = e => {
        e.preventDefault(); e.stopPropagation();
        const x0 = e.clientX, w0 = th.offsetWidth;
        const mv = ev => { widths[oi] = Math.max(40, w0 + ev.clientX - x0); th.style.width = widths[oi] + 'px'; };
        const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
      };
      htr.appendChild(th);
    });
    thead.replaceChildren(htr);
    let view = rows;
    if (sortIdx >= 0) {
      const ipv4 = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
      const ne = rows.filter(r => r[sortIdx] != null && r[sortIdx] !== '');
      const isIp = ne.length > 0 && ne.some(r => ipv4(String(r[sortIdx]))) && ne.every(r => { const v = String(r[sortIdx]); return ipv4(v) || v.includes(':'); });
      const numeric = !isIp && rows.every(r => r[sortIdx] == null || r[sortIdx] === '' || !isNaN(Number(r[sortIdx])));
      view = [...rows].sort((a, b) => {
        const x = a[sortIdx], y = b[sortIdx];
        if (isIp) {
          const xs = String(x == null ? '' : x), ys = String(y == null ? '' : y);
          const xo = ipv4(xs) ? xs.split('.').map(Number) : null;
          const yo = ipv4(ys) ? ys.split('.').map(Number) : null;
          if (xo && yo) { for (let i = 0; i < 4; i++) if (xo[i] !== yo[i]) return (xo[i] - yo[i]) * sortDir; return 0; }
          if (xo) return -sortDir;
          if (yo) return sortDir;
          return xs.localeCompare(ys) * sortDir;
        }
        if (numeric) return ((Number(x) || 0) - (Number(y) || 0)) * sortDir;
        return String(x == null ? '' : x).localeCompare(String(y == null ? '' : y)) * sortDir;
      });
    }
    tb.replaceChildren(...view.map((row, ri) => {
      const tr = document.createElement('tr');
      const numTd = document.createElement('td'); numTd.className = 'numcol'; numTd.textContent = String(ri + 1); tr.appendChild(numTd);
      order.forEach(oi => { if (hidden.has(oi)) return; const td = document.createElement('td'); td.textContent = fmtCell(row[oi], oi); tr.appendChild(td); });
      tr.style.cursor = 'pointer';
      tr.title = drill ? 'Cliquer pour exécuter le drill du panneau' : (DIMENSIONLESS.has(cols[0]) ? 'Cliquer pour voir tous les détails' : `Cliquer pour filtrer ${cols[0]}=${row[0]}`);
      tr.onclick = () => {
        if (drill) { const c = { value: row[0] }; if (DIMENSIONLESS.has(cols[0])) c.from = Number(row[0]); return customDrill(drill, c); }
        if (!DIMENSIONLESS.has(cols[0])) return drilldown(cols[0], row[0]);
        const nx = tr.nextSibling;
        if (nx && nx.classList && nx.classList.contains('rowdetail')) { nx.remove(); return; }
        const dtr = document.createElement('tr'); dtr.className = 'rowdetail';
        const td = document.createElement('td'); td.colSpan = vcount() + 1;
        const dl = document.createElement('dl'); dl.className = 'kvdetail';
        cols.forEach((c, i) => { const dt = document.createElement('dt'); dt.textContent = c; const dd = document.createElement('dd'); dd.textContent = (row[i] == null ? '-' : String(row[i])); dl.append(dt, dd); });
        td.appendChild(dl); dtr.appendChild(td); tr.after(dtr);
      };
      return tr;
    }));
    if (colsBtn) colsBtn.textContent = `Colonnes ${vcount()}/${order.length} ▾`;
  }
  build();
  if (order.length <= 7) return tbl;
  const wrap = document.createElement('div'); wrap.className = 'qtblwrap';
  const bar = document.createElement('div'); bar.className = 'qtblbar';
  colsBtn = document.createElement('button'); colsBtn.type = 'button'; colsBtn.className = 'colsbtn';
  colsBtn.textContent = `Colonnes ${vcount()}/${order.length} ▾`;
  colsBtn.onclick = (ev) => {
    ev.stopPropagation();
    const wasMine = _colsMenuOwner === id;
    closeColsMenu();
    if (wasMine) return;
    _colsMenuOwner = id;
    const menu = document.createElement('div'); menu.className = 'colsmenu';
    order.forEach(oi => {
      const lab = document.createElement('label');
      const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = !hidden.has(oi);
      cb.onchange = () => { if (cb.checked) hidden.delete(oi); else hidden.add(oi); build(); };
      const nm = document.createElement('span'); nm.className = 'colsnm'; nm.textContent = cols[oi];
      const pc = document.createElement('span'); pc.className = 'colspc'; pc.textContent = Math.round(cover[oi] * 100) + '%';
      lab.append(cb, nm, pc); menu.appendChild(lab);
    });
    const allb = document.createElement('button'); allb.type = 'button'; allb.className = 'colsall'; allb.textContent = 'Tout afficher';
    allb.onclick = () => { hidden.clear(); build(); menu.querySelectorAll('input').forEach(c => c.checked = true); };
    menu.appendChild(allb);
    const r = colsBtn.getBoundingClientRect();
    menu.style.top = (r.bottom + 4) + 'px'; menu.style.right = (window.innerWidth - r.right) + 'px';
    document.body.appendChild(menu);
    const onclose = e => { if (!menu.contains(e.target) && e.target !== colsBtn) closeColsMenu(); };
    const onscroll = () => closeColsMenu();
    _colsMenuClose = () => { menu.remove(); document.removeEventListener('click', onclose); document.removeEventListener('scroll', onscroll, true); };
    setTimeout(() => { document.addEventListener('click', onclose); document.addEventListener('scroll', onscroll, true); }, 0);
  };
  bar.appendChild(colsBtn); wrap.append(bar, tbl);
  return wrap;
}
export function statEl(cols, rows, query, drill) {
  const v = rows.length ? rows[0][rows[0].length - 1] : null;
  const d = document.createElement('div'); d.className = 'statbig'; d.textContent = (v == null ? '-' : String(v));
  if (query || drill) {
    d.style.cursor = 'pointer';
    d.title = drill ? 'Cliquer pour exécuter le drill du panneau' : 'Cliquer pour voir ce qui se cache derrière ce chiffre';
    d.onclick = () => statDrill(query, drill);
  }
  return d;
}
export function barEl(cols, rows, query, drill) {
  const vi = cols.length - 1;
  const nums = rows.map(r => Number(r[vi]) || 0);
  const max = Math.max(1, ...nums);
  const wrap = document.createElement('div'); wrap.className = 'bars';
  rows.forEach((r, i) => {
    const row = document.createElement('div'); row.className = 'barrow';
    const lab = document.createElement('span'); lab.className = 'barlabel'; lab.textContent = String(r[0]);
    const track = document.createElement('div'); track.className = 'bartrack';
    const fill = document.createElement('div'); fill.className = 'barfill'; fill.style.width = (nums[i] / max * 100) + '%';
    track.appendChild(fill);
    const val = document.createElement('span'); val.className = 'barval'; val.textContent = String(r[vi]);
    const tipTxt = `${r[0]} : ${r[vi]}`;
    row.addEventListener('mousemove', e => tipShow(tipTxt, e));
    row.addEventListener('mouseleave', tipHide);
    if (drill) { row.style.cursor = 'pointer'; row.title = 'Cliquer pour exécuter le drill du panneau'; row.onclick = () => customDrill(drill, { value: r[0] }); }
    else if (!DIMENSIONLESS.has(cols[0])) { row.style.cursor = 'pointer'; row.title = 'Cliquer pour filtrer'; row.onclick = () => drilldown(cols[0], r[0]); }
    row.append(lab, track, val); wrap.appendChild(row);
  });
  return wrap;
}
export function fmtMaybeTime(v) {
  const n = Number(v);
  if (n > 1e9 && n < 2e10) return new Date(n * 1000).toLocaleTimeString(LOC, { hour: '2-digit', minute: '2-digit' });
  return String(v);
}
export function lineEl(cols, rows, query, drill) {
  const NS = 'http://www.w3.org/2000/svg', mk = t => document.createElementNS(NS, t);
  const W = 640, H = 200, pad = 30;
  const xs = rows.map(r => Number(r[0]) || 0);
  const ys = rows.map(r => Number(r[r.length - 1]) || 0);
  const ymax = Math.max(1, ...ys), xmin = Math.min(...xs), xmax = Math.max(...xs);
  const sx = x => pad + (xmax > xmin ? (x - xmin) / (xmax - xmin) : 0.5) * (W - 2 * pad);
  const sy = y => H - pad - (y / ymax) * (H - 2 * pad);
  const svg = mk('svg'); svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('class', 'linechart');
  const txt = (x, y, s, a) => { const e = mk('text'); e.setAttribute('x', x); e.setAttribute('y', y); e.setAttribute('fill', CSSV('--mut', '#8aa0b4')); e.setAttribute('font-size', '10'); e.setAttribute('text-anchor', a || 'start'); e.textContent = s; svg.appendChild(e); };
  const axis = mk('path'); axis.setAttribute('d', `M${pad},${pad} L${pad},${H - pad} L${W - pad},${H - pad}`); axis.setAttribute('stroke', CSSV('--bd', '#16202e')); axis.setAttribute('fill', 'none'); svg.appendChild(axis);
  if (rows.length) {
    const pts = rows.map((r, i) => `${sx(xs[i])},${sy(ys[i])}`);
    const area = mk('polygon');
    area.setAttribute('points', `${sx(xs[0])},${H - pad} ${pts.join(' ')} ${sx(xs[xs.length - 1])},${H - pad}`);
    area.setAttribute('fill', CSSV('--acc-soft', 'rgba(45,212,191,.16)')); svg.appendChild(area);
    const poly = mk('polyline'); poly.setAttribute('points', pts.join(' ')); poly.setAttribute('fill', 'none'); poly.setAttribute('stroke', CSSV('--acc', '#2dd4bf')); poly.setAttribute('stroke-width', '2'); svg.appendChild(poly);
    rows.forEach((r, i) => { const c = mk('circle'); c.setAttribute('cx', sx(xs[i])); c.setAttribute('cy', sy(ys[i])); c.setAttribute('r', rows.length === 1 ? '4' : '2.5'); c.setAttribute('fill', CSSV('--acc', '#2dd4bf')); svg.appendChild(c); });
    txt(3, pad, String(ymax));
    txt(pad, H - 8, fmtMaybeTime(xs[0]));
    if (xs.length > 1) txt(W - pad, H - 8, fmtMaybeTime(xs[xs.length - 1]), 'end');
  }
  if (rows.length > 1 && xmin > 1e9 && xmax < 2e10) {
    attachZoom(svg, W, vx => xmin + Math.max(0, Math.min(1, (vx - pad) / (W - 2 * pad))) * (xmax - xmin));
  }
  attachTip(svg, W, vx => { let b = 0, bd = 1e9; for (let i = 0; i < xs.length; i++) { const d = Math.abs(sx(xs[i]) - vx); if (d < bd) { bd = d; b = i; } } return (xs.length && bd < 40) ? `${fmtMaybeTime(xs[b])} : ${ys[b]}` : ''; });
  if (rows.length) {
    const cross = mk('line'); cross.setAttribute('y1', pad); cross.setAttribute('y2', H - pad); cross.setAttribute('stroke', CSSV('--mut', '#8aa0b4')); cross.setAttribute('stroke-dasharray', '3 3'); cross.style.display = 'none'; svg.appendChild(cross);
    const mark = mk('circle'); mark.setAttribute('r', '4.5'); mark.setAttribute('fill', CSSV('--acc', '#2dd4bf')); mark.setAttribute('stroke', CSSV('--card', '#0c1422')); mark.setAttribute('stroke-width', '2'); mark.style.display = 'none'; svg.appendChild(mark);
    let hi = -1;
    const vbx = e => { const r = svg.getBoundingClientRect(); return (e.clientX - r.left) / r.width * W; };
    svg.addEventListener('mousemove', e => {
      const vx = vbx(e); let b = 0, bd = 1e9;
      for (let i = 0; i < xs.length; i++) { const d = Math.abs(sx(xs[i]) - vx); if (d < bd) { bd = d; b = i; } }
      if (bd < 60) { hi = b; const X = sx(xs[b]), Y = sy(ys[b]); cross.setAttribute('x1', X); cross.setAttribute('x2', X); cross.style.display = ''; mark.setAttribute('cx', X); mark.setAttribute('cy', Y); mark.style.display = ''; if (xs[b] > 1e9) svg.style.cursor = 'pointer'; }
      else { hi = -1; cross.style.display = 'none'; mark.style.display = 'none'; }
    });
    svg.addEventListener('mouseleave', () => { hi = -1; cross.style.display = 'none'; mark.style.display = 'none'; });
    svg.addEventListener('click', () => {
      if (svg._zoomed) { svg._zoomed = false; return; }
      if (hi < 0 || xs[hi] <= 1e9) return;
      const span = xs.length > 1 ? xs[1] - xs[0] : 60;
      if (drill) customDrill(drill, { from: xs[hi], to: xs[hi] + span, value: ys[hi] });
      else drillTime(xs[hi], span);
    });
  }
  return svg;
}

// =====================================================================================
//  Explore : facettes + pagination serveur + table/viz
// =====================================================================================
export let lastResult = null;
export function renderViz() {
  if (!lastResult) return;
  $('#qresult').replaceChildren(vizElement(($('#viz') && $('#viz').value) || 'table', lastResult.columns, lastResult.rows, $('#sql') ? $('#sql').value : ''));
}
export function addSearchFilter(field, value) {
  const q = $('#sql').value.trim();
  const pipe = q.indexOf('|');
  let head = (pipe < 0 ? q : q.slice(0, pipe)).trim();
  if (!/^\s*search\b/i.test(head)) head = ('search ' + head).trim();
  const tail = pipe < 0 ? '' : ' ' + q.slice(pipe);
  const lit = /^-?\d+(\.\d+)?$/.test(String(value)) ? String(value) : `"${String(value).replace(/"/g, '')}"`;
  $('#sql').value = `${head} ${field}=${lit}`.replace(/\s+/g, ' ').trim() + tail;
  runQuery();
}
export function facetBlock(rows, idx, field, label) {
  const counts = new Map();
  rows.forEach(r => { const raw = (r[idx] == null || r[idx] === '') ? null : r[idx]; counts.set(raw, (counts.get(raw) || 0) + 1); });
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const block = document.createElement('div'); block.className = 'fldblock';
  block.appendChild(Object.assign(document.createElement('div'), { className: 'fldname', textContent: label }));
  top.forEach(([raw, c]) => {
    const disp = raw == null ? '-' : String(raw);
    const row = document.createElement('button'); row.className = 'fldval';
    const s = document.createElement('span'); s.textContent = disp;
    const cc = document.createElement('span'); cc.className = 'fldc'; cc.textContent = c;
    row.append(s, cc);
    if (raw != null) row.onclick = () => addSearchFilter(field, raw);
    block.appendChild(row);
  });
  return block;
}
export function renderFacets(cols, rows) {
  const host = $('#facets'); if (!host) return;
  host.replaceChildren();
  if (!rows.length) return;
  const ix = n => cols.indexOf(n);
  [['severity', 'sévérité'], ['status', 'statut'], ['mitre', 'ATT&CK'], ['target', 'cible'], ['category', 'catégorie']].forEach(([f, lab]) => {
    const idx = ix(f); if (idx >= 0) host.appendChild(facetBlock(rows, idx, f, lab));
  });
}
// pager Explore (pagination CLIENT-side : /api/query renvoie le jeu complet, on tranche localement).
export let evState = { q: '', isSoql: true, page: 0, pageSize: 200, total: 0, shown: 0, cols: [], all: [] };
export function evPagerHtml() {
  const PS = evState.pageSize, total = evState.total, numbered = total >= 0;
  const pages = numbered ? Math.max(1, Math.ceil(total / PS)) : evState.page + (evState.shown >= PS ? 2 : 1);
  if (pages <= 1) return '';
  const from = evState.page * PS;
  return `<div class="evpager"><button class="evprev" type="button" title="précédent" ${evState.page === 0 ? 'disabled' : ''}>◀</button>${numbered ? pageNums(evState.page, pages).map(n => n === '…' ? '<span class="evdots">…</span>' : `<button type="button" class="evnum${n - 1 === evState.page ? ' on' : ''}" data-p="${n - 1}">${n}</button>`).join('') : `<span class="evdots">page ${evState.page + 1}</span>`}<button class="evnext" type="button" title="suivant" ${(numbered ? evState.page >= pages - 1 : evState.shown < PS) ? 'disabled' : ''}>▶</button><span class="evtot">${total >= 0 ? total + ' · ' : ''}${from + 1}–${from + evState.shown}</span></div>`;
}
export function wirePagers(root) {
  // navigation = re-tranchage local (le jeu complet est déjà en mémoire, pas de refetch).
  root.querySelectorAll('.evprev').forEach(b => b.onclick = () => { if (evState.page > 0) { evState.page--; evRenderPage(); } });
  root.querySelectorAll('.evnext').forEach(b => b.onclick = () => { evState.page++; evRenderPage(); });
  root.querySelectorAll('.evnum').forEach(b => b.onclick = () => { evState.page = Number(b.dataset.p); evRenderPage(); });
}
export function renderTablePaged(host, cols, rows) {
  host.replaceChildren();
  const pgr = evPagerHtml();
  if (pgr) { const t = document.createElement('div'); t.innerHTML = pgr; host.appendChild(t.firstElementChild); }
  host.appendChild(tableEl(cols, rows, evState.q));
  if (pgr) { const b = document.createElement('div'); b.innerHTML = pgr; host.appendChild(b.firstElementChild); }
  wirePagers(host);
}
export const evPageSize = () => { const s = $('#qsize'); return s ? (Number(s.value) || 200) : 200; };
export function pageNums(cur, pages) {
  const c = cur + 1, s = new Set([1, pages]);
  for (let i = c - 2; i <= c + 2; i++) if (i >= 1 && i <= pages) s.add(i);
  const arr = [...s].sort((a, b) => a - b), out = []; let prev = 0;
  for (const n of arr) { if (n - prev > 1) out.push('…'); out.push(n); prev = n; }
  return out;
}
// Rend une page localement à partir du jeu complet déjà chargé (pas de requête réseau).
export function evRenderPage() {
  evState.pageSize = evPageSize();
  const PS = evState.pageSize;
  const pages = Math.max(1, Math.ceil(evState.total / PS));
  if (evState.page > pages - 1) evState.page = pages - 1;
  if (evState.page < 0) evState.page = 0;
  const start = evState.page * PS;
  const slice = evState.all.slice(start, start + PS);
  evState.shown = slice.length;
  if ($('#viz')) $('#viz').hidden = true;
  renderTablePaged($('#qresult'), evState.cols, slice);
  $('#qstats').textContent = `page ${evState.page + 1}/${pages} · ${evState.total} ligne(s)` + (evState._net != null ? ` · ${evState._net} ms` : '');
  $('#qstats').title = evState._compiled || '';
}
// (re)charge le jeu complet depuis /api/query puis affiche la 1re page. Le backend renvoie tout
// (total = rows.length) — on garde les rows en mémoire et on pagine côté client.
export async function evLoad() {
  evState.pageSize = evPageSize();
  $('#qstats').textContent = 'exécution…';
  const t0 = performance.now();
  try {
    const j = await runQ(evState.q, evState.isSoql);
    if (j.error) { $('#qresult').replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + j.error })); $('#qstats').textContent = ''; return; }
    evState.cols = j.columns || [];
    evState.all = j.rows || [];
    evState.total = (typeof j.total === 'number') ? j.total : evState.all.length;
    evState._net = Math.round(performance.now() - t0);
    evState._compiled = j.compiled || '';
    renderFacets(evState.cols, evState.all);   // facettes calculées sur le jeu complet
    evRenderPage();
  } catch (e) { $('#qstats').textContent = 'erreur : ' + e.message; }
}
export async function runQuery() {
  const q = $('#sql').value.trim();
  if (!q) { $('#qresult').replaceChildren(); $('#qstats').textContent = ''; if ($('#facets')) $('#facets').replaceChildren(); return; }
  const isSoql = /^\s*search\b/i.test(q) || q.includes('|');
  const hasAgg = isSoql && /\|\s*(stats|timechart|top|rare|eventstats)\b/i.test(q);
  $('#qresult').replaceChildren();
  if (!hasAgg) {
    evState = { q, isSoql, page: 0, pageSize: evPageSize(), total: 0, shown: 0, cols: [], all: [] };
    await evLoad();
    return;
  }
  if ($('#facets')) $('#facets').replaceChildren();
  const t0 = performance.now();
  $('#qstats').textContent = 'exécution…';
  try {
    const j = await runQ(q, isSoql);
    if (j.error) { $('#qresult').replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + j.error })); $('#qstats').textContent = ''; return; }
    lastResult = { columns: j.columns, rows: j.rows };
    if ($('#viz')) $('#viz').hidden = false;
    renderViz();
    const net = Math.round(performance.now() - t0);
    const nrows = j.stats && typeof j.stats.rows === 'number' ? j.stats.rows : (j.rows ? j.rows.length : 0);
    $('#qstats').textContent = `${nrows} ligne(s) · total ${net} ms · soql`;
    $('#qstats').title = j.compiled || '';
  } catch (e) { $('#qstats').textContent = 'erreur : ' + e.message; }
}
if ($('#run')) $('#run').addEventListener('click', runQuery);
if ($('#sql')) $('#sql').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); } });
if ($('#viz')) $('#viz').addEventListener('change', renderViz);
if ($('#qsize')) $('#qsize').addEventListener('change', () => { if (evState.q && evState.all.length) { evState.page = 0; evRenderPage(); } });
// barre de recherche header -> Explore
if ($('#q')) $('#q').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const v = e.target.value.trim(); if (!v) return;
  location.hash = 'explore';
  $('#sql').value = (/^\s*search\b/i.test(v) || v.includes('|')) ? v : ('search ' + v);
  runQuery();
});

// =====================================================================================
//  Dashboards : panneaux soql (drag réordonner + resize) — schéma Forge (name/viz/col_span/position)
// =====================================================================================
// Hiérarchie portée de la console SOC (app.js L949-1316), recalée sur les endpoints RÉELS du backend
// Forge : modèle PLAT (pas d'entité « view » côté serveur). Chaque dashboard = une tuile avec sa grille
// de panneaux ; les panneaux portent un dashboard_id (assignable). Les attributs purement visuels que le
// backend ne persiste PAS (cols/collapse de tuile, hauteur/drill de panneau) sont stockés côté client
// (localStorage pour cols/collapse, mémoire de session pour drill/height). Les « Vues » sont des
// COLLECTIONS de dashboards locales (localStorage) : un filtre d'affichage, jamais un endpoint inventé.
