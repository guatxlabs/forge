import { OPERATOR_SECRET, api, setOperatorSecret, write } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { toast } from '../core/ui.js';

// =====================================================================================
//  IMPORT — migration : ingérer une SORTIE DE SCANNER EXISTANTE en findings orientés preuve.
//  POST /api/import (opérateur, ledgerisé, scope-guardé). PUR DATA : le fichier est parsé côté
//  serveur (moteur Python, SOURCE UNIQUE des parseurs), scope-filtré, secrets rédigés. Le secret
//  opérateur est partagé avec le lancement C2 (OPERATOR_SECRET, jamais persisté).
// =====================================================================================
export function imShowErr(msg) { const e = $('#im-err'); if (e) { e.textContent = msg; e.hidden = !msg; } }

export function loadImport() {
  // reflète l'état du secret opérateur en session (partagé avec la vue Lancement C2).
  const b = $('#im-c2state');
  if (b) {
    const ok = !!OPERATOR_SECRET;
    b.textContent = ok ? 'secret opérateur en session' : 'secret opérateur requis';
    b.className = 'badge ' + (ok ? 'webyes' : 'mut');
  }
  if ($('#im-operator') && OPERATOR_SECRET && !$('#im-operator').value) $('#im-operator').value = OPERATOR_SECRET;
}

export function readFileText(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result || ''));
    r.onerror = () => reject(new Error('lecture du fichier impossible'));
    r.readAsText(file);
  });
}

export function renderImportResult(j) {
  const host = $('#im-result');
  if (!host) return;
  const c = j.counts || {};
  const cell = v => (v === null || v === undefined) ? '—' : esc(String(v));
  host.innerHTML =
    '<div class="roecounters" style="margin-top:10px">' +
    `<span class="badge ok">ingérés : ${esc(String(j.ingested ?? 0))}</span>` +
    `<span class="badge">format : ${esc(String(j.format || '—'))}</span>` +
    `<span class="badge mut">parsés : ${cell(c.parsed)}</span>` +
    `<span class="badge webyes">in-scope : ${cell(c.in_scope)}</span>` +
    `<span class="badge expl">hors-scope : ${cell(c.out_of_scope)}</span>` +
    `<span class="badge mut">run : ${esc(String(j.run_id || '—'))}</span>` +
    '</div>' +
    '<p class="muted" style="margin:8px 0 0">Findings orientés preuve (jamais <code>vulnerable</code>). ' +
    'Consulte-les dans <a href="#findings">Findings</a> ; l\'import est tracé au <a href="#ledger">Ledger</a> ' +
    '(<code>console.import</code>).</p>';
  host.hidden = false;
}

export async function submitImport(ev) {
  if (ev) ev.preventDefault();
  imShowErr('');
  const campaign = ($('#im-campaign') && $('#im-campaign').value || '').trim();
  const format = ($('#im-format') && $('#im-format').value) || 'auto';
  const fileEl = $('#im-file');
  const file = fileEl && fileEl.files && fileEl.files[0];
  const flag = !!($('#im-flag') && $('#im-flag').checked);
  if (!OPERATOR_SECRET) { imShowErr('Secret opérateur C2 requis pour importer.'); if ($('#im-operator')) $('#im-operator').focus(); return; }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(campaign) || campaign.startsWith('-')) { imShowErr('Campagne invalide (^[A-Za-z0-9._-]{1,64}$, pas de « - » en tête).'); return; }
  if (!file) { imShowErr('Sélectionne un fichier de scan à importer.'); return; }
  const btn = $('#im-submit'); const stat = $('#im-stat');
  let content;
  try { content = await readFileText(file); }
  catch (e) { imShowErr('Erreur : ' + esc(String(e.message || e))); return; }
  if (!content.trim()) { imShowErr('Le fichier est vide.'); return; }
  if (btn) btn.disabled = true; if (stat) stat.textContent = 'import en cours…';
  let r;
  try {
    r = await write('/api/import', { body: { campaign, format, filename: file.name || '', content, flag_out_of_scope: flag }, auth: 'operator' });
  } catch (err) {
    if (btn) btn.disabled = false; if (stat) stat.textContent = '';
    imShowErr('Erreur réseau : ' + esc(String(err.message || err))); return;
  }
  if (btn) btn.disabled = false; if (stat) stat.textContent = '';
  const j = r.json;
  if (r.status === 403) { imShowErr('Refusé : rôle opérateur requis (vérifie le secret opérateur C2).'); return; }
  if (!r.ok) { imShowErr('Import refusé : ' + esc(String((j && (j.why || j.error)) || ('HTTP ' + r.status)))); return; }
  renderImportResult(j);
  toast(`Import OK — ${j.ingested ?? 0} finding(s) ingéré(s) (format ${j.format || '?'}).`, 'ok');
}

if ($('#im-form')) $('#im-form').addEventListener('submit', submitImport);
if ($('#im-operator')) $('#im-operator').addEventListener('input', e => { setOperatorSecret(e.target.value); loadImport(); });
if ($('#im-clearop')) $('#im-clearop').addEventListener('click', () => { setOperatorSecret(''); if ($('#im-operator')) $('#im-operator').value = ''; loadImport(); toast('Secret opérateur oublié (session).', 'ok'); });

