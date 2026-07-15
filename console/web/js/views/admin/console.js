import { isAdmin } from '../../core/auth.js';
import { $ } from '../../core/dom.js';
import { toast } from '../../core/ui.js';

// =====================================================================================
//  CONSOLE FORGE IN-UI (roadmap P5) — panneau #admin-console, réservé role=admin.
//  Ce N'EST PAS un terminal : on affiche une LISTE FIXE des commandes de l'allowlist serveur, chacune
//  avec seulement ses options TYPÉES (toggles/champs). Un clic « Exécuter » POST /api/console/exec avec
//  {command, args, confirm} ; le serveur valide (allowlist + schéma d'args), ledgerise `console.exec`,
//  et STREAME la sortie (SSE : events `log`/`status`). On consomme le flux via fetch() + ReadableStream
//  et on rend chaque ligne ÉCHAPPÉE (esc) dans un volet en lecture seule — jamais d'innerHTML de texte
//  serveur (anti-XSS). Aucune saisie de commande libre, aucun flag arbitraire : l'UI ne propose que ce
//  que l'allowlist autorise ; le serveur reste l'autorité (check_admin -> 403 ; hors-allowlist -> 400).
// =====================================================================================

// --- Descripteurs des commandes allowlistées (miroir UI du serveur — le serveur reste l'autorité) ---
//     type de champ : 'flag' (case à cocher -> bool), 'text' (chaîne typée), 'envvar' (NOM de variable).
const COMMANDS = [
  {
    id: 'status', label: 'status', danger: false,
    desc: 'État de la console (version, schéma, backend, tête de ledger vérifiée). Lecture seule.',
    fields: [],
  },
  {
    id: 'ledger-verify', label: 'ledger verify', danger: false,
    desc: 'Recalcule la chaîne SHA-256 du ledger et vérifie son intégrité. Lecture seule.',
    fields: [],
  },
  {
    id: 'read-findings', label: 'read findings', danger: false,
    desc: 'Liste les findings (lecture seule). Filtre optionnel par campagne.',
    fields: [
      { name: 'campaign', type: 'text', label: 'Campagne (optionnel)', placeholder: 'ex: engagement-1' },
      { name: 'json', type: 'flag', label: 'Sortie JSON' },
    ],
  },
  {
    id: 'read-roe', label: 'read roe', danger: false,
    desc: 'Liste les décisions ROE / scope-guard (lecture seule). Filtre optionnel par campagne.',
    fields: [
      { name: 'campaign', type: 'text', label: 'Campagne (optionnel)', placeholder: 'ex: engagement-1' },
      { name: 'json', type: 'flag', label: 'Sortie JSON' },
    ],
  },
  {
    id: 'read-coverage', label: 'read coverage', danger: false,
    desc: 'Couverture ATT&CK par technique (lecture seule). Filtre optionnel par campagne.',
    fields: [
      { name: 'campaign', type: 'text', label: 'Campagne (optionnel)', placeholder: 'ex: engagement-1' },
      { name: 'json', type: 'flag', label: 'Sortie JSON' },
    ],
  },
  {
    id: 'backup', label: 'backup', danger: false,
    desc: 'Crée une sauvegarde chiffrée dans le dossier géré du serveur. Vous fournissez un NOM de fichier et un NOM de variable d\'ENV (la passphrase est résolue côté serveur, jamais transmise).',
    fields: [
      { name: 'out', type: 'text', label: 'Nom de fichier (dossier géré)', placeholder: 'snapshot.forge', required: true },
      { name: 'passphrase-env', type: 'envvar', label: 'Variable d\'ENV de la passphrase', placeholder: 'FORGE_BACKUP_PASSPHRASE', required: true },
    ],
  },
  {
    id: 'upgrade', label: 'upgrade', danger: true, stateChanging: true,
    desc: 'Upgrade fail-closed (snapshot chiffré pré-upgrade -> migration additive -> vérif -> rollback sur échec). À EFFET D\'ÉTAT : exige une confirmation explicite (sauf --dry-run qui ne mute rien).',
    fields: [
      { name: 'passphrase-env', type: 'envvar', label: 'Variable d\'ENV de la passphrase', placeholder: 'FORGE_BACKUP_PASSPHRASE', required: true },
      { name: 'dry-run', type: 'flag', label: 'Dry-run (aucune mutation)' },
    ],
  },
];

// petit constructeur d'éléments (échappement systématique, aucun innerHTML de donnée).
function el(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (attrs) for (const k in attrs) { if (k === 'text') e.textContent = attrs[k]; else e.setAttribute(k, attrs[k]); }
  return e;
}

// --- Point d'entrée du panneau : rend une carte par commande allowlistée + un volet de sortie partagé.
export function loadConsolePanel() {
  const host = $('#admin-console-body'); if (!host) return;
  if (!isAdmin()) { host.replaceChildren(el('div', 'muted', { text: 'réservé aux administrateurs' })); return; }
  host.replaceChildren();

  // volet de sortie (lecture seule, monospace, scrollable).
  const out = el('pre', 'console-out', { 'aria-live': 'polite', tabindex: '0' });
  out.textContent = 'La sortie des commandes s’affichera ici.';

  const grid = el('div', 'console-cmd-grid');
  for (const cmd of COMMANDS) grid.appendChild(renderCommandCard(cmd, out));

  host.appendChild(grid);
  const outWrap = el('div', 'console-out-wrap');
  const outHead = el('div', 'console-out-head');
  outHead.appendChild(el('span', null, { text: 'Sortie' }));
  const clearBtn = el('button', 'k-theme', { type: 'button', title: 'Effacer le volet de sortie' });
  clearBtn.textContent = 'Effacer';
  clearBtn.addEventListener('click', () => { out.textContent = ''; });
  outHead.appendChild(clearBtn);
  outWrap.appendChild(outHead);
  outWrap.appendChild(out);
  host.appendChild(outWrap);
}

// --- Rend une carte de commande : titre + description + champs typés + « la commande qui va tourner »
//     (transparence) + bouton Exécuter (+ case de confirmation pour les commandes à effet d'état).
function renderCommandCard(cmd, out) {
  const card = el('div', 'console-cmd' + (cmd.danger ? ' danger' : ''));
  const head = el('div', 'console-cmd-head');
  head.appendChild(el('code', 'console-cmd-name', { text: 'forge ' + cmd.label }));
  if (cmd.stateChanging) head.appendChild(el('span', 'badge', { text: 'effet d’état', title: 'exige une confirmation explicite' }));
  card.appendChild(head);
  card.appendChild(el('p', 'muted console-cmd-desc', { text: cmd.desc }));

  const inputs = {};
  if (cmd.fields.length) {
    const fieldsWrap = el('div', 'console-cmd-fields');
    for (const f of cmd.fields) {
      if (f.type === 'flag') {
        const lab = el('label', 'console-f-inline');
        const cb = el('input', null, { type: 'checkbox' });
        inputs[f.name] = cb;
        lab.appendChild(cb);
        lab.appendChild(el('span', null, { text: f.label }));
        fieldsWrap.appendChild(lab);
      } else {
        const lab = el('label', 'console-f');
        lab.appendChild(el('span', null, { text: f.label }));
        const inp = el('input', null, { type: 'text', autocomplete: 'off', spellcheck: 'false' });
        if (f.placeholder) inp.setAttribute('placeholder', f.placeholder);
        inputs[f.name] = inp;
        lab.appendChild(inp);
        fieldsWrap.appendChild(lab);
      }
    }
    card.appendChild(fieldsWrap);
  }

  // case de confirmation obligatoire pour les commandes à effet d'état (miroir du gate serveur).
  let confirmCb = null;
  if (cmd.stateChanging) {
    const lab = el('label', 'console-f-inline console-confirm');
    confirmCb = el('input', null, { type: 'checkbox' });
    lab.appendChild(confirmCb);
    lab.appendChild(el('span', null, { text: 'Je confirme cette commande à effet d’état' }));
    card.appendChild(lab);
  }

  // « transparence » : affiche la commande qui va tourner, recalculée à chaque changement.
  const preview = el('code', 'console-preview');
  const runBtn = el('button', 'login-btn console-run', { type: 'button' });
  runBtn.textContent = 'Exécuter';

  const buildArgs = () => {
    const args = {};
    for (const f of cmd.fields) {
      const inp = inputs[f.name];
      if (f.type === 'flag') { if (inp.checked) args[f.name] = true; }
      else { const v = inp.value.trim(); if (v) args[f.name] = v; }
    }
    return args;
  };
  const refreshPreview = () => {
    const args = buildArgs();
    let s = 'forge ' + cmd.label;
    for (const f of cmd.fields) {
      if (f.type === 'flag') { if (args[f.name]) s += ' --' + f.name; }
      else if (args[f.name] != null) s += ' --' + f.name + ' ' + args[f.name];
    }
    preview.textContent = s;
  };
  for (const f of cmd.fields) inputs[f.name].addEventListener('input', refreshPreview);
  for (const f of cmd.fields) inputs[f.name].addEventListener('change', refreshPreview);
  refreshPreview();

  const previewWrap = el('div', 'console-preview-wrap');
  previewWrap.appendChild(el('span', 'muted console-preview-lbl', { text: 'Commande :' }));
  previewWrap.appendChild(preview);
  card.appendChild(previewWrap);

  runBtn.addEventListener('click', () => {
    // validation cliente minimale (le serveur reste l'autorité).
    for (const f of cmd.fields) {
      if (f.required && !inputs[f.name].value.trim()) { toast('Champ requis : ' + f.label, 'bad'); return; }
    }
    if (cmd.stateChanging && (!confirmCb || !confirmCb.checked)) { toast('Cochez la confirmation pour cette commande.', 'bad'); return; }
    const body = { command: cmd.id, args: buildArgs() };
    if (cmd.stateChanging) body.confirm = true;
    runExec(cmd, body, out, runBtn);
  });
  card.appendChild(runBtn);
  return card;
}

// --- Lance l'exec et STREAME la réponse SSE dans le volet de sortie (échappé). fetch() + ReadableStream
//     (POST -> EventSource impossible : GET-only) ; parsing SSE minimal (frames « event:/data: »).
async function runExec(cmd, body, out, runBtn) {
  runBtn.disabled = true;
  out.textContent = '';
  const append = (line, cls) => {
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = line + '\n'; // textContent => échappé, jamais d'innerHTML de texte serveur
    out.appendChild(span);
    out.scrollTop = out.scrollHeight;
  };
  append('$ forge ' + cmd.label, 'console-line-cmd');
  try {
    const r = await fetch('/api/console/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify(body),
    });
    if (!r.ok || !r.body) {
      let why = 'HTTP ' + r.status;
      try { const j = await r.json(); why = (j && (j.why || j.error)) || why; } catch (e) {}
      append('[refusé] ' + why, 'console-line-err');
      toast('Commande refusée : ' + why, 'bad');
      return;
    }
    // lecture incrémentale du flux SSE.
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      // une frame SSE se termine par une ligne vide (\n\n).
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        handleFrame(frame, append);
      }
    }
    if (buf.trim()) handleFrame(buf, append);
  } catch (e) {
    append('[erreur réseau] ' + (e && e.message ? e.message : e), 'console-line-err');
  } finally {
    runBtn.disabled = false;
  }
}

// --- Parse une frame SSE (« event: X\n data: {json} ») et rend la ligne (échappée) dans le volet.
function handleFrame(frame, append) {
  let ev = 'message';
  const datas = [];
  for (const raw of frame.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line.startsWith('event:')) ev = line.slice(6).trim();
    else if (line.startsWith('data:')) datas.push(line.slice(5).replace(/^ /, ''));
    // les lignes de commentaire (« : keep-alive ») sont ignorées.
  }
  if (!datas.length) return;
  let payload;
  try { payload = JSON.parse(datas.join('\n')); } catch (e) { return; }
  if (ev === 'status' || payload.kind === 'status') {
    const code = (payload.exit_code == null) ? '—' : payload.exit_code;
    const st = payload.status || 'done';
    append('[' + st + '] (exit ' + code + ')', st === 'done' ? 'console-line-ok' : 'console-line-err');
  } else {
    // event 'log' : {stream, line}
    const stream = payload.stream || 'stdout';
    const cls = stream === 'stderr' ? 'console-line-err' : (stream === 'system' ? 'console-line-sys' : null);
    append(payload.line != null ? String(payload.line) : '', cls);
  }
}
