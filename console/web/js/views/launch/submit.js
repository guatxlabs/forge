import { OPERATOR_SECRET, write } from '../../core/api.js';
import { $, esc } from '../../core/dom.js';
import { activeEngagement } from '../../core/state.js';
import { confirmModal, toast } from '../../core/ui.js';
import { collectModuleParams, highImpactOptIn } from './modules-form.js';
import { LC_LIVE, followRun, lcSetLiveBadge } from './live.js';
import { loadRuns } from './runs-list.js';

// affiche un message d'erreur clair sous le formulaire (mappe les codes du contrat run_create).
export const LC_ERRMAP = {
  operator_required: 'Secret opérateur requis ou invalide (en-tête X-Forge-Operator). Renseigne le mot de passe opérateur.',
  bad_campaign: 'Nom de campagne invalide : ^[A-Za-z0-9._-]{1,64}$ et pas de « - » en tête.',
  no_targets: 'Au moins une cible est requise (une par ligne).',
  bad_target: 'Cible invalide : hostname ou IP/CIDR, sans espace ni métacaractère.',
  out_of_scope: 'Cible hors du scope serveur autorisé — refusée avant lancement (le périmètre n\'est jamais élargi via le web).',
  bad_mode: 'Mode invalide (propose|auto).',
  exploit_floor: 'Module exploit/destructif refusé : active l\'opt-in « fort impact » (armer + raison + secret opérateur) pour l\'autoriser.',
  high_impact_requires_arm_and_reason: 'Opt-in « fort impact » incomplet : il faut cocher « armer » ET renseigner une raison non vide (le secret opérateur reste requis avant ce contrôle).',
  not_web_allowed: 'Module non autorisé en cadre web.',
  unknown_module: 'Module inconnu du moteur.',
  bad_module_params: 'Params de module mal formés (objet attendu, profondeur/longueurs bornées, pas de NUL).',
  param_for_unrequested_module: 'Params fournis pour un module non sélectionné — sélectionne le module ou retire ses params.',
  run_in_progress: 'Un run est déjà en cours (FIFO : un seul à la fois). Attends sa fin ou annule-le.',
  mkdir_failed: 'Erreur serveur : création du répertoire de run impossible.',
  write_failed: 'Erreur serveur : écriture scope/targets impossible.',
  spawn_failed: 'Erreur serveur : démarrage du moteur impossible.',
};
export function lcShowErr(msg) { const e = $('#lc-err'); if (e) { e.innerHTML = msg; e.hidden = false; } }
export function lcClearErr() { const e = $('#lc-err'); if (e) { e.textContent = ''; e.hidden = true; } }

// POST /api/run avec validation côté client miroir du contrat (messages clairs avant l'aller-retour).
export async function submitRun(e) {
  e.preventDefault();
  lcClearErr();
  const campaign = ($('#lc-campaign').value || '').trim();
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(campaign) || campaign.startsWith('-')) { lcShowErr(LC_ERRMAP.bad_campaign); return; }
  const targets = ($('#lc-targets').value || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!targets.length) { lcShowErr(LC_ERRMAP.no_targets); return; }
  // :not(:disabled) — défense en profondeur : un module désactivé/indispo (checkbox disabled) n'entre
  // JAMAIS dans le payload, même s'il a été coché programmatiquement (le serveur le refuserait de toute façon).
  const checkedCbs = [...document.querySelectorAll('#lc-modlist input[data-lcmod]:checked:not(:disabled)')];
  const modules = checkedCbs.map(c => c.value);
  // modules à fort impact (exploit/destructif) effectivement cochés — ne peuvent l'être que si l'opt-in est ON.
  const hiModules = checkedCbs.filter(c => c.dataset.lchi === '1').map(c => c.value);
  if (!OPERATOR_SECRET) { lcShowErr(LC_ERRMAP.operator_required); $('#lc-operator') && $('#lc-operator').focus(); return; }
  const arm = !!($('#lc-arm') && $('#lc-arm').checked);
  const allowHigh = highImpactOptIn();
  const reason = ($('#lc-reason') && $('#lc-reason').value || '').trim();
  // GOUVERNANCE opt-in fort impact (miroir client du gate serveur high_impact_requires_arm_and_reason) :
  // si l'opt-in est ON, exiger armer + raison non vide AVANT le POST (le secret est déjà vérifié ci-dessus).
  if (allowHigh && (!arm || !reason)) {
    lcShowErr(`<b>high_impact_requires_arm_and_reason</b> — ${esc(LC_ERRMAP.high_impact_requires_arm_and_reason)}`);
    if (!arm && $('#lc-arm')) $('#lc-arm').focus();
    else if ($('#lc-reason')) $('#lc-reason').focus();
    return;
  }
  const body = {
    campaign, targets,
    mode: ($('#lc-mode') && $('#lc-mode').value) || 'propose',
    arm,
    exhaustive: !!($('#lc-exhaustive') && $('#lc-exhaustive').checked),
    allow_high_impact: allowHigh,
  };
  if (modules.length) body.modules = modules;
  // params spécifiques par module : { kind: {...} } — uniquement pour les modules cochés (⊆ modules[]).
  const moduleParams = collectModuleParams();
  if (Object.keys(moduleParams).length) body.module_params = moduleParams;
  // DÉBIT (rate-limit) OPT-IN : si renseigné (>0), thread top-level `rate`. Le serveur l'écrit dans
  // scope.json (throttle des oracles HTTP) et pose `rate_explicit` -> le moteur ajoute les drapeaux de
  // débit aux outils (nmap --max-rate, nuclei -rl, masscan --rate…). Vide => rien (byte-identique).
  const rateRaw = ($('#lc-rate') && $('#lc-rate').value || '').trim();
  if (rateRaw !== '') { const rn = Number(rateRaw); if (!Number.isNaN(rn) && rn > 0) body.rate = Math.floor(rn); }
  const budgetRaw = ($('#lc-budget') && $('#lc-budget').value || '').trim();
  if (budgetRaw !== '') { const b = Number(budgetRaw); if (!Number.isNaN(b)) body.budget = b; }
  if (reason) body.reason = reason.slice(0, 200);
  // ENGAGEMENT : le run opère SUR l'engagement actif (son scope + son ledger gouvernent, cf. serveur).
  { const _eng = activeEngagement(); if (_eng != null) body.engagement_id = _eng; }

  // DOUBLE-CONFIRMATION : tout lancement avec allow_high_impact=true exige une validation explicite
  // récapitulant cibles, modules à fort impact, scope (⊆ scope serveur — hors-scope vétoé), et raison.
  if (allowHigh) {
    const ok = await confirmHighImpact({ campaign, targets, hiModules, modules, reason, mode: body.mode });
    if (!ok) return;
  }

  const btn = $('#lc-submit'); const stat = $('#lc-formstat');
  if (btn) btn.disabled = true; if (stat) stat.textContent = 'lancement…';
  let r, j;
  try {
    r = await write('/api/run', { body, auth: 'operator' });
    j = r.json;
  } catch (err) {
    if (btn) btn.disabled = false; if (stat) stat.textContent = '';
    lcShowErr('Erreur réseau : ' + esc(String(err.message || err))); return;
  }
  if (btn) btn.disabled = false; if (stat) stat.textContent = '';
  if (r.status === 202) {
    const hi = j.high_impact === true;
    toast(`Campagne « ${j.campaign} » lancée (${j.mode}${hi ? ' · fort impact' : ''}) — ${j.run_id}`, hi ? 'bad' : 'ok');
    location.hash = 'launch';
    followRun(j.run_id, { status: 'running', campaign: j.campaign, mode: j.mode, fired: 0, dry_run: 0, vetoed: 0, errors: 0 });
    loadRuns();
    return;
  }
  // refus : message clair (403 opérateur / 400 validation / 409 FIFO / 5xx serveur).
  const code = j && j.error ? j.error : ('http_' + r.status);
  const base = LC_ERRMAP[j && j.error] || ('Refus serveur (' + esc(code) + ')');
  lcShowErr(`<b>${esc(code)}</b> — ${esc(base)}` + (j && j.why ? `<br><span class="muted" style="margin:0">${esc(j.why)}</span>` : ''));
}

// DOUBLE-CONFIRMATION fort impact : modale récapitulative (DOM sûr, textContent) avant POST /api/run
// avec allow_high_impact=true. Liste cibles, modules à fort impact sélectionnés, scope et raison ;
// exige une confirmation explicite. Résout true (confirmé) / false (annulé).
export function confirmHighImpact(ctx) {
  return new Promise(resolve => {
    const ov = document.createElement('div'); ov.className = 'modal-ov';
    const box = document.createElement('div'); box.className = 'modal danger wide';
    const done = val => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); resolve(val); };
    const onKey = e => { if (e.key === 'Escape') done(false); };
    document.addEventListener('keydown', onKey);
    const h = document.createElement('h3'); h.textContent = 'Confirmer un lancement à FORT IMPACT'; box.appendChild(h);
    const warn = document.createElement('p'); warn.className = 'modal-msg';
    warn.textContent = 'Tu actives des modules exploit/destructif. Action scope-bornée et auditée : toute cible hors du scope serveur sera vétoée. Confirme l\'engagement.';
    box.appendChild(warn);
    const wrap = document.createElement('div'); wrap.className = 'lc-hiconf';
    const dl = document.createElement('dl');
    const row = (label, build) => { const dt = document.createElement('dt'); dt.textContent = label; const dd = document.createElement('dd'); build(dd); dl.append(dt, dd); };
    row('Campagne', dd => dd.textContent = ctx.campaign || '-');
    row('Mode', dd => dd.textContent = ctx.mode || 'propose');
    row('Cibles (⊆ scope)', dd => dd.textContent = (ctx.targets || []).join(', ') || '-');
    row('Modules fort impact', dd => {
      const chips = document.createElement('div'); chips.className = 'lc-hichips';
      (ctx.hiModules || []).forEach(k => { const b = document.createElement('span'); b.className = 'badge destr'; b.textContent = k; chips.appendChild(b); });
      if (!(ctx.hiModules || []).length) { const s = document.createElement('span'); s.className = 'muted'; s.textContent = 'aucun coché'; chips.appendChild(s); }
      dd.appendChild(chips);
    });
    const otherMods = (ctx.modules || []).filter(m => !(ctx.hiModules || []).includes(m));
    if (otherMods.length) row('Autres modules', dd => dd.textContent = otherMods.join(', '));
    row('Raison (audit)', dd => dd.textContent = ctx.reason || '-');
    wrap.appendChild(dl);
    const scopeNote = document.createElement('div'); scopeNote.className = 'lc-warn bad'; scopeNote.style.margin = '0';
    scopeNote.textContent = 'Garde-fou de périmètre INCHANGÉ : le serveur revérifie chaque cible contre le scope autorisé. Hors-scope = VETO dur, sans exception. Le lancement est journalisé au ledger.';
    wrap.appendChild(scopeNote);
    box.appendChild(wrap);
    const act = document.createElement('div'); act.className = 'modal-act';
    const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'm-cancel'; cancel.textContent = 'Annuler'; cancel.onclick = () => done(false);
    const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'm-ok danger'; ok.textContent = 'Confirmer & lancer (fort impact)'; ok.onclick = () => done(true);
    act.append(cancel, ok); box.appendChild(act);
    ov.onclick = e => { if (e.target === ov) done(false); };
    ov.appendChild(box); document.body.appendChild(ov);
    setTimeout(() => cancel.focus(), 30);
  });
}

export async function cancelRun() {
  const runId = LC_LIVE && LC_LIVE.runId;
  if (!runId) { toast('Aucun run en cours à annuler.', 'bad'); return; }
  if (!OPERATOR_SECRET) { lcShowErr(LC_ERRMAP.operator_required); location.hash = 'launch'; return; }
  if (!(await confirmModal('Annuler le run en cours ? Le groupe de processus sera tué.', { danger: true, okText: 'Annuler le run' }))) return;
  let r, j;
  try {
    r = await write('/api/runs/' + encodeURIComponent(runId) + '/cancel', { auth: 'operator' });
    j = r.json;
  } catch (err) { toast('Erreur réseau : ' + (err.message || err), 'bad'); return; }
  if (r.ok) { toast('Annulation demandée — kill group envoyé.', 'ok'); lcSetLiveBadge('cancelled'); }
  else {
    const map = { operator_required: LC_ERRMAP.operator_required, not_running: 'Le run n\'est pas/plus en cours.', unknown_run: 'Run inconnu.' };
    toast((map[j && j.error] || ('Refus (' + (j && j.error || r.status) + ')')), 'bad');
  }
}
