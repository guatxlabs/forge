import { OPERATOR_SECRET } from '../../core/api.js';
import { $ } from '../../core/dom.js';
import { MODULES } from '../modules.js';
import { guardList } from '../../core/ui.js';

export const MODULE_PARAMS = {
  'evasion.xhr': [
    { name: 'types', type: 'list', label: 'types (séparés par virgule)', placeholder: 'xhr, fetch, document' },
    { name: 'url_contains', type: 'text', label: 'url_contains (filtre sous-chaîne)', placeholder: '/api/' },
    { name: 'tab', type: 'text', label: 'tab (onglet browser)', placeholder: 'default' },
  ],
  'evasion.turnstile': [
    { name: 'strategy', type: 'select', label: 'strategy', value: 'turnstile', options: [{ value: 'turnstile', label: 'turnstile' }] },
    { name: 'threshold', type: 'number', label: 'threshold (0..1)', placeholder: '0.55', min: 0, max: 1, step: 0.05 },
    { name: 'tab', type: 'text', label: 'tab (onglet browser)', placeholder: 'default' },
  ],
};

// rendu de la liste de modules dans le formulaire : web_allowed=1 -> case cochable ;
// exploit|destructive -> GRISÉE par défaut + mention « CLI/opérateur — activer l'opt-in ».
// Quand l'opt-in « fort impact » est activé (case lc-allowhi) ET les conditions de gouvernance
// remplies (armer + raison + secret), ces modules deviennent SÉLECTIONNABLES (liseré danger).
// Le scope-guard serveur reste dur : hors-scope = VETO, indépendamment de cet opt-in côté front.
// Si le module définit des params (MODULE_PARAMS), ses champs propres apparaissent quand la case est cochée.
export function highImpactOptIn() { return !!($('#lc-allowhi') && $('#lc-allowhi').checked); }
export function renderLaunchModules() {
  const host = $('#lc-modlist'); if (!host) return;
  const hint = $('#lc-modhint');
  const hiOn = highImpactOptIn();
  const sorted = [...MODULES].sort((a, b) => String(a.kind).localeCompare(String(b.kind)));
  // connecteur DÉSACTIVÉ par l'admin (enabled=0 ou available_override=0) : jamais sélectionnable au
  // lancement (le serveur refuse de toute façon — module_disabled 400 ; on l'expose ici sans surprise).
  const connOff = m => (m.enabled === false) || (m.available_override === false);
  // disponibilité EFFECTIVE (sonde host ∧ intention opérateur) : effective_available si le moteur l'expose,
  // sinon la sonde brute `available`. Un module dont l'outil sous-jacent est ABSENT au niveau host n'est
  // PAS lançable — sans ce contrôle il serait sélectionnable puis SKIP silencieusement au run (no-op).
  const effAvail = m => (m.effective_available === undefined) ? (m.available !== false) : (m.effective_available !== false);
  // outil ABSENT (sonde host négative) SANS être une désactivation opérateur (enabled/override) : indispo.
  const toolAbsent = m => !effAvail(m) && !connOff(m);
  const webable = sorted.filter(m => m.web_allowed && !m.exploit && !m.destructive && !connOff(m) && !toolAbsent(m));
  const blocked = sorted.filter(m => m.exploit || m.destructive || !m.web_allowed || connOff(m) || toolAbsent(m));
  if (hint) hint.textContent = `${webable.length} web · ${blocked.length} ${hiOn ? 'à gouverner' : 'bloqués'}`;
  if (guardList(host, sorted, 'aucun module exposé par le moteur')) return;
  host.replaceChildren();
  sorted.forEach(m => {
    const highImpact = !!(m.exploit || m.destructive);
    // un connecteur DÉSACTIVÉ par l'admin n'est JAMAIS sélectionnable (au-dessus du plancher exploit :
    // même l'opt-in fort-impact ne le débloque pas — le serveur le refuse via module_disabled).
    const disabledByAdmin = connOff(m);
    // outil non installé sur l'hôte (sonde de disponibilité négative) : jamais lançable — le run le
    // SKIP en silence sinon (item no-op). Distinct d'une désactivation opérateur (disabledByAdmin).
    const disabledByAbsent = toolAbsent(m);
    // un module est sélectionnable s'il est web_allowed non-exploit/non-destructif, OU s'il est à
    // fort impact ET que l'opt-in gouverné est activé — et JAMAIS s'il est désactivé par l'admin
    // ou dont l'outil est absent du host.
    const allowed = !disabledByAdmin && !disabledByAbsent && ((!!m.web_allowed && !highImpact) || (highImpact && hiOn));
    const armedHi = highImpact && allowed;   // module à fort impact débloqué par l'opt-in
    const specs = (allowed && MODULE_PARAMS[m.kind]) || null;
    const lab = document.createElement('label');
    lab.className = 'lc-modopt' + (allowed ? '' : ' disabled') + (disabledByAbsent ? ' unavail' : '') + (armedHi ? ' hi-armed' : '') + (specs ? ' has-params' : '');
    // ligne du haut : case + nom (+ mention bloquée / fort impact)
    const top = document.createElement('div'); top.className = 'lc-modtop';
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.value = m.kind; cb.dataset.lcmod = '1';
    if (highImpact) cb.dataset.lchi = '1';
    cb.disabled = !allowed;
    const nm = document.createElement('span'); nm.className = 'lc-modname'; nm.textContent = m.kind;
    top.append(cb, nm);
    if (!allowed) {
      const why = disabledByAdmin
        ? 'désactivé (admin)'
        : disabledByAbsent
          ? 'indispo (outil absent)'
          : (highImpact
            ? 'CLI/opérateur — activer l\'opt-in ' + [m.exploit ? 'exploit' : '', m.destructive ? 'destructif' : ''].filter(Boolean).join('/')
            : 'CLI opérateur uniquement — non autorisé web');
      const tag = document.createElement('span'); tag.className = 'lc-clionly'; tag.textContent = why;
      top.appendChild(tag);
      lab.title = disabledByAdmin
        ? 'Connecteur désactivé par un administrateur (gouvernance) — non lançable (le serveur le refuse : module_disabled).'
        : disabledByAbsent
          ? 'Outil non installé sur l\'hôte (sonde de disponibilité négative) — non lançable (le run le SKIP en silence).'
          : (highImpact
            ? 'Module à fort impact : active l\'opt-in « fort impact » (zone danger) pour le sélectionner.'
            : 'Ce module ne peut pas être lancé depuis le web (non autorisé web).');
    } else if (armedHi) {
      const tag = document.createElement('span'); tag.className = 'lc-clionly'; tag.textContent = 'fort impact — ' + [m.exploit ? 'exploit' : '', m.destructive ? 'destructif' : ''].filter(Boolean).join('/');
      top.appendChild(tag);
      lab.title = 'Module à fort impact débloqué par l\'opt-in gouverné (scope-borné, audité).' + (m.mitre ? ' ' + m.mitre : '');
    } else if (m.mitre) {
      lab.title = m.mitre + (m.descr ? ' — ' + m.descr : '');
    }
    lab.appendChild(top);
    // bloc de params spécifiques : visible seulement quand la case est cochée (params-open).
    if (specs) {
      const pbox = document.createElement('div'); pbox.className = 'lc-modparams'; pbox.dataset.lcparamsFor = m.kind;
      specs.forEach(f => {
        const pf = document.createElement('div'); pf.className = 'lc-pf';
        const cap = document.createElement('span'); cap.textContent = f.label || f.name; pf.appendChild(cap);
        let inp;
        if (f.type === 'select') {
          inp = document.createElement('select');
          (f.options || []).forEach(o => { const op = document.createElement('option'); op.value = o.value; op.textContent = o.label; if (String(o.value) === String(f.value)) op.selected = true; inp.appendChild(op); });
        } else {
          inp = document.createElement('input');
          inp.type = f.type === 'number' ? 'number' : 'text';
          if (f.type === 'number') { if (f.min != null) inp.min = f.min; if (f.max != null) inp.max = f.max; if (f.step != null) inp.step = f.step; }
          if (f.placeholder) inp.placeholder = f.placeholder;
          if (f.value != null) inp.value = f.value;
        }
        inp.dataset.lcparam = f.name; inp.dataset.lcparamType = f.type || 'text';
        // un clic dans un champ ne doit pas (dé)cocher la case parente (label)
        inp.addEventListener('click', e => e.stopPropagation());
        pf.appendChild(inp); pbox.appendChild(pf);
      });
      lab.appendChild(pbox);
      // (dé)révèle le bloc params au cochage ; clic sur un champ ne propage pas.
      cb.addEventListener('change', () => lab.classList.toggle('params-open', cb.checked));
    }
    host.appendChild(lab);
  });
}

// Coche (on=true) / décoche (on=false) en masse les modules du formulaire de lancement.
// « Tout sélectionner » ne coche QUE les modules SÉLECTIONNABLES (checkbox non-disabled) : les modules
// désactivés (admin) ou dont l'outil est absent restent décochés (respect du gate d'indisponibilité).
// « Tout désélectionner » décoche tout (y compris un éventuel coché résiduel). On dispatche `change`
// pour que le bloc de params (params-open) reste synchronisé sans dupliquer la logique de rendu.
export function lcSelectModules(on) {
  [...document.querySelectorAll('#lc-modlist input[data-lcmod]')].forEach(cb => {
    if (on && cb.disabled) return;          // select-all ignore les modules non lançables
    if (cb.checked !== on) { cb.checked = on; cb.dispatchEvent(new Event('change')); }
  });
}

// Construit body.module_params à partir des modules WEB-ALLOWED cochés qui ont des champs renseignés.
// Coercition : list -> array (vide ignoré) ; number -> Number (NaN ignoré) ; text/select -> string non vide.
// Un module sans aucun champ renseigné est omis (pas de clé vide -> no-op côté backend).
export function collectModuleParams() {
  const out = {};
  document.querySelectorAll('#lc-modlist .lc-modparams').forEach(box => {
    const kind = box.dataset.lcparamsFor;
    const lab = box.closest('.lc-modopt');
    const cb = lab && lab.querySelector('input[data-lcmod]');
    if (!cb || !cb.checked || cb.disabled) return;  // seuls les modules cochés ET sélectionnables (⊆ modules[])
    const params = {};
    box.querySelectorAll('[data-lcparam]').forEach(inp => {
      const key = inp.dataset.lcparam, t = inp.dataset.lcparamType, raw = (inp.value || '').trim();
      if (raw === '') return;
      if (t === 'list') { const arr = raw.split(',').map(s => s.trim()).filter(Boolean); if (arr.length) params[key] = arr; }
      else if (t === 'number') { const n = Number(raw); if (!Number.isNaN(n)) params[key] = n; }
      else params[key] = raw;
    });
    if (Object.keys(params).length) out[kind] = params;
  });
  return out;
}

// État de la zone danger : reflète l'(in)complétude des conditions de gouvernance (armer/raison/secret)
// et bascule l'apparence + re-rend la liste de modules pour (dé)bloquer exploit/destructif.
export function lcSyncDanger() {
  const dz = $('#lc-danger'); if (!dz) return;
  const on = highImpactOptIn();
  dz.classList.toggle('on', on);
  const reqs = $('#lc-hireqs');
  if (reqs) {
    if (!on) { reqs.replaceChildren(); }
    else {
      const arm = !!($('#lc-arm') && $('#lc-arm').checked);
      const reason = !!(($('#lc-reason') && $('#lc-reason').value || '').trim());
      const secret = !!OPERATOR_SECRET;
      reqs.replaceChildren();
      [['armer', arm], ['raison', reason], ['secret opérateur', secret]].forEach(([label, ok]) => {
        const s = document.createElement('span'); s.className = 'req ' + (ok ? 'ok' : 'miss');
        s.textContent = (ok ? '✓ ' : '✗ ') + label; reqs.appendChild(s);
      });
    }
  }
  renderLaunchModules();   // re-rend pour (dé)bloquer les modules à fort impact selon l'opt-in
}
