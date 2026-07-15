import { $, esc } from './dom.js';


// =====================================================================================
//  modales + toasts in-page (remplacent alert/confirm/prompt)
// =====================================================================================
export function toast(msg, kind = 'info', ms = 3200) {
  let host = $('#toasts');
  if (!host) { host = document.createElement('div'); host.id = 'toasts'; host.setAttribute('aria-live', 'polite'); host.setAttribute('aria-atomic', 'false'); document.body.appendChild(host); }
  const t = document.createElement('div'); t.className = 'toast ' + kind; t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 220); }, ms);
}
export function showErr(form, msg) { const e = form.querySelector('.modal-err'); if (e) { e.textContent = msg; e.hidden = false; } }
// État vide réutilisable : rend un message « muted » dans un hôte (identique aux gardes open-codées
// `host.innerHTML = '<div class="muted">…</div>'` ; esc() est un no-op sur les libellés statiques).
export function emptyState(host, msg) { if (host) host.innerHTML = '<div class="muted">' + esc(msg) + '</div>'; }
// Garde de liste vide : rend le message et renvoie true quand la liste est vide -> `if (guardList(host,
// rows, 'aucun X')) return;` remplace `if (!rows.length) { host.innerHTML = '…'; return; }` à l'identique.
export function guardList(host, rows, msg) { if (rows && rows.length) return false; emptyState(host, msg); return true; }
export function modal(opts = {}) {
  return new Promise(resolve => {
    const prevFocus = document.activeElement;   // a11y : on rend le focus à l'élément déclencheur à la fermeture
    const ov = document.createElement('div'); ov.className = 'modal-ov';
    const box = document.createElement('div'); box.className = 'modal' + (opts.danger ? ' danger' : '') + (opts.wide ? ' wide' : '');
    box.setAttribute('role', 'dialog'); box.setAttribute('aria-modal', 'true');
    const form = document.createElement('form');
    let html = '';
    if (opts.title) html += `<h3>${esc(opts.title)}</h3>`;
    if (opts.message) html += `<p class="modal-msg">${esc(opts.message)}</p>`;
    (opts.fields || []).forEach(f => {
      html += `<label class="modal-f"><span>${esc(f.label || f.name)}</span>`;
      if (f.type === 'select') html += `<select data-n="${esc(f.name)}">${(f.options || []).map(o => `<option value="${esc(o.value)}"${String(o.value) === String(f.value) ? ' selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
      else if (f.type === 'checkbox') html += `<input type="checkbox" data-n="${esc(f.name)}"${f.value ? ' checked' : ''}>`;
      else if (f.type === 'textarea') html += `<textarea data-n="${esc(f.name)}" rows="2" spellcheck="false" placeholder="${esc(f.placeholder || '')}">${esc(f.value == null ? '' : f.value)}</textarea>`;
      else html += `<input type="${esc(f.type || 'text')}" data-n="${esc(f.name)}" value="${esc(f.value == null ? '' : f.value)}" placeholder="${esc(f.placeholder || '')}"${f.required ? ' required' : ''}>`;
      // indice explicatif optionnel sous le champ (accessible : décrit le champ, pas juste un label).
      if (f.hint) html += `<small class="modal-fhint">${esc(f.hint)}</small>`;
      html += `</label>`;
    });
    html += `<div class="modal-err" hidden></div>`;
    html += `<div class="modal-act"><button type="button" class="m-cancel">${esc(opts.cancelText || 'Annuler')}</button><button type="submit" class="m-ok${opts.danger ? ' danger' : ''}">${esc(opts.okText || 'OK')}</button></div>`;
    form.innerHTML = html; box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);
    const close = val => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); if (prevFocus && typeof prevFocus.focus === 'function') { try { prevFocus.focus(); } catch (e) {} } resolve(val); };
    const onKey = e => {
      if (e.key === 'Escape') { close(null); return; }
      // focus-trap : Tab/Shift-Tab bouclent DANS la modale (jamais vers le shell derrière l'overlay).
      if (e.key === 'Tab') {
        const f = box.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])');
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', onKey);
    const first = form.querySelector('input,select,textarea'); if (first) setTimeout(() => first.focus(), 30);
    form.querySelector('.m-cancel').onclick = () => close(null);
    ov.onclick = e => { if (e.target === ov) close(null); };
    form.onsubmit = e => {
      e.preventDefault();
      const vals = {}; form.querySelectorAll('[data-n]').forEach(el => { vals[el.dataset.n] = el.type === 'checkbox' ? el.checked : el.value; });
      for (const f of (opts.fields || [])) { if (f.required && !String(vals[f.name] || '').trim()) { showErr(form, `"${f.label || f.name}" est requis.`); return; } }
      if (opts.validate) { const err = opts.validate(vals); if (err) { showErr(form, err); return; } }
      close(vals);
    };
  });
}
export async function confirmModal(message, opts = {}) {
  const r = await modal({ title: opts.title || 'Confirmer', message, okText: opts.okText || 'Confirmer', cancelText: opts.cancelText, danger: opts.danger !== false });
  return r !== null;
}
// modalConfirm : confirmation stylée in-page (remplace window.confirm). Résout true (Confirmer) /
// false (Annuler). danger=true => bouton de confirmation rouge (action destructive). Réutilise modal()
// via confirmModal : focus-trap, aria-modal, Esc=annuler, Enter=confirmer, texte échappé par modal().
export async function modalConfirm({ title, message, confirmText, danger } = {}) {
  return confirmModal(message, { title, okText: confirmText || 'Confirmer', danger: !!danger });
}
// modalPrompt : saisie texte stylée in-page (remplace window.prompt). Résout la chaîne saisie, ou null
// si annulé. Enter valide, Esc annule, focus auto sur le champ (assurés par modal()). Tout texte
// interpolé (title/label/value/placeholder) est échappé par modal() -> aucune injection possible via value.
export async function modalPrompt({ title, label, value, placeholder, confirmText, hint, message, required, validate } = {}) {
  const r = await modal({
    title,
    message,
    okText: confirmText || 'Confirmer',
    fields: [{ name: 'value', label: label || '', value, placeholder, hint, required: !!required }],
    validate: validate ? (v => validate(v.value)) : undefined,
  });
  return r === null ? null : String(r.value == null ? '' : r.value);
}
// modale d'info read-only (détail finding / entrée ledger) : DOM sûr (textContent).
export function infoModal(title, buildBody) {
  const prevFocus = document.activeElement;   // a11y : restaurer le focus déclencheur à la fermeture
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal wide';
  box.setAttribute('role', 'dialog'); box.setAttribute('aria-modal', 'true');
  const onKey = e => {
    if (e.key === 'Escape') { close(); return; }
    if (e.key === 'Tab') {   // focus-trap : Tab boucle dans la modale
      const f = box.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])');
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); if (prevFocus && typeof prevFocus.focus === 'function') { try { prevFocus.focus(); } catch (e) {} } };
  document.addEventListener('keydown', onKey);
  const h = document.createElement('h3'); h.textContent = title; box.appendChild(h);
  const body = document.createElement('div'); body.className = 'infobody'; box.appendChild(body);
  buildBody(body);
  const act = document.createElement('div'); act.className = 'modal-act';
  const cb = document.createElement('button'); cb.type = 'button'; cb.className = 'm-cancel'; cb.textContent = 'Fermer'; cb.onclick = close;
  act.appendChild(cb); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
}
