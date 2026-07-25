import { adminApi } from '../../core/api.js';
import { isAdmin } from '../../core/auth.js';
import { $, esc } from '../../core/dom.js';
import { emptyState, infoModal, modal, toast } from '../../core/ui.js';
import { detEl } from '../../components/detection-source-form.js';

// =====================================================================================
//  SAUVEGARDE & RESTAURATION CHIFFRÉES (panneau #admin, réservé role=admin)
//  L'archive est TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305) et embarque base + ledger + clé
//  .ed25519. La passphrase est OBLIGATOIRE et n'est JAMAIS persistée côté client (saisie -> requête ->
//  oubliée ; les champs sont vidés à la fermeture de la modale). GET /api/backup/policy ne renvoie
//  AUCUN secret (rédigé). Modales natives (helper modal()) uniquement. Détails : docs/BACKUP.md.
// =====================================================================================
export const OFFSITE_KINDS = [
  { value: 'none', label: 'Aucun — pas d’expédition' },
  { value: 'local_dir', label: 'Dossier local (copie)' },
  { value: 'exec', label: 'Commande (argv fixe, sans shell)' },
];

// --- Créer une sauvegarde : demande la passphrase (jamais persistée) puis télécharge l'archive chiffrée.
export async function backupCreate() {
  const vals = await modal({
    title: 'Créer une sauvegarde chiffrée',
    message: 'L’archive embarque la base, le ledger et la clé de signature .ed25519 — elle est TOUJOURS chiffrée. Choisissez une passphrase FORTE : sans elle, l’archive est irrécupérable. Elle n’est ni stockée, ni loggée, ni ledgerisée.',
    okText: 'Créer & télécharger',
    fields: [
      { name: 'passphrase', label: 'Passphrase (obligatoire)', type: 'password', required: true, hint: 'Dérive la clé (argon2id) qui chiffre l\'archive. Elle n\'est ni stockée, ni loggée, ni ledgerisée — conservez-la hors-ligne : sans elle, l\'archive est définitivement irrécupérable.' },
      { name: 'confirm', label: 'Confirmer la passphrase', type: 'password', required: true, hint: 'Ressaisie pour éviter une faute de frappe sur une passphrase qu\'on ne peut pas récupérer.' },
    ],
    validate: v => (v.passphrase !== v.confirm ? 'Les deux passphrases diffèrent.' : (String(v.passphrase).length < 1 ? 'Passphrase requise.' : null)),
  });
  if (!vals) return;
  try {
    const r = await fetch('/api/backup', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/octet-stream' },
      body: JSON.stringify({ passphrase: vals.passphrase }),
    });
    if (!r.ok) {
      let why = 'HTTP ' + r.status;
      try { const j = await r.json(); why = (j && (j.why || j.error)) || why; } catch (e) {}
      throw new Error(why);
    }
    const blob = await r.blob();
    const cd = r.headers.get('content-disposition') || '';
    const m = /filename="?([^"]+)"?/.exec(cd);
    const name = (m && m[1]) || 'forge-backup.forge';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast('Sauvegarde chiffrée téléchargée (' + name + ').', 'ok');
  } catch (e) { toast('Sauvegarde refusée : ' + e.message, 'bad'); }
}

// --- Restaurer : modale native (fichier + passphrase + apply/confirm). Par défaut VALIDE sans écrire.
export function backupRestore() {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal wide danger';
  const form = document.createElement('form');
  form.innerHTML =
    '<h3>Restaurer une archive chiffrée</h3>' +
    '<p class="modal-msg">Par défaut, l’archive est <b>validée</b> (déchiffrement, sha256, chaîne ledger) sans rien écrire. Le <b>swap en place</b> (appliquer) remplace base + ledger + clé et <b>exige un redémarrage</b> de la console.</p>' +
    '<label class="modal-f"><span>Archive chiffrée (.forge)</span><input type="file" data-n="file" required><small class="modal-fhint">Le fichier produit par « Créer une sauvegarde » (base + ledger + clé de signature, chiffré).</small></label>' +
    '<label class="modal-f"><span>Passphrase</span><input type="password" data-n="passphrase" required><small class="modal-fhint">La passphrase utilisée à la création. Effacée du navigateur dès l\'envoi ; jamais conservée.</small></label>' +
    '<label class="modal-f det-inline"><input type="checkbox" data-n="apply"> <span>Appliquer le swap en place (destructif — redémarrage requis)</span></label>' +
    '<small class="modal-fhint">Décoché = validation seule (déchiffre + vérifie la chaîne ledger, n\'écrit rien). Coché = remplace la base/ledger/clé en place — irréversible, nécessite un redémarrage.</small>' +
    '<label class="modal-f det-inline"><input type="checkbox" data-n="confirm"> <span>Je confirme explicitement l’écrasement de l’installation existante</span></label>' +
    '<div class="modal-err" hidden></div>' +
    '<div class="modal-act"><button type="button" class="m-cancel">Annuler</button><button type="submit" class="m-ok danger">Valider / Restaurer</button></div>';
  box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  form.querySelector('.m-cancel').onclick = close;
  ov.onclick = e => { if (e.target === ov) close(); };
  const errBox = form.querySelector('.modal-err');
  const showE = m => { errBox.textContent = m; errBox.hidden = false; };
  form.onsubmit = async e => {
    e.preventDefault();
    const fileEl = form.querySelector('[data-n="file"]');
    const passEl = form.querySelector('[data-n="passphrase"]');
    const apply = form.querySelector('[data-n="apply"]').checked;
    const confirm = form.querySelector('[data-n="confirm"]').checked;
    const f = fileEl.files && fileEl.files[0];
    if (!f) { showE('Sélectionnez une archive.'); return; }
    if (!passEl.value) { showE('Passphrase requise.'); return; }
    if (apply && !confirm) { showE('Le swap en place exige la case de confirmation explicite.'); return; }
    const okBtn = form.querySelector('.m-ok'); okBtn.disabled = true;
    try {
      const archive_b64 = await new Promise((res, rej) => {
        const rd = new FileReader();
        rd.onerror = () => rej(new Error('lecture du fichier échouée'));
        rd.onload = () => res(String(rd.result).split(',')[1] || '');
        rd.readAsDataURL(f);
      });
      const j = await adminApi('/restore', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ archive_b64, passphrase: passEl.value, apply, confirm }),
      });
      // vide la passphrase du DOM aussitôt (ne jamais la garder côté client).
      passEl.value = '';
      if (j && j.applied) {
        close();
        infoModal('Restauration appliquée — redémarrage requis', body => {
          const p = document.createElement('p'); p.textContent = j.maintenance || 'Redémarrez la console pour charger l’état restauré.';
          body.appendChild(p);
        });
      } else {
        const v = (j && j.validated) || {};
        close();
        infoModal('Archive validée (aucune écriture)', body => {
          const add = (k, val) => { const d = document.createElement('div'); d.textContent = k + ' : ' + val; body.appendChild(d); };
          add('déchiffrable', 'oui'); add('chaîne ledger', v.ledger_ok ? 'intègre' : 'n/a');
          add('entrées ledger', v.ledger_entries != null ? v.ledger_entries : '—');
          add('contient base / ledger / clé', (v.has_db ? 'db ' : '') + (v.has_ledger ? 'ledger ' : '') + (v.has_key ? 'clé' : ''));
          const note = document.createElement('p'); note.className = 'muted';
          note.textContent = j.note || 'Pour appliquer : rouvrez la restauration, cochez « appliquer » + confirmation.';
          body.appendChild(note);
        });
      }
      toast(j && j.applied ? 'Restauration appliquée — redémarrez la console.' : 'Archive validée.', 'ok');
    } catch (e2) { showE('Refusé : ' + e2.message); okBtn.disabled = false; }
  };
  const first = form.querySelector('input'); if (first) setTimeout(() => first.focus(), 30);
}

// --- Panneau politique de sauvegarde programmée + offsite (GET rédige les secrets ; POST valide).
export async function loadAdminBackup() {
  const host = $('#admin-bk-policy'); if (!host) return;
  if (!isAdmin()) { emptyState(host, 'reserve aux administrateurs'); return; }
  host.innerHTML = '<div class="muted">chargement…</div>';
  let data;
  try { data = await adminApi('/backup/policy'); }
  catch (e) { host.innerHTML = `<div class="bad">erreur : ${esc(e.message)}</div>`; return; }
  const p = (data && data.policy) || { enabled: false, offsite: { kind: 'none' } };
  const off = p.offsite || { kind: 'none' };
  host.replaceChildren();

  const kindLabel = (OFFSITE_KINDS.find(k => k.value === (off.kind || 'none')) || {}).label || (off.kind || 'none');
  const summary = detEl('div', 'muted');
  summary.style.margin = '0 0 10px';
  summary.textContent = p.enabled
    ? `Programmée : toutes les ${p.interval_secs || '?'} s · rétention ${p.retention != null ? p.retention : '∞'} · passphrase via $${p.passphrase_env || '(non défini)'} · offsite : ${kindLabel}` + (data && data.last_run ? ` · dernière exécution @${data.last_run}` : '')
    : 'Aucune sauvegarde programmée (défaut). Configurez un intervalle + une variable d’ENV pour la passphrase pour activer le runner.';
  host.appendChild(summary);

  const edit = detEl('button', 'k-theme', { type: 'button', text: 'Éditer la politique…' });
  host.appendChild(edit);
  edit.addEventListener('click', () => editBackupPolicy(p));
}

// Éditeur de politique (modale native). N'affiche JAMAIS de secret ; `passphrase_env` = NOM d'ENV.
export async function editBackupPolicy(current) {
  const off = current.offsite || { kind: 'none' };
  const vals = await modal({
    title: 'Politique de sauvegarde programmée',
    wide: true,
    okText: 'Enregistrer',
    message: 'La passphrase du backup programmé provient d’une VARIABLE D’ENV (nommée ci-dessous) — jamais stockée en clair. L’offsite « exec » lance un argv FIXE (aucun shell). Rien n’est programmé si « activer » est décoché.',
    fields: [
      { name: 'enabled', label: 'Activer la sauvegarde programmée', type: 'checkbox', value: !!current.enabled, hint: 'Décoché = aucune sauvegarde automatique (défaut). Coché = le runner crée une archive chiffrée à chaque intervalle.' },
      { name: 'interval_secs', label: 'Intervalle (secondes)', type: 'text', value: current.interval_secs != null ? String(current.interval_secs) : '', hint: 'Fréquence des sauvegardes automatiques, en secondes (ex : 86400 = quotidien). Requis et > 0 quand activé.' },
      { name: 'retention', label: 'Rétention (nb d’archives locales, 0 = illimité)', type: 'text', value: current.retention != null ? String(current.retention) : '', hint: 'Combien d\'archives locales conserver ; les plus anciennes au-delà sont purgées. 0 = tout garder.' },
      { name: 'passphrase_env', label: 'Variable d’ENV portant la passphrase (nom)', type: 'text', value: current.passphrase_env || '', hint: 'NOM d\'une variable d\'environnement (ex : FORGE_BACKUP_PASSPHRASE), pas la passphrase elle-même. Le runner la lit à l\'exécution — jamais stockée en clair.' },
      { name: 'staging_dir', label: 'Dossier de staging (optionnel)', type: 'text', value: current.staging_dir || '', hint: 'Où déposer les archives locales avant expédition offsite. Vide = dossier par défaut de la console.' },
      { name: 'offsite_kind', label: 'Destination offsite', type: 'select', value: off.kind || 'none', options: OFFSITE_KINDS, hint: 'Copie hors-machine de l\'archive chiffrée : Aucune, Dossier local (montage/partage) ou Commande (argv fixe, sans shell — ex : rclone/scp).' },
      { name: 'offsite_dir', label: 'Offsite local_dir : dossier', type: 'text', value: off.dir || '', hint: 'Uniquement pour « Dossier local » : chemin de destination où copier l\'archive.' },
      { name: 'offsite_program', label: 'Offsite exec : programme (chemin absolu)', type: 'text', value: off.program || '', hint: 'Uniquement pour « Commande » : chemin absolu de l\'exécutable (sans shell). L\'archive chiffrée lui est passée.' },
      { name: 'offsite_args', label: 'Offsite exec : arguments (un par ligne ; {archive} = chemin)', type: 'textarea', value: Array.isArray(off.args) ? off.args.join('\n') : '', hint: 'Arguments fixes de la commande, un par ligne. Le jeton {archive} est remplacé par le chemin de l\'archive à expédier.' },
    ],
    validate: v => {
      if (v.enabled) {
        if (!(parseInt(v.interval_secs, 10) > 0)) return 'Intervalle > 0 requis quand activé.';
        if (!String(v.passphrase_env).trim()) return 'Variable d’ENV de passphrase requise quand activé.';
      }
      if (v.offsite_kind === 'local_dir' && !String(v.offsite_dir).trim()) return 'Offsite local_dir : dossier requis.';
      if (v.offsite_kind === 'exec') {
        if (!String(v.offsite_program).trim()) return 'Offsite exec : programme requis.';
        if (!String(v.offsite_program).trim().startsWith('/')) return 'Offsite exec : le programme doit être un chemin absolu.';
      }
      return null;
    },
  });
  if (!vals) return;
  const policy = { enabled: !!vals.enabled };
  if (String(vals.interval_secs).trim()) policy.interval_secs = parseInt(vals.interval_secs, 10);
  if (String(vals.retention).trim()) policy.retention = parseInt(vals.retention, 10);
  if (String(vals.passphrase_env).trim()) policy.passphrase_env = String(vals.passphrase_env).trim();
  if (String(vals.staging_dir).trim()) policy.staging_dir = String(vals.staging_dir).trim();
  const kind = vals.offsite_kind || 'none';
  const offsite = { kind };
  if (kind === 'local_dir') offsite.dir = String(vals.offsite_dir).trim();
  if (kind === 'exec') {
    offsite.program = String(vals.offsite_program).trim();
    offsite.args = String(vals.offsite_args || '').split('\n').map(s => s.trim()).filter(Boolean);
  }
  policy.offsite = offsite;
  try {
    await adminApi('/backup/policy', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ policy }),
    });
    toast('Politique de sauvegarde enregistrée.', 'ok');
    loadAdminBackup();
  } catch (e) { toast('Enregistrement refusé : ' + e.message, 'bad'); }
}
