import { infoModal, toast } from '../../core/ui.js';

// --- RAPPORT DE RUN : GET /api/runs/:id/report (text/markdown) -> modale read-only ---
export async function openRunReport(runId) {
  let r, md;
  try {
    r = await fetch('/api/runs/' + encodeURIComponent(runId) + '/report', { headers: { Accept: 'text/markdown' } });
    md = await r.text().catch(() => '');
  } catch (e) { toast('Rapport : ' + (e.message || e), 'bad'); return; }
  if (r.status === 404) { toast('Run inconnu (pas de rapport).', 'bad'); return; }
  if (!r.ok) { toast('Rapport indisponible (' + r.status + ').', 'bad'); return; }
  infoModal('Rapport — ' + runId, body => {
    const pre = document.createElement('pre'); pre.className = 'mailtext lc-report'; pre.textContent = md || '(rapport vide)';
    body.appendChild(pre);
  });
}

// --- RAPPORT HTML BRANDÉ : GET /api/runs/:id/report?format=html -> nouvelle fenêtre imprimable ---
// L'endpoint est sous auth_guard : on FETCH (le cookie de session forge_session, HttpOnly, part
// automatiquement en same-origin — aucun token à coller), puis on écrit le HTML dans une fenêtre same-origin en injectant
// une <base href> (l'URL canonique du rapport) pour que les liens relatifs (?format=pdf/md) et
// /quetzal.svg résolvent correctement. `print=true` déclenche l'impression (« Enregistrer en PDF »).
export async function openRunReportHtml(runId, print) {
  const url = '/api/runs/' + encodeURIComponent(runId) + '/report?format=html';
  let r, html;
  try {
    r = await fetch(url, { headers: { Accept: 'text/html' } });
    html = await r.text().catch(() => '');
  } catch (e) { toast('Rapport HTML : ' + (e.message || e), 'bad'); return; }
  if (r.status === 404) { toast('Run inconnu (pas de rapport).', 'bad'); return; }
  if (!r.ok) { toast('Rapport HTML indisponible (' + r.status + ').', 'bad'); return; }
  // La fenêtre est un document TOP-LEVEL same-origin (pas un iframe sandbox) : on NEUTRALISE donc
  // tout script embarqué via une CSP `script-src 'none'; object-src 'none'` injectée en TÊTE du <head>
  // (l'impression/rendu du rapport n'exécute aucun script — le contenu peut porter de la sortie d'outil
  // influençable par un attaquant, un <script> inline s'exécuterait sinon avec l'origine console).
  // On injecte AUSSI une <base href> (URL canonique du rapport) pour que les liens relatifs
  // (?format=pdf/md) et /quetzal.svg résolvent en same-origin, puis on publie le document via un Blob
  // URL (évite document.write). Le Blob URL est révoqué après ouverture.
  const baseHref = new URL(url, location.href).href;
  const csp = '<meta http-equiv="Content-Security-Policy" content="script-src \'none\'; object-src \'none\'">';
  const withBase = html.replace(/<head>/i, '<head>' + csp + '<base href="' + baseHref.replace(/"/g, '&quot;') + '">');
  const blobUrl = URL.createObjectURL(new Blob([withBase], { type: 'text/html;charset=utf-8' }));
  const win = window.open(blobUrl, '_blank');
  if (!win) { URL.revokeObjectURL(blobUrl); toast('Pop-up bloquée : autorise les fenêtres pour ouvrir le rapport.', 'bad'); return; }
  if (print) {
    // laisse le rendu/quetzal se charger avant d'ouvrir le dialogue d'impression.
    win.addEventListener('load', () => setTimeout(() => { try { win.focus(); win.print(); } catch (e) {} }, 400));
  }
  // révoque le Blob une fois la fenêtre chargée (libère la mémoire sans casser l'affichage).
  setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
}
