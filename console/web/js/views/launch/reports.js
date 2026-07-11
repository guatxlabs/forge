import { authHeaders } from '../../core/api.js';
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
// L'endpoint est sous auth_guard : une navigation directe ne porterait pas le Bearer (localStorage).
// On FETCH avec l'en-tête d'auth, puis on écrit le HTML dans une fenêtre same-origin en injectant
// une <base href> (l'URL canonique du rapport) pour que les liens relatifs (?format=pdf/md) et
// /quetzal.svg résolvent correctement. `print=true` déclenche l'impression (« Enregistrer en PDF »).
export async function openRunReportHtml(runId, print) {
  const url = '/api/runs/' + encodeURIComponent(runId) + '/report?format=html';
  let r, html;
  try {
    r = await fetch(url, { headers: authHeaders({ Accept: 'text/html' }) });
    html = await r.text().catch(() => '');
  } catch (e) { toast('Rapport HTML : ' + (e.message || e), 'bad'); return; }
  if (r.status === 404) { toast('Run inconnu (pas de rapport).', 'bad'); return; }
  if (!r.ok) { toast('Rapport HTML indisponible (' + r.status + ').', 'bad'); return; }
  // injecte une <base href> (URL canonique du rapport) pour que les liens relatifs (?format=pdf/md)
  // et /quetzal.svg résolvent en same-origin, puis publie le document via un Blob URL (évite
  // document.write ; le HTML provient de notre endpoint authentifié, tout dynamique étant échappé
  // côté serveur). Le Blob URL est révoqué après ouverture.
  const baseHref = new URL(url, location.href).href;
  const withBase = html.replace(/<head>/i, '<head><base href="' + baseHref.replace(/"/g, '&quot;') + '">');
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
