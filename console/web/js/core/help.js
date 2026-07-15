import { api, write } from './api.js';
import { $, ic } from './dom.js';
import { drilldown } from '../views/explore.js';
import { MODULES } from '../views/modules.js';
import { modal } from './ui.js';


// =====================================================================================
//  AIDE IN-APP — centre d'aide natif (aucun alert/confirm/prompt navigateur).
//  Un bouton « ? » persistant dans l'en-tête ouvre une modale accessible (role=dialog, aria-modal,
//  focus-trap, Escape/clic-dehors, restauration du focus) qui explique la vue COURANTE (déduite du
//  hash) et donne accès à toutes les rubriques, dont « Comment Forge fonctionne » (modèle de sûreté).
//  Le contenu est STATIQUE et rendu en DOM sûr (textContent) ; les liens sont des ancres in-app (#vue).
// =====================================================================================
// Rubriques ordonnées. blocks = [type, payload] : 'p' paragraphe, 'h' sous-titre, 'ul' liste, 'steps' étapes.
export const HELP_TOPICS = [
  { key: 'governance', title: 'Comment Forge fonctionne — sûreté & gouvernance', icon: 'shield', doc: 'docs/SECURITY_MODEL.md', pinned: true, blocks: [
    ['p', "Forge est un produit d'évaluation red-team autorisé et gouverné : chaque action passe par des garde-fous conçus pour échouer du côté sûr (fail-closed). Voici le modèle de sûreté qu'un opérateur doit comprendre AVANT de lancer quoi que ce soit."],
    ['h', 'Scope-guard fail-closed'],
    ['p', "Le périmètre autorisé (scope serveur) fait autorité. Toute cible hors-scope est vétoée côté serveur (VETO dur) et ne peut JAMAIS être élargie depuis le web. En cas de doute, on refuse plutôt que d'autoriser."],
    ['h', 'Défaut non-exploit / non-destructif'],
    ['p', "Un lancement est non-exploit et non-destructif par défaut. Les modules exploit/destructif restent grisés tant que l'opt-in gouverné « fort impact » n'est pas activé — il exige d'armer, une raison d'audit ET le secret opérateur, plus une double-confirmation explicite."],
    ['h', 'Proof-oracles'],
    ['p', "Un résultat n'est retenu que s'il est étayé par une preuve vérifiable (oracle), pas par une supposition. On ne fabrique jamais de résultat : une mesure impossible (source injoignable) est déclarée impossible, jamais transformée en « détecté »."],
    ['h', 'Ledger tamper-evident'],
    ['p', "Chaque décision et chaque lancement sont journalisés dans un ledger append-only chaîné par SHA-256 et signé. Toute altération casse la chaîne et devient visible. La console recalcule l'intégrité hash ; la signature cryptographique se vérifie en CLI."],
  ] },
  { key: 'overview', title: "Vue d'ensemble", icon: 'home', doc: 'docs/OVERVIEW.md', view: 'overview', blocks: [
    ['p', "Tableau de bord d'entrée : l'état de la boucle purple, la répartition des findings par sévérité et les capacités disponibles. C'est le point de départ pour situer l'engagement en cours."],
    ['p', "Le sélecteur de campagne (en-tête) filtre toutes les vues sur une campagne précise. Le badge « posture » résume l'état de la boucle."],
  ] },
  { key: 'launch', title: 'Lancement (campagne)', icon: 'play', doc: 'docs/PURPLE_CAMPAIGN.md', view: 'launch', blocks: [
    ['p', "Compose et lance une campagne gouvernée. Non-exploit / non-destructif par défaut ; tout est borné au scope serveur et journalisé au ledger (console.run.start)."],
    ['steps', [
      "Vérifiez une cible (lecture pure) : la décision in-scope / hors-scope s'affiche sans rien lancer.",
      "Renseignez la campagne, le mode (propose = simulation ; auto = exécute les actions FIRE) et les cibles (⊆ scope serveur, une par ligne).",
      "Choisissez des modules (vide = le planner décide). Les modules exploit/destructif restent grisés hors opt-in fort impact.",
      "Facultatif : « Dry-plan » affiche un aperçu INERTE des verdicts garde-fou (FIRE / DRY_RUN / VETO / SKIP) sans rien exécuter ni persister.",
      "Pour lancer : fournissez le secret opérateur. Pour le fort impact, activez la zone danger (armer + raison + secret) puis double-confirmez.",
    ]],
    ['p', "Le run en cours diffuse ses logs en direct ; la liste des runs conserve l'historique et permet d'annuler un run actif."],
  ] },
  { key: 'modules', title: 'Capacités & Modules', icon: 'flask', doc: 'docs/MODULES.md', view: 'modules', blocks: [
    ['p', "Catalogue des capacités du moteur. Le badge « web » marque un module lançable en cadre web ; « exploit » / « destructif » portent un risque accru et sont gatés par les ROE au lancement."],
    ['p', "La disponibilité EFFECTIVE d'un module dépend de la sonde host ET de la gouvernance des connecteurs (Administration). Un connecteur désactivé est SKIP au tir, même si son binaire est présent."],
  ] },
  { key: 'techniques', title: 'Techniques & Sélection', icon: 'flask', doc: 'docs/MODULES.md', view: 'techniques', blocks: [
    ['p', "Catalogue des techniques du moteur GROUPÉ PAR CATÉGORIE (SQLi, IDOR, SSRF, XSS…), DÉRIVÉ du registre : un nouveau module apparaît automatiquement sous sa catégorie. Chaque technique porte les outils qui la couvrent et son éligibilité (BB = bug bounty, pentest = pentest-only)."],
    ['p', "Sélection PAR-SCOPE : le profil (bug_bounty | pentest | custom) donne l'ensemble de base, puis les toggles par catégorie / par technique AJOUTENT ou RETIRENT (la désactivation prime — fail-closed). « Au scope, retirer un test automatique » : une technique décochée n'est NI planifiée NI tirée par le moteur, en plus du scope-guard."],
    ['p', "Enregistrer la sélection est réservé aux comptes operator/admin et journalisé au ledger. La sélection s'applique aux prochains runs (scope.json profile/techniques_enabled/categories_enabled)."],
  ] },
  { key: 'workflows', title: 'Workflows', icon: 'layout', doc: 'docs/MODULES.md', view: 'workflows', blocks: [
    ['p', "Pipelines COMPOSÉS sans code : une sélection ORDONNÉE de techniques/outils (+ params par étape), sauvegardée et éditable. Absorbe les scan-engines de reNgine, les workflows d'Osmedeus et les pipelines visuels de Trickest — le builder réutilise le catalogue par catégorie et l'état activé par le scope."],
    ['p', "GOUVERNANCE fail-closed : un workflow est une PROPOSITION. Le scope-guard ROE et la sélection par-scope restent seuls juges — une étape hors-scope / désactivée pour le scope est LARGUÉE au tir. Les étapes exploit restent derrière l'opt-in fort-impact. Les workflows intégrés (dérivés du registre) ne sont pas supprimables."],
    ['p', "Création/édition/suppression réservées operator/admin et journalisées au ledger (POST /api/workflows[/:name]). « Lancer ce workflow » passe par le lancement gouverné (POST /api/run modules=étapes, auto_pentest) : mêmes garde-fous que le lancement standard."],
  ] },
  { key: 'findings', title: 'Findings', icon: 'shield', doc: 'docs/CONCEPTS.md', view: 'findings', blocks: [
    ['p', "Résultats d'évaluation normalisés : sévérité, cible, technique MITRE, statut. Filtrez par sévérité, statut ou cible ; cliquez un finding pour son détail complet (preuve, contexte, référence ledger)."],
    ['p', "Les findings alimentent la couverture ATT&CK et la boucle purple : une technique tirée devient « détectée » ou « ratée » côté défense."],
  ] },
  { key: 'reports', title: "Rapport d'engagement (livrable)", icon: 'shield', doc: 'docs/CONCEPTS.md', view: 'reports', blocks: [
    ['p', "Le LIVRABLE CLIENT agrégé de l'engagement ACTIF : page de garde brandée, résumé exécutif, findings détaillés (secrets rédigés), couverture ATT&CK et annexe chaîne-de-custody. Formats HTML / PDF / DOCX / CSV / JSON — l'aperçu HTML s'affiche dans la vue."],
    ['p', "ISOLATION : le rapport ne reflète QUE l'engagement actif (jamais les données d'un autre). Chaque génération et chaque configuration de branding sont journalisées au ledger. Le branding (nom du commanditaire, logo, prestataire) est réservé au rôle admin ; PDF/DOCX dégradent proprement si le moteur d'impression ou python est absent sur l'hôte."],
    ['p', "Depuis Findings, « Export CSV / JSON » télécharge les findings de l'engagement actif et « Rapport complet » ouvre cette vue."],
  ] },
  { key: 'explore', title: 'Recherche & Explore (soql)', icon: 'search', doc: 'docs/CONCEPTS.md', view: 'explore', blocks: [
    ['p', "Requêteur soql (langage de recherche en pipeline) sur les données de l'engagement, ex : search severity=HIGH | stats count by mitre | sort -count | head 20."],
    ['p', "Choisissez une visualisation (table / barres / courbe / stat). Cliquez une valeur pour un drilldown ; « Panneau » enregistre la requête comme panneau réutilisable dans un dashboard."],
  ] },
  { key: 'coverage', title: 'Couverture ATT&CK', icon: 'activity', doc: 'docs/PURPLE_CAMPAIGN.md', view: 'coverage', blocks: [
    ['p', "Couverture ATT&CK côté offensif : par technique MITRE, combien de runs l'ont tentée et combien ont « tiré » (déclenché un résultat)."],
    ['p', "Une technique tentée mais à 0 tiré est couverte sans résultat côté cible. Pour l'axe défensif (détecté vs raté), voir « Détection purple »."],
  ] },
  { key: 'purple-coverage', title: 'Détection purple', icon: 'layout', doc: 'docs/DETECTION.md', view: 'purple-coverage', blocks: [
    ['p', "Mesure DÉFENSIVE et OPTIONNELLE : pour chaque technique tirée en red-team, a-t-elle été détectée par votre source BLUE (SOC/IDS/pare-feu) ? Vert = détecté, rouge = trou de détection. Le MTTD mesure le délai tir → alerte."],
    ['p', "Aucune source n'est requise : sans source, Forge tourne en AUTONOME (standalone) et l'état est neutre — ce n'est pas une panne. Si une source est configurée mais injoignable, la mesure est déclarée impossible ; aucun « détecté » n'est inventé."],
    ['h', 'Connecter une source de détection'],
    ['steps', [
      "Ouvrez Administration → Source de détection.",
      "Choisissez le type (Plume, CrowdSec, Elastic/OpenSearch, FortiGate/pfSense, fichier, commande…), l'endpoint, l'authentification et le mapping MITRE.",
      "Testez la joignabilité, puis enregistrez. La boucle purple s'active dès que la source répond.",
    ]],
  ] },
  { key: 'campaigns', title: 'Campagnes', icon: 'server', doc: 'docs/PURPLE_CAMPAIGN.md', view: 'campaigns', blocks: [
    ['p', "Regroupe l'activité par campagne (une opération d'évaluation nommée). Sélectionnez-en une pour filtrer transversalement findings, couverture, ROE et ledger."],
  ] },
  { key: 'roe', title: 'ROE / Garde-fou', icon: 'shield', doc: 'docs/SECURITY_MODEL.md', view: 'roe', blocks: [
    ['p', "Journal des décisions du garde-fou (Rules of Engagement). Chaque action proposée par le moteur reçoit un verdict : FIRE (exécutée), DRY_RUN (simulée) ou VETO (bloquée), avec sa raison."],
    ['p', "C'est la transparence anti-masquage : on voit pourquoi une action a été autorisée, simulée ou refusée — jamais de refus silencieux."],
  ] },
  { key: 'ledger', title: "Ledger d'engagement", icon: 'lock', doc: 'docs/SECURITY_MODEL.md', view: 'ledger', blocks: [
    ['p', "Journal d'engagement append-only chaîné par SHA-256 : preuve d'intégrité de toutes les actions et décisions. La console recalcule la chaîne de hash (intégrité hash-only)."],
    ['p', "La signature cryptographique se vérifie hors-console : forge ledger verify --pubkey <clé>."],
  ] },
  { key: 'dashboards', title: 'Dashboards / Vues', icon: 'layout', doc: 'docs/CONCEPTS.md', view: 'dashboards', blocks: [
    ['p', "Compose des dashboards de panneaux soql (glisser pour réordonner, coin pour redimensionner). Une « vue » est une collection de dashboards — un simple filtre d'affichage local."],
  ] },
  { key: 'admin', title: 'Administration', icon: 'user', doc: 'docs/ADMINISTRATION.md', view: 'admin', blocks: [
    ['p', "Réservé au rôle admin. Toutes les mutations sont attribuées à votre compte et ledgerisées."],
    ['h', 'Comptes'],
    ['p', "viewer (lecture seule) · operator (arme les campagnes) · admin (administre). Désactivation, rétrogradation et réinitialisation de mot de passe révoquent immédiatement les sessions du compte. Le dernier admin activé est protégé (anti-verrouillage)."],
    ['h', 'Connecteurs'],
    ['p', "Interrupteur opérateur par module. Désactiver — ou forcer « indisponible » — un connecteur le rend SKIP au tir, y compris pour les modules choisis par le planner. Disponibilité effective = activé ET (override ?? sonde host)."],
    ['h', 'Source de détection'],
    ['p', "Câble une source BLUE (SIEM/IDS/pare-feu) sans code, corrélée par identité MITRE. Le secret est write-only. Une source absente/injoignable ⇒ mesure déclarée impossible."],
    ['h', 'Sauvegarde & restauration'],
    ['p', "Archive TOUJOURS chiffrée (argon2id + XChaCha20-Poly1305) embarquant base + ledger + clé de signature. La passphrase est obligatoire et jamais persistée. La restauration valide par défaut ; le swap en place exige une confirmation + un redémarrage."],
  ] },
];
export const HELP_BY_KEY = Object.fromEntries(HELP_TOPICS.map(t => [t.key, t]));
// hash de la vue courante -> clé de rubrique (identité ; repli overview).
export function currentHelpKey() { const v = (location.hash.slice(1) || 'overview'); return HELP_BY_KEY[v] ? v : 'overview'; }
export function helpBlockEl(block) {
  const [type, payload] = block;
  if (type === 'h') { const e = document.createElement('h4'); e.className = 'help-h'; e.textContent = payload; return e; }
  if (type === 'ul') { const ul = document.createElement('ul'); ul.className = 'help-ul'; (payload || []).forEach(t => { const li = document.createElement('li'); li.textContent = t; ul.appendChild(li); }); return ul; }
  if (type === 'steps') { const ol = document.createElement('ol'); ol.className = 'help-steps'; (payload || []).forEach(t => { const li = document.createElement('li'); li.textContent = t; ol.appendChild(li); }); return ol; }
  const p = document.createElement('p'); p.className = 'help-p'; p.textContent = String(payload == null ? '' : payload); return p;
}
export let _helpOpen = false;
export function openHelp(startKey) {
  if (_helpOpen) return;              // une seule modale d'aide à la fois
  _helpOpen = true;
  const opener = document.activeElement; // pour restaurer le focus à la fermeture
  const titleId = 'help-title';
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div');
  box.className = 'modal wide help-modal';
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-labelledby', titleId);

  // en-tête : titre générique + bouton fermer
  const head = document.createElement('div'); head.className = 'help-head';
  const h = document.createElement('h3'); h.id = titleId; h.textContent = 'Aide — Forge';
  const xb = document.createElement('button'); xb.type = 'button'; xb.className = 'k-theme help-x'; xb.setAttribute('aria-label', 'Fermer l\'aide'); xb.innerHTML = ic('x');
  head.append(h, xb);

  // corps : table des matières (nav) + panneau de contenu
  const body = document.createElement('div'); body.className = 'help-body';
  const toc = document.createElement('nav'); toc.className = 'help-toc'; toc.setAttribute('aria-label', 'Rubriques d\'aide');
  const content = document.createElement('div'); content.className = 'help-content'; content.tabIndex = -1;
  body.append(toc, content);

  // boutons de TOC (governance épinglée en tête, séparée par un filet)
  const tocBtns = {};
  let pinnedDone = false;
  HELP_TOPICS.forEach(t => {
    if (!t.pinned && !pinnedDone) { const sep = document.createElement('div'); sep.className = 'help-toc-sep'; toc.appendChild(sep); pinnedDone = true; }
    const b = document.createElement('button'); b.type = 'button'; b.className = 'help-toc-btn' + (t.pinned ? ' pinned' : '');
    b.innerHTML = ic(t.icon || 'book'); const sp = document.createElement('span'); sp.textContent = t.title; b.appendChild(sp);
    b.addEventListener('click', () => select(t.key, true));
    toc.appendChild(b); tocBtns[t.key] = b;
  });

  function renderContent(key) {
    const t = HELP_BY_KEY[key] || HELP_TOPICS[0];
    content.replaceChildren();
    const th = document.createElement('h4'); th.className = 'help-title'; th.textContent = t.title; content.appendChild(th);
    (t.blocks || []).forEach(bl => content.appendChild(helpBlockEl(bl)));
    // pied : lien vers la vue in-app (ferme la modale) + référence documentaire
    const meta = document.createElement('div'); meta.className = 'help-meta';
    if (t.view) {
      const a = document.createElement('a'); a.href = '#' + t.view; a.className = 'help-gotolink'; a.innerHTML = ic('ext'); const gs = document.createElement('span'); gs.textContent = 'Aller à la vue'; a.appendChild(gs);
      a.addEventListener('click', () => { close(); });
      meta.appendChild(a);
    }
    if (t.doc) {
      const d = document.createElement('span'); d.className = 'help-doc'; d.title = 'Fichier de documentation dans le dépôt';
      d.innerHTML = ic('book'); const dl = document.createElement('span'); dl.className = 'help-doc-l'; dl.textContent = 'Documentation : '; const dc = document.createElement('code'); dc.textContent = t.doc;
      d.append(dl, dc); meta.appendChild(d);
    }
    content.appendChild(meta);
    content.scrollTop = 0;
  }
  function select(key, focusContent) {
    Object.entries(tocBtns).forEach(([k, b]) => { const on = k === key; b.classList.toggle('on', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    renderContent(key);
    if (focusContent) { try { content.focus(); } catch (e) {} }
  }

  box.append(head, body);
  ov.appendChild(box);
  document.body.appendChild(ov);

  // --- accessibilité : focus-trap (Tab cycle), Escape/clic-dehors, restauration du focus ---
  const focusable = () => [...box.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')].filter(el => el.offsetParent !== null || el === document.activeElement);
  const onKey = e => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key === 'Tab') {
      const f = focusable(); if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  function close() {
    if (!_helpOpen) return;
    _helpOpen = false;
    document.removeEventListener('keydown', onKey, true);
    ov.classList.add('out'); setTimeout(() => ov.remove(), 160);
    try { if (opener && typeof opener.focus === 'function') opener.focus(); } catch (e) {}
  }
  xb.addEventListener('click', close);
  ov.addEventListener('click', e => { if (e.target === ov) close(); });
  document.addEventListener('keydown', onKey, true);

  select(HELP_BY_KEY[startKey] ? startKey : currentHelpKey(), false);
  // focus initial : le bouton de rubrique actif (dans le trap, annonçable au lecteur d'écran)
  setTimeout(() => { const active = tocBtns[HELP_BY_KEY[startKey] ? startKey : currentHelpKey()]; try { (active || xb).focus(); } catch (e) {} }, 30);
}
// bouton « ? » de l'en-tête : ouvre l'aide de la vue courante.
if ($('#help')) $('#help').addEventListener('click', () => openHelp(currentHelpKey()));
// raccourci clavier « ? » (Shift+/) — ignoré si l'utilisateur tape dans un champ.
document.addEventListener('keydown', e => {
  if (e.key !== '?' || e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target, tag = t && t.tagName;
  if (t && (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable)) return;
  if (document.body.classList.contains('gated')) return; // pas d'aide shell derrière le portail de login
  e.preventDefault(); openHelp(currentHelpKey());
});

// =====================================================================================
//  zoom temporel + infobulle de graphe (porté de Plume)
// =====================================================================================
