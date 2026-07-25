// =====================================================================================
//  SOURCE DE DÉTECTION — composant PARTAGÉ (panneau #admin ET étape 3 du wizard)
//  La source BLUE (SIEM/IDS/pare-feu) est configurable SANS code : `kind` + connexion (endpoint/auth/
//  query) + éditeur de mapping MITRE (règle/signature native -> technique). Le SECRET est WRITE-ONLY :
//  affiché ••• une fois posé (secret_set), jamais re-rendu par le serveur. GET/POST /api/detection/source
//  (admin, ledgerisé) ; test de joignabilité via POST /api/detection/test. Le même composant sert le
//  wizard et l'admin (parité stricte du jeu de champs — exigence de cohérence).
//
//  Composant PUR (aucune dépendance à un autre module app) : c'est ce qui casse le cycle d'imports
//  auth.js ⇄ admin.js — auth.js (wizard) et admin/detection.js importent tous deux ce fichier, plus
//  jamais admin.js.
// =====================================================================================
// Liste FERMÉE des kinds (parité avec DETECTION_KINDS côté console + le registre collecteur Python).
export const DETECTION_KINDS = [
  { value: 'none', label: 'Aucune (standalone) — Forge en autonome' },
  { value: 'plume', label: 'Plume (SOC) — préréglage optionnel' },
  { value: 'generic_http', label: 'HTTP générique (JSON)' },
  { value: 'crowdsec', label: 'CrowdSec (LAPI)' },
  { value: 'elastic', label: 'Elastic (_search)' },
  { value: 'opensearch', label: 'OpenSearch (_search)' },
  { value: 'fortigate_syslog', label: 'FortiGate (syslog)' },
  { value: 'pfsense', label: 'pfSense (filterlog)' },
  { value: 'opnsense', label: 'OPNsense (filterlog)' },
  { value: 'file_jsonl', label: 'Fichier JSONL' },
  { value: 'exec', label: 'Commande (exec)' },
];
export const DET_HTTP_KINDS = new Set(['plume', 'generic_http', 'crowdsec', 'elastic', 'opensearch']);
export const DET_SYSLOG_KINDS = new Set(['fortigate_syslog', 'pfsense', 'opnsense']);
export const DET_TABLE_KINDS = new Set(['generic_http', 'crowdsec', 'elastic', 'opensearch', 'file_jsonl', 'exec']);
export const DET_AUTH_KINDS = new Set(['plume', 'generic_http', 'crowdsec', 'elastic', 'opensearch']);
export const DET_QUERY_KINDS = new Set(['generic_http', 'crowdsec', 'elastic', 'opensearch']);
export const DET_JSON_QUERY_KINDS = new Set(['elastic', 'opensearch']); // query = corps JSON (dict)
// clés de mapping représentables par l'éditeur de lignes (le reste -> éditeur JSON avancé).
export const DET_MAP_SIMPLE_KEYS = new Set(['table', 'field', 'rules', 'records', 'ts']);
// petit constructeur DOM sûr : détail = attrs (value/placeholder/type/...) posés via propriété (jamais innerHTML).
export function detEl(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (attrs) for (const k in attrs) { if (k === 'text') e.textContent = attrs[k]; else e[k] = attrs[k]; }
  return e;
}
export function detField(labelText, control, hint) {
  const l = detEl('label', 'login-f');
  l.appendChild(detEl('span', null, { text: labelText }));
  l.appendChild(control);
  // indice explicatif optionnel : reste dans le label -> se masque/affiche avec lui (refreshVisibility).
  if (hint) l.appendChild(detEl('small', 'det-fhint', { text: hint }));
  return l;
}
// Factory : monte le jeu de champs dans `host` et renvoie un contrôleur { setConfig, getConfig, clearSecret, el }.
export function detectionSourceForm(host) {
  host.classList.add('det-form');
  host.replaceChildren();
  const st = { secretSet: false, secretDirty: false, kind: 'none' };

  const kindSel = detEl('select', 'det-kind');
  DETECTION_KINDS.forEach(k => kindSel.appendChild(detEl('option', null, { value: k.value, text: k.label })));
  host.appendChild(detField('Type de source (kind)', kindSel,
    'La famille de la source BLUE : « Aucune » = autonome (Forge tourne sans SOC). Les autres câblent un SIEM/IDS/pare-feu (Plume, CrowdSec, Elastic, FortiGate, fichier, commande…) — le reste du formulaire s\'adapte au type choisi.'));

  // endpoint / chemin / commande (une seule entrée, ré-étiquetée selon le kind).
  const epInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off' });
  const epLabel = detField('Endpoint', epInput,
    'Où lire les détections : une URL (HTTP), un chemin de fichier (syslog/JSONL) ou une commande (exec). Le libellé s\'ajuste au type de source.');
  host.appendChild(epLabel);

  // --- bloc auth (http kinds) ---
  const authWrap = detEl('div', 'det-block');
  const authSel = detEl('select');
  [['', '— aucune'], ['basic', 'Basic'], ['bearer', 'Bearer'], ['api_key_header', "En-tête d'API"]]
    .forEach(([v, l]) => authSel.appendChild(detEl('option', null, { value: v, text: l })));
  authWrap.appendChild(detField("Type d'authentification", authSel,
    'Comment Forge s\'authentifie auprès de la source : Basic (login:mot de passe), Bearer (jeton porteur) ou En-tête d\'API (clé dans un en-tête nommé). « Aucune » si l\'endpoint est ouvert.'));
  const hdrInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: X-Api-Key' });
  const hdrLabel = detField("Nom de l'en-tête d'API", hdrInput,
    'Uniquement pour « En-tête d\'API » : le nom de l\'en-tête HTTP qui portera le secret (ex : X-Api-Key pour CrowdSec).');
  authWrap.appendChild(hdrLabel);
  const secInput = detEl('input', null, { type: 'password', autocomplete: 'new-password', placeholder: 'secret / token' });
  secInput.addEventListener('input', () => { st.secretDirty = true; });
  authWrap.appendChild(detField('Secret / token (write-only)', secInput,
    'Write-only : envoyé au serveur puis affiché ••• (jamais renvoyé). Laissez vide pour conserver le secret déjà posé ; saisissez une valeur uniquement pour le remplacer.'));
  host.appendChild(authWrap);

  // --- query (http kinds) ---
  const qInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: since={since}' });
  const qLabel = detField('Query', qInput,
    'Filtre côté source : chaîne avec {since} substitué à la fenêtre (HTTP/CrowdSec), ou corps JSON de requête _search (Elastic/OpenSearch).');
  host.appendChild(qLabel);

  // --- mapping MITRE ---
  const mapWrap = detEl('div', 'det-block');
  mapWrap.appendChild(detEl('div', 'det-sub', { text: 'Mapping MITRE — règle/signature native → technique' }));
  const sigInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: scenario' });
  const sigLabel = detField('Champ signature natif', sigInput,
    'Le champ de l\'événement source qui porte la règle/signature native (ex : scenario chez CrowdSec). Les lignes ci-dessous traduisent chaque valeur de ce champ en technique MITRE.');
  mapWrap.appendChild(sigLabel);
  const rowsHost = detEl('div', 'det-rows');
  mapWrap.appendChild(rowsHost);
  const addBtn = detEl('button', 'k-theme det-addrow', { type: 'button', text: '+ ligne' });
  mapWrap.appendChild(addBtn);
  // options mapping fines (records / ts) — kinds http/fichier.
  const recInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: hits.hits' });
  const recLabel = detField('Chemin du tableau (records, optionnel)', recInput,
    'Où trouver le tableau d\'événements dans la réponse JSON (ex : hits.hits pour Elastic). Vide = la racine est déjà un tableau.');
  mapWrap.appendChild(recLabel);
  const tsInput = detEl('input', null, { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'ex: created_at' });
  const tsLabel = detField('Champ horodatage (ts, optionnel)', tsInput,
    'Champ portant l\'heure de l\'alerte — sert à calculer le MTTD (délai tir → détection). Vide = MTTD non mesuré pour cette source.');
  mapWrap.appendChild(tsLabel);
  const advTa = detEl('textarea', null, { rows: 3, spellcheck: false, placeholder: '{"mitre":"_source.threat.technique.id","ts":"@timestamp"}' });
  const advLabel = detField('Mapping avancé (JSON — écrase l’éditeur ci-dessus)', advTa,
    'Pour les cas non couverts par les lignes : un objet JSON de mapping (chemins mitre/ts/records…). S\'il est renseigné, il remplace l\'éditeur de lignes ci-dessus.');
  mapWrap.appendChild(advLabel);
  host.appendChild(mapWrap);

  const hint = detEl('div', 'det-hint muted');
  host.appendChild(hint);

  function addRow(native, technique) {
    const row = detEl('div', 'det-row');
    const a = detEl('input', 'det-row-native', { type: 'text', spellcheck: false, autocomplete: 'off', value: native || '' });
    const b = detEl('input', 'det-row-tech', { type: 'text', spellcheck: false, autocomplete: 'off', placeholder: 'Txxxx', value: technique || '' });
    const rm = detEl('button', 'k-theme danger det-row-rm', { type: 'button', text: '×', title: 'Retirer la ligne' });
    rm.addEventListener('click', () => row.remove());
    row.appendChild(a); row.appendChild(b); row.appendChild(rm);
    rowsHost.appendChild(row);
  }
  addBtn.addEventListener('click', () => addRow('', ''));
  function setRows(rows) { rowsHost.replaceChildren(); (rows || []).forEach(r => addRow(r.native, r.technique)); }
  function collectRows() {
    return [...rowsHost.querySelectorAll('.det-row')].map(r => ({
      native: (r.querySelector('.det-row-native').value || '').trim(),
      technique: (r.querySelector('.det-row-tech').value || '').trim(),
    })).filter(r => r.native && r.technique);
  }

  const HINTS = {
    none: 'Aucune source (autonome / standalone) : Forge fonctionne SANS dépendre d’un SOC. La boucle purple reste en attente (source_reachable:false, aucune métrique inventée). Une source est OPTIONNELLE et ajoutable plus tard dans Administration.',
    plume: 'Préréglage Plume : GET {endpoint}/api/coverage/detections?since=N, Basic auth, mapping identité (aucun mapping requis).',
    generic_http: 'Source JSON : si elle porte déjà un champ `mitre`, aucun mapping ; sinon utilisez le mapping table (signature → technique).',
    crowdsec: 'CrowdSec n’est PAS taggé MITRE : mapping table scénario → technique REQUIS (endpoint LAPI + clé X-Api-Key).',
    elastic: 'Elastic _search : query = corps JSON (dict). Mapping via chemin `mitre` (ex _source.…) ou table + champ.',
    opensearch: 'OpenSearch _search : query = corps JSON (dict). Même dialecte qu’Elastic (hits.hits).',
    fortigate_syslog: 'FortiGate syslog : endpoint = chemin du fichier ; règles regex → technique REQUISES (pas de tag MITRE natif).',
    pfsense: 'pfSense filterlog : endpoint = chemin du fichier ; règles regex → technique REQUISES.',
    opnsense: 'OPNsense filterlog : endpoint = chemin du fichier ; règles regex → technique REQUISES.',
    file_jsonl: 'Fichier JSONL d’événements natifs : endpoint = chemin ; mapping table/champ (ou mitre direct).',
    exec: 'Commande (argv séparés par des espaces) imprimant du JSON sur stdout ; mapping table/champ. Admin de confiance uniquement.',
  };

  function refreshVisibility() {
    const kind = kindSel.value;
    st.kind = kind;
    const syslog = DET_SYSLOG_KINDS.has(kind);
    const isExec = kind === 'exec';
    const isFile = kind === 'file_jsonl';
    // libellé/visibilité de l'entrée connexion.
    if (isExec) { epLabel.querySelector('span').textContent = 'Commande (argv séparés par des espaces)'; epInput.placeholder = 'ex: /opt/soc/pull.sh --json'; }
    else if (syslog || isFile) { epLabel.querySelector('span').textContent = 'Chemin du fichier'; epInput.placeholder = 'ex: /var/log/filterlog'; }
    else { epLabel.querySelector('span').textContent = 'Endpoint (URL)'; epInput.placeholder = 'ex: http://soc.local:8080/api/coverage/detections'; }
    epLabel.hidden = (kind === 'none');
    authWrap.hidden = !DET_AUTH_KINDS.has(kind);
    hdrLabel.hidden = authSel.value !== 'api_key_header';
    qLabel.hidden = !DET_QUERY_KINDS.has(kind);
    qLabel.querySelector('span').textContent = DET_JSON_QUERY_KINDS.has(kind) ? 'Query (corps JSON)' : 'Query (chaîne, {since} substitué)';
    // mapping : masqué pour none et plume (identité) ; sinon visible. `field`/records/ts masqués en syslog.
    const showMap = kind !== 'none' && kind !== 'plume';
    mapWrap.hidden = !showMap;
    sigLabel.hidden = syslog || !DET_TABLE_KINDS.has(kind);
    recLabel.hidden = syslog || !showMap;
    tsLabel.hidden = syslog || !showMap;
    mapWrap.querySelector('.det-sub').textContent = syslog
      ? 'Mapping MITRE — regex (ligne syslog) → technique'
      : 'Mapping MITRE — signature native → technique';
    hint.textContent = HINTS[kind] || '';
  }
  kindSel.addEventListener('change', refreshVisibility);
  authSel.addEventListener('change', () => { hdrLabel.hidden = authSel.value !== 'api_key_header'; });

  function setConfig(cfg, secretSet) {
    cfg = (cfg && typeof cfg === 'object') ? cfg : {};
    kindSel.value = DETECTION_KINDS.some(k => k.value === cfg.kind) ? cfg.kind : 'none';
    // connexion
    if (cfg.kind === 'exec') epInput.value = Array.isArray(cfg.cmd) ? cfg.cmd.join(' ') : (Array.isArray(cfg.argv) ? cfg.argv.join(' ') : (cfg.cmd || ''));
    else epInput.value = cfg.endpoint || cfg.path || '';
    // auth
    const auth = (cfg.auth && typeof cfg.auth === 'object') ? cfg.auth : {};
    authSel.value = ['basic', 'bearer', 'api_key_header'].includes(auth.type || cfg.auth_type) ? (auth.type || cfg.auth_type) : '';
    hdrInput.value = auth.header || '';
    secInput.value = '';
    st.secretSet = !!secretSet; st.secretDirty = false;
    secInput.placeholder = secretSet ? '•••••••• (défini — laisser vide pour conserver)' : 'secret / token';
    // query
    const q = cfg.query;
    qInput.value = (typeof q === 'string') ? q : (q && typeof q === 'object' ? JSON.stringify(q) : '');
    // mapping
    const m = (cfg.mapping && typeof cfg.mapping === 'object') ? cfg.mapping : {};
    sigInput.value = m.field || '';
    recInput.value = m.records || '';
    tsInput.value = m.ts || '';
    const unrepresentable = Object.keys(m).some(k => !DET_MAP_SIMPLE_KEYS.has(k));
    if (unrepresentable) { advTa.value = JSON.stringify(m, null, 2); setRows([]); }
    else {
      advTa.value = '';
      if (Array.isArray(m.rules)) setRows(m.rules.filter(r => r && r.match).map(r => ({ native: r.match, technique: r.mitre || '' })));
      else if (m.table && typeof m.table === 'object') setRows(Object.entries(m.table).map(([k, v]) => ({ native: k, technique: String(v) })));
      else setRows([]);
    }
    refreshVisibility();
  }

  // Renvoie { config, keepSecret, error }. error non nul -> le hôte (save/test) affiche un toast et n'envoie rien.
  function getConfig() {
    const kind = kindSel.value;
    if (kind === 'none') return { config: { kind: 'none' }, keepSecret: false, error: null };
    const config = { kind };
    const ep = (epInput.value || '').trim();
    if (kind === 'exec') { if (ep) config.cmd = ep.split(/\s+/).filter(Boolean); }
    else if (ep) config.endpoint = ep;
    let keepSecret = false;
    if (DET_AUTH_KINDS.has(kind)) {
      const at = authSel.value;
      if (at) {
        const auth = { type: at };
        if (at === 'api_key_header' && (hdrInput.value || '').trim()) auth.header = hdrInput.value.trim();
        if (st.secretDirty && secInput.value) auth.secret = secInput.value;
        else if (st.secretSet && !st.secretDirty) keepSecret = true; // secret write-only conservé
        config.auth = auth;
      }
    }
    if (DET_QUERY_KINDS.has(kind)) {
      const qv = (qInput.value || '').trim();
      if (qv) {
        if (DET_JSON_QUERY_KINDS.has(kind)) {
          try { config.query = JSON.parse(qv); } catch (e) { return { config: null, keepSecret: false, error: 'Query (corps JSON) invalide : ' + e.message }; }
        } else config.query = qv;
      }
    }
    // mapping : JSON avancé prioritaire, sinon lignes.
    const adv = (advTa.value || '').trim();
    if (adv) {
      let parsed;
      try { parsed = JSON.parse(adv); } catch (e) { return { config: null, keepSecret: false, error: 'Mapping avancé (JSON) invalide : ' + e.message }; }
      if (parsed && typeof parsed === 'object') config.mapping = parsed;
    } else if (kind !== 'plume') {
      const mapping = {};
      const rows = collectRows();
      if (DET_SYSLOG_KINDS.has(kind)) { if (rows.length) mapping.rules = rows.map(r => ({ match: r.native, mitre: r.technique })); }
      else if (rows.length) {
        mapping.table = {}; rows.forEach(r => { mapping.table[r.native] = r.technique; });
        const fld = (sigInput.value || '').trim(); if (fld) mapping.field = fld;
      }
      const rec = (recInput.value || '').trim(); if (rec && !DET_SYSLOG_KINDS.has(kind)) mapping.records = rec;
      const ts = (tsInput.value || '').trim(); if (ts && !DET_SYSLOG_KINDS.has(kind)) mapping.ts = ts;
      if (Object.keys(mapping).length) config.mapping = mapping;
    }
    return { config, keepSecret, error: null };
  }
  function clearSecret() { secInput.value = ''; st.secretDirty = false; }

  refreshVisibility();
  return { el: host, setConfig, getConfig, clearSecret, kind: () => kindSel.value };
}
