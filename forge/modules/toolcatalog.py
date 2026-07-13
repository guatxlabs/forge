# SPDX-License-Identifier: AGPL-3.0-only
"""CATALOGUE d'outils OSS courants PRÉ-WRAPPÉS (specs déclaratifs, self-registering, dégradent si absent).

Chaque entrée est un `ToolSpec` (cf. `toolspec.py`) enregistré via `register_spec` : l'outil apparaît
AUTOMATIQUEMENT au catalogue groupé (`by_vuln_class`), au pipeline, à la sélection par-scope, aux profils
et à `forge modules --json` — SOUS la gouvernance (scope-guard fail-closed, argv fixe no-shell, plancher
exploit, dégradation, proof-oriented). C'est la voie de MIGRATION Trickest/Faraday/reNgine/Osmedeus :
ces outils y sont déjà orchestrés ; Forge les enveloppe À L'IDENTIQUE mais gouvernés.

On n'AJOUTE PAS ce que le cœur couvre déjà nativement (nuclei=`web.nuclei`, httpx=`recon.httpx`,
nmap=`recon.nmap`, secrets/gitleaks/trufflehog=`recon.secrets`) — on ÉTEND. Kinds tous distincts des
natifs (aucune collision). Tous `bug_bounty_eligible=False` (des scanners/outils de recon RAPPORTENT ;
ils ne PROUVENT pas -> `reported_by_tool`/`tested`, jamais `vulnerable`) : cohérent avec `web.nuclei`.

TAXONOMIE — chaque outil mappé à sa `vuln_class` + CWE/ATT&CK :
  Découverte de surface (recon, découvrent des ASSETS re-validés scope) :
    subfinder/amass (subdomains), dnsx (DNS resolve), naabu (ports), katana/gospider (crawl),
    gau (URLs d'archive), feroxbuster (content discovery).
  Fingerprint / détection (recon, rapportent SUR la cible) : whatweb (techno), wafw00f (WAF).
  Scanners (rapportent des faiblesses SUR la cible) : nikto (serveur web), wpscan (WordPress),
    testssl (TLS/SSL), dalfox (XSS, access).
  Exploitation gouvernée (gatée par le plancher opt-in) : sqlmap (SQLi, exploit).

INTÉGRATIONS EXTERNES SUPPLÉMENTAIRES (recon/scan/OSINT, NON-destructif, NON-exploit, proof-oriented) :
  masscan (balayage de ports rapide, PortScan — COMPLÈTE naabu par un sweep full-range rapporté sur
    cible), gobuster mode dns (énumération de sous-domaines, SubdomainEnum — COMPLÈTE feroxbuster qui,
    lui, couvre la découverte de CONTENU), theHarvester (OSINT PASSIF emails/sous-domaines),
    wfuzz (fuzzing de contenu/paramètres web), ZAP baseline (scan web PASSIF spider+règles passives,
    AUCUNE attaque active). Aucun outil de brute-force/cred-cracking (hydra/hashcat/john/medusa) ni C2
    (Cobalt Strike/Sliver/Empire) : ILS COLLISIONNENT avec la philosophie proof-oriented non-brute-force
    de Forge (les premiers) ou exigent un connecteur dédié + décision de politique (les seconds).
"""
from .toolspec import ToolSpec, register_spec

# --- Découverte de surface — chaque hit est un ASSET découvert (attribué + re-validé scope fail-closed) ---
CATALOG_SPECS = [
    ToolSpec(
        kind="recon.subfinder", vuln_class="Recon", binary="subfinder",
        argv_template=("-silent", "-d", "{target_host}"),
        mitre="T1590", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="projectdiscovery/subfinder", parser="lines",
        hit_status="tested", severity="INFO",
        description="Énumération PASSIVE de sous-domaines (subfinder) — assets découverts re-validés scope."),
    ToolSpec(
        kind="recon.amass", vuln_class="Recon", binary="amass",
        argv_template=("enum", "-passive", "-norecursive", "-d", "{target_host}"),
        mitre="T1590", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=(), parser="lines", hit_status="tested", severity="INFO",
        description="Énumération de sous-domaines (OWASP amass, mode passif) — assets re-validés scope."),
    ToolSpec(
        kind="recon.dnsx", vuln_class="Recon", binary="dnsx",
        argv_template=("-silent", "-a", "-resp", "-d", "{target_host}"),
        mitre="T1590.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.subdomains",), docker_image="projectdiscovery/dnsx", parser="lines",
        hit_status="tested", severity="INFO",
        description="Résolution/énumération DNS (dnsx) — enregistrements A/hosts, assets re-validés scope."),
    ToolSpec(
        kind="recon.naabu", vuln_class="PortScan", binary="naabu",
        argv_template=("-silent", "-host", "{target_host}", ("-rate", "{param:rate}")),
        mitre="T1046", phase="recon", capability="active", attck_tactic="Discovery",
        depends_on=(), docker_image="projectdiscovery/naabu", parser="lines",
        hit_status="tested", severity="INFO",
        description="Scan de ports rapide (naabu) — host:port ouverts, re-validés scope (jamais hors périmètre)."),
    ToolSpec(
        kind="recon.katana", vuln_class="Recon", binary="katana",
        argv_template=("-silent", "-u", "{target_url}"),
        mitre="T1594", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), docker_image="projectdiscovery/katana", parser="lines",
        hit_status="tested", severity="INFO",
        description="Crawler d'endpoints (katana) — URLs découvertes, re-validées scope fail-closed."),
    ToolSpec(
        kind="recon.gau", vuln_class="Recon", binary="gau",
        argv_template=("--subs", "{target_host}"),
        mitre="T1596", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), parser="lines", hit_status="tested", severity="INFO",
        description="URLs d'archive (getallurls/gau : Wayback/CommonCrawl) — assets historiques re-validés scope."),
    ToolSpec(
        kind="recon.gospider", vuln_class="Recon", binary="gospider",
        argv_template=("-q", "-s", "{target_url}"),
        mitre="T1594", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"https?://\S+",
        hit_status="tested", severity="INFO",
        description="Crawler web (gospider) — URLs découvertes, re-validées scope fail-closed."),
    ToolSpec(
        kind="recon.feroxbuster", vuln_class="ContentDiscovery", binary="feroxbuster",
        argv_template=("--silent", "-u", "{target_url}", ("-w", "{param:wordlist}"),
                       ("--rate-limit", "{param:rate}")),
        mitre="T1595.003", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"https?://\S+",
        hit_status="tested", severity="INFO",
        description="Découverte de contenu/routes (feroxbuster) — chemins trouvés, re-validés scope. Wordlist optionnelle via params.wordlist."),

    # --- Fingerprint / détection — rapportent SUR la cible (pas d'asset découvert) ---
    ToolSpec(
        kind="recon.whatweb", vuln_class="TechFingerprint", binary="whatweb",
        argv_template=("--no-errors", "-a", "3", "{target_url}"),
        mitre="T1592.002", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="lines", hit_status="tested", severity="INFO",
        hit_is_asset=False,
        description="Fingerprint de technologies web (whatweb) — bannières/CMS/frameworks sur la cible."),
    ToolSpec(
        kind="recon.wafw00f", vuln_class="WAFDetect", binary="wafw00f",
        argv_template=("-a", "{target_url}"),
        mitre="T1590", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex",
        parser_regex=r"(?im)^.*is behind .*$|^.*seems to be behind.*$|^.*No WAF detected.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        description="Détection de WAF/CDN (wafw00f) — identifie le pare-feu applicatif devant la cible."),

    # --- Scanners de faiblesses — rapportent SUR la cible (reported_by_tool, jamais vulnerable) ---
    ToolSpec(
        kind="web.nikto", vuln_class="Scanner", binary="nikto",
        argv_template=("-nointeractive", "-ask", "no", "-host", "{target_url}"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"(?m)^\+ .*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        description="Scanner de serveur web (nikto) — misconfigs/fichiers exposés signalés (reported_by_tool)."),
    ToolSpec(
        kind="web.wpscan", vuln_class="CMSScan", binary="wpscan",
        argv_template=("--no-banner", "--url", "{target_url}", ("--api-token", "{param:wpscan_token}")),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"(?m)^\[!\].*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        description="Scanner WordPress (wpscan) — plugins/thèmes/vulns signalés (reported_by_tool). Token API optionnel via params.wpscan_token."),
    ToolSpec(
        kind="web.testssl", vuln_class="TLS", binary="testssl.sh", tool_name="testssl",
        argv_template=("--quiet", "--color", "0", "{target_host}"),
        cwe="CWE-326", mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex",
        parser_regex=r"(?im)^.*(VULNERABLE|NOT ok|offered \(NOT ok\)|WEAK).*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        description="Audit TLS/SSL (testssl.sh) — protocoles/chiffrements faibles et CVE TLS signalés (reported_by_tool)."),
    ToolSpec(
        kind="xss.dalfox", vuln_class="XSS", binary="dalfox",
        argv_template=("url", "{target_url}", "--only-poc", "--silence",
                       ("-p", "{param:param}"), ("--delay", "{param:rate_delay_ms}")),
        cwe="CWE-79", mitre="T1059", phase="access", capability="active", attck_tactic="Execution",
        depends_on=("recon.js_endpoints",), parser="regex", parser_regex=r"(?m)^\[POC\].*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False,
        description="Scanner XSS (dalfox) — POC de reflet/DOM signalés (reported_by_tool ; PROUVER via oracle)."),

    # --- Exploitation gouvernée — GATÉE par le plancher opt-in (exploit=True -> le ROE exige allow_exploit) ---
    ToolSpec(
        kind="sqli.sqlmap", vuln_class="SQLi", binary="sqlmap",
        argv_template=("-u", "{target_url}", "--batch",
                       ("--level", "{param:level:1}"), ("--risk", "{param:risk:1}"),
                       ("--delay", "{param:rate_delay_s}")),
        cwe="CWE-89", mitre="T1190", phase="exploit", capability="exploit", attck_tactic="Initial Access",
        exploit=True, depends_on=("recon.js_endpoints",),
        parser="regex", parser_regex=r"(?im)^.*(Parameter: .*|.* is vulnerable|back-end DBMS: .*)$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        description="Exploitation SQLi (sqlmap) — GATÉE par le plancher exploit (allow_exploit). Hits reported_by_tool."),

    # --- INTÉGRATIONS EXTERNES GOUVERNÉES SUPPLÉMENTAIRES (recon/scan/OSINT, non-destructif/non-exploit) ---
    # masscan : balayage de ports MASSIF/rapide. COMPLÈTE naabu (asset host:port) par un sweep full-range
    #   RAPPORTÉ SUR la cible (hit_is_asset=False : la sortie humaine commence par « Discovered », pas par
    #   un jeton-asset -> on l'attribue à la cible, pas de faux asset). NON destructif (scan SYN).
    ToolSpec(
        kind="recon.masscan", vuln_class="PortScan", binary="masscan",
        argv_template=("-p1-65535", "--rate", "{param:rate:1000}", "{target_host}"),
        mitre="T1046", phase="recon", capability="active", attck_tactic="Discovery",
        depends_on=(), docker_image="ilyaglow/masscan", parser="regex",
        parser_regex=r"(?im)^Discovered open port \d+/\w+ on \S+.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        description="Balayage de ports rapide (masscan, -p1-65535 --rate 1000) — ports ouverts RAPPORTÉS "
                    "SUR la cible (non destructif, SYN scan). Complète naabu par un sweep full-range. "
                    "Image docker ilyaglow/masscan (Docker Hub, publiée)."),
    # gobuster mode DNS : énumération de SOUS-DOMAINES. On choisit le mode dns (PAS dir) car la découverte
    #   de CONTENU est DÉJÀ couverte par feroxbuster -> gobuster-dns COMPLÈTE (enum sous-domaines). Assets
    #   découverts (phase recon -> hit_is_asset dérivé True) RE-VALIDÉS scope fail-closed. Wordlist FOURNIE
    #   PAR L'UTILISATEUR (groupe optionnel tout-ou-rien) — aucun chemin machine-spécifique en dur.
    ToolSpec(
        kind="recon.gobuster_dns", vuln_class="SubdomainEnum", binary="gobuster",
        argv_template=("dns", "-q", "-d", "{target_host}", ("-w", "{param:wordlist}"),
                       ("--delay", "{param:rate_delay_dur}")),
        mitre="T1590.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="ghcr.io/oj/gobuster", parser="regex",
        parser_regex=r"(?im)^Found:\s+(\S+)",
        hit_status="tested", severity="INFO",
        description="Énumération DNS de sous-domaines (gobuster mode dns, -q) — COMPLÈTE feroxbuster "
                    "(découverte de contenu) ; assets re-validés scope. Wordlist FOURNIE PAR "
                    "L'UTILISATEUR via params.wordlist (convention : SecLists/Discovery/DNS/"
                    "subdomains-top1million-5000.txt). Image docker ghcr.io/oj/gobuster (à confirmer)."),
    # theHarvester : OSINT PASSIF (sources publiques -b all) -> emails + sous-domaines. hit_is_asset=False :
    #   un email n'est PAS un asset scannable (une re-validation scope le supprimerait) -> on RAPPORTE le
    #   renseignement SUR le domaine cible. capability=passive (pas de trafic vers la cible).
    ToolSpec(
        kind="recon.theharvester", vuln_class="OSINT", binary="theHarvester",
        argv_template=("-d", "{target_host}", "-b", "all"),
        mitre="T1589", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="laramies/theharvester", parser="regex",
        parser_regex=r"(?im)^\s*([\w.+-]+@[\w.-]+\.\w{2,}|(?:[a-z0-9_-]+\.)+[a-z]{2,})(?::[\d.]+)?\s*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        description="OSINT PASSIF emails/sous-domaines (theHarvester, -b all sources publiques) — "
                    "renseignement RAPPORTÉ sur le domaine cible (hit_is_asset=False). "
                    "Image docker laramies/theharvester (officielle de l'auteur)."),
    # wfuzz : fuzzing de contenu/paramètres (mot-clé FUZZ dans l'URL, 404 masqués). hit_is_asset=False :
    #   les lignes de résultat (ID:code…) ne sont pas des assets propres -> rapportées SUR la cible.
    #   phase=recon/capability=active — cohérent avec feroxbuster (découverte). Wordlist FOURNIE PAR
    #   L'UTILISATEUR (groupe optionnel) — pas de chemin en dur. NON-exploit, NON-destructif.
    ToolSpec(
        kind="fuzz.wfuzz", vuln_class="Fuzzing", binary="wfuzz",
        argv_template=("--hc", "404", ("-w", "{param:wordlist}"), ("-s", "{param:rate_delay_s}"),
                       "-u", "{target_url}/FUZZ"),
        mitre="T1595", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), docker_image="ghcr.io/xmendez/wfuzz", parser="regex",
        parser_regex=r"(?im)^\d{6,}:\s+\d+\s+.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        description="Fuzzing de contenu/paramètres web (wfuzz, mot-clé FUZZ, 404 masqués --hc 404) — "
                    "réponses non-404 RAPPORTÉES sur la cible (non-exploit). Wordlist FOURNIE PAR "
                    "L'UTILISATEUR via params.wordlist. Image docker ghcr.io/xmendez/wfuzz (à confirmer)."),
    # ZAP baseline : scan web PASSIF (spider + règles PASSIVES, AUCUNE attaque active -> pas d'-a). Alertes
    #   RAPPORTÉES sur la cible (hit_is_asset=False). L'entrypoint de l'image ZAP n'est PAS le script ->
    #   « zap-baseline.py » est le 1er token d'argv (usage docker standard : `docker run IMG zap-baseline.py
    #   -t URL`) + prefer_docker=True. NON-exploit, NON-destructif.
    ToolSpec(
        kind="web.zap_baseline", vuln_class="WebScan", binary="zap-baseline.py", tool_name="zap-baseline",
        argv_template=("zap-baseline.py", "-t", "{target_url}", "-I"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), docker_image="zaproxy/zap-stable", prefer_docker=True,
        parser="regex", parser_regex=r"(?im)^(?:WARN|FAIL)-(?:NEW|INPROG):.*\[\d+\].*x \d+.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False, exploit=False, destructive=False,
        timeout=600,
        description="Scan web BASELINE PASSIF (OWASP ZAP zap-baseline.py -I : spider + règles passives, "
                    "AUCUNE attaque active) — alertes RAPPORTÉES sur la cible. Image docker "
                    "zaproxy/zap-stable ; prefer_docker (entrypoint image != script -> zap-baseline.py "
                    "en 1er token d'argv)."),
]

# Self-registering : FOLD chaque spec dans techniques.py + @register (idempotent au ré-import).
REGISTERED = [register_spec(_spec) for _spec in CATALOG_SPECS]
