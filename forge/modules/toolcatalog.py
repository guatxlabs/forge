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
        argv_template=("-silent", "-host", "{target_host}"),
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
        argv_template=("--silent", "-u", "{target_url}", ("-w", "{param:wordlist}")),
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
                       ("-p", "{param:param}")),
        cwe="CWE-79", mitre="T1059", phase="access", capability="active", attck_tactic="Execution",
        depends_on=("recon.js_endpoints",), parser="regex", parser_regex=r"(?m)^\[POC\].*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False,
        description="Scanner XSS (dalfox) — POC de reflet/DOM signalés (reported_by_tool ; PROUVER via oracle)."),

    # --- Exploitation gouvernée — GATÉE par le plancher opt-in (exploit=True -> le ROE exige allow_exploit) ---
    ToolSpec(
        kind="sqli.sqlmap", vuln_class="SQLi", binary="sqlmap",
        argv_template=("-u", "{target_url}", "--batch",
                       ("--level", "{param:level:1}"), ("--risk", "{param:risk:1}")),
        cwe="CWE-89", mitre="T1190", phase="exploit", capability="exploit", attck_tactic="Initial Access",
        exploit=True, depends_on=("recon.js_endpoints",),
        parser="regex", parser_regex=r"(?im)^.*(Parameter: .*|.* is vulnerable|back-end DBMS: .*)$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        description="Exploitation SQLi (sqlmap) — GATÉE par le plancher exploit (allow_exploit). Hits reported_by_tool."),
]

# Self-registering : FOLD chaque spec dans techniques.py + @register (idempotent au ré-import).
REGISTERED = [register_spec(_spec) for _spec in CATALOG_SPECS]
