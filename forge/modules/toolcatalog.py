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
from .toolspec import ToolSpec, register_spec, FlagAllowlistMixin

# Champ de schéma PARTAGÉ : les extra_args libres (drapeaux) — bornés par la `flag_allowlist` du spec
# (tout flag hors liste est REFUSÉ fail-closed). Type `list` -> la console envoie une liste de tokens
# (jamais une chaîne shell-splittée). Réutilisé par CHAQUE outil pour donner un échappatoire power-user SÛR.
# SOURCE UNIQUE : le descripteur est POSSÉDÉ par `FlagAllowlistMixin.extra_args_param()` (toolspec.py) —
# on route à travers lui au lieu de RE-DÉCLARER le dict ici (dédup ; un seul point à faire évoluer).
_EXTRA = FlagAllowlistMixin.extra_args_param()

# --- Découverte de surface — chaque hit est un ASSET découvert (attribué + re-validé scope fail-closed) ---
# NOTE SCHÉMA : un knob n'a d'EFFET que s'il est référencé dans `argv_template` via un GROUPE optionnel
# `("-flag", "{param:NAME}")` (tout-ou-rien : abandonné si le param est absent -> défaut BYTE-IDENTIQUE).
# `params_schema` DÉCRIT ces knobs pour l'UI ; `{args}` EXPAND les extra_args allowlistés. Les toggles
# booléens (bare flags : -jc, --mining-dom, -p, -j…) NE sont PAS des champs de valeur (risque d'injection
# d'un flag arbitraire via une valeur non validée) : ils vivent dans la `flag_allowlist` (extra_args, ENFORCÉE).
CATALOG_SPECS = [
    ToolSpec(
        kind="recon.subfinder", vuln_class="Recon", binary="subfinder",
        argv_template=("-silent", "-d", "{target_host}", ("-sources", "{param:sources}"),
                       ("-rl", "{param:rate}"), ("-timeout", "{param:timeout}"),
                       ("-max-time", "{param:max_time}"), "{args}"),
        mitre="T1590", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="projectdiscovery/subfinder", parser="lines",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "sources", "type": "text", "label": "sources (-sources, ex crtsh,virustotal)", "flag": "-sources"},
            {"name": "rate", "type": "number", "label": "rate-limit (-rl req/s)", "flag": "-rl"},
            {"name": "timeout", "type": "number", "label": "timeout par source (-timeout s)", "flag": "-timeout"},
            {"name": "max_time", "type": "number", "label": "durée max (-max-time min)", "flag": "-max-time"},
            _EXTRA),
        flag_allowlist=("-all", "-recursive", "-nW", "-sources", "-rl", "-timeout", "-max-time", "-silent"),
        description="Énumération PASSIVE de sous-domaines (subfinder) — assets découverts re-validés scope."),
    ToolSpec(
        kind="recon.amass", vuln_class="Recon", binary="amass",
        argv_template=("enum", "-passive", "-norecursive", "-d", "{target_host}",
                       ("-timeout", "{param:timeout}"), ("-max-depth", "{param:max_depth}"), "{args}"),
        mitre="T1590", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=(), parser="lines", hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "timeout", "type": "number", "label": "timeout (-timeout min)", "flag": "-timeout"},
            {"name": "max_depth", "type": "number", "label": "profondeur max (-max-depth)", "flag": "-max-depth"},
            _EXTRA),
        flag_allowlist=("-passive", "-norecursive", "-timeout", "-max-depth", "-rqps", "-nolocaldb"),
        # amass v4 `enum` DÉMARRE un daemon `amass engine` DÉTACHÉ (pprof exposé sur :6060) qui SURVIT à la
        # fin de l'enum et échappe au reap par groupe de processus -> reap_daemon=True : run sous HOME privé
        # + marqueur unique, le moteur fuité est terminé de façon ciblée après l'exécution (cf. _daemon_reap).
        reap_daemon=True,
        description="Énumération de sous-domaines (OWASP amass, mode passif) — assets re-validés scope."),
    ToolSpec(
        kind="recon.dnsx", vuln_class="Recon", binary="dnsx",
        argv_template=("-silent", "-a", "-resp", "-d", "{target_host}", ("-rl", "{param:rate}"),
                       ("-t", "{param:threads}"), ("-retry", "{param:retries}"), "{args}"),
        mitre="T1590.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.subdomains",), docker_image="projectdiscovery/dnsx", parser="lines",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "rate", "type": "number", "label": "rate-limit (-rl req/s)", "flag": "-rl"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            {"name": "retries", "type": "number", "label": "retries (-retry)", "flag": "-retry"},
            _EXTRA),
        flag_allowlist=("-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-ptr", "-soa", "-resp",
                        "-resp-only", "-rl", "-t", "-retry", "-silent"),
        description="Résolution/énumération DNS (dnsx) — enregistrements A/hosts, assets re-validés scope."),
    ToolSpec(
        kind="recon.naabu", vuln_class="PortScan", binary="naabu",
        argv_template=("-silent", "-host", "{target_host}", ("-p", "{param:ports}"),
                       ("-top-ports", "{param:top_ports}"), ("-rate", "{param:rate}"),
                       ("-c", "{param:concurrency}"), ("-retries", "{param:retries}"), "{args}"),
        mitre="T1046", phase="recon", capability="active", attck_tactic="Discovery",
        depends_on=(), docker_image="projectdiscovery/naabu", parser="lines",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "ports", "type": "text", "label": "ports (-p, ex 80,443 ou 1-1000)", "flag": "-p"},
            {"name": "top_ports", "type": "number", "label": "top-ports (-top-ports N)", "flag": "-top-ports"},
            {"name": "rate", "type": "number", "label": "rate (-rate paquets/s)", "flag": "-rate"},
            {"name": "concurrency", "type": "number", "label": "concurrence (-c)", "flag": "-c"},
            {"name": "retries", "type": "number", "label": "retries (-retries)", "flag": "-retries"},
            _EXTRA),
        flag_allowlist=("-p", "-top-ports", "-rate", "-c", "-retries", "-timeout", "-warm-up-time",
                        "-silent", "-Pn", "-sn", "-scan-all-ips"),
        # DÉCOUVERTE DE SERVICE : chaque port ouvert HTTP-confirmé devient une cible CHAÎNABLE (host:port
        # + marqueur) que le cerveau scanne (fingerprint/oracles/scanners de contenu) — comme recon.nmap.
        emit_service_discovery=True,
        description="Scan de ports rapide (naabu) — host:port ouverts, re-validés scope (jamais hors périmètre). "
                    "Les ports HTTP-confirmés deviennent des cibles web chaînables (découverte de service)."),
    ToolSpec(
        kind="recon.katana", vuln_class="Recon", binary="katana",
        argv_template=("-silent", "-u", "{target_url}", ("-d", "{param:depth}"), ("-rl", "{param:rate}"),
                       ("-c", "{param:concurrency}"), ("-ct", "{param:crawl_duration}"), "{args}"),
        mitre="T1594", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), docker_image="projectdiscovery/katana", parser="lines",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "depth", "type": "number", "label": "profondeur de crawl (-d)", "flag": "-d"},
            {"name": "rate", "type": "number", "label": "rate-limit (-rl req/s)", "flag": "-rl"},
            {"name": "concurrency", "type": "number", "label": "concurrence (-c)", "flag": "-c"},
            {"name": "crawl_duration", "type": "text", "label": "durée max crawl (-ct, ex 5m)", "flag": "-ct"},
            _EXTRA),
        flag_allowlist=("-jc", "-jsl", "-d", "-rl", "-c", "-p", "-ct", "-kf", "-silent",
                        "-xhr-extraction", "-iqp"),
        # DÉCOUVERTE D'ENDPOINT : chaque URL crawlée in-scope devient une cible CHAÎNABLE (URL +
        # DISCOVERY_ENDPOINT_MARKER) que le cerveau branche aux oracles à injection (paramètre de query ->
        # sonde RÉELLE au lieu de « config manquante ») — au lieu d'un simple finding texte jamais vérifié.
        emit_endpoint_discovery=True,
        description="Crawler d'endpoints (katana) — URLs découvertes, re-validées scope fail-closed, émises "
                    "comme endpoints CHAÎNABLES (-> oracles à injection). js-crawl (-jc)/known-files (-kf) allowlistés."),
    ToolSpec(
        kind="recon.gau", vuln_class="Recon", binary="gau",
        argv_template=("--subs", ("--threads", "{param:threads}"), ("--providers", "{param:providers}"),
                       ("--blacklist", "{param:blacklist}"), ("--from", "{param:from_date}"),
                       ("--to", "{param:to_date}"), "{args}", "{target_host}"),
        mitre="T1596", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), parser="lines", hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "threads", "type": "number", "label": "threads (--threads)", "flag": "--threads"},
            {"name": "providers", "type": "text", "label": "providers (--providers, ex wayback,commoncrawl)", "flag": "--providers"},
            {"name": "blacklist", "type": "text", "label": "extensions exclues (--blacklist, ex png,jpg)", "flag": "--blacklist"},
            {"name": "from_date", "type": "text", "label": "depuis (--from, ex YYYYMM)", "flag": "--from"},
            {"name": "to_date", "type": "text", "label": "jusqu'à (--to, ex YYYYMM)", "flag": "--to"},
            _EXTRA),
        flag_allowlist=("--subs", "--threads", "--providers", "--blacklist", "--from", "--to",
                        "--fc", "--mc", "--fp", "--retries", "--timeout"),
        # SKIP CIBLE IP-LITTÉRALE : les archives (Wayback/CommonCrawl) sont indexées par NOM de domaine —
        # une IP nue n'a aucune archive utile (que du bruit) -> skip propre, aucun processus lancé.
        skip_bare_ip=True,
        # DÉCOUVERTE D'ENDPOINT : les URLs d'archive in-scope deviennent des endpoints CHAÎNABLES (-> oracles
        # à injection) au lieu de simples findings texte — les URLs d'archive portent souvent `?param=` legacy.
        emit_endpoint_discovery=True,
        description="URLs d'archive (getallurls/gau : Wayback/CommonCrawl) — assets historiques re-validés scope, "
                    "émis comme endpoints CHAÎNABLES (-> oracles à injection). Skip propre sur cible IP littérale."),
    ToolSpec(
        kind="recon.gospider", vuln_class="Recon", binary="gospider",
        argv_template=("-q", "-s", "{target_url}", ("-d", "{param:depth}"), ("-c", "{param:concurrency}"),
                       ("-t", "{param:threads}"), ("-k", "{param:delay}"), ("-m", "{param:timeout}"), "{args}"),
        mitre="T1594", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"https?://\S+",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "depth", "type": "number", "label": "profondeur (-d)", "flag": "-d"},
            {"name": "concurrency", "type": "number", "label": "concurrence sites (-c)", "flag": "-c"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            {"name": "delay", "type": "number", "label": "délai entre req (-k s)", "flag": "-k"},
            {"name": "timeout", "type": "number", "label": "timeout req (-m s)", "flag": "-m"},
            _EXTRA),
        flag_allowlist=("-d", "-c", "-t", "-k", "-K", "-m", "-a", "-w", "-r", "--js",
                        "--blacklist", "--whitelist", "-L", "-q", "-s"),
        # DÉCOUVERTE D'ENDPOINT : URLs crawlées in-scope -> endpoints CHAÎNABLES (-> oracles à injection).
        emit_endpoint_discovery=True,
        description="Crawler web (gospider) — URLs découvertes, re-validées scope fail-closed, émises comme "
                    "endpoints CHAÎNABLES (-> oracles à injection)."),
    ToolSpec(
        kind="recon.feroxbuster", vuln_class="ContentDiscovery", binary="feroxbuster",
        argv_template=("--silent", "-u", "{target_url}", ("-w", "{param:wordlist}"),
                       ("--rate-limit", "{param:rate}"), ("-t", "{param:threads}"),
                       ("-d", "{param:depth}"), ("-x", "{param:extensions}"),
                       ("-s", "{param:status_codes}"), ("--scan-limit", "{param:scan_limit}"), "{args}"),
        mitre="T1595.003", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"https?://\S+",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "wordlist", "type": "text", "label": "wordlist (-w, chemin)", "flag": "-w"},
            {"name": "rate", "type": "number", "label": "rate-limit (--rate-limit req/s)", "flag": "--rate-limit"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            {"name": "depth", "type": "number", "label": "profondeur récursion (-d)", "flag": "-d"},
            {"name": "extensions", "type": "text", "label": "extensions (-x, ex php,txt)", "flag": "-x"},
            {"name": "status_codes", "type": "text", "label": "codes acceptés (-s, ex 200,301)", "flag": "-s"},
            {"name": "scan_limit", "type": "number", "label": "scans concurrents (--scan-limit)", "flag": "--scan-limit"},
            _EXTRA),
        flag_allowlist=("-w", "-t", "-d", "-x", "-s", "-C", "-T", "--rate-limit", "--scan-limit",
                        "--silent", "-k", "-n", "-r", "-L"),
        description="Découverte de contenu/routes (feroxbuster) — chemins trouvés, re-validés scope. Wordlist optionnelle via params.wordlist."),

    # --- Fingerprint / détection — rapportent SUR la cible (pas d'asset découvert) ---
    ToolSpec(
        kind="recon.whatweb", vuln_class="TechFingerprint", binary="whatweb",
        argv_template=("--no-errors", "-a", "3", "{target_url}", ("--max-threads", "{param:max_threads}"),
                       ("--open-timeout", "{param:open_timeout}"), ("--read-timeout", "{param:read_timeout}"),
                       "{args}"),
        mitre="T1592.002", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="lines", hit_status="tested", severity="INFO",
        hit_is_asset=False,
        params_schema=(
            {"name": "max_threads", "type": "number", "label": "threads (--max-threads)", "flag": "--max-threads"},
            {"name": "open_timeout", "type": "number", "label": "timeout connexion (--open-timeout s)", "flag": "--open-timeout"},
            {"name": "read_timeout", "type": "number", "label": "timeout lecture (--read-timeout s)", "flag": "--read-timeout"},
            _EXTRA),
        flag_allowlist=("--max-threads", "--open-timeout", "--read-timeout", "--follow-redirect",
                        "--no-errors", "--wait"),
        description="Fingerprint de technologies web (whatweb) — bannières/CMS/frameworks sur la cible."),
    ToolSpec(
        kind="recon.wafw00f", vuln_class="WAFDetect", binary="wafw00f",
        argv_template=("-a", "{target_url}", ("-t", "{param:test}"), "{args}"),
        mitre="T1590", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex",
        parser_regex=r"(?im)^.*is behind .*$|^.*seems to be behind.*$|^.*No WAF detected.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        params_schema=(
            {"name": "test", "type": "text", "label": "tester un WAF précis (-t, ex Cloudflare)", "flag": "-t"},
            _EXTRA),
        flag_allowlist=("-a", "-v", "-r", "-t", "-n"),
        description="Détection de WAF/CDN (wafw00f) — identifie le pare-feu applicatif devant la cible."),

    # --- Scanners de faiblesses — rapportent SUR la cible (reported_by_tool, jamais vulnerable) ---
    ToolSpec(
        kind="web.nikto", vuln_class="Scanner", binary="nikto",
        argv_template=("-nointeractive", "-ask", "no", "-host", "{target_url}",
                       ("-Tuning", "{param:tuning}"), ("-timeout", "{param:timeout}"),
                       ("-maxtime", "{param:maxtime}"), ("-port", "{param:port}"), "{args}"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"(?m)^\+ .*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        params_schema=(
            {"name": "tuning", "type": "text", "label": "tuning tests (-Tuning, ex 123bde)", "flag": "-Tuning"},
            {"name": "timeout", "type": "number", "label": "timeout req (-timeout s)", "flag": "-timeout"},
            {"name": "maxtime", "type": "text", "label": "durée max (-maxtime, ex 1h ou 3600s)", "flag": "-maxtime"},
            {"name": "port", "type": "number", "label": "port (-port)", "flag": "-port"},
            _EXTRA),
        flag_allowlist=("-Tuning", "-timeout", "-maxtime", "-Plugins", "-port", "-useragent",
                        "-nossl", "-ssl", "-nointeractive", "-Display", "-D"),
        description="Scanner de serveur web (nikto) — misconfigs/fichiers exposés signalés (reported_by_tool)."),
    ToolSpec(
        kind="web.wpscan", vuln_class="CMSScan", binary="wpscan",
        argv_template=("--no-banner", "--url", "{target_url}", ("--api-token", "{param:wpscan_token}"),
                       ("--enumerate", "{param:enumerate}"), ("--plugins-detection", "{param:plugins_detection}"),
                       ("--throttle", "{param:rate_delay_ms}"), ("--max-threads", "{param:max_threads}"),
                       ("--request-timeout", "{param:timeout}"), "{args}"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"(?m)^\[!\].*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        params_schema=(
            {"name": "enumerate", "type": "text", "label": "énumération (--enumerate, ex vp,vt,u)", "flag": "--enumerate"},
            {"name": "plugins_detection", "type": "select", "label": "détection plugins (--plugins-detection)",
             "flag": "--plugins-detection", "allowed": ["passive", "aggressive", "mixed"]},
            {"name": "max_threads", "type": "number", "label": "threads (--max-threads)", "flag": "--max-threads"},
            {"name": "timeout", "type": "number", "label": "timeout req (--request-timeout s)", "flag": "--request-timeout"},
            _EXTRA),
        flag_allowlist=("--enumerate", "--plugins-detection", "--plugins-version-detection",
                        "--detection-mode", "--throttle", "--max-threads", "--request-timeout",
                        "--random-user-agent", "--no-banner", "--force", "--disable-tls-checks"),
        description="Scanner WordPress (wpscan) — plugins/thèmes/vulns signalés (reported_by_tool). Token API optionnel via params.wpscan_token."),
    ToolSpec(
        kind="web.testssl", vuln_class="TLS", binary="testssl.sh", tool_name="testssl",
        argv_template=("--quiet", "--color", "0", ("--severity", "{param:severity}"), "{args}", "{target_host}"),
        cwe="CWE-326", mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="regex",
        parser_regex=r"(?im)^.*(VULNERABLE|NOT ok|offered \(NOT ok\)|WEAK).*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        params_schema=(
            {"name": "severity", "type": "select", "label": "sévérité min rapportée (--severity)",
             "flag": "--severity", "allowed": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
            _EXTRA),
        flag_allowlist=("--severity", "-p", "--protocols", "-s", "-S", "-P", "-U", "-f", "-e",
                        "--fast", "--sneaky", "--quiet", "--warnings", "-4"),
        description="Audit TLS/SSL (testssl.sh) — protocoles/chiffrements faibles et CVE TLS signalés (reported_by_tool). "
                    "protocoles (-p) via extra_args allowlistés."),
    ToolSpec(
        kind="xss.dalfox", vuln_class="XSS", binary="dalfox",
        argv_template=("url", "{target_url}", "--only-poc", "--silence",
                       ("-p", "{param:param}"), ("--delay", "{param:rate_delay_ms}"),
                       ("-w", "{param:worker}"), ("--timeout", "{param:timeout}"), "{args}"),
        cwe="CWE-79", mitre="T1059", phase="access", capability="active", attck_tactic="Execution",
        depends_on=("recon.js_endpoints",), parser="regex", parser_regex=r"(?m)^\[POC\].*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False,
        params_schema=(
            {"name": "param", "type": "text", "label": "paramètre ciblé (-p)", "flag": "-p"},
            {"name": "worker", "type": "number", "label": "workers concurrents (-w)", "flag": "-w"},
            {"name": "timeout", "type": "number", "label": "timeout req (--timeout s)", "flag": "--timeout"},
            _EXTRA),
        flag_allowlist=("-p", "-w", "--delay", "--timeout", "--mining-dict", "--mining-dom",
                        "--skip-mining-dom", "--skip-mining-dict", "--skip-mining-all",
                        "--deep-domxss", "--only-poc", "--silence", "--waf-evasion"),
        description="Scanner XSS (dalfox) — POC de reflet/DOM signalés (reported_by_tool ; PROUVER via oracle). "
                    "mining (--mining-dom/--mining-dict) via extra_args allowlistés."),

    # --- Exploitation gouvernée — GATÉE par le plancher opt-in (exploit=True -> le ROE exige allow_exploit) ---
    ToolSpec(
        kind="sqli.sqlmap", vuln_class="SQLi", binary="sqlmap",
        argv_template=("-u", "{target_url}", "--batch",
                       ("--level", "{param:level:1}"), ("--risk", "{param:risk:1}"),
                       ("--technique", "{param:technique}"), ("--dbms", "{param:dbms}"),
                       ("--delay", "{param:rate_delay_s}"), ("--timeout", "{param:timeout}"),
                       ("--threads", "{param:threads}"), "{args}"),
        cwe="CWE-89", mitre="T1190", phase="exploit", capability="exploit", attck_tactic="Initial Access",
        exploit=True, depends_on=("recon.js_endpoints",),
        parser="regex", parser_regex=r"(?im)^.*(Parameter: .*|.* is vulnerable|back-end DBMS: .*)$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        params_schema=(
            {"name": "level", "type": "select", "label": "niveau de tests (--level)", "flag": "--level",
             "allowed": ["1", "2", "3", "4", "5"], "default": "1"},
            {"name": "risk", "type": "select", "label": "risque (--risk)", "flag": "--risk",
             "allowed": ["1", "2", "3"], "default": "1"},
            {"name": "technique", "type": "text", "label": "techniques (--technique, ex BEU)", "flag": "--technique"},
            {"name": "dbms", "type": "text", "label": "SGBD forcé (--dbms, ex MySQL)", "flag": "--dbms"},
            {"name": "timeout", "type": "number", "label": "timeout req (--timeout s)", "flag": "--timeout"},
            {"name": "threads", "type": "number", "label": "threads (--threads)", "flag": "--threads"},
            _EXTRA),
        # ALLOWLIST CONSERVATRICE : uniquement détection/tuning + bannière SGBD (version). EXCLUS
        # explicitement : --dump/--dump-all/--os-shell/--os-cmd/--sql-shell/--file-read/--file-write/
        # --eval/-r (fichier requête)/--tamper (charge des scripts)/--proxy/--output-dir/--config
        # (exfil de données, RCE, écriture/lecture de fichiers, exfil réseau — au-delà de l'usage gouverné).
        flag_allowlist=("--level", "--risk", "--technique", "--dbms", "--delay", "--timeout",
                        "--threads", "--batch", "--random-agent", "-p", "--banner", "--time-sec",
                        "--retries", "--string", "--not-string", "--code"),
        description="Exploitation SQLi (sqlmap) — GATÉE par le plancher exploit (allow_exploit). Hits reported_by_tool."),

    # --- INTÉGRATIONS EXTERNES GOUVERNÉES SUPPLÉMENTAIRES (recon/scan/OSINT, non-destructif/non-exploit) ---
    # masscan : balayage de ports MASSIF/rapide. COMPLÈTE naabu (asset host:port) par un sweep full-range
    #   RAPPORTÉ SUR la cible (hit_is_asset=False : la sortie humaine commence par « Discovered », pas par
    #   un jeton-asset -> on l'attribue à la cible, pas de faux asset). NON destructif (scan SYN).
    ToolSpec(
        kind="recon.masscan", vuln_class="PortScan", binary="masscan",
        # `-p{param:ports:1-65535}` : la valeur EST attachée au flag (UN token) -> défaut `-p1-65535`
        # BYTE-IDENTIQUE quand `ports` est absent ; `--rate {param:rate:1000}` garde `--rate 1000` par défaut.
        argv_template=("-p{param:ports:1-65535}", "--rate", "{param:rate:1000}", "{args}", "{target_host}"),
        mitre="T1046", phase="recon", capability="active", attck_tactic="Discovery",
        depends_on=(), docker_image="ilyaglow/masscan", parser="regex",
        parser_regex=r"(?im)^Discovered open port \d+/\w+ on \S+.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        params_schema=(
            {"name": "ports", "type": "text", "label": "ports (-p, défaut 1-65535)", "flag": "-p"},
            {"name": "rate", "type": "number", "label": "rate (--rate paquets/s, défaut 1000)", "flag": "--rate", "default": 1000},
            _EXTRA),
        flag_allowlist=("--rate", "--banners", "--ports", "-p", "--retries", "--open-only",
                        "--source-port", "--wait", "--ping"),
        # DÉCOUVERTE DE SERVICE : chaque port ouvert HTTP-confirmé devient une cible CHAÎNABLE (host:port
        # + marqueur) que le cerveau scanne — COMPLÈTE naabu sur toute la plage (-p1-65535).
        emit_service_discovery=True,
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
                       ("--delay", "{param:rate_delay_dur}"), ("-t", "{param:threads}"),
                       ("--timeout", "{param:timeout}"), "{args}"),
        mitre="T1590.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="ghcr.io/oj/gobuster", parser="regex",
        parser_regex=r"(?im)^Found:\s+(\S+)",
        hit_status="tested", severity="INFO",
        params_schema=(
            {"name": "wordlist", "type": "text", "label": "wordlist (-w, chemin)", "flag": "-w"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            {"name": "timeout", "type": "text", "label": "timeout (--timeout, ex 10s)", "flag": "--timeout"},
            _EXTRA),
        flag_allowlist=("-w", "-t", "--delay", "--timeout", "-i", "-c", "--wildcard", "-q",
                        "--no-color", "-r"),
        description="Énumération DNS de sous-domaines (gobuster mode dns, -q) — COMPLÈTE feroxbuster "
                    "(découverte de contenu) ; assets re-validés scope. Wordlist FOURNIE PAR "
                    "L'UTILISATEUR via params.wordlist (convention : SecLists/Discovery/DNS/"
                    "subdomains-top1million-5000.txt). Image docker ghcr.io/oj/gobuster (à confirmer)."),
    # theHarvester : OSINT PASSIF (sources publiques -b all) -> emails + sous-domaines. hit_is_asset=False :
    #   un email n'est PAS un asset scannable (une re-validation scope le supprimerait) -> on RAPPORTE le
    #   renseignement SUR le domaine cible. capability=passive (pas de trafic vers la cible).
    ToolSpec(
        kind="recon.theharvester", vuln_class="OSINT", binary="theHarvester",
        # `{param:sources:all}` porte le défaut `all` -> `-b all` BYTE-IDENTIQUE quand `sources` est absent.
        argv_template=("-d", "{target_host}", ("-b", "{param:sources:all}"), ("-l", "{param:limit}"), "{args}"),
        mitre="T1589", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="laramies/theharvester", parser="regex",
        parser_regex=r"(?im)^\s*([\w.+-]+@[\w.-]+\.\w{2,}|(?:[a-z0-9_-]+\.)+[a-z]{2,})(?::[\d.]+)?\s*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        params_schema=(
            {"name": "sources", "type": "text", "label": "sources (-b, défaut all)", "flag": "-b", "default": "all"},
            {"name": "limit", "type": "number", "label": "nb résultats max (-l)", "flag": "-l"},
            _EXTRA),
        flag_allowlist=("-b", "-l", "-s", "-g", "-n", "-c", "-r", "-t"),
        description="OSINT PASSIF emails/sous-domaines (theHarvester, -b all sources publiques) — "
                    "renseignement RAPPORTÉ sur le domaine cible (hit_is_asset=False). "
                    "Image docker laramies/theharvester (officielle de l'auteur)."),
    # wfuzz : fuzzing de contenu/paramètres (mot-clé FUZZ dans l'URL, 404 masqués). hit_is_asset=False :
    #   les lignes de résultat (ID:code…) ne sont pas des assets propres -> rapportées SUR la cible.
    #   phase=recon/capability=active — cohérent avec feroxbuster (découverte). Wordlist FOURNIE PAR
    #   L'UTILISATEUR (groupe optionnel) — pas de chemin en dur. NON-exploit, NON-destructif.
    ToolSpec(
        kind="fuzz.wfuzz", vuln_class="Fuzzing", binary="wfuzz",
        # `{param:hide_codes:404}` porte le défaut 404 -> `--hc 404` BYTE-IDENTIQUE quand `hide_codes` absent.
        argv_template=(("--hc", "{param:hide_codes:404}"), ("-w", "{param:wordlist}"),
                       ("-s", "{param:rate_delay_s}"), ("-t", "{param:threads}"),
                       ("--sc", "{param:show_codes}"), "{args}", "-u", "{target_url}/FUZZ"),
        mitre="T1595", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), docker_image="ghcr.io/xmendez/wfuzz", parser="regex",
        parser_regex=r"(?im)^\d{6,}:\s+\d+\s+.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        params_schema=(
            {"name": "wordlist", "type": "text", "label": "wordlist (-w, chemin)", "flag": "-w"},
            {"name": "hide_codes", "type": "text", "label": "codes masqués (--hc, défaut 404)", "flag": "--hc", "default": "404"},
            {"name": "show_codes", "type": "text", "label": "codes affichés (--sc, ex 200,301)", "flag": "--sc"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            _EXTRA),
        flag_allowlist=("-w", "--hc", "--sc", "--hl", "--sl", "--hw", "--sw", "--hh", "--sh",
                        "-t", "-z", "-d", "--follow", "-s"),
        description="Fuzzing de contenu/paramètres web (wfuzz, mot-clé FUZZ, 404 masqués --hc 404) — "
                    "réponses non-404 RAPPORTÉES sur la cible (non-exploit). Wordlist FOURNIE PAR "
                    "L'UTILISATEUR via params.wordlist. Image docker ghcr.io/xmendez/wfuzz (à confirmer)."),
    # ZAP baseline : scan web PASSIF (spider + règles PASSIVES, AUCUNE attaque active -> pas d'-a). Alertes
    #   RAPPORTÉES sur la cible (hit_is_asset=False). L'entrypoint de l'image ZAP n'est PAS le script ->
    #   « zap-baseline.py » est le 1er token d'argv (usage docker standard : `docker run IMG zap-baseline.py
    #   -t URL`) + prefer_docker=True. NON-exploit, NON-destructif.
    ToolSpec(
        kind="web.zap_baseline", vuln_class="WebScan", binary="zap-baseline.py", tool_name="zap-baseline",
        argv_template=("zap-baseline.py", "-t", "{target_url}", "-I", ("-m", "{param:spider_minutes}"),
                       ("-T", "{param:max_minutes}"), ("-D", "{param:delay}"), "{args}"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), docker_image="zaproxy/zap-stable", prefer_docker=True,
        parser="regex", parser_regex=r"(?im)^(?:WARN|FAIL)-(?:NEW|INPROG):.*\[\d+\].*x \d+.*$",
        hit_status="tested", severity="INFO", hit_is_asset=False, exploit=False, destructive=False,
        timeout=600,
        params_schema=(
            {"name": "spider_minutes", "type": "number", "label": "durée spider (-m min)", "flag": "-m"},
            {"name": "max_minutes", "type": "number", "label": "durée max scan (-T min)", "flag": "-T"},
            {"name": "delay", "type": "number", "label": "délai entre req (-D s)", "flag": "-D"},
            _EXTRA),
        # ajax spider (-j) via extra_args allowlisté. EXCLUS : -r/-w/-x/-J (fichiers de rapport),
        # -z (options ZAP arbitraires), -n/-u/-c (fichiers de contexte/config lus).
        flag_allowlist=("-m", "-T", "-D", "-j", "-a", "-I", "-d", "-i", "-s"),
        description="Scan web BASELINE PASSIF (OWASP ZAP zap-baseline.py -I : spider + règles passives, "
                    "AUCUNE attaque active) — alertes RAPPORTÉES sur la cible. Image docker "
                    "zaproxy/zap-stable ; prefer_docker (entrypoint image != script -> zap-baseline.py "
                    "en 1er token d'argv)."),

    # --- SONDES RÉSEAU GOUVERNÉES (HTTP/DNS) — non-exploit, non-destructif, scope-guardées ---
    # recon.curl : SONDE HTTP bénigne. Forge pilote curl pour SONDER une cible in-scope (statut/headers/
    #   corps) — JAMAIS pour exfiltrer : la réponse va sur STDOUT (aucun `-o`), et l'allowlist n'a AUCUN
    #   drapeau de sortie-fichier (-o/-O/--output), d'upload (-T/-F/--upload-file), de proxy (-x/--proxy),
    #   de config lue (-K/--config), de données POST (-d/--data*) ni de creds (-u). Le loader `dangerous_flag`
    #   refuse aussi ces drapeaux côté voie fichier (défense en profondeur). insecure (-k) / suivi de
    #   redirection (-L) / --connect-timeout : options SÛRES, dispo via extra_args allowlistés.
    ToolSpec(
        kind="recon.curl", vuln_class="HTTPProbe", binary="curl",
        argv_template=("-s", "-i", "-A", "forge", "--max-time", "{param:timeout:15}",
                       "-X", "{param:method:GET}", ("-H", "{param:header}"), "{args}", "{target_url}"),
        mitre="T1595", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.httpx",), parser="lines",
        hit_status="tested", severity="INFO", hit_is_asset=False,
        params_schema=(
            {"name": "method", "type": "select", "label": "méthode HTTP (-X)", "flag": "-X",
             "allowed": ["GET", "HEAD", "POST", "PUT", "OPTIONS"], "default": "GET"},
            {"name": "timeout", "type": "number", "label": "timeout total (--max-time s, défaut 15)",
             "flag": "--max-time", "default": 15},
            {"name": "header", "type": "text", "label": "en-tête de requête (-H, ex 'X-Foo: bar')", "flag": "-H"},
            _EXTRA),
        # ALLOWLIST CONSERVATRICE — SONDE gouvernée uniquement : méthode/en-tête/UA/affichage-headers/
        # timeouts/redirection/insecure. EXCLUS (jamais dans l'allowlist) : -o/-O/--output (écriture
        # fichier), -T/-F/--upload-file (upload/exfil), -K/--config (config lue), -x/--proxy (exfil
        # réseau), -d/--data* (corps POST arbitraire), -u (creds). insecure -k = TLS non vérifié (optionnel).
        flag_allowlist=("-X", "-H", "-A", "-i", "-s", "--max-time", "--connect-timeout", "-L", "-k"),
        description="Sonde HTTP gouvernée (curl -s -i -A forge) — requête bénigne dont la réponse va sur "
                    "STDOUT (headers+corps), JAMAIS d'exfil/écriture-fichier/upload/proxy/POST-data. Méthode "
                    "(GET/HEAD/POST/PUT/OPTIONS), en-tête (-H) et timeout (--max-time) via params ; insecure "
                    "(-k), suivi de redirection (-L) et --connect-timeout via extra_args allowlistés. "
                    "Scope-guardée (cible in-scope), non-exploit / non-destructif."),

    # recon.dig : LOOKUP DNS (dig +short). PASSIF (une requête de résolution), non-exploit, non-destructif.
    #   Le NOM interrogé ({target_host}) est SCOPE-GUARDÉ (cible in-scope, fail-closed). Le RÉSOLVEUR
    #   (@resolver, optionnel) est une infra CHOISIE par l'opérateur (ex 8.8.8.8) : une requête DNS (port 53)
    #   vers un résolveur choisi n'est PAS un fetch/SSRF (aucune URL arbitraire récupérée) — la discipline de
    #   périmètre porte sur le NOM interrogé, pas sur le résolveur. dig utilise des options `+opt` (pas `-opt`) :
    #   elles passent comme tokens NON-drapeaux via {args} (check_extra_args ne les prend pas pour des
    #   drapeaux) ; les drapeaux fichiers `-f` (batch file) et `-k` (clé TSIG) sont ABSENTS de l'allowlist
    #   -> un `-f`/`-k` en extra_args RESSEMBLE à un drapeau, hors allowlist => REFUSÉ fail-closed.
    ToolSpec(
        kind="recon.dig", vuln_class="DNSLookup", binary="dig",
        argv_template=("{param:record_type:A}", "{target_host}", "+short",
                       ("@{param:resolver}",), "{args}"),
        mitre="T1590.002", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), parser="lines", hit_status="tested", severity="INFO", hit_is_asset=False,
        params_schema=(
            {"name": "record_type", "type": "select", "label": "type d'enregistrement (positionnel)",
             "flag": "", "allowed": ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV", "PTR"],
             "default": "A"},
            {"name": "resolver", "type": "text", "label": "résolveur DNS (@resolver, optionnel, ex 8.8.8.8)",
             "flag": "@"},
            _EXTRA),
        # ALLOWLIST = uniquement des options dig `+opt` (options de requête SÛRES). dig ne prend PAS de
        # `-opt` de sortie-fichier ; EXCLUS explicitement : -f (batch file, lecture fichier) et -k (clé
        # TSIG, lecture fichier). Un `-f`/`-k` en extra_args ressemble à un drapeau -> hors allowlist -> REFUSÉ.
        flag_allowlist=("+short", "+noall", "+answer", "+trace", "+nssearch", "+tcp", "+time", "+tries"),
        description="Lookup DNS gouverné (dig +short) — enregistrements du NOM interrogé (scope-guardé). "
                    "Type d'enregistrement via params.record_type (select A/AAAA/MX/TXT/…), résolveur "
                    "optionnel via params.resolver (@srv, infra opérateur, pas un vecteur SSRF). PASSIF, "
                    "non-exploit / non-destructif ; options +opt via extra_args allowlistés (les -f/-k "
                    "fichiers sont refusés fail-closed)."),
]

# Self-registering : FOLD chaque spec dans techniques.py + @register (idempotent au ré-import).
REGISTERED = [register_spec(_spec) for _spec in CATALOG_SPECS]
