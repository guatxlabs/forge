# SPDX-License-Identifier: AGPL-3.0-or-later
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
    subfinder/amass (subdomains), dnsx (enum DNS par wordlist), naabu (ports), katana (crawl),
    gau (URLs d'archive), feroxbuster (content discovery).
  Fingerprint / détection (recon, rapportent SUR la cible) : whatweb (techno), wafw00f (WAF).
  Scanners (rapportent des faiblesses SUR la cible) : nikto (serveur web), wpscan (WordPress),
    testssl (TLS/SSL), dalfox (XSS, access).
  Exploitation gouvernée (gatée par le plancher opt-in) : sqlmap (SQLi, exploit).

  (gospider a été RETIRÉ — cf. la note de retrait plus bas ; `katana` couvre le crawl, avec image.)

INTÉGRATIONS EXTERNES SUPPLÉMENTAIRES (recon/scan, NON-destructif, NON-exploit, proof-oriented) :
  gobuster mode dns (énumération de sous-domaines, SubdomainEnum — COMPLÈTE feroxbuster qui, lui,
    couvre la découverte de CONTENU), wfuzz (fuzzing de contenu/paramètres web), ZAP baseline (scan
    web PASSIF spider+règles passives, AUCUNE attaque active). Aucun outil de brute-force/
    cred-cracking (hydra/hashcat/john/medusa) ni C2 (Cobalt Strike/Sliver/Empire) : ILS COLLISIONNENT
    avec la philosophie proof-oriented non-brute-force de Forge (les premiers) ou exigent un connecteur
    dédié + décision de politique (les seconds).

CE QU'UN CATALOGUE DOIT PROUVER — L'INVOCATION, PAS SEULEMENT L'INTENTION
-------------------------------------------------------------------------
Quatre entrées de ce fichier n'ont JAMAIS tourné, sur AUCUNE cible, depuis leur intégration : leur
argv était refusé par l'outil lui-même, ou leur image n'existait pas. Le ledger `gxrun2` en porte la
trace exacte — 52 findings pour CHACUNE des quatre causes, soit quatre outils mal invoqués sur CHAQUE
cible, tous rendus en « j'ai vérifié, rien trouvé ». Les argv ci-dessous sont désormais MESURÉS
(`docker run --rm <image> --help` sur l'image RÉELLEMENT utilisée) puis EXÉCUTÉS contre une cible
loopback jusqu'à obtenir une sortie PARSÉE — pas déduits. Deux des quatre diagnostics « évidents »
se sont révélés faux à la mesure (cf. `recon.gobuster_dns` et les deux notes de retrait ci-dessous).
Un spec qui exige une entrée absente est désormais INERTE ET NOMMÉ (`requires_params`), jamais lancé
pour aller mourir sur son propre message d'usage.

DEUX CONSERVÉS (gobuster, dnsx), DEUX RETIRÉS (theHarvester, masscan). On n'a pas forcé quatre
correctifs : deux des quatre entrées ne pouvaient PAS être rendues honnêtes ici, et une entrée de
catalogue qui ne peut pas fonctionner est PIRE qu'une entrée absente — elle fait croire à une
couverture.

L'AUTRE MOITIÉ DU MÊME PROBLÈME : L'OUTIL ABSENT (2026-08, campagne réelle)
---------------------------------------------------------------------------
La passe précédente a corrigé des outils MAL INVOQUÉS. Une campagne réelle a montré le trou d'à
côté, et il était plus large : **375 actions sautées en « module indisponible (outil sous-jacent
absent) »** — 15 outils × 25 cibles. Parmi eux, TOUS les outils de DÉCOUVERTE (feroxbuster, gau,
gospider, amass) : sans eux le moteur ne dépasse pas l'URL de départ, et le run n'a atteint que
**9 URLs distinctes**. Onze de ces quinze entrées ne déclaraient AUCUNE image docker : là où le
binaire n'est pas installé, elles ne pouvaient RIEN faire d'autre que se déclarer indisponibles.

CE QUI A ÉTÉ FAIT, ET LA BARRE QU'IL A FALLU TENIR. Pour chaque outil : (a) l'image existe-t-elle
(`docker manifest inspect`) ; (b) son ENTRYPOINT lance-t-il la CLI attendue ; (c) l'argv correspond-il
à la version de CETTE image, ET le `parser_regex` à sa SORTIE RÉELLE. Les trois ont été établis PAR
EXÉCUTION contre une cible LOOPBACK jetable (serveur HTTP/HTTPS local : routes découvrables,
paramètre reflété brut, endpoint SQLite réellement injectable, marqueurs WordPress, TLS auto-signé) —
aucun paquet vers un tiers. Les deux outils dont la fonction EST d'interroger des tiers ont été
mesurés contre un fournisseur MOCKÉ en local (gau) ou bornés à ce qui est démontrable sans trafic
tiers (amass, cf. sa note). Une image tirée mais jamais exécutée n'aurait rien prouvé.

CE QUE LA MESURE A TROUVÉ, ET QU'AUCUNE LECTURE N'AURAIT DONNÉ :
  - `xss.dalfox` : image SANS entrypoint (`Cmd ./dalfox` écrasé par les arguments -> rc=127), cible
    positionnelle REFUSÉE en 3.x (`--url` requis), `--only-poc` devenu à-valeur-obligatoire (rc=2).
    Trois fautes ; l'entrée ne pouvait produire un hit NI par docker NI par le binaire livré.
  - `recon.feroxbuster` : sans wordlist, **rc=0 et stdout VIDE** — le silence que la garde `rc != 0`
    ne rattrape pas, et il était en vigueur DANS l'image Forge livrée (binaire installé, SecLists
    non). Corrigé des deux côtés : `prefer_docker` (l'image amont embarque sa liste) + wordlist
    épinglée posée par le `Dockerfile` pour la voie locale.
  - `web.testssl` : parseur à GROUPE CAPTURANT (le finding s'appelait « NOT ok », sans sa ligne) ET
    insensible à la casse (« not vulnerable (OK) » compté comme constat).
  - `web.wpscan` : le parseur ne capturait QUE les deux avis « No WPScan API Token » — du bruit
    identique sur toute cible — pendant que les vrais constats, indentés ` | [!] …`, lui échappaient.
  - `web.nikto` : un tiers des « findings » étaient l'en-tête et le pied du rapport (Target/Start/End).
  - `recon.whatweb` : séquences ANSI dans chaque finding, le ledger et le rapport (`--colour never`).
Un argv juste avec un parseur périmé rend « aucun hit » ; un parseur trop large rend des findings qui
ne parlent pas de la cible. Les deux sont des phrases fausses, et les deux ont été corrigées ICI.

SEPT IMAGES DÉCLARÉES (toutes officielles ou désignées par le README amont) : `epi052/feroxbuster`,
`sxcurity/gau`, `caffix/amass`, `ghcr.io/sullo/nikto`, `drwetter/testssl.sh`, `wpscanteam/wpscan`,
`hahwul/dalfox`. TROIS ENTRÉES RESTENT BINAIRE-SEUL, faute d'image publiée sous le nom du projet
(vérifié) : `recon.whatweb`, `recon.wafw00f`, `sqli.sqlmap`. On ne les remplace PAS par un rebuild
tiers (`secsi/…`, `googlesky/…`) : c'est la règle qui a écarté `secsi/theharvester`, et elle vaut
toujours. Elles ne sont pas mortes pour autant — apt les cuit dans l'image Forge `full`, et leur argv
comme leur parseur y sont MESURÉS. Leur limite est NOMMÉE : hors d'un environnement qui installe le
binaire, elles dégradent en `skipped`.

ENTRÉE RETIRÉE — `recon.gospider` (crawler web). AUCUNE image publiée : le README amont
(jaeles-project/gospider) ne propose qu'un `docker build` à faire soi-même, et rien n'existe sous le
nom du projet (`jaeles-project/gospider`, `ghcr.io/jaeles-project/gospider`, `theblackturtle/gospider`
-> absents). Seul subsiste un rebuild tiers (`secsi/gospider`), écarté par la règle ci-dessus.
L'ARGV ET LE PARSEUR ÉTAIENT POURTANT BONS (mesuré sur le binaire livré : rc=0, 5 URLs parsées) —
c'est donc la DISPONIBILITÉ, et elle seule, qui décide. CE QUE LA COUVERTURE PERD, NOMMÉMENT : RIEN
de fonctionnel. `recon.katana` fait le même travail (crawl -> `emit_endpoint_discovery` -> oracles à
injection), il a une image OFFICIELLE (`projectdiscovery/katana`) et il tourne donc là où gospider ne
pouvait pas. Garder deux crawlers dont un ne démarre qu'à condition d'être installé à la main, c'est
afficher une couverture que l'exécution ne rend pas.

ENTRÉE RETIRÉE — `recon.masscan` (balayage de ports full-range). LE DIAGNOSTIC D'ORIGINE ÉTAIT JUSTE
MAIS INCOMPLET : oui, masscan n'accepte qu'une IP (`FAIL: unknown command-line parameter
"guatx.com"`, rc=1, stdout vide, 52 findings). Et la voie propre pour la lui donner EXISTE et a été
IMPLÉMENTÉE ET VÉRIFIÉE : ne PAS résoudre le nom soi-même (ce qui creuserait un écart entre ce que le
scope-guard a autorisé et ce qui est scanné, et rouvrirait la fenêtre TOCTOU que l'épinglage ferme)
mais CONSOMMER l'épinglage que le ROE pose déjà — `Roe.decide` résout une fois au point de tir, rend
son verdict CONTRE les IP résolues, et les dépose sur `action.params["_pinned_ips"]` (c'est ce que
`httpflow` lit déjà via `pin.pick`). L'argv produit était correct et l'IP scannée était, par
construction, celle que le ROE avait vettée.

  CE QUI A TUÉ L'ENTRÉE EST AILLEURS, ET C'EST LA MESURE QUI L'A SORTI. masscan émet des SYN BRUTS
  et attend la réponse SUR L'ADAPTATEUR (`-sS -Pn --send-eth`, ses options forcées). Quand la réponse
  ne revient pas par l'adaptateur auto-détecté, il sort **rc=0 avec stdout VIDE** — indiscernable
  d'une cible sans aucun port ouvert. MESURÉ sur cette machine, via le chemin d'invocation RÉEL de
  forge (`docker run --rm --network host`) : `127.0.0.1` -> 0 résultat ; `192.168.1.20` (port 22000
  DÉMONTRABLEMENT ouvert, `ss -lntp`) -> 0 résultat ; un conteneur sur le bridge docker (`172.17.0.2`,
  `curl` -> 200) -> 0 résultat ; et `-e docker0` -> `FAIL: failed to detect router`. La même commande
  lancée depuis l'AUTRE bout d'un lien (conteneur bridge -> `172.17.0.1`) rend bien `Discovered open
  port 22000/tcp`. Autrement dit : sur toute machine MULTI-HOMED — c'est-à-dire une machine de dev ou
  de CI ordinaire — masscan se tait sans échouer.

  ET C'EST EXACTEMENT LE CAS QUE `blindness.tool_did_not_run` NE PEUT PAS RATTRAPER : sa borne est
  `rc != 0`. Corriger l'argv aurait donc TRANSFORMÉ un `skipped` CORRECT (rc=1, nom d'hôte refusé —
  ce que la garde livrée la veille produisait déjà) en un `tested` MENSONGER, « j'ai vérifié, rien
  trouvé », sur une cible jamais observée. Le correctif aurait régressé l'honnêteté qu'il prétendait
  servir. On retire.

  CE QUE LA COUVERTURE PERD, NOMMÉMENT : la VITESSE d'un sweep full-range en SYN. Le RÉSULTAT, lui,
  reste couvert par `recon.naabu` — connect TCP ordinaire (aucun paquet forgé, aucun adaptateur à
  deviner), il VOIT localhost et les hôtes multi-homed, il émet déjà la découverte de service
  chaînable (`emit_service_discovery`), et il accepte `params.ports = "1-65535"` pour la plage
  complète. Il est plus lent ; il ne ment pas.

ENTRÉE RETIRÉE — `recon.theharvester` (OSINT emails/sous-domaines). MESURÉ, dans cet ordre :
  1. `laramies/theharvester` (ce que le spec déclarait) N'EXISTE PAS sur Docker Hub — `pull access
     denied ... repository does not exist` : rc=125, stdout vide, 52 findings du ledger. Une image
     qui n'existe pas ne peut pas « dégrader gracieusement » : elle échouait à chaque cible.
  2. L'image OFFICIELLE de l'auteur existe bien, mais ailleurs (`ghcr.io/laramies/theharvester`), et
     son ENTRYPOINT est `restfulHarvest -H 0.0.0.0 -p 80` — un SERVEUR REST, pas le CLI. L'argv du
     catalogue y rend `restfulHarvest: error: unrecognized arguments: -d example.com -b all`.
     ⚠️ CE BLOCAGE-LÀ EST LEVÉ (2026-08) : `runner` construit désormais `--entrypoint` (opt-in via
     `ToolSpec.docker_entrypoint`, interpréteur/shell REFUSÉ fail-closed), et `docker run --rm
     --entrypoint theHarvester ghcr.io/laramies/theharvester --help` rend bien la CLI (MESURÉ,
     rc=0). Cette note est conservée telle quelle pour que personne ne re-tire la conclusion périmée
     « c'est impossible » : ce n'est plus la raison du retrait.
  3. Il RESTE une image tierce fonctionnelle (`secsi/theharvester`, entrypoint `python
     theHarvester.py`, v4.10.0) : un rebuild NON officiel, non versionné, sur lequel on ferait
     reposer une entrée de catalogue signée. On ne l'a pas retenu — et depuis (2), il n'y a plus
     besoin de l'envisager.
  LA RAISON QUI RESTE, ET QUI SUFFIT À ELLE SEULE : `-b all` fan-oute vers des dizaines de
  fournisseurs OSINT dont la plupart exigent une clé d'API. SANS CLÉS, l'outil sort **rc=0 quasi
  vide** — exactement le silence que `blindness.tool_did_not_run` (borne `rc != 0`) NE PEUT PAS
  rattraper, et exactement ce qui a fait retirer `masscan`. Rendre l'invocation possible aurait donc
  converti un échec VISIBLE en un « j'ai vérifié, rien trouvé » MENSONGER. L'entrée reste retirée.
  CE QUE LA COUVERTURE PERD, NOMMÉMENT : la moisson d'EMAILS (le seul apport qui n'était pas déjà
  couvert). Les SOUS-DOMAINES, eux, restent couverts trois fois — `recon.subfinder`, `recon.amass` et
  `recon.subdomains` (crt.sh CT + passive DNS, natif) — et ceux-là TOURNENT. Un email n'était de
  toute façon pas un asset scannable (`hit_is_asset=False`) : il ne pouvait ni être re-validé contre
  le périmètre, ni chaîné vers un oracle.

CE QUE LE RUNNER NE FERA PAS POUR UNE ENTRÉE DE CE CATALOGUE — LES MONTAGES
---------------------------------------------------------------------------
`runner` ne construit AUCUN `-v`/`--mount`, et c'est un REFUS DOCUMENTÉ (le raisonnement complet vit
en tête de la voie docker de `forge/runner.py`). Conséquence directe et ASSUMÉE ici : `recon.gobuster_dns`
exige un CHEMIN de wordlist et n'est donc utilisable que par son BINAIRE LOCAL — via `docker_image`, le
chemin de l'hôte n'existe pas dans le conteneur (MESURÉ : « wordlist file "…" does not exist »). C'est
pourquoi `requires_params=("wordlist",)` rend l'outil INERTE ET NOMMÉ plutôt que faussement vert, et
pourquoi `recon.dnsx` — qui accepte une liste INLINE `-w www,mail,dev` — reste la voie sans fichier.
"""
from .toolspec import ToolSpec, register_spec, FlagAllowlistMixin

# Champ de schéma PARTAGÉ : les extra_args libres (drapeaux) — bornés par la `flag_allowlist` du spec
# (tout flag hors liste est REFUSÉ fail-closed). Type `list` -> la console envoie une liste de tokens
# (jamais une chaîne shell-splittée). Réutilisé par CHAQUE outil pour donner un échappatoire power-user SÛR.
# SOURCE UNIQUE : le descripteur est POSSÉDÉ par `FlagAllowlistMixin.extra_args_param()` (toolspec.py) —
# on route à travers lui au lieu de RE-DÉCLARER le dict ici (dédup ; un seul point à faire évoluer).
_EXTRA = FlagAllowlistMixin.extra_args_param(label="extra args (drapeaux allowlistés)")

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
    # amass — IMAGE OFFICIELLE `caffix/amass` (label OCI `org.opencontainers.image.source =
    #   github.com/owasp-amass/amass ; caffix == l'auteur du projet). MESURÉ : entrypoint `/bin/amass`
    #   (la CLI, pas un serveur — contrairement à theHarvester), et les QUATRE drapeaux de cet argv
    #   (`-passive -norecursive -max-depth -timeout`) existent à L'IDENTIQUE dans les DEUX versions que
    #   Forge peut exécuter : v4.2.0 (l'image) et v5.1.1 (le binaire épinglé de `tools.json`, cuit dans
    #   l'image `full`). L'écart de version est RÉEL et assumé : la voie LOCALE (v5.1.1, fraîche) est
    #   essayée d'abord, l'image ne sert que de repli là où aucun binaire n'est installé.
    #   CE QUI N'EST PAS PROUVÉ, ET POURQUOI ON LE DIT : aucune énumération RÉUSSIE n'a été observée
    #   — amass passif n'interroge QUE des fournisseurs TIERS (CT logs, agrégateurs), et la campagne de
    #   mesure s'interdisait d'émettre le moindre paquet vers un tiers. Ce qui EST mesuré, et qui suffit
    #   à écarter le scénario masscan/theHarvester : quand amass ne peut pas atteindre ses sources, il
    #   ÉCHOUE FORT — `rc=1`, stdout VIDE, stderr « the system was unable to build the pool of untrusted
    #   resolvers ». C'est la borne EXACTE de `blindness.tool_did_not_run` (rc != 0 + stdout vide) : le
    #   constat rendu est « l'outil n'a pas tourné », jamais « j'ai vérifié, rien trouvé ». Contrôle
    #   mesuré le même jour, qui empêche d'en tirer une règle trop large : subfinder, dnsx et gau, eux,
    #   sortent rc=0 stdout VIDE hors ligne — le silence est la norme des outils passifs, pas un
    #   discriminant ; amass est le plus BRUYANT des quatre.
    ToolSpec(
        kind="recon.amass", vuln_class="Recon", binary="amass",
        argv_template=("enum", "-passive", "-norecursive", "-d", "{target_host}",
                       ("-timeout", "{param:timeout}"), ("-max-depth", "{param:max_depth}"), "{args}"),
        mitre="T1590", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="caffix/amass", parser="lines", hit_status="tested", severity="INFO",
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
    # dnsx : ARGV MESURÉ (`docker run --rm projectdiscovery/dnsx -h`). dnsx a DEUX entrées, et une seule
    #   est atteignable ici : `-l` (liste d'hôtes à RÉSOUDRE) ne lit qu'un FICHIER ou STDIN — or
    #   `runner.tool` n'alimente pas stdin (mesuré : `-l example.com` traite « example.com » comme un
    #   chemin de fichier, rc=0 et AUCUNE sortie : un faux « aucun hit » que la garde rc!=0 ne verrait
    #   même pas). Reste `-d <domaine> -w <mots>`, qui EXIGE la wordlist : sans elle, dnsx s'arrête sur
    #   `missing wordlist(w) flag required with domain(d) input` (rc=1, stdout vide — 52 findings de
    #   `gxrun2` rendus en « aucun hit exploitable »). dnsx est donc, ICI, un ÉNUMÉRATEUR ; la
    #   résolution d'un hôte connu reste couverte par `recon.dig` (types A/AAAA/MX/TXT/NS/…).
    #   BON À SAVOIR : `-w` accepte une liste INLINE séparée par des virgules (`-w www,mail,dev`) —
    #   utilisable sans aucun fichier, contrairement à gobuster qui veut un chemin.
    ToolSpec(
        kind="recon.dnsx", vuln_class="Recon", binary="dnsx",
        # `-nc` (no-color) : MESURÉ — `-silent` ne suffit pas, dnsx colore sa sortie MÊME redirigée vers
        # un fichier (`example.com [\x1b[35mA\x1b[0m] [\x1b[32m1.2.3.4\x1b[0m]`). Sans `-nc`, chaque
        # finding embarquait des séquences d'échappement ANSI dans son évidence et dans le ledger.
        argv_template=("-silent", "-nc", "-a", "-resp", "-d", "{target_host}", ("-w", "{param:wordlist}"),
                       ("-r", "{param:resolver}"), ("-rl", "{param:rate}"),
                       ("-t", "{param:threads}"), ("-retry", "{param:retries}"), "{args}"),
        mitre="T1590.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=("recon.subdomains",), docker_image="projectdiscovery/dnsx", parser="lines",
        hit_status="tested", severity="INFO",
        # Même politique que gobuster : pas de wordlist embarquée, pas de lancement sans wordlist.
        requires_params=("wordlist",),
        requires_note=("Fournir params.wordlist : chemin de fichier OU liste inline séparée par des "
                       "virgules (`www,mail,dev`) — dnsx accepte les deux. L'énumération par wordlist "
                       "est du brute-force PAR VOLUME : le débit reste gouverné par le ROE "
                       "(`rate_explicit` -> `-rl`) et `-t` borne les threads."),
        params_schema=(
            {"name": "wordlist", "type": "text", "label": "wordlist (-w, chemin ou liste inline) — REQUIS",
             "flag": "-w"},
            {"name": "resolver", "type": "text", "label": "résolveur DNS (-r, ex 1.1.1.1:53)", "flag": "-r"},
            {"name": "rate", "type": "number", "label": "rate-limit (-rl req/s)", "flag": "-rl"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            {"name": "retries", "type": "number", "label": "retries (-retry)", "flag": "-retry"},
            _EXTRA),
        # `-d` VOLONTAIREMENT ABSENT de l'allowlist : un 2e domaine en extra_args contournerait le
        # scope-guard. `-o`/`-j` (sortie fichier) et `-l` (lecture fichier) exclus de même.
        flag_allowlist=("-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-ptr", "-soa", "-resp",
                        "-resp-only", "-rl", "-t", "-retry", "-silent", "-nc", "-w", "-r"),
        description="Énumération DNS de sous-domaines (dnsx `-d <domaine> -w <mots>`) — enregistrements "
                    "A + réponse, assets re-validés scope. La wordlist est REQUISE (dnsx refuse "
                    "`-d` sans `-w`) et accepte une liste INLINE `www,mail,dev` : sans elle l'outil est "
                    "inerte et le dit (skip nommé, zéro processus). La RÉSOLUTION d'un hôte déjà connu "
                    "passe par `recon.dig` (dnsx ne la lit que depuis un fichier/stdin)."),
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
    # gau — IMAGE `sxcurity/gau`, celle que le README AMONT (github.com/lc/gau) désigne nommément ;
    #   entrypoint `gau` (la CLI). ARGV + PARSEUR MESURÉS PAR EXÉCUTION, contre un fournisseur Wayback
    #   MOCKÉ EN LOCAL (aucun paquet vers web.archive.org) : `gau --subs --providers wayback lab.test`
    #   -> rc=0 et 4 URLs sur stdout, une par ligne, PARSÉES par ce spec (`parser="lines"`).
    #   CE QUE LA MESURE A RÉVÉLÉ EN PASSANT (bug AMONT, à connaître avant de lire un timeout) : dans
    #   gau v2.2.4 le `break` qui doit terminer la pagination est écrit DANS un `select`, il ne casse
    #   donc que le `select` et JAMAIS la boucle `for page` (mesuré : 4 846 pages demandées au mock
    #   avant qu'on ne l'arrête). En production c'est l'ERREUR HTTP du fournisseur qui termine la
    #   boucle. Conséquence pour Forge : un gau qui « n'en finit pas » n'est pas une cible lente, c'est
    #   cette boucle — et c'est le `timeout` du spec (300 s -> rc=124 -> `skipped`) qui la borne.
    ToolSpec(
        kind="recon.gau", vuln_class="Recon", binary="gau",
        argv_template=("--subs", ("--threads", "{param:threads}"), ("--providers", "{param:providers}"),
                       ("--blacklist", "{param:blacklist}"), ("--from", "{param:from_date}"),
                       ("--to", "{param:to_date}"), "{args}", "{target_host}"),
        mitre="T1596", phase="recon", capability="passive", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="sxcurity/gau", parser="lines", hit_status="tested", severity="INFO",
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
    # gospider : RETIRÉ (2026-08). Cf. « ENTRÉE RETIRÉE — recon.gospider » en tête de module.
    #   En un mot : AUCUNE image publiée (le README amont ne propose qu'un `docker build` à faire
    #   soi-même), et `recon.katana` — MÊME fonction (crawl -> endpoints chaînables), MÊME
    #   `emit_endpoint_discovery` — a, LUI, une image officielle qui tourne. La couverture ne perd rien.
    ToolSpec(
        kind="recon.feroxbuster", vuln_class="ContentDiscovery", binary="feroxbuster",
        # `--quiet` ET PAS `--silent` — C'EST LE CORRECTIF D8, ET IL EST DANS L'INVOCATION.
        # `--silent` n'imprime QUE les URLs : la colonne de STATUT n'existe pas dans la sortie, donc
        # forge ne pouvait PAS la voir, et son `https?://\S+` ingérait les **404** comme de la surface
        # (chaque 404 devenait un NŒUD du graphe, balayé ensuite par tout le panel d'oracles — c'est
        # l'origine du gros du volume : 1806 findings sur DVWA au banc). `--quiet` retire la bannière
        # et les barres de progression MAIS GARDE la ligne de résultat complète :
        #     404      GET        9l       33w      287c http://127.0.0.1:8081/Reports%20List
        #     301      GET        9l       28w      314c http://127.0.0.1:8081/docs => .../docs/
        # MESURÉ sur DVWA (`--no-recursion`, image `epi052/feroxbuster`) : `--silent` -> 21 URLs
        # ingérées, statut INVISIBLE ; `--quiet` -> 22 lignes dont **17 en 404**, et 4 URLs réelles
        # après rejet (`/`, `/docs`, `/config`, `/external`). 81 % de ce qu'on ingérait n'existait pas.
        # On ne DEVINE donc rien (l'auto-filtre de feroxbuster, lui, manque ces 404 : leur taille varie
        # avec la longueur du chemin) — on REGARDE, ce que `--silent` interdisait.
        argv_template=("--quiet", "-u", "{target_url}", ("-w", "{param:wordlist}"),
                       ("--rate-limit", "{param:rate}"), ("-t", "{param:threads}"),
                       ("-d", "{param:depth}"), ("-x", "{param:extensions}"),
                       ("-s", "{param:status_codes}"), ("--scan-limit", "{param:scan_limit}"), "{args}"),
        mitre="T1595.003", phase="recon", capability="active", attck_tactic="Reconnaissance",
        # IMAGE `epi052/feroxbuster` — le dépôt Docker Hub de l'AUTEUR (epi052), entrypoint `feroxbuster`
        # (la CLI). ARGV + PARSEUR MESURÉS : `--silent -u http://127.0.0.1:18080` sur cible loopback ->
        # rc=0, 14 URLs parsées par ce spec. L'image EMBARQUE sa wordlist par défaut
        # (`/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`) : elle est donc
        # AUTO-SUFFISANTE, aucun `-w` requis, aucun montage (que `runner` refuse de toute façon).
        #
        # `prefer_docker=True` — ET C'EST UN CORRECTIF, PAS UNE PRÉFÉRENCE DE STYLE. MESURÉ : un
        # feroxbuster LOCAL dont la wordlist par défaut est ABSENTE sort **rc=0 avec stdout VIDE** (le
        # motif n'est écrit que sur stderr : « Could not open /usr/share/seclists/… »). C'est le silence
        # EXACT que `blindness.tool_did_not_run` (borne `rc != 0`) NE PEUT PAS rattraper — celui qui a
        # fait retirer masscan — et il était en vigueur DANS L'IMAGE FORGE LIVRÉE, qui installe le
        # binaire mais pas SecLists : chaque action feroxbuster y concluait « aucun hit » sur une cible
        # jamais balayée. Deux verrous posés ensemble : (1) ici, docker d'abord — l'image est
        # auto-suffisante ; (2) dans le `Dockerfile`, la wordlist par défaut est désormais POSÉE
        # (SecLists 2024.3, épinglée SHA256) pour que la voie LOCALE — la seule qui existe DANS le
        # conteneur, où il n'y a pas de démon docker — trouve la sienne.
        docker_image="epi052/feroxbuster", prefer_docker=True,
        depends_on=("recon.httpx",), parser="regex", parser_regex=r"https?://\S+",
        # REJET DE LIGNE (jamais de hit) : une ligne de résultat dont la colonne de STATUT vaut 404
        # n'est pas de la surface. SEUL le 404 est rejeté — un 403/401/301/500 EST de la surface (une
        # ressource protégée reste une ressource), et une ligne SANS statut lisible n'est PAS rejetée :
        # refuser tout endpoint au statut inconnu serait l'excès inverse, et coûterait la couverture
        # qu'on vient de gagner. Cf. `toolspec.reject_lines` pour le sens de la dégradation.
        parser_reject_line=r"^\s*404\s",
        hit_status="tested", severity="INFO",
        # SANS ceci, ses hits sortaient en `feroxbuster: <URL>` SANS marqueur : 6 URLs -> 6 nœuds
        # au graphe -> **0 action**. Il était CLASSÉ producteur (`asset_hits`) tout en ne
        # produisant que des culs-de-sac — le même trou que `recon.content`, à deux endroits.
        emit_endpoint_discovery=True,
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
        description="Découverte de contenu/routes (feroxbuster) — chemins trouvés, re-validés scope. "
                    "Image docker epi052/feroxbuster (auteur), PRÉFÉRÉE car elle EMBARQUE sa wordlist "
                    "par défaut : sans wordlist, feroxbuster sort rc=0 stdout VIDE (mesuré) — un "
                    "silence que la garde rc!=0 ne rattrape pas. Wordlist surchargeable via "
                    "params.wordlist (chemin lisible par le binaire/conteneur)."),

    # --- Fingerprint / détection — rapportent SUR la cible (pas d'asset découvert) ---
    # whatweb — AUCUNE IMAGE OFFICIELLE. Vérifié : le README amont (urbanadventurer/WhatWeb) ne
    #   mentionne aucun docker, et aucune image n'existe sous le nom du projet (`whatweb/whatweb`,
    #   `urbanadventurer/whatweb` -> absents au `docker manifest inspect`). Les rebuilds tiers (secsi/…)
    #   sont écartés par la MÊME règle qui a écarté `secsi/theharvester` : on ne fait pas reposer une
    #   entrée de catalogue signée sur un rebuild non officiel et non versionné. L'entrée reste donc
    #   BINAIRE-SEUL — et elle n'est pas morte pour autant : whatweb est cuit par apt dans l'image
    #   Forge `full`, où l'argv ci-dessous est MESURÉ (whatweb 0.5.5, rc=0, 1 ligne parsée).
    #
    #   `--colour never` : CORRECTIF MESURÉ, même défaut que celui documenté sur `recon.dnsx`. Sans lui,
    #   whatweb colore sa sortie MÊME redirigée vers un pipe, et CHAQUE finding embarquait des séquences
    #   d'échappement ANSI (`\x1b[1m\x1b[34mhttp://…`) dans son évidence, son titre, le ledger signé et
    #   le rapport exporté. Mesuré des deux côtés : avec le drapeau, la ligne est propre.
    ToolSpec(
        kind="recon.whatweb", vuln_class="TechFingerprint", binary="whatweb",
        argv_template=("--no-errors", "--colour", "never", "-a", "3", "{target_url}",
                       ("--max-threads", "{param:max_threads}"),
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
                        "--no-errors", "--wait", "--colour", "--color"),
        description="Fingerprint de technologies web (whatweb --colour never) — bannières/CMS/frameworks "
                    "sur la cible, sortie SANS séquences ANSI. Aucune image officielle n'existe (vérifié) : "
                    "outil BINAIRE-SEUL (apt dans l'image Forge `full`), dégradation gracieuse ailleurs."),
    # wafw00f — AUCUNE IMAGE OFFICIELLE : le README amont (EnableSecurity/wafw00f) ne propose qu'un
    #   `docker build .` à faire soi-même, et rien n'est publié sous le nom du projet
    #   (`enablesecurity/wafw00f` -> absent). Entrée BINAIRE-SEUL, comme whatweb. ARGV + PARSEUR MESURÉS
    #   (wafw00f 2.2.0, image Forge `full`, cible loopback) : rc=0, et le hit rendu est EXACTEMENT
    #   `[-] No WAF detected by the generic detection` — vérifié en `repr()`, SANS ANSI : wafw00f ne
    #   colore que sa bannière ASCII, laquelle ne matche aucune des trois alternatives du parseur.
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
        description="Détection de WAF/CDN (wafw00f) — identifie le pare-feu applicatif devant la cible. "
                    "Aucune image officielle n'existe (vérifié) : outil BINAIRE-SEUL (apt dans l'image "
                    "Forge `full`), dégradation gracieuse ailleurs."),

    # --- Scanners de faiblesses — rapportent SUR la cible (reported_by_tool, jamais vulnerable) ---
    ToolSpec(
        kind="web.nikto", vuln_class="Scanner", binary="nikto",
        argv_template=("-nointeractive", "-ask", "no", "-host", "{target_url}",
                       ("-Tuning", "{param:tuning}"), ("-timeout", "{param:timeout}"),
                       ("-maxtime", "{param:maxtime}"), ("-port", "{param:port}"), "{args}"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        # IMAGE OFFICIELLE `ghcr.io/sullo/nikto` (label OCI source = github.com/sullo/nikto), entrypoint
        # `nikto.pl` = la CLI. ARGV MESURÉ : rc=0 sur cible loopback, 8 087 requêtes, 16 items rapportés.
        depends_on=("recon.httpx",), docker_image="ghcr.io/sullo/nikto", parser="regex",
        # PARSEUR MESURÉ SUR SORTIE RÉELLE — l'ancien `^\+ .*$` était juste dans sa forme et FAUX dans
        # son étendue : nikto préfixe de `+ ` non seulement ses constats mais aussi son EN-TÊTE et son
        # PIED de rapport. Sur la sortie mesurée, 8 des 25 « findings » n'étaient que du méta-scan —
        # `+ Target IP:`, `+ Target Hostname:`, `+ Target Port:`, `+ Start Time:`, `+ End Time:`,
        # `+ No CGI Directories found`, `+ 8087 requests: …`, `+ 1 host(s) tested` — c'est-à-dire un
        # tiers de findings LOW estampillés `reported_by_tool` qui ne disent RIEN de la cible, sur
        # CHAQUE cible. Le lot restant (17) est intégralement substantiel (bannières périmées, indexing,
        # robots.txt, en-têtes manquants, fichiers exposés). L'exclusion est ancrée sur les libellés
        # EXACTS observés, pas sur une heuristique.
        parser_regex=(r"(?m)^\+ (?!Target |Start Time:|End Time:|\d+ host\(s\) tested"
                      r"|\d+ requests:|No CGI Directories).*$"),
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        params_schema=(
            {"name": "tuning", "type": "text", "label": "tuning tests (-Tuning, ex 123bde)", "flag": "-Tuning"},
            {"name": "timeout", "type": "number", "label": "timeout req (-timeout s)", "flag": "-timeout"},
            {"name": "maxtime", "type": "text", "label": "durée max (-maxtime, ex 1h ou 3600s)", "flag": "-maxtime"},
            {"name": "port", "type": "number", "label": "port (-port)", "flag": "-port"},
            _EXTRA),
        flag_allowlist=("-Tuning", "-timeout", "-maxtime", "-Plugins", "-port", "-useragent",
                        "-nossl", "-ssl", "-nointeractive", "-Display", "-D"),
        description="Scanner de serveur web (nikto) — misconfigs/fichiers exposés signalés "
                    "(reported_by_tool). Image docker ghcr.io/sullo/nikto (officielle). Le parseur "
                    "écarte l'en-tête et le pied de rapport (Target/Start/End/requests/host(s) tested) : "
                    "ce sont des lignes `+ ` qui ne disent rien de la cible."),
    ToolSpec(
        kind="web.wpscan", vuln_class="CMSScan", binary="wpscan",
        argv_template=("--no-banner", "--url", "{target_url}", ("--api-token", "{param:wpscan_token}"),
                       ("--enumerate", "{param:enumerate}"), ("--plugins-detection", "{param:plugins_detection}"),
                       ("--throttle", "{param:rate_delay_ms}"), ("--max-threads", "{param:max_threads}"),
                       ("--request-timeout", "{param:timeout}"), "{args}"),
        mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        # IMAGE OFFICIELLE `wpscanteam/wpscan` (label OCI source = github.com/wpscanteam/wpscan),
        # entrypoint `/usr/local/bundle/bin/wpscan` = la CLI. ARGV MESURÉ : rc=0 en 4,9 s sur une cible
        # loopback maquillée en WordPress (WP 6.4.2 + thème détectés).
        depends_on=("recon.httpx",), docker_image="wpscanteam/wpscan", parser="regex",
        # PARSEUR RÉÉCRIT — L'ANCIEN NE CAPTURAIT QUE DU BRUIT, ET C'EST L'INVERSE EXACT DE CE QU'IL
        # FALLAIT. Mesuré sur la sortie réelle, `^\[!\].*$` rendait DEUX hits, tous deux les mêmes sur
        # toute cible : « [!] No WPScan API Token given… » et « [!] You can get a free API token… ».
        # Autrement dit 2 findings LOW par cible qui parlent de NOTRE configuration, jamais de la
        # cible — pendant que les VRAIS constats lui échappaient : les `[!]` de wpscan sont INDENTÉS
        # dans leurs blocs (` | [!] The version is out of date…`), donc jamais en début de ligne, et le
        # constat le plus lourd (« WordPress version 6.4.2 identified (Insecure, released on … ) »)
        # est préfixé `[+]`, pas `[!]`. Le nouveau motif accepte l'indentation ` | `, EXCLUT nommément
        # les deux avis de token, et récupère la ligne de version INSECURE. Vérifié sur la sortie
        # enregistrée : 2 hits, exactement les deux vrais, zéro avis de token.
        parser_regex=(r"(?m)^(?:\s*\|\s*)?\[!\](?! (?:No WPScan API Token|You can get a free API token)).*$"
                      r"|^\[\+\] WordPress version .*Insecure.*$"),
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
        description="Scanner WordPress (wpscan) — plugins/thèmes/vulns signalés (reported_by_tool). "
                    "Image docker wpscanteam/wpscan (officielle). Le parseur lit les `[!]` INDENTÉS "
                    "dans les blocs et la ligne de version « (Insecure …) », et écarte les deux avis "
                    "« No WPScan API Token » qui ne parlent pas de la cible. Token API optionnel via "
                    "params.wpscan_token."),
    ToolSpec(
        kind="web.testssl", vuln_class="TLS", binary="testssl.sh", tool_name="testssl",
        argv_template=("--quiet", "--color", "0", ("--severity", "{param:severity}"), "{args}", "{target_host}"),
        cwe="CWE-326", mitre="T1595.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        # IMAGE OFFICIELLE `drwetter/testssl.sh` (le dépôt Docker Hub de l'auteur), entrypoint
        # `testssl.sh` = la CLI. ARGV MESURÉ : rc=0 en 78 s contre un TLS loopback auto-signé.
        depends_on=("recon.httpx",), docker_image="drwetter/testssl.sh", parser="regex",
        # PARSEUR CORRIGÉ — DEUX FAUTES, MESURÉES SUR SORTIE RÉELLE, ET CHACUNE SUFFISAIT.
        #  (1) GROUPE CAPTURANT. `parse_output` rend `group(1)` dès qu'un groupe existe : l'ancien
        #      `(VULNERABLE|NOT ok|…)` faisait donc du hit la SEULE alternative matchée — le finding
        #      s'appelait littéralement « NOT ok », sans la ligne qui dit DE QUOI il s'agit. Mesuré :
        #      3 findings réels réduits à `NOT ok` / `vulnerable`. Le groupe est passé NON-CAPTURANT
        #      -> le hit redevient la LIGNE ENTIÈRE (« subjectAltName (SAN) missing (NOT ok) -- … »).
        #  (2) INSENSIBILITÉ À LA CASSE. `(?i)` + `VULNERABLE` matchait « not vulnerable (OK) » —
        #      c'est-à-dire le verdict SAIN que testssl écrit pour CHAQUE CVE testée (Heartbleed, CCS…).
        #      L'ancien parseur fabriquait donc des findings à partir de bonnes nouvelles. testssl écrit
        #      ses verdicts négatifs en CAPITALES (`VULNERABLE`, `NOT ok`, `WEAK`) : le `(?i)` tombe.
        parser_regex=r"(?m)^.*(?:VULNERABLE|NOT ok|WEAK).*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False, timeout=600,
        params_schema=(
            {"name": "severity", "type": "select", "label": "sévérité min rapportée (--severity)",
             "flag": "--severity", "allowed": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
            _EXTRA),
        flag_allowlist=("--severity", "-p", "--protocols", "-s", "-S", "-P", "-U", "-f", "-e",
                        "--fast", "--sneaky", "--quiet", "--warnings", "-4"),
        description="Audit TLS/SSL (testssl.sh) — protocoles/chiffrements faibles et CVE TLS signalés "
                    "(reported_by_tool). Image docker drwetter/testssl.sh (officielle). Le parseur rend "
                    "la LIGNE ENTIÈRE (groupe non-capturant) et respecte la CASSE : « not vulnerable (OK) » "
                    "n'est plus pris pour un constat. protocoles (-p) via extra_args allowlistés."),
    # dalfox — TROIS FAUTES SUPERPOSÉES, TOUTES MESURÉES, ET AUCUNE N'ÉTAIT VISIBLE SANS EXÉCUTER.
    #   C'est le cas `gobuster` en pire : l'entrée n'a jamais pu produire un hit, NI par docker, NI par
    #   le binaire que Forge livre pourtant lui-même.
    #   (1) IMAGE SANS ENTRYPOINT. `hahwul/dalfox` (officielle, label OCI source = github.com/hahwul/
    #       dalfox) n'a PAS d'`Entrypoint` : elle porte un `Cmd` `["./dalfox"]`, que `docker run IMAGE
    #       url …` REMPLACE. Mesuré : rc=127, stdout vide — docker cherchait à exécuter « url ». C'est
    #       la trappe theHarvester, et c'est exactement ce que `docker_entrypoint` sert à fermer ; le
    #       binaire vit en `/app/dalfox` (chemin ABSOLU, donc admis par `runner.entrypoint_refusal`,
    #       et `dalfox` n'est pas un interpréteur).
    #   (2) CIBLE POSITIONNELLE REFUSÉE. En dalfox 3.x l'URL passe par `--url` : `dalfox url <URL>`
    #       rend « error: the following required arguments were not provided: --url <URL> ». Le
    #       positionnel `[TARGET]…` existe encore mais ne SUFFIT pas.
    #   (3) `--only-poc` EXIGE UNE VALEUR (`[v, r, a, i, …]`) : passé nu, dalfox s'arrête sur « a value
    #       is required for '--only-poc' » (rc=2). Il est RETIRÉ de l'argv fixe — `--silence` fait déjà
    #       ce qu'on voulait (« Silence all logs except POC output to STDOUT ») sans se coupler à une
    #       énumération de valeurs qui bouge d'une version à l'autre. Il reste ALLOWLISTÉ : un opérateur
    #       le passe en DEUX tokens (`--only-poc v,r`), forme que `check_extra_args` accepte.
    #   VÉRIFIÉ SUR LES DEUX VERSIONS QUE FORGE PEUT LANCER — l'image (3.2.0) ET le binaire épinglé de
    #   `tools.json` (3.1.2, cuit dans l'image `full`) : l'argv réparé rend rc=0 et une sortie
    #   `[POC][V][GET][inHTML] http://…` sur un paramètre reflété en loopback, que ce parseur capture.
    ToolSpec(
        kind="xss.dalfox", vuln_class="XSS", binary="dalfox",
        argv_template=("url", "--url", "{target_url}", "--silence",
                       ("-p", "{param:param}"), ("--delay", "{param:rate_delay_ms}"),
                       ("--workers", "{param:worker}"), ("--timeout", "{param:timeout}"), "{args}"),
        cwe="CWE-79", mitre="T1059", phase="access", capability="active", attck_tactic="Execution",
        depends_on=("recon.js_endpoints",), docker_image="hahwul/dalfox",
        docker_entrypoint="/app/dalfox",
        parser="regex", parser_regex=r"(?m)^\[POC\].*$",
        hit_status="reported_by_tool", severity="LOW", hit_is_asset=False,
        params_schema=(
            {"name": "param", "type": "text", "label": "paramètre ciblé (-p)", "flag": "-p"},
            # `-w` N'EXISTE PLUS en 3.x (mesuré sur 3.1.2 ET 3.2.0) : le drapeau est `--workers`.
            {"name": "worker", "type": "number", "label": "workers concurrents (--workers)",
             "flag": "--workers"},
            {"name": "timeout", "type": "number", "label": "timeout req (--timeout s)", "flag": "--timeout"},
            _EXTRA),
        # ALLOWLIST RECALÉE SUR LES DRAPEAUX QUI EXISTENT EN 3.x (relevés à `dalfox url --help`). Les
        # anciens `-w`, `--mining-dict`, `--mining-dom`, `--skip-mining-all`, `--deep-domxss` ont
        # DISPARU : les garder faisait miroiter des options inexistantes. EXCLUS DÉLIBÉRÉMENT :
        # `-f`/`--format` (changerait la forme de sortie sous le parseur), `-o`/`--output` (écriture
        # fichier), `--proxy` (exfil réseau), `--config` (fichier lu), `--custom-payload`/
        # `--remote-payloads`/`--remote-wordlists` (chargement d'entrées distantes), `-b`/`--blind`
        # (rappel OOB vers un hôte tiers).
        flag_allowlist=("-p", "--param", "--workers", "--delay", "--timeout", "--only-poc",
                        "--skip-mining", "--skip-mining-dict", "--skip-mining-dom",
                        "--skip-ast-analysis", "--deep-scan", "-S", "--silence", "--waf-evasion",
                        "-r", "--rate-limit", "--retries", "--retry-delay", "-F", "--follow-redirects",
                        "--insecure", "--no-color"),
        description="Scanner XSS (dalfox 3.x : `url --url <URL> --silence`) — POC de reflet/DOM signalés "
                    "(reported_by_tool ; PROUVER via oracle). Image docker hahwul/dalfox avec "
                    "`--entrypoint /app/dalfox` (l'image n'a qu'un Cmd, que les arguments écraseraient). "
                    "mining/AST (--skip-mining*, --deep-scan) et `--only-poc v,r` via extra_args allowlistés."),

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
        description="Exploitation SQLi (sqlmap) — GATÉE par le plancher exploit (allow_exploit). Hits "
                    "reported_by_tool. Aucune image officielle n'existe (vérifié : rien sous "
                    "`sqlmapproject/…`) : outil BINAIRE-SEUL (apt dans l'image Forge `full`). ARGV et "
                    "parseur MESURÉS contre un endpoint loopback réellement injectable (SQLite "
                    "concaténé) : rc=0, hits « Parameter: id (GET) » et « back-end DBMS: SQLite »."),

    # --- INTÉGRATIONS EXTERNES GOUVERNÉES SUPPLÉMENTAIRES (recon/scan/OSINT, non-destructif/non-exploit) ---
    # masscan : RETIRÉ (2026-08). Cf. « ENTRÉE RETIRÉE — recon.masscan » en tête de module.
    # `recon.naabu` (juste au-dessus) couvre les ports, TOURNE partout, et émet déjà la découverte
    # de service chaînable. Pour un sweep full-range : `params.ports = "1-65535"` sur naabu.
    # gobuster mode DNS : énumération de SOUS-DOMAINES. On choisit le mode dns (PAS dir) car la découverte
    #   de CONTENU est DÉJÀ couverte par feroxbuster -> gobuster-dns COMPLÈTE (enum sous-domaines). Assets
    #   découverts (phase recon -> hit_is_asset dérivé True) RE-VALIDÉS scope fail-closed. Wordlist FOURNIE
    #   PAR L'UTILISATEUR — aucun chemin machine-spécifique en dur, et SANS elle l'outil ne tourne pas.
    #
    #   ARGV MESURÉ (gobuster 3.8.2, image `ghcr.io/oj/gobuster`, `docker run --rm <img> dns --help`) —
    #   ET LE DIAGNOSTIC « ÉVIDENT » ÉTAIT FAUX. Le ledger montrait `invalid value "guatx.com" for flag
    #   -d: parse error` (52 findings) et la lecture naturelle était « il manque -w ». La mesure dit
    #   autre chose : dans gobuster >= 3.x, **`-d` est l'abréviation de `--delay`** (une DURÉE), et le
    #   domaine s'appelle `--domain`/`--do`. `-d guatx.com` demandait donc à gobuster de lire un nom
    #   d'hôte comme un délai — d'où « parse error ». `-w` EST bien requis lui aussi (mesuré :
    #   `Required flag "wordlist" not set`, rc=1), mais il n'aurait JAMAIS été atteint : c'est le
    #   parsing de `-d` qui échouait en premier. Deux fautes, pas une, et l'ordre importe.
    ToolSpec(
        kind="recon.gobuster_dns", vuln_class="SubdomainEnum", binary="gobuster",
        argv_template=("dns", "-q", "--domain", "{target_host}", ("-w", "{param:wordlist}"),
                       ("--resolver", "{param:resolver}"),
                       ("--delay", "{param:rate_delay_dur}"), ("-t", "{param:threads}"),
                       ("--timeout", "{param:timeout}"), "{args}"),
        mitre="T1590.002", phase="recon", capability="active", attck_tactic="Reconnaissance",
        depends_on=(), docker_image="ghcr.io/oj/gobuster", parser="regex",
        # PARSEUR MESURÉ, PAS SUPPOSÉ — et c'était la TROISIÈME faute de cette entrée. L'ancien
        # `^Found:\s+(\S+)` datait de gobuster <= 3.6 ; en 3.8.2 le mode dns écrit `<hôte> <ip>` sans
        # préfixe (mesuré sur une énumération RÉELLE : `www.lab.test 127.0.0.42`). Un argv corrigé mais
        # un parseur périmé aurait rendu EXACTEMENT le même « aucun hit » — d'où la règle : on ne
        # valide pas un correctif d'invocation sans avoir LU une sortie réelle. Le préfixe `Found: `
        # reste toléré (optionnel) pour les gobuster plus anciens encore déployés. group(1) = l'hôte,
        # qui devient l'ASSET re-validé fail-closed contre le périmètre.
        parser_regex=r"(?im)^(?:Found:\s+)?([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)\b",
        hit_status="tested", severity="INFO",
        # INERTE-MAIS-HONNÊTE : sans wordlist, gobuster s'arrête sur `Required flag "wordlist" not set`.
        # On ne le lance pas pour ça — skip NOMMÉ. On n'embarque PAS de liste par défaut : ce serait
        # figer une politique (taille de l'énumération = volume de requêtes DNS) au nom de l'opérateur.
        requires_params=("wordlist",),
        requires_note=("Fournir params.wordlist (chemin lisible par le binaire/conteneur ; convention "
                       "SecLists/Discovery/DNS/subdomains-top1million-5000.txt). L'énumération par "
                       "wordlist est du brute-force PAR VOLUME : son débit reste gouverné par le ROE "
                       "(`rate_explicit` -> `rate_delay_dur` -> `--delay`), et `-t` borne les threads."),
        params_schema=(
            {"name": "wordlist", "type": "text", "label": "wordlist (-w, chemin) — REQUIS", "flag": "-w"},
            {"name": "resolver", "type": "text", "label": "résolveur DNS (--resolver, ex 1.1.1.1:53)",
             "flag": "--resolver"},
            {"name": "threads", "type": "number", "label": "threads (-t)", "flag": "-t"},
            {"name": "timeout", "type": "text", "label": "timeout (--timeout, ex 10s)", "flag": "--timeout"},
            _EXTRA),
        # ALLOWLIST RECALÉE SUR LES DRAPEAUX QUI EXISTENT VRAIMENT en 3.8.2 (les anciens `-i`/`-r` n'y
        # sont plus : les garder laissait croire à des options inexistantes). EXCLUS délibérément :
        # `--domain`/`--do` (un 2e domaine en extra_args ÉCRASERAIT la cible scope-guardée — le dernier
        # gagne : ce serait un contournement de périmètre), `-o`/`--output` (écriture fichier),
        # `-p`/`--pattern`/`--discover-pattern` (LECTURE de fichier).
        flag_allowlist=("-w", "-t", "-d", "--delay", "--timeout", "-c", "--check-cname",
                        "--wildcard", "--wc", "--no-fqdn", "--nf", "--protocol",
                        "-q", "--quiet", "--no-color", "--nc", "--no-progress", "--np",
                        "--no-error", "--ne", "--wordlist-offset", "--wo"),
        description="Énumération DNS de sous-domaines (gobuster 3.x mode dns, -q --domain) — COMPLÈTE "
                    "feroxbuster (découverte de contenu) ; assets re-validés scope. Le domaine passe "
                    "par `--domain` (en 3.x, `-d` est l'abréviation de `--delay`, une durée). Wordlist "
                    "FOURNIE PAR L'UTILISATEUR via params.wordlist et REQUISE : sans elle l'outil est "
                    "inerte et le dit (skip nommé, zéro processus). Résolveur optionnel via "
                    "params.resolver. Image docker ghcr.io/oj/gobuster."),
    # theHarvester : RETIRÉ (2026-08). Cf. « ENTRÉE RETIRÉE » en tête de module pour le raisonnement
    #   complet et ce que la couverture perd. En un mot : l'entrée déclarait une image qui N'EXISTE PAS,
    #   et aucune image utilisable par ce runner n'a été trouvée. Une entrée de catalogue qui ne peut
    #   pas fonctionner est PIRE qu'une entrée absente — elle fait croire à une couverture.
    #
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
