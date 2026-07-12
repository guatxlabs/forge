# Forge — Couverture des techniques (vs toolkit bug-bounty + findings)

> Réponse à : « toutes les techniques / outils / findings produits dans le workspace bug-bounty
> (FAISS : 200 outils indexés, 439 findings ; `toolkit/`) sont-ils reproductibles avec Forge ? »
>
> **Verdict** : pour l'usage bug-bounty gouverné et orienté-preuve que Forge cible — **oui, la quasi-totalité
> est reproductible aujourd'hui**. Les seuls non-couverts sont exactement ce que Forge **exclut par design**
> (DoS, cred-cracking, memory-safety native/kernel, spoofing LAN, forensics) — ce ne sont pas des lacunes.
> Analysé à HEAD `bd74f1e`.

## 1. Techniques de findings (439 findings FAISS) → oracle Forge

**100 % des techniques *web* mappent à un oracle natif avec discipline de preuve :**

| Technique (occurrences) | Oracle Forge natif |
|---|---|
| IDOR (53) | `access_control.idor` (CWE-639, preuve cross-compte) |
| CORS (45) | `cors.credentials` (CWE-942) |
| GraphQL authz (33) | `graphql.access` |
| XSS (32) | `xss.reflected` / `xss.stored` (CWE-79) |
| JWT (29) | `jwt.weakness` (CWE-347) |
| SSRF (23) | `ssrf.callback` / `ssrf.xspa` / `ssrf.cloud_metadata` (CWE-918, callback-confirmé) |
| Subdomain takeover (21) | `subdomain.takeover` (CWE-350) |
| OAuth/OIDC (16+13) | `oauth.flow` (CWE-601/287/352) |
| Open redirect (15) | `redirect.open` |
| CSRF (15) | `csrf.state_change` (CWE-352) |
| Race / TOCTOU (11+6) | `race.condition` (CWE-362/367) |
| Path traversal (9) | `path.traversal` (CWE-22) |
| Access control / privesc (7) | `access_control.idor` / `.privesc` |
| XXE (6) | `xxe.probe` (CWE-611) |
| Business logic (6) | `business_logic.scan` (CWE-840) |
| Auth bypass / ATO (6+4) | `auth.takeover` (CWE-287) |
| SQLi (5) | `sqli.probe` + ToolSpec `sqli.sqlmap` |
| Cache poisoning / proto-pollution / cmdi / NoSQL / SSTI / smuggling / header-inj | oracles natifs dédiés |
| Info-disclosure / hard-coded creds (17+6) | `framework.exposure` + `recon.secrets` / `recon.js_endpoints` |
| **DoS (13) · memory-safety native (systemd/BIND9/PowerDNS)** | **EXCLU PAR DESIGN** (voir §4) |

## 2. Scripts `toolkit/` → couverture Forge

- **`toolkit/web/` + `toolkit/oauth/`** (~40 scripts, la vraie surface de chasse) : **~95 % NATIF** (1:1 avec un `kind` Forge), le reste = extension **drop-in plugin** d'un kind existant. Zéro bespoke.
- **Recon / scanners** (`nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder`, `nikto`, `dalfox`, `testssl`, `wafw00f`, `masscan`, `gobuster`, `theHarvester`, `wfuzz`, `ZAP`…) : **catalogue ToolSpec (20 binaires)** + kinds recon natifs. Tout CLI manquant = **une ligne de ToolSpec / un fichier JSON** (`FORGE_TOOLSPECS`).
- **Connecteurs** : Metasploit (`msf.module`) + Burp (`burp.scan`) live.
- **Long tail** (enum framework-spécifiques : spring-actuator, laravel, nextjs, checks OIDC session-fixation…) : **drop-in plugin** — un `@register` déposé dans `forge/modules/` (auto-découvert) ou un `FORGE_PLUGINS` — passe le même gate `roe.decide`, aucun changement du core.

## 3. Trois façons d'ajouter ce qui manque (rappel)
1. **ToolSpec** (`toolcatalog.py` ou `FORGE_TOOLSPECS=*.json/yaml`) — wrapper CLI gouverné, zéro Python.
2. **Drop-in plugin** (`forge/modules/x.py` `@register`, ou `FORGE_PLUGINS=/dir`) — porter un script `toolkit/` en module gouverné.
3. **Module natif** — pour une logique/oracle bespoke.
Dans les trois cas, le module hérite du **scope-guard fail-closed + discipline de preuve + ledger** — un outil ajouté ne peut pas tirer hors-scope ni s'auto-promouvoir en `vulnerable`.

## 4. Hors-scope PAR DESIGN (pas des lacunes)
Refusés explicitement (`toolcatalog.py:29-30`, exploit-floor, cap 50-mots `tokenapi.py:111`) :
- **Cred-cracking / brute-force** : hydra, hashcat, john, medusa (`crack_hashes.sh`, `ssh_bruteforce.sh`, `brute.py`).
- **DoS / resource-exhaustion / packet-fuzz** : DNS fuzzers, PowerDNS/BIND9/systemd DoS findings.
- **Memory-safety native / kernel / boot** : systemd stub underflow, D-Bus fuzzers, libfuzzer harness.
- **Spoofing LAN / rogue-server** : LLMNR/mDNS poison, serveurs malicieux.
- **Forensics / CTF / post-ex local / meta-tooling bounty** (`ywh_*`, `h1_gate`, `cve_analyzer`, stego).

Forge est un **orchestrateur d'app distante gouverné** : ce qu'il ne fait pas est précisément ce qu'il a été conçu pour refuser. La finding PowerDNS-DoS, par ex., ne pourrait jamais être une cible Forge.

## 5. Note gouvernance
Reproduire une finding avec Forge = lancer la technique contre la **cible in-scope autorisée** (fail-closed `_scopeguard`) — soit exactement le workflow bug-bounty (SCOPE.md → engagement). La gouvernance qui rend Forge sûr est celle qu'un programme YWH impose déjà.

---
*Base de preuve : 75 kinds natifs (`grep @register forge/modules`), 20 ToolSpec (`toolcatalog.py`), 2 connecteurs, taxonomie `techniques_data.py` (38 kinds CWE-mappés) ; FAISS `list_tools()`/`get_stats()` + `programs/*/FINDINGS.md`.*
