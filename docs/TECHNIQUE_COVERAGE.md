# Forge — Couverture des techniques (vs un arsenal de scripts maison)

> **Question traitée** : les techniques que l'on teste habituellement à la main, avec un dossier de
> scripts one-off et un catalogue d'outils CLI, sont-elles reproductibles dans Forge — sous
> gouvernance et avec discipline de preuve ?
>
> **Verdict** : pour l'usage gouverné et orienté-preuve que Forge cible — **oui, la quasi-totalité
> est reproductible aujourd'hui**. Les seuls non-couverts sont exactement ce que Forge **exclut par
> design** (DoS, cred-cracking, memory-safety native/kernel, spoofing LAN, forensics) — ce ne sont
> pas des lacunes.

## 1. Techniques de findings web → oracle Forge

**100 % des techniques *web* courantes mappent à un oracle natif avec discipline de preuve :**

| Technique | Oracle Forge natif |
|---|---|
| IDOR | `access_control.idor` (CWE-639, preuve cross-compte) |
| CORS | `cors.credentials` (CWE-942) |
| GraphQL authz | `graphql.access` |
| XSS | `xss.reflected` / `xss.stored` (CWE-79) |
| JWT | `jwt.weakness` (CWE-347) |
| SSRF | `ssrf.callback` / `ssrf.xspa` / `ssrf.cloud_metadata` (CWE-918, callback-confirmé) |
| Subdomain takeover | `subdomain.takeover` (CWE-350) |
| OAuth/OIDC | `oauth.flow` (CWE-601/287/352) |
| Open redirect | `redirect.open` |
| CSRF | `csrf.state_change` (CWE-352) |
| Race / TOCTOU | `race.condition` (CWE-362/367) |
| Path traversal | `path.traversal` (CWE-22) |
| Access control / privesc | `access_control.idor` / `.privesc` |
| XXE | `xxe.probe` (CWE-611) |
| Business logic | `business_logic.scan` (CWE-840) |
| Auth bypass / ATO | `auth.takeover` (CWE-287) |
| SQLi | `sqli.probe` + ToolSpec `sqli.sqlmap` |
| Cache poisoning / proto-pollution / cmdi / NoSQL / SSTI / smuggling / header-inj | oracles natifs dédiés |
| Info-disclosure / hard-coded creds | `framework.exposure` + `recon.secrets` / `recon.js_endpoints` |
| **DoS · memory-safety native (services système, résolveurs DNS…)** | **EXCLU PAR DESIGN** (voir §4) |

## 2. Scripts one-off → couverture Forge

- **Testeurs web / OAuth** (le gros de la surface de chasse) : la très grande majorité est **NATIVE**
  (1:1 avec un `kind` Forge) ; le reste est une extension **drop-in plugin** d'un kind existant.
  Zéro bespoke.
- **Recon / scanners** (`nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder`, `nikto`, `dalfox`, `testssl`,
  `wafw00f`, `gobuster`, `dnsx`, `naabu`, `wfuzz`, `ZAP`…) : **catalogue ToolSpec** + kinds recon
  natifs. Tout CLI manquant = **une ligne de ToolSpec / un fichier JSON**
  (`FORGE_TOOLSPECS`).
- **Connecteurs** : Metasploit (`msf.module`) + Burp (`burp.scan`) live.
- **Long tail** (enum framework-spécifiques : spring-actuator, laravel, nextjs, checks OIDC
  session-fixation…) : **drop-in plugin** — un `@register` déposé dans `forge/modules/`
  (auto-découvert) ou un `FORGE_PLUGINS` — passe le même gate `roe.decide`, aucun changement du core.

## 3. Trois façons d'ajouter ce qui manque (rappel)
1. **ToolSpec** (`toolcatalog.py` ou `FORGE_TOOLSPECS=*.json/yaml`) — wrapper CLI gouverné, zéro Python.
2. **Drop-in plugin** (`forge/modules/x.py` `@register`, ou `FORGE_PLUGINS=/dir`) — porter un script
   one-off en module gouverné.
3. **Module natif** — pour une logique/oracle bespoke.
Dans les trois cas, le module hérite du **scope-guard fail-closed + discipline de preuve + ledger** — un
outil ajouté ne peut pas tirer hors-scope ni s'auto-promouvoir en `vulnerable`.

## 4. Hors-scope PAR DESIGN (pas des lacunes)
Refusés explicitement (`toolcatalog.py`, exploit-floor, cap de mots de `tokenapi.py`) :
- **Cred-cracking / brute-force** : hydra, hashcat, john, medusa.
- **DoS / resource-exhaustion / packet-fuzz** : fuzzers DNS, épuisement de ressources.
- **Memory-safety native / kernel / boot** : underflow d'un stub de boot, fuzzers d'IPC, harness libfuzzer.
- **Spoofing LAN / rogue-server** : poison LLMNR/mDNS, serveurs malicieux.
- **Forensics / CTF / post-ex local / méta-outillage de programme** (gestion de rapports, analyse de
  CVE, stéganographie).

Forge est un **orchestrateur d'app distante gouverné** : ce qu'il ne fait pas est précisément ce qu'il
a été conçu pour refuser. Un déni de service sur un service système, par exemple, ne pourrait jamais
être une cible Forge.

## 5. Note gouvernance
Reproduire une finding avec Forge = lancer la technique contre la **cible in-scope autorisée**
(fail-closed `_scopeguard`) — soit exactement le workflow attendu d'un programme de bug bounty ou
d'un pentest sous contrat (périmètre écrit → engagement). La gouvernance qui rend Forge sûr est celle
que ces cadres imposent déjà.

---
*Base de preuve : 75 kinds natifs (`grep @register forge/modules`), 20 ToolSpec (`toolcatalog.py`),
2 connecteurs, taxonomie `techniques_data.py` (38 kinds CWE-mappés).*
