# Forge — Technique coverage (vs an arsenal of home-made scripts)

[English](TECHNIQUE_COVERAGE.md) | [Français](TECHNIQUE_COVERAGE.fr.md)

> **Question addressed**: are the techniques usually tested by hand, with a folder of
> one-off scripts and a catalogue of CLI tools, reproducible in Forge — under
> governance and with evidence discipline?
>
> **Verdict**: for the governed, evidence-oriented use that Forge targets — **yes, nearly all of them
> are reproducible today**. The only ones not covered are exactly what Forge **excludes by
> design** (DoS, cred-cracking, native/kernel memory-safety, LAN spoofing, forensics) — these are
> not gaps.

## 1. Web finding techniques → Forge oracle

**100 % of common *web* techniques map to a native oracle with evidence discipline:**

| Technique | Native Forge oracle |
|---|---|
| IDOR | `access_control.idor` (CWE-639, cross-account evidence) |
| CORS | `cors.credentials` (CWE-942) |
| GraphQL authz | `graphql.access` |
| XSS | `xss.reflected` / `xss.stored` (CWE-79) |
| JWT | `jwt.weakness` (CWE-347) |
| SSRF | `ssrf.callback` / `ssrf.xspa` / `ssrf.cloud_metadata` (CWE-918, callback-confirmed) |
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
| Cache poisoning / proto-pollution / cmdi / NoSQL / SSTI / smuggling / header-inj | dedicated native oracles |
| Info-disclosure / hard-coded creds | `framework.exposure` + `recon.secrets` / `recon.js_endpoints` |
| **DoS · native memory-safety (system services, DNS resolvers…)** | **EXCLUDED BY DESIGN** (see §4) |

## 2. One-off scripts → Forge coverage

- **Web / OAuth testers** (the bulk of the hunting surface): the vast majority is **NATIVE**
  (1:1 with a Forge `kind`); the rest is a **drop-in plugin** extension of an existing kind.
  Zero bespoke.
- **Recon / scanners** (`nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder`, `nikto`, `dalfox`, `testssl`,
  `wafw00f`, `gobuster`, `dnsx`, `naabu`, `wfuzz`, `ZAP`…): **ToolSpec catalogue** + native recon
  kinds. Any missing CLI = **one ToolSpec line / one JSON file**
  (`FORGE_TOOLSPECS`).
- **Connectors**: Metasploit (`msf.module`) + Burp (`burp.scan`) live.
- **Long tail** (framework-specific enumeration: spring-actuator, laravel, nextjs, OIDC
  session-fixation checks…): **drop-in plugin** — a `@register` dropped into `forge/modules/`
  (auto-discovered) or a `FORGE_PLUGINS` — goes through the same `roe.decide` gate, no change to the core.

## 3. Three ways to add what is missing (reminder)
1. **ToolSpec** (`toolcatalog.py` or `FORGE_TOOLSPECS=*.json/yaml`) — governed CLI wrapper, zero Python.
2. **Drop-in plugin** (`forge/modules/x.py` `@register`, or `FORGE_PLUGINS=/dir`) — port a one-off
   script into a governed module.
3. **Native module** — for bespoke logic/oracle.
In all three cases, the module inherits the **fail-closed scope-guard + evidence discipline + ledger** — an
added tool cannot fire out of scope nor self-promote to `vulnerable`.

## 4. Out of scope BY DESIGN (not gaps)
Explicitly refused (`toolcatalog.py`, exploit-floor, word cap of `tokenapi.py`):
- **Cred-cracking / brute-force**: hydra, hashcat, john, medusa.
- **DoS / resource-exhaustion / packet-fuzz**: DNS fuzzers, resource exhaustion.
- **Native memory-safety / kernel / boot**: underflow in a boot stub, IPC fuzzers, libfuzzer harnesses.
- **LAN spoofing / rogue-server**: LLMNR/mDNS poisoning, malicious servers.
- **Forensics / CTF / local post-ex / program meta-tooling** (report management, CVE
  analysis, steganography).

Forge is a **governed remote-application orchestrator**: what it does not do is precisely what it
was designed to refuse. A denial of service on a system service, for example, could never
be a Forge target.

## 5. Governance note
Reproducing a finding with Forge = running the technique against the **authorised in-scope target**
(fail-closed `_scopeguard`) — which is exactly the workflow expected by a bug bounty programme or
a contracted pentest (written scope → engagement). The governance that makes Forge safe is the one
these frameworks already impose.

---
*Evidence base (MEASURED on 2026-11-24): 69 native kinds (`git grep -E '^\s*@register\(' forge/modules`) and 19 ToolSpecs
(`CATALOG_SPECS` in `toolcatalog.py`), i.e. the 88 modules of the registry,
2 connectors, `techniques_data.py` taxonomy (38 CWE-mapped kinds).*
