# Security Policy

Forge is a **governed** offensive-security engine: its entire value proposition is that
attacks cannot fire outside an authorized scope and that every action is provable. A flaw
in that governance is a serious bug, and we want to hear about it.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately, via either channel:

1. **GitHub Security Advisories** — the "Report a vulnerability" button on the repository's
   **Security** tab (preferred; keeps the report and fix coordinated and private).
2. **Email** — `<SECURITY_CONTACT>` *(maintainers: replace with a monitored address, e.g.
   `security@your-domain`, and remove this note before publishing).*

Please include: affected version/commit, a description, reproduction steps or a PoC, and the
impact. Encrypt if you can; we will provide a key on request.

We aim to **acknowledge within 3 business days** and to agree on a remediation timeline with
you. We practise **coordinated disclosure** and will credit you (unless you prefer to remain
anonymous) once a fix is released.

## What is in scope

A security bug in Forge is anything that lets an action escape the safety model, or that leaks
data/secrets. In particular:

- **Scope-guard / ROE bypass** — an action that fires against a target outside `in_scope`, or
  an `exploit`/`destructive` action that fires without the matching `allow_*` authorization.
- **Ledger integrity** — forging, reordering, truncating, or downgrading a signed engagement
  ledger entry so that `verify()` still passes.
- **Tenant / engagement isolation** — reading another engagement's or tenant's findings/data
  (e.g. via the SoQL surface) under the enterprise tenancy model.
- **Secret leakage** — operator session credentials, API keys, or signing keys escaping into a
  finding, the ledger, a report, a log, or an API response.
- **AuthN/AuthZ** — console authentication bypass, privilege escalation, cross-tenant IDOR.
- **Injection / RCE** in the engine or the console (command, SQL, path traversal, deserialization).
- **Capability widening via config** — a scope field, `module_param`, plugin, or resource
  profile granting a capability the operator did not authorize.

## What is NOT a vulnerability

- **Using Forge against a target you are not authorized to test.** Forge enforces *and proves*
  authorization; it does not, and cannot, grant it. Misuse is the operator's responsibility.
- **Passing a WAF/Cloudflare/anti-bot.** That is an access enabler, not a vulnerability — see the
  README.
- **The documented, accepted residuals** in [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md)
  (e.g. host-root access to a co-located ledger signing key, collectors that fail *open* on a
  measurement error). These are deployment-hardening trade-offs, documented with their opt-in
  mitigations. Report them only if you can defeat the mitigation or show a *new* impact.

## Supported versions

Forge is pre-1.0. Security fixes land on `main` and in the latest tagged release. Older tags are
not maintained; please upgrade.

| Version | Supported |
|---------|-----------|
| `main` / latest release | ✅ |
| older tags | ❌ |

## Hardening & audits

Forge ships a documented security model ([`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md),
[`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md)) and a CI pipeline that runs `cargo audit` and secret
scanning. The core safety controls (scope-guard, 4-layer ROE gate, tamper-evident ledger,
coverage-safe planner) are covered by tests and have been adversarially reviewed.
