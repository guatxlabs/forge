# Security Policy

Forge is a **governed** offensive-security engine: its entire value proposition is that
attacks cannot fire outside an authorized scope and that every action is provable. A flaw
in that governance is a serious bug, and we want to hear about it.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately, via either channel:

1. **GitHub Security Advisories** *(preferred)* — the "Report a vulnerability" button on this
   repository's **Security** tab. It keeps the report, the discussion and the fix coordinated and
   private end-to-end, and lets us credit you on disclosure.
2. **Email** — `security@guatx.com`, if you would rather not use a GitHub account, or if the issue
   concerns the repository itself.

Please use one of these rather than a public issue, a pull request, or a direct message.

Please include: affected version/commit, a description, reproduction steps or a PoC, and the
impact. GitHub Security Advisories are private end-to-end, so no additional encryption is needed.

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
  (e.g. via the GXQL surface) under the enterprise tenancy model.
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
- **The documented, accepted limits** of the default deployment (e.g. host-root access to a
  co-located ledger signing key — see [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md) — or detection
  collectors that fail *open* on a measurement error). These are deployment-hardening trade-offs,
  documented with their opt-in mitigations. Report them only if you can defeat the mitigation or
  show a *new* impact.

## Supported versions

Forge is pre-1.0 and has **no tagged release yet**. Security fixes land on `main`, which is the
only thing maintained, so please cite a `main` commit when you report.

| Version | Supported |
|---------|-----------|
| `main` | ✅ |
| tagged releases | none exist yet |

This section will name supported versions once tags exist — not before. Announcing per-version
support while no version exists would be a false promise, and would send a reporter looking for a
release number they cannot find.

## Hardening & audits

Forge ships a documented security model ([`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md),
[`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md)) and a CI pipeline that runs `cargo audit` and secret
scanning. The core safety controls (scope-guard, 4-layer ROE gate, tamper-evident ledger,
coverage-safe planner) are covered by tests. An internal adversarial review of the codebase was
carried out and the issues it identified were fixed before release.
