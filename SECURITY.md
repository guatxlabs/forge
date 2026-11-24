# Security policy

[English](SECURITY.md) | [Français](SECURITY.fr.md)

Forge is a **governed** offensive security engine: its whole value proposition rests on
attacks being unable to fire outside an authorized scope and on every action
being provable. A defect in that governance is a serious bug, and we want to
hear about it.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately, through either channel:

1. **GitHub Security Advisories** *(preferred)* — the "Report a vulnerability" button in
   this repository's **Security** tab. It keeps the report, the discussion and the fix
   coordinated and private end to end, and lets us credit you at disclosure.
2. **E-mail** — `security@guatx.com`, if you prefer not to use a GitHub account, or if the
   problem concerns the repository itself.

Please use one of these channels rather than a public issue, a pull request or a direct
message.

Please include: the affected version/commit, a description, the reproduction steps or a
PoC, and the impact. GitHub Security Advisories are private end to end, so no additional
encryption is needed.

We aim for an **acknowledgement within 3 business days** and an agreement with you on a remediation
timeline. We practice **coordinated disclosure** and will credit you (unless you
prefer to remain anonymous) once a fix is published.

## What is in scope

A security bug in Forge is anything that lets an action escape the safety model, or
that leaks data/secrets. In particular:

- **Scope-guard / ROE bypass** — an action that fires against a target outside
  `in_scope`, or an `exploit`/`destructive` action that fires without the corresponding `allow_*`
  authorization.
- **Ledger integrity** — forging, reordering, truncating or downgrading a signed engagement
  ledger entry such that `verify()` still passes.
- **Tenant / engagement isolation** — reading the findings/data of another engagement or tenant
  (e.g. via the GXQL surface) under the multi-tenant module (flag-gated).
- **Secret leak** — operator session credentials, API keys or signing
  keys escaping into a finding, the ledger, a report, a log or an API response.
- **AuthN/AuthZ** — console authentication bypass, privilege escalation, cross-tenant
  IDOR.
- **Injection / RCE** in the engine or the console (command, SQL, path traversal, deserialization).
- **Capability widening through config** — a scope field, a `module_param`, a plugin or
  a resource profile that grants a capability the operator did not authorize.

## What is NOT a vulnerability

- **Using Forge against a target you are not authorized to test.** Forge enforces *and
  proves* authorization; it does not grant it, and cannot. Misuse is the
  operator's responsibility.
- **Getting past a WAF/Cloudflare/anti-bot.** It is an access enabler, not a vulnerability —
  see the README.
- **The documented and accepted limits** of the default deployment (e.g. host-root access to a
  co-located ledger signing key — see [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md) — or
  detection collectors that fail *open* on a measurement error). These are
  deployment-hardening trade-offs, documented with their opt-in mitigations. Only
  report them if you can defeat the mitigation or demonstrate a *new* impact.

## Supported versions

Forge is pre-1.0 and has **no tagged release yet**. Security fixes
land on `main`, the only thing maintained, so please cite a `main` commit in your
report.

| Version | Supported |
|---------|-----------|
| `main` | ✅ |
| tagged releases | none exist yet |

This section will name the supported versions once tags exist — not before. Announcing
per-version support while no version exists would be a false promise, and would send
the reporter looking for a release number that cannot be found.

## Hardening & audits

Forge ships a documented security model ([`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md),
[`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md)) and a CI pipeline that runs `cargo audit` and secret
scanning. The core safety controls (scope-guard, 4-layer ROE gate, tamper-evident ledger,
coverage-safe planner) are covered by tests. An internal adversarial review of the codebase was
carried out and the problems it identified were fixed before publication.
