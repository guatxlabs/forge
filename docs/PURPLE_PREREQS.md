# Plume prerequisites for the Forge purple loop (the moat)

[English](PURPLE_PREREQS.md) | [Français](PURPLE_PREREQS.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Detection sources](DETECTION.md) ·
> [Concepts: purple loop](CONCEPTS.md#5-the-purple-loop) · [MTTD](MTTD.md)

> **Plume is ONE preset (`kind=plume`), not the only option.** The detection source is a **configurable
> plugin**: CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, a JSONL file or a custom
> command are wired **without code** (wizard / *Administration → Detection source*). The full
> `DetectionSource` model and the per-infrastructure presets are in **[`DETECTION.md`](DETECTION.md)**. This
> document only covers the **Plume** preset; `PLUME_URL`/`PLUME_TOKEN` remain supported for
> backward compatibility (interpreted as `kind=plume`).

## The flow, in brief

The Forge console `/api/detection/coverage` (backward-compatible alias `/api/purple/coverage`) reads the
fired run-records (per **technique**, multi-technique tags split), queries the **configured detection
source**, and **JOINs** into three states → detected (exact) / parent_approx / missed /
MTTD. For the Plume preset, the source is `GET {PLUME_URL}/api/coverage/detections`.

## Plume checklist (to do before the "go")

1. **`mitre` field exposed by the detection source**: every **alert** and every **rule** must
   carry an ATT&CK technique, and the field must be **indexed** on the source side (the aggregate in step 2
   is a query by `mitre`). A Plume version that does not expose this field yet must be updated
   before wiring the purple loop.

2. **Exposed endpoint**: `GET /api/coverage/detections?since=<epoch>` →
   `{"detections":[{mitre,count,first_ts},…]}` (aggregate `alert WHERE mitre<>'' GROUP BY mitre`,
   sorted `count DESC`).

3. ⭐ **MITRE-tagged rules** (manual work): `rule.mitre` filled in on the useful rules
   (e.g. brute-force → T1110, port-scan → T1046, web-scan → T1595.002, access → T1190). Otherwise Plume
   detects without `mitre` → matrix = everything "missed" (false gaps).

4. **Active rules + log sources flowing**: Plume ingests the events (journald / syslog)
   of the tested host → a shot triggers the rule → `alert` with an inherited `mitre`.

5. **Reachability + auth from the console**: endpoint under `/api/` → **Basic
   (viewer / editor / admin)** OR a trusted SSO header; agent **Bearer tokens are NOT
   accepted**. Provide a read-only Plume credential + an open network path. (To check during
   wiring: the console must send Basic / SSO, **not** Bearer.)

6. **Synchronised clocks (NTP)**: `ts_fired` (Forge) and `alert.ts` (Plume) consistent for an
   accurate MTTD (MTTD = `first_ts − ts_fired`).

7. **Authorised lab target monitored by Plume**: for the "fire" half, a host inside Plume's
   monitoring scope, authorised to be attacked. ROE / scope stays hard.

## Forge side at the "go"

Configure the **detection source** (Plume preset) — either in the UI (*Administration → Detection
source*, or step 3 of the wizard), or via `PLUME_URL` + `PLUME_TOKEN` (backward compatibility) — confirm the
auth type, launch the 1st ROE-gated lab campaign, produce the live matrix + the report. For any other
infrastructure (CrowdSec, FortiGate, Elastic…), see **[`DETECTION.md`](DETECTION.md)**.

## ⚠️ Safety

- The JOIN is **read-only** (safe).
- Firing techniques = **only** an authorised / scoped target. ROE / scope stays hard.
- **NEVER** fire at unauthorised production, nor at a hijacked detection source (`PLUME_URL`/`settings.detection_source`).
- Source absent/unreachable ⇒ `source_reachable:false`: the measurement is declared **impossible**, never invented.
