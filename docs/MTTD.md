# MTTD — what the metric measures (and does NOT measure)

[English](MTTD.md) | [Français](MTTD.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Concepts: purple loop](CONCEPTS.md#5-the-purple-loop) · [Plume prerequisites](PURPLE_PREREQS.md)

## TL;DR

The MTTD reported by Forge is a **time-to-ALERT**, not a **time-to-event**. It includes the
**Plume rule evaluation** latency (`interval_s`, default ~300 s) + the **log ingest** latency
(journald → Plume). The observed MTTDs (e.g. **352 s**, **623 s**) therefore largely reflect
the evaluation interval of the tested rules, and **must not be over-interpreted** as the
"raw" reaction time of the SOC.

## How the MTTD is computed

The console performs the purple JOIN (`console/src/main.rs`, coverage function):

```
MTTD(technique T) = first_detection_ts(T) − last_fire_ts(T)     (en secondes, tronqué à 0 si négatif)
```

- `last_fire_ts(T)` = timestamp of the most recent **red shot** for technique T (Forge side,
  `ts` field of the run-records).
- `first_detection_ts(T)` = `first_ts` returned by Plume (`GET {PLUME_URL}/api/coverage/detections`),
  i.e. the **first `alert.ts`** aggregated for this `mitre`.

The key point: `first_detection_ts` is the timestamp of an **ALERT**, not of the underlying **event**.

## Why it is a time-to-ALERT, not a time-to-event

A Plume alert only exists **after**:

1. **Ingest** — the event (journald / syslog of the tested host) is ingested by Plume. Non-zero
   collection/transport latency.
2. **Rule evaluation** — the associated Plume rule runs. Rules run **on an
   interval** (`interval_s`, default ~300 s), not continuously: an event that arrives just after an
   evaluation cycle waits ~until the next cycle before producing an alert.

So, for a technique detected by an interval rule:

```
MTTD ≈ latence_ingest + (temps jusqu'au prochain cycle d'évaluation) + temps_de_règle
     ≈ latence_ingest + [0 … interval_s]   (en moyenne ~interval_s/2, au pire ~interval_s)
```

With `interval_s ≈ 300 s`, an observed MTTD of **352 s** or **623 s** is consistent with
**1× to 2× the interval** + ingest — that is, dominated by the rule evaluation cadence,
not by a "real" detection slowness. Detection itself (the matching) is near-instantaneous;
what is measured is mostly **when the rule looked**.

## Consequence: do not over-interpret

- An MTTD of a few hundred seconds **does not indicate** a slow SOC: it mostly indicates
  the `interval_s` of the rules concerned. Comparing MTTDs across techniques only makes sense if
  the `interval_s` of each rule is known (two rules with different intervals are not
  directly comparable).
- The MTTD is **bounded from below** by the rule interval: a time-to-alert finer than the
  evaluation cadence cannot be measured, even if the logical detection is immediate.
- The JOIN stays **read-only** and the console **never fabricates** an MTTD (if Plume is
  unreachable/unreadable → `plume_reachable:false`, MTTD `null`, never invented). The metric is
  faithful; it is its **interpretation** that needs the `interval_s` context.

## Recommendations

1. **Document the `interval_s` of the tested rules** next to each MTTD in the purple report
   (without this data, an MTTD alone is ambiguous: slow detection vs mere interval cadence).
2. **For a finer MTTD**, lower the `interval_s` of the rules concerned (the MTTD floor
   then goes down towards the true ingest + matching latency). ⚠️ **Outside Forge's scope**: this is a
   configuration of the detection source, not a setting of this repository.
3. **Synchronised clocks (NTP)** between the Forge host (`ts` of the shot) and Plume (`alert.ts`) — without
   it, `first_detection_ts − last_fire_ts` is biased by the clock offset (cf.
   `PURPLE_PREREQS.md` §6). Truncation to 0 hides a negative offset but not a positive one.
4. **Present the MTTD as a time-to-ALERT** in any client deliverable: state explicitly
   that it covers ingest + rule evaluation cadence, to avoid the "SOC reaction
   time" reading.

## See also

- [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) — Plume prerequisites (`mitre`-tagged rules, endpoint
  `/api/coverage/detections`, NTP) for the MTTD JOIN to work.
- [`PURPLE_CAMPAIGN.md`](PURPLE_CAMPAIGN.md) — broad-recon campaign template that seeds the
  MTTD matrix.
