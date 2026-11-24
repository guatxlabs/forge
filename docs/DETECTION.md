# Detection source — plug in ANY BLUE infrastructure (no code)

[English](DETECTION.md) | [Français](DETECTION.fr.md)

> 🧭 [Forge documentation](README.md) · See also: [Concepts: purple loop](CONCEPTS.md#5-the-purple-loop) ·
> [Administration](ADMINISTRATION.md#2-detection-source) · [Plume prerequisites](PURPLE_PREREQS.md)

Forge's **purple** loop correlates the ATT&CK techniques **fired** by the red team (run-records) with the
techniques **detected** by the SOC/IDS/firewall, by **equality of MITRE identifier** — then derives
`detected` (exact) / `parent_approx` (sub-technique fired, only the parent covered) / `missed` /
**MTTD** from it. The *correlation* is infrastructure-neutral and **never changes**. Only the detection
**SOURCE** is specific to each client: it is a **configurable plugin**, described by a
JSON object, editable **in the UI** (first-deployment wizard or the Administration → « Source de
détection » (*Detection source*) panel) — **no code to write**.

> Plume is **only one preset among others** (`kind=plume`). CrowdSec, FortiGate, pfSense/OPNsense,
> Elastic/OpenSearch, a JSONL file or a custom command are wired the same way.

## Readable fail-open contract (safety invariant)

- An **absent** or **unreachable / misconfigured** source ⇒ `source_reachable:false`: Forge declares the
  measurement **impossible** and **NEVER invents** `detected` / `parent_approx` / `missed` / `MTTD`.
- A **reachable but empty** source (fresh SOC, nothing detected) is a **valid** state (`reachable:true`,
  `detections:[]`).
- The authentication **secret** (API key / SIEM token) is **write-only**: never returned by a GET,
  never logged, never written to the ledger (treated as a session secret, redacted in depth).
- **It is also encrypted AT REST** (`FORGE_FIELD_KEY`, default build): `settings.detection_source`
  no longer carries the token in plaintext. Without a field key, the write is refused (**503** `field_key_missing`)
  and collection **refuses to start** with a named reason — rather than querying the source **without
  authentication** and getting a 401 diagnosed as a SIEM outage. An existing database is
  converted **at boot**, in place; any plaintext left for lack of a key is **counted and announced**.
- **A token never goes out in plaintext to a PUBLIC source.** Rule **shared** with the notification
  channel (`net::reject_cleartext_secret`) — see the breaking-change note below.

## The `DetectionSource` model

Stored in `settings.detection_source` (written by the wizard or `POST /api/detection/source`, admin +
written to the ledger). JSON object:

```jsonc
{
  "kind": "generic_http",          // transport/parser plugin (closed list, see below)
  "endpoint": "http://siem:9200/idx/_search",  // URL (http kinds) OR file path (file/syslog)
  "auth": { "type": "bearer", "secret": "…", "header": "X-Api-Key" },  // WRITE-ONLY secret
  "query": "since={since}",        // string ({since}=epoch substituted) OR JSON body (elastic/opensearch)
  "mapping": { … },                // native NORMALISATION -> {mitre, ts} (see "MITRE mapping")
  "timeout": 8, "insecure_tls": false, "max_lines": 200000            // optional settings
}
```

| Field | Role |
|-------|------|
| `kind` | `none · plume · generic_http · crowdsec · elastic · opensearch · fortigate_syslog · pfsense · opnsense · file_jsonl · exec` |
| `endpoint` | http(s) URL (http kinds) **or** file path (`file_jsonl`, syslog in file mode). `path` accepted as an alias. |
| `auth.type` | `none · basic · bearer · api_key_header · mtls` (`mtls` = transport, via a kind delegated to the Python collector). |
| `auth.secret` | **[SECRET, write-only]** Basic = `base64("user:pass")` · Bearer = token · api_key_header = header value. |
| `auth.header` | header name for `api_key_header` (default `X-API-Key`). |
| `query` | HTTP: query string (`{since}` substituted); Elastic/OpenSearch: **JSON body** (dict). |
| `mapping` | normalisation rules towards MITRE (see below). |

### Where it runs

- The `plume` / `generic_http` kinds are queried **natively by the Rust console** (built-in fetcher,
  unchanged MITRE join), over **`http://` as well as `https://`**: the transport comes from the **TLS seam**
  (`console/src/tls.rs`), with a **verified** certificate (chain + host name + validity; a **private
  enterprise CA** is supplied via `FORGE_EXTRA_CA_PEM`). An `https` source therefore no longer triggers a Python
  spawn on a **read** route.

> ⚠️ **NAMED BREAKING CHANGE — a source secret no longer goes out in plaintext to a PUBLIC target.** The fetcher
> had **no** guard of this kind: a `generic_http`/`plume` source over **`http://`** towards a
> **public** address, with an `auth.secret`, put its `Authorization:` header **on the wire**. This is
> now **refused before connecting**, by the same rule as the notification channel, and **no**
> environment variable opens it. Fixes: switch the source to **`https://`** (a private CA is
> supplied via `FORGE_EXTRA_CA_PEM`), or remove the secret.
>
> **What has NOT changed, deliberately**: `http://` **+ secret** towards an authorised **internal**
> collector (`FORGE_ALLOW_INTERNAL_INTEGRATIONS=1`) is still **served**. This is the reference on-prem
> deployment (`PLUME_URL`/`PLUME_TOKEN` on a private segment). Requiring `https://` as soon as a secret is set
> would have killed this use without relocating it: an enterprise CA provides an **anchor**, not a **TLS
> listener** — a collector that exposes none would have had no path left.
- Everything else — **CrowdSec, Elastic/OpenSearch, syslog/filterlog, file, exec, or `auth.type=mtls`**
  (the seam can now present a client certificate, but that identity is the **PROCESS**'s,
  not the source's: two sources requiring two distinct certificates cannot be represented) — is
  **delegated to the Python collector** `forge.collectors`
  (rich protocols/parsing),
  invoked by the console (`python3 -m forge.cli detections --since N --source env:FORGE_DETECTION_SOURCE`).
  The console remains an infrastructure-neutral **joiner**: the output of any kind is normalised into
  `[{mitre,count,first_ts}]` then passed to the **same** correlation.

## MITRE mapping — the only thing to map

Most BLUE infrastructures **do NOT speak MITRE natively**: they emit *scenarios*, *rule
names*, *log lines*. The `mapping` turns these native signals into techniques. A technique is **never
guessed**: an unmapped signature is **ignored** (no false detected/missed).

Three modes (the UI editor offers "signature → technique" rows; the advanced JSON gives full
control):

1. **Table** (untagged native infrastructure) — `mapping.table` = `{signature_native → "Txxxx"}`, the signature
   being read from the `mapping.field` field. CrowdSec example: `field:"scenario"`, `table:{"crowdsecurity/ssh-bf":"T1110"}`.
2. **Direct** (already tagged SIEM) — `mapping.mitre` = dotted path to a field that already carries the `Txxxx`
   (Elastic example: `"_source.signal.rule.threat.technique.id"`). No table needed.
3. **Regex rules** (syslog/filterlog) — `mapping.rules` = `[{match:"<regex>", mitre:"Txxxx"}]`. A named
   group `(?P<ts>…)` provides the `first_ts` (epoch) if present.

Common options: `mapping.records` (dotted path to the event array — default: root, otherwise
`detections`/`results`, otherwise `hits.hits` for ES) · `mapping.ts` (timestamp field, default `first_ts`)
· `mapping.count` (optional; absent ⇒ 1 per record).

## Per-infrastructure presets

### `plume` — the historical preset (backward compatibility)

Plume contract: `GET {endpoint}/api/coverage/detections?since=N` → `{"detections":[{mitre,count,first_ts}]}`,
**Basic auth**, **identity mapping** (no mapping required). Queried natively by the console.

```json
{ "kind": "plume", "endpoint": "http://plume-internal:PORT",
  "auth": { "type": "basic", "secret": "BASE64_user_colon_pass" } }
```

**Env backward compatibility**: `PLUME_URL` + `PLUME_TOKEN` remain supported — when there is no
`settings.detection_source`, they are interpreted as this exact preset
(`{kind:plume, endpoint:PLUME_URL, auth:{type:basic, secret:PLUME_TOKEN}}`). See `docs/PURPLE_PREREQS.md`.

### `crowdsec` — LAPI

`GET {endpoint}/v1/decisions` (or `/v1/alerts`), `X-Api-Key` header. CrowdSec emits **scenarios**:
scenario → technique `mapping.table` **REQUIRED**.

```json
{ "kind": "crowdsec", "endpoint": "http://127.0.0.1:8080", "path": "/v1/decisions",
  "auth": { "type": "api_key_header", "header": "X-Api-Key", "secret": "<clé LAPI>" },
  "mapping": { "field": "scenario", "ts": "created_at",
               "table": { "crowdsecurity/ssh-bf": "T1110", "crowdsecurity/http-probing": "T1595.002" } } }
```

### `fortigate_syslog` — text syslog

Path to a materialised syslog file (`endpoint`/`path`). Regex → technique rules **REQUIRED**.

```json
{ "kind": "fortigate_syslog", "endpoint": "/var/log/fortigate.log",
  "mapping": { "rules": [
    { "match": "attack=\"?SSH\\.Brute", "mitre": "T1110" },
    { "match": "logdesc=\"?Port scan", "mitre": "T1046" } ] } }
```

### `pfsense` / `opnsense` — filterlog (or REST)

**File** mode (filterlog): like FortiGate (`endpoint` = path, `mapping.rules`). **REST** mode:
http(s) `endpoint` exposing JSON (driven by `mapping.records/mitre/table`).

```json
{ "kind": "opnsense", "endpoint": "/var/log/filter/latest.log",
  "mapping": { "rules": [ { "match": "\\bblock\\b.* proto TCP.* SYN", "mitre": "T1046" } ] } }
```

### `elastic` / `opensearch` — `_search`

`POST {endpoint}` (`_search` URL of a detections index), `query` body (dict) — otherwise a default
range on `@timestamp >= since`. Hits read from `hits.hits`; `mapping` paths targeting `_source.*`.

```json
{ "kind": "elastic", "endpoint": "https://es:9200/detections-*/_search",
  "auth": { "type": "api_key_header", "header": "Authorization", "secret": "ApiKey <base64>" },
  "query": { "size": 1000, "query": { "range": { "@timestamp": { "gte": "now-24h" } } } },
  "mapping": { "records": "hits.hits", "mitre": "_source.signal.rule.threat.technique.id",
               "ts": "_source.@timestamp" } }
```

### `file_jsonl` — file export/tap

One line = one native JSON object; normalised by `mapping` (table/field or direct `mitre`). Useful for a
SIEM export, a custom tap, a fixture.

```json
{ "kind": "file_jsonl", "endpoint": "/var/spool/forge/detections.jsonl",
  "mapping": { "field": "rule_name", "ts": "@timestamp",
               "table": { "SSH brute force": "T1110" } } }
```

### `exec` — trusted command (admin only)

Runs a **fixed argv** (no shell, hard timeout, minimal allowlisted env — the secret is
**never** propagated to the child process) that prints JSON events on stdout, then normalises via
`mapping`. For infrastructures without a standard transport.

```json
{ "kind": "exec", "cmd": ["/opt/soc/pull.sh", "--json", "--since", "{since}"],
  "mapping": { "field": "signature", "table": { "port-scan": "T1046" } } }
```

## Test & save

- **Test**: `POST /api/detection/test` (admin) runs a **single** collection against the supplied
  config and returns `{reachable, count, sample_mitres, error?}` — **never** the secret. The
  *Test connection* button of the admin panel (and the write-only field) use it; `keep_secret:true`
  lets you test an edited config **without re-entering** the secret already set.
- **Save**: `POST /api/detection/source` (admin, **written to the ledger** as `console.detection.source.set`)
  persists `settings.detection_source` and hot-reloads the source. `GET /api/detection/source`
  returns the config with the **secret redacted** + `secret_set`.
- **Offline diagnosis**: `python3 -m forge.cli doctor` includes a health line for the source, and
  `python3 -m forge.cli detections --source <spec> --since N` prints `{"detections":[…]}` (see the CLI).

## CLI / env

The Python collector reads its config via `--source`: `env:NOM` (**preferred path** — the console puts the
JSON *with* the secret there so as not to leak it via `argv`/`ps`), `@fichier`, or literal JSON.

```bash
# diagnose a source (never prints the secret)
FORGE_DETECTION_SOURCE='{"kind":"crowdsec","endpoint":"http://127.0.0.1:8080", …}' \
  python3 -m forge.cli detections --source env:FORGE_DETECTION_SOURCE --since 0
```
