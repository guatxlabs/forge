# Source de détection — brancher N'IMPORTE QUELLE infra BLUE (sans code)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Concepts : boucle purple](CONCEPTS.md#5-la-boucle-purple) ·
> [Administration](ADMINISTRATION.md#2-source-de-détection) · [Prérequis Plume](PURPLE_PREREQS.md)

La boucle **purple** de Forge corrèle les techniques ATT&CK **tirées** en red-team (run-records) aux
techniques **détectées** par le SOC/IDS/pare-feu, par **égalité d'identifiant MITRE** — puis en déduit
`detected` / `missed` / **MTTD**. La *corrélation* est infra-neutre et **ne change jamais**. Seule la
**SOURCE** de détection est spécifique à chaque client : c'est un **plugin configurable**, décrit par un
objet JSON, éditable **dans l'UI** (wizard de 1er déploiement ou panneau *Administration → Source de
détection*) — **aucun code à écrire**.

> Plume n'est **qu'un préréglage parmi d'autres** (`kind=plume`). CrowdSec, FortiGate, pfSense/OPNsense,
> Elastic/OpenSearch, un fichier JSONL ou une commande maison se câblent de la même façon.

## Contrat fail-open lisible (invariant de sûreté)

- Une source **absente** ou **injoignable / mal configurée** ⇒ `source_reachable:false` : Forge déclare la
  mesure **impossible** et **n'invente JAMAIS** `detected` / `missed` / `MTTD`.
- Une source **joignable mais vide** (SOC frais, rien détecté) est un état **valide** (`reachable:true`,
  `detections:[]`).
- Le **secret** d'authentification (clé API / token SIEM) est **write-only** : jamais renvoyé par un GET,
  jamais journalisé, jamais ledgerisé (traité comme un secret de session, rédigé en profondeur).

## Le modèle `DetectionSource`

Rangé dans `settings.detection_source` (écrit par le wizard ou `POST /api/detection/source`, admin +
ledgerisé). Objet JSON :

```jsonc
{
  "kind": "generic_http",          // plugin de transport/parseur (liste fermée, cf. ci-dessous)
  "endpoint": "http://siem:9200/idx/_search",  // URL (kinds http) OU chemin de fichier (file/syslog)
  "auth": { "type": "bearer", "secret": "…", "header": "X-Api-Key" },  // secret WRITE-ONLY
  "query": "since={since}",        // chaîne ({since}=epoch substitué) OU corps JSON (elastic/opensearch)
  "mapping": { … },                // NORMALISATION native -> {mitre, ts} (cf. « Mapping MITRE »)
  "timeout": 8, "insecure_tls": false, "max_lines": 200000            // options facultatives
}
```

| Champ | Rôle |
|-------|------|
| `kind` | `none · plume · generic_http · crowdsec · elastic · opensearch · fortigate_syslog · pfsense · opnsense · file_jsonl · exec` |
| `endpoint` | URL http(s) (kinds http) **ou** chemin de fichier (`file_jsonl`, syslog en mode fichier). `path` accepté comme alias. |
| `auth.type` | `none · basic · bearer · api_key_header · mtls` (`mtls` = transport, via un kind délégué au collecteur Python). |
| `auth.secret` | **[SECRET, write-only]** Basic = `base64("user:pass")` · Bearer = token · api_key_header = valeur d'en-tête. |
| `auth.header` | nom d'en-tête pour `api_key_header` (défaut `X-API-Key`). |
| `query` | HTTP : query-string (`{since}` substitué) ; Elastic/OpenSearch : **corps JSON** (dict). |
| `mapping` | règles de normalisation vers MITRE (voir plus bas). |

### Où c'est exécuté

- Les kinds **http en clair** `plume` / `generic_http` sont interrogés **nativement par la console Rust**
  (fetcher intégré, http-only, jointure MITRE inchangée).
- Tout le reste — **CrowdSec, Elastic/OpenSearch, syslog/filterlog, fichier, exec, ou generic_http en
  https/mTLS** — est **délégué au collecteur Python** `forge.collectors` (protocoles/parsing riches),
  invoqué par la console (`python3 -m forge.cli detections --since N --source env:FORGE_DETECTION_SOURCE`).
  La console reste un **joignteur** infra-neutre : la sortie de tout kind est normalisée en
  `[{mitre,count,first_ts}]` puis passée à la **même** corrélation.

## Mapping MITRE — la seule chose à cartographier

La plupart des infras BLUE **ne parlent PAS MITRE nativement** : elles émettent des *scénarios*, des *noms
de règle*, des *lignes de log*. Le `mapping` transforme ces signaux natifs en techniques. On **ne devine
jamais** une technique : une signature non cartographiée est **ignorée** (pas de faux détecté/raté).

Trois modes (l'éditeur de l'UI propose les lignes « signature → technique » ; le JSON avancé donne le
contrôle complet) :

1. **Table** (infra native non taggée) — `mapping.table` = `{signature_native → "Txxxx"}`, la signature
   étant lue au champ `mapping.field`. Ex CrowdSec : `field:"scenario"`, `table:{"crowdsecurity/ssh-bf":"T1110"}`.
2. **Direct** (SIEM déjà taggé) — `mapping.mitre` = chemin pointé d'un champ qui porte déjà le `Txxxx`
   (ex Elastic : `"_source.signal.rule.threat.technique.id"`). Aucune table nécessaire.
3. **Règles regex** (syslog/filterlog) — `mapping.rules` = `[{match:"<regex>", mitre:"Txxxx"}]`. Un groupe
   nommé `(?P<ts>…)` fournit le `first_ts` (epoch) si présent.

Options communes : `mapping.records` (chemin pointé du tableau d'événements — défaut : racine, sinon
`detections`/`results`, sinon `hits.hits` pour ES) · `mapping.ts` (champ horodatage, défaut `first_ts`)
· `mapping.count` (facultatif ; absent ⇒ 1 par enregistrement).

## Préréglages par infra

### `plume` — le préréglage historique (rétro-compat)

Contrat Plume : `GET {endpoint}/api/coverage/detections?since=N` → `{"detections":[{mitre,count,first_ts}]}`,
**Basic auth**, **mapping identité** (aucun mapping requis). Interrogé nativement par la console.

```json
{ "kind": "plume", "endpoint": "http://plume-internal:PORT",
  "auth": { "type": "basic", "secret": "BASE64_user_colon_pass" } }
```

**Rétro-compat env** : `PLUME_URL` + `PLUME_TOKEN` restent supportés — en l'absence de
`settings.detection_source`, ils sont interprétés comme ce préréglage exact
(`{kind:plume, endpoint:PLUME_URL, auth:{type:basic, secret:PLUME_TOKEN}}`). Voir `docs/PURPLE_PREREQS.md`.

### `crowdsec` — LAPI

`GET {endpoint}/v1/decisions` (ou `/v1/alerts`), en-tête `X-Api-Key`. CrowdSec émet des **scénarios** :
`mapping.table` scénario → technique **REQUIS**.

```json
{ "kind": "crowdsec", "endpoint": "http://127.0.0.1:8080", "path": "/v1/decisions",
  "auth": { "type": "api_key_header", "header": "X-Api-Key", "secret": "<clé LAPI>" },
  "mapping": { "field": "scenario", "ts": "created_at",
               "table": { "crowdsecurity/ssh-bf": "T1110", "crowdsecurity/http-probing": "T1595.002" } } }
```

### `fortigate_syslog` — syslog texte

Chemin d'un fichier syslog matérialisé (`endpoint`/`path`). Règles regex → technique **REQUISES**.

```json
{ "kind": "fortigate_syslog", "endpoint": "/var/log/fortigate.log",
  "mapping": { "rules": [
    { "match": "attack=\"?SSH\\.Brute", "mitre": "T1110" },
    { "match": "logdesc=\"?Port scan", "mitre": "T1046" } ] } }
```

### `pfsense` / `opnsense` — filterlog (ou REST)

Mode **fichier** (filterlog) : comme FortiGate (`endpoint` = chemin, `mapping.rules`). Mode **REST** :
`endpoint` http(s) exposant un JSON (piloté par `mapping.records/mitre/table`).

```json
{ "kind": "opnsense", "endpoint": "/var/log/filter/latest.log",
  "mapping": { "rules": [ { "match": "\\bblock\\b.* proto TCP.* SYN", "mitre": "T1046" } ] } }
```

### `elastic` / `opensearch` — `_search`

`POST {endpoint}` (URL `_search` d'un index de détections), corps `query` (dict) — sinon un range
par défaut sur `@timestamp >= since`. Hits lus dans `hits.hits` ; chemins `mapping` visant `_source.*`.

```json
{ "kind": "elastic", "endpoint": "https://es:9200/detections-*/_search",
  "auth": { "type": "api_key_header", "header": "Authorization", "secret": "ApiKey <base64>" },
  "query": { "size": 1000, "query": { "range": { "@timestamp": { "gte": "now-24h" } } } },
  "mapping": { "records": "hits.hits", "mitre": "_source.signal.rule.threat.technique.id",
               "ts": "_source.@timestamp" } }
```

### `file_jsonl` — export/tap fichier

Une ligne = un objet JSON natif ; normalisé par `mapping` (table/champ ou `mitre` direct). Utile pour un
export SIEM, un tap maison, une fixture.

```json
{ "kind": "file_jsonl", "endpoint": "/var/spool/forge/detections.jsonl",
  "mapping": { "field": "rule_name", "ts": "@timestamp",
               "table": { "SSH brute force": "T1110" } } }
```

### `exec` — commande de confiance (admin uniquement)

Exécute un **argv fixe** (aucun shell, timeout dur, env minimal sur liste blanche — le secret n'est
**jamais** propagé au process enfant) qui imprime des événements JSON sur stdout, puis normalise via
`mapping`. Pour les infras sans transport standard.

```json
{ "kind": "exec", "cmd": ["/opt/soc/pull.sh", "--json", "--since", "{since}"],
  "mapping": { "field": "signature", "table": { "port-scan": "T1046" } } }
```

## Tester & enregistrer

- **Tester** : `POST /api/detection/test` (admin) exécute une collecte **unique** contre la config
  fournie et renvoie `{reachable, count, sample_mitres, error?}` — **jamais** le secret. Le bouton
  *Tester la connexion* du panneau admin (et le champ write-only) l'utilisent ; `keep_secret:true`
  permet de tester une config éditée **sans re-saisir** le secret déjà posé.
- **Enregistrer** : `POST /api/detection/source` (admin, **ledgerisé** `console.detection.source.set`)
  persiste `settings.detection_source` et recharge la source à chaud. `GET /api/detection/source`
  renvoie la config **secret rédigé** + `secret_set`.
- **Diagnostic hors-ligne** : `python3 -m forge.cli doctor` inclut une ligne de santé de la source, et
  `python3 -m forge.cli detections --source <spec> --since N` imprime `{"detections":[…]}` (voir la CLI).

## CLI / env

Le collecteur Python lit sa config via `--source` : `env:NOM` (**voie privilégiée** — la console y met le
JSON *avec* secret pour ne pas le fuiter via `argv`/`ps`), `@fichier`, ou du JSON littéral.

```bash
# diagnostic d'une source (n'imprime jamais le secret)
FORGE_DETECTION_SOURCE='{"kind":"crowdsec","endpoint":"http://127.0.0.1:8080", …}' \
  python3 -m forge.cli detections --source env:FORGE_DETECTION_SOURCE --since 0
```
