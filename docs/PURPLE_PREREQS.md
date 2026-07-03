# Prérequis Plume pour la boucle purple Forge (le moat)

> **Plume est UN préréglage (`kind=plume`), pas la seule option.** La source de détection est un **plugin
> configurable** : CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, un fichier JSONL ou une
> commande maison se câblent **sans code** (wizard / *Administration → Source de détection*). Le modèle
> `DetectionSource` complet et les préréglages par infra sont dans **[`DETECTION.md`](DETECTION.md)**. Ce
> document ne couvre que le préréglage **Plume** ; `PLUME_URL`/`PLUME_TOKEN` restent supportés en
> rétro-compat (interprétés comme `kind=plume`).

## Rappel du flux

La console Forge `/api/detection/coverage` (alias rétro-compat `/api/purple/coverage`) lit les run-records
tirés (par `mitre`), interroge la **source de détection configurée**, et **JOIN** → detected / missed /
MTTD. Pour le préréglage Plume, la source est `GET {PLUME_URL}/api/coverage/detections`.

## Checklist Plume (à faire avant le « go »)

1. **Migration v39 déployée** : colonnes `alert.mitre` + `rule.mitre`
   (TEXT NOT NULL DEFAULT '') + `idx_alert_mitre`. Codé dans `plume/`, idempotent au boot →
   déployer le nouveau binaire en prod.

2. **Endpoint exposé** : `GET /api/coverage/detections?since=<epoch>` →
   `{"detections":[{mitre,count,first_ts},…]}` (agrégat `alert WHERE mitre<>'' GROUP BY mitre`,
   tri `count DESC`).

3. ⭐ **Règles taguées MITRE** (travail manuel) : `rule.mitre` rempli sur les règles utiles
   (ex. brute-force → T1110, port-scan → T1046, web-scan → T1595.002, accès → T1190). Sinon Plume
   détecte sans `mitre` → matrice = tout « raté » (faux trous).

4. **Règles actives + sources de logs qui coulent** : Plume ingère les events (journald / syslog)
   de l'hôte testé → un tir déclenche la règle → `alert` avec `mitre` hérité.

5. **Joignabilité + auth depuis la console** : endpoint sous `/api/` → **Basic
   (viewer / editor / admin)** OU header SSO de confiance ; les **tokens Bearer d'agent NE sont
   PAS acceptés**. Fournir un identifiant Plume lecture + chemin réseau ouvert. (À vérifier au
   câblage : la console doit envoyer du Basic / SSO, **pas** du Bearer.)

6. **Horloges synchronisées (NTP)** : `ts_fired` (Forge) et `alert.ts` (Plume) cohérents pour un
   MTTD juste (MTTD = `first_ts − ts_fired`).

7. **Cible lab autorisée surveillée par Plume** : pour la moitié « tir », un hôte dans le périmètre
   de monitoring Plume, autorisé à être attaqué. ROE / scope reste dur.

## Côté Forge au « go »

Configurer la **source de détection** (préréglage Plume) — soit dans l'UI (*Administration → Source de
détection*, ou l'étape 3 du wizard), soit via `PLUME_URL` + `PLUME_TOKEN` (rétro-compat) — confirmer le
type d'auth, lancer la 1ʳᵉ campagne lab gatée ROE, sortir la matrice live + le rapport. Pour toute autre
infra (CrowdSec, FortiGate, Elastic…), voir **[`DETECTION.md`](DETECTION.md)**.

## ⚠️ Sûreté

- Le JOIN est **lecture seule** (sûr).
- Tirer des techniques = **uniquement** cible autorisée / scopée. ROE / scope reste dur.
- **JAMAIS** de tir sur prod non autorisée ni source de détection (`PLUME_URL`/`settings.detection_source`) détournée.
- Source absente/injoignable ⇒ `source_reachable:false` : la mesure est déclarée **impossible**, jamais inventée.
