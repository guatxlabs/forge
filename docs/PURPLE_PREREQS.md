# Prérequis Plume pour la boucle purple Forge (le moat)

## Rappel du flux

La console Forge `/api/purple/coverage` lit les run-records tirés (par `mitre`), fait
`GET {PLUME_URL}/api/coverage/detections`, et **JOIN** → detected / missed / MTTD.

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

Régler `PLUME_URL` + auth Plume sur la console, confirmer le type d'auth, lancer la 1ʳᵉ campagne lab
gatée ROE, sortir la matrice live + le rapport.

## ⚠️ Sûreté

- Le JOIN est **lecture seule** (sûr).
- Tirer des techniques = **uniquement** cible autorisée / scopée. ROE / scope reste dur.
- **JAMAIS** de tir sur prod non autorisée ni `PLUME_URL` détourné.
