# MTTD — ce que la métrique mesure (et ne mesure PAS)

## TL;DR

Le MTTD reporté par Forge est un **time-to-ALERT**, pas un **time-to-event**. Il inclut la latence
d'**évaluation des règles Plume** (`interval_s`, défaut ~300 s) + la latence d'**ingest des logs**
(journald → Plume). Les MTTD observés (ex. **352 s**, **623 s**) reflètent donc en grande partie
l'intervalle d'évaluation des règles testées, et **ne doivent pas être surinterprétés** comme le
temps de réaction « brut » du SOC.

## Comment le MTTD est calculé

La console fait le JOIN purple (`console/src/main.rs`, fonction de couverture) :

```
MTTD(technique T) = first_detection_ts(T) − last_fire_ts(T)     (en secondes, tronqué à 0 si négatif)
```

- `last_fire_ts(T)` = horodatage du **tir red** le plus récent pour la technique T (côté Forge,
  champ `ts` des run-records).
- `first_detection_ts(T)` = `first_ts` renvoyé par Plume (`GET {PLUME_URL}/api/coverage/detections`),
  soit le **premier `alert.ts`** agrégé pour ce `mitre`.

Le point clé : `first_detection_ts` est le timestamp d'une **ALERTE**, pas de l'**événement** sous-jacent.

## Pourquoi c'est un time-to-ALERT, pas un time-to-event

Une alerte Plume n'existe qu'**après** que :

1. **Ingest** — l'événement (journald / syslog de l'hôte testé) est ingéré par Plume. Latence de
   collecte/transport non nulle.
2. **Évaluation de règle** — la règle Plume associée s'exécute. Les règles tournent **par
   intervalle** (`interval_s`, défaut ~300 s), pas en continu : un événement arrivé juste après un
   cycle d'évaluation attend ~jusqu'au cycle suivant avant de produire une alerte.

Donc, pour une technique détectée par une règle d'intervalle :

```
MTTD ≈ latence_ingest + (temps jusqu'au prochain cycle d'évaluation) + temps_de_règle
     ≈ latence_ingest + [0 … interval_s]   (en moyenne ~interval_s/2, au pire ~interval_s)
```

Avec `interval_s ≈ 300 s`, un MTTD observé de **352 s** ou **623 s** est cohérent avec
**1× à 2× l'intervalle** + l'ingest — c'est-à-dire dominé par la cadence d'évaluation des règles,
pas par une lenteur de détection « réelle ». La détection elle-même (le matching) est quasi-instantanée ;
ce qu'on mesure, c'est surtout **quand la règle a regardé**.

## Conséquence : ne pas surinterpréter

- Un MTTD de quelques centaines de secondes **n'indique pas** un SOC lent : il indique surtout
  l'`interval_s` des règles concernées. Comparer des MTTD entre techniques n'a de sens que si l'on
  connaît l'`interval_s` de chaque règle (deux règles à intervalles différents ne sont pas
  comparables directement).
- Le MTTD est **borné par le bas** par l'intervalle de la règle : on ne peut pas mesurer un
  time-to-alert plus fin que la cadence d'évaluation, même si la détection logique est immédiate.
- Le JOIN reste **lecture seule** et la console **ne fabrique jamais** de MTTD (si Plume est
  injoignable/illisible → `plume_reachable:false`, MTTD `null`, jamais inventé). La métrique est
  fidèle ; c'est son **interprétation** qui demande le contexte `interval_s`.

## Recommandations

1. **Documenter l'`interval_s` des règles testées** à côté de chaque MTTD dans le rapport purple
   (sans cette donnée, un MTTD seul est ambigu : détection lente vs simple cadence d'intervalle).
2. **Pour un MTTD plus fin**, baisser l'`interval_s` des règles concernées **côté Plume** (le
   plancher du MTTD descend alors vers la vraie latence d'ingest + matching). ⚠️ **Hors périmètre
   Forge** : c'est une configuration Plume, à faire dans le SOC, pas dans ce dépôt.
3. **Horloges synchronisées (NTP)** entre l'hôte Forge (`ts` du tir) et Plume (`alert.ts`) — sans
   ça, `first_detection_ts − last_fire_ts` est biaisé par le décalage d'horloge (cf.
   `PURPLE_PREREQS.md` §6). La troncature à 0 masque un décalage négatif mais pas un décalage positif.
4. **Présenter le MTTD comme un time-to-ALERT** dans tout livrable client : nommer explicitement
   qu'il englobe ingest + cadence d'évaluation des règles, pour éviter la lecture « temps de réaction
   du SOC ».

## Voir aussi

- [`PURPLE_PREREQS.md`](PURPLE_PREREQS.md) — prérequis Plume (règles taguées `mitre`, endpoint
  `/api/coverage/detections`, NTP) pour que le JOIN MTTD fonctionne.
- [`PURPLE_CAMPAIGN.md`](PURPLE_CAMPAIGN.md) — runbook de la campagne recon-large qui amorce la
  matrice MTTD sur `lab.guatx.com`.
