<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `bench/` — mesurer Forge, pas le supposer

Ce dossier ne contient **aucun** code de production. Ce sont des **observateurs** : ils pilotent la
CLI publique de Forge contre des cibles à vérité terrain connue et comptent ce qu'elle trouve, ce
qu'elle rate, et — surtout — ce qu'elle affirme à tort.

> Rien ici n'importe `forge/**` autrement que par la CLI et par lecture du store `--memory`.
> Un banc qui appellerait l'API interne ne mesurerait pas ce qu'un opérateur obtient.

## `detection/` — banc de détection multi-applications

**Pourquoi.** La seule mesure de pouvoir de détection du dépôt portait sur **une** cible (OWASP Juice
Shop). Un échantillon de 1 ne dit pas si le moteur généralise ou s'il a été ajusté à cette cible.

**Comment.** Quatre applications volontairement vulnérables, **stacks différentes**, chacune fournissant
sa PROPRE vérité terrain :

| app | stack | vérité terrain (fournie par l'application) |
|---|---|---|
| Juice Shop | Node/Express/Angular | `GET /api/Challenges` — son registre de challenges |
| DVWA | PHP/Apache/MariaDB | `/var/www/html/vulnerabilities/` — sa liste de modules |
| VAmPI | Python/Flask/OpenAPI3 | `README.md` § *List of Vulnerabilities* + les branches `if vuln:` |
| DVGA | Python/Flask/Graphene | `templates/partials/solutions/*.html` — ses pages de solutions |

**Deux pistes, mesurées séparément** — parce qu'elles ne disent pas la même chose :

- **piste A** — chaque oracle est **amorcé à la main** sur la vuln connue (URL + paramètre exacts).
  On neutralise la découverte : on ne mesure plus que le **jugement**.
- **piste B** — **campagne autonome** (`--auto-pentest`). On mesure la **chaîne complète**
  (découverte + jugement) et on obtient le volume où se comptent les **faux positifs**.

**Trois métriques, la troisième d'abord.** Vrais positifs par classe ; faux négatifs **avec leur
cause** ; et **faux positifs** — chaque finding ≥ MEDIUM est rejoué à la main contre l'application.

## Sûreté

- **Loopback strict.** Chaque conteneur est publié sur `127.0.0.1` uniquement ;
  `provision.verify_loopback_only()` **refuse** de continuer si un socket sort de la boucle locale.
- **Périmètre borné au port** (`in_scope: ["127.0.0.1:PORT"]`), vérifié par `forge scope-check`
  avant tout armement, avec contre-épreuve sur une cible hors périmètre.
- **Modules interrogeant un tiers exclus** (`provision.THIRD_PARTY_MODULES` : crt.sh, Wayback,
  résolveurs DNS publics, dépôts de templates, collecteurs de callback). La liste retenue/exclue est
  écrite dans `modules_loopback_safe.json` à chaque exécution.
- Ces applications sont **délibérément vulnérables** : ne jamais les exposer. `provision.teardown()`
  démonte tout.

## Utilisation

```bash
# lever les cibles, amorcer, jouer les deux pistes, écrire le manifeste
python3 -m bench.detection.run_bench --workdir /tmp/bench --track both --budget 900

# rendre le tableau (par app, par classe, + la liste des >= MEDIUM a verifier a la main)
python3 -m bench.detection.report --workdir /tmp/bench --verdicts verdicts.json

# demonter
python3 -c "from bench.detection import provision; provision.teardown()"
```

## Fichiers

| fichier | rôle |
|---|---|
| `groundtruth.py` | la vérité terrain, entrée par entrée, **avec sa source citée** |
| `provision.py` | lève les cibles en loopback, les amorce, écrit `scope.json`/`targets.json` |
| `seeded.py` | piste A : les actions amorcées à la main, une par vuln connue |
| `harness.py` | lance la CLI Forge, récolte le store `--memory`, rapporte si le budget a coupé |
| `score.py` | compte les trois métriques ; liste les ≥ MEDIUM à vérifier |
| `report.py` | rend le tableau final |
