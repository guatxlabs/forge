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
- Ces applications sont **délibérément vulnérables** : ne jamais les exposer. Le démontage est
  **systématique** — il vit dans un `finally`, couvre **tout ce qui porte le préfixe `forge-bench-`**
  (découvert auprès de docker, pas lu dans une liste), et **vérifie son propre effet** : `teardown()`
  relit docker + les sockets après avoir retiré, et rend `(ok, restes)`.
  `--keep-up` laisse le banc debout, mais c'est alors un choix explicite de l'opérateur.

  > Pourquoi ce niveau de soin : le rejeu du **2026-08-11** a trouvé `forge-bench-dvwa` encore à
  > l'écoute **après** un `teardown()` réputé complet. Le code portait trois chemins de fuite —
  > démontage opt-in **après** la boucle (aucune interruption n'y survivait) ; liste de démontage
  > réduite aux applications ayant **répondu**, laissant hors de portée un conteneur créé mais muet ;
  > et surtout le **refus de périmètre qui sortait sans démonter**, c'est-à-dire le garde qui, en
  > refusant d'armer parce qu'une application vulnérable écoutait hors de la boucle locale, la
  > laissait précisément écouter. Couvert par `tests/test_bench_teardown_final.py`.

## Utilisation

```bash
# lever les cibles, amorcer, jouer les deux pistes, écrire le manifeste
python3 -m bench.detection.run_bench --workdir /tmp/bench --track both --budget 900

# rendre le tableau (par app, par classe, + la liste des >= MEDIUM a verifier a la main)
python3 -m bench.detection.report --workdir /tmp/bench --verdicts bench/detection/verdicts.json

# demonter a la main (le run le fait deja tout seul, y compris s'il est interrompu)
python3 -c "from bench.detection import provision; print(provision.teardown())"
```

**Campagnes jouées, sorties brutes conservées (jamais écrasées)** — `RESULTS_2026-08-10.md` (mesure
initiale, 13 défauts) et `RESULTS_2026-08-11.md` (banc rejoué en entier après remédiation).
Comparaison AVANT/APRÈS et défauts encore ouverts : `../../docs/BENCH_DETECTION.md`.

**Deux réserves connues sur le banc lui-même** (consignées, non corrigées) :
`harness.run_forge` marque `partial=True` pour TOUTE campagne pourvue d'un `--run-timeout`, parce que
la bannière de lancement du moteur contient le mot « PARTIEL » — lire la bannière du rapport du moteur
plutôt que ce drapeau (défaut **D15**) ; et `THIRD_PARTY_MODULES` exclut par intention déclarée, pas
par egress observé — `recon.httpx` télécharge un modèle depuis `huggingface.co` (défaut **D17**).

## Fichiers

| fichier | rôle |
|---|---|
| `groundtruth.py` | la vérité terrain, entrée par entrée, **avec sa source citée** |
| `provision.py` | lève les cibles en loopback, les amorce, écrit `scope.json`/`targets.json` |
| `seeded.py` | piste A : les actions amorcées à la main, une par vuln connue |
| `harness.py` | lance la CLI Forge, récolte le store `--memory`, rapporte si le budget a coupé |
| `score.py` | compte les trois métriques ; liste les ≥ MEDIUM à vérifier |
| `report.py` | rend le tableau final |
