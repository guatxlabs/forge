# Roadmap — Cycle de vie des outils : installer-ou-non + mise à jour à la demande (hybride)

**Statut : PLANIFIÉ** — design approuvé par Hugo le 2026-07-04, non encore construit. Ce document consigne la décision pour ne pas la perdre.

## Problème
Aujourd'hui les outils de sécurité externes (httpx, nuclei, subfinder ; nmap est apt-installé à part) ne sont installés qu'au **build** via le toggle Dockerfile `FORGE_TOOLS_PROFILE=full|mini`. Les versions sont des ARG codés en dur, **dupliqués** entre `Dockerfile` et `docker-compose.yml`. Il n'existe **aucun** moyen d'installer un outil omis, ni de mettre à jour un outil, sans reconstruire l'image. Besoin de Hugo : (a) choisir si chaque outil est installé ou non, et (b) mettre à jour les outils à la demande.

## Approche retenue : HYBRIDE (baseline au build + surcouche runtime)
- **Baseline au build inchangée** : l'image continue de baker les outils selon `FORGE_TOOLS_PROFILE` (full/mini). La prod reste reproductible et SHA-pinnée. Comportement par défaut identique à aujourd'hui.
- **Surcouche runtime** : la console gagne une capacité **admin-gated et auditée** pour installer / mettre à jour / retirer un outil au runtime, dans un **volume outils persistant, propriété de l'utilisateur `forge`**, qui prime sur le PATH devant le `/usr/local/bin` baké. Installer/mettre à jour un outil au runtime **ne nécessite pas de rebuild**.

## Briques (issues de la reconnaissance du code, 2026-07-04)
1. **Centraliser les métadonnées outils** (fin de la duplication Dockerfile↔compose) : un manifeste unique (versions + pins SHA256 par arch + gabarit d'URL + activé-par-défaut). Le Dockerfile le lit ; l'installeur runtime lit le même fichier. Candidat : `forge/tools.json`, ou étendre le `ToolSpec` du catalogue (`forge/modules/toolspec.py`, actuellement seulement `binary` + `docker_image` — pas de version/checksum/url).
2. **Volume outils persistant** : nouveau volume nommé monté p.ex. `/data/tools/bin`, propriété uid 10001 (forge), préfixé au PATH. Survit à un recreate du conteneur (le `/usr/local/bin` baké, non). Touche compose + `VOLUME` Dockerfile + variable PATH.
3. **Modèle d'intégrité pour les installs runtime** (préserver la posture « jamais de download non vérifié », cf. `Dockerfile:151`) :
   - Préféré : n'installer que des versions présentes dans le manifeste, qui portent un SHA256 pinné → vérifier après download, comme au build.
   - Pour une version arbitraire/plus récente absente du manifeste : exiger que l'opérateur fournisse le SHA256 attendu (ou récupérer+afficher le checksum publié par ProjectDiscovery pour confirmation admin explicite). JAMAIS de confiance implicite.
4. **Surface console** :
   - API : étendre la surface admin/module (hook naturel : `POST /api/modules/:kind` `module_governance`, déjà `check_admin` à `main.rs:1675`) ou un nouveau `POST /api/tools/:name/{install|update|remove}`. Admin-only, audité via `append_console_ledger` (motif à `main.rs:1614`).
   - CLI : sous-commande `forge-console tools {list|install|update|remove}` (dispatch à `main.rs:9835`).
   - UI : panneau outils affichant version installée vs version cible, boutons install/update/remove, indicateur baseline mini/full.
5. **Visibilité des versions** : aujourd'hui la disponibilité est un booléen sondé (`shutil.which`, `runner.available`), sans version. Ajouter une sonde de version (`httpx -version`, etc.) pour que l'UI montre installé vs cible et propose l'update quand ils diffèrent.

## Contraintes / pièges (à respecter)
- Conteneur non-root (uid 10001) ; `/usr/local/bin` est root-owned et baké → les installs runtime doivent viser le volume outils forge-owned, pas `/usr/local/bin`.
- Egress hôte instable (observé : HTTP/2 partial-file `curl (18)` + read-timeout PyPI) → l'installeur runtime doit réutiliser les flags curl durcis (`--http1.1 --retry 5 --retry-delay 3 --retry-connrefused --retry-all-errors --connect-timeout 30 --max-time 300`).
- Garder intactes les sémantiques mini/full de `FORGE_TOOLS_PROFILE` ; l'hybride est additif.
- Principe vendor-agnostic : concevoir le manifeste outils de façon générique (bring-your-own-tool), pas codé en dur pour les 3 outils PD.

## Non-goals (pour l'instant)
- Pas d'auto-update / upgrade en tâche de fond ; action admin explicite uniquement.
- Pas de download non pinné / non vérifié.

## Séquencement quand ce sera construit
1. Manifeste outils single-source + Dockerfile/compose le lisent (supprime la duplication) — sûr, aucun changement de comportement.
2. Volume outils persistant + précédence PATH + sonde de version.
3. Install/update/remove runtime : CLI d'abord, puis API (admin + audit), puis panneau UI.
4. UX d'intégrité pour les versions hors-manifeste.

## Contexte lié
- Fix build préalable : `COPY forge/VERSION` (build cassé car `include_str!` compile-time cherchait `/build/forge/VERSION` absent) — commit `fc903fe`.
- Durcissement du download d'outils au build (curl `--http1.1` + retries) suite au flake réseau HTTP/2 — même lot que cette roadmap.
- Résidu connexe hors-scope : le `pip install weasyprint` du stage runtime n'a PAS de retry et a flaké une fois (read-timeout PyPI) ; candidat au même traitement plus tard.

## Résidus egress / robustesse réseau (à surveiller)
L'hôte de build a un **egress instable** (deux flakes observés le 2026-07-04 : `curl (18)` HTTP/2 partial-file sur le download des outils ProjectDiscovery, et un read-timeout PyPI sur `pip install`). Deux points consignés :

1. **`pip install weasyprint` sans retry.** Le stage runtime installe weasyprint (PDF) via `pip install` **sans** politique de retry/timeout, contrairement au download curl des outils désormais durci. Il a flaké une fois (read-timeout `files.pythonhosted.org`). **Pas encore corrigé — hors scope du lot courant.** Candidat au même traitement (retries + timeouts bornés, p.ex. `pip --retries N --timeout T` ou variables `PIP_RETRIES`/`PIP_DEFAULT_TIMEOUT`) **si ça se reproduit**.

2. **Le fix curl est un contournement, pas la racine.** Forcer HTTP/1.1 + retries sur le download des outils est robuste et suffisant en pratique, mais si les flakes réseau **persistent**, la vraie cause est la **connectivité egress de l'hôte** (réseau/DNS/MTU/proxy), pas le Dockerfile. Auquel cas : diagnostiquer la connectivité hôte plutôt que d'empiler des retries dans l'image.
