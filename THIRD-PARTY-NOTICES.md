# Composants tiers embarqués

Forge embarque les composants ci-dessous. Ils sont distribués **sous leur propre
licence**, pas sous l'AGPL v3 de Forge. L'AGPL v3 s'applique au code propre au
projet ; rien ici ne la leur substitue.

Ces composants sont volontairement **embarqués** (`console/web/fonts/`) plutôt
que récupérés à l'exécution : la console doit s'afficher sans réseau sortant vers
un CDN de polices. Sur un outil offensif la contrainte est plus forte encore —
une console qui appelle un CDN tiers signale l'engagement en cours à ce tiers.

## Inter

- **Emplacement** : `console/web/fonts/inter-latin.woff2`,
  `console/web/fonts/inter-latin-ext.woff2`
- **Licence** : SIL Open Font License 1.1 (`OFL-1.1`)
- **Texte** : [`console/web/fonts/OFL-Inter.txt`](console/web/fonts/OFL-Inter.txt)
- **Amont** : <https://github.com/rsms/inter>
- **Version** : 4.001 — la table `name` de la police porte
  `Version 4.001;git-66647c0bb`
- **Copyright** : `Copyright 2016 The Inter Project Authors` — le texte OFL amont
  écrit la même chose avec un `(c)` que la table `name` n'a pas

## JetBrains Mono

- **Emplacement** : `console/web/fonts/jetbrains-mono-latin.woff2`,
  `console/web/fonts/jetbrains-mono-latin-ext.woff2`
- **Licence** : SIL Open Font License 1.1 (`OFL-1.1`)
- **Texte** : [`console/web/fonts/OFL-JetBrainsMono.txt`](console/web/fonts/OFL-JetBrainsMono.txt)
- **Amont** : <https://github.com/JetBrains/JetBrainsMono>
- **Version** : 2.211 — la table `name` de la police porte `Version 2.211`
- **Copyright** : `Copyright 2020 The JetBrains Mono Project Authors`

Les deux avis de copyright ci-dessus sont ceux **lus dans la police elle-même**
(table `name`, identifiant 0), pas déduits du nom de fichier. Chaque texte de
licence a été récupéré de l'amont **tel quel** : celui d'Inter au commit
`66647c0bb` que la police déclare, celui de JetBrains Mono dans une révision où
il est identique d'une version à l'autre autour de la 2.211.

Ces fichiers sont des sous-ensembles `latin` / `latin-ext` convertis en WOFF2 —
donc des **Modified Versions** au sens de l'OFL. Cela reste autorisé : ni Inter
ni JetBrains Mono ne déclarent de **Reserved Font Name** après leur avis de
copyright, la clause 3 ne mord donc pas, et la clause 5 (rester sous OFL) est
respectée puisque nous ne les redistribuons sous aucune autre licence.

L'OFL n'est pas contaminante pour le reste du projet : sa clause 5 précise que
l'obligation de rester sous OFL ne s'étend pas aux documents produits avec la
police, et sa clause 2 autorise explicitement la redistribution **groupée avec
n'importe quel logiciel** dès lors que chaque copie porte l'avis de copyright et
la licence. C'est le cas ici pour le source **et pour l'image** : le `Dockerfile`
copie `console/web/` en entier, donc les deux fichiers de licence voyagent avec
les polices qu'ils couvrent.

---

## Ce qui n'est PAS un tiers embarqué

À relire avant d'ajouter une entrée ci-dessus, pour ne pas grossir la liste avec
ce qui n'y appartient pas :

- **Les dépendances Rust ne sont pas vendorisées.** Elles sont récupérées par
  Cargo au build (`console/Cargo.lock` les épingle) : ce dépôt ne redistribue pas
  leur code, donc n'a pas à redistribuer leur texte de licence. Cela changerait
  si un `vendor/` Cargo était commité.
- **Les dépendances Python ne sont pas vendorisées** non plus : `pyproject.toml`
  les déclare, pip les installe au build.
- **`guatx-core` est une git-dep**, pas une copie : elle est épinglée par tag,
  sous `LGPL-3.0-or-later`, et vit dans son propre dépôt.
- **Les captures de `docs/media/`, les SVG de `console/web/` et les `.jsonl` de
  `examples/reference-engagement/`** sont des productions du projet — les
  fixtures d'engagement de référence sont synthétiques (domaines `*.example`).

## Note de conformité

Les quatre `.woff2` étaient redistribués **sans aucun texte d'OFL** dans le
dépôt : l'OFL 1.1 exige à sa clause 2 que « each copy contains the above
copyright notice and this license », ce qui n'était pas satisfait. Les deux
textes ont été récupérés depuis l'amont et ajoutés avant toute publication.

Le défaut ne se voyait pas en cherchant des *fichiers de licence manquants* — il
se voit en recensant ce que le dépôt **redistribue**, par type de contenu et non
par extension. Le recensement a été refait ainsi : hors les polices, les seuls
binaires suivis sont des captures d'écran et des SVG produits par le projet, et
aucun JS/CSS tiers n'est embarqué (aucun bundle minifié, aucun en-tête
`@license`).

Toute mise à jour d'une police doit **reprendre son fichier de licence en même
temps que le binaire**, et mettre à jour la version indiquée ci-dessus — la
version se lit dans la table `name`, pas dans le nom de fichier.
