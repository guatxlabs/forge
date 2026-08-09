# Défauts trouvés en amont — reproductions prêtes à envoyer

Ce fichier existe parce qu'un défaut d'outil trouvé ici n'est **pas** propre à ce dépôt : n'importe
quel projet dans la même configuration l'a aussi, sans le savoir. Le signaler en amont vaut mieux que
de le contourner en silence — et une reproduction minimale coûte moins cher au mainteneur amont qu'un
rapport en prose.

Chaque entrée porte : le défaut, **comment il a été isolé** (facteur unique), la reproduction, et ce
que le projet a fait en attendant.

---

## 1. cargo-deny / krates — une dépendance OPTIONNELLE dont le nom de paquet ≠ nom de `[lib]` disparaît

**État : à signaler.** Trouvé le 2026-08-07, cargo-deny **0.18.2**.

### Le défaut

`cargo-deny` (via `krates`) **perd silencieusement tout un sous-arbre de dépendances** quand une
dépendance **optionnelle** a un nom de paquet différent du nom de sa cible `[lib]`.

La feature déclare le **paquet** (`object-store = ["dep:rust-s3"]`), mais l'arête résolue que rend
`cargo metadata` porte le nom de la **lib** (`"name": "s3"`). L'appariement échoue, la feature est
tenue pour désactivée, et l'ensemble du sous-arbre sort du graphe audité.

### Pourquoi c'est grave — ce n'est pas un faux négatif, c'est un faux VERT

L'outil ne dit pas « je n'ai pas regardé ». Il rend **`licenses ok`**. Mesuré sur deux copies du même
dépôt ne différant **que** par le nommage de cette dépendance :

| arbre | verdict |
|---|---|
| `rust-s3 = { optional = true }` (nom de lib `s3`) | `licenses ok` — 239 crates vus |
| `s3 = { package = "rust-s3", optional = true }` | **`licenses FAILED`** — 287 crates vus |

Les deux crates qui faisaient échouer l'audit — `attohttpc` (MPL-2.0) et `tiny-keccak` (CC0-1.0) —
étaient invisibles. Pire : la politique de ce dépôt avait **retiré `MPL-2.0`** de sa liste d'autorisées
au motif que « cargo-deny la signale non rencontrée ». Une décision de licence prise **à travers**
l'angle mort.

### Isolement — un seul facteur changé à la fois

| manifeste | invocation | crates vus | sous-arbre |
|---|---|---|---|
| `optional`, syntaxe `dep:rust-s3` | `--all-features` | 239 | absent |
| `optional`, syntaxe implicite `["rust-s3"]` | `--all-features` | 239 | absent |
| dépendance rendue **non** optionnelle | *(sans drapeau)* | 250 | **présent** |
| **renommée** `s3 = { package = "rust-s3" }` | `--all-features` | 287 | **présent** |

Éliminés par la mesure : ce n'est **pas** `--all-features` (il porte bien : 201 → 239, les optionnelles
des autres features entrent), **pas** la syntaxe `dep:`, **pas** un `targets` restreint (il n'y en a
pas), **pas** une exclusion. `cargo metadata --all-features` voit, lui, les 290 crates.

### Reproduction minimale

```toml
# Cargo.toml
[features]
object-store = ["dep:rust-s3"]

[dependencies]
rust-s3 = { version = "0.37", optional = true, default-features = false, features = ["sync-rustls-tls"] }
```

```bash
cargo-deny --all-features check licenses --config <chemin ABSOLU>/deny.toml
# -> le sous-arbre rust-s3 / attohttpc / aws-lc-sys est ABSENT du graphe

# puis, seule modification :
#   s3 = { package = "rust-s3", version = "0.37", optional = true, ... }
#   object-store = ["dep:s3"]
# -> le sous-arbre apparaît, +48 crates
```

`rust-s3` est un bon cas de test public : paquet `rust-s3`, `[lib] name = "s3"`.

### Comportement souhaité

Peu importe la correction retenue en amont — l'important est que l'outil **ne rende pas `ok`** sur un
graphe qu'il sait incomplet. Un avertissement nommant la dépendance perdue suffirait à transformer un
faux vert en question posée à l'humain.

### Ce que ce projet a fait en attendant

1. **Renommé la dépendance** (`s3 = { package = "rust-s3" }`) — une ligne, aucun changement de code
   (l'extern s'appelait déjà `s3`), `Cargo.lock` inchangé.
2. Ajouté `scripts/check_dep_licenses.py`, qui refait le contrôle sur `cargo metadata --all-features`
   en lisant la liste `allow` de `deny.toml` — **une seule vérité de politique, deux moteurs**.
   Câblé en CI avec un auto-test rouge, parce qu'une garde incapable d'échouer est un décor.
3. Documenté le périmètre réel de l'audit dans `docs/DEPLOYMENT.md` §3quater.2, y compris **ce qui
   n'est toujours pas couvert** (`bans` / `sources` sur ces crates).

### Note annexe, même famille

Un `--config` **relatif** est résolu depuis le dossier du manifeste et **retombe en silence** sur la
configuration par défaut si le chemin ne résout pas. Même classe de défaut : l'outil continue avec une
politique qui n'est pas celle qu'on lui a demandée, sans le dire. D'où le chemin **absolu** partout
dans ce dépôt.
