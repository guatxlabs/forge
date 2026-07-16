# Plan de refactor d'architecture — incrémental, jamais un big-bang

> **Statut : PLAN uniquement.** Ce document ne modifie aucun code. Il découle du
> `docs/HOLISTIC_AUDIT.md` §4(c) (« Refactors d'architecture — plan incrémental, JAMAIS un
> big-bang ») et cible les **deux plus grosses dettes d'architecture** de la base : le god-file
> `console/src/main.rs` et la duplication de boilerplate `extra_args`/allowlist dans
> `forge/modules/*.py`.
>
> **Principe directeur (non négociable) :** chaque étape est une **PURE MOVE / PURE EXTRACTION**
> à comportement strictement préservé, autonome (compile + tests verts seule), et ordonnée du
> **plus petit risque au plus grand**. On ne vise JAMAIS un fichier « propre » d'un coup ; on
> extrait par couplage, opportunistiquement. Le build communautaire reste **byte-identique**.

---

## 0. Garde-fous (à respecter à CHAQUE étape)

Ces invariants s'appliquent à toutes les étapes des deux chantiers. Une étape qui en viole un
seul est à annuler, pas à « corriger ensuite ».

1. **Vert avant / vert après.** Avant de committer une étape :
   - Rust : `cargo test -p forge-console` (ou `cargo test` à la racine du workspace console)
     → **31 tests Rust** doivent rester verts, **même nombre, mêmes noms**.
   - Python : `pytest` → **258 tests Python** doivent rester verts, même nombre.
   - `cargo build --release` (build communautaire, features par défaut) doit produire un binaire
     **byte-identique** au HEAD précédent : une PURE MOVE ne change ni le code généré ni les
     `include_str!`/assets. (Vérif : `cargo build --release` puis `sha256sum` du binaire
     avant/après ; ou `cargo build && git stash` A/B si l'environnement est déterministe.)
2. **Zéro changement de comportement.** Aucune signature publique, aucun ordre de `.route()`,
   aucun code de sortie CLI, aucun message d'erreur, aucun champ de Finding ne change. Les
   extractions n'introduisent que du déplacement + des `pub(crate) use` / des bases partagées.
3. **Une seule couture par commit.** Un commit = une extraction cohésive. Jamais deux seams
   dans le même diff (facilite la revue et le `git revert` chirurgical).
4. **Le pattern d'extraction est déjà établi dans le repo — on l'ÉTEND, on n'invente rien.**
   `main.rs` a déjà été scindé ainsi (findings.rs, runs.rs → runs_proc/runs_ha/runs_validate,
   engagements.rs, auth.rs, net.rs…), chaque fois via `mod x; pub(crate) use crate::x::*;` avec
   un commentaire « (PURE MOVE) ». Toute nouvelle extraction copie ce modèle **verbatim**.
5. **Déclencheur opportuniste.** Ces refactors se font quand on touche déjà la zone OU comme
   respiration de dette explicitement budgétée — jamais en « réécriture spéculative » qui
   bloquerait une livraison fonctionnelle.

---

## 1. `console/src/main.rs` (6065 lignes) — décomposition du god-file

### 1.1 État réel vérifié (lu, pas supposé)

Structure actuelle de `main.rs` (offsets vérifiés au commit `563611a`) :

| Lignes | Contenu | Nature |
|--------|---------|--------|
| 1–72 | `use` (axum, rusqlite, serde, std, tokio) | imports |
| 73–329 | ~30 × `mod x;` + `pub(crate) use crate::x::*;` + commentaires « PURE MOVE » | déclarations de modules déjà extraits |
| 330–359 | `async fn health(State<App>) -> Json<Value>` | handler |
| 360–375 | `fn health_db_ping(&App) -> bool` | helper de `health` |
| 376–387 | `fn catch_panic_response(err) -> Response` | responder du `CatchPanic` layer |
| 388–607 | `fn build_router(app: App, web_dir: &str) -> Router` | **60 `.route()` + 8 `.merge(x::routes())`** |
| 608–621 | `#[tokio::main] async fn main()` | glue (dispatch_cli → serve) |
| 623–732 | `fn dispatch_cli(args: &[String]) -> Option<i32>` | sous-commandes CLI (hashpw, ledger verify…) |
| 733–1122 | `async fn serve()` | boot serveur (~390 l : ouverture DB, PRAGMA, SCHEMA, migrate, store-gate, App, HA, bind) |
| 1123–1139 | `enum StoreSelection` | type de la store-gate |
| 1140–1164 | `fn enterprise_store_gate(...) -> Result<StoreSelection, String>` | décision SQLite/Postgres |
| 1166–1167 | `#[cfg(test)] pub(crate) mod testutil;` | **déjà un fichier externe** (`testutil.rs`, 83 l) |
| **1169–6065** | **`#[cfg(test)] mod tests { … }`** | **4897 lignes, 133 fns `#[test]`/`#[tokio::test]`** |

**Constat clé : ~80 % du fichier (4897/6065) est le module de tests inline.** Le code non-test
ne fait que **~1168 lignes**, dont la seule vraie « fonction-dieu » interne est `build_router`
(220 l, wiring pur de handlers déjà importés depuis les sous-modules). Le plan attaque donc
**d'abord le test module** (gain de taille massif, risque quasi nul), puis les seams de code.

> Les handlers routés par `build_router` (`whoami`, `ingest`, `findings`, `coverage`,
> `attack_matrix`, `run_create`…) sont **déjà** définis dans les sous-modules et re-exportés
> `pub(crate)` à la racine (§73–329). `build_router` ne fait que les câbler — l'extraire est donc
> mécanique. Les tests inline accèdent aux privés de la racine via `use super::*` +
> `use crate::testutil::*` ; un module de test **enfant** (fichier frère `mod tests;`) conserve
> cet accès (un module enfant voit les items privés de ses ancêtres). C'est ce qui rend toutes
> les étapes ci-dessous sûres.

### 1.2 Séquence ordonnée (petit risque → grand risque)

#### Étape 1 — Sortir le module de tests dans un fichier frère (`console/src/tests.rs`)
- **Move :** lignes **1169–6065** (`mod tests { use super::*; use crate::testutil::*; … }`)
  → nouveau fichier `console/src/tests.rs` (corps du module, sans les accolades `mod tests {}`).
  Dans `main.rs`, remplacer le bloc par `#[cfg(test)]\nmod tests;`.
- **Pourquoi sûr :** `super::*` depuis `tests.rs` (module enfant de la racine) résout exactement
  les mêmes items privés de `main.rs` qu'en inline ; `crate::testutil::*` est déjà un chemin
  absolu inchangé. Aucun `pub` à ajouter, aucun corps de test touché.
- **Résultat :** `main.rs` passe de 6065 → **~1168 lignes**. Gain de 80 %.
- **Risque : TRÈS FAIBLE.** Pur déplacement de texte compilé seulement en `cfg(test)`.
- **Vérif verte :** `cargo test -p forge-console` → **31 tests, mêmes noms** ; `cargo build
  --release` byte-identique (le code non-test est inchangé, tests exclus du build release).

#### Étape 2 — Scinder `tests.rs` par sous-système (miroir des modules source)
Une fois `tests.rs` isolé (4897 l, 133 tests), le scinder en fichiers de test frères, **par
grappes cohésives déjà contiguës** dans le fichier (offsets relevés dans le module courant) :

| Fichier de test proposé | Tests (thème) | Plage actuelle (dans main.rs) |
|-------------------------|---------------|-------------------------------|
| `tests_http_boot.rs` | panic-responder, security-headers, store-gate contract, health, standalone-boot | 1177–1335, 5955–6065 |
| `tests_auth_session.rs` | create_session, login-lockout, tokens, sessions, cookie/bearer, attribution, auth-gate, https-detect | 1461–1846 |
| `tests_users_admin.rs` | panel-write, admin CRUD, users routes 403, settings round-trip | 1846–2083 |
| `tests_setup.rs` | wizard end-to-end, migrate/provision self-disabling, path-confinement | 2100–2407 |
| `tests_net_policy.rs` | ip-in-cidr, operator-source-cidr, trusted-proxy, ct_eq, host_guard, network-policy API | 2407–2610, 2909–3046 |
| `tests_ledger.rs` | ledger chain consistency, reload continuity, interleave-no-fork | 1394–1461, 2623–2713 |
| `tests_runs_engagement.rs` | run scope/ledger isolation, per-engagement slot, migrate-backfill, engagement CRUD | 2713–2909, 3046–3218, 3891–4033 |
| `tests_tenancy_rbac.rs` | tenancy isolation, per-engagement RBAC, superadmin, tenant CRUD | 3218–3891 |
| `tests_planning_techniques.rs` | technique selection/profiles, plan threading, workflows, techniques catalog | 4033–4189, 5429–5955 |
| `tests_reports_purple.rs` | run-report md/html, cvss, html-escape, purple coverage, detection source | 4189–4912 |
| `tests_modules_tools.rs` | high-impact gate, validate_modules, extra_args allowlist, toolspec, tools CRUD, module routes | 4912–5429 |

- **Move mécanique :** pour chaque grappe, couper les fns concernées de `tests.rs` → fichier
  frère ; ajouter `#[cfg(test)] mod tests_<x>;` dans `main.rs` (ou dans un `mod tests;` parent
  qui `pub(crate) mod`-déclare les sous-fichiers). Chaque fichier débute par
  `use super::*; use crate::testutil::*;` — même préambule que le module d'origine.
- **Risque : FAIBLE.** Purement du texte ; le seul piège est un helper de test **partagé** défini
  dans le module (ex. `test_app`, `test_app_scoped`, `http_raw`, `get_req`, `post_req`,
  `parse_status`, `cookie_token`, `operator_headers`, `seed_two_tenants`…). **Prérequis :**
  déplacer d'abord ces helpers partagés dans `console/src/testutil.rs` (fichier déjà existant,
  `pub(crate)`), en une **sous-étape 2a** dédiée, avant tout découpage — sinon un fichier de test
  perd l'accès à son helper. Les helpers mono-usage restent avec leur test.
- **Faisabilité incrémentale :** chaque fichier peut être extrait **un à un** ; entre deux, le
  build est vert. On n'est PAS obligé de faire les 11 d'un coup — on en fait un quand on touche
  la zone.
- **Vérif verte :** après chaque fichier, `cargo test` → total inchangé.

#### Étape 3 — Extraire `build_router` dans `console/src/router.rs`
- **Move :** lignes **388–607** (`fn build_router`) → `console/src/router.rs` exposant
  `pub(crate) fn build_router(app: App, web_dir: &str) -> Router`. Emporter avec elle
  `catch_panic_response` (376–387) et `health`/`health_db_ping` (330–375) **si** elles ne sont
  utilisées que par le router/tests — sinon les laisser à la racine et les garder `pub(crate)`.
- **Pourquoi sûr :** `build_router` ne fait que câbler des handlers **déjà** re-exportés
  `pub(crate)` à la racine (§73–329) ; depuis `router.rs`, ces symboles restent accessibles via
  `use crate::*;` (ou imports ciblés). Aucun handler n'est déplacé, aucun ordre de route ne
  bouge, aucune string ne change → binaire identique.
- **Risque : FAIBLE.** Le seul point d'attention est la liste d'`use` à recopier ; le compilateur
  la garantit exhaustive.
- **Vérif verte :** `cargo test` (les tests `*_routes_do_not_conflict`, `security_headers_*`,
  `standalone_boot_serves_health_*` exercent déjà le router monté) + build release byte-identique.

#### Étape 4 (optionnelle, seulement si `main.rs` reste gros) — Extraire le boot dans `console/src/boot.rs`
- **Move :** `serve` (733–1122), `dispatch_cli` (623–732), `enterprise_store_gate` (1140–1164),
  `enum StoreSelection` (1123–1139) → `console/src/boot.rs` (`pub(crate)`). `main.rs` se réduit à
  `main()` + les `mod`/`use` de racine + le `mod tests`.
- **Pourquoi sûr :** ce sont des fonctions à couplage faible avec le reste (elles consomment
  `App`, `enterprise_store_gate`, `build_router`) ; l'extraction est un déplacement + `use`.
- **Risque : FAIBLE-MOYEN.** `serve` est la plus grosse (~390 l) et touche des `#[cfg(feature =
  "encryption")]` et le câblage HA — recopier les `use`/attributs `cfg` **à l'identique**. C'est
  la seule étape avec un peu de surface ; elle est **optionnelle** et ne se fait que si le gain de
  lisibilité le justifie après l'étape 1.
- **Vérif verte :** `cargo test` (les tests `enterprise_store_gate_contract`,
  `standalone_boot_*`, `health_surfaces_stamped_schema_version` couvrent la zone) + build
  release byte-identique.

### 1.3 Cible finale (indicative, PAS un objectif à atteindre d'un coup)
```
console/src/main.rs        ~60 l   (main() + mod/use racine + mod tests;)
console/src/router.rs      ~230 l  (build_router + health + catch_panic_response)
console/src/boot.rs        ~430 l  (serve + dispatch_cli + store-gate)   [étape 4, optionnelle]
console/src/testutil.rs    ~250 l  (helpers de test partagés, étendu en 2a)
console/src/tests_*.rs      11 fichiers, ~4900 l au total (répartis)
```
Ordre d'exécution recommandé : **1 → (2a → 2 au fil de l'eau) → 3 → 4 (si besoin)**. Après
l'étape 1 seule, la dette « god-file » est déjà résolue à 80 % pour un risque quasi nul.

---

## 2. `forge/modules/*.py` — factorisation du boilerplate `extra_args`/allowlist

### 2.1 État réel vérifié

La base a **déjà** deux socles de factorisation en place :
- `forge/modules/oracle.py::Oracle` (+ `ScopeGuardedOracle`) — factorise les 4 oracles à preuve
  (`proof`/`skip`/`_http`/`_curl`). **Bien fait, rien à refaire ici.**
- `forge/modules/toolspec.py::ExternalToolModule` (382–…) — base des wrappers **générés depuis un
  `ToolSpec`** : elle centralise DÉJÀ, dans un seul `fire()`, tout le contrat gouverné —
  scope-guard fail-closed, **anti-injection d'argument positionnel** (`unsafe_positional_target`),
  **allowlist `extra_args` fail-closed** (`unsafe_extra_args`, 436–445), plancher exploit,
  dégradation binaire absent, exécution no-shell.

**La dette est ailleurs :** les modules **écrits à la main** (pas générés depuis un `ToolSpec`)
**ré-implémentent chacun** ce que `ExternalToolModule` centralise déjà. Duplication vérifiée :

| Module | Classe(s) | `FLAG_ALLOWLIST` | `_refuse()` local | param-spec `extra_args` répété | gate dans `fire()` |
|--------|-----------|:---:|:---:|:---:|:---:|
| `recon.py` | `HttpxFingerprint`, `NmapServices` | 2× (l.53, 125) | 2× (l.81, 170) | 2× | 2× (`check_extra_args`) |
| `web.py` | `NucleiScan` | 1× (l.37) | 1× (l.77) | 1× | 1× |
| `origin.py` | `SubfinderEnum` | 1× (l.91) | (via check) | 1× | 2× (l.112, 130) |
| `recon_active.py` | `ContentDiscovery` (`PassiveSurface`) | 1× (l.96) | — | 1× | 6× refs |
| `injection.py` | `SqliProbe` (`InjectionOracle`) | 1× (l.286) | — | 1× | 1× (l.403) |

Le pattern dupliqué, **quasi-verbatim** d'un module à l'autre :
```python
FLAG_ALLOWLIST = ("-x", "-y", ...)                       # (1) constante par module
{"name": "extra_args", "type": "list", "label": "...", "flag": ""}   # (2) entrée de params répétée
# dans preview :
_, extra = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
# dans fire() :
bad_extra, _ = check_extra_args(p.get("extra_args"), self.FLAG_ALLOWLIST)
if bad_extra is not None:
    return self._refuse(action, f"argument libre refusé ({bad_extra})")   # (3) refus fail-closed dupliqué
```
`_refuse` est copié **à l'identique** dans `recon.py` (×2), `web.py`, `origin.py`.

### 2.2 Cible de factorisation

Introduire, **dans `toolspec.py`** (à côté de `check_extra_args`/`safe_value` déjà partagés), un
**mixin léger** pour les modules hand-written qui ne descendent pas de `ExternalToolModule` :

```python
class FlagAllowlistMixin:
    """Contrat extra_args gouverné pour les modules-wrappers ÉCRITS À LA MAIN.
    Factorise : la constante d'entrée de params, la porte fail-closed, et le finding de refus.
    Aucune capacité élargie — même allowlist, même comportement, une seule source."""

    FLAG_ALLOWLIST: tuple = ()          # déclarée par chaque module concret (inchangé)

    # (2) l'entrée de params répétée -> une classmethod qui la produit
    @classmethod
    def extra_args_param(cls, label="extra args (allowlist de drapeaux)"):
        return {"name": "extra_args", "type": "list", "label": label, "flag": ""}

    # (3) le refus fail-closed unifié (remplace les _refuse copiés)
    def _refuse(self, action, reason):
        return [self.finding(
            target=action.target, title=f"{self.kind} non exécuté — {reason}",
            severity="INFO", category="recon", status="skipped",
            tool=self._toolname(), evidence=f"{reason}. Aucun processus lancé (fail-closed).",
            poc=self.dry(action))]

    # (1+gate) la porte : None si OK, sinon le finding de refus déjà construit
    def gate_extra_args(self, action):
        bad_extra, _ = check_extra_args((action.params or {}).get("extra_args"), self.FLAG_ALLOWLIST)
        return self._refuse(action, f"argument libre refusé ({bad_extra})") if bad_extra is not None else None
```
> **Note d'exactitude comportementale :** le libellé/`category`/`status` du finding de refus doit
> être aligné **verbatim** sur ce que chaque module produit aujourd'hui (ex. `status="skipped"`
> vs le message exact). Si les modules divergent sur le wording, **conserver le wording par
> module** en le passant en argument, OU migrer d'abord les wordings vers une forme commune dans
> une étape isolée AVANT d'introduire le mixin — sinon un test de régression du finding casse.
> C'est le seul point de vigilance : la factorisation ne doit PAS uniformiser un message que les
> tests figent.

### 2.3 Séquence ordonnée (plus petit risque → plus grand)

| # | Module migré | Pourquoi cet ordre | Risque | Vérif verte |
|---|--------------|--------------------|:------:|-------------|
| 0 | **Ajouter `FlagAllowlistMixin` dans `toolspec.py`** (sans le brancher) + tests unitaires du mixin | Introduit le socle sans toucher aucun module → build vert par construction | Très faible | `pytest` : +N tests neufs, 258 existants inchangés |
| 1 | **`web.py::NucleiScan`** (1 classe, `_refuse` local le plus simple) | Cas le plus isolé → valide le mixin sur un vrai module | Faible | `pytest -k nuclei` + suite complète ; finding de refus byte-identique |
| 2 | **`recon.py::HttpxFingerprint` puis `NmapServices`** (2 classes, `_refuse` dupliqué ×2) | Élimine la duplication la plus flagrante ; deux classes ⇒ deux commits | Faible | tests `recon`/`module_routes_do_not_conflict` |
| 3 | **`origin.py::SubfinderEnum`** (gate en 2 points : preview + fire) | Vérifie que le mixin couvre le double appel `check_extra_args` | Faible | tests `origin`/exposure |
| 4 | **`recon_active.py::ContentDiscovery`** (`PassiveSurface`, 6 refs) | Plus de points de contact ⇒ après rodage du mixin | Faible-moyen | tests `recon_active`/secret-scan |
| 5 | **`injection.py::SqliProbe`** (`InjectionOracle` → `ScopeGuardedOracle`) | Héritage multiple (mixin + chaîne Oracle) ⇒ **en dernier**, MRO à valider | Moyen | test `validate_extra_args_enforces_allowlist` (Rust) + `pytest -k sqli` |

- **Chaque migration = 1 commit** : remplacer, dans le module, le `_refuse` local + le
  `{"name":"extra_args",...}` littéral + l'appel `check_extra_args`+garde par le mixin
  (`class X(FlagAllowlistMixin, ...)`, `params=[..., self.extra_args_param()]`,
  `if (r := self.gate_extra_args(action)): return r`). **La constante `FLAG_ALLOWLIST` reste
  déclarée par le module** (elle est intrinsèque à l'outil enveloppé — ne PAS la centraliser).
- **Piège MRO (étape 5) :** `InjectionOracle` descend déjà de `ScopeGuardedOracle`
  (`ScopeGuardMixin, Oracle`). Ajouter `FlagAllowlistMixin` en **tête** de bases
  (`class SqliProbe(FlagAllowlistMixin, InjectionOracle)`) pour que ses méthodes priment sans
  masquer `finding`/`_in_scope` de la chaîne Oracle. Valider par `SqliProbe.__mro__` + le test.
- **Non-objectif :** on ne fusionne PAS ces modules dans `ExternalToolModule` (ils ont une logique
  de parsing/jugement propre non générable depuis un `ToolSpec`). Le mixin factorise uniquement la
  plomberie `extra_args`, pas le corps métier.

### 2.4 Gain
- Supprime ~4 copies de `_refuse`, ~6 littéraux `{"name":"extra_args",...}`, et unifie la porte
  `extra_args` en une source unique — **sans** changer une allowlist ni un argv généré (les tests
  `validate_extra_args_enforces_allowlist` et `plan_threads_and_validates_module_params_extra_args`
  restent le filet).
- Aligne les modules hand-written sur le contrat déjà porté par `ExternalToolModule`, réduisant la
  divergence future (le prochain module wrapper hérite du bon comportement par défaut).

---

## 3. Ce que ce plan n'est PAS

- **Pas un big-bang.** Aucune étape ne dépend de la suivante pour être verte ; on peut s'arrêter
  après l'Étape 1 de chaque chantier et avoir déjà encaissé l'essentiel du gain.
- **Pas une réécriture.** Zéro logique nouvelle : déplacements de texte + une base partagée dont
  le corps est copié des implémentations existantes.
- **Pas de changement de surface communautaire.** Binaire release byte-identique ; findings,
  routes, codes de sortie, allowlists — tous inchangés.
- **Opportuniste.** Déclencheur : « je touche déjà cette zone » ou une fenêtre de dette budgétée.
  Jamais « refactorons pour refactorer ».
