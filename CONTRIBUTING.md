# Contribuer à Forge

Merci de votre intérêt pour Forge — le moteur red-team gouverné. Les contributions sont bienvenues,
sous quelques règles qui existent parce que Forge est un outil **safety-critical, qui applique
l'autorisation**.

En contribuant, vous acceptez que votre contribution soit licenciée sous **AGPL-3.0-or-later** (la
licence du projet), et vous certifiez le [Developer Certificate of Origin](https://developercertificate.org/)
en signant vos commits (`git commit -s` → ajoute `Signed-off-by:`).

## Non négociable : les invariants de gouvernance

Une pull request qui affaiblit l'un d'eux sera **rejetée**, aussi utile la fonctionnalité soit-elle :

- **Le scope-guard est fail-closed.** Toute requête sortante passe par le contrôle in-scope /
  `allow_private` *avant* toute I/O. Un scope vide signifie que rien ne se déclenche.
- **La gate ROE à 4 couches** (`forge/roe.py`) reste intacte : armed → in-scope → capability
  (`allow_exploit`/`allow_destructive`) → approved. Toute erreur d'évaluation est un `VETO`.
- **Le plancher exploit tient.** Aucune action `exploit`/`destructive` ne se déclenche sans
  autorisation explicite. Les flags de capacité sont dérivés des attributs de classe des modules et
  ne sont jamais qu'*élevés*, jamais accordés par la config, un `module_param`, un plugin ou un
  profil de ressources.
- **Le ledger est append-only et tamper-evident.** N'ajoutez pas de chemin de code qui mute,
  réordonne ou rétrograde une entrée signée, ou qui laisse `verify()` passer sur une chaîne altérée.
- **Les secrets sont rédigés à la frontière.** Les credentials de session, les clés d'API et les
  clés de signature ne doivent jamais atteindre un finding, le ledger, un rapport, un log ou une
  réponse d'API.
- **Le planner est coverage-safe** — les classes de vulnérabilités qualifiantes ne sont jamais
  affamées en silence ; les reports sont signalés, jamais abandonnés.
- **Les findings sont orientés preuve.** Un oracle ne promeut vers `vulnerable` que sur une preuve
  authentique, jamais sur un signal bénin.

En cas de doute, ajoutez un test qui prouve que l'invariant tient toujours.

## Build & tests

> **Note (build open-source) :** la console Rust dépend de `guatx-core` via une **git-dep publique
> épinglée** (`git = "https://github.com/guatxlabs/core", tag = "v0.2.1"` ; cf. `console/Cargo.toml`).
> Un clone standalone de *ce* dépôt build la console directement — le core est récupéré depuis GitHub
> au build. Pour un checkout de dev en monorepo, `console/.cargo/config.toml` (gitignoré) `[patch]`e
> la git-dep vers un `../../core` local.

```sh
make test           # suite complète : Python (unittest/pytest) + Rust (cargo test)
make test-py        # moteur Python seul (stdlib, zéro réseau)
make test-rust      # console Rust seule (offline)
make test-purple    # boucle purple bout-en-bout (nécessite un binaire console buildé — voir plus bas)
make doctor         # diagnostique les modules + outils/services attendus
```

Tout doit être **vert** et **offline** — les tests ne doivent toucher ni au réseau ni à une cible
réelle.

> **La boucle purple est testée de bout en bout, pas seulement côté par côté.** `make test-purple`
> (`scripts/purple_loop_e2e.py`, lancé par le job CI `purple-e2e`) pilote toute la chaîne sur une seule machine :
> le moteur déclenche le module synthétique `demo.fingerprint` → les run-records sont POSTés vers un vrai
> binaire console (`/api/ingest`) → la console interroge le stub SOC de démo `tools/mock_plume.py`
> (`GET /api/coverage/detections?since=…`) → `GET /api/purple/coverage` est confronté aux attentes
> *dérivées des tirs réels* (ensembles detected/missed, `detection_rate`, MTTD par technique). Cela reste
> dans la règle « aucune I/O réseau offensive » : le stub ne fait jamais que **répondre** sur 127.0.0.1, les cibles sont
> des littéraux d'IP loopback (donc la ROE les épingle sans aucune résolution DNS), et `demo.fingerprint` émet un
> finding synthétique sans toucher au réseau. Il faut un binaire console — passez
> `CONSOLE_BIN=console/target/debug/forge` si vous n'avez pas buildé en `--release`.

> **Un outil optionnel : un runtime JavaScript (`node`).** Le garde de gouvernance du SPA
> (`tests/test_console_spa_governance.py`) prouve *par exécution* que l'unique porte réseau de la console
> attache la preuve opérateur : il importe le vrai module API sous `node` avec chaque primitive réseau
> instrumentée. Des contrôles textuels ont été tentés et trompés de façon mesurable (un helper vidé, un nom
> sosie, même une chaîne morte gardaient la suite verte alors que chaque écriture partait sans preuve). Il pilote aussi la porte selon un
> plan de VARIATION — chaque route déclarée par le serveur, plus des formes d'URL générées, croisées avec l'ensemble fermé des
> méthodes HTTP et quelques méthodes d'extension inventées — de sorte qu'une décision de preuve qui dépend de l'URL ressort
> comme une incohérence plutôt que d'avoir à être devinée. Sans `node`, ces **six tests sont skippés avec un message
> explicite** — le reste du garde est en pur stdlib et tourne quand même.
> La CI pose `FORGE_REQUIRE_JS_RUNTIME=1`, qui transforme l'absence en **échec**, pour que le garde ne puisse jamais
> y être silencieusement off. `FORGE_JS_RUNTIME=<path>` pointe vers un runtime absent du `PATH`.

## Style de code

- **Moteur Python** — stdlib seule (aucune dép runtime au-delà de ce qui est déjà vendoré). Oracles
  à base de classes sur la base `Oracle` ; scope-guard via `ScopeGuardMixin` ; `argparse` avec
  exemples d'usage ; `log(msg, level)` avec les préfixes `[*] [+] [!] [-] [VULN]` ; **pas de shell**
  (argv fixe, jamais `sh -c`). Les nouveaux types d'outils s'enregistrent déclarativement
  (`@register` + `forge/techniques.py`).
- **Console Rust** — `openssl`-free (rustls/ring) **dans les builds par défaut et `store-postgres`,
  PAS sous `--features object-store`** (`aws-lc` transitif, cf. `docs/DEPLOYMENT.md` §3quater.1) ;
  garde : `python3 scripts/check_openssl_freedom.py`. Erreurs via `ApiError` ; le seam `Store` pour
  l'accès DB (aucun type de driver brut sur les sites d'appel) ; chaque valeur SQL bindée comme un
  `Param`.
- **SPA web** — pas d'`innerHTML` avec des données non fiables ; rendu via `textContent` / le tagged
  template `safeHtml` / `esc()`. Les écritures passent par le helper authentifié `write()`.

## Pull requests

1. Ouvrez d'abord une issue pour tout ce qui n'est pas trivial, afin qu'on s'accorde sur l'approche.
2. Un seul changement logique par PR. Gardez le diff focalisé.
3. Incluez des tests. Préservez ou améliorez la couverture.
4. Lancez `make test` et (pour les changements Rust) `cargo clippy`. Les deux doivent passer.
5. Signez vos commits (`-s`), et activez les hooks du dépôt une fois par clone :
   `git config core.hooksPath .githooks`. Le hook `commit-msg` refuse un message qui s'adresse à un
   interlocuteur, et une identité d'auteur autre que `guatxlabs <…@guatx.com>`. C'est une commodité,
   pas la barrière : les hooks ne sont pas transportés par `git clone` et ne s'exécutent jamais pour
   l'éditeur web de GitHub — le job CI `registre public` vérifie chaque commit poussé et c'est lui
   qui ferme réellement la porte.
6. **Écrivez pour un lecteur public** — dans les messages de commit, la documentation *et* les
   commentaires de code pareillement. Chacun d'eux s'adresse à quelqu'un qui n'était pas dans la
   pièce, ne vous connaît pas, et doit agir sur ce qu'il lit. Dites ce qui change et *pourquoi*. La
   longueur n'est pas un problème : un « pourquoi » mesuré vaut vingt lignes, et une date qui rend une
   affirmation traçable (« mesuré 2026-08-16 ») est de la traçabilité, pas un journal. Ce qui n'a pas
   sa place : le récit à la première personne de votre propre enquête (« j'avais écarté ceci plus
   tôt… »), l'adresse directe (« comme vous l'avez demandé »), et la chronologie de session utilisée
   comme fil narratif — cela va dans `ROADMAP.md`. Énoncer ce qu'un statut *signifie* (« un `skipped`
   dit : je n'ai pas pu vérifier ») est la voix de l'outil, et reste.
7. **Les problèmes de sécurité ne vont pas ici** — voir [`SECURITY.md`](SECURITY.md).

## Un mot sur l'intention

Forge est réservé à un usage **autorisé** uniquement (bug bounty in-scope, pentest sous contrat,
CTF, votre propre infrastructure). Les contributions qui facilitent l'*évasion d'autorisation* ou
l'attaque de cibles qui ne vous appartiennent pas sont hors périmètre pour ce projet.
