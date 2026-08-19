<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Forge — Roadmap

> **État : pré-1.0**, licence AGPL-3.0-or-later. Le build par défaut (communautaire) est
> **openssl-free** (rustls/ring) ; le cœur partagé est consommé via la git-dep publique épinglée
> [`guatxlabs/core`](https://github.com/guatxlabs/core).
> Documentation : [`docs/README.md`](docs/README.md) — installation, déploiement, référence CLI/API,
> modèle de sécurité.

Cette page décrit **ce qui est livré**, **ce qui reste ouvert** et **comment contribuer**. Les
changements datés sont dans [`CHANGELOG.md`](CHANGELOG.md) ; le détail d'un correctif est dans le
message du commit qui le porte.

## Livré

- **Intégrité des verdicts** — un oracle ne rend pas de verdict négatif sur une cible qu'il n'a pas
  atteinte. Une sonde sans réponse produit `skipped` (« je n'ai pas pu vérifier »), jamais `tested`
  (« vérifié, rien trouvé »). La distinction porte sur les classes usuelles : IDOR, ATO, SSRF, SQLi,
  élévation de privilèges, traversée de chemin.
- **Cœur de sûreté** — gate ROE fail-closed à 4 couches (armé → in-scope → capacité → approuvé),
  scope-guard, plancher exploit opt-in, ledger d'engagement tamper-evident (chaîne SHA-256 +
  Ed25519 par entrée, vérifiable par un tiers avec la seule clé publique).
- **Périmètre par port** — un motif de scope peut restreindre un hôte à un seul port
  (`example.com:3000`) ; sans port il porte sur l'hôte entier. Face à une cible qui ne révèle aucun
  port, `in_scope` refuse et `out_scope` bloque : chacun va vers la sûreté, il n'existe pas de
  réponse neutre.
- **Moteur** — planner coverage-safe (aucune classe qualifiante affamée en silence), oracles à
  preuve sur les classes web usuelles, chaînage recon → découverte de services → scan de contenu,
  arsenal d'outils CLI gouvernés (ToolSpec déclaratif, no-shell) + plugins drop-in, importateurs de
  scans, triage natif zéro-egress, assist LLM optionnel (off par défaut, egress-gaté, advisory).
- **Boucle purple** — run-records taggés ATT&CK, source de détection **plugin configurable**
  (Plume, CrowdSec, FortiGate, pfSense/OPNsense, Elastic/OpenSearch, fichier, exec), matrice de
  couverture exercé × détecté × MTTD.
- **Console** — wizard de premier déploiement (aucun défaut codé en dur), RBAC
  admin/opérateur/viewer, explorateur GXQL read-only, dashboards, gestion des runs, ajout d'outils
  et paramètres par-outil depuis l'UI, runner de sous-commandes gouverné, notifications,
  ownership + workflow de triage, exports HTML/PDF/CSV/JSON par engagement.
- **Entreprise / passage à l'échelle** — backend Postgres, topologie HA multi-instance, manifestes
  Kubernetes avec NetworkPolicies deny-by-default, isolation multi-tenant par-ligne, RBAC
  par-engagement, SSO OIDC + SCIM 2.0 (SAML via pont OIDC), rétention/legal-hold/export de preuves.
- **Cycle de vie** — sauvegardes toujours chiffrées (argon2id + XChaCha20-Poly1305) avec
  programmation et offsite, upgrade une-commande avec rollback automatique, migration de données,
  chiffrement au repos SQLCipher (image opt-in), custody de clé off-host PKCS#11 / KMS.
- **Ressources réglables au lancement** — profil unifié `low|balanced|full` **plus** des leviers
  individuels dans l'UI, générés depuis la table du moteur plutôt qu'une copie qui dériverait.
  L'allowlist est compilée côté serveur — le parseur itère les leviers connus et va chercher leur
  clé dans la requête, donc une clé inconnue est inatteignable par construction. Forge doit pouvoir
  tourner sur une machine contrainte sans la saturer, et aucune valeur de ressource n'est figée
  dans le code.

## Gouvernance du dépôt

Deux règles s'appliquent à toute contribution, humaine ou automatisée. Elles sont **vérifiées par
la machine** : un commit qui les enfreint est refusé. Le détail opérationnel, écrit pour un lecteur
sans contexte préalable, est dans [`AGENTS.md`](AGENTS.md).

**1. Une seule identité publique** — `guatxlabs <noreply@guatx.com>`, en auteur **et** en committer.
Aucune adresse personnelle ni nominative. Un dépôt publié sous un collectif ne doit pas exposer le
compte personnel de qui l'écrit.

**2. Un message de commit s'adresse à un lecteur public** — quelqu'un qui n'était pas dans la pièce,
qui ne connaît ni la session ni son auteur, et qui doit pouvoir agir sur ce qu'il lit. Un commit dit
**ce qui change et pourquoi**. Sont exclus le récit d'enquête à la première personne, l'adresse
directe à un interlocuteur, et la chronologie de session comme fil narratif. Restent admis la voix
de l'outil, une date de mesure, et un « pourquoi » long — la longueur n'a jamais été le défaut.

La première personne est refusée **en bloc**, pas verbe par verbe : une énumération ne peut pas être
complète, et celle qui l'a précédée laissait passer `j'ai inséré` là où elle refusait `j'ai mesuré`.
La voix de l'outil, qui s'écrit à la première personne, passe en portant une **marque de citation**
— guillemets, code entre backticks, ou ligne `>`. Le détail opérationnel, écrit pour un lecteur sans
contexte préalable, est dans [`AGENTS.md`](AGENTS.md).

Deux barrières appliquent ces règles depuis une **seule** implémentation
([`scripts/check_commit_register.py`](scripts/check_commit_register.py)) : le hook `commit-msg`
(`make hooks`) et un job de CI. Le hook ne ferme pas — `git clone` ne le transporte pas et l'édition
via l'interface web ne l'exécute jamais. **C'est la CI qui ferme** ; le hook évite seulement d'avoir
à corriger après coup. Les deux slots d'identité sont vérifiés, auteur **et** committer, et une
plage que git n'a pas su lire est un refus : une barrière échoue fermée.

## Ce qui reste ouvert

Ces points sont connus et nommés parce qu'un lecteur technique a besoin de savoir où sont les bords.
Aucun ne se corrige par un simple correctif.

- **Couverture des API GraphQL** — les classes d'injection y vivent derrière un point d'entrée
  unique, et le point d'injection est un argument à l'intérieur de la requête. Le moteur sait
  désormais l'atteindre — gabarit de corps avec échappement des deux contextes imbriqués (chaîne
  GraphQL dans chaîne JSON), chaînage automatique depuis l'introspection du schéma. La couverture
  reste inférieure à celle des surfaces REST classiques.
- **Le débit ne borne que ce que Forge émet lui-même.** Le plafond porte sur le point de passage
  HTTP du moteur. Un outil tiers piloté par Forge qui frappe la cible par son propre client — le
  scanner d'un proxy d'interception, par exemple — émet un trafic que ce plafond ne voit pas. À
  l'inverse, le trafic de plan de contrôle vers les services **de l'opérateur** n'est
  délibérément pas compté contre le budget de requêtes de la cible.
- **Surfaces authentifiées** — atteindre les pages internes d'une application suppose de porter une
  session jusqu'aux outils de découverte. Les outils qui ne déclarent pas de paramètre d'en-tête ou
  de cookie explorent en anonyme et ne voient donc que la surface publique.
- **Crawl et rendu JavaScript** — la découverte de surface repose sur des outils externes dont les
  capacités varient. Une application dont la navigation n'existe qu'à l'exécution est moins bien
  couverte qu'une application servie côté serveur.

## Limites assumées et documentées

- **Intégrité d'audit vs compromission host-root** — par défaut la clé de signature est locale et
  l'ancre est nulle. Deux contrôles opt-in ferment ce cas : signeur off-host (PKCS#11 / KMS) et
  ancre témoin. Voir [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md).
- **Collecteurs de détection fail-open par conception** — ils alimentent le reporting et la mesure
  de couverture, **jamais** une décision de tir : scope, ROE et ledger restent fail-closed.
- **Un secret PEUT partir en clair vers une cible INTERNE explicitement autorisée.** C'est la seule
  exception survivante à « pas de clair », et elle est étroite : il faut à la fois une adresse
  **privée**, une autorisation **explicite** (`FORGE_ALLOW_INTERNAL_INTEGRATIONS`), et rien de tout
  cela n'est le défaut. Vers une cible **publique**, un secret en clair est refusé avant connexion,
  sans variable pour l'ouvrir.
  *Pourquoi elle reste ouverte* : exiger `https` dès qu'un secret existe casse le déploiement
  on-prem de référence — un collecteur interne authentifié sans écouteur TLS. Une AC d'entreprise
  n'y change rien : elle fournit une **ancre**, pas un **écouteur**. Fermer cette porte est un
  arbitrage de produit, pas une dette technique ; techniquement, c'est une condition unique dans
  `net::reject_cleartext_secret`, au prix d'une rupture nette pour ces installations.
- **Matériel d'authentification dans les sauvegardes** — une archive contient la base entière, donc
  tout matériel d'auth stocké. C'est **inhérent** : une sauvegarde doit restaurer fidèlement, et
  rédiger l'archive ferait perdre le contexte à la restauration. La garantie n'est donc pas « pas de
  secret dans l'archive » mais **« aucune archive en clair ne peut exister »** — le chiffrement est
  obligatoire et fail-closed sur les trois chemins (API, CLI hors-ligne, planificateur), la
  passphrase vient de l'environnement et jamais d'argv, et deux couches indépendantes le refusent.

## Décisions produit actées

- **Pas de SAML in-process.** Le pont OIDC (Dex / Keycloak / oauth2-proxy) est la voie supportée :
  un SAML natif tirerait openssl + libxmlsec1 — ce qui casse le build openssl-free — et un XML-DSig
  maison est un piège. Une feature Cargo `saml` optionnelle reste différée.
- **Pas de driver KMS cloud dédié.** Le signeur PKCS#11 couvre HSM et CloudHSM, et le signeur `exec`
  générique couvre un KMS Ed25519 (recette dans [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md)).
  AWS-KMS ne signe pas Ed25519 et n'est donc pas utilisable pour ce ledger.
- **Le débit (`rate`) est une donnée de gouvernance** portée par le scope et les règles
  d'engagement, pas un levier de profil de ressources.

## Contribuer

Les correctifs, modules et ToolSpecs sont bienvenus. Lire d'abord
[`CONTRIBUTING.md`](CONTRIBUTING.md) (invariants de sûreté à ne pas casser, build et tests),
[`AGENTS.md`](AGENTS.md) (règles de commit, vérifiées par la machine) et
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Pour une vulnérabilité, suivre
[`SECURITY.md`](SECURITY.md) — pas d'issue publique. Les points ouverts ci-dessus le sont
réellement : ouvrir une issue pour en discuter avant un gros chantier.
