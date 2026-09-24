# Forge — Prestations & tarification (PROPOSITION)

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Positionnement](POSITIONING.md) · [Vue d'ensemble](OVERVIEW.md)

> ⚠️ **Statut : PROPOSITION de travail, pas un engagement commercial.** Les montants ci-dessous sont
> des ordres de grandeur pour cadrer la discussion GTM (cf. [`POSITIONING.md`](POSITIONING.md)). Aucun
> tarif n'est ferme tant qu'un premier engagement de référence n'a pas validé la valeur de couverture
> (cf. [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md)).

> 💡 **Le produit est gratuit et open source.** Forge est publié sous **[AGPL-3.0-or-later](../LICENSE)**,
> avec **toutes** ses capacités — y compris les modules avancés (multi-tenant/MSSP, SSO/SCIM, RBAC avancé,
> conformité WORM/legal-hold, signeur de ledger hors-host). Il n'y a **ni édition payante, ni fonction
> bridée derrière un paywall** : ce qui se facture, ce sont des **prestations de service** autour de
> l'outil, jamais l'outil lui-même. Détail des modules : [`ADVANCED_MODULES.md`](ADVANCED_MODULES.md).
>
> « Gratuit / libre » vaut au sens des **libertés AGPL-3.0**, pas « sans obligation » : l'AGPL est un
> **copyleft fort** — source à offrir sur usage réseau (§13), dérivés qui restent sous AGPL, mentions de
> licence préservées (cf. [`LICENSE`](../LICENSE)).

---

## 1. La logique de prix

On ne tarife **PAS** le logiciel (il est libre) ni le nombre d'exploits (Forge n'en fournit pas — il
pilote MSF/Burp/nuclei). La facturation porte sur la **prestation** — la valeur de gouvernance et de
couverture mesurée qu'un accompagnement apporte :

- ce que coûte aujourd'hui au client de **prouver manuellement** qu'un red-team est resté in-scope
  (heures juridiques + risque d'audit) ;
- ce que vaut de **chiffrer la couverture défensive** (le SOC voit-il 40 % ou 80 % des techniques ?
  combien coûte un trou non détecté ?) ;
- l'effet **même-vendeur** rouge × bleu : un seul interlocuteur pour la boucle purple, une seule
  corrélation ATT&CK.

**Ancrage marché** : Metasploit Pro se vend ~**15 000 $/siège/an** pour de la *capacité* offensive.
Forge n'achète pas la capacité (le client l'a déjà) et ne vend **aucune licence produit** — il vend la
**preuve + la mesure**, livrées par une prestation. La valeur se justifie par la couverture mesurée, pas
par la capacité brute ni par un droit d'usage du code.

---

## 2. Les prestations (proposition)

| Prestation | Contenu | Pour qui | Ordre de grandeur |
|---|---|---|---|
| **Engagement de référence** ⭐ | Une campagne autorisée de bout en bout : périmètre + gate ROE, **ledger Ed25519 tiers-vérifiable**, **matrice de couverture ATT&CK** (detected / missed / MTTD réel) et rapport livré. C'est le livrable qui prouve la valeur. | Premier client / audit ponctuel qui veut chiffrer sa couverture. | Forfait par engagement. |
| **Accompagnement purple** | Câblage **Forge × Plume** (SOC bleu), mise en place de la boucle de couverture, comblement itératif des trous, montée en compétence de l'équipe interne. | RSSI / lead purple qui veut installer la boucle dans la durée. | Forfait ou régie. |
| **Support & SLA** | Support ouvré, mises à jour, aide au déploiement — **y compris les modules avancés** (multi-tenant/MSSP, SSO/SCIM, conformité WORM, ancrage ledger hors-host) —, revue de scope, réponse priorisée. | Équipe interne stable / MSSP avec roster d'opérateurs. | Abonnement annuel. |
| **Hébergement / managé** | Forge opéré par GuatX : ancrage du ledger hors-host, sauvegardes chiffrées, mises à jour, supervision. | Client régulé / sans équipe ops dédiée. | Sur devis. |

> Le produit reste **entièrement auto-hébergeable et gratuit** dans chacun de ces cas. La prestation ne
> déverrouille aucune fonction : elle apporte du **temps expert, de la garantie et de la preuve livrée**.

---

## 3. Axes de facturation (esquisse, à arbitrer)

Deux modèles plausibles, non exclusifs :

### (a) Par-engagement
- **Unité** : une campagne autorisée (un scope, un ledger, une matrice de couverture livrée).
- **Adapté à** : cabinets de conseil / audits ponctuels, premiers clients (faible engagement initial).
- **Livrable facturé** : le rapport d'engagement signé + la matrice purple (cf. template).

### (b) Support / abonnement annuel
- **Unité** : contrat de support par opérateur actif (siège) ou par périmètre.
- **Adapté à** : équipe interne stable, MSSP avec roster d'opérateurs.
- **Note d'archi** : le build par défaut est **stateful single-replica** (SQLite + ledger sur PVC
  RWO, cf. [`DEPLOYMENT.md`](DEPLOYMENT.md)) → profil idéal **mono-opérateur / petit MSSP**. Le
  **multi-tenant scale-out** est un **module open, flag-gated** (`FORGE_ENTERPRISE_STORE=postgres`,
  ledger hors-host, cf. [`ADVANCED_MODULES.md`](ADVANCED_MODULES.md)) : disponible dans le code,
  mais son **exploitation en managé multi-client** relève de la prestation d'hébergement.

> **Recommandation GTM** : démarrer **par-engagement** (faible friction, prouve la valeur sur un
> premier client de référence), puis basculer les clients récurrents en **support/abonnement**.

### Niveaux de support
| Niveau | Contenu | |
|---|---|---|
| **Communautaire** | Docs, best-effort, pas de SLA. | gratuit, avec l'open source |
| **Standard** | Support ouvré, mises à jour, aide au câblage Plume. | prestation |
| **Priorisé** | Réponse priorisée, onboarding accompagné, aide à l'ancrage ledger hors-host, revue de scope, déploiement des modules avancés. | prestation, sur devis |

---

## 4. Ce qui justifie la valeur de l'accompagnement purple (argumentaire)

1. **Valeur de couverture mesurée** : passer d'un SOC « on pense être couverts » à « on détecte
   N techniques ATT&CK sur M, MTTD médian = X min » est un livrable directement présentable au COMEX
   et à l'auditeur. C'est la sortie native de la boucle purple.
2. **Un seul interlocuteur pour rouge + bleu** : pas d'intégration tierce fragile entre l'outil offensif
   et le SIEM — la corrélation ATT&CK est native (champ `mitre` joint en lecture seule).
3. **Preuve d'autorisation incluse** : le ledger Ed25519 vérifiable par un tiers réduit le coût
   juridique/audit de chaque campagne (moins d'heures d'avocat pour « prouver qu'on est resté
   in-scope »).
4. **Safe-by-default** : moindre risque opérationnel (inerte par défaut, fail-closed) = argument
   d'assurance / conformité.

---

## 5. Limites honnêtes à dire au prospect

- **Capacité offensive brute faible** : si le besoin est « plus d'exploits / du post-ex / du C2 »,
  Forge n'est PAS la réponse — garder MSF/CS, ajouter Forge par-dessus.
- **Maturité v0.0.1** : les premiers clients sont des **design partners** (prestation à tarif réduit
  contre retour terrain et droit de référence).
- **Single-replica par défaut** : le multi-tenant scale-out **existe** comme module open flag-gated,
  mais l'**offre managée multi-client** (SLA, ancrage hors-host opéré par GuatX) est une roadmap de
  prestation, pas un acquis.

---

*Voir aussi : [`POSITIONING.md`](POSITIONING.md) (le pitch + teardown concurrentiel) ·
[`ADVANCED_MODULES.md`](ADVANCED_MODULES.md) (les modules avancés open, flag-gated) ·
[`DEPLOYMENT.md`](DEPLOYMENT.md) (contrainte single-replica) · [`PLAN.md`](PLAN.md) (roadmap).*
