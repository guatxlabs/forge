# Forge — Pricing (PROPOSITION)

> ⚠️ **Statut : PROPOSITION de travail, pas un engagement commercial.** Les montants ci-dessous sont
> des ordres de grandeur pour cadrer la discussion GTM (cf. [`POSITIONING.md`](POSITIONING.md)). Aucun
> tarif n'est ferme tant qu'un premier engagement de référence n'a pas validé la valeur de couverture
> (cf. [`REFERENCE_ENGAGEMENT_TEMPLATE.md`](REFERENCE_ENGAGEMENT_TEMPLATE.md)).

---

## 1. La logique de prix

Forge ne se tarife **PAS** au nombre d'exploits (il n'en fournit pas — il pilote MSF/Burp/nuclei).
Il se tarife sur la **valeur de gouvernance et de couverture mesurée** :

- ce que coûte aujourd'hui au client de **prouver manuellement** qu'un red-team est resté in-scope
  (heures juridiques + risque d'audit) ;
- ce que vaut de **chiffrer la couverture défensive** (le SOC voit-il 40 % ou 80 % des techniques ?
  combien coûte un trou non détecté ?) ;
- l'effet **même-vendeur** rouge × bleu : un seul fournisseur pour la boucle purple, un seul contrat,
  une seule corrélation ATT&CK.

**Ancrage marché** : Metasploit Pro se vend ~**15 000 $/siège/an** pour de la *capacité* offensive.
Forge n'achète pas la capacité (le client l'a déjà) — il achète la **preuve + la mesure**. Le tier
Purple se positionne en **premium justifié** par la couverture mesurée, pas par la capacité brute.

---

## 2. Les tiers (proposition)

| Tier | Périmètre produit | Pour qui | Ordre de grandeur |
|---|---|---|---|
| **Forge Red** | Moteur Forge seul : gate ROE fail-closed, ledger Ed25519 tiers-vérifiable, console + soql + dashboards, connecteurs MSF / Burp / nuclei. **Gouvernance + preuve, sans la boucle purple.** | Équipe red-team / MSSP qui veut auditabilité + chaîne de custody signée. | **Sous** MSF Pro (~15 k$/siège) — la valeur est la gouvernance, pas la capacité. |
| **Forge Purple** ⭐ | Tout Red **+ Plume** (SOC bleu) + boucle de couverture ATT&CK (detected / missed / MTTD réel). **Le différenciateur même-vendeur.** | RSSI / lead purple qui veut chiffrer et combler la couverture défensive. | **Premium au-dessus** de Red — justifié par la valeur de couverture mesurée (≈ tier MSF Pro et au-delà selon le périmètre). |
| **Enterprise / MSSP** | Purple + multi-engagement, attribution individuelle (comptes utilisateurs), ancrage ledger hors-host (témoin distant), export client brandé (PDF/HTML), onboarding. | Grand compte régulé / MSSP multi-clients. | Sur devis (annuel, par périmètre). |

> Le tier **Purple est le produit phare** : c'est lui qui porte le moat (rouge + bleu, même vendeur,
> corrélés ATT&CK). Red existe surtout comme porte d'entrée / upsell vers Purple.

---

## 3. Axes de facturation (esquisse, à arbitrer)

Deux modèles plausibles, non exclusifs :

### (a) Par-siège / abonnement annuel
- **Unité** : opérateur red-team actif (siège).
- **Adapté à** : équipe interne stable, MSSP avec roster d'opérateurs.
- **Note d'archi** : Forge est aujourd'hui **stateful single-replica** (SQLite + ledger sur PVC
  RWO, cf. [`DEPLOYMENT.md`](DEPLOYMENT.md)) → profil idéal **mono-opérateur / petit MSSP**. Le
  multi-tenant scale-out est une évolution (ledger hors-host + store partagé), à tarifer Enterprise.

### (b) Par-engagement
- **Unité** : une campagne autorisée (un scope, un ledger, une matrice de couverture livrée).
- **Adapté à** : cabinets de conseil / audits ponctuels, premiers clients (faible engagement initial).
- **Livrable facturé** : le rapport d'engagement signé + la matrice purple (cf. template).

> **Recommandation GTM** : démarrer **par-engagement** (faible friction, prouve la valeur sur un
> premier client de référence), puis basculer les clients récurrents en **abonnement par-siège**.

### Support / SLA (module additionnel)
| Niveau | Contenu | |
|---|---|---|
| **Community** | Docs, best-effort, pas de SLA. | inclus Red |
| **Standard** | Support ouvré, mises à jour, aide au câblage Plume. | option |
| **Enterprise SLA** | Réponse priorisée, onboarding accompagné, aide à l'ancrage ledger hors-host, revue de scope. | sur devis |

---

## 4. Ce qui justifie le premium Purple (argumentaire)

1. **Valeur de couverture mesurée** : passer d'un SOC « on pense être couverts » à « on détecte
   N techniques ATT&CK sur M, MTTD médian = X min » est un livrable directement présentable au COMEX
   et à l'auditeur. C'est la sortie native de la boucle purple.
2. **Un seul vendeur pour rouge + bleu** : pas d'intégration tierce fragile entre l'outil offensif et
   le SIEM — la corrélation ATT&CK est native (champ `mitre` joint en lecture seule).
3. **Preuve d'autorisation incluse** : le ledger Ed25519 vérifiable par un tiers réduit le coût
   juridique/audit de chaque campagne (moins d'heures d'avocat pour « prouver qu'on est resté
   in-scope »).
4. **Safe-by-default** : moindre risque opérationnel (inerte par défaut, fail-closed) = argument
   d'assurance / conformité.

---

## 5. Limites honnêtes à dire au prospect

- **Capacité offensive brute faible** : si le besoin est « plus d'exploits / du post-ex / du C2 »,
  Forge n'est PAS la réponse — garder MSF/CS, ajouter Forge par-dessus.
- **Maturité v0.0.1** : les premiers clients sont des **design partners** (tarif réduit contre
  retour terrain et droit de référence).
- **Single-replica** : pas (encore) de multi-tenant scale-out ; le tier Enterprise multi-client est
  une roadmap, pas un acquis.

---

*Voir aussi : [`POSITIONING.md`](POSITIONING.md) (le pitch + teardown concurrentiel) ·
[`DEPLOYMENT.md`](DEPLOYMENT.md) (contrainte single-replica) · [`PLAN.md`](PLAN.md) (roadmap).*
