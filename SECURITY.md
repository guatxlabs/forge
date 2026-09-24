# Politique de sécurité

Forge est un moteur de sécurité offensive **gouverné** : toute sa proposition de valeur tient à ce
que les attaques ne puissent pas se déclencher hors d'un scope autorisé et à ce que chaque action
soit prouvable. Un défaut dans cette gouvernance est un bug sérieux, et nous voulons en être
informés.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une vulnérabilité de sécurité.**

Signalez en privé, par l'un ou l'autre canal :

1. **GitHub Security Advisories** *(à privilégier)* — le bouton « Report a vulnerability » de
   l'onglet **Security** de ce dépôt. Il garde le signalement, la discussion et le correctif
   coordonnés et privés de bout en bout, et nous permet de vous créditer à la divulgation.
2. **E-mail** — `security@guatx.com`, si vous préférez ne pas utiliser de compte GitHub, ou si le
   problème concerne le dépôt lui-même.

Merci d'utiliser l'un de ces canaux plutôt qu'une issue publique, une pull request ou un message
direct.

Merci d'inclure : la version/le commit affecté, une description, les étapes de reproduction ou un
PoC, et l'impact. Les GitHub Security Advisories sont privés de bout en bout, aucun chiffrement
supplémentaire n'est donc nécessaire.

Nous visons un **accusé de réception sous 3 jours ouvrés** et un accord avec vous sur un calendrier
de remédiation. Nous pratiquons la **divulgation coordonnée** et vous créditerons (sauf si vous
préférez rester anonyme) une fois un correctif publié.

## Ce qui est dans le périmètre

Un bug de sécurité dans Forge, c'est tout ce qui laisse une action échapper au modèle de sûreté, ou
qui fuite des données/secrets. En particulier :

- **Contournement du scope-guard / de la ROE** — une action qui se déclenche contre une cible hors
  `in_scope`, ou une action `exploit`/`destructive` qui se déclenche sans l'autorisation `allow_*`
  correspondante.
- **Intégrité du ledger** — forger, réordonner, tronquer ou rétrograder une entrée de ledger
  d'engagement signée de sorte que `verify()` passe quand même.
- **Isolation tenant / engagement** — lire les findings/données d'un autre engagement ou tenant
  (p. ex. via la surface GXQL) sous le module multi-tenant (flag-gated).
- **Fuite de secret** — des credentials de session opérateur, des clés d'API ou des clés de
  signature qui s'échappent dans un finding, le ledger, un rapport, un log ou une réponse d'API.
- **AuthN/AuthZ** — contournement d'authentification de la console, élévation de privilèges, IDOR
  cross-tenant.
- **Injection / RCE** dans le moteur ou la console (commande, SQL, path traversal, désérialisation).
- **Élargissement de capacité via la config** — un champ de scope, un `module_param`, un plugin ou
  un profil de ressources qui accorde une capacité que l'opérateur n'a pas autorisée.

## Ce qui N'EST PAS une vulnérabilité

- **Utiliser Forge contre une cible que vous n'êtes pas autorisé à tester.** Forge applique *et
  prouve* l'autorisation ; il ne l'accorde pas, et ne le peut pas. Le mésusage relève de la
  responsabilité de l'opérateur.
- **Franchir un WAF/Cloudflare/anti-bot.** C'est un facilitateur d'accès, pas une vulnérabilité —
  voir le README.
- **Les limites documentées et assumées** du déploiement par défaut (p. ex. l'accès host-root à une
  clé de signature de ledger co-localisée — voir [`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md) — ou
  des collecteurs de détection qui échouent *ouvert* sur une erreur de mesure). Ce sont des
  compromis de durcissement de déploiement, documentés avec leurs mitigations opt-in. Ne les
  signalez que si vous pouvez défaire la mitigation ou démontrer un impact *nouveau*.

## Versions supportées

Forge est en pré-1.0 et n'a **encore aucune release taguée**. Les correctifs de sécurité
atterrissent sur `main`, la seule chose maintenue, merci donc de citer un commit `main` dans votre
signalement.

| Version | Supportée |
|---------|-----------|
| `main` | ✅ |
| releases taguées | aucune n'existe encore |

Cette section nommera les versions supportées une fois que des tags existeront — pas avant. Annoncer
un support par version alors qu'aucune version n'existe serait une fausse promesse, et enverrait
celui qui signale chercher un numéro de release introuvable.

## Durcissement & audits

Forge livre un modèle de sécurité documenté ([`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md),
[`docs/KEY_CUSTODY.md`](docs/KEY_CUSTODY.md)) et un pipeline CI qui lance `cargo audit` et du secret
scanning. Les contrôles de sûreté cœur (scope-guard, gate ROE à 4 couches, ledger tamper-evident,
planner coverage-safe) sont couverts par des tests. Une revue adverse interne de la base de code a
été menée et les problèmes qu'elle a identifiés ont été corrigés avant la publication.
