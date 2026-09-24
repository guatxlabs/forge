# Forge — Engagement de référence embarqué (FIXTURE DE DÉMO)

> ⚠️ **100 % synthétique. Pas une vraie cible, pas un vrai SOC.** Chaque hôte utilise le TLD
> réservé `.example` (RFC 2606) et chaque IP utilise une plage de documentation (RFC 5737). Ce dossier
> est livré avec Forge pour qu'une installation neuve soit **démontrable de bout en bout, hors-ligne, avec
> zéro I/O réseau**. Rien ici n'a été testé contre un système réel.

Voici un petit **engagement en labo maison** réaliste — « ACME Retail (labo) » — utilisé pour peupler une
console Forge neuve (Findings / Coverage / Purple / Runs) en une seule commande, et comme
démonstration commerciale/onboarding de ce à quoi ressemble un livrable Forge.

## Ce qu'il y a ici

| Fichier | Rôle |
|---|---|
| `scope.json` | Scope/ROE autorisé (grey-box, `allow_exploit=false`, `allow_destructive=false`). In-scope : `shop.lab.example`, `api.lab.example`, `lab.example`. Out-of-scope : `corp.internal.example`, `*.prod.example`. |
| `targets.json` | Les trois cibles synthétiques. |
| `findings.jsonl` | 6 findings répartis sur 5 techniques ATT&CK, avec CWE / sévérité / statut (IDOR, SSRF, CORS permissif, token de reset prévisible, exposition d'origine, en-têtes manquants). |
| `runrecords.jsonl` | 8 run-records ATT&CK tirés (la timeline red-team). Alimente l'onglet **Coverage** et le côté red de la jointure **Purple**. |
| `roe_decisions.jsonl` | 11 décisions de gouvernance : 8 `FIRE` + 2 `VETO` (out-of-scope, exploit non armé) + 1 `DRY_RUN`. Alimente `/api/roe` (transparence anti-masquage). |
| `detections.jsonl` | Le côté **blue** : 4 « détections SOC » taggées MITRE, servies par le stub mock-Plume. Délibérément un *sous-ensemble* de ce qui a été tiré, pour que la matrice montre les **trois** états — détecté, parent-approx et manqué. |
| `REFERENCE_ENGAGEMENT.md` | Une copie **remplie** de [`docs/REFERENCE_ENGAGEMENT_TEMPLATE.md`](../../docs/REFERENCE_ENGAGEMENT_TEMPLATE.md) — le compte rendu / livrable rédigé façon labo (caviardé). |

## La matrice purple que cela produit

Techniques tirées (red, depuis `runrecords.jsonl`) jointes aux détections (blue, depuis `detections.jsonl`) :

| ATT&CK | Tirée | Détectée | MTTD | Statut |
|---|:---:|:---:|---|---|
| T1595 — Active Scanning | ✅ | ✅ exact | 4 min | 🟢 detected-exact |
| T1046 — Network Service Discovery | ✅ | ✅ exact | 2.5 min | 🟢 detected-exact |
| T1190 — Exploit Public-Facing App (IDOR + SSRF) | ✅ | ✅ exact | 3 min | 🟢 detected-exact |
| T1212 — Exploitation for Credential Access | ✅ | ✅ exact | 6 min | 🟢 detected-exact |
| T1595.002 — Vulnerability Scanning | ✅ | ⚠️ parent `T1595` seul (3 alertes) | — | 🟠 **detected-parent-approx** |
| T1590.005 — Gather Victim Network Info: IPs | ✅ | ❌ | — | 🔴 **missed** |
| T1539 — Steal Web Session Cookie (CORS) | ✅ | ❌ | — | 🔴 **missed** |

**7 techniques tirées · 4 detected-exact · 1 parent-approx · 2 missed → taux de détection 57 % ·
MTTD moy. 232,5 s (≈ 3,9 min), max 360 s (6 min).**

> Mesuré, pas affirmé : `forge seed-demo --dir examples/reference-engagement` + `tools/mock_plume.py`
> + `GET /api/purple/coverage` renvoie `techniques_fired=7, techniques_detected=4,
> techniques_parent_approx=1, techniques_missed=2, detection_rate=0.5714285714285714,
> mttd_avg_secs=232.5, mttd_max_secs=360`.
>
> **Lisez attentivement la ligne T1595.002** — c'est tout l'intérêt de la jointure à trois états. Le SOC alerte bien sur
> `T1595` (Active Scanning), et Forge a tiré la **sous-technique** `T1595.002` (Vulnerability Scanning).
> Une règle parente n'est **pas la preuve** que le vecteur de la sous-technique est couvert, donc elle n'est **pas** comptée comme
> détectée : le taux reste **4/7**, et aucun MTTD n'est inventé pour elle. Elle n'est pas jetée pour autant — c'est
> un **angle mort nommé** : *« vous avez tiré T1595.002 ; tout ce que vous avez, c'est une règle générique T1595. »* Cette ligne est le
> livrable. Une matrice à deux états l'aurait montrée comme un simple `missed`, masquant le fait qu'une règle
> voisine existe et n'a besoin que d'être resserrée.

## Comment le lancer

Depuis la racine du dépôt :

```bash
# Console peuplée (Findings / Coverage / Runs) — hors-ligne, aucun SOC requis :
make demo            # -> http://127.0.0.1:7100

# Boucle purple complète (ajoute la matrice detected / parent-approx / missed / MTTD) avec le stub mock-Plume :
make demo-purple     # démarre tools/mock_plume.py + console avec PLUME_URL défini
```

Sous le capot, `make demo` lance `forge seed-demo --dir examples/reference-engagement`,
qui ingère ces fixtures **directement dans la base SQLite** (`FORGE_CONSOLE_DB`, défaut
`forge-demo.db`) — sans aller-retour serveur, sans réseau. C'est **idempotent** : une réexécution ne
touche que la campagne de démo `acme-lab` et jamais aucune donnée d'engagement réel dans la même base.

Vous pouvez aussi seeder manuellement et pointer vers n'importe quelle base :

```bash
FORGE_CONSOLE_DB=my.db console/target/release/forge seed-demo --dir examples/reference-engagement
```

## Sécurité

- `allow_exploit=false` / `allow_destructive=false` dans `scope.json` — les findings ont été obtenus par
  **vérification en lecture seule** (*read* IDOR cross-tenant, callback SSRF out-of-band, sonde d'en-tête
  CORS avec identifiants). Les deux lignes `VETO` de `roe_decisions.jsonl` montrent le scope-guard refusant une
  cible out-of-scope et un module d'exploit non armé ; la ligne `DRY_RUN` montre une action non approuvée
  simulée, jamais exécutée.
- `tools/mock_plume.py` est un **stub stdlib**, clairement étiqueté `DEMO FIXTURE` dans chaque réponse
  (`_demo:true`, `_warning`, en-tête `X-Demo-Fixture`). **Ne jamais** pointer un engagement réel dessus.
