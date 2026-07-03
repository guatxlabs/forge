# Forge — Plan & Roadmap

> 🧭 [Documentation Forge](README.md) · Voir aussi : [Vue d'ensemble](OVERVIEW.md) · [Positionnement](POSITIONING.md)

> ✅ MISE À JOUR 2026-06-28 — **Étape 2** (P1 vendable : reporting + comptes) & **Étape 3**
> (crédibilité offensive) ainsi que le **blocker #6** (comptes utilisateurs / attribution
> individuelle) sont **LIVRÉS dans `f3495d6`**. Seul reste ouvert ⏳ le **blocker #5**
> (vrai finding terrain réel). Le reste de ce plan est conservé pour l'historique et le contexte.

## Positionnement

Forge = couche d'orchestration red-team **GOUVERNÉE** + mesure **PURPLE**, companion de
Plume (blue).

- **Segment** : red-team **auditable sous conformité + purple intégré**.
- **Acheteur** : RSSI / lead purple / juridique — **PAS** le pentester chasseur d'exploits.

> **Slogan** : « Forge n'est pas un remplaçant de Metasploit — c'est la couche gouvernance
> + preuve + mesure purple par-dessus les outils que vous avez déjà (il pilote MSF/Burp/nuclei). »

## Red / Blue / Purple

- **Plume = BLEU** (détection / SOC).
- **Forge = ROUGE** (offensif).
- **« Purple » n'est PAS un 3ᵉ produit** : c'est la boucle de collaboration rouge × bleu
  (rouge + bleu = violet). La matrice de couverture (tiré vs détecté → detected / missed / MTTD)
  **EST** cette boucle.

**Le MOAT** = rouge + bleu **MÊME VENDEUR**, corrélés par ATT&CK + preuve d'autorisation signée
(ROE fail-closed + ledger Ed25519) — ce qu'aucun incumbent (MSF / Cobalt Strike / Maltego / Splunk)
n'a.

## ✅ Déjà fait

- **Audit** : 34 bugs, 4 HIGH fermés (CSPRNG fallback, downgrade ledger, bypass scope CIDR, XSS).
- **Parité CLI ↔ UI** (+ opt-in exploit gouverné).
- **Connecteurs** MSF / Burp.
- **Fondation P0** : git v0.0.1, packaging / Makefile / pyproject, Docker / compose / systemd / CI,
  `forge doctor`, LICENSE.
- **Boucle purple** (code + tests, vérifiée en mocké).

## Roadmap séquencée

### Étape 1 — GO LIVE PURPLE (en attente de Plume déployée)

Câbler `PLUME_URL` → Plume prod (JOIN lecture seule) + 1ʳᵉ campagne purple réelle sur cible lab
autorisée → 1ʳᵉ matrice avec vraies détections SOC + MTTD réel. (Voir
[`PURPLE_PREREQS.md`](PURPLE_PREREQS.md).)

### Étape 2 — P1 vendable

- Export PDF / HTML client (#4).
- Comptes utilisateurs / attribution individuelle (#6).

### Étape 3 — crédibilité offensive

- Durcir l'oracle IDOR (fragile : faux positifs / faux négatifs).
- 2-3 oracles à-preuve (SSRF callback-vérifié, auth / ATO).
- Engine **ITÉRATIF** (chaînage recon → origin → nuclei → idor).
- Connecteur MSF session-poll (preuve réelle, pas faux positif).

### Étape 4 — GTM

- Page de positionnement + pricing (tier « Purple » premium vs MSF Pro ~15k$/seat).
- 1 write-up d'engagement de référence.

## Statut des 6 blockers

| # | Blocker | Statut |
|---|---|---|
| 1 | secrets / .gitignore | ✅ |
| 2 | versionnement / packaging | ✅ |
| 3 | boucle purple | ✅ (code + tests ; reste démo live) |
| 4 | livrable PDF | 🟡 (rapport console complet ✓, reste export PDF / HTML brandé) |
| 5 | vrai finding terrain | ⏳ |
| 6 | comptes utilisateurs | ⏳ |

## Avis offensif honnête

- Profondeur offensive native **FAIBLE** (1 oracle à-preuve fragile + wraps + connecteurs).
- Ne **PAS** courir après la parité MSF / CS (perdu d'avance, hors-charte).
- Miser sur **gouvernance + purple + oracles à-preuve crédibles**.
- L'expérience **BLEUE** de l'auteur est l'avantage déloyal (la mesure purple, où rouge rencontre
  bleu).
- **NE PAS** : beacon / C2 maison, Cellebrite / forensics, course au nombre d'exploits.

## Time-to-sellable

~4-5 mois solo jusqu'à un 1er client convaincu par la démo purple.

**Risque principal = FOCUS** : la boucle purple doit rester **#1**, sinon dispersion.
