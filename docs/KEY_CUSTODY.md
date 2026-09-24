<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Garde de clés — signature de ledger off-host (PKCS#11 / KMS / HSM)

Le ledger d'engagement de Forge est signé en **Ed25519** (asymétrique → non-répudiation : un tiers
vérifie avec la **clé publique seule**). Par défaut, la clé privée réside sur l'hôte dans
`<ledger>.ed25519` (0600) — le `LocalFileSigner` communautaire. C'est byte-identique, sans dépendance,
et stdlib-only, mais cela a une **limite connue** : la clé de signature se trouve sur le même hôte que
l'écrivain, donc **root sur cet hôte** atteint la clé.

Ce document explique comment déplacer la clé privée **off-host** pour que host-root ne puisse plus
signer, et comment un witness anchor off-host la complète.

---

## Pourquoi PKCS#11 (et pas AWS-KMS directement)

Le ledger est en **Ed25519**. Cela contraint le backend :

| Backend | Ed25519 ? | Comment Forge l'atteint |
|---|---|---|
| **AWS KMS** | ❌ RSA / ECDSA seulement — *ne peut pas* signer en Ed25519 | inutilisable directement pour ce ledger |
| **PKCS#11 (`CKM_EDDSA`)** | ✅ | `FORGE_LEDGER_SIGNER=pkcs11` (ce driver) |
| **GCP KMS** (clés `ED25519`) | ✅ | **exec signer** générique (`gcloud kms asymmetric-sign`) |
| **N'importe quel HSM / AWS CloudHSM** | ✅ (expose un provider PKCS#11) | `FORGE_LEDGER_SIGNER=pkcs11` |
| **SoftHSM2** (dev/CI) | ✅ | `FORGE_LEDGER_SIGNER=pkcs11` |

Donc **AWS-KMS ne peut pas piloter ce ledger** sans changer l'algorithme du ledger pour RSA/ECDSA (ce
que nous ne faisons délibérément pas — Ed25519 nous donne des signatures petites, déterministes, rapides
et une non-répudiation propre). **PKCS#11** est la voie vendor-neutral : SoftHSM2 en dev/CI, n'importe
quel HSM (y compris AWS CloudHSM, qui expose une bibliothèque PKCS#11) ou un pont cloud-KMS→PKCS#11 en
prod. C'est un mince FFI, donc Forge reste **openssl-free** et le moteur par défaut conserve **zéro
dépendance runtime** — rien de nouveau n'est importé tant que vous n'activez pas explicitement le signer
PKCS#11.

---

## Le signer PKCS#11 — comment il se branche

`forge/signing_pkcs11.py` ajoute `Pkcs11Signer`, une sous-classe du `RemoteSigner` existant. Il réutilise
le **même contrat fail-closed** :

- signe via le token avec `CKM_EDDSA` ;
- **re-vérifie** la signature retournée contre la clé publique avant de l'accepter — une réponse bidon ou
  incohérente est **rejetée**, jamais écrite ;
- **ne se rabat jamais** sur une clé locale ;
- n'expose que la **clé publique** à ce processus, donc `verify` / `verify_external(pubkey)` sont
  inchangés pour les auditeurs tiers ;
- une signature d'**auto-test au build** prouve que la paire de clés du token vérifie réellement avant que
  le signer soit retourné (fail fast sur un mauvais appariement token/clé).

Il est **optionnel et opt-in**. `python-pkcs11` est un **import paresseux à l'intérieur du driver** — le
build communautaire par défaut n'importe rien de nouveau et reste stdlib-only. N'installez l'extra que
lorsque vous l'utilisez :

```bash
pip install 'forge[pkcs11]'      # pulls python-pkcs11; the default install does NOT
```

### Configuration — ENV seulement (le PIN jamais sur argv)

| Variable d'env | Sens |
|---|---|
| `FORGE_ENTERPRISE_COMPLIANCE=1` | **Requis** — engage le seam de signer off-host du module compliance (gate) |
| `FORGE_LEDGER_SIGNER=pkcs11` | sélectionne ce driver |
| `FORGE_LEDGER_PKCS11_MODULE` | chemin du `.so` du provider PKCS#11 (p. ex. `libsofthsm2.so`) — **requis** |
| `FORGE_LEDGER_PKCS11_TOKEN_LABEL` | label du token (ou utiliser `…_SLOT`) |
| `FORGE_LEDGER_PKCS11_SLOT` | index de slot (alternative au label de token) |
| `FORGE_LEDGER_PKCS11_KEY_LABEL` | label de clé (`CKA_LABEL`) — label et/ou id requis |
| `FORGE_LEDGER_PKCS11_KEY_ID` | id de clé, hex ou texte (`CKA_ID`) |
| `FORGE_LEDGER_PKCS11_PIN` | **PIN utilisateur — secret, env seulement**, jamais argv/logs |

Le PIN et les détails de provider/token sont traités comme des secrets : ils n'apparaissent jamais dans
`repr`, les logs, les entrées de ledger, ni les erreurs levées (`redact_signer_config` rédige `pin`).

---

## Mise en place dev / CI avec SoftHSM2

SoftHSM2 est un token PKCS#11 logiciel — parfait pour le développement et la CI (sans matériel). Exemple :

```bash
# 1. install SoftHSM2 + the Python binding
sudo apt-get install -y softhsm2            # Debian/Ubuntu (provides libsofthsm2.so)
pip install 'forge[pkcs11]'

# 2. isolated token store (so CI leaves no global state)
export SOFTHSM2_CONF="$PWD/softhsm2.conf"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$PWD" > "$SOFTHSM2_CONF"
mkdir -p "$PWD/tokens"

# 3. init a token
softhsm2-util --init-token --free --label forge-test --pin 1234 --so-pin 5678

# 4. generate an Ed25519 key ON the token (pkcs11-tool from opensc, or python-pkcs11)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
    --keypairgen --key-type EC:edwards25519 --label forge-ledger

# 5. point Forge at it
export FORGE_ENTERPRISE_COMPLIANCE=1
export FORGE_LEDGER_SIGNER=pkcs11
export FORGE_LEDGER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export FORGE_LEDGER_PKCS11_TOKEN_LABEL=forge-test
export FORGE_LEDGER_PKCS11_KEY_LABEL=forge-ledger
export FORGE_LEDGER_PKCS11_PIN=1234
```

Forge signe désormais chaque entrée de ledger sur le token ; la clé privée n'entre jamais dans le
processus. `tests/test_pkcs11_signer.py::TestLiveSoftHSMRoundTrip` effectue exactement ce round-trip
lorsque SoftHSM2 + `python-pkcs11` sont présents (il est auto-skippé sinon).

---

## Production — HSM / AWS CloudHSM / cloud-KMS via PKCS#11

Chacun d'eux expose une **bibliothèque de provider PKCS#11** ; pointez `FORGE_LEDGER_PKCS11_MODULE` dessus
et renseignez le token/slot, le label/id de clé, et le PIN :

- **HSM on-prem / réseau** (Thales Luna, Entrust nShield, Utimaco, YubiHSM2…) : utilisez le `.so` PKCS#11
  du vendeur, une clé Ed25519 générée non-exportable sur l'appareil.
- **AWS CloudHSM** : installez le CloudHSM Client SDK, utilisez `libcloudhsm_pkcs11.so`, PIN = `CU_user:password`.
  (**AWS KMS** nu **n'est pas utilisable** ici — il n'offre pas Ed25519 ; voir la table ci-dessus.)
- **cloud-KMS via un pont PKCS#11** : p. ex. le `libkmsp11.so` de Google Cloud, ou un proxy SoftHSM/`p11-kit`
  devant un KMS qui parle Ed25519.

Stockez le PIN via votre gestionnaire de secrets et injectez-le comme `FORGE_LEDGER_PKCS11_PIN` au runtime
(env, pas argv). Faites tourner la clé du ledger en générant une nouvelle clé de token et en ré-ancrant ;
la clé publique change, donc publiez la nouvelle clé publique à vos auditeurs/witness.

### Échappatoire — GCP-KMS-Ed25519 via l'exec signer générique (voie cloud-KMS recommandée)

Si votre backend signe en Ed25519 mais n'a **aucun provider PKCS#11** — le cas canonique est **GCP KMS
piloté par la CLI `gcloud`** — utilisez l'**exec signer no-shell** générique déjà présent dans
`forge/signing.py`. Il exécute un **argv fixe, configuré par l'admin** (un tableau JSON — jamais une
chaîne shell, donc aucun métacaractère n'est jamais interprété), envoie les octets-à-signer sur **stdin**,
et relit la **signature Ed25519 en hex (128 caractères hex)** depuis **stdout**. Même garantie fail-closed
que tout signer off-host : `RemoteSigner.sign` **re-vérifie** la signature retournée contre
`FORGE_LEDGER_SIGNER_PUBKEY` avant que l'entrée soit écrite — une réponse malformée ou qui ne vérifie pas
est **rejetée** et l'append avorte (jamais une entrée non signée).

> **Aucun driver GCP sur mesure — par conception.** Forge ne livre **aucun** code spécifique à GCP-KMS :
> l'exec signer générique couvre déjà GCP-KMS de bout en bout (ci-dessous). **AWS-KMS reste non supporté
> pour ce ledger** — il n'offre aucun type de clé Ed25519 (RSA/ECDSA seulement ; voir la table ci-dessus).
> Pour AWS, placez plutôt un HSM/CloudHSM **PKCS#11** devant le ledger, ou utilisez GCP KMS.

**1 — créer une clé de signature Ed25519 dans GCP KMS** (algorithme `EC_SIGN_ED25519`) :

```bash
gcloud kms keyrings create forge --location=global
gcloud kms keys create ledger \
  --location=global --keyring=forge \
  --purpose=asymmetric-signing \
  --default-algorithm=ec-sign-ed25519      # EC_SIGN_ED25519 — Ed25519, matches the ledger algorithm
```

**2 — exporter la clé PUBLIQUE en 64-hex** (exactement ce que `verify_external` / `ledger verify --pubkey` attend) :

```bash
gcloud kms keys versions get-public-key 1 \
  --location=global --keyring=forge --key=ledger --output-file=ledger.pub.pem
# PEM (SubjectPublicKeyInfo) → raw 32-byte Ed25519 pubkey → hex:
python3 -c 'from cryptography.hazmat.primitives.serialization import load_pem_public_key; \
  print(load_pem_public_key(open("ledger.pub.pem","rb").read()).public_bytes_raw().hex())'
# → 64 hex chars. This is FORGE_LEDGER_SIGNER_PUBKEY — publish it to your auditors/witness.
```

**3 — le helper de signature** `/opt/forge/gcp-kms-ed25519-sign.sh` — lit les octets sur stdin, appelle
`gcloud kms asymmetric-sign` (qui, pour Ed25519, signe l'**entrée brute**, sans pré-digest), et encode en
hex la signature **brute de 64 octets** que GCP retourne sur stdout :

```bash
#!/usr/bin/env bash
set -euo pipefail
loc="$1"; kr="$2"; key="$3"; ver="$4"                    # passed as fixed argv elements (no shell parsing)
gcloud kms asymmetric-sign \
  --location="$loc" --keyring="$kr" --key="$key" --version="$ver" \
  --input-file=- --signature-file=- \
  | python3 -c 'import sys; sys.stdout.write(sys.stdin.buffer.read().hex())'
```

**4 — brancher l'exec signer** (l'argv est un tableau JSON — le chemin du helper plus ses arguments fixes) :

```bash
export FORGE_ENTERPRISE_COMPLIANCE=1
export FORGE_LEDGER_SIGNER=exec
export FORGE_LEDGER_SIGNER_PUBKEY=<64-hex from step 2>
export FORGE_LEDGER_SIGNER_ARGV='["/opt/forge/gcp-kms-ed25519-sign.sh","global","forge","ledger","1"]'
```

La clé privée **ne quitte jamais GCP KMS** (seul `gcloud … asymmetric-sign` est invoqué ; aucun matériel
de clé sur un volume de pod). Faites la rotation en créant une nouvelle version de clé et en ré-exportant
la clé publique (étape 2) — puis publiez la nouvelle clé publique à vos auditeurs/witness.

---

## Garde de clés en HA (Kubernetes) — garder la clé privée HORS du volume de ledger partagé

> **Pourquoi cela compte en HA.** En HA, le ledger tamper-evident est un **fichier** sur un **PVC
> ReadWriteMany partagé** (`forge-ledger`, monté sur `/data/ledger` par chaque réplique — voir
> `k8s/40-console.yaml`). Le `LocalFileSigner` communautaire écrit sa clé **privée** à côté du ledger
> sous `<ledger>.ed25519` (0600). Sur ce volume RWX, un bit de perms `0600` n'est **pas** une frontière
> d'isolation : **n'importe quel pod ou sidecar** qui monte le même PVC, et **n'importe quel
> snapshot/backup de PVC**, livre la clé de signature Ed25519 brute — avec laquelle un attaquant peut
> forger des entrées de ledger forge arbitraires. La clé locale perms-seulement convient pour un hôte
> single-tenant ; elle ne convient **pas** sur un volume partagé multi-writer. Déplacez la clé **hors** de
> ce volume. Deux patterns supportés, le plus sûr d'abord :

### Pattern 1 (PRÉFÉRÉ pour HA / multi-tenant) — signer off-host, clé sur aucun volume de pod

Utilisez le **signer PKCS#11** (`FORGE_LEDGER_SIGNER=pkcs11`, documenté ci-dessus) ou l'**exec signer**
générique vers un KMS off-host. La clé privée réside sur un HSM/token et **ne touche jamais aucun volume
de pod** — donc ni le PVC RWX, ni un snapshot, ni un sidecar co-monté ne la voit jamais. C'est la posture
HA recommandée et aussi le contrôle qui supprime la limite host-root décrite ci-dessous.

Câblage k8s (bloc opt-in dans `k8s/40-console.yaml` ; PIN/module via le Secret `forge-ledger-pkcs11` —
placeholder dans `k8s/10-secrets.example.yaml`, EVAL-ONLY, appliqué explicitement) :

```yaml
env:
  - name: FORGE_ENTERPRISE_COMPLIANCE
    value: "1"
  - name: FORGE_LEDGER_SIGNER
    value: pkcs11
  - name: FORGE_LEDGER_PKCS11_MODULE
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_MODULE } }
  - name: FORGE_LEDGER_PKCS11_TOKEN_LABEL
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_TOKEN_LABEL } }
  - name: FORGE_LEDGER_PKCS11_KEY_LABEL
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_KEY_LABEL } }
  - name: FORGE_LEDGER_PKCS11_PIN
    valueFrom: { secretKeyRef: { name: forge-ledger-pkcs11, key: FORGE_LEDGER_PKCS11_PIN } }
```

Nécessite une image `store-postgres` construite avec l'extra `pkcs11` et un `.so` de provider PKCS#11
présent dans le conteneur (baké dedans ou via un sidecar). Aucun Secret de clé n'est créé ; le PVC RWX ne
porte alors **que** la projection JSONL du ledger.

### Pattern 2 (REPLI) — signer local, clé en Secret read-only PAS sur le PVC RWX

Si vous devez conserver le signer **local** en HA (p. ex. aucun HSM disponible), découplez le **chemin** de
la clé du chemin du ledger avec **`FORGE_LEDGER_KEY`** et fournissez la clé comme un **Secret read-only
dédié** plutôt que de la laisser s'écrire sur `/data/ledger` :

1. **Pré-générez** la clé Ed25519 hors bande (ne laissez pas le pod la créer automatiquement sur le volume partagé) :

   ```bash
   python3 -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; \
               import base64; print(base64.b64encode(K.generate().private_bytes_raw()).decode())'
   # → base64 of the raw 32-byte private key; put it in Secret forge-ledger-key, data.forge.ed25519
   ```

2. Fournissez-la comme Secret **`forge-ledger-key`** (placeholder dans `k8s/10-secrets.example.yaml`),
   monté **read-only** à un chemin, et pointez **`FORGE_LEDGER_KEY`** sur ce montage (bloc opt-in dans
   `k8s/40-console.yaml`) :

   ```yaml
   env:
     - name: FORGE_LEDGER_KEY
       value: /etc/forge/ledger-key/forge.ed25519      # read-only Secret mount, NOT /data/ledger
   volumeMounts:
     - name: ledger-key
       mountPath: /etc/forge/ledger-key
       readOnly: true                                   # signer READS the key; never rewrites it
   volumes:
     - name: ledger-key
       secret:
         secretName: forge-ledger-key
         defaultMode: 0440   # owner+group read; fsGroup gives the process the GROUP, not ownership
         items: [ { key: forge.ed25519, path: forge.ed25519 } ]
   ```

`FORGE_LEDGER_KEY` fait lire au signer la clé **depuis le montage read-only** au lieu d'écrire/lire
`<ledger>.ed25519` sur le PVC RWX. Comme le montage est read-only et que la clé pré-existe, elle est
**lue, pas réécrite** — la clé privée n'est **jamais** placée sur le volume `forge-ledger` partagé, qui ne
porte alors que `engagement.jsonl` + le high-water-mark. Faites la rotation en remplaçant le Secret et en
ré-ancrant (publiez la nouvelle clé publique à vos auditeurs/witness).

**Résiduel pour le Pattern 2.** La clé atterrit tout de même dans un **Secret** k8s (etcd) et est présente
dans le montage tmpfs du pod — donc un accès cluster-admin / etcd l'atteint encore. Le Pattern 2 supprime
l'exposition *volume-partagé / snapshot*, pas la confiance dans le magasin de secrets k8s ; pour la
propriété plus forte (clé sur aucun volume de pod du tout, host-root ne peut pas exfiltrer) utilisez le
**Pattern 1**. Les deux conservent `runAsNonRoot`, `readOnlyRootFilesystem`, et les NetworkPolicies
deny-by-default intactes ; le Secret de clé et le Secret PKCS#11 sont **opt-in** (hors du chemin
`kubectl apply -k k8s/` par défaut).

Voir `docs/DEPLOYMENT.md` §3bis.6 (HA sur Kubernetes) pour la topologie environnante.

## Contre quoi les deux modes protègent

Avec la clé on-host et le `NullAnchor` par défaut, l'intégrité du ledger dépend de l'hôte lui-même :
quiconque y a root atteint la clé de signature. Deux contrôles opt-in suppriment ensemble cette
dépendance :

1. **Garde de clés off-host (ce driver).** Avec `FORGE_LEDGER_SIGNER=pkcs11` (ou l'exec signer vers un
   KMS off-host), la clé privée réside sur le token/HSM. Host-root peut *demander* des signatures sur du
   nouveau contenu mais **ne peut pas extraire la clé**, donc il ne peut pas re-signer silencieusement un
   passé réécrit à lui seul.
2. **Witness anchor off-host** (`forge/anchor.py` — `WitnessAnchor` + `reconcile`). Un hôte séparé détient
   une clé distincte et contre-signe des checkpoints `(seq|head|ts)` dans son propre log append-only.
   `reconcile` recalcule les heads du ledger depuis genesis et les compare à ce que le witness a
   contre-signé — détectant un passé réécrit (même re-signé).

**Pourquoi les deux sont nécessaires.** La signature off-host seule arrête l'*exfiltration* de clé, mais
un host-root qui peut encore *appeler* le signer pourrait re-signer un ledger tronqué/réécrit pour la
suite. Le witness anchor épingle les heads historiques quelque part que l'hôte ne peut pas altérer, donc
`reconcile` attrape la réécriture. Inversement, le witness seul ne protège pas la clé. Activez les **deux**
et forger la piste d'audit exige de compromettre **l'hôte de Forge *et* le witness *et* le HSM**.

Les deux contrôles sont **opt-in** : le défaut communautaire reste local + `NullAnchor` (byte-identique et
sans dépendance). Voir `forge/anchor.py` pour le modèle de menace derrière le witness anchor.

---

## Secrets de données au repos — ce que vous devez garder, et ce qui casse sinon

La discussion sur la garde ci-dessus porte sur la **clé de signature du ledger** (intégrité). Deux
*autres* secrets gouvernent la **confidentialité au repos**. Ils sont indépendants l'un de l'autre et de
la clé de signature, et une restauration n'est pleinement réussie que lorsque vous détenez encore ceux que
vous avez utilisés :

| Secret | Protège | Si vous le perdez |
|---|---|---|
| `FORGE_FIELD_KEY` (+ `_FILE`) | Le **matériel d'authentification** des engagements — bearers, cookies et valeurs d'en-tête des comptes de test de l'opérateur (`scope_json.auth`). Chiffrement de champ, **build par défaut**, AEAD pur Rust. | La base reste pleinement intacte et lisible ; seul ce matériel reste **scellé**. Les runs sur ces engagements **refusent de démarrer** (jamais un contexte d'auth vide en silence). Récupération = **ré-entrer** le matériel dans l'éditeur d'engagement. |
| `FORGE_DB_KEY` | Le **fichier SQLite entier** (SQLCipher, image `encryption` seulement). | La base est **illisible**. Aucune récupération partielle. |
| Passphrase de backup | L'**archive** (`forge backup`), qui porte le snapshot de la DB + le ledger + la clé de signature. | L'archive est **irrécupérable** — il n'y a aucune voie de sortie en clair. |

**Ils se composent, et ils sont vérifiés indépendamment.** Restaurer une archive avec la bonne passphrase
sur un hôte qui n'a pas `FORGE_FIELD_KEY` donne une installation complète et fonctionnelle dont le
matériel d'auth reste scellé — ce qui est le comportement fail-closed voulu, pas de la corruption. Stockez
la field key là où vous stockez la passphrase de backup : elles sont nécessaires ensemble pour ramener un
engagement **armé**.

> **Rotation.** Le scellement est par-écriture et idempotent : le matériel déjà scellé sous une ancienne
> clé est laissé tel quel. Pour faire passer un engagement à une nouvelle clé, posez le nouveau
> `FORGE_FIELD_KEY` et **ré-entrez** son matériel dans l'éditeur — la console le scelle alors sous la
> nouvelle clé. Il n'y a pas de re-key en masse in-place, délibérément : cela exigerait de détenir les deux
> clés à la fois dans le processus.
