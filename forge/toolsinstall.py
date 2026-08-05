# SPDX-License-Identifier: AGPL-3.0-or-later
"""Surcouche RUNTIME du cycle de vie des outils — installer / mettre a jour / retirer SANS rebuild.

La baseline reste celle du BUILD (`FORGE_TOOLS_PROFILE=full|mini`, cf. Dockerfile) : reproductible,
SHA-pinnee, inchangee. Ce module AJOUTE une couche par-dessus, dans un repertoire outils PERSISTANT
appartenant a l'utilisateur applicatif et place EN TETE du PATH — un outil installe ici prime donc sur
le binaire bake, et une mise a jour ne demande plus de reconstruire l'image.

Installer un binaire au runtime dans un outil offensif est exactement le genre de capacite qui annule
une gouvernance si elle est mal posee. Les contraintes ci-dessous ne sont donc pas negociables ; chacune
est couverte par un test (`tests/test_tools_runtime_install.py`) :

  1. INTEGRITE OBLIGATOIRE, FAIL-CLOSED. L'archive telechargee est hachee en SHA256 pendant l'ecriture
     et comparee au pin du manifeste POUR SON ARCHITECTURE. Digest absent du manifeste -> refus AVANT
     tout reseau. Digest non concordant -> refus, fichier temporaire detruit, RIEN n'atterrit sur le
     PATH. Il n'existe aucun chemin « on installe quand meme ».
  2. SOURCE ALLOWLISTEE. L'URL est CALCULEE depuis le manifeste (`forge/tools.json`). Il n'y a pas de
     parametre d'URL : ni la CLI, ni cette API, ni l'environnement ne peuvent designer une autre source.
     Un nom absent du manifeste n'est pas installable. Redirections : HTTPS -> HTTPS uniquement.
  3. PAS DE SHELL. Aucun `subprocess`, aucun `shell=True`, aucun appel a curl/unzip/tar : telechargement
     `urllib` (HTTP/1.1 par construction — `http.client` ne parle pas HTTP/2, la cause du flake amont),
     decompression `zipfile`/`tarfile`, un SEUL membre extrait par lecture de flux. Le nom du membre
     n'est JAMAIS utilise comme chemin d'ecriture : la destination est calculee par nous (anti zip-slip).
  4. JOURNALISE AU LEDGER. Toute installation, mise a jour, retrait — ET TOUT REFUS — laisse une entree
     chainee et signee (`tools.install`, `tools.update`, `tools.remove`, `tools.refused`) portant le nom,
     la version, l'architecture, le digest verifie, l'URL et l'acteur. Un changement de capacite se trace.
     Sans ledger joignable -> REFUS : aucune installation non journalisee.
  5. AUCUNE ELEVATION. Cette couche n'ouvre AUCUNE porte : ni le scope-guard ROE, ni le plancher exploit,
     ni le contrat `Module` ne sont touches. Un outil installe ici reste soumis a la meme sonde de
     disponibilite (`shutil.which`) et aux memes gates. On n'ecrit jamais hors du repertoire outils
     (`bin` est un NOM valide par le manifeste ; la destination resolue est re-verifiee).
  6. DEFAUT = NO-OP. Rien n'est cree, sonde ou telecharge a l'import. Sans action operateur explicite,
     le repertoire outils n'existe meme pas et la resolution PATH est identique a la baseline.

NON COUVERT DELIBEREMENT : installer une version ABSENTE du manifeste (il faudrait accepter un digest
saisi par l'operateur — c'est l'etape 4 de la roadmap, sa propre UX d'integrite). Mettre a jour = bumper
le manifeste (changement revu, pinne) puis `forge tools update <nom>` : pas de rebuild, pas de confiance
implicite.

Zero dependance (stdlib) — coherent avec le coeur Forge.
"""
import hashlib
import json
import os
import shutil
import stat
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from fnmatch import fnmatch
from pathlib import Path

from . import portability
from . import toolsmanifest

# Repertoire outils : override operateur, sinon un sous-dossier du repertoire de donnees Forge.
# L'image conteneur pose `FORGE_TOOLS_DIR=/data/tools` (volume persistant, forge-owned).
TOOLS_DIR_ENV = "FORGE_TOOLS_DIR"
# Ledger d'engagement par defaut — la MEME variable que celle deja lue par la console.
LEDGER_ENV = "FORGE_CONSOLE_LEDGER"

_HTTP_TIMEOUT = 60                 # s par tentative de lecture
_RETRIES = 5                       # egress instable observe (partial-file, read-timeout)
_RETRY_DELAY = 3                   # s entre deux tentatives
_CHUNK = 64 * 1024
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024   # garde-fou disque (l'integrite, elle, vient du SHA256)
_BIN_MODE = 0o755


class ToolInstallError(RuntimeError):
    """Refus gouverne (integrite, allowlist, ledger, ecriture). Le message dit TOUJOURS pourquoi."""


# =================================================================================================
#  Emplacements — rien n'est cree tant qu'une action operateur ne le demande pas (no-op par defaut)
# =================================================================================================
def tools_dir():
    """Racine du repertoire outils runtime. `FORGE_TOOLS_DIR` sinon `<data_dir>/tools`. NE CREE RIEN."""
    override = os.environ.get(TOOLS_DIR_ENV)
    if override:
        return Path(os.path.expanduser(os.path.expandvars(override)))
    return portability.data_dir() / "tools"


def bin_dir():
    """Repertoire des binaires installes — c'est LUI qui est place en tete du PATH. NE CREE RIEN."""
    return tools_dir() / "bin"


def state_dir():
    """Repertoire des recus d'installation (un JSON par outil). NE CREE RIEN."""
    return tools_dir() / "state"


def receipt_path(name):
    return state_dir() / (name + ".json")


def _read_receipt(name):
    """Recu d'installation runtime (`{name, version, arch, sha256, url, ts}`) ou None. Ne leve jamais."""
    try:
        raw = receipt_path(name).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


# =================================================================================================
#  Architecture — nomenclature Docker (celle du manifeste), derivee de la machine hote
# =================================================================================================
_UNAME_TO_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def current_arch():
    """Architecture courante en nomenclature manifeste (amd64/arm64), ou la valeur brute si inconnue
    — auquel cas aucun pin ne correspondra et l'installation sera REFUSEE (fail-closed)."""
    machine = os.uname().machine if hasattr(os, "uname") else ""
    return _UNAME_TO_ARCH.get(machine, machine or "inconnue")


# =================================================================================================
#  Etat — ce qui est installe, ce qui est disponible (LECTURE SEULE, aucun processus lance)
# =================================================================================================
def status(manifest=None, arch=None):
    """Etat par outil du manifeste, SANS executer quoi que ce soit (pas de `--version` lance : lister
    ne doit pas etre une execution). Chaque ligne dit la version CIBLE, ou le binaire est resolu sur le
    PATH, s'il vient de la couche runtime, et la version installee QUAND elle est connue (recu)."""
    man = manifest if manifest is not None else toolsmanifest.load()
    arch = arch or current_arch()
    bd = bin_dir()
    rows = []
    for entry in man:
        resolved = shutil.which(entry.bin)
        receipt = _read_receipt(entry.name)
        managed = bool(resolved) and Path(resolved).parent == bd
        row = entry.as_dict(arch=arch)
        row.update({
            "installable": entry.supports(arch),
            "arch": arch,
            "resolved_path": resolved or "",
            "available": bool(resolved),
            "source": "runtime" if managed else ("baseline" if resolved else "absent"),
            "installed_version": (receipt or {}).get("version", "") if managed else "",
            "up_to_date": bool(managed and (receipt or {}).get("version") == entry.version),
        })
        rows.append(row)
    return rows


# =================================================================================================
#  Telechargement — urllib (HTTP/1.1 par construction), HTTPS strict, redirections gardees
# =================================================================================================
class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse une redirection qui QUITTE HTTPS. Les releases GitHub redirigent vers un CDN (toujours
    HTTPS) ; une redirection vers `http://` degraderait le transport a l'insu de l'operateur — on la
    traite comme une erreur, pas comme un detail. L'integrite finale reste le SHA256, mais un canal
    clair permettrait a un intermediaire de choisir QUEL octet nous faisons echouer."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not str(newurl).lower().startswith("https://"):
            raise urllib.error.URLError(
                f"redirection hors HTTPS refusee (vers {newurl!r}) — telechargement d'outil abandonne")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_opener():
    """Opener urllib sans proxy implicite surprise, avec la garde de redirection HTTPS."""
    return urllib.request.build_opener(_HttpsOnlyRedirect)


def _fetch_to(url, dest, opener=None, timeout=_HTTP_TIMEOUT, retries=_RETRIES, sleep=time.sleep):
    """Telecharge `url` vers `dest` en STREAMING et retourne le SHA256 hexa des octets ECRITS.

    Le hash est calcule SUR LE FLUX pendant l'ecriture : on ne relit pas le fichier apres coup (aucune
    fenetre entre verification et usage). Retries bornes (egress instable observe cote build) avec
    troncature du fichier a chaque tentative. Depassement de `_MAX_ARCHIVE_BYTES` -> abandon (garde-fou
    disque ; l'integrite, elle, est portee par le digest)."""
    op = opener if opener is not None else _default_opener()
    last = None
    for attempt in range(1, max(1, retries) + 1):
        digest = hashlib.sha256()
        total = 0
        try:
            with op.open(url, timeout=timeout) as resp, open(dest, "wb") as out:
                while True:
                    chunk = resp.read(_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_ARCHIVE_BYTES:
                        raise ToolInstallError(
                            f"archive au-dela de la borne ({_MAX_ARCHIVE_BYTES} octets) — abandon")
                    digest.update(chunk)
                    out.write(chunk)
            return digest.hexdigest()
        except ToolInstallError:
            raise
        except Exception as e:                       # noqa: BLE001 — reseau : toute erreur est retentable
            last = e
            try:
                Path(dest).unlink()
            except OSError:
                pass
            if attempt < max(1, retries):
                sleep(_RETRY_DELAY)
    raise ToolInstallError(f"telechargement impossible apres {max(1, retries)} tentatives : {last!r}")


# =================================================================================================
#  Extraction — UN SEUL membre, ecrit a une destination QUE NOUS calculons (anti zip-slip)
# =================================================================================================
def _resolve_member(names, pattern):
    """Resout le membre d'archive : correspondance EXACTE sinon glob. Exige UNE seule correspondance
    (zero -> l'archive n'est pas celle attendue ; plusieurs -> ambigu). Fail-closed dans les deux cas."""
    if pattern in names:
        return pattern
    hits = sorted(n for n in names if fnmatch(n, pattern))
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise ToolInstallError(f"membre {pattern!r} absent de l'archive")
    raise ToolInstallError(f"membre {pattern!r} ambigu dans l'archive ({len(hits)} correspondances)")


def _extract_member(archive_path, kind, member, dest):
    """Extrait le SEUL membre demande vers `dest` (chemin que NOUS fixons — le nom interne a l'archive
    n'est jamais utilise comme chemin d'ecriture, donc ni `../` ni chemin absolu ne peuvent sortir)."""
    if kind == "zip":
        with zipfile.ZipFile(archive_path) as zf:
            name = _resolve_member(zf.namelist(), member)
            with zf.open(name) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out, _CHUNK)
        return
    if kind == "tar.gz":
        with tarfile.open(archive_path, "r:gz") as tf:
            name = _resolve_member(tf.getnames(), member)
            info = tf.getmember(name)
            if not info.isfile():
                raise ToolInstallError(f"membre {name!r} n'est pas un fichier regulier — refus")
            src = tf.extractfile(info)
            if src is None:
                raise ToolInstallError(f"membre {name!r} illisible dans l'archive")
            with src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out, _CHUNK)
        return
    raise ToolInstallError(f"format d'archive non supporte : {kind!r}")


# =================================================================================================
#  Ledger — aucune installation non journalisee (fail-closed AVANT le reseau)
# =================================================================================================
def resolve_ledger(path=None):
    """Ledger d'engagement a journaliser : argument explicite, sinon `FORGE_CONSOLE_LEDGER`.
    Retourne None si aucun n'est resolu — l'appelant DOIT alors refuser l'action."""
    p = path or os.environ.get(LEDGER_ENV)
    return Path(os.path.expanduser(os.path.expandvars(p))) if p else None


def _open_ledger(path):
    from .ledger import Ledger                       # import local : `status`/`list` n'en depend pas
    return Ledger(path)


def _record(ledger, kind, detail):
    """Ecrit une entree de ledger. Une ecriture impossible est une ERREUR (pas un best-effort) : une
    capacite qui change sans trace auditable, c'est precisement ce qu'on refuse."""
    try:
        ledger.append(kind, detail)
    except Exception as e:                           # noqa: BLE001
        raise ToolInstallError(f"journalisation au ledger impossible ({e!r}) — action refusee") from e


# =================================================================================================
#  Actions gouvernees — install / update / remove
# =================================================================================================
def _entry_or_refuse(manifest, name):
    entry = manifest.get(name)
    if entry is None:
        raise ToolInstallError(
            f"outil {name!r} absent du manifeste — seules les entrees de forge/tools.json sont "
            f"installables (allowlist de source). Connus : {', '.join(manifest.names())}")
    return entry


def _dest_for(entry):
    """Destination du binaire, RE-VERIFIEE comme etant dans le repertoire outils (defense en
    profondeur : le manifeste valide deja `bin` comme un NOM, on refuse quand meme toute evasion)."""
    bd = bin_dir()
    dest = bd / entry.bin
    if dest.parent.resolve(strict=False) != bd.resolve(strict=False):
        raise ToolInstallError(f"destination hors du repertoire outils pour {entry.name!r} — refus")
    return dest


def install(name, *, manifest=None, arch=None, ledger_path=None, actor="", force=False,
            opener=None, sleep=time.sleep):
    """Installe (ou met a jour) UN outil du manifeste dans le repertoire outils runtime.

    Ordre des gardes — tout ce qui peut refuser le fait AVANT le moindre octet reseau :
      allowlist (nom connu) -> pin SHA256 present pour l'architecture -> ledger joignable
      -> telechargement + hash en streaming -> comparaison au pin -> extraction d'UN membre
      -> pose atomique (os.replace) + mode 0755 -> recu -> entree de ledger.

    Retourne un dict d'issue (`{'action': 'installed'|'updated'|'unchanged', ...}`).
    Leve `ToolInstallError` sur tout refus — auquel cas RIEN n'a ete pose sur le PATH."""
    man = manifest if manifest is not None else toolsmanifest.load()
    entry = _entry_or_refuse(man, name)
    arch = arch or current_arch()

    expected = entry.digest(arch) if arch in toolsmanifest.ARCH_ALIASES else None
    if not expected:
        raise ToolInstallError(
            f"aucun pin SHA256 pour {entry.name!r} en {arch} — refus de telecharger non verifie "
            f"(architectures pinnees : {', '.join(sorted(entry.sha256)) or 'aucune'})")

    lp = resolve_ledger(ledger_path)
    if lp is None:
        raise ToolInstallError(
            f"aucun ledger resolu (--ledger ou {LEDGER_ENV}) — une installation d'outil est un "
            f"changement de capacite : elle ne s'effectue pas sans trace auditable")
    ledger = _open_ledger(lp)

    dest = _dest_for(entry)
    receipt = _read_receipt(entry.name)
    already = dest.exists() and (receipt or {}).get("version") == entry.version
    if already and not force:
        return {"action": "unchanged", "name": entry.name, "version": entry.version,
                "arch": arch, "path": str(dest), "sha256": expected}

    url = entry.url(arch)                            # SEULE source autorisee pour cet outil
    bd = bin_dir()
    staging = tools_dir() / ".staging"
    for d in (bd, state_dir(), staging):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise ToolInstallError(f"repertoire outils non inscriptible ({d}) : {e}") from e

    archive = staging / f"{entry.name}.{os.getpid()}.archive"
    staged_bin = staging / f"{entry.name}.{os.getpid()}.bin"
    try:
        got = _fetch_to(url, archive, opener=opener, sleep=sleep)
        if got != expected:
            _record(ledger, "tools.refused",
                    {"name": entry.name, "version": entry.version, "arch": arch, "url": url,
                     "expected_sha256": expected, "actual_sha256": got, "actor": actor,
                     "reason": "digest SHA256 non concordant"})
            raise ToolInstallError(
                f"INTEGRITE : digest SHA256 non concordant pour {entry.name} {entry.version} "
                f"({arch}) — attendu {expected}, obtenu {got}. Rien n'a ete installe.")
        _extract_member(archive, entry.archive, entry.member(arch), staged_bin)
        os.chmod(staged_bin, _BIN_MODE)
        previous = (receipt or {}).get("version", "")
        os.replace(staged_bin, dest)                 # pose ATOMIQUE : jamais de binaire a moitie ecrit
    finally:
        for tmp in (archive, staged_bin):
            try:
                tmp.unlink()
            except OSError:
                pass

    record = {"name": entry.name, "bin": entry.bin, "version": entry.version, "arch": arch,
              "sha256": expected, "url": url, "path": str(dest), "ts": int(time.time())}
    receipt_path(entry.name).write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    action = "updated" if previous and previous != entry.version else "installed"
    _record(ledger, "tools.update" if action == "updated" else "tools.install",
            dict(record, actor=actor, previous_version=previous))
    out = dict(record)
    out["action"] = action
    out["previous_version"] = previous
    return out


def update(name, **kwargs):
    """Met a jour vers la version du MANIFESTE (reinstalle meme si deja presente). Il n'existe pas
    d'update « vers la derniere version amont » : ce serait un telechargement non pinne."""
    kwargs["force"] = True
    return install(name, **kwargs)


def remove(name, *, manifest=None, ledger_path=None, actor=""):
    """Retire un outil de la couche RUNTIME (binaire + recu). Ne touche JAMAIS la baseline bakee :
    apres retrait, le PATH retombe sur le binaire de l'image s'il existe (degradation naturelle)."""
    man = manifest if manifest is not None else toolsmanifest.load()
    entry = _entry_or_refuse(man, name)

    lp = resolve_ledger(ledger_path)
    if lp is None:
        raise ToolInstallError(
            f"aucun ledger resolu (--ledger ou {LEDGER_ENV}) — un retrait d'outil est un changement "
            f"de capacite : il ne s'effectue pas sans trace auditable")
    ledger = _open_ledger(lp)

    dest = _dest_for(entry)
    receipt = _read_receipt(entry.name) or {}
    existed = dest.exists()
    if existed:
        dest.unlink()
    try:
        receipt_path(entry.name).unlink()
    except OSError:
        pass
    _record(ledger, "tools.remove",
            {"name": entry.name, "bin": entry.bin, "version": receipt.get("version", ""),
             "path": str(dest), "removed": existed, "actor": actor})
    return {"action": "removed" if existed else "absent", "name": entry.name,
            "version": receipt.get("version", ""), "path": str(dest)}


def is_executable(path):
    """True si `path` est un fichier avec un bit d'execution (diagnostic ; ne leve jamais)."""
    try:
        return bool(os.stat(path).st_mode & stat.S_IXUSR)
    except OSError:
        return False
