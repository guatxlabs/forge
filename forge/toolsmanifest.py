# SPDX-License-Identifier: AGPL-3.0-or-later
"""Manifeste des outils externes — SOURCE DE VERITE UNIQUE (versions + pins SHA256 + gabarits d'URL).

Le probleme ferme ici : les versions et les digests des binaires de securite telecharges (httpx,
nuclei, subfinder, dnsx, naabu, katana, amass, gau, gospider, dalfox, feroxbuster, ffuf) etaient des
`ARG` codes en dur DUPLIQUES entre `Dockerfile` et `docker-compose.yml`. Deux copies d'un pin = une
classe de bug (divergence silencieuse). Desormais tout vit dans `forge/tools.json`, que LISENT :

  * le **Dockerfile** au build (baseline bakee dans l'image, profil `FORGE_TOOLS_PROFILE=full|mini`) —
    via l'emetteur TSV de ce module, lance en `python3 forge/toolsmanifest.py` (script autonome :
    AUCUN import relatif, stdlib pure, pour tourner AVANT que le package ne soit copie) ;
  * l'**installeur runtime** (`forge/toolsinstall.py`, `forge tools install|update|remove`), qui
    installe/met a jour un outil SANS rebuild dans le volume outils persistant.

GOUVERNANCE PORTEE PAR LE MANIFESTE (le reste du systeme s'y adosse) :
  - **Allowlist de sources** : l'URL est un GABARIT DU MANIFESTE. Aucun chemin (CLI, API, env) ne
    permet d'installer depuis une URL fournie par l'operateur — il n'existe pas de parametre d'URL.
  - **Integrite obligatoire** : un outil n'est installable que s'il porte un SHA256 pin pour
    l'architecture cible. Pas de pin -> pas d'installation (fail-closed), jamais de telechargement
    non verifie. Le chargeur REFUSE un manifeste dont un digest n'est pas 64 hexa minuscules.
  - **HTTPS seulement** : un gabarit d'URL non-`https://` fait echouer le chargement (fail-closed).
  - **Pas d'evasion de chemin** : `bin` est un NOM de fichier (ni `/` ni `..`), `member` (chemin
    interne a l'archive) ne peut etre absolu ni contenir `..` — l'installeur ecrit donc toujours
    DANS son repertoire, jamais ailleurs.

Gabarits : `{version}`, `{arch}` (nomenclature Docker : amd64|arm64), `{arch_uname}` (x86_64|aarch64
— certains editeurs nomment leurs assets ainsi). Principe **bring-your-own-tool** : ajouter un outil
= ajouter une entree JSON, aucun code.

Zero dependance (stdlib) — coherent avec le coeur Forge.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

# Nom du fichier de donnees, a cote de ce module (ship' avec le package : cf. pyproject
# `[tool.setuptools.package-data]`). Surchargeable pour les tests / un manifeste operateur.
MANIFEST_FILENAME = "tools.json"
MANIFEST_ENV = "FORGE_TOOLS_MANIFEST"

SCHEMA_VERSION = 1

# Architectures connues : cle = nomenclature Docker (`TARGETARCH`), valeur = nomenclature `uname -m`.
ARCH_ALIASES = {"amd64": "x86_64", "arm64": "aarch64"}

# Formats d'archive supportes par l'extracteur (build ET runtime).
ARCHIVE_KINDS = ("zip", "tar.gz")

_NAME_RX = re.compile(r"^[a-z0-9][a-z0-9._-]*$")     # nom d'outil / nom de binaire pose sur le PATH
_SHA_RX = re.compile(r"^[0-9a-f]{64}$")              # digest SHA256, hexa MINUSCULE strict
_WS_RX = re.compile(r"\s")                           # aucun champ emis ne peut contenir d'espace


class ManifestError(ValueError):
    """Manifeste invalide (fail-closed). Le message nomme TOUJOURS l'entree fautive."""


def _require(cond, msg):
    if not cond:
        raise ManifestError(msg)


class ToolEntry:
    """Une entree du manifeste — immuable apres construction (aucune methode ne la mute)."""

    __slots__ = ("name", "group", "enabled", "profiles", "version", "archive", "url_template",
                 "member_template", "bin", "sha256", "description")

    def __init__(self, raw, where="<manifeste>"):
        _require(isinstance(raw, dict), f"{where}: entree d'outil non-objet")
        name = raw.get("name")
        _require(isinstance(name, str) and _NAME_RX.match(name),
                 f"{where}: 'name' invalide ({name!r}) — attendu [a-z0-9][a-z0-9._-]*")
        self.name = name
        w = f"{where}[{name}]"

        binary = raw.get("bin", name)
        _require(isinstance(binary, str) and _NAME_RX.match(binary),
                 f"{w}: 'bin' invalide ({binary!r}) — doit etre un NOM de fichier (ni '/' ni '..')")
        self.bin = binary

        group = raw.get("group", "extended")
        _require(isinstance(group, str) and group, f"{w}: 'group' invalide")
        self.group = group

        self.enabled = bool(raw.get("enabled", True))

        profiles = raw.get("profiles", ["full"])
        _require(isinstance(profiles, list) and profiles
                 and all(isinstance(p, str) and p for p in profiles), f"{w}: 'profiles' invalide")
        self.profiles = tuple(profiles)

        version = raw.get("version")
        _require(isinstance(version, str) and version and not _WS_RX.search(version),
                 f"{w}: 'version' invalide ({version!r})")
        self.version = version

        archive = raw.get("archive")
        _require(archive in ARCHIVE_KINDS,
                 f"{w}: 'archive' invalide ({archive!r}) — attendu {ARCHIVE_KINDS}")
        self.archive = archive

        url = raw.get("url")
        _require(isinstance(url, str) and url.startswith("https://") and not _WS_RX.search(url),
                 f"{w}: 'url' invalide — un gabarit HTTPS sans espace est exige (allowlist de source)")
        self.url_template = url

        member = raw.get("member", binary)
        _require(isinstance(member, str) and member and not _WS_RX.search(member),
                 f"{w}: 'member' invalide ({member!r})")
        _require(not member.startswith("/") and ".." not in member.split("/"),
                 f"{w}: 'member' ne peut etre absolu ni contenir '..' (anti-evasion de chemin)")
        self.member_template = member

        sha = raw.get("sha256")
        _require(isinstance(sha, dict) and sha, f"{w}: 'sha256' manquant — un pin par architecture est EXIGE")
        for arch, digest in sha.items():
            _require(arch in ARCH_ALIASES, f"{w}: architecture inconnue dans 'sha256' ({arch!r})")
            _require(isinstance(digest, str) and _SHA_RX.match(digest),
                     f"{w}: digest SHA256 invalide pour {arch} — 64 hexa minuscules attendus")
        self.sha256 = dict(sha)

        self.description = str(raw.get("description", ""))

    # --- resolution des gabarits -------------------------------------------------------------
    def _fmt(self, template, arch):
        return (template
                .replace("{version}", self.version)
                .replace("{arch_uname}", ARCH_ALIASES[arch])
                .replace("{arch}", arch))

    def url(self, arch):
        """URL de telechargement resolue pour `arch`. C'est la SEULE source autorisee pour cet outil."""
        self._check_arch(arch)
        return self._fmt(self.url_template, arch)

    def member(self, arch):
        """Chemin (ou motif glob) du binaire DANS l'archive, resolu pour `arch`."""
        self._check_arch(arch)
        return self._fmt(self.member_template, arch)

    def digest(self, arch):
        """SHA256 pin pour `arch`, ou None si l'outil n'est pas pin pour cette architecture
        (-> NON installable : refus fail-closed cote build comme cote runtime)."""
        return self.sha256.get(arch)

    def supports(self, arch):
        """True si un pin SHA256 existe pour `arch` (condition NECESSAIRE a toute installation)."""
        return arch in self.sha256

    def strip_components(self, arch):
        """Nombre de composants de chemin a retirer a l'extraction tar (= profondeur du `member`)."""
        return self.member(arch).count("/")

    def basename(self, arch):
        """Nom du fichier extrait (dernier composant du `member`)."""
        return self.member(arch).rsplit("/", 1)[-1]

    def _check_arch(self, arch):
        _require(arch in ARCH_ALIASES, f"architecture inconnue: {arch!r} (attendu {sorted(ARCH_ALIASES)})")

    def as_dict(self, arch=None):
        """Vue serialisable (pour `forge tools list --json`). Avec `arch`, ajoute l'URL/digest resolus."""
        out = {"name": self.name, "bin": self.bin, "group": self.group, "enabled": self.enabled,
               "profiles": list(self.profiles), "version": self.version, "archive": self.archive,
               "arches": sorted(self.sha256), "description": self.description}
        if arch is not None and self.supports(arch):
            out.update({"url": self.url(arch), "sha256": self.digest(arch), "member": self.member(arch)})
        return out


class Manifest:
    """Le manifeste charge : une collection ordonnee de `ToolEntry`, indexee par nom."""

    __slots__ = ("path", "schema", "tools")

    def __init__(self, raw, path="<manifeste>"):
        _require(isinstance(raw, dict), f"{path}: racine non-objet")
        schema = raw.get("schema")
        _require(schema == SCHEMA_VERSION,
                 f"{path}: schema {schema!r} non supporte (attendu {SCHEMA_VERSION})")
        items = raw.get("tools")
        _require(isinstance(items, list) and items, f"{path}: 'tools' doit etre une liste non vide")
        self.path = str(path)
        self.schema = schema
        self.tools = []
        seen = set()
        for item in items:
            entry = ToolEntry(item, where=path)
            _require(entry.name not in seen, f"{path}: outil duplique ({entry.name!r})")
            seen.add(entry.name)
            self.tools.append(entry)

    def __iter__(self):
        return iter(self.tools)

    def __len__(self):
        return len(self.tools)

    def get(self, name):
        """Entree nommee, ou None. C'est l'ALLOWLIST : un nom absent n'est PAS installable."""
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def names(self):
        return [t.name for t in self.tools]

    def select(self, group=None, arch=None, profile=None, enabled_only=True):
        """Sous-ensemble filtre, ordre du manifeste preserve. `arch` ne garde que les outils PINNES
        pour cette architecture (un outil sans pin est ecarte, jamais telecharge non verifie)."""
        out = []
        for t in self.tools:
            if enabled_only and not t.enabled:
                continue
            if group is not None and t.group != group:
                continue
            if profile is not None and profile not in t.profiles:
                continue
            if arch is not None and not t.supports(arch):
                continue
            out.append(t)
        return out


def manifest_path():
    """Chemin du manifeste : override `FORGE_TOOLS_MANIFEST`, sinon `tools.json` a cote de ce module."""
    override = os.environ.get(MANIFEST_ENV)
    if override:
        return Path(override)
    return Path(__file__).resolve().with_name(MANIFEST_FILENAME)


def load(path=None):
    """Charge et VALIDE le manifeste (fail-closed : toute anomalie leve `ManifestError`)."""
    p = Path(path) if path is not None else manifest_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ManifestError(f"manifeste illisible ({p}): {e}") from e
    except ValueError as e:
        raise ManifestError(f"manifeste JSON invalide ({p}): {e}") from e
    return Manifest(raw, path=str(p))


# =================================================================================================
#  Emetteur TSV — l'interface CONSOMMEE PAR LE DOCKERFILE (une ligne par outil a installer)
# =================================================================================================
# Champs (separes par UN espace, dans cet ordre) :  name version archive sha256 strip member bin url
# Aucun champ ne peut contenir d'espace (verifie ici, fail-closed) : la boucle `while read` du
# Dockerfile peut donc utiliser l'IFS par defaut, sans quoting exotique ni risque de decoupe.
EMIT_FIELDS = ("name", "version", "archive", "sha256", "strip", "member", "bin", "url")


def emit_rows(manifest, arch, group=None, profile=None):
    """Lignes TSV (list[str]) pour `arch`, filtrees par groupe/profil. Leve `ManifestError` si un
    champ contient un espace (l'emetteur ne produit JAMAIS une ligne que le lecteur decouperait mal)."""
    rows = []
    for t in manifest.select(group=group, arch=arch, profile=profile):
        fields = [t.name, t.version, t.archive, t.digest(arch), str(t.strip_components(arch)),
                  t.member(arch), t.bin, t.url(arch)]
        for value in fields:
            _require(not _WS_RX.search(value),
                     f"{t.name}: champ emis contenant un espace ({value!r}) — refus fail-closed")
        rows.append(" ".join(fields))
    return rows


def omitted(manifest, arch, group=None, profile=None):
    """Outils ACTIVES (et du profil demande) ECARTES faute de pin SHA256 pour `arch`. Ils ne sont
    jamais telecharges — l'integrite prime sur la couverture — et les modules correspondants
    degradent en `available:false` (deja gere par l'engine). Sert au rapport de build."""
    selected = {t.name for t in manifest.select(group=group, arch=arch, profile=profile)}
    return [t.name for t in manifest.select(group=group, arch=None, profile=profile)
            if t.name not in selected]


def require_complete(manifest, arch, group, profile=None):
    """Leve `ManifestError` si un outil ACTIVE du groupe `group` n'a PAS de pin pour `arch`.

    C'est la garde du BUILD sur le groupe socle (`core`) : l'image `full` promet httpx/nuclei/subfinder
    — un pin manquant doit FAIRE ECHOUER le build (bruyamment) plutot que produire une image
    silencieusement amputee. Les groupes optionnels (`extended`) ne passent PAS par cette garde : ils
    degradent proprement, comme aujourd'hui sur une architecture non-amd64."""
    missing = omitted(manifest, arch, group=group, profile=profile)
    _require(not missing,
             f"groupe '{group}' incomplet pour {arch} — pin SHA256 absent pour {sorted(missing)} ; "
             f"refus de construire une image amputee (ajouter le digest au manifeste)")


def main(argv=None):
    """`python3 forge/toolsmanifest.py --arch amd64 --group core [--profile full]` -> TSV sur stdout.

    Utilise TEL QUEL par le Dockerfile. Sortie vide = rien a installer (cas legitime : aucune entree
    pinnee pour cette architecture). Toute anomalie du manifeste -> message sur stderr + code 1
    (le `set -e` du build ECHOUE : jamais d'image silencieusement amputee d'un outil)."""
    p = argparse.ArgumentParser(
        prog="forge-tools-manifest",
        description="Emet le plan d'installation des outils (une ligne par outil) depuis forge/tools.json.")
    p.add_argument("--arch", required=True, choices=sorted(ARCH_ALIASES),
                   help="architecture cible (nomenclature Docker TARGETARCH)")
    p.add_argument("--group", help="ne garder que ce groupe (core|extended|...)")
    p.add_argument("--profile", help="ne garder que les outils embarques par ce profil d'image (ex full)")
    p.add_argument("--manifest", help="chemin du manifeste (defaut : tools.json a cote de ce module)")
    p.add_argument("--names", action="store_true", help="n'imprimer que les noms (diagnostic)")
    p.add_argument("--require-complete", dest="require_complete", metavar="GROUP", action="append",
                   default=[], help="ECHOUE si un outil active de GROUP n'a pas de pin pour --arch "
                                    "(garde du build sur le groupe socle) ; repetable")
    args = p.parse_args(argv)
    try:
        man = load(args.manifest)
        for group in args.require_complete:
            require_complete(man, args.arch, group, profile=args.profile)
        skipped = omitted(man, args.arch, group=args.group, profile=args.profile)
        if args.names:
            out = [t.name for t in man.select(group=args.group, arch=args.arch, profile=args.profile)]
        else:
            out = emit_rows(man, args.arch, group=args.group, profile=args.profile)
    except ManifestError as e:
        print(f"[forge] FATAL manifeste d'outils: {e}", file=sys.stderr)
        return 1
    if skipped:                                    # stderr : n'altere pas le plan lu par le Dockerfile
        print(f"[forge] outils OMIS pour {args.arch} (aucun pin SHA256 — jamais telecharges non "
              f"verifies) : {' '.join(sorted(skipped))}", file=sys.stderr)
    for line in out:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
