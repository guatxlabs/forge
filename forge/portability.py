# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-platform portability seams for the Forge engine — pur-stdlib, sans effet de bord.

Ce module CENTRALISE les décisions OS-spécifiques pour que le reste du moteur reste OS-agnostique.
Il ne change RIEN au comportement sous Linux : il ne fait qu'expliciter *comment* on résout les
répertoires de config/données par défaut et *comment* on garde les appels POSIX-only (chmod 0600)
inoffensifs sur une plateforme non-POSIX (Windows) — jamais de crash à l'import ni à l'exécution.

Contenu :
  - is_posix()/is_windows()/is_macos() : prédicats de plateforme minces.
  - config_dir()/data_dir()            : répertoires de config/données par défaut PAR OS, avec
                                         override d'environnement FORGE_* qui l'emporte toujours ;
                                         seuls les DÉFAUTS deviennent per-OS.
  - restrict_file_permissions()        : 0600 (propriétaire seul) sur POSIX ; no-op best-effort
                                         ailleurs (Windows n'exprime pas 0600) — le fichier atterrit
                                         quand même, juste sans les perms POSIX. Ne lève jamais.

Rien ici ne suppose un OS unique via un chemin/binaire codé en dur.
"""
import os
import sys
from pathlib import Path


def is_posix() -> bool:
    """True sur Linux/macOS/*BSD (os.name == 'posix')."""
    return os.name == "posix"


def is_windows() -> bool:
    """True sur Windows (os.name == 'nt')."""
    return os.name == "nt"


def is_macos() -> bool:
    """True sur macOS (Darwin)."""
    return sys.platform == "darwin"


def _override(env_var):
    """Chemin fourni via env (FORGE_*), développé (~ et vars), ou None. L'override l'emporte toujours."""
    raw = os.environ.get(env_var)
    if not raw:
        return None
    return Path(os.path.expanduser(os.path.expandvars(raw)))


def _mk(path, create):
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def config_dir(app="forge", env_var="FORGE_CONFIG_DIR", create=False):
    """Répertoire de CONFIG par défaut pour `app`, avec override d'environnement prioritaire.

    Précédence (seuls les DÉFAUTS sont per-OS ; l'override gagne toujours) :
      1. $FORGE_CONFIG_DIR (override opérateur explicite) — utilisé tel quel (~ / vars développés).
      2. Windows : %APPDATA%\\<app>  (repli ~/AppData/Roaming/<app> si APPDATA absent).
      3. POSIX/autre : $XDG_CONFIG_HOME/<app> sinon ~/.config/<app>.
    macOS retombe dans la branche POSIX (~/.config/<app>) — prévisible et sans surprise.
    Retourne un `pathlib.Path`. `create=True` -> mkdir(parents, exist_ok)."""
    ov = _override(env_var)
    if ov is not None:
        return _mk(ov, create)
    if is_windows():
        appdata = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
        return _mk(Path(appdata) / app, create)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else Path(os.path.expanduser("~")) / ".config"
    return _mk(root / app, create)


def data_dir(app="forge", env_var="FORGE_DATA_DIR", create=False):
    """Répertoire de DONNÉES par défaut (ledgers, mémoire, index) — même forme de précédence que
    config_dir(). Windows : %LOCALAPPDATA%\\<app> ; POSIX/autre : $XDG_DATA_HOME/<app> sinon
    ~/.local/share/<app>. Override : $FORGE_DATA_DIR. Retourne un `pathlib.Path`."""
    ov = _override(env_var)
    if ov is not None:
        return _mk(ov, create)
    if is_windows():
        local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return _mk(Path(local) / app, create)
    xdg = os.environ.get("XDG_DATA_HOME")
    root = Path(xdg) if xdg else Path(os.path.expanduser("~")) / ".local" / "share"
    return _mk(root / app, create)


def restrict_file_permissions(path, mode=0o600) -> bool:
    """Restreint `path` au propriétaire seul (0600 par défaut) SUR POSIX. Sur non-POSIX (Windows),
    c'est un no-op best-effort — `os.chmod` n'y bascule que le bit lecture-seule et ne peut pas
    exprimer 0600 — donc le fichier atterrit quand même, sans les perms POSIX. Ne lève JAMAIS
    (conserve la sémantique `try/except OSError: pass` des sites d'appel). Retourne True si le
    chmod POSIX a été appliqué, False sinon (non-POSIX, ou OSError avalé)."""
    if not is_posix():
        return False
    try:
        os.chmod(path, mode)
        return True
    except OSError:
        return False


def env_secret(name, env=None):
    """Résout un SECRET depuis l'environnement avec indirection `*_FILE` (pattern 12-factor / secrets
    Docker & k8s — « la clé ne doit pas être posée à côté de la porte »). La valeur en clair peut ainsi
    vivre dans un FICHIER monté (root-owned) plutôt que dans un `.env` à côté de l'app ; l'env ne porte
    alors qu'un CHEMIN, pas le secret.

    Priorité :
      1. `<name>` posé ET non vide      -> sa valeur (voie directe ; DÉFAUT COMMUNAUTAIRE — byte-identique).
      2. sinon `<name>_FILE` posé        -> LIT le fichier, retire le newline/espace de FIN (un `\\n`
                                            final dans un fichier de secret Docker ne doit pas corrompre
                                            le token/passphrase), et retourne le contenu.
         fichier illisible/absent         -> None + avertissement (nomme la VARIABLE, JAMAIS la valeur).
      3. sinon                           -> None.

    FAIL-SOFT : un `<name>_FILE` illisible ne lève jamais et ne renvoie jamais un secret vide silencieux
    (qui affaiblirait l'auth) — il renvoie None pour que le repli de l'appelant (génération/refus
    fail-closed) s'applique. La valeur du secret n'est JAMAIS journalisée. `env` (défaut os.environ)
    permet aux tests d'injecter un mapping.
    """
    e = os.environ if env is None else env
    v = e.get(name)
    if v is not None and v != "":
        return v                                    # voie directe — communauté inchangée
    file_path = e.get(name + "_FILE")
    if not file_path:
        return None
    try:
        data = Path(file_path).read_text(encoding="utf-8")
    except OSError as ex:                            # FAIL-SOFT : jamais de crash, jamais la valeur
        import sys
        print(f"[forge] avertissement : {name}_FILE illisible ({type(ex).__name__}) — "
              f"secret non résolu (fail-soft, aucune valeur exposée)", file=sys.stderr)
        return None
    # Retire whitespace/newline de FIN (convention fichier-secret Docker/k8s : `\n` terminal).
    return data.rstrip()
