"""Exécuteur d'outils externes — porté de `secpipe/runner.py`.

Lance un outil via le binaire local s'il est présent, sinon via `docker run --rm` — sans
jamais rien installer globalement. Les modules construisent la commande ; le runner exécute.
La GATE ROE est en amont : le runner n'est atteint qu'après un verdict FIRE. Zéro dépendance.
"""
import shutil
import subprocess


def cmdline(binary, docker_image=None, args=None, prefer_docker=False):
    """Chaîne de commande (pour dry-run / PoC) — ne lance rien.

    Sélection cohérente avec tool() : `prefer_docker` n'est qu'une PRÉFÉRENCE d'ordre, pas une
    exigence. Avec prefer_docker -> docker d'abord, REPLI sur le binaire local s'il est présent et
    docker absent (on ne renvoie « indisponible » que si NI docker NI binaire local). Sans
    prefer_docker -> binaire local d'abord, sinon docker. Dans les deux cas la voie restante est
    tentée plutôt que d'échouer en silence sur un outil pourtant disponible localement."""
    args = list(args or [])
    docker_ok = docker_image and shutil.which("docker")
    local_ok = bool(shutil.which(binary))
    if prefer_docker:
        order = (("docker", docker_ok), ("local", local_ok))
    else:
        order = (("local", local_ok), ("docker", docker_ok))
    for which, ok in order:
        if ok and which == "local":
            return " ".join([binary, *args])
        if ok and which == "docker":
            return " ".join(["docker", "run", "--rm", "--network", "host", docker_image, *args])
    return f"# indisponible: ni binaire '{binary}' ni image docker"


def available(binary, docker_image=None, prefer_docker=False):
    # Cohérent avec tool()/cmdline() : `prefer_docker` est une préférence d'ordre, pas une
    # exigence. Un outil est disponible dès que le binaire local OU docker(+image) est présent —
    # peu importe la préférence (sinon un binaire local pourtant exécutable serait masqué).
    return bool(shutil.which(binary)) or (docker_image is not None and bool(shutil.which("docker")))


def tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=120, env=None):
    """Exécute. Retourne (returncode, stdout, stderr). 127 si indisponible, 124 si timeout.

    `prefer_docker` n'est qu'une PRÉFÉRENCE d'ordre : avec prefer_docker -> docker d'abord, REPLI
    sur le binaire local présent si docker est absent ; sans prefer_docker -> binaire local d'abord,
    sinon docker. 127 (indisponible) UNIQUEMENT si NI docker NI binaire local n'est présent — on ne
    refuse plus un outil pourtant exécutable localement sous prétexte qu'il est dockerisé.

    `env` (optionnel) : environnement COMPLET du process enfant (dict). None (défaut) -> l'enfant
    HÉRITE de l'environnement courant (comportement historique, byte-identique). Un appelant qui doit
    marquer/isoler l'enfant (cf. `_daemon_reap.reaping_env` : HOME privé + FORGE_RUN_MARKER pour reaper
    un daemon fuité) passe un dict `os.environ`-dérivé — jamais un env partiel (PATH doit rester)."""
    args = list(args or [])
    docker_ok = docker_image and shutil.which("docker")
    # Résolution PATH via shutil.which : gère les suffixes .exe/.bat/.cmd (PATHEXT) sous Windows,
    # là où passer le nom nu à CreateProcess ne trouverait pas un wrapper .bat/.cmd. Sous Linux le
    # chemin résolu pointe le même binaire — comportement inchangé.
    local_path = shutil.which(binary)
    local_ok = bool(local_path)
    cmd = None
    order = (("docker", docker_ok), ("local", local_ok)) if prefer_docker \
        else (("local", local_ok), ("docker", docker_ok))
    for which, ok in order:
        if ok and which == "local":
            cmd = [local_path, *args]              # argv = binaire RÉSOLU (pas le nom nu) — portable
            break
        if ok and which == "docker":
            cmd = ["docker", "run", "--rm", "--network", "host", docker_image, *args]
            break
    if cmd is None:
        return (127, "", f"indisponible: ni binaire '{binary}' ni docker pour l'image '{docker_image}'")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return (p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return (124, "", f"timeout après {timeout}s")
    except Exception as e:  # noqa: BLE001
        return (1, "", f"erreur d'exécution: {e!r}")
