"""Exécuteur d'outils externes — porté de `secpipe/runner.py`.

Lance un outil via le binaire local s'il est présent, sinon via `docker run --rm` — sans
jamais rien installer globalement. Les modules construisent la commande ; le runner exécute.
La GATE ROE est en amont : le runner n'est atteint qu'après un verdict FIRE. Zéro dépendance.
"""
import os
import shutil
import signal
import subprocess

# Délai de grâce SIGTERM->SIGKILL laissé au GROUPE de process pour se fermer proprement après un
# dépassement de timeout (miroir de `_daemon_reap.reap_marker` : term gracieux d'abord, kill ferme).
_TERM_GRACE = 5


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


def _terminate_group(proc, *, force=False):
    """TERMINE le GROUPE de process de `proc` (lancé avec start_new_session=True -> `proc` est LEADER de
    son propre groupe, pgid == pid). `force=False` -> SIGTERM (fermeture propre) ; `force=True` -> SIGKILL.

    Viser le GROUPE (et non `proc.kill()`, qui ne toucherait que l'enfant DIRECT) est la CLÉ de l'anti-hang :
    un outil comme nikto ou `docker run` FORK des petits-enfants (perl, conteneur) qui HÉRITENT du pipe
    stdout ; tuer le seul parent les laisse tenir le pipe ouvert -> `communicate()` HANGE au-delà du timeout
    (bug T27 : un tool gelait tout le pipeline 4+ min). Le kill de groupe emporte TOUT le sous-arbre.

    PORTABLE-SAFE : sans `os.killpg`/`SIGKILL` (Windows) -> repli sur `proc.terminate()`/`proc.kill()`
    (enfant direct). BEST-EFFORT : ne lève jamais (process déjà mort -> ProcessLookupError/OSError avalé)."""
    try:
        if hasattr(os, "killpg") and hasattr(signal, "SIGKILL"):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL if force else signal.SIGTERM)
        else:                                      # plateforme sans groupes POSIX -> enfant direct seul
            (proc.kill if force else proc.terminate)()
    except (ProcessLookupError, OSError):
        pass


def tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=120, env=None):
    """Exécute. Retourne (returncode, stdout, stderr). 127 si indisponible, 124 si timeout.

    `prefer_docker` n'est qu'une PRÉFÉRENCE d'ordre : avec prefer_docker -> docker d'abord, REPLI
    sur le binaire local présent si docker est absent ; sans prefer_docker -> binaire local d'abord,
    sinon docker. 127 (indisponible) UNIQUEMENT si NI docker NI binaire local n'est présent — on ne
    refuse plus un outil pourtant exécutable localement sous prétexte qu'il est dockerisé.

    BORNE DE RUNTIME PAR-ACTION (anti-hang) : `timeout` (s) borne DUREMENT l'exécution. Au dépassement, le
    GROUPE de process ENTIER est terminé (SIGTERM puis SIGKILL) — pas seulement l'enfant direct — de sorte
    qu'un tool qui hang (ou dont un petit-enfant tient le pipe) NE GÈLE PAS le pipeline : l'action rend 124
    et l'engine passe à la SUIVANTE. Voir `_spawn_and_wait`.

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
    return _spawn_and_wait(cmd, timeout, env)


def _spawn_and_wait(cmd, timeout, env):
    """Lance `cmd` (argv FIXE, NO-SHELL) dans son PROPRE groupe de process (`start_new_session=True`) et
    BORNE son runtime à `timeout`s. Retourne (rc, stdout, stderr) ; 124 si timeout ; 1 sur erreur de
    lancement. On N'UTILISE PAS `subprocess.run(timeout=)` : sa gestion de timeout ne tue que l'enfant
    DIRECT (`Popen.kill()`) puis re-`communicate()` — si un petit-enfant tient le pipe, elle HANGE quand
    même au-delà du timeout. Ici on tue le GROUPE ENTIER (cf. `_terminate_group`) puis on draine.

    COMPOSITION :
      - D1 (watchdog whole-run) : la nouvelle SESSION isole l'outil du groupe de process de Forge, donc
        `os.killpg` ne vise QUE le sous-arbre de l'outil (jamais Forge). Le SIGTERM whole-run de la console
        atteint Forge, dont l'attente ICI est BORNÉE par `timeout` : au retour, le checkpoint de l'engine
        déclenche l'arrêt gracieux. Le shutdown est donc DIFFÉRÉ d'au plus un timeout d'action — jamais gelé.
      - E2 (reap daemon, `_daemon_reap`) : mécanisme DISJOINT (kill par MARQUEUR d'env, dans le `finally`
        de `reaping_env` APRÈS ce retour) qui ramasse un daemon double-fork/setsid ayant ÉCHAPPÉ au groupe.
        Aucun double-kill/deadlock : `os.kill` sur un pid déjà mort est avalé (best-effort des deux côtés)."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env, start_new_session=True)
    except Exception as e:  # noqa: BLE001
        return (1, "", f"erreur d'exécution: {e!r}")
    try:
        out, err = proc.communicate(timeout=timeout)
        return (proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        _terminate_group(proc)                                  # SIGTERM au GROUPE (fermeture propre)
        try:
            out, err = proc.communicate(timeout=_TERM_GRACE)
        except subprocess.TimeoutExpired:
            _terminate_group(proc, force=True)                  # dernier ressort : SIGKILL du GROUPE
            try:
                out, err = proc.communicate(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                out, err = "", ""                               # drain impossible -> on rend la main quand même
        return (124, out or "", f"timeout après {timeout}s (groupe de process terminé)")
    except Exception as e:  # noqa: BLE001
        _terminate_group(proc, force=True)
        return (1, "", f"erreur d'exécution: {e!r}")
