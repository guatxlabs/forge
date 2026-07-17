"""Exécuteur d'outils externes — porté de `secpipe/runner.py`.

Lance un outil via le binaire local s'il est présent, sinon via `docker run --rm` — sans
jamais rien installer globalement. Les modules construisent la commande ; le runner exécute.
La GATE ROE est en amont : le runner n'est atteint qu'après un verdict FIRE. Zéro dépendance.
"""
import os
import shutil
import signal
import subprocess
import threading

from . import resource_profile

# Défaut-code de la borne par-action (s). == profil `balanced` -> un `FORGE_RESOURCE_PROFILE` non
# défini garde EXACTEMENT le comportement historique (byte-identique).
_DEFAULT_ACTION_TIMEOUT = 120

# Délai de grâce SIGTERM->SIGKILL laissé au GROUPE de process pour se fermer proprement après un
# dépassement de timeout (miroir de `_daemon_reap.reap_marker` : term gracieux d'abord, kill ferme).
_TERM_GRACE = 5

# REGISTRE DES GROUPES D'OUTILS VIVANTS (fix E4) — chaque outil tourne dans sa PROPRE session
# (`start_new_session=True`) : un SIGTERM whole-run (cancel/watchdog de la console) atteint le moteur
# Forge mais PAS ces sessions séparées. Un `nuclei` en cours SURVIVRAIT donc au cancel (orphelin
# reparenté à init) — c'est le hard-kill manuel qu'il fallait faire à la main (T29). On tient donc un
# registre des pgid d'outils en vol pour que le handler SIGTERM du moteur (`forge/cli/engine.py`) les
# coupe EXPLICITEMENT et ne laisse AUCUN survivant. E4 tenait DÉJÀ un registre MULTI-pgid : c'est
# exactement ce que produit l'exécuteur PARALLÈLE borné du moteur (FORGE_PARALLELISM) — plusieurs outils
# en vol simultanément, chacun dans sa propre session. Sous parallélisme, les mutations
# (register/unregister) arrivent depuis les THREADS WORKERS (le `fire()` d'un module tourne dans le pool),
# plus seulement depuis le thread principal : l'ancien argument « un seul thread » ne tient plus. On
# SÉRIALISE donc register/unregister/snapshot par un VERROU. `set.add/discard` restent atomiques sous GIL,
# mais `list(set)` PEUT lever `RuntimeError: Set changed size during iteration` si un worker mute pendant
# que le handler prend son snapshot -> le verrou ferme cette fenêtre. SÛRETÉ DU HANDLER : le SIGTERM du
# moteur est délivré au THREAD PRINCIPAL (les workers ne posent jamais de handler) ; sous parallélisme le
# thread principal est bloqué à `future.result()` et NE DÉTIENT PAS ce verrou pendant un fire (ce sont les
# workers qui l'acquièrent, brièvement) -> le handler l'obtient sans auto-blocage. Un handler Python
# s'exécute comme du bytecode ordinaire à une frontière d'instruction : acquérir un `threading.Lock` y est
# licite (un worker le relâche en nanosecondes). En mode SÉRIEL (pool<=1) le fire tourne sur le thread
# principal mais l'exécuteur n'est pas utilisé : aucune contention, comportement inchangé.
_LIVE_TOOL_PGIDS = set()
_PGID_LOCK = threading.Lock()


def _register_tool_pgid(pgid):
    """Enregistre le groupe d'un outil qui vient d'être lancé (pgid == pid du leader, cf. start_new_session)."""
    with _PGID_LOCK:
        _LIVE_TOOL_PGIDS.add(pgid)


def _unregister_tool_pgid(pgid):
    """Retire le groupe d'un outil terminé/récolté (best-effort : discard ne lève pas si déjà absent)."""
    with _PGID_LOCK:
        _LIVE_TOOL_PGIDS.discard(pgid)


def terminate_live_tool_groups(force=True):
    """Coupe TOUS les groupes d'outils encore en vol — appelé par le handler SIGTERM du moteur sur un
    cancel/watchdog whole-run (fix E4). Sans ça, les outils en SESSIONS séparées (start_new_session)
    survivent au SIGTERM du groupe moteur. `force=True` -> SIGKILL immédiat (un cancel doit STOPPER NET ;
    le travail déjà collecté est flushé par D1 au checkpoint, l'outil en vol n'a rien rendu de toute façon).
    Coupe TOUS les groupes EN VOL simultanément -> compose avec l'exécuteur parallèle (plusieurs outils
    en vol tués ensemble, pas un seul).

    Snapshot `list(...)` pris SOUS `_PGID_LOCK` (les workers peuvent muter le set en parallèle -> sans le
    verrou, `list(set)` lèverait `RuntimeError` sur une mutation concurrente). `os.killpg` (un seul syscall)
    est appelé HORS du verrou pour ne pas retenir un worker pendant le kill, et ne lève jamais (process/
    groupe déjà mort -> ProcessLookupError/OSError avalé). PORTABLE : sans `os.killpg`/`SIGKILL` (Windows)
    -> no-op (pas de groupes POSIX ; documenté)."""
    if not (hasattr(os, "killpg") and hasattr(signal, "SIGKILL")):
        return
    sig = signal.SIGKILL if force else signal.SIGTERM
    with _PGID_LOCK:
        snapshot = list(_LIVE_TOOL_PGIDS)
    for pgid in snapshot:
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, OSError):
            pass


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


def tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=None, env=None):
    """Exécute. Retourne (returncode, stdout, stderr). 127 si indisponible, 124 si timeout.

    `timeout` (borne DURE par-action, s) — PRÉCÉDENCE : valeur explicite de l'appelant (override,
    ex. web.nuclei=600) > profil de ressources (`FORGE_RESOURCE_PROFILE`, levier `action_timeout_secs`)
    > défaut-code 120. `timeout=None` (défaut) déclenche la résolution par profil ; `balanced` == 120
    -> profil non défini byte-identique. `low` raccourcit (60s), `full` allonge (300s).

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
    if timeout is None:                                # défaut résolu par le profil de ressources
        timeout = resource_profile.resolve("action_timeout_secs", default=_DEFAULT_ACTION_TIMEOUT)
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
    # ENREGISTRE le groupe de l'outil (pgid == pid : leader de sa session) pour qu'un cancel/watchdog
    # whole-run puisse le couper malgré sa session séparée (fix E4). `finally` -> retiré à coup sûr, que
    # l'outil sorte normalement, timeoute ou lève (jamais de pgid réutilisé qui traînerait au registre).
    _register_tool_pgid(proc.pid)
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
            return (proc.returncode, out, err)
        except subprocess.TimeoutExpired:
            _terminate_group(proc)                              # SIGTERM au GROUPE (fermeture propre)
            try:
                out, err = proc.communicate(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                _terminate_group(proc, force=True)              # dernier ressort : SIGKILL du GROUPE
                try:
                    out, err = proc.communicate(timeout=_TERM_GRACE)
                except subprocess.TimeoutExpired:
                    out, err = "", ""                           # drain impossible -> on rend la main quand même
            return (124, out or "", f"timeout après {timeout}s (groupe de process terminé)")
        except Exception as e:  # noqa: BLE001
            _terminate_group(proc, force=True)
            return (1, "", f"erreur d'exécution: {e!r}")
    finally:
        _unregister_tool_pgid(proc.pid)
