# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exécuteur d'outils externes.

Lance un outil via le binaire local s'il est présent, sinon via `docker run --rm` — sans
jamais rien installer globalement. Les modules construisent la commande ; le runner exécute.
La GATE ROE est en amont : le runner n'est atteint qu'après un verdict FIRE. Zéro dépendance.
"""
import itertools
import os
import re
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

# --- GARDE-FOU MÉMOIRE : BORNE LE NB DE SOUS-PROCESS OUTILS SIMULTANÉS (R4) -----------------------
# L'engine PARALLÉLISE les TIRS bloquants (module.fire -> runner.tool -> Popen) dans un pool de threads
# borné (FORGE_PARALLELISM). Chaque tir peut lancer un OUTIL LOURD (nuclei/sqlmap/docker run) qui, à N
# simultanés, peut faire SATURER la RAM d'une machine cliente FAIBLE (OOM). On pose donc un SÉMAPHORE
# BORNÉ GLOBAL autour du LANCEMENT RÉEL du process externe : au plus `max_concurrent_procs()` process
# vivants à la fois, TOUS pools/threads confondus. Il est acquis JUSTE AVANT `Popen` et relâché dans un
# `finally` APRÈS que le groupe de process a été RÉCOLTÉ (crash/timeout/kill compris) -> jamais de fuite.
#
# NO-OP PAR DÉFAUT : la table de profils garantit `max_concurrent_procs >= parallelism` pour CHAQUE
# profil (balanced 6>=4, low 2>=1, full 16>=12) -> sous les défauts le plafond est >= la taille du pool :
# le sémaphore ne BLOQUE JAMAIS (comportement byte-identique à aujourd'hui). Sa valeur est de laisser un
# opérateur sur machine contrainte poser `FORGE_MAX_CONCURRENT_PROCS=1` (ou un profil `low`) pour PLAFONNER
# les outils lourds SOUS la taille du pool et éviter l'OOM — sans toucher au parallélisme intra-vague.
#
# SÛRETÉ : le sémaphore borne les PROCESS, pas les WORKERS. Un worker bloqué à l'acquisition attend juste
# son tour (au plus `pool` workers en contention, plafond >= 1 -> au moins un progresse toujours) => AUCUN
# deadlock. Il n'enveloppe QUE la phase de tir parallèle (spawn/attente), JAMAIS l'ingest sériel de `_apply`
# (ledger/findings) ni le checkpoint D1 -> déterminisme et coverage-safety INCHANGÉS.
_ENV_MAX_CONCURRENT = "FORGE_MAX_CONCURRENT_PROCS"


def _max_concurrent_procs():
    """Plafond RÉSOLU de sous-process outils simultanés — PRÉCÉDENCE : override env
    `FORGE_MAX_CONCURRENT_PROCS` > profil de ressources (`FORGE_RESOURCE_PROFILE`) > défaut-code
    (valeur `balanced` = 6). RÉUTILISE le résolveur unique de `resource_profile` (aucune valeur codée en
    dur). Un override garbage retombe sur le profil (fail-open). Retourne toujours un int >= 1."""
    env = os.environ.get(_ENV_MAX_CONCURRENT)
    return resource_profile.max_concurrent_procs(override=env)


class _BoundedProcGate:
    """Sémaphore BORNÉ à plafond DYNAMIQUE — au plus `_resolver()` process externes vivants à la fois.

    Un `threading.BoundedSemaphore` fige sa valeur à la construction ; ici le plafond est RE-RÉSOLU à
    CHAQUE acquisition (via `_resolver`) pour refléter l'env/profil EN VIGUEUR sans reconstruction — ce
    qui rend le no-op-par-défaut et le cap-abaissé testables sans état mis en cache entre runs. Compte
    protégé par une `Condition` : un acquéreur attend tant que `actif >= plafond` puis incrémente ; la
    libération décrémente et réveille UN attendeur. Réentrant NON (aucun chemin n'imbrique deux tirs dans
    un même thread). DEADLOCK-FREE : `actif` est borné par le nb de workers en contention (<= pool) et le
    plafond est >= 1 -> au moins un acquéreur passe toujours ; un worker bloqué attend juste son tour."""

    def __init__(self, resolver):
        self._resolver = resolver
        self._cond = threading.Condition()
        self._active = 0

    def _cap(self):
        try:
            return max(1, int(self._resolver()))
        except (TypeError, ValueError):
            return 1

    def __enter__(self):
        with self._cond:
            self._cond.wait_for(lambda: self._active < self._cap())
            self._active += 1
        return self

    def __exit__(self, *exc):
        with self._cond:
            if self._active > 0:
                self._active -= 1
            self._cond.notify()
        return False


# Instance GLOBALE (un seul plafond partagé par tous les pools/threads du process).
_PROC_GATE = _BoundedProcGate(_max_concurrent_procs)

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
    # ET LA MOITIÉ QUI VIT DANS LE DÉMON DOCKER. Un cancel whole-run qui ne coupe que les groupes de
    # process LOCAUX laisse debout les conteneurs d'outils : `os.killpg` tue le client `docker run`,
    # jamais le conteneur (cf. le bloc « conteneur orphelin »). Le filet est ici parce que c'est ICI
    # qu'on a promis « coupe TOUS les groupes d'outils encore en vol ».
    terminate_live_containers()


# =================================================================================================
#  VOIE DOCKER — CE QU'ELLE CONSTRUIT, ET CE QU'ELLE REFUSE DE CONSTRUIRE
# =================================================================================================
#  La commande est `docker run --rm --network host [--entrypoint E] <image> <args…>`. Deux choses en
#  découlent, et les deux sont des DÉCISIONS, pas des oublis.
#
#  1. AUCUN `-v` / `--mount` — ET C'EST DÉLIBÉRÉ (refus documenté, pas une commodité manquante).
#     CE QUE ÇA COÛTE, NOMMÉMENT : `gobuster` exige un CHEMIN de wordlist -> inutilisable par la voie
#     docker (MESURÉ : `docker run --rm --network host ghcr.io/oj/gobuster dns --domain lab.test -w
#     <chemin hôte>` -> « wordlist file "…" does not exist » — le chemin de l'hôte n'existe pas DANS le
#     conteneur) ; `web.nuclei` a dû abandonner `-list <fichier>` au profit de `-u a,b,c`.
#     POURQUOI ON NE L'OUVRE PAS QUAND MÊME :
#       (a) `--network host` est DÉJÀ sur chaque invocation. Un montage, même `:ro`, borne les
#           ÉCRITURES — pas les LECTURES ; et une lecture dans un conteneur qui a le réseau de l'hôte
#           est à un `curl` de l'exfiltration. `:ro` + `--network host` ne protège donc PAS ce qui
#           compte ici (des secrets lus), il protège ce qui compte le moins (des fichiers écrits).
#       (b) le chemin à monter viendrait d'un PARAM d'exécution (`params.wordlist`, un champ `text` du
#           formulaire console), c'est-à-dire du canal de CONFIANCE LA PLUS BASSE du moteur. Toute la
#           posture du dépôt consiste à empêcher qu'une VALEUR de param devienne une CAPACITÉ
#           (`check_extra_args`, `safe_value`, `unsafe_positional_target`) ; transformer une valeur de
#           param en CHEMIN DE L'HÔTE MONTÉ dans une image tierce ferait exactement l'inverse.
#       (c) le borner correctement (allowlist de racines de montage) impose un défaut VIDE — sinon on
#           laisse passer `/` ou `~/.ssh`. Donc la capacité serait INERTE par défaut : elle ne servirait
#           qu'à l'opérateur qui l'arme explicitement, lequel dispose déjà de deux voies MESURÉES et
#           documentées — installer le binaire LOCAL (gobuster local lit le chemin hôte sans conteneur,
#           avec les privilèges du moteur et non ceux d'une image tierce), ou `dnsx -w www,mail,dev`
#           (liste INLINE, aucun fichier). On n'ouvre pas une surface d'accès fichier pour un gain nul
#           par défaut.
#     CE QUI RESTE VRAI : un opérateur qui veut vraiment monter un fichier dans un conteneur d'outil le
#     fait à la main, hors moteur. Le moteur, lui, ne fabrique jamais d'accès au système de fichiers de
#     l'hôte pour une image tierce.
#
#  2. `--entrypoint` EST construit (opt-in, déclaré par le spec) — il n'expose AUCUN fichier.
#     CE QU'IL DÉBLOQUE, MESURÉ : l'image officielle `ghcr.io/laramies/theharvester` a pour entrypoint
#     `["restfulHarvest","-H","0.0.0.0","-p","80"]` — un SERVEUR REST, pas la CLI ; sans override, tout
#     argv de catalogue y rend `unrecognized arguments`. C'était un blocage NOMMÉ dans `toolcatalog` et
#     `docs/TOOLS.md` ; il est levé.
#     GOUVERNÉ FAIL-CLOSED : un entrypoint INTERPRÉTEUR/SHELL est REFUSÉ (`entrypoint_refusal`). Sans
#     ce garde-fou, un ToolSpec DÉCLARATIF (dossier `./toolspecs`, monté `:ro` par défaut, vendu comme
#     « gouverné, zéro code ») pourrait poser `docker_entrypoint: "sh"` + `argv_template: ["-c", …]` et
#     RÉINTRODUIRE LE SHELL que tout le reste du moteur interdit. Le refus est posé ICI, au chokepoint
#     unique où l'entrypoint atteint `docker run` : il couvre TOUTES les voies de déclaration (code,
#     fichier, plugin), pas seulement celle qu'on aurait pensé à valider.

# Charset BORNÉ d'un entrypoint : un NOM ou un CHEMIN ABSOLU d'exécutable DANS l'image. Ne commence
# JAMAIS par '-' (anti option-smuggling vers `docker run` lui-même), aucun espace, aucun métacaractère
# shell, aucun NUL. Le chemin ABSOLU est admis à dessein (`--entrypoint /usr/local/bin/theHarvester`
# est la forme docker la plus courante) — c'est ce qui rend le contrôle d'interpréteur ci-dessous
# RÉELLEMENT ATTEIGNABLE : sans lui, `/bin/sh` tomberait sur le charset et la normalisation de basename
# ne servirait jamais. Le chemin RELATIF (`./x`, `../x`) reste refusé : rien à y gagner, une ambiguïté
# de résolution à y perdre.
_ENTRYPOINT_RX = re.compile(r"^[A-Za-z0-9/][A-Za-z0-9._+/-]*$")

# Interpréteurs/shells REFUSÉS comme entrypoint. MIROIR VOLONTAIRE de `modules/loader._INTERPRETER_BINARIES`
# (lui-même miroir de `INTERPRETER_BINARIES` côté Rust, console/src/tools.rs) : la liste n'est pas importée
# pour garder `runner` sans dépendance sur le paquet `modules` (cycle : modules.toolspec importe runner).
# `test_runner_docker_entrypoint.TestInterpreterListParity` VERROUILLE l'inclusion — si la liste amont
# gagne une entrée, le test CASSE au lieu de laisser ce refus silencieusement en retard.
_ENTRYPOINT_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash", "busybox", "env", "python",
    "python2", "python3", "perl", "ruby", "node", "nodejs", "deno", "bun", "php", "lua", "awk", "gawk",
    "mawk", "expect", "tclsh", "wish", "powershell", "pwsh", "cmd", "xargs", "find", "eval", "exec",
    "source", "sudo", "doas", "ssh", "scp", "sftp", "socat", "nc", "ncat", "netcat", "telnet", "rsync",
})


def entrypoint_refusal(entrypoint):
    """RAISON de refus d'un `--entrypoint` docker (str), ou None s'il est acceptable.

    Trois barrières, dans cet ordre : (1) charset borné (`_ENTRYPOINT_RX` — pas de '-' initial, pas
    d'espace, pas de métacaractère) ; (2) le BASENAME normalisé comme le fait le loader
    (`re.split(r"[\\\\/]")[-1].lower().split(".")[0]`, de sorte que `/bin/sh` et `python3.11` sont vus
    comme `sh` et `python3`) ; (3) ce basename ne doit PAS être un interpréteur/shell. Absent/vide ->
    None (aucun entrypoint = comportement historique). Pur, ne lève jamais."""
    if entrypoint is None or entrypoint == "":
        return None
    if not isinstance(entrypoint, str):
        return f"docker_entrypoint doit être une chaîne (reçu {type(entrypoint).__name__})"
    if not _ENTRYPOINT_RX.match(entrypoint):
        return (f"entrypoint docker {entrypoint!r} hors charset borné (alphanumérique + `. _ + / -`, "
                f"jamais un '-' initial, ni espace, ni métacaractère shell)")
    base = re.split(r"[\\/]", entrypoint)[-1].lower().split(".")[0]
    if base in _ENTRYPOINT_INTERPRETERS:
        return (f"entrypoint docker {entrypoint!r} est un interpréteur/shell ({base!r}) — refusé : "
                f"`--entrypoint {base} IMAGE -c '…'` réintroduirait le shell que l'argv fixe interdit")
    return None


# =================================================================================================
#  CONTENEUR ORPHELIN — `--rm` NE SUFFIT PAS, ET LE COÛT EST UNE CIBLE MARTELÉE APRÈS LE RUN.
#
#  MESURÉ le 2026-08-11, preuve horodatée : DEUX conteneurs feroxbuster encore VIVANTS des HEURES
#  après la fin de leurs campagnes —
#      zealous_easley    démarré 12:57:34   `feroxbuster --quiet -u http://127.0.0.1:3000 --rate-limit 5`
#      agitated_mestorf  démarré 13:50:09   `… --rate-limit 20`
#  … toujours en train de crawler à 16:11. Ils ont pollué trois mesures successives (une cible « au
#  repos » à 1,68 Gio, puis une cible MORTE avant même qu'une campagne ne soit tirée) avant qu'on ne
#  comprenne que la charge ne venait pas du run en cours.
#
#  LE PIÈGE : `docker run` est un CLIENT. Le conteneur, lui, vit dans le démon. `_terminate_group`
#  tue le sous-arbre de process LOCAL — le client meurt, le conteneur SURVIT, et `--rm` (qui ne se
#  déclenche qu'à la SORTIE du conteneur) n'arrive donc JAMAIS. Le SIGTERM est proxifié par le client
#  et peut suffire ; le SIGKILL, par construction, ne l'est pas. Un timeout d'action = un orphelin.
#
#  POURQUOI C'EST UNE FAILLE DE SÛRETÉ ET PAS UNE FUITE DE RESSOURCE : en engagement réel, c'est un
#  crawler qui continue de marteler la cible du client APRÈS la fin du run, sans borne, sans budget,
#  et SANS TRACE — le ledger dit « run terminé ». C'est exactement le « avoid service degradation »
#  que la quasi-totalité des programmes exigent.
#
#  LE CORRECTIF : chaque conteneur reçoit un NOM porteur du préfixe, et il est RETIRÉ DE FORCE en
#  sortie de tir, quelle que soit la voie (retour normal, timeout, exception). `cmdline()` (dry-run,
#  PoC) ne reçoit PAS de nom : ce qu'on montre à un humain reste copiable tel quel.
# =================================================================================================
CONTAINER_PREFIX = "forge-tool-"
_container_seq = itertools.count()


def _container_name():
    """Nom unique et RECONNAISSABLE. Le pid distingue deux forges concurrents sur la même machine ;
    le compteur, deux tirs du même forge. Le préfixe est ce qui rend le balayage de sûreté possible
    SANS tenir de liste (cf. `terminate_live_containers`)."""
    return f"{CONTAINER_PREFIX}{os.getpid()}-{next(_container_seq)}"


def _docker_rm(name):
    """Retire le conteneur DE FORCE. Best-effort et SILENCIEUX : sur le chemin normal `--rm` l'a déjà
    retiré et docker répond « No such container » — ce n'est pas une erreur, c'est la preuve que tout
    s'est bien passé. Ne lève jamais ; borné dans le temps (un démon docker qui rame ne doit pas
    retenir un worker)."""
    if not name:
        return
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
    except Exception:                                       # noqa: BLE001 — best-effort par contrat
        pass


def live_containers():
    """Conteneurs d'outils de CE forge encore présents — DÉRIVÉS de docker, jamais d'une liste tenue
    à la main (un conteneur orphelin est précisément celui qu'aucune liste ne connaît plus)."""
    try:
        r = subprocess.run(["docker", "ps", "-a", "--filter", f"name={CONTAINER_PREFIX}{os.getpid()}-",
                            "--format", "{{.Names}}"], capture_output=True, text=True, timeout=20)
    except Exception:                                       # noqa: BLE001
        return []
    return sorted({n.strip() for n in r.stdout.splitlines() if n.strip()})


def terminate_live_containers():
    """Filet de sûreté de fin de run : retire TOUT conteneur d'outil de ce forge encore debout, et
    REND CE QU'IL A TROUVÉ. Pendant du balayage de groupes de process (`terminate_live_tool_groups`),
    pour la moitié qui vit dans le démon docker et qu'aucun signal local n'atteint."""
    names = live_containers()
    for n in names:
        _docker_rm(n)
    return names


def _docker_argv(docker_image, args=None, entrypoint=None, name=None):
    """argv `docker run` — SOURCE UNIQUE partagée par `cmdline` (dry-run/PoC) et `tool` (exécution) :
    ce qu'on MONTRE est exactement ce qu'on LANCE, y compris l'entrypoint. Aucun `-v`/`--mount` n'y est
    construit (cf. la décision §1 ci-dessus). N'est appelé qu'après `entrypoint_refusal` -> None. Pur.

    `name` n'est posé QUE sur la voie d'exécution (cf. le bloc « conteneur orphelin ») : sans lui, un
    conteneur survivant au client `docker run` n'est plus identifiable, donc plus arrêtable. Absent
    (dry-run/PoC) -> argv BYTE-IDENTIQUE à l'historique."""
    cmd = ["docker", "run", "--rm", "--network", "host"]
    if name:
        cmd += ["--name", name]
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    cmd.append(docker_image)
    cmd += list(args or [])
    return cmd


def cmdline(binary, docker_image=None, args=None, prefer_docker=False, docker_entrypoint=None):
    """Chaîne de commande (pour dry-run / PoC) — ne lance rien.

    Sélection cohérente avec tool() : `prefer_docker` n'est qu'une PRÉFÉRENCE d'ordre, pas une
    exigence. Avec prefer_docker -> docker d'abord, REPLI sur le binaire local s'il est présent et
    docker absent (on ne renvoie « indisponible » que si NI docker NI binaire local). Sans
    prefer_docker -> binaire local d'abord, sinon docker. Dans les deux cas la voie restante est
    tentée plutôt que d'échouer en silence sur un outil pourtant disponible localement.

    `docker_entrypoint` (optionnel) n'a de sens QUE sur la voie docker : la voie locale exécute le
    binaire lui-même. Un entrypoint REFUSÉ (`entrypoint_refusal`) rend une ligne `# refusé: …` — jamais
    une commande qu'on ne lancerait de toute façon pas (le PoC affiché reste VRAI)."""
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
            bad = entrypoint_refusal(docker_entrypoint)
            if bad is not None:
                return f"# refusé: {bad}"
            return " ".join(_docker_argv(docker_image, args, docker_entrypoint))
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


def tool(binary, docker_image=None, args=None, prefer_docker=False, timeout=None, env=None,
         docker_entrypoint=None):
    """Exécute. Retourne (returncode, stdout, stderr). 127 si indisponible, 124 si timeout, 126 si
    l'entrypoint docker demandé est REFUSÉ (aucun processus lancé).

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
    un daemon fuité) passe un dict `os.environ`-dérivé — jamais un env partiel (PATH doit rester).

    `docker_entrypoint` (optionnel, voie DOCKER uniquement) : override de l'entrypoint de l'image, pour
    les images dont l'entrypoint n'est PAS la CLI attendue (mesuré : `ghcr.io/laramies/theharvester`
    démarre un serveur REST). REFUS FAIL-CLOSED d'un interpréteur/shell (`entrypoint_refusal`) -> rc=126
    et AUCUN processus lancé : sans ce refus, un spec déclaratif pourrait réintroduire le shell via
    `--entrypoint sh IMAGE -c '…'`. None/"" -> aucun `--entrypoint` (chemin historique BYTE-IDENTIQUE)."""
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
    container = None                                   # nom du conteneur, SI la voie docker est retenue
    order = (("docker", docker_ok), ("local", local_ok)) if prefer_docker \
        else (("local", local_ok), ("docker", docker_ok))
    for which, ok in order:
        if ok and which == "local":
            cmd = [local_path, *args]              # argv = binaire RÉSOLU (pas le nom nu) — portable
            break
        if ok and which == "docker":
            bad = entrypoint_refusal(docker_entrypoint)
            if bad is not None:                   # fail-closed : ZÉRO processus lancé
                return (126, "", f"entrypoint docker refusé (fail-closed) : {bad}")
            container = _container_name()         # cf. bloc « conteneur orphelin » : sans nom, inarrêtable
            cmd = _docker_argv(docker_image, args, docker_entrypoint, name=container)
            break
    if cmd is None:
        return (127, "", f"indisponible: ni binaire '{binary}' ni docker pour l'image '{docker_image}'")
    return _spawn_and_wait(cmd, timeout, env, container=container)


def _spawn_and_wait(cmd, timeout, env, container=None):
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
        Aucun double-kill/deadlock : `os.kill` sur un pid déjà mort est avalé (best-effort des deux côtés).

    GARDE-FOU MÉMOIRE (R4) : le LANCEMENT et l'attente sont enveloppés par le sémaphore borné global
    `_PROC_GATE` (plafond `max_concurrent_procs()`), acquis AVANT `Popen` et relâché dans le `finally`
    du `with` APRÈS récolte du process (retour normal, timeout OU exception) -> jamais de fuite de slot.
    Inerte sous les défauts (plafond >= pool). Il borne les PROCESS, pas les workers -> pas de deadlock
    (cf. `_BoundedProcGate`). N'enveloppe QUE ce tir : l'ingest sériel de l'engine reste hors sémaphore."""
    with _PROC_GATE:                                            # slot borné (garde-fou mémoire) — relâché en __exit__
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
                _terminate_group(proc)                          # SIGTERM au GROUPE (fermeture propre)
                try:
                    out, err = proc.communicate(timeout=_TERM_GRACE)
                except subprocess.TimeoutExpired:
                    _terminate_group(proc, force=True)          # dernier ressort : SIGKILL du GROUPE
                    try:
                        out, err = proc.communicate(timeout=_TERM_GRACE)
                    except subprocess.TimeoutExpired:
                        out, err = "", ""                       # drain impossible -> on rend la main quand même
                return (124, out or "", f"timeout après {timeout}s (groupe de process terminé)")
            except Exception as e:  # noqa: BLE001
                _terminate_group(proc, force=True)
                return (1, "", f"erreur d'exécution: {e!r}")
        finally:
            _unregister_tool_pgid(proc.pid)
            # LA MOITIÉ QUI NE VIT PAS DANS NOTRE ARBRE DE PROCESS. `_terminate_group` a tué le client
            # `docker run` ; le conteneur, lui, est dans le démon et lui survit — c'est ainsi qu'on a
            # laissé deux feroxbuster crawler pendant des heures après la fin de leurs runs. On retire
            # donc explicitement, sur TOUTES les voies de sortie. Sur le chemin normal `--rm` a déjà
            # fait le travail et docker répond « No such container » : le coût est un aller-retour.
            _docker_rm(container)
