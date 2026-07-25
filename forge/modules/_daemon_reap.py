# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reaper CIBLÉ de daemons ORPHELINS laissés par un outil externe — stdlib pure, jamais de `pkill`.

Certains outils enveloppés (notamment `amass enum` en v4) DÉMARRENT un daemon persistant en tâche de
fond (`amass engine`, qui écoute sur :6060 avec `net/http/pprof` exposé) qui NE MEURT PAS quand l'outil
principal se termine. Le daemon est souvent DÉTACHÉ (setsid/double-fork) → il ÉCHAPPE au reap par groupe
de processus et FUIT (host-networking → pprof sur 0.0.0.0). Chaque run en laisse un de plus.

STRATÉGIE — MARQUEUR unique par run, PAS de `pkill amass` aveugle :
  1. l'outil est lancé avec un environnement portant un token UNIQUE (`FORGE_RUN_MARKER=<uuid>`) ;
  2. tout daemon qu'il démarre HÉRITE de cet environnement (fork/exec préservent l'environ, même
     après setsid/double-fork) ;
  3. APRÈS que l'outil principal se soit terminé (succès, timeout OU annulation), on SCANNE `/proc`
     et on TERMINE UNIQUEMENT les processus survivants dont l'environ porte NOTRE token — jamais un
     `amass` concurrent/utilisateur (token différent ou absent). Kill ciblé, déterministe, fail-safe.

INVARIANTS :
  - CIBLÉ : seul un processus portant EXACTEMENT notre token unique est tué. Un amass tiers survit.
  - GRACIEUX puis FERME : SIGTERM d'abord (laisse le daemon fermer proprement), SIGKILL en dernier ressort.
  - BEST-EFFORT : ne lève JAMAIS (I/O `/proc` tolérante) — le nettoyage ne doit pas casser le run.
  - PORTABLE-SAFE : sans `/proc` (non-Linux), le scan renvoie [] → no-op (aucun kill hasardeux).
"""
import contextlib
import os
import shutil
import signal
import tempfile
import time
import uuid

_MARKER_ENV = "FORGE_RUN_MARKER"        # nom de la variable d'env portant le token unique du run


def _iter_pids():
    """Itère les PID courants via `/proc` (Linux). Vide si `/proc` absent (non-Linux) → no-op sûr."""
    try:
        names = os.listdir("/proc")
    except OSError:
        return
    for name in names:
        if name.isdigit():
            yield int(name)


def _environ_has_marker(pid, token):
    """True si l'environ du process `pid` contient EXACTEMENT l'entrée `FORGE_RUN_MARKER=<token>`.
    Best-effort : un environ illisible (process disparu, autre utilisateur, permission) → False (jamais
    de kill à l'aveugle). Le match est fait sur une entrée NUL-délimitée COMPLÈTE (pas une sous-chaîne),
    et le token étant un uuid unique, aucun faux positif possible."""
    try:
        with open("/proc/%d/environ" % pid, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    needle = ("%s=%s" % (_MARKER_ENV, token)).encode()
    return any(entry == needle for entry in data.split(b"\x00"))


def pids_with_marker(token):
    """PID (hors soi-même) dont l'environ porte notre token unique — les descendants survivants du run."""
    me = os.getpid()
    return [pid for pid in _iter_pids() if pid != me and _environ_has_marker(pid, token)]


def _alive(pid):
    """True si `pid` existe ET n'est pas un zombie (défunt). Un zombie == déjà mort (kill réussi)."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            fields = fh.read().rsplit(b")", 1)
        state = fields[1].split()[0:1]
        return bool(state) and state[0] != b"Z"
    except OSError:
        return False


def reap_marker(token, *, term_grace=0.5, poll=0.02):
    """TERMINE tout process survivant portant `token` (SIGTERM, puis SIGKILL après `term_grace`s).
    CIBLÉ (token unique par run) — ne touche JAMAIS un outil tiers. Best-effort, ne lève jamais.
    Retourne la liste des PID visés."""
    victims = pids_with_marker(token)
    for pid in victims:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.monotonic() + max(0.0, term_grace)
    while time.monotonic() < deadline:
        if not any(_alive(pid) for pid in victims):
            break
        time.sleep(poll)
    for pid in victims:
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    return victims


@contextlib.contextmanager
def reaping_env(base_env=None, prefix="forge-tool-"):
    """Contexte fournissant un environnement d'exécution ISOLÉ pour un outil qui fuit un daemon :
      - `HOME` privé (répertoire temporaire) → l'outil (amass) y garde config/db/socket-moteur du run,
        sans polluer le HOME partagé ni collisionner avec un amass concurrent ;
      - `FORGE_RUN_MARKER=<uuid>` unique → tout daemon démarré hérite du token et devient IDENTIFIABLE.
    À la SORTIE (succès, timeout OU exception/annulation), REAP ciblé du token puis suppression du HOME
    privé. Le reap dans le `finally` garantit qu'un run interrompu (D1 SIGTERM/timeout) nettoie AUSSI."""
    token = uuid.uuid4().hex
    home = tempfile.mkdtemp(prefix=prefix)
    env = dict(os.environ if base_env is None else base_env)
    env["HOME"] = home
    env[_MARKER_ENV] = token
    try:
        yield env
    finally:
        try:
            reap_marker(token)
        finally:
            shutil.rmtree(home, ignore_errors=True)
