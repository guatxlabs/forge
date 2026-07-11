"""Connecteur Metasploit (`msf.module`) — PILOTE msfrpcd, ne génère AUCUN payload.

Forge ne développe pas de capacité offensive ici : il PARLE à msfrpcd (le démon RPC de
Metasploit, un framework de pentest STANDARD que l'opérateur exécute déjà lui-même), lance le
module MSF que l'opérateur a explicitement choisi dans `action.params.msf_module`, et MAPPE le
résultat de l'outil en Finding(s). Toute la génération de shellcode/payload reste CÔTÉ MSF.

Transport : MessagePack-RPC sur HTTP POST `/api/` (le protocole natif de msfrpcd). Codec msgpack
auto-contenu (sous-ensemble : nil/bool/int/str/bin/array/map) pour rester PUR-STDLIB — zéro
dépendance dure, comme le reste du cœur Forge. `available` sonde le service À FIRE-TIME (TTL
court), JAMAIS au catalogue : lister les modules ne doit pas marteler le réseau.

Oracle À PREUVE (anti-faux-positif structurel) — DEUX canaux de preuve, chacun CONCRET :
  - EXPLOIT : `module.execute` est FIRE-AND-FORGET — il rend un `job_id`/`uuid` dès que le job
    DÉMARRE, AVANT de savoir si l'exploit a réussi. Promouvoir en `vulnerable` sur ce seul signal =
    faux positif systématique (« job lancé » ≠ « cible compromise »). On PRÉLÈVE donc les sessions
    AVANT le tir (`session.list`), puis on POLLE `session.list` après (budget BORNÉ) à la recherche
    d'une session NOUVELLE — corrélée par `exploit_uuid == uuid` quand disponible, sinon toute session
    apparue absente du snapshot. La PREUVE = une session réellement ouverte ; `vulnerable` QU'À CETTE
    CONDITION, avec le SESSION-ID dans l'evidence. Sans session dans le budget -> `reported_by_tool`.
  - AUXILIARY / SCANNER : jamais de session. La PREUVE = une CheckCode confirmée par le module lui-même
    (`module.results(uuid)` -> {status, result.code}). Un scanner qui CONFIRME l'état
    (`code in {vulnerable, appears}`) -> `vulnerable` (preuve : condition confirmée par l'outil) ;
    `code == safe` -> `not_vulnerable` ; toute autre issue (detected/unknown/inconclusive, résultats
    indisponibles) -> `reported_by_tool` (l'outil a tourné, aucune confirmation). Ce canal de preuve
    est OPT-IN (`params.check`) : sans lui, un auxiliary lancé reste `reported_by_tool` (comportement
    historique, aucun poll supplémentaire). NON DESTRUCTIF (une vérification/`check`, pas d'exploitation).

Gouvernance — DÉFENSE EN PROFONDEUR au-delà du ROE de l'engine (les MÊMES garde-fous, re-vérifiés ICI
quand un scope gouverné est LIÉ autour de fire() via `session.using` ; en fire() DIRECT non-lié — le
harnais de test — le module s'en remet au ROE de l'engine, la gate primaire) :

  (1) SCOPE-GUARD sur l'HÔTE CIBLE — on ne lance un module QUE si `action.target` ET tout `RHOSTS`/
      `RHOST` de `msf_options` sont IN-SCOPE (le scope du store fait foi). Un hôte hors-scope (dérivé à
      runtime, chaîné, découvert) => REFUS (status=skipped) SANS le moindre I/O vers msfrpcd (aucun
      auth.login, aucun module.execute, AUCUNE session ouverte).
  (2) PLANCHER EXPLOIT/DESTRUCTIF — INCHANGÉ, opt-in fort : un module MSF de type 'exploit' déclare
      exploit=True (via _exploit_for) => l'engine exige déjà allow_exploit en amont. En profondeur, si
      un scope est lié et que l'opt-in `allow_exploit`/`allow_high_impact` n'est PAS armé, l'exploit est
      REFUSÉ ICI (status=skipped, raison claire) — AUCUNE session ouverte, AUCUN I/O. auxiliary/scanner
      restent NON DESTRUCTIFS (aucun opt-in requis).
  (3) SESSION SECRÈTE — le matériel d'auth de la session gouvernée (réutilisé, jamais recopié) et les
      credentials msfrpcd (user/pass/token) n'entrent JAMAIS dans un finding, un PoC/dry, ni le ledger.
      Les options MSF sensibles (pass/token/secret/cred/key) sont RÉDIGÉES de toute evidence/dry.
  (4) DÉGRADATION GRACIEUSE — msfrpcd injoignable => status=skipped (offline-safe), jamais un plantage.

  - web_allowed=False : ce connecteur n'est PAS une surface de scan web public/recon — il se lance via
    opérateur/opt-in derrière la gouvernance, donc il ne compte pas dans le plancher web.

Mapping proof-oriented (LOT INTÉGRATION) — chaque Finding porte cwe/mitre dérivés de `forge/techniques.py`
(source de vérité) : un `params.cwe` explicite (l'opérateur connaît la classe de vuln du module choisi)
ou un « CWE-NNN » extrait du nom/résultat -> `techniques.mitre_for_cwe(cwe)` rattache la tactique ATT&CK
(repli T1210) et `schema` auto-déduit la remédiation.

Config via env (miroir scope) : MSF_RPC_HOST/PORT/USER/PASS/SSL, ou MSF_RPC_TOKEN (token
permanent). action.params peut surcharger (host/port/user/pass/ssl/token).
"""
import os
import re
import socket
import time
import urllib.error
import urllib.request

from ._msgpack import mp_pack, mp_unpack
from .registry import register, Module
from .. import session as _session
from .. import techniques
from ..schema import extract_cwe


_EXPLOIT_KINDS = ("exploit",)                     # seul ce type MSF élève à exploit=True
_SEV_BY_TYPE = {"exploit": "HIGH", "post": "MEDIUM", "auxiliary": "LOW",
                "scanner": "LOW", "encoder": "INFO", "nop": "INFO", "payload": "INFO"}
# Sévérité d'un finding CONFIRMÉ par un scanner (CheckCode vulnerable/appears) : condition prouvée par
# l'outil mais SANS shell -> MEDIUM (au-dessus du LOW informatif d'un simple lancement, sous le HIGH
# d'une session ouverte). Un scanner qui CONFIRME `safe` -> not_vulnerable, sévérité INFO.
_SEV_SCANNER_CONFIRMED = "MEDIUM"
# CheckCode MSF positifs / négatifs (Msf::Exploit::CheckCode). `detected`/`unknown`/`unsupported` =
# inconcluant -> reported_by_tool (aucune sur-classification sans preuve).
_CHECK_POSITIVE = ("vulnerable", "appears")
_CHECK_NEGATIVE = ("safe",)
# Options MSF susceptibles de contenir un secret -> rédigées de TOUTE evidence/dry (jamais journalisées).
_SECRET_OPT_RX = re.compile(r"(?i)(pass|password|secret|token|cred|api[_-]?key|\bkey\b)")


def _cfg(action):
    """Config msfrpcd depuis env (miroir scope), surchargée par action.params."""
    p = action.params or {}
    return {
        "host": p.get("host") or os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
        "port": int(p.get("port") or os.environ.get("MSF_RPC_PORT", "55553")),
        "user": p.get("user") or os.environ.get("MSF_RPC_USER", "msf"),
        "pass": p.get("pass") or os.environ.get("MSF_RPC_PASS", ""),
        "ssl": _as_bool(p.get("ssl"), os.environ.get("MSF_RPC_SSL", "true")),
        "token": p.get("token") or os.environ.get("MSF_RPC_TOKEN") or None,
    }


def _as_bool(override, env_default):
    if override is not None:
        return bool(override) if isinstance(override, bool) else str(override).lower() in ("1", "true", "yes")
    return str(env_default).lower() in ("1", "true", "yes")


def _truthy(v):
    """Interprète un flag opt-in (params) de façon robuste (bool | '1'/'true'/'yes'/'on')."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on") if v is not None else False


def _safe_opts(opts):
    """Copie des options MSF avec les valeurs SECRÈTES rédigées (jamais dans un finding/dry/ledger)."""
    if not isinstance(opts, dict):
        return opts
    return {k: ("<redacted>" if _SECRET_OPT_RX.search(str(k)) else v) for k, v in opts.items()}


def _rpc_url(cfg):
    scheme = "https" if cfg["ssl"] else "http"
    return f"{scheme}://{cfg['host']}:{cfg['port']}/api/"


def _rpc_call(cfg, method, *args, timeout=30):
    """Un appel msgpack-RPC à msfrpcd. Renvoie l'objet décodé, ou lève sur erreur réseau."""
    payload = mp_pack([method, *args])
    req = urllib.request.Request(_rpc_url(cfg), data=payload, method="POST",
                                 headers={"Content-Type": "binary/message-pack"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return mp_unpack(r.read())


def _probe(cfg, timeout=2):
    """available() à fire-time : le service msfrpcd est-il joignable ? (TCP connect, jamais lève)."""
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=timeout):
            return True
    except OSError:
        return False


def _scanner_verdict(res):
    """Interprète `module.results(uuid)` d'un scanner/auxiliary en (verdict, code, message, done).

    verdict : 'vulnerable' (CheckCode positive) | 'not_vulnerable' (CheckCode safe) | None (inconcluant).
    done : False UNIQUEMENT quand le run est encore en cours (`status` running/queued/pending) -> il
    faut re-poller ; True sinon (terminé/erreur/indéterminé) -> arrêter le poll. Pur, ne lève jamais."""
    if not isinstance(res, dict):
        return (None, "", "", True)
    if res.get("error"):
        return (None, "", "", True)
    status = str(res.get("status") or "").lower()
    if status in ("running", "queued", "pending"):
        return (None, "", "", False)                  # pas encore de résultat -> continuer le poll
    result = res.get("result")
    code, msg = "", ""
    if isinstance(result, dict):
        code = str(result.get("code") or result.get("check") or "").lower()
        msg = str(result.get("message") or result.get("details") or "")
    elif isinstance(result, str):
        code = result.lower()
    if code in _CHECK_POSITIVE:
        return ("vulnerable", code, msg, True)
    if code in _CHECK_NEGATIVE:
        return ("not_vulnerable", code, msg, True)
    return (None, code, msg, True)                     # terminé mais aucune CheckCode -> inconcluant


@register("msf.module")
class MsfModule(Module):
    kind = "msf.module"
    # `exploit` STATIQUE conservateur : un module MSF arbitraire PEUT être un exploit, donc on
    # déclare exploit=True au niveau classe (fail-safe : l'engine exigera allow_exploit). Le verdict
    # FIN par action est affiné par _exploit_for (auxiliary/scanner/post -> n'a pas besoin d'opt-in,
    # mais on ne RABAISSE jamais la garde au niveau classe — on ne fait que la documenter).
    exploit = True
    destructive = False
    web_allowed = False                               # lancé via opérateur/opt-in, PAS surface web recon
    mitre = "T1210"                                   # Exploitation of Remote Services
    description = ("Pilote msfrpcd (RPC msgpack) : lance le module Metasploit choisi par "
                  "l'opérateur, PROUVE la réussite (session ouverte pour un exploit ; CheckCode "
                  "confirmée pour un scanner) et ne promeut en vulnerable QU'AVEC preuve — sinon "
                  "reported_by_tool. Scope-guard sur l'hôte cible + plancher exploit opt-in.")

    # Budget de poll BORNÉ après un tir : max_polls × poll_interval (surchargés par params).
    # Défauts modestes (un module à 1 session/1 check répond vite ; on ne martèle pas msfrpcd).
    _POLL_INTERVAL = 1.0
    _MAX_POLLS = 15                                    # ~15s par défaut

    @property
    def available(self):
        # SONDE À FIRE-TIME, jamais figée au catalogue. cmd_modules lit `.available` -> on garde
        # la sonde rapide (TCP connect 2s) ; pas d'auth/exec ici (lister != lancer).
        return _probe(_cfg(_FakeAction()))

    @staticmethod
    def _exploit_for(module_type):
        """exploit=True UNIQUEMENT pour un module MSF de type 'exploit' (fort-impact)."""
        return str(module_type or "").lower() in _EXPLOIT_KINDS

    # --- résolution scope / opt-in gouvernés (via le store lié par le moteur autour de fire()) -------
    @staticmethod
    def _bound():
        """(store, scope, allow_exploit) depuis le SessionStore lié — (None, None, False) si aucun.

        `allow_exploit` réunit les deux noms d'opt-in fort-impact acceptés : `allow_exploit` (ROE de
        Forge) et `allow_high_impact` (alias en avance de phase). Non lié -> (None, None, False) : le
        module s'en remet au ROE de l'engine (gate primaire) et ne se sur-refuse pas en fire() direct."""
        store = _session.current()
        scope = getattr(store, "scope", None) if store is not None else None
        allow_exploit = False
        if scope is not None:
            allow_exploit = bool(getattr(scope, "allow_exploit", False)
                                 or getattr(scope, "allow_high_impact", False))
        return store, scope, allow_exploit

    @staticmethod
    def _target_candidates(target, opts):
        """Hôtes CIBLES à valider contre le scope : `action.target` + tout RHOSTS/RHOST des options."""
        cands = [target] if target else []
        for k in ("RHOSTS", "RHOST", "rhosts", "rhost"):
            v = (opts or {}).get(k)
            if v:
                cands += [s for s in re.split(r"[\s,]+", str(v)) if s]
        return cands

    @classmethod
    def _out_of_scope(cls, scope, target, opts):
        """Liste des hôtes cibles HORS scope (vide si tout in-scope). scope=None -> [] (défère au ROE)."""
        if scope is None:
            return []
        return [c for c in cls._target_candidates(target, opts) if not scope.is_in_scope(c)]

    @staticmethod
    def _msf_cwe(p, name, blob):
        """CWE canonique du finding : `params.cwe` explicite (l'opérateur connaît la classe du module),
        sinon un « CWE-NNN » extrait du nom du module ou du résultat brut. "" si indéterminable. Pur."""
        for src in (str((p or {}).get("cwe") or ""), str(name or ""), str(blob or "")):
            c = extract_cwe(src)
            if c:
                return c
        return ""

    def _login(self, cfg):
        """auth.login -> token, sauf si un token permanent est fourni. Lève sur échec."""
        if cfg.get("token"):
            return cfg["token"]
        res = _rpc_call(cfg, "auth.login", cfg["user"], cfg["pass"])
        if isinstance(res, dict) and res.get("result") == "success" and res.get("token"):
            return res["token"]
        raise RuntimeError(f"auth.login refusé: {res!r}")

    def dry(self, action):
        p = action.params or {}
        mtype = (p.get("msf_type") or "exploit").lower()
        name = p.get("msf_module", "?")
        opts = _safe_opts(p.get("msf_options", {}) or {})
        cfg = _cfg(action)
        is_exploit = self._exploit_for(mtype)
        _store, scope, allow_exploit = self._bound()
        confirm = _truthy(p.get("check") or p.get("confirm") or p.get("poll_results"))
        tail = ("session.list poll (preuve=session)" if is_exploit
                else ("module.results poll (CheckCode)" if confirm else "reported_by_tool"))
        posture = (f"exploit={is_exploit} needs_optin={'yes' if is_exploit else 'no'} "
                   f"optin_armed={'yes' if allow_exploit else 'no'} "
                   f"scope={'bound' if scope is not None else 'unbound'}")
        return (f"# msgpack-RPC -> {_rpc_url(cfg)} : auth.login(user) -> token ; "
                f"module.execute('{mtype}', '{name}', {opts}) ; {tail}   "
                f"# PILOTE msfrpcd (opérateur) — {posture} ; aucun payload généré par Forge")

    def fire(self, action):
        p = action.params or {}
        name = p.get("msf_module")
        mtype = (p.get("msf_type") or "exploit").lower()
        opts = p.get("msf_options", {}) or {}
        cfg = _cfg(action)

        if not name:
            return [self.finding(
                target=action.target, title="MSF non lancé — module manquant", severity="INFO",
                category="msf", status="tested", tool="msfrpcd",
                evidence="Requiert params.msf_module (ex: 'auxiliary/scanner/http/title') et params.msf_type.",
                poc=self.dry(action))]

        is_exploit = self._exploit_for(mtype)
        # Gouvernance DÉFENSE-EN-PROFONDEUR : ne s'active que si un scope gouverné est LIÉ (engine).
        _store, scope, allow_exploit = self._bound()

        # (1) SCOPE-GUARD — l'hôte cible (+ RHOSTS) doit être in-scope. Hors-scope => REFUS, ZÉRO I/O.
        oos = self._out_of_scope(scope, action.target, opts)
        if oos:
            return [self.finding(
                target=action.target, title="MSF — cible hors scope, module refusé", severity="INFO",
                category="msf", mitre=self.mitre, status="skipped", tool="msfrpcd",
                evidence=(f"scope-guard: {len(oos)} hôte(s) hors périmètre refusé(s) ({', '.join(oos)}), "
                          f"aucun I/O émis vers msfrpcd, aucune session ouverte"),
                poc=self.dry(action))]

        # (2) PLANCHER EXPLOIT/DESTRUCTIF (INCHANGÉ) — un exploit exige l'opt-in fort-impact armé.
        #     Refus DUR ici (défense en profondeur) : AUCUNE session ouverte, AUCUN I/O.
        if is_exploit and scope is not None and not allow_exploit:
            return [self.finding(
                target=action.target, title="MSF exploit refusé — opt-in fort-impact non armé",
                severity="INFO", category="msf", mitre=self.mitre, status="skipped", tool="msfrpcd",
                evidence=("plancher exploit: un module MSF de type 'exploit' exige "
                          "allow_exploit/allow_high_impact (opt-in gouverné) ET un scope autorisant — "
                          "non armé -> refusé, aucune session ouverte, aucun I/O vers msfrpcd"),
                poc=self.dry(action))]

        # (4) DÉGRADATION GRACIEUSE — msfrpcd injoignable -> status=skipped (offline-safe), pré-tir.
        if not _probe(cfg):
            return [self.finding(
                target=action.target, title="MSF — msfrpcd injoignable, module sauté", severity="INFO",
                category="msf", mitre=self.mitre, status="skipped", tool="msfrpcd",
                evidence=f"msfrpcd injoignable ({_rpc_url(cfg)}) — dégradation gracieuse (offline-safe)",
                poc=self.dry(action))]

        try:
            token = self._login(cfg)
            # Snapshot des sessions AVANT le tir (seulement pour un exploit : on corrèle une
            # session NOUVELLE après coup). session.list ne lève pas le test hors-exploit.
            pre_sessions = self._session_ids(cfg, token) if is_exploit else set()
            res = _rpc_call(cfg, "module.execute", token, mtype, name, opts)
        except (urllib.error.URLError, OSError) as e:
            # transport injoignable en cours d'appel -> dégradation gracieuse (offline-safe).
            return [self.finding(
                target=action.target, title="MSF — msfrpcd injoignable, module sauté", severity="INFO",
                category="msf", mitre=self.mitre, status="skipped", tool="msfrpcd",
                evidence=f"transport injoignable: {type(e).__name__}: {str(e)[:300]}", poc=self.dry(action))]
        except (RuntimeError, ValueError) as e:
            # service JOIGNABLE mais échec applicatif (auth refusée, msgpack invalide) -> finding traçable.
            return [self.finding(
                target=action.target, title=f"MSF — échec RPC ({type(e).__name__})", severity="INFO",
                category="msf", status="tested", tool="msfrpcd",
                evidence=str(e)[:500], poc=self.dry(action))]

        return self._map_result(action, cfg, token, name, mtype, is_exploit, opts, res, pre_sessions)

    @staticmethod
    def _session_ids(cfg, token):
        """Ensemble des session-ids ACTUELS (session.list -> map {id: info}). Vide si erreur/aucune."""
        try:
            res = _rpc_call(cfg, "session.list", token, timeout=10)
        except (urllib.error.URLError, OSError, ValueError):
            return set()
        if isinstance(res, dict) and not res.get("error"):
            return {str(k) for k in res.keys()}
        return set()

    def _session_table(self, cfg, token):
        """La map complète des sessions (session.list). {} si erreur/aucune session."""
        try:
            res = _rpc_call(cfg, "session.list", token, timeout=10)
        except (urllib.error.URLError, OSError, ValueError):
            return {}
        return res if (isinstance(res, dict) and not res.get("error")) else {}

    def _poll_for_session(self, action, cfg, token, uuid, pre_sessions):
        """Poll BORNÉ de session.list : renvoie (session_id, info) d'une session NOUVELLE, ou
        (None, None) si rien dans le budget. Corrélation : exploit_uuid == uuid du job si présent,
        sinon premier id absent du snapshot pré-tir."""
        p = action.params or {}
        max_polls = max(1, int(p.get("max_polls") or self._MAX_POLLS))
        interval = float(p.get("poll_interval") or self._POLL_INTERVAL)
        for i in range(max_polls):
            table = self._session_table(cfg, token)
            # 1) corrélation forte par exploit_uuid (la session porte l'uuid du job qui l'a ouverte).
            if uuid:
                for sid, info in table.items():
                    if isinstance(info, dict) and str(info.get("exploit_uuid") or "") == str(uuid):
                        return str(sid), info
            # 2) à défaut, toute session apparue qui n'existait pas avant le tir.
            for sid in table:
                if str(sid) not in pre_sessions:
                    return str(sid), table[sid]
            # budget BORNÉ : on ne dort PAS après la dernière sonde (sinon on gaspille `interval`
            # secondes pour rien) — le poll reste réactif et son temps total est ≤ (max_polls-1)*interval.
            if i < max_polls - 1:
                time.sleep(interval)
        return None, None

    def _confirm_via_results(self, action, cfg, token, uuid):
        """Poll BORNÉ de `module.results(uuid)` pour un auxiliary/scanner : renvoie (verdict, code, msg).
        verdict : 'vulnerable' | 'not_vulnerable' | None (inconcluant). Non destructif : une simple
        lecture du résultat de vérification du module (CheckCode), aucune weaponization. Dégrade en
        (None,'','') si les résultats sont indisponibles (méthode absente, transport, budget épuisé)."""
        p = action.params or {}
        max_polls = max(1, int(p.get("max_polls") or self._MAX_POLLS))
        interval = float(p.get("poll_interval") or self._POLL_INTERVAL)
        for i in range(max_polls):
            try:
                res = _rpc_call(cfg, "module.results", token, uuid, timeout=10)
            except (urllib.error.URLError, OSError, ValueError):
                return (None, "", "")                  # résultats indisponibles -> inconcluant
            verdict, code, msg, done = _scanner_verdict(res)
            if done:
                return (verdict, code, msg)
            if i < max_polls - 1:
                time.sleep(interval)
        return (None, "", "")                           # toujours en cours au bout du budget -> inconcluant

    def _map_result(self, action, cfg, token, name, mtype, is_exploit, opts, res, pre_sessions):
        """Mappe module.execute (job_id/uuid/error) en Finding(s) à PREUVE.

        EXPLOIT : POLL session.list ; `vulnerable` UNIQUEMENT sur session réelle (PREUVE, session-id
        en evidence), sinon `reported_by_tool`. AUXILIARY/SCANNER avec opt-in `check` : POLL
        module.results ; `vulnerable` sur CheckCode confirmée (preuve), `not_vulnerable` sur `safe`,
        sinon `reported_by_tool`. Sans opt-in `check` : `reported_by_tool` (l'outil a tourné).
        cwe/mitre dérivés de forge/techniques.py (source de vérité) sur CHAQUE finding."""
        p = action.params or {}
        confirm = _truthy(p.get("check") or p.get("confirm") or p.get("poll_results"))
        sev = _SEV_BY_TYPE.get(mtype, "INFO")
        safe_opts = _safe_opts(opts)
        cwe = self._msf_cwe(p, name, str(res)[:400])
        mitre = techniques.mitre_for_cwe(cwe) or self.mitre

        if isinstance(res, dict) and res.get("error"):
            return [self.finding(
                target=action.target, title=f"MSF {name} — refusé par le framework",
                severity="INFO", category="msf", cwe=cwe, mitre=mitre, status="not_vulnerable",
                tool=f"msfrpcd:{name}",
                evidence=f"error={res.get('error_message') or res.get('error_string') or res.get('error')}"[:500],
                poc=self.dry(action))]

        job_id = res.get("job_id") if isinstance(res, dict) else None
        uuid = res.get("uuid") if isinstance(res, dict) else None
        launched = isinstance(res, dict) and (res.get("result") == "success" or job_id is not None or uuid)

        if not launched:
            return [self.finding(
                target=action.target, title=f"MSF {name} — réponse inattendue",
                severity="INFO", category="msf", cwe=cwe, mitre=mitre, status="tested",
                tool=f"msfrpcd:{name}",
                evidence=f"type={mtype} exploit={is_exploit} job_id={job_id} uuid={uuid} options={safe_opts} raw={str(res)[:400]}",
                poc=self.dry(action))]

        # --- EXPLOIT lancé -> POLL pour une session : la PREUVE de compromission. ---
        if is_exploit:
            sid, sinfo = self._poll_for_session(action, cfg, token, uuid, pre_sessions)
            if sid is not None:
                stype = (sinfo.get("type") if isinstance(sinfo, dict) else None) or "?"
                shost = (sinfo.get("session_host") or sinfo.get("target_host")
                         if isinstance(sinfo, dict) else None) or action.target
                return [self.finding(
                    target=action.target, title=f"MSF exploit RÉUSSI: {name} (session {sid})",
                    severity=sev, category="msf", cwe=cwe, mitre=mitre, status="vulnerable",
                    tool=f"msfrpcd:{name}",
                    evidence=(f"PREUVE: session {sid} ouverte (type={stype} host={shost} "
                              f"exploit_uuid={uuid}) via job_id={job_id} options={safe_opts}"),
                    poc=self.dry(action))]
            # Lancé mais AUCUNE session dans le budget -> pas de preuve -> reported_by_tool.
            return [self.finding(
                target=action.target, title=f"MSF exploit lancé (sans session): {name} (job {job_id})",
                severity=sev, category="msf", cwe=cwe, mitre=mitre, status="reported_by_tool",
                tool=f"msfrpcd:{name}",
                evidence=(f"job lancé sans session obtenue dans le budget de poll "
                          f"(job_id={job_id} uuid={uuid} options={safe_opts}) — PAS de preuve de shell"),
                poc=self.dry(action))]

        # --- AUXILIARY / SCANNER avec opt-in `check` -> POLL module.results : la PREUVE = CheckCode. ---
        if confirm and uuid:
            verdict, code, msg = self._confirm_via_results(action, cfg, token, uuid)
            if verdict == "vulnerable":
                return [self.finding(
                    target=action.target, title=f"MSF {mtype} CONFIRMÉ vulnérable: {name}",
                    severity=_SEV_SCANNER_CONFIRMED, category="msf", cwe=cwe, mitre=mitre,
                    status="vulnerable", tool=f"msfrpcd:{name}",
                    evidence=(f"PREUVE: condition confirmée par le module (CheckCode={code}"
                              f"{'; ' + msg[:200] if msg else ''}) job_id={job_id} uuid={uuid} "
                              f"options={safe_opts}"),
                    poc=self.dry(action))]
            if verdict == "not_vulnerable":
                return [self.finding(
                    target=action.target, title=f"MSF {mtype} — cible non vulnérable: {name}",
                    severity="INFO", category="msf", cwe=cwe, mitre=mitre, status="not_vulnerable",
                    tool=f"msfrpcd:{name}",
                    evidence=(f"CheckCode={code} (safe) — le module a vérifié et n'a PAS confirmé la "
                              f"condition (job_id={job_id} uuid={uuid} options={safe_opts})"),
                    poc=self.dry(action))]
            # confirmation demandée mais résultat inconcluant/indisponible -> reported_by_tool.
            return [self.finding(
                target=action.target, title=f"MSF {mtype} lancé (check non concluant): {name}",
                severity=sev, category="msf", cwe=cwe, mitre=mitre, status="reported_by_tool",
                tool=f"msfrpcd:{name}",
                evidence=(f"type={mtype} job_id={job_id} uuid={uuid} check={code or '?'} "
                          f"options={safe_opts} — l'outil a tourné, AUCUNE CheckCode confirmée"),
                poc=self.dry(action))]

        # --- auxiliary/scanner/post lancé sans opt-in check -> l'outil a tourné, pas de preuve. ---
        return [self.finding(
            target=action.target, title=f"MSF {mtype} lancé: {name}",
            severity=sev, category="msf", cwe=cwe, mitre=mitre, status="reported_by_tool",
            tool=f"msfrpcd:{name}",
            evidence=f"type={mtype} exploit={is_exploit} job_id={job_id} uuid={uuid} options={safe_opts} raw={str(res)[:400]}",
            poc=self.dry(action))]


class _FakeAction:
    """Action minimale pour lire la config env depuis la property `available` (pas de params)."""
    params = {}
