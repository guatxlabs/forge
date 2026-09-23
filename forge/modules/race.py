# SPDX-License-Identifier: AGPL-3.0-or-later
"""LOT AUTH-FLOW / RACE — oracle de VÉRIFICATION Race-Condition / TOCTOU à PREUVE COMPTE-OPÉRATEUR
(`race.condition`).

Cet oracle CONFIRME qu'une action à USAGE LIMITÉ du compte de l'OPÉRATEUR est sujette à une course
(TOCTOU) avec une preuve MINIMALE, BORNÉE et NON DESTRUCTIVE au-delà de ce qui la prouve sur la
ressource PROPRE de l'opérateur — détection/vérification pour test autorisé, jamais un tiers :

  - race.condition : tire une PETITE rafale de requêtes PARALLÈLES (bornée par `_MAX_BURST` — jamais un
                     DoS) vers une action à usage limité de l'opérateur (code à usage unique, coupon,
                     refresh/device/recovery token, retrait de solde…) et COMPTE combien ont réussi.
                     PREUVE = un nombre de succès STRICTEMENT SUPÉRIEUR au quota `limit` autorisé
                     (défaut 1 pour un usage unique) -> la limite est DÉMONTRABLEMENT contournée par la
                     fenêtre TOCTOU (check-then-act non atomique). Le contournement porte UNIQUEMENT sur
                     la ressource PROPRE de l'opérateur (son propre code/coupon/token) — jamais un tiers,
                     jamais un solde d'autrui. Aucun succès au-delà du quota -> `tested` (jamais de
                     verdict à l'aveugle). Miroir conceptuel des PoC de course sur code de
                     récupération / refresh-token / device-code. CWE-362 (Race Condition) / CWE-367 (TOCTOU).

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise (défense en
      profondeur : l'engine gate déjà en Couche 2, on re-valide localement AVANT tout réseau).
  (2) PREUVE MINIMALE, BÉNIGNE & COMPTE-OPÉRATEUR : promotion `vulnerable` UNIQUEMENT si le quota est
      DÉMONTRABLEMENT dépassé sur la ressource PROPRE de l'opérateur. Sinon `tested`. Jamais un tiers.
  (3) BORNÉE, NON DoS : la rafale est plafonnée DUREMENT par `_MAX_BURST` (une poignée de requêtes
      concurrentes, jamais un flood) ; `exploit=False`, `destructive=False` (le seul état muté est la
      ressource LIMITÉE PROPRE de l'opérateur — la mutation minimale qui CONSTITUE la preuve).
  (4) SESSION SECRÈTE : le matériel d'auth gouverné (SessionStore) est fusionné par `Oracle._http`
      UNIQUEMENT sur des URL in-scope et n'est JAMAIS journalisé/rapporté (le PoC dérive des en-têtes de
      l'appelant, pas de la requête fusionnée).
  (5) DÉGRADATION GRACIEUSE : transport totalement indisponible -> `skipped` (offline-safe).

Bâti sur la base `ScopeGuardedOracle` (scope-guard + dégradation) + `Oracle` (Finding + HTTP + curl
partagés). `exploit=False`, `destructive=False` : sonde de vérification bornée compte-opérateur —
gardée par le ROE comme toute interaction web (`web_allowed`). Concurrence 100% stdlib
(concurrent.futures) : aucune dépendance externe (seul le réseau peut manquer)."""
import concurrent.futures as _cf
import socket as _socket
import ssl as _ssl
import time as _time
import urllib.parse as _urlparse

from .oracle import ScopeGuardedOracle
from .registry import register
from .. import techniques

# Codes HTTP considérés « succès » d'une action à usage limité par défaut (2xx d'écriture/redemption).
_SUCCESS_CODES = frozenset({200, 201, 202, 204})
# Plafond DUR de la rafale — « small burst », jamais un DoS/flood. Une course TOCTOU se gagne avec une
# poignée de requêtes concurrentes ; au-delà c'est du bruit inutile (et hostile).
_MAX_BURST = 24
_MIN_BURST = 2
_DEFAULT_BURST = 8


@register("race.condition")
class RaceCondition(ScopeGuardedOracle):
    kind = "race.condition"
    exploit = False              # contournement limité à la ressource PROPRE de l'opérateur -> non-exploit
    destructive = False          # seul état muté = la ressource LIMITÉE de l'opérateur (preuve minimale)
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # stdlib (concurrent.futures/urllib) -> toujours disponible
    mitre = techniques.mitre_for("race.condition")       # source de vérité : forge/techniques.py (T1190)
    cwe = "CWE-362"                                       # Race Condition (TOCTOU CWE-367 dans l'evidence)
    tool = "forge/modules/race.py:race.condition"
    fix = ("Rendre le check-then-act ATOMIQUE côté serveur : consommer la ressource à usage limité sous "
           "un verrou (SELECT … FOR UPDATE / contrainte d'unicité / compteur atomique / opération "
           "conditionnelle idempotente), invalider le code/coupon/token AVANT de délivrer la valeur, et "
           "sérialiser les redemptions concurrentes ; ne jamais dériver la disponibilité d'une lecture "
           "non verrouillée suivie d'une écriture séparée (CWE-362 / CWE-367).")
    description = ("Oracle Race/TOCTOU à PREUVE COMPTE-OPÉRATEUR : une petite rafale de requêtes "
                   "PARALLÈLES bornée (jamais un DoS) prouve qu'une action à usage limité de l'opérateur "
                   "réussit PLUS que le quota autorisé. Ressource PROPRE seulement, jamais un tiers. "
                   "Sinon tested. CWE-362/367.")

    @staticmethod
    def _burst_size(action):
        """Taille de rafale EFFECTIVE, clampée dans [_MIN_BURST, _MAX_BURST] (plafond DUR anti-DoS).
        Une valeur absente/illisible retombe sur `_DEFAULT_BURST`. Pur, ne lève jamais."""
        try:
            n = int(action.params.get("burst", _DEFAULT_BURST))
        except (TypeError, ValueError):
            n = _DEFAULT_BURST
        return max(_MIN_BURST, min(n, _MAX_BURST))

    def _limit(self, action):
        """Quota AUTORISÉ de succès (défaut 1 = usage unique). L'opérateur le déclare car il connaît sa
        ressource ; au-delà de ce quota, un succès concurrent supplémentaire = la course est gagnée."""
        try:
            return max(0, int(action.params.get("limit", 1)))
        except (TypeError, ValueError):
            return 1

    @staticmethod
    def _ok_codes(action):
        """L14 — ensemble des codes de statut comptés comme SUCCÈS. `success_codes` (param OPÉRATEUR, donc
        potentiellement malformé) est parsé DÉFENSIVEMENT : chaque entrée non convertible en `int` est
        IGNORÉE au lieu de crasher le module. Accepte une liste, un int seul, ou une chaîne « 200,201 ».
        Absent / vide / entièrement invalide -> repli sur `_SUCCESS_CODES`. Contrat : ne lève JAMAIS."""
        codes = action.params.get("success_codes")
        if not codes or isinstance(codes, bool):
            return _SUCCESS_CODES                       # None/''/[]/bool -> défauts
        if isinstance(codes, int):
            codes = [codes]
        elif isinstance(codes, str):
            codes = codes.replace(",", " ").split()
        try:
            items = list(codes)
        except TypeError:
            return _SUCCESS_CODES                       # valeur non itérable -> défauts (jamais de crash)
        parsed = set()
        for c in items:
            try:
                parsed.add(int(c))
            except (TypeError, ValueError):
                continue                                # entrée invalide -> ignorée (skip)
        return frozenset(parsed) if parsed else _SUCCESS_CODES

    def _is_success(self, st, body, action):
        """True si une réponse compte comme un SUCCÈS de l'action à usage limité. Précision > rappel :
        code 2xx d'écriture ET (marqueur de succès présent si fourni) ET (pas de marqueur d'échec)."""
        ok_codes = self._ok_codes(action)
        if st not in ok_codes:
            return False
        fail = action.params.get("failure_marker")
        if fail and str(fail) in (body or ""):
            return False
        marker = action.params.get("success_marker")
        if marker:
            return str(marker) in (body or "")
        return True

    def _burst(self, action, url, method, data, headers, n, timeout):
        """Tire n requêtes PARALLÈLES (rafale bornée) et renvoie la liste des (status, body).

        Deux SYNCHRONISATIONS, choisies par `params.sync` :

          * `"threads"` (DÉFAUT, inchangé) — `ThreadPoolExecutor` sur le seam `_fetch`. Simple et
            gouverné, mais la gigue entre les requêtes est de l'ordre de la MILLISECONDE : seules
            les fenêtres TOCTOU larges sont atteignables.
          * `"last_byte"` — synchronisation à DERNIER OCTET (« single-packet », J. Kettle 2023).
            On ouvre n connexions, on envoie chaque requête AMPUTÉE de son dernier octet, on laisse
            le serveur les mettre en attente, puis on envoie les n derniers octets d'affilée. La
            gigue tombe à quelques dizaines de MICROSECONDES.

        ⚠️ Pourquoi ce n'est pas un détail : sur les piles modernes, la fenêtre d'un check-then-act
        se compte en microsecondes. Un négatif obtenu en mode `threads` ne dit PAS « pas de race »,
        il dit « pas de race atteignable à la milliseconde ». C'est la différence entre un test et
        un verdict — et `fire()` l'écrit dans l'évidence plutôt que de la taire.

        Robuste : une exception d'un worker -> (None, '') ; un échec du transport bas niveau replie
        sur `threads` (le seam `_fetch` reste donc le chemin par défaut ET le filet).
        """
        if str(action.params.get("sync", "threads")).lower() == "last_byte":
            out = self._burst_last_byte(url, method, data, headers, n, timeout)
            if out:
                return out
            # repli silencieux impossible : `fire()` relit `params.sync` pour l'évidence, et le
            # mode réellement employé est reporté par `_sync_used`.
            action.params["_sync_fallback"] = True

        results = []

        def _one(_i):
            try:
                return self._fetch(url, headers=dict(headers), timeout=timeout,
                                   method=method, data=data)
            except Exception:            # noqa: BLE001  (worker hostile : on ne casse pas la rafale)
                return (None, "")

        with _cf.ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(_one, i) for i in range(n)]
            for fut in _cf.as_completed(futures):
                results.append(fut.result())
        return results

    @staticmethod
    def _raw_request(url, method, data, headers):
        """Sérialise une requête HTTP/1.1 complète en octets. `Connection: close` -> une réponse
        par connexion, pas de keep-alive à démêler."""
        u = _urlparse.urlparse(url)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        body = data if isinstance(data, bytes) else (data or "").encode()
        lignes = [f"{method} {path} HTTP/1.1", f"Host: {u.hostname}", "Connection: close"]
        vus = {"host", "connection", "content-length"}
        for k, v in (headers or {}).items():
            if str(k).lower() not in vus:
                lignes.append(f"{k}: {v}")
        if body:
            lignes.append(f"Content-Length: {len(body)}")
        return ("\r\n".join(lignes) + "\r\n\r\n").encode() + body

    @staticmethod
    def _parse_response(raw):
        """(status, corps) depuis une réponse HTTP brute. (None, '') si illisible."""
        if not raw:
            return (None, "")
        try:
            tete, _, corps = raw.partition(b"\r\n\r\n")
            premiere = tete.split(b"\r\n", 1)[0].decode("latin-1")
            return (int(premiere.split()[1]), corps.decode("utf-8", "replace"))
        except Exception:            # noqa: BLE001
            return (None, "")

    def _burst_last_byte(self, url, method, data, headers, n, timeout):
        """Synchronisation à DERNIER OCTET. Renvoie [] si le transport n'aboutit pas (-> repli).

        Le dernier octet est retenu sur CHAQUE connexion, puis les n derniers octets partent
        d'affilée : les requêtes deviennent complètes quasi simultanément côté serveur. `TCP_NODELAY`
        est indispensable — sans lui, l'algorithme de Nagle regrouperait nos envois et rendrait la
        synchronisation illusoire.

        AUCUNE requête supplémentaire par rapport au mode `threads` : c'est la MÊME rafale bornée,
        seulement mieux synchronisée. Le plafond `_MAX_BURST` s'applique en amont, dans `_burst_size`.
        """
        u = _urlparse.urlparse(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            return []
        port = u.port or (443 if u.scheme == "https" else 80)
        raw = self._raw_request(url, method, data, headers)
        if len(raw) < 2:
            return []

        conns = []
        try:
            ctx = _ssl.create_default_context() if u.scheme == "https" else None
            for _ in range(n):
                s = _socket.create_connection((u.hostname, port), timeout=timeout)
                s.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
                if ctx is not None:
                    s = ctx.wrap_socket(s, server_hostname=u.hostname)
                conns.append(s)

            for s in conns:                    # tout sauf le dernier octet
                s.sendall(raw[:-1])
            _time.sleep(0.10)                  # laisse les tampons serveur se remplir
            for s in conns:                    # les n derniers octets, d'affilée
                s.sendall(raw[-1:])

            out = []
            for s in conns:
                buf = b""
                try:
                    while True:
                        bout = s.recv(65536)
                        if not bout:
                            break
                        buf += bout
                        if len(buf) > 1_000_000:   # borne de lecture, jamais de mémoire illimitée
                            break
                except Exception:            # noqa: BLE001
                    pass
                out.append(self._parse_response(buf))
            return out
        except Exception:                    # noqa: BLE001  (DNS, TLS, refus… -> repli sur threads)
            return []
        finally:
            for s in conns:
                try:
                    s.close()
                except Exception:            # noqa: BLE001
                    pass

    def dry(self, action):
        n = self._burst_size(action)
        limit = self._limit(action)
        method = str(action.params.get("method", "POST")).upper()
        return (f"# tire une rafale BORNÉE de {n} requêtes PARALLÈLES {method} {action.target} vers la "
                f"ressource à usage LIMITÉ de l'OPÉRATEUR (code unique/coupon/refresh-token/solde) ; "
                f"PREUVE = plus de {limit} succès concurrents (quota contourné par la course TOCTOU) sur "
                f"SA PROPRE ressource ; rafale plafonnée à {_MAX_BURST} (jamais un DoS) ; sinon tested")

    def fire(self, action):
        # (1) SCOPE-GUARD fail-closed — hors périmètre -> skipped, AUCUN réseau (défense en profondeur).
        if not self._in_scope(action, action.target):
            return [self._scope_refused(action)]
        # config : il faut savoir DÉTECTER un succès pour compter les redemptions concurrentes (sinon
        # une évaluation de course n'a pas de sens et serait faux-positive-prone).
        if not action.params.get("success_marker") and not action.params.get("success_codes"):
            return [self.skip(
                target=action.target, title="Race/TOCTOU non testé — config manquante",
                evidence=("Requiert de définir la DÉTECTION de succès de l'action à usage limité : "
                          "params.success_marker (sous-chaîne unique d'une redemption réussie) OU "
                          "params.success_codes. Optionnel : params.limit (quota autorisé, défaut 1), "
                          "params.burst (taille de rafale, plafonnée à "
                          f"{_MAX_BURST}), params.method (défaut POST), params.data (corps portant la "
                          "ressource PROPRE de l'opérateur, ex le code à usage unique), params.headers, "
                          "params.failure_marker."),
                poc=self.dry(action))]
        method = str(action.params.get("method", "POST")).upper()
        data = action.params.get("data")
        headers = dict(action.params.get("headers", {}))
        try:
            timeout = max(1, min(int(action.params.get("timeout", 15)), 60))
        except (TypeError, ValueError):
            timeout = 15
        n = self._burst_size(action)
        limit = self._limit(action)

        # SONDE DE CONTRÔLE « CATCH-ALL » — UNIQUEMENT quand le succès est compté SUR LE STATUT SEUL.
        #
        # `_is_success` accepte deux contrats (cf. la garde de config ci-dessus) : `success_marker`
        # (PREUVE DE CORPS) ou `success_codes` (STATUT SEUL). Le second est exactement le défaut qui a
        # produit 8 faux HIGH dans `framework.exposure` : sur une cible qui répond 2xx à N'IMPORTE
        # QUELLE requête (SPA catch-all), la rafale entière est comptée « succès », `successes > limit`
        # est VRAI par construction, et l'oracle promeut un « Race/TOCTOU CONFIRMÉ » HIGH sans qu'aucune
        # redemption n'ait eu lieu. On demande donc d'abord deux chemins qui ne peuvent pas exister :
        # 2xx sur les deux -> `skipped`, et AUCUNE rafale n'est tirée (on n'envoie pas N écritures
        # concurrentes qu'on serait de toute façon incapable de juger).
        #
        # Le chemin `success_marker` n'est PAS sondé : sa preuve vient du CORPS, un catch-all ne peut
        # pas la fabriquer. Zéro requête ajoutée pour les opérateurs qui fournissent un marqueur.
        if not action.params.get("success_marker"):
            disc = self.path_discrimination(action, action.target, timeout=timeout)
            if disc.catchall:
                return [self.catchall_degraded(
                    target=action.target,
                    what=("race.condition (succès compté sur le STATUT seul — params.success_codes "
                          "sans params.success_marker)"),
                    disc=disc, poc=self.dry(action))]

        results = self._burst(action, action.target, method, data, headers, n, timeout)
        # (5) DÉGRADATION GRACIEUSE : aucune réponse du tout (transport indisponible) -> skipped (offline).
        seen = [(st, body) for st, body in results if st is not None]
        if not seen:
            return [self.degraded(
                target=action.target,
                title="Race/TOCTOU non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse du serveur à la rafale (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        successes = sum(1 for st, body in seen if self._is_success(st, body, action))
        # PREUVE : STRICTEMENT plus de succès que le quota autorisé -> la limite est contournée par la
        # course (check-then-act non atomique) sur la ressource PROPRE de l'opérateur.
        proven = successes > limit

        # PRÉCISION DE SYNCHRONISATION — dite dans l'évidence, jamais tue.
        # Un négatif obtenu par `threads` ne signifie PAS « pas de race » : la gigue y est de l'ordre
        # de la MILLISECONDE, quand une fenêtre check-then-act moderne se compte en microsecondes.
        # Le taire produirait exactement le faux négatif silencieux que cet oracle existe pour éviter
        # — et c'est le défaut mesuré le 2026-09-09 : 12 couples (cible, classe payante) sur 13 clos
        # sous les cinq tentatives, souvent sur un seul geste pris pour un verdict.
        demande = str(action.params.get("sync", "threads")).lower()
        replie = bool(action.params.get("_sync_fallback"))
        employe = "last_byte" if (demande == "last_byte" and not replie) else "threads"
        if employe == "last_byte":
            note_sync = ("synchronisation DERNIER OCTET (single-packet) : gigue de quelques dizaines "
                         "de microsecondes — les fenêtres courtes sont atteintes.")
        else:
            note_sync = ("synchronisation par THREADS : gigue de l'ordre de la milliseconde. "
                         + ("Le mode `last_byte` a été demandé mais le transport bas niveau n'a pas "
                            "abouti (DNS/TLS/refus) — repli. " if replie else "")
                         + ("⚠️ CE NÉGATIF NE CLÔT PAS LA CLASSE : une fenêtre de quelques "
                            "microsecondes reste hors de portée à cette précision. Rejouer avec "
                            "`params.sync=last_byte` avant de conclure." if not proven else ""))

        return [self.proof(
            target=action.target, proven=proven,
            title=(f"Race/TOCTOU CONFIRMÉ — {successes} succès concurrents > quota {limit} (usage limité "
                   f"contourné sur la ressource PROPRE de l'opérateur)" if proven
                   else "Race/TOCTOU non confirmé — le quota d'usage limité n'a pas été dépassé (pas de "
                        "verdict aveugle)"),
            severity=("HIGH" if proven else "INFO"),
            evidence=(f"rafale PARALLÈLE bornée={n} (réponses reçues={len(seen)}) ; succès comptés="
                      f"{successes} ; quota autorisé (limit)={limit} ; contournement={'OUI' if proven else 'non'} ; "
                      f"{note_sync} "
                      f"portée LIMITÉE à la ressource PROPRE de l'opérateur (code/coupon/token/solde à SON "
                      f"compte) — jamais un tiers ; rafale plafonnée à {_MAX_BURST} (non DoS) ; session "
                      f"gouvernée non journalisée ; TOCTOU = check-then-act non atomique (CWE-362/CWE-367)."),
            poc=(f"# tirer la MÊME requête N fois EN PARALLÈLE (course) sur la ressource à usage limité "
                 f"de l'OPÉRATEUR :\n"
                 f"# for i in $(seq 1 {n}); do {self._curl(action.target, headers, method, data)} & done; wait\n"
                 f"# PREUVE = plus de {limit} redemptions réussies en concurrence (quota contourné) sur SA "
                 f"PROPRE ressource ; rafale bornée (jamais un flood)"))]
