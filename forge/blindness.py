# SPDX-License-Identifier: AGPL-3.0-or-later
"""CÉCITÉ CONSTATÉE — « je n'ai pas pu vérifier » ne doit JAMAIS s'écrire « j'ai vérifié, rien trouvé ».

CE QUI A ÉTÉ MESURÉ (campagne `gxrun2`, ledger signé de 11 Mo, infra de production autorisée
entièrement derrière un tunnel Cloudflare — aucun service sur 80/443, les 7 hôtes rendent un
interstitiel de défi à tout client HTTP) :

  - **4 839 findings `tested`** ont été émis alors que le moteur n'a JAMAIS vu une seule page de
    l'application. `tested` signifie « j'ai vérifié, rien trouvé » : un mur a donc produit des
    milliers d'AFFIRMATIONS DE NON-VULNÉRABILITÉ sur des cibles jamais regardées. C'est la forme la
    plus dangereuse du faux négatif — elle RESSEMBLE à de la couverture.
  - La garde existait pourtant déjà (`clearance.response_is_challenge`, câblée dans
    `clientflow._challenge_degraded`). Elle N'A PAS TIRÉ : `cache_poisoning.probe` et
    `header_injection.probe`, qui la portent, ont rendu **49 `tested` chacun** sur les hôtes que
    `curl` voyait répondre `403 cf-mitigated: challenge`, et **ZÉRO dégradation**.

POURQUOI ELLE N'A PAS TIRÉ — LA CAUSE RACINE, NOMMÉE
----------------------------------------------------
`Oracle._http` **JETTE le corps** sur `HTTPError` (`return e.code, "", e.headers`). Or l'interstitiel
Cloudflare — 5 229 octets de « Just a moment… » + `/cdn-cgi/challenge-platform`, la signature la plus
fiable qui soit, celle que `httpx` a enregistrée 19 fois dans ce même ledger — vit EXACTEMENT là. La
détection n'avait donc plus qu'une voie, l'en-tête `cf-mitigated` ; et cet en-tête, vu par `curl` en
HTTP/2, n'a démontrablement PAS atteint le chemin urllib (HTTP/1.1) : d'où les 49 + 49 `tested`.
La signature était sur la table, jamais servie.

CE QUE FAIT CE MODULE
---------------------
Un TÉMOIN par action (thread-local, exactement le patron de `throttle`/`session`/`pin`), alimenté au
CHOKEPOINT où la réponse ENTRE dans l'oracle (`Oracle._http`), et lu une seule fois à la frontière de
`fire()`. Deux compteurs, rien d'autre :

  - `challenges` : réponses portant une signature EXPLICITE de défi managé ;
  - `contents`   : réponses PROUVANT que l'application a été vue (`clearance.reach_is_content`).

Verdict d'AVEUGLEMENT (`blind()`) = `challenges > 0 ET contents == 0` : « un mur s'est interposé, et
je n'ai vu l'application à AUCUN moment de cette action ».

LA LIGNE À NE PAS FRANCHIR — pourquoi la conjonction, et pas moins
------------------------------------------------------------------
Le seul acquis solide du dépôt, sur deux campagnes réelles, est le **ZÉRO faux positif**. Ce chantier
peut le détruire dans les deux sens, et les deux bornes sont ici :

  1. `challenges > 0` exige une signature EXPLICITE (`clearance.response_is_challenge` : en-tête
     `cf-mitigated`/DataDome, ou interstitiel dans le corps) — JAMAIS un simple code de statut. Un
     **401/403 NU reste un verdict applicatif** : c'est le signal NORMAL d'un contrôle d'accès qui
     fonctionne, et c'est précisément ce qu'un oracle IDOR doit pouvoir juger. Confondre les deux
     rendrait forge aveugle à sa classe de vulnérabilité la plus payante.
  2. `contents == 0` : si UNE SEULE réponse de l'action a prouvé qu'on voyait l'application, l'oracle
     n'était PAS aveugle et son verdict est GARDÉ INTACT — même si une autre sonde a tapé un mur.
     Sans cette borne, un différentiel d'autorisation dont un seul côté est filtré par le WAF perdrait
     un verdict parfaitement valide.

Résiduel ASSUMÉ et NOMMÉ : un mur SANS signature (la règle d'edge `www` -> apex qui rend `301` corps
vide, mesurée sur `www.guatx.com`) reste indétectable ici — un `3xx` nu est trop ambigu pour taire un
oracle. `reach_is_content` refuse déjà d'y voir une réussite ; c'est au franchissement
(`evasion`/`clearance`) de l'ouvrir, pas à ce témoin de le deviner.

SECRET : ce module ne retient QUE des compteurs, des codes de statut et des hostnames. Jamais une
valeur de cookie, jamais un en-tête d'authentification, jamais un fragment de corps.
"""
import threading

from . import clearance as _clearance

_state = threading.local()

_MAX_HOSTS = 6                   # borne de l'évidence (des noms d'hôtes, pas un inventaire)


class Witness:
    """Compteurs d'une SEULE action. Ne lève jamais : une entrée hostile est comptée comme « rien vu »."""

    __slots__ = ("responses", "challenges", "contents", "hosts", "statuses")

    def __init__(self):
        self.responses = 0
        self.challenges = 0
        self.contents = 0
        self.hosts = []              # hostnames challengés (ordre stable, bornés) — AUCUN secret
        self.statuses = []           # codes de statut challengés (bornés)

    def note(self, status, body="", headers=None, host=""):
        """Enregistre UNE réponse entrée dans l'oracle. Retourne True si elle porte une signature
        EXPLICITE de défi managé (l'appelant s'en sert pour propager l'état au store gouverné)."""
        self.responses += 1
        try:
            challenged = _clearance.response_is_challenge(status, body, headers)
        except Exception:            # noqa: BLE001 (entrée hostile : jamais d'exception au chokepoint)
            challenged = False
        if challenged:
            self.challenges += 1
            h = str(host or "")
            if h and h not in self.hosts and len(self.hosts) < _MAX_HOSTS:
                self.hosts.append(h)
            if len(self.statuses) < _MAX_HOSTS:
                self.statuses.append(status)
            return True
        try:
            if _clearance.reach_is_content(status, body, headers):
                self.contents += 1
        except Exception:            # noqa: BLE001
            pass
        return False

    def blind(self):
        """L'action s'est-elle déroulée DERRIÈRE un mur, sans jamais voir l'application ?
        Conjonction STRICTE (cf. les deux bornes en tête de module)."""
        return self.challenges > 0 and self.contents == 0

    def why(self):
        """Explication SÛRE (compteurs + statuts + hostnames) pour l'évidence d'un finding."""
        hosts = ", ".join(self.hosts) or "—"
        codes = ", ".join(str(s) for s in self.statuses) or "—"
        return (f"{self.challenges}/{self.responses} réponse(s) portaient une signature de défi managé "
                f"(HTTP {codes} sur {hosts}) et AUCUNE n'a prouvé que l'application était visible")


# Préfixe d'évidence apposé à un finding DÉCLASSÉ : il NOMME le mur et ce que le statut veut dire.
DOWNGRADE_PREFIX = (
    "NON VÉRIFIÉ — un challenge/WAF managé s'est interposé : {why}. Ce constat ne vient donc PAS de "
    "l'application mais du mur, et il ne peut RIEN affirmer ; le statut passe de `tested` "
    "(« j'ai vérifié, rien trouvé ») à `skipped` (« je n'ai pas pu vérifier »). Router le "
    "franchissement (`evasion.turnstile`/`evasion.discover` récoltent la clearance vers la session "
    "gouvernée), puis rejouer. Constat d'origine, conservé tel quel ci-dessous : ")


def downgrade(witness, findings):
    """Déclasse `tested` -> `skipped` les findings d'une action rendue AVEUGLE. Rend `findings` (muté
    en place : `Finding` est une dataclass mutable, et rien d'autre que le statut/l'évidence ne change
    — cwe/fix/CVSS déjà dérivés restent EXACTS).

    Ne touche JAMAIS :
      - un `vulnerable` : une PREUVE obtenue reste une preuve, on ne supprime pas un positif ;
      - un `skipped` déjà posé (idempotent) ni aucun autre statut ;
      - quoi que ce soit si l'action n'était pas aveugle (`blind()` False) -> retour à l'identique,
        BYTE pour BYTE. C'est ce qui garantit que les tests hors-mur restent inchangés.
    Ne lève jamais (une liste hostile est rendue telle quelle)."""
    if witness is None or not witness.blind():
        return findings
    why = witness.why()
    try:
        for f in findings or []:
            if getattr(f, "status", None) != "tested":
                continue
            f.status = "skipped"
            f.evidence = DOWNGRADE_PREFIX.format(why=why) + (getattr(f, "evidence", "") or "")
    except Exception:                # noqa: BLE001 (jamais d'exception au retour d'un fire())
        return findings
    return findings


def current():
    """Témoin lié au thread courant, ou None (hors contexte -> aucun suivi). Ne lève jamais."""
    return getattr(_state, "witness", None)


def note(status, body="", headers=None, host=""):
    """Enregistre une réponse sur le témoin courant. **No-op strict hors contexte** (dev/test/appel
    direct de `Oracle._http`) : retourne False sans rien faire. Ne lève jamais."""
    w = current()
    if w is None:
        return False
    return w.note(status, body, headers, host)


class using:
    """Lie un témoin le temps d'un `fire()`. RÉENTRANT PAR RÉUTILISATION : si un témoin est déjà lié
    (oracle imbriqué), on rend CELUI-LÀ au lieu d'en créer un second — les sondes de l'appel interne
    sont ainsi comptées dans l'action englobante, et le déclassement se décide sur la vue COMPLÈTE de
    l'action (jamais sur une vue partielle, qui pourrait déclarer aveugle un oracle qui a vu la cible
    par un autre chemin). `owned` dit à l'appelant s'il est PROPRIÉTAIRE du témoin : seul le
    propriétaire déclasse, un appel imbriqué ne juge jamais sur une vue partielle."""

    def __init__(self):
        self.owned = current() is None
        self.witness = Witness() if self.owned else current()

    def __enter__(self):
        if self.owned:
            self.prev = getattr(_state, "witness", None)
            _state.witness = self.witness
        return self.witness

    def __exit__(self, *a):
        if self.owned:
            _state.witness = self.prev
        return False
