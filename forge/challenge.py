# SPDX-License-Identifier: AGPL-3.0-or-later
"""Détection de challenge/WAF managé sur une réponse HTTP — heuristiques HTTP pures (stdlib,
jamais de réseau), SANS rapport avec la taxonomie des techniques. Extrait de `techniques.py`
(pur déplacement) ; ré-exporté par `techniques.py` pour préserver les chemins d'import publics.
"""


# --- Détection de challenge/WAF managé sur une réponse HTTP (pur, stdlib, jamais de réseau) ---------
# Codes de statut typiques d'un blocage/challenge managé (Cloudflare & co) et sous-chaînes d'interstitiel
# de challenge dans le corps HTML. Sert aux modules de découverte HTTP à SIGNALER « recon bloquée par un
# challenge » (0 endpoint + signature) pour que le cerveau bascule sur la voie backed-browser. Volontairement
# CONSERVATEUR (sous-chaînes non ambiguës) pour éviter les faux positifs.
CHALLENGE_STATUS_CODES = frozenset({403, 429, 503})
CHALLENGE_BODY_SIGNATURES = (
    "just a moment", "checking your browser", "attention required", "cf-chl", "__cf_chl",
    "cf-mitigated", "cf_chl_opt", "/cdn-cgi/challenge-platform", "turnstile", "captcha-delivery",
    "datadome", "please enable javascript and cookies", "please stand by, while we are checking",
    "ddos protection by", "incapsula incident id", "this request was blocked",
)


def looks_like_challenge(status, body=""):
    """True si une réponse HTTP porte une SIGNATURE de challenge/WAF managé : code de blocage
    (403/429/503) OU interstitiel de challenge dans le corps HTML (Cloudflare « Just a moment »,
    DataDome, Turnstile…). Pur, ne lève jamais ; conservateur (sous-chaînes non ambiguës). Sert de
    signal « recon plain-HTTP bloquée » pour basculer sur la découverte backed-browser."""
    try:
        if status in CHALLENGE_STATUS_CODES:
            return True
        low = (body or "").lower()
        return any(sig in low for sig in CHALLENGE_BODY_SIGNATURES)
    except Exception:                                        # noqa: BLE001 (entrée hostile)
        return False
