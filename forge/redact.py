# SPDX-License-Identifier: AGPL-3.0-only
"""forge.redact — LA SURFACE UNIQUE ET AUDITÉE de rédaction des secrets.

Miroir du principe « une seule surface » du scope-guard (`roe.Scope`) : de même qu'il n'existe
qu'UN scope-guard, il n'existe qu'UN rédacteur de secrets. TOUT chemin qui doit neutraliser un secret
avant de le rendre / l'ingérer / le journaliser DÉLÈGUE ici. Trois implémentations avaient divergé
(rapport d'engagement = superset ; importateurs = tokens cloud manquants ; exposure = pire encore +
regex PEM `[A-Z ]*` cassée sur un type contenant un chiffre) — de vrais secrets FUYAIENT par deux des
trois chemins. Ce module rassemble l'UNION la plus large des trois, motifs compilés au chargement.

Propriétés garanties :
  - SUPERSET STRICT : masque au moins tout ce que chacune des trois anciennes implémentations masquait
    (plus jamais MOINS). La rédaction est monotone : réappliquer ne fait que masquer davantage.
  - IDEMPOTENT : réappliquer sur un texte déjà rédigé ne change rien (le marqueur ne re-déclenche pas).
  - PUR / NE LÈVE JAMAIS : entrée non-`str` (int/None…) renvoyée telle quelle ; `""` renvoyé tel quel.
  - STDLIB ONLY (`re`), regex à quantificateurs bornés côté classe (pas de backtracking catastrophique).

Familles couvertes (ordre le plus-spécifique-d'abord pour ne rien masquer à moitié) :
  clé privée PEM (type quelconque, chiffre inclus) · AWS AKIA/ASIA · JWT (`eyJ….….…`) · GitHub
  (`ghp_/gho_/ghu_/ghs_/ghr_`) · Slack (`xox[baprs]-`) · Google (`AIza…`) · OpenAI (`sk-…`) · GitLab
  (`glpat-…`) · `aws_secret_access_key=…` · schémas `Bearer`/`Basic <token>` · en-têtes toujours-secrets
  (Authorization/Proxy-Authorization/Cookie/Set-Cookie/X-Api-Key/X-Auth-Token/Api-Key) masqués jusqu'en
  fin de ligne · identifiants embarqués dans une URL (`scheme://user:pass@`) · paires clef=valeur
  sensibles, forme JSON `"clef":"valeur"` ET forme brute `clef=valeur`.
"""
from __future__ import annotations

import re
from typing import List, Pattern

REDACTED: str = "[REDACTED]"

# --- (1) formes de tokens à très haut signal (masquées EN ENTIER) — plus spécifiques d'abord -------
_TOKEN_PATTERNS: List[Pattern[str]] = [
    # clé privée PEM — `[A-Z0-9 ]*` couvre les types avec CHIFFRE (ex: `EC2 PRIVATE KEY`) que l'ancienne
    # regex `[A-Z ]*` d'exposure.py ratait. DOTALL : le corps multi-ligne est absorbé (non-gourmand).
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),                                    # AWS access key id
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),  # JWT
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),                                  # GitHub token
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}\b"),                                 # Slack token
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),                                     # Google API key
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                                         # OpenAI-style key
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),                                   # GitLab PAT
]

# --- (2) `aws_secret_access_key = …` — la valeur (souvent 40 car. base64) n'a pas de forme AKIA -----
_AWS_SECRET = re.compile(r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*\S+")

# --- (3) schémas de jeton portés inline (Bearer/Basic <token>) — on garde le nom du schéma ----------
_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-=/+]{6,}")

# --- (4) en-têtes quasi toujours secrets : on masque tout le reste de la ligne (`.` n'inclut pas \n) -
_HEADER_LINE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|"
    r"api-key|apikey)(\s*[:=]\s*)(\S.*)")

# --- (5) identifiants embarqués dans une URL (`scheme://user:pass@host`) — masque le mot de passe ---
# Quantificateurs BORNÉS (schéma/userinfo/mot de passe) : sans borne, `[a-z0-9+.\-]*://` rebacktrack à
# CHAQUE position -> O(n²) (DoS sur les corps ~300 KB d'exposure). Un schéma fait <31 car., un
# userinfo/mot de passe d'URL réaliste <256 — largement au-dessus des cas légitimes.
_URL_CRED = re.compile(r"(?i)([a-z][a-z0-9+.\-]{0,30}://)([^/\s:@]{1,256}):([^/\s@]{1,256})@")

# --- (6) paire clef=valeur sensible, forme JSON `"clef":"valeur"` (quote optionnelle des deux côtés) -
#         La classe de valeur n'exclut PAS `;` (parité avec l'ancien exposure : masque `a;b` en entier).
_KV_JSON = re.compile(
    r'(?i)("?(?:pass(?:word)?|passwd|pwd|secret[_-]?key|client[_-]?secret|aws[_-]?secret|'
    r'db[_-]?password|connection[_-]?string|api[_-]?key|apikey|access[_-]?key|access[_-]?token|'
    r'refresh[_-]?token|auth[_-]?token|id[_-]?token|session[_-]?token|session[_-]?id|sessionid|'
    r'private[_-]?key|app[_-]?key|x-api-key|x-auth-token|set-cookie|cookie|authorization|bearer|'
    r'credential|secret|token|auth)"?\s*[:=]\s*)("?)([^"\'\s,}&]{3,})(\2)')

# --- (7) paire clef=valeur sensible, forme brute `clef=valeur` (valeur bornée par \s ; & ; , ') ------
#         Conservée VERBATIM depuis report_engagement pour garantir la parité stricte du chemin rapport.
_KV = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|secret[_-]?key|client[_-]?secret|api[_-]?key|apikey|"
    r"access[_-]?key|access[_-]?token|token|authorization|auth|x-api-key|cookie|set-cookie|"
    r"private[_-]?key|session[_-]?token)\b(\s*[:=]\s*)(\"?)([^\s\"'&;,]{3,})")


def redact_secrets(text: str) -> str:
    """Neutralise les secrets d'une chaîne (UNION la plus large des formes connues + paires clef=valeur
    + creds d'URL + en-têtes secrets). Renvoie l'entrée telle quelle si ce n'est pas une chaîne
    (int/None…) ou si elle est vide. Pur, idempotent, ne lève jamais."""
    if not isinstance(text, str) or not text:
        return text
    s = text
    for p in _TOKEN_PATTERNS:
        s = p.sub(REDACTED, s)
    s = _AWS_SECRET.sub("aws_secret_access_key=" + REDACTED, s)
    s = _SCHEME.sub(lambda m: f"{m.group(1)} {REDACTED}", s)
    s = _HEADER_LINE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
    s = _URL_CRED.sub(lambda m: f"{m.group(1)}{m.group(2)}:{REDACTED}@", s)
    s = _KV_JSON.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(4)}", s)
    s = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}", s)
    return s
