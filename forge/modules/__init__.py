"""Modules Forge. Importer ce package enregistre les modules livrés."""
from . import demo     # noqa: F401  (demo.fingerprint — no-op)
from . import recon    # noqa: F401  (recon.httpx, recon.nmap)
from . import web      # noqa: F401  (web.nuclei)
from . import access_control  # noqa: F401  (access_control.idor — IDOR/BOLA 2-comptes, CWE-639)
from . import ssrf     # noqa: F401  (ssrf.callback — SSRF callback-vérifié, CWE-918)
from . import auth     # noqa: F401  (auth.takeover — ATO/auth-bypass à preuve, CWE-287/640)
from . import cors     # noqa: F401  (cors.credentials — CORS-credentials à preuve, CWE-942)
from . import origin   # noqa: F401  (origin.find — IP d'origine derrière CDN)
from . import evasion  # noqa: F401  (evasion.xhr, evasion.turnstile, evasion.idor_intercept)
from . import msf       # noqa: F401  (msf.module — connecteur msfrpcd, opérateur opt-in)
from . import burp      # noqa: F401  (burp.scan — connecteur REST API Burp Suite)
from .registry import REGISTRY, register, get, kinds, Module  # noqa: F401
