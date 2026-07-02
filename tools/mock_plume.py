#!/usr/bin/env python3
"""mock_plume.py — DEMO FIXTURE stub of the Plume SOC detection API (stdlib only).

⚠️  THIS IS NOT A REAL SOC. It serves a fixed, synthetic seed of MITRE-tagged "detections"
so that Forge's purple-team loop (`GET /api/purple/coverage`) can be demoed end-to-end,
fully offline, with a populated detected / missed / MTTD matrix. Never point a real
engagement at this stub.

It implements the single contract the Forge console consumes:

    GET /api/coverage/detections?since=<epoch_seconds>
        -> 200 {"detections":[{"mitre":"T1595","count":3,"first_ts":<epoch>}, ...],
                "_demo":true, "_warning":"DEMO FIXTURE — synthetic detections, NOT a real SOC"}

Detections with first_ts < since are filtered out (matches how a real SOC would answer a
windowed query). The seed is read from a JSONL file (default: the bundled reference
engagement) where each line is {"mitre","count","first_ts"[,...]}.

Also serves GET /health -> {"status":"ok","_demo":true}.

Stdlib only (http.server, json, argparse). Binds 127.0.0.1 by default. Zero dependencies.
"""
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

DEMO_WARNING = "DEMO FIXTURE — synthetic detections, NOT a real SOC"
DEFAULT_DETECTIONS = (
    Path(__file__).resolve().parents[1]
    / "examples" / "reference-engagement" / "detections.jsonl"
)


def load_detections(path):
    """Lit un JSONL de détections -> liste de dicts {mitre,count,first_ts,...}.

    Ignore les lignes vides et les commentaires (# ...). Lève ValueError si une ligne
    utile n'est pas un objet JSON avec un champ `mitre`. Pur, sans effet de bord réseau.
    """
    out = []
    text = Path(path).read_text(encoding="utf-8")
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict) or "mitre" not in obj:
            raise ValueError(f"{path}:{i}: chaque ligne doit être un objet avec un champ 'mitre'")
        out.append({
            "mitre": str(obj.get("mitre", "")),
            "count": int(obj.get("count", 0)),
            "first_ts": int(obj.get("first_ts", 0)),
            # champs additionnels conservés (rule/source…) — la console les ignore, l'humain les lit.
            **{k: v for k, v in obj.items() if k not in ("mitre", "count", "first_ts")},
        })
    return out


def detections_since(detections, since):
    """Sous-ensemble des détections dont first_ts >= since (fenêtre demandée par la console)."""
    try:
        since = int(since)
    except (TypeError, ValueError):
        since = 0
    return [d for d in detections if int(d.get("first_ts", 0)) >= since]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-plume-demo/0"

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Demo-Fixture", "mock-plume")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        # HTTP/1.1 : on force la fermeture (la console envoie `Connection: close` et lit jusqu'à EOF).
        self.close_connection = True

    def do_GET(self):  # noqa: N802 (nom imposé par BaseHTTPRequestHandler)
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok", "_demo": True, "_warning": DEMO_WARNING})
            return
        if parsed.path == "/api/coverage/detections":
            qs = parse_qs(parsed.query)
            since = qs.get("since", ["0"])[0]
            dets = detections_since(self.server.detections, since)
            self._send_json(200, {
                "detections": dets,
                "_demo": True,
                "_warning": DEMO_WARNING,
            })
            return
        self._send_json(404, {"error": "not_found", "_demo": True, "_warning": DEMO_WARNING})

    def log_message(self, fmt, *args):  # concis, sur stderr, préfixé DEMO (silencé si server.quiet)
        if getattr(self.server, "quiet", False):
            return
        sys.stderr.write("[mock-plume DEMO] %s - %s\n" % (self.address_string(), fmt % args))


def make_server(host, port, detections, quiet=False):
    """Construit un ThreadingHTTPServer prêt à `serve_forever()`. Les détections sont attachées
    à l'instance serveur (lues par le handler). `quiet=True` coupe le log par requête (tests).
    Réutilisable par les tests (thread + shutdown)."""
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.detections = list(detections)
    httpd.quiet = quiet
    return httpd


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="DEMO FIXTURE mock of the Plume SOC detections API (stdlib only, NOT a real SOC).",
    )
    ap.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8899, help="bind port (default 8899)")
    ap.add_argument("--detections", default=str(DEFAULT_DETECTIONS),
                    help="JSONL seed of detections (default: bundled reference engagement)")
    args = ap.parse_args(argv)

    try:
        detections = load_detections(args.detections)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        sys.stderr.write(f"[mock-plume DEMO] cannot load detections '{args.detections}': {e}\n")
        return 2

    httpd = make_server(args.host, args.port, detections)
    sys.stderr.write(
        "[mock-plume DEMO] ⚠️  SYNTHETIC SOC STUB — NOT A REAL SOC.\n"
        f"[mock-plume DEMO] serving {len(detections)} MITRE-tagged detection(s) from {args.detections}\n"
        f"[mock-plume DEMO] GET http://{args.host}:{args.port}/api/coverage/detections?since=<epoch>\n"
        f"[mock-plume DEMO] point the console at it with  PLUME_URL=http://{args.host}:{args.port}\n"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[mock-plume DEMO] shutting down.\n")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
