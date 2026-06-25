"""Modules de recon — wrappers réels sur des outils externes via le runner.

Recon = non-exploit, mais touche quand même le réseau -> reste gaté (in-scope + armé requis).
Auto-neutralisation (`available`) si ni binaire ni docker présents : discipline héritée de Plume.
"""
from .registry import register, Module
from .. import runner


@register("recon.httpx")
class HttpxFingerprint(Module):
    kind = "recon.httpx"
    exploit = False
    mitre = "T1595"
    description = "Fingerprint HTTP (httpx) : status, titre, techno détectées."
    BIN, IMG = "httpx", "projectdiscovery/httpx"
    available = property(lambda self: runner.available("httpx", "projectdiscovery/httpx", prefer_docker=True))

    def _args(self, target):
        return ["-u", target, "-silent", "-status-code", "-title", "-tech-detect", "-json", "-no-color"]

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action.target), prefer_docker=True)

    def fire(self, action):
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action.target), timeout=60, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "httpx")
        if failed:
            return [failed]
        return [self.finding(
            target=action.target, title="Fingerprint HTTP (httpx)", severity="INFO",
            category="recon", mitre="T1595", status="tested", tool="httpx",
            evidence=(out or err).strip()[:1500], poc=self.dry(action))]


@register("recon.nmap")
class NmapServices(Module):
    kind = "recon.nmap"
    exploit = False
    mitre = "T1046"
    description = "Découverte des services exposés (nmap -sV) sur le top 1000 ports."
    BIN, IMG = "nmap", "instrumentisto/nmap"
    available = property(lambda self: runner.available("nmap", "instrumentisto/nmap", prefer_docker=True))

    def _args(self, target):
        return ["-sV", "-Pn", "--top-ports", "1000", target]

    def dry(self, action):
        return runner.cmdline(self.BIN, self.IMG, self._args(action.target), prefer_docker=True)

    def fire(self, action):
        rc, out, err = runner.tool(self.BIN, self.IMG, self._args(action.target), timeout=300, prefer_docker=True)
        failed = self.tool_failed(action, rc, out, err, "nmap")
        if failed:
            return [failed]
        return [self.finding(
            target=action.target, title="Services exposés (nmap -sV)", severity="INFO",
            category="recon", mitre="T1046", status="tested", tool="nmap",
            evidence=(out or err).strip()[:1500], poc=self.dry(action))]
