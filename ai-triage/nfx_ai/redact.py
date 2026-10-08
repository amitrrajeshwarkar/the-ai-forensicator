"""Replace identifying values with stable tokens before evidence leaves the analyst's machine.

The same value always maps to the same token (USER_1, IP_2, HOST), so the AI can still see that
two findings refer to the same account or address. The mapping stays local and is used to put
the real values back into the final report.
"""
from __future__ import annotations

import ipaddress
import re

# Accounts that exist on nearly every Unix system; naming them reveals nothing about the host.
WELL_KNOWN_USERS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
    "www-data", "backup", "list", "irc", "nobody", "systemd-network", "systemd-resolve", "messagebus",
    "sshd", "syslog", "_apt", "polkitd", "postgres", "mysql", "redis", "nginx", "apache", "_www",
}
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


class Redactor:
    def __init__(self, host: str = "", users=(), enabled: bool = True):
        self.enabled = enabled
        self.forward: dict = {}
        self.counters: dict = {}
        # Very short hostnames ("vm", "db") identify nothing and would collide with ordinary
        # words and paths, so only mask names of 4+ characters.
        if host and len(host) >= 4 and host not in ("localhost", "unknown"):
            self.forward[host] = "HOST"
        for u in sorted(set(users)):
            if u and u not in WELL_KNOWN_USERS:
                self._token(u, "USER")

    def _token(self, value: str, kind: str) -> str:
        if value not in self.forward:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.forward[value] = f"{kind}_{self.counters[kind]}"
        return self.forward[value]

    def _ip(self, m: re.Match) -> str:
        v = m.group(0)
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return v
        if ip.is_loopback or ip.is_unspecified:
            return v
        kind = "PRIVATE_IP" if ip.is_private else "IP"
        return self._token(v, kind)

    def text(self, s: str) -> str:
        if not self.enabled or not s:
            return s
        s = IPV4_RE.sub(self._ip, s)
        s = EMAIL_RE.sub(lambda m: self._token(m.group(0), "EMAIL"), s)
        # Longest values first so "amit-admin" is replaced before "amit".
        for value in sorted((v for v in self.forward if not v.startswith(("IP_", "PRIVATE_IP_"))), key=len, reverse=True):
            token = self.forward[value]
            if token.startswith(("IP_", "PRIVATE_IP_", "EMAIL_")):
                continue
            s = re.sub(rf"(?<![\w-]){re.escape(value)}(?![\w-])", token, s)
        return s

    def restore(self, s: str) -> str:
        if not self.enabled or not s:
            return s
        for value, token in sorted(self.forward.items(), key=lambda kv: len(kv[1]), reverse=True):
            s = re.sub(rf"\b{re.escape(token)}\b", value, s)
        return s
