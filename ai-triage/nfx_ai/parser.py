"""Parse an nfx-triage output directory into structured findings.

Every nfx tool prints findings as lines of the form

    [!] [TAG] message

This module reads each tool's text output, turns those lines into Finding records with a
stable evidence ID (tool:line), and extracts the entities they mention (paths, users, PIDs,
IP addresses) so later stages can correlate across tools.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict

FLAG_RE = re.compile(r"^\[!\]\s+\[([A-Za-z0-9_$.-]+)\]\s+(.*)$")
PATH_RE = re.compile(r"(?<![\w.:~/-])(/(?:[\w.@+-]+/?)+)")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PID_RE = re.compile(r"\bpid[ =](\d+)\b", re.I)
USER_RE = re.compile(r"\buser[ =:]+([a-z_][a-z0-9_.-]{0,31})\b", re.I)
ACCOUNT_RE = re.compile(r"^(?:system account with an interactive shell|account with home[^:]*):\s*([a-z_][a-z0-9_.-]*)", re.I)
TS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\b")
SUDOERS_USER_RE = re.compile(r"sudoers[^:\s]*:\d+:\s*([a-z_%][a-z0-9_.-]*)", re.I)
HEADER_RE = re.compile(r"^nfx-(\S+) v(\S+) \| host=(\S*) \| os=(\S*) \| user=(\S*) \| utc=(\S*)")

# Output files that are not per-tool reports.
SKIP_FILES = {"triage.log", "findings.txt"}


@dataclass
class Finding:
    id: str                 # stable evidence ID, e.g. "ssh:14"
    tool: str               # nfx tool name without prefix
    tag: str                # finding tag, e.g. AUTHKEYS-RECENT
    message: str            # text after the tag
    raw: str                # the original line, verbatim
    file: str               # source file name inside the triage directory
    line: int               # 1-based line number in that file
    paths: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    pids: list = field(default_factory=list)
    users: list = field(default_factory=list)
    timestamps: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Triage:
    directory: str
    host: str = ""
    os: str = ""
    collected_utc: str = ""
    collected_as: str = ""
    tools_run: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    complete: bool = True   # False when the collector stopped before writing its summary
    notes: list = field(default_factory=list)


def extract_entities(message: str) -> dict:
    paths = [p.rstrip("/.,:;)") or "/" for p in PATH_RE.findall(message)]
    users = USER_RE.findall(message) + ACCOUNT_RE.findall(message) + SUDOERS_USER_RE.findall(message)
    return {
        "paths": _dedupe(paths),
        "ips": _dedupe(IPV4_RE.findall(message)),
        "pids": _dedupe(PID_RE.findall(message)),
        "users": _dedupe(u.lower() for u in users),
        "timestamps": _dedupe(TS_RE.findall(message)),
    }


def _dedupe(items) -> list:
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def parse_file(path: str, tool: str | None = None) -> tuple[list, dict]:
    """Parse one tool output file. Returns (findings, header) where header may be empty."""
    name = os.path.basename(path)
    tool = tool or os.path.splitext(name)[0]
    findings, header = [], {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not header:
                h = HEADER_RE.match(line)
                if h:
                    header = dict(zip(("tool", "version", "host", "os", "user", "utc"), h.groups()))
                    continue
            m = FLAG_RE.match(line)
            if not m:
                continue
            tag, msg = m.group(1).upper(), m.group(2).strip()
            findings.append(Finding(id=f"{tool}:{n}", tool=tool, tag=tag, message=msg, raw=line,
                                    file=name, line=n, **extract_entities(msg)))
    return findings, header


def load_triage(directory: str) -> Triage:
    """Load every per-tool report in an nfx-triage directory (or a single tool output file)."""
    if os.path.isfile(directory):
        f, h = parse_file(directory)
        t = Triage(directory=os.path.dirname(os.path.abspath(directory)), findings=f)
        _apply_header(t, h)
        t.tools_run = [os.path.splitext(os.path.basename(directory))[0]]
        return t
    if not os.path.isdir(directory):
        raise FileNotFoundError(directory)
    t = Triage(directory=os.path.abspath(directory))
    for name in sorted(os.listdir(directory)):
        full = os.path.join(directory, name)
        if name in SKIP_FILES or not name.endswith(".txt") or not os.path.isfile(full):
            continue
        f, h = parse_file(full)
        t.findings.extend(f)
        t.tools_run.append(os.path.splitext(name)[0])
        if h and not t.host:
            _apply_header(t, h)
    if not os.path.exists(os.path.join(directory, "manifest.csv")):
        t.complete = False
        t.notes.append("No manifest.csv: the collector did not finish, so some tools may be missing "
                       "or their output cut short. Hashes were not recorded.")
    return t


def _apply_header(t: Triage, h: dict) -> None:
    if h:
        t.host, t.os, t.collected_as, t.collected_utc = h["host"], h["os"], h["user"], h["utc"]
