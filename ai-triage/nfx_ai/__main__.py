"""nfx-analyze: correlate nfx-triage output and explain it, with or without AI.

Examples
  nfx-analyze nfx-triage-host01-20261008T101500Z/                  # offline, no AI
  nfx-analyze case-42/ --ai anthropic --redact                      # Claude, identifiers masked
  nfx-analyze case-42/ --ai openai --base-url http://localhost:11434/v1 --model llama3.1   # local
"""
from __future__ import annotations

import argparse
import os
import sys
import tarfile
import tempfile

from . import __version__
from .ai import build_payload, call_model, parse_json, restore, validate
from .correlate import analyse
from .parser import load_triage
from .redact import Redactor
from .report import to_json, to_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nfx-analyze", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("triage", help="nfx-triage output directory, its .tar.gz, or a single tool output file")
    p.add_argument("-o", "--output", help="report file (default: <triage>/analysis.md)")
    p.add_argument("--json", help="also write machine-readable results to this file")
    p.add_argument("--ai", choices=["none", "anthropic", "openai"], default="none",
                   help="AI provider: none (default), anthropic (Claude API), openai (any OpenAI-compatible API, "
                        "including local Ollama / LM Studio)")
    p.add_argument("--model", help="model name (default: claude-sonnet-5-5 for anthropic, llama3.1 for openai)")
    p.add_argument("--base-url", help="API base URL (for local models, e.g. http://localhost:11434/v1)")
    p.add_argument("--redact", action="store_true",
                   help="mask hostname, non-system usernames, IP addresses and emails before sending to the AI")
    p.add_argument("--max-leads", type=int, default=15, help="leads sent to the AI (default 15)")
    p.add_argument("--dry-run", action="store_true", help="write the exact AI request to stdout and stop")
    p.add_argument("-V", "--version", action="version", version=f"nfx-analyze {__version__}")
    a = p.parse_args(argv)

    src = a.triage
    if src.endswith((".tar.gz", ".tgz")) and os.path.isfile(src):
        tmp = tempfile.mkdtemp(prefix="nfx-analyze-")
        with tarfile.open(src) as tf:
            try:
                tf.extractall(tmp, filter="data")      # refuses absolute paths and links outside tmp
            except TypeError:                          # Python < 3.12 without the filter backport
                for m in tf.getmembers():
                    if m.name.startswith("/") or ".." in m.name.split("/") or m.issym() or m.islnk():
                        raise SystemExit(f"refusing unsafe archive member: {m.name}")
                tf.extractall(tmp)
        subdirs = [os.path.join(tmp, d) for d in os.listdir(tmp)]
        src = subdirs[0] if len(subdirs) == 1 and os.path.isdir(subdirs[0]) else tmp

    triage = load_triage(src)
    analysis = analyse(triage.findings)
    users = {u for f in triage.findings for u in f.users} | ({triage.collected_as} if triage.collected_as else set())
    redactor = Redactor(host=triage.host, users=users, enabled=a.redact)

    ai_reply, problems = None, []
    meta = {"version": __version__, "engine": "offline correlation (no AI)", "redacted": a.redact}
    if a.ai != "none" or a.dry_run:
        payload = build_payload(triage, analysis, redactor, a.max_leads)
        if a.dry_run:
            import json
            print(json.dumps(payload, indent=1))
            return 0
        model = a.model or {"anthropic": "claude-sonnet-5-5", "openai": "llama3.1"}[a.ai]
        meta["engine"] = f"correlation + {a.ai} ({model}{', redacted' if a.redact else ''})"
        print(f"[*] sending {len(payload['leads'])} leads and {len(payload['clusters'])} clusters to {a.ai} ({model})",
              file=sys.stderr)
        try:
            raw = call_model(payload, a.ai, model, a.base_url)
            ai_reply, problems = validate(parse_json(raw), payload)
            ai_reply = restore(ai_reply, redactor)
        except Exception as e:  # report still useful without AI
            problems = [f"AI step failed, report is offline-only: {e}"]
            meta["engine"] += " - FAILED, offline fallback"
            ai_reply = None

    out = a.output or os.path.join(triage.directory, "analysis.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(triage, analysis, ai_reply, problems, meta))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(triage, analysis, ai_reply, problems, meta))
    s = analysis.stats
    print(f"[*] {s['findings']:,} findings -> {len(analysis.clusters)} noise clusters + {s['leads']} leads", file=sys.stderr)
    for pr in problems:
        print(f"[-] {pr}", file=sys.stderr)
    print(f"[*] report: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
