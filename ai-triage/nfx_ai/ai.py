"""AI explanation layer: rank and explain leads, with every claim tied to evidence IDs.

The model never sees the raw host. It receives the leads and noise clusters produced by
correlate.py (optionally redacted) and must answer in JSON. Before anything reaches the report,
validate() checks that each cited evidence ID was actually sent; claims citing unknown IDs are
removed and listed, so a hallucinated "fact" cannot slip into the findings.

Providers (standard library only, no SDK needed):
  anthropic  Claude via the Anthropic Messages API (ANTHROPIC_API_KEY)
  openai     any OpenAI-compatible endpoint, including local models served by Ollama or
             LM Studio (--base-url http://localhost:11434/v1), so evidence never leaves the host
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from .correlate import Analysis, evidence_for
from .knowledge import SEVERITY_NAMES, describe
from .redact import Redactor

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "llama3.1"}
MAX_PAYLOAD_CHARS = 60_000

SYSTEM_PROMPT = """You are a senior incident responder reviewing live-response output from the \
nfx toolkit (Linux and macOS). You receive leads that a deterministic engine has already \
grouped, plus clusters of high-volume findings. Your job is to help the analyst decide what to \
look at first and why.

Rules:
1. Use only the evidence provided. Every lead you discuss must cite evidence IDs exactly as \
given (for example "ssh:18"). Never invent IDs, file paths, users, processes or events.
2. For each lead, give the most likely benign explanation as well as the concerning one. Many \
findings are normal on build machines, containers and developer laptops.
3. Say "insufficient evidence" when the data cannot support a conclusion. Do not overstate.
4. Next steps must be checks an analyst can run to confirm or rule out the concern. Do not \
give instructions for attacking or evading anything.
5. Use the host context (OS, whether it looks like a container or build image) when judging.
6. Plain, precise English. No marketing language.

Reply with one JSON object and nothing else:
{
  "verdict": "no_clear_compromise" | "suspicious_activity" | "likely_compromise" | "insufficient_evidence",
  "summary": "3-5 sentences for an incident lead",
  "leads": [
    {"lead_id": "<id from input>", "assessment": "likely_benign" | "needs_review" | "suspicious",
     "confidence": "low" | "medium" | "high", "explanation": "...",
     "benign_explanation": "...", "next_steps": ["..."], "evidence": ["<evidence ids>"]}
  ],
  "noise": [{"tag": "<cluster tag>", "explanation": "...", "evidence": ["<sample ids>"]}],
  "gaps": ["what is missing from the collection that limits the conclusion"]
}"""


def build_payload(triage, analysis: Analysis, redactor: Redactor, max_leads: int = 15) -> dict:
    index = {f.id: f for f in triage.findings}
    leads = []
    for lead in analysis.leads[:max_leads]:
        items = evidence_for(lead, index)
        leads.append({
            "lead_id": lead.id, "kind": lead.kind, "title": redactor.text(lead.title),
            "severity": lead.severity_name, "tools": lead.tools, "tags": lead.tags,
            "attack": sorted({a for f in items for a in describe(f.tag)["attack"]}),
            "question": lead.question,
            "evidence": [{"id": f.id, "tool": f.tool, "tag": f.tag, "text": redactor.text(f.message)} for f in items],
        })
    clusters = []
    for c in analysis.clusters:
        samples = [index[i] for i in c.sample_ids if i in index]
        clusters.append({
            "tag": c.tag, "count": c.count, "category": c.category,
            "top_locations": [[redactor.text(p), n] for p, n in c.top_locations],
            "first_seen": c.first_seen, "last_seen": c.last_seen, "densest_window": c.densest_window,
            "samples": [{"id": f.id, "text": redactor.text(f.message)} for f in samples],
        })
    payload = {
        "host": {"os": triage.os, "collected_utc": triage.collected_utc, "collected_as": triage.collected_as,
                 "tools_run": triage.tools_run, "collection_complete": triage.complete,
                 "context": [redactor.text(x) for x in host_context(triage)]},
        "stats": analysis.stats,
        "leads": leads,
        "clusters": clusters,
        "notes": triage.notes,
    }
    # Keep the request bounded: drop the lowest-ranked leads until it fits.
    while len(json.dumps(payload)) > MAX_PAYLOAD_CHARS and len(payload["leads"]) > 3:
        payload["leads"].pop()
    return payload


def host_context(triage) -> list:
    """Short, factual lines from sysinfo/containers output that help judge what is normal."""
    out = []
    for name in ("sysinfo.txt", "containers.txt"):
        path = os.path.join(triage.directory, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                l = line.strip()
                if re.match(r"^(os|kernel|virtualization|container|in container|uptime|boot)\b", l, re.I) or \
                   re.search(r"am I in a container|running inside|docker|kubernetes|virtuali[sz]", l, re.I):
                    out.append(l[:200])
    return out[:15]


def call_model(payload: dict, provider: str, model: str | None = None, base_url: str | None = None,
               timeout: int = 180) -> str:
    model = model or DEFAULT_MODELS.get(provider, "")
    user = "Live-response leads to review:\n" + json.dumps(payload, indent=1)
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        url = (base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
        body = {"model": model, "max_tokens": 4096, "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user}]}
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        data = _post(url, body, headers, timeout)
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    if provider == "openai":
        url = (base_url or "http://localhost:11434/v1").rstrip("/") + "/chat/completions"
        headers = {"content-type": "application/json"}
        if os.environ.get("OPENAI_API_KEY"):
            headers["authorization"] = "Bearer " + os.environ["OPENAI_API_KEY"]
        body = {"model": model, "temperature": 0.1,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]}
        data = _post(url, body, headers, timeout)
        return data["choices"][0]["message"]["content"]
    raise ValueError(f"unknown provider: {provider}")


def _post(url: str, body: dict, headers: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{url} returned HTTP {e.code}: {e.read().decode(errors='replace')[:300]}") from None


def parse_json(text: str) -> dict:
    """Accept a bare JSON object, or one wrapped in a ```json fence."""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("model reply contained no JSON object")
    return json.loads(text[start:end + 1])


VERDICTS = {"no_clear_compromise", "suspicious_activity", "likely_compromise", "insufficient_evidence"}
ASSESSMENTS = {"likely_benign", "needs_review", "suspicious"}


def validate(reply: dict, payload: dict) -> tuple[dict, list]:
    """Keep only claims grounded in evidence that was sent. Returns (clean_reply, problems)."""
    sent_ids = {e["id"] for l in payload["leads"] for e in l["evidence"]}
    sent_ids |= {s["id"] for c in payload["clusters"] for s in c["samples"]}
    lead_ids = {l["lead_id"] for l in payload["leads"]}
    cluster_tags = {c["tag"] for c in payload["clusters"]}
    problems, clean_leads, clean_noise = [], [], []

    for l in reply.get("leads", []) or []:
        lid = l.get("lead_id")
        cited = [i for i in (l.get("evidence") or []) if isinstance(i, str)]
        unknown = [i for i in cited if i not in sent_ids]
        if lid not in lead_ids:
            problems.append(f"dropped a lead with unknown id {lid!r}")
            continue
        if unknown:
            problems.append(f"lead {lid}: removed citations that were never provided: {', '.join(unknown)}")
        cited = [i for i in cited if i in sent_ids]
        if not cited:
            problems.append(f"dropped lead {lid}: no valid evidence cited")
            continue
        clean_leads.append({
            "lead_id": lid,
            "assessment": l.get("assessment") if l.get("assessment") in ASSESSMENTS else "needs_review",
            "confidence": l.get("confidence") if l.get("confidence") in ("low", "medium", "high") else "low",
            "explanation": str(l.get("explanation", "")).strip(),
            "benign_explanation": str(l.get("benign_explanation", "")).strip(),
            "next_steps": [str(s) for s in (l.get("next_steps") or [])][:6],
            "evidence": cited,
        })
    for n in reply.get("noise", []) or []:
        if n.get("tag") not in cluster_tags:
            problems.append(f"dropped noise note for unknown cluster {n.get('tag')!r}")
            continue
        cited = [i for i in (n.get("evidence") or []) if i in sent_ids]
        clean_noise.append({"tag": n["tag"], "explanation": str(n.get("explanation", "")).strip(), "evidence": cited})

    verdict = reply.get("verdict") if reply.get("verdict") in VERDICTS else "insufficient_evidence"
    return ({"verdict": verdict, "summary": str(reply.get("summary", "")).strip(), "leads": clean_leads,
             "noise": clean_noise, "gaps": [str(g) for g in (reply.get("gaps") or [])][:8]}, problems)


def restore(reply: dict, redactor: Redactor) -> dict:
    """Put real names back into the AI's text for the local report."""
    r = redactor.restore
    reply["summary"] = r(reply["summary"])
    reply["gaps"] = [r(g) for g in reply["gaps"]]
    for l in reply["leads"]:
        for k in ("explanation", "benign_explanation"):
            l[k] = r(l[k])
        l["next_steps"] = [r(s) for s in l["next_steps"]]
    for n in reply["noise"]:
        n["explanation"] = r(n["explanation"])
    return reply
