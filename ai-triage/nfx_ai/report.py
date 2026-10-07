"""Write the analysis as a Markdown report and a machine-readable JSON file."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .correlate import evidence_for, location_of
from .knowledge import SEVERITY_NAMES, describe

VERDICT_TEXT = {
    "no_clear_compromise": "No clear sign of compromise in the collected data",
    "suspicious_activity": "Suspicious activity that needs review",
    "likely_compromise": "Likely compromise",
    "insufficient_evidence": "Insufficient evidence to conclude",
}
ASSESS_TEXT = {"likely_benign": "Likely benign", "needs_review": "Needs review", "suspicious": "Suspicious"}


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|")


def to_markdown(triage, analysis, ai: dict | None, problems: list, meta: dict) -> str:
    index = {f.id: f for f in triage.findings}
    ai_leads = {l["lead_id"]: l for l in (ai or {}).get("leads", [])}
    ai_noise = {n["tag"]: n for n in (ai or {}).get("noise", [])}
    s = analysis.stats
    out = [f"# nfx triage analysis: {triage.host or 'unknown host'}", ""]
    out += [
        "| | |", "| --- | --- |",
        f"| Host | {triage.host or 'unknown'} ({triage.os or 'unknown OS'}) |",
        f"| Collected | {triage.collected_utc or 'unknown'} as `{triage.collected_as or '?'}` |",
        f"| Collection | {'complete' if triage.complete else '**incomplete**'}, {len(triage.tools_run)} tool outputs |",
        f"| Findings | {s['findings']:,} raw, {s['clustered']:,} grouped into {len(analysis.clusters)} noise clusters, "
        f"{s['leads']} leads |",
        f"| Analysis | {meta['engine']} |",
        f"| Generated | {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} |", "",
    ]

    out += ["## Verdict", ""]
    if ai:
        out += [f"**{VERDICT_TEXT.get(ai['verdict'], ai['verdict'])}**", "", ai["summary"], ""]
    else:
        high = sum(1 for l in analysis.leads if l.severity >= 4)
        out += [f"Offline analysis (no AI): {len(analysis.leads)} leads, {high} rated high. "
                "Review the leads below in order; each one cites the exact lines it is based on.", ""]
    out += ["> Leads are starting points for an analyst, not conclusions. "
            "Confirm every lead against the source lines before acting.", ""]

    out += ["## Leads", ""]
    if not analysis.leads:
        out += ["No leads above context level.", ""]
    for n, lead in enumerate(analysis.leads, 1):
        items = evidence_for(lead, index)
        attack = sorted({a for f in items for a in describe(f.tag)["attack"]})
        a = ai_leads.get(lead.id)
        badge = f" · {ASSESS_TEXT[a['assessment']]} ({a['confidence']} confidence)" if a else ""
        out += [f"### {n}. {lead.title}", "",
                f"**{lead.severity_name.capitalize()}**{badge} · tools: {', '.join(lead.tools)}"
                + (f" · ATT&CK: {', '.join(attack)}" if attack else "") + f" · `{lead.id}`", ""]
        if a:
            if a["explanation"]:
                out += [a["explanation"], ""]
            if a["benign_explanation"]:
                out += [f"*Possible benign explanation:* {a['benign_explanation']}", ""]
            if a["next_steps"]:
                out += ["*Next steps:*", ""] + [f"- {x}" for x in a["next_steps"]] + [""]
        elif lead.question:
            out += [f"*Question to answer:* {lead.question}", ""]
        out += ["Evidence:", "", "```"]
        out += [f"{location_of(f):<22} {f.raw}" for f in items]
        out += ["```", ""]

    if analysis.clusters:
        out += ["## Noise clusters", "",
                "High-volume tags are summarised here instead of listed. Volume alone is not suspicious; "
                "a tight time window often points to a package install, image build or restore.", "",
                "| Tag | Count | Where | When | Note |", "| --- | ---: | --- | --- | --- |"]
        for c in analysis.clusters:
            where = ", ".join(f"{p} ({n:,})" for p, n in c.top_locations[:3])
            when = c.densest_window or (f"{c.first_seen} to {c.last_seen}" if c.first_seen else "")
            note = ai_noise.get(c.tag, {}).get("explanation", "")
            out.append(f"| {c.tag} | {c.count:,} | {_md_escape(where)} | {_md_escape(when)} | {_md_escape(note)} |")
        out += [""]
        out += ["Sample lines:", "", "```"]
        for c in analysis.clusters:
            for i in c.sample_ids[:3]:
                if i in index:
                    out.append(f"{location_of(index[i]):<22} {index[i].raw[:200]}")
        out += ["```", ""]

    gaps = list(triage.notes) + list((ai or {}).get("gaps", []))
    if gaps:
        out += ["## Collection gaps", ""] + [f"- {g}" for g in gaps] + [""]

    if ai is not None or problems:
        out += ["## AI output checks", ""]
        if ai is None:
            out += ["The AI step did not complete, so this report contains the offline analysis only:", ""]
            out += [f"- {p}" for p in problems] + [""]
        elif problems:
            out += ["The AI reply was checked against the evidence it was given. These parts were removed:", ""]
            out += [f"- {p}" for p in problems] + [""]
        else:
            out += ["Every AI statement in this report cites evidence IDs that exist in the collection.", ""]

    out += ["---", "",
            f"Generated by nfx-analyze ({meta['engine']}). Evidence IDs are `tool:line` in the triage "
            f"directory `{triage.directory}`.", ""]
    return "\n".join(out)


def to_json(triage, analysis, ai, problems, meta) -> str:
    index = {f.id: f for f in triage.findings}
    doc = {
        "meta": meta,
        "host": {"name": triage.host, "os": triage.os, "collected_utc": triage.collected_utc,
                 "collected_as": triage.collected_as, "complete": triage.complete, "tools_run": triage.tools_run},
        "stats": analysis.stats,
        "leads": [{
            "id": l.id, "kind": l.kind, "title": l.title, "severity": l.severity_name, "score": round(l.score, 2),
            "tools": l.tools, "tags": l.tags, "question": l.question,
            "evidence": [index[i].to_dict() for i in l.evidence if i in index],
        } for l in analysis.leads],
        "clusters": [c.__dict__ for c in analysis.clusters],
        "ai": ai, "ai_problems": problems, "notes": triage.notes,
    }
    return json.dumps(doc, indent=2, default=str)
