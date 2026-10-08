"""Turn raw findings into ranked leads.

Three steps, all deterministic so the result is reproducible without any AI:

1. Noise clustering: a tag raised hundreds of times (for example TIMESTOMP after a package
   install) becomes one cluster with statistics instead of hundreds of leads.
2. Entity correlation: findings from different tools that mention the same path, user, PID or
   IP address are linked, because independent tools agreeing is a stronger signal.
3. Themes: related tags (for example several logging gaps) are grouped into one question an
   analyst can answer.

Each lead keeps the evidence IDs of the findings behind it, so every statement in a report can
be traced to an exact line in the collected output.
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from .knowledge import GENERIC_ENTITIES, SEVERITY_NAMES, THEMES, describe

CLUSTER_THRESHOLD = 25      # a tag raised more often than this is summarised, not listed
ENTITY_MAX_FANOUT = 30      # entities mentioned by more findings than this are too common to link
MAX_EVIDENCE_PER_LEAD = 25


@dataclass
class Cluster:
    tag: str
    count: int
    category: str
    severity: int
    top_locations: list            # [(directory prefix, count)]
    first_seen: str = ""
    last_seen: str = ""
    densest_window: str = ""       # e.g. "92% within 2026-10-02 15:00-17:00 UTC"
    sample_ids: list = field(default_factory=list)


@dataclass
class Lead:
    id: str
    kind: str                      # "theme" | "correlation" | "finding"
    title: str
    severity: int
    score: float
    tools: list
    tags: list
    evidence: list                 # finding IDs
    question: str = ""
    entity: str = ""

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, "low")


@dataclass
class Analysis:
    leads: list
    clusters: list
    stats: dict


def _prefix(path: str, depth: int = 2) -> str:
    parts = [p for p in path.split("/") if p]
    return "/" + "/".join(parts[:depth]) if parts else "/"


def _parse_ts(ts: str):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def build_cluster(tag: str, items: list) -> Cluster:
    d = describe(tag)
    locs = Counter(_prefix(p) for f in items for p in f.paths[:1])
    times = sorted(t for f in items for t in (_parse_ts(x) for x in f.timestamps[:1]) if t)
    c = Cluster(tag=tag, count=len(items), category=d["category"], severity=d["severity"],
                top_locations=locs.most_common(5),
                sample_ids=[f.id for f in _spread(items, 5)])
    if times:
        c.first_seen, c.last_seen = times[0].strftime("%Y-%m-%dT%H:%MZ"), times[-1].strftime("%Y-%m-%dT%H:%MZ")
        hours = Counter(t.replace(minute=0, second=0) for t in times)
        best = max(hours, key=lambda h: hours[h] + hours.get(h.replace(hour=(h.hour + 1) % 24), 0))
        in_window = sum(1 for t in times if 0 <= (t - best).total_seconds() < 7200)
        share = in_window / len(times)
        if share >= 0.5:
            c.densest_window = f"{share:.0%} within {best:%Y-%m-%d %H:00}+2h UTC"
    return c


def _spread(items: list, n: int) -> list:
    """Pick n items spread across the list so samples are not all from one place."""
    if len(items) <= n:
        return list(items)
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def analyse(findings: list) -> Analysis:
    by_tag = defaultdict(list)
    for f in findings:
        by_tag[f.tag].append(f)

    clusters, kept = [], []
    for tag, items in by_tag.items():
        if len(items) > CLUSTER_THRESHOLD:
            clusters.append(build_cluster(tag, items))
        else:
            kept.extend(items)
    clusters.sort(key=lambda c: (-c.severity, -c.count))
    index = {f.id: f for f in findings}
    used = set()
    leads = []

    # Themes first: they answer the biggest questions.
    present_tags = {f.tag for f in kept}
    for th in THEMES:
        hit = sorted(present_tags & th["tags"])
        if len(hit) < th["min_tags"]:
            continue
        ev = [f for f in kept if f.tag in th["tags"]]
        sev = max(describe(f.tag)["severity"] for f in ev)
        tools = sorted({f.tool for f in ev})
        leads.append(Lead(id=f"T-{th['id']}", kind="theme", title=th["title"], severity=sev,
                          score=sev + 0.5 * (len(tools) - 1) + 0.25 * (len(hit) - 1),
                          tools=tools, tags=hit, evidence=[f.id for f in ev[:MAX_EVIDENCE_PER_LEAD]],
                          question=th["question"]))
        used.update(f.id for f in ev)

    # Cross-tool correlations on shared entities.
    ent_map = defaultdict(list)
    for f in kept:
        for kind, values in (("path", f.paths), ("user", f.users), ("pid", f.pids), ("ip", f.ips)):
            for v in values:
                if v not in GENERIC_ENTITIES[kind]:
                    ent_map[(kind, v)].append(f)
    n = 0
    for (kind, value), items in sorted(ent_map.items(), key=lambda kv: -len(kv[1])):
        tools = sorted({f.tool for f in items})
        tags = sorted({f.tag for f in items})
        if len(items) > ENTITY_MAX_FANOUT or (len(tools) < 2 and len(tags) < 2):
            continue
        if sum(f.id in used for f in items) * 2 >= len(items):
            continue   # mostly explained by a stronger lead already
        sev = max(describe(f.tag)["severity"] for f in items)
        n += 1
        leads.append(Lead(id=f"C-{n}", kind="correlation",
                          title=f"{kind} {value} appears in {len(items)} findings from {', '.join(tools)}",
                          severity=sev, score=sev + 0.75 * (len(tools) - 1) + 0.1 * (len(tags) - 1),
                          tools=tools, tags=tags, evidence=[f.id for f in items[:MAX_EVIDENCE_PER_LEAD]],
                          entity=f"{kind}:{value}"))
        used.update(f.id for f in items)

    # Remaining medium and high single findings.
    for f in kept:
        if f.id in used:
            continue
        d = describe(f.tag)
        if d["severity"] >= 3:
            leads.append(Lead(id=f"F-{f.id}", kind="finding", title=f"{f.tag}: {f.message[:140]}",
                              severity=d["severity"], score=float(d["severity"]), tools=[f.tool],
                              tags=[f.tag], evidence=[f.id]))
            used.add(f.id)

    leads.sort(key=lambda l: (-l.score, l.id))
    sev_counts = Counter(SEVERITY_NAMES[describe(f.tag)["severity"]] for f in findings)
    stats = {
        "findings": len(findings),
        "tools_with_findings": sorted({f.tool for f in findings}),
        "clustered": sum(c.count for c in clusters),
        "unclustered_context": sum(1 for f in kept if f.id not in used),
        "by_severity": dict(sev_counts),
        "leads": len(leads),
    }
    return Analysis(leads=leads, clusters=clusters, stats=stats)


def evidence_for(lead: Lead, index: dict) -> list:
    return [index[i] for i in lead.evidence if i in index]


def location_of(f) -> str:
    return f"{f.file}:{f.line}"
