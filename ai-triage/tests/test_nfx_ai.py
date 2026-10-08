"""Unit tests for the nfx AI triage layer. Run: python3 -m unittest discover -s ai-triage/tests"""
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nfx_ai.ai import build_payload, parse_json, restore, validate  # noqa: E402
from nfx_ai.correlate import CLUSTER_THRESHOLD, analyse  # noqa: E402
from nfx_ai.knowledge import describe  # noqa: E402
from nfx_ai.parser import extract_entities, load_triage  # noqa: E402
from nfx_ai.redact import Redactor  # noqa: E402
from nfx_ai.__main__ import main  # noqa: E402

HEADER = "nfx-{t} v1.0.0 | host=lab-web01 | os=linux | user=root | utc=2026-10-08T05:00:00Z\n"

FIXTURE = {
    "auth": ["[!] [NO-AUTH-LOGS] no authentication log lines found - logs missing, unreadable or cleared?",
             "[!] [EMPTY-LOG] /var/log/wtmp is zero bytes - possibly cleared (T1070.002)"],
    "logs": ["[!] [LOG-EMPTY] /var/log/wtmp is 0 bytes"],
    "users": ["[!] [SUDO-NOPASSWD] /etc/sudoers:12:deploy ALL=(ALL) NOPASSWD: ALL",
              "[!] [SYSTEM-SHELL] system account with an interactive shell: deploy uid=998 shell=/bin/bash"],
    "persistence": ["[!] [RECENT] /etc/cron.d/backup-job modified within 7d"],
    "packages": ["[!] [ORPHAN-BIN] binary in a system path not owned by any package: /etc/cron.d/backup-job"],
    "network": ["[!] [HOSTS-ENTRY] non-loopback /etc/hosts entry (redirect/blocking?): 10.20.30.40 updates.example.com"],
    "recent": [f"[!] [TIMESTOMP] mtime 2026-10-01T10:{i % 60:02d}:00Z < birth 2026-10-01T11:00:00Z: /usr/lib/pkg/file{i}.py"
               for i in range(CLUSTER_THRESHOLD + 10)],
}


def make_triage(root, manifest=True):
    os.makedirs(root, exist_ok=True)
    for tool, lines in FIXTURE.items():
        with open(os.path.join(root, f"{tool}.txt"), "w") as fh:
            fh.write(HEADER.format(t=tool))
            fh.write("==== section ====\n")
            fh.write("\n".join(lines) + "\n")
    if manifest:
        with open(os.path.join(root, "manifest.csv"), "w") as fh:
            fh.write("sha256,bytes,file\n")
    return root


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = make_triage(os.path.join(self.tmp, "nfx-triage-lab"))
        self.t = load_triage(self.dir)
        self.a = analyse(self.t.findings)

    def tearDown(self):
        shutil.rmtree(self.tmp)


class ParserTests(Base):
    def test_header_and_ids(self):
        self.assertEqual(self.t.host, "lab-web01")
        self.assertTrue(self.t.complete)
        ids = {f.id for f in self.t.findings}
        self.assertIn("auth:3", ids)          # header line 1, section line 2, first flag line 3
        self.assertEqual(len(self.t.findings), sum(len(v) for v in FIXTURE.values()))

    def test_entities(self):
        e = extract_entities("/etc/sudoers:12:deploy ALL=(ALL) NOPASSWD: ALL")
        self.assertEqual(e["users"], ["deploy"])
        self.assertEqual(e["paths"], ["/etc/sudoers"])
        e = extract_entities("https_proxy=http://127.0.0.1:3128")
        self.assertEqual(e["paths"], [])
        self.assertEqual(e["ips"], ["127.0.0.1"])

    def test_incomplete_collection_is_reported(self):
        d = make_triage(os.path.join(self.tmp, "partial"), manifest=False)
        t = load_triage(d)
        self.assertFalse(t.complete)
        self.assertTrue(t.notes)


class CorrelationTests(Base):
    def test_mass_tag_becomes_cluster(self):
        tags = [c.tag for c in self.a.clusters]
        self.assertEqual(tags, ["TIMESTOMP"])
        c = self.a.clusters[0]
        self.assertEqual(c.count, CLUSTER_THRESHOLD + 10)
        self.assertEqual(c.top_locations[0][0], "/usr/lib")
        self.assertTrue(c.densest_window.startswith("100%"))
        self.assertFalse(any("TIMESTOMP" in l.tags for l in self.a.leads))

    def test_log_gap_theme_spans_tools(self):
        lead = next(l for l in self.a.leads if l.id == "T-log-gap")
        self.assertEqual(lead.tools, ["auth", "logs"])
        self.assertEqual(set(lead.tags), {"NO-AUTH-LOGS", "EMPTY-LOG", "LOG-EMPTY"})

    def test_shared_path_links_tools(self):
        lead = next(l for l in self.a.leads if l.entity == "path:/etc/cron.d/backup-job")
        self.assertEqual(lead.tools, ["packages", "persistence"])

    def test_every_lead_cites_real_findings(self):
        ids = {f.id for f in self.t.findings}
        for l in self.a.leads:
            self.assertTrue(l.evidence)
            self.assertTrue(set(l.evidence) <= ids, l.id)

    def test_unknown_tag_has_safe_default(self):
        self.assertEqual(describe("SOMETHING-NEW")["severity"], 2)


class RedactionTests(Base):
    def test_round_trip(self):
        r = Redactor(host="lab-web01", users={"deploy", "root"})
        s = "deploy on lab-web01 reached 10.20.30.40 and 8.8.8.8 from 127.0.0.1; root ok"
        red = r.text(s)
        for secret in ("deploy", "lab-web01", "10.20.30.40", "8.8.8.8"):
            self.assertNotIn(secret, red)
        self.assertIn("127.0.0.1", red)
        self.assertIn("root", red)
        self.assertEqual(r.restore(red), s)

    def test_payload_is_redacted(self):
        r = Redactor(host=self.t.host, users={u for f in self.t.findings for u in f.users})
        p = json.dumps(build_payload(self.t, self.a, r))
        self.assertNotIn("deploy", p)
        self.assertNotIn("10.20.30.40", p)

    def test_disabled_redactor_is_identity(self):
        r = Redactor(host="lab-web01", users={"deploy"}, enabled=False)
        self.assertEqual(r.text("deploy@lab-web01"), "deploy@lab-web01")


class ValidationTests(Base):
    def setUp(self):
        super().setUp()
        self.r = Redactor(host=self.t.host, users={"deploy"})
        self.payload = build_payload(self.t, self.a, self.r)

    def test_invented_citations_and_leads_are_removed(self):
        real = self.payload["leads"][0]
        reply = {"verdict": "made_up", "summary": "x", "leads": [
            {"lead_id": real["lead_id"], "assessment": "suspicious", "confidence": "high",
             "explanation": "e", "evidence": [real["evidence"][0]["id"], "auth:9999"]},
            {"lead_id": "NOPE", "evidence": [real["evidence"][0]["id"]]},
            {"lead_id": real["lead_id"], "evidence": ["ghost:1"]},
        ], "noise": [{"tag": "NOT-A-CLUSTER", "explanation": "x"}]}
        clean, problems = validate(reply, self.payload)
        self.assertEqual(clean["verdict"], "insufficient_evidence")
        self.assertEqual(len(clean["leads"]), 1)
        self.assertEqual(clean["leads"][0]["evidence"], [real["evidence"][0]["id"]])
        # bad citation, unknown lead, ghost-only citation (2 notes: removed + dropped), unknown cluster
        self.assertEqual(len(problems), 5)

    def test_parse_fenced_json_and_restore(self):
        raw = 'Here you go:\n```json\n{"verdict":"no_clear_compromise","summary":"USER_1 is fine","leads":[],"noise":[],"gaps":[]}\n```'
        clean, _ = validate(parse_json(raw), self.payload)
        self.assertEqual(restore(clean, self.r)["summary"], "deploy is fine")


class CliTests(Base):
    def test_offline_report_and_json(self):
        out, js = os.path.join(self.tmp, "r.md"), os.path.join(self.tmp, "r.json")
        self.assertEqual(main([self.dir, "-o", out, "--json", js]), 0)
        md = open(out).read()
        self.assertIn("Logging gap", md)
        self.assertIn("auth.txt:3", md)
        self.assertIn("TIMESTOMP", md)
        doc = json.load(open(js))
        self.assertGreaterEqual(len(doc["leads"]), 2)
        self.assertIsNone(doc["ai"])

    def test_tarball_input(self):
        tgz = os.path.join(self.tmp, "case.tar.gz")
        with tarfile.open(tgz, "w:gz") as tf:
            tf.add(self.dir, arcname="nfx-triage-lab")
        out = os.path.join(self.tmp, "t.md")
        self.assertEqual(main([tgz, "-o", out]), 0)
        self.assertIn("lab-web01", open(out).read())

    def test_ai_failure_falls_back_to_offline(self):
        out = os.path.join(self.tmp, "f.md")
        env = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            self.assertEqual(main([self.dir, "-o", out, "--ai", "anthropic"]), 0)
        finally:
            if env:
                os.environ["ANTHROPIC_API_KEY"] = env
        md = open(out).read()
        self.assertIn("offline fallback", md)
        self.assertIn("ANTHROPIC_API_KEY is not set", md)


if __name__ == "__main__":
    unittest.main()
