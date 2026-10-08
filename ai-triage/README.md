# nfx-analyze: AI-assisted triage for nix-forensics output

`nfx-analyze` reads the output of `nfx-triage`, groups and correlates the findings, and produces a ranked report an analyst can verify line by line. An AI model can optionally explain each lead, but it never gets the final word: every statement it makes must cite evidence that exists in the collection, or it is removed.

```
nfx-triage output (hundreds to tens of thousands of [!] lines)
        │
        ▼
1. Parse        every [!] [TAG] line → finding with an evidence ID (tool:line)
2. Cluster      high-volume tags → one summary with location and time-window statistics
3. Correlate    shared paths, users, PIDs and IPs across tools; themed groups of related tags
4. Rank         severity, number of independent tools agreeing, breadth of evidence
5. Explain      optional AI: likely benign vs concerning reading, next checks, all cited
6. Verify       citations checked against what was sent; anything ungrounded is dropped
        │
        ▼
analysis.md (+ optional JSON)
```

Steps 1 to 4 are deterministic and need no network, so the tool is useful fully offline.

## Quick start

```bash
cd the-ai-forensicator
sudo nix-forensics/bin/nfx-triage -d case-42 --case 42        # collect on the suspect host
ai-triage/bin/nfx-analyze case-42                             # offline report → case-42/analysis.md
```

With AI:

```bash
# Claude via the Anthropic API, with identifiers masked before sending
export ANTHROPIC_API_KEY=...
ai-triage/bin/nfx-analyze case-42 --ai anthropic --redact

# A local model (Ollama, LM Studio, vLLM): evidence never leaves your machine
ai-triage/bin/nfx-analyze case-42 --ai openai --base-url http://localhost:11434/v1 --model llama3.1

# See exactly what would be sent, without sending anything
ai-triage/bin/nfx-analyze case-42 --redact --dry-run
```

Input can be a triage directory, the `.tar.gz` that `nfx-triage` produces, or a single tool's output file. Requires Python 3.8+ and nothing else: no packages, no SDK.

## What a real run looks like

On a cloud build machine, `nfx-triage --quick` raised **36,041** findings. `nfx-analyze` reduced them to **6 leads and 2 noise clusters**:

- 35,896 `TIMESTOMP` flags became one cluster: almost all under `/usr`, with 96% inside a single two-hour window. That pattern matches the image being built (archives keep old modification times), not someone editing timestamps by hand.
- Separate "log is empty" findings from `nfx-auth` and `nfx-logs` became one question: were logs never configured, or cleared?
- Passwordless sudo and an interactive shell on the same service account were linked into one lead.

## Guardrails

| Risk | How it is handled |
| --- | --- |
| AI invents a file, user or event | Every lead must cite evidence IDs that were sent. Unknown IDs are removed, leads without valid evidence are dropped, and both are listed in the report. |
| Sensitive data leaves the host | `--redact` masks the hostname, non-system usernames, IP addresses and emails with stable tokens (`USER_1`, `IP_2`); real values are restored only in the local report. `--dry-run` shows the exact request. Or use a local model. |
| Overconfident conclusions | The model must give a benign explanation for each lead and may answer "insufficient evidence". The report states that leads are starting points, not verdicts. |
| AI unavailable or failing | The report falls back to the offline analysis and says why. |
| Huge collections | Mass findings are clustered and the request is capped at about 60k characters. |

## Output

`analysis.md` contains the verdict and summary, the ranked leads (each with severity, tools, MITRE ATT&CK techniques, the AI's assessment if used, and the exact source lines), noise clusters, collection gaps, and the AI output checks. `--json FILE` writes the same data in machine-readable form for a SOAR or case-management system.

## Tests

```bash
python3 -m unittest discover -s ai-triage/tests
```

## Status

Version 0.1, an early release. Planned next: JSON output from every `nfx` tool (instead of parsing text), a baseline mode that compares a host against a known-good one, and HTML reports.
