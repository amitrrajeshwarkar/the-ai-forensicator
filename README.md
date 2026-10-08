# The AI Forensicator

**Fast, explainable live response for Linux and macOS, built to feed AI-assisted triage.**

[![smoke-test](https://github.com/amitrrajeshwarkar/the-ai-forensicator/actions/workflows/smoke.yml/badge.svg)](https://github.com/amitrrajeshwarkar/the-ai-forensicator/actions/workflows/smoke.yml)
![bash 3.2+](https://img.shields.io/badge/bash-3.2%2B-informational)
![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-informational)
![license](https://img.shields.io/badge/license-MIT-green)

Incident responders on Linux and macOS often lack what Windows investigators take for granted: small, trustworthy tools that each answer one question about one artifact. The AI Forensicator starts there. Its first component, **nix-forensics (nfx)**, is a set of 22 read-only command-line tools that collect and flag evidence in a consistent, machine-readable format. That consistency is what makes the next step possible: handing structured findings to an AI model for triage, without handing it the decision.

## What is in this repository

| Component | Status | What it does |
| --- | --- | --- |
| [`nix-forensics/`](nix-forensics/) | Available | 22 `nfx-*` live-response tools: persistence, processes, network, SSH, shell history, timeline, SUID, kernel modules, containers, webshells, IOC sweeps, macOS artifacts, and a one-command triage collector |
| [`ai-triage/`](ai-triage/) | Early release (v0.1) | `nfx-analyze`: clusters noise, correlates findings across tools, and (optionally) uses Claude or a local model to explain each lead, with every claim checked against the evidence |

## Quick start

```bash
git clone https://github.com/amitrrajeshwarkar/the-ai-forensicator
cd the-ai-forensicator/nix-forensics
sudo bin/nfx-triage --case demo-001          # full collection, packaged with a sha256 manifest
sudo bin/nfx-persistence --since 7d          # or ask a single question
tests/smoke.sh                               # verify every tool on this host
../ai-triage/bin/nfx-analyze nfx-triage-*/   # ranked, explained report from a triage run
```

Pure bash 3.2+ with no dependencies, so the folder can be copied to a suspect host and run immediately. Every tool is read-only on the host. Full documentation: [nix-forensics/README.md](nix-forensics/README.md). New to Linux forensics? Start with the [beginner's guide](nix-forensics/docs/LINUX-FORENSICS-GUIDE.md).

## Design principles

- **One artifact, one tool.** Each script is short enough to read and explain, which matters when findings end up in a report or in court.
- **Flags are leads, not verdicts.** Tools print `[!] [TAG]` lines for an analyst to review. The AI layer (`nfx-analyze`) follows the same rule: it ranks and explains, and every claim points back to the raw line that supports it.
- **Mapped to MITRE ATT&CK.** Each tool lists the techniques its checks cover.
- **Tested on every change.** CI runs the full smoke test on Ubuntu and macOS.

## Roadmap

- [x] nix-forensics: 22 live-response tools for Linux and macOS
- [x] CI smoke tests on Ubuntu and macOS
- [ ] Structured JSON output for every tool
- [x] AI triage layer: ranked findings with citations to the source evidence (`nfx-analyze` v0.1)
- [ ] Worked investigation examples built in a lab environment

## Author

**Amit Rajeshwarkar**, incident responder and detection engineer. GCIH, GCFE, GIAC Advisory Board.
[LinkedIn](https://www.linkedin.com/in/amit-rajeshwarkar)

## Responsible use

Run these tools only on systems you own or are authorised to investigate. All examples and test data in this repository come from lab systems; no employer or client data is included.

## License

[MIT](LICENSE)
