# Artex Antidote — Operator Skill Book

This Skill Book provides step-by-step operational playbooks for running the **2:1 Autonomous Defender Swarm**, synthesizing on-the-fly virtual patches, performing **REA static forensics**, tracing attacker origin IPs, and exporting **STIX 2.1 + FBI IC3 / CISA** incident reports.

## Available Skills
1. **[Swarm Defense & On-the-Fly Patching](swarm-defense/SKILL.md)** — How to operate the 2:1 defender swarm, deploy Coraza SecLang virtual patches, and exploit Artex's `429`/`503` backoff and budget limits.
2. **[REA Forensics, Attribution & Federal Reporting](rea-attribution-reporting/SKILL.md)** — How to run REA statically on captured artifacts, resolve attacker origin IPs via RDAP/ASN, and generate STIX 2.1 + FBI IC3 / CISA evidence packages.

## Quick Commands
```bash
# 1. Reverse-engineer an inbound probe, dispatch 2:1 swarm, synthesize Coraza + Python patches, and export IC3/STIX bundle
python -m artex_antidote.cli reverse-patch --ip 203.0.113.45 --path "/.env" --ua "nuclei" --export-dir ./evidence_out

# 2. Run REA static analysis on a captured JS/ASAR/artifact (never executes target)
python -m artex_antidote.cli rea-analyze /path/to/captured/artifact

# 3. Audit local host for unauthorized Artex listeners (:8787, :8788)
python -m artex_antidote.cli audit-host
```
