---
name: rea-attribution-reporting
description: Run REA static forensics, resolve attacker origin IPs via RDAP/ASN, and compile STIX 2.1 + FBI IC3 / CISA incident reports.
---

# REA Forensics, Attribution & Federal Reporting

## Legal Boundary
All attribution and forensics are strictly defensive and passive. Never perform offensive counter-exploitation ("hack-back") against external infrastructure.

## Procedure
1. **Static Artifact Forensics (REA):** Run `python -m artex_antidote.cli rea-analyze <captured_artifact>` (or REA MCP `open_binary` / `analyze_javascript_application`) to extract hardcoded C2 IPs, domains, and signatures **without executing the sample**.
2. **Origin IP & RDAP Enrichment:** Extract the primary client IP and full `X-Forwarded-For` chain, then run `lookup_rdap(ip)` to identify the originating ASN, network block, and country.
3. **Export Federal Evidence Bundle:** Run `reverse-patch ... --export-dir ./evidence_out` (or call `export_federal_bundle`) to generate:
   - `stix_bundle.json`: STIX 2.1 Bundle (`ipv4-addr` + `indicator` objects) for CISA / TAXII sharing.
   - `ic3_cisa_report.md`: Chain-of-custody report ready for **FBI IC3** (`https://www.ic3.gov`) and **CISA** (`https://www.cisa.gov/report`).
