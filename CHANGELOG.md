# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

First public release. Root Justice (Artex Antidote) is a strictly-defensive,
standard-library-only blue-team package.

### Added

- **Edge shield / detection** — corroborated, multi-signal scoring of autonomous
  scanner and LLM-driven probing, with fail-open behavior so an internal error
  never takes down the protected app. A single spoofable signal (e.g. a
  user-agent) never blocks legitimate traffic.
- **2:1 defensive swarm** — inline containment paired with origin attribution.
- **Origin attribution** — resolved from the unspoofable TCP peer inward,
  honoring a configured trusted-proxy list, with per-hop confidence; low
  (spoofable) confidence origins are held back from any federal bundle.
- **Containment responses** — tarpit, decoy, and a warning banner served only on
  the attacker's own connection (no hack-back).
- **Hash-chained evidence ledger** — append-only, SHA-256 chained records with a
  `verify-evidence` integrity check.
- **Signing** — detached signatures over evidence artifacts for chain-of-custody.
- **Federal reporting** — STIX 2.1 export and FBI IC3 / CISA incident-package
  preparation behind a human review gate (the tool never transmits to
  authorities).
- **TAXII / threat-intel** feeds, domain watch, and fingerprinting helpers.
- **Hardening, posture, health, and host/firmware audit** utilities.
- **Durable registry / retention** for persisted state and evidence lifecycle.
- **CLI** (`root-justice`) and a deployable service (systemd / Windows) that
  starts log-only, bound to localhost, and runs unprivileged.
- **Coverage dashboard** and credential-policy checks.

### Security

- Fail-open design throughout: any internal error allows traffic.
- Strictly defensive scope; no outbound action against third parties.

## Known limitations / tech debt

The following audit items are acknowledged and **deferred** to a later release:

- async -> sync swarm refactor
- `attribution.py` god-module split
- per-record keyed/HMAC chain + sequence numbers
- `DurableRegistry` WAL / pooling
- real RFC-3161 TSA (trusted timestamping)
- structured logging
- CLI dispatch-dict refactor
- `_netutil` deduplication

[0.1.0]: https://github.com/qanvass/root-justice/releases/tag/v0.1.0
