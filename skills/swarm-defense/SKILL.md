---
name: artex-swarm-defense
description: Operate the 2:1 Autonomous Defender Swarm, Coraza virtual patching, and 429/tarpit countermeasures against Artex-style scanners.
---

# Swarm Defense & On-the-Fly Virtual Patching

## When to Use
Use this skill when an Artex-style autonomous scanner probes your perimeter or APIs.

## Procedure
1. **Verify 2:1 Swarm Ratio:** Every unique flagged attacker stream (`artex-stream-<hash>`) must be paired with:
   - `contain-<stream_id>`: applies virtual patches / IP blocks and returns `429`/`503` or canary tarpit responses.
   - `attrib-<stream_id>`: preserves chain-of-custody telemetry (UTC timestamp, `X-Forwarded-For` chain, User-Agent, SHA-256 body hash).
2. **Apply Synthesized Coraza SecLang Rule:** Take the `coraza_seclang_rule` emitted by `reverse_engineer_request` and load it into your Coraza/CrowdSec AppSec edge proxy.
3. **Exploit Artex's Noise Governor:** Return `HTTP 429` or `503` with `Retry-After` on non-canary probes to trigger Artex's `noise_profile.go` backoff, and route canary hits (`/.env`, `/.git/config`, `/wp-admin`) to slow tarpits to exhaust its `50,000`-token / `10`-turn worker budget.
4. **Local Host Containment:** Run `python -m artex_antidote.cli audit-host` to verify `:8787` and `:8788` are not listening locally.
