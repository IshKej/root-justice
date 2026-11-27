<p align="center">
  <img src="assets/root-justice-logo.png" alt="Root Justice" width="320">
</p>

<h1 align="center">Root Justice</h1>

<p align="center">
  <b>Defend your servers against AI-driven hackers — detect, contain, attribute, and build the evidence file.</b>
</p>

<p align="center">
  <a href="https://github.com/qanvass/root-justice/actions/workflows/ci.yml"><img src="https://github.com/qanvass/root-justice/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg" alt="Standard library only">
  <img src="https://img.shields.io/badge/tests-448%20passing-brightgreen.svg" alt="448 tests passing">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome">
  <img src="https://img.shields.io/badge/scope-strictly%20defensive-informational.svg" alt="Strictly defensive">
</p>

> **Root Justice** is an open-source, strictly-defensive blue-team edge shield and
> incident-evidence toolkit. It detects autonomous scanners and **LLM / AI-agent-driven
> attacks** (nuclei, sqlmap, ffuf, bbot, and AI "hacking agents"), contains them inline
> with virtual patches, tarpits and decoys, attributes the true origin (RDAP + ASN, no
> spoofable headers), and assembles a tamper-evident, **STIX 2.1 / FBI IC3 / CISA**-ready
> evidence package for a human to review. Zero hack-back. Stdlib-only. Runs anywhere Python does.

A **strictly defensive** blue-team edge shield: it detects autonomous scanner /
LLM-driven probing (e.g. Artex-style tooling), and on detection it contains the
source inline and records attribution evidence in a **tamper-evident
(hash-chained)** ledger. It can then prepare **FBI IC3 / CISA** evidence packages
for a human to review and submit.

### Naming

| Layer | Name |
| --- | --- |
| Product | **Root Justice** |
| Python package | `artex_antidote` |
| CLI binary / service | `root-justice` |

> **Legal boundary.** Everything here is defensive and operates only on
> infrastructure you own. There is **no hack-back**: the warning notice is served
> in the response to the attacker's *own* request, never by reaching out to their
> address. Evidence is prepared for authorities by a human reviewer — the tool
> never transmits anything to the FBI/CISA on its own.
>
> **Counsel review.** The warning banner served in `--enforce` mode is legal
> wording shown to third parties. Have your own counsel review it for your
> operating jurisdiction before you enable enforcement.

## How it works

```
request → edge shield (detect) → on detection: contain source + record attribution
             │                          │
       warning banner            tamper-evident (hash-chained) evidence ledger
       (on attacker's                   │
        own connection)         human review gate → STIX 2.1 + IC3/CISA bundle
```

- **Detection** is a corroborated score, never a single spoofable signal. A
  user-agent alone never blocks legitimate traffic (`httpx`, Go, curl pass).
- **Attribution** is resolved from the unspoofable TCP peer inward, honoring a
  configured trusted-proxy list, with per-hop confidence. Low-confidence
  (spoofable) origins are held back from any federal bundle.
- **Evidence** is an append-only, SHA-256 hash-chained ledger (`verify-evidence`
  detects tampering). The chain makes the ledger **tamper-evident**, not a
  "cryptographic chain of custody" in the legal sense.
- **Evidence seal (HMAC).** The optional `--sign-key` seal is an HMAC. It proves
  **integrity-at-rest to whoever holds the key** — anyone with the key can both
  produce and verify it, so it does **not** provide third-party non-repudiation.
  Court-grade, independently verifiable signing (asymmetric Ed25519/RSA plus an
  RFC-3161 trusted timestamp) is a **TODO**, not shipped.
- **Fail-open**: any internal error allows traffic — the shield never takes down
  the app it protects.

## Install (deploy as a service)

Safe by default: starts **log-only**, bound to `127.0.0.1`.

**Linux (systemd):**
```bash
sudo ./deploy/install.sh
# edit /etc/root-justice/root-justice.env to enforce / set trusted proxies
sudo systemctl restart root-justice
```

**Windows (elevated PowerShell):**
```powershell
.\deploy\windows\Install-RootJustice.ps1            # log-only
.\deploy\windows\Install-RootJustice.ps1 -Enforce -TrustedProxy 10.0.0.0/8
```

The service runs **unprivileged** (systemd `DynamicUser` / Windows virtual
service account). Admin is used only to register it.

## Use (CLI)

**Run the shield** (log-only by default; `--enforce` to block/tarpit/decoy):
```bash
root-justice serve \
  --enforce \
  --trusted-proxy 10.0.0.0/8 \     # believe XFF only from these proxies
  --upstream http://app:9000 \     # reverse-proxy CLEAN traffic to your app
  --tls-cert cert.pem --tls-key key.pem \   # terminate HTTPS
  --allowlist allow.txt \          # never flag your monitors/CI (IP/CIDR, repeatable)
  --intel blocklist.txt \          # threat-intel feed (file or URL, repeatable)
  --db state.sqlite3 \             # persist blocks/patches across restarts
  --webhook https://hooks.example/… \  # alert on high/critical streams
  --no-decoy --no-tarpit           # opt OUT of deception (both on by default in enforce)
```
Health/ops endpoints are served automatically: `GET /healthz`, `/readyz`, and
`/dashboard`. **`/dashboard` is loopback-gated and unauthenticated** — it only
answers requests from `127.0.0.1`/`::1` and has no login. Do not expose it to the
network or terminate a proxy in front of it; reach it over an SSH tunnel instead.

**Everything else:**
```bash
root-justice audit-host                                   # local Artex listeners (:8787/:8788)
root-justice attribute --ip <ip>                          # RDAP + ASN
root-justice verify-evidence --evidence <ledger>          # hash-chain integrity
root-justice export-report --evidence <ledger> --enrich --reviewed-by "Your Name"
root-justice export-report ... --sign-key key.bin         # also sign the STIX bundle
root-justice validate-stix ./out/stix_bundle.json
root-justice sign-bundle <file> --key key.bin [--generate-key]
root-justice verify-bundle <file> --key key.bin
root-justice dashboard --evidence <ledger> --out dash.html
root-justice health                                       # liveness payload
root-justice intel-refresh --intel blocklist.txt          # load/preview feeds
root-justice taxii-push --api-root <url> --collection <id> --token <t> --evidence <ledger>
```

`export-report` refuses to write a federal bundle without `--reviewed-by`, and
excludes low-confidence (spoofable) origins automatically.

**Defensive asset audits** (operator-owned assets only — no third-party probing):
```bash
root-justice firmware-audit <image> [--deep]        # scan your own firmware/binary for leaked secrets (--deep adds REA)
root-justice domain-watch example.com               # enumerate lookalike/homoglyph domains of YOUR brand, flag registered
root-justice cloud-posture --bucket <url> [...]      # probe YOUR S3/GCS/Azure URLs for public exposure (repeatable)
root-justice check-password-policy --hash <h> [...]  # classify stored hashes; --hash-file <file> reads one per line
root-justice harden-guide [--endpoint|--wifi] [--markdown] [--quickcheck]   # endpoint/Wi-Fi hardening baselines
root-justice coverage [--markdown]                   # the defense-coverage control matrix below
```
`firmware-audit`, `check-password-policy`, `harden-guide` and `coverage` are
fully offline. `domain-watch` uses DNS resolution and `cloud-posture` makes
HTTP(S) probes — both only against the operator's **own** assets. Stored hashes
are never transmitted: classification is purely structural.

## PII & retention

The evidence ledger records personal data about connecting clients. Treat it as
sensitive and govern it under your own privacy obligations.

- **What is stored:** the origin IP address, the `User-Agent` string, and the
  request **path without its query string**, plus detection metadata (score,
  timestamp, matched signals).
- **What is not stored:** query strings are **not persisted** (they are dropped
  before an event is written), nor are request bodies or arbitrary headers.
- **Retention:** there is no automatic expiry — the ledger is append-only. Decide
  a retention window appropriate to your jurisdiction and purpose, and rotate or
  prune the ledger on that schedule. Restrict read access to the evidence path.

## Defense coverage (AI-hacking-tool classes)

Root Justice is mapped, as an auditable matrix, against the reference set of
offensive AI-hacking tool classes. For each class the matrix names the
operator-owned control that answers it and how completely — `neutralized` (fully
defends your own asset), `partial` (meaningful mitigation), or `advisory`
(hardening guidance only, no live block). Run `root-justice coverage` for the
machine-readable JSON (with a status rollup) or `--markdown` for this table:

| ID | Attack | Root Justice control | Status | Note |
| --- | --- | --- | --- | --- |
| exposed_site_files | Exposed site files / directory & backup-file exposure scanning | shield + decoy + tarpit + evidence | neutralized | Probes for .git, backups and stray config on the operator's own edge are blocked by the shield, lured into decoys, slowed by the tarpit, and recorded as evidence — the scan sees nothing real. |
| firmware_secrets | Firmware secret extraction (hard-coded keys/credentials in images) | firmware_audit + REA static analysis | partial | Pre-ship firmware auditing plus REA static analysis surfaces baked-in secrets in the operator's own images before release, but cannot reach firmware already shipped on devices in the field. |
| hash_cracking | Offline password-hash cracking of stolen credential stores | credpolicy + credential-theft-vector detection | partial | Credential-policy checks push strong hashing and high work factors, and theft-vector detection flags exfiltration paths, raising the cost of cracking — but a leaked store can still be attacked offline. |
| cloud_buckets | Cloud object-storage bucket enumeration & exposure | cloud posture audit | partial | A posture audit of the operator's own buckets finds public ACLs and listable objects so they can be locked down, but does not enforce provider-side policy or continuously block new misconfigurations. |
| lookalike_domains | Lookalike / homoglyph phishing-domain registration | domainwatch | partial | Domainwatch monitors for newly registered lookalikes of the operator's brands and raises alerts, but registration and takedown of third-party domains remain outside this package's control. |
| keystroke_injection | USB keystroke-injection (HID) attacks on endpoints | hardening advisory (endpoint) | advisory | Root Justice ships endpoint hardening guidance (USB/HID policy, device allowlisting, screen lock) but performs no live USB enforcement itself. |
| wifi_cracking | Wi-Fi handshake capture & WPA passphrase cracking | hardening advisory (wifi) | advisory | Root Justice advises on Wi-Fi hardening (WPA3, long passphrases, management-frame protection) for the operator's own networks but does not operate the radio or block captures. |

Every control above acts only on assets the operator owns or controls; none
probes, attacks, or reaches out to a third party.

> **Enforcement caveat.** Every `neutralized` status in the matrix applies **only
> under `--enforce`**. In the default log-only mode the shield **detects and
> records** probes but blocks, tarpits, and decoys nothing — the scan still sees
> real responses. `partial` and `advisory` controls are unchanged by the mode.

## Run in Docker (log-only by default)

```bash
docker compose up -d        # builds, runs 'root-justice serve' as non-root, evidence volume mounted
```
The image runs **non-root** with a read-only rootfs and `no-new-privileges`; it stays
log-only until you add `--enforce` to the service command. The process binds
`0.0.0.0` inside the container (required for Docker port forwarding), but
`docker-compose.yml` publishes the port on the **host loopback** (`127.0.0.1`)
only. If you widen that mapping, put the shield behind your own TLS/reverse proxy
and keep the unauthenticated `/dashboard` off the network.

## Test

```bash
python -m unittest discover -s tests -v      # 390 tests
```

## Integration points (for the Go/Coraza core & CrowdSec)

- `export_crowdsec_decisions()` emits a CrowdSec-bouncer-compatible decisions file.
- `run_rea_static_analysis()` bridges REA for static forensics on captured artifacts.
- Detection emits Coraza/ModSecurity SecLang rules per probe for an inline WAF.

## Status

Alpha. See [`CHANGELOG.md`](CHANGELOG.md) for the feature set and the tracked
roadmap / known limitations (live CrowdSec bouncer, Go inline core, per-record
signing, official `stix2-validator` via the `stix` extra). Contributions welcome —
see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Contributing & security

This is **defensive** software for protecting systems you own or are authorized to
defend. No offensive "hack-back" features are accepted. Please report vulnerabilities
privately per [`SECURITY.md`](SECURITY.md).

---

<sub><b>Topics:</b> cybersecurity · defensive-security · blue-team · WAF · intrusion-detection ·
scanner &amp; bot detection · honeypot · tarpit · AI / LLM security · agentic-AI defense ·
prompt-injection defense · threat intelligence · incident response · origin attribution (RDAP/ASN) ·
STIX 2.1 · TAXII · FBI IC3 / CISA reporting · chain-of-custody · DFIR · SOC · Python · stdlib-only.</sub>
