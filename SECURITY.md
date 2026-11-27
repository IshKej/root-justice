# Security Policy

Root Justice (Artex Antidote) is **strictly defensive** blue-team software. It
operates only on infrastructure you own or are explicitly authorized to protect.

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for a suspected vulnerability.

- **Preferred:** open a private advisory through GitHub's
  [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (Security tab -> "Report a vulnerability").
- **Alternative:** email the maintainers at `security@root-justice.example`
  (placeholder — replace with the project's real security contact before the
  first public release).

Please include enough detail to reproduce the issue (affected version, a
minimal repro, and the impact you observed). We aim to acknowledge reports
within a few business days and will coordinate a fix and disclosure timeline
with you.

Do not include live credentials, production evidence ledgers, or personal data
in a report.

## Supported versions

The project is pre-1.0; only the latest `0.x` release line receives security
fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Scope

In scope: vulnerabilities in the `artex_antidote` package and its shipped
deployment scaffolding (e.g. evidence-ledger tampering that bypasses
verification, authentication/attribution bypass, denial of service of the
shield itself, or code that violates the fail-open guarantee).

Out of scope: findings that require already-privileged local access, issues in
optional third-party dependencies, and reports asking the project to add
offensive capability (it will not).

## Responsible / lawful use

This is **defensive** software, intended for lawful, authorized use on systems
you own or operate. It performs **no hack-back**: any warning notice is served
only in the response to an attacker's own request and is never sent outbound to
a third party. Attribution and evidence features are for your own records and
for a human reviewer.

Before submitting any generated evidence to law enforcement or other
authorities, **consult qualified legal counsel.** Nothing here is legal advice,
and the tool never transmits anything to authorities on its own.
