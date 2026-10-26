# Contributing to bug-bounty-writeups

Every writeup here is a **sanitized, reproducible lab reconstruction** of a real
finding. This guide explains how to add or improve one.

## What belongs here

A writeup should document a vulnerability class or technique that:

- appears in the real world, and
- is commonly mis-fixed, and
- can be demonstrated against a deliberately vulnerable lab.

Each writeup must contain **every** section in
[`report-template.md`](../templates/report-template.md) unless the technique
proves a section is genuinely inapplicable.

## Ground rules

1. **No live client data.** No customer names, domains, hosts, endpoints,
   credentials, tokens, session IDs, stack traces, or screenshots from a real
   assessment. Everything is reproduced against a lab.
2. **No exploit tooling aimed at third parties.** We publish *methodology*, not
   *weaponized payloads* for production systems.
3. **Impact-first framing.** Every writeup explains *why the obvious fix is
   insufficient* and *how to verify the fix worked*.
4. **Consistent severity.** Use the
   [severity model](../templates/report-template.md#severity-model) — never
   inflate a headline number to grab attention.

## How to contribute

### Option A — open a pull request

1. Fork the repo.
2. Copy [`templates/report-template.md`](templates/report-template.md) into
   `writeups/<slug>.md`.
3. Fill it in. Run it past the
   [`templates/triage-checklist.md`](templates/triage-checklist.md).
4. Add or update the index table in [`README.md`](README.md).
5. Open a PR.

### Option B — open a "New writeup" issue

Use the **New writeup / contribution** issue template and we can co-develop it.

## Writing guidance

| Element | Guidance |
|---|---|
| **Title** | Descriptive and stable: `SSRF-in-avatar-fetch.md` |
| **CWE** | Map the root cause, not the symptom |
| **Severity** | Rate *realistic impact in context* |
| **Repro lab** | Provide a self-contained lab (e.g. a minimal Flask app) |
| **Fix** | Show the *correct* fix and explain why the naive fix fails |
| **Verification** | Give a command or check an attacker can still/can no longer do |

## Style

- US English spelling, sentence case headings.
- Prefer plain Markdown over screenshots where text suffices.
- When a screenshot is needed, crop tightly and redact any host/PII.

## Reporting a security issue

If you believe a published writeup discloses something that should not be public,
**report it privately** via
[GitHub Security Advisories](https://github.com/bhuvanchandt/bug-bounty-writeups/security/advisories/new).
Do not open a public issue for the underlying concern.
