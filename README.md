<div align="center">

# 🐞 Bug Bounty & VAPT Writeups

**Impact-focused, reproducible vulnerability reports.**

Every writeup follows the same template so triage is fast and remediation is
unambiguous.

[![License: MIT](https://img.shields.io/badge/License-MIT-6D28D9.svg)](LICENSE)
[![Writeups](https://img.shields.io/badge/writeups-4-4F46E5?style=flat-square&logo=github)](writeups/)
[![Severity](https://img.shields.io/badge/severity%20tagged-7C3AED?style=flat-square)](templates/report-template.md)

</div>

---

## Why this exists

Most public writeups stop at "the endpoint returned data it shouldn't." That is
the finding, not the report.

Every writeup here documents:

- the **root cause** in code, not just the symptom
- why the obvious fix is **insufficient**
- the **remediation** a developer can implement directly
- how to **verify the fix actually worked**

The goal is that an engineer on the other side can act on it without asking a
follow-up question.

---

## Index

| Writeup | Severity | Class | CWE |
|---|---|---|---|
| [IDOR — Invoice API](writeups/IDOR-invoice-api.md) | 🔴 High | Broken Access Control | CWE-639 |
| [SSRF — Avatar Fetch](writeups/SSRF-avatar-fetch.md) | 🔴 High | Server-Side Request Forgery | CWE-918 |
| [Business Logic — Promo Race Condition](writeups/BusinessLogic-promo-race.md) | 🟠 Medium-High | Insecure Design | CWE-840 |
| [Report Template](templates/report-template.md) | — | Reference | — |

**Categories covered:** IDOR · SSRF · SQLi · XSS · Auth Bypass · Business Logic ·
API Security · Access Control

---

## Structure

```
templates/
  report-template.md       Standard vulnerability report template
  triage-checklist.md      Pre-submission quality checklist
writeups/
  IDOR-invoice-api.md
  SSRF-avatar-fetch.md
  BusinessLogic-promo-race.md
```

---

## Severity model

| Rating | Criteria |
|---|---|
| **Critical** | Remote unauthenticated compromise, RCE, full DB extraction, auth bypass on admin |
| **High** | Cross-user data access, SSRF reaching internal services, privilege escalation |
| **Medium** | Stored XSS, limited info disclosure, business logic with financial impact |
| **Low** | Minor info disclosure, missing headers, verbose errors |
| **Informational** | Defence-in-depth, hardening suggestions, best practice |

Severity is rated on **realistic impact in context** — who can reach it, what it
returns, and what it enables next. An unauthenticated info leak is not "low"
just because the response is small.

---

## ⚠️ Ethics & Scope

**All testing referenced here was performed with explicit written authorization** —
either a client engagement with a signed scope document, or within a defined bug
bounty program scope.

Every report in this repository is a **sanitized or reconstructed lab
reproduction**. Specifically:

- No real client names, domains, or infrastructure
- No real user data, credentials, tokens, or session identifiers
- No live URLs
- No exploitation of third-party systems

Where a finding originated in client work, identifying details are removed and
the technique is reproduced against a deliberately vulnerable lab environment so
the methodology stays public.

> If you find a vulnerability in someone else's system, report it to them.
> Never publish it here, and never without authorization.

---

## Reporting a vulnerability

If you have found an issue in a system you are authorized to test, my approach is:

1. **Validate manually** — confirm it is real, not a scanner artefact
2. **Assess real impact** — what does it actually let an attacker do?
3. **Report privately and promptly**
4. **Give reasonable time** for a fix before any disclosure
5. **Publish only after remediation**, sanitized, as a learning artifact

---

## Contact

[![GitHub](https://img.shields.io/badge/GitHub-@bhuvanchandt-18181B?style=for-the-badge&logo=github)](https://github.com/bhuvanchandt)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-4F46E5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/thangudu-bhuvan-chand)
[![Email](https://img.shields.io/badge/Email-Contact-312E81?style=for-the-badge&logo=gmail&logoColor=white)](mailto:bhuvanthangudu7@gmail.com)

---

## License

[MIT](LICENSE) © Bhuvan Chand Thangudu

---

<div align="center">
Made by [@bhuvanchandt](https://github.com/bhuvanchandt)
</div>
