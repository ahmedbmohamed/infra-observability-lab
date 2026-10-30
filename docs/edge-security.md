# Edge security: WAF, certificates, cache and origin protection

The edge is a reverse proxy in front of the web servers. It is the only public entry point and it does what a
CDN/WAF such as Cloudflare or Akamai does for a customer: TLS termination, web application firewall, rate
limiting, caching, and protection of the origin servers. Everything is built from open source parts, so the
whole setup can be tested in CI on every push.

```mermaid
flowchart LR
    C[Client] -- "HTTPS (TLS 1.2/1.3)" --> E

    subgraph E[edge]
        direction TB
        T[TLS termination<br/>AEAD ciphers, HSTS] --> R[Rate limit<br/>/api/login]
        R --> W[ModSecurity<br/>OWASP CRS 4<br/>+ local rules]
        W --> K[Cache<br/>Cache-Control]
    end

    K -- "mTLS: client certificate<br/>edge-origin-pull" --> O1[web1]
    K -- mTLS --> O2[web2]
    X[Direct request<br/>bypassing the edge] -. 403 .-> O1

    E -. audit log, access log .-> M[edge_exporter<br/>blackbox_exporter]
    M --> P[Prometheus<br/>alerts] --> G[Grafana<br/>Edge security]
```

## 1. Request path

| Order | Check | Answer when it fails | File |
|---|---|---|---|
| 1 | TLS: 1.2 or 1.3, forward secrecy, AEAD ciphers only (no CBC) | handshake refused | `edge-site.conf.j2` |
| 2 | Rate limit on `/api/login`: 10 per minute per IP, burst 5 | 429 | `edge-site.conf.j2` |
| 3 | IP deny list (rule 10001) | 403 | `custom-rules.conf.j2` |
| 4 | Virtual patch: `/actuator`, `/jolokia`, `/manager/html`... (10010) | 403 | `custom-rules.conf.j2` |
| 5 | API contract: write requests to `/api/` must be JSON (10020, 10021) | 415 | `custom-rules.conf.j2` |
| 6 | Virtual patches for gaps found with GoTestWAF: XXE (10030), UTF-7 XML (10031), out-of-band callback domains (10040) | 403 | `custom-rules.conf.j2` |
| 7 | OWASP CRS 4.30: blocks at paranoia level 1, logs level 2 matches, anomaly threshold 5 | 403 | `crs-setup.conf.j2` |
| 8 | Cache: only what the origin marks cacheable, never with credentials | - | `edge-site.conf.j2` |
| 9 | Origin: the edge proves who it is with a client certificate | 403 at the origin | `lab-site.conf.j2` |

Every response carries an `X-Request-ID`. The same ID is the transaction ID in the WAF audit log, so a
blocked customer can quote it and support finds the exact rules that matched
(`tools/waf_report.py --request-id`).

## 2. WAF: how it decides

The CRS uses **anomaly scoring**. Each rule that matches adds points (critical = 5, error = 4, warning = 3)
and lets the request continue. At the end, rule 949110 blocks if the total reaches the threshold (5). One
critical match blocks; two weak signals also block. This is why one rule can be removed for one field without
opening a hole: the other rules still score.

**Paranoia levels** add stricter rules on top of each other (level 2: more SQL and command injection
patterns, off-domain URLs...). They catch more evasions and give more false positives. The edge **blocks
with the level 1 rules and runs the level 2 rules in detection only**: their matches go to the audit log
(with a 200 answer) and show what raising the level would block, before anyone is blocked. This is the
usual way to move up a level safely. Why level 1 for blocking: see the measurements below.

## 3. Tuning and choosing the paranoia level

### Own corpus

`tests/waf_corpus.py` holds 24 attacks and 12 legitimate requests that look suspicious (a strong password,
an apostrophe in a name, "select the best laptop", a review with `;` and `--`, a link in a profile).
Without tuning, these legitimate requests were blocked:

| Configuration | Legitimate requests allowed |
|---|---|
| Paranoia level 1, no exclusion | 11/12 |
| Paranoia level 2, no exclusion | 9/12 |
| Level 1 or 2 with the 3 exclusions below | 12/12 |

The three false positives and their fixes (`exclusions-before-crs.conf.j2`):

| Request | Rules that matched | Fix, smallest possible scope |
|---|---|---|
| `POST /api/login` with password `Tr0ub4dor&3';--Horse!` | 942540 (level 1), 942180, 942440 (SQL) | Remove SQL injection rules for `json.password` on `/api/login` only. A password is hashed, never put in a query. The username is still inspected. |
| `POST /api/comments` "I'd buy it again; 5/5 -- Sam" | 932200 (RCE bypass), 942440 (SQL comment), level 2 | Remove those 2 rules for `json.text` on `/api/comments` only. XSS and other rules still apply. |
| `POST /api/profile` with `website: https://example.com/...` | 931130 (off-domain URL, RFI), level 2 | Remove that rule for `json.website` on `/api/profile` only. |

Rules followed: one rule (or one rule family), one parameter, one URL. Never turn a rule off everywhere and
never lower the paranoia level of the whole site for one form field. The test suite runs the attack cases
after each change, so an exclusion that opens a hole fails the CI.

A lesson from building the tests: a test endpoint called `/api/whoami` was blocked by three RCE rules,
because `whoami` is a Unix command. Paths and parameter names are inspected too.

### Independent benchmark: GoTestWAF

The own corpus was written while building the lab, so it proves the tuning but is not an independent
measure. [GoTestWAF](https://github.com/wallarm/gotestwaf) (Wallarm, open source) sends its own attacks in
URLs, forms, multipart, JSON, XML, headers and paths, plus 141 legitimate texts built to look suspicious
("union was a great select", "bash away in the gym"). It runs in every CI build, and the manual workflow
`waf-benchmark` compares the paranoia levels on fresh labs. Results:

| Blocking level | Own corpus: attacks / legitimate | GoTestWAF attacks blocked | same, without Base64 payloads | GoTestWAF legitimate texts allowed |
|---|---|---|---|---|
| **1 (chosen)** | 24/24 / 12/12 | 340/668 = 50.9% | 340/433 = **78.5%** | 128/141 = **90.8%** |
| 2 | 24/24 / 12/12 | 374/668 = 56.0% | 374/433 = 86.4% | 91/141 = 64.5% |
| 3 | 24/24 / 10/12 | 457/668 = 68.4% | 402/433 = 92.8% | 48/141 = 34.0% |
| 4 | 24/24 / 4/12 | 502/668 = 75.1% | 423/433 = 97.7% | 0/141 = 0% |

Each row is a fresh lab built by the `waf-benchmark` workflow (GoTestWAF v0.5.11, CRS 4.30, same exclusions
and local rules), on 30/10/2026.

About a third of GoTestWAF's attacks are Base64-encoded. A Base64 string is harmless unless the
application decodes it, and pattern-based WAFs (CRS, and most managed rule sets) do not decode it, so the
results are shown with and without them.

**Decision:** block at level 1, detect at level 2. Level 2 blocks 8 points more of the non-encoded attacks
but refuses about a third of GoTestWAF's legitimate texts (50 instead of 13). For a customer site, that many false positives would get
the WAF switched off. The level 2 rules still run in detection, so the audit log shows exactly which
requests level 2 would block; the level can be raised per application once those are tuned.

### Gaps found by GoTestWAF and closed

| Gap | Fix |
|---|---|
| XML external entity (XXE) declarations go through: the CRS has no rule for them | local rule 10030 |
| The same XXE encoded in UTF-7 (`+ADwAIQ-DOCTYPE`) | local rule 10031 (no client sends UTF-7 XML) |
| Out-of-band callback domains (Burp Collaborator, interactsh...) in headers | local rule 10040 |

Gaps left open, with the reason, are listed in the [assessment report](assessment-report.md).

## 4. Cache

- The origin decides: pages and static files are sent with `Cache-Control: max-age=60`, the API with
  `no-cache`. The edge also never caches `/api/`.
- Requests with an `Authorization` header or a session cookie bypass the cache (`X-Cache-Status: BYPASS`):
  a personal page must never be stored in a shared cache.
- If every origin fails, the edge serves the last good copy (`proxy_cache_use_stale`).
- **Bug found and fixed:** at first the edge cached the origin's gzip-compressed response and served it to
  clients that had not asked for gzip. Now the edge asks the origin for an uncompressed body
  (`Accept-Encoding: ""`) and compresses itself, with `Vary: Accept-Encoding`. A test checks both cases.

## 5. Origin protection

A WAF is useless if attackers can reach the origin directly. The origins ask for a client certificate
(`ssl_verify_client optional`) and answer 403 unless it is valid, issued by the lab CA, and has the CN
`edge-origin-pull`. This is what Cloudflare calls *Authenticated Origin Pulls* (Akamai: *mTLS origin
keystore*, or *Site Shield* for an IP-based allow list). The edge also verifies the origin certificate
(`proxy_ssl_verify`, name `origin.lab`), the equivalent of Cloudflare's *Full (strict)* mode.

The `/healthz` page stays open, for monitoring.

## 6. Monitoring

| Signal | Source | Alert |
|---|---|---|
| HTTPS probe of the edge and of each origin, certificate expiry | blackbox_exporter on the edge | `EndpointProbeFailed`, `CertificateExpiringSoon` (21 days), `CertificateExpiryCritical` (7 days) |
| Blocked requests, by attack type | `edge_exporter` reading the ModSecurity JSON audit log | `WafAttackSpike` (> 0.5/s for 30 s) |
| Responses by status class and cache status | `edge_exporter` reading the JSON access log | `EdgeHighErrorRate` (> 5% of 5xx for 5 min) |

`edge_exporter.py` is a small exporter written for this lab (Python standard library only). Its labels are
bounded (status class, cache status, CRS attack tag) so the number of time series stays small.

The alert rules have unit tests (`tests/alerts_test.yml`, run by `promtool`), and two drills run in CI:

- **Origin outage** (`tests/alert_drill.py`): nginx stops on web1, `NginxDown` fires, and the edge keeps
  serving the site from web2 during the outage, then sends traffic to web1 again.
- **Attack campaign** (`tests/waf_drill.py`): about 2 malicious requests per second with every 403 payload
  type of the corpus while a normal user keeps browsing. Measured in CI: `WafAttackSpike` fired 54 s after the first
  attack, 171/171 attacks were blocked, no legitimate request was refused, and the alert cleared 45 s after
  the attack stopped.

Runbooks: [WAF attack spike](runbooks/waf-attack-spike.md), [certificates](runbooks/certificate-expiry.md).

## 7. Same ideas on Cloudflare and Akamai

| Lab | Cloudflare | Akamai |
|---|---|---|
| OWASP CRS, anomaly scoring, paranoia level, detection-only level | OWASP Core Ruleset (score threshold, paranoia level) + Cloudflare Managed Ruleset | App & API Protector (Adaptive Security Engine, attack groups) |
| Local rules (deny list, virtual patch, API contract) | WAF custom rules | Custom rules, network lists |
| Exclusions for one field on one URL | Managed rule exceptions / overrides | Rule exceptions in the security policy |
| `limit_req` → 429 | Rate limiting rules | Rate controls |
| Client certificate to the origin | Authenticated Origin Pulls | mTLS origin keystore, Site Shield |
| Internal CA, certificate expiry alerts | Origin CA, edge certificate notifications | Certificate Provisioning System (CPS) |
| `proxy_cache` + `Cache-Control` | Cache rules | Caching behavior in Property Manager |

The Cloudflare version of this policy is written in Terraform in [`cloudflare/`](../cloudflare/README.md).

## 8. Limits (said openly)

- ModSecurity v3 + CRS is what many managed WAFs started from, but it is not Cloudflare's or Akamai's engine:
  no machine-learning attack score, no bot management, no IP reputation, no DDoS protection.
- The rate limit is per IP on a single edge. Behind a NAT, many users share one IP; several edges would need a
  shared counter.
- The attack corpus was written while building the lab, so it is not independent. GoTestWAF is the
  independent measure, and it shows that a pattern-based WAF at level 1 lets through about a quarter of
  the non-encoded attacks: the WAF is one layer, not a replacement for fixing the application.
- Response bodies are inspected only up to 512 KB, and the audit log does not keep request bodies (they may
  hold passwords): an investigation sees the matched value, not the whole body.
- One edge is a single point of failure. In production there would be at least two, behind anycast or a
  load balancer.
