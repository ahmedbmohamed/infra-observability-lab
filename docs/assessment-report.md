# Edge security assessment — Infra Observability Lab

*Written as it would be for a customer. The "customer" is the lab itself: one edge (nginx + ModSecurity +
OWASP CRS 4.30) in front of two origin web servers.*

| | |
|---|---|
| Scope | `https://localhost:8440` (edge), origins `web1`, `web2`, their certificates, the WAF, cache and rate limit configuration, monitoring |
| Date | 30/10/2026 |
| Method | Configuration review; own test corpus (24 attacks, 12 legitimate requests); GoTestWAF v0.5.11 at paranoia levels 1 to 4 on fresh labs; attack and outage drills; TLS checks |
| Author | Ahmed Benmohamed |

## 1. Summary

The edge is in a good state for a first production step. It blocks every attack of the own corpus without
blocking any of the tricky legitimate requests, the origins cannot be reached without the edge, TLS is
limited to modern ciphers, and attacks and certificate problems raise alerts within a minute.

The main limit is the nature of a pattern-based WAF: at the chosen level it blocks **78.5%** of the
independent benchmark's non-encoded attacks while allowing **90.8%** of its legitimate texts. A stricter
level blocks more but refuses many legitimate requests. The WAF reduces risk; it does not replace fixing the
application.

**Top 3 recommendations**

1. Keep blocking at paranoia level 1 and review the level 2 detections weekly; raise the level for the API
   once its false positives are tuned (finding F1).
2. Route the alerts to the on-call channel: today they are only visible in Prometheus and Grafana (F2).
3. Add a second edge and per-account login limits in the application (F3, F4).

## 2. Measurements

### WAF

| Test | Result |
|---|---|
| Own corpus, attacks (SQLi, XSS, LFI, RCE, Log4Shell, SSRF, XXE, PHP, Java, scanners, recon, local rules) | 24/24 blocked |
| Own corpus, legitimate requests that look suspicious | 12/12 allowed (11/12 before tuning) |
| GoTestWAF, all attacks | 340/668 = 50.9% blocked |
| GoTestWAF, attacks without Base64 encoding | 340/433 = 78.5% blocked |
| GoTestWAF, legitimate texts | 128/141 = 90.8% allowed |

Comparison of the paranoia levels (same benchmark, fresh lab each time):

| Blocking level | Non-encoded attacks blocked | Legitimate texts allowed |
|---|---|---|
| 1 (current) | 78.5% | 90.8% |
| 2 | 86.4% | 64.5% |
| 3 | 92.8% | 34.0% |
| 4 | 97.7% | 0% |

### Other controls

| Control | Result |
|---|---|
| Direct request to an origin, without the edge client certificate | 403 on every origin |
| TLS | 1.2 and 1.3 only; TLS 1.2 limited to ECDHE + AES-GCM / ChaCha20; CBC suites refused; HSTS one year |
| Origin certificates | verified by the edge (name `origin.lab`, lab CA) |
| Certificates | valid for more than 300 days; alerts at 21 and 7 days tested |
| Login rate limit | 10 per minute per IP, burst 5, then 429 |
| Cache | public content cached; API and requests with credentials never cached; one gzip caching bug found and fixed |
| Attack drill | 21 payload types at about 2 per second: `WafAttackSpike` fired after 54 s, 171/171 attacks blocked, no legitimate request refused, alert cleared 45 s after the attack stopped |
| Outage drill | nginx stopped on web1: the edge kept serving from web2, `NginxDown` fired after 38 s, cleared 14 s after the repair, traffic back on web1 |

## 3. Findings

Severity: **High** = can lead to a compromise or an outage soon; **Medium** = weakens a control;
**Low** = hardening; **Info** = accepted trade-off, documented.

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| F1 | Medium | About one non-encoded attack in five passes the WAF at level 1. Classes seen in GoTestWAF: LDAP and NoSQL injection, XSS with recent JavaScript syntax (`alert?.(...)`), HTML-entity-encoded XSS, path traversal and CRLF with unusual encodings. | Keep level 2 in detection and review its matches weekly. Raise the blocking level for `/api/` first (its 3 false positives are already tuned). Fix the application side: parameterised queries (SQL, LDAP, NoSQL), output encoding, strict input validation. |
| F2 | Medium | Alerts (`WafAttackSpike`, `CertificateExpiryCritical`, `EndpointProbeFailed`...) are visible in Prometheus and Grafana but not sent to anyone. | Add Alertmanager with routing to the on-call channel (e-mail, Teams/Slack, phone for critical). Link each alert to its runbook (already in the alert annotations). |
| F3 | Medium | A single edge is a single point of failure: if it stops, the site is down even though both origins are fine. | Two edges behind a load balancer or anycast; shared rate limit counters. On Cloudflare/Akamai this is built in. |
| F4 | Medium | The login rate limit counts per IP. A credential stuffing campaign spread over many IPs stays under it; many users behind one NAT can be blocked together. | Add per-account limits and lockout in the application; on a managed WAF, use bot management and leaked-credential checks. |
| F5 | Low | Certificates live 397 days and are renewed by hand (delete, then run Ansible). | Automate with ACME (internal step-ca or Let's Encrypt for public names) and shorter lifetimes (90 days or less). |
| F6 | Low | The WAF audit log keeps headers and matched values but no request bodies. | Accepted on purpose (bodies may contain passwords). For investigations, enable body logging for one URL and a short time only. |
| F7 | Low | Response bodies are inspected only up to 512 KB. | Acceptable for this site; raise the limit only for endpoints that return sensitive data in large responses. |
| F8 | Info | Base64-encoded attacks pass (about a third of GoTestWAF's attacks). | Expected for pattern-based WAFs: the payload is harmless unless the application decodes it. Where an application decodes Base64 input, add a rule with `t:base64Decode` for that parameter. |
| F9 | Info | Thirteen GoTestWAF legitimate texts are blocked at level 1 (for example "union was a great select"). | Accepted for now; review if real users send such texts (the audit log and the `X-Request-ID` show it). |

## 4. Changes made during the assessment

| Change | Why |
|---|---|
| Virtual patch 10030: block XML external entity declarations | GoTestWAF XXE payloads were not blocked: the CRS has no rule for them |
| Virtual patch 10031: block XML encoded in UTF-7 | the same XXE hidden with UTF-7 |
| Rule 10040: block out-of-band callback domains (Burp Collaborator, interactsh...) | used to detect blind SSRF/XXE/Log4Shell; never in real traffic |
| Blocking level 2 → level 1, level 2 kept in detection | benchmark above: level 2 refused 50 of 141 legitimate texts |
| Cache: the edge compresses, the origin sends uncompressed bodies, `Vary: Accept-Encoding` | a gzip body was served to a client that had not asked for gzip |
| Three narrow exclusions (password, review text, profile URL) | real false positives, each removed for one rule, one field, one URL |

## 5. How to check this report

Everything above is reproduced by the CI on each push (`.github/workflows/ci.yml`) and by the manual
`waf-benchmark` workflow. Locally: `make all`, then `make waf-check` and `make gotestwaf`.
