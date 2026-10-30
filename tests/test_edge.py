"""The edge: WAF (ModSecurity + OWASP CRS), authenticated origin pull, cache, rate limit, TLS policy, metrics."""

import socket
import ssl
import uuid
from urllib.parse import urlparse

import pytest
import requests

from conftest import CA_CERT, ROOT, SSH_KEY, ssh, wait_for
from waf_corpus import ATTACKS, LEGITIMATE, send

CLIENT_CERT = (ROOT / ".secrets" / "pki" / "edge-origin-pull.crt", ROOT / ".secrets" / "pki" / "edge-origin-pull.key")


@pytest.fixture(scope="session")
def edge(outputs) -> dict:
    return outputs["edge"]


@pytest.fixture(scope="session")
def site(edge) -> str:
    return edge["https_url"]


# ---------- Reverse proxy and origin protection ----------

def test_site_is_served_through_the_edge(site):
    r = requests.get(site, verify=CA_CERT, timeout=10)
    assert r.status_code == 200
    assert "<h1>web" in r.text
    assert r.headers["Server"] == "nginx"  # no version number
    assert r.headers["Strict-Transport-Security"].startswith("max-age=31536000")
    assert len(r.headers["X-Request-ID"]) == 32


def test_api_is_balanced_across_every_origin(site, nodes):
    seen = {requests.get(f"{site}/api/server-info", verify=CA_CERT, timeout=10).json()["server"] for _ in range(20)}
    assert seen == set(nodes)


def test_origins_refuse_requests_that_bypass_the_edge(nodes):
    for node in nodes.values():
        for path in ("/", "/api/search?q=x"):
            r = requests.get(node["https_url"] + path, verify=CA_CERT, timeout=10)
            assert r.status_code == 403, path
            assert "Direct access to the origin is not allowed" in r.text


def test_origins_accept_the_edge_client_certificate(nodes):
    for name, node in nodes.items():
        r = requests.get(node["https_url"], verify=CA_CERT, cert=CLIENT_CERT, timeout=10)
        assert r.status_code == 200
        assert f"<h1>{name}</h1>" in r.text


# ---------- WAF ----------

@pytest.mark.parametrize("case", ATTACKS, ids=lambda c: c.name)
def test_waf_blocks_attacks(site, case):
    r = send(site, case, CA_CERT)
    assert r.status_code == case.expect, r.text[:200]


@pytest.mark.parametrize("case", LEGITIMATE, ids=lambda c: c.name)
def test_waf_lets_legitimate_traffic_through(site, case):
    r = send(site, case, CA_CERT)
    assert r.status_code == case.expect, f"false positive, request id {r.headers.get('X-Request-ID')}"


def test_blocked_request_can_be_traced_with_its_request_id(site, edge):
    """The ID a blocked customer sees is the key to the WAF audit log entry (rules matched, score)."""
    r = requests.get(f"{site}/api/search", params={"q": "1' UNION SELECT password FROM users--"}, verify=CA_CERT, timeout=10)
    assert r.status_code == 403
    request_id = r.headers["X-Request-ID"]

    def audit_entry():
        out = ssh(edge["ssh_port"], "ops", f"sudo -n grep -F {request_id} /var/log/modsec/audit.json", "-i", str(SSH_KEY))
        return out.stdout

    entry = wait_for(audit_entry, timeout=10, every=1)
    assert '"ruleId":"949110"' in entry  # inbound anomaly score exceeded
    assert '"attack-sqli"' in entry


# ---------- Cache ----------

def test_static_files_are_cached(site):
    url = f"{site}/static/app.css?v={uuid.uuid4().hex}"  # new cache key on each run
    statuses = [requests.get(url, verify=CA_CERT, timeout=10).headers["X-Cache-Status"] for _ in range(3)]
    assert statuses[0] in ("MISS", "EXPIRED")
    assert statuses[1:] == ["HIT", "HIT"]


def test_api_responses_are_never_cached(site):
    for _ in range(2):
        r = requests.get(f"{site}/api/orders?page=1", verify=CA_CERT, timeout=10)
        assert r.headers.get("X-Cache-Status", "") == ""


def test_requests_with_credentials_bypass_the_cache(site):
    r = requests.get(f"{site}/static/app.css", headers={"Authorization": "Bearer abc"}, verify=CA_CERT, timeout=10)
    assert r.headers["X-Cache-Status"] == "BYPASS"


def test_compression_follows_the_client(site):
    plain = requests.get(f"{site}/static/app.css", headers={"Accept-Encoding": "identity"}, verify=CA_CERT, timeout=10)
    assert "Content-Encoding" not in plain.headers
    assert "font-family" in plain.text
    gzipped = requests.get(f"{site}/static/app.css", headers={"Accept-Encoding": "gzip"}, verify=CA_CERT, timeout=10)
    assert gzipped.headers.get("Content-Encoding") == "gzip"
    assert "Accept-Encoding" in gzipped.headers["Vary"]


# ---------- TLS policy ----------

def test_tls_1_2_refuses_cbc_ciphers(site):
    url = urlparse(site)
    ctx = ssl.create_default_context(cafile=CA_CERT)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA")
    with socket.create_connection((url.hostname, url.port), timeout=10) as sock:
        with pytest.raises(ssl.SSLError):
            ctx.wrap_socket(sock, server_hostname=url.hostname)


def test_tls_1_3_and_1_2_aead_work(site):
    url = urlparse(site)
    for version in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
        ctx = ssl.create_default_context(cafile=CA_CERT)
        ctx.minimum_version = ctx.maximum_version = version
        with socket.create_connection((url.hostname, url.port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=url.hostname) as tls:
                assert "GCM" in tls.cipher()[0] or "CHACHA20" in tls.cipher()[0]


# ---------- Monitoring of the edge ----------

def query(prometheus: str, promql: str) -> list:
    return requests.get(f"{prometheus}/api/v1/query", params={"query": promql}, timeout=10).json()["data"]["result"]


def test_probes_succeed_for_the_edge_and_every_origin(prometheus, nodes):
    expected = {"https://edge/healthz"} | {f"https://{n}/healthz" for n in nodes}
    ok = wait_for(lambda: {r["metric"]["instance"] for r in query(prometheus, "probe_success == 1")} >= expected, timeout=90)
    assert ok, query(prometheus, "probe_success")


def test_certificates_are_valid_for_more_than_300_days(prometheus):
    days = wait_for(lambda: query(prometheus, "(probe_ssl_earliest_cert_expiry - time()) / 86400"), timeout=60)
    assert days and all(float(r["value"][1]) > 300 for r in days)


def test_blocked_requests_reach_prometheus(prometheus):
    assert wait_for(lambda: query(prometheus, "sum(edge_waf_blocked_requests_total) > 0"), timeout=60)
    attacks = wait_for(lambda: {r["metric"]["attack"] for r in query(prometheus, "edge_waf_attacks_total")} >= {"sqli", "xss"}, timeout=60)
    assert attacks


# ---------- Rate limit (last: it uses up the login budget for a minute) ----------

def test_login_is_rate_limited(site):
    codes = [
        requests.post(f"{site}/api/login", json={"username": "bob", "password": "wrong"}, verify=CA_CERT, timeout=10).status_code
        for _ in range(15)
    ]
    # Budget: burst of 5 + 1 request every 6 s. Whatever was left from earlier runs, most attempts are refused.
    assert codes.count(200) <= 6, codes
    assert codes.count(429) >= 9, codes
