"""The web servers: HTTPS with the internal CA, security headers, SSH hardening."""

import socket
import ssl
from urllib.parse import urlparse

import pytest
import requests

from conftest import CA_CERT, SSH_KEY, ssh


def test_every_server_answers_over_https(nodes):
    for name, node in nodes.items():
        r = requests.get(node["https_url"], verify=CA_CERT, timeout=10)
        assert r.status_code == 200, name
        assert f"<h1>{name}</h1>" in r.text


def test_health_endpoint(nodes):
    for node in nodes.values():
        r = requests.get(node["https_url"] + "/healthz", verify=CA_CERT, timeout=10)
        assert r.text == "ok\n"


def test_security_headers_and_no_version_leak(nodes):
    for node in nodes.values():
        h = requests.get(node["https_url"], verify=CA_CERT, timeout=10).headers
        assert h["Strict-Transport-Security"].startswith("max-age=")
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in h["Content-Security-Policy"]
        assert h["Server"] == "nginx"  # server_tokens off: no version number


def test_certificate_is_not_trusted_without_the_lab_ca(nodes):
    url = next(iter(nodes.values()))["https_url"]
    with pytest.raises(requests.exceptions.SSLError):
        requests.get(url, timeout=10)


def test_tls_1_2_and_1_3_handshakes(nodes):
    for node in nodes.values():
        url = urlparse(node["https_url"])
        for version, name in [(ssl.TLSVersion.TLSv1_3, "TLSv1.3"), (ssl.TLSVersion.TLSv1_2, "TLSv1.2")]:
            ctx = ssl.create_default_context(cafile=CA_CERT)
            ctx.minimum_version = ctx.maximum_version = version
            with socket.create_connection((url.hostname, url.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=url.hostname) as tls:
                    assert tls.version() == name


def test_ssh_refuses_passwords(nodes):
    for node in nodes.values():
        r = ssh(node["ssh_port"], "ops", "true", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password")
        assert r.returncode == 255
        assert "Permission denied (publickey)" in r.stderr


def test_ssh_refuses_root_even_with_the_key(nodes):
    for node in nodes.values():
        r = ssh(node["ssh_port"], "root", "true", "-i", str(SSH_KEY))
        assert r.returncode == 255
        assert "Permission denied" in r.stderr


def test_ops_user_logs_in_with_the_key_and_uses_sudo(nodes):
    for node in nodes.values():
        r = ssh(node["ssh_port"], "ops", "sudo -n supervisorctl status nginx", "-i", str(SSH_KEY))
        assert r.returncode == 0, r.stderr
        assert "RUNNING" in r.stdout
