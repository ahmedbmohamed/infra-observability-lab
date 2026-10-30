# Runbook: certificate alerts

| Alert | Fires when | Severity |
|---|---|---|
| `CertificateExpiringSoon` | a probed certificate expires in less than 21 days | warning |
| `CertificateExpiryCritical` | less than 7 days | critical |
| `EndpointProbeFailed` | the HTTPS probe fails (down, wrong status, certificate not trusted or expired) | critical |

The probes run from the edge (blackbox_exporter, module `https_lab`) against `https://edge/healthz`
and `https://<origin>/healthz`. They trust only the lab CA.

## 1. Which certificate, how long

Grafana > *Edge security* > *Certificate expires in (days)*, or:

```bash
curl -s 'http://localhost:9090/api/v1/query?query=(probe_ssl_earliest_cert_expiry-time())/86400'
```

Read it directly on the server:

```bash
openssl s_client -connect localhost:8440 -servername edge </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -ext subjectAltName
```

## 2. Renew

The internal CA issues certificates for 397 days. Ansible only issues a certificate if the file is
missing, so renewing means removing the old one and running the playbook:

```bash
rm .secrets/pki/edge.crt .secrets/pki/edge.csr   # or web1, web2, edge-origin-pull
make configure                                    # issues, copies and reloads nginx (no downtime)
```

For the origin servers, also check that the new certificate still has `DNS:origin.lab`
(the name the edge verifies). For the edge client certificate (`edge-origin-pull`), the origins
check the CN: a certificate with another CN gets 403 from every origin, and the site goes down.

## 3. Check

The probe metric updates within 10 seconds and the alert clears after the `for` delay. Run
`make test` (TLS and certificate tests).

## If the probe fails but the certificate is fine

- `probe_http_status_code` is not 200: the service answers, but not normally (look at nginx).
- `probe_ssl_earliest_cert_expiry` is missing: the TLS handshake failed (wrong CA, expired,
  name mismatch). `openssl s_client` above shows why.
- On Cloudflare the same checks are the *SSL/TLS > Edge Certificates* page and the certificate
  expiry notifications; with `ssl = "strict"` an expired origin certificate gives a 526 error.
