# The edge policy on Cloudflare (Terraform)

The lab runs its own edge (nginx + ModSecurity + OWASP CRS) so that everything can be tested for free in
CI. This folder writes the **same policy** for Cloudflare with the official Terraform provider (v5), so the
lab maps directly to a managed CDN/WAF.

The CI runs `terraform fmt -check` and `terraform validate` on it. It is not applied automatically: that
needs a real domain on Cloudflare and an API token.

## Lab ↔ Cloudflare

| Lab (this repository) | Cloudflare | Here |
|---|---|---|
| OWASP CRS 4 in ModSecurity, paranoia level 2 | Cloudflare OWASP Core Ruleset + Cloudflare Managed Ruleset (Pro+). Free plan: Free Managed Ruleset, automatic | `cloudflare_ruleset.managed_waf` |
| `custom-rules.conf.j2`: IP deny list, virtual patch, JSON-only API writes | WAF custom rules | `cloudflare_ruleset.custom_rules` |
| `exclusions-before-crs.conf.j2`: one rule, one field, one URL | Managed rule exceptions (skip rule) / overrides | not needed on Free |
| `limit_req` on `/api/login` → 429 | Rate limiting rule | `cloudflare_ruleset.rate_limit` |
| TLS 1.2+, AEAD ciphers, HSTS | `min_tls_version`, `tls_1_3`, `always_use_https` | `cloudflare_zone_setting.tls` |
| `proxy_ssl_verify` with the lab CA | SSL mode **Full (strict)** | `ssl = "strict"` |
| Authenticated origin pull (client certificate, origins return 403 without it) | Authenticated Origin Pulls (mTLS to the origin) | to enable per zone |
| `proxy_cache` driven by the origin's `Cache-Control`, credentials bypass | Cache rules (default: respects origin headers) | defaults |
| `X-Request-ID` in responses and audit log | `Cf-Ray` header and Security Events | built in |
| blackbox_exporter + `CertificateExpiringSoon` | Edge certificate expiry notifications | dashboard |
| `edge_exporter` + Grafana *Edge security* | Security Analytics / Security Events | dashboard |

## Use

```bash
cd cloudflare
cp terraform.tfvars.example terraform.tfvars        # zone_id, plan, blocked_ips
export CLOUDFLARE_API_TOKEN=...                      # Zone Settings Edit + Zone WAF Edit, this zone only
terraform init
terraform plan
terraform apply
```

## Free plan limits to keep in mind

- 5 custom rules, no regular expressions in rule expressions (the virtual patch uses `starts_with`).
- 1 rate limiting rule, 10 second counting period and 10 second timeout, counted per IP and data center.
- The Cloudflare Managed Ruleset and the OWASP ruleset need Pro or above: `plan = "pro"` deploys them.

Check these limits on the Cloudflare plan page before relying on them: they change over time.
