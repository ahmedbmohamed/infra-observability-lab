# The lab's edge policy, written for Cloudflare. Each block names the lab file it mirrors.
# Not applied by the CI (it needs a real domain and an API token): the CI only runs "terraform validate".

locals {
  # ansible/roles/edge/templates/edge-site.conf.j2: HTTPS only, TLS 1.2 minimum, TLS 1.3 on.
  # "strict": Cloudflare checks the origin certificate, like proxy_ssl_verify in the lab.
  zone_settings = {
    ssl                      = "strict"
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
  }

  # ansible/roles/edge/templates/custom-rules.conf.j2. Free plan: up to 5 custom rules, no regular expressions.
  custom_rules = concat(
    # Kept only when the deny list is not empty (an empty "in {}" list is not a valid expression).
    slice([{
      ref         = "ip_denylist"
      description = "Incident response: blocked client IPs (lab rule 10001)"
      expression  = "(ip.src in {${join(" ", var.blocked_ips)}})"
      action      = "block"
    }], 0, length(var.blocked_ips) > 0 ? 1 : 0),
    [
      {
        ref         = "virtual_patch_management_endpoints"
        description = "Virtual patch: management endpoints of Java frameworks (lab rule 10010)"
        expression  = "(starts_with(lower(http.request.uri.path), \"/actuator\") or starts_with(lower(http.request.uri.path), \"/jolokia\") or starts_with(lower(http.request.uri.path), \"/manager/html\"))"
        action      = "block"
      },
      {
        ref         = "api_requires_json"
        description = "API contract: write requests must be JSON (lab rules 10020 and 10021)"
        expression  = "(starts_with(http.request.uri.path, \"/api/\") and http.request.method in {\"POST\" \"PUT\" \"PATCH\"} and not any(starts_with(lower(http.request.headers[\"content-type\"][*]), \"application/json\")))"
        action      = "block"
      },
      {
        ref         = "block_attack_tools"
        description = "Known attack tools by user agent (CRS 913100 in the lab)"
        expression  = "(lower(http.user_agent) contains \"sqlmap\" or lower(http.user_agent) contains \"nikto\" or lower(http.user_agent) contains \"nuclei\")"
        action      = "block"
      },
    ],
  )

  # Managed rulesets (pro plan and above). IDs are the same in every account.
  managed_rulesets = {
    cloudflare_managed = "efb7b8c949ac4650a09736fc376e9aee"
    owasp_core         = "4814384a9e5d4991b9815dcfc25d2f1f"
  }
}

resource "cloudflare_zone_setting" "tls" {
  for_each = local.zone_settings

  zone_id    = var.zone_id
  setting_id = each.key
  value      = each.value
}

resource "cloudflare_ruleset" "custom_rules" {
  zone_id     = var.zone_id
  name        = "Edge custom rules"
  description = "Virtual patches, API contract and deny list (mirrors the lab's custom-rules.conf)"
  kind        = "zone"
  phase       = "http_request_firewall_custom"
  rules       = local.custom_rules
}

# Lab: limit_req zone=login (10 per minute, burst 5). Free plan: one rule, 10 s period and 10 s timeout,
# and only a few fields in the expression (the URI path is one of them, the method is not).
resource "cloudflare_ruleset" "rate_limit" {
  zone_id     = var.zone_id
  name        = "Edge rate limiting"
  description = "Brute force and credential stuffing on the login API"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [{
    ref         = "login_rate_limit"
    description = "At most 5 login attempts per 10 seconds per IP and data center"
    expression  = "(http.request.uri.path eq \"${var.login_path}\")"
    action      = "block"
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = 10
      requests_per_period = 5
      mitigation_timeout  = 10
    }
  }]
}

# Lab: ModSecurity + OWASP CRS. On the free plan Cloudflare already runs its Free Managed Ruleset by itself.
resource "cloudflare_ruleset" "managed_waf" {
  count = var.plan == "free" ? 0 : 1

  zone_id     = var.zone_id
  name        = "Edge managed rules"
  description = "Cloudflare Managed Ruleset and Cloudflare OWASP Core Ruleset"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules = [for name, id in local.managed_rulesets : {
    ref               = "execute_${name}"
    description       = "Execute ${name}"
    expression        = "true"
    action            = "execute"
    action_parameters = { id = id }
  }]
}
