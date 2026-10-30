output "custom_rules" {
  description = "Custom rules deployed, in evaluation order."
  value       = [for r in local.custom_rules : r.description]
}

output "managed_rulesets_deployed" {
  value = var.plan == "free" ? "Cloudflare Free Managed Ruleset (automatic on the free plan)" : join(", ", keys(local.managed_rulesets))
}
