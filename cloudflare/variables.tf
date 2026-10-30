variable "zone_id" {
  description = "ID of the Cloudflare zone (dashboard > domain > Overview > API)."
  type        = string
}

variable "plan" {
  description = "Cloudflare plan of the zone: free, pro, business or enterprise. The managed rulesets need pro or above."
  type        = string
  default     = "free"

  validation {
    condition     = contains(["free", "pro", "business", "enterprise"], var.plan)
    error_message = "plan must be free, pro, business or enterprise."
  }
}

variable "blocked_ips" {
  description = "Incident response: client IPs or CIDRs to block (same role as edge_ip_denylist in the lab)."
  type        = list(string)
  default     = []
}

variable "login_path" {
  description = "Path of the login API, protected by the rate limiting rule."
  type        = string
  default     = "/api/login"
}
