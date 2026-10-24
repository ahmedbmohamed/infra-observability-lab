variable "web_count" {
  description = "Number of web servers to create."
  type        = number
  default     = 2

  validation {
    condition     = var.web_count >= 1 && var.web_count <= 5
    error_message = "web_count must be between 1 and 5."
  }
}

variable "network_cidr" {
  description = "Subnet of the lab network."
  type        = string
  default     = "172.30.0.0/24"
}

variable "ssh_public_key_path" {
  description = "Public key allowed to log in as the ops user on the web servers."
  type        = string
  default     = "../.secrets/id_ed25519.pub"
}

variable "prometheus_image" {
  description = "Prometheus image, pinned to a version."
  type        = string
  default     = "prom/prometheus:v2.54.1"
}

variable "grafana_image" {
  description = "Grafana image, pinned to a version."
  type        = string
  default     = "grafana/grafana:11.2.2"
}
