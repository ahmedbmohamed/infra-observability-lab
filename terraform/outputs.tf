output "web_nodes" {
  description = "HTTPS URL and SSH port of each web server."
  value = {
    for name, node in local.web_nodes : name => {
      https_url = "https://localhost:${node.https_port}"
      ssh_port  = node.ssh_port
    }
  }
}

output "prometheus_url" {
  value = "http://localhost:9090"
}

output "grafana_url" {
  value = "http://localhost:3000"
}

output "grafana_admin_password" {
  description = "Read it with: terraform output -raw grafana_admin_password"
  value       = random_password.grafana_admin.result
  sensitive   = true
}
