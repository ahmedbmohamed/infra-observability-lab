locals {
  # Each web server gets a fixed IP and its own ports on the host (SSH 2221+, HTTPS 8443+).
  web_nodes = {
    for i in range(var.web_count) : "web${i + 1}" => {
      ip         = cidrhost(var.network_cidr, 11 + i)
      ssh_port   = 2221 + i
      https_port = 8443 + i
    }
  }

  # The edge (WAF + cache) sits in front of the web servers. Same server image, its own role in Ansible.
  edge_node = {
    ip         = cidrhost(var.network_cidr, 10)
    ssh_port   = 2220
    https_port = 8440
  }

  all_nodes = concat(keys(local.web_nodes), ["edge"])
  # Probed by blackbox_exporter on the edge: availability and certificate expiry.
  probe_targets = concat(["https://edge/healthz"], [for n in keys(local.web_nodes) : "https://${n}/healthz"])

  node_image_dir = "${path.module}/../images/node"
  monitoring_dir = "${path.module}/../monitoring"
}

resource "docker_network" "lab" {
  name = "iol-lab"

  ipam_config {
    subnet = var.network_cidr
  }
}

# ---------- Web servers (stand-ins for Linux VMs, configured by Ansible over SSH) ----------

resource "docker_image" "node" {
  name = "iol-node:latest"

  build {
    context = local.node_image_dir
  }

  # Rebuild the image when a file in images/node changes.
  triggers = {
    files = sha1(join("", [for f in sort(fileset(local.node_image_dir, "*")) : filesha1("${local.node_image_dir}/${f}")]))
  }
}

resource "docker_container" "web" {
  for_each = local.web_nodes

  name     = "iol-${each.key}"
  hostname = each.key
  image    = docker_image.node.image_id
  restart  = "unless-stopped"

  env = ["AUTHORIZED_KEY=${trimspace(file(var.ssh_public_key_path))}"]

  networks_advanced {
    name         = docker_network.lab.name
    ipv4_address = each.value.ip
    aliases      = [each.key]
  }

  ports {
    internal = 22
    external = each.value.ssh_port
    ip       = "127.0.0.1"
  }

  ports {
    internal = 443
    external = each.value.https_port
    ip       = "127.0.0.1"
  }
}

# ---------- Edge: WAF, cache and rate limiting in front of the web servers ----------

resource "docker_container" "edge" {
  name     = "iol-edge"
  hostname = "edge"
  image    = docker_image.node.image_id
  restart  = "unless-stopped"

  env = ["AUTHORIZED_KEY=${trimspace(file(var.ssh_public_key_path))}"]

  networks_advanced {
    name         = docker_network.lab.name
    ipv4_address = local.edge_node.ip
    aliases      = ["edge"]
  }

  ports {
    internal = 22
    external = local.edge_node.ssh_port
    ip       = "127.0.0.1"
  }

  # The only public entry point of the site.
  ports {
    internal = 443
    external = local.edge_node.https_port
    ip       = "127.0.0.1"
  }
}

# ---------- Monitoring ----------

resource "docker_image" "prometheus" {
  name = var.prometheus_image
}

resource "docker_container" "prometheus" {
  name    = "iol-prometheus"
  image   = docker_image.prometheus.image_id
  restart = "unless-stopped"

  command = [
    "--config.file=/etc/prometheus/prometheus.yml",
    "--storage.tsdb.path=/prometheus",
    "--storage.tsdb.retention.time=2d",
  ]

  # The scrape targets come from web_nodes, so adding a server also adds it to monitoring.
  upload {
    file    = "/etc/prometheus/prometheus.yml"
    content = templatefile("${path.module}/templates/prometheus.yml.tftpl", { nodes = local.all_nodes, probes = local.probe_targets })
  }

  upload {
    file    = "/etc/prometheus/alerts.yml"
    content = file("${local.monitoring_dir}/alerts.yml")
  }

  networks_advanced {
    name    = docker_network.lab.name
    aliases = ["prometheus"]
  }

  ports {
    internal = 9090
    external = 9090
    ip       = "127.0.0.1"
  }
}

resource "random_password" "grafana_admin" {
  length  = 20
  special = false
}

resource "docker_image" "grafana" {
  name = var.grafana_image
}

resource "docker_container" "grafana" {
  name    = "iol-grafana"
  image   = docker_image.grafana.image_id
  restart = "unless-stopped"

  env = [
    "GF_SECURITY_ADMIN_PASSWORD=${random_password.grafana_admin.result}",
    "GF_USERS_ALLOW_SIGN_UP=false",
    "GF_AUTH_ANONYMOUS_ENABLED=false",
    "GF_ANALYTICS_REPORTING_ENABLED=false",
  ]

  upload {
    file    = "/etc/grafana/provisioning/datasources/prometheus.yml"
    content = file("${local.monitoring_dir}/grafana/datasource.yml")
  }

  upload {
    file    = "/etc/grafana/provisioning/dashboards/provider.yml"
    content = file("${local.monitoring_dir}/grafana/dashboard-provider.yml")
  }

  upload {
    file    = "/etc/grafana/dashboards/lab-overview.json"
    content = file("${local.monitoring_dir}/grafana/lab-overview.json")
  }

  upload {
    file    = "/etc/grafana/dashboards/edge-security.json"
    content = file("${local.monitoring_dir}/grafana/edge-security.json")
  }

  networks_advanced {
    name    = docker_network.lab.name
    aliases = ["grafana"]
  }

  ports {
    internal = 3000
    external = 3000
    ip       = "127.0.0.1"
  }

  depends_on = [docker_container.prometheus]
}

# ---------- Hand-off to Ansible ----------

resource "local_file" "ansible_inventory" {
  filename        = "${path.module}/../ansible/inventory/hosts.yml"
  file_permission = "0644"
  content = templatefile("${path.module}/templates/hosts.yml.tftpl", {
    nodes       = local.web_nodes
    edge        = local.edge_node
    private_key = abspath(trimsuffix(var.ssh_public_key_path, ".pub"))
  })
}
