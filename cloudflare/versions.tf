terraform {
  required_version = ">= 1.6"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# Reads the API token from the CLOUDFLARE_API_TOKEN environment variable (never from a file in the repository).
# Token permissions: Zone Settings Edit, Zone WAF Edit, for this zone only.
provider "cloudflare" {}
