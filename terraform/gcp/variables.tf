# ==========================================
# TERRAFORM & PROVIDER CONFIGURATION
# ==========================================

terraform {
  required_providers {
    google   = { source = "hashicorp/google", version = "~> 5.0" }
    http     = { source = "hashicorp/http", version = "~> 3.0" }
    external = { source = "hashicorp/external", version = "~> 2.0" }
    random   = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ==========================================
# GLOBAL LOGIC & DATA SOURCES
# ==========================================

data "http" "my_ip" {
  url = "https://ipv4.icanhazip.com"
}

resource "random_password" "mcp_token" {
  length  = 32
  special = false
}

locals {
  env = terraform.workspace == "default" ? "prod" : terraform.workspace

  raw_ip          = chomp(data.http.my_ip.response_body)
  my_auto_subnet  = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  effective_mcp_token = var.mcp_auth_token != "" ? var.mcp_auth_token : random_password.mcp_token.result

  # Bootstrap template for the dedicated Remote MCP Server VM
  mcp_userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    node_role         = "mcp"
    airs_key          = ""
    airs_profile      = ""
    gcp_project       = var.gcp_project_id
    gcp_region        = var.gcp_region
    env               = local.env
    target_cloud      = "gcp"
    gateway_provider  = var.gateway_provider
    portkey_api_key   = ""
    portkey_slug      = ""
    portkey_mcp_slug  = var.portkey_mcp_slug
    mcp_gateway_url   = ""
    mcp_internal_ip   = "0.0.0.0"
    mcp_port          = tostring(var.mcp_port)
    mcp_auth_token    = local.effective_mcp_token
    aws_region        = ""
    bedrock_model_ids = ""
  })

  # Bootstrap template for the AI Agent / Web UI VM
  app_userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    node_role         = "app"
    airs_key          = var.airs_key
    airs_profile      = var.airs_profile
    gcp_project       = var.gcp_project_id
    gcp_region        = var.gcp_region
    env               = local.env
    target_cloud      = "gcp"
    gateway_provider  = var.gateway_provider
    portkey_api_key   = var.portkey_api_key
    portkey_slug      = var.portkey_slug
    portkey_mcp_slug  = var.portkey_mcp_slug
    mcp_gateway_url   = var.mcp_gateway_url
    mcp_internal_ip   = google_compute_instance.t_airs_mcp.network_interface[0].network_ip
    mcp_port          = tostring(var.mcp_port)
    mcp_auth_token    = local.effective_mcp_token
    aws_region        = ""
    bedrock_model_ids = ""
  })
}

# ==========================================
# GCP IMAGE (MACHINE IMAGE) SELECTION
# ==========================================

data "google_compute_image" "ubuntu_standard_gcp" {
  family  = "ubuntu-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

# ==========================================
# GCP NETWORKING (SHARED VPC)
# ==========================================

resource "google_compute_network" "t_airs_vpc" {
  name                    = "${var.gcp_vpc_name}-${local.env}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "t_airs_sub" {
  name          = "${var.gcp_vpc_name}-sub-${local.env}"
  ip_cidr_range = var.gcp_subnet_cidr
  region        = var.gcp_region
  network       = google_compute_network.t_airs_vpc.id
}

# Firewall for the App / Agent VM (Web UI + SSH)
resource "google_compute_firewall" "restricted_access" {
  name    = "t-airs-restricted-firewall-${local.env}"
  network = google_compute_network.t_airs_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8000", "11434", "22"]
  }

  target_tags   = ["t-airs-app"]
  source_ranges = local.allowed_ingress
}

# Firewall 1 for Remote MCP VM: SSH strictly restricted to admin subnet + Prisma AIRS scanner IPs
resource "google_compute_firewall" "mcp_ssh_access" {
  name    = "t-airs-mcp-ssh-${local.env}"
  network = google_compute_network.t_airs_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  target_tags   = ["t-airs-mcp"]
  source_ranges = local.allowed_ingress
}

# Firewall 2 for Remote MCP VM: MCP Streamable HTTP endpoint (protected by Bearer token auth)
resource "google_compute_firewall" "mcp_http_access" {
  name    = "t-airs-mcp-http-${local.env}"
  network = google_compute_network.t_airs_vpc.name

  allow {
    protocol = "tcp"
    ports    = [tostring(var.mcp_port)]
  }

  target_tags   = ["t-airs-mcp"]
  source_ranges = distinct(concat(var.mcp_allowed_cidrs, [var.gcp_subnet_cidr]))
}

# ==========================================
# IAM & SERVICE ACCOUNT FOR VERTEX AI ACCESS
# ==========================================

resource "google_service_account" "t_airs_sa" {
  account_id   = "t-airs-vertex-sa-${local.env}"
  display_name = "T-AIRS Application Identity (${local.env})"
}

resource "google_project_iam_member" "vertex_access" {
  project = var.gcp_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.t_airs_sa.email}"
}

# ==========================================
# GCP COMPUTE INSTANCES (SAME VPC)
# ==========================================

# 1. Dedicated Remote SQLite MCP Server VM
resource "google_compute_instance" "t_airs_mcp" {
  name         = "t-airs-mcp-${local.env}"
  zone         = "${var.gcp_region}-a"
  machine_type = "e2-small"
  tags         = ["t-airs-mcp"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu_standard_gcp.self_link
      size  = 15
    }
  }

  metadata_startup_script = local.mcp_userdata

  network_interface {
    subnetwork = google_compute_subnetwork.t_airs_sub.id
    access_config {
      nat_ip = var.mcp_static_ip != "" ? var.mcp_static_ip : null
    }
  }
}

# 2. Main AI Agent & FastAPI UI VM
resource "google_compute_instance" "t_airs_node" {
  name         = "t-airs-node-${local.env}"
  zone         = "${var.gcp_region}-a"
  machine_type = "e2-standard-2"
  tags         = ["t-airs-app"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu_standard_gcp.self_link
      size  = 20
    }
  }

  service_account {
    email  = google_service_account.t_airs_sa.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = local.app_userdata

  network_interface {
    subnetwork = google_compute_subnetwork.t_airs_sub.id
    access_config {
      nat_ip = var.static_ip != "" ? var.static_ip : null
    }
  }
}