terraform {
  required_providers {
    google   = { source = "hashicorp/google", version = "~> 5.0" }
    http     = { source = "hashicorp/http", version = "~> 3.0" }
    external = { source = "hashicorp/external", version = "~> 2.0" }
  }
}

# --- Standard GCP Provider ---
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# --- Global Logic ---
data "http" "my_ip" {
  url = "https://ipv4.icanhazip.com"
}

locals {
  raw_ip = chomp(data.http.my_ip.response_body)
  my_auto_subnet = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    airs_key         = var.airs_key
    airs_profile     = var.airs_profile
    gcp_project      = var.gcp_project_id
    gcp_region       = var.gcp_region
    enable_local_llm = var.enable_local_llm
    target_cloud     = "gcp"
  })
}

# --- GCP Image Data Sources ---
data "google_compute_image" "ubuntu_standard_gcp" {
  family  = "ubuntu-2404-lts-amd64"    
  project = "ubuntu-os-cloud"
}

data "external" "latest_dlvm_family" {
  program = [
    "bash", "-e", "-c",
    "FAMILY=$(gcloud compute images list --project=deeplearning-platform-release --format='value(family)' | grep -i 'ubuntu-2204' | grep 'common-cu' | sort -r | head -n 1) && printf '{\"family\": \"%s\"}' \"$FAMILY\""
  ]
}

data "google_compute_image" "ubuntu_dlvm_gcp" {
  family  = data.external.latest_dlvm_family.result.family
  project = "deeplearning-platform-release"
}

# --- GCP Networking Resources ---
resource "google_compute_network" "t_airs_vpc" {
  name                    = var.gcp_vpc_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "t_airs_sub" {
  name          = "${var.gcp_vpc_name}-sub"
  ip_cidr_range = var.gcp_subnet_cidr
  region        = var.gcp_region
  network       = google_compute_network.t_airs_vpc.id
}

resource "google_compute_firewall" "restricted_access" {
  name    = "t-airs-restricted-firewall"
  network = google_compute_network.t_airs_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8000", "11434", "22"]
  }
  source_ranges = local.allowed_ingress
}

# ==========================================
# 🌟 NEW: GCP IAM & Service Accounts
# ==========================================

# 1. Create a dedicated identity for the T-AIRS VM
resource "google_service_account" "t_airs_sa" {
  account_id   = "t-airs-vertex-sa"
  display_name = "T-AIRS Application Identity"
}

# 2. Grant the identity permission to generate AI content via Vertex
resource "google_project_iam_member" "vertex_access" {
  project = var.gcp_project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.t_airs_sa.email}"
}

# --- GCP Compute Instance ---
resource "google_compute_instance" "t_airs_node" {
  name         = "t-airs-node"
  zone         = "${var.gcp_region}-a"
  machine_type = var.enable_local_llm ? "n1-standard-4" : "e2-standard-2"

  dynamic "guest_accelerator" {
    for_each = var.enable_local_llm ? [1] : []
    content {
      type  = "nvidia-tesla-t4"
      count = 1
    }
  }

  scheduling {
    on_host_maintenance = var.enable_local_llm ? "TERMINATE" : "MIGRATE"
  }

  boot_disk {
    initialize_params { 
      image = var.enable_local_llm ? data.google_compute_image.ubuntu_dlvm_gcp.self_link : data.google_compute_image.ubuntu_standard_gcp.self_link
      size  = var.enable_local_llm ? 50 : 20 
    }
  }

  # 🌟 FIXED: Replaced the default compute account with our new secure identity
  service_account {
    email  = google_service_account.t_airs_sa.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = local.userdata

  network_interface {
    subnetwork = google_compute_subnetwork.t_airs_sub.id
    access_config {} # Assign Public IP
  }
}