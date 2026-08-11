# ==========================================
# TERRAFORM & PROVIDER CONFIGURATION
# ==========================================

# Defines the required providers for this configuration.
terraform {
  required_providers {
    google   = { source = "hashicorp/google", version = "~> 5.0" }   # For managing GCP resources.
    http     = { source = "hashicorp/http", version = "~> 3.0" }     # For making HTTP requests (e.g., to get public IP).
    external = { source = "hashicorp/external", version = "~> 2.0" } # For running external programs (like gcloud CLI).
  }
}

# Configures the Google Cloud provider with the specified project and region.
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ==========================================
# GLOBAL LOGIC & DATA SOURCES
# ==========================================

# Fetches the public IP of the machine running Terraform to automatically allow SSH access.
data "http" "my_ip" {
  url = "https://ipv4.icanhazip.com"
}

locals {
  # Use terraform workspace to distinguish environments. 'default' workspace is considered production.
  env = terraform.workspace == "default" ? "prod" : terraform.workspace

  # Cleans up the fetched IP address.
  raw_ip = chomp(data.http.my_ip.response_body)
  # Creates a /24 subnet from the user's public IP for the firewall source range.
  my_auto_subnet = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  # Combines the user's IP with Prisma AIRS IPs for the firewall ingress rules.
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  # Renders the bootstrap script, passing in all necessary variables for the GCP environment.
  # Unused AWS variables are passed as empty strings to satisfy the template.
  userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    airs_key         = var.airs_key
    airs_profile     = var.airs_profile
    gcp_project      = var.gcp_project_id
    gcp_region       = var.gcp_region
    env              = local.env
    target_cloud     = "gcp"
    aws_region       = "" # Not used in GCP deployment
    bedrock_model_ids = "" # Not used in GCP deployment
  })
}

# ==========================================
# GCP IMAGE (MACHINE IMAGE) SELECTION
# ==========================================

# Finds the latest Ubuntu 24.04 LTS server image for standard (non-GPU) instances.
data "google_compute_image" "ubuntu_standard_gcp" {
  family  = "ubuntu-2404-lts-amd64"    
  project = "ubuntu-os-cloud"
}


# ==========================================
# GCP NETWORKING
# ==========================================

# Creates a dedicated Virtual Private Cloud (VPC) network for the application.
resource "google_compute_network" "t_airs_vpc" {
  name                    = "${var.gcp_vpc_name}-${local.env}"
  auto_create_subnetworks = false
}

# Creates a subnet within the VPC.
resource "google_compute_subnetwork" "t_airs_sub" {
  name          = "${var.gcp_vpc_name}-sub-${local.env}"
  ip_cidr_range = var.gcp_subnet_cidr
  region        = var.gcp_region
  network       = google_compute_network.t_airs_vpc.id
}

# Defines a firewall rule to allow specific ingress traffic to the instances.
resource "google_compute_firewall" "restricted_access" {
  name    = "t-airs-restricted-firewall-${local.env}"
  network = google_compute_network.t_airs_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8000", "11434", "22"]
  }
  # Allows access only from the user's IP and the Prisma AIRS IPs.
  source_ranges = local.allowed_ingress
}

# ==========================================
# IAM & SERVICE ACCOUNT FOR VERTEX AI ACCESS
# ==========================================

# 1. Creates a dedicated service account to provide a unique identity for the VM.
# This follows the principle of least privilege.
resource "google_service_account" "t_airs_sa" {
  account_id   = "t-airs-vertex-sa-${local.env}"
  display_name = "T-AIRS Application Identity (${local.env})"
}

# 2. Grants the service account the 'Vertex AI User' role.
# This allows the application running on the VM to make calls to the Vertex AI API (e.g., Gemini).
resource "google_project_iam_member" "vertex_access" {
  project = var.gcp_project_id # Role is assigned at the project level
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.t_airs_sa.email}"
}

# ==========================================
# GCP COMPUTE INSTANCE
# ==========================================

# Defines the GCE instance that will run the application.
# Note: Do not scale down flavors, otherwise it won't work for laoding BAAI/bge-small-en-v1.5) for RAG
resource "google_compute_instance" "t_airs_node" {
  name         = "t-airs-node-${local.env}"
  zone         = "${var.gcp_region}-a"
  machine_type = "e2-standard-2"

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu_standard_gcp.self_link
      size  = 20
    }
  }

  # Attaches the dedicated service account to the instance.
  service_account {
    email  = google_service_account.t_airs_sa.email
    scopes = ["cloud-platform"]
  }

  # Injects the bootstrap script to run on instance startup.
  metadata_startup_script = local.userdata

  network_interface {
    subnetwork = google_compute_subnetwork.t_airs_sub.id
    access_config {} # An empty access_config block assigns an ephemeral public IP.
  }
}
