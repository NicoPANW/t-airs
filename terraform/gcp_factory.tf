resource "google_compute_network" "t_airs_vpc" {
  count                   = var.target_cloud == "gcp" ? 1 : 0
  name                    = var.gcp_vpc_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "t_airs_sub" {
  count         = var.target_cloud == "gcp" ? 1 : 0
  name          = "${var.gcp_vpc_name}-sub"
  ip_cidr_range = var.gcp_subnet_cidr
  region        = var.gcp_region
  network       = google_compute_network.t_airs_vpc[0].id
}

resource "google_compute_firewall" "restricted_access" {
  count   = var.target_cloud == "gcp" ? 1 : 0
  name    = "t-airs-restricted-firewall"
  network = google_compute_network.t_airs_vpc[0].name

  allow {
    protocol = "tcp"
    ports    = ["8000", "11434", "22"]
  }
  source_ranges = local.allowed_ingress
}

resource "google_compute_instance" "t_airs_node" {
  count        = var.target_cloud == "gcp" ? 1 : 0
  name         = "t-airs-production-node"
  zone         = "${var.gcp_region}-a"

  # DYNAMIC FLAVOR: N1 for GPU, E2 for CPU-only
  machine_type = var.enable_local_llm ? "n1-standard-4" : "e2-standard-2"

  # DYNAMIC GPU: Only attach the T4 if enable_local_llm is true
  dynamic "guest_accelerator" {
    for_each = var.enable_local_llm ? [1] : []
    content {
      type  = "nvidia-tesla-t4"
      count = 1
    }
  }

  # DYNAMIC SCHEDULING: GPUs require TERMINATE, CPUs can use MIGRATE
  scheduling {
    on_host_maintenance = var.enable_local_llm ? "TERMINATE" : "MIGRATE"
  }

  boot_disk {
    initialize_params { 
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.enable_local_llm ? 50 : 20 
    }
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = local.userdata

  network_interface {
    subnetwork = google_compute_subnetwork.t_airs_sub[0].id
    access_config {} # Assign Public IP
  }
}
