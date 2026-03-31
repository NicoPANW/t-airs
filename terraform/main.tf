terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    google = { source = "hashicorp/google", version = "~> 5.0" }
    http   = { source = "hashicorp/http", version = "~> 3.0" }
  }
}

# --- AWS Provider (Mocks if targeting GCP) ---
provider "aws" { 
  region = var.aws_region 

  access_key                  = var.target_cloud == "aws" ? null : "mock_access_key"
  secret_key                  = var.target_cloud == "aws" ? null : "mock_secret_key"
  skip_credentials_validation = var.target_cloud == "aws" ? false : true
  skip_requesting_account_id  = var.target_cloud == "aws" ? false : true
  skip_metadata_api_check     = var.target_cloud == "aws" ? false : true
}

# --- GCP Provider (Mocks if targeting AWS) ---
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region

  # Feeds a fake OAuth token if we are deploying to AWS so it bypasses local auth checks
  access_token = var.target_cloud == "gcp" ? null : "ya29.mock_token_for_aws_deployments_only"
}

# --- Global Logic ---

# Auto-detect your local machine's public IPv4 address
data "http" "my_ip" {
  url = "https://ipv4.icanhazip.com"
}

locals {
  # 1. Get the exact IP (e.g., "202.181.130.201")
  raw_ip = chomp(data.http.my_ip.response_body)
  
  # 2. Dynamically convert it to a /24 subnet to handle ISP NAT pooling (e.g., "202.181.130.0/24")
  my_auto_subnet = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  
  # 3. Combine your dynamic subnet with Prisma's IPs
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  # Inject variables into the bootstrap script
  userdata = templatefile("${path.module}/bootstrap.sh", {
    airs_key     = var.airs_key
    airs_profile = var.airs_profile
    gcp_project  = var.gcp_project_id
    gcp_region   = var.gcp_region
    enable_local_llm = var.enable_local_llm
    target_cloud     = var.target_cloud
    aws_region       = var.aws_region
    bedrock_model_id = var.bedrock_model_id
  })
}
