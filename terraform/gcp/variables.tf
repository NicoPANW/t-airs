# ==========================================
# GLOBAL VARIABLES
# ==========================================
variable "prisma_airs_ips" {
  description = "List of official Prisma AIRS Egress IPs"
  type        = list(string)
  default     = [
    "3.210.133.47/32", 
    "34.235.13.250/32", 
    "34.75.54.101/32", 
    "35.185.127.202/32", 
    "35.197.73.227/32", 
    "104.198.97.107/32", 
    "136.117.114.204/32"
  ]
}

variable "enable_local_llm" {
  description = "If true, deploys an N1 instance with a T4 GPU and installs Ollama/Llama3."
  type        = bool
  default     = false
}

variable "airs_key" {
  description = "Prisma AIRS API Key (Passed via TF_VAR_airs_key)"
  type        = string
  sensitive   = true
}

variable "airs_profile" {
  description = "Prisma AIRS Security Profile"
  type        = string
  default     = "default"
}

# ==========================================
# GCP-SPECIFIC VARIABLES
# ==========================================
variable "gcp_project_id" {
  description = "The GCP Project ID (Passed via TF_VAR_gcp_project_id)"
  type        = string
}

variable "gcp_region" {
  description = "The GCP Region for Vertex AI"
  type        = string
  default     = "us-central1"
}

variable "gcp_vpc_name" {
  description = "Name of the GCP VPC"
  type        = string
  default     = "t-airs-vpc-gcp"
}

variable "gcp_subnet_cidr" {
  description = "CIDR block for the GCP Subnet"
  type        = string
  default     = "10.10.0.0/24"
}