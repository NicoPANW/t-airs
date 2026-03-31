# --- GLOBAL VARIABLES ---

variable "target_cloud" {
  description = "Which cloud to deploy to (gcp or aws)"
  type        = string
  default     = "gcp" 
}

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
  # NO DEFAULT - Required for both clouds.
}

variable "airs_profile" {
  description = "Prisma AIRS Security Profile"
  type        = string
  default     = "default"
}

# --- GCP VARIABLES ---

variable "gcp_project_id" {
  description = "The GCP Project ID (Passed via TF_VAR_gcp_project_id)"
  type        = string
  default     = "yours"
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

# --- AWS VARIABLES ---

variable "aws_region" {
  description = "The AWS Region for Bedrock"
  type        = string
  default     = "us-east-1"
}

variable "aws_vpc_cidr" {
  description = "CIDR block for the AWS VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aws_subnet_cidr" {
  description = "CIDR block for the AWS Subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "bedrock_model_id" {
  description = "The AWS Bedrock Model ID to deploy"
  type        = string
  default     = "meta.llama3-8b-instruct-v1:0"
}

