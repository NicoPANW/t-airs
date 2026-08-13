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
  description = "If true, deploys an instance with a T4 GPU and installs Ollama/Llama3."
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
# AWS-SPECIFIC VARIABLES
# ==========================================
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

variable "bedrock_model_ids" {
  description = "A list of AWS Bedrock model IDs to enable in the application."
  type        = list(string)
  default     = ["meta.llama3-8b-instruct-v1:0", "mistral.ministral-3-8b-instruct"]
}

variable "gateway_provider" {
  description = "AI Gateway Provider (portkey or litellm)"
  type        = string
  default     = "portkey"
}

variable "portkey_api_key" {
  description = "Portkey API Key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "portkey_slug" {
  description = "Portkey Slug (Saved Integration Virtual Key, e.g. @slug-name)"
  type        = string
  default     = ""
}

variable "portkey_virtual_key" {
  description = "Portkey Virtual Key"
  type        = string
  default     = ""
  sensitive   = true
}