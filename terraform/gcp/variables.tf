# ==========================================
# GLOBAL VARIABLES
# ==========================================
variable "prisma_airs_ips" {
  description = "List of official Prisma AIRS Egress IPs"
  type        = list(string)
  default = [
    "3.210.133.47/32",
    "34.235.13.250/32",
    "34.75.54.101/32",
    "35.185.127.202/32",
    "35.197.73.227/32",
    "104.198.97.107/32",
    "136.117.114.204/32"
  ]
}

variable "gateway_provider" {
  description = "AI Gateway Provider (portkey or litellm)"
  type        = string
  default     = "portkey"
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

variable "static_ip" {
  description = "Optional pre-allocated static external IP for the App VM. If empty, an ephemeral IP is used."
  type        = string
  default     = ""
}

variable "mcp_static_ip" {
  description = "Optional pre-allocated static external IP for the remote MCP VM. If empty, an ephemeral IP is used."
  type        = string
  default     = ""
}

variable "portkey_api_key" {
  description = "Prisma AIRS AI Gateway (Portkey) API Key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "portkey_slug" {
  description = "Prisma AIRS AI Gateway LLM Integration Slug (e.g. @slug-name)"
  type        = string
  default     = ""
}

variable "portkey_mcp_slug" {
  description = "Prisma AIRS AI Gateway MCP Server Slug registered in MCP Registry"
  type        = string
  default     = "t-airs-sqlite"
}

variable "mcp_gateway_url" {
  description = "Optional full MCP Gateway URL override (e.g. for self-hosted Prisma AIRS AI Gateway in VPC)"
  type        = string
  default     = ""
}

variable "mcp_port" {
  description = "Listening TCP port for the remote MCP Streamable HTTP server"
  type        = number
  default     = 8080
}

variable "mcp_auth_token" {
  description = "Bearer token protecting the remote MCP VM (Passed via TF_VAR_mcp_auth_token). Leave empty to auto-generate."
  type        = string
  default     = ""
  sensitive   = true
}