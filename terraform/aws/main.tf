# ==========================================
# TERRAFORM & PROVIDER CONFIGURATION
# ==========================================

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    http   = { source = "hashicorp/http", version = "~> 3.0" }
    tls    = { source = "hashicorp/tls", version = "~> 4.0" }
    local  = { source = "hashicorp/local", version = "~> 2.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

provider "aws" {
  region = var.aws_region
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

# Optional pre-allocated Elastic IPs for persistent public endpoints
data "aws_eip" "app_eip" {
  count     = var.static_ip != "" ? 1 : 0
  public_ip = startswith(var.static_ip, "eipalloc-") ? null : var.static_ip
  id        = startswith(var.static_ip, "eipalloc-") ? var.static_ip : null
}

data "aws_eip" "mcp_eip" {
  count     = var.mcp_static_ip != "" ? 1 : 0
  public_ip = startswith(var.mcp_static_ip, "eipalloc-") ? null : var.mcp_static_ip
  id        = startswith(var.mcp_static_ip, "eipalloc-") ? var.mcp_static_ip : null
}

locals {
  env = terraform.workspace == "default" ? "prod" : terraform.workspace

  raw_ip          = chomp(data.http.my_ip.response_body)
  my_auto_subnet  = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  effective_mcp_token = var.mcp_auth_token != "" ? var.mcp_auth_token : random_password.mcp_token.result

  app_public_ip = var.static_ip != "" ? data.aws_eip.app_eip[0].public_ip : aws_instance.t_airs_node.public_ip
  mcp_public_ip = var.mcp_static_ip != "" ? data.aws_eip.mcp_eip[0].public_ip : aws_instance.t_airs_mcp.public_ip

  # Bootstrap template for the dedicated Remote MCP Server EC2 instance
  mcp_userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    node_role         = "mcp"
    airs_key          = ""
    airs_profile      = ""
    gcp_project       = ""
    gcp_region        = ""
    env               = local.env
    target_cloud      = "aws"
    gateway_provider  = var.gateway_provider
    portkey_api_key   = ""
    portkey_slug      = ""
    portkey_mcp_slug  = var.portkey_mcp_slug
    mcp_gateway_url   = ""
    mcp_internal_ip   = "0.0.0.0"
    mcp_port          = tostring(var.mcp_port)
    mcp_auth_token    = local.effective_mcp_token
    aws_region        = var.aws_region
    bedrock_model_ids = ""
  })

  # Bootstrap template for the AI Agent / Web UI EC2 instance
  app_userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    node_role         = "app"
    airs_key          = var.airs_key
    airs_profile      = var.airs_profile
    gcp_project       = ""
    gcp_region        = ""
    env               = local.env
    target_cloud      = "aws"
    gateway_provider  = var.gateway_provider
    portkey_api_key   = var.portkey_api_key
    portkey_slug      = var.portkey_slug
    portkey_mcp_slug  = var.portkey_mcp_slug
    mcp_gateway_url   = var.mcp_gateway_url
    mcp_internal_ip   = aws_instance.t_airs_mcp.private_ip
    mcp_port          = tostring(var.mcp_port)
    mcp_auth_token    = local.effective_mcp_token
    aws_region        = var.aws_region
    bedrock_model_ids = join(" ", var.bedrock_model_ids)
  })
}

# ==========================================
# AWS AMI (MACHINE IMAGE) SELECTION
# ==========================================

data "aws_ami" "ubuntu_standard" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

# ==========================================
# AWS NETWORKING (SHARED VPC)
# ==========================================

resource "aws_vpc" "t_airs_vpc" {
  cidr_block           = var.aws_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "t-airs-vpc-aws-${local.env}" }
}

# =================================================
# DYNAMIC SSH KEY GENERATION & MANAGEMENT
# =================================================

resource "tls_private_key" "t_airs_key" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "generated_key" {
  key_name   = "t-airs-dynamic-key-${local.env}"
  public_key = tls_private_key.t_airs_key.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.t_airs_key.private_key_openssh
  filename        = "${path.module}/t-airs-key-${local.env}.pem"
  file_permission = "0400"
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.t_airs_vpc.id
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.t_airs_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.t_airs_vpc.id
  cidr_block              = var.aws_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  tags                    = { Name = "t-airs-subnet-aws-${local.env}" }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group for the App / Agent EC2 instance (Web UI + SSH)
resource "aws_security_group" "restricted_airs" {
  name   = "t-airs-restricted-sg-${local.env}"
  vpc_id = aws_vpc.t_airs_vpc.id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = local.allowed_ingress
  }

  ingress {
    from_port   = 11434
    to_port     = 11434
    protocol    = "tcp"
    cidr_blocks = local.allowed_ingress
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.my_auto_subnet]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for the Remote MCP EC2 instance:
# SSH strictly locked to your subnet; MCP HTTP port protected by Bearer token auth.
resource "aws_security_group" "mcp_sg" {
  name   = "t-airs-mcp-sg-${local.env}"
  vpc_id = aws_vpc.t_airs_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.my_auto_subnet]
  }

  ingress {
    from_port   = var.mcp_port
    to_port     = var.mcp_port
    protocol    = "tcp"
    cidr_blocks = distinct(concat(var.mcp_allowed_cidrs, [var.aws_vpc_cidr]))
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ==========================================
# AWS COMPUTE & IAM (SAME VPC)
# ==========================================

# 1. Dedicated Remote SQLite MCP Server EC2 Instance
resource "aws_instance" "t_airs_mcp" {
  ami           = data.aws_ami.ubuntu_standard.id
  instance_type = "t3.small"
  key_name      = aws_key_pair.generated_key.key_name

  root_block_device {
    volume_size           = 15
    volume_type           = "gp3"
    delete_on_termination = true
  }

  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.mcp_sg.id]
  user_data              = local.mcp_userdata
  tags                   = { Name = "t-airs-mcp-${local.env}" }
}

resource "aws_eip_association" "mcp_eip_assoc" {
  count         = var.mcp_static_ip != "" ? 1 : 0
  instance_id   = aws_instance.t_airs_mcp.id
  allocation_id = data.aws_eip.mcp_eip[0].id
}

# 2. Main AI Agent & FastAPI UI EC2 Instance
resource "aws_instance" "t_airs_node" {
  ami                  = data.aws_ami.ubuntu_standard.id
  instance_type        = "t3.large"
  key_name             = aws_key_pair.generated_key.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.restricted_airs.id]
  user_data              = local.app_userdata
  tags                   = { Name = "t-airs-node-${local.env}" }
}

resource "aws_eip_association" "app_eip_assoc" {
  count         = var.static_ip != "" ? 1 : 0
  instance_id   = aws_instance.t_airs_node.id
  allocation_id = data.aws_eip.app_eip[0].id
}

resource "aws_iam_role" "ec2_bedrock_role" {
  name = "t-airs-bedrock-role-${local.env}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "bedrock_access" {
  name = "t-airs-bedrock-policy-${local.env}"
  role = aws_iam_role.ec2_bedrock_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "bedrock:InvokeModel",
          "bedrock:Converse"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "t-airs-ec2-profile-${local.env}"
  role = aws_iam_role.ec2_bedrock_role.name
}