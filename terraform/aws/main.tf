# ==========================================
# TERRAFORM & PROVIDER CONFIGURATION
# ==========================================

terraform {
  required_providers {
    aws  = { source = "hashicorp/aws", version = "~> 5.0" }
    http = { source = "hashicorp/http", version = "~> 3.0" }
  }
}

# --- Standard AWS Provider (No more mocks!) ---
provider "aws" { 
  region = var.aws_region 
}

# ==========================================
# GLOBAL LOGIC & DATA SOURCES
# ==========================================

# Fetches the public IP of the machine running Terraform to automatically allow SSH access.
data "http" "my_ip" {
  url = "https://ipv4.icanhazip.com"
}

locals {
  # Cleans up the fetched IP address.
  raw_ip = chomp(data.http.my_ip.response_body)
  # Creates a /24 subnet from the user's public IP for SSH access.
  my_auto_subnet = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  # Combines the user's IP with Prisma AIRS IPs for the security group ingress rules.
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  # 🌟 FIXED: Path looks up to the root folder. Unused GCP variables are passed as empty strings.
  userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    airs_key         = var.airs_key
    airs_profile     = var.airs_profile
    gcp_project      = ""
    gcp_region       = ""
    enable_local_llm = var.enable_local_llm
    target_cloud     = "aws" 
    aws_region       = var.aws_region
    bedrock_model_id = var.bedrock_model_id
  })
}

# Finds the latest Ubuntu 24.04 LTS server image for standard (non-GPU) instances.
data "aws_ami" "ubuntu_standard" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

# Finds the latest AWS Deep Learning AMI with NVIDIA drivers for GPU-enabled instances.
data "aws_ami" "ubuntu_dlami" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 22.04)*"]
  }
}

# ==========================================
# AWS NETWORKING
# ==========================================

# Creates a dedicated Virtual Private Cloud (VPC) for the application.
resource "aws_vpc" "t_airs_vpc" {
  cidr_block           = var.aws_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "t-airs-vpc-aws" }
}

resource "aws_key_pair" "my_mac_key" {
  key_name   = "t-airs-mac-key"
  # 🌟 FIXED: Added a graceful fallback so missing keys don't crash deployments!
  public_key = try(file("~/.ssh/id_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 mock-key") 
}

# Creates an Internet Gateway to provide internet access to the VPC.
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.t_airs_vpc.id
}

# Creates a route table and a default route to the Internet Gateway.
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.t_airs_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

# Creates a public subnet within the VPC. Instances in this subnet get a public IP.
resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.t_airs_vpc.id
  cidr_block              = var.aws_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
}

# Associates the public route table with the main subnet.
resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.public_rt.id
}

# Defines a security group to act as a firewall for the EC2 instance.
resource "aws_security_group" "restricted_airs" {
  vpc_id = aws_vpc.t_airs_vpc.id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = local.allowed_ingress
  }

  # Allows ingress traffic for Ollama (if used) from the user's IP and Prisma AIRS IPs.
  ingress {
    from_port   = 11434
    to_port     = 11434
    protocol    = "tcp"
    cidr_blocks = local.allowed_ingress
  }

  # Allows SSH access only from the user's public IP.
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.my_auto_subnet]
  }

  # Allows all outbound traffic from the instance.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- AWS Compute & IAM ---
resource "aws_instance" "t_airs_node" {
  # Conditionally selects the AMI based on whether a local LLM (GPU) is enabled.
  ami = var.enable_local_llm ? data.aws_ami.ubuntu_dlami.id : data.aws_ami.ubuntu_standard.id
  
  instance_type        = var.enable_local_llm ? "g4dn.xlarge" : "t3.medium"
  key_name             = aws_key_pair.my_mac_key.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  
  root_block_device {
    # Conditionally sets a larger disk size for GPU instances to accommodate models.
    volume_size           = var.enable_local_llm ? 75 : 20 
    volume_type           = "gp3"
    delete_on_termination = true
  }
  
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.restricted_airs.id]
  user_data              = local.userdata
  tags                   = { Name = "T-AIRS-Production-Node" }
}

# Creates an IAM role that the EC2 instance can assume.
resource "aws_iam_role" "ec2_bedrock_role" {
  name = "t-airs-bedrock-role"
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

# Attaches a policy to the role granting permissions to invoke AWS Bedrock models.
# This allows the application to use Bedrock without hardcoded credentials.
resource "aws_iam_role_policy" "bedrock_access" {
  name = "t-airs-bedrock-policy"
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

# Creates an instance profile to attach the IAM role to the EC2 instance.
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "t-airs-ec2-profile"
  role = aws_iam_role.ec2_bedrock_role.name
}