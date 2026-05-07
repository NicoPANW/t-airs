terraform {
  required_providers {
    aws   = { source = "hashicorp/aws", version = "~> 5.0" }
    http  = { source = "hashicorp/http", version = "~> 3.0" }
    tls   = { source = "hashicorp/tls", version = "~> 4.0" }
    local = { source = "hashicorp/local", version = "~> 2.0" }
  }
}


provider "aws" { 
  region = var.aws_region 
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
    gcp_project      = ""
    gcp_region       = ""
    enable_local_llm = var.enable_local_llm
    target_cloud     = "aws" 
    aws_region       = var.aws_region
    bedrock_model_id = var.bedrock_model_id
  })
}

# --- AWS AMI Data Sources ---
data "aws_ami" "ubuntu_standard" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

data "aws_ami" "ubuntu_dlami" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 22.04)*"]
  }
}

# --- AWS Networking ---
resource "aws_vpc" "t_airs_vpc" {
  cidr_block           = var.aws_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "t-airs-vpc-aws" }
}

# ==========================================
# Dynamic SSH Key Generation
# ==========================================

# 1. Generate a shiny new ED25519 key pair on the fly
resource "tls_private_key" "t_airs_key" {
  algorithm = "ED25519"
}

# 2. Upload the Public Key to AWS
resource "aws_key_pair" "generated_key" {
  key_name   = "t-airs-dynamic-key"
  public_key = tls_private_key.t_airs_key.public_key_openssh
}

# 3. Save the Private Key locally so the user can actually SSH in!
resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.t_airs_key.private_key_openssh
  filename        = "${path.module}/t-airs-key.pem"
  file_permission = "0400" # Strict read-only permissions required by SSH
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
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "restricted_airs" {
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

# --- AWS Compute & IAM ---
resource "aws_instance" "t_airs_node" {
  ami = var.enable_local_llm ? data.aws_ami.ubuntu_dlami.id : data.aws_ami.ubuntu_standard.id
  
  instance_type        = var.enable_local_llm ? "g4dn.xlarge" : "t3.large"
  key_name = aws_key_pair.generated_key.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  
  root_block_device {
    volume_size           = var.enable_local_llm ? 75 : 20 
    volume_type           = "gp3"
    delete_on_termination = true
  }
  
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.restricted_airs.id]
  user_data              = local.userdata
  tags                   = { Name = "T-AIRS-Production-Node" }
}

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

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "t-airs-ec2-profile"
  role = aws_iam_role.ec2_bedrock_role.name
}