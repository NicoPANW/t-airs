# ==========================================
# TERRAFORM & PROVIDER CONFIGURATION
# ==========================================

# Defines the required providers for this configuration.
terraform {
  required_providers {
    aws   = { source = "hashicorp/aws", version = "~> 5.0" }   # For managing AWS resources.
    http  = { source = "hashicorp/http", version = "~> 3.0" }   # For making HTTP requests (e.g., to get public IP).
    tls   = { source = "hashicorp/tls", version = "~> 4.0" }   # For generating cryptographic keys.
    local = { source = "hashicorp/local", version = "~> 2.0" } # For writing files to the local machine.
  }
}

# Configures the AWS provider with the specified region.
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
  # Use terraform workspace to distinguish environments. 'default' workspace is considered production.
  env = terraform.workspace == "default" ? "prod" : terraform.workspace

  # Cleans up the fetched IP address.
  raw_ip = chomp(data.http.my_ip.response_body)
  # Creates a /24 subnet from the user's public IP for SSH access.
  my_auto_subnet = "${regex("^([0-9]+\\.[0-9]+\\.[0-9]+\\.)", local.raw_ip)[0]}0/24"
  # Combines the user's IP with Prisma AIRS IPs for the security group ingress rules.
  allowed_ingress = concat([local.my_auto_subnet], var.prisma_airs_ips)

  # Renders the bootstrap script, passing in all necessary variables for the AWS environment.
  userdata = templatefile("${path.module}/../scripts/bootstrap.sh", {
    airs_key         = var.airs_key
    airs_profile     = var.airs_profile
    gcp_project      = ""
    gcp_region       = ""
    env              = local.env
    target_cloud     = "aws" 
    aws_region       = var.aws_region
    # Pass the list of models as a space-separated string for easy parsing in bash.
    bedrock_model_ids = join(" ", var.bedrock_model_ids)
  })
}

# ==========================================
# AWS AMI (MACHINE IMAGE) SELECTION
# ==========================================

# Finds the latest Ubuntu 24.04 LTS server image for standard (non-GPU) instances.
data "aws_ami" "ubuntu_standard" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
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
  tags                 = { Name = "t-airs-vpc-aws-${local.env}" }
}

# =================================================
# DYNAMIC SSH KEY GENERATION & MANAGEMENT
# =================================================

# 1. Generates a new, secure ED25519 key pair in memory during the Terraform run.
resource "tls_private_key" "t_airs_key" {
  algorithm = "ED25519"
}

# 2. Uploads the public part of the generated key to AWS EC2 Key Pairs.
resource "aws_key_pair" "generated_key" {
  key_name   = "t-airs-dynamic-key-${local.env}"
  public_key = tls_private_key.t_airs_key.public_key_openssh
}

# 3. Saves the private part of the key to a local file (`t-airs-key.pem`).
# This allows the user to SSH into the created instance.
resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.t_airs_key.private_key_openssh
  filename        = "${path.module}/t-airs-key-${local.env}.pem"
  file_permission = "0400" # Strict read-only permissions required by SSH
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
  tags                    = { Name = "t-airs-subnet-aws-${local.env}" }
}

# Associates the public route table with the main subnet.
resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.public_rt.id
}

# Defines a security group to act as a firewall for the EC2 instance.
resource "aws_security_group" "restricted_airs" {
  name   = "t-airs-restricted-sg-${local.env}"
  vpc_id = aws_vpc.t_airs_vpc.id

  # Allows ingress traffic for the web application from the user's IP and Prisma AIRS IPs.
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

# ==========================================
# AWS COMPUTE & IAM
# ==========================================

# Defines the EC2 instance that will run the application.
# Note: Do not scale down flavors, otherwise it won't work for laoding BAAI/bge-small-en-v1.5) for RAG
resource "aws_instance" "t_airs_node" {
  ami = data.aws_ami.ubuntu_standard.id
  
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
  user_data              = local.userdata
  tags                   = { Name = "t-airs-node-${local.env}" }
}

# Creates an IAM role that the EC2 instance can assume.
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

# Attaches a policy to the role granting permissions to invoke AWS Bedrock models.
# This allows the application to use Bedrock without hardcoded credentials.
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

# Creates an instance profile to attach the IAM role to the EC2 instance.
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "t-airs-ec2-profile-${local.env}"
  role = aws_iam_role.ec2_bedrock_role.name
}
