# Dynamically fetch the latest Canonical Ubuntu 24.04 AMI
data "aws_ami" "ubuntu_standard" {
  count       = var.target_cloud == "aws" ? 1 : 0
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

# Dynamically fetch the AWS Deep Learning AMI
data "aws_ami" "ubuntu_dlami" {
  count       = var.target_cloud == "aws" ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 22.04)*"]
  }
}

resource "aws_vpc" "t_airs_vpc" {
  count      = var.target_cloud == "aws" ? 1 : 0
  cidr_block = var.aws_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags       = { Name = "t-airs-vpc-aws" }
}

resource "aws_key_pair" "my_mac_key" {
  count      = var.target_cloud == "aws" ? 1 : 0
  key_name   = "t-airs-mac-key"
  public_key = file("~/.ssh/id_ed25519.pub") 
}

resource "aws_internet_gateway" "gw" {
  count  = var.target_cloud == "aws" ? 1 : 0
  vpc_id = aws_vpc.t_airs_vpc[0].id
}

resource "aws_route_table" "public_rt" {
  count  = var.target_cloud == "aws" ? 1 : 0
  vpc_id = aws_vpc.t_airs_vpc[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw[0].id
  }
}

resource "aws_subnet" "main" {
  count                   = var.target_cloud == "aws" ? 1 : 0
  vpc_id                  = aws_vpc.t_airs_vpc[0].id
  cidr_block              = var.aws_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
}

resource "aws_route_table_association" "public_assoc" {
  count          = var.target_cloud == "aws" ? 1 : 0
  subnet_id      = aws_subnet.main[0].id
  route_table_id = aws_route_table.public_rt[0].id
}

resource "aws_security_group" "restricted_airs" {
  count  = var.target_cloud == "aws" ? 1 : 0
  vpc_id = aws_vpc.t_airs_vpc[0].id

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

resource "aws_instance" "t_airs_node" {
  count                  = var.target_cloud == "aws" ? 1 : 0
  ami = var.enable_local_llm ? data.aws_ami.ubuntu_dlami[0].id : data.aws_ami.ubuntu_standard[0].id
  
  # DYNAMIC FLAVOR: g4dn.xlarge (1x NVIDIA T4 GPU) if true, t3.medium (CPU) if false
  instance_type          = var.enable_local_llm ? "g4dn.xlarge" : "t3.medium"
  
  key_name               = aws_key_pair.my_mac_key[0].key_name
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile[0].name
  
  root_block_device {
    # DYNAMIC DISK: Local LLMs and NVIDIA drivers take massive space. 
    # 50GB for GPU mode, 20GB for CPU-only mode.
    volume_size           = var.enable_local_llm ? 50 : 20 
    volume_type           = "gp3"
    delete_on_termination = true
  }
  
  subnet_id              = aws_subnet.main[0].id
  vpc_security_group_ids = [aws_security_group.restricted_airs[0].id]
  user_data              = local.userdata
  tags = { Name = "T-AIRS-Production-Node" }
}

# 1. Create the IAM Role for the EC2 instance
resource "aws_iam_role" "ec2_bedrock_role" {
  count = var.target_cloud == "aws" ? 1 : 0
  name  = "t-airs-bedrock-role"

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

# 2. Give the Role permission to use Bedrock
resource "aws_iam_role_policy" "bedrock_access" {
  count = var.target_cloud == "aws" ? 1 : 0
  name  = "t-airs-bedrock-policy"
  role  = aws_iam_role.ec2_bedrock_role[0].id

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

# 3. Create the Instance Profile (The actual "ID Badge" we attach to the server)
resource "aws_iam_instance_profile" "ec2_profile" {
  count = var.target_cloud == "aws" ? 1 : 0
  name  = "t-airs-ec2-profile"
  role  = aws_iam_role.ec2_bedrock_role[0].name
}
