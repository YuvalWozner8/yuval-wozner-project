terraform {
  required_version = ">= 0.12"

  # =========================
  # SCA: Vulnerable provider version
  # =========================
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 3.19.0" # intentionally old & vulnerable
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# =========================
# SCA: Vulnerable public module version
# =========================
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.21.0" # very old version with known issues

  name = "insecure-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnets = ["10.0.101.0/24", "10.0.102.0/24"]
}

# =========================
# IaC: Public S3 bucket
# =========================
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-very-insecure-bucket-123456"
  acl    = "public-read"
}

# =========================
# IaC: Security group open to the world
# =========================
resource "aws_security_group" "open_sg" {
  name   = "open-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =========================
# IaC: Over-privileged IAM policy
# =========================
resource "aws_iam_policy" "wildcard" {
  name = "wildcard-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# =========================
# IaC: Public RDS with hardcoded creds
# =========================
resource "aws_db_instance" "public_db" {
  identifier          = "insecure-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "Admin12345!"
  publicly_accessible = true
  skip_final_snapshot = true
}

# =========================
# IaC: Secrets in user_data
# =========================
resource "aws_instance" "bad_ec2" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.open_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              echo "TOKEN=supersecrettoken" >> /etc/environment
              EOF
}