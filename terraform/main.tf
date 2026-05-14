# Terraform — AWS Security Infrastructure
# This template creates a basic secure VPC with monitoring

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC with private subnets
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Private subnet
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidr
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.project_name}-private-subnet"
    Environment = var.environment
  }
}

# Security group — least privilege
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "Security group for application — least privilege"
  vpc_id      = aws_vpc.main.id

  # Allow outbound HTTPS only
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound"
  }

  # No inbound from internet by default
  tags = {
    Name        = "${var.project_name}-app-sg"
    Environment = var.environment
  }
}

# CloudWatch log group for monitoring
resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/${var.project_name}"
  retention_in_days = 30

  tags = {
    Environment = var.environment
    Application = var.project_name
  }
}

# CloudTrail for audit logging
resource "aws_cloudtrail" "audit" {
  name                          = "${var.project_name}-audit-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  tags = {
    Environment = var.environment
    Purpose     = "security-audit"
  }
}

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "trail" {
  bucket        = "${var.project_name}-audit-logs-${var.environment}"
  force_destroy = false

  tags = {
    Environment = var.environment
    Purpose     = "audit-logs"
  }
}

# Block public access to audit bucket
resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
