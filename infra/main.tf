terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = var.project_name
      Course  = "UCS531"
    }
  }
}

locals {
  name       = var.project_name
  account_id = data.aws_caller_identity.current.account_id

  # WAF rule metric names, also passed to the app for sampled requests.
  waf_metrics = {
    rate      = "${local.name}-rate-limit"
    aws_sqli  = "${local.name}-aws-sqli"
    custom    = "${local.name}-custom-sqli"
    bad_input = "${local.name}-known-bad-inputs"
  }
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}
