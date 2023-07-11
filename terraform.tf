terraform {
  # We could store the state file on an Exoscale bucket, but there is no DynamoDB equivalent neither encryption, as far as I know.
  # https://github.com/exoscale/terraform-provider-exoscale/tree/master/examples/sos-backend
  backend "s3" {
    encrypt        = true
    bucket         = "camptocamp-aws-is-sandbox-terraform-state"
    key            = "c511a348-7464-4250-b57a-bf12b5eda7be"
    region         = "eu-west-1"
    dynamodb_table = "camptocamp-aws-is-sandbox-terraform-statelock"
  }

  required_providers {
    exoscale = {
      source  = "exoscale/exoscale"
      version = "~> 0.47"
    }
    aws = { # Needed to store the state file in S3 and to create S3 buckets (provider configuration bellow)
      source  = "hashicorp/aws"
      version = "~> 4"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2"
    }
    argocd = {
      source  = "oboukili/argocd"
      version = "~> 5"
    }
    keycloak = {
      source  = "mrparkers/keycloak"
      version = "~> 4"
    }
  }
}

provider "aws" {
  endpoints {
    s3 = "https://sos-${local.zone}.exo.io"
  }

  region = local.zone

  access_key = var.exoscale_iam_key
  secret_key = var.exoscale_iam_secret

  # Skip validations specific to AWS in order to use this provider for Exoscale services
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
