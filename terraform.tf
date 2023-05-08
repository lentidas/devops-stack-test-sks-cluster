terraform {
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
    # TODO Consider storing the state file in a remote Exoscale backend instead of AWS
    aws = { # Needed to store the state file in S3
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
      version = "~> 4"
    }
  }
}
