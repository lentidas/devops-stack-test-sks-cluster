locals {
  kubernetes_version     = "1.26.4"
  cluster_name           = "gh-sks-cluster"
  zone                   = "ch-gva-2"
  base_domain            = "sks-sandbox.camptocamp.com"
  cluster_issuer         = "letsencrypt-staging"
  enable_service_monitor = false # Can be enabled after the first bootstrap
}
