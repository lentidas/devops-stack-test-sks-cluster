locals {
  kubernetes_version     = "1.27.3"
  cluster_name           = "gh-sks-cluster"
  zone                   = "ch-gva-2"
  service_level          = "starter"
  base_domain            = "exoscale-sandbox.camptocamp.com"
  cluster_issuer         = "letsencrypt-staging"
  enable_service_monitor = false # Can be enabled after the first bootstrap
}
