locals {
  kubernetes_version       = "1.28.3"
  cluster_name             = "gh-sks-cluster" # Must be unique for each DevOps Stack deployment in a single account.
  zone                     = "ch-gva-2"
  service_level            = "starter"
  base_domain              = "is-sandbox-exo.camptocamp.com"
  activate_wildcard_record = true
  cluster_issuer           = module.cert-manager.cluster_issuers.staging
  enable_service_monitor   = false # Can be enabled after the first bootstrap
  app_autosync             = true ? { allow_empty = false, prune = true, self_heal = true } : {}
}
