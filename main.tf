module "sks" {
  source = "git::https://github.com/camptocamp/devops-stack-module-cluster-sks.git?ref=v1.1.0"

  cluster_name       = local.cluster_name
  kubernetes_version = local.kubernetes_version
  zone               = local.zone
  base_domain        = data.exoscale_domain.domain.name

  service_level = local.service_level
  # create_kubeconfig_file = true

  nodepools = {
    "${local.cluster_name}-default" = {
      size            = 3
      instance_type   = "standard.large"
      description     = "Default node pool for ${local.cluster_name}."
      instance_prefix = "default"
      disk_size       = 100
    },
  }
}

module "argocd_bootstrap" {
  source = "git::https://github.com/camptocamp/devops-stack-module-argocd.git//bootstrap?ref=v3.5.1"
  # source = "../../devops-stack-module-argocd/bootstrap"

  argocd_projects = {
    "${module.sks.cluster_name}" = {
      destination_cluster = "in-cluster"
    }
  }

  depends_on = [module.sks]
}

module "traefik" {
  source = "git::https://github.com/camptocamp/devops-stack-module-traefik.git//sks?ref=v4.1.0"
  # source = "../../devops-stack-module-traefik/sks"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  nlb_id                  = module.sks.nlb_id
  router_nodepool_id      = module.sks.router_nodepool_id
  router_instance_pool_id = module.sks.router_instance_pool_id

  app_autosync           = local.app_autosync
  enable_service_monitor = local.enable_service_monitor

  dependency_ids = {
    argocd = module.argocd_bootstrap.id
  }
}

module "cert-manager" {
  source = "git::https://github.com/camptocamp/devops-stack-module-cert-manager.git//sks?ref=v7.0.1"
  # source = "../../devops-stack-module-cert-manager/sks"

  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  letsencrypt_issuer_email = local.letsencrypt_issuer_email

  app_autosync           = local.app_autosync
  enable_service_monitor = local.enable_service_monitor


  dependency_ids = {
    argocd = module.argocd_bootstrap.id
  }
}

# TODO Create an external database as PoC
module "keycloak" {
  source = "git::https://github.com/camptocamp/devops-stack-module-keycloak.git?ref=v2.1.0"
  # source = "../../devops-stack-module-keycloak"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  app_autosync = local.app_autosync

  dependency_ids = {
    argocd       = module.argocd_bootstrap.id
    traefik      = module.traefik.id
    cert-manager = module.cert-manager.id
  }
}

module "oidc" {
  source = "git::https://github.com/camptocamp/devops-stack-module-keycloak.git//oidc_bootstrap?ref=v2.1.0"

  cluster_name   = module.sks.cluster_name
  base_domain    = module.sks.base_domain
  cluster_issuer = local.cluster_issuer

  user_map = {
    gheleno = {
      username   = "gheleno"
      email      = "goncalo.heleno@camptocamp.com"
      first_name = "Gonçalo"
      last_name  = "Heleno"
    },
  }

  dependency_ids = {
    keycloak = module.keycloak.id
  }
}

module "longhorn" {
  source = "git::https://github.com/camptocamp/devops-stack-module-longhorn.git?ref=v2.3.0"
  # source = "../../devops-stack-module-longhorn"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  app_autosync           = local.app_autosync
  enable_service_monitor = local.enable_service_monitor

  enable_dashboard_ingress = true
  oidc                     = module.oidc.oidc

  enable_pv_backups = true
  backup_storage = {
    bucket_name = resource.aws_s3_bucket.this["longhorn"].id
    region      = resource.aws_s3_bucket.this["longhorn"].region
    endpoint    = "sos-${resource.aws_s3_bucket.this["longhorn"].region}.exo.io"
    access_key  = resource.exoscale_iam_access_key.s3_iam_key["longhorn"].key
    secret_key  = resource.exoscale_iam_access_key.s3_iam_key["longhorn"].secret
  }

  dependency_ids = {
    argocd       = module.argocd_bootstrap.id
    traefik      = module.traefik.id
    cert-manager = module.cert-manager.id
    keycloak     = module.keycloak.id
    oidc         = module.oidc.id
  }
}

module "loki-stack" {
  source = "git::https://github.com/camptocamp/devops-stack-module-loki-stack.git//sks?ref=v6.0.0"
  # source = "../../devops-stack-module-loki-stack/sks"

  cluster_id       = module.sks.cluster_id
  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  app_autosync = local.app_autosync

  logs_storage = {
    bucket_name = resource.aws_s3_bucket.this["loki"].id
    region      = resource.aws_s3_bucket.this["loki"].region
    access_key  = resource.exoscale_iam_access_key.s3_iam_key["loki"].key
    secret_key  = resource.exoscale_iam_access_key.s3_iam_key["loki"].secret
  }

  dependency_ids = {
    argocd   = module.argocd_bootstrap.id
    longhorn = module.longhorn.id
  }
}

module "thanos" {
  source = "git::https://github.com/camptocamp/devops-stack-module-thanos.git//sks?ref=v2.7.0"
  # source          = "../../devops-stack-module-thanos/sks"

  # target_revision = "chart-autoupdate-patch-thanos"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  cluster_id       = module.sks.cluster_id
  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  app_autosync = local.app_autosync

  metrics_storage = {
    bucket_name = resource.aws_s3_bucket.this["thanos"].id
    region      = resource.aws_s3_bucket.this["thanos"].region
    access_key  = resource.exoscale_iam_access_key.s3_iam_key["thanos"].key
    secret_key  = resource.exoscale_iam_access_key.s3_iam_key["thanos"].secret
  }

  thanos = {
    oidc = module.oidc.oidc
  }

  dependency_ids = {
    argocd       = module.argocd_bootstrap.id
    traefik      = module.traefik.id
    cert-manager = module.cert-manager.id
    keycloak     = module.keycloak.id
    oidc         = module.oidc.id
    longhorn     = module.longhorn.id
  }
}

module "kube-prometheus-stack" {
  source = "git::https://github.com/camptocamp/devops-stack-module-kube-prometheus-stack.git//sks?ref=v8.0.0"
  # source = "../../devops-stack-module-kube-prometheus-stack/sks"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace
  argocd_project   = module.sks.cluster_name

  app_autosync = local.app_autosync

  metrics_storage = {
    bucket_name = resource.aws_s3_bucket.this["thanos"].id
    region      = resource.aws_s3_bucket.this["thanos"].region
    access_key  = resource.exoscale_iam_access_key.s3_iam_key["thanos"].key
    secret_key  = resource.exoscale_iam_access_key.s3_iam_key["thanos"].secret
  }

  prometheus = {
    oidc = module.oidc.oidc
  }
  alertmanager = {
    oidc = module.oidc.oidc
  }
  grafana = {
    oidc = module.oidc.oidc
  }

  dependency_ids = {
    argocd       = module.argocd_bootstrap.id
    traefik      = module.traefik.id
    cert-manager = module.cert-manager.id
    keycloak     = module.keycloak.id
    oidc         = module.oidc.id
    longhorn     = module.longhorn.id
    loki-stack   = module.loki-stack.id
  }
}

# ╷
# │ Error: Error while waiting for application kube-prometheus-stack to be created
# │ 
# │   with module.kube-prometheus-stack.module.kube-prometheus-stack.argocd_application.this,
# │   on .terraform/modules/kube-prometheus-stack/main.tf line 76, in resource "argocd_application" "this":
# │   76: resource "argocd_application" "this" {
# │ 
# │ error while waiting for application kube-prometheus-stack to be synced and healthy: rpc error: code = Unavailable desc = connection error: desc = "transport: error while dialing: dial tcp 127.0.0.1:33081: connect: connection refused"
# ╵

# -------

# ╷
# │ Error: Error while waiting for application argocd to be created
# │ 
# │   with module.argocd.argocd_application.this,
# │   on .terraform/modules/argocd/main.tf line 55, in resource "argocd_application" "this":
# │   55: resource "argocd_application" "this" {
# │ 
# │ error while waiting for application argocd to be synced and healthy: rpc error: code = Unavailable desc = connection error: desc = "transport: error while dialing: dial tcp 127.0.0.1:43377: connect: connection refused"
# ╵

module "argocd" {
  source = "git::https://github.com/camptocamp/devops-stack-module-argocd.git?ref=v3.5.1"
  # source = "../../devops-stack-module-argocd"

  cluster_name   = module.sks.cluster_name
  base_domain    = module.sks.base_domain
  cluster_issuer = local.cluster_issuer
  argocd_project = module.sks.cluster_name

  accounts_pipeline_tokens = module.argocd_bootstrap.argocd_accounts_pipeline_tokens
  server_secretkey         = module.argocd_bootstrap.argocd_server_secretkey

  app_autosync = local.app_autosync

  admin_enabled = false
  exec_enabled  = true

  oidc = {
    name         = "OIDC"
    issuer       = module.oidc.oidc.issuer_url
    clientID     = module.oidc.oidc.client_id
    clientSecret = module.oidc.oidc.client_secret
    requestedIDTokenClaims = {
      groups = {
        essential = true
      }
    }
  }

  rbac = {
    policy_csv = <<-EOT
      g, pipeline, role:admin
      g, devops-stack-admins, role:admin
    EOT
  }

  dependency_ids = {
    argocd                = module.argocd_bootstrap.id
    traefik               = module.traefik.id
    cert-manager          = module.cert-manager.id
    oidc                  = module.oidc.id
    kube-prometheus-stack = module.kube-prometheus-stack.id
  }
}
