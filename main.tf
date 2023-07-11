# Providers configuration

# These providers depend on the output of the respectives modules declared below.
# However, for clarity and easo of maintenance we grouped them all together in this section.

provider "kubernetes" {
  host                   = module.sks.kubernetes_host
  client_certificate     = module.sks.kubernetes_client_certificate
  client_key             = module.sks.kubernetes_client_key
  cluster_ca_certificate = module.sks.kubernetes_cluster_ca_certificate
}

provider "helm" {
  kubernetes {
    host                   = module.sks.kubernetes_host
    client_certificate     = module.sks.kubernetes_client_certificate
    client_key             = module.sks.kubernetes_client_key
    cluster_ca_certificate = module.sks.kubernetes_cluster_ca_certificate
  }
}

provider "argocd" {
  server_addr                 = "placeholder.camptocamp.com" # Needed for the bootstrap, otherwise the port-forwarding is what it's used.
  auth_token                  = module.argocd_bootstrap.argocd_auth_token
  insecure                    = true
  plain_text                  = true
  port_forward                = true
  port_forward_with_namespace = module.argocd_bootstrap.argocd_namespace
  kubernetes {
    host                   = module.sks.kubernetes_host
    client_certificate     = module.sks.kubernetes_client_certificate
    client_key             = module.sks.kubernetes_client_key
    cluster_ca_certificate = module.sks.kubernetes_cluster_ca_certificate
  }
}

provider "keycloak" {
  client_id                = "admin-cli"
  username                 = module.keycloak.admin_credentials.username
  password                 = module.keycloak.admin_credentials.password
  url                      = "https://keycloak.apps.${module.sks.cluster_name}.${module.sks.base_domain}"
  tls_insecure_skip_verify = true # Can be disabled/removed when using letsencrypt-prod as cluster issuer
  initial_login            = false
}

###

# Module declarations and configuration

module "sks" {
  source = "git::https://github.com/camptocamp/devops-stack-module-cluster-sks.git?ref=v1.0.0"

  cluster_name       = local.cluster_name
  kubernetes_version = local.kubernetes_version
  zone               = local.zone
  base_domain        = local.base_domain

  cni                    = "cilium"
  service_level          = local.service_level
  create_kubeconfig_file = true

  nodepools = {
    "${local.cluster_name}-default" = {
      size            = 3
      instance_type   = "standard.large"
      description     = "Default node pool for ${local.cluster_name}."
      instance_prefix = "default"
    },
  }
}

module "argocd_bootstrap" {
  source = "git::https://github.com/camptocamp/devops-stack-module-argocd.git//bootstrap?ref=v3.1.0"
  # source = "../../devops-stack-module-argocd/bootstrap"

  depends_on = [module.sks]
}

module "traefik" {
  source = "git::https://github.com/camptocamp/devops-stack-module-traefik.git//sks?ref=v2.0.0"
  # source = "../../devops-stack-module-traefik/sks"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  nlb_id                  = module.sks.nlb_id
  router_nodepool_id      = module.sks.router_nodepool_id
  router_instance_pool_id = module.sks.router_instance_pool_id

  enable_service_monitor = local.enable_service_monitor

  dependency_ids = {
    argocd = module.argocd_bootstrap.id
  }
}

module "cert-manager" {
  source = "git::https://github.com/camptocamp/devops-stack-module-cert-manager.git//sks?ref=v5.0.0"
  # source = "../../devops-stack-module-cert-manager/sks"

  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  enable_service_monitor = local.enable_service_monitor

  dependency_ids = {
    argocd = module.argocd_bootstrap.id
  }
}

# TODO Create an external database as PoC
module "keycloak" {
  source = "git::https://github.com/camptocamp/devops-stack-module-keycloak?ref=v2.0.0"
  # source = "../../devops-stack-module-keycloak"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  dependency_ids = {
    argocd       = module.argocd_bootstrap.id
    traefik      = module.traefik.id
    cert-manager = module.cert-manager.id
  }
}

module "oidc" {
  source = "git::https://github.com/camptocamp/devops-stack-module-keycloak//oidc_bootstrap?ref=v2.0.0"

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
  source = "git::https://github.com/camptocamp/devops-stack-module-longhorn.git?ref=v2.0.0"
  # source          = "../../devops-stack-module-longhorn"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

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
  source = "git::https://github.com/camptocamp/devops-stack-module-loki-stack//sks?ref=v4.0.0"
  # source = "../../devops-stack-module-loki-stack/sks"

  cluster_id       = module.sks.cluster_id
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  distributed_mode = true

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
  source = "git::https://github.com/camptocamp/devops-stack-module-thanos//sks?ref=v2.0.0"
  # source          = "../../devops-stack-module-thanos/sks"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  cluster_id       = module.sks.cluster_id
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

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
  source = "git::https://github.com/camptocamp/devops-stack-module-kube-prometheus-stack//sks?ref=v5.0.0"
  # source = "../../devops-stack-module-kube-prometheus-stack/sks"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

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
  source = "git::https://github.com/camptocamp/devops-stack-module-argocd.git?ref=v3.1.0"
  # source = "../../devops-stack-module-argocd"

  cluster_name             = module.sks.cluster_name
  base_domain              = module.sks.base_domain
  cluster_issuer           = local.cluster_issuer
  server_secretkey         = module.argocd_bootstrap.argocd_server_secretkey
  accounts_pipeline_tokens = module.argocd_bootstrap.argocd_accounts_pipeline_tokens

  admin_enabled = true
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
    traefik               = module.traefik.id
    cert-manager          = module.cert-manager.id
    oidc                  = module.oidc.id
    kube-prometheus-stack = module.kube-prometheus-stack.id
  }
}
