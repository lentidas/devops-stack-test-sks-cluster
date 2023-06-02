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
  server_addr                 = "127.0.0.1:8080"
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
  # source = "git::https://github.com/camptocamp/devops-stack-module-cluster-sks.git?ref=v1.0.0"
  source = "git::https://github.com/camptocamp/devops-stack-module-cluster-sks.git?ref=ISDEVOPS-212-initial-implementation"

  cluster_name       = local.cluster_name
  kubernetes_version = local.kubernetes_version
  zone               = local.zone
  # base_domain        = local.base_domain # TODO Check with Christian how to properly deploy a domain on Exoscale as for now I can create it but the DNS does not propagate
  domain_id = resource.exoscale_domain.domain.id

  service_level = "starter"

  # router_nodepool = "${local.cluster_name}-router"
  nodepools = {
    "${local.cluster_name}-default" = {
      size            = 3
      instance_type   = "standard.large"
      description     = "Default nodepool for ${local.cluster_name}."
      instance_prefix = null
      disk_size       = null

      labels              = {}
      taints              = {}
      private_network_ids = null
    },
    # "${local.cluster_name}-router" = {
    #   size            = 2
    #   instance_type   = "standard.small"
    #   description     = "Router nodepool for ${local.cluster_name} used to avoid loopbacks"
    #   instance_prefix = null
    #   disk_size       = null

    #   labels = {
    #     role = "router"
    #   }
    #   taints = {
    #     router = "router:NoSchedule"
    #   }
    #   private_network_ids = null
    # },
    # "${local.cluster_name}-monitoring" = {
    #   size            = 2
    #   instance_type   = "standard.large"
    #   description     = "Monitoring nodepool for ${local.cluster_name}"
    #   instance_prefix = null
    #   disk_size       = 150

    #   labels = {
    #     role = "monitoring"
    #   }
    #   taints              = {}
    #   private_network_ids = null
    # },
  }
}

module "argocd_bootstrap" {
  source = "git::https://github.com/camptocamp/devops-stack-module-argocd.git//bootstrap?ref=v1.1.0"

  depends_on = [module.sks]
}

module "argocd" {
  source = "git::https://github.com/camptocamp/devops-stack-module-argocd.git?ref=fix/oidc-ca-certificate-staging"

  cluster_name             = module.sks.cluster_name
  base_domain              = module.sks.base_domain
  cluster_issuer           = local.cluster_issuer
  server_secretkey         = module.argocd_bootstrap.argocd_server_secretkey
  accounts_pipeline_tokens = module.argocd_bootstrap.argocd_accounts_pipeline_tokens

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

  dependency_ids = {
    traefik               = module.traefik.id
    cert-manager          = module.cert-manager.id
    oidc                  = module.oidc.id
    kube-prometheus-stack = module.kube-prometheus-stack.id
  }
}

module "longhorn" {
  source          = "../devops-stack-module-longhorn"
  target_revision = "dev"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  enable_service_monitor   = true
  enable_dashboard_ingress = true

  oidc = {
    enabled       = true
    issuer_url    = format("https://keycloak.apps.%s.%s/realms/devops-stack", module.sks.cluster_name, module.sks.base_domain)
    redirect_url  = format("https://longhorn.apps.%s.%s/oauth2/callback", module.sks.cluster_name, module.sks.base_domain)
    client_id     = module.oidc.oidc.client_id
    client_secret = module.oidc.oidc.client_secret
  }

  dependency_ids = {
    argocd                = module.argocd_bootstrap.id
    kube-prometheus-stack = module.kube-prometheus-stack.id
  }
}

module "traefik" {
  source = "git::https://github.com/camptocamp/devops-stack-module-traefik.git//sks?ref=v1.2.1"

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
  source = "git::https://github.com/camptocamp/devops-stack-module-cert-manager.git//sks?ref=v4.0.1"

  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  enable_service_monitor = local.enable_service_monitor

  helm_values = [{
    letsencrypt = {
      issuers = {
        letsencrypt-staging = {
          email  = "letsencrypt@camptocamp.com"
          server = "https://acme-staging-v02.api.letsencrypt.org/directory"
        }
      }
    }
  }]

  dependency_ids = {
    argocd = module.argocd_bootstrap.id
  }
}

# TODO Create an external database as PoC
module "keycloak" {
  source = "git::https://github.com/camptocamp/devops-stack-module-keycloak?ref=v1.1.0"

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
  source = "git::https://github.com/camptocamp/devops-stack-module-keycloak//oidc_bootstrap?ref=v1.1.0"

  cluster_name   = module.sks.cluster_name
  base_domain    = module.sks.base_domain
  cluster_issuer = local.cluster_issuer

  dependency_ids = {
    keycloak = module.keycloak.id
  }
}

module "loki-stack" {
  # TODO Use an sks variant
  source = "git::https://github.com/camptocamp/devops-stack-module-loki-stack//kind?ref=v2.0.2"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  distributed_mode = true

  logs_storage = {
    bucket_name       = resource.aws_s3_bucket.this["loki"].id
    endpoint          = resource.aws_s3_bucket.this["loki"].bucket_domain_name
    access_key        = resource.exoscale_iam_access_key.s3_iam_key["loki"].key
    secret_access_key = resource.exoscale_iam_access_key.s3_iam_key["loki"].secret
  }

  dependency_ids = {
    argocd   = module.argocd_bootstrap.id
    longhorn = module.longhorn.id
  }
}

# module "thanos" {
#   # TODO Use an sks variant
#   source = "git::https://github.com/camptocamp/devops-stack-module-thanos//kind?ref=v1.0.0"

#   cluster_name     = module.sks.cluster_name
#   base_domain      = module.sks.base_domain
#   cluster_issuer   = local.cluster_issuer
#   argocd_namespace = module.argocd_bootstrap.argocd_namespace

#   metrics_storage = {
#     bucket_name       = resource.aws_s3_bucket.this["thanos"].id
#     endpoint          = resource.aws_s3_bucket.this["thanos"].bucket_domain_name
#     access_key        = resource.exoscale_iam_access_key.s3_iam_key["thanos"].key
#     secret_access_key = resource.exoscale_iam_access_key.s3_iam_key["thanos"].secret
#   }

#   thanos = {
#     oidc = module.oidc.oidc
#   }

#   dependency_ids = {
#     argocd       = module.argocd_bootstrap.id
#     traefik      = module.traefik.id
#     cert-manager = module.cert-manager.id
#     oidc         = module.oidc.id
#   }
# }

module "kube-prometheus-stack" {
  # TODO Use an sks variant
  source = "git::https://github.com/camptocamp/devops-stack-module-kube-prometheus-stack//kind?ref=v2.3.0"

  cluster_name     = module.sks.cluster_name
  base_domain      = module.sks.base_domain
  cluster_issuer   = local.cluster_issuer
  argocd_namespace = module.argocd_bootstrap.argocd_namespace

  # metrics_storage = {
  #   bucket     = resource.aws_s3_bucket.this["thanos"].id
  #   endpoint   = resource.aws_s3_bucket.this["thanos"].bucket_domain_name
  #   access_key = resource.exoscale_iam_access_key.s3_iam_key["thanos"].key
  #   secret_key = resource.exoscale_iam_access_key.s3_iam_key["thanos"].secret
  # }

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
    oidc         = module.oidc.id
  }
}
