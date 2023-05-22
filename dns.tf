# Requires a subscription to Exoscale DNS service, which should be mannually activated on the web console.
# If using nip.io, which is deployed automatically, both these resources are not needed.

resource "exoscale_domain" "domain" {
  name = local.base_domain
}

resource "exoscale_domain_record" "wildcard" {
  domain      = resource.exoscale_domain.domain.id
  name        = "*.apps"
  record_type = "A"
  ttl         = "300"
  content     = module.sks.nlb_ip_address
}
