variable "exoscale_iam_key" {
  description = "Exoscale IAM access key to use for the S3 provider."
  type        = string
  sensitive   = true
}

variable "exoscale_iam_secret" {
  description = "Exoscale IAM access secret to use for the S3 provider."
  type        = string
  sensitive   = true
}

variable "alertmanager_slack_route_api_url" {
  description = "The URL of the Alertmanager Slack route API."
  type        = string
  sensitive   = true
}
