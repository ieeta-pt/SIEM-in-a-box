#===============================
#   Dependencies and Versions
#===============================
#
# It specifies the minimum versions of Terraform and the providers
# This protects against automatic updates that could break something
#

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "~> 0.11"
    }
  }
}

