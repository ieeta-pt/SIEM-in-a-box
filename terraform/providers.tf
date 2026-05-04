#=====================================
#   Connecting to the Elastic Stack
#=====================================
#
# Configures the connection to Elasticsearch and Kibana.
# Credentials come from variables (defined in variables.tf)
# and the concrete values come from the .tfvars file.
# Never put passwords directly here.
#

provider "elasticstack" {
  elasticsearch {
    endpoints = [var.elasticsearch_url]
    username  = var.elastic_username
    password  = var.elastic_password
    ca_file   = var.ca_cert_path
  }

  kibana {
    endpoints = [var.kibana_url]
    username  = var.elastic_username
    password  = var.elastic_password
    ca_certs  = [var.ca_cert_path]
  }
}
