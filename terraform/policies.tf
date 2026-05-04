# terraform/policies.tf
#
# Invoca o módulo policies, passando as integrações como variáveis.
# A dependência é implícita: o Terraform só cria as policies após as
# integrações existirem, porque os valores vêm dos seus atributos.

module "policies" {
  source = "./policies"

  system_integration_name    = elasticstack_fleet_integration.system.name
  system_integration_version = elasticstack_fleet_integration.system.version

  auditd_integration_name    = elasticstack_fleet_integration.auditd.name
  auditd_integration_version = elasticstack_fleet_integration.auditd.version

  nginx_integration_name    = elasticstack_fleet_integration.nginx.name
  nginx_integration_version = elasticstack_fleet_integration.nginx.version

  apache_integration_name    = elasticstack_fleet_integration.apache.name
  apache_integration_version = elasticstack_fleet_integration.apache.version

  windows_integration_name    = elasticstack_fleet_integration.windows.name
  windows_integration_version = elasticstack_fleet_integration.windows.version
}
