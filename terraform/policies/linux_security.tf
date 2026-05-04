# terraform/policies/linux_security.tf
#
# Política para servidores Linux de alta segurança.
# Uso: bastion hosts, servidores de autenticação, servidores críticos.
# Cobre: system metrics + auth/syslog + auditd (logs do kernel Linux)
#
# O auditd regista todas as chamadas ao sistema operativo:
# quem acedeu a que ficheiros, que comandos foram corridos, etc.
# Requer que o serviço auditd esteja activo no servidor.

resource "elasticstack_fleet_agent_policy" "linux_security" {
  name            = "Linux - Security"
  namespace       = "linux"
  description     = "Bastion hosts e servidores críticos. Inclui auditd para auditoria completa."
  monitor_logs    = true
  monitor_metrics = true
}

resource "elasticstack_fleet_integration_policy" "linux_security_system" {
  name                = "system-security"
  namespace           = "linux"
  agent_policy_id     = elasticstack_fleet_agent_policy.linux_security.policy_id
  integration_name    = var.system_integration_name
  integration_version = var.system_integration_version
}

resource "elasticstack_fleet_integration_policy" "linux_security_auditd" {
  name                = "auditd-security"
  namespace           = "linux"
  agent_policy_id     = elasticstack_fleet_agent_policy.linux_security.policy_id
  integration_name    = var.auditd_integration_name
  integration_version = var.auditd_integration_version
}
