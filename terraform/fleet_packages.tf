# terraform/fleet_packages.tf
#
# Instala as integrações necessárias no Elastic Package Registry.
# Equivalente ao xpack.fleet.packages do kibana.yml, mas gerido pelo Terraform.
#
# O Terraform verifica se a integração já está instalada antes de tentar instalar.
# Se já estiver, não faz nada (idempotente).
# Se a versão mudar, actualiza.

resource "elasticstack_fleet_integration" "fleet_server" {
  name    = "fleet_server"
  version = "1.6.0"
  force   = false
}

resource "elasticstack_fleet_integration" "system" {
  name    = "system"
  version = "2.6.3"
  force   = false
  # "system" cobre: CPU, memória, disco, rede, auth.log, syslog, winlog
}

resource "elasticstack_fleet_integration" "nginx" {
  name    = "nginx"
  version = "3.0.0"
  force   = false
}

resource "elasticstack_fleet_integration" "apache" {
  name    = "apache"
  version = "3.0.0"
  force   = false
}

resource "elasticstack_fleet_integration" "auditd" {
  name    = "auditd"
  version = "3.22.1"
  force   = false
  # auditd: logs de auditoria do kernel Linux
}

resource "elasticstack_fleet_integration" "windows" {
  name    = "windows"
  version = "3.5.0"
  force   = false
  # windows: PowerShell, Sysmon, WEF
}

# ── Integrações adicionais a instalar para o futuro ───────────────────────────
# Descomenta quando precisares de adicionar uma nova política que use estes pacotes.

# resource "elasticstack_fleet_integration" "postgresql" {
#   name    = "postgresql"
#   version = "latest"
#   force   = false
# }

# resource "elasticstack_fleet_integration" "mysql" {
#   name    = "mysql"
#   version = "latest"
#   force   = false
# }

# resource "elasticstack_fleet_integration" "cisco" {
#   name    = "cisco"
#   version = "latest"
#   force   = false
# }
