# terraform/policies/linux_web.tf
#
# Política para servidores web Linux.
# Uso: servidores com nginx e/ou apache instalados.
#
# NOTAS SOBRE ESTADOS DESACTIVADOS:
# - nginx/metrics (stubstatus): requer módulo stub_status activo no nginx.
#   Para activar: mudar enabled = true e correr terraform apply.
# - apache: desactivado por default. Activar apenas se apache estiver instalado.

resource "elasticstack_fleet_agent_policy" "linux_web" {
  name            = "Linux - Web Server"
  namespace       = "linux"
  description     = "Servidores web Linux. nginx.stubstatus e apache desactivados por default."
  monitor_logs    = true
  monitor_metrics = true
}

# ── Integração system (métricas + auth/syslog) ────────────────────────────────
resource "elasticstack_fleet_integration_policy" "linux_web_system" {
  name                = "system-web"
  namespace           = "linux"
  agent_policy_id     = elasticstack_fleet_agent_policy.linux_web.policy_id
  integration_name    = var.system_integration_name
  integration_version = var.system_integration_version
}

# ── Integração nginx ──────────────────────────────────────────────────────────
resource "elasticstack_fleet_integration_policy" "linux_web_nginx" {
  name                = "nginx-web"
  namespace           = "linux"
  agent_policy_id     = elasticstack_fleet_agent_policy.linux_web.policy_id
  integration_name    = var.nginx_integration_name
  integration_version = var.nginx_integration_version
}

# ── Integração apache — DESACTIVADA por default ───────────────────────────────
# Para activar: mudar enabled = true nos inputs e correr terraform apply
resource "elasticstack_fleet_integration_policy" "linux_web_apache" {
  name                = "apache-web"
  namespace           = "linux"
  agent_policy_id     = elasticstack_fleet_agent_policy.linux_web.policy_id
  integration_name    = var.apache_integration_name
  integration_version = var.apache_integration_version
}
