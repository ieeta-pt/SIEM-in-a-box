# terraform/policies/linux_base.tf
#
# Política para servidores Linux genéricos.
# Uso: qualquer servidor Linux que não seja web server nem servidor crítico.
# Cobre: métricas de sistema (CPU, memória, disco, rede) + auth.log + syslog

# ── A política em si (a "caixa" que agrupa integrações) ───────────────────────
resource "elasticstack_fleet_agent_policy" "linux_base" {
  name            = "Linux - Base"
  namespace       = "linux"
  description     = "Servidores Linux genéricos. Métricas de sistema + auth/syslog."
  monitor_logs    = true
  monitor_metrics = true
}

# ── A integração system dentro desta política ─────────────────────────────────
# Uma "integration policy" define como uma integração específica está configurada
# dentro de uma agent policy.
resource "elasticstack_fleet_integration_policy" "linux_base_system" {
  name                = "system-base"
  namespace           = "linux"
  agent_policy_id     = elasticstack_fleet_agent_policy.linux_base.policy_id
  integration_name    = var.system_integration_name
  integration_version = var.system_integration_version
}
