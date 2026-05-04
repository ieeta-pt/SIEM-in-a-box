# terraform/policies/windows_security.tf
#
# Política para servidores Windows.
# Uso: Domain Controllers, servidores de aplicação Windows, workstations críticas.
#
# NOTAS SOBRE ESTADOS DESACTIVADOS:
# - sysmon_operational: requer Sysmon instalado (https://docs.microsoft.com/sysmon)
#   O Sysmon regista criação de processos, ligações de rede, etc.
#   Para activar: instalar Sysmon no host, mudar enabled = true, terraform apply
#
# - forwarded: requer Windows Event Forwarding (WEF) configurado
#   Para activar: configurar WEF no host, mudar enabled = true, terraform apply

resource "elasticstack_fleet_agent_policy" "windows_security" {
  name            = "Windows - Security"
  namespace       = "windows"
  description     = "Servidores Windows. Sysmon e WEF desactivados por default."
  monitor_logs    = true
  monitor_metrics = true
}

# ── Integração system para Windows ───────────────────────────────────────────
resource "elasticstack_fleet_integration_policy" "windows_security_system" {
  name                = "system-windows"
  namespace           = "windows"
  agent_policy_id     = elasticstack_fleet_agent_policy.windows_security.policy_id
  integration_name    = var.system_integration_name
  integration_version = var.system_integration_version
}

# ── Integração windows (PowerShell + Sysmon + WEF) ───────────────────────────
# Sysmon e WEF desactivados por default nos defaults da integração
resource "elasticstack_fleet_integration_policy" "windows_security_windows" {
  name                = "windows-security"
  namespace           = "windows"
  agent_policy_id     = elasticstack_fleet_agent_policy.windows_security.policy_id
  integration_name    = var.windows_integration_name
  integration_version = var.windows_integration_version
}
