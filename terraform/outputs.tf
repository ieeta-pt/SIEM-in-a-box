# terraform/outputs.tf
#
# Os outputs são valores que o Terraform mostra após o apply.
# Úteis para obter os IDs das políticas sem ter de ir ao Kibana UI.
#
# Ver com: terraform output
# Ver um específico: terraform output linux_base_policy_id

output "fleet_server_url" {
  description = "URL do Fleet Server para enrollment de agentes"
  value       = var.fleet_server_url
}

output "linux_base_policy_id" {
  description = "ID da política Linux - Base (para enrollment manual)"
  value       = module.policies.linux_base_policy_id
}

output "linux_web_policy_id" {
  description = "ID da política Linux - Web Server"
  value       = module.policies.linux_web_policy_id
}

output "linux_security_policy_id" {
  description = "ID da política Linux - Security"
  value       = module.policies.linux_security_policy_id
}

output "windows_security_policy_id" {
  description = "ID da política Windows - Security"
  value       = module.policies.windows_security_policy_id
}
