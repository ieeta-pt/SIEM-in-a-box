output "linux_base_policy_id" {
  value = elasticstack_fleet_agent_policy.linux_base.policy_id
}

output "linux_web_policy_id" {
  value = elasticstack_fleet_agent_policy.linux_web.policy_id
}

output "linux_security_policy_id" {
  value = elasticstack_fleet_agent_policy.linux_security.policy_id
}

output "windows_security_policy_id" {
  value = elasticstack_fleet_agent_policy.windows_security.policy_id
}
