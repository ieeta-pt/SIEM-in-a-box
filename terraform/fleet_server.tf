# terraform/fleet_server.tf
#
# Configura o Fleet Server Host — o URL que os Elastic Agents usam para se registar.
# Este recurso é necessário antes de criar qualquer política.
#
# NOTA: O kibana.yml também configura isto via xpack.fleet.fleetServerHosts.
# O Terraform vai sobrescrever esse valor quando correr.
# Se quiser manter apenas o Terraform a gerir isto, pode remover do kibana.yml.

# Fleet Server Host is managed via kibana.yml (xpack.fleet.fleetServerHosts)
# The elasticstack_fleet_server_host resource is not used here due to a provider
# bug where the `default` field produces an inconsistent result after apply.
