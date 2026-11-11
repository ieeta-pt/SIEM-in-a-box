# Fleet and Terraform

[← Technical documentation](README.md)

Fleet Server runs as a container in the core stack and centrally manages the Elastic Agents deployed on monitored hosts. Terraform manages the Fleet configuration (integrations and agent policies) as code. This path is optional: the Kafka push path works without it.

## Agent policies

| Policy | File | For | Integrations |
| --- | --- | --- | --- |
| **Linux - Base** | [`linux_base.tf`](../terraform/policies/linux_base.tf) | Generic Linux (application and database servers) | `system` (CPU, memory, disk, network metrics, auth.log, syslog) |
| **Linux - Security** | [`linux_security.tf`](../terraform/policies/linux_security.tf) | Bastion hosts, authentication servers, high-value targets | `system` + `auditd` |
| **Linux - Web Server** | [`linux_web.tf`](../terraform/policies/linux_web.tf) | nginx or Apache servers | `system` + `nginx` + `apache` (Apache disabled by default) |
| **Windows - Security** | [`windows_security.tf`](../terraform/policies/windows_security.tf) | Domain Controllers, Windows servers, critical workstations | `system` + `windows` (PowerShell; Sysmon and WEF disabled by default) |

## Installed integrations

Installed by [`fleet_packages.tf`](../terraform/fleet_packages.tf):

| Integration | Version | Purpose |
| --- | --- | --- |
| `fleet_server` | 1.6.0 | Fleet Server bootstrap |
| `system` | 2.6.3 | System metrics, auth.log, syslog |
| `nginx` | 3.0.0 | Nginx access and error logs |
| `apache` | 3.0.0 | Apache access and error logs |
| `auditd` | 3.22.1 | Linux kernel audit logs |
| `windows` | 3.5.0 | Windows Event Log, PowerShell, Sysmon |

## Running Terraform

Prerequisites: Terraform installed, the stack running, and the CA certificate exported.

```bash
# Export the CA certificate
docker cp siem-setup:/usr/share/elasticsearch/config/certs/ca/ca.crt ./stack/certs/ca.crt

cd terraform
terraform init

# Local lab
terraform apply -var-file=environments/lab.tfvars

# Production (edit prod.tfvars first)
terraform apply -var-file=environments/prod.tfvars
```

Terraform is idempotent: re-running `apply` changes only what has drifted from the declared state. All inputs are described in [`variables.tf`](../terraform/variables.tf).

[`utils/configure-fleet-ssl.sh`](../utils/configure-fleet-ssl.sh) configures the Fleet output SSL settings and the service token.
