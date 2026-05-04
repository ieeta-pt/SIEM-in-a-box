# terraform/policies/variables.tf
#
# Variáveis de entrada do módulo policies.
# Os valores vêm do módulo raiz (fleet_packages.tf), o que cria
# dependências implícitas: o módulo só corre após as integrações existirem.

variable "system_integration_name" {
  description = "Nome da integração system"
  type        = string
}

variable "system_integration_version" {
  description = "Versão da integração system"
  type        = string
}

variable "auditd_integration_name" {
  description = "Nome da integração auditd"
  type        = string
}

variable "auditd_integration_version" {
  description = "Versão da integração auditd"
  type        = string
}

variable "nginx_integration_name" {
  description = "Nome da integração nginx"
  type        = string
}

variable "nginx_integration_version" {
  description = "Versão da integração nginx"
  type        = string
}

variable "apache_integration_name" {
  description = "Nome da integração apache"
  type        = string
}

variable "apache_integration_version" {
  description = "Versão da integração apache"
  type        = string
}

variable "windows_integration_name" {
  description = "Nome da integração windows"
  type        = string
}

variable "windows_integration_version" {
  description = "Versão da integração windows"
  type        = string
}
