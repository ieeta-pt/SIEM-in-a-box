# terraform/variables.tf
#
# Define todas as variáveis do projecto.
# Os defaults apontam para o lab local.
# Para produção/datacenter, usa environments/datacenter.tfvars.

variable "elasticsearch_url" {
  description = "URL do Elasticsearch. Em lab: https://localhost:9200"
  type        = string
  default     = "https://localhost:9200"
}

variable "kibana_url" {
  description = "URL do Kibana. Em lab: https://localhost:5601"
  type        = string
  default     = "https://localhost:5601"
}

variable "elastic_username" {
  description = "Utilizador do Elasticsearch/Kibana"
  type        = string
  default     = "elastic"
}

variable "elastic_password" {
  description = <<-EOF
    Password do Elasticsearch/Kibana.
    Não tem default — tens de fornecer sempre um valor.
    Pode ser passada de três formas:
      1. terraform apply -var="elastic_password=..."
      2. Variável de ambiente: export TF_VAR_elastic_password=...
      3. Ficheiro .tfvars: elastic_password = "..."
  EOF
  type        = string
  sensitive   = true # não aparece em logs nem em outputs
}

variable "fleet_server_url" {
  description = <<-EOF
    URL do Fleet Server acessível pelos Elastic Agents externos.
    Este é o IP/DNS do servidor físico que corre o Docker, não o IP do container.
    Em lab: https://192.168.122.1:8220
    Em datacenter: https://<IP-PÚBLICO-DO-SERVIDOR>:8220
  EOF
  type        = string
  default     = "https://192.168.122.1:8220"
}

variable "ca_cert_path" {
  description = <<-EOF
    Caminho para o certificado CA do stack Elastic.
    Gerado automaticamente pelo setup.sh em:
    stack/certs/ca/ca.crt (dentro do volume Docker)

    Para o Terraform aceder, o certificado precisa de estar acessível
    na máquina onde corres o terraform. Exportar com:
      docker cp siem-setup:/usr/share/elasticsearch/config/certs/ca/ca.crt \
        ./stack/certs/ca.crt
  EOF
  type        = string
  default     = "../stack/certs/ca.crt"
}
