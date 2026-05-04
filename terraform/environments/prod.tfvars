# terraform/environments/datacenter.tfvars
# Valores para o datacenter.
# NUNCA commitar este ficheiro — contém passwords de produção.
# Adicionar ao .gitignore: terraform/environments/datacenter.tfvars

elasticsearch_url = "https://<IP-MACHINE>:9200"
kibana_url        = "https://<IP-MACHINE>:5601"
elastic_username  = "elastic"
elastic_password  = "PASSWORD_REAL"
fleet_server_url  = "https://<IP-MACHINE>:8220"
ca_cert_path      = "../stack/certs/ca.crt"
