# terraform/environments/lab.tfvars
# Valores para o ambiente de lab local.
# NÃO commitar este ficheiro se contiver passwords reais.

elasticsearch_url = "https://localhost:9200"
kibana_url        = "https://localhost:5601"
elastic_username  = "elastic"
elastic_password  = "elastic"
fleet_server_url  = "https://192.168.0.23:8220"
ca_cert_path      = "../stack/certs/ca.crt"
