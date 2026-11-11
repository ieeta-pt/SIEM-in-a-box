# =============================================================================
# SIEM-in-a-Box — Makefile de orquestração
# =============================================================================
# Uso:
#   make up              — inicia o stack principal (Variante A)
#   make down            — para o stack (volumes preservados)
#   make down-volumes    — para o stack e apaga os volumes (perda de dados)
#   make status          — mostra estado dos serviços e do cluster ES
#   make verify          — lista índices ES e contagens dos pipelines Logstash
#
# Variáveis de ambiente:
#   ELASTIC_PASSWORD (default: elastic)
#   KIBANA_URL (default: https://localhost:5601)
#   ES_URL (default: https://localhost:9200)
# =============================================================================

ELASTIC_PASSWORD ?= elastic
ELASTIC_USER     ?= elastic
ES_URL           ?= https://localhost:9200
KIBANA_URL       ?= https://localhost:5601
KAFKA_BOOTSTRAP  ?= localhost:9094
STACK_DIR     := stack/

# Usar Python do venv se existir, caso contrário python3 do sistema
PYTHON := $(shell test -f .venv/bin/python3 && echo .venv/bin/python3 || echo python3)

.PHONY: up down down-volumes status verify help

help:
	@echo "SIEM-in-a-Box — alvos disponíveis:"
	@echo "  make up           — Stack principal (Variante A)"
	@echo "  make down         — Parar stack principal (volumes preservados)"
	@echo "  make down-volumes — Parar stack e apagar volumes (perda de dados)"
	@echo "  make status       — Estado dos serviços e do cluster ES"
	@echo "  make verify       — Índices ES e contagens dos pipelines Logstash"

# ── Stack principal ───────────────────────────────────────────────────────────
up:
	@echo ">> A iniciar stack principal..."
	cd $(STACK_DIR) && docker compose up -d
	@echo ">> A aguardar ES (pode demorar 2-3 min)..."
	@until curl -sk -u "$(ELASTIC_USER):$(ELASTIC_PASSWORD)" \
		"$(ES_URL)/_cluster/health" 2>/dev/null | grep -q '"status"'; do \
		echo -n "."; sleep 5; done; echo ""
	@echo ">> Stack principal OK."
	@echo "   Kibana: https://localhost:5601 (elastic/$(ELASTIC_PASSWORD))"

down:
	cd $(STACK_DIR) && docker compose down

down-volumes:
	cd $(STACK_DIR) && docker compose down -v
	@echo ">> AVISO: volumes apagados — certificados e dados perdidos."

# ── Estado ────────────────────────────────────────────────────────────────────
status:
	@echo "=== Stack Principal ==="
	@cd $(STACK_DIR) && docker compose ps 2>/dev/null || echo "  (não iniciado)"
	@echo ""
	@echo "=== ES Cluster Health ==="
	@curl -sk -u "$(ELASTIC_USER):$(ELASTIC_PASSWORD)" \
		"$(ES_URL)/_cluster/health?pretty" 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin); \
		print(f'  Status: {d[\"status\"]} | Nodes: {d.get(\"number_of_nodes\",\"?\")} node(s)')" \
		2>/dev/null || echo "  (ES não acessível)"

verify:
	@echo "=== Verificação de índices ==="
	@curl -sk -u "$(ELASTIC_USER):$(ELASTIC_PASSWORD)" \
		"$(ES_URL)/_cat/indices/logs-*?v&s=index&h=index,docs.count,store.size,health" \
		2>/dev/null || echo "  (ES não acessível)"
	@echo ""
	@echo "=== Pipelines Logstash ==="
	@curl -s "http://localhost:9600/_node/pipelines" 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'  {n}: in={i.get(\"events\",{}).get(\"in\",0)} out={i.get(\"events\",{}).get(\"out\",0)}') for n,i in d.get('pipelines',{}).items()]" \
		2>/dev/null || echo "  (Logstash não acessível)"
