# =============================================================================
# SIEM-in-a-Box — Makefile de orquestração
# =============================================================================
# Uso:
#   make up              — inicia o stack principal (Variante A)
#   make up-obs          — inicia o stack de observabilidade
#   make up-sources      — inicia os contentores de fontes
#   make down            — para tudo
#   make status          — mostra estado de todos os serviços
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

.PHONY: all up down down-volumes down-all status verify help

help:
	@echo "SIEM-in-a-Box — alvos disponíveis:"
	@echo "  make up           — Stack principal (Variante A)"
	@echo "  make down         — Parar stack principal"
	@echo "  make status       — Estado de todos os serviços"

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

# ── Parar tudo ────────────────────────────────────────────────────────────────
down-all: down down-obs down-sources

# ── Estado ────────────────────────────────────────────────────────────────────
status:
	@echo "=== Stack Principal ==="
	@cd $(STACK_DIR) && docker compose ps 2>/dev/null || echo "  (não iniciado)"
	@echo ""
	@echo "=== Observabilidade ==="
	@cd $(OBS_DIR) && docker compose ps 2>/dev/null || echo "  (não iniciado)"
	@echo ""
	@echo "=== Fontes ==="
	@cd $(SOURCES_DIR) && docker compose ps 2>/dev/null || echo "  (não iniciado)"
	@echo ""
	@echo "=== ES Cluster Health ==="
	@curl -sk -u "$(ELASTIC_USER):$(ELASTIC_PASSWORD)" \
		"$(ES_URL)/_cluster/health?pretty" 2>/dev/null \
		| python3 -c "import json,sys; d=json.load(sys.stdin); \
		print(f'  Status: {d[\"status\"]} | Docs: {d.get(\"number_of_nodes\",\"?\")} node(s)')" \
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
