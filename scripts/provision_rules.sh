#!/usr/bin/env bash
# =============================================================================
# Provisiona todas as regras de deteção no Kibana via API
# Uso: ELASTIC_PASSWORD=elastic bash provision_rules.sh
# =============================================================================

set -euo pipefail

KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"
ELASTIC_USER="${ELASTIC_USER:-elastic}"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-elastic}"
RULES_DIR="${RULES_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../rules" && pwd)}"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] OK: $*"; }
fail() { echo "[$(date '+%H:%M:%S')] ERRO: $*" >&2; }

# Aguardar Kibana
log "A aguardar Kibana ($KIBANA_URL)..."
until curl -sk -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
    "${KIBANA_URL}/api/status" | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('status',{}).get('overall',{}).get('level','')
sys.exit(0 if s=='available' else 1)
" 2>/dev/null; do
    echo -n "."
    sleep 5
done
echo ""
log "Kibana disponível."

# Aplicar template bench-fields.json ao ES
TEMPLATES_DIR="${RULES_DIR}/../utils/templates"
if [[ -f "${TEMPLATES_DIR}/bench-fields.json" ]]; then
    log "A aplicar component template bench-fields..."
    ES_URL="${ES_URL:-https://localhost:9200}"
    RESULT=$(curl -sk -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
        -X PUT "${ES_URL}/_component_template/bench-fields" \
        -H "Content-Type: application/json" \
        -d @"${TEMPLATES_DIR}/bench-fields.json")
    echo "$RESULT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('bench-fields template:', 'OK' if d.get('acknowledged') else d)
"
fi

# Provisionar cada regra
TOTAL=0
SUCCESS=0

for rule_file in "${RULES_DIR}"/*.json; do
    [[ -f "$rule_file" ]] || continue
    RULE_NAME=$(python3 -c "import json; print(json.load(open('${rule_file}')).get('name','?'))")
    TOTAL=$((TOTAL+1))

    log "A provisionar: ${RULE_NAME}..."

    # Verificar se a regra já existe
    EXISTING=$(curl -sk -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
        -X GET "${KIBANA_URL}/api/detection_engine/rules?name=${RULE_NAME}" \
        -H "kbn-xsrf: true" 2>/dev/null || echo '{"total":0}')

    EXISTS_COUNT=$(echo "$EXISTING" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('total',0))
except:
    print(0)
" 2>/dev/null || echo "0")

    if [[ "$EXISTS_COUNT" -gt 0 ]]; then
        # Actualizar regra existente
        RULE_ID=$(echo "$EXISTING" | python3 -c "
import json,sys
d=json.load(sys.stdin)
rules=d.get('data',[])
print(rules[0]['id'] if rules else '')
" 2>/dev/null || echo "")

        if [[ -n "$RULE_ID" ]]; then
            RESP=$(curl -sk -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
                -X PATCH "${KIBANA_URL}/api/detection_engine/rules" \
                -H "kbn-xsrf: true" \
                -H "Content-Type: application/json" \
                -d "$(python3 -c "
import json
d=json.load(open('${rule_file}'))
d['id']='${RULE_ID}'
print(json.dumps(d))
")" 2>/dev/null || echo '{}')
        fi
        ok "Actualizada: ${RULE_NAME}"
    else
        # Criar nova regra
        RESP=$(curl -sk -u "${ELASTIC_USER}:${ELASTIC_PASSWORD}" \
            -X POST "${KIBANA_URL}/api/detection_engine/rules" \
            -H "kbn-xsrf: true" \
            -H "Content-Type: application/json" \
            -d @"${rule_file}" 2>/dev/null || echo '{}')

        ERROR=$(echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('message','') or d.get('error',''))
" 2>/dev/null || echo "")

        if [[ -n "$ERROR" ]]; then
            fail "Falha ${RULE_NAME}: ${ERROR}"
        else
            ok "Criada: ${RULE_NAME}"
            SUCCESS=$((SUCCESS+1))
        fi
    fi
done

log "Regras aprovisionadas: ${SUCCESS}/${TOTAL}"
log "Ver em: ${KIBANA_URL}/app/security/rules"
