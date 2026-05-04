#!/bin/bash

# ============================================
# SIEM Rule Manager - Bash Version
# Ferramenta para gerir regras de detecção do SIEM
# ============================================

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuração
KIBANA_HOST="${KIBANA_HOST:-https://localhost:5601}"
USERNAME="${ELASTICSEARCH_USERNAME:-elastic}"
PASSWORD="${ELASTIC_PASSWORD}"
VERIFY_SSL="${VERIFY_SSL:-false}"

if [ "$VERIFY_SSL" = "true" ]; then
    CURL_OPTS="-s"
else
    CURL_OPTS="-s -k"
fi

# ============================================
# Funções Auxiliares
# ============================================
check_password() {
    if [ -z "$PASSWORD" ]; then
        echo -e "${RED}Erro: ELASTIC_PASSWORD não definida${NC}"
        echo "Export: export ELASTIC_PASSWORD=your_password"
        exit 1
    fi
}

check_dependencies() {
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Erro: curl não encontrado${NC}"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}Erro: jq não encontrado${NC}"
        exit 1
    fi
}

# ============================================
# List Rules
# ============================================
cmd_list() {
    local enabled_only="$1"
    local severity="$2"
    
    check_password
    check_dependencies
    
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Erro ao conectar ao Kibana${NC}"
        exit 1
    fi
    
    # Aplicar filtros com jq
    local jq_filter='.data[]'
    
    if [ "$enabled_only" = "true" ]; then
        jq_filter="$jq_filter | select(.enabled == true)"
    fi
    
    if [ -n "$severity" ]; then
        jq_filter="$jq_filter | select(.severity == \"$severity\")"
    fi
    
    local rules
    rules=$(echo "$response" | jq -r "$jq_filter")
    
    local total=$(echo "$rules" | jq -s 'length')
    
    echo
    echo "========================================================================"
    echo "Total de Regras: $total"
    echo "========================================================================"
    echo
    
    # Mostrar regras
    echo "$rules" | jq -r '. | 
        (if .enabled then "✓" else "✗" end) + " [" + 
        (.severity | ascii_upcase | .[0:8]) + "] " + 
        .name + "\n   ID: " + .rule_id + 
        "\n   Tags: " + (.tags | join(", ")) + "\n"'
}

# ============================================
# Stats
# ============================================
cmd_stats() {
    check_password
    check_dependencies
    
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    local rules=$(echo "$response" | jq -r '.data[]')
    local total=$(echo "$rules" | jq -s 'length')
    local enabled=$(echo "$rules" | jq -s '[.[] | select(.enabled == true)] | length')
    local disabled=$((total - enabled))
    
    echo
    echo "========================================================================"
    echo "ESTATÍSTICAS DAS REGRAS"
    echo "========================================================================"
    echo
    echo "Total de Regras: $total"
    echo "  Ativas: $enabled"
    echo "  Inativas: $disabled"
    echo
    
    # Por severidade
    echo "Por Severidade:"
    echo "$rules" | jq -s 'group_by(.severity) | .[] | 
        "  " + (.[0].severity | ascii_upcase | .[0:10]) + " : " + (length | tostring)' -r
    
    echo
    
    # Por tipo
    echo "Por Tipo:"
    echo "$rules" | jq -s 'group_by(.type) | .[] | 
        "  " + (.[0].type | .[0:10]) + " : " + (length | tostring)' -r
    
    echo
}

# ============================================
# Enable/Disable Rule
# ============================================
toggle_rule() {
    local rule_id="$1"
    local enable="$2"
    
    check_password
    check_dependencies
    
    # Obter ID interno da regra
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    local internal_id
    internal_id=$(echo "$response" | jq -r ".data[] | select(.rule_id == \"$rule_id\") | .id")
    
    if [ -z "$internal_id" ]; then
        echo -e "${RED}Regra $rule_id não encontrada${NC}"
        exit 1
    fi
    
    # Atualizar regra
    local update_response
    update_response=$(curl $CURL_OPTS -w "\n%{http_code}" \
        -X PATCH "$KIBANA_HOST/api/detection_engine/rules?id=$internal_id" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -u "$USERNAME:$PASSWORD" \
        -d "{\"enabled\": $enable}" 2>/dev/null)
    
    local http_code=$(echo "$update_response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        if [ "$enable" = "true" ]; then
            echo -e "${GREEN}✓ Regra $rule_id ativada${NC}"
        else
            echo -e "${GREEN}✓ Regra $rule_id desativada${NC}"
        fi
    else
        echo -e "${RED}✗ Erro: HTTP $http_code${NC}"
        exit 1
    fi
}

cmd_enable() {
    toggle_rule "$1" "true"
}

cmd_disable() {
    toggle_rule "$1" "false"
}

# ============================================
# Delete Rule
# ============================================
cmd_delete() {
    local rule_id="$1"
    
    check_password
    check_dependencies
    
    # Obter ID interno
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    local internal_id
    internal_id=$(echo "$response" | jq -r ".data[] | select(.rule_id == \"$rule_id\") | .id")
    
    if [ -z "$internal_id" ]; then
        echo -e "${RED}Regra $rule_id não encontrada${NC}"
        exit 1
    fi
    
    # Deletar
    local delete_response
    delete_response=$(curl $CURL_OPTS -w "%{http_code}" \
        -X DELETE "$KIBANA_HOST/api/detection_engine/rules?id=$internal_id" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    if [ "$delete_response" = "200" ]; then
        echo -e "${GREEN}✓ Regra $rule_id eliminada${NC}"
    else
        echo -e "${RED}✗ Erro: HTTP $delete_response${NC}"
        exit 1
    fi
}

# ============================================
# Export Rules
# ============================================
cmd_export() {
    local output_dir="${1:-./exported-rules}"
    
    check_password
    check_dependencies
    
    mkdir -p "$output_dir"
    
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    local rules=$(echo "$response" | jq '.data')
    local total=$(echo "$rules" | jq 'length')
    
    if [ "$total" -eq 0 ]; then
        echo -e "${YELLOW}Nenhuma regra para exportar${NC}"
        exit 0
    fi
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Exportar todas
    local all_file="$output_dir/all_rules_$timestamp.json"
    echo "$rules" | jq '.' > "$all_file"
    
    echo -e "${GREEN}✓ $total regras exportadas para $all_file${NC}"
    
    # Exportar por severidade
    for severity in critical high medium low; do
        local sev_rules=$(echo "$rules" | jq "[.[] | select(.severity == \"$severity\")]")
        local count=$(echo "$sev_rules" | jq 'length')
        
        if [ "$count" -gt 0 ]; then
            local sev_file="$output_dir/rules_${severity}_$timestamp.json"
            echo "$sev_rules" | jq '.' > "$sev_file"
            echo "  - $severity: $count regras"
        fi
    done
}

# ============================================
# Test Rule
# ============================================
cmd_test() {
    local rule_id="$1"
    
    check_password
    check_dependencies
    
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    local rule
    rule=$(echo "$response" | jq ".data[] | select(.rule_id == \"$rule_id\")")
    
    if [ -z "$rule" ]; then
        echo -e "${RED}Regra $rule_id não encontrada${NC}"
        exit 1
    fi
    
    echo
    echo "========================================================================"
    echo "Teste de Regra: $(echo "$rule" | jq -r '.name')"
    echo "========================================================================"
    echo
    
    echo "ID: $(echo "$rule" | jq -r '.rule_id')"
    echo "Tipo: $(echo "$rule" | jq -r '.type')"
    echo "Severidade: $(echo "$rule" | jq -r '.severity')"
    echo "Risk Score: $(echo "$rule" | jq -r '.risk_score')"
    echo "Ativa: $(echo "$rule" | jq -r '.enabled')"
    
    echo
    echo "Query:"
    echo "  $(echo "$rule" | jq -r '.query // "N/A"')"
    
    echo
    echo "Índices:"
    echo "$rule" | jq -r '.index[]? // empty' | sed 's/^/  - /'
    
    echo
    echo "Tags:"
    echo "$rule" | jq -r '.tags[]? // empty' | sed 's/^/  - /'
    
    # MITRE ATT&CK
    local threats=$(echo "$rule" | jq '.threat[]? // empty')
    if [ -n "$threats" ]; then
        echo
        echo "MITRE ATT&CK:"
        echo "$threats" | jq -r '
            "  Tactic: " + .tactic.name + " (" + .tactic.id + ")" + 
            (if .technique then "\n" + (.technique[] | 
                "    - " + .name + " (" + .id + ")"
            ) else "" end)
        '
    fi
    
    echo
}

# ============================================
# Create from Template
# ============================================
cmd_create() {
    local name="$1"
    local output_file="$2"
    
    if [ -z "$name" ] || [ -z "$output_file" ]; then
        echo -e "${RED}Uso: $0 create \"Nome da Regra\" output-file.json${NC}"
        exit 1
    fi
    
    local template_file="../rule-templates/rule-template.json"
    
    if [ ! -f "$template_file" ]; then
        echo -e "${RED}Template não encontrado: $template_file${NC}"
        exit 1
    fi
    
    local timestamp=$(date +%Y%m%d%H%M%S)
    local rule_id="custom-$timestamp"
    
    # Criar regra a partir do template
    cat "$template_file" | jq \
        --arg name "$name" \
        --arg rule_id "$rule_id" \
        '.name = $name | .rule_id = $rule_id' \
        > "$output_file"
    
    echo -e "${GREEN}✓ Regra criada: $output_file${NC}"
    echo "  Edite o ficheiro e depois use 'provision' para aplicar"
}

# ============================================
# Help
# ============================================
show_help() {
    cat << EOF
${BLUE}╔════════════════════════════════════════════════════════════╗
║        SIEM Rule Manager - Bash Edition                   ║
╚════════════════════════════════════════════════════════════╝${NC}

${GREEN}Uso:${NC} $0 <comando> [opções]

${GREEN}Comandos Disponíveis:${NC}

  ${YELLOW}list${NC} [--enabled-only] [--severity LEVEL]
      Lista regras configuradas
      
      Opções:
        --enabled-only        Apenas regras ativas
        --severity LEVEL      Filtrar por severidade (low|medium|high|critical)
      
      Exemplos:
        $0 list
        $0 list --enabled-only
        $0 list --severity critical

  ${YELLOW}stats${NC}
      Mostra estatísticas das regras
      
      Exemplo:
        $0 stats

  ${YELLOW}enable${NC} <rule_id>
      Ativa uma regra
      
      Exemplo:
        $0 enable web-001-sql-injection

  ${YELLOW}disable${NC} <rule_id>
      Desativa uma regra
      
      Exemplo:
        $0 disable web-001-sql-injection

  ${YELLOW}delete${NC} <rule_id>
      Elimina uma regra
      
      Exemplo:
        $0 delete web-001-sql-injection

  ${YELLOW}export${NC} [output_dir]
      Exporta todas as regras para ficheiros JSON
      
      Exemplo:
        $0 export ./backup-rules

  ${YELLOW}test${NC} <rule_id>
      Mostra detalhes de uma regra
      
      Exemplo:
        $0 test web-001-sql-injection

  ${YELLOW}create${NC} "Nome da Regra" <output_file>
      Cria nova regra a partir do template
      
      Exemplo:
        $0 create "Minha Regra" rules/custom/my-rule.json

${GREEN}Variáveis de Ambiente:${NC}

  KIBANA_HOST              URL do Kibana (default: https://localhost:5601)
  ELASTICSEARCH_USERNAME   Username (default: elastic)
  ELASTIC_PASSWORD         Password (OBRIGATÓRIO)
  VERIFY_SSL               Verificar SSL (default: false)

${GREEN}Exemplos:${NC}

  # Definir password
  export ELASTIC_PASSWORD=your_password_here
  
  # Listar todas as regras
  $0 list
  
  # Listar apenas regras críticas ativas
  $0 list --enabled-only --severity critical
  
  # Estatísticas
  $0 stats
  
  # Exportar para backup
  $0 export ./backup-\$(date +%Y%m%d)

EOF
}

# ============================================
# Main
# ============================================
main() {
    local command="$1"
    shift
    
    case "$command" in
        list)
            local enabled_only="false"
            local severity=""
            
            while [ $# -gt 0 ]; do
                case "$1" in
                    --enabled-only)
                        enabled_only="true"
                        shift
                        ;;
                    --severity)
                        severity="$2"
                        shift 2
                        ;;
                    *)
                        shift
                        ;;
                esac
            done
            
            cmd_list "$enabled_only" "$severity"
            ;;
            
        stats)
            cmd_stats
            ;;
            
        enable)
            if [ -z "$1" ]; then
                echo -e "${RED}Erro: rule_id não especificado${NC}"
                echo "Uso: $0 enable <rule_id>"
                exit 1
            fi
            cmd_enable "$1"
            ;;
            
        disable)
            if [ -z "$1" ]; then
                echo -e "${RED}Erro: rule_id não especificado${NC}"
                echo "Uso: $0 disable <rule_id>"
                exit 1
            fi
            cmd_disable "$1"
            ;;
            
        delete)
            if [ -z "$1" ]; then
                echo -e "${RED}Erro: rule_id não especificado${NC}"
                echo "Uso: $0 delete <rule_id>"
                exit 1
            fi
            cmd_delete "$1"
            ;;
            
        export)
            cmd_export "$1"
            ;;
            
        test)
            if [ -z "$1" ]; then
                echo -e "${RED}Erro: rule_id não especificado${NC}"
                echo "Uso: $0 test <rule_id>"
                exit 1
            fi
            cmd_test "$1"
            ;;
            
        create)
            cmd_create "$1" "$2"
            ;;
            
        help|--help|-h)
            show_help
            ;;
            
        *)
            echo -e "${RED}Comando desconhecido: $command${NC}"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Executar
main "$@"
