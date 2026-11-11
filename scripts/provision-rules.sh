#!/bin/bash
set -e

# ============================================
# SIEM Rule Provisioner - Bash Version
# Provisiona automaticamente regras de detecção no Kibana Detection Engine
# ============================================

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuração
KIBANA_HOST="${KIBANA_HOST:-https://localhost:5601}"
USERNAME="${ELASTICSEARCH_USERNAME:-elastic}"
PASSWORD="${ELASTIC_PASSWORD}"
VERIFY_SSL="${VERIFY_SSL:-false}"
RULES_DIR="${RULES_DIR:-/rules}"
MAX_RETRIES=60
RETRY_DELAY=10

# Opções curl baseadas em SSL
if [ "$VERIFY_SSL" = "true" ]; then
    CURL_OPTS="-s"
else
    CURL_OPTS="-s -k"
fi

# ============================================
# Funções de Log
# ============================================
log_info() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
}

# ============================================
# Verificações
# ============================================
check_dependencies() {
    log_info "Verificando dependências..."
    
    if ! command -v curl &> /dev/null; then
        log_error "curl não encontrado. Instale: apt-get install curl"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq não encontrado. Instale: apt-get install jq"
        exit 1
    fi
    
    if [ -z "$PASSWORD" ]; then
        log_error "ELASTIC_PASSWORD não definida"
        exit 1
    fi
    
    log_success "Dependências verificadas"
}

# ============================================
# Wait for Kibana
# ============================================
wait_for_kibana() {
    log_info "Aguardando Kibana ficar disponível..."
    
    local attempt=0
    while [ $attempt -lt $MAX_RETRIES ]; do
        if curl $CURL_OPTS -u "$USERNAME:$PASSWORD" \
            "$KIBANA_HOST/api/status" \
            -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200"; then
            log_success "Kibana está disponível!"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep $RETRY_DELAY
    done
    
    log_error "Timeout aguardando Kibana"
    return 1
}

# ============================================
# Enable Detection Engine
# ============================================
enable_detection_engine() {
    log_info "Habilitando Detection Engine..."
    
    local response
    response=$(curl $CURL_OPTS -w "\n%{http_code}" \
        -X POST "$KIBANA_HOST/api/detection_engine/index" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    local http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "409" ]; then
        log_success "Detection Engine habilitado"
        return 0
    else
        log_warn "Status: $http_code"
        return 1
    fi
}

# ============================================
# Get Existing Rules
# ============================================
get_existing_rules() {
    log_info "Verificando regras existentes..."
    
    local response
    response=$(curl $CURL_OPTS \
        -X GET "$KIBANA_HOST/api/detection_engine/rules/_find?per_page=1000" \
        -H "kbn-xsrf: true" \
        -u "$USERNAME:$PASSWORD" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        # Criar mapeamento rule_id -> id
        echo "$response" | jq -r '.data[] | "\(.rule_id):\(.id)"' > /tmp/existing_rules.txt
        
        local count=$(wc -l < /tmp/existing_rules.txt)
        log_success "Encontradas $count regras existentes"
        return 0
    else
        log_warn "Erro ao listar regras"
        return 1
    fi
}

# ============================================
# Load Rule Files
# ============================================
load_rule_files() {
    log_info "Carregando ficheiros de regras..."
    
    if [ ! -d "$RULES_DIR" ]; then
        log_warn "Diretório $RULES_DIR não encontrado"
        return 1
    fi
    
    # Encontrar todos os ficheiros .json recursivamente
    find "$RULES_DIR" -type f -name "*.json" > /tmp/rule_files.txt
    
    local count=$(wc -l < /tmp/rule_files.txt)
    
    if [ $count -eq 0 ]; then
        log_warn "Nenhum ficheiro de regras encontrado"
        return 1
    fi
    
    log_success "$count ficheiros de regras encontrados"
    return 0
}

# ============================================
# Create or Update Rule
# ============================================
create_or_update_rule() {
    local rule_file="$1"
    local rule_content
    
    # Ler conteúdo do ficheiro
    rule_content=$(cat "$rule_file")
    
    # Verificar se é JSON válido
    if ! echo "$rule_content" | jq empty 2>/dev/null; then
        log_fail "$(basename "$rule_file"): JSON inválido"
        return 1
    fi
    
    # Pode ser um array ou objeto único
    local is_array=$(echo "$rule_content" | jq -r 'if type=="array" then "true" else "false" end')
    
    if [ "$is_array" = "true" ]; then
        # Processar cada regra do array
        local count=$(echo "$rule_content" | jq '. | length')
        for i in $(seq 0 $((count - 1))); do
            local rule=$(echo "$rule_content" | jq ".[$i]")
            process_single_rule "$rule" "$(basename "$rule_file")"
        done
    else
        # Processar regra única
        process_single_rule "$rule_content" "$(basename "$rule_file")"
    fi
}

process_single_rule() {
    local rule="$1"
    local filename="$2"
    
    local rule_id=$(echo "$rule" | jq -r '.rule_id // empty')
    local name=$(echo "$rule" | jq -r '.name // "Unknown"')
    
    if [ -z "$rule_id" ]; then
        log_fail "$name: rule_id não definido"
        return 1
    fi
    
    # Verificar se regra já existe
    local internal_id=""
    if [ -f /tmp/existing_rules.txt ]; then
        internal_id=$(grep "^$rule_id:" /tmp/existing_rules.txt | cut -d: -f2)
    fi
    
    local response
    local http_code
    
    if [ -n "$internal_id" ]; then
        # Atualizar regra existente
        response=$(curl $CURL_OPTS -w "\n%{http_code}" \
            -X PUT "$KIBANA_HOST/api/detection_engine/rules?id=$internal_id" \
            -H "kbn-xsrf: true" \
            -H "Content-Type: application/json" \
            -u "$USERNAME:$PASSWORD" \
            -d "$rule" 2>/dev/null)
        
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            log_success "Atualizada: $name"
            return 0
        else
            log_fail "Erro ao atualizar $name: HTTP $http_code"
            return 1
        fi
    else
        # Criar nova regra
        response=$(curl $CURL_OPTS -w "\n%{http_code}" \
            -X POST "$KIBANA_HOST/api/detection_engine/rules" \
            -H "kbn-xsrf: true" \
            -H "Content-Type: application/json" \
            -u "$USERNAME:$PASSWORD" \
            -d "$rule" 2>/dev/null)
        
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            log_success "Criada: $name"
            return 0
        else
            log_fail "Erro ao criar $name: HTTP $http_code"
            # Mostrar erro (primeiras 200 chars)
            echo "$response" | head -n-1 | jq -r '.message // .error // .' 2>/dev/null | head -c 200
            echo
            return 1
        fi
    fi
}

# ============================================
# Provision All Rules
# ============================================
provision_rules() {
    local success_count=0
    local total_count=0
    
    log_info "Provisionando regras..."
    echo
    
    while IFS= read -r rule_file; do
        if [ -f "$rule_file" ]; then
            total_count=$((total_count + 1))
            
            if create_or_update_rule "$rule_file"; then
                success_count=$((success_count + 1))
            fi
        fi
    done < /tmp/rule_files.txt
    
    echo
    echo "=================================="
    echo "Total: $total_count regras"
    echo -e "${GREEN}Sucesso: $success_count${NC}"
    echo -e "${RED}Falhas: $((total_count - success_count))${NC}"
    echo "=================================="
    
    if [ $success_count -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# ============================================
# Cleanup
# ============================================
cleanup() {
    rm -f /tmp/existing_rules.txt /tmp/rule_files.txt
}

# ============================================
# Main
# ============================================
main() {
    echo
    echo "============================================================"
    echo "🚀 SIEM Rule Provisioner - Bash Edition"
    echo "============================================================"
    echo
    
    # Trap para cleanup
    trap cleanup EXIT
    
    check_dependencies
    wait_for_kibana || exit 1
    
    sleep 5
    
    enable_detection_engine
    sleep 5
    
    get_existing_rules
    
    if ! load_rule_files; then
        log_warn "Nenhuma regra para provisionar"
        exit 0
    fi
    
    if provision_rules; then
        echo
        log_success "Provisionamento concluído!"
        exit 0
    else
        log_error "Provisionamento falhou"
        exit 1
    fi
}

# Executar
main "$@"
