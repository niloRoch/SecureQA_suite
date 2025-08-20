#!/bin/bash
# health-check.sh - Script de verificação de saúde

set -e

APP_URL="http://localhost:8501"
TIMEOUT=30

echo "🏥 Verificando saúde da aplicação..."

# Função para verificar se a aplicação está respondendo
check_health() {
    local url="$1"
    local timeout="$2"
    
    if curl -f -s --max-time "$timeout" "$url/_stcore/health" > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Tentar conectar
if check_health "$APP_URL" "$TIMEOUT"; then
    echo "✅ Aplicação está saudável!"
    
    # Verificar métricas adicionais
    echo "📊 Verificando métricas:"
    
    # Status dos containers
    if command -v docker &> /dev/null; then
        echo "🐳 Status dos containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep secureqa || true
    fi
    
    # Uso de memória
    if [ -f "/proc/meminfo" ]; then
        MEMORY_USAGE=$(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
        echo "💾 Uso de memória: $MEMORY_USAGE"
    fi
    
    # Espaço em disco
    DISK_USAGE=$(df -h . | awk 'NR==2{print $5}')
    echo "💿 Uso de disco: $DISK_USAGE"
    
    exit 0
else
    echo "❌ Aplicação não está respondendo!"
    
    # Tentar obter logs
    if command -v docker &> /dev/null; then
        echo "📋 Últimos logs:"
        docker logs --tail=20 secureqa-suite 2>/dev/null || echo "Não foi possível obter logs"
    fi
    
    exit 1
fi

---
