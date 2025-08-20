#!/bin/bash
# deploy.sh - Script de deploy para SecureQA Suite

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 SecureQA Suite Deploy Script${NC}"
echo "=================================="

# Verificar se Docker está instalado
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker não encontrado. Por favor, instale o Docker primeiro.${NC}"
    exit 1
fi

# Verificar se Docker Compose está disponível
if ! docker compose version &> /dev/null && ! docker-compose --version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose não encontrado. Por favor, instale o Docker Compose.${NC}"
    exit 1
fi

# Função para usar docker compose ou docker-compose
docker_compose_cmd() {
    if docker compose version &> /dev/null; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

# Criar diretórios necessários
echo -e "${YELLOW}📁 Criando diretórios...${NC}"
mkdir -p temp logs reports ssl

# Definir permissões
chmod 755 temp logs reports

# Build da imagem
echo -e "${YELLOW}🔨 Construindo imagem Docker...${NC}"
docker build -t secureqa-suite:latest .

# Verificar se build foi bem-sucedido
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Build concluído com sucesso!${NC}"
else
    echo -e "${RED}❌ Erro no build da imagem${NC}"
    exit 1
fi

# Parar containers existentes
echo -e "${YELLOW}🛑 Parando containers existentes...${NC}"
docker_compose_cmd down --remove-orphans

# Subir aplicação
echo -e "${YELLOW}🆙 Subindo aplicação...${NC}"
docker_compose_cmd up -d

# Verificar status
sleep 10
if docker_compose_cmd ps | grep -q "Up"; then
    echo -e "${GREEN}✅ SecureQA Suite está rodando!${NC}"
    echo -e "${GREEN}🌐 Acesse: http://localhost:8501${NC}"
    
    # Mostrar logs
    echo -e "${YELLOW}📋 Últimos logs:${NC}"
    docker_compose_cmd logs --tail=10 secureqa-suite
else
    echo -e "${RED}❌ Erro ao iniciar aplicação${NC}"
    docker_compose_cmd logs secureqa-suite
    exit 1
fi

echo -e "${GREEN}🎉 Deploy concluído com sucesso!${NC}"

---