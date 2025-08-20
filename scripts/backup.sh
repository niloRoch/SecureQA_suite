#!/bin/bash
# backup.sh - Script de backup

set -e

BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="secureqa_backup_$TIMESTAMP"

echo "💾 Iniciando backup do SecureQA Suite..."

# Criar diretório de backup
mkdir -p "$BACKUP_DIR"

# Criar arquivo de backup
tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='temp/*' \
    --exclude='logs/*.log' \
    .

echo "✅ Backup criado: $BACKUP_DIR/$BACKUP_NAME.tar.gz"

# Manter apenas os últimos 5 backups
cd "$BACKUP_DIR"
ls -t secureqa_backup_*.tar.gz | tail -n +6 | xargs -r rm

echo "🧹 Backups antigos removidos (mantendo os 5 mais recentes)"

---

# Makefile para automação

.PHONY: install run test build deploy clean backup health

# Instalação
install:
	@echo "📦 Instalando SecureQA Suite..."
	@chmod +x scripts/setup.sh
	@./scripts/setup.sh

# Executar em desenvolvimento
run:
	@echo "🚀 Executando aplicação..."
	@source venv/bin/activate && streamlit run app.py

# Executar testes
test:
	@echo "🧪 Executando testes..."
	@source venv/bin/activate && python -m pytest tests/

# Build Docker
build:
	@echo "🔨 Construindo imagem Docker..."
	@docker build -t secureqa-suite:latest .

# Deploy com Docker
deploy:
	@echo "🚀 Fazendo deploy..."
	@chmod +x scripts/deploy.sh
	@./scripts/deploy.sh

# Verificar saúde
health:
	@echo "🏥 Verificando saúde..."
	@chmod +x scripts/health-check.sh
	@./scripts/health-check.sh

# Backup
backup:
	@echo "💾 Criando backup..."
	@chmod +x scripts/backup.sh
	@./scripts/backup.sh

# Limpeza
clean:
	@echo "🧹 Limpando arquivos temporários..."
	@rm -rf temp/* logs/*.log reports/*.pdf cache/*
	@docker system prune -f

# Ajuda
help:
	@echo "SecureQA Suite - Comandos disponíveis:"
	@echo ""
	@echo "  install  - Instalar dependências"
	@echo "  run      - Executar em desenvolvimento"
	@echo "  test     - Executar testes"
	@echo "  build    - Build da imagem Docker"
	@echo "  deploy   - Deploy com Docker"
	@echo "  health   - Verificar saúde da aplicação"
	@echo "  backup   - Criar backup"
	@echo "  clean    - Limpar arquivos temporários"
	@echo "  help     - Mostrar esta ajuda"