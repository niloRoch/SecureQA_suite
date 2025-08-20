#!/bin/bash
# setup.sh - Script de configuração inicial

set -e

echo "🔧 Configuração Inicial do SecureQA Suite"
echo "========================================"

# Verificar Python
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo "❌ Python não encontrado. Por favor, instale Python 3.8+"
    exit 1
fi

# Verificar versão do Python
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "🐍 Python versão: $PYTHON_VERSION"

# Criar ambiente virtual
echo "📦 Criando ambiente virtual..."
$PYTHON_CMD -m venv venv

# Ativar ambiente virtual
source venv/bin/activate

# Atualizar pip
echo "⬆️ Atualizando pip..."
pip install --upgrade pip

# Instalar dependências
echo "📚 Instalando dependências..."
pip install -r requirements.txt

# Criar diretórios
echo "📁 Criando estrutura de diretórios..."
mkdir -p {temp,logs,reports,cache}

# Configurar git hooks (opcional)
if [ -d ".git" ]; then
    echo "🪝 Configurando git hooks..."
    cp scripts/pre-commit.sh .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
fi

echo "✅ Configuração concluída!"
echo ""
echo "Para executar a aplicação:"
echo "1. source venv/bin/activate"
echo "2. streamlit run app.py"

---