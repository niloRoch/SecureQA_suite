"""
Test data module for SecureQA Suite

Este módulo contém arquivos de teste com vulnerabilidades intencionais
para validar o funcionamento do scanner de segurança.

Arquivos incluídos:
- vulnerable_app.py: Aplicação Python com múltiplas vulnerabilidades
- requirements.txt: Dependências Python vulneráveis
- package.json: Dependências Node.js vulneráveis
- Dockerfile: Container com configurações inseguras
- .env: Variáveis de ambiente com secrets expostos
- config.yaml: Arquivo de configuração com credenciais hardcoded
- javascript_vuln.js: Código JavaScript vulnerável
- private_key.pem: Chave privada de exemplo
- database.sql: Script SQL com credenciais expostas

ATENÇÃO: Estes arquivos contêm vulnerabilidades INTENCIONAIS
e devem ser usados APENAS para testes do scanner de segurança.
Nunca use este código em produção!
"""

import os
from pathlib import Path

# Diretório dos dados de teste
TEST_DATA_DIR = Path(__file__).parent

# Lista de arquivos de teste disponíveis
TEST_FILES = [
    'vulnerable_app.py',
    'requirements.txt', 
    'package.json',
    'Dockerfile',
    '.env',
    'config.yaml',
    'javascript_vuln.js',
    'private_key.pem',
    'database.sql',
    'docker-compose.yml'
]

def get_test_file_path(filename: str) -> str:
    """
    Retorna o caminho completo para um arquivo de teste
    
    Args:
        filename: Nome do arquivo de teste
        
    Returns:
        Caminho completo para o arquivo
    """
    file_path = TEST_DATA_DIR / filename
    if not file_path.exists():
        raise FileNotFoundError(f"Arquivo de teste não encontrado: {filename}")
    
    return str(file_path)

def get_test_file_content(filename: str) -> str:
    """
    Lê o conteúdo de um arquivo de teste
    
    Args:
        filename: Nome do arquivo de teste
        
    Returns:
        Conteúdo do arquivo como string
    """
    file_path = get_test_file_path(filename)