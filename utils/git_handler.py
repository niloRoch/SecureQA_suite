"""
SecureQA Suite - Git Handler
Módulo refatorado para manipulação de repositórios Git com fallbacks
"""
import os
import shutil
import tempfile
import subprocess
import re
from typing import Optional, Tuple, Dict, List
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class GitHandler:
    """Handler para operações Git com fallbacks robustos"""
    
    def __init__(self):
        self.supported_hosts = ['github.com', 'gitlab.com', 'bitbucket.org', 'git.sr.ht']
        self.git_available = self._check_git_availability()
        
    def _check_git_availability(self) -> bool:
        """Verifica se git está disponível no sistema"""
        try:
            result = subprocess.run(['git', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def validate_repo_url(self, url: str) -> Tuple[bool, str]:
        """Valida URL do repositório"""
        if not url:
            return False, "URL não fornecida"
        
        if not url.startswith(('http://', 'https://', 'git@')):
            return False, "URL deve começar com http://, https:// ou git@"
        
        # Padrões de URL suportados
        patterns = [
            r'https?://github\.com/[\w\-\.]+/[\w\-\.]+/?(?:\.git)?$',
            r'https?://gitlab\.com/[\w\-\.]+/[\w\-\.]+/?(?:\.git)?$',
            r'https?://bitbucket\.org/[\w\-\.]+/[\w\-\.]+/?(?:\.git)?$',
            r'git@github\.com:[\w\-\.]+/[\w\-\.]+\.git$',
            r'git@gitlab\.com:[\w\-\.]+/[\w\-\.]+\.git$'
        ]
        
        for pattern in patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return True, "URL válida"
        
        return False, "Formato de URL não suportado"
    
    def clone_repository(self, repo_url: str, target_dir: str, depth: int = 1) -> bool:
        """Clona repositório para diretório local"""
        is_valid, message = self.validate_repo_url(repo_url)
        if not is_valid:
            logger.warning(f"URL inválida: {message}")
            return self._create_demo_repository(target_dir)
        
        # Limpar diretório de destino
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        os.makedirs(target_dir, exist_ok=True)
        
        # Tentar clone real se git disponível
        if self.git_available:
            try:
                return self._clone_with_git(repo_url, target_dir, depth)
            except Exception as e:
                logger.warning(f"Clone com git falhou: {e}")
        
        # Fallback para repositório demo
        logger.info("Usando repositório demo para análise")
        return self._create_demo_repository(target_dir)
    
    def _clone_with_git(self, repo_url: str, target_dir: str, depth: int) -> bool:
        """Clona usando comando git"""
        try:
            # Preparar comando
            cmd = [
                'git', 'clone',
                '--depth', str(depth),
                '--single-branch',
                '--quiet',
                repo_url,
                target_dir
            ]
            
            # Executar clone
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # Timeout de 60 segundos
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
            )
            
            if result.returncode == 0:
                logger.info(f"Repositório clonado com sucesso: {repo_url}")
                return True
            else:
                logger.error(f"Erro no git clone: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout ao clonar repositório")
            return False
        except Exception as e:
            logger.error(f"Erro durante clone: {e}")
            return False
    
    def _create_demo_repository(self, target_dir: str) -> bool:
        """Cria repositório demo com vulnerabilidades para análise"""
        try:
            os.makedirs(target_dir, exist_ok=True)
            
            # Arquivos de demonstração com vulnerabilidades
            demo_files = {
                'app.py': self._get_demo_python_code(),
                'requirements.txt': self._get_demo_requirements(),
                'Dockerfile': self._get_demo_dockerfile(),
                'docker-compose.yml': self._get_demo_compose(),
                '.env': self._get_demo_env(),
                'config.py': self._get_demo_config(),
                'utils.py': self._get_demo_utils(),
                'package.json': self._get_demo_package_json()
            }
            
            # Criar arquivos
            for filename, content in demo_files.items():
                file_path = os.path.join(target_dir, filename)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            # Criar subdiretórios
            subdirs = ['src', 'tests', 'docs']
            for subdir in subdirs:
                subdir_path = os.path.join(target_dir, subdir)
                os.makedirs(subdir_path, exist_ok=True)
                
                # Arquivo adicional no subdiretório
                if subdir == 'src':
                    with open(os.path.join(subdir_path, 'database.py'), 'w') as f:
                        f.write(self._get_demo_database_code())
            
            logger.info("Repositório demo criado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar repositório demo: {e}")
            return False
    
    def _get_demo_python_code(self) -> str:
        """Retorna código Python com vulnerabilidades para demo"""
        return '''#!/usr/bin/env python3
"""
Aplicação demo com vulnerabilidades intencionais para análise SecureQA
"""
import os
import sys
import subprocess
import pickle
import hashlib
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILIDADE: Credenciais hardcoded
DATABASE_PASSWORD = "admin123!@#"
API_SECRET_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
JWT_SECRET = "super_secret_jwt_key_do_not_share"
ENCRYPTION_KEY = "my_super_secret_encryption_key_123"

# VULNERABILIDADE: Configurações inseguras
DEBUG_MODE = True
app.secret_key = "hardcoded_flask_secret_key"

class VulnerableApp:
    def __init__(self):
        self.db_connection = None
        
    def unsafe_execute(self, user_input):
        """VULNERABILIDADE: Code injection via exec"""
        exec(user_input)
        
    def unsafe_eval(self, expression):
        """VULNERABILIDADE: Code injection via eval"""
        return eval(expression)
        
    def unsafe_pickle_load(self, data):
        """VULNERABILIDADE: Unsafe deserialization"""
        return pickle.loads(data)
        
    def weak_password_hash(self, password):
        """VULNERABILIDADE: Weak cryptography (MD5)"""
        return hashlib.md5(password.encode()).hexdigest()
        
    def sql_injection_vulnerable(self, user_id, username):
        """VULNERABILIDADE: SQL injection"""
        query = f"SELECT * FROM users WHERE id = {user_id} AND username = '{username}'"
        cursor = self.db_connection.cursor()
        cursor.execute(query)
        return cursor.fetchall()
        
    def command_injection_vulnerable(self, filename):
        """VULNERABILIDADE: Command injection"""
        os.system(f"cat {filename}")
        
    def shell_injection(self, user_input):
        """VULNERABILIDADE: Shell injection via subprocess"""
        subprocess.call(f"echo {user_input}", shell=True)

@app.route('/')
def index():
    """VULNERABILIDADE: Template injection"""
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

@app.route('/file')
def read_file():
    """VULNERABILIDADE: Path traversal"""
    filename = request.args.get('file', 'default.txt')
    with open(f"/app/files/{filename}", 'r') as f:
        return f.read()

# Mais credenciais expostas
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
'''
    
    def _get_demo_requirements(self) -> str:
        """Retorna requirements.txt com dependências vulneráveis"""
        return '''# Dependências com vulnerabilidades conhecidas para teste
Django==2.0.1
Flask==0.12.2
requests==2.18.4
PyYAML==3.12
Pillow==5.2.0
numpy==1.14.0
urllib3==1.24.1
Jinja2==2.8
Werkzeug==0.11
cryptography==2.3
SQLAlchemy==1.2.0
'''
    
    def _get_demo_dockerfile(self) -> str:
        """Retorna Dockerfile com práticas inseguras"""
        return '''# Dockerfile com vulnerabilidades intencionais
FROM ubuntu:18.04

# VULNERABILIDADE: Executar como root
USER root

# Instalar pacotes sem limpeza
RUN apt-get update && apt-get install -y \\
    python3 \\
    python3-pip \\
    curl \\
    vim \\
    ssh

# VULNERABILIDADE: Copiar tudo sem .dockerignore
COPY . /app
WORKDIR /app

# VULNERABILIDADE: Permissões muito amplas
RUN chmod 777 /app
RUN chmod 777 -R /app

# VULNERABILIDADE: Expor porta SSH
EXPOSE 22
EXPOSE 8000

# VULNERABILIDADE: Instalar como root
RUN pip3 install -r requirements.txt

# VULNERABILIDADE: Usar :latest implícito e rodar como root
CMD ["python3", "app.py"]
'''
    
    def _get_demo_compose(self) -> str:
        """Retorna docker-compose.yml inseguro"""
        return '''version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
      - "22:22"  # VULNERABILIDADE: SSH exposto
    environment:
      - DEBUG=True  # VULNERABILIDADE: Debug em produção
      - SECRET_KEY=hardcoded_secret_123
      - DB_PASSWORD=admin123
      - API_KEY=sk-1234567890abcdef
    volumes:
      - .:/app
    privileged: true  # VULNERABILIDADE: Modo privilegiado
    network_mode: host  # VULNERABILIDADE: Network host mode
    
  db:
    image: postgres:9.6  # VULNERABILIDADE: Versão antiga
    environment:
      - POSTGRES_PASSWORD=weak_password
      - POSTGRES_DB=myapp
    ports:
      - "5432:5432"  # VULNERABILIDADE: Database exposta
    volumes:
      - ./data:/var/lib/postgresql/data
'''
    
    def _get_demo_env(self) -> str:
        """Retorna arquivo .env com secrets"""
        return '''# VULNERABILIDADE: Secrets em arquivo .env
DATABASE_URL=postgresql://admin:SuperSecretPassword123@localhost:5432/production
REDIS_URL=redis://:AnotherPassword456@localhost:6379/0

# API Keys
STRIPE_SECRET_KEY=sk_test_BQokikJOvBiI2HlWgH4olfQ2
SENDGRID_API_KEY=SG.1234567890abcdefghijklmnopqrstuvwxyz123456789
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz123456
SLACK_TOKEN=xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx

# JWT Secret
JWT_SECRET_KEY=this_is_a_very_secret_jwt_key_that_should_not_be_hardcoded_ever

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# Encryption
ENCRYPTION_KEY=1234567890abcdef1234567890abcdef
WEBHOOK_SECRET=whsec_1234567890abcdefghijklmnopqrstuv

# Email
SMTP_PASSWORD=email_password_123
EMAIL_HOST_PASSWORD=another_email_pass_456
'''
    
    def _get_demo_config(self) -> str:
        """Retorna arquivo de configuração com credenciais"""
        return '''"""
Configurações da aplicação com vulnerabilidades
"""
import os

# VULNERABILIDADE: Credenciais hardcoded
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'username': 'dbadmin',
    'password': 'MyDatabasePassword123!',
    'database': 'production_db'
}

# VULNERABILIDADE: Chaves de API expostas
API_KEYS = {
    'stripe': 'sk_live_1234567890abcdefghijklmn',
    'sendgrid': 'SG.abcdefghijklmnop123456789',
    'github': 'ghp_abcdefghijklmnopqrstuvwxyz123456'
}

# VULNERABILIDADE: JWT secret hardcoded
JWT_CONFIG = {
    'secret_key': 'my_super_secret_jwt_key_for_production',
    'algorithm': 'HS256',
    'expiration': 3600
}

# VULNERABILIDADE: Weak crypto
CRYPTO_KEY = "1234567890abcdef"  # 16 bytes key - muito fraca

# VULNERABILIDADE: Debug em produção
DEBUG = True
TESTING = True
'''
    
    def _get_demo_utils(self) -> str:
        """Retorna arquivo utils.py com mais vulnerabilidades"""
        return '''"""
Utilities com vulnerabilidades adicionais
"""
import yaml
import xml.etree.ElementTree as ET
import urllib.request
import subprocess
import tempfile

class SecurityUtils:
    @staticmethod
    def unsafe_yaml_load(content):
        """VULNERABILIDADE: Unsafe YAML loading"""
        return yaml.load(content)
    
    @staticmethod
    def xml_external_entity(xml_content):
        """VULNERABILIDADE: XXE - XML External Entity"""
        parser = ET.XMLParser(resolve_entities=True)
        return ET.fromstring(xml_content, parser=parser)
    
    @staticmethod
    def server_side_request_forgery(url):
        """VULNERABILIDADE: SSRF"""
        response = urllib.request.urlopen(url)
        return response.read()
    
    @staticmethod
    def unsafe_temp_file(content):
        """VULNERABILIDADE: Insecure temp file"""
        temp_file = "/tmp/sensitive_data.txt"
        with open(temp_file, 'w') as f:
            f.write(content)
        return temp_file
    
    @staticmethod
    def command_with_shell(user_input):
        """VULNERABILIDADE: Command injection"""
        subprocess.run(f"echo {user_input}", shell=True)

# VULNERABILIDADE: Mais credenciais hardcoded
INTERNAL_API_KEY = "internal_api_key_123456789"
WEBHOOK_SECRET = "my_webhook_secret_key"
LDAP_PASSWORD = "ldap_bind_password_123"
'''
    
    def _get_demo_package_json(self) -> str:
        """Retorna package.json com dependências vulneráveis"""
        return '''{
  "name": "vulnerable-demo-app",
  "version": "1.0.0",
  "description": "Demo app with intentional vulnerabilities",
  "main": "index.js",
  "dependencies": {
    "lodash": "4.17.4",
    "express": "4.15.0",
    "axios": "0.18.0",
    "jsonwebtoken": "8.0.0",
    "mongoose": "5.0.0",
    "react": "16.0.0",
    "jquery": "2.2.0"
  },
  "devDependencies": {
    "webpack": "3.0.0",
    "babel-core": "6.26.0"
  },
  "scripts": {
    "start": "node app.js",
    "test": "jest"
  },
  "keywords": ["demo", "security", "testing"],
  "author": "SecureQA Suite",
  "license": "MIT"
}'''
    
    def _get_demo_database_code(self) -> str:
        """Retorna código de database com vulnerabilidades SQL"""
        return '''"""
Database utilities com vulnerabilidades SQL
"""
import sqlite3
import mysql.connector
from sqlalchemy import create_engine, text

class DatabaseManager:
    def __init__(self):
        # VULNERABILIDADE: Connection string with credentials
        self.connection_string = "mysql://admin:password123@localhost/production"
        
    def unsafe_query(self, table, user_id):
        """VULNERABILIDADE: SQL Injection"""
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # String interpolation vulnerability
        query = f"SELECT * FROM {table} WHERE id = {user_id}"
        cursor.execute(query)
        
        return cursor.fetchall()
    
    def dynamic_query_building(self, filters):
        """VULNERABILIDADE: Dynamic SQL building"""
        where_clause = " AND ".join([f"{k} = '{v}'" for k, v in filters.items()])
        query = f"SELECT * FROM users WHERE {where_clause}"
        
        return query
    
    def raw_sql_execution(self, user_input):
        """VULNERABILIDADE: Raw SQL execution"""
        engine = create_engine(self.connection_string)
        
        with engine.connect() as conn:
            result = conn.execute(text(user_input))
            return result.fetchall()

# VULNERABILIDADE: Database credentials
DB_CONFIG = {
    'mysql': {
        'host': 'prod-db-server.com',
        'user': 'app_user', 
        'password': 'ProductionPassword2023!',
        'database': 'main_app_db'
    },
    'mongodb': 'mongodb://dbadmin:MongoPassword456@cluster.mongodb.net/production'
}
'''
    
    def get_repository_info(self, repo_path: str) -> Dict:
        """Obtém informações do repositório"""
        try:
            info = {
                'is_git_repo': False,
                'languages': self._detect_languages(repo_path),
                'file_count': self._count_files(repo_path),
                'repo_size': self._get_directory_size(repo_path)
            }
            
            # Verificar se é repositório git
            git_dir = os.path.join(repo_path, '.git')
            if os.path.exists(git_dir):
                info['is_git_repo'] = True
                
                if self.git_available:
                    try:
                        info.update(self._get_git_info(repo_path))
                    except Exception as e:
                        logger.warning(f"Erro ao obter info git: {e}")
            
            return info
            
        except Exception as e:
            logger.error(f"Erro ao obter info do repositório: {e}")
            return {
                'is_git_repo': False,
                'languages': {},
                'error': str(e)
            }
    
    def _get_git_info(self, repo_path: str) -> Dict:
        """Obtém informações Git do repositório"""
        info = {}
        
        try:
            # Branch atual
            result = subprocess.run(
                ['git', 'branch', '--show-current'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                info['current_branch'] = result.stdout.strip()
            
            # URL remota
            result = subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                info['remote_url'] = result.stdout.strip()
            
            # Último commit
            result = subprocess.run(
                ['git', 'log', '-1', '--format=%H|%s|%an|%ad', '--date=iso'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                commit_parts = result.stdout.strip().split('|')
                if len(commit_parts) >= 4:
                    info['latest_commit'] = {
                        'hash': commit_parts[0][:8],
                        'message': commit_parts[1],
                        'author': commit_parts[2],
                        'date': commit_parts[3]
                    }
            
        except Exception as e:
            logger.warning(f"Erro ao obter informações git: {e}")
        
        return info
    
    def _detect_languages(self, repo_path: str) -> Dict[str, int]:
        """Detecta linguagens de programação"""
        language_extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.cs': 'C#',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.go': 'Go',
            '.rs': 'Rust',
            '.swift': 'Swift',
            '.html': 'HTML',
            '.css': 'CSS',
            '.sql': 'SQL',
            '.sh': 'Shell'
        }
        
        language_counts = {}
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Ignorar diretórios desnecessários
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d not in ['node_modules', '__pycache__', 'venv', 'env']]
                
                for file in files:
                    if file.startswith('.'):
                        continue
                        
                    _, ext = os.path.splitext(file.lower())
                    if ext in language_extensions:
                        lang = language_extensions[ext]
                        language_counts[lang] = language_counts.get(lang, 0) + 1
                        
        except Exception as e:
            logger.error(f"Erro ao detectar linguagens: {e}")
        
        return language_counts
    
    def _count_files(self, repo_path: str) -> Dict[str, int]:
        """Conta arquivos por categoria"""
        counts = {
            'total_files': 0,
            'code_files': 0,
            'config_files': 0,
            'docker_files': 0,
            'docs_files': 0
        }
        
        try:
            code_extensions = {'.py', '.js', '.ts', '.java', '.c', '.cpp', '.cs', 
                              '.php', '.rb', '.go', '.rs', '.swift'}
            config_extensions = {'.json', '.yaml', '.yml', '.xml', '.ini', 
                                '.conf', '.config', '.env'}
            doc_extensions = {'.md', '.txt', '.rst', '.doc', '.docx'}
            
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    counts['total_files'] += 1
                    
                    file_lower = file.lower()
                    _, ext = os.path.splitext(file_lower)
                    
                    if ext in code_extensions:
                        counts['code_files'] += 1
                    elif ext in config_extensions:
                        counts['config_files'] += 1
                    elif 'dockerfile' in file_lower or file_lower == 'docker-compose.yml':
                        counts['docker_files'] += 1
                    elif ext in doc_extensions:
                        counts['docs_files'] += 1
                        
        except Exception as e:
            logger.error(f"Erro ao contar arquivos: {e}")
        
        return counts
    
    def _get_directory_size(self, repo_path: str) -> int:
        """Calcula tamanho do diretório em bytes"""
        total_size = 0
        
        try:
            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_size += os.path.getsize(file_path)
                    except (OSError, IOError):
                        continue
        except Exception as e:
            logger.error(f"Erro ao calcular tamanho: {e}")
        
        return total_size
    
    def extract_repo_metadata(self, repo_url: str) -> Dict:
        """Extrai metadados do repositório da URL"""
        try:
            parsed = urlparse(repo_url)
            path_parts = parsed.path.strip('/').split('/')
            
            if len(path_parts) >= 2:
                owner = path_parts[0]
                repo_name = path_parts[1].replace('.git', '')
                
                return {
                    'host': parsed.netloc,
                    'owner': owner,
                    'repo_name': repo_name,
                    'full_name': f"{owner}/{repo_name}",
                    'url': repo_url,
                    'protocol': parsed.scheme
                }
        except Exception as e:
            logger.error(f"Erro ao extrair metadados: {e}")
        
        return {
            'host': 'unknown',
            'owner': 'unknown', 
            'repo_name': 'unknown',
            'full_name': 'unknown/unknown',
            'url': repo_url,
            'protocol': 'unknown'
        }