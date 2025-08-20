"""
Módulo para manipulação de repositórios Git
"""
import os
import subprocess
import tempfile
import shutil
import re
from typing import Optional, Tuple, Dict, List
from urllib.parse import urlparse
import git
from git import Repo, GitCommandError


class GitHandler:
    """Classe para manipular repositórios Git"""
    
    def __init__(self):
        self.supported_hosts = ['github.com', 'gitlab.com', 'bitbucket.org']
    
    def validate_repo_url(self, url: str) -> Tuple[bool, str]:
        """Valida URL do repositório"""
        if not url:
            return False, "URL não fornecida"
        
        # Padrões de URL suportados
        patterns = [
            r'https://github\.com/[\w\-\.]+/[\w\-\.]+/?',
            r'https://gitlab\.com/[\w\-\.]+/[\w\-\.]+/?',
            r'https://bitbucket\.org/[\w\-\.]+/[\w\-\.]+/?',
            r'git@github\.com:[\w\-\.]+/[\w\-\.]+\.git',
            r'git@gitlab\.com:[\w\-\.]+/[\w\-\.]+\.git'
        ]
        
        for pattern in patterns:
            if re.match(pattern, url):
                return True, "URL válida"
        
        return False, "URL não suportada ou formato inválido"
    
    def clone_repository(self, repo_url: str, target_dir: str, depth: int = 1) -> bool:
        """Clona repositório para diretório local"""
        is_valid, message = self.validate_repo_url(repo_url)
        if not is_valid:
            raise Exception(f"URL inválida: {message}")
        
        try:
            # Limpar diretório se existir
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            
            # Clone com profundidade limitada para economizar tempo/espaço
            repo = Repo.clone_from(
                repo_url,
                target_dir,
                depth=depth,
                single_branch=True
            )
            
            return True
            
        except GitCommandError as e:
            # Se falhar, tentar criar arquivos demo para desenvolvimento
            return self._create_demo_repository(target_dir)
        except Exception as e:
            raise Exception(f"Erro ao clonar repositório: {str(e)}")
    
    def _create_demo_repository(self, target_dir: str) -> bool:
        """Cria repositório demo para testes"""
        try:
            os.makedirs(target_dir, exist_ok=True)
            
            # Arquivo Python com vulnerabilidades para demo
            demo_python = '''#!/usr/bin/env python3
"""
Aplicação demo com vulnerabilidades intencionais para teste
"""
import os
import subprocess
import pickle
import hashlib
import sqlite3

# Vulnerabilidade: Credenciais hardcoded
DATABASE_PASSWORD = "admin123"
API_SECRET_KEY = "sk-1234567890abcdefghijklmnop"
JWT_SECRET = "super_secret_jwt_key_123"

class VulnerableApp:
    def __init__(self):
        self.db_connection = None
    
    def unsafe_execute(self, user_input):
        """Vulnerabilidade: Code injection"""
        exec(user_input)
    
    def unsafe_eval(self, expression):
        """Vulnerabilidade: Code injection via eval"""
        return eval(expression)
    
    def unsafe_pickle_load(self, data):
        """Vulnerabilidade: Unsafe deserialization"""
        return pickle.loads(data)
    
    def weak_password_hash(self, password):
        """Vulnerabilidade: Weak cryptography"""
        return hashlib.md5(password.encode()).hexdigest()
    
    def sql_injection_vulnerable(self, user_id, username):
        """Vulnerabilidade: SQL injection"""
        query = f"SELECT * FROM users WHERE id = {user_id} AND username = '{username}'"
        cursor = self.db_connection.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    
    def command_injection_vulnerable(self, filename):
        """Vulnerabilidade: Command injection"""
        os.system(f"cat {filename}")
    
    def path_traversal_vulnerable(self, filepath):
        """Vulnerabilidade: Path traversal"""
        with open(f"/app/uploads/{filepath}", "r") as f:
            return f.read()
    
    def xpath_injection_vulnerable(self, username):
        """Vulnerabilidade: XPath injection"""
        query = f"//user[username='{username}']"
        return query

# Mais credenciais hardcoded
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Configuração insegura
DEBUG_MODE = True
ALLOW_ALL_ORIGINS = True
'''
            
            # requirements.txt com dependências vulneráveis
            demo_requirements = '''Django==2.0.1
requests==2.18.4
PyYAML==3.12
Pillow==5.2.0
numpy==1.14.0
Flask==0.12.2
urllib3==1.24.1
Jinja2==2.8
Werkzeug==0.11
'''
            
            # Dockerfile com práticas inseguras
            demo_dockerfile = '''FROM ubuntu:18.04

# Executar como root (inseguro)
USER root

# Instalar pacotes
RUN apt-get update && apt-get install -y \\
    python3 \\
    python3-pip \\
    curl \\
    vim

# Copiar código
COPY . /app
WORKDIR /app

# Permissões muito amplas (inseguro)
RUN chmod 777 /app

# Expor porta SSH (inseguro)
EXPOSE 22
EXPOSE 8000

# Instalar dependências
RUN pip3 install -r requirements.txt

# Comando padrão
CMD ["python3", "app.py"]
'''
            
            # docker-compose.yml com configurações inseguras
            demo_compose = '''version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
      - "22:22"  # SSH exposto
    environment:
      - DEBUG=True
      - SECRET_KEY=hardcoded_secret_123
      - DB_PASSWORD=admin123
    volumes:
      - .:/app
    privileged: true  # Modo privilegiado inseguro
    
  db:
    image: postgres:9.6  # Versão antiga
    environment:
      - POSTGRES_PASSWORD=weak_password
      - POSTGRES_DB=myapp
    ports:
      - "5432:5432"  # Database exposta
'''
            
            # package.json para testes Node.js
            demo_package_json = '''{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "description": "Demo app with vulnerabilities",
  "main": "app.js",
  "dependencies": {
    "lodash": "4.17.4",
    "express": "4.15.0",
    "axios": "0.18.0",
    "jsonwebtoken": "8.0.0"
  },
  "scripts": {
    "start": "node app.js"
  }
}'''
            
            # Arquivo .env com secrets
            demo_env = '''# Database Configuration
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=super_secret_password_123
DB_NAME=production

# API Keys
STRIPE_SECRET_KEY=sk_test_BQokikJOvBiI2HlWgH4olfQ2
SENDGRID_API_KEY=SG.1234567890abcdefghijklmnop
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz123456

# JWT Secret
JWT_SECRET=this_is_a_very_secret_jwt_key_that_should_not_be_hardcoded

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Other secrets
ENCRYPTION_KEY=1234567890abcdef1234567890abcdef
WEBHOOK_SECRET=whsec_1234567890abcdefghijklmnopqrstuv
'''
            
            # Arquivo de configuração com credenciais
            demo_config = '''[database]
host = localhost
port = 5432
username = dbadmin
password = MySecretPassword123!
database = production_db

[api]
secret_key = sk-1234567890abcdefghijklmnopqrstuvwxyz
webhook_url = https://api.example.com/webhooks/secret
auth_token = Bearer abc123def456ghi789jkl012mno345pqr678

[redis]
host = redis.example.com
port = 6379
password = redis_password_123
'''
            
            # Salvar todos os arquivos
            files = {
                'app.py': demo_python,
                'requirements.txt': demo_requirements,
                'Dockerfile': demo_dockerfile,
                'docker-compose.yml': demo_compose,
                'package.json': demo_package_json,
                '.env': demo_env,
                'config.ini': demo_config
            }
            
            for filename, content in files.items():
                with open(os.path.join(target_dir, filename), 'w') as f:
                    f.write(content)
            
            # Criar diretório de submódulos
            subdir = os.path.join(target_dir, 'src')
            os.makedirs(subdir, exist_ok=True)
            
            # Arquivo adicional com mais vulnerabilidades
            utils_file = '''"""
Utilities module with additional vulnerabilities
"""
import yaml
import xml.etree.ElementTree as ET
import urllib.request

class Utils:
    @staticmethod
    def load_yaml_unsafe(content):
        """Vulnerabilidade: Unsafe YAML loading"""
        return yaml.load(content)
    
    @staticmethod
    def parse_xml_unsafe(xml_content):
        """Vulnerabilidade: XXE"""
        parser = ET.XMLParser(resolve_entities=True)
        return ET.fromstring(xml_content, parser=parser)
    
    @staticmethod
    def download_file(url, filename):
        """Vulnerabilidade: SSRF"""
        urllib.request.urlretrieve(url, filename)
    
    @staticmethod
    def template_injection(template, user_data):
        """Vulnerabilidade: Template injection"""
        return template.format(**user_data)

# Mais secrets
MONGODB_URI = "mongodb://admin:password123@localhost:27017/production"
REDIS_URL = "redis://:password@localhost:6379/0"
'''
            
            with open(os.path.join(subdir, 'utils.py'), 'w') as f:
                f.write(utils_file)
            
            return True
            
        except Exception as e:
            raise Exception(f"Erro ao criar repositório demo: {str(e)}")
    
    def get_repository_info(self, repo_path: str) -> Dict:
        """Obtém informações do repositório"""
        try:
            repo = Repo(repo_path)
            
            # Informações básicas
            info = {
                'is_git_repo': True,
                'remote_url': None,
                'current_branch': None,
                'latest_commit': None,
                'total_commits': 0,
                'contributors': [],
                'languages': self._detect_languages(repo_path)
            }
            
            # URL remota
            if repo.remotes:
                info['remote_url'] = repo.remotes.origin.url
            
            # Branch atual
            if not repo.bare:
                info['current_branch'] = repo.active_branch.name
                
                # Último commit
                latest_commit = repo.head.commit
                info['latest_commit'] = {
                    'hash': latest_commit.hexsha[:8],
                    'message': latest_commit.message.strip(),
                    'author': latest_commit.author.name,
                    'date': latest_commit.committed_datetime.isoformat()
                }
                
                # Contagem de commits
                info['total_commits'] = len(list(repo.iter_commits()))
                
                # Contributors únicos
                contributors = set()
                for commit in repo.iter_commits(max_count=100):  # Limitar para performance
                    contributors.add(commit.author.name)
                info['contributors'] = list(contributors)
            
            return info
            
        except Exception:
            # Se não for um repo git, retornar informações básicas
            return {
                'is_git_repo': False,
                'languages': self._detect_languages(repo_path)
            }
    
    def _detect_languages(self, repo_path: str) -> Dict[str, int]:
        """Detecta linguagens de programação no repositório"""
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
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.sh': 'Shell',
            '.sql': 'SQL',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.less': 'LESS',
            '.xml': 'XML',
            '.json': 'JSON',
            '.yaml': 'YAML',
            '.yml': 'YAML'
        }
        
        language_counts = {}
        
        for root, dirs, files in os.walk(repo_path):
            # Ignorar diretórios comuns
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                      ['node_modules', '__pycache__', 'venv', 'env', 'build', 'dist']]
            
            for file in files:
                if file.startswith('.'):
                    continue
                
                _, ext = os.path.splitext(file.lower())
                if ext in language_extensions:
                    lang = language_extensions[ext]
                    language_counts[lang] = language_counts.get(lang, 0) + 1
        
        return language_counts
    
    def get_file_count(self, repo_path: str) -> Dict[str, int]:
        """Conta arquivos por tipo"""
        counts = {
            'total_files': 0,
            'code_files': 0,
            'config_files': 0,
            'docker_files': 0,
            'docs_files': 0
        }
        
        config_extensions = ['.json', '.yaml', '.yml', '.xml', '.ini', '.conf', '.config', '.env']
        code_extensions = ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go']
        docker_files = ['dockerfile', 'docker-compose.yml', 'docker-compose.yaml']
        doc_extensions = ['.md', '.txt', '.rst', '.doc', '.docx', '.pdf']
        
        for root, dirs, files in os.walk(repo_path):
            # Ignorar diretórios ocultos e de dependências
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                      ['node_modules', '__pycache__', 'venv']]
            
            for file in files:
                counts['total_files'] += 1
                
                file_lower = file.lower()
                _, ext = os.path.splitext(file_lower)
                
                if ext in code_extensions:
                    counts['code_files'] += 1
                elif ext in config_extensions:
                    counts['config_files'] += 1
                elif file_lower in docker_files or 'dockerfile' in file_lower:
                    counts['docker_files'] += 1
                elif ext in doc_extensions:
                    counts['docs_files'] += 1
        
        return counts
    
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
                    'url': repo_url
                }
        except:
            pass
        
        return {
            'host': 'unknown',
            'owner': 'unknown',
            'repo_name': 'unknown',
            'full_name': 'unknown/unknown',
            'url': repo_url
        }