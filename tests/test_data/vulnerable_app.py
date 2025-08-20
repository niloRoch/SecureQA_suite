"""
Aplicação de exemplo com múltiplas vulnerabilidades para testes
Este arquivo contém vulnerabilidades intencionais para testar o scanner
"""
import os
import subprocess
import pickle
import hashlib
import sqlite3
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILIDADE: Hardcoded secrets
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk_live_1234567890abcdef1234567890abcdef"
SECRET_KEY = "my-super-secret-key-for-jwt"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABILIDADE: Weak cryptography
def hash_password(password):
    """Usa MD5 para hash de senhas - VULNERÁVEL"""
    return hashlib.md5(password.encode()).hexdigest()

def weak_hash(data):
    """Usa SHA1 - VULNERÁVEL"""
    return hashlib.sha1(data.encode()).hexdigest()

# VULNERABILIDADE: Command injection
def process_file(filename):
    """Executa comandos sem sanitização - VULNERÁVEL"""
    os.system(f"cat {filename}")
    
def backup_database(db_name):
    """Command injection via subprocess - VULNERÁVEL"""
    subprocess.call(f"pg_dump {db_name} > backup.sql", shell=True)

def run_user_command(command):
    """Execução direta de comando do usuário - CRÍTICO"""
    os.system(command)

# VULNERABILIDADE: Code injection
def execute_user_code(code):
    """Permite execução de código arbitrário - CRÍTICO"""
    exec(code)

def evaluate_expression(expression):
    """Avalia expressões do usuário - CRÍTICO"""
    return eval(expression)

# VULNERABILIDADE: SQL Injection
def get_user_by_id(user_id):
    """SQL injection clássico - VULNERÁVEL"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def authenticate_user(username, password):
    """SQL injection em autenticação - CRÍTICO"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(search_term):
    """SQL injection em busca - VULNERÁVEL"""
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILIDADE: Unsafe deserialization
def load_user_data(serialized_data):
    """Deserialização insegura com pickle - CRÍTICO"""
    return pickle.loads(serialized_data)

def load_config_from_yaml(yaml_content):
    """YAML load inseguro - VULNERÁVEL"""
    return yaml.load(yaml_content)

def deserialize_session(session_data):
    """Deserialização de sessão sem validação - VULNERÁVEL"""
    import json
    return json.loads(session_data)  # Sem validação adequada

# VULNERABILIDADE: Path traversal
def read_file(filename):
    """Leitura de arquivo sem validação - VULNERÁVEL"""
    with open(filename, 'r') as f:
        return f.read()

def serve_static_file(filepath):
    """Path traversal em arquivos estáticos - VULNERÁVEL"""
    return open(f"./static/{filepath}", 'r').read()

def load_template(template_name):
    """Path traversal em templates - VULNERÁVEL"""
    with open(f"templates/../{template_name}", 'r') as f:
        return f.read()

# VULNERABILIDADE: Server-Side Template Injection (SSTI)
@app.route('/hello')
def hello():
    """SSTI via render_template_string - CRÍTICO"""
    name = request.args.get('name', 'World')
    template = f"Hello {name}!"
    return render_template_string(template)

def generate_email(user_name, message):
    """SSTI em geração de email - VULNERÁVEL"""
    template = f"Dear {user_name}, {message}"
    return render_template_string(template)

# VULNERABILIDADE: XSS via template
@app.route('/profile')
def profile():
    """XSS via template sem escape - VULNERÁVEL"""
    user_bio = request.args.get('bio', '')
    return f"<html><body>Bio: {user_bio}</body></html>"

# VULNERABILIDADE: Insecure random
import random

def generate_session_id():
    """Geração insegura de ID de sessão - VULNERÁVEL"""
    return str(random.randint(1000000, 9999999))

def generate_password_reset_token():
    """Token previsível para reset de senha - CRÍTICO"""
    import time
    return hashlib.md5(str(time.time()).encode()).hexdigest()

# VULNERABILIDADE: Hardcoded database connection
def get_database_connection():
    """Conexão com credenciais hardcoded - VULNERÁVEL"""
    import psycopg2
    return psycopg2.connect(
        host="localhost",
        database="myapp",
        user="admin",
        password="admin123"
    )

# VULNERABILIDADE: Information disclosure
def debug_info():
    """Exposição de informações sensíveis - VULNERÁVEL"""
    import sys
    return {
        'python_version': sys.version,
        'environment': os.environ,
        'current_user': os.getlogin(),
        'working_directory': os.getcwd()
    }

# VULNERABILIDADE: Weak session management
sessions = {}  # Armazenamento inseguro de sessões

def create_session(user_id):
    """Gerenciamento inseguro de sessão - VULNERÁVEL"""
    session_id = str(user_id) + "_session"  # ID previsível
    sessions[session_id] = {'user_id': user_id, 'created': time.time()}
    return session_id

# VULNERABILIDADE: LDAP injection
def ldap_search(username):
    """LDAP injection - VULNERÁVEL"""
    import ldap
    ldap_conn = ldap.initialize("ldap://localhost")
    search_filter = f"(uid={username})"  # Sem sanitização
    return ldap_conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)

# VULNERABILIDADE: XXE (XML External Entity)
def parse_xml(xml_content):
    """Parser XML vulnerável a XXE - CRÍTICO"""
    import xml.etree.ElementTree as ET
    # Parser sem proteção contra XXE
    return ET.fromstring(xml_content)

# VULNERABILIDADE: Insecure file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload de arquivo sem validação - CRÍTICO"""
    file = request.files['file']
    # Salva qualquer arquivo sem verificação
    file.save(f"uploads/{file.filename}")
    return "File uploaded successfully"

# VULNERABILIDADE: Directory listing
@app.route('/files/<path:filename>')
def download_file(filename):
    """Download de arquivo com directory traversal - VULNERÁVEL"""
    import os
    file_path = os.path.join("files", filename)
    with open(file_path, 'rb') as f:
        return f.read()

# VULNERABILIDADE: Timing attack
def check_admin_password(password):
    """Verificação de senha vulnerável a timing attack - VULNERÁVEL"""
    correct_password = "super_admin_password_123"
    if len(password) != len(correct_password):
        return False
    
    for i in range(len(password)):
        if password[i] != correct_password[i]:
            return False
        # Pequeno delay que pode vazar informação
        time.sleep(0.001)
    
    return True

# VULNERABILIDADE: Race condition
import threading

counter = 0
lock_missing = True  # Simula falta de lock

def increment_counter():
    """Race condition sem sincronização - VULNERÁVEL"""
    global counter
    if not lock_missing:  # Se houvesse lock
        # with some_lock:
        pass
    temp = counter
    time.sleep(0.001)  # Simula processamento
    counter = temp + 1

# VULNERABILIDADE: Buffer overflow simulation (em Python é difícil, mas...)
def process_large_input(data):
    """Processamento que pode causar DoS - VULNERÁVEL"""
    if len(data) > 1000000:  # Sem limite adequado
        result = ""
        for char in data:
            result += char * 1000  # Amplificação que pode causar DoS
        return result
    return data

# VULNERABILIDADE: Regex DoS (ReDoS)
import re

def validate_email(email):
    """Regex vulnerável a ReDoS - VULNERÁVEL"""
    # Regex com backtracking catastrófico
    pattern = r'^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))
    return re.match(pattern, email) is not None

if __name__ == '__main__':
    # VULNERABILIDADE: Debug mode em produção
    app.run(debug=True, host='0.0.0.0')  # Debug ativo e bind em todas interfaces