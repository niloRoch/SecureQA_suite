"""
Testes unitários para SecurityScanner
"""
import unittest
import tempfile
import os
import shutil
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import sys

# Adicionar path do projeto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_scanner import SecurityScanner
from utils.vulnerability_db import VulnerabilityDatabase


class TestSecurityScanner(unittest.TestCase):
    """Testes para a classe SecurityScanner"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.scanner = SecurityScanner()
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Limpeza após cada teste"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def create_test_file(self, filename: str, content: str):
        """Cria arquivo de teste temporário"""
        file_path = os.path.join(self.temp_dir, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return file_path
    
    def test_static_code_analysis_sql_injection(self):
        """Testa detecção de SQL injection"""
        vulnerable_code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()
        '''
        
        self.create_test_file('vulnerable.py', vulnerable_code)
        results = self.scanner.static_code_analysis(self.temp_dir)
        
        # Verificar se SQL injection foi detectado
        sql_vulns = [v for v in results if v['type'] == 'sql_injection']
        self.assertGreater(len(sql_vulns), 0)
        self.assertEqual(sql_vulns[0]['severity'], 'HIGH')
    
    def test_static_code_analysis_command_injection(self):
        """Testa detecção de command injection"""
        vulnerable_code = '''
import os
import subprocess

def process_file(filename):
    os.system(f"cat {filename}")
    subprocess.call(f"ls {filename}", shell=True)
        '''
        
        self.create_test_file('command_vuln.py', vulnerable_code)
        results = self.scanner.static_code_analysis(self.temp_dir)
        
        # Verificar se command injection foi detectado
        cmd_vulns = [v for v in results if v['type'] == 'command_injection']
        self.assertGreater(len(cmd_vulns), 0)
        self.assertEqual(cmd_vulns[0]['severity'], 'CRITICAL')
    
    def test_static_code_analysis_hardcoded_secrets(self):
        """Testa detecção de secrets hardcoded"""
        vulnerable_code = '''
# Configurações da aplicação
DATABASE_PASSWORD = "super_secret_123"
API_KEY = "ak_1234567890abcdef"
SECRET_KEY = "my-secret-key-123"
        '''
        
        self.create_test_file('config.py', vulnerable_code)
        results = self.scanner.static_code_analysis(self.temp_dir)
        
        # Verificar se secrets foram detectados
        secret_vulns = [v for v in results if v['type'] == 'hardcoded_secrets']
        self.assertGreater(len(secret_vulns), 0)
    
    def test_static_code_analysis_weak_crypto(self):
        """Testa detecção de criptografia fraca"""
        vulnerable_code = '''
import hashlib
import crypt

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def old_crypt(data):
    return crypt.crypt(data, "salt")
        '''
        
        self.create_test_file('crypto_weak.py', vulnerable_code)
        results = self.scanner.static_code_analysis(self.temp_dir)
        
        # Verificar se crypto fraco foi detectado
        crypto_vulns = [v for v in results if v['type'] == 'weak_crypto']
        self.assertGreater(len(crypto_vulns), 0)
        self.assertEqual(crypto_vulns[0]['severity'], 'MEDIUM')
    
    def test_static_code_analysis_unsafe_deserialization(self):
        """Testa detecção de deserialização insegura"""
        vulnerable_code = '''
import pickle
import yaml

def load_data(data):
    return pickle.loads(data)

def load_config(config_str):
    return yaml.load(config_str)
        '''
        
        self.create_test_file('deserial.py', vulnerable_code)
        results = self.scanner.static_code_analysis(self.temp_dir)
        
        # Verificar se deserialização insegura foi detectada
        deserial_vulns = [v for v in results if v['type'] == 'unsafe_deserialization']
        self.assertGreater(len(deserial_vulns), 0)
    
    def test_dependency_vulnerability_check_requirements_txt(self):
        """Testa verificação de vulnerabilidades em requirements.txt"""
        requirements_content = '''
Django==2.0.1
requests==2.18.4
PyYAML==3.12
Pillow==5.2.0
numpy==1.14.0
        '''
        
        self.create_test_file('requirements.txt', requirements_content)
        
        # Mock da base de vulnerabilidades
        with patch.object(self.scanner, 'vuln_db') as mock_db:
            mock_db.check_vulnerability.return_value = [
                {
                    'cve': 'CVE-2018-7536',
                    'severity': 'HIGH',
                    'description': 'Vulnerabilidade conhecida em Django 2.0.1',
                    'cvss_score': 7.5,
                    'fixed_version': '2.0.2'
                }
            ]
            
            results = self.scanner.dependency_vulnerability_check(self.temp_dir)
            
            # Verificar se vulnerabilidades foram encontradas
            self.assertGreater(len(results), 0)
            django_vulns = [v for v in results if v['package'] == 'Django']
            self.assertGreater(len(django_vulns), 0)
            self.assertEqual(django_vulns[0]['cve'], 'CVE-2018-7536')
    
    def test_dependency_vulnerability_check_package_json(self):
        """Testa verificação de vulnerabilidades em package.json"""
        package_json = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.10",
                "express": "4.16.0"
            },
            "devDependencies": {
                "webpack": "4.0.0"
            }
        }
        
        self.create_test_file('package.json', json.dumps(package_json))
        
        # Mock da base de vulnerabilidades
        with patch.object(self.scanner, 'vuln_db') as mock_db:
            mock_db.check_vulnerability.return_value = [
                {
                    'cve': 'CVE-2018-3721',
                    'severity': 'HIGH',
                    'description': 'Prototype pollution in lodash',
                    'cvss_score': 8.1,
                    'fixed_version': '4.17.11'
                }
            ]
            
            results = self.scanner.dependency_vulnerability_check(self.temp_dir)
            
            # Verificar se vulnerabilidades foram encontradas
            lodash_vulns = [v for v in results if v['package'] == 'lodash']
            self.assertGreater(len(lodash_vulns), 0)
    
    def test_secrets_detection_aws_keys(self):
        """Testa detecção de chaves AWS"""
        secrets_code = '''
# AWS Configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        '''
        
        self.create_test_file('aws_config.py', secrets_code)
        results = self.scanner.secrets_detection(self.temp_dir)
        
        # Verificar se chaves AWS foram detectadas
        aws_secrets = [s for s in results if 'aws' in s['type']]
        self.assertGreater(len(aws_secrets), 0)
    
    def test_secrets_detection_github_token(self):
        """Testa detecção de tokens GitHub"""
        secrets_code = '''
# GitHub configuration
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef123456"
        '''
        
        self.create_test_file('github_config.py', secrets_code)
        results = self.scanner.secrets_detection(self.temp_dir)
        
        # Verificar se token GitHub foi detectado
        github_secrets = [s for s in results if s['type'] == 'github_token']
        self.assertGreater(len(github_secrets), 0)
    
    def test_secrets_detection_private_key(self):
        """Testa detecção de chaves privadas"""
        private_key = '''
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
... (key content) ...
-----END PRIVATE KEY-----
        '''
        
        self.create_test_file('private_key.pem', private_key)
        results = self.scanner.secrets_detection(self.temp_dir)
        
        # Verificar se chave privada foi detectada
        key_secrets = [s for s in results if s['type'] == 'private_key']
        self.assertGreater(len(key_secrets), 0)
    
    def test_secrets_detection_jwt_token(self):
        """Testa detecção de tokens JWT"""
        jwt_code = '''
# JWT Token for testing
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        '''
        
        self.create_test_file('jwt_config.py', jwt_code)
        results = self.scanner.secrets_detection(self.temp_dir)
        
        # Verificar se JWT foi detectado
        jwt_secrets = [s for s in results if s['type'] == 'jwt_token']
        self.assertGreater(len(jwt_secrets), 0)
    
    def test_dockerfile_analysis_root_user(self):
        """Testa detecção de usuário root no Dockerfile"""
        dockerfile_content = '''
FROM ubuntu:18.04
RUN apt-get update && apt-get install -y python3
USER root
COPY . /app
WORKDIR /app
EXPOSE 8000
CMD ["python3", "app.py"]
        '''
        
        self.create_test_file('Dockerfile', dockerfile_content)
        results = self.scanner.dockerfile_analysis(self.temp_dir)
        
        # Verificar se problema do root foi detectado
        root_issues = [i for i in results if i['rule'] == 'root_user']
        self.assertGreater(len(root_issues), 0)
        self.assertEqual(root_issues[0]['severity'], 'HIGH')
    
    def test_dockerfile_analysis_latest_tag(self):
        """Testa detecção de tag latest no Dockerfile"""
        dockerfile_content = '''
FROM ubuntu:latest
RUN apt-get update
        '''
        
        self.create_test_file('Dockerfile', dockerfile_content)
        results = self.scanner.dockerfile_analysis(self.temp_dir)
        
        # Verificar se problema da tag latest foi detectado
        latest_issues = [i for i in results if i['rule'] == 'latest_tag']
        self.assertGreater(len(latest_issues), 0)
        self.assertEqual(latest_issues[0]['severity'], 'MEDIUM')
    
    def test_dockerfile_analysis_sensitive_ports(self):
        """Testa detecção de portas sensíveis no Dockerfile"""
        dockerfile_content = '''
FROM ubuntu:20.04
EXPOSE 22
EXPOSE 3306
EXPOSE 5432
        '''
        
        self.create_test_file('Dockerfile', dockerfile_content)
        results = self.scanner.dockerfile_analysis(self.temp_dir)
        
        # Verificar se portas sensíveis foram detectadas
        port_issues = [i for i in results if i['rule'] == 'sensitive_ports']
        self.assertGreater(len(port_issues), 0)
    
    def test_dockerfile_analysis_wide_permissions(self):
        """Testa detecção de permissões muito amplas"""
        dockerfile_content = '''
FROM ubuntu:20.04
COPY . /app
RUN chmod 777 /app
        '''
        
        self.create_test_file('Dockerfile', dockerfile_content)
        results = self.scanner.dockerfile_analysis(self.temp_dir)
        
        # Verificar se permissões amplas foram detectadas
        perm_issues = [i for i in results if i['rule'] == 'wide_permissions']
        self.assertGreater(len(perm_issues), 0)
        self.assertEqual(perm_issues[0]['severity'], 'HIGH')
    
    def test_dockerfile_analysis_no_user_specified(self):
        """Testa detecção de ausência de usuário não-root"""
        dockerfile_content = '''
FROM ubuntu:20.04
RUN apt-get update
COPY . /app
WORKDIR /app
        '''
        
        self.create_test_file('Dockerfile', dockerfile_content)
        results = self.scanner.dockerfile_analysis(self.temp_dir)
        
        # Verificar se ausência de USER foi detectada
        no_user_issues = [i for i in results if i['rule'] == 'no_user_specified']
        self.assertGreater(len(no_user_issues), 0)
        self.assertEqual(no_user_issues[0]['severity'], 'MEDIUM')
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_ssl_tls_check_valid_certificate(self, mock_ssl_context, mock_socket):
        """Testa verificação SSL com certificado válido"""
        # Mock do certificado
        mock_cert = {
            'subject': [('CN', 'example.com')],
            'issuer': [('CN', 'Let\'s Encrypt Authority X3')],
            'notAfter': 'Dec 31 23:59:59 2024 GMT',
            'subjectAltName': [('DNS', 'example.com'), ('DNS', 'www.example.com')]
        }
        
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = mock_cert
        mock_ssl_sock.cipher.return_value = ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
        mock_ssl_sock.version.return_value = 'TLSv1.3'
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        results = self.scanner.ssl_tls_check('example.com')
        
        self.assertTrue(results['valid'])
        self.assertEqual(results['version'], 'TLSv1.3')
        self.assertIsInstance(results['security_score'], int)
    
    @patch('requests.head')
    def test_security_headers_check_missing_headers(self, mock_requests):
        """Testa verificação de headers com headers ausentes"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_requests.return_value = mock_response
        
        results = self.scanner.security_headers_check('https://example.com')
        
        self.assertEqual(results['status_code'], 200)
        self.assertGreater(len(results['missing_headers']), 0)
        self.assertLess(results['security_score'], 100)
        
        # Verificar se CSP está ausente
        csp_missing = any(h['header'] == 'Content-Security-Policy' 
                         for h in results['missing_headers'])
        self.assertTrue(csp_missing)
    
    @patch('requests.head')
    def test_security_headers_check_info_disclosure(self, mock_requests):
        """Testa detecção de headers que expõem informações"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'Apache/2.4.41 (Ubuntu)',
            'X-Powered-By': 'PHP/7.4.3'
        }
        mock_requests.return_value = mock_response
        
        results = self.scanner.security_headers_check('https://example.com')
        
        self.assertGreater(len(results['insecure_headers']), 0)
        
        # Verificar se Server header foi detectado
        server_disclosed = any(h['header'] == 'Server' 
                              for h in results['insecure_headers'])
        self.assertTrue(server_disclosed)
    
    def test_generate_summary_with_vulnerabilities(self):
        """Testa geração de resumo com vulnerabilidades"""
        # Simular resultados
        self.scanner.results = {
            'static_analysis': [
                {'severity': 'CRITICAL', 'type': 'sql_injection'},
                {'severity': 'HIGH', 'type': 'command_injection'}
            ],
            'dependency_check': [
                {'severity': 'HIGH', 'package': 'django'},
                {'severity': 'MEDIUM', 'package': 'requests'}
            ],
            'secrets_detection': [
                {'type': 'aws_key'},
                {'type': 'github_token'}
            ],
            'dockerfile_analysis': [
                {'severity': 'HIGH', 'rule': 'root_user'}
            ],
            'ssl_check': {'issues': [{'severity': 'MEDIUM'}]},
            'headers_check': {'missing_headers': [1, 2, 3]}
        }
        
        summary = self.scanner.generate_summary()
        
        self.assertEqual(summary['critical_issues'], 3)  # 1 + 2 secrets
        self.assertEqual(summary['high_issues'], 3)
        self.assertEqual(summary['medium_issues'], 5)  # 1 + 1 + 3 missing headers
        self.assertGreater(summary['risk_score'], 0)
        self.assertEqual(summary['risk_level'], 'CRITICAL')
        self.assertGreater(len(summary['recommendations']), 0)
    
    def test_generate_summary_no_vulnerabilities(self):
        """Testa geração de resumo sem vulnerabilidades"""
        # Simular resultados vazios
        self.scanner.results = {
            'static_analysis': [],
            'dependency_check': [],
            'secrets_detection': [],
            'dockerfile_analysis': [],
            'ssl_check': {'issues': []},
            'headers_check': {'missing_headers': []}
        }
        
        summary = self.scanner.generate_summary()
        
        self.assertEqual(summary['total_issues'], 0)
        self.assertEqual(summary['critical_issues'], 0)
        self.assertEqual(summary['high_issues'], 0)
        self.assertEqual(summary['risk_score'], 0)
        self.assertEqual(summary['risk_level'], 'LOW')
    
    def test_calculate_entropy(self):
        """Testa cálculo de entropia"""
        # String com baixa entropia
        low_entropy = "aaaaaaaaaa"
        entropy_low = self.scanner._calculate_entropy(low_entropy)
        
        # String com alta entropia
        high_entropy = "a1B2c3D4e5F6g7H8"
        entropy_high = self.scanner._calculate_entropy(high_entropy)
        
        self.assertLess(entropy_low, entropy_high)
    
    def test_is_likely_secret(self):
        """Testa identificação de possíveis secrets"""
        # Não é secret
        not_secret = "example"
        self.assertFalse(self.scanner._is_likely_secret(not_secret))
        
        # É provável secret
        likely_secret = "ak_1234567890abcdef1234567890abcdef"
        self.assertTrue(self.scanner._is_likely_secret(likely_secret))
        
        # String muito repetitiva
        repetitive = "aaaaaaaaaaaaaaaaaaa"
        self.assertFalse(self.scanner._is_likely_secret(repetitive))
    
    def test_is_weak_cipher(self):
        """Testa detecção de cipher suites fracos"""
        weak_ciphers = [
            'RC4-MD5',
            'DES-CBC-SHA',
            'EXPORT-RC4-40-MD5',
            'NULL-MD5'
        ]
        
        strong_cipher = 'ECDHE-RSA-AES256-GCM-SHA384'
        
        for cipher in weak_ciphers:
            self.assertTrue(self.scanner._is_weak_cipher(cipher))
        
        self.assertFalse(self.scanner._is_weak_cipher(strong_cipher))
    
    def test_get_docker_recommendation(self):
        """Testa geração de recomendações Docker"""
        recommendation = self.scanner._get_docker_recommendation('root_user')
        self.assertIn('usuário', recommendation.lower())
        
        recommendation = self.scanner._get_docker_recommendation('latest_tag')
        self.assertIn('tag', recommendation.lower())
    
    def test_parse_requirements_txt_malformed(self):
        """Testa parsing de requirements.txt malformado"""
        malformed_content = '''
Django==2.0.1
requests  # sem versão
invalid-line-here
# comentário
numpy>=1.14.0  # versão com >=
        '''
        
        self.create_test_file('requirements.txt', malformed_content)
        dependencies = self.scanner._parse_requirements_txt(
            os.path.join(self.temp_dir, 'requirements.txt')
        )
        
        # Deve parsear apenas as linhas válidas com ==
        valid_deps = [d for d in dependencies if d['name'] == 'Django']
        self.assertEqual(len(valid_deps), 1)
        self.assertEqual(valid_deps[0]['version'], '2.0.1')


class TestSecurityScannerIntegration(unittest.TestCase):
    """Testes de integração para SecurityScanner"""
    
    def setUp(self):
        """Configuração inicial"""
        self.scanner = SecurityScanner()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Limpeza após teste"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @patch('utils.git_handler.GitHandler.clone_repository')
    def test_scan_repository_complete_flow(self, mock_clone):
        """Testa fluxo completo de scan de repositório"""
        # Mock do clone
        mock_clone.return_value = True
        
        # Criar estrutura de teste
        test_files = {
            'app.py': '''
import os
PASSWORD = "secret123"

def run_cmd(cmd):
    os.system(cmd)
            ''',
            'requirements.txt': 'Django==2.0.1\nrequests==2.18.4',
            'Dockerfile': '''
FROM ubuntu:latest
USER root
EXPOSE 22
            ''',
            'config.json': '''
{
    "api_key": "sk_test_1234567890abcdef",
    "database_url": "postgresql://user:pass@localhost/db"
}
            '''
        }
        
        # Criar arquivos de teste
        for filename, content in test_files.items():
            file_path = os.path.join(self.temp_dir, filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                f.write(content)
        
        # Executar análises individuais (simulando scan_repository)
        static_results = self.scanner.static_code_analysis(self.temp_dir)
        dependency_results = self.scanner.dependency_vulnerability_check(self.temp_dir)
        secrets_results = self.scanner.secrets_detection(self.temp_dir)
        docker_results = self.scanner.dockerfile_analysis(self.temp_dir)
        summary = self.scanner.generate_summary()
        
        # Verificar se cada tipo de vulnerabilidade foi detectado
        self.assertGreater(len(static_results), 0)
        self.assertGreater(len(secrets_results), 0)
        self.assertGreater(len(docker_results), 0)
        
        # Verificar resumo
        self.assertGreater(summary['total_issues'], 0)
        self.assertIn('risk_level', summary)
        self.assertIsInstance(summary['recommendations'], list)


if __name__ == '__main__':
    # Configurar logging para os testes
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Executar testes
    unittest.main(verbosity=2)