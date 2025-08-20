"""
SecureQA Suite - Security Scanner
Versão refatorada e otimizada para produção
"""
import os
import re
import json
import hashlib
import tempfile
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Scanner de segurança principal"""
    
    def __init__(self):
        self.results = {
            'static_analysis': [],
            'dependency_check': [],
            'secrets_detection': [],
            'dockerfile_analysis': [],
            'ssl_check': {},
            'headers_check': {},
            'summary': {}
        }
        
        # Padrões de vulnerabilidades
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.secret_patterns = self._load_secret_patterns()
        self.docker_checks = self._load_docker_checks()
        
        # Base de dados de vulnerabilidades
        self.vuln_database = self._load_vulnerability_database()
    
    def _load_vulnerability_patterns(self) -> Dict[str, Dict]:
        """Carrega padrões de vulnerabilidades"""
        return {
            'code_injection': {
                'exec_usage': {
                    'pattern': r'exec\s*\(',
                    'severity': 'CRITICAL',
                    'description': 'Uso de exec() pode permitir execução de código arbitrário',
                    'cwe': 'CWE-94'
                },
                'eval_usage': {
                    'pattern': r'eval\s*\(',
                    'severity': 'CRITICAL',
                    'description': 'Uso de eval() pode permitir execução de código arbitrário',
                    'cwe': 'CWE-94'
                }
            },
            'injection_vulnerabilities': {
                'sql_injection': {
                    'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*\%s|f["\'].*SELECT.*{.*}.*["\']',
                    'severity': 'HIGH',
                    'description': 'Possível vulnerabilidade de SQL injection',
                    'cwe': 'CWE-89'
                },
                'command_injection': {
                    'pattern': r'os\.system\s*\(|subprocess\.call\s*\(.*shell=True',
                    'severity': 'CRITICAL',
                    'description': 'Possível vulnerabilidade de command injection',
                    'cwe': 'CWE-78'
                },
                'xpath_injection': {
                    'pattern': r'xpath.*\+|xpath.*\%',
                    'severity': 'HIGH',
                    'description': 'Possível vulnerabilidade XPath injection',
                    'cwe': 'CWE-643'
                }
            },
            'cryptographic_issues': {
                'weak_hash': {
                    'pattern': r'hashlib\.(md5|sha1)\s*\(',
                    'severity': 'MEDIUM',
                    'description': 'Algoritmo de hash criptograficamente fraco',
                    'cwe': 'CWE-327'
                },
                'hardcoded_crypto_key': {
                    'pattern': r'(AES\.new|DES\.new).*["\'][a-zA-Z0-9]{16,}["\']',
                    'severity': 'HIGH',
                    'description': 'Chave criptográfica hardcoded',
                    'cwe': 'CWE-798'
                }
            },
            'deserialization': {
                'pickle_loads': {
                    'pattern': r'pickle\.loads\s*\(',
                    'severity': 'HIGH',
                    'description': 'pickle.loads() pode ser explorado para execução de código',
                    'cwe': 'CWE-502'
                },
                'yaml_load': {
                    'pattern': r'yaml\.load\s*\(',
                    'severity': 'HIGH',
                    'description': 'yaml.load() pode executar código arbitrário',
                    'cwe': 'CWE-502'
                }
            },
            'hardcoded_credentials': {
                'hardcoded_password': {
                    'pattern': r'PASSWORD\s*=\s*["\'][^"\']+["\']',
                    'severity': 'HIGH',
                    'description': 'Senha hardcoded no código fonte',
                    'cwe': 'CWE-798'
                },
                'hardcoded_api_key': {
                    'pattern': r'API[_-]?KEY\s*=\s*["\'][^"\']+["\']',
                    'severity': 'HIGH',
                    'description': 'Chave de API hardcoded no código fonte',
                    'cwe': 'CWE-798'
                }
            }
        }
    
    def _load_secret_patterns(self) -> Dict[str, Dict]:
        """Carrega padrões para detecção de secrets"""
        return {
            'aws_credentials': {
                'aws_access_key': {
                    'pattern': r'AKIA[0-9A-Z]{16}',
                    'entropy_threshold': 4.5,
                    'description': 'AWS Access Key ID'
                },
                'aws_secret_key': {
                    'pattern': r'[A-Za-z0-9/+=]{40}',
                    'entropy_threshold': 4.8,
                    'description': 'AWS Secret Access Key'
                }
            },
            'github_tokens': {
                'github_token': {
                    'pattern': r'ghp_[0-9a-zA-Z]{36}',
                    'entropy_threshold': 4.0,
                    'description': 'GitHub Personal Access Token'
                },
                'github_oauth': {
                    'pattern': r'gho_[0-9a-zA-Z]{36}',
                    'entropy_threshold': 4.0,
                    'description': 'GitHub OAuth Token'
                }
            },
            'api_keys': {
                'generic_api_key': {
                    'pattern': r'api[_-]?key["\']?\s*[:=]\s*["\']?[0-9a-zA-Z]{20,}["\']?',
                    'entropy_threshold': 4.0,
                    'description': 'Generic API Key'
                },
                'bearer_token': {
                    'pattern': r'Bearer\s+[A-Za-z0-9\-_=]{20,}',
                    'entropy_threshold': 4.2,
                    'description': 'Bearer Token'
                }
            },
            'database_urls': {
                'connection_string': {
                    'pattern': r'(mongodb|mysql|postgresql)://[^\s]+:[^\s]+@[^\s]+',
                    'entropy_threshold': 3.5,
                    'description': 'Database Connection String'
                }
            },
            'private_keys': {
                'rsa_private_key': {
                    'pattern': r'-----BEGIN (RSA )?PRIVATE KEY-----',
                    'entropy_threshold': 3.0,
                    'description': 'RSA Private Key'
                },
                'ssh_private_key': {
                    'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
                    'entropy_threshold': 3.0,
                    'description': 'SSH Private Key'
                }
            },
            'jwt_tokens': {
                'jwt_token': {
                    'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                    'entropy_threshold': 4.5,
                    'description': 'JSON Web Token'
                }
            }
        }
    
    def _load_docker_checks(self) -> List[Dict]:
        """Carrega verificações para Dockerfile"""
        return [
            {
                'pattern': r'USER\s+root',
                'severity': 'HIGH',
                'message': 'Running as root user',
                'description': 'Container não deve executar como usuário root',
                'recommendation': 'Criar usuário não-privilegiado: RUN useradd -m appuser && USER appuser'
            },
            {
                'pattern': r'chmod\s+777',
                'severity': 'HIGH',
                'message': 'Overly permissive file permissions',
                'description': 'Permissões 777 são muito permissivas e inseguras',
                'recommendation': 'Use permissões mais restritivas como 644 ou 755'
            },
            {
                'pattern': r'EXPOSE\s+22',
                'severity': 'MEDIUM',
                'message': 'SSH port exposed',
                'description': 'Porta SSH exposta pode ser um vetor de ataque',
                'recommendation': 'Remova EXPOSE 22 se SSH não for necessário'
            },
            {
                'pattern': r'FROM.*:latest',
                'severity': 'LOW',
                'message': 'Using latest tag',
                'description': 'Tag :latest não é recomendada em produção',
                'recommendation': 'Use tags específicas para garantir builds reproduzíveis'
            },
            {
                'pattern': r'ADD\s+http',
                'severity': 'MEDIUM',
                'message': 'Using ADD with remote URLs',
                'description': 'ADD com URLs remotas pode ser inseguro',
                'recommendation': 'Use COPY em vez de ADD para arquivos locais'
            },
            {
                'pattern': r'--privileged',
                'severity': 'CRITICAL',
                'message': 'Privileged mode enabled',
                'description': 'Modo privilegiado remove isolamento de segurança',
                'recommendation': 'Remova --privileged ou use capacidades específicas'
            }
        ]
    
    def _load_vulnerability_database(self) -> Dict:
        """Carrega base de dados de vulnerabilidades conhecidas"""
        return {
            'pypi': {
                'Django': {
                    '1.11.0': [
                        {
                            'cve': 'CVE-2017-7233',
                            'severity': 'HIGH',
                            'cvss_score': 7.5,
                            'description': 'Open redirect vulnerability in django.views.static.serve',
                            'published_date': '2017-04-04',
                            'fixed_version': '1.11.1'
                        }
                    ],
                    '2.0.1': [
                        {
                            'cve': 'CVE-2018-7536',
                            'severity': 'CRITICAL',
                            'cvss_score': 9.8,
                            'description': 'Catastrophic backtracking in django.utils.text.Truncator',
                            'published_date': '2018-03-06',
                            'fixed_version': '2.0.3'
                        }
                    ]
                },
                'requests': {
                    '2.18.4': [
                        {
                            'cve': 'CVE-2018-18074',
                            'severity': 'HIGH',
                            'cvss_score': 7.5,
                            'description': 'Credentials exposure due to improper URL parsing',
                            'published_date': '2018-10-09',
                            'fixed_version': '2.20.0'
                        }
                    ]
                },
                'PyYAML': {
                    '3.12': [
                        {
                            'cve': 'CVE-2017-18342',
                            'severity': 'CRITICAL',
                            'cvss_score': 9.8,
                            'description': 'Arbitrary code execution via yaml.load()',
                            'published_date': '2018-06-27',
                            'fixed_version': '5.1'
                        }
                    ]
                }
            },
            'npm': {
                'lodash': {
                    '4.17.4': [
                        {
                            'cve': 'CVE-2018-3721',
                            'severity': 'HIGH',
                            'cvss_score': 7.5,
                            'description': 'Prototype pollution in merge, mergeWith, and defaultsDeep',
                            'published_date': '2018-04-26',
                            'fixed_version': '4.17.11'
                        }
                    ]
                }
            }
        }
    
    def static_code_analysis(self, target_dir: str) -> List[Dict]:
        """Realiza análise estática de código"""
        vulnerabilities = []
        
        try:
            for root, dirs, files in os.walk(target_dir):
                # Ignorar diretórios comuns que não devem ser analisados
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                          ['__pycache__', 'node_modules', 'venv', 'env', '.git']]
                
                for file in files:
                    if self._should_analyze_file(file):
                        file_path = os.path.join(root, file)
                        file_vulns = self._analyze_file(file_path, file)
                        vulnerabilities.extend(file_vulns)
            
            # Ordenar por severidade
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
            
            self.results['static_analysis'] = vulnerabilities
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Erro na análise estática: {e}")
            return []
    
    def _should_analyze_file(self, filename: str) -> bool:
        """Determina se arquivo deve ser analisado"""
        analyze_extensions = {'.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c'}
        _, ext = os.path.splitext(filename.lower())
        return ext in analyze_extensions
    
    def _analyze_file(self, file_path: str, filename: str) -> List[Dict]:
        """Analisa arquivo individual"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Análise por categorias de vulnerabilidade
            for category, patterns in self.vulnerability_patterns.items():
                for vuln_type, vuln_info in patterns.items():
                    matches = re.finditer(vuln_info['pattern'], content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Verificar contexto para reduzir falsos positivos
                        if self._validate_vulnerability_context(content, match, vuln_type):
                            vulnerability = {
                                'type': vuln_type,
                                'category': category,
                                'severity': vuln_info['severity'],
                                'file': filename,
                                'line': line_num,
                                'code': self._get_code_context(content, match.start()),
                                'description': vuln_info['description'],
                                'cwe': vuln_info.get('cwe', ''),
                                'confidence': self._calculate_confidence(content, match, vuln_type)
                            }
                            vulnerabilities.append(vulnerability)
                            
        except Exception as e:
            logger.error(f"Erro ao analisar arquivo {file_path}: {e}")
        
        return vulnerabilities
    
    def _validate_vulnerability_context(self, content: str, match: re.Match, vuln_type: str) -> bool:
        """Valida contexto da vulnerabilidade para reduzir falsos positivos"""
        line_start = content.rfind('\n', 0, match.start()) + 1
        line_end = content.find('\n', match.end())
        if line_end == -1:
            line_end = len(content)
        
        line_content = content[line_start:line_end].strip()
        
        # Verificações específicas por tipo
        if vuln_type in ['exec_usage', 'eval_usage']:
            # Ignorar se está em comentário
            if line_content.strip().startswith('#'):
                return False
        
        return True
    
    def _get_code_context(self, content: str, position: int) -> str:
        """Obtém contexto do código ao redor da vulnerabilidade"""
        lines = content.split('\n')
        line_num = content[:position].count('\n')
        
        start = max(0, line_num - 1)
        end = min(len(lines), line_num + 2)
        
        context_lines = lines[start:end]
        return '\n'.join(context_lines)
    
    def _calculate_confidence(self, content: str, match: re.Match, vuln_type: str) -> str:
        """Calcula nível de confiança da detecção"""
        # Implementação simplificada
        if vuln_type in ['hardcoded_password', 'hardcoded_api_key']:
            return 'HIGH'
        elif vuln_type in ['exec_usage', 'eval_usage']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def dependency_vulnerability_check(self, target_dir: str) -> List[Dict]:
        """Verifica vulnerabilidades em dependências"""
        vulnerabilities = []
        
        # Verificar diferentes tipos de arquivos de dependência
        dependency_files = [
            ('requirements.txt', 'pypi', self._parse_requirements_txt),
            ('package.json', 'npm', self._parse_package_json),
            ('Pipfile', 'pypi', self._parse_pipfile),
            ('poetry.lock', 'pypi', self._parse_poetry_lock)
        ]
        
        for filename, ecosystem, parser in dependency_files:
            file_path = os.path.join(target_dir, filename)
            if os.path.exists(file_path):
                dependencies = parser(file_path)
                file_vulns = self._check_dependencies_vulnerabilities(dependencies, ecosystem)
                vulnerabilities.extend(file_vulns)
        
        self.results['dependency_check'] = vulnerabilities
        return vulnerabilities
    
    def _parse_requirements_txt(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse requirements.txt"""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '==' in line:
                        parts = line.split('==')
                        if len(parts) == 2:
                            package = parts[0].strip()
                            version = parts[1].strip().split(';')[0]  # Remove markers
                            dependencies.append((package, version))
        except Exception as e:
            logger.error(f"Erro ao parsear {file_path}: {e}")
        
        return dependencies
    
    def _parse_package_json(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse package.json"""
        dependencies = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Verificar dependencies e devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for package, version in data[dep_type].items():
                        # Limpar caracteres de versioning (^, ~, etc.)
                        clean_version = re.sub(r'[^\d\.]', '', version)
                        if clean_version:
                            dependencies.append((package, clean_version))
                            
        except Exception as e:
            logger.error(f"Erro ao parsear {file_path}: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse Pipfile"""
        # Implementação simplificada - poderia usar toml parser
        return []
    
    def _parse_poetry_lock(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse poetry.lock"""
        # Implementação simplificada - poderia usar toml parser
        return []
    
    def _check_dependencies_vulnerabilities(self, dependencies: List[Tuple[str, str]], 
                                          ecosystem: str) -> List[Dict]:
        """Verifica vulnerabilidades nas dependências"""
        vulnerabilities = []
        
        ecosystem_db = self.vuln_database.get(ecosystem, {})
        
        for package, version in dependencies:
            package_vulns = ecosystem_db.get(package, {})
            
            # Verificar versão exata
            if version in package_vulns:
                for vuln in package_vulns[version]:
                    vulnerability = {
                        'package': package,
                        'version': version,
                        'cve': vuln['cve'],
                        'severity': vuln['severity'],
                        'cvss_score': vuln.get('cvss_score', 0),
                        'description': vuln['description'],
                        'published_date': vuln.get('published_date', ''),
                        'fixed_version': vuln.get('fixed_version', ''),
                        'ecosystem': ecosystem
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def secrets_detection(self, target_dir: str) -> List[Dict]:
        """Detecta secrets expostos"""
        secrets = []
        
        try:
            for root, dirs, files in os.walk(target_dir):
                # Ignorar diretórios desnecessários
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                          ['__pycache__', 'node_modules', 'venv']]
                
                for file in files:
                    if self._should_scan_for_secrets(file):
                        file_path = os.path.join(root, file)
                        file_secrets = self._scan_file_for_secrets(file_path, file)
                        secrets.extend(file_secrets)
            
            self.results['secrets_detection'] = secrets
            return secrets
            
        except Exception as e:
            logger.error(f"Erro na detecção de secrets: {e}")
            return []
    
    def _should_scan_for_secrets(self, filename: str) -> bool:
        """Determina se arquivo deve ser escaneado para secrets"""
        scan_extensions = {'.py', '.js', '.json', '.yaml', '.yml', '.env', '.config', '.ini', '.txt', '.md'}
        skip_files = {'requirements.txt', 'package-lock.json', 'yarn.lock'}
        
        if filename in skip_files:
            return False
            
        _, ext = os.path.splitext(filename.lower())
        return ext in scan_extensions or filename.startswith('.env')
    
    def _scan_file_for_secrets(self, file_path: str, filename: str) -> List[Dict]:
        """Escaneia arquivo individual para secrets"""
        secrets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for category, patterns in self.secret_patterns.items():
                for secret_type, secret_info in patterns.items():
                    matches = re.finditer(secret_info['pattern'], content, re.IGNORECASE)
                    
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        matched_text = match.group()
                        
                        # Calcular entropia
                        entropy = self._calculate_entropy(matched_text)
                        
                        # Verificar threshold de entropia
                        if entropy >= secret_info.get('entropy_threshold', 3.0):
                            # Verificar se não é falso positivo
                            if self._validate_secret(matched_text, secret_type, content, match):
                                secret = {
                                    'type': secret_type,
                                    'category': category,
                                    'file': filename,
                                    'line': line_num,
                                    'match': self._mask_secret(matched_text),
                                    'entropy': round(entropy, 2),
                                    'severity': 'CRITICAL',
                                    'description': secret_info['description'],
                                    'confidence': self._calculate_secret_confidence(entropy, secret_type)
                                }
                                secrets.append(secret)
                                
        except Exception as e:
            logger.error(f"Erro ao escanear {file_path} para secrets: {e}")
        
        return secrets
    
    def _calculate_entropy(self, text: str) -> float:
        """Calcula entropia de Shannon de uma string"""
        if not text:
            return 0
        
        # Contar frequência de caracteres
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calcular entropia
        entropy = 0
        length = len(text)
        
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability ** 0.5).bit_length()
        
        return entropy
    
    def _validate_secret(self, matched_text: str, secret_type: str, content: str, match: re.Match) -> bool:
        """Valida se o match é realmente um secret"""
        # Verificar se está em comentário
        line_start = content.rfind('\n', 0, match.start()) + 1
        line_end = content.find('\n', match.end())
        if line_end == -1:
            line_end = len(content)
        
        line_content = content[line_start:line_end].strip()
        
        # Ignorar se está em comentário
        if line_content.startswith('#') or line_content.startswith('//'):
            return False
        
        # Verificar padrões de falso positivo
        false_positive_patterns = [
            r'example',
            r'sample',
            r'dummy',
            r'test',
            r'placeholder',
            r'xxxxx',
            r'aaaaa'
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, matched_text.lower()):
                return False
        
        return True
    
    def _mask_secret(self, secret: str) -> str:
        """Mascara o secret para exibição segura"""
        if len(secret) <= 8:
            return '*' * len(secret)
        
        visible_chars = 4
        return secret[:visible_chars] + '*' * (len(secret) - visible_chars * 2) + secret[-visible_chars:]
    
    def _calculate_secret_confidence(self, entropy: float, secret_type: str) -> str:
        """Calcula confiança da detecção de secret"""
        if entropy > 4.5:
            return 'HIGH'
        elif entropy > 3.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def dockerfile_analysis(self, target_dir: str) -> List[Dict]:
        """Analisa Dockerfile para questões de segurança"""
        issues = []
        
        dockerfile_paths = [
            os.path.join(target_dir, 'Dockerfile'),
            os.path.join(target_dir, 'dockerfile'),
            os.path.join(target_dir, 'Dockerfile.prod'),
            os.path.join(target_dir, 'docker', 'Dockerfile')
        ]
        
        for dockerfile_path in dockerfile_paths:
            if os.path.exists(dockerfile_path):
                file_issues = self._analyze_dockerfile(dockerfile_path)
                issues.extend(file_issues)
        
        self.results['dockerfile_analysis'] = issues
        return issues
    
    def _analyze_dockerfile(self, dockerfile_path: str) -> List[Dict]:
        """Analiza um Dockerfile específico"""
        issues = []
        
        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                line_upper = line.strip().upper()
                
                for check in self.docker_checks:
                    if re.search(check['pattern'], line, re.IGNORECASE):
                        issue = {
                            'line': i,
                            'issue': check['message'],
                            'severity': check['severity'],
                            'description': check['description'],
                            'recommendation': check['recommendation'],
                            'dockerfile': os.path.basename(dockerfile_path),
                            'line_content': line.strip()
                        }
                        issues.append(issue)
                        
        except Exception as e:
            logger.error(f"Erro ao analisar {dockerfile_path}: {e}")
        
        return issues
    
    def ssl_tls_check(self, domain: str) -> Dict:
        """Verifica configuração SSL/TLS"""
        try:
            import ssl
            import socket
            from datetime import datetime
            
            # Parse domain
            if domain.startswith('http://') or domain.startswith('https://'):
                parsed = urlparse(domain)
                hostname = parsed.netloc
            else:
                hostname = domain
            
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            result = {
                'domain': hostname,
                'ssl_enabled': False,
                'certificate_valid': False,
                'issues': []
            }
            
            try:
                # Verificar SSL
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        result['ssl_enabled'] = True
                        result['certificate_valid'] = True
                        result['tls_version'] = ssock.version()
                        result['cipher_suite'] = ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                        
                        # Verificar expiração
                        if 'notAfter' in cert:
                            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry_date - datetime.now()).days
                            result['certificate_expiry'] = expiry_date.isoformat()
                            result['days_until_expiry'] = days_until_expiry
                            
                            if days_until_expiry < 30:
                                result['issues'].append({
                                    'type': 'certificate_expiry',
                                    'severity': 'HIGH' if days_until_expiry < 7 else 'MEDIUM',
                                    'description': f'Certificado expira em {days_until_expiry} dias'
                                })
                        
                        # Verificar versão TLS
                        if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            result['issues'].append({
                                'type': 'weak_tls_version',
                                'severity': 'HIGH',
                                'description': f'Versão TLS insegura: {ssock.version()}'
                            })
                            
            except Exception as ssl_error:
                result['ssl_enabled'] = False
                result['issues'].append({
                    'type': 'ssl_connection_error',
                    'severity': 'HIGH',
                    'description': f'Erro na conexão SSL: {str(ssl_error)}'
                })
            
            self.results['ssl_check'] = result
            return result
            
        except Exception as e:
            logger.error(f"Erro na verificação SSL: {e}")
            return {'error': str(e)}
    
    def security_headers_check(self, url: str) -> Dict:
        """Verifica headers de segurança HTTP"""
        try:
            import requests
            
            result = {
                'url': url,
                'headers_found': {},
                'missing_headers': [],
                'insecure_headers': [],
                'security_score': 0
            }
            
            # Headers de segurança importantes
            security_headers = {
                'Content-Security-Policy': {'score': 25, 'severity': 'HIGH'},
                'Strict-Transport-Security': {'score': 20, 'severity': 'HIGH'},
                'X-Frame-Options': {'score': 15, 'severity': 'MEDIUM'},
                'X-Content-Type-Options': {'score': 10, 'severity': 'MEDIUM'},
                'X-XSS-Protection': {'score': 10, 'severity': 'LOW'},
                'Referrer-Policy': {'score': 10, 'severity': 'LOW'},
                'Permissions-Policy': {'score': 10, 'severity': 'LOW'}
            }
            
            try:
                response = requests.get(url, timeout=10, allow_redirects=True)
                headers = response.headers
                
                score = 0
                for header, info in security_headers.items():
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        result['headers_found'][header] = True
                        score += info['score']
                    else:
                        result['headers_found'][header] = False
                        result['missing_headers'].append({
                            'header': header,
                            'severity': info['severity'],
                            'description': f'Header {header} não configurado'
                        })
                
                # Verificar headers que expõem informações
                info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                for header in info_headers:
                    if header in headers:
                        result['insecure_headers'].append({
                            'header': header,
                            'value': headers[header],
                            'issue': 'Expõe informações do servidor'
                        })
                
                result['security_score'] = score
                
            except Exception as req_error:
                result['error'] = f'Erro na requisição HTTP: {str(req_error)}'
            
            self.results['headers_check'] = result
            return result
            
        except Exception as e:
            logger.error(f"Erro na verificação de headers: {e}")
            return {'error': str(e)}
    
    def generate_summary(self) -> Dict:
        """Gera resumo consolidado dos resultados"""
        # Coletar todos os issues
        all_issues = []
        categories = {}
        
        for analysis_type in ['static_analysis', 'dependency_check', 'secrets_detection', 'dockerfile_analysis']:
            issues = self.results.get(analysis_type, [])
            all_issues.extend(issues)
            categories[analysis_type] = len(issues)
        
        # Contar por severidade
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for issue in all_issues:
            severity = issue.get('severity', 'LOW')
            severity_counts[severity] += 1
        
        total_issues = len(all_issues)
        
        # Calcular risk score (0-100)
        risk_score = min(100, (
            severity_counts['CRITICAL'] * 25 +
            severity_counts['HIGH'] * 15 +
            severity_counts['MEDIUM'] * 8 +
            severity_counts['LOW'] * 3
        ))
        
        # Determinar nível de risco
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Gerar recomendações
        recommendations = self._generate_recommendations(severity_counts, categories)
        
        summary = {
            'total_issues': total_issues,
            'critical_issues': severity_counts['CRITICAL'],
            'high_issues': severity_counts['HIGH'],
            'medium_issues': severity_counts['MEDIUM'],
            'low_issues': severity_counts['LOW'],
            'risk_score': risk_score,
            'risk_level': risk_level,
            'scan_date': datetime.now().isoformat(),
            'categories': categories,
            'recommendations': recommendations
        }
        
        self.results['summary'] = summary
        return summary
    
    def _generate_recommendations(self, severity_counts: Dict, categories: Dict) -> List[str]:
        """Gera recomendações baseadas nos resultados"""
        recommendations = []
        
        if severity_counts['CRITICAL'] > 0:
            recommendations.append(f"🔴 URGENTE: Corrigir {severity_counts['CRITICAL']} vulnerabilidade(s) crítica(s) imediatamente")
        
        if severity_counts['HIGH'] > 0:
            recommendations.append(f"🟠 Priorizar correção de {severity_counts['HIGH']} vulnerabilidade(s) de alto risco")
        
        if categories.get('secrets_detection', 0) > 0:
            recommendations.append("🔐 Remover todos os secrets hardcoded e implementar gerenciamento seguro")
        
        if categories.get('dependency_check', 0) > 0:
            recommendations.append("📦 Atualizar dependências vulneráveis para versões corrigidas")
        
        if categories.get('dockerfile_analysis', 0) > 0:
            recommendations.append("🐳 Revisar e corrigir configurações inseguras no Dockerfile")
        
        # Recomendações gerais baseadas no score
        total_issues = sum(severity_counts.values())
        if total_issues > 20:
            recommendations.append("📊 Implementar análise de segurança automatizada no pipeline CI/CD")
        
        if not recommendations:
            recommendations.append("✅ Manter boas práticas de segurança e realizar auditorias regulares")
        
        return recommendations[:10]  # Limitar a 10