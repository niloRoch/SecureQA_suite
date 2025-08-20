import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import os
import tempfile
import shutil
import json
import re
import zipfile
import io
import hashlib
from urllib.parse import urlparse
import ssl
import socket
from typing import Dict, List, Tuple, Any
import base64
import time

# Configuração da página
st.set_page_config(
    page_title="SecureQA Suite",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

class SecurityScanner:
    """Classe principal para escaneamento de segurança"""
    
    def __init__(self):
        self.results = {
            'static_analysis': [],
            'dependency_check': [],
            'secrets_detection': [],
            'ssl_check': {},
            'headers_check': {},
            'dockerfile_analysis': [],
            'summary': {}
        }
        
    def clone_repository(self, repo_url: str, target_dir: str) -> bool:
        """Clona repositório do GitHub - versão simplificada para demo"""
        try:
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            
            # Criar arquivos de exemplo para demonstração
            self._create_demo_files(target_dir)
            return True
        except Exception as e:
            st.error(f"Erro ao clonar repositório: {str(e)}")
            return False
    
    def _create_demo_files(self, target_dir: str):
        """Cria arquivos de demonstração"""
        # Arquivo Python com vulnerabilidades intencionais
        python_code = '''
import os
import subprocess
import pickle
import hashlib

# Vulnerabilidade: Hardcoded password
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def unsafe_exec(user_input):
    # Vulnerabilidade: Code injection
    exec(user_input)

def unsafe_pickle(data):
    # Vulnerabilidade: Unsafe deserialization
    return pickle.loads(data)

def weak_hash(password):
    # Vulnerabilidade: Weak cryptography
    return hashlib.md5(password.encode()).hexdigest()

def sql_injection_vulnerable(user_id):
    # Vulnerabilidade: SQL injection potential
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Vulnerabilidade: Command injection
def run_command(filename):
    os.system(f"cat {filename}")
'''
        
        requirements_txt = '''
Django==2.0.1
requests==2.18.4
PyYAML==3.12
Pillow==5.2.0
numpy==1.14.0
'''
        
        dockerfile = '''
FROM ubuntu:18.04
RUN apt-get update
USER root
COPY . /app
WORKDIR /app
RUN chmod 777 /app
EXPOSE 22
CMD ["python", "app.py"]
'''
        
        # Salvar arquivos
        with open(os.path.join(target_dir, "vulnerable_app.py"), "w") as f:
            f.write(python_code)
        
        with open(os.path.join(target_dir, "requirements.txt"), "w") as f:
            f.write(requirements_txt)
            
        with open(os.path.join(target_dir, "Dockerfile"), "w") as f:
            f.write(dockerfile)
    
    def static_code_analysis(self, target_dir: str) -> List[Dict]:
        """Análise estática de código"""
        vulnerabilities = []
        
        # Padrões de vulnerabilidades
        patterns = {
            'hardcoded_password': r'PASSWORD\s*=\s*["\'][^"\']+["\']',
            'hardcoded_api_key': r'API_KEY\s*=\s*["\'][^"\']+["\']',
            'exec_usage': r'exec\s*\(',
            'eval_usage': r'eval\s*\(',
            'pickle_loads': r'pickle\.loads\s*\(',
            'md5_usage': r'hashlib\.md5\s*\(',
            'sql_injection': r'f["\'].*SELECT.*{.*}.*["\']',
            'command_injection': r'os\.system\s*\(',
        }
        
        severity_map = {
            'hardcoded_password': 'HIGH',
            'hardcoded_api_key': 'HIGH',
            'exec_usage': 'CRITICAL',
            'eval_usage': 'HIGH',
            'pickle_loads': 'HIGH',
            'md5_usage': 'MEDIUM',
            'sql_injection': 'HIGH',
            'command_injection': 'CRITICAL'
        }
        
        # Escanear arquivos Python
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for vuln_type, pattern in patterns.items():
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                vulnerabilities.append({
                                    'type': vuln_type,
                                    'severity': severity_map[vuln_type],
                                    'file': file,
                                    'line': line_num,
                                    'code': match.group(),
                                    'description': self._get_vulnerability_description(vuln_type)
                                })
                    except Exception as e:
                        continue
        
        self.results['static_analysis'] = vulnerabilities
        return vulnerabilities
    
    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Retorna descrição da vulnerabilidade"""
        descriptions = {
            'hardcoded_password': 'Senha hardcoded no código fonte',
            'hardcoded_api_key': 'Chave de API hardcoded no código fonte',
            'exec_usage': 'Uso de exec() pode permitir execução de código arbitrário',
            'eval_usage': 'Uso de eval() pode permitir execução de código arbitrário',
            'pickle_loads': 'pickle.loads() pode ser explorado para execução de código',
            'md5_usage': 'MD5 é um algoritmo de hash criptograficamente fraco',
            'sql_injection': 'Possível vulnerabilidade de SQL injection',
            'command_injection': 'Possível vulnerabilidade de command injection'
        }
        return descriptions.get(vuln_type, 'Vulnerabilidade detectada')
    
    def dependency_vulnerability_check(self, target_dir: str) -> List[Dict]:
        """Verifica vulnerabilidades em dependências"""
        vulnerabilities = []
        requirements_file = os.path.join(target_dir, 'requirements.txt')
        
        if os.path.exists(requirements_file):
            # Base de dados simulada de vulnerabilidades
            vuln_db = {
                'Django': {
                    '2.0.1': ['CVE-2018-7536', 'CVE-2018-7537'],
                    '2.1.0': ['CVE-2018-14574']
                },
                'requests': {
                    '2.18.4': ['CVE-2018-18074']
                },
                'PyYAML': {
                    '3.12': ['CVE-2017-18342']
                },
                'Pillow': {
                    '5.2.0': ['CVE-2018-16509', 'CVE-2018-16510']
                }
            }
            
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '==' in line:
                            package, version = line.split('==')
                            package = package.strip()
                            version = version.strip()
                            
                            if package in vuln_db and version in vuln_db[package]:
                                for cve in vuln_db[package][version]:
                                    vulnerabilities.append({
                                        'package': package,
                                        'version': version,
                                        'cve': cve,
                                        'severity': 'HIGH' if 'CVE-2018' in cve else 'MEDIUM',
                                        'description': f'Vulnerabilidade conhecida em {package} {version}'
                                    })
        
        self.results['dependency_check'] = vulnerabilities
        return vulnerabilities
    
    def secrets_detection(self, target_dir: str) -> List[Dict]:
        """Detecta secrets e credenciais expostas"""
        secrets = []
        
        # Padrões de secrets
        secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+=]{40}',
            'github_token': r'ghp_[0-9a-zA-Z]{36}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z-]+',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?[0-9a-zA-Z]{20,}',
            'password': r'password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
            'private_key': r'-----BEGIN PRIVATE KEY-----',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        }
        
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env', '.config')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        for secret_type, pattern in secret_patterns.items():
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                secrets.append({
                                    'type': secret_type,
                                    'file': file,
                                    'line': line_num,
                                    'match': match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                                    'severity': 'CRITICAL'
                                })
                    except Exception:
                        continue
        
        self.results['secrets_detection'] = secrets
        return secrets
    
    def dockerfile_analysis(self, target_dir: str) -> List[Dict]:
        """Analisa Dockerfile para práticas de segurança"""
        issues = []
        dockerfile_path = os.path.join(target_dir, 'Dockerfile')
        
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                line = line.strip().upper()
                
                # Verificações de segurança
                if line.startswith('USER ROOT'):
                    issues.append({
                        'line': i,
                        'issue': 'Running as root user',
                        'severity': 'HIGH',
                        'description': 'Container não deve executar como root'
                    })
                
                if 'CHMOD 777' in line:
                    issues.append({
                        'line': i,
                        'issue': 'Overly permissive file permissions',
                        'severity': 'HIGH',
                        'description': 'Permissões 777 são muito permissivas'
                    })
                
                if line.startswith('EXPOSE 22'):
                    issues.append({
                        'line': i,
                        'issue': 'SSH port exposed',
                        'severity': 'MEDIUM',
                        'description': 'Porta SSH exposta pode ser um risco'
                    })
                
                if 'FROM' in line and ':LATEST' in line:
                    issues.append({
                        'line': i,
                        'issue': 'Using latest tag',
                        'severity': 'LOW',
                        'description': 'Tag :latest não é recomendada em produção'
                    })
        
        self.results['dockerfile_analysis'] = issues
        return issues
    
    def ssl_tls_check(self, domain: str) -> Dict:
        """Verifica configuração SSL/TLS - versão simplificada"""
        if not domain:
            return {}
            
        try:
            # Simular verificação SSL (versão simplificada)
            ssl_info = {
                'domain': domain,
                'ssl_enabled': True,
                'certificate_valid': True,
                'tls_version': 'TLSv1.3',
                'cipher_suite': 'TLS_AES_256_GCM_SHA384',
                'certificate_expiry': '2024-12-31',
                'issues': [
                    {
                        'type': 'weak_cipher',
                        'severity': 'LOW',
                        'description': 'Alguns cipher suites fracos ainda habilitados'
                    }
                ]
            }
            
            self.results['ssl_check'] = ssl_info
            return ssl_info
        except Exception as e:
            return {'error': str(e)}
    
    def security_headers_check(self, url: str) -> Dict:
        """Verifica headers de segurança"""
        if not url:
            return {}
            
        # Simular verificação de headers
        headers_analysis = {
            'url': url,
            'headers_found': {
                'Content-Security-Policy': False,
                'X-Frame-Options': True,
                'X-Content-Type-Options': True,
                'Strict-Transport-Security': False,
                'X-XSS-Protection': True
            },
            'security_score': 60,
            'recommendations': [
                'Implementar Content-Security-Policy',
                'Adicionar Strict-Transport-Security',
                'Configurar Referrer-Policy'
            ]
        }
        
        self.results['headers_check'] = headers_analysis
        return headers_analysis
    
    def generate_summary(self) -> Dict:
        """Gera resumo dos resultados"""
        total_issues = (
            len(self.results.get('static_analysis', [])) +
            len(self.results.get('dependency_check', [])) +
            len(self.results.get('secrets_detection', [])) +
            len(self.results.get('dockerfile_analysis', []))
        )
        
        critical_issues = sum(1 for item in self.results.get('static_analysis', []) if item.get('severity') == 'CRITICAL')
        critical_issues += sum(1 for item in self.results.get('secrets_detection', []) if item.get('severity') == 'CRITICAL')
        
        high_issues = sum(1 for item in self.results.get('static_analysis', []) if item.get('severity') == 'HIGH')
        high_issues += sum(1 for item in self.results.get('dependency_check', []) if item.get('severity') == 'HIGH')
        high_issues += sum(1 for item in self.results.get('dockerfile_analysis', []) if item.get('severity') == 'HIGH')
        
        summary = {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'high_issues': high_issues,
            'medium_issues': total_issues - critical_issues - high_issues,
            'scan_date': datetime.now().isoformat(),
            'risk_score': min(100, (critical_issues * 10 + high_issues * 5))
        }
        
        self.results['summary'] = summary
        return summary

def create_dashboard():
    """Cria o dashboard principal"""
    st.title("🔒 SecureQA Suite")
    st.markdown("### Plataforma Completa de Testes de Segurança")
    
    # Sidebar
    st.sidebar.header("Configurações")
    
    # Input do repositório
    repo_url = st.sidebar.text_input(
        "URL do Repositório GitHub",
        placeholder="https://github.com/user/repo"
    )
    
    domain_url = st.sidebar.text_input(
        "Domínio para Teste SSL/Headers",
        placeholder="https://example.com"
    )
    
    # Botão de scan
    if st.sidebar.button("🚀 Iniciar Escaneamento", type="primary"):
        if repo_url or domain_url:
            run_security_scan(repo_url, domain_url)
        else:
            st.sidebar.error("Forneça pelo menos uma URL")
    
    # Se não há dados, mostrar dashboard demo
    if 'scan_results' not in st.session_state:
        show_demo_dashboard()
    else:
        show_results_dashboard()

def show_demo_dashboard():
    """Mostra dashboard demo"""
    st.info("👆 Configure um repositório na barra lateral para começar o escaneamento")
    
    # Métricas demo
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Issues Críticos", "3", delta="2")
    with col2:
        st.metric("Issues Alto Risco", "7", delta="1")
    with col3:
        st.metric("Dependencies Vulneráveis", "4", delta="-1")
    with col4:
        st.metric("Score de Segurança", "65/100", delta="-5")
    
    # Gráfico demo
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Distribuição de Vulnerabilidades")
        demo_data = pd.DataFrame({
            'Severity': ['Critical', 'High', 'Medium', 'Low'],
            'Count': [3, 7, 12, 5]
        })
        fig = px.pie(demo_data, values='Count', names='Severity',
                    color_discrete_map={'Critical': '#FF4B4B', 'High': '#FF8C00', 
                                      'Medium': '#FFD700', 'Low': '#32CD32'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Timeline de Escaneamentos")
        timeline_data = pd.DataFrame({
            'Date': pd.date_range(start='2024-01-01', periods=7, freq='D'),
            'Issues': [15, 12, 18, 8, 14, 11, 9]
        })
        fig = px.line(timeline_data, x='Date', y='Issues', 
                     title="Issues Encontrados por Dia")
        st.plotly_chart(fig, use_container_width=True)
    
    # Tabela demo de vulnerabilidades
    st.subheader("Últimas Vulnerabilidades Detectadas")
    demo_vulns = pd.DataFrame({
        'Arquivo': ['app.py', 'config.py', 'utils.py', 'models.py'],
        'Tipo': ['SQL Injection', 'Hardcoded Password', 'Command Injection', 'Weak Crypto'],
        'Severidade': ['High', 'Critical', 'High', 'Medium'],
        'Linha': [45, 12, 78, 234]
    })
    
    st.dataframe(demo_vulns, use_container_width=True)

def run_security_scan(repo_url: str, domain_url: str):
    """Executa o escaneamento de segurança"""
    scanner = SecurityScanner()
    
    with st.spinner("🔍 Executando escaneamento de segurança..."):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Simular progresso
        if repo_url:
            status_text.text("Clonando repositório...")
            progress_bar.progress(10)
            time.sleep(1)
            
            with tempfile.TemporaryDirectory() as temp_dir:
                if scanner.clone_repository(repo_url, temp_dir):
                    status_text.text("Analisando código...")
                    progress_bar.progress(30)
                    scanner.static_code_analysis(temp_dir)
                    
                    status_text.text("Verificando dependências...")
                    progress_bar.progress(50)
                    scanner.dependency_vulnerability_check(temp_dir)
                    
                    status_text.text("Detectando secrets...")
                    progress_bar.progress(70)
                    scanner.secrets_detection(temp_dir)
                    
                    status_text.text("Analisando Dockerfile...")
                    progress_bar.progress(85)
                    scanner.dockerfile_analysis(temp_dir)
        
        if domain_url:
            status_text.text("Verificando SSL/TLS...")
            progress_bar.progress(90)
            scanner.ssl_tls_check(domain_url)
            scanner.security_headers_check(domain_url)
        
        status_text.text("Gerando relatório...")
        progress_bar.progress(100)
        scanner.generate_summary()
        
        # Salvar resultados na sessão
        st.session_state['scan_results'] = scanner.results
        
        progress_bar.empty()
        status_text.empty()
        
        st.success("✅ Escaneamento concluído!")
        st.rerun()

def show_results_dashboard():
    """Mostra dashboard com resultados"""
    results = st.session_state['scan_results']
    summary = results['summary']
    
    # Métricas principais
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total de Issues", summary['total_issues'])
    with col2:
        st.metric("Críticos", summary['critical_issues'], 
                 delta=f"+{summary['critical_issues']}" if summary['critical_issues'] > 0 else None)
    with col3:
        st.metric("Alto Risco", summary['high_issues'],
                 delta=f"+{summary['high_issues']}" if summary['high_issues'] > 0 else None)
    with col4:
        st.metric("Risk Score", f"{summary['risk_score']}/100",
                 delta=f"+{summary['risk_score']}" if summary['risk_score'] > 50 else None)
    
    # Tabs para diferentes análises
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Resumo", "🔍 Código", "📦 Dependências", "🔑 Secrets", "🐳 Docker"
    ])
    
    with tab1:
        show_summary_tab(results)
    
    with tab2:
        show_static_analysis_tab(results.get('static_analysis', []))
    
    with tab3:
        show_dependency_tab(results.get('dependency_check', []))
    
    with tab4:
        show_secrets_tab(results.get('secrets_detection', []))
    
    with tab5:
        show_docker_tab(results.get('dockerfile_analysis', []))

def show_summary_tab(results):
    """Tab de resumo"""
    col1, col2 = st.columns(2)
    
    with col1:
        # Gráfico de distribuição por severidade
        severity_data = []
        for analysis in ['static_analysis', 'dependency_check', 'secrets_detection', 'dockerfile_analysis']:
            for item in results.get(analysis, []):
                severity_data.append(item.get('severity', 'Unknown'))
        
        if severity_data:
            severity_df = pd.DataFrame(severity_data, columns=['Severity'])
            severity_counts = severity_df['Severity'].value_counts()
            
            fig = px.pie(values=severity_counts.values, names=severity_counts.index,
                        title="Distribuição por Severidade",
                        color_discrete_map={'CRITICAL': '#FF4B4B', 'HIGH': '#FF8C00', 
                                          'MEDIUM': '#FFD700', 'LOW': '#32CD32'})
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Gráfico por categoria
        categories = {
            'Análise de Código': len(results.get('static_analysis', [])),
            'Dependências': len(results.get('dependency_check', [])),
            'Secrets': len(results.get('secrets_detection', [])),
            'Docker': len(results.get('dockerfile_analysis', []))
        }
        
        cat_df = pd.DataFrame(list(categories.items()), columns=['Categoria', 'Issues'])
        fig = px.bar(cat_df, x='Categoria', y='Issues', 
                    title="Issues por Categoria")
        st.plotly_chart(fig, use_container_width=True)

def show_static_analysis_tab(static_results):
    """Tab de análise estática"""
    st.subheader("🔍 Análise Estática de Código")
    
    if not static_results:
        st.info("Nenhum issue encontrado na análise de código")
        return
    
    df = pd.DataFrame(static_results)
    
    # Filtros
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.selectbox("Filtrar por Severidade", 
                                     ['Todos'] + list(df['severity'].unique()))
    with col2:
        file_filter = st.selectbox("Filtrar por Arquivo",
                                  ['Todos'] + list(df['file'].unique()))
    
    # Aplicar filtros
    filtered_df = df.copy()
    if severity_filter != 'Todos':
        filtered_df = filtered_df[filtered_df['severity'] == severity_filter]
    if file_filter != 'Todos':
        filtered_df = filtered_df[filtered_df['file'] == file_filter]
    
    # Mostrar resultados
    for _, row in filtered_df.iterrows():
        severity_color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        with st.expander(f"{severity_color.get(row['severity'], '⚪')} {row['type']} - {row['file']}:{row['line']}"):
            st.write(f"**Severidade:** {row['severity']}")
            st.write(f"**Descrição:** {row['description']}")
            st.code(row['code'], language='python')

def show_dependency_tab(dep_results):
    """Tab de dependências"""
    st.subheader("📦 Análise de Dependências")
    
    if not dep_results:
        st.info("Nenhuma vulnerabilidade encontrada nas dependências")
        return
    
    df = pd.DataFrame(dep_results)
    st.dataframe(df, use_container_width=True)
    
    # Detalhes das vulnerabilidades
    st.subheader("Detalhes das Vulnerabilidades")
    for _, row in df.iterrows():
        severity_color = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        with st.expander(f"{severity_color.get(row['severity'], '⚪')} {row['package']} {row['version']} - {row['cve']}"):
            st.write(f"**CVE:** {row['cve']}")
            st.write(f"**Severidade:** {row['severity']}")
            st.write(f"**Descrição:** {row['description']}")

def show_secrets_tab(secrets_results):
    """Tab de secrets"""
    st.subheader("🔑 Detecção de Secrets")
    
    if not secrets_results:
        st.success("✅ Nenhum secret detectado!")
        return
    
    st.warning(f"⚠️ {len(secrets_results)} secrets detectados!")
    
    for secret in secrets_results:
        with st.expander(f"🔴 {secret['type']} - {secret['file']}:{secret['line']}"):
            st.write(f"**Tipo:** {secret['type']}")
            st.write(f"**Arquivo:** {secret['file']}")
            st.write(f"**Linha:** {secret['line']}")
            st.code(secret['match'])
            st.error("⚠️ **AÇÃO NECESSÁRIA:** Remover este secret e usar variáveis de ambiente")

def show_docker_tab(docker_results):
    """Tab de análise Docker"""
    st.subheader("🐳 Análise de Dockerfile")
    
    if not docker_results:
        st.info("Nenhum issue encontrado no Dockerfile")
        return
    
    for issue in docker_results:
        severity_color = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        
        with st.expander(f"{severity_color.get(issue['severity'], '⚪')} {issue['issue']} - Linha {issue['line']}"):
            st.write(f"**Severidade:** {issue['severity']}")
            st.write(f"**Problema:** {issue['issue']}")
            st.write(f"**Descrição:** {issue['description']}")
            st.write(f"**Linha:** {issue['line']}")

def main():
    """Função principal"""
    # CSS customizado
    st.markdown("""
    <style>
    .main > div {
        padding-top: 2rem;
    }
    
    .stMetric > div > div > div > div {
        background-color: #f0f2f6;
        border: 1px solid #e1e5e9;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    
    .stButton > button {
        width: 100%;
        border-radius: 20px;
        height: 3em;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
    }
    
    .stSelectbox > div > div {
        background-color: white;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Inicializar session state
    if 'scan_results' not in st.session_state:
        st.session_state['scan_results'] = None
    
    create_dashboard()
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666; padding: 20px;'>
            <p>🔒 <strong>SecureQA Suite</strong> - Desenvolvido para demonstração de portfolio</p>
            <p>Suíte completa de testes de segurança automatizados</p>
        </div>
        """,
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()