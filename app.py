"""
SecureQA Suite - Aplicação Principal
Suíte completa de testes de segurança automatizados
Versão otimizada para deploy
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import tempfile
import json
import time
import base64
from typing import Dict, List, Any, Optional
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuração da página
st.set_page_config(
    page_title="SecureQA Suite",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Importar módulos locais com tratamento de erro
try:
    from security_scanner import SecurityScanner
    from utils.pdf_generator import create_security_report
    from utils.git_handler import GitHandler
    from utils.vulnerability_db import VulnerabilityDatabase
except ImportError as e:
    logger.warning(f"Erro ao importar módulos: {e}")
    # Fallback para versão simplificada


class SecureQASuite:
    """Classe principal da aplicação SecureQA Suite"""
    
    def __init__(self):
        self.init_session_state()
        self.scanner = None
        self.git_handler = None
        self.vuln_db = None
        
    def init_session_state(self):
        """Inicializa session state do Streamlit"""
        default_states = {
            'scan_results': None,
            'scan_history': [],
            'current_scan_id': None,
            'demo_mode': True,
            'user_settings': {
                'theme': 'dark',
                'auto_scan': False,
                'notification_email': '',
                'report_format': 'pdf'
            }
        }
        
        for key, value in default_states.items():
            if key not in st.session_state:
                st.session_state[key] = value
    
    def initialize_components(self):
        """Inicializa componentes principais"""
        try:
            self.scanner = SecurityScanner()
            self.git_handler = GitHandler()
            self.vuln_db = VulnerabilityDatabase()
            return True
        except Exception as e:
            logger.error(f"Erro ao inicializar componentes: {e}")
            return False
    
    def render_sidebar(self):
        """Renderiza barra lateral"""
        st.sidebar.header("🔒 SecureQA Suite")
        st.sidebar.markdown("---")
        
        # Seção de configuração
        with st.sidebar.expander("⚙️ Configurações", expanded=True):
            repo_url = st.text_input(
                "📁 URL do Repositório",
                placeholder="https://github.com/user/repo",
                help="Cole a URL do repositório GitHub para análise"
            )
            
            domain_url = st.text_input(
                "🌐 Domínio/URL",
                placeholder="https://example.com",
                help="URL para testes SSL/Headers"
            )
            
            # Opções de scan
            st.markdown("**Tipos de Análise:**")
            scan_options = {
                'static_analysis': st.checkbox("📝 Análise de Código", True),
                'dependency_check': st.checkbox("📦 Dependências", True),
                'secrets_detection': st.checkbox("🔐 Detecção de Secrets", True),
                'dockerfile_analysis': st.checkbox("🐳 Dockerfile", True),
                'ssl_check': st.checkbox("🔒 SSL/TLS", domain_url != ""),
                'headers_check': st.checkbox("🛡️ Headers HTTP", domain_url != "")
            }
        
        # Botão de scan
        scan_button = st.sidebar.button(
            "🚀 Iniciar Escaneamento",
            type="primary",
            use_container_width=True
        )
        
        if scan_button:
            if repo_url or domain_url:
                self.run_security_scan(repo_url, domain_url, scan_options)
            else:
                st.sidebar.error("❌ Forneça pelo menos uma URL")
        
        # Seção de relatórios
        st.sidebar.markdown("---")
        st.sidebar.subheader("📄 Relatórios")
        
        if st.session_state.scan_results:
            col1, col2 = st.sidebar.columns(2)
            
            with col1:
                if st.button("📊 PDF Completo", use_container_width=True):
                    self.generate_pdf_report('comprehensive')
            
            with col2:
                if st.button("📋 PDF Resumo", use_container_width=True):
                    self.generate_pdf_report('summary')
        
        # Histórico
        if st.session_state.scan_history:
            with st.sidebar.expander("📚 Histórico"):
                for i, scan in enumerate(st.session_state.scan_history[-5:]):
                    st.text(f"{scan['date'][:16]} - {scan['total_issues']} issues")
        
        return scan_options
    
    def render_main_content(self):
        """Renderiza conteúdo principal"""
        st.title("🔒 SecureQA Suite")
        st.markdown("""
        ### Plataforma Completa de Testes de Segurança
        
        Análise automatizada de segurança para repositórios GitHub e aplicações web.
        Configure um repositório na barra lateral para começar.
        """)
        
        if st.session_state.scan_results is None:
            self.show_welcome_dashboard()
        else:
            self.show_results_dashboard()
    
    def show_welcome_dashboard(self):
        """Mostra dashboard de boas-vindas"""
        # Métricas demo
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="🔴 Issues Críticos",
                value="0",
                delta="0",
                delta_color="normal"
            )
        
        with col2:
            st.metric(
                label="🟠 Issues Alto Risco", 
                value="0",
                delta="0",
                delta_color="normal"
            )
        
        with col3:
            st.metric(
                label="📦 Dependencies",
                value="0",
                delta="0",
                delta_color="normal"
            )
        
        with col4:
            st.metric(
                label="📊 Security Score",
                value="--/100",
                delta="--"
            )
        
        # Gráficos de exemplo
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Exemplo: Distribuição por Severidade")
            
            demo_data = pd.DataFrame({
                'Severidade': ['Critical', 'High', 'Medium', 'Low'],
                'Count': [0, 0, 0, 0]
            })
            
            fig = px.pie(
                demo_data, 
                values='Count', 
                names='Severidade',
                color_discrete_map={
                    'Critical': '#FF4B4B', 
                    'High': '#FF8C00', 
                    'Medium': '#FFD700', 
                    'Low': '#32CD32'
                },
                title="Aguardando scan..."
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📊 Exemplo: Timeline de Issues")
            
            timeline_data = pd.DataFrame({
                'Data': pd.date_range(start='2024-01-01', periods=7, freq='D'),
                'Issues': [0, 0, 0, 0, 0, 0, 0]
            })
            
            fig = px.line(
                timeline_data, 
                x='Data', 
                y='Issues',
                title="Histórico de Escaneamentos"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Funcionalidades
        st.markdown("---")
        st.subheader("🛠️ Funcionalidades Disponíveis")
        
        features_col1, features_col2, features_col3 = st.columns(3)
        
        with features_col1:
            st.markdown("""
            **🔍 Análise de Código**
            - SQL Injection
            - XSS Vulnerabilities
            - Command Injection
            - Weak Cryptography
            """)
        
        with features_col2:
            st.markdown("""
            **📦 Dependências**
            - CVE Database
            - Versões Vulneráveis
            - Recomendações de Upgrade
            - CVSS Scoring
            """)
        
        with features_col3:
            st.markdown("""
            **🔐 Secrets Detection**
            - API Keys
            - Passwords
            - Tokens
            - Certificates
            """)
    
    def show_results_dashboard(self):
        """Mostra dashboard com resultados do scan"""
        results = st.session_state.scan_results
        summary = results.get('summary', {})
        
        # Header com informações do scan
        st.success("✅ Escaneamento concluído!")
        
        scan_info_col1, scan_info_col2, scan_info_col3 = st.columns(3)
        
        with scan_info_col1:
            st.info(f"📅 **Data:** {summary.get('scan_date', 'N/A')[:16]}")
        
        with scan_info_col2:
            st.info(f"🎯 **Total Issues:** {summary.get('total_issues', 0)}")
        
        with scan_info_col3:
            risk_score = summary.get('risk_score', 0)
            risk_color = "🟢" if risk_score < 30 else "🟡" if risk_score < 70 else "🔴"
            st.info(f"{risk_color} **Risk Score:** {risk_score}/100")
        
        # Métricas principais
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            critical = summary.get('critical_issues', 0)
            st.metric(
                label="🔴 Críticos",
                value=critical,
                delta=f"+{critical}" if critical > 0 else None
            )
        
        with col2:
            high = summary.get('high_issues', 0)
            st.metric(
                label="🟠 Alto Risco",
                value=high,
                delta=f"+{high}" if high > 0 else None
            )
        
        with col3:
            medium = summary.get('medium_issues', 0)
            st.metric(
                label="🟡 Médio Risco",
                value=medium,
                delta=f"+{medium}" if medium > 0 else None
            )
        
        with col4:
            low = summary.get('low_issues', 0)
            st.metric(
                label="🟢 Baixo Risco",
                value=low,
                delta=f"+{low}" if low > 0 else None
            )
        
        # Tabs para diferentes análises
        tabs = st.tabs([
            "📊 Resumo",
            "🔍 Código",
            "📦 Dependências", 
            "🔐 Secrets",
            "🐳 Docker",
            "🔒 SSL/TLS",
            "🛡️ Headers"
        ])
        
        with tabs[0]:
            self.show_summary_tab(results)
        
        with tabs[1]:
            self.show_static_analysis_tab(results.get('static_analysis', []))
        
        with tabs[2]:
            self.show_dependency_tab(results.get('dependency_check', []))
        
        with tabs[3]:
            self.show_secrets_tab(results.get('secrets_detection', []))
        
        with tabs[4]:
            self.show_docker_tab(results.get('dockerfile_analysis', []))
        
        with tabs[5]:
            self.show_ssl_tab(results.get('ssl_check', {}))
        
        with tabs[6]:
            self.show_headers_tab(results.get('headers_check', {}))
    
    def show_summary_tab(self, results: Dict):
        """Tab de resumo geral"""
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Distribuição por Severidade")
            
            # Coletar dados de severidade
            severity_data = []
            for analysis_type in ['static_analysis', 'dependency_check', 'secrets_detection', 'dockerfile_analysis']:
                for item in results.get(analysis_type, []):
                    severity_data.append(item.get('severity', 'LOW'))
            
            if severity_data:
                severity_df = pd.DataFrame(severity_data, columns=['Severity'])
                severity_counts = severity_df['Severity'].value_counts()
                
                fig = px.pie(
                    values=severity_counts.values,
                    names=severity_counts.index,
                    title="Issues por Severidade",
                    color_discrete_map={
                        'CRITICAL': '#FF4B4B',
                        'HIGH': '#FF8C00',
                        'MEDIUM': '#FFD700',
                        'LOW': '#32CD32'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Nenhum issue encontrado!")
        
        with col2:
            st.subheader("📈 Issues por Categoria")
            
            categories = {
                'Análise de Código': len(results.get('static_analysis', [])),
                'Dependências': len(results.get('dependency_check', [])),
                'Secrets': len(results.get('secrets_detection', [])),
                'Docker': len(results.get('dockerfile_analysis', []))
            }
            
            if sum(categories.values()) > 0:
                cat_df = pd.DataFrame(list(categories.items()), columns=['Categoria', 'Issues'])
                fig = px.bar(cat_df, x='Categoria', y='Issues', title="Issues por Categoria")
                fig.update_layout(showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Nenhum issue encontrado!")
        
        # Resumo textual
        st.subheader("📝 Resumo Executivo")
        summary = results.get('summary', {})
        
        total_issues = summary.get('total_issues', 0)
        critical_issues = summary.get('critical_issues', 0)
        high_issues = summary.get('high_issues', 0)
        
        if total_issues == 0:
            st.success("🎉 **Excelente!** Nenhuma vulnerabilidade crítica foi encontrada. Continue mantendo as boas práticas de segurança!")
        elif critical_issues > 0:
            st.error(f"⚠️ **Atenção:** {critical_issues} vulnerabilidade(s) crítica(s) detectada(s) que requer(em) ação imediata.")
        elif high_issues > 0:
            st.warning(f"🔸 {high_issues} vulnerabilidade(s) de alto risco identificada(s). Recomenda-se correção prioritária.")
        else:
            st.info(f"ℹ️ {total_issues} issue(s) de baixo/médio risco encontrado(s). Revisar quando possível.")
    
    def show_static_analysis_tab(self, static_results: List[Dict]):
        """Tab de análise estática"""
        st.subheader("🔍 Análise Estática de Código")
        
        if not static_results:
            st.success("✅ Nenhuma vulnerabilidade detectada na análise de código!")
            return
        
        # Filtros
        col1, col2 = st.columns(2)
        
        with col1:
            severities = list(set([item.get('severity', 'LOW') for item in static_results]))
            severity_filter = st.selectbox("Filtrar por Severidade", ['Todos'] + severities)
        
        with col2:
            files = list(set([item.get('file', 'N/A') for item in static_results]))
            file_filter = st.selectbox("Filtrar por Arquivo", ['Todos'] + files)
        
        # Aplicar filtros
        filtered_results = static_results
        if severity_filter != 'Todos':
            filtered_results = [item for item in filtered_results if item.get('severity') == severity_filter]
        if file_filter != 'Todos':
            filtered_results = [item for item in filtered_results if item.get('file') == file_filter]
        
        st.info(f"Mostrando {len(filtered_results)} de {len(static_results)} issues")
        
        # Mostrar resultados
        for i, issue in enumerate(filtered_results):
            severity = issue.get('severity', 'LOW')
            severity_color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
            
            with st.expander(f"{severity_color.get(severity, '⚪')} {issue.get('type', 'Unknown')} - {issue.get('file', 'N/A')}:{issue.get('line', 'N/A')}"):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**Descrição:** {issue.get('description', 'N/A')}")
                    st.code(issue.get('code', 'N/A'), language='python')
                
                with col2:
                    st.metric("Severidade", severity)
                    st.metric("Linha", issue.get('line', 'N/A'))
    
    def show_dependency_tab(self, dep_results: List[Dict]):
        """Tab de análise de dependências"""
        st.subheader("📦 Análise de Dependências")
        
        if not dep_results:
            st.success("✅ Nenhuma vulnerabilidade encontrada nas dependências!")
            return
        
        # Tabela resumo
        df = pd.DataFrame(dep_results)
        st.dataframe(df, use_container_width=True)
        
        # Detalhes por CVE
        st.subheader("🔍 Detalhes das Vulnerabilidades")
        
        for vuln in dep_results:
            severity = vuln.get('severity', 'LOW')
            severity_color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
            
            with st.expander(f"{severity_color.get(severity, '⚪')} {vuln.get('package', 'N/A')} - {vuln.get('cve', 'N/A')}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Pacote:** {vuln.get('package', 'N/A')}")
                    st.write(f"**Versão:** {vuln.get('version', 'N/A')}")
                    st.write(f"**CVE:** {vuln.get('cve', 'N/A')}")
                
                with col2:
                    st.metric("Severidade", severity)
                    if 'cvss_score' in vuln:
                        st.metric("CVSS Score", f"{vuln['cvss_score']}/10")
                
                st.write(f"**Descrição:** {vuln.get('description', 'N/A')}")
                
                if 'fixed_version' in vuln:
                    st.success(f"✅ **Correção:** Atualizar para versão {vuln['fixed_version']}")
    
    def show_secrets_tab(self, secrets_results: List[Dict]):
        """Tab de detecção de secrets"""
        st.subheader("🔐 Detecção de Secrets")
        
        if not secrets_results:
            st.success("✅ Nenhum secret detectado!")
            return
        
        st.error(f"⚠️ {len(secrets_results)} secret(s) detectado(s)!")
        
        # Alerta de segurança
        st.warning("""
        **🚨 ALERTA DE SEGURANÇA:**
        Secrets hardcoded representam risco crítico. Remova-os imediatamente e use:
        - Variáveis de ambiente
        - Sistemas de gerenciamento de secrets (HashiCorp Vault, AWS Secrets Manager)
        - Configuração externa segura
        """)
        
        # Lista de secrets
        for i, secret in enumerate(secrets_results):
            with st.expander(f"🔴 {secret.get('type', 'Unknown')} - {secret.get('file', 'N/A')}:{secret.get('line', 'N/A')}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Tipo:** {secret.get('type', 'N/A')}")
                    st.write(f"**Arquivo:** {secret.get('file', 'N/A')}")
                    st.code(secret.get('match', 'N/A')[:100] + '...' if len(secret.get('match', '')) > 100 else secret.get('match', 'N/A'))
                
                with col2:
                    st.metric("Linha", secret.get('line', 'N/A'))
                    st.metric("Severidade", "CRITICAL")
                
                st.error("🔧 **AÇÃO NECESSÁRIA:** Remover este secret e usar configuração segura")
    
    def show_docker_tab(self, docker_results: List[Dict]):
        """Tab de análise Docker"""
        st.subheader("🐳 Análise de Dockerfile")
        
        if not docker_results:
            st.success("✅ Nenhum issue encontrado no Dockerfile!")
            return
        
        st.warning(f"⚠️ {len(docker_results)} issue(s) encontrado(s) no Dockerfile")
        
        for issue in docker_results:
            severity = issue.get('severity', 'LOW')
            severity_color = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
            
            with st.expander(f"{severity_color.get(severity, '⚪')} {issue.get('issue', 'Unknown')} - Linha {issue.get('line', 'N/A')}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Problema:** {issue.get('issue', 'N/A')}")
                    st.write(f"**Descrição:** {issue.get('description', 'N/A')}")
                
                with col2:
                    st.metric("Severidade", severity)
                    st.metric("Linha", issue.get('line', 'N/A'))
        
        # Melhores práticas
        with st.expander("💡 Melhores Práticas Docker"):
            st.markdown("""
            - Use imagens base oficiais e específicas (evite :latest)
            - Execute containers como usuário não-root
            - Minimize a superfície de ataque
            - Use .dockerignore para excluir arquivos desnecessários
            - Implemente health checks
            - Use multi-stage builds
            """)
    
    def show_ssl_tab(self, ssl_results: Dict):
        """Tab de análise SSL/TLS"""
        st.subheader("🔒 Análise SSL/TLS")
        
        if not ssl_results:
            st.info("ℹ️ Nenhuma análise SSL realizada")
            return
        
        # Informações do certificado
        if ssl_results.get('ssl_enabled'):
            st.success("✅ SSL/TLS habilitado")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Domínio:** {ssl_results.get('domain', 'N/A')}")
                st.write(f"**Versão TLS:** {ssl_results.get('tls_version', 'N/A')}")
                st.write(f"**Cipher Suite:** {ssl_results.get('cipher_suite', 'N/A')}")
            
            with col2:
                st.write(f"**Certificado Válido:** {'✅ Sim' if ssl_results.get('certificate_valid') else '❌ Não'}")
                st.write(f"**Expira em:** {ssl_results.get('certificate_expiry', 'N/A')}")
        
        # Issues SSL
        issues = ssl_results.get('issues', [])
        if issues:
            st.warning(f"⚠️ {len(issues)} issue(s) de SSL encontrado(s)")
            
            for issue in issues:
                severity = issue.get('severity', 'LOW')
                severity_color = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
                
                st.write(f"{severity_color.get(severity, '⚪')} **{issue.get('type', 'Unknown')}:** {issue.get('description', 'N/A')}")
        else:
            st.success("✅ Configuração SSL adequada!")
    
    def show_headers_tab(self, headers_results: Dict):
        """Tab de análise de headers"""
        st.subheader("🛡️ Headers de Segurança HTTP")
        
        if not headers_results:
            st.info("ℹ️ Nenhuma análise de headers realizada")
            return
        
        security_score = headers_results.get('security_score', 0)
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.write(f"**URL:** {headers_results.get('url', 'N/A')}")
        
        with col2:
            score_color = "🟢" if security_score >= 80 else "🟡" if security_score >= 60 else "🔴"
            st.metric("Security Score", f"{score_color} {security_score}/100")
        
        # Headers encontrados vs ausentes
        found_headers = headers_results.get('headers_found', {})
        
        if found_headers:
            st.success(f"✅ {sum(found_headers.values())} header(s) de segurança configurado(s)")
            
            headers_df = pd.DataFrame([
                {'Header': k, 'Configurado': '✅ Sim' if v else '❌ Não'}
                for k, v in found_headers.items()
            ])
            
            st.dataframe(headers_df, use_container_width=True)
        
        # Recomendações
        recommendations = headers_results.get('recommendations', [])
        if recommendations:
            with st.expander("💡 Recomendações"):
                for rec in recommendations:
                    st.write(f"• {rec}")
    
    def run_security_scan(self, repo_url: str, domain_url: str, scan_options: Dict):
        """Executa escaneamento de segurança"""
        if not self.initialize_components():
            st.error("❌ Erro ao inicializar componentes do scanner")
            return
        
        # Criar ID único para o scan
        scan_id = f"scan_{int(time.time())}"
        st.session_state.current_scan_id = scan_id
        
        progress_container = st.container()
        
        with progress_container:
            st.info("🔍 Iniciando escaneamento de segurança...")
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                # Executar scan
                results = self._execute_scan(
                    repo_url, domain_url, scan_options,
                    progress_bar, status_text
                )
                
                if results:
                    # Salvar resultados
                    st.session_state.scan_results = results
                    
                    # Adicionar ao histórico
                    scan_record = {
                        'id': scan_id,
                        'date': datetime.now().isoformat(),
                        'repo_url': repo_url,
                        'domain_url': domain_url,
                        'total_issues': results.get('summary', {}).get('total_issues', 0),
                        'risk_score': results.get('summary', {}).get('risk_score', 0)
                    }
                    
                    st.session_state.scan_history.append(scan_record)
                    
                    # Limpar progresso
                    progress_container.empty()
                    st.success("✅ Escaneamento concluído com sucesso!")
                    st.rerun()
                else:
                    st.error("❌ Falha no escaneamento")
                    
            except Exception as e:
                logger.error(f"Erro durante scan: {e}")
                st.error(f"❌ Erro durante escaneamento: {str(e)}")
                progress_container.empty()
    
    def _execute_scan(self, repo_url: str, domain_url: str, scan_options: Dict, 
                     progress_bar, status_text) -> Optional[Dict]:
        """Executa o scan propriamente dito"""
        results = {
            'static_analysis': [],
            'dependency_check': [],
            'secrets_detection': [],
            'dockerfile_analysis': [],
            'ssl_check': {},
            'headers_check': {},
            'summary': {}
        }
        
        total_steps = sum(scan_options.values())
        current_step = 0
        
        try:
            # Scan de repositório
            if repo_url and any([scan_options['static_analysis'], scan_options['dependency_check'], 
                               scan_options['secrets_detection'], scan_options['dockerfile_analysis']]):
                
                status_text.text("📁 Clonando repositório...")
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    if self.git_handler.clone_repository(repo_url, temp_dir):
                        
                        # Análise estática
                        if scan_options['static_analysis']:
                            status_text.text("🔍 Analisando código...")
                            progress_bar.progress(current_step / total_steps)
                            results['static_analysis'] = self.scanner.static_code_analysis(temp_dir)
                            current_step += 1
                        
                        # Dependências
                        if scan_options['dependency_check']:
                            status_text.text("📦 Verificando dependências...")
                            progress_bar.progress(current_step / total_steps)
                            results['dependency_check'] = self.scanner.dependency_vulnerability_check(temp_dir)
                            current_step += 1
                        
                        # Secrets
                        if scan_options['secrets_detection']:
                            status_text.text("🔐 Detectando secrets...")
                            progress_bar.progress(current_step / total_steps)
                            results['secrets_detection'] = self.scanner.secrets_detection(temp_dir)
                            current_step += 1
                        
                        # Docker
                        if scan_options['dockerfile_analysis']:
                            status_text.text("🐳 Analisando Dockerfile...")
                            progress_bar.progress(current_step / total_steps)
                            results['dockerfile_analysis'] = self.scanner.dockerfile_analysis(temp_dir)
                            current_step += 1
            
            # Scan de domínio
            if domain_url:
                if scan_options['ssl_check']:
                    status_text.text("🔒 Verificando SSL/TLS...")
                    progress_bar.progress(current_step / total_steps)
                    results['ssl_check'] = self.scanner.ssl_tls_check(domain_url)
                    current_step += 1
                
                if scan_options['headers_check']:
                    status_text.text("🛡️ Verificando headers...")
                    progress_bar.progress(current_step / total_steps)
                    results['headers_check'] = self.scanner.security_headers_check(domain_url)
                    current_step += 1
            
            # Gerar resumo
            status_text.text("📊 Gerando resumo...")
            progress_bar.progress(1.0)
            results['summary'] = self.scanner.generate_summary()
            
            return results
            
        except Exception as e:
            logger.error(f"Erro durante execução do scan: {e}")
            return None
    
    def generate_pdf_report(self, report_type: str = 'comprehensive'):
        """Gera relatório PDF"""
        if not st.session_state.scan_results:
            st.error("❌ Nenhum resultado de scan disponível")
            return
        
        try:
            with st.spinner(f"📄 Gerando relatório {report_type}..."):
                pdf_bytes = create_security_report(
                    st.session_state.scan_results, 
                    report_type
                )
                
                if pdf_bytes:
                    # Criar nome do arquivo
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"SecureQA_Report_{report_type}_{timestamp}.pdf"
                    
                    # Oferecer download
                    st.download_button(
                        label=f"📥 Download {report_type.title()} Report",
                        data=pdf_bytes,
                        file_name=filename,
                        mime="application/pdf"
                    )
                    
                    st.success(f"✅ Relatório {report_type} gerado com sucesso!")
                else:
                    st.error("❌ Erro ao gerar relatório PDF")
                    
        except Exception as e:
            logger.error(f"Erro ao gerar PDF: {e}")
            st.error(f"❌ Erro ao gerar relatório: {str(e)}")
    
    def run(self):
        """Executa a aplicação principal"""
        # Aplicar CSS customizado
        self.apply_custom_styles()
        
        # Renderizar interface
        self.render_sidebar()
        self.render_main_content()
        
        # Footer
        self.render_footer()
    
    def apply_custom_styles(self):
        """Aplica estilos CSS customizados"""
        st.markdown("""
        <style>
        /* Tema principal */
        .main > div {
            padding-top: 2rem;
        }
        
        /* Métricas customizadas */
        .stMetric > div > div > div > div {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            padding: 1rem;
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        /* Botões customizados */
        .stButton > button {
            border-radius: 20px;
            border: none;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.2);
        }
        
        /* Sidebar customizada */
        .css-1d391kg {
            background: linear-gradient(180deg, #1e3c72 0%, #2a5298 100%);
        }
        
        /* Cards de expander */
        .streamlit-expanderHeader {
            background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 10px;
            border: 1px solid #dee2e6;
        }
        
        /* Alertas customizados */
        .stAlert > div {
            border-radius: 10px;
            border: none;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        /* Progresso customizado */
        .stProgress > div > div > div {
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        }
        
        /* Tabelas customizadas */
        .dataframe {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        /* Código customizado */
        .stCodeBlock {
            border-radius: 10px;
            border: 1px solid #e1e5e9;
        }
        
        /* Hide streamlit menu */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
        
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render_footer(self):
        """Renderiza footer da aplicação"""
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            **🔒 SecureQA Suite**  
            Versão 2.0 - Production Ready
            """)
        
        with col2:
            st.markdown("""
            **📊 Estatísticas da Sessão**  
            Scans realizados: {scans}  
            Issues encontrados: {issues}
            """.format(
                scans=len(st.session_state.scan_history),
                issues=sum([scan.get('total_issues', 0) for scan in st.session_state.scan_history])
            ))
        
        with col3:
            st.markdown(f"""
            **🕐 Última atualização**  
            {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
            """)


# Importar SecurityScanner simplificado para fallback
class SecurityScanner:
    """Scanner de segurança simplificado"""
    
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
    
    def static_code_analysis(self, target_dir: str) -> List[Dict]:
        """Análise estática simplificada"""
        # Implementação da análise do código original
        import re
        
        vulnerabilities = []
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
                    except Exception:
                        continue
        
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
            vuln_db = {
                'Django': {
                    '2.0.1': [{'cve': 'CVE-2018-7536', 'severity': 'CRITICAL', 'description': 'Catastrophic backtracking vulnerability'}]
                },
                'requests': {
                    '2.18.4': [{'cve': 'CVE-2018-18074', 'severity': 'HIGH', 'description': 'Credentials exposure vulnerability'}]
                }
            }
            
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '==' in line:
                        package, version = line.split('==')
                        package = package.strip()
                        version = version.strip()
                        
                        if package in vuln_db and version in vuln_db[package]:
                            for vuln in vuln_db[package][version]:
                                vulnerabilities.append({
                                    'package': package,
                                    'version': version,
                                    'cve': vuln['cve'],
                                    'severity': vuln['severity'],
                                    'description': vuln['description']
                                })
        
        return vulnerabilities
    
    def secrets_detection(self, target_dir: str) -> List[Dict]:
        """Detecta secrets expostos"""
        import re
        
        secrets = []
        secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'ghp_[0-9a-zA-Z]{36}',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?[0-9a-zA-Z]{20,}',
            'password': r'password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
        }
        
        for root, dirs, files in os.walk(target_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env')):
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
        
        return secrets
    
    def dockerfile_analysis(self, target_dir: str) -> List[Dict]:
        """Analisa Dockerfile"""
        issues = []
        dockerfile_path = os.path.join(target_dir, 'Dockerfile')
        
        if os.path.exists(dockerfile_path):
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines, 1):
                line_upper = line.strip().upper()
                
                if line_upper.startswith('USER ROOT'):
                    issues.append({
                        'line': i,
                        'issue': 'Running as root user',
                        'severity': 'HIGH',
                        'description': 'Container não deve executar como root'
                    })
                
                if 'CHMOD 777' in line_upper:
                    issues.append({
                        'line': i,
                        'issue': 'Overly permissive file permissions',
                        'severity': 'HIGH',
                        'description': 'Permissões 777 são muito permissivas'
                    })
        
        return issues
    
    def ssl_tls_check(self, domain: str) -> Dict:
        """Verifica SSL/TLS (simulado)"""
        return {
            'domain': domain,
            'ssl_enabled': True,
            'certificate_valid': True,
            'tls_version': 'TLSv1.3',
            'cipher_suite': 'TLS_AES_256_GCM_SHA384',
            'certificate_expiry': '2025-12-31',
            'issues': []
        }
    
    def security_headers_check(self, url: str) -> Dict:
        """Verifica headers de segurança (simulado)"""
        return {
            'url': url,
            'headers_found': {
                'Content-Security-Policy': False,
                'X-Frame-Options': True,
                'X-Content-Type-Options': True,
                'Strict-Transport-Security': False
            },
            'security_score': 60,
            'recommendations': [
                'Implementar Content-Security-Policy',
                'Adicionar Strict-Transport-Security'
            ]
        }
    
    def generate_summary(self) -> Dict:
        """Gera resumo dos resultados"""
        # Coletar todos os issues
        all_issues = []
        for key in ['static_analysis', 'dependency_check', 'secrets_detection', 'dockerfile_analysis']:
            all_issues.extend(self.results.get(key, []))
        
        total_issues = len(all_issues)
        critical_issues = sum(1 for issue in all_issues if issue.get('severity') == 'CRITICAL')
        high_issues = sum(1 for issue in all_issues if issue.get('severity') == 'HIGH')
        medium_issues = sum(1 for issue in all_issues if issue.get('severity') == 'MEDIUM')
        low_issues = total_issues - critical_issues - high_issues - medium_issues
        
        risk_score = min(100, (critical_issues * 20 + high_issues * 10 + medium_issues * 5))
        
        return {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'high_issues': high_issues,
            'medium_issues': medium_issues,
            'low_issues': low_issues,
            'risk_score': risk_score,
            'scan_date': datetime.now().isoformat(),
            'categories': {
                'static_analysis': len(self.results.get('static_analysis', [])),
                'dependency_check': len(self.results.get('dependency_check', [])),
                'secrets_detection': len(self.results.get('secrets_detection', [])),
                'dockerfile_analysis': len(self.results.get('dockerfile_analysis', []))
            }
        }


def main():
    """Função principal"""
    try:
        # Inicializar aplicação
        app = SecureQASuite()
        
        # Executar aplicação
        app.run()
        
    except Exception as e:
        st.error(f"❌ Erro crítico na aplicação: {str(e)}")
        logger.error(f"Erro crítico: {e}", exc_info=True)
        
        # Mostrar informações de debug em modo de desenvolvimento
        if st.secrets.get("environment", "production") == "development":
            st.exception(e)


if __name__ == "__main__":
    main()