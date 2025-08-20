"""
SecureQA Suite - Gerador de Relatórios PDF
Módulo responsável por gerar relatórios detalhados em PDF dos resultados de segurança
"""

import io
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import base64

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch, cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, KeepTogether, Frame, PageTemplate
)
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF


class SecurityReportGenerator:
    """Gerador de relatórios PDF para resultados de segurança"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
        
    def _create_custom_styles(self):
        """Cria estilos customizados para o relatório"""
        # Título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#1f4e79'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtítulo
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor('#2e75b6'),
            spaceBefore=20,
            spaceAfter=15,
            fontName='Helvetica-Bold'
        ))
        
        # Cabeçalho de seção
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1f4e79'),
            spaceBefore=15,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))
        
        # Texto crítico (para vulnerabilidades críticas)
        self.styles.add(ParagraphStyle(
            name='CriticalText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        
        # Texto de alto risco
        self.styles.add(ParagraphStyle(
            name='HighText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.orange,
            fontName='Helvetica-Bold'
        ))
        
        # Texto de médio risco
        self.styles.add(ParagraphStyle(
            name='MediumText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#FFD700'),
            fontName='Helvetica'
        ))
        
        # Texto de baixo risco
        self.styles.add(ParagraphStyle(
            name='LowText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.green,
            fontName='Helvetica'
        ))
        
        # Código
        self.styles.add(ParagraphStyle(
            name='CodeStyle',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            backgroundColor=colors.HexColor('#f5f5f5'),
            leftIndent=20,
            rightIndent=20,
            spaceBefore=5,
            spaceAfter=5
        ))
        
    def generate_comprehensive_report(self, scan_results: Dict, output_path: Optional[str] = None) -> bytes:
        """Gera relatório completo em PDF"""
        if output_path:
            doc = SimpleDocTemplate(output_path, pagesize=A4,
                                  rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
        else:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4,
                                  rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
        
        story = []
        
        # Capa
        story.extend(self._create_cover_page(scan_results))
        story.append(PageBreak())
        
        # Resumo Executivo
        story.extend(self._create_executive_summary(scan_results))
        story.append(PageBreak())
        
        # Métricas e Gráficos
        story.extend(self._create_metrics_section(scan_results))
        story.append(PageBreak())
        
        # Análise de Código
        if scan_results.get('static_analysis'):
            story.extend(self._create_static_analysis_section(scan_results['static_analysis']))
            story.append(PageBreak())
        
        # Dependências
        if scan_results.get('dependency_check'):
            story.extend(self._create_dependencies_section(scan_results['dependency_check']))
            story.append(PageBreak())
        
        # Secrets
        if scan_results.get('secrets_detection'):
            story.extend(self._create_secrets_section(scan_results['secrets_detection']))
            story.append(PageBreak())
        
        # Docker
        if scan_results.get('dockerfile_analysis'):
            story.extend(self._create_docker_section(scan_results['dockerfile_analysis']))
            story.append(PageBreak())
        
        # SSL/TLS
        if scan_results.get('ssl_check'):
            story.extend(self._create_ssl_section(scan_results['ssl_check']))
            story.append(PageBreak())
        
        # Headers HTTP
        if scan_results.get('headers_check'):
            story.extend(self._create_headers_section(scan_results['headers_check']))
            story.append(PageBreak())
        
        # Recomendações
        story.extend(self._create_recommendations_section(scan_results))
        story.append(PageBreak())
        
        # Anexos
        story.extend(self._create_appendices(scan_results))
        
        # Construir PDF
        doc.build(story)
        
        if output_path:
            return None
        else:
            buffer.seek(0)
            return buffer.getvalue()
    
    def _create_cover_page(self, scan_results: Dict) -> List:
        """Cria página de capa"""
        elements = []
        summary = scan_results.get('summary', {})
        
        # Logo/Título
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph("🔒 SecureQA Suite", self.styles['CustomTitle']))
        elements.append(Paragraph("Relatório de Análise de Segurança", self.styles['CustomSubtitle']))
        
        elements.append(Spacer(1, 1*inch))
        
        # Informações do scan
        scan_info = [
            ['Data do Scan:', summary.get('scan_timestamp', 'N/A')[:19].replace('T', ' ')],
            ['Total de Issues:', str(summary.get('total_issues', 0))],
            ['Risk Score:', f"{summary.get('risk_score', 0)}/100"],
            ['Nível de Risco:', summary.get('risk_level', 'N/A')]
        ]
        
        info_table = Table(scan_info, colWidths=[2*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 1*inch))
        
        # Resumo rápido de vulnerabilidades
        risk_summary = [
            ['🔴 Críticas:', str(summary.get('critical_issues', 0))],
            ['🟠 Altas:', str(summary.get('high_issues', 0))],
            ['🟡 Médias:', str(summary.get('medium_issues', 0))],
            ['🟢 Baixas:', str(summary.get('low_issues', 0))]
        ]
        
        risk_table = Table(risk_summary, colWidths=[2*inch, 1*inch])
        risk_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(risk_table)
        
        # Disclaimer
        elements.append(Spacer(1, 1*inch))
        disclaimer = """
        <b>Aviso:</b> Este relatório foi gerado automaticamente pelo SecureQA Suite. 
        Os resultados devem ser validados por profissionais de segurança antes de 
        implementar correções em ambiente de produção.
        """
        elements.append(Paragraph(disclaimer, self.styles['Normal']))
        
        return elements
    
    def _create_executive_summary(self, scan_results: Dict) -> List:
        """Cria resumo executivo"""
        elements = []
        summary = scan_results.get('summary', {})
        
        elements.append(Paragraph("Resumo Executivo", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        # Visão geral
        overview = f"""
        Este relatório apresenta os resultados da análise de segurança realizada em 
        {summary.get('scan_timestamp', 'N/A')[:10]}. Foram identificados 
        <b>{summary.get('total_issues', 0)} issues</b> de segurança, com um 
        <b>risk score de {summary.get('risk_score', 0)}/100</b>.
        """
        elements.append(Paragraph(overview, self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Principais achados
        elements.append(Paragraph("Principais Achados:", self.styles['SectionHeader']))
        
        critical = summary.get('critical_issues', 0)
        high = summary.get('high_issues', 0)
        
        if critical > 0:
            finding = f"⚠️ <b>ATENÇÃO:</b> {critical} vulnerabilidade(s) crítica(s) detectada(s) que requer(em) ação imediata."
            elements.append(Paragraph(finding, self.styles['CriticalText']))
            elements.append(Spacer(1, 10))
        
        if high > 0:
            finding = f"🔸 {high} vulnerabilidade(s) de alto risco identificada(s)."
            elements.append(Paragraph(finding, self.styles['HighText']))
            elements.append(Spacer(1, 10))
        
        # Categorias mais afetadas
        categories = summary.get('categories', {})
        max_category = max(categories.items(), key=lambda x: x[1]) if categories else None
        
        if max_category and max_category[1] > 0:
            category_text = f"""
            A categoria mais afetada é <b>{max_category[0]}</b> com {max_category[1]} issue(s).
            """
            elements.append(Paragraph(category_text, self.styles['Normal']))
        
        elements.append(Spacer(1, 20))
        
        # Recomendações prioritárias
        recommendations = summary.get('recommendations', [])
        if recommendations:
            elements.append(Paragraph("Recomendações Prioritárias:", self.styles['SectionHeader']))
            
            for i, rec in enumerate(recommendations[:5], 1):  # Top 5
                elements.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
                elements.append(Spacer(1, 5))
        
        return elements
    
    def _create_metrics_section(self, scan_results: Dict) -> List:
        """Cria seção de métricas com gráficos"""
        elements = []
        summary = scan_results.get('summary', {})
        
        elements.append(Paragraph("Métricas de Segurança", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        # Tabela de métricas principais
        metrics_data = [
            ['Métrica', 'Valor', 'Status'],
            ['Total de Issues', str(summary.get('total_issues', 0)), self._get_status_icon(summary.get('total_issues', 0))],
            ['Issues Críticas', str(summary.get('critical_issues', 0)), self._get_severity_icon('CRITICAL')],
            ['Issues Altas', str(summary.get('high_issues', 0)), self._get_severity_icon('HIGH')],
            ['Issues Médias', str(summary.get('medium_issues', 0)), self._get_severity_icon('MEDIUM')],
            ['Issues Baixas', str(summary.get('low_issues', 0)), self._get_severity_icon('LOW')],
            ['Risk Score', f"{summary.get('risk_score', 0)}/100", self._get_risk_status(summary.get('risk_score', 0))],
        ]
        
        metrics_table = Table(metrics_data, colWidths=[2*inch, 1*inch, 1*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(metrics_table)
        elements.append(Spacer(1, 30))
        
        # Distribuição por categoria
        categories = summary.get('categories', {})
        if categories:
            elements.append(Paragraph("Distribuição por Categoria:", self.styles['SectionHeader']))
            
            cat_data = [['Categoria', 'Issues']]
            for cat, count in categories.items():
                if count > 0:
                    cat_data.append([cat.replace('_', ' ').title(), str(count)])
            
            if len(cat_data) > 1:
                cat_table = Table(cat_data, colWidths=[3*inch, 1*inch])
                cat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2e75b6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                
                elements.append(cat_table)
        
        return elements
    
    def _create_static_analysis_section(self, static_results: List[Dict]) -> List:
        """Cria seção de análise estática"""
        elements = []
        
        elements.append(Paragraph("🔍 Análise Estática de Código", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        if not static_results:
            elements.append(Paragraph("✅ Nenhuma vulnerabilidade detectada na análise de código!", 
                                    self.styles['Normal']))
            return elements
        
        elements.append(Paragraph(f"Total de issues encontrados: {len(static_results)}", 
                                self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Agrupar por severidade
        by_severity = {}
        for issue in static_results:
            severity = issue.get('severity', 'LOW')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(issue)
        
        # Ordenar por severidade
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            if severity in by_severity:
                issues = by_severity[severity]
                
                elements.append(Paragraph(f"{self._get_severity_icon(severity)} {severity} ({len(issues)} issues):", 
                                        self.styles['SectionHeader']))
                
                # Tabela de issues
                issue_data = [['Arquivo', 'Linha', 'Tipo', 'Descrição']]
                
                for issue in issues[:10]:  # Limitar a 10 por severidade
                    issue_data.append([
                        issue.get('file', 'N/A')[:30] + '...' if len(issue.get('file', '')) > 30 else issue.get('file', 'N/A'),
                        str(issue.get('line', 'N/A')),
                        issue.get('type', 'N/A')[:20] + '...' if len(issue.get('type', '')) > 20 else issue.get('type', 'N/A'),
                        issue.get('description', 'N/A')[:40] + '...' if len(issue.get('description', '')) > 40 else issue.get('description', 'N/A')
                    ])
                
                issue_table = Table(issue_data, colWidths=[1.5*inch, 0.5*inch, 1.5*inch, 2.5*inch])
                issue_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self._get_severity_color(severity)),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                
                elements.append(issue_table)
                elements.append(Spacer(1, 15))
                
                if len(issues) > 10:
                    elements.append(Paragraph(f"... e mais {len(issues) - 10} issues de severidade {severity}", 
                                            self.styles['Normal']))
                    elements.append(Spacer(1, 10))
        
        return elements
    
    def _create_dependencies_section(self, dependency_results: List[Dict]) -> List:
        """Cria seção de análise de dependências"""
        elements = []
        
        elements.append(Paragraph("📦 Análise de Dependências", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        if not dependency_results:
            elements.append(Paragraph("✅ Nenhuma vulnerabilidade detectada nas dependências!", 
                                    self.styles['Normal']))
            return elements
        
        # Agrupar por package
        by_package = {}
        for dep in dependency_results:
            package = dep.get('package', 'Unknown')
            if package not in by_package:
                by_package[package] = []
            by_package[package].append(dep)
        
        elements.append(Paragraph(f"Pacotes vulneráveis encontrados: {len(by_package)}", 
                                self.styles['Normal']))
        elements.append(Paragraph(f"Total de vulnerabilidades: {len(dependency_results)}", 
                                self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Tabela resumo
        dep_data = [['Pacote', 'Versão', 'Vulnerabilidades', 'Max Severidade']]
        
        for package, vulns in by_package.items():
            version = vulns[0].get('version', 'N/A')
            vuln_count = len(vulns)
            max_severity = max((v.get('severity', 'LOW') for v in vulns), 
                             key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x, 0))
            
            dep_data.append([
                package[:25] + '...' if len(package) > 25 else package,
                version,
                str(vuln_count),
                max_severity
            ])
        
        dep_table = Table(dep_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch])
        dep_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(dep_table)
        elements.append(Spacer(1, 20))
        
        # Detalhes das vulnerabilidades críticas/altas
        critical_high = [dep for dep in dependency_results 
                        if dep.get('severity', 'LOW') in ['CRITICAL', 'HIGH']]
        
        if critical_high:
            elements.append(Paragraph("Vulnerabilidades Críticas/Altas:", self.styles['SectionHeader']))
            
            for vuln in critical_high[:15]:  # Limitar para não ficar muito longo
                severity_icon = self._get_severity_icon(vuln.get('severity', 'LOW'))
                vuln_text = f"""
                {severity_icon} <b>{vuln.get('package', 'N/A')} {vuln.get('version', 'N/A')}</b>
                <br/>CVE: {vuln.get('cve', 'N/A')}
                <br/>Descrição: {vuln.get('description', 'N/A')[:100]}...
                <br/>Versão corrigida: {vuln.get('fixed_version', 'N/A')}
                """
                elements.append(Paragraph(vuln_text, self.styles['Normal']))
                elements.append(Spacer(1, 10))
        
        return elements
    
    def _create_secrets_section(self, secrets_results: List[Dict]) -> List:
        """Cria seção de detecção de secrets"""
        elements = []
        
        elements.append(Paragraph("🔐 Detecção de Secrets", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        if not secrets_results:
            elements.append(Paragraph("✅ Nenhum secret detectado!", self.styles['Normal']))
            return elements
        
        elements.append(Paragraph(f"⚠️ {len(secrets_results)} secret(s) detectado(s)!", 
                                self.styles['CriticalText']))
        elements.append(Spacer(1, 15))
        
        # Alerta de segurança
        warning = """
        <b>ALERTA DE SEGURANÇA:</b> Secrets hardcoded no código representam um risco 
        crítico de segurança. Estes devem ser removidos imediatamente e substituídos 
        por variáveis de ambiente ou sistemas de gerenciamento de secrets.
        """
        elements.append(Paragraph(warning, self.styles['CriticalText']))
        elements.append(Spacer(1, 15))
        
        # Tabela de secrets
        secret_data = [['Tipo', 'Arquivo', 'Linha', 'Entropia']]
        
        for secret in secrets_results:
            secret_data.append([
                secret.get('type', 'N/A').replace('_', ' ').title(),
                secret.get('file', 'N/A')[:30] + '...' if len(secret.get('file', '')) > 30 else secret.get('file', 'N/A'),
                str(secret.get('line', 'N/A')),
                f"{secret.get('entropy', 0):.2f}" if secret.get('entropy') else 'N/A'
            ])
        
        secret_table = Table(secret_data, colWidths=[1.5*inch, 2*inch, 0.5*inch, 0.7*inch])
        secret_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(secret_table)
        elements.append(Spacer(1, 20))
        
        # Recomendações específicas para secrets
        elements.append(Paragraph("Ações Recomendadas:", self.styles['SectionHeader']))
        recommendations = [
            "1. Remover imediatamente todos os secrets hardcoded",
            "2. Implementar uso de variáveis de ambiente",
            "3. Considerar uso de sistemas como HashiCorp Vault, AWS Secrets Manager",
            "4. Implementar rotação automática de credenciais",
            "5. Configurar pre-commit hooks para detectar secrets"
        ]
        
        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['Normal']))
            elements.append(Spacer(1, 5))
        
        return elements
    
    def _create_docker_section(self, docker_results: List[Dict]) -> List:
        """Cria seção de análise Docker"""
        elements = []
        
        elements.append(Paragraph("🐳 Análise de Dockerfile", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        if not docker_results:
            elements.append(Paragraph("✅ Nenhum issue encontrado no Dockerfile!", 
                                    self.styles['Normal']))
            return elements
        
        elements.append(Paragraph(f"Issues encontrados: {len(docker_results)}", 
                                self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Tabela de issues Docker
        docker_data = [['Severidade', 'Issue', 'Linha', 'Recomendação']]
        
        for issue in docker_results:
            severity = issue.get('severity', 'LOW')
            docker_data.append([
                severity,
                issue.get('message', 'N/A')[:30] + '...' if len(issue.get('message', '')) > 30 else issue.get('message', 'N/A'),
                str(issue.get('line', 'N/A')),
                issue.get('recommendation', 'N/A')[:40] + '...' if len(issue.get('recommendation', '')) > 40 else issue.get('recommendation', 'N/A')
            ])
        
        docker_table = Table(docker_data, colWidths=[0.8*inch, 2*inch, 0.5*inch, 2.2*inch])
        docker_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(docker_table)
        elements.append(Spacer(1, 15))
        
        # Melhores práticas Docker
        elements.append(Paragraph("Melhores Práticas Docker:", self.styles['SectionHeader']))
        best_practices = [
            "• Use imagens base oficiais e específicas (evite :latest)",
            "• Execute containers como usuário não-root",
            "• Minimize a superfície de ataque (menos pacotes instalados)",
            "• Use .dockerignore para excluir arquivos desnecessários",
            "• Implemente health checks",
            "• Use multi-stage builds para reduzir tamanho da imagem"
        ]
        
        for practice in best_practices:
            elements.append(Paragraph(practice, self.styles['Normal']))
            elements.append(Spacer(1, 5))
        
        return elements
    
    def _create_ssl_section(self, ssl_results: Dict) -> List:
        """Cria seção de análise SSL/TLS"""
        elements = []
        
        elements.append(Paragraph("🔒 Análise SSL/TLS", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        if not ssl_results or not ssl_results.get('valid', False):
            error_msg = ssl_results.get('error', 'Falha na verificação SSL')
            elements.append(Paragraph(f"❌ Erro na verificação SSL: {error_msg}", 
                                    self.styles['CriticalText']))
            return elements
        
        # Informações do certificado
        elements.append(Paragraph("Informações do Certificado:", self.styles['SectionHeader']))
        
        cert_info = [
            ['Domínio:', ssl_results.get('domain', 'N/A')],
            ['Válido:', 'Sim' if ssl_results.get('valid') else 'Não'],
            ['Versão TLS:', ssl_results.get('version', 'N/A')],
            ['Cipher Suite:', ssl_results.get('cipher_suite', 'N/A')],
            ['Expira em:', ssl_results.get('expires', 'N/A')],
            ['Dias até expirar:', str(ssl_results.get('days_until_expiry', 'N/A'))],
            ['Security Score:', f"{ssl_results.get('security_score', 0)}/100"]
        ]
        
        cert_table = Table(cert_info, colWidths=[2*inch, 3*inch])
        cert_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        elements.append(cert_table)
        elements.append(Spacer(1, 15))
        
        # Issues SSL
        issues = ssl_results.get('issues', [])
        if issues:
            elements.append(Paragraph("Issues Identificados:", self.styles['SectionHeader']))
            
            for issue in issues:
                severity_icon = self._get_severity_icon(issue.get('severity', 'LOW'))
                issue_text = f"{severity_icon} {issue.get('description', 'N/A')}"
                elements.append(Paragraph(issue_text, self.styles['Normal']))
                elements.append(Spacer(1, 5))
        else:
            elements.append(Paragraph("✅ Configuração SSL adequada!", self.styles['Normal']))
        
        return elements
    
    def _create_headers_section(self, headers_results: Dict) -> List:
        """Cria seção de análise de headers HTTP"""
        elements = []
        
        elements.append(Paragraph("🛡️ Headers de Segurança HTTP", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        if not headers_results:
            elements.append(Paragraph("❌ Falha na verificação de headers", 
                                    self.styles['CriticalText']))
            return elements
        
        security_score = headers_results.get('security_score', 0)
        elements.append(Paragraph(f"Security Score: {security_score}/100", self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Headers encontrados
        found_headers = headers_results.get('found_headers', {})
        if found_headers:
            elements.append(Paragraph("Headers de Segurança Configurados:", self.styles['SectionHeader']))
            
            found_data = [['Header', 'Valor']]
            for header, info in found_headers.items():
                value = info.get('value', 'N/A')
                # Truncar valores muito longos
                if len(value) > 50:
                    value = value[:47] + '...'
                found_data.append([header, value])
            
            found_table = Table(found_data, colWidths=[2.5*inch, 3*inch])
            found_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            
            elements.append(found_table)
            elements.append(Spacer(1, 15))
        
        # Headers ausentes
        missing_headers = headers_results.get('missing_headers', [])
        if missing_headers:
            elements.append(Paragraph("Headers de Segurança Ausentes:", self.styles['SectionHeader']))
            
            missing_data = [['Header', 'Descrição', 'Severidade']]
            for header in missing_headers:
                missing_data.append([
                    header.get('header', 'N/A'),
                    header.get('description', 'N/A')[:40] + '...' if len(header.get('description', '')) > 40 else header.get('description', 'N/A'),
                    header.get('severity', 'LOW')
                ])
            
            missing_table = Table(missing_data, colWidths=[2*inch, 2.5*inch, 1*inch])
            missing_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (2, 0), (2, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            
            elements.append(missing_table)
            elements.append(Spacer(1, 15))
        
        # Headers inseguros
        insecure_headers = headers_results.get('insecure_headers', [])
        if insecure_headers:
            elements.append(Paragraph("Headers que Expõem Informações:", self.styles['SectionHeader']))
            
            insecure_data = [['Header', 'Valor', 'Issue']]
            for header in insecure_headers:
                insecure_data.append([
                    header.get('header', 'N/A'),
                    header.get('value', 'N/A')[:30] + '...' if len(header.get('value', '')) > 30 else header.get('value', 'N/A'),
                    header.get('issue', 'N/A')
                ])
            
            insecure_table = Table(insecure_data, colWidths=[1.5*inch, 2*inch, 2*inch])
            insecure_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            
            elements.append(insecure_table)
        
        return elements
    
    def _create_recommendations_section(self, scan_results: Dict) -> List:
        """Cria seção de recomendações"""
        elements = []
        
        elements.append(Paragraph("💡 Recomendações de Segurança", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        summary = scan_results.get('summary', {})
        recommendations = summary.get('recommendations', [])
        
        if not recommendations:
            elements.append(Paragraph("✅ Nenhuma recomendação específica gerada. "
                                    "Continue mantendo as boas práticas de segurança!",
                                    self.styles['Normal']))
            return elements
        
        elements.append(Paragraph("Baseado na análise realizada, recomendamos as seguintes ações:", 
                                self.styles['Normal']))
        elements.append(Spacer(1, 15))
        
        # Recomendações prioritárias
        elements.append(Paragraph("🔥 Ações Prioritárias:", self.styles['SectionHeader']))
        
        critical_issues = summary.get('critical_issues', 0)
        high_issues = summary.get('high_issues', 0)
        
        if critical_issues > 0:
            priority_text = f"""
            <b>CRÍTICO:</b> {critical_issues} vulnerabilidade(s) crítica(s) detectada(s). 
            Estas representam risco imediato e devem ser corrigidas com máxima prioridade.
            """
            elements.append(Paragraph(priority_text, self.styles['CriticalText']))
            elements.append(Spacer(1, 10))
        
        if high_issues > 0:
            high_text = f"""
            <b>ALTO:</b> {high_issues} vulnerabilidade(s) de alto risco identificada(s). 
            Programar correção dentro de 7 dias.
            """
            elements.append(Paragraph(high_text, self.styles['HighText']))
            elements.append(Spacer(1, 10))
        
        elements.append(Spacer(1, 15))
        
        # Lista de recomendações
        elements.append(Paragraph("📋 Plano de Ação Detalhado:", self.styles['SectionHeader']))
        
        for i, rec in enumerate(recommendations, 1):
            rec_text = f"<b>{i}.</b> {rec}"
            elements.append(Paragraph(rec_text, self.styles['Normal']))
            elements.append(Spacer(1, 8))
        
        elements.append(Spacer(1, 20))
        
        # Recomendações gerais de segurança
        elements.append(Paragraph("🛡️ Melhores Práticas Gerais:", self.styles['SectionHeader']))
        
        general_recs = [
            "Implementar pipeline de segurança (DevSecOps)",
            "Realizar auditorias de segurança regulares",
            "Manter dependências sempre atualizadas",
            "Usar análise de segurança automatizada em CI/CD",
            "Implementar logging e monitoramento de segurança",
            "Treinar equipe em práticas de codificação segura",
            "Estabelecer processo de resposta a incidentes",
            "Realizar testes de penetração periodicamente"
        ]
        
        for rec in general_recs:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 5))
        
        return elements
    
    def _create_appendices(self, scan_results: Dict) -> List:
        """Cria anexos do relatório"""
        elements = []
        
        elements.append(Paragraph("📎 Anexos", self.styles['CustomTitle']))
        elements.append(Spacer(1, 20))
        
        # Anexo A - Metodologia
        elements.append(Paragraph("Anexo A - Metodologia de Análise", self.styles['SectionHeader']))
        
        methodology = """
        Este relatório foi gerado pelo SecureQA Suite, uma ferramenta automatizada de 
        análise de segurança que utiliza as seguintes técnicas:
        
        <b>1. Análise Estática de Código (SAST):</b>
        • Análise baseada em padrões regex para identificar vulnerabilidades comuns
        • Análise AST (Abstract Syntax Tree) para Python
        • Detecção de padrões de código inseguro (SQL injection, XSS, etc.)
        
        <b>2. Análise de Dependências (SCA):</b>
        • Verificação contra base de dados de vulnerabilidades conhecidas
        • Suporte para múltiplos ecosistemas (npm, PyPI, Maven, etc.)
        • Identificação de versões vulneráveis
        
        <b>3. Detecção de Secrets:</b>
        • Padrões regex para diferentes tipos de credenciais
        • Análise de entropia para detectar strings suspeitas
        • Verificação contextual para reduzir falsos positivos
        
        <b>4. Análise de Container (Docker):</b>
        • Verificação de práticas de segurança em Dockerfile
        • Detecção de configurações inseguras
        • Análise de imagens base e permissões
        
        <b>5. Análise de Infraestrutura:</b>
        • Verificação de configuração SSL/TLS
        • Análise de headers de segurança HTTP
        • Testes de conectividade e certificados
        """
        
        elements.append(Paragraph(methodology, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Anexo B - Classificação de Severidade
        elements.append(Paragraph("Anexo B - Classificação de Severidade", self.styles['SectionHeader']))
        
        severity_info = [
            ['Severidade', 'Descrição', 'SLA de Correção'],
            ['CRITICAL', 'Risco imediato à segurança. Exploração ativa possível.', 'Imediato (24h)'],
            ['HIGH', 'Risco significativo. Possível impacto na segurança.', '7 dias'],
            ['MEDIUM', 'Risco moderado. Melhoria de segurança recomendada.', '30 dias'],
            ['LOW', 'Risco baixo. Melhoria geral de qualidade.', '90 dias']
        ]
        
        severity_table = Table(severity_info, colWidths=[1*inch, 3*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(severity_table)
        elements.append(Spacer(1, 20))
        
        # Anexo C - Referências
        elements.append(Paragraph("Anexo C - Referências e Links Úteis", self.styles['SectionHeader']))
        
        references = [
            "• OWASP Top 10: https://owasp.org/www-project-top-ten/",
            "• CWE (Common Weakness Enumeration): https://cwe.mitre.org/",
            "• NIST Cybersecurity Framework: https://www.nist.gov/cyberframework",
            "• SANS Top 25: https://www.sans.org/top25-software-errors/",
            "• Docker Security Best Practices: https://docs.docker.com/engine/security/",
            "• Mozilla Security Guidelines: https://infosec.mozilla.org/guidelines/",
            "• OWASP Secure Coding Practices: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/"
        ]
        
        for ref in references:
            elements.append(Paragraph(ref, self.styles['Normal']))
            elements.append(Spacer(1, 5))
        
        elements.append(Spacer(1, 20))
        
        # Rodapé
        footer_text = f"""
        <b>Relatório gerado em:</b> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
        <b>SecureQA Suite</b> - Versão 1.0<br/>
        <i>Este relatório é confidencial e deve ser tratado de acordo com as políticas de segurança da organização.</i>
        """
        elements.append(Paragraph(footer_text, self.styles['Normal']))
        
        return elements
    
    def _get_severity_icon(self, severity: str) -> str:
        """Retorna ícone para severidade"""
        icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        return icons.get(severity, '⚪')
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """Retorna cor para severidade"""
        color_map = {
            'CRITICAL': colors.red,
            'HIGH': colors.orange,
            'MEDIUM': colors.HexColor('#FFD700'),
            'LOW': colors.green
        }
        return color_map.get(severity, colors.grey)
    
    def _get_status_icon(self, count: int) -> str:
        """Retorna ícone baseado na contagem"""
        if count == 0:
            return '✅'
        elif count < 5:
            return '⚠️'
        else:
            return '❌'
    
    def _get_risk_status(self, score: int) -> str:
        """Retorna status baseado no risk score"""
        if score >= 80:
            return '🔴 CRÍTICO'
        elif score >= 60:
            return '🟠 ALTO'
        elif score >= 30:
            return '🟡 MÉDIO'
        else:
            return '🟢 BAIXO'


def generate_quick_summary_pdf(scan_results: Dict, output_path: Optional[str] = None) -> bytes:
    """Gera relatório resumido (versão rápida)"""
    generator = SecurityReportGenerator()
    
    if output_path:
        doc = SimpleDocTemplate(output_path, pagesize=A4)
    else:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
    
    story = []
    summary = scan_results.get('summary', {})
    
    # Título
    story.append(Paragraph("🔒 SecureQA Suite - Resumo Executivo", generator.styles['CustomTitle']))
    story.append(Spacer(1, 20))
    
    # Métricas principais
    metrics_data = [
        ['Métrica', 'Valor'],
        ['Data do Scan', summary.get('scan_timestamp', 'N/A')[:19].replace('T', ' ')],
        ['Total de Issues', str(summary.get('total_issues', 0))],
        ['Issues Críticas', str(summary.get('critical_issues', 0))],
        ['Issues Altas', str(summary.get('high_issues', 0))],
        ['Risk Score', f"{summary.get('risk_score', 0)}/100"],
        ['Nível de Risco', summary.get('risk_level', 'N/A')]
    ]
    
    metrics_table = Table(metrics_data, colWidths=[2*inch, 2*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    story.append(metrics_table)
    story.append(Spacer(1, 20))
    
    # Top 5 recomendações
    recommendations = summary.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Top 5 Recomendações:", generator.styles['SectionHeader']))
        
        for i, rec in enumerate(recommendations[:5], 1):
            story.append(Paragraph(f"{i}. {rec}", generator.styles['Normal']))
            story.append(Spacer(1, 8))
    
    doc.build(story)
    
    if output_path:
        return None
    else:
        buffer.seek(0)
        return buffer.getvalue()


# Função auxiliar para uso direto
def create_security_report(scan_results: Dict, report_type: str = "comprehensive") -> bytes:
    """
    Função principal para criar relatórios
    
    Args:
        scan_results: Resultados do scan de segurança
        report_type: 'comprehensive' ou 'summary'
    
    Returns:
        bytes: PDF gerado
    """
    generator = SecurityReportGenerator()
    
    if report_type == "summary":
        return generate_quick_summary_pdf(scan_results)
    else:
        return generator.generate_comprehensive_report(scan_results)