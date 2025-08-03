#!/usr/bin/env python3
"""
Módulo de Relatórios e Logging
Sistema avançado de geração de relatórios e logging para pentesting
"""

import json
import xml.etree.ElementTree as ET
import html
import logging
import os
import shutil
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
import base64
import hashlib

class AdvancedReporting:
    """
    Sistema avançado de relatórios para pentesting
    """
    
    def __init__(self, output_dir, logger=None):
        self.output_dir = output_dir
        self.logger = logger
        self.report_data = {}
        self.scan_metadata = {}
        
        # Templates HTML
        self.html_template = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Penetration Testing</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #f39c12; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #27ae60; }
        .info { border-left: 5px solid #3498db; }
        .vulnerability { margin: 10px 0; padding: 15px; border-radius: 3px; }
        .vuln-title { font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }
        .vuln-details { margin-left: 20px; }
        .summary-table { width: 100%; border-collapse: collapse; }
        .summary-table th, .summary-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .summary-table th { background-color: #34495e; color: white; }
        .code-block { background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 3px; font-family: monospace; white-space: pre-wrap; }
        .toc { background-color: #ecf0f1; padding: 15px; border-radius: 5px; }
        .toc ul { list-style-type: none; padding-left: 20px; }
        .toc a { text-decoration: none; color: #2c3e50; }
        .toc a:hover { color: #3498db; }
        .chart-container { text-align: center; margin: 20px 0; }
        .progress-bar { width: 100%; background-color: #ecf0f1; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 20px; background-color: #3498db; text-align: center; line-height: 20px; color: white; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório de Penetration Testing</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Data:</strong> {date}</p>
        <p><strong>Pentester:</strong> {pentester}</p>
    </div>
    
    <div class="section toc">
        <h2>Índice</h2>
        <ul>
            <li><a href="#executive-summary">1. Resumo Executivo</a></li>
            <li><a href="#methodology">2. Metodologia</a></li>
            <li><a href="#reconnaissance">3. Reconhecimento</a></li>
            <li><a href="#vulnerabilities">4. Vulnerabilidades Identificadas</a></li>
            <li><a href="#recommendations">5. Recomendações</a></li>
            <li><a href="#technical-details">6. Detalhes Técnicos</a></li>
            <li><a href="#appendix">7. Anexos</a></li>
        </ul>
    </div>
    
    {content}
    
    <div class="section">
        <h2>Informações do Relatório</h2>
        <p><strong>Gerado em:</strong> {generation_time}</p>
        <p><strong>Versão do Scanner:</strong> Advanced Pentest Scanner v1.0</p>
        <p><strong>Hash do Relatório:</strong> {report_hash}</p>
    </div>
</body>
</html>
        """
        
    def log(self, message):
        """Helper para logging"""
        if self.logger:
            self.logger.info(message)
        else:
            print(f"[INFO] {message}")
            
    def set_scan_metadata(self, target, pentester="Pentester Senior", scan_type="Completo"):
        """Define metadados do scan"""
        self.scan_metadata = {
            'target': target,
            'pentester': pentester,
            'scan_type': scan_type,
            'start_time': datetime.now(),
            'scanner_version': 'Advanced Pentest Scanner v1.0'
        }
        
    def add_reconnaissance_data(self, recon_data):
        """Adiciona dados de reconhecimento"""
        self.report_data['reconnaissance'] = recon_data
        
    def add_enumeration_data(self, enum_data):
        """Adiciona dados de enumeração"""
        self.report_data['enumeration'] = enum_data
        
    def add_vulnerability_data(self, vuln_data):
        """Adiciona dados de vulnerabilidades"""
        self.report_data['vulnerabilities'] = vuln_data
        
    def generate_executive_summary(self):
        """Gera resumo executivo"""
        summary = {
            'total_hosts': 0,
            'total_ports': 0,
            'vulnerabilities_by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'top_vulnerabilities': [],
            'risk_score': 0
        }
        
        # Contar hosts descobertos
        if 'reconnaissance' in self.report_data:
            recon = self.report_data['reconnaissance']
            if 'discovered_hosts' in recon:
                summary['total_hosts'] = len(recon['discovered_hosts'])
                
        # Contar vulnerabilidades por severidade
        if 'vulnerabilities' in self.report_data:
            vulns = self.report_data['vulnerabilities']
            for target, target_vulns in vulns.items():
                for severity, vuln_list in target_vulns.items():
                    if severity in summary['vulnerabilities_by_severity'] and vuln_list:
                        count = len([v for v in vuln_list.values() if 'VULNERABLE' in str(v)])
                        summary['vulnerabilities_by_severity'][severity] += count
                        
        # Calcular score de risco
        risk_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_risk = 0
        for severity, count in summary['vulnerabilities_by_severity'].items():
            total_risk += count * risk_weights.get(severity, 0)
        summary['risk_score'] = min(total_risk, 100)  # Máximo 100
        
        return summary
        
    def generate_html_report(self, output_file="pentest_report.html"):
        """Gera relatório em formato HTML"""
        self.log("Gerando relatório HTML...")
        
        summary = self.generate_executive_summary()
        
        # Construir conteúdo HTML
        content_sections = []
        
        # Resumo Executivo
        exec_summary = f"""
        <div class="section" id="executive-summary">
            <h2>1. Resumo Executivo</h2>
            <div class="chart-container">
                <h3>Score de Risco: {summary['risk_score']}/100</h3>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {summary['risk_score']}%">{summary['risk_score']}%</div>
                </div>
            </div>
            
            <table class="summary-table">
                <tr><th>Métrica</th><th>Valor</th></tr>
                <tr><td>Hosts Descobertos</td><td>{summary['total_hosts']}</td></tr>
                <tr><td>Vulnerabilidades Críticas</td><td>{summary['vulnerabilities_by_severity']['critical']}</td></tr>
                <tr><td>Vulnerabilidades Altas</td><td>{summary['vulnerabilities_by_severity']['high']}</td></tr>
                <tr><td>Vulnerabilidades Médias</td><td>{summary['vulnerabilities_by_severity']['medium']}</td></tr>
                <tr><td>Vulnerabilidades Baixas</td><td>{summary['vulnerabilities_by_severity']['low']}</td></tr>
            </table>
        </div>
        """
        content_sections.append(exec_summary)
        
        # Metodologia
        methodology = """
        <div class="section" id="methodology">
            <h2>2. Metodologia</h2>
            <p>Este teste de penetração foi conduzido seguindo as melhores práticas da indústria:</p>
            <ul>
                <li><strong>Reconhecimento:</strong> Descoberta de hosts ativos e mapeamento de rede</li>
                <li><strong>Enumeração:</strong> Identificação de serviços e versões</li>
                <li><strong>Análise de Vulnerabilidades:</strong> Verificação de vulnerabilidades conhecidas</li>
                <li><strong>Testes de Configuração:</strong> Verificação de configurações inseguras</li>
                <li><strong>Testes de Credenciais:</strong> Verificação de credenciais padrão</li>
            </ul>
        </div>
        """
        content_sections.append(methodology)
        
        # Reconhecimento
        if 'reconnaissance' in self.report_data:
            recon_section = self._generate_reconnaissance_section()
            content_sections.append(recon_section)
            
        # Vulnerabilidades
        if 'vulnerabilities' in self.report_data:
            vuln_section = self._generate_vulnerabilities_section()
            content_sections.append(vuln_section)
            
        # Recomendações
        recommendations = self._generate_recommendations_section()
        content_sections.append(recommendations)
        
        # Detalhes Técnicos
        technical_details = self._generate_technical_details_section()
        content_sections.append(technical_details)
        
        # Juntar todas as seções
        full_content = '\n'.join(content_sections)
        
        # Calcular hash do relatório
        report_hash = hashlib.sha256(full_content.encode()).hexdigest()[:16]
        
        # Preencher template
        html_content = self.html_template.format(
            target=self.scan_metadata.get('target', 'N/A'),
            date=self.scan_metadata.get('start_time', datetime.now()).strftime('%d/%m/%Y %H:%M'),
            pentester=self.scan_metadata.get('pentester', 'N/A'),
            content=full_content,
            generation_time=datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            report_hash=report_hash
        )
        
        # Salvar arquivo
        output_path = os.path.join(self.output_dir, "reports", output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        self.log(f"Relatório HTML salvo em: {output_path}")
        return output_path
        
    def generate_json_report(self, output_file="pentest_report.json"):
        """Gera relatório em formato JSON"""
        self.log("Gerando relatório JSON...")
        
        json_data = {
            'metadata': self.scan_metadata,
            'executive_summary': self.generate_executive_summary(),
            'data': self.report_data,
            'generation_time': datetime.now().isoformat()
        }
        
        output_path = os.path.join(self.output_dir, "reports", output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str, ensure_ascii=False)
            
        self.log(f"Relatório JSON salvo em: {output_path}")
        return output_path
        
    def generate_xml_report(self, output_file="pentest_report.xml"):
        """Gera relatório em formato XML"""
        self.log("Gerando relatório XML...")
        
        root = ET.Element("pentest_report")
        
        # Metadata
        metadata = ET.SubElement(root, "metadata")
        for key, value in self.scan_metadata.items():
            elem = ET.SubElement(metadata, key)
            elem.text = str(value)
            
        # Executive Summary
        summary = self.generate_executive_summary()
        summary_elem = ET.SubElement(root, "executive_summary")
        for key, value in summary.items():
            if isinstance(value, dict):
                sub_elem = ET.SubElement(summary_elem, key)
                for sub_key, sub_value in value.items():
                    sub_sub_elem = ET.SubElement(sub_elem, sub_key)
                    sub_sub_elem.text = str(sub_value)
            else:
                elem = ET.SubElement(summary_elem, key)
                elem.text = str(value)
                
        # Data
        data_elem = ET.SubElement(root, "scan_data")
        self._dict_to_xml(self.report_data, data_elem)
        
        # Salvar arquivo
        tree = ET.ElementTree(root)
        output_path = os.path.join(self.output_dir, "reports", output_file)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        
        self.log(f"Relatório XML salvo em: {output_path}")
        return output_path
        
    def generate_csv_summary(self, output_file="vulnerability_summary.csv"):
        """Gera resumo de vulnerabilidades em CSV"""
        self.log("Gerando resumo CSV...")
        
        csv_content = "Target,Vulnerability,Severity,Status,Description\n"
        
        if 'vulnerabilities' in self.report_data:
            for target, target_vulns in self.report_data['vulnerabilities'].items():
                for severity, vuln_list in target_vulns.items():
                    if isinstance(vuln_list, dict):
                        for vuln_name, vuln_data in vuln_list.items():
                            status = "VULNERABLE" if "VULNERABLE" in str(vuln_data) else "Not Vulnerable"
                            description = str(vuln_data)[:100] + "..." if len(str(vuln_data)) > 100 else str(vuln_data)
                            description = description.replace('"', '""')  # Escape quotes
                            csv_content += f'"{target}","{vuln_name}","{severity}","{status}","{description}"\n'
                            
        output_path = os.path.join(self.output_dir, "reports", output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(csv_content)
            
        self.log(f"Resumo CSV salvo em: {output_path}")
        return output_path
        
    def create_archive(self, archive_name="pentest_results.zip"):
        """Cria arquivo compactado com todos os resultados"""
        self.log("Criando arquivo compactado...")
        
        archive_path = os.path.join(self.output_dir, archive_name)
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.output_dir):
                for file in files:
                    if file != archive_name:  # Não incluir o próprio arquivo
                        file_path = os.path.join(root, file)
                        arc_name = os.path.relpath(file_path, self.output_dir)
                        zipf.write(file_path, arc_name)
                        
        self.log(f"Arquivo compactado criado: {archive_path}")
        return archive_path
        
    def setup_advanced_logging(self, log_level=logging.INFO):
        """Configura sistema de logging avançado"""
        log_dir = os.path.join(self.output_dir, "logs")
        Path(log_dir).mkdir(exist_ok=True)
        
        # Logger principal
        main_logger = logging.getLogger('pentest_main')
        main_logger.setLevel(log_level)
        
        # Handler para arquivo principal
        main_handler = logging.FileHandler(
            os.path.join(log_dir, f"pentest_main_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        )
        main_handler.setLevel(log_level)
        
        # Handler para erros
        error_handler = logging.FileHandler(
            os.path.join(log_dir, f"pentest_errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        )
        error_handler.setLevel(logging.ERROR)
        
        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatadores
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        main_handler.setFormatter(detailed_formatter)
        error_handler.setFormatter(detailed_formatter)
        console_handler.setFormatter(simple_formatter)
        
        main_logger.addHandler(main_handler)
        main_logger.addHandler(error_handler)
        main_logger.addHandler(console_handler)
        
        return main_logger
        
    def _generate_reconnaissance_section(self):
        """Gera seção de reconhecimento para HTML"""
        recon = self.report_data['reconnaissance']
        
        section = """
        <div class="section" id="reconnaissance">
            <h2>3. Reconhecimento</h2>
        """
        
        if 'discovered_hosts' in recon:
            section += f"""
            <h3>Hosts Descobertos ({len(recon['discovered_hosts'])})</h3>
            <div class="code-block">
            """
            for host in recon['discovered_hosts']:
                section += f"{host}\n"
            section += "</div>"
            
        if 'open_ports' in recon:
            section += "<h3>Portas Abertas por Host</h3>"
            for host, ports in recon['open_ports'].items():
                section += f"<h4>{host}</h4><div class='code-block'>"
                for scan_type, port_list in ports.items():
                    section += f"{scan_type}: {', '.join(port_list) if port_list else 'Nenhuma'}\n"
                section += "</div>"
                
        section += "</div>"
        return section
        
    def _generate_vulnerabilities_section(self):
        """Gera seção de vulnerabilidades para HTML"""
        vulns = self.report_data['vulnerabilities']
        
        section = """
        <div class="section" id="vulnerabilities">
            <h2>4. Vulnerabilidades Identificadas</h2>
        """
        
        severity_classes = {
            'critical': 'critical',
            'high': 'high', 
            'medium': 'medium',
            'low': 'low',
            'info': 'info'
        }
        
        for target, target_vulns in vulns.items():
            section += f"<h3>Target: {target}</h3>"
            
            for severity, vuln_list in target_vulns.items():
                if vuln_list and isinstance(vuln_list, dict):
                    vulnerable_items = [v for v in vuln_list.values() if 'VULNERABLE' in str(v)]
                    if vulnerable_items:
                        css_class = severity_classes.get(severity, 'info')
                        section += f"""
                        <div class="vulnerability {css_class}">
                            <div class="vuln-title">Severidade: {severity.upper()} ({len(vulnerable_items)} vulnerabilidades)</div>
                            <div class="vuln-details">
                        """
                        
                        for vuln_name, vuln_data in vuln_list.items():
                            if 'VULNERABLE' in str(vuln_data):
                                section += f"<strong>{vuln_name}:</strong><br>"
                                vuln_str = str(vuln_data)[:500] + "..." if len(str(vuln_data)) > 500 else str(vuln_data)
                                section += f"<div class='code-block'>{html.escape(vuln_str)}</div><br>"
                                
                        section += "</div></div>"
                        
        section += "</div>"
        return section
        
    def _generate_recommendations_section(self):
        """Gera seção de recomendações"""
        return """
        <div class="section" id="recommendations">
            <h2>5. Recomendações</h2>
            <h3>Prioridade Alta</h3>
            <ul>
                <li>Aplicar patches de segurança para vulnerabilidades críticas identificadas</li>
                <li>Alterar credenciais padrão em todos os serviços</li>
                <li>Desabilitar serviços desnecessários</li>
                <li>Implementar segmentação de rede</li>
            </ul>
            
            <h3>Prioridade Média</h3>
            <ul>
                <li>Configurar SSL/TLS adequadamente</li>
                <li>Implementar políticas de senha robustas</li>
                <li>Configurar logging e monitoramento</li>
                <li>Realizar testes de penetração regulares</li>
            </ul>
            
            <h3>Prioridade Baixa</h3>
            <ul>
                <li>Ocultar banners de serviços</li>
                <li>Implementar rate limiting</li>
                <li>Configurar timeouts adequados</li>
                <li>Documentar configurações de segurança</li>
            </ul>
        </div>
        """
        
    def _generate_technical_details_section(self):
        """Gera seção de detalhes técnicos"""
        return """
        <div class="section" id="technical-details">
            <h2>6. Detalhes Técnicos</h2>
            <h3>Ferramentas Utilizadas</h3>
            <ul>
                <li>Nmap - Network discovery e port scanning</li>
                <li>NSE Scripts - Vulnerability detection</li>
                <li>Custom Python Scripts - Automation e reporting</li>
            </ul>
            
            <h3>Metodologia de Teste</h3>
            <p>Os testes foram conduzidos de forma não-destrutiva, focando na identificação de vulnerabilidades sem causar impacto nos sistemas testados.</p>
        </div>
        """
        
    def _dict_to_xml(self, data, parent):
        """Converte dicionário para XML recursivamente"""
        for key, value in data.items():
            if isinstance(value, dict):
                elem = ET.SubElement(parent, str(key))
                self._dict_to_xml(value, elem)
            elif isinstance(value, list):
                for item in value:
                    elem = ET.SubElement(parent, str(key))
                    if isinstance(item, dict):
                        self._dict_to_xml(item, elem)
                    else:
                        elem.text = str(item)
            else:
                elem = ET.SubElement(parent, str(key))
                elem.text = str(value)

