#!/usr/bin/env python3
"""
Módulo de Enumeração Avançada
Enumeração detalhada de serviços específicos para pentesting
"""

import subprocess
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import random

class AdvancedEnumeration:
    """
    Classe para enumeração avançada de serviços
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.enumeration_results = {}
        
        # Scripts NSE organizados por serviço
        self.service_scripts = {
            'http': [
                'http-enum', 'http-headers', 'http-methods', 'http-robots.txt',
                'http-title', 'http-server-header', 'http-sitemap-generator',
                'http-apache-negotiation', 'http-apache-server-status',
                'http-backup-finder', 'http-config-backup', 'http-cross-domain-policy',
                'http-default-accounts', 'http-frontpage-login', 'http-git',
                'http-iis-webdav-vuln', 'http-internal-ip-disclosure',
                'http-ls', 'http-method-tamper', 'http-open-proxy',
                'http-passwd', 'http-php-version', 'http-put', 'http-shellshock',
                'http-sql-injection', 'http-stored-xss', 'http-trace',
                'http-unsafe-output-escaping', 'http-userdir-enum',
                'http-vhosts', 'http-waf-detect', 'http-waf-fingerprint'
            ],
            'https': [
                'ssl-cert', 'ssl-cert-intaddr', 'ssl-date', 'ssl-enum-ciphers',
                'ssl-google-cert-catalog', 'ssl-heartbleed', 'ssl-known-key',
                'ssl-poodle', 'sslv2', 'ssl-ccs-injection', 'ssl-dh-params'
            ],
            'ssh': [
                'ssh-auth-methods', 'ssh-hostkey', 'ssh-publickey-acceptance',
                'ssh-run', 'ssh2-enum-algos', 'sshv1'
            ],
            'smb': [
                'smb-enum-domains', 'smb-enum-groups', 'smb-enum-processes',
                'smb-enum-sessions', 'smb-enum-shares', 'smb-enum-users',
                'smb-ls', 'smb-mbenum', 'smb-os-discovery', 'smb-print-text',
                'smb-protocols', 'smb-psexec', 'smb-security-mode',
                'smb-server-stats', 'smb-system-info', 'smb-vuln-conficker',
                'smb-vuln-cve2009-3103', 'smb-vuln-ms06-025', 'smb-vuln-ms07-029',
                'smb-vuln-ms08-067', 'smb-vuln-ms10-054', 'smb-vuln-ms10-061',
                'smb-vuln-ms17-010', 'smb-vuln-regsvc-dos'
            ],
            'ftp': [
                'ftp-anon', 'ftp-bounce', 'ftp-libopie', 'ftp-proftpd-backdoor',
                'ftp-vsftpd-backdoor', 'ftp-vuln-cve2010-4221'
            ],
            'dns': [
                'dns-blacklist', 'dns-brute', 'dns-cache-snoop', 'dns-check-zone',
                'dns-client-subnet-scan', 'dns-fuzz', 'dns-ip6-arpa-scan',
                'dns-nsec-enum', 'dns-nsec3-enum', 'dns-nsid', 'dns-random-srcport',
                'dns-random-txid', 'dns-recursion', 'dns-service-discovery',
                'dns-srv-enum', 'dns-update', 'dns-zeustracker', 'dns-zone-transfer'
            ],
            'snmp': [
                'snmp-brute', 'snmp-hh3c-logins', 'snmp-info', 'snmp-interfaces',
                'snmp-ios-config', 'snmp-netstat', 'snmp-processes', 'snmp-sysdescr',
                'snmp-win32-services', 'snmp-win32-shares', 'snmp-win32-software',
                'snmp-win32-users'
            ],
            'mysql': [
                'mysql-audit', 'mysql-brute', 'mysql-databases', 'mysql-dump-hashes',
                'mysql-empty-password', 'mysql-enum', 'mysql-info', 'mysql-query',
                'mysql-users', 'mysql-variables', 'mysql-vuln-cve2012-2122'
            ],
            'mssql': [
                'ms-sql-brute', 'ms-sql-config', 'ms-sql-dac', 'ms-sql-dump-hashes',
                'ms-sql-empty-password', 'ms-sql-hasdbaccess', 'ms-sql-info',
                'ms-sql-ntlm-info', 'ms-sql-query', 'ms-sql-tables', 'ms-sql-xp-cmdshell'
            ],
            'oracle': [
                'oracle-brute', 'oracle-brute-stealth', 'oracle-enum-users',
                'oracle-sid-brute', 'oracle-tns-version'
            ],
            'rdp': [
                'rdp-enum-encryption', 'rdp-vuln-ms12-020'
            ],
            'vnc': [
                'vnc-info', 'vnc-title'
            ],
            'telnet': [
                'telnet-brute', 'telnet-encryption', 'telnet-ntlm-info'
            ]
        }
        
        # Portas padrão para cada serviço
        self.service_ports = {
            'http': [80, 8080, 8000, 8008, 8888, 9000, 9090],
            'https': [443, 8443, 9443],
            'ssh': [22, 2222],
            'smb': [139, 445],
            'ftp': [21],
            'dns': [53],
            'snmp': [161, 162],
            'mysql': [3306],
            'mssql': [1433, 1434],
            'oracle': [1521, 1522, 1526],
            'rdp': [3389],
            'vnc': [5900, 5901, 5902],
            'telnet': [23]
        }
        
    def log(self, message):
        """Helper para logging"""
        if self.logger:
            self.logger.info(message)
        else:
            print(f"[INFO] {message}")
            
    def enumerate_all_services(self, target, timing='T4'):
        """Enumera todos os serviços detectados"""
        self.log(f"Iniciando enumeração completa de serviços para {target}")
        
        # Primeiro, descobrir quais serviços estão rodando
        open_ports = self._discover_services(target, timing)
        
        # Enumerar cada serviço encontrado
        for service, ports in open_ports.items():
            if service in self.service_scripts:
                self.log(f"Enumerando serviço {service} nas portas {ports}")
                result = self._enumerate_service(target, service, ports, timing)
                self.enumeration_results[f"{target}_{service}"] = result
                
        return self.enumeration_results
        
    def enumerate_http_services(self, target, ports=None, timing='T4'):
        """Enumeração específica e detalhada de serviços HTTP/HTTPS"""
        self.log(f"Iniciando enumeração HTTP detalhada para {target}")
        
        if not ports:
            ports = self.service_ports['http'] + self.service_ports['https']
            
        http_results = {}
        
        # Enumeração básica HTTP
        for port in ports:
            self.log(f"Enumerando HTTP na porta {port}")
            
            # Scripts básicos HTTP
            basic_scripts = [
                'http-enum', 'http-headers', 'http-methods', 'http-robots.txt',
                'http-title', 'http-server-header'
            ]
            
            for script in basic_scripts:
                command = f"nmap --script {script} -p {port} {target}"
                result = self._run_nmap_command(command, timing)
                if result:
                    http_results[f"port_{port}_{script}"] = result
                    
            # Enumeração de diretórios e arquivos
            directory_scripts = [
                'http-enum', 'http-backup-finder', 'http-config-backup',
                'http-git', 'http-ls', 'http-passwd'
            ]
            
            for script in directory_scripts:
                command = f"nmap --script {script} -p {port} {target}"
                result = self._run_nmap_command(command, timing)
                if result:
                    http_results[f"port_{port}_dir_{script}"] = result
                    
            # Detecção de vulnerabilidades HTTP
            vuln_scripts = [
                'http-sql-injection', 'http-stored-xss', 'http-shellshock',
                'http-put', 'http-trace', 'http-unsafe-output-escaping'
            ]
            
            for script in vuln_scripts:
                command = f"nmap --script {script} -p {port} {target}"
                result = self._run_nmap_command(command, timing)
                if result:
                    http_results[f"port_{port}_vuln_{script}"] = result
                    
            # Detecção de WAF
            waf_scripts = ['http-waf-detect', 'http-waf-fingerprint']
            for script in waf_scripts:
                command = f"nmap --script {script} -p {port} {target}"
                result = self._run_nmap_command(command, timing)
                if result:
                    http_results[f"port_{port}_waf_{script}"] = result
                    
        return http_results
        
    def enumerate_smb_services(self, target, timing='T4'):
        """Enumeração específica de serviços SMB"""
        self.log(f"Iniciando enumeração SMB para {target}")
        
        smb_results = {}
        
        # Enumeração básica SMB
        basic_scripts = [
            'smb-os-discovery', 'smb-protocols', 'smb-security-mode',
            'smb-enum-shares', 'smb-enum-users', 'smb-enum-groups'
        ]
        
        for script in basic_scripts:
            command = f"nmap --script {script} -p 139,445 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                smb_results[script] = result
                
        # Enumeração de vulnerabilidades SMB
        vuln_scripts = [
            'smb-vuln-ms17-010', 'smb-vuln-ms08-067', 'smb-vuln-ms06-025',
            'smb-vuln-ms07-029', 'smb-vuln-ms10-054', 'smb-vuln-ms10-061',
            'smb-vuln-conficker'
        ]
        
        for script in vuln_scripts:
            command = f"nmap --script {script} -p 139,445 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                smb_results[f"vuln_{script}"] = result
                
        # Enumeração detalhada de shares
        command = f"nmap --script smb-enum-shares,smb-ls --script-args smbuser=guest,smbpass= -p 139,445 {target}"
        result = self._run_nmap_command(command, timing)
        if result:
            smb_results['detailed_shares'] = result
            
        return smb_results
        
    def enumerate_ssh_services(self, target, timing='T4'):
        """Enumeração específica de serviços SSH"""
        self.log(f"Iniciando enumeração SSH para {target}")
        
        ssh_results = {}
        
        # Scripts SSH básicos
        ssh_scripts = [
            'ssh-hostkey', 'ssh-auth-methods', 'ssh2-enum-algos',
            'ssh-publickey-acceptance', 'sshv1'
        ]
        
        for script in ssh_scripts:
            command = f"nmap --script {script} -p 22,2222 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                ssh_results[script] = result
                
        return ssh_results
        
    def enumerate_dns_services(self, target, domain=None, timing='T4'):
        """Enumeração específica de serviços DNS"""
        self.log(f"Iniciando enumeração DNS para {target}")
        
        dns_results = {}
        
        # Scripts DNS básicos
        basic_scripts = [
            'dns-recursion', 'dns-service-discovery', 'dns-nsid'
        ]
        
        for script in basic_scripts:
            command = f"nmap --script {script} -p 53 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                dns_results[script] = result
                
        # Se um domínio foi fornecido, fazer enumeração específica
        if domain:
            domain_scripts = [
                'dns-zone-transfer', 'dns-brute', 'dns-srv-enum'
            ]
            
            for script in domain_scripts:
                if script == 'dns-zone-transfer':
                    command = f"nmap --script {script} --script-args dns-zone-transfer.domain={domain} -p 53 {target}"
                elif script == 'dns-brute':
                    command = f"nmap --script {script} --script-args dns-brute.domain={domain} {target}"
                else:
                    command = f"nmap --script {script} --script-args domain={domain} -p 53 {target}"
                    
                result = self._run_nmap_command(command, timing)
                if result:
                    dns_results[f"domain_{script}"] = result
                    
        return dns_results
        
    def enumerate_database_services(self, target, timing='T4'):
        """Enumeração de serviços de banco de dados"""
        self.log(f"Iniciando enumeração de bancos de dados para {target}")
        
        db_results = {}
        
        # MySQL
        mysql_scripts = [
            'mysql-info', 'mysql-databases', 'mysql-users', 'mysql-variables',
            'mysql-empty-password', 'mysql-vuln-cve2012-2122'
        ]
        
        for script in mysql_scripts:
            command = f"nmap --script {script} -p 3306 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                db_results[f"mysql_{script}"] = result
                
        # MSSQL
        mssql_scripts = [
            'ms-sql-info', 'ms-sql-config', 'ms-sql-empty-password',
            'ms-sql-hasdbaccess', 'ms-sql-tables'
        ]
        
        for script in mssql_scripts:
            command = f"nmap --script {script} -p 1433,1434 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                db_results[f"mssql_{script}"] = result
                
        # Oracle
        oracle_scripts = [
            'oracle-tns-version', 'oracle-sid-brute', 'oracle-enum-users'
        ]
        
        for script in oracle_scripts:
            command = f"nmap --script {script} -p 1521,1522 {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                db_results[f"oracle_{script}"] = result
                
        return db_results
        
    def enumerate_snmp_services(self, target, timing='T4'):
        """Enumeração específica de serviços SNMP"""
        self.log(f"Iniciando enumeração SNMP para {target}")
        
        snmp_results = {}
        
        # Community strings comuns para testar
        communities = ['public', 'private', 'community', 'manager', 'admin']
        
        for community in communities:
            self.log(f"Testando community string: {community}")
            
            snmp_scripts = [
                'snmp-info', 'snmp-sysdescr', 'snmp-interfaces',
                'snmp-processes', 'snmp-netstat'
            ]
            
            for script in snmp_scripts:
                command = f"nmap --script {script} --script-args snmpcommunity={community} -p 161 {target}"
                result = self._run_nmap_command(command, timing)
                if result and 'ERROR' not in result:
                    snmp_results[f"{community}_{script}"] = result
                    
        return snmp_results
        
    def custom_script_execution(self, target, custom_scripts, timing='T4'):
        """Executa scripts NSE customizados"""
        self.log(f"Executando scripts customizados para {target}")
        
        custom_results = {}
        
        for script_name, script_args in custom_scripts.items():
            if script_args:
                command = f"nmap --script {script_name} --script-args {script_args} {target}"
            else:
                command = f"nmap --script {script_name} {target}"
                
            result = self._run_nmap_command(command, timing)
            if result:
                custom_results[script_name] = result
                
        return custom_results
        
    def parallel_service_enumeration(self, targets, max_workers=5):
        """Enumeração paralela de serviços para múltiplos targets"""
        self.log(f"Iniciando enumeração paralela para {len(targets)} targets")
        
        all_results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.enumerate_all_services, target): target
                for target in targets
            }
            
            for future in future_to_target:
                target = future_to_target[future]
                try:
                    result = future.result(timeout=1800)  # 30 minutos por target
                    all_results[target] = result
                except Exception as e:
                    self.log(f"Erro na enumeração do target {target}: {str(e)}")
                    all_results[target] = {}
                    
        return all_results
        
    def _discover_services(self, target, timing):
        """Descobre quais serviços estão rodando"""
        command = f"nmap -sV --top-ports 1000 -{timing} {target}"
        result = self._run_nmap_command(command, timing)
        
        services = {}
        if result:
            lines = result.split('\n')
            for line in lines:
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        port_num = port_info.split('/')[0]
                        
                        if service not in services:
                            services[service] = []
                        services[service].append(port_num)
                        
        return services
        
    def _enumerate_service(self, target, service, ports, timing):
        """Enumera um serviço específico"""
        if service not in self.service_scripts:
            return None
            
        scripts = self.service_scripts[service]
        port_list = ','.join(ports)
        
        results = {}
        for script in scripts:
            command = f"nmap --script {script} -p {port_list} {target}"
            result = self._run_nmap_command(command, timing)
            if result:
                results[script] = result
                
        return results
        
    def _run_nmap_command(self, command, timing):
        """Executa comando nmap com tratamento de erros"""
        try:
            # Adicionar delay aleatório para evitar detecção
            delay = random.uniform(0.5, 2.0)
            time.sleep(delay)
            
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=900  # 15 minutos timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                self.log(f"Erro no comando: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.log("Timeout na execução do comando de enumeração")
            return None
        except Exception as e:
            self.log(f"Erro inesperado: {str(e)}")
            return None
            
    def generate_enumeration_report(self, output_file):
        """Gera relatório detalhado da enumeração"""
        self.log("Gerando relatório de enumeração...")
        
        with open(output_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("RELATÓRIO DE ENUMERAÇÃO DE SERVIÇOS\n")
            f.write("="*60 + "\n\n")
            
            for target_service, results in self.enumeration_results.items():
                f.write(f"TARGET/SERVIÇO: {target_service}\n")
                f.write("-" * 40 + "\n")
                
                if isinstance(results, dict):
                    for script, output in results.items():
                        f.write(f"\nScript: {script}\n")
                        f.write("~" * 20 + "\n")
                        f.write(output[:1000] + "...\n" if len(output) > 1000 else output + "\n")
                else:
                    f.write(str(results) + "\n")
                    
                f.write("\n" + "="*60 + "\n\n")
                
        self.log(f"Relatório de enumeração salvo em: {output_file}")

