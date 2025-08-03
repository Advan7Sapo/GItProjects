#!/usr/bin/env python3
"""
Módulo Avançado de Reconhecimento
Técnicas stealth e evasivas para descoberta de hosts e serviços
"""

import subprocess
import random
import time
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
import ipaddress

class AdvancedReconnaissance:
    """
    Classe para técnicas avançadas de reconhecimento
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.discovered_hosts = []
        self.open_ports = {}
        self.timing_delays = {
            'T0': (5, 10),    # Paranoid
            'T1': (3, 5),     # Sneaky  
            'T2': (1, 3),     # Polite
            'T3': (0.5, 1),   # Normal
            'T4': (0.1, 0.5), # Aggressive
            'T5': (0, 0.1)    # Insane
        }
        
    def log(self, message):
        """Helper para logging"""
        if self.logger:
            self.logger.info(message)
        else:
            print(f"[INFO] {message}")
            
    def generate_decoy_ips(self, target_network, count=5):
        """Gera IPs decoy para mascarar origem do scan"""
        try:
            network = ipaddress.ip_network(target_network, strict=False)
            decoys = []
            
            for _ in range(count):
                # Gera IP aleatório na mesma rede
                random_ip = network.network_address + random.randint(1, network.num_addresses - 2)
                decoys.append(str(random_ip))
                
            return decoys
        except:
            # Fallback para IPs aleatórios
            return [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(count)]
            
    def stealth_host_discovery(self, target, timing='T4'):
        """Descoberta stealth de hosts usando múltiplas técnicas"""
        self.log("Iniciando descoberta stealth de hosts...")
        
        discovered = []
        
        # Técnica 1: TCP SYN Ping em portas comuns
        common_ports = [22, 23, 25, 53, 80, 110, 443, 993, 995, 1723, 3389, 5900]
        for port in common_ports:
            command = f"nmap -PS{port} -sn --disable-arp-ping {target}"
            result = self._run_nmap_stealth(command, timing)
            if result:
                hosts = self._extract_hosts_from_output(result)
                discovered.extend(hosts)
                
        # Técnica 2: TCP ACK Ping
        command = f"nmap -PA80,443 -sn --disable-arp-ping {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            hosts = self._extract_hosts_from_output(result)
            discovered.extend(hosts)
            
        # Técnica 3: UDP Ping
        command = f"nmap -PU53,67,68,123,135,137,161,500,514,520,631,1434 -sn {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            hosts = self._extract_hosts_from_output(result)
            discovered.extend(hosts)
            
        # Técnica 4: ICMP Ping com diferentes tipos
        icmp_types = [8, 13, 15, 17]  # Echo, Timestamp, Info Request, Address Mask
        for icmp_type in icmp_types:
            command = f"nmap -PE -sn --icmp-type {icmp_type} {target}"
            result = self._run_nmap_stealth(command, timing)
            if result:
                hosts = self._extract_hosts_from_output(result)
                discovered.extend(hosts)
                
        # Remove duplicatas e retorna
        unique_hosts = list(set(discovered))
        self.discovered_hosts = unique_hosts
        self.log(f"Descobertos {len(unique_hosts)} hosts ativos")
        
        return unique_hosts
        
    def firewall_evasion_scan(self, target, timing='T4'):
        """Técnicas de evasão de firewall"""
        self.log("Iniciando scan com evasão de firewall...")
        
        # Gerar IPs decoy
        decoys = self.generate_decoy_ips(target)
        decoy_string = ','.join(decoys)
        
        evasion_techniques = [
            # Fragmentação de pacotes
            f"nmap -f -sS {target}",
            f"nmap -ff -sS {target}",
            
            # MTU customizado
            f"nmap --mtu 16 -sS {target}",
            f"nmap --mtu 24 -sS {target}",
            
            # Decoy scan
            f"nmap -D {decoy_string} -sS {target}",
            
            # Source port spoofing
            f"nmap --source-port 53 -sS {target}",
            f"nmap --source-port 80 -sS {target}",
            f"nmap --source-port 443 -sS {target}",
            
            # Idle scan (se possível)
            f"nmap -sI {decoys[0]} {target}",
            
            # TCP Window scan
            f"nmap -sW {target}",
            
            # TCP Maimon scan
            f"nmap -sM {target}",
            
            # Scan com dados customizados
            f"nmap --data-length 25 -sS {target}",
            
            # Randomização de ordem das portas
            f"nmap --randomize-hosts -sS {target}",
            
            # Spoof MAC address
            f"nmap --spoof-mac 0 -sS {target}"
        ]
        
        results = []
        for technique in evasion_techniques:
            self.log(f"Testando: {technique}")
            result = self._run_nmap_stealth(technique, timing)
            if result:
                results.append(result)
                
        return results
        
    def advanced_port_discovery(self, target, timing='T4'):
        """Descoberta avançada de portas usando múltiplas técnicas"""
        self.log("Iniciando descoberta avançada de portas...")
        
        port_results = {}
        
        # Técnica 1: TCP Connect Scan (menos stealth, mais confiável)
        command = f"nmap -sT --top-ports 1000 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['tcp_connect'] = ports
            
        # Técnica 2: TCP SYN Scan (stealth)
        command = f"nmap -sS --top-ports 1000 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['tcp_syn'] = ports
            
        # Técnica 3: TCP FIN Scan (evasivo)
        command = f"nmap -sF --top-ports 1000 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['tcp_fin'] = ports
            
        # Técnica 4: TCP NULL Scan
        command = f"nmap -sN --top-ports 1000 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['tcp_null'] = ports
            
        # Técnica 5: TCP Xmas Scan
        command = f"nmap -sX --top-ports 1000 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['tcp_xmas'] = ports
            
        # Técnica 6: UDP Scan em portas críticas
        udp_ports = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,5353"
        command = f"nmap -sU -p {udp_ports} {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['udp'] = ports
            
        # Técnica 7: SCTP INIT Scan
        command = f"nmap -sY --top-ports 100 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            ports = self._extract_ports_from_output(result)
            port_results['sctp'] = ports
            
        self.open_ports[target] = port_results
        return port_results
        
    def os_fingerprinting_advanced(self, target, timing='T4'):
        """Fingerprinting avançado de sistema operacional"""
        self.log("Iniciando fingerprinting avançado de OS...")
        
        fingerprint_results = {}
        
        # Técnica 1: OS Detection padrão
        command = f"nmap -O {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            fingerprint_results['standard'] = result
            
        # Técnica 2: OS Detection agressivo
        command = f"nmap -O --osscan-guess --osscan-limit {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            fingerprint_results['aggressive'] = result
            
        # Técnica 3: TCP/IP Stack fingerprinting
        command = f"nmap -sS -O --script smb-os-discovery {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            fingerprint_results['smb_discovery'] = result
            
        # Técnica 4: HTTP Server fingerprinting
        command = f"nmap --script http-server-header,http-title -p 80,443,8080,8443 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            fingerprint_results['http_fingerprint'] = result
            
        # Técnica 5: SSH fingerprinting
        command = f"nmap --script ssh-hostkey,ssh2-enum-algos -p 22 {target}"
        result = self._run_nmap_stealth(command, timing)
        if result:
            fingerprint_results['ssh_fingerprint'] = result
            
        return fingerprint_results
        
    def dns_reconnaissance(self, domain):
        """Reconhecimento DNS avançado"""
        self.log(f"Iniciando reconhecimento DNS para {domain}...")
        
        dns_results = {}
        
        # DNS Zone Transfer
        command = f"nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain={domain} -p 53"
        result = self._run_nmap_stealth(command, 'T4')
        if result:
            dns_results['zone_transfer'] = result
            
        # DNS Brute Force
        command = f"nmap --script dns-brute --script-args dns-brute.domain={domain}"
        result = self._run_nmap_stealth(command, 'T4')
        if result:
            dns_results['brute_force'] = result
            
        # DNS Cache Snooping
        command = f"nmap --script dns-cache-snoop --script-args dns-cache-snoop.mode=timed -p 53"
        result = self._run_nmap_stealth(command, 'T4')
        if result:
            dns_results['cache_snoop'] = result
            
        return dns_results
        
    def _run_nmap_stealth(self, command, timing):
        """Executa comando nmap com delays para stealth"""
        try:
            # Adicionar delay baseado no timing
            if timing in self.timing_delays:
                min_delay, max_delay = self.timing_delays[timing]
                delay = random.uniform(min_delay, max_delay)
                time.sleep(delay)
                
            # Adicionar flags de stealth
            if '-T' not in command:
                command += f" -{timing}"
                
            # Executar comando
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutos timeout
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                self.log(f"Erro no comando: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.log("Timeout na execução do comando stealth")
            return None
        except Exception as e:
            self.log(f"Erro inesperado: {str(e)}")
            return None
            
    def _extract_hosts_from_output(self, nmap_output):
        """Extrai lista de hosts do output do nmap"""
        hosts = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if 'Nmap scan report for' in line:
                # Extrair IP ou hostname
                parts = line.split()
                if len(parts) >= 5:
                    host = parts[4]
                    if '(' in host and ')' in host:
                        # Formato: hostname (ip)
                        host = host.split('(')[1].split(')')[0]
                    hosts.append(host)
                    
        return hosts
        
    def _extract_ports_from_output(self, nmap_output):
        """Extrai portas abertas do output do nmap"""
        ports = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 2 and ('open' in parts[1] or 'filtered' in parts[1]):
                    port_info = parts[0]
                    ports.append(port_info)
                    
        return ports
        
    def parallel_host_discovery(self, target_list, max_workers=10):
        """Descoberta paralela de hosts para múltiplos targets"""
        self.log(f"Iniciando descoberta paralela para {len(target_list)} targets...")
        
        all_results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.stealth_host_discovery, target): target 
                for target in target_list
            }
            
            for future in future_to_target:
                target = future_to_target[future]
                try:
                    result = future.result(timeout=600)  # 10 minutos por target
                    all_results[target] = result
                except Exception as e:
                    self.log(f"Erro no target {target}: {str(e)}")
                    all_results[target] = []
                    
        return all_results
        
    def generate_reconnaissance_report(self, output_file):
        """Gera relatório detalhado do reconhecimento"""
        self.log("Gerando relatório de reconhecimento...")
        
        with open(output_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("RELATÓRIO DE RECONHECIMENTO AVANÇADO\n")
            f.write("="*60 + "\n\n")
            
            f.write("HOSTS DESCOBERTOS:\n")
            f.write("-" * 20 + "\n")
            for i, host in enumerate(self.discovered_hosts, 1):
                f.write(f"{i}. {host}\n")
            f.write(f"\nTotal: {len(self.discovered_hosts)} hosts\n\n")
            
            f.write("PORTAS ABERTAS POR HOST:\n")
            f.write("-" * 25 + "\n")
            for host, port_data in self.open_ports.items():
                f.write(f"\nHost: {host}\n")
                for scan_type, ports in port_data.items():
                    f.write(f"  {scan_type}: {', '.join(ports) if ports else 'Nenhuma'}\n")
                    
        self.log(f"Relatório salvo em: {output_file}")

