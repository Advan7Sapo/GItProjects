# Advanced Penetration Testing Scanner v2.0

## Descrição

O Advanced Penetration Testing Scanner é uma ferramenta avançada de pentesting desenvolvida especificamente para profissionais de segurança cibernética. Esta ferramenta utiliza o nmap como base e adiciona funcionalidades avançadas de reconhecimento, enumeração, detecção de vulnerabilidades e geração de relatórios.

## ⚠️ AVISO LEGAL

**IMPORTANTE**: Esta ferramenta deve ser usada APENAS em ambientes autorizados para testes de penetração. O uso não autorizado pode violar leis locais e internacionais. O usuário é totalmente responsável por garantir que possui autorização adequada antes de usar esta ferramenta.

## Características Principais

### 🔍 Reconhecimento Avançado
- Descoberta stealth de hosts ativos
- Técnicas de evasão de firewall e IDS
- Varredura avançada de portas (TCP/UDP)
- Fingerprinting detalhado de sistemas operacionais
- Geração de IPs decoy para mascarar origem

### 🔎 Enumeração Detalhada
- Enumeração específica por serviço (HTTP, SSH, SMB, FTP, DNS, SNMP)
- Scripts NSE customizados organizados por categoria
- Detecção de versões e configurações
- Enumeração paralela para múltiplos targets

### 🛡️ Detecção de Vulnerabilidades
- Verificação de vulnerabilidades críticas (EternalBlue, Heartbleed, Shellshock)
- Teste de credenciais padrão
- Verificação de configurações inseguras
- Classificação por severidade (Crítica, Alta, Média, Baixa)
- Base de dados de CVEs conhecidos

### 📊 Relatórios Profissionais
- Relatórios em múltiplos formatos (HTML, JSON, XML, CSV)
- Resumo executivo com score de risco
- Gráficos e visualizações
- Recomendações de remediação
- Arquivamento automático de resultados

## Estrutura do Projeto

```
advanced_pentest_scanner/
├── advanced_pentest_scanner.py    # Script principal
├── reconnaissance_module.py       # Módulo de reconhecimento
├── enumeration_module.py         # Módulo de enumeração
├── vulnerability_scanner.py      # Scanner de vulnerabilidades
├── reporting_module.py           # Gerador de relatórios
├── README.md                     # Esta documentação
├── INSTALL.md                    # Guia de instalação
└── examples/                     # Exemplos de uso
    ├── basic_scan.sh
    ├── advanced_scan.sh
    └── quick_scan.sh
```

## Requisitos do Sistema

### Software Necessário
- Python 3.7 ou superior
- Nmap 7.80 ou superior
- Sistema operacional Linux (recomendado: Kali Linux)

### Dependências Python
```bash
# Bibliotecas padrão (já incluídas no Python)
- argparse
- json
- xml.etree.ElementTree
- subprocess
- logging
- threading
- pathlib
- datetime
- re
- time
- random
- hashlib
- base64
- zipfile

# Bibliotecas externas (instalar se necessário)
- requests (para funcionalidades futuras)
```

## Instalação

### 1. Clonar ou baixar os arquivos
```bash
# Criar diretório do projeto
mkdir advanced_pentest_scanner
cd advanced_pentest_scanner

# Copiar todos os arquivos .py para este diretório
```

### 2. Verificar dependências
```bash
# Verificar se o nmap está instalado
nmap --version

# Verificar Python
python3 --version

# Instalar nmap se necessário (Ubuntu/Debian)
sudo apt update
sudo apt install nmap

# Instalar nmap (CentOS/RHEL)
sudo yum install nmap
```

### 3. Tornar o script executável
```bash
chmod +x advanced_pentest_scanner.py
```

### 4. Teste de instalação
```bash
python3 advanced_pentest_scanner.py --help
```

## Uso Básico

### Sintaxe Geral
```bash
python3 advanced_pentest_scanner.py -t <target> [opções]
```

### Exemplos de Uso

#### Scan Completo (Recomendado)
```bash
# Scan completo de um host
python3 advanced_pentest_scanner.py -t 192.168.1.100

# Scan completo de uma rede
python3 advanced_pentest_scanner.py -t 192.168.1.0/24

# Scan completo de um domínio
python3 advanced_pentest_scanner.py -t example.com
```

#### Scan Rápido (Apenas Vulnerabilidades Críticas)
```bash
python3 advanced_pentest_scanner.py -t 192.168.1.100 --mode quick
```

#### Scan com Timing Personalizado
```bash
# Scan stealth (mais lento, menos detectável)
python3 advanced_pentest_scanner.py -t 192.168.1.100 --timing T1

# Scan agressivo (mais rápido, mais detectável)
python3 advanced_pentest_scanner.py -t 192.168.1.100 --timing T5
```

#### Modos Específicos
```bash
# Apenas reconhecimento
python3 advanced_pentest_scanner.py -t 192.168.1.100 --mode reconnaissance

# Apenas enumeração
python3 advanced_pentest_scanner.py -t 192.168.1.100 --mode enumeration

# Apenas vulnerabilidades
python3 advanced_pentest_scanner.py -t 192.168.1.100 --mode vulnerabilities
```

## Parâmetros de Linha de Comando

| Parâmetro | Descrição | Exemplo |
|-----------|-----------|---------|
| `-t, --target` | Target IP, hostname ou rede (obrigatório) | `-t 192.168.1.1` |
| `-o, --output` | Diretório base para saída | `-o my_scan_results` |
| `--timing` | Template de timing do nmap (T0-T5) | `--timing T3` |
| `--mode` | Modo de scan | `--mode complete` |
| `--no-confirm` | Pular confirmação de autorização | `--no-confirm` |

### Modos de Scan Disponíveis

- **complete**: Scan completo com todas as fases (padrão)
- **quick**: Scan rápido focado em vulnerabilidades críticas
- **reconnaissance**: Apenas fase de reconhecimento
- **enumeration**: Apenas fase de enumeração
- **vulnerabilities**: Apenas fase de vulnerabilidades

### Templates de Timing

- **T0 (Paranoid)**: Extremamente lento, máximo stealth
- **T1 (Sneaky)**: Lento, stealth
- **T2 (Polite)**: Moderado, menos agressivo
- **T3 (Normal)**: Velocidade normal
- **T4 (Aggressive)**: Rápido, mais agressivo (padrão)
- **T5 (Insane)**: Muito rápido, máxima agressividade

## Estrutura de Saída

Após a execução, o scanner cria uma estrutura organizada de diretórios:

```
pentest_results_YYYYMMDD_HHMMSS/
├── nmap_scans/           # Arquivos brutos do nmap
│   ├── host_discovery.*
│   ├── port_scan.*
│   ├── service_enum.*
│   └── vulnerability.*
├── reports/              # Relatórios gerados
│   ├── pentest_report.html
│   ├── pentest_report.json
│   ├── pentest_report.xml
│   ├── vulnerability_summary.csv
│   ├── reconnaissance_report.txt
│   ├── enumeration_report.txt
│   └── vulnerability_report.txt
├── logs/                 # Logs de execução
│   ├── pentest_main_*.log
│   └── pentest_errors_*.log
├── screenshots/          # Screenshots (se aplicável)
├── raw_data/            # Dados brutos adicionais
└── pentest_complete_results.zip  # Arquivo compactado
```

## Relatórios Gerados

### 1. Relatório HTML (Principal)
- Relatório visual completo com gráficos
- Resumo executivo com score de risco
- Detalhes técnicos organizados por seção
- Recomendações de remediação

### 2. Relatório JSON
- Dados estruturados para integração
- Metadados completos do scan
- Resultados detalhados por fase

### 3. Relatório XML
- Formato estruturado para parsing
- Compatível com outras ferramentas

### 4. Resumo CSV
- Lista de vulnerabilidades em formato tabular
- Ideal para análise em planilhas

## Funcionalidades Avançadas

### Técnicas de Evasão
- Fragmentação de pacotes
- Spoofing de endereço MAC
- Uso de IPs decoy
- Randomização de ordem de portas
- Source port spoofing

### Scripts NSE Incluídos
O scanner utiliza mais de 100 scripts NSE organizados por categoria:

- **Descoberta**: dns-brute, smb-enum-shares, snmp-sysdescr
- **Vulnerabilidades**: smb-vuln-ms17-010, ssl-heartbleed, http-shellshock
- **Enumeração**: http-enum, ssh-hostkey, ssl-enum-ciphers
- **Exploração**: smb-brute, ssh-brute, ftp-brute

### Detecção de Vulnerabilidades Críticas
- **EternalBlue (MS17-010)**: Vulnerabilidade crítica do SMB
- **Heartbleed (CVE-2014-0160)**: Vazamento de memória OpenSSL
- **Shellshock (CVE-2014-6271)**: Execução remota via bash
- **POODLE**: Vulnerabilidade SSL/TLS
- **E muitas outras...**

## Boas Práticas de Uso

### 1. Autorização
- **SEMPRE** obtenha autorização por escrito antes de usar
- Documente o escopo do teste
- Mantenha logs de todas as atividades

### 2. Timing e Stealth
- Use timing T1 ou T2 para ambientes sensíveis
- Use timing T4 ou T5 apenas em ambientes de teste
- Monitore logs do target durante o scan

### 3. Análise de Resultados
- Revise todos os relatórios gerados
- Priorize vulnerabilidades críticas
- Valide manualmente os resultados

### 4. Documentação
- Mantenha registros detalhados
- Archive resultados adequadamente
- Compartilhe apenas com pessoal autorizado

## Solução de Problemas

### Problemas Comuns

#### 1. Erro de Importação de Módulos
```bash
# Erro: ModuleNotFoundError
# Solução: Verificar se todos os arquivos .py estão no mesmo diretório
ls -la *.py
```

#### 2. Nmap Não Encontrado
```bash
# Erro: nmap command not found
# Solução: Instalar nmap
sudo apt install nmap
```

#### 3. Permissões Insuficientes
```bash
# Erro: Permission denied
# Solução: Executar com sudo para scans que requerem privilégios
sudo python3 advanced_pentest_scanner.py -t target
```

#### 4. Timeout em Scans
```bash
# Problema: Scans muito lentos
# Solução: Usar timing mais agressivo
python3 advanced_pentest_scanner.py -t target --timing T4
```

### Logs de Debug
Os logs detalhados estão disponíveis em:
- `logs/pentest_main_*.log` - Log principal
- `logs/pentest_errors_*.log` - Log de erros

## Limitações Conhecidas

1. **Dependência do Nmap**: Requer nmap instalado no sistema
2. **Recursos do Sistema**: Scans completos podem consumir muitos recursos
3. **Detecção**: Pode ser detectado por sistemas IDS/IPS
4. **Falsos Positivos**: Alguns resultados podem precisar validação manual

## Desenvolvimento e Contribuições

### Estrutura Modular
O scanner foi desenvolvido com arquitetura modular:

- `advanced_pentest_scanner.py`: Orquestrador principal
- `reconnaissance_module.py`: Lógica de reconhecimento
- `enumeration_module.py`: Lógica de enumeração
- `vulnerability_scanner.py`: Detecção de vulnerabilidades
- `reporting_module.py`: Geração de relatórios

### Extensibilidade
Para adicionar novas funcionalidades:

1. Crie novos métodos nos módulos existentes
2. Adicione novos scripts NSE às listas
3. Implemente novos formatos de relatório
4. Adicione novos modos de scan

## Changelog

### v2.0 (Atual)
- Arquitetura modular completa
- Relatórios HTML profissionais
- Técnicas avançadas de evasão
- Detecção de vulnerabilidades críticas
- Sistema de logging avançado

### v1.0 (Inicial)
- Funcionalidades básicas de scan
- Relatórios simples em texto
- Scripts NSE básicos

## Licença e Responsabilidade

Este software é fornecido "como está" sem garantias de qualquer tipo. O desenvolvedor não se responsabiliza por qualquer dano causado pelo uso inadequado desta ferramenta.

**USO RESPONSÁVEL**: Esta ferramenta foi desenvolvida para profissionais de segurança cibernética e deve ser usada apenas em ambientes autorizados para testes de penetração.

## Suporte

Para suporte técnico ou dúvidas:
1. Consulte esta documentação
2. Verifique os logs de erro
3. Teste em ambiente controlado primeiro

---

**Desenvolvido por**: Pentester Senior  
**Versão**: 2.0  
**Data**: 2025  
**Compatibilidade**: Linux (Kali Linux recomendado)

