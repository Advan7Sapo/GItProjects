# Guia de Instalação - Advanced Penetration Testing Scanner v2.0

## Pré-requisitos

### Sistema Operacional
- **Recomendado**: Kali Linux 2023.x ou superior
- **Compatível**: Ubuntu 20.04+, Debian 11+, CentOS 8+, Fedora 35+
- **Arquitetura**: x86_64 (64-bit)

### Software Base
- Python 3.7 ou superior
- Nmap 7.80 ou superior
- Acesso root/sudo (para algumas funcionalidades)

## Instalação Passo a Passo

### 1. Preparação do Ambiente

#### No Kali Linux
```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Verificar se nmap está instalado (geralmente já vem no Kali)
nmap --version

# Verificar Python
python3 --version
```

#### No Ubuntu/Debian
```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependências
sudo apt install -y python3 python3-pip nmap git

# Verificar instalação
nmap --version
python3 --version
```

#### No CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum update -y
sudo yum install -y python3 python3-pip nmap git

# Fedora
sudo dnf update -y
sudo dnf install -y python3 python3-pip nmap git
```

### 2. Download dos Arquivos

#### Opção A: Download Manual
```bash
# Criar diretório do projeto
mkdir -p ~/tools/advanced_pentest_scanner
cd ~/tools/advanced_pentest_scanner

# Baixar arquivos (substitua pelos métodos de download apropriados)
# Os arquivos necessários são:
# - advanced_pentest_scanner.py
# - reconnaissance_module.py
# - enumeration_module.py
# - vulnerability_scanner.py
# - reporting_module.py
# - README.md
# - INSTALL.md
```

#### Opção B: Usando Git (se disponível em repositório)
```bash
# Clonar repositório
git clone <repository_url> ~/tools/advanced_pentest_scanner
cd ~/tools/advanced_pentest_scanner
```

### 3. Configuração de Permissões

```bash
# Navegar para o diretório
cd ~/tools/advanced_pentest_scanner

# Tornar scripts executáveis
chmod +x advanced_pentest_scanner.py
chmod +x *.py

# Verificar permissões
ls -la *.py
```

### 4. Teste de Instalação

```bash
# Testar sintaxe dos scripts
python3 -m py_compile *.py

# Testar help do script principal
python3 advanced_pentest_scanner.py --help

# Teste básico (sem execução real)
python3 advanced_pentest_scanner.py -t 127.0.0.1 --no-confirm --mode quick
```

### 5. Configuração de Ambiente (Opcional)

#### Criar Alias
```bash
# Adicionar ao ~/.bashrc ou ~/.zshrc
echo 'alias pentest="python3 ~/tools/advanced_pentest_scanner/advanced_pentest_scanner.py"' >> ~/.bashrc
source ~/.bashrc

# Agora você pode usar:
pentest -t target_ip
```

#### Adicionar ao PATH
```bash
# Criar link simbólico
sudo ln -s ~/tools/advanced_pentest_scanner/advanced_pentest_scanner.py /usr/local/bin/pentest-scanner

# Usar diretamente
pentest-scanner -t target_ip
```

## Verificação da Instalação

### Teste Completo
```bash
# Executar teste de sintaxe
python3 -c "
import sys
sys.path.append('.')
try:
    from reconnaissance_module import AdvancedReconnaissance
    from enumeration_module import AdvancedEnumeration
    from vulnerability_scanner import VulnerabilityScanner
    from reporting_module import AdvancedReporting
    print('✓ Todos os módulos importados com sucesso')
except ImportError as e:
    print(f'✗ Erro de importação: {e}')
"
```

### Teste de Funcionalidades
```bash
# Teste de help
python3 advanced_pentest_scanner.py --help

# Teste de validação de target
python3 advanced_pentest_scanner.py -t 127.0.0.1 --no-confirm --mode reconnaissance
```

## Instalação de Dependências Adicionais (Se Necessário)

### Bibliotecas Python Extras
```bash
# Se houver erros de importação, instalar bibliotecas extras
pip3 install requests beautifulsoup4 lxml

# Para funcionalidades futuras
pip3 install python-nmap scapy
```

### Ferramentas Complementares
```bash
# Ferramentas úteis para pentesting (opcional)
sudo apt install -y masscan nikto dirb gobuster hydra john

# No Kali Linux (já incluídas)
sudo apt install -y kali-tools-top10
```

## Configuração Avançada

### 1. Configuração de Sudoers (Para Scans Privilegiados)
```bash
# Editar sudoers para permitir nmap sem senha (CUIDADO!)
sudo visudo

# Adicionar linha (substitua 'username' pelo seu usuário):
username ALL=(ALL) NOPASSWD: /usr/bin/nmap

# Alternativa mais segura - usar apenas quando necessário:
sudo python3 advanced_pentest_scanner.py -t target
```

### 2. Configuração de Firewall
```bash
# Permitir tráfego de saída para scans
sudo ufw allow out 1:65535

# Ou configurar regras específicas conforme necessário
```

### 3. Otimização de Performance
```bash
# Aumentar limites de arquivo (para muitos hosts)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Configurar kernel para melhor performance de rede
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Estrutura de Diretórios Recomendada

```bash
# Criar estrutura organizada
mkdir -p ~/pentest/{tools,results,wordlists,scripts}
mv ~/tools/advanced_pentest_scanner ~/pentest/tools/

# Criar links úteis
ln -s ~/pentest/tools/advanced_pentest_scanner/advanced_pentest_scanner.py ~/pentest/scanner
```

## Solução de Problemas de Instalação

### Problema 1: Python não encontrado
```bash
# Verificar versão do Python
python3 --version

# Se não estiver instalado
sudo apt install python3 python3-pip

# Verificar se python3 está no PATH
which python3
```

### Problema 2: Nmap não encontrado
```bash
# Instalar nmap
sudo apt install nmap

# Verificar instalação
nmap --version
which nmap
```

### Problema 3: Permissões negadas
```bash
# Verificar permissões dos arquivos
ls -la *.py

# Corrigir permissões
chmod +x *.py
chmod 644 *.md

# Para scans que requerem root
sudo python3 advanced_pentest_scanner.py -t target
```

### Problema 4: Módulos não encontrados
```bash
# Verificar se todos os arquivos estão presentes
ls -la *.py

# Verificar se estão no mesmo diretório
pwd
ls -la

# Testar importação manual
python3 -c "import reconnaissance_module"
```

### Problema 5: Erro de sintaxe
```bash
# Verificar versão do Python (mínimo 3.7)
python3 --version

# Testar sintaxe de cada arquivo
python3 -m py_compile advanced_pentest_scanner.py
python3 -m py_compile reconnaissance_module.py
python3 -m py_compile enumeration_module.py
python3 -m py_compile vulnerability_scanner.py
python3 -m py_compile reporting_module.py
```

## Instalação em Ambientes Específicos

### Docker (Opcional)
```dockerfile
# Dockerfile para containerização
FROM kalilinux/kali-rolling

RUN apt update && apt install -y python3 python3-pip nmap

WORKDIR /app
COPY *.py ./
COPY *.md ./

RUN chmod +x *.py

ENTRYPOINT ["python3", "advanced_pentest_scanner.py"]
```

### Virtual Environment
```bash
# Criar ambiente virtual
python3 -m venv pentest_env
source pentest_env/bin/activate

# Instalar dependências no ambiente virtual
pip install requests beautifulsoup4

# Usar o scanner no ambiente virtual
python advanced_pentest_scanner.py -t target
```

## Verificação Final

### Checklist de Instalação
- [ ] Python 3.7+ instalado e funcionando
- [ ] Nmap 7.80+ instalado e funcionando
- [ ] Todos os arquivos .py presentes no diretório
- [ ] Permissões de execução configuradas
- [ ] Teste de sintaxe passou em todos os módulos
- [ ] Help do script principal funciona
- [ ] Teste básico executa sem erros

### Comando de Teste Final
```bash
# Teste completo da instalação
python3 advanced_pentest_scanner.py --help && \
echo "✓ Instalação concluída com sucesso!" || \
echo "✗ Problemas na instalação - verifique os logs"
```

## Próximos Passos

Após a instalação bem-sucedida:

1. **Leia a documentação**: Consulte o README.md para uso detalhado
2. **Teste em ambiente controlado**: Execute primeiro em targets de teste
3. **Configure autorização**: Sempre obtenha autorização antes de usar
4. **Pratique**: Familiarize-se com os diferentes modos e opções

## Suporte

Se encontrar problemas durante a instalação:

1. Verifique os logs de erro
2. Consulte a seção de solução de problemas
3. Teste em ambiente limpo (VM)
4. Verifique compatibilidade do sistema operacional

---

**Nota**: Esta ferramenta é destinada apenas para uso autorizado em testes de penetração. Certifique-se de ter todas as permissões necessárias antes de usar.

