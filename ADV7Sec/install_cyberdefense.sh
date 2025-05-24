#!/bin/bash
set -e

# Instala dependências do sistema para Kali Rolling e Python 3.13
sudo apt-get update
sudo apt-get install -y python3.13 python3.13-venv python3-pip clang linux-headers-$(uname -r) tcpdump build-essential libffi-dev libssl-dev

# Cria e ativa ambiente virtual Python 3.13
cd "$(dirname "$0")"
if [ ! -d ".env" ]; then
  python3.13 -m venv .env
fi
source .env/bin/activate

# Instala dependências Python no venv (com upgrade forçado e wheel para compatibilidade)
pip install --upgrade pip wheel
pip install --upgrade flask scapy numpy requests cryptography torch

# Segurança: Corrige permissões do venv
find .env -type d -exec chmod 700 {} +
find .env -type f -exec chmod 600 {} +

# Segurança: Remove cache pip
pip cache purge || true

deactivate

# Cria arquivo de log, se necessário
sudo touch /var/log/cyberdefense.log
sudo chown root:root /var/log/cyberdefense.log
sudo chmod 600 /var/log/cyberdefense.log

# Instala o serviço systemd com verificação
if [ -f cyberdefense.service ]; then
  sudo cp cyberdefense.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable cyberdefense.service
else
  echo "Arquivo cyberdefense.service não encontrado!" >&2
fi

# Instruções finais
cat <<EOF

Instalação concluída!
Use 'sudo systemctl start cyberdefense.service' para iniciar o serviço.
Verifique logs com: 'journalctl -u cyberdefense -f'
EOF
