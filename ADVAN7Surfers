#!/bin/bash
#----------------------------------------------------------------------------
# Project	: Advan7BasicTool
#----------------------------------------------------------------------------
# Date		: 25/03/2025
#----------------------------------------------------------------------------
# WheremI	: /home/sapo
#----------------------------------------------------------------------------
# CreatedBy	: ADVAN7Sapo | https://github.com/Advan7Sapo
#----------------------------------------------------------------------------
clear 
sudo apt update -y
sudo apt upgrade -y
sudo apt install anonsurf -y
sudo apt install tor -y
sudo apt install macchanger -y

# MAC Spoofing
# Verifica root
if [ "$EUID" -ne 0 ]; then
    echo "Execute como root: sudo $0"
    exit 1
fi

# Detecta a interface ativa
detect_interface() {
    interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | while read -r int; do
        if ip -4 addr show "$int" 2>/dev/null | grep -q "inet"; then
            echo "$int"
            break
        fi
    done)
    
    if [ -z "$interface" ]; then
        echo "Nenhuma interface ativa encontrada!"
        exit 1
    fi
    echo "$interface"
}

# Configurações principais
INTERFACE=$(detect_interface)
COMMAND="macchanger -r"  # Modo padrão: MAC randômico

# Menu de ajuda
show_help() {
    echo "Uso: $0 [opções]"
    echo "Opções:"
    echo "  -r          MAC aleatório (padrão)"
    echo "  -s [MAC]    Usar MAC específico"
    echo "  -p          Resetar para MAC permanente original"
    exit 0
}

# Processa argumentos
while getopts "rs:ph" opt; do
    case $opt in
        r) COMMAND="macchanger -r";;
        s) COMMAND="macchanger -m $OPTARG";;
        p) COMMAND="macchanger -p";;
        h) show_help;;
        *) echo "Opção inválida"; exit 1;;
    esac
done

# Executa a mudança de MAC
echo "=== Interface detectada: $INTERFACE ==="
echo "MAC original:"
macchanger -s "$INTERFACE"

echo -e "\nAlterando MAC..."
{
    ip link set dev "$INTERFACE" down
    $COMMAND "$INTERFACE"
    ip link set dev "$INTERFACE" up
} > /dev/null 2>&1

echo -e "\nNovo MAC:"
macchanger -s "$INTERFACE"

# Configuração de segurança: Restringe permissões de arquivos
umask 077

# Caminho do log
LOG_FILE="/var/log/anonsurf_auto.log"
MAX_LOG_SIZE=$((10*1024*1024)) # 10MB

# Sistema de lock usando flock para evitar múltiplas instâncias
LOCK_FILE="/tmp/anonsurf_auto.lock"

# Verificação de dependências críticas
check_dependencies() {
    local missing=()
    command -v anonsurf &> /dev/null || missing+=("anonsurf")
    command -v shred &> /dev/null || missing+=("shred")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Erro: Dependências ausentes: ${missing[*]}" >&2
        exit 1
    fi
}

# Verifica se o script está sendo executado como root
if [[ $EUID -ne 0 ]]; then
    echo "Este script deve ser executado como root!" >&2
    exit 1
fi

# Verifica dependências antes de iniciar
check_dependencies

# Configuração do lock para instância única
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "O script já está em execução. Saindo." >&2
    exit 1
fi

# Função para gestão segura de logs
rotate_log() {
    if [[ -f "$LOG_FILE" && $(stat -c %s "$LOG_FILE") -ge $MAX_LOG_SIZE ]]; then
        local timestamp=$(date +%Y%m%d%H%M%S)
        local old_log="${LOG_FILE}.${timestamp}.gz"
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Rotacionando arquivo de log" >> "$LOG_FILE"
        gzip -c "$LOG_FILE" > "$old_log" && shred -u "$LOG_FILE" 2>/dev/null
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
}

# Função para limpeza segura
cleanup() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Script finalizado." | tee -a "$LOG_FILE"
    shred -u "$LOCK_FILE" 2>/dev/null
    exit 0
}

# Registra sinais de interrupção
trap cleanup SIGINT SIGTERM SIGHUP

# Loop principal de operação
while true; do
    rotate_log
    
    # Gera intervalo aleatório criptograficamente seguro
    INTERVAL=$(( 3 + $(od -An -N2 -i /dev/urandom | tr -d ' ') % 28 ))
    
    # Registro de atividades
    MESSAGE="$(date '+%Y-%m-%d %H:%M:%S') - Iniciando troca de identidade. Próxima troca em $INTERVAL segundos."
    echo "$MESSAGE" | tee -a "$LOG_FILE"
    
    # Executa a mudança de identidade com tratamento de erros
    if ! anonsurf changeid &>> "$LOG_FILE"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERRO: Falha na troca de identidade. Verifique o sistema." | tee -a "$LOG_FILE"
        sleep 10  # Espera antes de tentar novamente
        continue
    fi
    
    # Aguarda intervalo com checagem ativa
    while (( INTERVAL > 0 )); do
        sleep 1
        ((INTERVAL--))
    done
done