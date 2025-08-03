#!/bin/bash
# Exemplo de Scan Básico - Advanced Penetration Testing Scanner
# Uso: ./basic_scan.sh <target>

# Verificar se target foi fornecido
if [ $# -eq 0 ]; then
    echo "Uso: $0 <target>"
    echo "Exemplo: $0 192.168.1.100"
    exit 1
fi

TARGET=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_PATH="$SCRIPT_DIR/../advanced_pentest_scanner.py"

echo "=================================================="
echo "ADVANCED PENETRATION TESTING SCANNER"
echo "Scan Básico para: $TARGET"
echo "=================================================="

# Verificar se o scanner existe
if [ ! -f "$SCANNER_PATH" ]; then
    echo "Erro: Scanner não encontrado em $SCANNER_PATH"
    exit 1
fi

# Executar scan básico
echo "Iniciando scan básico..."
python3 "$SCANNER_PATH" \
    --target "$TARGET" \
    --mode complete \
    --timing T4 \
    --output "basic_scan_$(date +%Y%m%d_%H%M%S)"

echo "Scan básico concluído!"
echo "Verifique os resultados no diretório de saída."

