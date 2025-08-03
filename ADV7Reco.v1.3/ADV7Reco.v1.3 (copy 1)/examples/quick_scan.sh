#!/bin/bash
# Exemplo de Scan Rápido - Advanced Penetration Testing Scanner
# Foca apenas em vulnerabilidades críticas
# Uso: ./quick_scan.sh <target>

# Verificar se target foi fornecido
if [ $# -eq 0 ]; then
    echo "Uso: $0 <target>"
    echo "Exemplo: $0 192.168.1.100"
    echo ""
    echo "Este script executa um scan rápido focado em vulnerabilidades críticas:"
    echo "- EternalBlue (MS17-010)"
    echo "- Heartbleed"
    echo "- Shellshock"
    echo "- E outras vulnerabilidades críticas"
    exit 1
fi

TARGET=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_PATH="$SCRIPT_DIR/../advanced_pentest_scanner.py"

echo "=================================================="
echo "ADVANCED PENETRATION TESTING SCANNER"
echo "Scan Rápido (Vulnerabilidades Críticas)"
echo "Target: $TARGET"
echo "=================================================="

# Verificar se o scanner existe
if [ ! -f "$SCANNER_PATH" ]; then
    echo "Erro: Scanner não encontrado em $SCANNER_PATH"
    exit 1
fi

# Criar diretório de resultados
RESULTS_DIR="quick_scan_$(date +%Y%m%d_%H%M%S)"

echo "Iniciando scan rápido..."
echo "Foco: Vulnerabilidades críticas"
echo "Timing: T5 (agressivo para velocidade)"
echo ""

# Executar scan rápido
python3 "$SCANNER_PATH" \
    --target "$TARGET" \
    --mode quick \
    --timing T5 \
    --output "$RESULTS_DIR"

# Verificar resultado
if [ $? -eq 0 ]; then
    echo ""
    echo "=================================================="
    echo "SCAN RÁPIDO CONCLUÍDO!"
    echo "=================================================="
    echo "Resultados em: $RESULTS_DIR"
    echo ""
    echo "Arquivo principal: $RESULTS_DIR/reports/quick_scan_report.json"
    echo ""
    
    # Tentar mostrar resumo se jq estiver disponível
    if command -v jq &> /dev/null; then
        echo "Resumo das vulnerabilidades encontradas:"
        echo "----------------------------------------"
        jq -r '.executive_summary.vulnerabilities_by_severity | to_entries[] | "\(.key): \(.value)"' \
            "$RESULTS_DIR/reports/quick_scan_report.json" 2>/dev/null || \
            echo "Dados de resumo não disponíveis"
    else
        echo "Instale 'jq' para ver resumo automático: sudo apt install jq"
    fi
    
    echo ""
    echo "Para análise detalhada, execute um scan completo:"
    echo "./advanced_scan.sh $TARGET"
else
    echo ""
    echo "Erro durante o scan rápido!"
    echo "Verifique os logs em: $RESULTS_DIR/logs/"
    exit 1
fi

