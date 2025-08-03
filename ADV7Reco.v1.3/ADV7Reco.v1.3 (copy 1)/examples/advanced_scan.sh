#!/bin/bash
# Exemplo de Scan Avançado - Advanced Penetration Testing Scanner
# Uso: ./advanced_scan.sh <target> [timing]

# Verificar argumentos
if [ $# -eq 0 ]; then
    echo "Uso: $0 <target> [timing]"
    echo "Exemplo: $0 192.168.1.0/24 T3"
    echo "Timing: T0 (stealth) até T5 (agressivo)"
    exit 1
fi

TARGET=$1
TIMING=${2:-T3}  # Default T3 se não especificado
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_PATH="$SCRIPT_DIR/../advanced_pentest_scanner.py"

echo "=================================================="
echo "ADVANCED PENETRATION TESTING SCANNER"
echo "Scan Avançado para: $TARGET"
echo "Timing: $TIMING"
echo "=================================================="

# Verificar se o scanner existe
if [ ! -f "$SCANNER_PATH" ]; then
    echo "Erro: Scanner não encontrado em $SCANNER_PATH"
    exit 1
fi

# Criar diretório de resultados com timestamp
RESULTS_DIR="advanced_scan_$(date +%Y%m%d_%H%M%S)"

echo "Iniciando scan avançado..."
echo "Target: $TARGET"
echo "Timing: $TIMING"
echo "Resultados serão salvos em: $RESULTS_DIR"
echo ""

# Executar scan avançado com todas as fases
python3 "$SCANNER_PATH" \
    --target "$TARGET" \
    --mode complete \
    --timing "$TIMING" \
    --output "$RESULTS_DIR"

# Verificar se o scan foi bem-sucedido
if [ $? -eq 0 ]; then
    echo ""
    echo "=================================================="
    echo "SCAN AVANÇADO CONCLUÍDO COM SUCESSO!"
    echo "=================================================="
    echo "Resultados disponíveis em: $RESULTS_DIR"
    echo ""
    echo "Principais arquivos gerados:"
    echo "- Relatório HTML: $RESULTS_DIR/reports/pentest_report.html"
    echo "- Dados JSON: $RESULTS_DIR/reports/pentest_report.json"
    echo "- Arquivo ZIP: $RESULTS_DIR/pentest_complete_results.zip"
    echo ""
    echo "Para visualizar o relatório HTML:"
    echo "firefox $RESULTS_DIR/reports/pentest_report.html"
else
    echo ""
    echo "=================================================="
    echo "ERRO DURANTE O SCAN!"
    echo "=================================================="
    echo "Verifique os logs em: $RESULTS_DIR/logs/"
    exit 1
fi

