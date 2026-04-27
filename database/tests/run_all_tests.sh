#!/bin/bash
# ============================================================================
# Runner principal des tests Module 2
# ============================================================================
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

C_GREEN='\033[0;32m'
C_RED='\033[0;31m'
C_BLUE='\033[0;34m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

clear
cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════╗
║                    TESTS AUTOMATISÉS                              ║
║                  SIEM Africa - Module 2                           ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER

if [ ! -f "$DB_PATH" ]; then
    echo "✗ BDD introuvable : $DB_PATH"
    exit 1
fi

TESTS=(
    "test_schema.sh"
    "test_signatures.sh"
    "test_relationships.sh"
    "test_performance.sh"
    "test_filters.sh"
)

PASSED=0
FAILED=0

for t in "${TESTS[@]}"; do
    echo ""
    echo -e "${C_BOLD}${C_BLUE}▶ Lancement : $t${C_RESET}"
    echo ""
    if bash "$TESTS_DIR/$t"; then
        PASSED=$((PASSED+1))
    else
        FAILED=$((FAILED+1))
    fi
done

echo ""
echo -e "${C_BOLD}${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}                     RÉSUMÉ GLOBAL${C_RESET}"
echo -e "${C_BOLD}${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo -e "  Tests passés : ${C_GREEN}$PASSED${C_RESET} / ${#TESTS[@]}"
echo -e "  Tests échoués: ${C_RED}$FAILED${C_RESET} / ${#TESTS[@]}"
echo ""

if [ "$FAILED" -eq "0" ]; then
    echo -e "  ${C_GREEN}${C_BOLD}🎉 Tous les tests sont passés !${C_RESET}"
    exit 0
else
    echo -e "  ${C_RED}${C_BOLD}❌ Des tests ont échoué.${C_RESET}"
    exit 1
fi
