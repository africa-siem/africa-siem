#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Module 3 — Tests automatisés
# ============================================================================
# Lance les 5 tests dans l'ordre et fait un résumé final.
# À lancer après ./install_agent.sh + ./verify.sh
# ============================================================================

LC_ALL=C
LANG=C

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_CYAN='\033[0;36m'
C_RESET='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être lancé en root. Utilisez : sudo bash $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TESTS=(
    "test_db_access.sh:Accès BDD (lecture/écriture)"
    "test_signature_lookup.sh:Lookup signature par rule_id"
    "test_filters.sh:Mécanismes faux positifs (5 types)"
    "test_email.sh:Envoi SMTP test"
    "test_systemd.sh:Service systemd actif et capabilities"
)

PASSED=0
FAILED=0
TOTAL=${#TESTS[@]}

clear || true
echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}              SIEM AFRICA — Module 3 — Tests automatisés              ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""

I=0
for entry in "${TESTS[@]}"; do
    I=$((I+1))
    test_file="${entry%%:*}"
    test_label="${entry#*:}"

    echo -e "${C_CYAN}[${I}/${TOTAL}]${C_RESET} ${test_label}..."

    if [ ! -f "${SCRIPT_DIR}/${test_file}" ]; then
        echo -e "  ${C_RED}✗ Test introuvable : ${test_file}${C_RESET}"
        FAILED=$((FAILED+1))
        continue
    fi

    if bash "${SCRIPT_DIR}/${test_file}"; then
        echo -e "  ${C_GREEN}✓ ${test_label}${C_RESET}"
        PASSED=$((PASSED+1))
    else
        echo -e "  ${C_RED}✗ ${test_label}${C_RESET}"
        FAILED=$((FAILED+1))
    fi
    echo ""
done

# Résumé
echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}                          RÉSULTAT FINAL${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"

if [ $FAILED -eq 0 ]; then
    echo -e "  ${C_GREEN}${PASSED}/${TOTAL} TESTS RÉUSSIS${C_RESET}"
    echo ""
    echo -e "${C_GREEN}✓ Module 3 entièrement fonctionnel${C_RESET}"
    exit 0
else
    echo -e "  ${C_GREEN}Réussis : ${PASSED}${C_RESET}"
    echo -e "  ${C_RED}Échoués : ${FAILED}${C_RESET}"
    echo ""
    echo -e "${C_RED}⚠ Certains tests ont échoué${C_RESET}"
    echo "  Logs : sudo journalctl -u siem-agent -n 100"
    exit 1
fi
