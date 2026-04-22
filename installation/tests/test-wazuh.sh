#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1 / Tests
# tests/test-wazuh.sh — Tests de validation de Wazuh Manager
# ============================================================================
#
# Ce script vérifie que Wazuh fonctionne correctement :
#   1. Le paquet wazuh-manager est installé
#   2. Le dossier /var/ossec existe
#   3. Le fichier ossec.conf est valide
#   4. Le service wazuh-manager est actif
#   5. L'API Wazuh répond
#   6. Les ports d'écoute sont ouverts
#   7. Mode FULL : Indexer et Dashboard actifs
#
# Usage :
#   sudo ./tests/test-wazuh.sh
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"

# --- Compteurs ------------------------------------------------------------
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name=$1
    local test_command=$2
    local expected_code=${3:-0}

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    echo -n "  ${test_name}... "

    eval "$test_command" >/dev/null 2>&1
    local actual_code=$?

    if [ "$actual_code" -eq "$expected_code" ]; then
        echo -e "${COLOR_GREEN}✓${COLOR_RESET}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${COLOR_RED}✗${COLOR_RESET}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# --- Détection du mode (lite ou full) -------------------------------------
detect_mode() {
    if dpkg -l 2>/dev/null | grep -qE "^ii\s+wazuh-dashboard"; then
        echo "full"
    else
        echo "lite"
    fi
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ Ce script nécessite les droits root"
        exit 1
    fi

    log_init

    log_banner "TESTS DE VALIDATION WAZUH"

    local mode
    mode=$(detect_mode)
    echo ""
    echo "  Mode détecté : ${mode^^}"

    # --- TEST 1 : Paquets installés --------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[1] Installation des paquets${COLOR_RESET}"
    run_test "Paquet wazuh-manager installé" \
        "dpkg -l | grep -qE '^ii\s+wazuh-manager'"

    if [ "$mode" = "full" ]; then
        run_test "Paquet wazuh-indexer installé" \
            "dpkg -l | grep -qE '^ii\s+wazuh-indexer'"

        run_test "Paquet wazuh-dashboard installé" \
            "dpkg -l | grep -qE '^ii\s+wazuh-dashboard'"
    fi

    # --- TEST 2 : Dossiers Wazuh -----------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[2] Structure de fichiers${COLOR_RESET}"
    run_test "Dossier /var/ossec existe" \
        "[ -d /var/ossec ]"

    run_test "Fichier /var/ossec/etc/ossec.conf existe" \
        "[ -f /var/ossec/etc/ossec.conf ]"

    run_test "Dossier /var/ossec/logs/alerts existe" \
        "[ -d /var/ossec/logs/alerts ]"

    # --- TEST 3 : Config valide ------------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[3] Configuration${COLOR_RESET}"

    # Test XML basique de ossec.conf
    run_test "ossec.conf est un XML valide" \
        "xmllint --noout /var/ossec/etc/ossec.conf 2>/dev/null || python3 -c 'import xml.etree.ElementTree as ET; ET.parse(\"/var/ossec/etc/ossec.conf\")'"

    # Intégration Snort présente
    run_test "Intégration Snort configurée dans ossec.conf" \
        "grep -q 'snort-fast' /var/ossec/etc/ossec.conf"

    # --- TEST 4 : Services -----------------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[4] Services Wazuh${COLOR_RESET}"
    run_test "Service wazuh-manager existe" \
        "systemctl list-unit-files | grep -q 'wazuh-manager.service'"

    run_test "Service wazuh-manager actif" \
        "systemctl is-active --quiet wazuh-manager.service"

    run_test "Service wazuh-manager activé au boot" \
        "systemctl is-enabled --quiet wazuh-manager.service"

    if [ "$mode" = "full" ]; then
        run_test "Service wazuh-indexer actif" \
            "systemctl is-active --quiet wazuh-indexer.service"

        run_test "Service wazuh-dashboard actif" \
            "systemctl is-active --quiet wazuh-dashboard.service"
    fi

    # --- TEST 5 : Ports réseau -------------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[5] Ports réseau${COLOR_RESET}"

    run_test "Port 1514 (agents Wazuh) en écoute" \
        "ss -tuln | grep -q ':1514 '"

    run_test "Port 1515 (enrôlement) en écoute" \
        "ss -tuln | grep -q ':1515 '"

    run_test "Port 55000 (API Wazuh) en écoute" \
        "ss -tuln | grep -q ':55000 '"

    if [ "$mode" = "full" ]; then
        run_test "Port 9200 (Indexer) en écoute" \
            "ss -tuln | grep -q ':9200 '"

        run_test "Port 443 (Dashboard) en écoute" \
            "ss -tuln | grep -q ':443 '"
    fi

    # --- TEST 6 : Processus Wazuh ----------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[6] Processus${COLOR_RESET}"

    # Wazuh Manager démarre plusieurs processus : ossec-*, wazuh-*
    local wazuh_processes
    wazuh_processes=$(pgrep -f "wazuh-\|ossec-" | wc -l)
    echo "  Processus Wazuh en cours : ${wazuh_processes}"

    if [ "$wazuh_processes" -gt 0 ]; then
        echo -e "  ${COLOR_GREEN}✓ Wazuh tourne${COLOR_RESET}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${COLOR_RED}✗ Aucun processus Wazuh${COLOR_RESET}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    # --- TEST 7 : User wazuh dans le groupe siem-africa -----------------
    echo ""
    echo -e "${COLOR_BOLD}[7] Intégration SIEM Africa${COLOR_RESET}"

    run_test "User wazuh existe" \
        "id wazuh"

    run_test "User wazuh dans le groupe siem-africa" \
        "groups wazuh | grep -q 'siem-africa'"

    # --- TEST 8 : Dashboard accessible (mode full) -----------------------
    if [ "$mode" = "full" ]; then
        echo ""
        echo -e "${COLOR_BOLD}[8] Dashboard Wazuh${COLOR_RESET}"

        run_test "Dashboard accessible via HTTPS local" \
            "curl -k -s -o /dev/null -w '%{http_code}' https://localhost/ | grep -q '200\|302\|401'"

        if [ -f /etc/siem-africa/secrets/wazuh-admin.pwd ]; then
            echo -e "  Password admin disponible : ${COLOR_GREEN}/etc/siem-africa/secrets/wazuh-admin.pwd${COLOR_RESET}"
        fi
    fi

    # ========================================================================
    # RÉSUMÉ
    # ========================================================================
    log_separator
    echo ""
    echo -e "${COLOR_BOLD}RÉSUMÉ DES TESTS WAZUH${COLOR_RESET}"
    echo "  Total  : ${TESTS_TOTAL}"
    echo -e "  Passés : ${COLOR_GREEN}${TESTS_PASSED}${COLOR_RESET}"

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "  Échoués: ${COLOR_RED}${TESTS_FAILED}${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_YELLOW}⚠ Certains tests ont échoué${COLOR_RESET}"
        echo "  Diagnostic : sudo journalctl -u wazuh-manager -n 50"
        echo "  Réparation : sudo ./repair.sh"
        exit 1
    else
        echo ""
        echo -e "${COLOR_GREEN}✅ Tous les tests passent${COLOR_RESET}"
        exit 0
    fi
}

main "$@"
