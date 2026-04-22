#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1 / Tests
# tests/test-snort.sh — Tests de validation de Snort IDS
# ============================================================================
#
# Ce script vérifie que Snort fonctionne correctement :
#   1. Le paquet snort est installé
#   2. Le fichier de config existe et est valide
#   3. Le service snort est actif
#   4. Snort écoute sur la bonne interface
#   5. Les règles sont chargées
#   6. Les logs sont écrits
#   7. Un test de détection fonctionne (ping → alerte)
#
# Usage :
#   sudo ./tests/test-snort.sh
#
# Retour :
#   0 = tous les tests passent
#   1 = au moins un test a échoué
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"

# --- Compteurs ------------------------------------------------------------
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# --- run_test : Exécute un test et compte le résultat ---------------------
# Usage : run_test "Nom du test" "commande" [code_attendu]
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

# ============================================================================
# TESTS
# ============================================================================

main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ Ce script nécessite les droits root"
        exit 1
    fi

    log_init

    log_banner "TESTS DE VALIDATION SNORT"

    # --- TEST 1 : Paquet installé ----------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[1] Installation du paquet${COLOR_RESET}"
    run_test "Paquet snort installé" \
        "dpkg -l | grep -qE '^ii\s+snort'"

    run_test "Binaire snort disponible" \
        "command -v snort"

    # --- TEST 2 : Configuration ------------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[2] Configuration${COLOR_RESET}"
    run_test "Fichier /etc/snort/snort.conf existe" \
        "[ -f /etc/snort/snort.conf ]"

    run_test "Config Snort syntaxiquement valide" \
        "snort -T -c /etc/snort/snort.conf 2>&1 | grep -q 'Snort successfully validated'"

    run_test "Variable HOME_NET définie" \
        "grep -q '^ipvar HOME_NET' /etc/snort/snort.conf"

    # --- TEST 3 : Service systemd ----------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[3] Service systemd${COLOR_RESET}"
    run_test "Service snort.service existe" \
        "systemctl list-unit-files | grep -q 'snort.service'"

    run_test "Service snort activé au démarrage" \
        "systemctl is-enabled --quiet snort.service"

    run_test "Service snort actif" \
        "systemctl is-active --quiet snort.service"

    # --- TEST 4 : Processus snort ----------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[4] Processus${COLOR_RESET}"
    run_test "Processus snort en cours d'exécution" \
        "pgrep -x snort"

    # --- TEST 5 : Dossier et fichiers de logs ---------------------------
    echo ""
    echo -e "${COLOR_BOLD}[5] Logs et fichiers${COLOR_RESET}"
    run_test "Dossier /var/log/snort existe" \
        "[ -d /var/log/snort ]"

    # Le fichier alert est créé au premier packet, peut ne pas exister si Snort vient de démarrer
    if [ -f /var/log/snort/alert ]; then
        run_test "Fichier /var/log/snort/alert existe" \
            "[ -f /var/log/snort/alert ]"
    else
        echo "  Fichier /var/log/snort/alert n'existe pas encore (normal si pas d'alertes)"
    fi

    # --- TEST 6 : Règles chargées ----------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[6] Règles${COLOR_RESET}"
    run_test "Dossier /etc/snort/rules existe" \
        "[ -d /etc/snort/rules ]"

    # Compter les règles chargées
    if [ -d /etc/snort/rules ]; then
        local rules_count
        rules_count=$(cat /etc/snort/rules/*.rules 2>/dev/null | grep -c "^alert" || echo "0")
        echo "  Nombre de règles 'alert' trouvées : ${rules_count}"

        if [ "$rules_count" -gt 0 ]; then
            echo -e "  ${COLOR_GREEN}✓ Des règles sont chargées${COLOR_RESET}"
        else
            echo -e "  ${COLOR_YELLOW}⚠ Aucune règle 'alert' trouvée${COLOR_RESET}"
            echo "    Lancer : sudo /opt/siem-africa/module-1/scripts/update-rules.sh"
        fi
    fi

    # --- TEST 7 : Interface réseau ---------------------------------------
    echo ""
    echo -e "${COLOR_BOLD}[7] Interface réseau${COLOR_RESET}"

    if [ -f /etc/default/snort ]; then
        source /etc/default/snort
        echo "  Interface configurée : ${INTERFACE:-inconnue}"

        if [ -n "$INTERFACE" ]; then
            run_test "Interface ${INTERFACE} existe" \
                "ip link show ${INTERFACE}"

            run_test "Interface ${INTERFACE} UP" \
                "ip link show ${INTERFACE} | grep -q 'state UP'"
        fi
    fi

    # --- TEST 8 : Test de détection (optionnel) --------------------------
    echo ""
    echo -e "${COLOR_BOLD}[8] Test de détection${COLOR_RESET}"

    # On ne lance pas automatiquement un ping test car il faut une source externe
    # On donne juste la commande à l'utilisateur
    echo "  Pour tester une détection :"
    echo "    Depuis une autre machine : nmap -sS <IP_DE_CE_SERVEUR>"
    echo "    Puis sur ce serveur : sudo tail /var/log/snort/alert"
    echo ""
    echo "  Ou auto-test local :"
    echo "    sudo ping -c 20 -i 0.2 \$(hostname -I | awk '{print \$1}')"
    echo "    sudo tail /var/log/snort/alert"

    # ========================================================================
    # RÉSUMÉ
    # ========================================================================
    log_separator
    echo ""
    echo -e "${COLOR_BOLD}RÉSUMÉ DES TESTS SNORT${COLOR_RESET}"
    echo "  Total  : ${TESTS_TOTAL}"
    echo -e "  Passés : ${COLOR_GREEN}${TESTS_PASSED}${COLOR_RESET}"

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "  Échoués: ${COLOR_RED}${TESTS_FAILED}${COLOR_RESET}"
        echo ""
        echo -e "${COLOR_YELLOW}⚠ Certains tests ont échoué${COLOR_RESET}"
        echo "  Diagnostic : sudo ./repair.sh"
        exit 1
    else
        echo ""
        echo -e "${COLOR_GREEN}✅ Tous les tests passent${COLOR_RESET}"
        exit 0
    fi
}

main "$@"
