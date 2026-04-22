#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1 / Tests
# tests/test-integration.sh — Test de l'intégration Snort ↔ Wazuh
# ============================================================================
#
# Ce script vérifie que Snort et Wazuh communiquent correctement :
#   1. Lance les tests individuels (test-snort.sh + test-wazuh.sh)
#   2. Génère une attaque simulée (auto-ping)
#   3. Vérifie que Snort a détecté (via /var/log/snort/alert)
#   4. Vérifie que Wazuh a reçu l'alerte (via alerts.json)
#   5. Vérifie le workflow complet
#
# Usage :
#   sudo ./tests/test-integration.sh
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"

# ============================================================================
# FONCTION : Lance les tests individuels
# ============================================================================

run_individual_tests() {
    log_banner "TESTS INDIVIDUELS"

    log_info "1️⃣  Exécution de test-snort.sh..."
    if bash "${SCRIPT_DIR}/tests/test-snort.sh" >/dev/null 2>&1; then
        log_success "Tests Snort : OK"
    else
        log_error "Tests Snort : ÉCHECS détectés"
        log_info "Relancer manuellement : sudo ./tests/test-snort.sh"
        return 1
    fi

    log_info "2️⃣  Exécution de test-wazuh.sh..."
    if bash "${SCRIPT_DIR}/tests/test-wazuh.sh" >/dev/null 2>&1; then
        log_success "Tests Wazuh : OK"
    else
        log_error "Tests Wazuh : ÉCHECS détectés"
        log_info "Relancer manuellement : sudo ./tests/test-wazuh.sh"
        return 1
    fi

    return 0
}

# ============================================================================
# FONCTION : Vérifie que les deux services sont actifs
# ============================================================================

check_services_running() {
    log_info "Vérification que les services tournent..."

    if ! systemctl is-active --quiet snort.service; then
        log_error "Snort n'est pas actif"
        log_info "Démarrer : sudo systemctl start snort"
        return 1
    fi

    if ! systemctl is-active --quiet wazuh-manager.service; then
        log_error "Wazuh Manager n'est pas actif"
        log_info "Démarrer : sudo systemctl start wazuh-manager"
        return 1
    fi

    log_success "Snort et Wazuh Manager sont actifs"
    return 0
}

# ============================================================================
# FONCTION : Génère une alerte Snort (test de détection)
# ============================================================================

# --- generate_test_alert : Utilise un ping pour déclencher une règle -----
# Les Community Rules Emerging Threats incluent des règles ICMP qui
# peuvent se déclencher avec des pings massifs (flood).
generate_test_alert() {
    log_info "Génération d'une alerte de test (ping flood local)..."

    # Récupérer l'IP locale
    local local_ip
    local_ip=$(hostname -I | awk '{print $1}')

    if [ -z "$local_ip" ]; then
        log_warning "Impossible de détecter l'IP locale"
        return 1
    fi

    log_info "Ping vers ${local_ip} (30 paquets en 3 secondes)..."

    # Snapshot du nombre d'alertes AVANT
    local alerts_before=0
    if [ -f /var/log/snort/alert ]; then
        alerts_before=$(wc -l < /var/log/snort/alert)
    fi

    # Ping massif (déclenche les règles ICMP flood)
    # -f : flood (max speed, requires root)
    # -c 30 : 30 paquets
    # -W 2 : timeout 2s
    ping -f -c 30 -W 2 "$local_ip" >/dev/null 2>&1 &
    local ping_pid=$!

    # Attendre 5 secondes pour que Snort traite
    sleep 5

    # Tuer le ping s'il tourne encore
    kill $ping_pid 2>/dev/null
    wait $ping_pid 2>/dev/null

    # Snapshot APRÈS
    local alerts_after=0
    if [ -f /var/log/snort/alert ]; then
        alerts_after=$(wc -l < /var/log/snort/alert)
    fi

    local new_alerts=$((alerts_after - alerts_before))

    log_info "Alertes détectées : ${new_alerts}"

    if [ "$new_alerts" -gt 0 ]; then
        log_success "Snort a détecté ${new_alerts} alertes ✓"
        return 0
    else
        log_warning "Aucune nouvelle alerte Snort détectée"
        log_info "Cela peut être normal si les règles ICMP ne sont pas activées"
        log_info "Tenter un vrai scan depuis une autre machine :"
        log_info "  nmap -sS ${local_ip}"
        return 1
    fi
}

# ============================================================================
# FONCTION : Vérifie que Wazuh a reçu les alertes
# ============================================================================

check_wazuh_received_alerts() {
    log_info "Vérification de la réception par Wazuh..."

    local alerts_json="/var/ossec/logs/alerts/alerts.json"

    if [ ! -f "$alerts_json" ]; then
        log_warning "Fichier ${alerts_json} n'existe pas"
        log_info "Wazuh le créera à la première alerte reçue"
        return 1
    fi

    # Regarder les 30 dernières secondes
    local snort_alerts_in_wazuh
    snort_alerts_in_wazuh=$(tail -100 "$alerts_json" 2>/dev/null | grep -c "\"decoder\":{\"name\":\"snort\"" || echo "0")

    if [ "$snort_alerts_in_wazuh" -gt 0 ]; then
        log_success "Wazuh a reçu ${snort_alerts_in_wazuh} alertes Snort ✓"
        log_info "Intégration Snort → Wazuh fonctionnelle !"
        return 0
    else
        log_warning "Aucune alerte Snort trouvée dans Wazuh alerts.json"
        log_info ""
        log_info "Diagnostic possible :"
        log_info "  1. Le decoder Snort de Wazuh ne reconnaît pas le format"
        log_info "     → Vérifier : grep 'snort-fast' /var/ossec/etc/ossec.conf"
        log_info "  2. Le fichier /var/log/snort/alert n'est pas lu"
        log_info "     → Vérifier : ls -la /var/log/snort/alert"
        log_info "     → Permissions : chmod 644 /var/log/snort/alert"
        log_info "  3. Wazuh n'a pas été redémarré après la config"
        log_info "     → sudo systemctl restart wazuh-manager"
        return 1
    fi
}

# ============================================================================
# FONCTION : Test du pare-feu UFW
# ============================================================================

check_firewall() {
    log_info "Vérification du pare-feu UFW..."

    if ! command -v ufw >/dev/null 2>&1; then
        log_info "UFW non installé (OK si autre firewall utilisé)"
        return 0
    fi

    if ufw status | grep -q "Status: active"; then
        log_success "UFW est actif"

        # Vérifier les ports SIEM
        local ufw_rules
        ufw_rules=$(ufw status | grep -cE "(1514|1515|55000|9200|443)")

        if [ "$ufw_rules" -gt 0 ]; then
            log_success "Règles UFW SIEM détectées (${ufw_rules})"
        fi
    else
        log_warning "UFW n'est pas actif"
    fi

    return 0
}

# ============================================================================
# FONCTION : Affichage du résumé final
# ============================================================================

show_summary() {
    log_separator
    log_banner "RÉSUMÉ DE L'INTÉGRATION"

    echo ""
    echo -e "${COLOR_BOLD}État des services :${COLOR_RESET}"

    for service in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl list-unit-files 2>/dev/null | grep -q "${service}.service"; then
            if systemctl is-active --quiet "${service}.service"; then
                echo -e "  ${service}: ${COLOR_GREEN}✓ actif${COLOR_RESET}"
            else
                echo -e "  ${service}: ${COLOR_RED}✗ inactif${COLOR_RESET}"
            fi
        fi
    done

    echo ""
    echo -e "${COLOR_BOLD}Statistiques :${COLOR_RESET}"

    # Nombre de règles Snort chargées
    if [ -d /etc/snort/rules ]; then
        local rules_count
        rules_count=$(cat /etc/snort/rules/*.rules 2>/dev/null | grep -c "^alert" || echo "0")
        echo "  Règles Snort actives  : ${rules_count}"
    fi

    # Nombre d'alertes dans alerts.json
    if [ -f /var/ossec/logs/alerts/alerts.json ]; then
        local alerts_count
        alerts_count=$(wc -l < /var/ossec/logs/alerts/alerts.json)
        echo "  Alertes Wazuh totales : ${alerts_count}"
    fi

    # Taille du log Snort
    if [ -f /var/log/snort/alert ]; then
        local snort_alerts
        snort_alerts=$(wc -l < /var/log/snort/alert)
        echo "  Alertes Snort totales : ${snort_alerts}"
    fi

    echo ""
    echo -e "${COLOR_BOLD}Commandes utiles :${COLOR_RESET}"
    echo "  Logs Snort en temps réel :"
    echo "    sudo tail -f /var/log/snort/alert"
    echo ""
    echo "  Alertes Wazuh en temps réel :"
    echo "    sudo tail -f /var/ossec/logs/alerts/alerts.json"
    echo ""
    echo "  Tester depuis une autre machine :"
    echo "    nmap -sS $(hostname -I | awk '{print $1}')"
    echo ""
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

    log_banner "TEST D'INTÉGRATION SNORT ↔ WAZUH"

    echo ""
    echo -e "  ${COLOR_BOLD}Ce test va :${COLOR_RESET}"
    echo "    1. Vérifier Snort et Wazuh individuellement"
    echo "    2. Générer une attaque simulée (ping flood local)"
    echo "    3. Vérifier la détection et la corrélation"
    echo ""

    local all_ok=0

    # Étape 1 : tests individuels
    run_individual_tests || all_ok=1

    # Étape 2 : services actifs
    check_services_running || all_ok=1

    # Étape 3 : générer alerte
    if ! generate_test_alert; then
        log_warning "Génération d'alerte échouée, on continue..."
    fi

    # Attendre que Wazuh traite les logs
    log_info "Attente du traitement par Wazuh (5 secondes)..."
    sleep 5

    # Étape 4 : Wazuh a-t-il reçu ?
    check_wazuh_received_alerts || all_ok=1

    # Étape 5 : firewall
    check_firewall

    # Résumé final
    show_summary

    if [ $all_ok -eq 0 ]; then
        log_success "Intégration Snort ↔ Wazuh fonctionnelle ✓"
        exit 0
    else
        log_warning "L'intégration a des problèmes, voir les logs ci-dessus"
        exit 1
    fi
}

main "$@"
