#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# install-full.sh — Installation directe en Mode FULL (all-in-one)
# ============================================================================
#
# Ce script installe le Module 1 en Mode FULL :
#   - Snort IDS
#   - Wazuh Manager
#   - Wazuh Indexer (OpenSearch)
#   - Wazuh Dashboard (interface web)
#
# Prérequis : 8 GB RAM, 50 GB disque, Ubuntu 22.04/24.04 ou Debian 11/12
#
# Utilisation :
#   sudo ./install-full.sh
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export INSTALL_MODE="full"

# Chargement des fonctions utilitaires
source "${SCRIPT_DIR}/core/logging.sh"
source "${SCRIPT_DIR}/core/langue.sh"
source "${SCRIPT_DIR}/core/os-detect.sh"
source "${SCRIPT_DIR}/core/prerequis.sh"
source "${SCRIPT_DIR}/core/users.sh"
source "${SCRIPT_DIR}/core/state.sh"

main() {
    log_init
    log_banner "SIEM AFRICA - INSTALLATION MODE FULL"

    # Vérification root
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Ce script doit être exécuté en tant que root"
        log_info  "Relancez avec : sudo ./install-full.sh"
        exit 1
    fi

    log_info "Démarrage installation Mode FULL (all-in-one)"
    log_info "Date : $(date '+%Y-%m-%d %H:%M:%S')"

    # Sélection de la langue (si pas déjà fait)
    if [ -z "$SIEM_LANG" ]; then
        select_language
    fi

    # ÉTAPE 1 : OS
    log_step "1/9" "$(t step_os)"
    verify_os_compatible

    # ÉTAPE 2 : Prérequis (note : mode full nécessite 8 GB RAM)
    check_all_prerequisites "full"

    # ÉTAPE 3 : Préparation système
    log_step "3/9" "$(t step_sysprep)"
    source "${SCRIPT_DIR}/modules/01-system-prep.sh"
    run_system_prep || die "Échec préparation système"

    # ÉTAPE 4 : Snort
    log_step "4/9" "$(t step_snort)"
    source "${SCRIPT_DIR}/modules/02-snort.sh"
    install_snort || die "Échec installation Snort"

    # ÉTAPE 5 : Wazuh Manager
    log_step "5/9" "$(t step_wazuh_mgr)"
    source "${SCRIPT_DIR}/modules/03-wazuh-manager.sh"
    install_wazuh_manager || die "Échec installation Wazuh Manager"

    # ÉTAPE 6 : Wazuh Indexer (spécifique mode FULL)
    log_step "6/9" "$(t step_wazuh_indexer)"
    source "${SCRIPT_DIR}/modules/04-wazuh-indexer.sh"
    install_wazuh_indexer || die "Échec installation Wazuh Indexer"

    # ÉTAPE 7 : Wazuh Dashboard (spécifique mode FULL)
    log_step "7/9" "$(t step_wazuh_dash)"
    source "${SCRIPT_DIR}/modules/05-wazuh-dashboard.sh"
    install_wazuh_dashboard || die "Échec installation Wazuh Dashboard"

    # ÉTAPE 8 : Intégration
    log_step "8/9" "$(t step_integration)"
    source "${SCRIPT_DIR}/modules/06-integration.sh"
    integrate_snort_wazuh || die "Échec intégration Snort-Wazuh"

    # ÉTAPE 9 : Fichier d'état
    log_step "9/9" "$(t step_state)"
    source "${SCRIPT_DIR}/modules/07-state-file.sh"
    finalize_state "full" || log_warning "Avertissement finalisation"

    # FINAL
    log_separator
    log_banner "$(t install_success)"
    display_resume

    log_success "Installation Mode FULL terminée"
    log_info "Accédez au Dashboard Wazuh : https://${DETECTED_IP}"
    return 0
}

main "$@"
