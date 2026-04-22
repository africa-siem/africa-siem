#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# install-lite.sh — Installation directe en Mode LITE
# ============================================================================
#
# Ce script installe le Module 1 en Mode LITE :
#   - Wazuh Manager
#   - Snort IDS
#   (Pas de Wazuh Indexer, pas de Wazuh Dashboard)
#
# Prérequis : 4 GB RAM, 50 GB disque, Ubuntu 22.04/24.04 ou Debian 11/12
#
# Utilisation :
#   sudo ./install-lite.sh
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export INSTALL_MODE="lite"

# Chargement des fonctions utilitaires
source "${SCRIPT_DIR}/core/logging.sh"
source "${SCRIPT_DIR}/core/langue.sh"
source "${SCRIPT_DIR}/core/os-detect.sh"
source "${SCRIPT_DIR}/core/prerequis.sh"
source "${SCRIPT_DIR}/core/users.sh"
source "${SCRIPT_DIR}/core/state.sh"

main() {
    log_init
    log_banner "SIEM AFRICA - INSTALLATION MODE LITE"

    # Vérification root
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Ce script doit être exécuté en tant que root"
        log_info  "Relancez avec : sudo ./install-lite.sh"
        exit 1
    fi

    log_info "Démarrage installation Mode LITE"
    log_info "Date : $(date '+%Y-%m-%d %H:%M:%S')"

    # Sélection de la langue (si pas déjà fait)
    if [ -z "$SIEM_LANG" ]; then
        select_language
    fi

    # ÉTAPE 1 : OS
    log_step "1/7" "$(t step_os)"
    verify_os_compatible

    # ÉTAPE 2 : Prérequis
    check_all_prerequisites "lite"

    # ÉTAPE 3 : Préparation système
    log_step "3/7" "$(t step_sysprep)"
    source "${SCRIPT_DIR}/modules/01-system-prep.sh"
    run_system_prep || die "Échec préparation système"

    # ÉTAPE 4 : Snort
    log_step "4/7" "$(t step_snort)"
    source "${SCRIPT_DIR}/modules/02-snort.sh"
    install_snort || die "Échec installation Snort"

    # ÉTAPE 5 : Wazuh Manager
    log_step "5/7" "$(t step_wazuh_mgr)"
    source "${SCRIPT_DIR}/modules/03-wazuh-manager.sh"
    install_wazuh_manager || die "Échec installation Wazuh Manager"

    # ÉTAPE 6 : Intégration
    log_step "6/7" "$(t step_integration)"
    source "${SCRIPT_DIR}/modules/06-integration.sh"
    integrate_snort_wazuh || die "Échec intégration Snort-Wazuh"

    # ÉTAPE 7 : Fichier d'état
    log_step "7/7" "$(t step_state)"
    source "${SCRIPT_DIR}/modules/07-state-file.sh"
    finalize_state "lite" || log_warning "Avertissement finalisation"

    # FINAL
    log_separator
    log_banner "$(t install_success)"
    display_resume

    log_success "Installation Mode LITE terminée"
    return 0
}

main "$@"
