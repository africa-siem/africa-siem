#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# repair.sh — Réparation d'une installation cassée
# ============================================================================
#
# Ce script tente de réparer une installation SIEM Africa endommagée.
#
# Cas couverts :
#   1. Services qui ne démarrent pas
#   2. Fichiers de config corrompus (restauration depuis backup)
#   3. Permissions incorrectes (réapplication)
#   4. Snort qui n'écoute pas sur la bonne interface
#   5. Fichier d'état corrompu (regénération)
#   6. Dossiers manquants (recréation)
#
# Le script est NON DESTRUCTIF : il ne supprime rien, il corrige.
# Si la réparation échoue, utiliser uninstall.sh puis install.sh.
#
# ============================================================================

# --- Répertoire du script -------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Chargement des fonctions utilitaires --------------------------------
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/os-detect.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/users.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/state.sh"

# ============================================================================
# FONCTION 1 : Diagnostic initial
# ============================================================================

run_diagnostic() {
    log_step "1/8" "Diagnostic initial"

    # Détection du mode d'installation
    if [ -f /etc/siem-africa/siem-africa.state.yaml ]; then
        local mode
        mode=$(grep "^  mode:" /etc/siem-africa/siem-africa.state.yaml | awk -F'"' '{print $2}')
        log_info "Mode d'installation détecté : ${mode:-inconnu}"
        INSTALL_MODE="${mode:-lite}"
    else
        log_warning "Fichier d'état introuvable, mode LITE supposé"
        INSTALL_MODE="lite"
    fi
    export INSTALL_MODE

    # État des services
    log_info "État des services :"

    local services=("snort" "wazuh-manager")
    if [ "$INSTALL_MODE" = "full" ]; then
        services+=("wazuh-indexer" "wazuh-dashboard")
    fi

    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "${service}.service"; then
            if systemctl is-active --quiet "${service}.service"; then
                log_success "  ${service} : actif"
            else
                log_warning "  ${service} : inactif ou en erreur"
            fi
        else
            log_warning "  ${service} : non installé"
        fi
    done

    # État des fichiers critiques
    log_info "Fichiers critiques :"
    for file in /etc/snort/snort.conf /var/ossec/etc/ossec.conf /etc/siem-africa/siem-africa.state.yaml; do
        if [ -f "$file" ]; then
            log_success "  ${file} : OK"
        else
            log_warning "  ${file} : MANQUANT"
        fi
    done

    return 0
}

# ============================================================================
# FONCTION 2 : Réparation du groupe et des users
# ============================================================================

repair_users_and_group() {
    log_step "2/8" "Réparation groupe et utilisateurs"

    # Recréer le groupe si manquant
    if ! group_exists "$SIEM_GROUP"; then
        log_warning "Groupe ${SIEM_GROUP} manquant, recréation..."
        create_siem_group
    else
        log_success "Groupe ${SIEM_GROUP} existe"
    fi

    # Recréer siem-ids si manquant
    if ! user_exists "siem-ids"; then
        log_warning "User siem-ids manquant, recréation..."
        create_siem_user "siem-ids" "Module 1 - Snort IDS et Wazuh Manager"
    else
        log_success "User siem-ids existe"

        # S'assurer qu'il est dans le groupe
        if ! groups siem-ids 2>/dev/null | grep -q "\b${SIEM_GROUP}\b"; then
            usermod -aG "$SIEM_GROUP" siem-ids
            log_info "User siem-ids ajouté au groupe ${SIEM_GROUP}"
        fi
    fi

    # Intégration user wazuh au groupe siem-africa (hard-won fix V1)
    if user_exists "wazuh"; then
        usermod -aG "$SIEM_GROUP" wazuh 2>/dev/null || true
        log_info "User wazuh ajouté au groupe ${SIEM_GROUP}"
    fi

    return 0
}

# ============================================================================
# FONCTION 3 : Réparation des répertoires
# ============================================================================

repair_directories() {
    log_step "3/8" "Réparation des répertoires"

    # Créer les dossiers manquants avec bonnes permissions
    local dirs=(
        "/etc/siem-africa:750:root:${SIEM_GROUP}"
        "/etc/siem-africa/secrets:700:root:root"
        "/var/lib/siem-africa:775:root:${SIEM_GROUP}"
        "/var/log/siem-africa:775:root:${SIEM_GROUP}"
        "/opt/siem-africa:755:root:${SIEM_GROUP}"
        "/var/backups/siem-africa:770:root:${SIEM_GROUP}"
    )

    for dir_spec in "${dirs[@]}"; do
        IFS=':' read -r dir perm owner group <<< "$dir_spec"

        if [ ! -d "$dir" ]; then
            log_info "Création : ${dir}"
            mkdir -p "$dir"
        fi

        chown "${owner}:${group}" "$dir" 2>/dev/null || true
        chmod "$perm" "$dir" 2>/dev/null || true
    done

    log_success "Répertoires restaurés"
    return 0
}

# ============================================================================
# FONCTION 4 : Réparation des permissions Snort
# ============================================================================

repair_snort_permissions() {
    log_step "4/8" "Réparation permissions Snort"

    if [ ! -d /etc/snort ]; then
        log_warning "Dossier /etc/snort manquant - réinstallation nécessaire"
        log_info "Utilisez : sudo ./uninstall.sh puis sudo ./install.sh"
        return 1
    fi

    # Permissions sur les fichiers de config
    chown -R snort:snort /etc/snort 2>/dev/null || chown -R root:root /etc/snort
    chmod 755 /etc/snort

    # Permissions sur les logs
    if [ -d /var/log/snort ]; then
        chown -R snort:snort /var/log/snort 2>/dev/null || chown -R root:adm /var/log/snort
        chmod 755 /var/log/snort
    fi

    log_success "Permissions Snort réparées"
    return 0
}

# ============================================================================
# FONCTION 5 : Réparation de la config Snort
# ============================================================================

repair_snort_config() {
    log_step "5/8" "Vérification de la config Snort"

    if [ ! -f /etc/snort/snort.conf ]; then
        log_error "/etc/snort/snort.conf manquant"
        return 1
    fi

    # Test de la config
    if snort -T -c /etc/snort/snort.conf 2>&1 | grep -q "Snort successfully validated"; then
        log_success "Config Snort valide"
        return 0
    fi

    log_warning "Config Snort invalide, tentative de restauration depuis backup..."

    # Chercher un backup
    if [ -f /etc/snort/snort.conf.original ]; then
        cp /etc/snort/snort.conf.original /etc/snort/snort.conf
        log_success "Config restaurée depuis snort.conf.original"

        # Retest
        if snort -T -c /etc/snort/snort.conf 2>&1 | grep -q "Snort successfully validated"; then
            log_success "Config restaurée valide"
            return 0
        fi
    fi

    log_error "Impossible de réparer la config Snort automatiquement"
    log_info  "Solution : sudo ./uninstall.sh && sudo ./install.sh"
    return 1
}

# ============================================================================
# FONCTION 6 : Redémarrage des services
# ============================================================================

restart_services() {
    log_step "6/8" "Redémarrage des services"

    local services=("snort" "wazuh-manager")
    if [ "$INSTALL_MODE" = "full" ]; then
        services+=("wazuh-indexer" "wazuh-dashboard")
    fi

    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "${service}.service"; then
            log_info "Redémarrage de ${service}..."

            if systemctl restart "${service}.service" 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
                sleep 3

                if systemctl is-active --quiet "${service}.service"; then
                    log_success "${service} : actif"
                else
                    log_warning "${service} : problème de démarrage"
                    log_info "  Voir : sudo journalctl -u ${service} -n 30"
                fi
            else
                log_warning "${service} : échec du redémarrage"
            fi
        fi
    done

    return 0
}

# ============================================================================
# FONCTION 7 : Regénération du fichier d'état
# ============================================================================

regenerate_state_file() {
    log_step "7/8" "Regénération du fichier d'état"

    # Redétecter les infos système
    detect_os

    # Détecter l'interface
    if [ -z "$DETECTED_INTERFACE" ]; then
        DETECTED_INTERFACE=$(ip -o link show | grep "state UP" | grep -v "lo:" | awk -F': ' '{print $2}' | head -1)
        export DETECTED_INTERFACE
    fi

    if [ -z "$DETECTED_IP" ] && [ -n "$DETECTED_INTERFACE" ]; then
        DETECTED_IP=$(ip -o -4 addr show "$DETECTED_INTERFACE" | awk '{print $4}' | cut -d'/' -f1 | head -1)
        export DETECTED_IP
    fi

    # Regénérer les fichiers d'état
    generate_state_file "$INSTALL_MODE" || log_warning "Échec génération state.yaml"
    generate_resume_file "$INSTALL_MODE" || log_warning "Échec génération RESUME.txt"

    log_success "Fichier d'état regénéré"
    return 0
}

# ============================================================================
# FONCTION 8 : Tests finaux
# ============================================================================

final_tests() {
    log_step "8/8" "Tests finaux"

    local all_ok=true

    # Test 1 : Snort
    if systemctl is-active --quiet snort.service 2>/dev/null; then
        log_success "Snort : opérationnel"
    else
        log_warning "Snort : non opérationnel"
        all_ok=false
    fi

    # Test 2 : Wazuh Manager
    if systemctl is-active --quiet wazuh-manager.service 2>/dev/null; then
        log_success "Wazuh Manager : opérationnel"
    else
        log_warning "Wazuh Manager : non opérationnel"
        all_ok=false
    fi

    # Test 3 : Fichier alerts.json accessible
    if [ -f /var/ossec/logs/alerts/alerts.json ] || [ -d /var/ossec/logs/alerts ]; then
        log_success "Dossier alertes Wazuh : OK"
    else
        log_warning "Dossier alertes Wazuh : manquant"
        all_ok=false
    fi

    if [ "$all_ok" = "true" ]; then
        log_success "Tous les tests passent ✓"
    else
        log_warning "Certains tests ont échoué, voir les logs"
    fi

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

main() {
    # Vérification root
    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ Ce script doit être exécuté en tant que root"
        exit 1
    fi

    log_init

    log_banner "SIEM AFRICA - RÉPARATION DU MODULE 1"

    echo ""
    log_info "Ce script va tenter de réparer une installation cassée."
    log_info "Il est NON DESTRUCTIF : aucun fichier ne sera supprimé."
    echo ""

    run_diagnostic
    repair_users_and_group
    repair_directories
    repair_snort_permissions
    repair_snort_config  # peut échouer
    restart_services
    regenerate_state_file
    final_tests

    log_separator
    log_banner "✅ RÉPARATION TERMINÉE"

    log_info ""
    log_info "Consultez le résumé :"
    log_info "  sudo cat /etc/siem-africa/RESUME.txt"
    log_info ""
    log_info "Si le problème persiste :"
    log_info "  1. Vérifier les logs : sudo journalctl -u snort -u wazuh-manager -n 50"
    log_info "  2. Désinstaller : sudo ./uninstall.sh"
    log_info "  3. Réinstaller : sudo ./install.sh"
    echo ""

    return 0
}

trap 'log_warning "Réparation interrompue"; exit 130' INT TERM

main "$@"
