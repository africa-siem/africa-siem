#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/05-wazuh-dashboard.sh — Installation Wazuh Dashboard (mode FULL)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/langue.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/os-detect.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/cleanup.sh"    # ✨ NOUVEAU
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/state.sh"      # pour save_secret

# ============================================================================
# GÉNÉRATION D'UN MOT DE PASSE ALÉATOIRE SÉCURISÉ
# ============================================================================

generate_secure_password() {
    # 16 caractères alphanumériques + symboles
    # tr -dc ne garde que les caractères souhaités
    tr -dc 'A-Za-z0-9@#%&*_+=' < /dev/urandom | head -c 16
}

# ============================================================================
# INSTALLATION DE WAZUH DASHBOARD
# ============================================================================

install_wazuh_dashboard() {
    log_step "8/8" "$(t step_wazuh_dash)"

    # ✨ AUTO-CLEANUP
    cleanup_wazuh_dashboard
    sleep 2

    log_info "Installation de Wazuh Dashboard..."

    if ! timeout 600 apt-get install -y wazuh-dashboard 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Échec installation Wazuh Dashboard"
        return 1
    fi

    # Intégration groupe siem-africa
    if getent group siem-africa >/dev/null 2>&1; then
        if id wazuh-dashboard >/dev/null 2>&1; then
            usermod -aG siem-africa wazuh-dashboard
        fi
    fi

    # ========================================================================
    # Génération du mot de passe admin
    # ========================================================================

    log_info "Génération d'un mot de passe admin sécurisé..."
    local admin_password
    admin_password=$(generate_secure_password)

    # Sauvegarde dans /etc/siem-africa/secrets/
    save_secret "wazuh-admin.pwd" "$admin_password"

    # Le hash sera configuré plus tard via le wazuh-passwords-tool
    # (ce script est généré par le Wazuh Indexer)

    # ========================================================================
    # Démarrage
    # ========================================================================

    log_info "Démarrage de Wazuh Dashboard..."
    systemctl daemon-reload
    systemctl enable wazuh-dashboard >/dev/null 2>&1

    if ! systemctl start wazuh-dashboard; then
        log_error "Wazuh Dashboard n'a pas démarré"
        systemctl status wazuh-dashboard --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    # Dashboard peut prendre jusqu'à 2 minutes à se lancer
    log_info "Attente du démarrage du dashboard (peut prendre 60-120s)..."
    local waited=0
    while [ $waited -lt 120 ]; do
        if curl -sk "https://localhost" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "200|302"; then
            log_success "Wazuh Dashboard répond sur HTTPS"
            break
        fi
        sleep 10
        waited=$((waited + 10))
    done

    if ! systemctl is-active --quiet wazuh-dashboard; then
        log_error "Wazuh Dashboard ne tourne pas"
        systemctl status wazuh-dashboard --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    log_success "Wazuh Dashboard est actif"
    log_info "URL : https://${DETECTED_IP:-<IP_SERVEUR>}"
    log_info "User : admin"
    log_info "Password : cat /etc/siem-africa/secrets/wazuh-admin.pwd"

    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    log_init
    install_wazuh_dashboard
fi

# ============================================================================
# Fin de modules/05-wazuh-dashboard.sh
# ============================================================================
