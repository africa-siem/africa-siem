#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/03-wazuh-manager.sh — Installation Wazuh Manager (avec auto-cleanup)
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

# ============================================================================
# AJOUT DU DÉPÔT WAZUH (idempotent — ne refait pas si déjà configuré)
# ============================================================================

add_wazuh_repo() {
    # Si le dépôt est déjà configuré et fonctionnel, on ne refait rien
    if [ -f /etc/apt/sources.list.d/wazuh.list ] && \
       [ -f /usr/share/keyrings/wazuh.gpg ]; then
        log_info "Dépôt Wazuh déjà configuré"
        return 0
    fi

    log_info "Configuration du dépôt APT Wazuh..."

    # Installer les prérequis
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl gnupg apt-transport-https 2>/dev/null

    # Importer la clé GPG
    if ! curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
         gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null; then
        log_error "Impossible d'importer la clé GPG Wazuh"
        return 1
    fi
    chmod 644 /usr/share/keyrings/wazuh.gpg

    # Ajouter le dépôt
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list

    # Mettre à jour apt
    if ! DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Échec apt-get update après ajout du dépôt Wazuh"
        return 1
    fi

    log_success "Dépôt Wazuh configuré"
    return 0
}

# ============================================================================
# INSTALLATION DE WAZUH MANAGER
# ============================================================================

install_wazuh_manager() {
    log_step "6/8" "$(t step_wazuh_mgr)"

    # ========================================================================
    # ✨ AUTO-CLEANUP : purger toute installation antérieure
    # ========================================================================
    cleanup_wazuh_manager
    cleanup_filebeat    # Filebeat est souvent lié à Wazuh

    sleep 2

    # Note : on NE purge PAS le dépôt apt Wazuh, on en a besoin pour réinstaller

    # ========================================================================
    # Ajout du dépôt
    # ========================================================================

    if ! add_wazuh_repo; then
        log_error "Impossible de configurer le dépôt Wazuh"
        return 1
    fi

    # ========================================================================
    # Installation
    # ========================================================================

    log_info "Installation de Wazuh Manager (cela peut prendre quelques minutes)..."

    # Timeout à 600s car l'install Wazuh peut être lente
    if ! timeout 600 apt-get install -y wazuh-manager 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Échec installation Wazuh Manager (timeout ou erreur)"
        log_info "Consultez les détails : ${LOG_FILE}"
        return 1
    fi

    # Vérification : /var/ossec doit exister
    if [ ! -d /var/ossec ]; then
        log_error "Wazuh Manager installé mais /var/ossec absent (installation corrompue)"
        log_info "Tentative de réparation : sudo apt-get install --reinstall wazuh-manager"
        return 1
    fi

    log_success "Wazuh Manager installé"

    # ========================================================================
    # Configuration (si template fourni)
    # ========================================================================

    if [ -f "${SCRIPT_DIR}/config/wazuh/ossec.conf.template" ]; then
        log_info "Application de la config SIEM Africa..."
        # Backup de la config par défaut
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.default
        # Application du template
        cp "${SCRIPT_DIR}/config/wazuh/ossec.conf.template" /var/ossec/etc/ossec.conf
        chown root:wazuh /var/ossec/etc/ossec.conf
        chmod 660 /var/ossec/etc/ossec.conf
    fi

    # ========================================================================
    # Intégration au groupe siem-africa
    # ========================================================================

    if getent group siem-africa >/dev/null 2>&1; then
        if id wazuh >/dev/null 2>&1; then
            usermod -aG siem-africa wazuh
            log_info "User 'wazuh' ajouté au groupe 'siem-africa'"
        fi
    fi

    # ========================================================================
    # Démarrage
    # ========================================================================

    log_info "Démarrage de Wazuh Manager..."

    systemctl daemon-reload
    systemctl enable wazuh-manager >/dev/null 2>&1

    if ! systemctl start wazuh-manager; then
        log_error "Wazuh Manager n'a pas démarré"
        systemctl status wazuh-manager --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    # Attente de 10s pour que Wazuh se stabilise
    log_info "Attente de la stabilisation (10s)..."
    sleep 10

    if ! systemctl is-active --quiet wazuh-manager; then
        log_error "Wazuh Manager a démarré puis s'est arrêté"
        systemctl status wazuh-manager --no-pager | tee -a "$LOG_FILE"
        log_info "Logs Wazuh : sudo tail -50 /var/ossec/logs/ossec.log"
        return 1
    fi

    # Vérification que alerts.json est prêt (ou au moins que le dossier existe)
    if [ ! -d /var/ossec/logs/alerts ]; then
        log_warning "Dossier /var/ossec/logs/alerts absent (sera créé à la première alerte)"
    fi

    log_success "Wazuh Manager est actif"
    return 0
}

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    log_init
    install_wazuh_manager
fi

# ============================================================================
# Fin de modules/03-wazuh-manager.sh
# ============================================================================
