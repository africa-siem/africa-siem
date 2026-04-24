#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/04-wazuh-indexer.sh — Installation Wazuh Indexer (mode FULL uniquement)
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
# INSTALLATION DE WAZUH INDEXER
# ============================================================================

install_wazuh_indexer() {
    log_step "7/8" "$(t step_wazuh_indexer)"

    # ✨ AUTO-CLEANUP
    cleanup_wazuh_indexer
    sleep 2

    # Configuration mémoire JVM (critique pour indexer)
    # Par défaut Wazuh Indexer prend 1G de heap, mais sur petite VM il faut ajuster
    local total_ram_gb
    total_ram_gb=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
    local heap_size="1g"

    if [ "$total_ram_gb" -ge 16 ]; then
        heap_size="4g"
    elif [ "$total_ram_gb" -ge 8 ]; then
        heap_size="2g"
    fi

    log_info "Configuration JVM heap : ${heap_size} (RAM totale : ${total_ram_gb} GB)"

    # Installation (le dépôt a été ajouté par 03-wazuh-manager.sh)
    log_info "Installation de Wazuh Indexer (cela peut prendre plusieurs minutes)..."

    if ! timeout 900 apt-get install -y wazuh-indexer 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Échec installation Wazuh Indexer"
        return 1
    fi

    # Configuration du heap JVM
    if [ -f /etc/wazuh-indexer/jvm.options ]; then
        sed -i "s/^-Xms.*/-Xms${heap_size}/" /etc/wazuh-indexer/jvm.options
        sed -i "s/^-Xmx.*/-Xmx${heap_size}/" /etc/wazuh-indexer/jvm.options
        log_success "Heap JVM configuré à ${heap_size}"
    fi

    # Génération des certificats (si script Wazuh dispo)
    if [ -f /usr/share/wazuh-indexer/bin/indexer-security-init.sh ]; then
        log_info "Initialisation de la sécurité de l'indexer..."
        # Cette étape peut demander des certificats qui sont générés plus tard
        # par le script wazuh-certs-tool.sh (voir install-full.sh)
    fi

    # Intégration groupe siem-africa
    if getent group siem-africa >/dev/null 2>&1; then
        if id wazuh-indexer >/dev/null 2>&1; then
            usermod -aG siem-africa wazuh-indexer
        fi
    fi

    log_info "Démarrage de Wazuh Indexer..."
    systemctl daemon-reload
    systemctl enable wazuh-indexer >/dev/null 2>&1

    if ! systemctl start wazuh-indexer; then
        log_error "Wazuh Indexer n'a pas démarré"
        systemctl status wazuh-indexer --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    # Indexer met du temps à s'initialiser (30-60s)
    log_info "Attente de l'initialisation de l'indexer (60s)..."
    local waited=0
    while [ $waited -lt 60 ]; do
        if curl -sk https://localhost:9200 -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "200|401"; then
            log_success "Wazuh Indexer répond sur le port 9200"
            break
        fi
        sleep 5
        waited=$((waited + 5))
    done

    if ! systemctl is-active --quiet wazuh-indexer; then
        log_error "Wazuh Indexer ne tourne pas"
        systemctl status wazuh-indexer --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    log_success "Wazuh Indexer est actif"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    log_init
    install_wazuh_indexer
fi

# ============================================================================
# Fin de modules/04-wazuh-indexer.sh
# ============================================================================
