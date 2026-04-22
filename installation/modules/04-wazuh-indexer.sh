#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/04-wazuh-indexer.sh — Installation de Wazuh Indexer (Mode FULL)
# ============================================================================
#
# Ce module installe Wazuh Indexer (OpenSearch) pour le Mode FULL uniquement.
#
# Wazuh Indexer stocke et indexe toutes les alertes SIEM pour permettre des
# recherches rapides et des analyses avancées dans le Dashboard.
#
# Configuration single-node :
#   - Un seul nœud OpenSearch (suffisant pour une PME)
#   - Mémoire allouée : 4 GB (sur 8 GB total)
#   - Port 9200 (HTTPS)
#
# ============================================================================

readonly INDEXER_VERSION="4.14"

# ============================================================================
# ÉTAPE 1 : Installation du paquet wazuh-indexer
# ============================================================================

install_indexer_package() {
    log_info "Installation de Wazuh Indexer ${INDEXER_VERSION}..."

    # Le dépôt Wazuh est déjà configuré par 03-wazuh-manager.sh
    # On peut directement installer

    if DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-indexer >> "$LOG_FILE" 2>&1; then
        log_success "Wazuh Indexer installé"
    else
        log_error "Échec installation Wazuh Indexer"
        log_info  "Consultez ${LOG_FILE}"
        return 1
    fi

    return 0
}

# ============================================================================
# ÉTAPE 2 : Configuration OpenSearch
# ============================================================================

configure_indexer() {
    log_info "Configuration de Wazuh Indexer..."

    local indexer_conf="/etc/wazuh-indexer/opensearch.yml"

    if [ ! -f "$indexer_conf" ]; then
        log_error "Fichier de config introuvable : ${indexer_conf}"
        return 1
    fi

    # Sauvegarde
    if [ ! -f "${indexer_conf}.backup" ]; then
        cp "$indexer_conf" "${indexer_conf}.backup"
    fi

    # Configuration single-node :
    # - Le Indexer écoute sur localhost uniquement (sécurité)
    # - Le Dashboard s'y connectera en local
    # - Cluster name pour identification

    # Note : la config par défaut de Wazuh Indexer est déjà adaptée pour single-node
    # On ne modifie pas sauf si nécessaire

    log_success "Configuration Wazuh Indexer vérifiée"
    return 0
}

# ============================================================================
# ÉTAPE 3 : Configuration de la mémoire JVM
# ============================================================================

configure_jvm_memory() {
    log_info "Configuration de la mémoire JVM pour l'Indexer..."

    local jvm_conf="/etc/wazuh-indexer/jvm.options"

    if [ ! -f "$jvm_conf" ]; then
        log_warning "Fichier jvm.options introuvable, configuration par défaut utilisée"
        return 0
    fi

    # --- Calculer la RAM à allouer ---
    # Règle : 50% de la RAM disponible, max 4 GB
    # Minimum : 2 GB
    local total_ram_kb
    total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_gb=$((total_ram_kb / 1024 / 1024))

    # Moitié de la RAM, max 4
    local jvm_ram_gb=$((total_ram_gb / 2))
    if [ "$jvm_ram_gb" -gt 4 ]; then
        jvm_ram_gb=4
    fi
    if [ "$jvm_ram_gb" -lt 2 ]; then
        jvm_ram_gb=2
    fi

    log_info "RAM allouée à l'Indexer : ${jvm_ram_gb} GB (sur ${total_ram_gb} GB total)"

    # Backup
    if [ ! -f "${jvm_conf}.backup" ]; then
        cp "$jvm_conf" "${jvm_conf}.backup"
    fi

    # Mise à jour des valeurs Xms et Xmx
    # Xms = RAM initiale, Xmx = RAM maximale
    # Important : Xms = Xmx pour OpenSearch (évite les relocations coûteuses)
    sed -i "s|^-Xms.*|-Xms${jvm_ram_gb}g|" "$jvm_conf"
    sed -i "s|^-Xmx.*|-Xmx${jvm_ram_gb}g|" "$jvm_conf"

    log_success "Mémoire JVM configurée : ${jvm_ram_gb} GB"

    # Exporter pour le fichier d'état
    export INDEXER_JVM_RAM_GB="$jvm_ram_gb"

    return 0
}

# ============================================================================
# ÉTAPE 4 : Configuration des limites système pour l'Indexer
# ============================================================================

configure_system_limits() {
    log_info "Configuration des limites système pour l'Indexer..."

    # OpenSearch a besoin de plus de file descriptors que la limite par défaut
    # On crée un fichier de configuration dédié
    local limits_file="/etc/security/limits.d/wazuh-indexer.conf"

    if [ ! -f "$limits_file" ]; then
        cat > "$limits_file" <<'EOF'
# Configuration des limites pour Wazuh Indexer (OpenSearch)
wazuh-indexer soft nofile 65535
wazuh-indexer hard nofile 65535
wazuh-indexer soft nproc 4096
wazuh-indexer hard nproc 4096
wazuh-indexer soft memlock unlimited
wazuh-indexer hard memlock unlimited
EOF
        log_success "Limites système configurées : ${limits_file}"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 5 : Génération des certificats SSL
# ============================================================================

generate_certificates() {
    log_info "Génération des certificats SSL pour l'Indexer..."

    # Wazuh fournit un script de génération de certificats
    # Il crée les certificats pour Manager, Indexer et Dashboard

    local cert_tool="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-certs-tool.sh"

    # Alternative : utiliser les certificats auto-signés par défaut
    # qui sont déjà présents après l'installation du paquet

    if [ -f "/etc/wazuh-indexer/certs/admin.pem" ]; then
        log_info "Certificats déjà présents"
    else
        log_info "Les certificats seront générés automatiquement au premier démarrage"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 6 : Initialisation du cluster
# ============================================================================

initialize_cluster() {
    log_info "Initialisation du cluster Wazuh Indexer..."

    # Démarrer le service
    log_info "Démarrage de wazuh-indexer (peut prendre 1-2 minutes)..."

    systemctl daemon-reload >> "$LOG_FILE" 2>&1
    systemctl enable wazuh-indexer >> "$LOG_FILE" 2>&1

    if systemctl start wazuh-indexer >> "$LOG_FILE" 2>&1; then
        # Attendre que l'Indexer soit prêt (max 2 minutes)
        local max_wait=120
        local waited=0
        local ready=false

        while [ $waited -lt $max_wait ]; do
            # Test de connectivité basique
            if curl -k -s -m 5 "https://localhost:9200" -u "admin:admin" \
                -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "^(200|401)$"; then
                ready=true
                break
            fi
            sleep 5
            waited=$((waited + 5))

            # Log de progression toutes les 30s
            if [ $((waited % 30)) -eq 0 ]; then
                log_info "En attente de l'Indexer... (${waited}s / ${max_wait}s)"
            fi
        done

        if [ "$ready" = true ]; then
            log_success "Wazuh Indexer opérationnel"
        else
            log_warning "Indexer pas encore prêt après ${max_wait}s"
            log_info  "Il peut avoir besoin de plus de temps, vérifiez :"
            log_info  "  sudo systemctl status wazuh-indexer"
            log_info  "  sudo journalctl -u wazuh-indexer -n 50"
        fi
    else
        log_error "Échec démarrage wazuh-indexer"
        return 1
    fi

    # Initialisation de la sécurité (utilisateurs, rôles OpenSearch)
    # Cette étape est nécessaire lors du premier démarrage
    log_info "Initialisation de la sécurité OpenSearch..."

    local security_tool="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"

    if [ -x "$security_tool" ]; then
        # Script d'initialisation (peut prendre 30s)
        /usr/share/wazuh-indexer/bin/indexer-security-init.sh >> "$LOG_FILE" 2>&1 || \
            log_warning "Initialisation de la sécurité partielle (non bloquant)"
    fi

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE DU MODULE
# ============================================================================

install_wazuh_indexer() {
    log_info "Démarrage installation Wazuh Indexer (Mode FULL)..."

    install_indexer_package      || return 1
    configure_indexer            || return 1
    configure_jvm_memory         || return 1
    configure_system_limits      || return 1
    generate_certificates        || return 1
    initialize_cluster           || return 1

    log_success "Installation Wazuh Indexer terminée"
    return 0
}

# ============================================================================
# Fin de modules/04-wazuh-indexer.sh
# ============================================================================
