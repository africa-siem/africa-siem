#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/01-system-prep.sh — Préparation système
# ============================================================================
#
# Ce module prépare le système avant l'installation des composants SIEM :
#   1. Mise à jour des paquets système
#   2. Installation des dépendances communes
#   3. Configuration du firewall UFW
#   4. Création du groupe siem-africa et des users
#   5. Création des répertoires avec permissions
#   6. Optimisations système (sysctl)
#
# ============================================================================

# ============================================================================
# ÉTAPE 1 : Mise à jour système
# ============================================================================

update_system() {
    log_info "Mise à jour de la liste des paquets..."

    # DEBIAN_FRONTEND=noninteractive : empêche apt de poser des questions
    # -y : accepte automatiquement toutes les confirmations
    if DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOG_FILE" 2>&1; then
        log_success "Liste des paquets mise à jour"
    else
        log_error "Échec mise à jour apt-get update"
        return 1
    fi

    return 0
}

# ============================================================================
# ÉTAPE 2 : Installation des dépendances
# ============================================================================

install_dependencies() {
    log_info "Installation des dépendances système..."

    # Paquets essentiels pour SIEM Africa, communs Ubuntu/Debian
    local packages=(
        curl
        wget
        gnupg
        gpg
        ca-certificates
        apt-transport-https
        lsb-release
        software-properties-common
        net-tools
        iputils-ping
        ufw
        tar
        gzip
        unzip
        rsyslog
    )

    if DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" >> "$LOG_FILE" 2>&1; then
        log_success "Dépendances installées (${#packages[@]} paquets)"
    else
        log_error "Échec installation des dépendances"
        log_info  "Consultez ${LOG_FILE}"
        return 1
    fi

    return 0
}

# ============================================================================
# ÉTAPE 3 : Configuration firewall
# ============================================================================

configure_firewall() {
    log_info "Configuration du firewall UFW..."

    # Règles par défaut : tout bloqué sauf SSH et ports SIEM
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1

    # SSH indispensable (sinon on se déconnecte au moment d'activer UFW)
    ufw allow 22/tcp comment "SSH Administration" >> "$LOG_FILE" 2>&1

    # Ports Wazuh Manager
    ufw allow 1514/tcp comment "Wazuh agents TCP" >> "$LOG_FILE" 2>&1
    ufw allow 1514/udp comment "Wazuh agents UDP" >> "$LOG_FILE" 2>&1
    ufw allow 1515/tcp comment "Wazuh enrollment" >> "$LOG_FILE" 2>&1
    ufw allow 55000/tcp comment "Wazuh API" >> "$LOG_FILE" 2>&1

    # Mode FULL : ports supplémentaires
    if [ "$INSTALL_MODE" = "full" ]; then
        ufw allow 9200/tcp comment "Wazuh Indexer" >> "$LOG_FILE" 2>&1
        ufw allow 443/tcp comment "Wazuh Dashboard HTTPS" >> "$LOG_FILE" 2>&1
    fi

    # Activation
    if ufw --force enable >> "$LOG_FILE" 2>&1; then
        log_success "Firewall UFW configuré et activé"
    else
        log_warning "Échec activation UFW (non bloquant)"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 4 : Optimisations système
# ============================================================================

optimize_system() {
    log_info "Application des optimisations système..."

    # vm.max_map_count : requis par OpenSearch (Wazuh Indexer)
    # Sans ça : "max virtual memory areas vm.max_map_count [65530] is too low"
    if ! grep -q "vm.max_map_count" /etc/sysctl.conf 2>/dev/null; then
        echo "vm.max_map_count=262144" >> /etc/sysctl.conf
        sysctl -p >> "$LOG_FILE" 2>&1
        log_success "vm.max_map_count configuré à 262144"
    else
        log_info "vm.max_map_count déjà configuré"
    fi

    # swappiness : réduire l'usage du swap (mieux pour SIEM)
    if ! grep -q "vm.swappiness" /etc/sysctl.conf 2>/dev/null; then
        echo "vm.swappiness=10" >> /etc/sysctl.conf
        sysctl -p >> "$LOG_FILE" 2>&1
        log_success "vm.swappiness configuré à 10"
    else
        log_info "vm.swappiness déjà configuré"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 5 : Timezone et NTP
# ============================================================================

ensure_timezone() {
    local current_tz
    current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")

    log_info "Fuseau horaire : ${current_tz}"

    # Activer NTP pour synchronisation horloge
    if command -v timedatectl >/dev/null 2>&1; then
        if timedatectl status 2>/dev/null | grep -q "System clock synchronized: no"; then
            log_info "Activation synchronisation NTP..."
            timedatectl set-ntp true >> "$LOG_FILE" 2>&1 || log_warning "Activation NTP échouée"
        fi
    fi

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

run_system_prep() {
    log_info "Démarrage de la préparation système..."

    update_system          || return 1
    install_dependencies   || return 1
    optimize_system        || return 1
    ensure_timezone        || return 1
    setup_module1_users    || return 1  # défini dans core/users.sh
    configure_firewall     || return 1

    log_success "Préparation système terminée"
    return 0
}

# ============================================================================
# Fin de modules/01-system-prep.sh
# ============================================================================
