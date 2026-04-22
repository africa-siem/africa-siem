#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1 / Étape 2
# modules/02-snort.sh — Installation et configuration de Snort IDS
# ============================================================================
#
# Ce script installe Snort 2.9 et le configure en mode IDS passif avec
# les Community Rules Emerging Threats (gratuit, 30 000+ règles).
#
# Étapes :
#   1. Installation du paquet snort via apt
#   2. Configuration de l'interface à monitorer
#   3. Configuration du réseau HOME_NET
#   4. Téléchargement des règles Emerging Threats Open
#   5. Installation du cron de mise à jour hebdomadaire
#   6. Test de la configuration
#   7. Activation du service systemd
#
# Choix architectural :
#   Les règles custom SIEM Africa NE SONT PAS dans Snort.
#   Elles seront dans le Module 2 (base de données SQLite).
#   Module 1 = uniquement Community Rules.
#
# ============================================================================

# --- Chargement du contexte ------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/os-detect.sh"

# --- Variables ------------------------------------------------------------
readonly SNORT_CONF="/etc/snort/snort.conf"
readonly SNORT_LOG_DIR="/var/log/snort"
readonly SNORT_RULES_DIR="/etc/snort/rules"

# ============================================================================
# FONCTION 1 : Calcul du réseau CIDR
# ============================================================================

get_network_cidr() {
    if [ -z "$DETECTED_INTERFACE" ]; then
        DETECTED_INTERFACE=$(ip -o link show | grep "state UP" | grep -v "lo:" | awk -F': ' '{print $2}' | head -1)
    fi

    local ip_cidr
    ip_cidr=$(ip -o -4 addr show "$DETECTED_INTERFACE" 2>/dev/null | awk '{print $4}' | head -1)

    if [ -z "$ip_cidr" ]; then
        log_warning "Impossible de détecter le CIDR, utilisation de 192.168.0.0/16"
        echo "192.168.0.0/16"
        return 1
    fi

    local ip_only
    ip_only=$(echo "$ip_cidr" | cut -d'/' -f1)

    local network
    network=$(echo "$ip_only" | awk -F'.' '{print $1"."$2"."$3".0"}')

    echo "${network}/24"
    return 0
}

# ============================================================================
# FONCTION 2 : Installation du paquet Snort
# ============================================================================

install_snort_package() {
    log_info "Installation du paquet Snort..."

    echo "snort snort/address_range string $(get_network_cidr)" | debconf-set-selections
    echo "snort snort/interface string ${DETECTED_INTERFACE:-any}" | debconf-set-selections

    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq snort 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        log_error "Échec de l'installation de Snort"
        return 1
    fi

    if ! command -v snort >/dev/null 2>&1; then
        log_error "Snort installé mais binaire introuvable"
        return 1
    fi

    local snort_version
    snort_version=$(snort -V 2>&1 | grep -oP "Version \K[0-9.]+" | head -1)
    log_success "Snort installé (version ${snort_version:-inconnue})"

    return 0
}

# ============================================================================
# FONCTION 3 : Configuration de Snort
# ============================================================================

configure_snort() {
    log_info "Configuration de Snort..."

    if [ -f "$SNORT_CONF" ] && [ ! -f "${SNORT_CONF}.original" ]; then
        cp "$SNORT_CONF" "${SNORT_CONF}.original"
        log_info "Backup : ${SNORT_CONF}.original"
    fi

    local home_net
    home_net=$(get_network_cidr)

    log_info "Réseau HOME_NET : ${home_net}"
    log_info "Interface : ${DETECTED_INTERFACE}"

    if grep -q "^ipvar HOME_NET" "$SNORT_CONF"; then
        sed -i "s|^ipvar HOME_NET.*|ipvar HOME_NET ${home_net}|" "$SNORT_CONF"
    else
        sed -i "1i\ipvar HOME_NET ${home_net}" "$SNORT_CONF"
    fi

    if grep -q "^ipvar EXTERNAL_NET" "$SNORT_CONF"; then
        sed -i "s|^ipvar EXTERNAL_NET.*|ipvar EXTERNAL_NET !\$HOME_NET|" "$SNORT_CONF"
    fi

    mkdir -p "$SNORT_LOG_DIR"
    chown snort:snort "$SNORT_LOG_DIR" 2>/dev/null || chown root:adm "$SNORT_LOG_DIR"
    chmod 755 "$SNORT_LOG_DIR"

    mkdir -p "$SNORT_RULES_DIR"

    log_success "Snort configuré"
    return 0
}

# ============================================================================
# FONCTION 4 : Téléchargement des Community Rules
# ============================================================================

# Appelle scripts/update-rules.sh qui télécharge Emerging Threats Open.
download_community_rules() {
    log_info "Téléchargement des Community Rules depuis Emerging Threats..."
    log_info "Source : https://rules.emergingthreats.net (GRATUIT)"

    local update_script="${SCRIPT_DIR}/scripts/update-rules.sh"

    if [ ! -f "$update_script" ]; then
        log_error "Script update-rules.sh introuvable"
        return 1
    fi

    chmod +x "$update_script"

    if ! bash "$update_script"; then
        log_warning "Échec du téléchargement des règles"
        log_info "Snort fonctionnera mais sans règles communautaires"
        log_info "Réessayer plus tard : sudo ${update_script}"
        return 0
    fi

    log_success "Community Rules installées"
    return 0
}

# ============================================================================
# FONCTION 5 : Ajout de l'include des règles dans snort.conf
# ============================================================================

configure_rules_include() {
    log_info "Configuration des inclusions de règles..."

    local includes_file="/etc/snort/rules-includes.conf"

    if ! grep -q "rules-includes.conf" "$SNORT_CONF"; then
        echo "" >> "$SNORT_CONF"
        echo "# SIEM AFRICA - Inclusion des règles communautaires" >> "$SNORT_CONF"
        echo "include ${includes_file}" >> "$SNORT_CONF"
        log_success "Include ajouté à snort.conf"
    else
        log_info "Include déjà présent"
    fi

    return 0
}

# ============================================================================
# FONCTION 6 : Installation du cron de mise à jour hebdomadaire
# ============================================================================

install_update_cron() {
    log_info "Installation du cron de mise à jour..."

    local cron_source="${SCRIPT_DIR}/config/cron/siem-africa-rules-update"
    local cron_target="/etc/cron.d/siem-africa-rules-update"

    if [ ! -f "$cron_source" ]; then
        log_warning "Fichier cron introuvable"
        return 0
    fi

    cp "$cron_source" "$cron_target"
    chown root:root "$cron_target"
    chmod 644 "$cron_target"

    systemctl reload cron 2>/dev/null || service cron reload 2>/dev/null || true

    log_success "Cron installé : mise à jour chaque lundi à 3h"
    return 0
}

# ============================================================================
# FONCTION 7 : Test de la configuration
# ============================================================================

test_snort_config() {
    log_info "Test de la configuration Snort..."

    local test_output
    test_output=$(snort -T -c "$SNORT_CONF" 2>&1)

    if echo "$test_output" | grep -q "Snort successfully validated"; then
        log_success "Configuration Snort valide"
    else
        log_warning "Configuration Snort a des avertissements (non bloquant)"
    fi

    return 0
}

# ============================================================================
# FONCTION 8 : Service systemd
# ============================================================================

configure_snort_service() {
    log_info "Configuration du service systemd Snort..."

    if ! systemctl list-unit-files | grep -q "snort.service"; then
        log_info "Création manuelle du service..."

        local service_template="${SCRIPT_DIR}/config/systemd/snort.service"

        if [ -f "$service_template" ]; then
            cp "$service_template" /etc/systemd/system/snort.service
        else
            cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort NIDS Daemon
After=network.target

[Service]
Type=simple
User=snort
Group=snort
ExecStart=/usr/sbin/snort -D -c ${SNORT_CONF} -i ${DETECTED_INTERFACE} -l ${SNORT_LOG_DIR}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        fi

        systemctl daemon-reload
    fi

    # Variables d'environnement
    cat > /etc/default/snort <<EOF
# SIEM AFRICA - Variables Snort
INTERFACE=${DETECTED_INTERFACE:-eth0}
MODE=passive
PROMISC=yes
EOF

    systemctl enable snort.service 2>&1 | tee -a "$LOG_FILE" >/dev/null
    log_success "Service Snort activé au démarrage"

    log_info "Démarrage de Snort..."
    if systemctl start snort.service 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        sleep 3
        if systemctl is-active --quiet snort.service; then
            log_success "Service Snort actif"
        else
            log_warning "Snort démarré mais pas actif"
        fi
    else
        log_warning "Impossible de démarrer Snort"
    fi

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

main() {
    log_info "=== Étape : Installation de Snort IDS ==="

    install_snort_package    || die "Échec installation Snort"
    configure_snort          || die "Échec configuration Snort"
    download_community_rules # non bloquant
    configure_rules_include  # non bloquant
    install_update_cron      # non bloquant
    test_snort_config        # non bloquant
    configure_snort_service  # non bloquant

    log_success "Snort IDS installé avec succès ✓"
    log_info ""
    log_info "📋 Règles : Emerging Threats Open (communautaires, gratuites)"
    log_info "🔄 Mise à jour auto : chaque lundi à 3h"
    log_info "🛠️  Mise à jour manuelle :"
    log_info "    sudo /opt/siem-africa/module-1/scripts/update-rules.sh"
    log_info ""
    log_info "ℹ️  Les règles custom SIEM Africa (mapping MITRE, attaques"
    log_info "   spécifiques) seront gérées via le Module 2 (base de données)"
    log_info ""

    return 0
}

main "$@"
