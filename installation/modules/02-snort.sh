#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/02-snort.sh — Installation Snort IDS (avec auto-cleanup)
# ============================================================================
#
# Ce script installe Snort IDS en mode passif sur l'interface réseau
# détectée automatiquement.
#
# ✨ NOUVEAUTÉ V2.1 : auto-cleanup avant installation
#    Si une installation antérieure est détectée, elle est automatiquement
#    purgée avant la nouvelle installation.
#
# ============================================================================

# --- Répertoire racine du module (niveau au-dessus de modules/) -----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Chargement des fonctions utilitaires --------------------------------
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/langue.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/os-detect.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/cleanup.sh"    # ✨ NOUVEAU

# ============================================================================
# INSTALLATION DE SNORT
# ============================================================================

install_snort() {
    log_step "5/8" "$(t step_snort)"

    # ========================================================================
    # ✨ ÉTAPE NOUVEAU : Auto-cleanup avant installation
    # ========================================================================
    # Si Snort est déjà installé (ou partiellement), on purge avant.
    # Cela résout le problème "installation qui plante à cause de résidus".
    cleanup_snort

    # Pause de 2 secondes pour laisser le système se stabiliser après cleanup
    sleep 2

    # ========================================================================
    # Installation fraîche
    # ========================================================================

    log_info "Mise à jour de la liste des paquets..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null

    log_info "Installation de Snort 2.9 et ses dépendances..."

    # Pré-réponse aux prompts debconf (Snort demande l'interface réseau en install)
    # On force l'interface détectée automatiquement
    echo "snort snort/address_range string any/any" | debconf-set-selections
    echo "snort snort/interface string ${DETECTED_INTERFACE:-any}" | debconf-set-selections
    echo "snort snort/startup string boot" | debconf-set-selections

    # Installation avec DEBIAN_FRONTEND non-interactif pour éviter les prompts bloquants
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        snort snort-common snort-rules-default 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Échec installation Snort via apt"
        log_info "Consultez les détails : ${LOG_FILE}"
        return 1
    fi

    # Vérification que Snort est bien installé
    if ! command -v snort >/dev/null 2>&1; then
        log_error "Snort n'a pas été installé correctement (binaire introuvable)"
        return 1
    fi

    log_success "Snort installé (version: $(snort -V 2>&1 | grep Version | awk '{print $3}'))"

    # ========================================================================
    # Configuration de Snort
    # ========================================================================

    log_info "Configuration de Snort pour l'interface ${DETECTED_INTERFACE}..."

    # Créer les dossiers nécessaires
    mkdir -p /etc/snort/rules
    mkdir -p /var/log/snort
    mkdir -p /var/log/siem-africa

    # Configurer les permissions (user snort créé par le paquet)
    if id snort >/dev/null 2>&1; then
        chown -R snort:snort /var/log/snort
        # Ajouter snort au groupe siem-africa pour partage de logs
        if getent group siem-africa >/dev/null 2>&1; then
            usermod -aG siem-africa snort
            log_info "User 'snort' ajouté au groupe 'siem-africa'"
        fi
    fi

    # Modifier la config pour utiliser la bonne interface
    if [ -f /etc/snort/snort.debian.conf ]; then
        sed -i "s/^DEBIAN_SNORT_INTERFACE=.*/DEBIAN_SNORT_INTERFACE=\"${DETECTED_INTERFACE}\"/" \
            /etc/snort/snort.debian.conf
    fi

    # Copier le template de config custom si présent
    if [ -f "${SCRIPT_DIR}/config/snort/snort.conf.template" ]; then
        # Remplacement des variables dans le template
        sed -e "s|{{INTERFACE}}|${DETECTED_INTERFACE}|g" \
            -e "s|{{HOME_NET}}|$(echo "$DETECTED_IP" | cut -d'.' -f1-3).0/24|g" \
            "${SCRIPT_DIR}/config/snort/snort.conf.template" > /etc/snort/siem-africa.conf
        log_info "Config SIEM Africa installée : /etc/snort/siem-africa.conf"
    fi

    # ========================================================================
    # Service systemd custom (remplace celui par défaut du paquet)
    # ========================================================================

    log_info "Installation du service systemd personnalisé..."

    if [ -f "${SCRIPT_DIR}/config/systemd/siem-africa-snort.service" ]; then
        cp "${SCRIPT_DIR}/config/systemd/siem-africa-snort.service" \
           /etc/systemd/system/snort.service
    else
        # Fallback : génération inline d'un service minimal
        cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=SIEM Africa - Snort IDS
After=network.target

[Service]
Type=forking
PIDFile=/var/log/siem-africa/snort.pid
ExecStartPre=/bin/mkdir -p /var/log/siem-africa
ExecStart=/usr/sbin/snort -D -i ${DETECTED_INTERFACE} -c /etc/snort/snort.conf -l /var/log/snort
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload

    # ========================================================================
    # Démarrage du service
    # ========================================================================

    log_info "Démarrage de Snort..."

    if systemctl enable snort >/dev/null 2>&1; then
        log_success "Service Snort activé au démarrage"
    fi

    if ! systemctl start snort; then
        log_error "Snort n'a pas démarré. Diagnostic :"
        systemctl status snort --no-pager | tee -a "$LOG_FILE"
        log_info "Commandes de debug :"
        log_info "  sudo journalctl -u snort -n 50"
        log_info "  sudo snort -T -c /etc/snort/snort.conf  (test config)"
        return 1
    fi

    # Attendre 3 secondes et vérifier que le service tourne toujours
    sleep 3
    if ! systemctl is-active --quiet snort; then
        log_error "Snort a démarré puis s'est arrêté. Vérifiez la config."
        systemctl status snort --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    log_success "Snort est actif et surveille l'interface ${DETECTED_INTERFACE}"
    return 0
}

# ============================================================================
# POINT D'ENTRÉE (si le script est exécuté directement pour debug)
# ============================================================================

# Si ce script est sourcé par un autre, on ne fait rien ici.
# Si il est exécuté directement (./02-snort.sh), on lance install_snort.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    log_init
    install_snort
fi

# ============================================================================
# Fin de modules/02-snort.sh
# ============================================================================
