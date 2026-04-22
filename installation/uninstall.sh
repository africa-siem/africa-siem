#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# uninstall.sh — Désinstallation propre du Module 1
# ============================================================================
#
# Ce script désinstalle COMPLÈTEMENT le Module 1 :
#   1. Arrête tous les services (Snort, Wazuh)
#   2. Désinstalle les paquets (snort, wazuh-*)
#   3. Supprime les fichiers de configuration
#   4. Supprime les utilisateurs système créés
#   5. Conserve les logs pour audit (optionnel : tout supprimer avec --purge)
#
# Usage :
#   sudo ./uninstall.sh              # Désinstallation standard (conserve logs)
#   sudo ./uninstall.sh --purge      # Tout supprimer (y compris logs)
#   sudo ./uninstall.sh --force      # Ne demande pas confirmation
#
# ⚠️  ATTENTION : Cette action est IRRÉVERSIBLE.
#
# ============================================================================

# --- Répertoire du script -------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Chargement des fonctions utilitaires --------------------------------
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/users.sh"

# --- Variables de contrôle ------------------------------------------------
PURGE_MODE=false
FORCE_MODE=false

# --- Parse des arguments --------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --purge)
            PURGE_MODE=true
            ;;
        --force)
            FORCE_MODE=true
            ;;
        --help|-h)
            echo "Usage: sudo ./uninstall.sh [--purge] [--force]"
            echo ""
            echo "Options:"
            echo "  --purge   Supprime TOUT (y compris les logs)"
            echo "  --force   Ne demande pas de confirmation"
            echo "  --help    Affiche cette aide"
            exit 0
            ;;
    esac
done

# ============================================================================
# FONCTION : Confirmation utilisateur
# ============================================================================

ask_uninstall_confirmation() {
    if [ "$FORCE_MODE" = "true" ]; then
        return 0
    fi

    clear
    log_banner "⚠️  DÉSINSTALLATION SIEM AFRICA - MODULE 1"

    echo ""
    echo -e "  ${COLOR_YELLOW}Vous êtes sur le point de DÉSINSTALLER le Module 1 :${COLOR_RESET}"
    echo ""
    echo "    • Services arrêtés : Snort, Wazuh Manager"
    if systemctl list-unit-files | grep -q "wazuh-indexer"; then
        echo "    • Services arrêtés : Wazuh Indexer, Wazuh Dashboard"
    fi
    echo "    • Paquets désinstallés : snort, wazuh-manager, wazuh-indexer, wazuh-dashboard"
    echo "    • Fichiers supprimés : /etc/snort, /var/ossec, /etc/siem-africa"
    echo "    • Users supprimés : siem-ids"

    if [ "$PURGE_MODE" = "true" ]; then
        echo ""
        echo -e "    ${COLOR_RED}⚠️  MODE PURGE ACTIVÉ :${COLOR_RESET}"
        echo "      • /var/log/siem-africa SERA SUPPRIMÉ"
        echo "      • /var/log/snort SERA SUPPRIMÉ"
        echo "      • /var/backups/siem-africa SERA SUPPRIMÉ"
    fi

    echo ""
    echo -e "  ${COLOR_RED}⚠️  Cette action est IRRÉVERSIBLE.${COLOR_RESET}"
    echo ""

    if ! ask_confirmation "Êtes-vous VRAIMENT sûr de vouloir continuer ?"; then
        log_info "Désinstallation annulée."
        exit 0
    fi

    echo ""
    if ! ask_confirmation "Dernière confirmation : continuer la désinstallation ?"; then
        log_info "Désinstallation annulée."
        exit 0
    fi

    return 0
}

# ============================================================================
# FONCTION : Arrêt des services
# ============================================================================

stop_services() {
    log_step "1/6" "Arrêt des services"

    local services=(
        "wazuh-dashboard"
        "wazuh-indexer"
        "wazuh-manager"
        "snort"
    )

    for service in "${services[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "${service}.service"; then
            log_info "Arrêt de ${service}..."

            # Désactiver au boot
            systemctl disable "${service}.service" 2>/dev/null || true

            # Arrêter
            if systemctl is-active --quiet "${service}.service" 2>/dev/null; then
                systemctl stop "${service}.service" 2>/dev/null || true
            fi

            log_success "${service} arrêté"
        fi
    done

    return 0
}

# ============================================================================
# FONCTION : Désinstallation des paquets
# ============================================================================

uninstall_packages() {
    log_step "2/6" "Désinstallation des paquets"

    local packages=(
        "wazuh-dashboard"
        "wazuh-indexer"
        "wazuh-manager"
        "snort"
        "snort-common"
        "snort-common-libraries"
        "snort-doc"
        "snort-rules-default"
    )

    for pkg in "${packages[@]}"; do
        if dpkg -l 2>/dev/null | grep -qE "^ii\s+${pkg}\s"; then
            log_info "Désinstallation de ${pkg}..."
            DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "$pkg" 2>&1 | tee -a "$LOG_FILE" >/dev/null || true
            log_success "${pkg} désinstallé"
        fi
    done

    # Nettoyage des dépendances orphelines
    log_info "Nettoyage des dépendances orphelines..."
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>&1 | tee -a "$LOG_FILE" >/dev/null

    return 0
}

# ============================================================================
# FONCTION : Suppression des dépôts
# ============================================================================

remove_repositories() {
    log_step "3/6" "Suppression des dépôts externes"

    # Dépôt Wazuh
    if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
        rm -f /etc/apt/sources.list.d/wazuh.list
        log_success "Dépôt Wazuh supprimé"
    fi

    # Clé GPG Wazuh
    if [ -f /usr/share/keyrings/wazuh.gpg ]; then
        rm -f /usr/share/keyrings/wazuh.gpg
        log_success "Clé GPG Wazuh supprimée"
    fi

    # Mettre à jour la liste des paquets
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null

    return 0
}

# ============================================================================
# FONCTION : Suppression des fichiers et dossiers
# ============================================================================

remove_files() {
    log_step "4/6" "Suppression des fichiers et dossiers"

    # Dossiers de configuration
    local config_dirs=(
        "/etc/snort"
        "/etc/wazuh-indexer"
        "/etc/wazuh-dashboard"
        "/etc/siem-africa"
        "/var/ossec"
        "/var/lib/wazuh-indexer"
        "/var/lib/wazuh-dashboard"
        "/opt/siem-africa"
    )

    for dir in "${config_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log_info "Suppression de ${dir}..."
            rm -rf "$dir"
            log_success "${dir} supprimé"
        fi
    done

    # Service systemd custom
    if [ -f /etc/systemd/system/snort.service ]; then
        rm -f /etc/systemd/system/snort.service
        log_info "Service systemd snort supprimé"
    fi

    # Cron
    if [ -f /etc/cron.d/siem-africa-rules-update ]; then
        rm -f /etc/cron.d/siem-africa-rules-update
        log_info "Cron supprimé"
    fi

    # Variables d'environnement
    if [ -f /etc/default/snort ]; then
        rm -f /etc/default/snort
    fi

    # Recharger systemd
    systemctl daemon-reload

    # Si mode PURGE, on supprime aussi les logs et backups
    if [ "$PURGE_MODE" = "true" ]; then
        log_info "Mode PURGE : suppression des logs..."

        rm -rf /var/log/snort
        rm -rf /var/log/siem-africa
        rm -rf /var/log/wazuh-indexer
        rm -rf /var/log/wazuh-dashboard
        rm -rf /var/backups/siem-africa

        log_success "Logs et backups supprimés"
    else
        log_info "Logs conservés dans :"
        log_info "  /var/log/siem-africa (si existe)"
        log_info "  /var/log/snort (si existe)"
        log_info "Pour les supprimer : relancer avec --purge"
    fi

    return 0
}

# ============================================================================
# FONCTION : Suppression des utilisateurs système
# ============================================================================

remove_users() {
    log_step "5/6" "Suppression des utilisateurs système"

    # Users créés par SIEM Africa Module 1
    local users_to_remove=("siem-ids")

    for user in "${users_to_remove[@]}"; do
        if user_exists "$user"; then
            log_info "Suppression du user ${user}..."
            userdel "$user" 2>/dev/null || log_warning "Échec suppression user ${user}"
        fi
    done

    # Users créés par les paquets (snort, wazuh)
    # Ces users sont généralement supprimés par apt-get remove --purge
    # Mais on vérifie
    for user in snort wazuh wazuh-indexer wazuh-dashboard; do
        if user_exists "$user"; then
            log_info "Suppression du user ${user}..."
            userdel "$user" 2>/dev/null || true
        fi
    done

    # Suppression du groupe siem-africa
    # Seulement si aucun autre user n'est dedans (Module 2, 3, 4 non installés)
    if group_exists "$SIEM_GROUP"; then
        local remaining_users
        remaining_users=$(getent group "$SIEM_GROUP" | cut -d: -f4)

        if [ -z "$remaining_users" ]; then
            groupdel "$SIEM_GROUP" 2>/dev/null || true
            log_success "Groupe ${SIEM_GROUP} supprimé"
        else
            log_warning "Groupe ${SIEM_GROUP} conservé (des users en dépendent : ${remaining_users})"
        fi
    fi

    return 0
}

# ============================================================================
# FONCTION : Nettoyage final
# ============================================================================

final_cleanup() {
    log_step "6/6" "Nettoyage final"

    # Fermeture des ports firewall
    log_info "Suppression des règles UFW SIEM Africa..."

    for port in 1514 1515 55000 9200 443; do
        ufw delete allow "$port/tcp" 2>/dev/null || true
        ufw delete allow "$port/udp" 2>/dev/null || true
    done

    log_success "Règles UFW nettoyées"

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

main() {
    # Vérification root
    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ Ce script doit être exécuté en tant que root (utilisez sudo)"
        exit 1
    fi

    # Initialisation du log
    log_init

    # Confirmation
    ask_uninstall_confirmation

    log_banner "DÉSINSTALLATION EN COURS"

    stop_services          # non bloquant
    uninstall_packages     # non bloquant
    remove_repositories    # non bloquant
    remove_files           # non bloquant
    remove_users           # non bloquant
    final_cleanup          # non bloquant

    log_separator
    log_banner "✅ DÉSINSTALLATION TERMINÉE"

    echo ""
    log_info "Le Module 1 a été désinstallé avec succès."

    if [ "$PURGE_MODE" = "false" ]; then
        log_info ""
        log_info "Les logs et sauvegardes ont été conservés :"
        [ -d /var/log/siem-africa ] && log_info "  /var/log/siem-africa"
        [ -d /var/log/snort ] && log_info "  /var/log/snort"
        [ -d /var/backups/siem-africa ] && log_info "  /var/backups/siem-africa"
        log_info ""
        log_info "Pour les supprimer : sudo ./uninstall.sh --purge"
    fi

    log_info ""
    log_info "Pour réinstaller : sudo ./install.sh"
    echo ""

    return 0
}

# Gestion Ctrl+C
trap 'log_warning "Désinstallation interrompue"; exit 130' INT TERM

# Lancement
main "$@"
