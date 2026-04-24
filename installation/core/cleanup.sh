#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/cleanup.sh — Fonctions de détection & nettoyage d'installations
# ============================================================================
#
# Ce fichier contient TOUTES les fonctions de détection d'installation
# antérieure et de nettoyage propre. Chaque module d'installation l'appelle
# AVANT de commencer pour garantir qu'il installe sur un état propre.
#
# PRINCIPE :
#   Avant chaque install  → on cherche des traces d'une install précédente
#                           → si trouvée, on la supprime proprement
#                           → puis on installe fraîchement
#
# Usage dans les scripts modules/XX-*.sh :
#   source "${SCRIPT_DIR}/core/cleanup.sh"
#   cleanup_snort           # ou cleanup_wazuh, cleanup_wazuh_indexer, etc.
#
# Usage global (purge TOUT) :
#   cleanup_all
#
# ============================================================================

# ============================================================================
# SECTION 1 : NETTOYAGE SNORT
# ============================================================================

# --- cleanup_snort : Supprime proprement Snort ----------------------------
# Étapes :
#   1. Arrête le service Snort si actif
#   2. Désactive le service
#   3. Supprime le package apt
#   4. Supprime les fichiers de config
#   5. Supprime les logs
#   6. Supprime le fichier service systemd custom
cleanup_snort() {
    local found=0

    # Détection : le paquet est-il installé ?
    if dpkg -l 2>/dev/null | grep -qE "^ii\s+snort"; then
        found=1
    fi

    # Détection : des traces existent-elles sans le paquet ?
    if [ -d /etc/snort ] || [ -d /var/log/snort ] || \
       [ -f /etc/systemd/system/siem-africa-snort.service ] || \
       [ -f /etc/systemd/system/snort.service ]; then
        found=1
    fi

    if [ "$found" -eq 0 ]; then
        log_info "Snort : aucune installation antérieure détectée"
        return 0
    fi

    log_warning "Snort : installation antérieure détectée, nettoyage en cours..."

    # 1. Arrêter et désactiver le service
    systemctl stop snort 2>/dev/null
    systemctl stop siem-africa-snort 2>/dev/null
    systemctl disable snort 2>/dev/null
    systemctl disable siem-africa-snort 2>/dev/null

    # Tuer tout processus snort résiduel (au cas où)
    pkill -9 snort 2>/dev/null

    # 2. Supprimer les fichiers service systemd
    rm -f /etc/systemd/system/snort.service
    rm -f /etc/systemd/system/siem-africa-snort.service
    rm -f /lib/systemd/system/snort.service  2>/dev/null
    systemctl daemon-reload 2>/dev/null

    # 3. Désinstaller le paquet avec purge (retire aussi la config)
    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y snort snort-common snort-common-libraries snort-rules-default 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null

    # 4. Supprimer les répertoires résiduels
    rm -rf /etc/snort
    rm -rf /var/log/snort
    rm -rf /var/run/snort
    rm -f  /var/log/siem-africa/snort.pid

    log_success "Snort : nettoyage terminé"
    return 0
}

# ============================================================================
# SECTION 2 : NETTOYAGE WAZUH MANAGER
# ============================================================================

# --- cleanup_wazuh_manager : Supprime Wazuh Manager -----------------------
cleanup_wazuh_manager() {
    local found=0

    if dpkg -l 2>/dev/null | grep -qE "^ii\s+wazuh-manager"; then
        found=1
    fi
    if [ -d /var/ossec ]; then
        found=1
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q "wazuh-manager.service"; then
        found=1
    fi

    if [ "$found" -eq 0 ]; then
        log_info "Wazuh Manager : aucune installation antérieure détectée"
        return 0
    fi

    log_warning "Wazuh Manager : installation antérieure détectée, nettoyage en cours..."

    # 1. Arrêter le service (avec timeout car Wazuh peut traîner)
    systemctl stop wazuh-manager 2>/dev/null
    sleep 2

    # Tuer les processus ossec résiduels
    pkill -9 -f 'ossec-' 2>/dev/null
    pkill -9 -f 'wazuh-' 2>/dev/null

    # 2. Désactiver le service
    systemctl disable wazuh-manager 2>/dev/null

    # 3. Purger le paquet
    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y wazuh-manager 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null

    # 4. Supprimer les répertoires
    rm -rf /var/ossec
    rm -rf /var/log/wazuh-manager
    rm -rf /etc/wazuh-manager

    # 5. Nettoyer systemd
    systemctl daemon-reload 2>/dev/null
    systemctl reset-failed 2>/dev/null

    log_success "Wazuh Manager : nettoyage terminé"
    return 0
}

# ============================================================================
# SECTION 3 : NETTOYAGE WAZUH INDEXER
# ============================================================================

cleanup_wazuh_indexer() {
    local found=0

    if dpkg -l 2>/dev/null | grep -qE "^ii\s+wazuh-indexer"; then
        found=1
    fi
    if [ -d /var/lib/wazuh-indexer ] || [ -d /etc/wazuh-indexer ]; then
        found=1
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q "wazuh-indexer.service"; then
        found=1
    fi

    if [ "$found" -eq 0 ]; then
        log_info "Wazuh Indexer : aucune installation antérieure détectée"
        return 0
    fi

    log_warning "Wazuh Indexer : installation antérieure détectée, nettoyage en cours..."

    systemctl stop wazuh-indexer 2>/dev/null
    sleep 3
    pkill -9 -f 'wazuh-indexer' 2>/dev/null
    pkill -9 -f 'opensearch' 2>/dev/null

    systemctl disable wazuh-indexer 2>/dev/null

    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y wazuh-indexer 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null

    rm -rf /var/lib/wazuh-indexer
    rm -rf /var/log/wazuh-indexer
    rm -rf /etc/wazuh-indexer
    rm -rf /usr/share/wazuh-indexer

    systemctl daemon-reload 2>/dev/null

    log_success "Wazuh Indexer : nettoyage terminé"
    return 0
}

# ============================================================================
# SECTION 4 : NETTOYAGE WAZUH DASHBOARD
# ============================================================================

cleanup_wazuh_dashboard() {
    local found=0

    if dpkg -l 2>/dev/null | grep -qE "^ii\s+wazuh-dashboard"; then
        found=1
    fi
    if [ -d /var/lib/wazuh-dashboard ] || [ -d /etc/wazuh-dashboard ]; then
        found=1
    fi

    if [ "$found" -eq 0 ]; then
        log_info "Wazuh Dashboard : aucune installation antérieure détectée"
        return 0
    fi

    log_warning "Wazuh Dashboard : installation antérieure détectée, nettoyage en cours..."

    systemctl stop wazuh-dashboard 2>/dev/null
    sleep 2
    pkill -9 -f 'wazuh-dashboard' 2>/dev/null
    pkill -9 -f 'opensearch-dashboards' 2>/dev/null

    systemctl disable wazuh-dashboard 2>/dev/null

    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y wazuh-dashboard 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null

    rm -rf /var/lib/wazuh-dashboard
    rm -rf /var/log/wazuh-dashboard
    rm -rf /etc/wazuh-dashboard
    rm -rf /usr/share/wazuh-dashboard

    systemctl daemon-reload 2>/dev/null

    log_success "Wazuh Dashboard : nettoyage terminé"
    return 0
}

# ============================================================================
# SECTION 5 : NETTOYAGE FILEBEAT (utilisé par Wazuh)
# ============================================================================

cleanup_filebeat() {
    if ! dpkg -l 2>/dev/null | grep -qE "^ii\s+filebeat"; then
        if [ ! -d /etc/filebeat ] && [ ! -d /var/lib/filebeat ]; then
            return 0
        fi
    fi

    log_warning "Filebeat : nettoyage en cours..."
    systemctl stop filebeat 2>/dev/null
    pkill -9 -f 'filebeat' 2>/dev/null
    systemctl disable filebeat 2>/dev/null

    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y filebeat 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null

    rm -rf /etc/filebeat
    rm -rf /var/lib/filebeat
    rm -rf /var/log/filebeat
    rm -rf /usr/share/filebeat

    systemctl daemon-reload 2>/dev/null
    log_success "Filebeat : nettoyage terminé"
}

# ============================================================================
# SECTION 6 : NETTOYAGE DÉPÔTS APT WAZUH
# ============================================================================

# --- cleanup_wazuh_repo : Supprime le dépôt apt et la clé GPG -------------
# À appeler UNIQUEMENT si on veut repartir de zéro (pas lors d'un reinstall
# simple, car on veut garder le dépôt pour réinstaller).
cleanup_wazuh_repo() {
    log_info "Nettoyage du dépôt APT Wazuh..."
    rm -f /etc/apt/sources.list.d/wazuh.list
    rm -f /usr/share/keyrings/wazuh.gpg
    rm -f /etc/apt/trusted.gpg.d/wazuh.gpg 2>/dev/null
    apt-get update 2>/dev/null
    log_success "Dépôt APT Wazuh nettoyé"
}

# ============================================================================
# SECTION 7 : NETTOYAGE FICHIERS D'ÉTAT SIEM AFRICA
# ============================================================================

# --- cleanup_siem_state_files : Supprime les fichiers d'état --------------
# Supprime le state.yaml, RESUME.txt, logs, secrets.
# ATTENTION : supprime aussi les mots de passe stockés !
cleanup_siem_state_files() {
    local found=0

    if [ -f /etc/siem-africa/siem-africa.state.yaml ]; then found=1; fi
    if [ -f /etc/siem-africa/RESUME.txt ]; then found=1; fi
    if [ -d /etc/siem-africa/secrets ]; then found=1; fi

    if [ "$found" -eq 0 ]; then
        log_info "Fichiers d'état SIEM : aucun fichier antérieur"
        return 0
    fi

    log_warning "Fichiers d'état SIEM : suppression en cours..."

    # Backup avant suppression (par sécurité)
    local backup_dir="/var/backups/siem-africa-old-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir" 2>/dev/null
    cp -r /etc/siem-africa "$backup_dir/" 2>/dev/null
    log_info "Backup créé : ${backup_dir}"

    rm -rf /etc/siem-africa
    rm -rf /var/log/siem-africa
    rm -rf /var/lib/siem-africa
    rm -rf /opt/siem-africa

    log_success "Fichiers d'état SIEM : supprimés"
    return 0
}

# ============================================================================
# SECTION 8 : NETTOYAGE USERS ET GROUPE
# ============================================================================

# --- cleanup_siem_users : Supprime les users et le groupe SIEM ------------
# À n'appeler que pour un reset complet (uninstall total).
cleanup_siem_users() {
    local users=("siem-ids" "siem-db" "siem-agent" "siem-web")

    for user in "${users[@]}"; do
        if id "$user" >/dev/null 2>&1; then
            userdel "$user" 2>/dev/null && log_info "User ${user} supprimé"
        fi
    done

    if getent group siem-africa >/dev/null 2>&1; then
        groupdel siem-africa 2>/dev/null && log_info "Groupe siem-africa supprimé"
    fi
}

# ============================================================================
# SECTION 9 : FONCTION MAÎTRE — cleanup_all
# ============================================================================

# --- cleanup_all : Purge TOUT (utilisé par clean-install.sh) --------------
# Effectue un reset complet AVANT réinstallation.
# Ordre important : du plus "dépendant" au plus "racine"
cleanup_all() {
    log_banner "PURGE COMPLÈTE SIEM AFRICA"

    log_info "Arrêt de tous les services en cours..."

    # Ordre de suppression : dashboard → indexer → manager → snort
    # (inverse de l'ordre d'installation pour éviter les dépendances)
    cleanup_wazuh_dashboard
    cleanup_wazuh_indexer
    cleanup_filebeat
    cleanup_wazuh_manager
    cleanup_snort

    # Fichiers d'état SIEM Africa
    cleanup_siem_state_files

    # Users (on garde le groupe si d'autres modules tournent)
    # Pour un uninstall TOTAL, ajouter cleanup_siem_users

    # Mise à jour apt pour nettoyer le cache
    apt-get update 2>/dev/null
    apt-get autoclean 2>/dev/null

    log_success "Purge complète terminée"
    echo ""
}

# ============================================================================
# SECTION 10 : FONCTION DE VÉRIFICATION POST-CLEANUP
# ============================================================================

# --- verify_cleanup : Vérifie qu'il ne reste aucune trace ------------------
# Retourne 0 si le système est propre, 1 sinon.
verify_cleanup() {
    local residues=()

    # Vérifier les paquets
    for pkg in snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
        if dpkg -l 2>/dev/null | grep -qE "^ii\s+${pkg}"; then
            residues+=("Paquet ${pkg} encore installé")
        fi
    done

    # Vérifier les dossiers
    local dirs=(
        "/var/ossec"
        "/etc/snort"
        "/var/lib/wazuh-indexer"
        "/var/lib/wazuh-dashboard"
        "/etc/siem-africa"
    )
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            residues+=("Dossier ${dir} existe encore")
        fi
    done

    # Vérifier les services systemd
    for svc in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl list-unit-files 2>/dev/null | grep -q "${svc}.service"; then
            residues+=("Service ${svc} encore enregistré")
        fi
    done

    if [ ${#residues[@]} -eq 0 ]; then
        log_success "Vérification OK : système propre"
        return 0
    else
        log_warning "Résidus détectés :"
        for r in "${residues[@]}"; do
            log_warning "  • $r"
        done
        return 1
    fi
}

# ============================================================================
# Fin de core/cleanup.sh
# ============================================================================
