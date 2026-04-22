#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/prerequis.sh — Vérifications des prérequis système
# ============================================================================
#
# Ce fichier vérifie tous les prérequis avant l'installation.
# Si UN SEUL prérequis échoue, l'installation s'arrête avec un message clair
# et une solution proposée à l'utilisateur.
#
# Vérifications effectuées :
#   1. Droits root (sudo)
#   2. OS supporté (géré par os-detect.sh, appelé ici)
#   3. Connexion internet
#   4. RAM suffisante (4 GB lite / 8 GB full)
#   5. Espace disque (50 GB minimum)
#   6. Interface réseau active
#   7. Ports requis disponibles
#   8. Absence d'installation corrompue
#
# Utilisation :
#   source core/prerequis.sh
#   check_all_prerequisites "lite"   # ou "full"
#
# ============================================================================

# --- Valeurs minimales requises -------------------------------------------
# Ces valeurs peuvent être ajustées selon l'évolution des besoins.
readonly MIN_RAM_LITE_GB=4
readonly MIN_RAM_FULL_GB=8
readonly MIN_DISK_GB=50

# Ports utilisés par SIEM Africa (doivent être libres)
readonly REQUIRED_PORTS_LITE=("1514" "1515" "55000")
readonly REQUIRED_PORTS_FULL=("1514" "1515" "55000" "9200" "443")

# ============================================================================
# VÉRIFICATION 1 : Droits root
# ============================================================================

# --- check_root : Vérifie que le script tourne en tant que root -----------
# Retour : 0 si root, 1 sinon
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "$(t err_not_root)"
        log_info  "Solution : Relancez avec 'sudo ./install.sh'"
        return 1
    fi
    log_success "$(t check_root)"
    return 0
}

# ============================================================================
# VÉRIFICATION 2 : Connexion internet
# ============================================================================

# --- check_internet : Vérifie la connectivité internet --------------------
# Teste la connexion vers plusieurs serveurs pour fiabilité.
# Tente d'abord le DNS (8.8.8.8), puis un ping HTTP.
check_internet() {
    local test_hosts=("8.8.8.8" "1.1.1.1" "packages.wazuh.com")
    local success=0

    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 3 "$host" >/dev/null 2>&1; then
            success=1
            break
        fi
    done

    if [ "$success" -eq 0 ]; then
        log_error "$(t err_no_internet)"
        log_info  "Solution : Vérifiez votre connexion réseau et le DNS"
        log_info  "  1. ip a       (vérifier l'IP)"
        log_info  "  2. ping 8.8.8.8  (test de connectivité)"
        log_info  "  3. cat /etc/resolv.conf  (vérifier le DNS)"
        return 1
    fi

    log_success "$(t check_internet)"
    return 0
}

# ============================================================================
# VÉRIFICATION 3 : RAM suffisante
# ============================================================================

# --- check_ram : Vérifie la RAM disponible --------------------------------
# Argument : $1 = "lite" ou "full"
check_ram() {
    local mode=$1
    local required_gb

    if [ "$mode" = "full" ]; then
        required_gb=$MIN_RAM_FULL_GB
    else
        required_gb=$MIN_RAM_LITE_GB
    fi

    # /proc/meminfo donne la RAM totale en kB
    # On la convertit en GB pour comparaison
    local total_kb
    total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_gb=$(( total_kb / 1024 / 1024 ))

    # On ajoute 1 de tolérance (ex: 3.9 GB doit passer pour 4 GB requis)
    # Car la RAM affichée est souvent légèrement inférieure à la RAM physique
    local total_kb_tolerance=$(( total_kb + 500000 ))  # +0.5 GB
    local total_gb_tolerance=$(( total_kb_tolerance / 1024 / 1024 ))

    if [ "$total_gb_tolerance" -lt "$required_gb" ]; then
        log_error "$(t err_ram_insufficient)"
        log_error "RAM détectée : ${total_gb} GB"
        log_error "RAM requise  : ${required_gb} GB (mode ${mode})"
        log_info  "Solution : Augmentez la RAM de la VM dans VirtualBox"
        return 1
    fi

    log_success "$(t check_ram) : ${total_gb} GB (requis : ${required_gb} GB)"
    return 0
}

# ============================================================================
# VÉRIFICATION 4 : Espace disque
# ============================================================================

# --- check_disk : Vérifie l'espace disque disponible ----------------------
# Vérifie la partition où sera installé SIEM Africa (/)
check_disk() {
    # df affiche l'espace disque en kB par défaut avec -k
    # -P force le format POSIX (plus fiable à parser)
    local available_kb
    available_kb=$(df -kP / | awk 'NR==2 {print $4}')
    local available_gb=$(( available_kb / 1024 / 1024 ))

    if [ "$available_gb" -lt "$MIN_DISK_GB" ]; then
        log_error "$(t err_disk_insufficient)"
        log_error "Espace disponible : ${available_gb} GB"
        log_error "Espace requis     : ${MIN_DISK_GB} GB"
        log_info  "Solution : Libérez de l'espace ou agrandissez le disque"
        log_info  "  • Nettoyer les paquets : sudo apt autoremove --purge"
        log_info  "  • Vider les caches : sudo apt clean"
        log_info  "  • Agrandir le disque VM : VBoxManage modifyhd"
        return 1
    fi

    log_success "$(t check_disk) : ${available_gb} GB disponibles (requis : ${MIN_DISK_GB} GB)"
    return 0
}

# ============================================================================
# VÉRIFICATION 5 : Interface réseau
# ============================================================================

# --- check_network_interface : Détecte et valide l'interface réseau -------
# Détecte automatiquement l'interface active (qui a une IP et est UP).
# Définit la variable globale DETECTED_INTERFACE.
check_network_interface() {
    # ip -o link show : liste les interfaces en une ligne chacune
    # grep "state UP" : filtre uniquement celles qui sont actives
    # grep -v "lo:" : exclut l'interface loopback
    # awk : extrait le nom de l'interface
    local interface
    interface=$(ip -o link show | grep "state UP" | grep -v "lo:" | awk -F': ' '{print $2}' | head -1)

    if [ -z "$interface" ]; then
        log_error "$(t err_no_interface)"
        log_info  "Solution : Vérifiez la configuration réseau de la VM"
        log_info  "  1. Vérifiez l'adaptateur dans VirtualBox"
        log_info  "  2. Mode 'NAT' ou 'Accès par pont' recommandé"
        log_info  "  3. Activez l'interface : sudo ip link set <interface> up"
        return 1
    fi

    # Vérifier que l'interface a bien une IP
    local ip_address
    ip_address=$(ip -o -4 addr show "$interface" | awk '{print $4}' | cut -d'/' -f1)

    if [ -z "$ip_address" ]; then
        log_warning "L'interface ${interface} est UP mais n'a pas d'IP"
        log_info  "Tentative de configuration DHCP..."

        # Tentative automatique
        dhclient "$interface" 2>/dev/null
        sleep 2

        ip_address=$(ip -o -4 addr show "$interface" | awk '{print $4}' | cut -d'/' -f1)

        if [ -z "$ip_address" ]; then
            log_error "Impossible d'obtenir une IP sur ${interface}"
            log_info  "Solution manuelle : sudo dhclient ${interface}"
            return 1
        fi
    fi

    # Exporter pour les autres scripts
    DETECTED_INTERFACE="$interface"
    DETECTED_IP="$ip_address"
    export DETECTED_INTERFACE DETECTED_IP

    log_success "$(t check_network) : ${interface} (${ip_address})"
    return 0
}

# ============================================================================
# VÉRIFICATION 6 : Ports disponibles
# ============================================================================

# --- check_ports : Vérifie que les ports requis sont libres ---------------
# Argument : $1 = "lite" ou "full"
check_ports() {
    local mode=$1
    local ports_to_check=()

    if [ "$mode" = "full" ]; then
        ports_to_check=("${REQUIRED_PORTS_FULL[@]}")
    else
        ports_to_check=("${REQUIRED_PORTS_LITE[@]}")
    fi

    local busy_ports=()

    for port in "${ports_to_check[@]}"; do
        # ss -tuln : liste les ports TCP/UDP en écoute
        # grep ":$port " : cherche le port exact
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            busy_ports+=("$port")
        fi
    done

    if [ ${#busy_ports[@]} -gt 0 ]; then
        log_error "$(t err_port_busy) : ${busy_ports[*]}"

        # Afficher qui utilise chaque port
        for port in "${busy_ports[@]}"; do
            local process
            process=$(ss -tulnp 2>/dev/null | grep ":${port} " | awk '{print $NF}' | head -1)
            log_error "  Port ${port} utilisé par : ${process}"
        done

        log_info  "Solution :"
        log_info  "  1. Arrêter le service concurrent"
        log_info  "  2. Ou désinstaller une installation précédente : sudo ./uninstall.sh"
        return 1
    fi

    log_success "$(t check_ports) : ${ports_to_check[*]}"
    return 0
}

# ============================================================================
# VÉRIFICATION 7 : Pas d'installation corrompue
# ============================================================================

# --- check_no_corrupted_install : Détecte les installations cassées -------
# Hard-won fix de la V1 : une install cassée peut bloquer une réinstallation.
# On détecte 3 cas :
#   1. Package Wazuh installé mais /var/ossec absent
#   2. Package Snort installé mais pas de config
#   3. Services systemd qui existent mais failed
check_no_corrupted_install() {
    local corrupted=0
    local issues=()

    # Cas 1 : Wazuh installé mais dossier manquant
    if dpkg -l 2>/dev/null | grep -qE "^ii\s+wazuh-manager"; then
        if [ ! -d /var/ossec ]; then
            corrupted=1
            issues+=("Wazuh Manager installé mais /var/ossec manquant")
        fi
    fi

    # Cas 2 : Snort installé mais pas de config
    if dpkg -l 2>/dev/null | grep -qE "^ii\s+snort"; then
        if [ ! -f /etc/snort/snort.conf ]; then
            corrupted=1
            issues+=("Snort installé mais /etc/snort/snort.conf manquant")
        fi
    fi

    # Cas 3 : Service Wazuh existe mais en état "failed"
    if systemctl list-unit-files 2>/dev/null | grep -q "wazuh-manager.service"; then
        if systemctl is-failed --quiet wazuh-manager.service; then
            corrupted=1
            issues+=("Service wazuh-manager en état 'failed'")
        fi
    fi

    # Cas 4 : Package à demi-installé (état dpkg "iF" = install failed)
    local broken_packages
    broken_packages=$(dpkg -l 2>/dev/null | awk '$1 ~ /^iF|iU|iH/ {print $2}')
    if [ -n "$broken_packages" ]; then
        corrupted=1
        issues+=("Paquets à demi-installés : ${broken_packages}")
    fi

    if [ $corrupted -eq 1 ]; then
        log_error "Installation précédente corrompue détectée :"
        for issue in "${issues[@]}"; do
            log_error "  • ${issue}"
        done
        log_info  "Solution : Désinstallez d'abord avec 'sudo ./uninstall.sh'"
        log_info  "Ou tentez une réparation : 'sudo ./repair.sh'"
        return 1
    fi

    log_success "$(t check_corrupt)"
    return 0
}

# ============================================================================
# ORCHESTRATEUR : Toutes les vérifications
# ============================================================================

# --- check_all_prerequisites : Lance toutes les vérifications -------------
# Argument : $1 = "lite" ou "full"
#
# Retourne 0 si TOUT est OK, sinon quitte avec die() au premier échec.
#
# Usage :
#   check_all_prerequisites "lite"
#   check_all_prerequisites "full"
check_all_prerequisites() {
    local mode=$1

    log_step "3/8" "$(t step_prereq)"

    # Chaque check retourne 0 (OK) ou 1 (FAIL).
    # Au premier FAIL, on arrête tout avec die().

    check_root          || die "$(t err_not_root)"
    verify_os_compatible    # cette fonction utilise die() directement
    check_internet      || die "$(t err_no_internet)"
    check_ram "$mode"   || die "$(t err_ram_insufficient)"
    check_disk          || die "$(t err_disk_insufficient)"
    check_network_interface || die "$(t err_no_interface)"
    check_ports "$mode" || die "$(t err_port_busy)"
    check_no_corrupted_install || die "Installation corrompue"

    log_separator
    log_success "Tous les prérequis sont validés ✓"

    return 0
}

# ============================================================================
# Fin de core/prerequis.sh
# ============================================================================
