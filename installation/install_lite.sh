#!/bin/bash
#===============================================================================
#
#          FILE: install_lite.sh
#
#   DESCRIPTION: SIEM Africa - Module 1 LITE
#                Installation légère : Snort + Wazuh Manager uniquement
#
#         USAGE: sudo ./install_lite.sh [--lang fr|en]
#
#       CONFIG MINIMALE : 2 Go RAM, 15 Go disque, 1 cœur CPU
#
#===============================================================================

# NOTE: set -e désactivé (provoque des plantages silencieux sur && / conditions)

#---------------------------------------
# COULEURS
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

#---------------------------------------
# VARIABLES GLOBALES
#---------------------------------------
LOG_FILE="/var/log/siem-install.log"
CREDENTIALS_FILE="/root/siem_credentials.txt"
WAZUH_VERSION="4.7"
SNORT_CONF="/etc/snort/snort.conf"
MIN_RAM=2
MIN_DISK=15
MIN_CPU=1

SIEM_GROUP="siem-africa"
SIEM_IDS_USER="siem-ids"
SIEM_WAZUH_USER="siem-wazuh"

SIEM_IDS_PASSWORD=""
SIEM_WAZUH_PASSWORD=""

LANG_CODE="fr"

#---------------------------------------
# FONCTIONS DE LOG
#---------------------------------------
log()         { echo -e "$1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_success() { log "${GREEN}[✓]${NC} $1"; }
log_error()   { log "${RED}[✗]${NC} $1"; }
log_info()    { log "${CYAN}[i]${NC} $1"; }
log_warning() { log "${YELLOW}[!]${NC} $1"; }
log_step()    { log "${BLUE}[STEP $1]${NC} $2"; }

#---------------------------------------
# ABORT
#---------------------------------------
abort() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ✗ INSTALLATION ARRÊTÉE                                       ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Raison : $1${NC}"
    echo -e "  Log : $LOG_FILE"
    echo ""
    exit 1
}

generate_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

#---------------------------------------
# PARSE ARGS
#---------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --lang) LANG_CODE="$2"; shift 2 ;;
            --lang=*) LANG_CODE="${1#*=}"; shift ;;
            *) shift ;;
        esac
    done
    if [ "$LANG_CODE" != "fr" ] && [ "$LANG_CODE" != "en" ]; then
        LANG_CODE="fr"
    fi
}

#---------------------------------------
# BANNER
#---------------------------------------
show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║         🛡️   SIEM AFRICA - MODULE 1 (LITE)                      ║"
    echo "║                                                                  ║"
    echo "║         Snort IDS + Wazuh Manager                                ║"
    echo "║         (version légère, sans Dashboard)                         ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

#---------------------------------------
# CHECKS
#---------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        abort "Ce script doit être exécuté en tant que root (sudo)"
    fi
    log_success "Exécution en tant que root"
}

check_os() {
    if [ ! -f /etc/os-release ]; then
        abort "Impossible de détecter l'OS"
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    case $ID in
        ubuntu)
            if [ "$VERSION_ID" != "20.04" ] && [ "$VERSION_ID" != "22.04" ] && [ "$VERSION_ID" != "24.04" ]; then
                abort "Ubuntu $VERSION_ID non supporté (20.04, 22.04, 24.04 uniquement)"
            fi
            log_success "OS compatible : Ubuntu $VERSION_ID"
            ;;
        debian)
            if [ "$VERSION_ID" != "11" ] && [ "$VERSION_ID" != "12" ]; then
                abort "Debian $VERSION_ID non supporté (11, 12 uniquement)"
            fi
            log_success "OS compatible : Debian $VERSION_ID"
            ;;
        *)
            abort "OS non supporté : $ID (Ubuntu/Debian uniquement)"
            ;;
    esac
}

check_ram() {
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt "$MIN_RAM" ]; then
        abort "RAM insuffisante : ${TOTAL_RAM}Go (minimum ${MIN_RAM}Go)"
    fi
    log_success "RAM : ${TOTAL_RAM} Go"
}

check_disk() {
    AVAILABLE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$AVAILABLE" -lt "$MIN_DISK" ]; then
        abort "Disque insuffisant : ${AVAILABLE}Go (minimum ${MIN_DISK}Go)"
    fi
    log_success "Espace disque : ${AVAILABLE} Go"
}

check_cpu() {
    CORES=$(nproc)
    if [ "$CORES" -lt "$MIN_CPU" ]; then
        abort "CPU insuffisant : ${CORES} cœur(s)"
    fi
    log_success "Cœurs CPU : ${CORES}"
}

check_internet() {
    log_info "Vérification connexion Internet..."
    if ! ping -c 3 8.8.8.8 >/dev/null 2>&1; then
        abort "Pas de connexion Internet"
    fi
    if ! ping -c 3 google.com >/dev/null 2>&1; then
        log_warning "Problème DNS - Correction..."
        echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
        if ! ping -c 3 google.com >/dev/null 2>&1; then
            abort "DNS non fonctionnel"
        fi
    fi
    if ! curl -s --head --connect-timeout 10 https://packages.wazuh.com >/dev/null 2>&1; then
        abort "Impossible d'accéder aux dépôts Wazuh"
    fi
    log_success "Connexion Internet OK"
}

#---------------------------------------
# CLEANUP
#---------------------------------------
cleanup_all() {
    log_info "Nettoyage en cours..."
    systemctl stop snort wazuh-manager filebeat 2>/dev/null
    systemctl disable snort wazuh-manager filebeat 2>/dev/null
    pkill -9 snort 2>/dev/null
    pkill -9 -f 'ossec-' 2>/dev/null
    pkill -9 -f 'wazuh-' 2>/dev/null

    DEBIAN_FRONTEND=noninteractive apt remove --purge -y \
        snort snort-common snort-rules-default \
        wazuh-manager wazuh-agent filebeat 2>/dev/null

    rm -rf /var/ossec /etc/snort /var/log/snort /var/run/snort
    rm -rf /etc/filebeat /var/lib/filebeat /usr/share/filebeat
    rm -f /etc/systemd/system/snort.service

    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>/dev/null

    log_success "Nettoyage terminé"
}

check_existing() {
    log_info "Vérification installations existantes..."
    if dpkg -l 2>/dev/null | grep -qE "snort|wazuh-manager" || \
       [ -d "/etc/snort" ] || [ -d "/var/ossec" ]; then
        log_warning "Installation existante détectée → suppression"
        cleanup_all
    else
        log_success "Aucune installation existante"
    fi
}

#---------------------------------------
# UPDATE & DEPS
#---------------------------------------
update_system() {
    log_info "Mise à jour système..."
    if ! apt update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        abort "Échec apt update"
    fi
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null
    log_success "Système mis à jour"
}

install_dependencies() {
    log_info "Installation des dépendances..."
    if ! DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        curl wget gnupg apt-transport-https lsb-release ca-certificates \
        software-properties-common net-tools jq iproute2 \
        2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        abort "Échec installation dépendances"
    fi
    log_success "Dépendances installées"
}

#---------------------------------------
# GROUPE + USERS
#---------------------------------------
create_siem_group_and_users() {
    log_step "1/4" "Création du groupe et des users SIEM Africa..."

    if ! getent group "$SIEM_GROUP" >/dev/null 2>&1; then
        if ! groupadd "$SIEM_GROUP"; then
            abort "Impossible de créer le groupe $SIEM_GROUP"
        fi
    fi

    SIEM_IDS_PASSWORD=$(generate_password)
    if ! id "$SIEM_IDS_USER" >/dev/null 2>&1; then
        if ! useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_IDS_USER"; then
            abort "Impossible de créer $SIEM_IDS_USER"
        fi
    else
        usermod -g "$SIEM_GROUP" "$SIEM_IDS_USER"
    fi
    echo "$SIEM_IDS_USER:$SIEM_IDS_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_IDS_USER" 2>/dev/null

    SIEM_WAZUH_PASSWORD=$(generate_password)
    if ! id "$SIEM_WAZUH_USER" >/dev/null 2>&1; then
        if ! useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_WAZUH_USER"; then
            abort "Impossible de créer $SIEM_WAZUH_USER"
        fi
    else
        usermod -g "$SIEM_GROUP" "$SIEM_WAZUH_USER"
    fi
    echo "$SIEM_WAZUH_USER:$SIEM_WAZUH_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_WAZUH_USER" 2>/dev/null

    log_success "Groupe et users créés"
}

#---------------------------------------
# SNORT
#---------------------------------------
install_snort() {
    log_step "2/4" "Installation de Snort..."
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        INTERFACE="eth0"
    fi
    echo "snort snort/interface string $INTERFACE" | debconf-set-selections
    echo "snort snort/address_range string any/any" | debconf-set-selections
    echo "snort snort/startup string boot" | debconf-set-selections
    if ! DEBIAN_FRONTEND=noninteractive apt install -y snort 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        abort "Impossible d'installer Snort"
    fi
    log_success "Snort installé"
}

configure_snort() {
    log_info "Configuration de Snort..."
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    if [ -z "$LOCAL_NET" ]; then
        LOCAL_NET="192.168.1.0/24"
    fi
    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
    fi
    mkdir -p /var/log/snort /etc/snort/rules
    chown -R "$SIEM_IDS_USER":"$SIEM_GROUP" /var/log/snort /etc/snort 2>/dev/null
    chmod 770 /var/log/snort

    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        INTERFACE="eth0"
    fi

    cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=SIEM Africa - Snort IDS (Lite)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i $INTERFACE -A fast
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable snort 2>/dev/null
    systemctl start snort 2>/dev/null

    log_success "Snort configuré - Interface: $INTERFACE, HOME_NET: $LOCAL_NET"
}

#---------------------------------------
# WAZUH MANAGER
#---------------------------------------
install_wazuh_manager_only() {
    log_step "3/4" "Installation Wazuh Manager seul (5-10 minutes)..."

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list

    if ! apt update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        abort "apt update échoué après ajout du dépôt Wazuh"
    fi

    if ! DEBIAN_FRONTEND=noninteractive apt install -y wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        abort "Impossible d'installer wazuh-manager"
    fi

    if [ ! -d /var/ossec ]; then
        abort "Wazuh Manager installé mais /var/ossec absent"
    fi

    systemctl daemon-reload
    systemctl enable wazuh-manager 2>/dev/null
    systemctl start wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null

    sleep 5
    if ! systemctl is-active --quiet wazuh-manager; then
        abort "Wazuh Manager n'a pas démarré"
    fi

    if id wazuh >/dev/null 2>&1; then
        usermod -aG "$SIEM_GROUP" wazuh 2>/dev/null
    fi

    log_success "Wazuh Manager installé"
}

#---------------------------------------
# INTÉGRATION
#---------------------------------------
configure_integration() {
    log_step "4/4" "Configuration intégration Snort ↔ Wazuh..."
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    if [ ! -f "$OSSEC_CONF" ]; then
        abort "ossec.conf introuvable"
    fi

    if ! grep -q "/var/log/snort/alert" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>snort-full</log_format>\n    <location>/var/log/snort/alert</location>\n  </localfile>' "$OSSEC_CONF"
    fi

    if ! systemctl restart wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        abort "Impossible de redémarrer wazuh-manager"
    fi

    log_success "Intégration configurée"
}

#---------------------------------------
# CREDENTIALS FILE
#---------------------------------------
create_credentials_file() {
    log_info "Création du fichier credentials..."

    SERVER_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    if [ -z "$INTERFACE" ]; then INTERFACE="eth0"; fi
    if [ -z "$LOCAL_NET" ]; then LOCAL_NET="192.168.1.0/24"; fi

    LANG_DISPLAY="Français"
    if [ "$LANG_CODE" = "en" ]; then
        LANG_DISPLAY="English"
    fi

    cat > "$CREDENTIALS_FILE" <<EOF
╔══════════════════════════════════════════════════════════════════╗
║                SIEM AFRICA - CREDENTIALS                         ║
║                     MODULE 1 - LITE                              ║
╚══════════════════════════════════════════════════════════════════╝

Date installation : $DATE
Mode              : LITE (Snort + Wazuh Manager uniquement)
Serveur IP        : $SERVER_IP
Hostname          : $HOSTNAME
Langue            : $LANG_DISPLAY

══════════════════════════════════════════════════════════════════
USERS SYSTÈME
══════════════════════════════════════════════════════════════════
Username   : $SIEM_IDS_USER
Password   : $SIEM_IDS_PASSWORD
Sudo       : oui
Rôle       : Gestion Snort IDS

Username   : $SIEM_WAZUH_USER
Password   : $SIEM_WAZUH_PASSWORD
Sudo       : oui
Rôle       : Gestion Wazuh SIEM

══════════════════════════════════════════════════════════════════
GROUPE PARTAGÉ
══════════════════════════════════════════════════════════════════
Nom        : $SIEM_GROUP
Usage      : Partage des permissions entre Module 2, 3, 4

══════════════════════════════════════════════════════════════════
PAS DE DASHBOARD WEB DANS CETTE VERSION
══════════════════════════════════════════════════════════════════
La version LITE n'installe PAS le Wazuh Dashboard.
Pour consulter les alertes, utilisez la ligne de commande :

  sudo tail -f /var/ossec/logs/alerts/alerts.json
  sudo tail -f /var/log/snort/alert

Pour avoir le dashboard web, utilisez le script FULL :
  sudo ./install_full.sh

══════════════════════════════════════════════════════════════════
SNORT IDS
══════════════════════════════════════════════════════════════════
Interface  : $INTERFACE
Home Net   : $LOCAL_NET
Config     : /etc/snort/snort.conf
Logs       : /var/log/snort/alert
Service    : systemctl status snort

══════════════════════════════════════════════════════════════════
WAZUH MANAGER
══════════════════════════════════════════════════════════════════
Service    : systemctl status wazuh-manager
Config     : /var/ossec/etc/ossec.conf
Logs       : /var/ossec/logs/ossec.log
Alertes    : /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
PORTS UTILISÉS (LITE)
══════════════════════════════════════════════════════════════════
1514  - Wazuh Agent communication
1515  - Wazuh Agent enrollment
55000 - Wazuh API

(Pas de 443 ni 9200 : pas de Dashboard ni Indexer)

══════════════════════════════════════════════════════════════════
FICHIERS IMPORTANTS
══════════════════════════════════════════════════════════════════
$CREDENTIALS_FILE  - Ce fichier
/var/log/siem-install.log          - Log d'installation

══════════════════════════════════════════════════════════════════
COMMANDES DE VÉRIFICATION
══════════════════════════════════════════════════════════════════
État :
  sudo systemctl status snort wazuh-manager

Alertes temps réel :
  sudo tail -f /var/log/snort/alert
  sudo tail -f /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
⚠️  Ce fichier contient des mots de passe : chmod 600 appliqué.
══════════════════════════════════════════════════════════════════
EOF

    chmod 600 "$CREDENTIALS_FILE"
    log_success "Credentials sauvegardés dans $CREDENTIALS_FILE"
}

#---------------------------------------
# RÉSUMÉ FINAL
#---------------------------------------
show_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✓ INSTALLATION LITE TERMINÉE                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        UTILISATEURS                                ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  • ${YELLOW}$SIEM_IDS_USER${NC}    / ${GREEN}$SIEM_IDS_PASSWORD${NC}"
    echo -e "  • ${YELLOW}$SIEM_WAZUH_USER${NC}  / ${GREEN}$SIEM_WAZUH_PASSWORD${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        SERVICES                                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    for service in snort wazuh-manager; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  $service : ${GREEN}● Actif${NC}"
        else
            echo -e "  $service : ${RED}○ Inactif${NC}"
        fi
    done
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        CREDENTIALS                                 ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Fichier : ${YELLOW}$CREDENTIALS_FILE${NC}"
    echo -e "  Voir    : ${GREEN}sudo cat $CREDENTIALS_FILE${NC}"
    echo ""

    echo -e "${YELLOW}  ℹ️  Pas de dashboard web dans LITE. Pour le dashboard : script FULL.${NC}"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    # Init log
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "=== SIEM Africa - Module 1 LITE - $(date) ===" > "$LOG_FILE"

    parse_args "$@"
    show_banner

    echo -e "${CYAN}[VÉRIFICATIONS OBLIGATOIRES]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_root
    check_os
    check_ram
    check_disk
    check_cpu
    check_internet
    echo ""

    echo -e "${CYAN}[VÉRIFICATION INSTALLATION EXISTANTE]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_existing
    echo ""

    echo -e "${CYAN}[PRÉPARATION SYSTÈME]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    update_system
    install_dependencies
    echo ""

    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    create_siem_group_and_users
    echo ""
    install_snort
    configure_snort
    echo ""
    install_wazuh_manager_only
    echo ""
    configure_integration
    echo ""
    create_credentials_file
    echo ""

    show_summary

    log_info "Installation LITE terminée - $(date)"
}

main "$@"
