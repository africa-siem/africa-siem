#!/bin/bash
#===============================================================================
#
#          FILE: install_full.sh
#
#   DESCRIPTION: SIEM Africa - Module 1 FULL
#                Installation complète : Snort + Wazuh (Manager + Indexer + Dashboard)
#
#         USAGE: sudo ./install_full.sh [--lang fr|en]
#
#       CONFIG MINIMALE : 4 Go RAM, 30 Go disque, 2 cœurs CPU
#       CONFIG RECOMMANDÉE : 8 Go RAM, 50 Go disque, 4 cœurs CPU
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
MIN_RAM=4
MIN_DISK=30
MIN_CPU=2
RETRY_COUNT=3

SIEM_GROUP="siem-africa"
SIEM_IDS_USER="siem-ids"
SIEM_WAZUH_USER="siem-wazuh"

SIEM_IDS_PASSWORD=""
SIEM_WAZUH_PASSWORD=""
WAZUH_ADMIN_PASSWORD=""

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
    echo "║         🛡️   SIEM AFRICA - MODULE 1 (FULL)                      ║"
    echo "║                                                                  ║"
    echo "║         Snort IDS + Wazuh (Manager + Indexer + Dashboard)        ║"
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
        abort "CPU insuffisant : ${CORES} cœur(s) (minimum ${MIN_CPU})"
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
    log_info "Nettoyage complet..."
    systemctl stop snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null
    systemctl disable snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null

    pkill -9 snort 2>/dev/null
    pkill -9 -f 'ossec-' 2>/dev/null
    pkill -9 -f 'wazuh-' 2>/dev/null
    pkill -9 -f 'opensearch' 2>/dev/null
    pkill -9 -f 'filebeat' 2>/dev/null

    DEBIAN_FRONTEND=noninteractive apt remove --purge -y \
        snort snort-common snort-rules-default \
        wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
        filebeat 2>/dev/null

    rm -rf /var/ossec
    rm -rf /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer
    rm -rf /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard
    rm -rf /etc/filebeat /var/lib/filebeat /usr/share/filebeat
    rm -rf /etc/snort /var/log/snort /var/run/snort

    rm -f /root/wazuh-install.sh /root/wazuh-install-files.tar
    rm -f wazuh-install.sh wazuh-install-files.tar
    rm -f /etc/systemd/system/snort.service
    rm -f /var/log/wazuh-install.log

    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt clean 2>/dev/null

    log_success "Nettoyage terminé"
}

check_existing() {
    log_info "Vérification installations existantes..."
    if dpkg -l 2>/dev/null | grep -qE "snort|wazuh" || \
       [ -d "/etc/snort" ] || \
       [ -d "/var/ossec" ] || \
       [ -d "/etc/wazuh-indexer" ]; then
        log_warning "Installation existante détectée → suppression et réinstallation"
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
    log_step "1/5" "Création du groupe et des users SIEM Africa..."

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
    log_info "  - Groupe : $SIEM_GROUP"
    log_info "  - Users  : $SIEM_IDS_USER, $SIEM_WAZUH_USER"
}

#---------------------------------------
# SNORT
#---------------------------------------
install_snort() {
    log_step "2/5" "Installation de Snort..."
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
Description=SIEM Africa - Snort IDS
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
# WAZUH (avec retry)
#---------------------------------------
install_wazuh() {
    log_step "3/5" "Installation de Wazuh $WAZUH_VERSION (10-20 minutes)..."

    cd /root 2>/dev/null || cd /tmp
    if ! curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"; then
        abort "Impossible de télécharger Wazuh"
    fi
    chmod +x wazuh-install.sh

    local attempt=1
    local success=false

    while [ "$attempt" -le "$RETRY_COUNT" ]; do
        log_info "Tentative $attempt/$RETRY_COUNT..."

        if bash wazuh-install.sh -a -i >> "$LOG_FILE" 2>&1; then
            success=true
            break
        fi

        log_warning "Tentative $attempt échouée"

        if [ "$attempt" -lt "$RETRY_COUNT" ]; then
            systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null
            apt remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null
            rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer wazuh-install-files.tar
            sleep 5
        fi

        attempt=$((attempt + 1))
    done

    if [ "$success" = false ]; then
        abort "Installation Wazuh échouée après $RETRY_COUNT tentatives"
    fi

    log_success "Wazuh installé"

    if [ -f "wazuh-install-files.tar" ]; then
        cp wazuh-install-files.tar /root/
    fi

    if id wazuh >/dev/null 2>&1; then
        usermod -aG "$SIEM_GROUP" wazuh 2>/dev/null
    fi
}

#---------------------------------------
# INTÉGRATION
#---------------------------------------
configure_integration() {
    log_step "4/5" "Configuration intégration Snort ↔ Wazuh..."

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
# EXTRACTION PASSWORD ADMIN WAZUH
#---------------------------------------
extract_wazuh_admin_password() {
    WAZUH_ADMIN_PASSWORD="Voir /root/wazuh-install-files.tar"
    if [ -f "/root/wazuh-install-files.tar" ]; then
        mkdir -p /tmp/wazuh-extract
        tar -xf /root/wazuh-install-files.tar -C /tmp/wazuh-extract 2>/dev/null
        if [ -f "/tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt" ]; then
            EXTRACTED=$(grep -A1 "'admin'" /tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep "password" | head -1 | sed "s/.*password: '//" | sed "s/'.*//")
            if [ -n "$EXTRACTED" ]; then
                WAZUH_ADMIN_PASSWORD="$EXTRACTED"
            fi
        fi
        rm -rf /tmp/wazuh-extract
    fi
}

#---------------------------------------
# CREDENTIALS FILE
#---------------------------------------
create_credentials_file() {
    log_step "5/5" "Création du fichier credentials..."

    extract_wazuh_admin_password

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
║                     MODULE 1 - FULL                              ║
╚══════════════════════════════════════════════════════════════════╝

Date installation : $DATE
Mode              : FULL (Snort + Wazuh Manager + Indexer + Dashboard)
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
Membres    : $SIEM_IDS_USER, $SIEM_WAZUH_USER, wazuh

══════════════════════════════════════════════════════════════════
WAZUH DASHBOARD
══════════════════════════════════════════════════════════════════
URL        : https://$SERVER_IP
Username   : admin
Password   : $WAZUH_ADMIN_PASSWORD

Certificat : Auto-signé (accepter dans le navigateur)

══════════════════════════════════════════════════════════════════
SNORT IDS
══════════════════════════════════════════════════════════════════
Interface  : $INTERFACE
Home Net   : $LOCAL_NET
Config     : /etc/snort/snort.conf
Logs       : /var/log/snort/alert
Service    : systemctl status snort

══════════════════════════════════════════════════════════════════
WAZUH SIEM
══════════════════════════════════════════════════════════════════
Manager    : systemctl status wazuh-manager
Indexer    : systemctl status wazuh-indexer
Dashboard  : systemctl status wazuh-dashboard
Config     : /var/ossec/etc/ossec.conf
Logs       : /var/ossec/logs/ossec.log
Alertes    : /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
PORTS UTILISÉS
══════════════════════════════════════════════════════════════════
443   - Wazuh Dashboard (HTTPS)
1514  - Wazuh Agent communication
1515  - Wazuh Agent enrollment
9200  - Wazuh Indexer (OpenSearch)
55000 - Wazuh API

══════════════════════════════════════════════════════════════════
FICHIERS IMPORTANTS
══════════════════════════════════════════════════════════════════
$CREDENTIALS_FILE       - Ce fichier (lecture via 'cat')
/root/wazuh-install-files.tar    - Backup des fichiers Wazuh
/var/log/siem-install.log        - Log d'installation complet

══════════════════════════════════════════════════════════════════
COMMANDES DE VÉRIFICATION
══════════════════════════════════════════════════════════════════
État des services :
  sudo systemctl status snort wazuh-manager wazuh-indexer wazuh-dashboard

Test Dashboard :
  curl -k -s -o /dev/null -w '%{http_code}' https://localhost

Vérifier les ports :
  sudo ss -tlnp | grep -E '443|1514|1515|9200|55000'

Suivre les alertes en temps réel :
  sudo tail -f /var/log/snort/alert
  sudo tail -f /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
⚠️  SÉCURITÉ
══════════════════════════════════════════════════════════════════
- Ce fichier contient des mots de passe : protégez-le (chmod 600)
- Changez tous les mots de passe en production
- Le certificat SSL est auto-signé : utilisez un vrai cert en prod

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
    echo -e "${GREEN}║   ✓ INSTALLATION FULL TERMINÉE AVEC SUCCÈS                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   ACCÈS AU DASHBOARD WAZUH                        ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  URL        : ${GREEN}https://${SERVER_IP}${NC}"
    echo -e "  User       : ${YELLOW}admin${NC}"
    echo -e "  Password   : ${YELLOW}$WAZUH_ADMIN_PASSWORD${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   UTILISATEURS CRÉÉS                              ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  • ${YELLOW}$SIEM_IDS_USER${NC}    / ${GREEN}$SIEM_IDS_PASSWORD${NC}    (sudo)"
    echo -e "  • ${YELLOW}$SIEM_WAZUH_USER${NC}  / ${GREEN}$SIEM_WAZUH_PASSWORD${NC}  (sudo)"
    echo -e "  • Groupe   : ${YELLOW}$SIEM_GROUP${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   ÉTAT DES SERVICES                               ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    for service in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  $service : ${GREEN}● Actif${NC}"
        else
            echo -e "  $service : ${RED}○ Inactif${NC}"
        fi
    done
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   FICHIER CREDENTIALS                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Tous les mots de passe : ${YELLOW}$CREDENTIALS_FILE${NC}"
    echo -e "  Pour afficher          : ${GREEN}sudo cat $CREDENTIALS_FILE${NC}"
    echo ""

    echo -e "${YELLOW}  ⚠️  Note : Le certificat SSL est auto-signé.${NC}"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "=== SIEM Africa - Module 1 FULL - $(date) ===" > "$LOG_FILE"

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
    install_wazuh
    echo ""
    configure_integration
    echo ""
    create_credentials_file
    echo ""

    show_summary

    log_info "Installation FULL terminée - $(date)"
}

main "$@"
