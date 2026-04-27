#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Module 3 — Désinstallation
# ============================================================================
# Désinstalle proprement l'agent (SANS toucher au Module 1 ni au Module 2).
# Le groupe siem-africa est conservé (utilisé par les autres modules).
# ============================================================================

LC_ALL=C
LANG=C

if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

SYSTEM_GROUP="siem-africa"
SYSTEM_USER="siem-agent"
INSTALL_DIR="/opt/siem-africa-agent"
CONFIG_DIR="/etc/siem-africa"
LOG_DIR="/var/log/siem-africa"
SERVICE_NAME="siem-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="${CONFIG_DIR}/agent.env"
CREDENTIALS_FILE="/root/siem_credentials.txt"

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_RESET='\033[0m'

log() {
    local level="$1"; shift
    local color=""
    case "$level" in
        OK) color="$C_GREEN" ;;
        INFO) color="$C_BLUE" ;;
        WARN) color="$C_YELLOW" ;;
        ERROR) color="$C_RED" ;;
    esac
    echo -e "${color}[${level}]${C_RESET} $*"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être lancé en root. Utilisez : sudo bash $0"
    exit 1
fi

clear || true
echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}              SIEM AFRICA — Module 3 — DÉSINSTALLATION                ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo "Ce script va supprimer :"
echo "  • Service systemd ${SERVICE_NAME}"
echo "  • ${INSTALL_DIR}/"
echo "  • Utilisateur Linux ${SYSTEM_USER}"
echo "  • Section [MODULE 3] de ${CREDENTIALS_FILE}"
echo "  • Optionnellement : Ollama et son modèle"
echo ""
echo "Sera CONSERVÉ :"
echo "  • Module 1 (Wazuh + Snort)"
echo "  • Module 2 (BDD ${INSTALL_DIR/-agent/})"
echo "  • Groupe ${SYSTEM_GROUP} (utilisé par les autres modules)"
echo "  • Logs ${LOG_DIR}/ (à supprimer manuellement si souhaité)"
echo ""
echo -n "Confirmer la désinstallation ? [o/N] : "
read -r confirm
case "${confirm:-N}" in
    [oOyY]*) ;;
    *) log INFO "Désinstallation annulée"; exit 0 ;;
esac

echo ""

# ============================================================================
# 1. Arrêt du service
# ============================================================================

log INFO "Arrêt du service ${SERVICE_NAME}"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME" || true
    log OK "Service arrêté"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME" || true
    log OK "Service désactivé"
fi

if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    log OK "Service systemd supprimé"
fi

# ============================================================================
# 2. Nettoyage des règles iptables (Active Response)
# ============================================================================

log INFO "Vérification des règles iptables actives"
if [ -f "/var/lib/siem-africa/siem.db" ] && command -v sqlite3 >/dev/null 2>&1; then
    # Récupérer les IPs encore actives en BDD
    BLOCKED_IPS=$(sqlite3 /var/lib/siem-africa/siem.db \
        "SELECT ip_address FROM blocked_ips WHERE is_active=1" 2>/dev/null)

    if [ -n "$BLOCKED_IPS" ]; then
        echo "  IPs actuellement bloquées par l'agent :"
        echo "$BLOCKED_IPS" | sed 's/^/    /'
        echo ""
        echo -n "  Retirer ces règles iptables ? [O/n] : "
        read -r unblock_confirm
        case "${unblock_confirm:-O}" in
            [nN]*) log INFO "Règles iptables conservées" ;;
            *)
                while IFS= read -r ip; do
                    [ -z "$ip" ] && continue
                    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
                done <<< "$BLOCKED_IPS"
                # Marquer inactif en BDD
                sqlite3 /var/lib/siem-africa/siem.db \
                    "UPDATE blocked_ips SET is_active=0, unblocked_at=CURRENT_TIMESTAMP, unblock_reason='Désinstallation Module 3' WHERE is_active=1" 2>/dev/null
                log OK "Règles iptables retirées"
                ;;
        esac
    else
        log INFO "Aucune règle iptables active"
    fi
fi

# ============================================================================
# 3. Suppression du dossier d'installation
# ============================================================================

if [ -d "$INSTALL_DIR" ]; then
    BACKUP="${INSTALL_DIR}.uninstall.$(date +%Y%m%d_%H%M%S)"
    log INFO "Sauvegarde dans $BACKUP"
    mv "$INSTALL_DIR" "$BACKUP"
    log OK "Installation sauvegardée puis supprimée"
fi

# ============================================================================
# 4. Suppression de la config (avec backup)
# ============================================================================

if [ -f "$ENV_FILE" ]; then
    BACKUP="${ENV_FILE}.uninstall.$(date +%Y%m%d_%H%M%S)"
    log INFO "Sauvegarde de la config dans $BACKUP"
    mv "$ENV_FILE" "$BACKUP"
    log OK "Config Module 3 sauvegardée"
fi

# Supprimer /etc/siem-africa SI vide
if [ -d "$CONFIG_DIR" ] && [ -z "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]; then
    rmdir "$CONFIG_DIR"
    log OK "Dossier $CONFIG_DIR supprimé (était vide)"
fi

# ============================================================================
# 5. Suppression de l'utilisateur (mais pas du groupe)
# ============================================================================

if id "$SYSTEM_USER" >/dev/null 2>&1; then
    log INFO "Suppression de l'utilisateur $SYSTEM_USER"
    userdel "$SYSTEM_USER" 2>/dev/null || true
    log OK "Utilisateur supprimé"
fi

log INFO "Groupe $SYSTEM_GROUP CONSERVÉ (utilisé par Module 1/2/4)"

# ============================================================================
# 6. Ollama (optionnel)
# ============================================================================

if command -v ollama >/dev/null 2>&1; then
    echo ""
    echo -n "Désinstaller Ollama et libérer ~2 GB ? [o/N] : "
    read -r ollama_confirm
    case "${ollama_confirm:-N}" in
        [oOyY]*)
            log INFO "Suppression du modèle Ollama"
            ollama rm llama3.2:3b 2>/dev/null || true

            log INFO "Arrêt du service Ollama"
            systemctl stop ollama 2>/dev/null || true
            systemctl disable ollama 2>/dev/null || true

            log INFO "Suppression du binaire Ollama"
            rm -f /usr/local/bin/ollama 2>/dev/null
            rm -f /etc/systemd/system/ollama.service 2>/dev/null
            rm -rf /usr/share/ollama 2>/dev/null

            # User ollama (créé par leur installer)
            if id ollama >/dev/null 2>&1; then
                userdel -r ollama 2>/dev/null || true
            fi
            if getent group ollama >/dev/null 2>&1; then
                groupdel ollama 2>/dev/null || true
            fi

            systemctl daemon-reload
            log OK "Ollama désinstallé"
            ;;
        *)
            log INFO "Ollama conservé (réutilisable plus tard)"
            ;;
    esac
fi

# ============================================================================
# 7. Nettoyage section [MODULE 3] dans credentials
# ============================================================================

if [ -f "$CREDENTIALS_FILE" ]; then
    if grep -q "\[MODULE 3\]" "$CREDENTIALS_FILE"; then
        log INFO "Suppression section [MODULE 3] du fichier credentials"

        # Backup
        cp "$CREDENTIALS_FILE" "${CREDENTIALS_FILE}.before-uninstall-m3.$(date +%Y%m%d_%H%M%S)"

        # Suppression de la section [MODULE 3] (jusqu'à la prochaine section ou EOF)
        awk '
            /^═+$/ && getline next_line {
                if (next_line ~ /\[MODULE 3\]/) {
                    in_m3 = 1
                    next
                } else {
                    print
                    print next_line
                    in_m3 = 0
                }
                next
            }
            /^═+$/ && in_m3 { in_m3 = 0; next }
            !in_m3 { print }
        ' "$CREDENTIALS_FILE" > "${CREDENTIALS_FILE}.tmp" && mv "${CREDENTIALS_FILE}.tmp" "$CREDENTIALS_FILE"

        chmod 600 "$CREDENTIALS_FILE"
        log OK "Section [MODULE 3] retirée"
    fi
fi

# ============================================================================
# 8. Logs (laissés intentionnellement, à supprimer manuellement)
# ============================================================================

if [ -d "$LOG_DIR" ] && [ -f "$LOG_DIR/agent.log" ]; then
    log INFO "Logs conservés : $LOG_DIR/agent.log* (à supprimer manuellement si souhaité)"
fi

# ============================================================================
# RESUME
# ============================================================================

echo ""
echo -e "${C_GREEN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_GREEN}  Désinstallation Module 3 terminée${C_RESET}"
echo -e "${C_GREEN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo "Pour réinstaller :"
echo "  cd ~/africa-siem/agent"
echo "  sudo ./install_agent.sh"
echo ""

exit 0
