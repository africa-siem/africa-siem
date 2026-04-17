#!/usr/bin/env bash
#
# SIEM Africa - Module 3 : Python agent installer
# Target : Ubuntu 22.04 LTS (root required)
# Requires Modules 1 and 2 already installed.
#
# Installs: /opt/siem-africa/agent/agent.py
# Service : siem-africa-agent.service  (StandardOutput=null, PIDFile=/var/log/siem-africa/agent.pid)

LC_ALL=C
LANG=C

# If this script was piped from `curl ... | sudo bash`, our stdin IS the script
# itself — and any `read` would eat the next line of the script, breaking the
# very next `case` statement. Reattach stdin to the user's terminal in that case.
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

# --------- Globals ---------
GROUP="siem-africa"
INSTALL_DIR="/opt/siem-africa"
AGENT_DIR="${INSTALL_DIR}/agent"
LOG_DIR="/var/log/siem-africa"
DB_FILE="${INSTALL_DIR}/siem_africa.db"
SERVICE_NAME="siem-africa-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
RAW_BASE="https://raw.githubusercontent.com/africa-siem/africa-siem/main/agent"
LANG_CHOICE=""
STEP_NUM=0

# --------- i18n ---------
say() {
    local key="$1"
    case "$key" in
        banner)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "=== SIEM Africa - Module 3 : Agent Python ===" \
                || echo "=== SIEM Africa - Module 3: Python agent ===" ;;
        need_module1)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Module 1 absent (groupe ${GROUP} introuvable)." \
                || echo "Module 1 missing (group ${GROUP} not found)." ;;
        need_module2)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Module 2 absent : ${DB_FILE} introuvable." \
                || echo "Module 2 missing: ${DB_FILE} not found." ;;
        previous_found)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Une installation precedente de l'agent a ete detectee." \
                || echo "A previous agent install was detected." ;;
        previous_confirm)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "La reinstaller proprement ? [O/n] : " \
                || echo -n "Reinstall cleanly? [Y/n]: " ;;
        cancelled)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation annulee." \
                || echo "Installation cancelled." ;;
        removing)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Suppression de l'ancien agent..." \
                || echo "Removing previous agent..." ;;
        installing_deps)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation des dependances (python3, iptables)..." \
                || echo "Installing dependencies (python3, iptables)..." ;;
        downloading)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Telechargement de agent.py..." \
                || echo "Downloading agent.py..." ;;
        validating)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Validation syntaxique de agent.py..." \
                || echo "Validating agent.py syntax..." ;;
        installing_service)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Configuration du service systemd..." \
                || echo "Configuring systemd service..." ;;
        firewall_chain)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Creation de la chaine iptables SIEM-AFRICA..." \
                || echo "Creating iptables chain SIEM-AFRICA..." ;;
        starting)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Demarrage du service..." \
                || echo "Starting service..." ;;
        done_ok)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Module 3 installe avec succes." \
                || echo "Module 3 installed successfully." ;;
        hp_note)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Honeypots actifs : SSH:2222  HTTP:8888  MySQL:3307" \
                || echo "Honeypots active: SSH:2222  HTTP:8888  MySQL:3307" ;;
        smtp_hint)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Pour configurer l'envoi d'emails : sudo bash agent/install-smtp.sh" \
                || echo "To configure email delivery: sudo bash agent/install-smtp.sh" ;;
    esac
}

step() {
    STEP_NUM=$((STEP_NUM + 1))
    echo ""
    echo "----- [${STEP_NUM}] $* -----"
}

# --------- 0. Pre-flight ---------
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root. Use: sudo bash $0"
    exit 1
fi

echo "================================================"
echo " SIEM Africa - Module 3 Installer"
echo "================================================"
echo ""
echo "Language / Langue :"
echo "  1) Francais"
echo "  2) English"
echo -n "Choice [1]: "
read -r lang_input
case "${lang_input:-1}" in
    2) LANG_CHOICE="en" ;;
    *) LANG_CHOICE="fr" ;;
esac
echo ""
say banner
echo ""

# --------- 1. Pre-req checks (Module 1 + Module 2) ---------
step "Checking prerequisites"
if ! getent group "$GROUP" >/dev/null 2>&1; then
    say need_module1
    exit 1
fi
if [ ! -f "$DB_FILE" ]; then
    say need_module2
    exit 1
fi

# --------- 2. Detect previous install ---------
detect_previous() {
    local found=0
    [ -f "$SERVICE_FILE" ] && found=1
    [ -f "${AGENT_DIR}/agent.py" ] && found=1
    systemctl list-units --all --type=service --no-legend 2>/dev/null | grep -q "${SERVICE_NAME}\.service" && found=1
    [ "$found" -eq 1 ]
}

remove_previous() {
    say removing
    systemctl stop  "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    rm -f "$SERVICE_FILE"
    rm -f "${LOG_DIR}/agent.pid"
    rm -rf "$AGENT_DIR"
    systemctl daemon-reload
}

if detect_previous; then
    say previous_found
    say previous_confirm
    read -r confirm
    case "${confirm:-y}" in
        n|N) say cancelled; exit 0 ;;
    esac
    remove_previous
fi

# --------- 3. Dependencies ---------
step "$(say installing_deps)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-minimal iptables curl ca-certificates

# --------- 4. Create agent dir (BEFORE service, per rule #9) ---------
step "Preparing directories"
mkdir -p "$AGENT_DIR" "$LOG_DIR"
chown -R root:"$GROUP" "$AGENT_DIR"
chmod 755 "$AGENT_DIR"
chown root:"$GROUP" "$LOG_DIR"
chmod 755 "$LOG_DIR"

# --------- 5. Fetch agent.py ---------
step "$(say downloading)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/agent.py" ]; then
    cp "${SCRIPT_DIR}/agent.py" "${AGENT_DIR}/agent.py"
    echo "Using local copy ${SCRIPT_DIR}/agent.py"
else
    curl -fsSL "${RAW_BASE}/agent.py" -o "${AGENT_DIR}/agent.py"
fi
if [ ! -s "${AGENT_DIR}/agent.py" ]; then
    echo "Could not obtain agent.py"
    exit 1
fi
chown root:"$GROUP" "${AGENT_DIR}/agent.py"
chmod 755 "${AGENT_DIR}/agent.py"

# --------- 6. Validate Python syntax ---------
step "$(say validating)"
if ! python3 -m py_compile "${AGENT_DIR}/agent.py"; then
    echo "agent.py failed syntax check"
    exit 1
fi

# --------- 7. Ensure siem-africa system user exists (owner of DB) ---------
if ! id -u siem-africa >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin -g "$GROUP" siem-africa
fi
# Reassert DB ownership (Module 2 should have done this, but keep resilient)
if [ -f "$DB_FILE" ]; then
    chown siem-africa:"$GROUP" "$DB_FILE" 2>/dev/null || true
    chmod 664 "$DB_FILE"
fi

# --------- 8. iptables chain ---------
step "$(say firewall_chain)"
iptables -nL SIEM-AFRICA >/dev/null 2>&1 || iptables -N SIEM-AFRICA
iptables -C INPUT -j SIEM-AFRICA 2>/dev/null || iptables -I INPUT 1 -j SIEM-AFRICA

# --------- 9. systemd service ---------
step "$(say installing_service)"
cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=SIEM Africa - intelligent agent
After=network-online.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=${GROUP}
UMask=0007
ExecStart=/usr/bin/python3 ${AGENT_DIR}/agent.py --log-level INFO
PIDFile=${LOG_DIR}/agent.pid
Restart=on-failure
RestartSec=5
StandardOutput=null
StandardError=journal
# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${INSTALL_DIR} ${LOG_DIR}
# Capabilities required for iptables
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# --------- 10. Start ---------
step "$(say starting)"
systemctl restart "$SERVICE_NAME"
sleep 2

# --------- 11. Summary ---------
echo ""
echo "================================================"
say done_ok
echo "================================================"
echo ""
systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1 \
    && echo "Service     : active" \
    || echo "Service     : INACTIVE — check: journalctl -u ${SERVICE_NAME} -e"
say hp_note
echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Logs agent    : ${LOG_DIR}/agent.log"
    echo "Base de donnees : ${DB_FILE}"
    say smtp_hint
    echo "Prochaine etape : installer le Module 4 (dashboard Django)."
else
    echo "Agent logs    : ${LOG_DIR}/agent.log"
    echo "Database      : ${DB_FILE}"
    say smtp_hint
    echo "Next step     : install Module 4 (Django dashboard)."
fi

exit 0
