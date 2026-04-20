#!/usr/bin/env bash
#
# SIEM Africa - Module 1 : Snort IDS + Wazuh Manager
# Target : Ubuntu 22.04 LTS (root required)
# Docs   : https://github.com/africa-siem/africa-siem
#
# RULES: no "set -e", log_format=snort-fast, /var/log/siem-africa for PIDs,
#        group siem-africa shared, interactive, idempotent.

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
LOG_DIR="/var/log/siem-africa"
CRED_FILE="${INSTALL_DIR}/credentials.txt"
SNORT_LOG_DIR="/var/log/snort"
WAZUH_VERSION="4.x"
LANG_CHOICE=""
ORG_NAME=""
ALERT_EMAIL=""
IFACE=""
HOME_NET=""
STEP_NUM=0

# --------- i18n helpers ---------
say() {
    local key="$1"
    case "$key" in
        banner)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "=== SIEM Africa - Module 1 : Snort + Wazuh Manager ===" \
                || echo "=== SIEM Africa - Module 1: Snort + Wazuh Manager ===" ;;
        need_root)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Ce script doit etre lance en root. Utilisez : sudo bash $0" \
                || echo "This script must run as root. Use: sudo bash $0" ;;
        need_ubuntu)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Ce script requiert Ubuntu 22.04 LTS." \
                || echo "This script requires Ubuntu 22.04 LTS." ;;
        org_prompt)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Nom de l'organisation : " \
                || echo -n "Organization name: " ;;
        email_prompt)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Email pour recevoir les alertes : " \
                || echo -n "Email to receive alerts: " ;;
        iface_prompt)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Interface reseau a surveiller [${IFACE}] : " \
                || echo -n "Network interface to monitor [${IFACE}]: " ;;
        homenet_detected)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Reseau local detecte : ${HOME_NET}" \
                || echo "Local network detected: ${HOME_NET}" ;;
        previous_found)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Une installation precedente a ete detectee." \
                || echo "A previous installation was detected." ;;
        previous_confirm)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Tout supprimer et reinstaller ? [o/N] : " \
                || echo -n "Remove everything and reinstall? [y/N]: " ;;
        cancelled)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation annulee." \
                || echo "Installation cancelled." ;;
        uninstalling)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Desinstallation de la version precedente..." \
                || echo "Uninstalling previous version..." ;;
        updating_apt)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Mise a jour des depots APT..." \
                || echo "Updating APT repositories..." ;;
        installing_snort)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation de Snort IDS..." \
                || echo "Installing Snort IDS..." ;;
        installing_wazuh)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation de Wazuh Manager..." \
                || echo "Installing Wazuh Manager..." ;;
        configuring_snort)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Configuration de Snort..." \
                || echo "Configuring Snort..." ;;
        configuring_wazuh)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Configuration de Wazuh Manager..." \
                || echo "Configuring Wazuh Manager..." ;;
        starting_services)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Demarrage des services..." \
                || echo "Starting services..." ;;
        done_ok)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation terminee avec succes." \
                || echo "Installation completed successfully." ;;
        fail_snort)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC : l'installation de Snort a echoue." \
                || echo "FAIL: Snort installation failed." ;;
        fail_wazuh)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC : l'installation de Wazuh Manager a echoue." \
                || echo "FAIL: Wazuh Manager installation failed." ;;
        fail_ossec_missing)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC : /var/ossec absent apres installation de Wazuh." \
                || echo "FAIL: /var/ossec missing after Wazuh install." ;;
    esac
}

step() {
    STEP_NUM=$((STEP_NUM + 1))
    echo ""
    echo "----- [${STEP_NUM}] $* -----"
}

err() {
    echo "ERROR: $*" >&2
}

# --------- 0. Pre-flight ---------
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root. Use: sudo bash $0"
    exit 1
fi

if ! grep -q "Ubuntu 22.04" /etc/os-release 2>/dev/null; then
    echo "WARNING: this script is tested on Ubuntu 22.04 LTS only."
    echo -n "Continue anyway? [y/N]: "
    read -r cont
    case "$cont" in
        y|Y|o|O) : ;;
        *) exit 1 ;;
    esac
fi

# --------- 1. Language ---------
echo "================================================"
echo " SIEM Africa - Module 1 Installer"
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

# --------- 2. Detect previous install ---------
detect_previous() {
    local found=0
    dpkg -l snort 2>/dev/null | grep -q "^ii" && found=1
    dpkg -l wazuh-manager 2>/dev/null | grep -q "^ii" && found=1
    [ -d /etc/snort ] && found=1
    [ -d /var/ossec ] && found=1
    [ -d "$INSTALL_DIR" ] && found=1
    [ -f /etc/systemd/system/snort-africa.service ] && found=1
    [ "$found" -eq 1 ]
}

uninstall_previous() {
    say uninstalling
    systemctl stop snort-africa 2>/dev/null
    systemctl disable snort-africa 2>/dev/null
    rm -f /etc/systemd/system/snort-africa.service
    systemctl stop wazuh-manager 2>/dev/null
    systemctl disable wazuh-manager 2>/dev/null
    systemctl stop snort 2>/dev/null
    systemctl disable snort 2>/dev/null

    # Purge Wazuh first (it locks its own files)
    DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge wazuh-manager 2>/dev/null
    # Purge Snort
    DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
        snort snort-common snort-common-libraries snort-rules-default 2>/dev/null

    # Clean up
    rm -rf /etc/snort /var/log/snort /var/ossec /etc/apt/sources.list.d/wazuh.list
    rm -f /usr/share/keyrings/wazuh.gpg
    rm -rf "$INSTALL_DIR" "$LOG_DIR"

    # Fix apt state
    dpkg --configure -a 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -f -y 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y 2>/dev/null
    systemctl daemon-reload
}

if detect_previous; then
    say previous_found
    say previous_confirm
    read -r confirm
    case "$confirm" in
        y|Y|o|O) uninstall_previous ;;
        *) say cancelled; exit 0 ;;
    esac
fi

# --------- 3. Collect user inputs ---------
step "User configuration"
while [ -z "$ORG_NAME" ]; do
    say org_prompt
    read -r ORG_NAME
done
while [ -z "$ALERT_EMAIL" ]; do
    say email_prompt
    read -r ALERT_EMAIL
done

# --------- 4. Detect interface + HOME_NET ---------
IFACE=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')
[ -z "$IFACE" ] && IFACE="eth0"
say iface_prompt
read -r iface_input
[ -n "$iface_input" ] && IFACE="$iface_input"

CIDR=$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | head -n1)
if [ -n "$CIDR" ]; then
    HOME_NET=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_network('$CIDR', strict=False))" 2>/dev/null)
fi
[ -z "$HOME_NET" ] && HOME_NET="any"
say homenet_detected

# --------- 5. Create group + dirs (BEFORE services) ---------
step "Creating system group and directories"
getent group "$GROUP" >/dev/null 2>&1 || groupadd "$GROUP"

mkdir -p "$INSTALL_DIR" "$LOG_DIR"
chown root:"$GROUP" "$INSTALL_DIR" "$LOG_DIR"
chmod 775 "$INSTALL_DIR"
chmod 755 "$LOG_DIR"

# --------- 6. Update APT ---------
step "$(say updating_apt)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl gnupg lsb-release ca-certificates debconf-utils \
    apt-transport-https python3 jq

# --------- 7. Preseed + install Snort ---------
step "$(say installing_snort)"
cat > /tmp/snort-africa.preseed <<PS
snort snort/address_range string any
snort snort/interface string ${IFACE}
snort snort/startup string boot
snort snort/config_item note
PS
debconf-set-selections /tmp/snort-africa.preseed
rm -f /tmp/snort-africa.preseed

apt-get install -y snort
# Snort frequently leaves apt in a broken state - fix it before touching anything else
dpkg --configure -a
apt-get install -f -y

if ! dpkg -l snort 2>/dev/null | grep -q "^ii"; then
    say fail_snort
    exit 1
fi

# --------- 8. Configure Snort ---------
step "$(say configuring_snort)"
# Add snort user to siem-africa group
usermod -aG "$GROUP" snort 2>/dev/null

# Ensure /var/log/snort exists with proper group + setgid
mkdir -p "$SNORT_LOG_DIR"
chown snort:"$GROUP" "$SNORT_LOG_DIR"
chmod 2775 "$SNORT_LOG_DIR"

# Patch HOME_NET in /etc/snort/snort.conf
if [ -f /etc/snort/snort.conf ]; then
    sed -i "s|^ipvar HOME_NET .*|ipvar HOME_NET [${HOME_NET}]|" /etc/snort/snort.conf
    # If the line used 'var' instead of 'ipvar', patch that too
    sed -i "s|^var HOME_NET .*|var HOME_NET [${HOME_NET}]|" /etc/snort/snort.conf
fi

# Patch interface in /etc/snort/snort.debian.conf
if [ -f /etc/snort/snort.debian.conf ]; then
    sed -i "s|^DEBIAN_SNORT_INTERFACE=.*|DEBIAN_SNORT_INTERFACE=\"${IFACE}\"|" /etc/snort/snort.debian.conf
    sed -i "s|^DEBIAN_SNORT_HOME_NET=.*|DEBIAN_SNORT_HOME_NET=\"${HOME_NET}\"|" /etc/snort/snort.debian.conf
fi

# Disable built-in init - we use our own systemd unit
systemctl stop snort 2>/dev/null
systemctl disable snort 2>/dev/null

# --------- 9. Install Wazuh Manager ---------
step "$(say installing_wazuh)"
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_VERSION}/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -y
apt-get install -y wazuh-manager

if ! dpkg -l wazuh-manager 2>/dev/null | grep -q "^ii"; then
    say fail_wazuh
    exit 1
fi
if [ ! -d /var/ossec ]; then
    say fail_ossec_missing
    exit 1
fi

# --------- 10. Configure Wazuh ---------
step "$(say configuring_wazuh)"
# Add wazuh user to siem-africa group so it can read /var/log/snort/alert
usermod -aG "$GROUP" wazuh 2>/dev/null
# Some packages use 'ossec' user
usermod -aG "$GROUP" ossec 2>/dev/null

OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    cp "$OSSEC_CONF" "${OSSEC_CONF}.siem-africa.bak"

    # Append localfile block for Snort fast alerts
    # Multiple <ossec_config> roots are allowed by Wazuh
    cat >> "$OSSEC_CONF" <<'OCFG'

<!-- === SIEM Africa additions === -->
<ossec_config>
  <localfile>
    <log_format>snort-fast</log_format>
    <location>/var/log/snort/alert</location>
  </localfile>
</ossec_config>
OCFG

    # Configure email notifications
    SMTP_HOST="localhost"
    ESC_EMAIL=$(printf '%s' "$ALERT_EMAIL" | sed 's|[&/\\]|\\&|g')
    # Replace existing values if present; otherwise rely on a fallback block
    sed -i "s|<email_notification>no</email_notification>|<email_notification>yes</email_notification>|" "$OSSEC_CONF"
    if grep -q "<email_to>" "$OSSEC_CONF"; then
        sed -i "s|<email_to>[^<]*</email_to>|<email_to>${ESC_EMAIL}</email_to>|" "$OSSEC_CONF"
    fi
    if grep -q "<smtp_server>" "$OSSEC_CONF"; then
        sed -i "s|<smtp_server>[^<]*</smtp_server>|<smtp_server>${SMTP_HOST}</smtp_server>|" "$OSSEC_CONF"
    fi
fi

# --------- 11. Create Snort systemd unit ---------
step "Creating snort-africa systemd service"
cat > /etc/systemd/system/snort-africa.service <<SVC
[Unit]
Description=SIEM Africa - Snort IDS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=snort
Group=${GROUP}
UMask=0022
PIDFile=${LOG_DIR}/snort.pid
ExecStart=/usr/sbin/snort -A fast -b -d -i ${IFACE} -u snort -g ${GROUP} -c /etc/snort/snort.conf -l ${SNORT_LOG_DIR}
Restart=on-failure
RestartSec=5
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload

# --------- 12. Start services ---------
step "$(say starting_services)"
systemctl enable wazuh-manager
systemctl restart wazuh-manager
systemctl enable snort-africa
systemctl start snort-africa

sleep 2

# --------- 13. Write credentials + env ---------
step "Writing ${CRED_FILE}"
cat > "$CRED_FILE" <<CRD
# SIEM Africa - Module 1 credentials
# Generated: $(date -u +'%Y-%m-%d %H:%M:%S UTC')

ORGANIZATION="${ORG_NAME}"
ALERT_EMAIL="${ALERT_EMAIL}"
INTERFACE="${IFACE}"
HOME_NET="${HOME_NET}"
LANGUAGE="${LANG_CHOICE}"

# Paths
SIEM_INSTALL_DIR="${INSTALL_DIR}"
SIEM_LOG_DIR="${LOG_DIR}"
SNORT_LOG_DIR="${SNORT_LOG_DIR}"
WAZUH_DIR="/var/ossec"
CRD
chown root:"$GROUP" "$CRED_FILE"
chmod 640 "$CRED_FILE"

cat > "${INSTALL_DIR}/.env" <<ENV
# Sourced by other modules; values quoted so spaces/special chars survive.
ORG_NAME="${ORG_NAME}"
ALERT_EMAIL="${ALERT_EMAIL}"
LANG_CHOICE="${LANG_CHOICE}"
INTERFACE="${IFACE}"
HOME_NET="${HOME_NET}"
ENV
chown root:"$GROUP" "${INSTALL_DIR}/.env"
chmod 660 "${INSTALL_DIR}/.env"

# --------- 14. Final summary ---------
echo ""
echo "================================================"
say done_ok
echo "================================================"
echo ""
echo "Snort interface    : ${IFACE}"
echo "HOME_NET           : ${HOME_NET}"
echo "Alert email        : ${ALERT_EMAIL}"
echo "Credentials file   : ${CRED_FILE}"
echo ""
echo "Services :"
systemctl is-active snort-africa && echo "  snort-africa     : active" || echo "  snort-africa     : INACTIVE"
systemctl is-active wazuh-manager && echo "  wazuh-manager    : active" || echo "  wazuh-manager    : INACTIVE"
echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Logs Snort   : ${SNORT_LOG_DIR}/alert"
    echo "Logs Wazuh   : /var/ossec/logs/alerts/alerts.json"
    echo "Prochaine etape : installer le Module 2 (base de donnees)."
else
    echo "Snort logs   : ${SNORT_LOG_DIR}/alert"
    echo "Wazuh logs   : /var/ossec/logs/alerts/alerts.json"
    echo "Next step    : install Module 2 (database)."
fi

exit 0
