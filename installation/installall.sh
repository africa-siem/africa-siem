#!/usr/bin/env bash
#
# SIEM Africa - Module 1 : Snort IDS + Wazuh All-in-One (Manager + Indexer + Dashboard)
# Target : Ubuntu 22.04 LTS (root required, 4 GB RAM minimum recommended)
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
WAZUH_ASSIST_VERSION="4.9"
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
                && echo "=== SIEM Africa - Module 1 All-in-One : Snort + Wazuh complet ===" \
                || echo "=== SIEM Africa - Module 1 All-in-One: Snort + full Wazuh stack ===" ;;
        mem_warn)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ATTENTION : 4 GB RAM recommandes pour la version All-in-One." \
                || echo "WARNING: 4 GB RAM recommended for the All-in-One install." ;;
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
        installing_snort)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation de Snort IDS..." \
                || echo "Installing Snort IDS..." ;;
        installing_wazuh_stack)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation du stack Wazuh complet (Manager + Indexer + Dashboard)..." \
                || echo "Installing full Wazuh stack (Manager + Indexer + Dashboard)..." ;;
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
                && echo "ECHEC : l'installation de Wazuh a echoue." \
                || echo "FAIL: Wazuh installation failed." ;;
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

# RAM check (warn only)
RAM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
if [ -n "$RAM_MB" ] && [ "$RAM_MB" -lt 3500 ]; then
    echo "WARNING: detected ${RAM_MB} MB RAM. All-in-One needs at least 4 GB."
fi

# --------- 1. Language ---------
echo "================================================"
echo " SIEM Africa - Module 1 All-in-One Installer"
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
say mem_warn

# --------- 2. Detect previous install ---------
detect_previous() {
    local found=0
    dpkg -l snort 2>/dev/null | grep -q "^ii" && found=1
    dpkg -l wazuh-manager 2>/dev/null | grep -q "^ii" && found=1
    dpkg -l wazuh-indexer 2>/dev/null | grep -q "^ii" && found=1
    dpkg -l wazuh-dashboard 2>/dev/null | grep -q "^ii" && found=1
    [ -d /etc/snort ] && found=1
    [ -d /var/ossec ] && found=1
    [ -d /etc/wazuh-indexer ] && found=1
    [ -d /etc/wazuh-dashboard ] && found=1
    [ -d "$INSTALL_DIR" ] && found=1
    [ -f /etc/systemd/system/snort-africa.service ] && found=1
    [ "$found" -eq 1 ]
}

uninstall_previous() {
    say uninstalling
    systemctl stop snort-africa 2>/dev/null
    systemctl disable snort-africa 2>/dev/null
    rm -f /etc/systemd/system/snort-africa.service
    systemctl stop wazuh-dashboard 2>/dev/null
    systemctl stop wazuh-indexer 2>/dev/null
    systemctl stop wazuh-manager 2>/dev/null
    systemctl stop snort 2>/dev/null
    systemctl disable wazuh-dashboard 2>/dev/null
    systemctl disable wazuh-indexer 2>/dev/null
    systemctl disable wazuh-manager 2>/dev/null
    systemctl disable snort 2>/dev/null

    DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
        wazuh-dashboard wazuh-indexer wazuh-manager filebeat 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
        snort snort-common snort-common-libraries snort-rules-default 2>/dev/null

    rm -rf /etc/snort /var/log/snort
    rm -rf /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard /etc/filebeat
    rm -rf /var/lib/wazuh-indexer /var/log/wazuh-indexer /var/log/wazuh-dashboard
    rm -f /etc/apt/sources.list.d/wazuh.list /usr/share/keyrings/wazuh.gpg
    rm -f /tmp/wazuh-install.sh /tmp/wazuh-install-files.tar
    rm -rf "$INSTALL_DIR" "$LOG_DIR"

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

# --------- 6. Update APT + base tools ---------
step "Updating APT and installing base tools"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl gnupg lsb-release ca-certificates debconf-utils \
    apt-transport-https python3 jq tar

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
usermod -aG "$GROUP" snort 2>/dev/null

mkdir -p "$SNORT_LOG_DIR"
chown snort:"$GROUP" "$SNORT_LOG_DIR"
chmod 2775 "$SNORT_LOG_DIR"

if [ -f /etc/snort/snort.conf ]; then
    sed -i "s|^ipvar HOME_NET .*|ipvar HOME_NET [${HOME_NET}]|" /etc/snort/snort.conf
    sed -i "s|^var HOME_NET .*|var HOME_NET [${HOME_NET}]|" /etc/snort/snort.conf
fi
if [ -f /etc/snort/snort.debian.conf ]; then
    sed -i "s|^DEBIAN_SNORT_INTERFACE=.*|DEBIAN_SNORT_INTERFACE=\"${IFACE}\"|" /etc/snort/snort.debian.conf
    sed -i "s|^DEBIAN_SNORT_HOME_NET=.*|DEBIAN_SNORT_HOME_NET=\"${HOME_NET}\"|" /etc/snort/snort.debian.conf
fi

systemctl stop snort 2>/dev/null
systemctl disable snort 2>/dev/null

# --------- 9. Install Wazuh All-in-One via official assistant ---------
step "$(say installing_wazuh_stack)"
ASSIST_URL="https://packages.wazuh.com/${WAZUH_ASSIST_VERSION}/wazuh-install.sh"
curl -fsSL "$ASSIST_URL" -o /tmp/wazuh-install.sh
if [ ! -s /tmp/wazuh-install.sh ]; then
    say fail_wazuh
    echo "Could not download Wazuh installer from ${ASSIST_URL}"
    exit 1
fi
chmod +x /tmp/wazuh-install.sh

# -a = all-in-one (Manager + Indexer + Dashboard), -i = ignore health checks
bash /tmp/wazuh-install.sh -a -i
ASSIST_RC=$?

if [ "$ASSIST_RC" -ne 0 ]; then
    say fail_wazuh
    echo "wazuh-install.sh exited with code ${ASSIST_RC}"
    echo "Log: /var/log/wazuh-install.log"
    exit 1
fi

if ! dpkg -l wazuh-manager 2>/dev/null | grep -q "^ii"; then
    say fail_wazuh
    exit 1
fi
if [ ! -d /var/ossec ]; then
    say fail_ossec_missing
    exit 1
fi

# Stash the passwords tarball generated by the assistant (contains admin + kibana creds)
WAZUH_PASS_TAR=""
for f in /wazuh-install-files.tar /root/wazuh-install-files.tar /tmp/wazuh-install-files.tar; do
    [ -f "$f" ] && WAZUH_PASS_TAR="$f" && break
done

# --------- 10. Configure Wazuh Manager ---------
step "$(say configuring_wazuh)"
usermod -aG "$GROUP" wazuh 2>/dev/null
usermod -aG "$GROUP" ossec 2>/dev/null

OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    cp "$OSSEC_CONF" "${OSSEC_CONF}.siem-africa.bak"

    cat >> "$OSSEC_CONF" <<'OCFG'

<!-- === SIEM Africa additions === -->
<ossec_config>
  <localfile>
    <log_format>snort-fast</log_format>
    <location>/var/log/snort/alert</location>
  </localfile>
</ossec_config>
OCFG

    SMTP_HOST="localhost"
    ESC_EMAIL=$(printf '%s' "$ALERT_EMAIL" | sed 's|[&/\\]|\\&|g')
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

# --------- 13. Extract + save admin passwords ---------
ADMIN_PASS=""
KIBANA_PASS=""
if [ -n "$WAZUH_PASS_TAR" ]; then
    mkdir -p /tmp/wazuh-pass-extract
    tar -xf "$WAZUH_PASS_TAR" -C /tmp/wazuh-pass-extract 2>/dev/null
    PASS_FILE=$(find /tmp/wazuh-pass-extract -name "wazuh-passwords.txt" 2>/dev/null | head -n1)
    if [ -n "$PASS_FILE" ] && [ -f "$PASS_FILE" ]; then
        ADMIN_PASS=$(awk -F"'" '/indexer_password.*admin/ {print $2; exit}' "$PASS_FILE")
        [ -z "$ADMIN_PASS" ] && ADMIN_PASS=$(grep -A1 "The password for user admin" "$PASS_FILE" 2>/dev/null | awk -F"'" '{print $2}' | head -n1)
        KIBANA_PASS=$(awk -F"'" '/api_password.*wazuh/ {print $2; exit}' "$PASS_FILE")
    fi
    rm -rf /tmp/wazuh-pass-extract
fi

# --------- 14. Write credentials + env ---------
step "Writing ${CRED_FILE}"
cat > "$CRED_FILE" <<CRD
# SIEM Africa - Module 1 All-in-One credentials
# Generated: $(date -u +'%Y-%m-%d %H:%M:%S UTC')

ORGANIZATION="${ORG_NAME}"
ALERT_EMAIL="${ALERT_EMAIL}"
INTERFACE="${IFACE}"
HOME_NET="${HOME_NET}"
LANGUAGE="${LANG_CHOICE}"

# Wazuh endpoints
WAZUH_MANAGER_API="https://localhost:55000"
WAZUH_INDEXER_URL="https://localhost:9200"
WAZUH_DASHBOARD_URL="https://localhost:443"

# Credentials (Wazuh All-in-One admin)
WAZUH_ADMIN_USER="admin"
WAZUH_ADMIN_PASS="${ADMIN_PASS}"
WAZUH_API_USER="wazuh"
WAZUH_API_PASS="${KIBANA_PASS}"

# Paths
SIEM_INSTALL_DIR="${INSTALL_DIR}"
SIEM_LOG_DIR="${LOG_DIR}"
SNORT_LOG_DIR="${SNORT_LOG_DIR}"
WAZUH_DIR="/var/ossec"
CRD
chown root:"$GROUP" "$CRED_FILE"
chmod 640 "$CRED_FILE"

cat > "${INSTALL_DIR}/.env" <<ENV
ORG_NAME=${ORG_NAME}
ALERT_EMAIL=${ALERT_EMAIL}
LANG=${LANG_CHOICE}
INTERFACE=${IFACE}
HOME_NET=${HOME_NET}
WAZUH_ADMIN_PASS=${ADMIN_PASS}
WAZUH_API_PASS=${KIBANA_PASS}
ENV
chown root:"$GROUP" "${INSTALL_DIR}/.env"
chmod 660 "${INSTALL_DIR}/.env"

# --------- 15. Final summary ---------
echo ""
echo "================================================"
say done_ok
echo "================================================"
echo ""
echo "Snort interface      : ${IFACE}"
echo "HOME_NET             : ${HOME_NET}"
echo "Alert email          : ${ALERT_EMAIL}"
echo "Credentials file     : ${CRED_FILE}"
echo ""
echo "Services :"
systemctl is-active snort-africa     >/dev/null 2>&1 && echo "  snort-africa       : active"    || echo "  snort-africa       : INACTIVE"
systemctl is-active wazuh-manager    >/dev/null 2>&1 && echo "  wazuh-manager      : active"    || echo "  wazuh-manager      : INACTIVE"
systemctl is-active wazuh-indexer    >/dev/null 2>&1 && echo "  wazuh-indexer      : active"    || echo "  wazuh-indexer      : INACTIVE"
systemctl is-active wazuh-dashboard  >/dev/null 2>&1 && echo "  wazuh-dashboard    : active"    || echo "  wazuh-dashboard    : INACTIVE"
echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Dashboard Wazuh  : https://$(hostname -I | awk '{print $1}')/"
    echo "Utilisateur      : admin"
    echo "Mot de passe     : voir ${CRED_FILE}"
    echo "Logs Snort       : ${SNORT_LOG_DIR}/alert"
    echo "Logs Wazuh       : /var/ossec/logs/alerts/alerts.json"
    echo "Prochaine etape  : installer le Module 2 (base de donnees)."
else
    echo "Wazuh dashboard  : https://$(hostname -I | awk '{print $1}')/"
    echo "Username         : admin"
    echo "Password         : see ${CRED_FILE}"
    echo "Snort logs       : ${SNORT_LOG_DIR}/alert"
    echo "Wazuh logs       : /var/ossec/logs/alerts/alerts.json"
    echo "Next step        : install Module 2 (database)."
fi

exit 0
