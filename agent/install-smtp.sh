#!/usr/bin/env bash
#
# SIEM Africa - Module 3 : interactive SMTP configuration
# Writes /opt/siem-africa/smtp.conf (660 root:siem-africa) and restarts the agent.

LC_ALL=C
LANG=C

# If this script was piped from `curl ... | sudo bash`, our stdin IS the script
# itself — and any `read` would eat the next line of the script, breaking the
# very next `case` statement. Reattach stdin to the user's terminal in that case.
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

GROUP="siem-africa"
INSTALL_DIR="/opt/siem-africa"
SMTP_CONF="${INSTALL_DIR}/smtp.conf"
SERVICE_NAME="siem-africa-agent"
LANG_CHOICE=""

say() {
    case "$1" in
        banner)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "=== Configuration SMTP — SIEM Africa ===" \
                || echo "=== SMTP configuration — SIEM Africa ===" ;;
        host)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Serveur SMTP (ex: smtp.gmail.com) : " \
                || echo -n "SMTP host (e.g. smtp.gmail.com): " ;;
        port)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Port SMTP [587] : " \
                || echo -n "SMTP port [587]: " ;;
        tls)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Utiliser STARTTLS ? [O/n] : " \
                || echo -n "Use STARTTLS? [Y/n]: " ;;
        user)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Utilisateur SMTP (vide pour anonyme) : " \
                || echo -n "SMTP username (blank for anonymous): " ;;
        pass)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Mot de passe SMTP : " \
                || echo -n "SMTP password: " ;;
        from)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Adresse expediteur (From) : " \
                || echo -n "From address: " ;;
        testing)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Envoi d'un email de test..." \
                || echo "Sending test email..." ;;
        ok)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Configuration SMTP enregistree." \
                || echo "SMTP configuration saved." ;;
        fail)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ATTENTION : le test SMTP a echoue — la configuration reste enregistree." \
                || echo "WARNING: SMTP test failed — configuration is still saved." ;;
    esac
}

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root. Use: sudo bash $0"
    exit 1
fi
if [ ! -d "$INSTALL_DIR" ]; then
    echo "SIEM Africa is not installed ($INSTALL_DIR missing)."
    exit 1
fi

echo "================================================"
echo " SIEM Africa - SMTP configuration"
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

# Load existing config as defaults (if any)
EX_HOST=""; EX_PORT="587"; EX_TLS="true"; EX_USER=""; EX_FROM=""
if [ -f "$SMTP_CONF" ]; then
    # shellcheck disable=SC1090
    . "$SMTP_CONF" 2>/dev/null
    EX_HOST="${SMTP_HOST:-$EX_HOST}"
    EX_PORT="${SMTP_PORT:-$EX_PORT}"
    EX_TLS="${SMTP_TLS:-$EX_TLS}"
    EX_USER="${SMTP_USER:-$EX_USER}"
    EX_FROM="${SMTP_FROM:-$EX_FROM}"
fi

say host
read -r SMTP_HOST
[ -z "$SMTP_HOST" ] && SMTP_HOST="$EX_HOST"
while [ -z "$SMTP_HOST" ]; do
    say host
    read -r SMTP_HOST
done

say port
read -r SMTP_PORT
SMTP_PORT="${SMTP_PORT:-$EX_PORT}"

say tls
read -r tls_input
case "${tls_input:-y}" in
    n|N) SMTP_TLS="false" ;;
    *)   SMTP_TLS="true"  ;;
esac

say user
read -r SMTP_USER
[ -z "$SMTP_USER" ] && SMTP_USER="$EX_USER"

SMTP_PASS=""
if [ -n "$SMTP_USER" ]; then
    say pass
    # Read password without echo
    stty -echo 2>/dev/null
    read -r SMTP_PASS
    stty echo 2>/dev/null
    echo ""
fi

say from
read -r SMTP_FROM
[ -z "$SMTP_FROM" ] && SMTP_FROM="$EX_FROM"
if [ -z "$SMTP_FROM" ]; then
    SMTP_FROM="SIEM Africa <noreply@$(hostname -f 2>/dev/null || hostname)>"
fi

# Persist config
umask 027
cat > "$SMTP_CONF" <<CONF
# SIEM Africa - SMTP configuration
# Read by /opt/siem-africa/agent/agent.py (EmailNotifier)
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_TLS=${SMTP_TLS}
SMTP_USER=${SMTP_USER}
SMTP_PASS=${SMTP_PASS}
SMTP_FROM=${SMTP_FROM}
CONF
chown root:"$GROUP" "$SMTP_CONF"
chmod 660 "$SMTP_CONF"
say ok

# --- Test send ---
ALERT_EMAIL=""
if [ -f "${INSTALL_DIR}/.env" ]; then
    # shellcheck disable=SC1090
    . "${INSTALL_DIR}/.env" 2>/dev/null
    ALERT_EMAIL="${ALERT_EMAIL:-}"
fi

if [ -n "$ALERT_EMAIL" ]; then
    say testing
    python3 - <<PY
import smtplib, os, sys
from email.mime.text import MIMEText
cfg = {}
with open("${SMTP_CONF}") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.strip()

host = cfg.get("SMTP_HOST") or "localhost"
port = int(cfg.get("SMTP_PORT") or "25")
use_tls = (cfg.get("SMTP_TLS") or "false").lower() in ("1","true","yes","on")
user = cfg.get("SMTP_USER") or ""
pwd  = cfg.get("SMTP_PASS") or ""
sender = cfg.get("SMTP_FROM") or "noreply@localhost"
recipient = "${ALERT_EMAIL}"

msg = MIMEText("SIEM Africa SMTP test — if you receive this, configuration works.", "plain", "utf-8")
msg["From"] = sender
msg["To"]   = recipient
msg["Subject"] = "[SIEM Africa] SMTP test"

try:
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        s = smtplib.SMTP(host, port, timeout=15)
        if use_tls:
            s.starttls()
    if user and pwd:
        s.login(user, pwd)
    s.sendmail(sender, [recipient], msg.as_string())
    s.quit()
    print("SMTP test OK")
    sys.exit(0)
except Exception as exc:
    print(f"SMTP test FAILED: {exc}")
    sys.exit(1)
PY
    RC=$?
    if [ $RC -ne 0 ]; then
        say fail
    fi
fi

# Restart agent to pick up new SMTP config
if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl restart "$SERVICE_NAME"
fi

echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Fichier enregistre : ${SMTP_CONF} (660 root:${GROUP})"
else
    echo "File written      : ${SMTP_CONF} (660 root:${GROUP})"
fi

exit 0
