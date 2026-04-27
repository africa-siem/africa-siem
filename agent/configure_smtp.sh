#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Module 3 — Reconfiguration SMTP
# ============================================================================
# Permet de reconfigurer SMTP après l'installation initiale.
# Le service est redémarré automatiquement à la fin.
#
# Usage : sudo ./configure_smtp.sh
# ============================================================================

LC_ALL=C
LANG=C

# Reattach stdin si curl|bash
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

SYSTEM_GROUP="siem-africa"
CONFIG_DIR="/etc/siem-africa"
ENV_FILE="${CONFIG_DIR}/agent.env"
SERVICE_NAME="siem-agent"
LANG_CHOICE="fr"

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_RESET='\033[0m'

# ============================================================================
# I18N
# ============================================================================

t() {
    local key="$1"
    case "$LANG_CHOICE" in
        fr)
            case "$key" in
                must_root)         echo "Ce script doit être lancé en root. Utilisez : sudo bash $0" ;;
                missing_env)       echo "Module 3 non installé (${ENV_FILE} introuvable)" ;;
                banner)            echo "Reconfiguration SMTP — SIEM Africa" ;;
                ask_host)          echo -n "Serveur SMTP (ex: smtp.gmail.com) : " ;;
                ask_port)          echo -n "Port SMTP" ;;
                ask_tls)           echo -n "Utiliser STARTTLS ?" ;;
                ask_user)          echo -n "Utilisateur SMTP (vide pour anonyme) : " ;;
                ask_pass)          echo -n "Mot de passe SMTP (App Password pour Gmail) : " ;;
                ask_from)          echo -n "Adresse expéditeur From" ;;
                ask_alert_email)   echo -n "Email destinataire des alertes" ;;
                saving)            echo "Enregistrement de la configuration" ;;
                ok_saved)          echo "Configuration SMTP enregistrée" ;;
                testing)           echo "Envoi d'un email de test" ;;
                test_ok)           echo "Email de test envoyé avec succès" ;;
                test_fail)         echo "ATTENTION : test SMTP échoué — config quand même enregistrée" ;;
                restarting)        echo "Redémarrage du service ${SERVICE_NAME}" ;;
                restart_ok)        echo "Service redémarré" ;;
                no_restart)        echo "Service non actif (sera lancé manuellement)" ;;
            esac
            ;;
        *)
            case "$key" in
                must_root)         echo "This script must run as root. Use: sudo bash $0" ;;
                missing_env)       echo "Module 3 not installed (${ENV_FILE} missing)" ;;
                banner)            echo "SMTP Reconfiguration — SIEM Africa" ;;
                ask_host)          echo -n "SMTP host (e.g. smtp.gmail.com): " ;;
                ask_port)          echo -n "SMTP port" ;;
                ask_tls)           echo -n "Use STARTTLS?" ;;
                ask_user)          echo -n "SMTP user (blank for anonymous): " ;;
                ask_pass)          echo -n "SMTP password (App Password for Gmail): " ;;
                ask_from)          echo -n "From address" ;;
                ask_alert_email)   echo -n "Alert recipient email" ;;
                saving)            echo "Saving configuration" ;;
                ok_saved)          echo "SMTP configuration saved" ;;
                testing)           echo "Sending test email" ;;
                test_ok)           echo "Test email sent successfully" ;;
                test_fail)         echo "WARNING: SMTP test failed — config still saved" ;;
                restarting)        echo "Restarting service ${SERVICE_NAME}" ;;
                restart_ok)        echo "Service restarted" ;;
                no_restart)        echo "Service not active (will need manual start)" ;;
            esac
            ;;
    esac
}

log() {
    local level="$1"; shift
    local color=""
    case "$level" in
        OK)    color="$C_GREEN"  ;;
        INFO)  color="$C_BLUE"   ;;
        WARN)  color="$C_YELLOW" ;;
        ERROR) color="$C_RED"    ;;
    esac
    echo -e "${color}[${level}]${C_RESET} $*"
}

# ============================================================================
# CHECKS
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "$(t must_root)"
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    log ERROR "$(t missing_env)"
    exit 1
fi

# ============================================================================
# CHOIX LANGUE
# ============================================================================

echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}              SIEM AFRICA — SMTP RECONFIGURATION                       ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo "Language / Langue :"
echo "  1) Français"
echo "  2) English"
echo -n "Choice [1]: "
read -r lang_input
case "${lang_input:-1}" in
    2) LANG_CHOICE="en" ;;
    *) LANG_CHOICE="fr" ;;
esac

echo ""
echo -e "${C_CYAN}$(t banner)${C_RESET}"
echo ""

# ============================================================================
# LECTURE CONFIG ACTUELLE (defaults)
# ============================================================================

read_env_var() {
    local key="$1"
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed 's/^"\(.*\)"$/\1/'
}

EX_HOST=$(read_env_var "SMTP_HOST")
EX_PORT=$(read_env_var "SMTP_PORT")
EX_TLS=$(read_env_var "SMTP_USE_TLS")
EX_USER=$(read_env_var "SMTP_USER")
EX_FROM=$(read_env_var "SMTP_FROM")
EX_EMAIL=$(read_env_var "ALERT_EMAIL")

# Affichage des défauts
echo "Configuration actuelle :"
echo "  SMTP_HOST    : ${EX_HOST:-(vide)}"
echo "  SMTP_PORT    : ${EX_PORT:-(vide)}"
echo "  SMTP_USER    : ${EX_USER:-(vide)}"
echo "  SMTP_FROM    : ${EX_FROM:-(vide)}"
echo "  ALERT_EMAIL  : ${EX_EMAIL:-(vide)}"
echo ""
echo "(Appuyez Entrée pour conserver une valeur)"
echo ""

# ============================================================================
# QUESTIONS
# ============================================================================

t ask_host
read -r SMTP_HOST
SMTP_HOST="${SMTP_HOST:-$EX_HOST}"
while [ -z "$SMTP_HOST" ]; do
    t ask_host
    read -r SMTP_HOST
done

t ask_port; echo -n " [${EX_PORT:-587}] : "
read -r SMTP_PORT
SMTP_PORT="${SMTP_PORT:-${EX_PORT:-587}}"

t ask_tls; echo -n " [${EX_TLS:-1}=oui/0=non] [${EX_TLS:-1}] : "
read -r tls
case "${tls:-${EX_TLS:-1}}" in
    0|n|N|no|non) SMTP_USE_TLS="0" ;;
    *) SMTP_USE_TLS="1" ;;
esac

t ask_user
read -r SMTP_USER
[ -z "$SMTP_USER" ] && SMTP_USER="$EX_USER"

SMTP_PASSWORD=""
if [ -n "$SMTP_USER" ]; then
    t ask_pass
    stty -echo 2>/dev/null
    read -r SMTP_PASSWORD
    stty echo 2>/dev/null
    echo ""
fi

DEFAULT_FROM="${EX_FROM:-agent@$(hostname -f 2>/dev/null || hostname)}"
t ask_from; echo -n " [${DEFAULT_FROM}] : "
read -r SMTP_FROM
SMTP_FROM="${SMTP_FROM:-$DEFAULT_FROM}"

t ask_alert_email; echo -n " [${EX_EMAIL:-(vide)}] : "
read -r ALERT_EMAIL
ALERT_EMAIL="${ALERT_EMAIL:-$EX_EMAIL}"

# ============================================================================
# SAUVEGARDE
# ============================================================================

log INFO "$(t saving)"

# Backup avant modification
cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Mise à jour ligne par ligne (préserve les commentaires)
update_env_var() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}=" "$ENV_FILE"; then
        # Échapper les caractères spéciaux pour sed
        local escaped_value=$(printf '%s\n' "$value" | sed 's/[\/&]/\\&/g')
        sed -i "s|^${key}=.*|${key}=${escaped_value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

update_env_var "SMTP_HOST" "$SMTP_HOST"
update_env_var "SMTP_PORT" "$SMTP_PORT"
update_env_var "SMTP_USE_TLS" "$SMTP_USE_TLS"
update_env_var "SMTP_USER" "$SMTP_USER"
[ -n "$SMTP_PASSWORD" ] && update_env_var "SMTP_PASSWORD" "$SMTP_PASSWORD"
update_env_var "SMTP_FROM" "$SMTP_FROM"
update_env_var "ALERT_EMAIL" "$ALERT_EMAIL"

# Permissions strictes
chown root:"$SYSTEM_GROUP" "$ENV_FILE"
chmod 640 "$ENV_FILE"

log OK "$(t ok_saved) → $ENV_FILE"

# ============================================================================
# TEST SMTP
# ============================================================================

if [ -n "$SMTP_HOST" ] && [ -n "$ALERT_EMAIL" ]; then
    log INFO "$(t testing)"

    if SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USER="$SMTP_USER" \
       SMTP_PASSWORD="$SMTP_PASSWORD" SMTP_USE_TLS="$SMTP_USE_TLS" \
       SMTP_FROM="$SMTP_FROM" ALERT_EMAIL="$ALERT_EMAIL" \
       python3 - <<'PYEOF'
import os, sys, smtplib
from email.mime.text import MIMEText

host = os.environ.get("SMTP_HOST")
port = int(os.environ.get("SMTP_PORT") or "587")
user = os.environ.get("SMTP_USER", "")
pwd  = os.environ.get("SMTP_PASSWORD", "")
use_tls = os.environ.get("SMTP_USE_TLS", "1") in ("1","true","yes","on")
sender  = os.environ.get("SMTP_FROM", "agent@localhost")
to      = os.environ.get("ALERT_EMAIL", "")

if not host or not to:
    sys.exit(0)

msg = MIMEText("SIEM Africa — Test de reconfiguration SMTP. Si vous recevez ce message, la nouvelle configuration fonctionne.", "plain", "utf-8")
msg["From"] = sender
msg["To"] = to
msg["Subject"] = "[SIEM Africa] Reconfiguration SMTP test"

try:
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        s = smtplib.SMTP(host, port, timeout=15)
        if use_tls:
            s.starttls()
    if user and pwd:
        s.login(user, pwd)
    s.sendmail(sender, [to], msg.as_string())
    s.quit()
    sys.exit(0)
except Exception as e:
    print(f"Erreur SMTP : {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
    then
        log OK "$(t test_ok)"
    else
        log WARN "$(t test_fail)"
    fi
fi

# ============================================================================
# RESTART SERVICE
# ============================================================================

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    log INFO "$(t restarting)"
    if systemctl restart "$SERVICE_NAME"; then
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log OK "$(t restart_ok)"
        fi
    fi
else
    log INFO "$(t no_restart)"
fi

echo ""
log OK "Reconfiguration SMTP terminée"
echo ""

exit 0
