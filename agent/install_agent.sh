#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Module 3 (Agent intelligent) — Installation
# ============================================================================
# Ce script installe l'agent SIEM Africa.
#
# Prérequis :
#   - Linux (testé Ubuntu 22.04/24.04)
#   - Module 2 (BDD) déjà installé
#   - Wazuh recommandé (Module 1 ou installation tierce)
#   - Connexion Internet (pour Ollama)
#   - Root
#
# Usage :
#   sudo ./install_agent.sh                # Installation complète interactive
#   sudo ./install_agent.sh --no-ollama    # Installer sans Ollama
#   sudo ./install_agent.sh --uninstall    # Désinstaller (voir uninstall_agent.sh)
# ============================================================================

LC_ALL=C
LANG=C

# Reattach stdin si exécuté via curl|bash
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

# ============================================================================
# CONSTANTES
# ============================================================================
SYSTEM_GROUP="siem-africa"
SYSTEM_USER="siem-agent"
INSTALL_DIR="/opt/siem-africa-agent"
CONFIG_DIR="/etc/siem-africa"
LOG_DIR="/var/log/siem-africa"
RUN_DIR="/var/run"
DB_PATH="/var/lib/siem-africa/siem.db"
ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"
SERVICE_NAME="siem-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="${CONFIG_DIR}/agent.env"
CREDENTIALS_FILE="/root/siem_credentials.txt"
LOG_FILE="${LOG_DIR}/install-agent.log"

OLLAMA_URL="http://localhost:11434"
OLLAMA_MODEL="llama3.2:3b"

INSTALL_OLLAMA=1
LANG_CHOICE="fr"

# Couleurs ANSI
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
                must_root)              echo "Ce script doit être lancé en root. Utilisez : sudo bash $0" ;;
                banner)                 echo "Installation du Module 3 (Agent intelligent)" ;;
                lang_choice)            echo "Choix de la langue / Language" ;;
                phase1)                 echo "PHASE 1 : Vérification des prérequis" ;;
                phase2)                 echo "PHASE 2 : Préparation système" ;;
                phase3)                 echo "PHASE 3 : Installation des fichiers" ;;
                phase4)                 echo "PHASE 4 : Configuration interactive" ;;
                phase5)                 echo "PHASE 5 : Installation Ollama (IA)" ;;
                phase6)                 echo "PHASE 6 : Service systemd" ;;
                phase7)                 echo "PHASE 7 : Validation finale" ;;
                missing_db)             echo "Module 2 (BDD) introuvable. Installez-le d'abord." ;;
                wazuh_ok)               echo "Wazuh détecté et actif" ;;
                wazuh_inactive)         echo "Wazuh installé mais service inactif" ;;
                wazuh_missing)          echo "Wazuh non détecté (installation continue)" ;;
                snort_ok)               echo "Snort détecté" ;;
                installing_python)      echo "Installation des dépendances Python" ;;
                creating_user)          echo "Création de l'utilisateur système" ;;
                copying_files)          echo "Copie des fichiers de l'agent" ;;
                creating_config)        echo "Création du fichier de configuration" ;;
                ask_admin_email)        echo -n "Email destinataire des alertes (laisser vide pour configurer plus tard) : " ;;
                ask_lang_default)       echo "Langue par défaut des emails" ;;
                ask_min_severity)       echo "Sévérité minimum pour déclencher un email" ;;
                ask_smtp_now)           echo -n "Configurer SMTP maintenant ? [O/n] : " ;;
                ask_smtp_host)          echo -n "Serveur SMTP (ex: smtp.gmail.com) : " ;;
                ask_smtp_port)          echo -n "Port SMTP [587] : " ;;
                ask_smtp_tls)           echo -n "Utiliser STARTTLS ? [O/n] : " ;;
                ask_smtp_user)          echo -n "Utilisateur SMTP (vide pour anonyme) : " ;;
                ask_smtp_pass)          echo -n "Mot de passe SMTP (App Password pour Gmail) : " ;;
                ask_smtp_from)          echo -n "Adresse expéditeur From [agent@hostname] : " ;;
                ask_install_ollama)     echo -n "Installer Ollama (IA) maintenant ? [O/n] : " ;;
                ollama_already)         echo "Ollama déjà installé" ;;
                ollama_installing)      echo "Téléchargement et installation d'Ollama (peut prendre quelques minutes)" ;;
                ollama_pulling)         echo "Téléchargement du modèle ${OLLAMA_MODEL} (~2 GB, soyez patient)" ;;
                ollama_skip)            echo "Installation Ollama ignorée. L'IA sera désactivée." ;;
                ollama_ok)              echo "Ollama opérationnel" ;;
                ollama_failed)          echo "Installation Ollama échouée. L'agent fonctionnera sans IA." ;;
                installing_systemd)     echo "Installation du service systemd" ;;
                starting_service)       echo "Démarrage du service" ;;
                service_started)        echo "Service démarré avec succès" ;;
                service_failed)         echo "Service échoué au démarrage. Vérifier : journalctl -u ${SERVICE_NAME}" ;;
                summary_title)          echo "Installation terminée" ;;
                check_logs)             echo "Logs en temps réel : journalctl -u ${SERVICE_NAME} -f" ;;
                check_status)           echo "Statut : systemctl status ${SERVICE_NAME}" ;;
                check_smtp_later)       echo "Reconfigurer SMTP plus tard : sudo ./configure_smtp.sh" ;;
                test_smtp)              echo "Envoi d'un email de test" ;;
                smtp_test_ok)           echo "Email de test envoyé avec succès" ;;
                smtp_test_failed)       echo "Échec envoi email test (config sauvegardée quand même)" ;;
            esac
            ;;
        *)
            case "$key" in
                must_root)              echo "This script must be run as root. Use: sudo bash $0" ;;
                banner)                 echo "Module 3 (Intelligent Agent) Installation" ;;
                lang_choice)            echo "Language / Choix de la langue" ;;
                phase1)                 echo "PHASE 1: Prerequisites check" ;;
                phase2)                 echo "PHASE 2: System preparation" ;;
                phase3)                 echo "PHASE 3: Files installation" ;;
                phase4)                 echo "PHASE 4: Interactive configuration" ;;
                phase5)                 echo "PHASE 5: Ollama installation (AI)" ;;
                phase6)                 echo "PHASE 6: Systemd service" ;;
                phase7)                 echo "PHASE 7: Final validation" ;;
                missing_db)             echo "Module 2 (database) not found. Install it first." ;;
                wazuh_ok)               echo "Wazuh detected and active" ;;
                wazuh_inactive)         echo "Wazuh installed but service inactive" ;;
                wazuh_missing)          echo "Wazuh not detected (installation continues)" ;;
                snort_ok)               echo "Snort detected" ;;
                installing_python)      echo "Installing Python dependencies" ;;
                creating_user)          echo "Creating system user" ;;
                copying_files)          echo "Copying agent files" ;;
                creating_config)        echo "Creating configuration file" ;;
                ask_admin_email)        echo -n "Alert recipient email (leave empty to configure later): " ;;
                ask_lang_default)       echo "Default email language" ;;
                ask_min_severity)       echo "Minimum severity to trigger an email" ;;
                ask_smtp_now)           echo -n "Configure SMTP now? [Y/n]: " ;;
                ask_smtp_host)          echo -n "SMTP host (e.g. smtp.gmail.com): " ;;
                ask_smtp_port)          echo -n "SMTP port [587]: " ;;
                ask_smtp_tls)           echo -n "Use STARTTLS? [Y/n]: " ;;
                ask_smtp_user)          echo -n "SMTP user (blank for anonymous): " ;;
                ask_smtp_pass)          echo -n "SMTP password (App Password for Gmail): " ;;
                ask_smtp_from)          echo -n "From address [agent@hostname]: " ;;
                ask_install_ollama)     echo -n "Install Ollama (AI) now? [Y/n]: " ;;
                ollama_already)         echo "Ollama already installed" ;;
                ollama_installing)      echo "Downloading and installing Ollama (may take a few minutes)" ;;
                ollama_pulling)         echo "Pulling model ${OLLAMA_MODEL} (~2 GB, please wait)" ;;
                ollama_skip)            echo "Ollama installation skipped. AI will be disabled." ;;
                ollama_ok)              echo "Ollama operational" ;;
                ollama_failed)          echo "Ollama installation failed. Agent will work without AI." ;;
                installing_systemd)     echo "Installing systemd service" ;;
                starting_service)       echo "Starting service" ;;
                service_started)        echo "Service started successfully" ;;
                service_failed)         echo "Service failed to start. Check: journalctl -u ${SERVICE_NAME}" ;;
                summary_title)          echo "Installation complete" ;;
                check_logs)             echo "Live logs: journalctl -u ${SERVICE_NAME} -f" ;;
                check_status)           echo "Status: systemctl status ${SERVICE_NAME}" ;;
                check_smtp_later)       echo "Reconfigure SMTP later: sudo ./configure_smtp.sh" ;;
                test_smtp)              echo "Sending test email" ;;
                smtp_test_ok)           echo "Test email sent successfully" ;;
                smtp_test_failed)       echo "Test email failed (config saved anyway)" ;;
            esac
            ;;
    esac
}

# ============================================================================
# HELPERS
# ============================================================================

log() {
    local level="$1"
    shift
    local msg="$*"
    local color=""
    case "$level" in
        OK)    color="$C_GREEN"  ;;
        INFO)  color="$C_BLUE"   ;;
        WARN)  color="$C_YELLOW" ;;
        ERROR) color="$C_RED"    ;;
        STEP)  color="$C_CYAN"   ;;
    esac
    echo -e "${color}[${level}]${C_RESET} ${msg}"
    [ -d "$LOG_DIR" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [${level}] ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

abort() {
    log ERROR "$1"
    exit 1
}

section() {
    echo ""
    echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║${C_RESET}  $1"
    echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
}

run_cmd() {
    if eval "$1" >> "$LOG_FILE" 2>&1; then
        return 0
    else
        log WARN "Commande échouée : $1"
        return 1
    fi
}

ask_yes_no() {
    # $1 : prompt key, $2 : default Y or N
    local prompt_key="$1"
    local default="${2:-Y}"
    local response
    t "$prompt_key"
    read -r response
    case "${response:-$default}" in
        [oOyY]*) return 0 ;;
        *) return 1 ;;
    esac
}

# ============================================================================
# PARSING DES ARGS
# ============================================================================

while [ $# -gt 0 ]; do
    case "$1" in
        --no-ollama) INSTALL_OLLAMA=0 ;;
        --uninstall)
            log INFO "Pour désinstaller, utilisez : sudo ./uninstall_agent.sh"
            exit 0
            ;;
        -h|--help)
            echo "Usage: sudo $0 [--no-ollama]"
            exit 0
            ;;
    esac
    shift
done

# ============================================================================
# DEMARRAGE
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "$(t must_root)"
    exit 1
fi

# Préparer les dossiers de log immédiatement
mkdir -p "$LOG_DIR"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Installation Module 3 démarrée" >> "$LOG_FILE"

# Bannière
clear || true
echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}                                                                      ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}              ${C_GREEN}SIEM AFRICA — MODULE 3 (Agent)${C_RESET}                          ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}              Installation interactive                                ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}                                                                      ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""

# Choix de la langue
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

# ============================================================================
# PHASE 1 : VERIFICATION DES PREREQUIS
# ============================================================================
section "$(t phase1)"

# Module 2 (BDD)
if [ ! -f "$DB_PATH" ]; then
    abort "$(t missing_db)"
fi
log OK "Module 2 BDD trouvée : $DB_PATH"

# Wazuh
if [ -d "/var/ossec" ] && systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    log OK "$(t wazuh_ok)"
elif [ -d "/var/ossec" ]; then
    log WARN "$(t wazuh_inactive)"
else
    log INFO "$(t wazuh_missing)"
fi

# Snort
if command -v snort >/dev/null 2>&1 || [ -d "/etc/snort" ]; then
    log OK "$(t snort_ok)"
fi

# Python 3
if ! command -v python3 >/dev/null 2>&1; then
    log INFO "Python 3 manquant, installation"
    run_cmd "apt-get update -qq && apt-get install -y python3 python3-pip"
fi
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
log OK "Python ${PYTHON_VERSION}"

# iptables
if ! command -v iptables >/dev/null 2>&1; then
    log INFO "iptables manquant, installation"
    run_cmd "apt-get install -y iptables"
fi
log OK "iptables disponible"

# curl (pour Ollama)
if ! command -v curl >/dev/null 2>&1; then
    run_cmd "apt-get install -y curl"
fi

# Groupe siem-africa (créé par Module 1 ou Module 2 — sinon on le crée)
if ! getent group "$SYSTEM_GROUP" >/dev/null 2>&1; then
    log INFO "Groupe ${SYSTEM_GROUP} manquant, création"
    run_cmd "groupadd --system $SYSTEM_GROUP"
fi
log OK "Groupe ${SYSTEM_GROUP} disponible"

# Détection installation précédente
if [ -d "$INSTALL_DIR" ]; then
    log WARN "Installation précédente détectée : $INSTALL_DIR"
    echo -n "Réinstaller en écrasant l'ancien ? [O/n] : "
    read -r confirm
    case "${confirm:-O}" in
        [nN]*) abort "Installation annulée" ;;
    esac

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log INFO "Arrêt du service existant"
        run_cmd "systemctl stop $SERVICE_NAME"
    fi
    log INFO "Sauvegarde de l'ancien $INSTALL_DIR"
    BACKUP="${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
    run_cmd "mv '$INSTALL_DIR' '$BACKUP'"
fi

# ============================================================================
# PHASE 2 : PREPARATION SYSTEME
# ============================================================================
section "$(t phase2)"

# Utilisateur siem-agent
if ! id "$SYSTEM_USER" >/dev/null 2>&1; then
    log INFO "$(t creating_user) : $SYSTEM_USER"
    run_cmd "useradd --system --gid $SYSTEM_GROUP --shell /usr/sbin/nologin --home-dir $INSTALL_DIR --no-create-home $SYSTEM_USER"
else
    # Vérifier qu'il est dans le bon groupe
    if ! id -nG "$SYSTEM_USER" | grep -qw "$SYSTEM_GROUP"; then
        run_cmd "usermod -aG $SYSTEM_GROUP $SYSTEM_USER"
    fi
fi
log OK "Utilisateur $SYSTEM_USER (membre $SYSTEM_GROUP)"

# Ajouter aussi wazuh/ossec au groupe pour qu'ils puissent lire la BDD si besoin
for ext_user in wazuh ossec; do
    if id "$ext_user" >/dev/null 2>&1; then
        if ! id -nG "$ext_user" | grep -qw "$SYSTEM_GROUP"; then
            log INFO "Ajout de $ext_user au groupe $SYSTEM_GROUP"
            run_cmd "usermod -aG $SYSTEM_GROUP $ext_user"
        fi
    fi
done

# Dossiers
for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"; do
    if [ ! -d "$dir" ]; then
        run_cmd "mkdir -p $dir"
    fi
done

# Permissions
run_cmd "chown -R $SYSTEM_USER:$SYSTEM_GROUP $INSTALL_DIR"
run_cmd "chmod 750 $INSTALL_DIR"

run_cmd "chown root:$SYSTEM_GROUP $CONFIG_DIR"
run_cmd "chmod 750 $CONFIG_DIR"

run_cmd "chown $SYSTEM_USER:$SYSTEM_GROUP $LOG_DIR"
run_cmd "chmod 770 $LOG_DIR"

log OK "Dossiers créés"

# Lecture seule sur alerts.json pour siem-agent (s'il existe)
if [ -f "$ALERTS_JSON" ]; then
    OSSEC_GROUP=$(stat -c "%G" "$ALERTS_JSON" 2>/dev/null || echo "")
    if [ -n "$OSSEC_GROUP" ] && getent group "$OSSEC_GROUP" >/dev/null 2>&1; then
        if ! id -nG "$SYSTEM_USER" | grep -qw "$OSSEC_GROUP"; then
            log INFO "Ajout de $SYSTEM_USER au groupe $OSSEC_GROUP (pour lire alerts.json)"
            run_cmd "usermod -aG $OSSEC_GROUP $SYSTEM_USER"
        fi
    fi
fi

# Python : pas de pip, on utilise stdlib uniquement
log OK "$(t installing_python) : aucune dépendance externe (stdlib only)"

# ============================================================================
# PHASE 3 : COPIE DES FICHIERS
# ============================================================================
section "$(t phase3)"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log INFO "$(t copying_files)"
run_cmd "cp '$SCRIPT_DIR/agent.py' '$INSTALL_DIR/'"
run_cmd "cp -r '$SCRIPT_DIR/modules' '$INSTALL_DIR/'"
run_cmd "chown -R $SYSTEM_USER:$SYSTEM_GROUP $INSTALL_DIR"
run_cmd "chmod 755 $INSTALL_DIR/agent.py"
log OK "Fichiers Python copiés"

# ============================================================================
# PHASE 4 : CONFIGURATION INTERACTIVE
# ============================================================================
section "$(t phase4)"

# Email destinataire
t ask_admin_email
read -r ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-}"

# Langue email
echo ""
echo "$(t ask_lang_default) :"
echo "  1) Français [défaut]"
echo "  2) English"
echo -n "Choice [1]: "
read -r email_lang
case "${email_lang:-1}" in
    2) EMAIL_LANG="en" ;;
    *) EMAIL_LANG="fr" ;;
esac

# Sévérité minimum
echo ""
echo "$(t ask_min_severity) :"
echo "  1) MEDIUM (toutes les alertes importantes)"
echo "  2) HIGH (alertes graves) [défaut]"
echo "  3) CRITICAL (uniquement les critiques)"
echo -n "Choice [2]: "
read -r min_sev
case "${min_sev:-2}" in
    1) MIN_SEVERITY="MEDIUM" ;;
    3) MIN_SEVERITY="CRITICAL" ;;
    *) MIN_SEVERITY="HIGH" ;;
esac

# SMTP
echo ""
SMTP_HOST=""
SMTP_PORT="587"
SMTP_USE_TLS="1"
SMTP_USER=""
SMTP_PASSWORD=""
SMTP_FROM=""

if ask_yes_no ask_smtp_now O; then
    t ask_smtp_host
    read -r SMTP_HOST
    SMTP_HOST="${SMTP_HOST:-}"

    if [ -n "$SMTP_HOST" ]; then
        t ask_smtp_port
        read -r p
        SMTP_PORT="${p:-587}"

        t ask_smtp_tls
        read -r tls
        case "${tls:-O}" in
            [nN]*) SMTP_USE_TLS="0" ;;
            *) SMTP_USE_TLS="1" ;;
        esac

        t ask_smtp_user
        read -r SMTP_USER
        SMTP_USER="${SMTP_USER:-}"

        if [ -n "$SMTP_USER" ]; then
            t ask_smtp_pass
            stty -echo 2>/dev/null
            read -r SMTP_PASSWORD
            stty echo 2>/dev/null
            echo ""
        fi

        DEFAULT_FROM="agent@$(hostname -f 2>/dev/null || hostname)"
        t ask_smtp_from
        read -r SMTP_FROM
        SMTP_FROM="${SMTP_FROM:-$DEFAULT_FROM}"
    fi
fi

# Génération du fichier de config
log INFO "$(t creating_config)"

cat > "$ENV_FILE" <<EOF
# ============================================================================
# SIEM Africa — Module 3 (Agent) — Configuration
# Généré par install_agent.sh le $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

# Chemins système
DB_PATH=${DB_PATH}
ALERTS_JSON=${ALERTS_JSON}
LOG_FILE=${LOG_DIR}/agent.log
PID_FILE=${RUN_DIR}/siem-africa-agent.pid

# Comportement
POLLING_INTERVAL_SEC=5
BATCH_SIZE=100
LOG_LEVEL=INFO
LANG=${EMAIL_LANG}

# Corrélation
CORRELATION_WINDOW_SEC=60
CORRELATION_THRESHOLD=3

# Active Response (blocage iptables auto)
ACTIVE_RESPONSE_ENABLED=1
ACTIVE_RESPONSE_DELAY_SEC=300
ACTIVE_RESPONSE_DURATION_SEC=3600

# Honeypots
HONEYPOT_ENABLED=1
HONEYPOT_SSH_PORT=2222
HONEYPOT_HTTP_PORT=8888
HONEYPOT_MYSQL_PORT=3307
HONEYPOT_AUTO_BLOCK_DURATION_SEC=3600

# IA Ollama
AI_ENABLED=1
AI_PROVIDER=ollama
AI_OLLAMA_URL=${OLLAMA_URL}
AI_OLLAMA_MODEL=${OLLAMA_MODEL}
AI_TIMEOUT_SEC=30
AI_CACHE_ENABLED=1

# Bruit-killer
NOISE_KILLER_THRESHOLD=100
NOISE_KILLER_WINDOW_HOURS=1
NOISE_KILLER_FILTER_DURATION_HOURS=24

# SMTP
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASSWORD}
SMTP_USE_TLS=${SMTP_USE_TLS}
SMTP_FROM=${SMTP_FROM}

# Notifications
ALERT_EMAIL=${ADMIN_EMAIL}
EMAIL_DEDUP_WINDOW_MIN=15
MIN_SEVERITY_FOR_EMAIL=${MIN_SEVERITY}

# Serveur
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
DASHBOARD_URL=http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"):8000
EOF

run_cmd "chown root:$SYSTEM_GROUP $ENV_FILE"
run_cmd "chmod 640 $ENV_FILE"
log OK "Configuration créée : $ENV_FILE"

# Test SMTP si configuré
if [ -n "$SMTP_HOST" ] && [ -n "$ADMIN_EMAIL" ]; then
    log INFO "$(t test_smtp)"
    if SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USER="$SMTP_USER" \
       SMTP_PASSWORD="$SMTP_PASSWORD" SMTP_USE_TLS="$SMTP_USE_TLS" \
       SMTP_FROM="$SMTP_FROM" ALERT_EMAIL="$ADMIN_EMAIL" \
       python3 - <<'PYEOF' 2>>"$LOG_FILE"
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

msg = MIMEText("SIEM Africa — Test SMTP. Si vous recevez ce message, la configuration fonctionne.", "plain", "utf-8")
msg["From"] = sender
msg["To"] = to
msg["Subject"] = "[SIEM Africa] Test SMTP install"

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
        log OK "$(t smtp_test_ok)"
    else
        log WARN "$(t smtp_test_failed)"
    fi
fi

# ============================================================================
# PHASE 5 : OLLAMA
# ============================================================================
section "$(t phase5)"

if [ "$INSTALL_OLLAMA" -eq 0 ]; then
    log INFO "$(t ollama_skip)"
    # Désactiver IA dans la config
    sed -i 's/^AI_ENABLED=1$/AI_ENABLED=0/' "$ENV_FILE"
else
    if ! ask_yes_no ask_install_ollama O; then
        log INFO "$(t ollama_skip)"
        sed -i 's/^AI_ENABLED=1$/AI_ENABLED=0/' "$ENV_FILE"
    else
        # Vérifier si Ollama est déjà installé
        if command -v ollama >/dev/null 2>&1; then
            log OK "$(t ollama_already)"
        else
            log INFO "$(t ollama_installing)"
            if curl -fsSL https://ollama.com/install.sh | sh >> "$LOG_FILE" 2>&1; then
                log OK "Ollama installé"
            else
                log WARN "$(t ollama_failed)"
                sed -i 's/^AI_ENABLED=1$/AI_ENABLED=0/' "$ENV_FILE"
                INSTALL_OLLAMA=0
            fi
        fi

        if [ "$INSTALL_OLLAMA" -eq 1 ] && command -v ollama >/dev/null 2>&1; then
            # Démarrer Ollama (service systemd installé par leur installer)
            if ! systemctl is-active --quiet ollama 2>/dev/null; then
                run_cmd "systemctl enable ollama"
                run_cmd "systemctl start ollama"
                sleep 3
            fi

            # Pull du modèle (peut prendre du temps !)
            log INFO "$(t ollama_pulling)"
            if ollama pull "$OLLAMA_MODEL" >> "$LOG_FILE" 2>&1; then
                log OK "Modèle ${OLLAMA_MODEL} téléchargé"
                # Test rapide
                if curl -s -m 5 "${OLLAMA_URL}/api/tags" | grep -q "$OLLAMA_MODEL" 2>/dev/null; then
                    log OK "$(t ollama_ok)"
                else
                    log WARN "Modèle pullé mais Ollama API non accessible"
                fi
            else
                log WARN "Pull du modèle ${OLLAMA_MODEL} échoué"
                sed -i 's/^AI_ENABLED=1$/AI_ENABLED=0/' "$ENV_FILE"
            fi
        fi
    fi
fi

# ============================================================================
# PHASE 6 : SERVICE SYSTEMD
# ============================================================================
section "$(t phase6)"

log INFO "$(t installing_systemd)"

# Installer le fichier de service depuis systemd/ ou créer à la volée
if [ -f "$SCRIPT_DIR/systemd/${SERVICE_NAME}.service" ]; then
    cp "$SCRIPT_DIR/systemd/${SERVICE_NAME}.service" "$SERVICE_FILE"
else
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SIEM Africa - Intelligent Agent (Module 3)
Documentation=https://github.com/africa-siem/africa-siem
After=network.target wazuh-manager.service
Wants=network.target

[Service]
Type=simple
User=${SYSTEM_USER}
Group=${SYSTEM_GROUP}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agent.py
Restart=on-failure
RestartSec=10s
StartLimitInterval=300
StartLimitBurst=5

# Capabilities pour iptables (Active Response) et ports < 1024 si jamais
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=siem-agent

# Sécurité (sans hardening agressif qui casse CHDIR)
NoNewPrivileges=false
PrivateTmp=false

# Variables d'env
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF
fi

run_cmd "chmod 644 $SERVICE_FILE"
run_cmd "systemctl daemon-reload"
run_cmd "systemctl enable $SERVICE_NAME"

log INFO "$(t starting_service)"
if systemctl start "$SERVICE_NAME"; then
    sleep 3
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log OK "$(t service_started)"
    else
        log ERROR "$(t service_failed)"
    fi
else
    log ERROR "$(t service_failed)"
fi

# ============================================================================
# PHASE 7 : CREDENTIALS + RESUME
# ============================================================================
section "$(t phase7)"

# APPEND credentials
if [ ! -f "$CREDENTIALS_FILE" ]; then
    cat > "$CREDENTIALS_FILE" <<HEADER
═══════════════════════════════════════════════════════════════
SIEM AFRICA - CREDENTIALS
═══════════════════════════════════════════════════════════════
ATTENTION : ce fichier contient des informations sensibles.
Permissions 600 (lecture root uniquement).
═══════════════════════════════════════════════════════════════

HEADER
fi

cat >> "$CREDENTIALS_FILE" <<EOF


═══════════════════════════════════════════════════════════════
[MODULE 3] Agent intelligent
═══════════════════════════════════════════════════════════════
Date d'installation : $(date '+%Y-%m-%d %H:%M:%S')
Version             : 1.0
Chemin install      : ${INSTALL_DIR}
Configuration       : ${ENV_FILE}
Logs                : ${LOG_DIR}/agent.log
Service systemd     : ${SERVICE_NAME}
Utilisateur Linux   : ${SYSTEM_USER} (membre ${SYSTEM_GROUP})

CONFIGURATION ACTIVE
─────────────────────────────────────────────────────────────
Email destinataire  : ${ADMIN_EMAIL:-non configuré}
Langue emails       : ${EMAIL_LANG}
Sévérité min email  : ${MIN_SEVERITY}
SMTP Host           : ${SMTP_HOST:-non configuré}
IA Ollama           : $([ "$INSTALL_OLLAMA" -eq 1 ] && echo "actif (${OLLAMA_MODEL})" || echo "désactivé")
Honeypots           : SSH:2222 HTTP:8888 MySQL:3307
Active Response     : actif (blocage iptables auto pour CRITICAL)

COMMANDES UTILES
─────────────────────────────────────────────────────────────
Statut              : sudo systemctl status ${SERVICE_NAME}
Logs temps réel     : sudo journalctl -u ${SERVICE_NAME} -f
Reconfigurer SMTP   : sudo ./configure_smtp.sh
Désinstaller        : sudo ./uninstall_agent.sh

EOF

run_cmd "chmod 600 $CREDENTIALS_FILE"
run_cmd "chown root:root $CREDENTIALS_FILE"
log OK "Credentials ajoutés à $CREDENTIALS_FILE"

# Résumé final
echo ""
echo -e "${C_GREEN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_GREEN}  $(t summary_title)${C_RESET}"
echo -e "${C_GREEN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo -e "  ${C_CYAN}•${C_RESET} Service          : ${SERVICE_NAME}"
echo -e "  ${C_CYAN}•${C_RESET} Installation     : ${INSTALL_DIR}"
echo -e "  ${C_CYAN}•${C_RESET} Configuration    : ${ENV_FILE}"
echo -e "  ${C_CYAN}•${C_RESET} Logs             : ${LOG_DIR}/agent.log"
echo -e "  ${C_CYAN}•${C_RESET} Credentials      : ${CREDENTIALS_FILE}"
echo ""
echo -e "  $(t check_status)"
echo -e "  $(t check_logs)"
echo -e "  $(t check_smtp_later)"
echo ""

exit 0
