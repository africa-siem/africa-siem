#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Module 4 (Dashboard Django) — Installation
# ============================================================================
# Usage one-liner :
#   curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/dashboard/install.sh | sudo bash
#
# Prérequis :
#   - Module 1 (Wazuh) installé
#   - Module 2 (BDD) installé
#   - Module 3 (Agent) recommandé
# ============================================================================

LC_ALL=C
LANG=C

# Reattach stdin si curl|bash
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

# ============================================================================
# CONSTANTES
# ============================================================================
GITHUB_BASE="https://raw.githubusercontent.com/africa-siem/africa-siem/main/dashboard"
WORK_DIR="/tmp/siem-africa-m4-install-$$"

SYSTEM_GROUP="siem-africa"
SYSTEM_USER="siem-dashboard"
INSTALL_DIR="/opt/siem-africa-dashboard"
CONFIG_DIR="/etc/siem-africa"
LOG_DIR="/var/log/siem-africa"
DB_PATH="/var/lib/siem-africa/siem.db"
ENV_FILE="${CONFIG_DIR}/dashboard.env"
SERVICE_NAME="siem-dashboard"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CREDENTIALS_FILE="/root/siem_credentials.txt"
PORT=8000

C_RED=$'\033[0;31m'
C_GREEN=$'\033[0;32m'
C_YELLOW=$'\033[0;33m'
C_BLUE=$'\033[0;34m'
C_CYAN=$'\033[0;36m'
C_BOLD=$'\033[1m'
C_RESET=$'\033[0m'

log_ok()    { printf "%s[OK]%s %s\n"    "$C_GREEN"  "$C_RESET" "$*"; }
log_info()  { printf "%s[INFO]%s %s\n"  "$C_BLUE"   "$C_RESET" "$*"; }
log_warn()  { printf "%s[WARN]%s %s\n"  "$C_YELLOW" "$C_RESET" "$*"; }
log_err()   { printf "%s[ERROR]%s %s\n" "$C_RED"    "$C_RESET" "$*"; }

abort() {
    log_err "$1"
    rm -rf "$WORK_DIR" 2>/dev/null
    exit 1
}

cleanup() {
    [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

section() {
    echo ""
    echo "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo "${C_CYAN}  $1${C_RESET}"
    echo "${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
}

# ============================================================================
# CHECKS
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    abort "Ce script doit être lancé en root. Utilisez : sudo bash $0"
fi

clear || true
echo ""
echo "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo "${C_CYAN}║${C_RESET}        ${C_BOLD}SIEM AFRICA — MODULE 4 (Dashboard Django)${C_RESET}                ${C_CYAN}║${C_RESET}"
echo "${C_CYAN}║${C_RESET}        Installation rapide                                       ${C_CYAN}║${C_RESET}"
echo "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""

# ============================================================================
# PHASE 1 : VERIFICATION DES PREREQUIS
# ============================================================================
section "PHASE 1 : Vérification des prérequis"

if [ ! -f "$DB_PATH" ]; then
    abort "Module 2 (BDD) introuvable. Installez-le d'abord."
fi
log_ok "Module 2 BDD trouvée"

# Groupe siem-africa
if ! getent group "$SYSTEM_GROUP" >/dev/null 2>&1; then
    log_info "Création du groupe $SYSTEM_GROUP"
    groupadd --system "$SYSTEM_GROUP"
fi
log_ok "Groupe $SYSTEM_GROUP disponible"

# Python + pip
if ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1
fi
log_ok "Python3 disponible : $(python3 --version)"

# curl
if ! command -v curl >/dev/null 2>&1; then
    apt-get install -y curl >/dev/null 2>&1
fi

# Détection installation précédente
if [ -d "$INSTALL_DIR" ] || [ -f "$SERVICE_FILE" ]; then
    log_warn "Installation précédente détectée — désinstallation auto"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    [ -d "$INSTALL_DIR" ] && mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
    log_ok "Ancienne installation sauvegardée"
fi

# ============================================================================
# PHASE 2 : TELECHARGEMENT DES FICHIERS
# ============================================================================
section "PHASE 2 : Téléchargement des fichiers depuis GitHub"

mkdir -p "$WORK_DIR"/{siem_africa,core,templates,static/css}
cd "$WORK_DIR"

download() {
    local src="$1"
    local dest="$2"
    if curl -sL --fail "$src" -o "$dest" && [ -s "$dest" ]; then
        return 0
    fi
    return 1
}

# Fichiers racine
ROOT_FILES=(manage.py requirements.txt)
for f in "${ROOT_FILES[@]}"; do
    download "${GITHUB_BASE}/${f}" "${WORK_DIR}/${f}" || abort "Téléchargement $f échoué"
    printf "  %s✓%s %s\n" "$C_GREEN" "$C_RESET" "$f"
done

# Package siem_africa
SIEM_FILES=(__init__.py settings.py urls.py wsgi.py)
for f in "${SIEM_FILES[@]}"; do
    download "${GITHUB_BASE}/siem_africa/${f}" "${WORK_DIR}/siem_africa/${f}" || abort "Téléchargement siem_africa/$f échoué"
    printf "  %s✓%s siem_africa/%s\n" "$C_GREEN" "$C_RESET" "$f"
done

# Package core
CORE_FILES=(__init__.py db.py auth.py middleware.py context.py views.py urls.py ai.py)
for f in "${CORE_FILES[@]}"; do
    download "${GITHUB_BASE}/core/${f}" "${WORK_DIR}/core/${f}" || abort "Téléchargement core/$f échoué"
    printf "  %s✓%s core/%s\n" "$C_GREEN" "$C_RESET" "$f"
done

# Templates
TEMPLATE_FILES=(base.html login.html change_password.html dashboard.html alerts.html alert_detail.html filters.html filter_form.html blocked_ips.html mitre.html mitre_detail.html honeypot.html users.html user_form.html settings.html ai.html)
for f in "${TEMPLATE_FILES[@]}"; do
    download "${GITHUB_BASE}/templates/${f}" "${WORK_DIR}/templates/${f}" || abort "Téléchargement templates/$f échoué"
    printf "  %s✓%s templates/%s\n" "$C_GREEN" "$C_RESET" "$f"
done

# CSS
download "${GITHUB_BASE}/static/css/style.css" "${WORK_DIR}/static/css/style.css" || abort "Téléchargement CSS échoué"
printf "  %s✓%s static/css/style.css\n" "$C_GREEN" "$C_RESET"

log_ok "Tous les fichiers téléchargés"

# ============================================================================
# PHASE 3 : INSTALLATION DEPENDANCES PYTHON
# ============================================================================
section "PHASE 3 : Installation des dépendances Python"

log_info "Installation Django + gunicorn + whitenoise + bcrypt"
pip3 install --quiet --break-system-packages \
    'django>=4.2,<5.0' \
    'gunicorn>=21.0' \
    'whitenoise>=6.0' \
    'bcrypt>=4.0' 2>&1 | tail -5 || \
pip3 install --quiet \
    'django>=4.2,<5.0' \
    'gunicorn>=21.0' \
    'whitenoise>=6.0' \
    'bcrypt>=4.0' 2>&1 | tail -5

# Vérifier
python3 -c "import django; print(f'Django {django.__version__}')" 2>/dev/null && \
    log_ok "Django installé : $(python3 -c 'import django; print(django.__version__)')" || \
    abort "Django non installé"

# ============================================================================
# PHASE 4 : PREPARATION SYSTEME
# ============================================================================
section "PHASE 4 : Préparation système"

# Utilisateur siem-dashboard
if ! id "$SYSTEM_USER" >/dev/null 2>&1; then
    log_info "Création de l'utilisateur $SYSTEM_USER"
    useradd --system --gid "$SYSTEM_GROUP" --shell /usr/sbin/nologin \
            --home-dir "$INSTALL_DIR" --no-create-home "$SYSTEM_USER"
fi

# Ajouter au groupe siem-africa pour accès BDD
usermod -aG "$SYSTEM_GROUP" "$SYSTEM_USER" 2>/dev/null || true
log_ok "Utilisateur $SYSTEM_USER prêt"

# Dossiers
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chown "$SYSTEM_USER:$SYSTEM_GROUP" "$LOG_DIR"
chmod 770 "$LOG_DIR"

# Permission BDD : siem-dashboard doit pouvoir lire/écrire
chgrp "$SYSTEM_GROUP" "$DB_PATH" 2>/dev/null
chmod 660 "$DB_PATH" 2>/dev/null
log_ok "Permissions BDD ajustées"

# ============================================================================
# PHASE 5 : COPIE DES FICHIERS
# ============================================================================
section "PHASE 5 : Installation des fichiers"

cp -r "$WORK_DIR"/* "$INSTALL_DIR"/
chown -R "$SYSTEM_USER:$SYSTEM_GROUP" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/manage.py"
log_ok "Fichiers copiés dans $INSTALL_DIR"

# ============================================================================
# PHASE 6 : CONFIGURATION
# ============================================================================
section "PHASE 6 : Configuration"

# Génération SECRET_KEY
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")

# Adresse IP serveur
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# Fichier de config
cat > "$ENV_FILE" <<EOF
# SIEM Africa - Dashboard Django config
# Généré : $(date '+%Y-%m-%d %H:%M:%S')

SECRET_KEY=${SECRET_KEY}
DEBUG=0
DB_PATH=${DB_PATH}
SERVER_IP=${SERVER_IP}
DASHBOARD_PORT=${PORT}
EOF

chown root:"$SYSTEM_GROUP" "$ENV_FILE"
chmod 640 "$ENV_FILE"
log_ok "Fichier de config créé : $ENV_FILE"

# ============================================================================
# PHASE 7 : INIT DJANGO (sessions DB + collectstatic)
# ============================================================================
section "PHASE 7 : Initialisation Django"

cd "$INSTALL_DIR"

# Créer la BDD des sessions Django
sudo -u "$SYSTEM_USER" python3 manage.py migrate --run-syncdb >> "$LOG_DIR/dashboard-install.log" 2>&1
log_ok "BDD sessions Django initialisée"

# Collecter les fichiers statiques
sudo -u "$SYSTEM_USER" python3 manage.py collectstatic --noinput >> "$LOG_DIR/dashboard-install.log" 2>&1
log_ok "Fichiers statiques collectés"

# ============================================================================
# PHASE 8 : SERVICE SYSTEMD
# ============================================================================
section "PHASE 8 : Service systemd"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SIEM Africa - Dashboard Django (Module 4)
Documentation=https://github.com/africa-siem/africa-siem
After=network.target siem-agent.service
Wants=network.target

[Service]
Type=simple
User=${SYSTEM_USER}
Group=${SYSTEM_GROUP}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 -m gunicorn \\
    --bind 0.0.0.0:${PORT} \\
    --workers 3 \\
    --timeout 120 \\
    --access-logfile ${LOG_DIR}/dashboard-access.log \\
    --error-logfile ${LOG_DIR}/dashboard-error.log \\
    siem_africa.wsgi:application

Restart=on-failure
RestartSec=10s
StartLimitInterval=300
StartLimitBurst=5

Environment=DJANGO_SETTINGS_MODULE=siem_africa.settings
Environment=PYTHONUNBUFFERED=1

NoNewPrivileges=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1

log_info "Démarrage du service"
systemctl start "$SERVICE_NAME"
sleep 4

if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Service ${SERVICE_NAME} ACTIF"
else
    log_warn "Service non actif — diagnostic :"
    journalctl -u "$SERVICE_NAME" -n 15 --no-pager 2>/dev/null | tail -10
fi

# ============================================================================
# PHASE 9 : CREDENTIALS + RESUME
# ============================================================================
section "PHASE 9 : Finalisation"

# Récupérer admin existant du Module 2
ADMIN_EMAIL=$(sqlite3 "$DB_PATH" "SELECT email FROM users u JOIN roles r ON u.role_id=r.id WHERE r.code='ADMIN' AND u.is_active=1 LIMIT 1" 2>/dev/null || echo "")

# APPEND credentials
cat >> "$CREDENTIALS_FILE" <<EOF


═══════════════════════════════════════════════════════════════
[MODULE 4] Dashboard Django
═══════════════════════════════════════════════════════════════
Date d'installation : $(date '+%Y-%m-%d %H:%M:%S')
Version             : 1.0
Chemin install      : ${INSTALL_DIR}
Configuration       : ${ENV_FILE}
Service systemd     : ${SERVICE_NAME}
Logs                : ${LOG_DIR}/dashboard-{access,error}.log
Utilisateur Linux   : ${SYSTEM_USER} (membre ${SYSTEM_GROUP})

ACCES AU DASHBOARD
─────────────────────────────────────────────────────────────
URL                 : http://${SERVER_IP}:${PORT}
Login admin         : ${ADMIN_EMAIL:-(voir Module 2 credentials)}
Mot de passe        : (celui défini lors du Module 2)

COMMANDES UTILES
─────────────────────────────────────────────────────────────
Statut              : sudo systemctl status ${SERVICE_NAME}
Logs temps réel     : sudo journalctl -u ${SERVICE_NAME} -f
Redémarrer          : sudo systemctl restart ${SERVICE_NAME}

EOF

chmod 600 "$CREDENTIALS_FILE"
log_ok "Credentials ajoutés dans $CREDENTIALS_FILE"

# ============================================================================
# RESUME FINAL
# ============================================================================
echo ""
echo "${C_GREEN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo "${C_GREEN}║${C_RESET}      ${C_BOLD}Module 4 (Dashboard) installé avec succès${C_RESET}                    ${C_GREEN}║${C_RESET}"
echo "${C_GREEN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo "  ${C_CYAN}🌐 ACCES AU DASHBOARD :${C_RESET}"
echo ""
echo "    ${C_BOLD}http://${SERVER_IP}:${PORT}${C_RESET}"
echo ""
echo "  ${C_CYAN}👤 IDENTIFIANTS :${C_RESET}"
echo ""
echo "    Email     : ${ADMIN_EMAIL:-(voir /root/siem_credentials.txt)}"
echo "    Password  : (celui défini au Module 2)"
echo ""
echo "  ${C_CYAN}📋 COMMANDES UTILES :${C_RESET}"
echo ""
echo "    Statut          : sudo systemctl status ${SERVICE_NAME}"
echo "    Logs temps réel : sudo journalctl -u ${SERVICE_NAME} -f"
echo "    Redémarrer      : sudo systemctl restart ${SERVICE_NAME}"
echo ""
echo "  ${C_YELLOW}⚠️  Si le port ${PORT} n'est pas accessible depuis l'extérieur :${C_RESET}"
echo "    sudo ufw allow ${PORT}/tcp"
echo ""

exit 0
