#!/usr/bin/env bash
#
# SIEM Africa - Module 2 : SQLite database (14 tables + 2 views + 380 MITRE signatures)
# Target : Ubuntu 22.04 LTS (root required)
# Requires Module 1 (group siem-africa + /opt/siem-africa) to be installed first.
#
# RULES: no "set -e", no PRAGMA journal_mode = WAL, file chmod 664 / siem-africa:siem-africa.

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
DB_FILE="${INSTALL_DIR}/siem_africa.db"
LOG_DIR="/var/log/siem-africa"
RAW_BASE="https://raw.githubusercontent.com/africa-siem/africa-siem/main/database"
SCHEMA_FILE=""
ATTACKS_FILE=""
TMP_DIR=""
LANG_CHOICE=""
STEP_NUM=0

# --------- i18n ---------
say() {
    local key="$1"
    case "$key" in
        banner)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "=== SIEM Africa - Module 2 : Base de donnees ===" \
                || echo "=== SIEM Africa - Module 2: Database ===" ;;
        need_module1)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Module 1 absent : installez d'abord installation/install.sh ou installall.sh." \
                || echo "Module 1 missing: please install installation/install.sh or installall.sh first." ;;
        previous_db)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Une base de donnees existe deja : ${DB_FILE}" \
                || echo "A database already exists: ${DB_FILE}" ;;
        previous_confirm)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Sauvegarder et remplacer ? [O/n] : " \
                || echo -n "Backup and replace? [Y/n]: " ;;
        backing_up)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Sauvegarde de l'ancienne base..." \
                || echo "Backing up previous database..." ;;
        installing_deps)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation des dependances SQLite..." \
                || echo "Installing SQLite dependencies..." ;;
        downloading)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Telechargement des scripts SQL..." \
                || echo "Downloading SQL scripts..." ;;
        building_db)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Creation de la base et import du schema..." \
                || echo "Creating database and importing schema..." ;;
        loading_signatures)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Chargement des 380 signatures MITRE ATT&CK..." \
                || echo "Loading 380 MITRE ATT&CK signatures..." ;;
        setting_perms)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Configuration des permissions (siem-africa:siem-africa, 664)..." \
                || echo "Setting permissions (siem-africa:siem-africa, 664)..." ;;
        verifying)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Verification du contenu de la base..." \
                || echo "Verifying database contents..." ;;
        done_ok)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Module 2 installe avec succes." \
                || echo "Module 2 installed successfully." ;;
        fail_schema)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC : import du schema SQL." \
                || echo "FAIL: schema SQL import." ;;
        fail_attacks)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC : chargement des signatures MITRE." \
                || echo "FAIL: MITRE signatures load." ;;
        fail_verify)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC : verification finale KO." \
                || echo "FAIL: final verification KO." ;;
    esac
}

step() {
    STEP_NUM=$((STEP_NUM + 1))
    echo ""
    echo "----- [${STEP_NUM}] $* -----"
}

cleanup() {
    [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# --------- 0. Pre-flight ---------
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root. Use: sudo bash $0"
    exit 1
fi

# --------- 1. Language ---------
echo "================================================"
echo " SIEM Africa - Module 2 Installer"
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

# --------- 2. Pre-req : group siem-africa + /opt/siem-africa ---------
step "Checking Module 1 prerequisites"
if ! getent group "$GROUP" >/dev/null 2>&1; then
    say need_module1
    exit 1
fi
if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    chown root:"$GROUP" "$INSTALL_DIR"
    chmod 775 "$INSTALL_DIR"
fi
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    chown root:"$GROUP" "$LOG_DIR"
    chmod 755 "$LOG_DIR"
fi

# --------- 3. Detect previous DB ---------
if [ -f "$DB_FILE" ]; then
    say previous_db
    say previous_confirm
    read -r confirm
    case "${confirm:-y}" in
        n|N) echo "Installation cancelled."; exit 0 ;;
    esac
    say backing_up
    BACKUP_NAME="${DB_FILE}.$(date -u +'%Y%m%d-%H%M%S').bak"
    cp -a "$DB_FILE" "$BACKUP_NAME"
    rm -f "$DB_FILE"
fi

# --------- 4. Dependencies ---------
step "$(say installing_deps)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y sqlite3 curl ca-certificates

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "sqlite3 not found after install. Abort."
    exit 1
fi

# --------- 5. Locate or download SQL scripts ---------
step "$(say downloading)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${SCRIPT_DIR}/schema.sql" ] && [ -f "${SCRIPT_DIR}/attacks.sql" ]; then
    SCHEMA_FILE="${SCRIPT_DIR}/schema.sql"
    ATTACKS_FILE="${SCRIPT_DIR}/attacks.sql"
    echo "Using local copies:"
    echo "  ${SCHEMA_FILE}"
    echo "  ${ATTACKS_FILE}"
else
    TMP_DIR=$(mktemp -d /tmp/siem-africa-db.XXXXXX)
    SCHEMA_FILE="${TMP_DIR}/schema.sql"
    ATTACKS_FILE="${TMP_DIR}/attacks.sql"
    curl -fsSL "${RAW_BASE}/schema.sql"  -o "$SCHEMA_FILE"
    curl -fsSL "${RAW_BASE}/attacks.sql" -o "$ATTACKS_FILE"
    if [ ! -s "$SCHEMA_FILE" ] || [ ! -s "$ATTACKS_FILE" ]; then
        echo "Could not download SQL scripts from ${RAW_BASE}"
        exit 1
    fi
    echo "Downloaded to ${TMP_DIR}"
fi

# --------- 6. Build DB ---------
step "$(say building_db)"
sqlite3 "$DB_FILE" < "$SCHEMA_FILE"
RC=$?
if [ $RC -ne 0 ]; then
    say fail_schema
    exit 1
fi

step "$(say loading_signatures)"
sqlite3 "$DB_FILE" < "$ATTACKS_FILE"
RC=$?
if [ $RC -ne 0 ]; then
    say fail_attacks
    exit 1
fi

# --------- 7. Permissions ---------
step "$(say setting_perms)"
chown siem-africa:"$GROUP" "$DB_FILE" 2>/dev/null \
    || chown root:"$GROUP" "$DB_FILE"
chmod 664 "$DB_FILE"

# --------- 8. Verify ---------
step "$(say verifying)"
TACTICS=$(sqlite3 "$DB_FILE"    "SELECT COUNT(*) FROM mitre_tactics;"    2>/dev/null)
TECHNIQUES=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM mitre_techniques;" 2>/dev/null)
SIGNATURES=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM signatures;"       2>/dev/null)
TABLES=$(sqlite3 "$DB_FILE"     "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';" 2>/dev/null)
VIEWS=$(sqlite3 "$DB_FILE"      "SELECT COUNT(*) FROM sqlite_master WHERE type='view';"  2>/dev/null)

echo ""
echo "Tables     : ${TABLES}"
echo "Views      : ${VIEWS}"
echo "Tactics    : ${TACTICS}"
echo "Techniques : ${TECHNIQUES}"
echo "Signatures : ${SIGNATURES}"

OK=1
[ "${TABLES:-0}"     -lt 14  ] && OK=0
[ "${VIEWS:-0}"      -lt 2   ] && OK=0
[ "${TACTICS:-0}"    -lt 14  ] && OK=0
[ "${SIGNATURES:-0}" -lt 380 ] && OK=0

if [ $OK -ne 1 ]; then
    say fail_verify
    exit 1
fi

# --------- 9. Summary ---------
echo ""
echo "================================================"
say done_ok
echo "================================================"
echo ""
echo "Database file : ${DB_FILE}"
echo "Owner / mode  : $(stat -c '%U:%G %a' "$DB_FILE")"
echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Pour interroger la base :"
    echo "  sudo -u siem-africa sqlite3 ${DB_FILE}"
    echo "Prochaine etape : installer le Module 3 (agent Python)."
else
    echo "To query the database:"
    echo "  sudo -u siem-africa sqlite3 ${DB_FILE}"
    echo "Next step : install Module 3 (Python agent)."
fi

exit 0
