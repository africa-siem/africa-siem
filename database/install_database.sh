#!/bin/bash
# ============================================================================
# SIEM AFRICA - Module 2 (Database)
# database/install_database.sh
# ============================================================================
# Script d'installation interactif de la base de données SQLite.
#
# UTILISATION :
#   sudo ./install_database.sh                # Installation par défaut
#   sudo ./install_database.sh --verbose      # Mode verbose détaillé
#   sudo ./install_database.sh --silent       # Mode silencieux (CI/CD)
#   sudo ./install_database.sh --no-admin     # Ne pas créer admin (déjà existe)
#
# ÉTAPES :
#   1. Vérification des prérequis
#   2. Préparation système (groupe siem-africa, user siem-db)
#   3. Backup BDD existante si présente
#   4. Création de la BDD et import des données
#   5. Génération admin (mot de passe aléatoire 16 chars)
#   6. Configuration des permissions
#   7. APPEND credentials dans /root/siem_credentials.txt
#   8. Vérification finale
# ============================================================================

# NOTE : pas de "set -e" volontairement (cause des arrêts silencieux)

# ============================================================================
# CONSTANTES
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="/var/lib/siem-africa/siem.db"
DB_DIR="/var/lib/siem-africa"
SYSTEM_GROUP="siem-africa"
SYSTEM_USER="siem-db"
CREDENTIALS_FILE="/root/siem_credentials.txt"
LOG_FILE="/var/log/siem-africa/db-install.log"
LOG_DIR="/var/log/siem-africa"

# Couleurs ANSI
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'
C_MAGENTA='\033[0;35m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

# Modes
VERBOSE=1       # Verbose par défaut
SILENT=0
NO_ADMIN=0

# Parser les arguments
for arg in "$@"; do
    case "$arg" in
        --verbose) VERBOSE=2 ;;
        --silent)  VERBOSE=0; SILENT=1 ;;
        --no-admin) NO_ADMIN=1 ;;
        --help|-h)
            cat <<HELP_EOF
SIEM Africa Module 2 - Database installer

Usage: sudo $0 [OPTIONS]

Options:
    --verbose       Mode verbose (toutes commandes affichées)
    --silent        Mode silencieux (uniquement erreurs)
    --no-admin      Ne pas créer d'utilisateur admin
    --help, -h      Cette aide
HELP_EOF
            exit 0
            ;;
    esac
done

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

log() {
    local level="$1"; shift
    local msg="$*"
    local prefix=""
    case "$level" in
        INFO)    prefix="${C_CYAN}[i]${C_RESET}" ;;
        OK)      prefix="${C_GREEN}[✓]${C_RESET}" ;;
        WARN)    prefix="${C_YELLOW}[!]${C_RESET}" ;;
        ERROR)   prefix="${C_RED}[✗]${C_RESET}" ;;
        STEP)    prefix="${C_MAGENTA}[▶]${C_RESET}" ;;
        CMD)     prefix="${C_MAGENTA}[CMD]${C_RESET}" ;;
        PROMPT)  prefix="${C_BOLD}[?]${C_RESET}" ;;
        *)       prefix="[*]" ;;
    esac
    
    [ "$SILENT" = "1" ] && [ "$level" != "ERROR" ] && return
    
    echo -e "${prefix} ${msg}" | tee -a "$LOG_FILE" 2>/dev/null
}

run_cmd() {
    local cmd="$*"
    [ "$VERBOSE" = "2" ] && log CMD "$cmd"
    eval "$cmd" 2>&1 | tee -a "$LOG_FILE" 2>/dev/null
    return ${PIPESTATUS[0]}
}

abort() {
    log ERROR "$@"
    log ERROR "Installation interrompue. Voir $LOG_FILE pour les détails."
    exit 1
}

section() {
    echo ""
    echo -e "${C_BOLD}${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}  $1${C_RESET}"
    echo -e "${C_BOLD}${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
}

random_password() {
    # Génère un mot de passe aléatoire de 16 caractères alphanumériques
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

random_uuid() {
    # Génère un UUID v4 simple
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null || \
            python3 -c "import uuid; print(uuid.uuid4())"
    fi
}

# ============================================================================
# PHASE 0 : INITIALISATION
# ============================================================================

# Créer dossier de logs si absent
mkdir -p "$LOG_DIR" 2>/dev/null
touch "$LOG_FILE" 2>/dev/null

clear
cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║         🛡️   S I E M   A F R I C A   -   M O D U L E   2          ║
║                                                                   ║
║              Installation de la base de données SQLite            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER

log INFO "Démarrage de l'installation Module 2 (Database)"
log INFO "Date : $(date '+%Y-%m-%d %H:%M:%S')"
log INFO "Logs : $LOG_FILE"

# ============================================================================
# PHASE 1 : VÉRIFICATION DES PRÉREQUIS
# ============================================================================

section "PHASE 1 : Vérification des prérequis"

# Droits root
if [ "$EUID" -ne 0 ]; then
    abort "Ce script doit être exécuté avec les droits root (sudo)."
fi
log OK "Droits root confirmés"

# OS supporté
if [ ! -f /etc/os-release ]; then
    abort "Impossible de détecter le système d'exploitation"
fi
. /etc/os-release
case "$ID" in
    ubuntu|debian)
        log OK "Distribution : $PRETTY_NAME"
        ;;
    *)
        log WARN "Distribution non testée : $ID. Continuation à vos risques."
        ;;
esac

# Détection Wazuh (Module 1 ou installation tierce)
WAZUH_DETECTED=0
SNORT_DETECTED=0

if [ -d "/var/ossec" ] && systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    log OK "Wazuh détecté et actif"
    WAZUH_DETECTED=1
elif [ -d "/var/ossec" ]; then
    log WARN "Wazuh installé mais service inactif"
    WAZUH_DETECTED=1
else
    log INFO "Wazuh non détecté (le Module 2 s'installe quand même)"
fi

# Détection Snort (binaire ou config)
if command -v snort >/dev/null 2>&1 || [ -d "/etc/snort" ]; then
    log OK "Snort détecté"
    SNORT_DETECTED=1
else
    log INFO "Snort non détecté (le Module 2 s'installe quand même)"
fi

# SQLite3
if ! command -v sqlite3 >/dev/null 2>&1; then
    log INFO "SQLite3 non trouvé, installation en cours..."
    run_cmd "apt-get update -qq && apt-get install -y sqlite3"
    if ! command -v sqlite3 >/dev/null 2>&1; then
        abort "Impossible d'installer SQLite3"
    fi
fi
SQLITE_VERSION=$(sqlite3 --version | awk '{print $1}')
log OK "SQLite3 disponible (version $SQLITE_VERSION)"

# Python3 (pour génération hash argon2id et UUIDs)
if ! command -v python3 >/dev/null 2>&1; then
    log INFO "Python3 non trouvé, installation en cours..."
    run_cmd "apt-get install -y python3 python3-pip"
fi

# Bibliothèque argon2 pour hash mot de passe
if ! python3 -c "import argon2" 2>/dev/null; then
    log INFO "Installation de python3-argon2..."
    run_cmd "apt-get install -y python3-argon2 2>/dev/null || pip3 install argon2-cffi --break-system-packages"
fi

if python3 -c "import argon2" 2>/dev/null; then
    log OK "Argon2 disponible (hash sécurisé des mots de passe)"
else
    log WARN "Argon2 indisponible, fallback sur SHA-256 (moins sécurisé)"
fi

# Vérification fichiers SQL
REQUIRED_FILES=("schema.sql" "mitre_tactics.sql" "mitre_techniques.sql" "categories.sql" "signatures.sql" "seed.sql")
for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$f" ]; then
        abort "Fichier requis manquant : $SCRIPT_DIR/$f"
    fi
done
log OK "Tous les fichiers SQL sont présents (${#REQUIRED_FILES[@]} fichiers)"

# Détection installation antérieure
if [ -f "$DB_PATH" ]; then
    DB_SIZE=$(du -h "$DB_PATH" | cut -f1)
    log WARN "BDD existante détectée : $DB_PATH ($DB_SIZE)"
    
    # Backup automatique
    BACKUP_PATH="${DB_PATH}.backup.$(date +%Y%m%d_%H%M%S)"
    log INFO "Sauvegarde automatique dans : $BACKUP_PATH"
    run_cmd "cp '$DB_PATH' '$BACKUP_PATH'"
    if [ ! -f "$BACKUP_PATH" ]; then
        abort "Échec de la sauvegarde de la BDD existante"
    fi
    log OK "Backup créé"
    
    # Suppression BDD existante
    log INFO "Suppression de l'ancienne BDD pour réinstallation propre..."
    run_cmd "rm -f '$DB_PATH' '${DB_PATH}-wal' '${DB_PATH}-shm'"
fi

# ============================================================================
# PHASE 2 : PRÉPARATION SYSTÈME
# ============================================================================

section "PHASE 2 : Préparation système"

# Créer le groupe siem-africa s'il n'existe pas
if ! getent group "$SYSTEM_GROUP" >/dev/null 2>&1; then
    log INFO "Création du groupe système : $SYSTEM_GROUP"
    run_cmd "groupadd --system $SYSTEM_GROUP"
fi
log OK "Groupe $SYSTEM_GROUP disponible"

# Créer l'utilisateur siem-db s'il n'existe pas
if ! id "$SYSTEM_USER" >/dev/null 2>&1; then
    log INFO "Création de l'utilisateur système : $SYSTEM_USER"
    run_cmd "useradd --system --gid $SYSTEM_GROUP --shell /usr/sbin/nologin --home-dir $DB_DIR --no-create-home $SYSTEM_USER"
fi
log OK "Utilisateur $SYSTEM_USER disponible"

# Ajouter wazuh/snort au groupe siem-africa s'ils existent
# Cela leur permet d'accéder à siem.db (permissions 660 siem-db:siem-africa)
for ext_user in wazuh ossec snort; do
    if id "$ext_user" >/dev/null 2>&1; then
        if ! id -nG "$ext_user" | grep -qw "$SYSTEM_GROUP"; then
            log INFO "Ajout de l'utilisateur '$ext_user' au groupe $SYSTEM_GROUP"
            run_cmd "usermod -aG $SYSTEM_GROUP $ext_user"
        else
            log OK "Utilisateur '$ext_user' déjà dans le groupe $SYSTEM_GROUP"
        fi
    fi
done

# Créer le dossier de la BDD
if [ ! -d "$DB_DIR" ]; then
    log INFO "Création du dossier : $DB_DIR"
    run_cmd "mkdir -p $DB_DIR"
fi
log OK "Dossier $DB_DIR prêt"

# ============================================================================
# PHASE 3 : CRÉATION DE LA BASE DE DONNÉES
# ============================================================================

section "PHASE 3 : Création de la base de données"

cd "$SCRIPT_DIR" || abort "Impossible de cd vers $SCRIPT_DIR"

log STEP "Étape 1/6 : Schéma (22 tables, 3 vues, 9 triggers, 88 index)"
run_cmd "sqlite3 '$DB_PATH' < schema.sql"
TABLE_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
[ "$TABLE_COUNT" = "22" ] && log OK "22 tables créées" || log WARN "Tables : $TABLE_COUNT (attendu 22)"

log STEP "Étape 2/6 : Tactiques MITRE (14)"
run_cmd "sqlite3 '$DB_PATH' < mitre_tactics.sql"
TAC_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_tactics;")
log OK "$TAC_COUNT tactiques MITRE insérées"

log STEP "Étape 3/6 : Techniques MITRE (137)"
run_cmd "sqlite3 '$DB_PATH' < mitre_techniques.sql"
TEC_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques;")
log OK "$TEC_COUNT techniques MITRE insérées"

log STEP "Étape 4/6 : Catégories de signatures (10)"
run_cmd "sqlite3 '$DB_PATH' < categories.sql"
CAT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signature_categories;")
log OK "$CAT_COUNT catégories insérées"

log STEP "Étape 5/6 : Signatures (380)"
run_cmd "sqlite3 '$DB_PATH' < signatures.sql"
SIG_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures;")
WAZUH_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='WAZUH';")
SNORT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='SNORT';")
log OK "$SIG_COUNT signatures insérées ($WAZUH_COUNT Wazuh + $SNORT_COUNT Snort)"

log STEP "Étape 6/6 : Données initiales (rôles, settings, filtres)"
run_cmd "sqlite3 '$DB_PATH' < seed.sql"
ROLE_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM roles;")
SET_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM settings;")
FLT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alert_filters WHERE filter_type='PRE_TAGGED';")
log OK "$ROLE_COUNT rôles, $SET_COUNT settings, $FLT_COUNT filtres pré-taggés"

# Mettre à jour la date d'installation
INSTALL_DATE="$(date -Iseconds)"
sqlite3 "$DB_PATH" "UPDATE settings SET value='$INSTALL_DATE' WHERE key='install_date';"

# ============================================================================
# PHASE 4 : CRÉATION DE L'UTILISATEUR ADMIN
# ============================================================================

if [ "$NO_ADMIN" = "0" ]; then
    section "PHASE 4 : Création de l'utilisateur admin"
    
    # Demander email admin
    DEFAULT_EMAIL="admin@siem-africa.local"
    if [ "$SILENT" = "1" ]; then
        ADMIN_EMAIL="$DEFAULT_EMAIL"
    else
        echo ""
        log PROMPT "Email de l'administrateur SIEM Africa"
        echo -n "    (défaut: $DEFAULT_EMAIL) > "
        read -r ADMIN_EMAIL
        ADMIN_EMAIL="${ADMIN_EMAIL:-$DEFAULT_EMAIL}"
    fi
    
    # Demander nom organisation
    if [ "$SILENT" = "0" ]; then
        echo ""
        log PROMPT "Nom de votre organisation"
        echo -n "    (défaut: SIEM Africa) > "
        read -r ORG_NAME
        ORG_NAME="${ORG_NAME:-SIEM Africa}"
        sqlite3 "$DB_PATH" "UPDATE settings SET value='$ORG_NAME' WHERE key='org_name';"
        log OK "Organisation : $ORG_NAME"
    fi
    
    # Générer mot de passe aléatoire
    ADMIN_PASSWORD=$(random_password)
    ADMIN_UUID=$(random_uuid)
    
    # Hash argon2id
    PASSWORD_HASH=$(python3 -c "
import sys
try:
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    print(ph.hash('$ADMIN_PASSWORD'))
except ImportError:
    import hashlib
    print('sha256\$' + hashlib.sha256(b'$ADMIN_PASSWORD').hexdigest())
" 2>/dev/null)
    
    if [ -z "$PASSWORD_HASH" ]; then
        abort "Impossible de générer le hash du mot de passe"
    fi
    
    # Insérer admin
    sqlite3 "$DB_PATH" <<SQL
INSERT INTO users (
    user_uuid, email, first_name, last_name, password_hash,
    must_change_pwd, is_active, role_id, language, timezone
) VALUES (
    '$ADMIN_UUID',
    '$ADMIN_EMAIL',
    'Administrator',
    'SIEM Africa',
    '$PASSWORD_HASH',
    1, 1, 1, 'fr', 'Africa/Abidjan'
);
SQL
    
    if [ $? -eq 0 ]; then
        log OK "Utilisateur admin créé : $ADMIN_EMAIL"
    else
        abort "Échec création utilisateur admin"
    fi
fi

# ============================================================================
# PHASE 5 : PERMISSIONS
# ============================================================================

section "PHASE 5 : Configuration des permissions"

run_cmd "chown -R $SYSTEM_USER:$SYSTEM_GROUP $DB_DIR"
run_cmd "chmod 770 $DB_DIR"
run_cmd "chmod 660 $DB_PATH"
[ -f "${DB_PATH}-wal" ] && run_cmd "chmod 660 ${DB_PATH}-wal"
[ -f "${DB_PATH}-shm" ] && run_cmd "chmod 660 ${DB_PATH}-shm"

# Permissions logs
run_cmd "chown -R $SYSTEM_USER:$SYSTEM_GROUP $LOG_DIR"
run_cmd "chmod 770 $LOG_DIR"

log OK "Permissions configurées : $SYSTEM_USER:$SYSTEM_GROUP, mode 660/770"

# ============================================================================
# PHASE 6 : APPEND DANS /root/siem_credentials.txt
# ============================================================================

section "PHASE 6 : Sauvegarde des credentials"

# Créer le fichier s'il n'existe pas (Module 1 devrait l'avoir créé)
if [ ! -f "$CREDENTIALS_FILE" ]; then
    log WARN "Fichier $CREDENTIALS_FILE n'existe pas (Module 1 absent ?)"
    log INFO "Création d'un nouveau fichier credentials"
    cat > "$CREDENTIALS_FILE" <<HEADER
═══════════════════════════════════════════════════════════════
SIEM AFRICA - CREDENTIALS
═══════════════════════════════════════════════════════════════
ATTENTION : ce fichier contient des informations sensibles.
Ne pas le partager. Permissions 600 (lecture root uniquement).

HEADER
fi

# APPEND la section Module 2 (sans écraser le Module 1)
cat >> "$CREDENTIALS_FILE" <<EOF


═══════════════════════════════════════════════════════════════
[MODULE 2] Base de données SQLite
═══════════════════════════════════════════════════════════════
Date              : $INSTALL_DATE
Chemin BDD        : $DB_PATH
Taille BDD        : $(du -h "$DB_PATH" | cut -f1)

CONTENU DE LA BDD
─────────────────────────────────────────────────────────────
Tables            : $TABLE_COUNT
Tactiques MITRE   : $TAC_COUNT
Techniques MITRE  : $TEC_COUNT
Catégories        : $CAT_COUNT
Signatures        : $SIG_COUNT (Wazuh: $WAZUH_COUNT, Snort: $SNORT_COUNT)
Rôles RBAC        : $ROLE_COUNT
Settings          : $SET_COUNT
Filtres pré-tag   : $FLT_COUNT

EOF

if [ "$NO_ADMIN" = "0" ]; then
    cat >> "$CREDENTIALS_FILE" <<EOF
ADMIN DASHBOARD (à utiliser pour le premier login)
─────────────────────────────────────────────────────────────
Email             : $ADMIN_EMAIL
Mot de passe      : $ADMIN_PASSWORD
Rôle              : ADMIN (tous les droits)

⚠ IMPORTANT : ce mot de passe doit être changé à la première
   connexion. La page de login forcera le changement.

EOF
fi

cat >> "$CREDENTIALS_FILE" <<EOF
UTILISATEUR SYSTÈME LINUX
─────────────────────────────────────────────────────────────
Username          : $SYSTEM_USER
Groupe            : $SYSTEM_GROUP
Permissions       : 660 (lecture/écriture user et groupe)

COMMANDES UTILES
─────────────────────────────────────────────────────────────
# Inspecter la BDD
sudo -u $SYSTEM_USER sqlite3 $DB_PATH

# Voir les alertes récentes
sudo -u $SYSTEM_USER sqlite3 $DB_PATH "SELECT * FROM v_alerts_enriched LIMIT 10;"

# Voir les métriques dashboard
sudo -u $SYSTEM_USER sqlite3 $DB_PATH "SELECT * FROM v_dashboard_metrics;"

# Lancer la vérification
sudo $SCRIPT_DIR/verify.sh

EOF

# Permissions strictes du fichier credentials
chmod 600 "$CREDENTIALS_FILE"
log OK "Credentials ajoutés à $CREDENTIALS_FILE"

# ============================================================================
# PHASE 7 : VÉRIFICATION FINALE
# ============================================================================

section "PHASE 7 : Vérification finale"

# Test requête simple
TEST_RESULT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM v_dashboard_metrics;" 2>&1)
if [ "$TEST_RESULT" = "1" ]; then
    log OK "Vue v_dashboard_metrics fonctionnelle"
else
    log WARN "Vue v_dashboard_metrics : $TEST_RESULT"
fi

# Test foreign keys
FK_STATE=$(sqlite3 "$DB_PATH" "PRAGMA foreign_keys;")
[ "$FK_STATE" = "1" ] && log OK "Foreign keys activées" || log WARN "Foreign keys désactivées"

# Test journal mode
JOURNAL_MODE=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;")
[ "$JOURNAL_MODE" = "wal" ] && log OK "Mode WAL activé" || log WARN "Mode journal : $JOURNAL_MODE"

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

section "✅ INSTALLATION TERMINÉE"

cat <<SUMMARY

  ${C_GREEN}🎉 La base de données SIEM Africa est installée et opérationnelle.${C_RESET}

  📊 STATISTIQUES
  ───────────────
  • Tables          : $TABLE_COUNT
  • Signatures      : $SIG_COUNT (Wazuh: $WAZUH_COUNT, Snort: $SNORT_COUNT)
  • Tactiques MITRE : $TAC_COUNT
  • Techniques MITRE: $TEC_COUNT
  • Catégories      : $CAT_COUNT
  • Settings        : $SET_COUNT (dont 7 SMTP vides)
  • Filtres bruit   : $FLT_COUNT

  📁 EMPLACEMENTS
  ───────────────
  • BDD SQLite      : $DB_PATH
  • Logs            : $LOG_FILE
  • Credentials     : $CREDENTIALS_FILE

SUMMARY

if [ "$NO_ADMIN" = "0" ]; then
    cat <<ADMIN_INFO
  👤 ADMIN CRÉÉ
  ─────────────
  • Email           : $ADMIN_EMAIL
  • Mot de passe    : ${C_YELLOW}$ADMIN_PASSWORD${C_RESET}
  
  ${C_YELLOW}⚠  IMPORTANT : notez ce mot de passe (aussi sauvegardé dans $CREDENTIALS_FILE).${C_RESET}
  ${C_YELLOW}   Il vous sera demandé de le changer à la première connexion.${C_RESET}

ADMIN_INFO
fi

cat <<NEXT_STEPS

  🚀 PROCHAINES ÉTAPES
  ───────────────────
  1. Vérification     : sudo $SCRIPT_DIR/verify.sh
  2. Tests            : sudo $SCRIPT_DIR/tests/run_all_tests.sh
  3. Module 3 (agent) : installation à venir
  4. Module 4 (UI)    : installation à venir

NEXT_STEPS

log OK "Installation Module 2 terminée avec succès"
exit 0
