#!/bin/bash
# ============================================================================
# SIEM AFRICA - Module 2 (Database)
# database/verify.sh
# ============================================================================
# Vérifie l'intégrité et le bon état de la base de données.
# Utilisable après installation ou périodiquement.
# ============================================================================

DB_PATH="/var/lib/siem-africa/siem.db"

# Couleurs
C_GREEN='\033[0;32m'
C_RED='\033[0;31m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    local op="${4:-eq}"
    
    case "$op" in
        eq)
            if [ "$actual" = "$expected" ]; then
                echo -e "  ${C_GREEN}✓${C_RESET} $label : $actual"
                PASS=$((PASS+1))
            else
                echo -e "  ${C_RED}✗${C_RESET} $label : $actual ${C_RED}(attendu : $expected)${C_RESET}"
                FAIL=$((FAIL+1))
            fi
            ;;
        ge)
            if [ "$actual" -ge "$expected" ] 2>/dev/null; then
                echo -e "  ${C_GREEN}✓${C_RESET} $label : $actual"
                PASS=$((PASS+1))
            else
                echo -e "  ${C_RED}✗${C_RESET} $label : $actual ${C_RED}(attendu ≥ $expected)${C_RESET}"
                FAIL=$((FAIL+1))
            fi
            ;;
        warn)
            if [ "$actual" = "$expected" ]; then
                echo -e "  ${C_GREEN}✓${C_RESET} $label : $actual"
                PASS=$((PASS+1))
            else
                echo -e "  ${C_YELLOW}⚠${C_RESET} $label : $actual ${C_YELLOW}(recommandé : $expected)${C_RESET}"
                WARN=$((WARN+1))
            fi
            ;;
    esac
}

section() {
    echo ""
    echo -e "${C_BOLD}${C_BLUE}── $1 ──${C_RESET}"
}

clear
cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════╗
║              VÉRIFICATION DE LA BASE DE DONNÉES                   ║
║                       SIEM Africa - Module 2                      ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER

# Vérifier que la BDD existe
if [ ! -f "$DB_PATH" ]; then
    echo -e "${C_RED}✗ BDD introuvable : $DB_PATH${C_RESET}"
    echo ""
    echo "Avez-vous lancé install_database.sh ?"
    exit 1
fi

DB_SIZE=$(du -h "$DB_PATH" | cut -f1)
echo ""
echo -e "  📁 BDD trouvée : ${C_GREEN}$DB_PATH${C_RESET} (${DB_SIZE})"

# ============================================================================
# 1. STRUCTURE
# ============================================================================
section "Structure de la base de données"

TABLES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
check "Nombre de tables" "$TABLES" "22"

VIEWS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='view';")
check "Nombre de vues" "$VIEWS" "3"

TRIGGERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger';")
check "Triggers" "$TRIGGERS" "5" "ge"

INDEXES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%';")
check "Index" "$INDEXES" "50" "ge"

# ============================================================================
# 2. CONFIGURATION SQLITE
# ============================================================================
section "Configuration SQLite"

FK=$(sqlite3 "$DB_PATH" "PRAGMA foreign_keys;")
check "Foreign keys" "$FK" "1"

JOURNAL=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;")
check "Journal mode" "$JOURNAL" "wal"

# ============================================================================
# 3. RÉFÉRENTIELS MITRE
# ============================================================================
section "Référentiels MITRE ATT&CK"

TACTICS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_tactics;")
check "Tactiques MITRE" "$TACTICS" "14"

TECHNIQUES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques;")
check "Techniques MITRE" "$TECHNIQUES" "100" "ge"

# ============================================================================
# 4. SIGNATURES
# ============================================================================
section "Signatures de détection"

CATEGORIES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signature_categories;")
check "Catégories" "$CATEGORIES" "10"

SIGS_TOTAL=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures;")
check "Signatures totales" "$SIGS_TOTAL" "380"

SIGS_WAZUH=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='WAZUH';")
check "Signatures Wazuh" "$SIGS_WAZUH" "190"

SIGS_SNORT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='SNORT';")
check "Signatures Snort" "$SIGS_SNORT" "190"

SIGS_MITRE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE technique_id IS NOT NULL;")
check "Signatures mappées MITRE" "$SIGS_MITRE" "300" "ge"

SIGS_NOISY=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE is_noisy=1;")
check "Signatures pré-taggées bruyantes" "$SIGS_NOISY" "1" "ge"

# ============================================================================
# 5. UTILISATEURS & SÉCURITÉ
# ============================================================================
section "Utilisateurs et sécurité"

ROLES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM roles;")
check "Rôles RBAC" "$ROLES" "4"

USERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE is_active=1;")
check "Utilisateurs actifs" "$USERS" "1" "ge"

ADMIN_EXISTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE r.code='ADMIN' AND u.is_active=1;")
check "Au moins 1 admin actif" "$ADMIN_EXISTS" "1" "ge"

# ============================================================================
# 6. CONFIGURATION
# ============================================================================
section "Configuration système"

SETTINGS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM settings;")
check "Paramètres système" "$SETTINGS" "30" "ge"

SMTP_KEYS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM settings WHERE category='smtp';")
check "Paramètres SMTP" "$SMTP_KEYS" "7"

AI_KEYS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM settings WHERE category='ai';")
check "Paramètres IA" "$AI_KEYS" "5" "ge"

# ============================================================================
# 7. FAUX POSITIFS
# ============================================================================
section "Gestion des faux positifs"

FILTERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alert_filters WHERE filter_type='PRE_TAGGED' AND is_active=1;")
check "Filtres pré-taggés actifs" "$FILTERS" "5" "ge"

# ============================================================================
# 8. PERMISSIONS FICHIER
# ============================================================================
section "Permissions du fichier BDD"

OWNER=$(stat -c '%U' "$DB_PATH" 2>/dev/null)
check "Propriétaire" "$OWNER" "siem-db" "warn"

GROUP=$(stat -c '%G' "$DB_PATH" 2>/dev/null)
check "Groupe" "$GROUP" "siem-africa" "warn"

PERMS=$(stat -c '%a' "$DB_PATH" 2>/dev/null)
check "Permissions" "$PERMS" "660" "warn"

# ============================================================================
# 9. VUES FONCTIONNELLES
# ============================================================================
section "Vues fonctionnelles"

if sqlite3 "$DB_PATH" "SELECT * FROM v_alerts_enriched LIMIT 1;" >/dev/null 2>&1; then
    echo -e "  ${C_GREEN}✓${C_RESET} Vue v_alerts_enriched accessible"
    PASS=$((PASS+1))
else
    echo -e "  ${C_RED}✗${C_RESET} Vue v_alerts_enriched inaccessible"
    FAIL=$((FAIL+1))
fi

if sqlite3 "$DB_PATH" "SELECT * FROM v_dashboard_metrics LIMIT 1;" >/dev/null 2>&1; then
    echo -e "  ${C_GREEN}✓${C_RESET} Vue v_dashboard_metrics accessible"
    PASS=$((PASS+1))
else
    echo -e "  ${C_RED}✗${C_RESET} Vue v_dashboard_metrics inaccessible"
    FAIL=$((FAIL+1))
fi

if sqlite3 "$DB_PATH" "SELECT * FROM v_top_attackers_week LIMIT 1;" >/dev/null 2>&1; then
    echo -e "  ${C_GREEN}✓${C_RESET} Vue v_top_attackers_week accessible"
    PASS=$((PASS+1))
else
    echo -e "  ${C_RED}✗${C_RESET} Vue v_top_attackers_week inaccessible"
    FAIL=$((FAIL+1))
fi

# ============================================================================
# RÉSUMÉ
# ============================================================================
TOTAL=$((PASS+FAIL+WARN))

echo ""
echo -e "${C_BOLD}${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}                          RÉSUMÉ${C_RESET}"
echo -e "${C_BOLD}${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo -e "  ${C_GREEN}✓ Réussis  : $PASS${C_RESET}"
echo -e "  ${C_YELLOW}⚠ Avertis  : $WARN${C_RESET}"
echo -e "  ${C_RED}✗ Échoués  : $FAIL${C_RESET}"
echo -e "  ────────────"
echo -e "  Total      : $TOTAL"
echo ""

if [ "$FAIL" -eq "0" ]; then
    echo -e "${C_GREEN}${C_BOLD}🎉 La base de données est en parfait état !${C_RESET}"
    echo ""
    exit 0
else
    echo -e "${C_RED}${C_BOLD}⚠️  Des problèmes ont été détectés.${C_RESET}"
    echo "Consulter les logs : /var/log/siem-africa/db-install.log"
    echo ""
    exit 1
fi
