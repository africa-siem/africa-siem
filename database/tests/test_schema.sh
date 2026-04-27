#!/bin/bash
# ============================================================================
# Test 1/5 : Validation du schéma SQL
# ============================================================================
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

echo "TEST 1/5 : Schéma SQL"
echo "====================="

if [ ! -f "$DB_PATH" ]; then
    echo "[FAIL] BDD introuvable : $DB_PATH"
    exit 1
fi

PASS=0
FAIL=0

t() {
    local label="$1"; local actual="$2"; local expected="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  ✓ $label"
        PASS=$((PASS+1))
    else
        echo "  ✗ $label : $actual (attendu $expected)"
        FAIL=$((FAIL+1))
    fi
}

# Tables attendues
EXPECTED_TABLES="ai_explanations alert_filters alerts assets audit_log blocked_ips email_logs honeypot_hits incidents ip_reputation mitre_tactics mitre_techniques notifications raw_events reports roles settings signature_categories signatures threat_intel user_sessions users"

ACTUAL_TABLES=$(sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;" | tr '\n' ' ' | sed 's/ $//')

if [ "$ACTUAL_TABLES" = "$EXPECTED_TABLES" ]; then
    echo "  ✓ Toutes les 22 tables attendues sont présentes"
    PASS=$((PASS+1))
else
    echo "  ✗ Tables différentes :"
    echo "    Attendues : $EXPECTED_TABLES"
    echo "    Présentes : $ACTUAL_TABLES"
    FAIL=$((FAIL+1))
fi

# Tests individuels
TABLES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
t "22 tables" "$TABLES" "22"

VIEWS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='view';")
t "3 vues" "$VIEWS" "3"

FK=$(sqlite3 "$DB_PATH" "PRAGMA foreign_keys = ON; PRAGMA foreign_keys;" | tail -1)
t "Foreign keys ON (avec PRAGMA)" "$FK" "1"

JM=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;")
t "WAL mode" "$JM" "wal"

echo ""
echo "Résultat : $PASS réussis, $FAIL échoués"
[ "$FAIL" -eq "0" ] && exit 0 || exit 1
