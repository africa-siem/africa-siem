#!/bin/bash
# ============================================================================
# Test 2/5 : Validation des signatures
# ============================================================================
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

echo "TEST 2/5 : Signatures"
echo "====================="

PASS=0; FAIL=0

t() {
    local label="$1"; local actual="$2"; local expected="$3"; local op="${4:-eq}"
    case "$op" in
        eq) [ "$actual" = "$expected" ] && { echo "  ✓ $label : $actual"; PASS=$((PASS+1)); } || { echo "  ✗ $label : $actual (attendu $expected)"; FAIL=$((FAIL+1)); } ;;
        ge) [ "$actual" -ge "$expected" ] && { echo "  ✓ $label : $actual"; PASS=$((PASS+1)); } || { echo "  ✗ $label : $actual (attendu ≥ $expected)"; FAIL=$((FAIL+1)); } ;;
    esac
}

# Comptages
TOTAL=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures;")
t "Total signatures" "$TOTAL" "380"

WAZUH=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='WAZUH';")
t "Signatures Wazuh" "$WAZUH" "190"

SNORT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='SNORT';")
t "Signatures Snort" "$SNORT" "190"

# Mapping MITRE
WITH_MITRE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE technique_id IS NOT NULL;")
t "Mappées MITRE" "$WITH_MITRE" "300" "ge"

# Catégories
ALL_CAT=$(sqlite3 "$DB_PATH" "SELECT COUNT(DISTINCT category_id) FROM signatures;")
t "Catégories utilisées" "$ALL_CAT" "5" "ge"

# Sévérités
CRITICAL=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE severity='CRITICAL';")
t "Signatures CRITICAL" "$CRITICAL" "20" "ge"

HIGH=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE severity='HIGH';")
t "Signatures HIGH" "$HIGH" "50" "ge"

# Pré-tagging
NOISY=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE is_noisy=1;")
t "Signatures bruyantes" "$NOISY" "1" "ge"

# Vérifier signatures clés
echo ""
echo "  Vérification signatures clés :"
for SID in 5710 5712 5402 31510 100100; do
    EXISTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE id=$SID;")
    [ "$EXISTS" = "1" ] && { echo "    ✓ Signature $SID présente"; PASS=$((PASS+1)); } || { echo "    ✗ Signature $SID manquante"; FAIL=$((FAIL+1)); }
done

echo ""
echo "Résultat : $PASS réussis, $FAIL échoués"
[ "$FAIL" -eq "0" ] && exit 0 || exit 1
