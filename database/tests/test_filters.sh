#!/bin/bash
# ============================================================================
# Test 5/5 : Gestion des faux positifs (filtres)
# ============================================================================
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

echo "TEST 5/5 : Gestion des faux positifs"
echo "===================================="

PASS=0; FAIL=0

t() {
    local label="$1"; local actual="$2"; local expected="$3"; local op="${4:-eq}"
    case "$op" in
        eq) [ "$actual" = "$expected" ] && { echo "  ✓ $label : $actual"; PASS=$((PASS+1)); } || { echo "  ✗ $label : $actual (attendu $expected)"; FAIL=$((FAIL+1)); } ;;
        ge) [ "$actual" -ge "$expected" ] && { echo "  ✓ $label : $actual"; PASS=$((PASS+1)); } || { echo "  ✗ $label : $actual (attendu ≥ $expected)"; FAIL=$((FAIL+1)); } ;;
    esac
}

# Filtres pré-taggés
echo ""
echo "  Mécanisme 1/5 : Pré-tagging des règles bruyantes"
PRE_TAG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alert_filters WHERE filter_type='PRE_TAGGED' AND is_active=1;")
t "Filtres pré-taggés actifs" "$PRE_TAG" "5" "ge"

# Vérifier que les règles bruyantes connues ont un filtre
for SIG_ID in 5402 5501 5715 31100; do
    EXISTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alert_filters WHERE signature_id=$SIG_ID AND is_active=1;")
    if [ "$EXISTS" -ge "1" ]; then
        echo "  ✓ Filtre actif pour rule_id $SIG_ID"
        PASS=$((PASS+1))
    else
        echo "  ⚠ Pas de filtre pour rule_id $SIG_ID"
    fi
done

# Mécanisme 2 : workflow FALSE_POSITIVE
echo ""
echo "  Mécanisme 2/5 : Workflow manuel FALSE_POSITIVE"

# Vérifier que la table alerts a bien le statut FALSE_POSITIVE
HAS_FP=$(sqlite3 "$DB_PATH" "SELECT sql FROM sqlite_master WHERE name='alerts';" | grep -c "FALSE_POSITIVE")
t "Statut FALSE_POSITIVE défini dans schéma alerts" "$HAS_FP" "1" "ge"

# Mécanisme 3 : bruit-killer auto
echo ""
echo "  Mécanisme 3/5 : Bruit-killer automatique (settings)"
NK_ENABLED=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='noise_killer_enabled';")
t "noise_killer_enabled" "$NK_ENABLED" "1"

NK_THRESHOLD=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='noise_killer_threshold_per_hour';")
t "noise_killer_threshold_per_hour" "$NK_THRESHOLD" "100"

# Mécanisme 4 : confidence dynamique (triggers)
echo ""
echo "  Mécanisme 4/5 : Confidence dynamique (triggers)"
TRG_DEC=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='trg_decrease_confidence_on_fp';")
t "Trigger trg_decrease_confidence_on_fp" "$TRG_DEC" "1"

TRG_INC=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='trg_increase_confidence_on_resolved';")
t "Trigger trg_increase_confidence_on_resolved" "$TRG_INC" "1"

# Mécanisme 5 : table alert_filters
echo ""
echo "  Mécanisme 5/5 : Table alert_filters"
TBL_FLT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alert_filters';")
t "Table alert_filters existe" "$TBL_FLT" "1"

# Test fonctionnel : insérer une alerte, marquer FP, vérifier que la confidence baisse
echo ""
echo "  Test fonctionnel : trigger confidence dynamique"

# Préparer un asset de test
sqlite3 "$DB_PATH" "INSERT OR IGNORE INTO assets (asset_uuid, hostname, ip_address, asset_type) VALUES ('test-asset-uuid', 'test-host', '10.0.0.1', 'SERVER');" 2>/dev/null

# Mémoriser confidence avant
CONF_BEFORE=$(sqlite3 "$DB_PATH" "SELECT confidence FROM signatures WHERE id=5712;")

# Insérer alerte de test
TEST_UUID="test-alert-$(date +%s)"
sqlite3 "$DB_PATH" <<SQL 2>/dev/null
INSERT INTO alerts (alert_uuid, signature_id, severity, title, first_seen, last_seen, status)
VALUES ('$TEST_UUID', 5712, 'HIGH', 'Test alert', datetime('now'), datetime('now'), 'NEW');
SQL

# Marquer FALSE_POSITIVE
sqlite3 "$DB_PATH" "UPDATE alerts SET status='FALSE_POSITIVE' WHERE alert_uuid='$TEST_UUID';" 2>/dev/null

# Vérifier que la confidence a baissé
CONF_AFTER=$(sqlite3 "$DB_PATH" "SELECT confidence FROM signatures WHERE id=5712;")

if [ "$CONF_AFTER" -lt "$CONF_BEFORE" ]; then
    echo "  ✓ Confidence ajustée : $CONF_BEFORE → $CONF_AFTER"
    PASS=$((PASS+1))
elif [ "$CONF_BEFORE" = "50" ] && [ "$CONF_AFTER" = "50" ]; then
    echo "  ✓ Confidence déjà au plancher (50)"
    PASS=$((PASS+1))
else
    echo "  ⚠ Confidence inchangée : $CONF_BEFORE → $CONF_AFTER"
fi

# Cleanup
sqlite3 "$DB_PATH" "DELETE FROM alerts WHERE alert_uuid='$TEST_UUID';" 2>/dev/null
sqlite3 "$DB_PATH" "DELETE FROM assets WHERE asset_uuid='test-asset-uuid';" 2>/dev/null

echo ""
echo "Résultat : $PASS réussis, $FAIL échoués"
[ "$FAIL" -eq "0" ] && exit 0 || exit 1
