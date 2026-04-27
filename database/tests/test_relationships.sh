#!/bin/bash
# ============================================================================
# Test 3/5 : Intégrité référentielle
# ============================================================================
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

echo "TEST 3/5 : Intégrité référentielle (Foreign Keys)"
echo "================================================="

PASS=0; FAIL=0

# Foreign keys check : aucune ligne ne doit avoir une FK invalide
echo ""
echo "  PRAGMA foreign_key_check:"
FK_ISSUES=$(sqlite3 "$DB_PATH" "PRAGMA foreign_keys = ON; PRAGMA foreign_key_check;")
if [ -z "$FK_ISSUES" ]; then
    echo "    ✓ Aucune violation de foreign key"
    PASS=$((PASS+1))
else
    echo "    ✗ Violations détectées :"
    echo "$FK_ISSUES" | head -10
    FAIL=$((FAIL+1))
fi

# Vérifier les jointures importantes
echo ""
echo "  Tests de jointures :"

# Toutes les signatures ont une catégorie valide
ORPHAN_SIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures s LEFT JOIN signature_categories c ON s.category_id=c.id WHERE c.id IS NULL;")
if [ "$ORPHAN_SIG" = "0" ]; then
    echo "    ✓ Toutes les signatures ont une catégorie valide"
    PASS=$((PASS+1))
else
    echo "    ✗ $ORPHAN_SIG signatures orphelines (sans catégorie)"
    FAIL=$((FAIL+1))
fi

# Toutes les techniques MITRE ont une tactique valide
ORPHAN_TEC=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques t LEFT JOIN mitre_tactics ta ON t.tactic_id=ta.id WHERE ta.id IS NULL;")
if [ "$ORPHAN_TEC" = "0" ]; then
    echo "    ✓ Toutes les techniques MITRE ont une tactique valide"
    PASS=$((PASS+1))
else
    echo "    ✗ $ORPHAN_TEC techniques orphelines"
    FAIL=$((FAIL+1))
fi

# Tous les utilisateurs ont un rôle valide
ORPHAN_USR=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users u LEFT JOIN roles r ON u.role_id=r.id WHERE r.id IS NULL;")
if [ "$ORPHAN_USR" = "0" ]; then
    echo "    ✓ Tous les utilisateurs ont un rôle valide"
    PASS=$((PASS+1))
else
    echo "    ✗ $ORPHAN_USR utilisateurs sans rôle"
    FAIL=$((FAIL+1))
fi

# Test integrity check
echo ""
echo "  PRAGMA integrity_check :"
INT_RESULT=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;")
if [ "$INT_RESULT" = "ok" ]; then
    echo "    ✓ Intégrité de la BDD OK"
    PASS=$((PASS+1))
else
    echo "    ✗ Problèmes d'intégrité : $INT_RESULT"
    FAIL=$((FAIL+1))
fi

echo ""
echo "Résultat : $PASS réussis, $FAIL échoués"
[ "$FAIL" -eq "0" ] && exit 0 || exit 1
