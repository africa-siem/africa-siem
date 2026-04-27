#!/bin/bash
# ============================================================================
# Test 4/5 : Performance des requêtes
# ============================================================================
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

echo "TEST 4/5 : Performance des requêtes"
echo "==================================="

PASS=0; FAIL=0

bench() {
    local label="$1"; local query="$2"; local max_ms="$3"
    local start_ns end_ns elapsed_ms
    
    start_ns=$(date +%s%N)
    sqlite3 "$DB_PATH" "$query" > /dev/null 2>&1
    end_ns=$(date +%s%N)
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    
    if [ "$elapsed_ms" -le "$max_ms" ]; then
        echo "  ✓ $label : ${elapsed_ms}ms (max ${max_ms}ms)"
        PASS=$((PASS+1))
    else
        echo "  ✗ $label : ${elapsed_ms}ms (max ${max_ms}ms)"
        FAIL=$((FAIL+1))
    fi
}

# Tests de performance critique
echo ""
echo "  Requêtes critiques (utilisées par l'agent Module 3) :"

bench "SELECT signature WHERE id=X (lookup direct)" \
    "SELECT * FROM signatures WHERE id = 5712;" 50

bench "SELECT signatures par catégorie" \
    "SELECT * FROM signatures WHERE category_id = 1;" 100

bench "JOIN signature + catégorie + technique MITRE" \
    "SELECT s.id, s.name, c.name, t.name FROM signatures s JOIN signature_categories c ON s.category_id=c.id LEFT JOIN mitre_techniques t ON s.technique_id=t.id LIMIT 100;" 200

echo ""
echo "  Vues du dashboard :"

bench "v_dashboard_metrics" \
    "SELECT * FROM v_dashboard_metrics;" 100

bench "v_alerts_enriched (vide)" \
    "SELECT * FROM v_alerts_enriched LIMIT 50;" 100

bench "v_top_attackers_week (vide)" \
    "SELECT * FROM v_top_attackers_week;" 100

echo ""
echo "  Requêtes complexes :"

bench "Comptage par sévérité" \
    "SELECT severity, COUNT(*) FROM signatures GROUP BY severity;" 50

bench "Recherche full-text dans descriptions" \
    "SELECT id, name FROM signatures WHERE description_fr LIKE '%brute%';" 100

# Taille BDD
DB_SIZE=$(stat -c '%s' "$DB_PATH")
DB_SIZE_KB=$((DB_SIZE / 1024))
echo ""
echo "  Taille BDD : ${DB_SIZE_KB} KB"

if [ "$DB_SIZE_KB" -lt "5000" ]; then
    echo "  ✓ Taille BDD raisonnable (< 5 MB)"
    PASS=$((PASS+1))
else
    echo "  ⚠ Taille BDD : ${DB_SIZE_KB} KB"
fi

echo ""
echo "Résultat : $PASS réussis, $FAIL échoués"
[ "$FAIL" -eq "0" ] && exit 0 || exit 1
