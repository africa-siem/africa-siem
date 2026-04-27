#!/usr/bin/env bash
# Test : matching rule_id → signature dans la BDD

DB_PATH="/var/lib/siem-africa/siem.db"
SYSTEM_USER="siem-agent"

# Vérifier qu'on a bien 380 signatures
NB=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures" 2>/dev/null)
if [ "$NB" -lt 380 ]; then
    echo "  Seulement $NB signatures (attendu 380)"
    exit 1
fi

# Tester quelques lookups critiques
for rule_id in 5712 5501 5402 5715 31509; do
    found=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
        "SELECT name FROM signatures WHERE id=$rule_id LIMIT 1" 2>/dev/null)
    if [ -z "$found" ]; then
        echo "  Signature rule_id=$rule_id introuvable"
        exit 1
    fi
done

# Vérifier MITRE résolu via JOIN
TEST=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT mt.technique_id FROM signatures s
     JOIN mitre_techniques mt ON s.technique_id = mt.id
     WHERE s.id = 5712 LIMIT 1" 2>/dev/null)
if [ -z "$TEST" ]; then
    echo "  JOIN MITRE échoué pour signature 5712"
    exit 1
fi

echo "  Lookup OK : 380 sigs, 5 lookups testés, JOIN MITRE fonctionnel"
exit 0
