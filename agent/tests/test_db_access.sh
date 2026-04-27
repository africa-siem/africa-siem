#!/usr/bin/env bash
# Test : l'agent peut lire ET écrire la BDD

DB_PATH="/var/lib/siem-africa/siem.db"
SYSTEM_USER="siem-agent"

if [ ! -f "$DB_PATH" ]; then
    echo "  BDD introuvable : $DB_PATH"
    exit 1
fi

# Test lecture
if ! sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures" >/dev/null 2>&1; then
    echo "  $SYSTEM_USER ne peut pas lire la BDD"
    exit 1
fi

# Test écriture (transaction rollback pour ne rien modifier)
if ! sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "BEGIN; UPDATE settings SET updated_at=updated_at WHERE id=1; ROLLBACK;" >/dev/null 2>&1; then
    echo "  $SYSTEM_USER ne peut pas écrire dans la BDD"
    exit 1
fi

# Vérifier que les FK fonctionnent
if ! sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "PRAGMA foreign_key_check" >/dev/null 2>&1; then
    echo "  Impossible d'exécuter foreign_key_check"
    exit 1
fi

echo "  BDD accessible en lecture/écriture par $SYSTEM_USER"
exit 0
